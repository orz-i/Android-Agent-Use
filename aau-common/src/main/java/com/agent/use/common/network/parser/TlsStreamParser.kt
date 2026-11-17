package com.agent.use.common.network.parser

import android.os.RemoteException
import android.util.Log
import com.agent.use.common.network.HttpHeader
import com.agent.use.common.network.HttpRequestEvent
import com.agent.use.common.network.HttpResponseEvent
import com.agent.use.common.network.INetworkEventListener
import com.agent.use.common.network.NetworkCaptureConfig
import com.agent.use.common.network.plugin.NetworkCapturePluginRegistry
import com.agent.use.common.network.plugin.NetworkTrafficMiddleware
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/**
 * Shared plaintext TLS/HTTP stream demultiplexer that auto-detects HTTP/2 vs HTTP/1.x,
 * buffers response bodies before firing `onResponseReceived`, and applies [NetworkCaptureConfig] URL filtering.
 */
class TlsStreamParser @JvmOverloads constructor(
    private val config: NetworkCaptureConfig,
    private val listener: INetworkEventListener,
    private val defaultConnectionHostHint: String? = null,
    private val middlewares: List<NetworkTrafficMiddleware> =
        NetworkCapturePluginRegistry.resolveMiddlewares(config.targetPackage)
) {

    companion object {
        private const val TAG = "TlsStreamParser"
        private const val MAX_CACHED_BODIES = 500
        private const val MAX_PENDING_DECODED_BODIES = 32
        private const val DECODED_BODY_TTL_MS = 3000L
        val HTTP2_PREFACE_PREFIX = "PRI ".toByteArray(StandardCharsets.ISO_8859_1)

        /**
         * Reliable frame-level HTTP/2 detection per RFC 7540:
         * 9-byte frame header (length: 24-bit, type: 0x0..0x9, flags: 8-bit, streamId: 31-bit),
         * streamId bit constraints (0 for SETTINGS/PING/GOAWAY, >0 for DATA/HEADERS),
         * length constraints, and not starting with ASCII HTTP/1.x method/status.
         */
        fun startsWithHttp2Frame(data: ByteArray, offset: Int = 0): Boolean {
            if (data.size - offset < 9) return false

            val b0 = data[offset].toInt() and 0xFF
            val b1 = data[offset + 1].toInt() and 0xFF
            val b2 = data[offset + 2].toInt() and 0xFF
            val b3 = data[offset + 3].toInt() and 0xFF

            // Quick check against common ASCII HTTP/1.x prefixes
            if (b0 == 'G'.code && b1 == 'E'.code && b2 == 'T'.code && b3 == ' '.code) return false
            if (b0 == 'P'.code && b1 == 'O'.code && b2 == 'S'.code && b3 == 'T'.code) return false
            if (b0 == 'H'.code && b1 == 'E'.code && b2 == 'A'.code && b3 == 'D'.code) return false
            if (b0 == 'P'.code && b1 == 'U'.code && b2 == 'T'.code && b3 == ' '.code) return false
            if (b0 == 'D'.code && b1 == 'E'.code && b2 == 'L'.code && b3 == 'E'.code) return false
            if (b0 == 'O'.code && b1 == 'P'.code && b2 == 'T'.code && b3 == 'I'.code) return false
            if (b0 == 'P'.code && b1 == 'A'.code && b2 == 'T'.code && b3 == 'C'.code) return false
            if (b0 == 'C'.code && b1 == 'O'.code && b2 == 'N'.code && b3 == 'N'.code) return false
            if (b0 == 'T'.code && b1 == 'R'.code && b2 == 'A'.code && b3 == 'C'.code) return false
            if (b0 == 'H'.code && b1 == 'T'.code && b2 == 'T'.code && b3 == 'P'.code) return false

            val length = (b0 shl 16) or (b1 shl 8) or b2
            val type = b3
            val streamId = ((data[offset + 5].toInt() and 0x7F) shl 24) or
                ((data[offset + 6].toInt() and 0xFF) shl 16) or
                ((data[offset + 7].toInt() and 0xFF) shl 8) or
                (data[offset + 8].toInt() and 0xFF)

            if (type !in 0x0..0x9) return false
            if (length < 0 || length > 16 * 1024 * 1024) return false

            when (type) {
                0x0 -> if (streamId == 0) return false // DATA
                0x1 -> if (streamId == 0) return false // HEADERS
                0x2 -> if (streamId == 0 || length != 5) return false // PRIORITY
                0x3 -> if (streamId == 0 || length != 4) return false // RST_STREAM
                0x4 -> if (streamId != 0 || (length % 6) != 0) return false // SETTINGS
                0x5 -> if (streamId == 0 || length < 4) return false // PUSH_PROMISE
                0x6 -> if (streamId != 0 || length != 8) return false // PING
                0x7 -> if (streamId != 0 || length < 8) return false // GOAWAY
                0x8 -> if (length != 4) return false // WINDOW_UPDATE
                0x9 -> if (streamId == 0) return false // CONTINUATION
            }

            val nextOffset = offset + 9 + length
            if (data.size >= nextOffset + 9) {
                val nextType = data[nextOffset + 3].toInt() and 0xFF
                if (nextType !in 0x0..0x9) return false
            }

            return true
        }

        fun startsWithHttp2Preface(data: ByteArray): Boolean {
            if (data.size < HTTP2_PREFACE_PREFIX.size) return false
            for (i in HTTP2_PREFACE_PREFIX.indices) {
                if (data[i] != HTTP2_PREFACE_PREFIX[i]) return false
            }
            return true
        }

        fun isHttp2Traffic(data: ByteArray): Boolean =
            startsWithHttp2Preface(data) || startsWithHttp2Frame(data)
    }

    private enum class Protocol {
        UNKNOWN,
        HTTP_1_1,
        HTTP_2
    }

    private val connectionProtocols = ConcurrentHashMap<String, Protocol>()
    private val connectionHostHints = ConcurrentHashMap<String, String>()
    private val http1Parsers = ConcurrentHashMap<String, Http1PlaintextParser>()
    private val http2Parsers = ConcurrentHashMap<String, Http2PlaintextParser>()

    private class CronetStreamState(
        val requestId: String,
        var url: String,
        var method: String = "GET",
        var statusCode: Int = 200,
        var statusText: String = "OK",
        var responseHeaders: List<HttpHeader> = emptyList(),
        var mimeType: String? = null,
        var contentLength: Long = -1L,
        var hasContentEncoding: Boolean = false,
        var requestDispatched: Boolean = false,
        var responseHeadersReceived: Boolean = false,
        var responseDispatched: Boolean = false,
        val bodyBuffer: ByteArrayOutputStream = ByteArrayOutputStream()
    )

    private val cronetSeq = AtomicLong(1L)
    private val cronetStreams = ConcurrentHashMap<String, CronetStreamState>()

    @Volatile
    private var lastKnownHost: String? = defaultConnectionHostHint?.takeIf { isUsableHost(it) }

    private val responseBodies = Collections.synchronizedMap(
        object : LinkedHashMap<String, ByteArrayOutputStream>(64, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, ByteArrayOutputStream>?): Boolean {
                return size > MAX_CACHED_BODIES
            }
        }
    )

    private class DecodedBody(val producedAt: Long, val bytes: ByteArray)

    // Plaintext decoded inside the target process by the JNI bridge, waiting for its
    // matching HTTP response. Entries expire so a stray decode cannot attach to a
    // response that arrives much later.
    private val pendingDecodedBodies = ArrayDeque<DecodedBody>()
    private val decodedBodyLock = Any()

    /**
     * Receives plaintext produced by an in-process native decoder (JNI bridge probe).
     *
     * Apps like BOSS encrypt response bodies *above* TLS, so the SSL layer only ever
     * yields ciphertext. This channel carries the post-decryption bytes observed at
     * the native decoder's return value — no injection, no key material required.
     */
    fun onDecodedJniBody(methodId: Int, body: ByteArray) {
        if (body.isEmpty()) return
        val normalized = normalizeDecodedBody(body)
        val now = System.currentTimeMillis()
        synchronized(decodedBodyLock) {
            while (pendingDecodedBodies.isNotEmpty() &&
                now - pendingDecodedBodies.first().producedAt > DECODED_BODY_TTL_MS
            ) {
                pendingDecodedBodies.removeFirst()
            }
            pendingDecodedBodies.addLast(DecodedBody(now, normalized))
            while (pendingDecodedBodies.size > MAX_PENDING_DECODED_BODIES) {
                pendingDecodedBodies.removeFirst()
            }
        }
        if (Log.isLoggable(TAG, Log.VERBOSE)) {
            Log.v(TAG, "decoded jni body method=$methodId bytes=${normalized.size}")
        }
    }

    /**
     * Normalizes the two encodings the BOSS decoder emits.
     *
     * Its UTF-16 output is byte-identical JSON otherwise, so transcoding here keeps
     * every downstream consumer (shape checks, middlewares, the UI) encoding-blind.
     */
    private fun normalizeDecodedBody(body: ByteArray): ByteArray {
        if (body.size < 4 || body.size % 2 != 0) return body
        val first = body[0]
        if (first != '{'.code.toByte() && first != '['.code.toByte()) return body
        // UTF-16LE keeps the second byte of each ASCII char at zero.
        if (body[1] != 0.toByte() || body[3] != 0.toByte()) return body
        return runCatching {
            String(body, Charsets.UTF_16LE).toByteArray(Charsets.UTF_8)
        }.getOrDefault(body)
    }

    /**
     * Pops the oldest staged plaintext that satisfies [accept].
     *
     * The shape filter matters: the loader already refuses to emit payloads it cannot
     * positively identify, but a mis-resolved `jbyteArray` can still slip through as
     * printable garbage. Letting such a frame replace a good ciphertext body would make
     * the response *less* useful than leaving it untouched, so non-matching entries are
     * left in the queue (they may pair with a later response within the TTL) instead of
     * being discarded.
     */
    private fun takeDecodedBody(accept: (ByteArray) -> Boolean = { true }): ByteArray? {
        val now = System.currentTimeMillis()
        synchronized(decodedBodyLock) {
            var scanned = 0
            while (scanned < pendingDecodedBodies.size) {
                val entry = pendingDecodedBodies.removeFirst()
                if (now - entry.producedAt > DECODED_BODY_TTL_MS) continue
                if (accept(entry.bytes)) return entry.bytes
                pendingDecodedBodies.addLast(entry)
                scanned++
            }
        }
        return null
    }

    fun setConnectionHostHint(connectionId: String, hostHint: String) {
        val clean = extractHost(hostHint) ?: return
        if (isUsableHost(clean)) {
            connectionHostHints[connectionId] = clean
            lastKnownHost = clean
            http1Parsers[connectionId]?.setConnectionHostHint(clean)
            http2Parsers[connectionId]?.setConnectionHostHint(clean)
        }
    }

    fun onOutboundData(connectionId: String, data: ByteArray, hostHint: String? = null) {
        if (data.isEmpty()) return
        if (hostHint != null) setConnectionHostHint(connectionId, hostHint)
        when (resolveOrUpgradeProtocol(connectionId, data)) {
            Protocol.HTTP_2 -> http2Parsers.computeIfAbsent(connectionId) { createHttp2Parser(connectionId) }.feedOutbound(data, connectionId)
            else -> http1Parsers.computeIfAbsent(connectionId) { createHttp1Parser(connectionId) }.feedOutbound(data, connectionId)
        }
    }

    fun onInboundData(connectionId: String, data: ByteArray, hostHint: String? = null) {
        if (data.isEmpty()) return
        if (hostHint != null) setConnectionHostHint(connectionId, hostHint)
        when (resolveOrUpgradeProtocol(connectionId, data)) {
            Protocol.HTTP_2 -> http2Parsers.computeIfAbsent(connectionId) { createHttp2Parser(connectionId) }.feedInbound(data, connectionId)
            else -> http1Parsers.computeIfAbsent(connectionId) { createHttp1Parser(connectionId) }.feedInbound(data, connectionId)
        }
    }

    fun onCronetRequest(connectionId: String, payload: ByteArray) {
        if (payload.isEmpty()) return
        val nulIdx = payload.indexOf(0.toByte())
        val endIdx = if (nulIdx >= 0) nulIdx else payload.size
        val url = String(payload, 0, endIdx, StandardCharsets.UTF_8).trim()
        if (url.isEmpty()) return

        cronetStreams.remove(connectionId)?.let { prev ->
            if (prev.responseHeadersReceived && !prev.responseDispatched) {
                finalizeCronetStream(connectionId, prev)
            }
        }

        extractHost(url)?.takeIf { isUsableHost(it) }?.let { host ->
            connectionHostHints[connectionId] = host
            lastKnownHost = host
        }

        val state = CronetStreamState(
            requestId = "${connectionId}_cr_${cronetSeq.getAndIncrement()}",
            url = url
        )
        cronetStreams[connectionId] = state
        dispatchCronetRequestIfNeeded(state)
    }

    fun onCronetResponseStarted(connectionId: String, payload: ByteArray) {
        if (payload.size < 4) return
        val statusCode = (payload[0].toInt() and 0xFF) or
            ((payload[1].toInt() and 0xFF) shl 8) or
            ((payload[2].toInt() and 0xFF) shl 16) or
            ((payload[3].toInt() and 0xFF) shl 24)

        val state = cronetStreams.computeIfAbsent(connectionId) {
            val fallbackHost = connectionHostHints[connectionId] ?: lastKnownHost ?: defaultConnectionHostHint ?: "unknown-host"
            CronetStreamState(
                requestId = "${connectionId}_cr_${cronetSeq.getAndIncrement()}",
                url = "https://$fallbackHost/"
            )
        }

        val (parsedStatusText, headers) = parseCronetHeaders(payload, 4, payload.size - 4)
        synchronized(state) {
            state.statusCode = if (statusCode > 0) statusCode else 200
            if (parsedStatusText != null) {
                state.statusText = parsedStatusText
            } else {
                state.statusText = if (state.statusCode in 200..299) "OK" else ""
            }
            state.responseHeaders = headers
            state.mimeType = headers.firstOrNull { it.name.equals("content-type", ignoreCase = true) }?.value
            state.contentLength = headers.firstOrNull { it.name.equals("content-length", ignoreCase = true) }
                ?.value?.trim()?.toLongOrNull() ?: -1L
            val encoding = headers.firstOrNull { it.name.equals("content-encoding", ignoreCase = true) }?.value?.trim()?.lowercase()
            state.hasContentEncoding = !encoding.isNullOrBlank() && encoding != "identity"
            state.responseHeadersReceived = true
        }
        dispatchCronetRequestIfNeeded(state)
    }

    fun onCronetReadCompleted(connectionId: String, payload: ByteArray) {
        if (payload.isEmpty()) return
        val state = cronetStreams[connectionId] ?: return
        val shouldFinalize = synchronized(state) {
            if (state.responseDispatched) return@synchronized false
            val remaining = (config.maxBodySizeBytes - state.bodyBuffer.size()).toInt().coerceAtLeast(0)
            val toWrite = minOf(payload.size, remaining)
            if (toWrite > 0) {
                state.bodyBuffer.write(payload, 0, toWrite)
            }
            !state.hasContentEncoding &&
                state.responseHeadersReceived &&
                state.contentLength > 0L &&
                state.bodyBuffer.size().toLong() >= state.contentLength
        }
        if (shouldFinalize) {
            finalizeCronetStream(connectionId, state)
        }
    }

    fun onCronetFinish(connectionId: String) {
        val state = cronetStreams.remove(connectionId) ?: return
        finalizeCronetStream(connectionId, state)
    }

    private fun dispatchCronetRequestIfNeeded(state: CronetStreamState) {
        val shouldSend = synchronized(state) {
            if (state.requestDispatched) false else {
                state.requestDispatched = true
                true
            }
        }
        if (!shouldSend) return
        dispatchRequest(
            HttpRequestEvent(
                requestId = state.requestId,
                timestamp = System.currentTimeMillis(),
                url = state.url,
                method = state.method,
                headers = emptyList(),
                postData = null,
                isTls = state.url.startsWith("https", ignoreCase = true)
            )
        )
    }

    private fun finalizeCronetStream(connectionId: String, state: CronetStreamState) {
        val rawBytes: ByteArray
        synchronized(state) {
            if (state.responseDispatched) return
            state.responseDispatched = true
            rawBytes = state.bodyBuffer.toByteArray()
        }
        cronetStreams.remove(connectionId, state)
        dispatchCronetRequestIfNeeded(state)

        val isGzipMagic = HttpContentDecoder.hasGzipMagic(rawBytes)
        val isZstdMagic = HttpContentDecoder.hasZstdMagic(rawBytes)
        val finalBody = if (isGzipMagic || isZstdMagic) {
            HttpContentDecoder.decompressByMagicOrEncoding(rawBytes)
        } else {
            rawBytes
        }

        if (finalBody.isNotEmpty()) {
            stageResponseBody(state.requestId, finalBody)
        }

        val effectiveLength = if (finalBody.isNotEmpty()) {
            finalBody.size.toLong()
        } else {
            state.contentLength.coerceAtLeast(0L)
        }

        dispatchResponse(
            HttpResponseEvent(
                requestId = state.requestId,
                timestamp = System.currentTimeMillis(),
                url = state.url,
                statusCode = state.statusCode,
                statusText = state.statusText,
                headers = state.responseHeaders,
                mimeType = state.mimeType,
                contentLength = effectiveLength,
                fromCache = false
            )
        )
    }

    private fun parseCronetHeaders(payload: ByteArray, offset: Int, len: Int): Pair<String?, List<HttpHeader>> {
        if (len <= 0 || offset >= payload.size) return null to emptyList()
        val safeLen = minOf(len, payload.size - offset)
        val rawText = String(payload, offset, safeLen, StandardCharsets.ISO_8859_1)
        val lines = rawText.split('\u0000', '\n')
        var statusText: String? = null
        val headers = ArrayList<HttpHeader>()
        for (rawLine in lines) {
            val line = rawLine.trim('\r', ' ', '\t')
            if (line.isEmpty()) continue
            if (line.startsWith("HTTP/", ignoreCase = true)) {
                val firstSpace = line.indexOf(' ')
                if (firstSpace > 0) {
                    val afterProto = line.substring(firstSpace + 1).trim()
                    val secondSpace = afterProto.indexOf(' ')
                    if (secondSpace > 0 && secondSpace + 1 < afterProto.length) {
                        statusText = afterProto.substring(secondSpace + 1).trim()
                    }
                }
                continue
            }
            val colon = line.indexOf(':', startIndex = if (line.startsWith(':')) 1 else 0)
            if (colon > 0) {
                val name = line.substring(0, colon).trim()
                val value = line.substring(colon + 1).trim()
                if (name.isNotEmpty()) {
                    headers.add(HttpHeader(name, value))
                }
            }
        }
        return statusText to headers
    }

    fun finishConnection(connectionId: String) {
        http1Parsers[connectionId]?.finishOnEof()
        http1Parsers.remove(connectionId)
        // 连接被切断时把还没等到 END_STREAM 的 HTTP/2 流排空，
        // 否则半截响应会随着 parser 一起被丢掉。
        http2Parsers.remove(connectionId)?.finish()
        cronetStreams.remove(connectionId)?.let { finalizeCronetStream(connectionId, it) }
        connectionProtocols.remove(connectionId)
        connectionHostHints.remove(connectionId)
    }

    fun getResponseBody(requestId: String): ByteArray? {
        val stream = synchronized(responseBodies) { responseBodies[requestId] } ?: return null
        return synchronized(stream) { stream.toByteArray() }
    }

    fun clear() {
        connectionProtocols.clear()
        connectionHostHints.clear()
        http1Parsers.clear()
        http2Parsers.clear()
        cronetStreams.clear()
        lastKnownHost = defaultConnectionHostHint?.takeIf { isUsableHost(it) }
        synchronized(responseBodies) { responseBodies.clear() }
    }

    private fun resolveOrUpgradeProtocol(connectionId: String, data: ByteArray): Protocol {
        val existing = connectionProtocols[connectionId]
        if (existing == Protocol.HTTP_2) {
            return Protocol.HTTP_2
        }

        val isH2 = isHttp2Traffic(data)

        if (existing == Protocol.HTTP_1_1) {
            if (isH2) {
                val h1 = http1Parsers[connectionId]
                if (h1 == null || !h1.hasDispatched()) {
                    // Upgrade cleanly to HTTP/2
                    val bufferedOut = h1?.getUnconsumedOutbound() ?: ByteArray(0)
                    val bufferedIn = h1?.getUnconsumedInbound() ?: ByteArray(0)
                    http1Parsers.remove(connectionId)
                    connectionProtocols[connectionId] = Protocol.HTTP_2

                    val h2 = http2Parsers.computeIfAbsent(connectionId) { createHttp2Parser(connectionId) }
                    if (bufferedOut.isNotEmpty()) {
                        h2.feedOutbound(bufferedOut, connectionId)
                    }
                    if (bufferedIn.isNotEmpty()) {
                        h2.feedInbound(bufferedIn, connectionId)
                    }
                    return Protocol.HTTP_2
                }
            }
            return Protocol.HTTP_1_1
        }

        // existing was null or Protocol.UNKNOWN
        val determined = if (isH2) Protocol.HTTP_2 else Protocol.HTTP_1_1
        connectionProtocols[connectionId] = determined
        return determined
    }

    private fun createHttp1Parser(connectionId: String): Http1PlaintextParser =
        Http1PlaintextParser(
            maxBodySizeBytes = config.maxBodySizeBytes,
            connectionHostHint = connectionHostHints[connectionId] ?: lastKnownHost ?: defaultConnectionHostHint,
            onParsedRequest = ::dispatchRequest,
            onParsedResponse = ::dispatchResponse,
            onBodyChunk = ::stageResponseBody
        )

    private fun createHttp2Parser(connectionId: String): Http2PlaintextParser =
        Http2PlaintextParser(
            maxBodySizeBytes = config.maxBodySizeBytes,
            connectionHostHint = connectionHostHints[connectionId] ?: lastKnownHost ?: defaultConnectionHostHint,
            onParsedRequest = ::dispatchRequest,
            onParsedResponse = ::dispatchResponse,
            onBodyChunk = ::stageResponseBody
        )

    private fun dispatchRequest(request: HttpRequestEvent) {
        var effective = request
        val currentHost = extractHost(request.url)
        if (currentHost != null) {
            lastKnownHost = currentHost
        } else if (request.url.contains("://unknown-host")) {
            val resolved = extractHostFromHeaders(request.headers) ?: lastKnownHost ?: defaultConnectionHostHint
            if (resolved != null && isUsableHost(resolved)) {
                lastKnownHost = resolved
                effective = request.copy(url = request.url.replace("://unknown-host", "://$resolved"))
            }
        }
        for (middleware in middlewares) {
            effective = middleware.onRequest(config.targetPackage, effective)
        }
        extractHost(effective.url)?.takeIf { isUsableHost(it) }?.let { host ->
            lastKnownHost = host
        }
        if (!config.matchesUrl(effective.url)) return
        try {
            listener.onRequestWillBeSent(effective)
        } catch (e: RemoteException) {
            Log.w(TAG, "RemoteException dispatching onRequestWillBeSent: ${e.message}")
        }
    }

    private fun dispatchResponse(response: HttpResponseEvent) {
        var effective = applyDecodedBodyOverride(response)
        val currentHost = extractHost(response.url)
        if (currentHost != null) {
            lastKnownHost = currentHost
        } else if (response.url.contains("://unknown-host")) {
            val resolved = extractHostFromHeaders(response.headers) ?: lastKnownHost ?: defaultConnectionHostHint
            if (resolved != null && isUsableHost(resolved)) {
                lastKnownHost = resolved
                effective = response.copy(url = response.url.replace("://unknown-host", "://$resolved"))
            }
        }
        if (middlewares.isNotEmpty()) {
            var currentBody = getResponseBody(effective.requestId)
            val initialBody = currentBody
            for (middleware in middlewares) {
                val (nextEvent, nextBody) = middleware.onResponse(config.targetPackage, effective, currentBody)
                effective = nextEvent
                currentBody = nextBody
            }
            extractHost(effective.url)?.takeIf { isUsableHost(it) }?.let { host ->
                lastKnownHost = host
            }
            if (currentBody !== initialBody && !currentBody.contentEquals(initialBody)) {
                if (currentBody == null) {
                    synchronized(responseBodies) { responseBodies.remove(effective.requestId) }
                    effective = effective.copy(contentLength = 0L)
                } else {
                    val out = ByteArrayOutputStream()
                    val maxBytes = config.maxBodySizeBytes.coerceIn(0L, Int.MAX_VALUE.toLong()).toInt()
                    val toWrite = minOf(currentBody.size, maxBytes)
                    if (toWrite > 0) {
                        out.write(currentBody, 0, toWrite)
                    }
                    synchronized(responseBodies) { responseBodies[effective.requestId] = out }
                    effective = effective.copy(contentLength = out.size().toLong())
                }
            }
        }
        if (!config.matchesUrl(effective.url)) return
        val finalBody = getResponseBody(effective.requestId)
        if (finalBody != null && finalBody.isNotEmpty()) {
            try {
                listener.onDataChunkReceived(effective.requestId, finalBody)
            } catch (e: RemoteException) {
                Log.w(TAG, "RemoteException dispatching onDataChunkReceived: ${e.message}")
            }
        }
        try {
            listener.onResponseReceived(effective)
        } catch (e: RemoteException) {
            Log.w(TAG, "RemoteException dispatching onResponseReceived: ${e.message}")
        }
    }

    /**
     * Swaps an opaque response body for the plaintext captured by the JNI bridge.
     *
     * Guarded so it only ever fires on payloads that *look* encrypted: the response
     * advertises JSON yet the staged bytes are not JSON. Genuinely plaintext
     * responses, images, and binary blobs are left untouched.
     */
    private fun applyDecodedBodyOverride(event: HttpResponseEvent): HttpResponseEvent {
        val requestId = event.requestId
        val staged = getResponseBody(requestId)
        if (staged == null || staged.isEmpty()) return event
        if (isLikelyJsonPayload(staged)) return event
        if (!advertisesJson(event)) return event

        val decoded = takeDecodedBody(::looksRecognizable) ?: return event
        if (decoded.isEmpty()) return event

        val maxBytes = config.maxBodySizeBytes.coerceIn(0L, Int.MAX_VALUE.toLong()).toInt()
        val out = ByteArrayOutputStream()
        val toWrite = minOf(decoded.size, maxBytes)
        if (toWrite > 0) out.write(decoded, 0, toWrite)
        synchronized(responseBodies) { responseBodies[requestId] = out }

        val hint = "jni:${staged.size}->${decoded.size}"
        Log.d(TAG, "decoded body override $requestId $hint")
        return event.copy(
            contentLength = out.size().toLong(),
            headers = event.headers + HttpHeader("x-aau-decode-hint", hint)
        )
    }

    private fun advertisesJson(event: HttpResponseEvent): Boolean {
        val contentType = event.headers.firstOrNull {
            it.name.equals("content-type", ignoreCase = true)
        }?.value ?: return false
        return contentType.contains("json", ignoreCase = true)
    }

    private fun isLikelyJsonPayload(bytes: ByteArray): Boolean {
        var i = 0
        if (bytes.size >= 3 &&
            bytes[0] == 0xEF.toByte() && bytes[1] == 0xBB.toByte() && bytes[2] == 0xBF.toByte()
        ) {
            i = 3
        }
        while (i < bytes.size) {
            val b = bytes[i]
            if (b == ' '.code.toByte() || b == '\n'.code.toByte() ||
                b == '\r'.code.toByte() || b == '\t'.code.toByte()
            ) {
                i++
            } else {
                break
            }
        }
        if (i >= bytes.size) return false
        return bytes[i] == '{'.code.toByte() || bytes[i] == '['.code.toByte()
    }

    /**
     * Cheap acceptance test for a payload the JNI bridge claims is plaintext.
     *
     * A real decoder hands back either JSON or a container whose header is ASCII
     * (`BZPBlock` and friends). A mis-resolved `jbyteArray` reads back as arbitrary
     * process memory, which essentially never starts with four printable bytes —
     * so this rejects the garbage without needing to know any app-specific format.
     */
    private fun looksRecognizable(bytes: ByteArray): Boolean {
        if (isLikelyJsonPayload(bytes)) {
            // A decoder that splits a large string across several arrays hands us a
            // valid-looking prefix that never closes. Injecting that would silently
            // corrupt the body, which is worse than leaving the ciphertext in place.
            var end = bytes.size - 1
            while (end >= 0) {
                val b = bytes[end].toInt() and 0xFF
                if (b == 0x20 || b == 0x09 || b == 0x0A || b == 0x0D || b == 0x00) end-- else break
            }
            if (end < 0) return false
            val tail = bytes[end].toInt() and 0xFF
            return tail == '}'.code || tail == ']'.code
        }
        if (bytes.size < 4) return false
        for (i in 0 until 4) {
            val b = bytes[i].toInt() and 0xFF
            if (b < 0x20 || b > 0x7E) return false
        }
        return true
    }

    private fun stageResponseBody(requestId: String, chunk: ByteArray) {
        val bodyStream = synchronized(responseBodies) {
            responseBodies.getOrPut(requestId) { ByteArrayOutputStream() }
        }
        synchronized(bodyStream) {
            if (bodyStream.size() < config.maxBodySizeBytes) {
                val allowed = (config.maxBodySizeBytes - bodyStream.size()).toInt().coerceAtLeast(0)
                val toWrite = minOf(chunk.size, allowed)
                if (toWrite > 0) bodyStream.write(chunk, 0, toWrite)
            }
        }
    }
}
