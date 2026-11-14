package com.agent.use.common.network.parser

import android.os.RemoteException
import android.util.Log
import com.agent.use.common.network.HttpHeader
import com.agent.use.common.network.HttpRequestEvent
import com.agent.use.common.network.HttpResponseEvent
import com.agent.use.common.network.INetworkEventListener
import com.agent.use.common.network.NetworkCaptureConfig
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/**
 * Shared plaintext TLS/HTTP stream demultiplexer that auto-detects HTTP/2 vs HTTP/1.x,
 * buffers response bodies before firing `onResponseReceived`, and applies [NetworkCaptureConfig] URL filtering.
 */
class TlsStreamParser(
    private val config: NetworkCaptureConfig,
    private val listener: INetworkEventListener,
    private val defaultConnectionHostHint: String? = null
) {

    companion object {
        private const val TAG = "TlsStreamParser"
        private const val MAX_CACHED_BODIES = 500
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

        // Cronet's OnReadCompleted delivers decompressed bytes even when raw_headers_ retains Content-Encoding.
        // Only run gzip decompression if the bytes still have the gzip magic header (0x1f 0x8b).
        val isGzipMagic = rawBytes.size >= 2 &&
            (rawBytes[0].toInt() and 0xFF) == 0x1F &&
            (rawBytes[1].toInt() and 0xFF) == 0x8B
        val finalBody = if (isGzipMagic) {
            HttpContentDecoder.decompressIfNeeded(rawBytes, state.responseHeaders)
        } else {
            rawBytes
        }

        if (finalBody.isNotEmpty()) {
            dispatchBodyChunk(state.requestId, finalBody)
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
        http2Parsers.remove(connectionId)
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
            onBodyChunk = ::dispatchBodyChunk
        )

    private fun createHttp2Parser(connectionId: String): Http2PlaintextParser =
        Http2PlaintextParser(
            maxBodySizeBytes = config.maxBodySizeBytes,
            connectionHostHint = connectionHostHints[connectionId] ?: lastKnownHost ?: defaultConnectionHostHint,
            onParsedRequest = ::dispatchRequest,
            onParsedResponse = ::dispatchResponse,
            onBodyChunk = ::dispatchBodyChunk
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
        if (!config.matchesUrl(effective.url)) return
        try {
            listener.onRequestWillBeSent(effective)
        } catch (e: RemoteException) {
            Log.w(TAG, "RemoteException dispatching onRequestWillBeSent: ${e.message}")
        }
    }

    private fun dispatchResponse(response: HttpResponseEvent) {
        var effective = response
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
        if (!config.matchesUrl(effective.url)) return
        try {
            listener.onResponseReceived(effective)
        } catch (e: RemoteException) {
            Log.w(TAG, "RemoteException dispatching onResponseReceived: ${e.message}")
        }
    }

    private fun dispatchBodyChunk(requestId: String, chunk: ByteArray) {
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
        try {
            listener.onDataChunkReceived(requestId, chunk)
        } catch (e: RemoteException) {
            Log.w(TAG, "RemoteException dispatching onDataChunkReceived: ${e.message}")
        }
    }
}
