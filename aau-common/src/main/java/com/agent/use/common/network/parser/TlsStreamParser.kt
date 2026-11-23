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
        private const val MAX_PENDING_DECODED_BODIES = 64
        /** 等明文时留存的密文开头长度，和 loader 采集的指纹长度对齐。 */
        private const val STAGED_HEAD_BYTES = 16
        private const val DECODED_BODY_TTL_MS = 3000L
        /** 明文比响应晚到时,这条响应最多等多久。比 [DECODED_BODY_TTL_MS] 略长:要先等明文产生。 */
        private const val AWAITING_PLAINTEXT_TTL_MS = 5000L
        private const val MAX_AWAITING_PLAINTEXT = 64
        /** 解出明文/剥过容器时挂在响应头上的标记。 */
        internal const val AUX_DECODE_HINT_HEADER = "x-aau-decode-hint"
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

    /**
     * A plaintext decoded inside the process, plus the lengths its source body could have had.
     *
     * [srcSizes] comes from the decoder call's *input* array — the ciphertext — so it identifies
     * the response exactly. Responses that compress before encrypting decode to something longer
     * than the wire bytes, which is why the plaintext's own size is not a usable identity.
     */
    private class DecodedBody(
        val producedAt: Long,
        val bytes: ByteArray,
        val srcSizes: Set<Int>,
        /** 解码器入参数组的开头若干字节，也就是线上那包密文：按内容配对，不靠长度猜。 */
        val srcPrefix: ByteArray? = null
    ) {
        /**
         * 这条响应的长度对不对得上。
         *
         * 解码器入参数组的字节数就是线上那包密文的长度，[srcSizes] 记的是
         * `GetArrayLength` 读回来的真值，所以这一道是精确的。
         */
        fun sizeMatches(cipherSize: Int): Boolean =
            if (srcSizes.isEmpty()) bytes.size == cipherSize else srcSizes.contains(cipherSize)

        /**
         * 内容指纹对不对得上。
         *
         * 指纹是**否决项**，不是加分项：同一套信封的密文前缀本来就一样（同一个密钥流 +
         * 同样的 `{"code":0,...` 开头），单靠它认不出是哪一条，所以它不能替代长度；
         * 而长度撞车、其实不是同一家的两包，只有它能分开。拿它当门槛时最坏结果是
         * "这次没贴上、继续留密文"，反过来最坏结果是"贴错一包、内容张冠李戴"——
         * 后者更糟，所以宁可作废。
         *
         * 长度和指纹都指着同一包时才算数；loader 没给指纹(空)时退回只看长度。
         */
        fun fingerprintMatches(stagedHead: ByteArray?): Boolean {
            val want = srcPrefix
            if (want == null || want.isEmpty()) return true
            if (stagedHead == null) return true
            val n = minOf(want.size, stagedHead.size)
            if (n < 4) return true
            for (i in 0 until n) {
                if (stagedHead[i] != want[i]) return false
            }
            return true
        }

        /** 长度与指纹都通过，才算这条响应的明文。 */
        fun matches(cipherSize: Int, stagedHead: ByteArray?): Boolean =
            sizeMatches(cipherSize) && fingerprintMatches(stagedHead)
    }

    // Plaintext decoded inside the target process by the JNI bridge, waiting for its
    // matching HTTP response. Entries expire so a stray decode cannot attach to a
    // response that arrives much later.
    private val pendingDecodedBodies = ArrayDeque<DecodedBody>()
    private val decodedBodyLock = Any()

    /**
     * Responses that arrived as ciphertext and are still waiting for their plaintext.
     *
     * The in-process decoder runs *after* the bytes are on the wire, and the helper hands
     * captured frames over in ~250ms batches, so most plaintext shows up slightly after the
     * response is dispatched. Waiting in [pendingDecodedBodies] alone would lose every one of
     * those: the entry would sit there until it expired or, worse, be glued onto the next
     * response. Instead the response is remembered here and re-dispatched once its plaintext
     * arrives (see [attachLatePlaintext]).
     */
    private class AwaitingPlaintext(
        val requestId: String,
        val event: HttpResponseEvent,
        val stagedSize: Int,
        /** 密文开头，用来和明文的 [DecodedBody.srcPrefix] 逐字节对。 */
        val stagedHead: ByteArray,
        val at: Long
    )

    private val awaitingPlaintext = ArrayDeque<AwaitingPlaintext>()
    private val awaitingLock = Any()

    /**
     * Receives plaintext produced by an in-process native decoder (JNI bridge probe).
     *
     * Apps like BOSS encrypt response bodies *above* TLS, so the SSL layer only ever
     * yields ciphertext. This channel carries the post-decryption bytes observed at
     * the native decoder's return value — no injection, no key material required.
     *
     * [sourceLengths] are candidate byte-lengths of the array that was handed to the decoder,
     * i.e. the response body it came from. Without them a plaintext can only be paired by its
     * own length, which fails as soon as the app compresses before encrypting.
     */
    @JvmOverloads
    fun onDecodedJniBody(
        methodId: Int,
        body: ByteArray,
        sourceLengths: IntArray? = null,
        sourcePrefix: IntArray? = null
    ) {
        if (body.isEmpty()) return
        val normalized = normalizeDecodedBody(body)
        val sources = sourceLengths
            ?.filter { it > 0 }
            ?.toSet()
            .orEmpty()
        // 指纹是小端 u32 序列，原样摊回字节；全 0 说明这次没抓到入参数组的字节。
        val prefix = sourcePrefix
            ?.takeIf { words -> words.any { it != 0 } }
            ?.let { words ->
                val out = ByteArray(words.size * 4)
                for (i in words.indices) {
                    val w = words[i]
                    out[i * 4] = (w and 0xFF).toByte()
                    out[i * 4 + 1] = ((w ushr 8) and 0xFF).toByte()
                    out[i * 4 + 2] = ((w ushr 16) and 0xFF).toByte()
                    out[i * 4 + 3] = ((w ushr 24) and 0xFF).toByte()
                }
                out
            }
        val now = System.currentTimeMillis()
        synchronized(decodedBodyLock) {
            while (pendingDecodedBodies.isNotEmpty() &&
                now - pendingDecodedBodies.first().producedAt > DECODED_BODY_TTL_MS
            ) {
                pendingDecodedBodies.removeFirst()
            }
            pendingDecodedBodies.addLast(DecodedBody(now, normalized, sources, prefix))
            while (pendingDecodedBodies.size > MAX_PENDING_DECODED_BODIES) {
                pendingDecodedBodies.removeFirst()
            }
        }
        if (Log.isLoggable(TAG, Log.VERBOSE)) {
            Log.v(TAG, "decoded jni body method=$methodId bytes=${normalized.size} src=$sources fp=${prefix?.size ?: 0}")
        }
        attachLatePlaintext(DecodedBody(now, normalized, sources, prefix))
    }

    /**
     * Hands a late-arriving plaintext to the response it belongs to, and re-dispatches it.
     *
     * The frame names the native method, never the request, so identity comes from the decoder's
     * input length — the response body's own size. Only a single unambiguous fit is used: when
     * two responses share that size the plaintext stays queued instead of overwriting one of
     * them, because a body left as ciphertext can still be retried while a wrong JSON cannot.
     */
    private fun attachLatePlaintext(plain: DecodedBody) {
        // 长度对上还不够:误读的 jbyteArray 也能凑巧同长,贴上去就是拿垃圾盖掉密文。
        if (!looksRecognizable(plain.bytes)) return
        val now = System.currentTimeMillis()
        val target = synchronized(awaitingLock) {
            while (awaitingPlaintext.isNotEmpty() && now - awaitingPlaintext.first().at > AWAITING_PLAINTEXT_TTL_MS) {
                awaitingPlaintext.removeFirst()
            }
            val fits = awaitingPlaintext.filter { plain.matches(it.stagedSize, it.stagedHead) }
            val chosen = fits.singleOrNull()
            if (chosen == null) {
                if (Log.isLoggable(TAG, Log.DEBUG)) {
                    Log.d(
                        TAG,
                        "late plaintext ${plain.bytes.size} src=${plain.srcSizes} fp=${plain.srcPrefix?.size ?: 0} joined " +
                            "${fits.size} of ${awaitingPlaintext.map { it.stagedSize }}"
                    )
                }
                return
            }
            awaitingPlaintext.remove(chosen)
            chosen
        }
        // 这份明文已经在 [pendingDecodedBodies] 里排着了,别让后面同长的响应再收到它一次。
        dropQueuedPlaintext(plain.bytes)

        val maxBytes = config.maxBodySizeBytes.coerceIn(0L, Int.MAX_VALUE.toLong()).toInt()
        val out = ByteArrayOutputStream()
        val toWrite = minOf(plain.bytes.size, maxBytes)
        if (toWrite > 0) out.write(plain.bytes, 0, toWrite)
        synchronized(responseBodies) { responseBodies[target.requestId] = out }

        Log.d(TAG, "late plaintext for ${target.requestId}: ${target.stagedSize} bytes")
        // 再走一遍正常响应:中间件还要在明文上再剥一层容器,listener 也按 requestId 覆盖上一条。
        // 带上 hint 既留证,也避免这次重派发再把自己登记回等待队列。
        val hinted = target.event.copy(
            headers = target.event.headers + HttpHeader(AUX_DECODE_HINT_HEADER, "jni-late:${plain.bytes.size}")
        )
        dispatchResponse(hinted)
    }

    /** 从待配对队列里摘掉一份已经用掉的明文(同一份字节可能被重复上报)。 */
    private fun dropQueuedPlaintext(plain: ByteArray) {
        synchronized(decodedBodyLock) {
            val hit = pendingDecodedBodies.firstOrNull { it.bytes.contentEquals(plain) } ?: return
            pendingDecodedBodies.remove(hit)
        }
    }

    /**
     * 这条响应还是密文:值得等明文。
     *
     * 不再要求响应自称 JSON——真机上就撞见过 `content-type` 与实际内容对不上的接口,
     * 而按 `mimeType` 兜底又漏掉了 h2 上只到 mimeType 的那些。判据只留"体不是 JSON",
     * 贴错的风险由 [attachLatePlaintext] 的精确长度配对兜住。
     */
    /**
     * 这条响应还是密文:值得等明文。
     *
     * 判据只能看响应体本身。中间件也会挂 `x-aau-decode-hint`,但它挂的 `bzp-aes:`/`bzp-raw:`
     * 恰恰是"解不开、需要 native 解"的标记——把这些当成"已经解过",就永远等不到明文,
     * 而这正是这条链路上最难发现的失效方式。只有我们自己补发时打的 `jni*` 才算已解。
     */
    private fun needsLatePlaintext(event: HttpResponseEvent): Boolean {
        val decodedByUs = event.headers.any {
            it.name.equals(AUX_DECODE_HINT_HEADER, ignoreCase = true) && it.value.startsWith("jni")
        }
        if (decodedByUs) {
            if (Log.isLoggable(TAG, Log.VERBOSE)) Log.v(TAG, "no wait for ${event.requestId}: already republished")
            return false
        }
        val body = getResponseBody(event.requestId)
        if (body == null || body.isEmpty()) {
            if (Log.isLoggable(TAG, Log.VERBOSE)) Log.v(TAG, "no wait for ${event.requestId}: body=${body?.size}")
            return false
        }
        if (isLikelyJsonPayload(body)) {
            if (Log.isLoggable(TAG, Log.VERBOSE)) Log.v(TAG, "no wait for ${event.requestId}: already plaintext")
            return false
        }
        return true
    }

    private fun rememberAwaiting(event: HttpResponseEvent) {
        val staged = getResponseBody(event.requestId) ?: return
        val size = staged.size
        val head = staged.copyOfRange(0, minOf(STAGED_HEAD_BYTES, staged.size))
        val now = System.currentTimeMillis()
        synchronized(awaitingLock) {
            awaitingPlaintext.removeAll { it.requestId == event.requestId }
            while (awaitingPlaintext.isNotEmpty() && now - awaitingPlaintext.first().at > AWAITING_PLAINTEXT_TTL_MS) {
                awaitingPlaintext.removeFirst()
            }
            awaitingPlaintext.addLast(AwaitingPlaintext(event.requestId, event, size, head, now))
            while (awaitingPlaintext.size > MAX_AWAITING_PLAINTEXT) {
                awaitingPlaintext.removeFirst()
            }
            if (Log.isLoggable(TAG, Log.VERBOSE)) {
                Log.v(TAG, "waiting plaintext for ${event.requestId}: $size bytes")
            }
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
     * Pops the staged plaintext that belongs to the response whose body is [cipherSize] bytes.
     *
     * The app decodes above TLS, and the frame it arrives in names the native method, not the
     * request, so the parser used to pair first-in-first-out. With a batch of h2 responses in
     * flight that glued A's plaintext onto B — the result looked decoded and was wrong, which is
     * worse than no plaintext at all.
     *
     * Identity now comes from the decoder's *input* length, which [DecodedBody.srcSizes] carries
     * and which is exactly the response body size. Note that the plaintext's own size is not a
     * substitute: when the app compresses before encrypting, the decoded body is larger than what
     * travelled on the wire (BOSS batch endpoints answer 20 KB of ciphertext with 100 KB+ JSON).
     * Older loaders cannot report the input size; those entries fall back to comparing sizes,
     * which still holds for the uncompressed family.
     *
     * When nothing fits, nothing is consumed: a body left as ciphertext can be retried, a body
     * holding the wrong JSON cannot.
     *
     * The shape filter [accept] still applies. The loader already refuses payloads it cannot
     * positively identify, but a mis-resolved `jbyteArray` can slip through as printable garbage;
     * such entries stay queued in case a later response fits them instead of being thrown away.
     */
    private fun takeDecodedBody(
        cipherSize: Int,
        stagedHead: ByteArray? = null,
        accept: (ByteArray) -> Boolean = { true }
    ): ByteArray? {
        val now = System.currentTimeMillis()
        synchronized(decodedBodyLock) {
            while (pendingDecodedBodies.isNotEmpty() &&
                now - pendingDecodedBodies.first().producedAt > DECODED_BODY_TTL_MS
            ) {
                pendingDecodedBodies.removeFirst()
            }
            val usable = pendingDecodedBodies.filter { accept(it.bytes) }
            if (usable.isEmpty()) return null

            val fitting = usable.filter { it.matches(cipherSize, stagedHead) }
            val first = fitting.firstOrNull()
            // 同一份明文被重复上报是常态(chunked 写入会重放),内容一致就照收;
            // 内容不同说明真的判不出来,宁可留着密文。
            val chosen = when {
                first == null -> null
                fitting.all { it.bytes.contentEquals(first.bytes) } -> first
                else -> null
            }
            if (chosen == null) {
                if (Log.isLoggable(TAG, Log.VERBOSE)) {
                    Log.v(TAG, "no decoded body for $cipherSize bytes: ${usable.map { it.bytes.size }}, keeping ciphertext")
                }
                return null
            }
            pendingDecodedBodies.remove(chosen)
            return chosen.bytes
        }
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
        // 明文通常比响应晚一点点到(解码发生在进程内、抓包是 250ms 一批),先登记等它。
        if (needsLatePlaintext(effective)) rememberAwaiting(effective)
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

        val head = staged.copyOfRange(0, minOf(STAGED_HEAD_BYTES, staged.size))
        val decoded = takeDecodedBody(staged.size, head, ::looksRecognizable) ?: return event
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
            headers = event.headers + HttpHeader(AUX_DECODE_HINT_HEADER, hint)
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
