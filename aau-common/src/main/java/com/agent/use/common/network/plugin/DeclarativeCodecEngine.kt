package com.agent.use.common.network.plugin

import com.agent.use.common.network.HttpHeader
import com.agent.use.common.network.HttpRequestEvent
import com.agent.use.common.network.HttpResponseEvent
import com.agent.use.common.network.getIgnoreCase
import com.agent.use.common.network.parser.HttpContentDecoder
import com.agent.use.common.network.parser.Lz4BlockDecoder
import java.nio.charset.StandardCharsets
import java.util.Base64

/**
 * 声明式解码解释器：按配置把响应体一层层剥到明文。
 *
 * 失败语义很重要——**任何一步解不开就放弃这条规则**，由调用方保留原始字节。
 * 宁可让模型看到密文，也不能把半截乱码当成明文贴进对话。
 */
object DeclarativeCodecEngine {

    const val MAX_DECODED_BYTES = 32 * 1024 * 1024

    /** 解出明文后挂在响应头上的说明，形如 `bzp-block>lz4-block:643->512`。 */
    const val DECODE_HINT_HEADER = "x-aau-decode-hint"

    data class Decoded(
        val bytes: ByteArray,
        val trace: String,
        val contentType: String?,
    )

    fun decode(
        body: ByteArray,
        headers: List<HttpHeader>,
        rules: List<ResponseCodecRule>,
        maxBytes: Int = MAX_DECODED_BYTES,
    ): Decoded? {
        if (body.isEmpty() || rules.isEmpty()) return null
        for (rule in rules) {
            if (!matches(rule, headers, body)) continue
            applyRule(rule, body, maxBytes)?.let { return it }
        }
        return null
    }

    fun matches(rule: ResponseCodecRule, headers: List<HttpHeader>, body: ByteArray): Boolean {
        for (condition in rule.whenConditions) {
            if (!matches(condition, headers, body)) return false
        }
        return true
    }

    private fun matches(condition: CodecCondition, headers: List<HttpHeader>, body: ByteArray): Boolean {
        condition.magic?.let { magic ->
            val bytes = magic.toByteArray(StandardCharsets.UTF_8)
            if (!startsWith(body, bytes, 0)) return false
        }
        val header = condition.header ?: return true
        val value = headers.getIgnoreCase(header)
        if (condition.absent) return value == null
        if (value == null) return false
        condition.equals?.let { if (!value.equals(it, ignoreCase = true)) return false }
        condition.contains?.let { if (!value.contains(it, ignoreCase = true)) return false }
        return true
    }

    private fun applyRule(rule: ResponseCodecRule, body: ByteArray, maxBytes: Int): Decoded? {
        // 输入已经是明文就不再套管道。注意这个判断只放在**入口**：
        // 压缩流的首字节碰巧是 `{`（0x7B）的概率并不为零，在步骤之间做同样的判断
        // 会把一段压缩数据误认成明文，然后当成"解好了"交给调用方——那比解不开更糟。
        if (rule.stopWhenJson && looksLikeJson(body)) return null

        var current = body
        var expected = 0
        var contentType: String? = null
        val trace = ArrayList<String>()

        for (step in rule.steps) {
            val outcome = applyStep(step, current, expected, maxBytes) ?: return null
            current = outcome.bytes
            expected = outcome.expectedSize
            step.contentType?.let { contentType = it }
            trace += step.traceName
        }

        if (trace.isEmpty() || current.contentEquals(body)) return null
        return Decoded(current, trace.joinToString(">"), contentType)
    }

    private fun applyStep(step: CodecStep, input: ByteArray, expectedSize: Int, maxBytes: Int): StepOutcome? =
        when (step.op) {
            "container" -> container(step, input, maxBytes)
            "decompress" -> decompress(step.algo, input, expectedSize, maxBytes)
            "base64" -> decodeBase64(input, maxBytes)
            "stripprefix" -> {
                val drop = step.prefixBytes
                if (drop <= 0 || drop >= input.size) null else StepOutcome(input.copyOfRange(drop, input.size), 0)
            }
            else -> null
        }

    private fun container(step: CodecStep, input: ByteArray, maxBytes: Int): StepOutcome? {
        val magic = step.magicBytes()
        if (magic != null && !startsWith(input, magic, step.magicOffset)) return null
        val start = when {
            step.headerSize > 0 -> step.headerSize
            magic != null -> step.magicOffset + magic.size
            else -> 0
        }
        if (start >= input.size) return null
        val available = input.size - start
        var length = available
        step.payloadLen?.read(input)?.let { declared ->
            // 声明长度只用来裁掉"拼接在尾部"的多余字节；明显越界时按实际长度处理
            if (declared in 1..available.toLong()) length = declared.toInt()
        }
        if (length <= 0) return null
        val expected = step.rawLen?.read(input)
            ?.takeIf { it in 1..maxBytes.toLong() }
            ?.toInt() ?: 0
        return StepOutcome(input.copyOfRange(start, start + length), expected)
    }

    private fun decompress(algo: String?, input: ByteArray, expectedSize: Int, maxBytes: Int): StepOutcome? {
        val out = when (algo?.lowercase()) {
            "gzip" -> runCatching { HttpContentDecoder.gunzip(input, maxBytes) }.getOrNull()
            "zlib" -> runCatching { HttpContentDecoder.inflate(input, maxBytes) }.getOrNull()
            "lz4-block" -> Lz4BlockDecoder.decode(input, 0, input.size, expectedSize, maxBytes)
            "zstd" -> HttpContentDecoder.decompressZstd(input, maxDecompressedBytes = maxBytes)
            "br", "brotli" -> HttpContentDecoder.decompressBrotli(input, maxBytes)
            else -> null
        }
        if (out == null || out.isEmpty() || out.contentEquals(input)) return null
        return StepOutcome(out, 0)
    }

    private fun decodeBase64(input: ByteArray, maxBytes: Int): StepOutcome? {
        val text = String(input, StandardCharsets.ISO_8859_1)
            .filterNot { it.isWhitespace() }
        if (text.isEmpty()) return null
        val decoder = runCatching { Base64.getMimeDecoder().decode(text) }
            .recoverCatching { Base64.getUrlDecoder().decode(text) }
            .getOrNull() ?: return null
        if (decoder.isEmpty() || decoder.size > maxBytes) return null
        return StepOutcome(decoder, 0)
    }

    private fun CodecStep.magicBytes(): ByteArray? {
        magicHex?.let { hex ->
            val clean = hex.trim().removePrefix("0x").filterNot { it == ' ' || it == ':' }
            if (clean.length % 2 != 0) return null
            val out = ByteArray(clean.length / 2)
            for (i in out.indices) {
                out[i] = clean.substring(i * 2, i * 2 + 2).toIntOrNull(16)?.toByte() ?: return null
            }
            return out
        }
        return magic?.toByteArray(StandardCharsets.UTF_8)
    }

    private fun startsWith(bytes: ByteArray, prefix: ByteArray, offset: Int): Boolean {
        if (offset < 0 || bytes.size - offset < prefix.size) return false
        for (i in prefix.indices) {
            if (bytes[offset + i] != prefix[i]) return false
        }
        return true
    }

    fun looksLikeJson(bytes: ByteArray): Boolean {
        for (b in bytes) {
            val c = b.toInt() and 0xFF
            if (c == 0x20 || c == 0x09 || c == 0x0A || c == 0x0D) continue
            return c == '{'.code || c == '['.code
        }
        return false
    }

    private data class StepOutcome(val bytes: ByteArray, val expectedSize: Int)
}

/**
 * 由配置驱动的流量中间件：补 `unknown-host`，再按 [DeclarativeConfig.responseCodecs] 解响应体。
 *
 * 一个 App 换信封时，注册一个 `DeclarativeTrafficMiddleware` 即可，不必新增 Kotlin 类。
 */
class DeclarativeTrafficMiddleware(
    override val id: String,
    private val config: DeclarativeConfig,
) : NetworkTrafficMiddleware {

    override fun onRequest(targetPackage: String, event: HttpRequestEvent): HttpRequestEvent {
        val fix = config.hostFix ?: return event
        if (!event.url.contains(UNKNOWN_HOST)) return event
        val host = resolveHost(event.headers, fix) ?: return event
        return event.copy(url = event.url.replace(UNKNOWN_HOST, "://$host"))
    }

    override fun onResponse(
        targetPackage: String,
        event: HttpResponseEvent,
        body: ByteArray?,
    ): Pair<HttpResponseEvent, ByteArray?> {
        var nextEvent = event
        var nextBody = body

        val fix = config.hostFix
        if (fix != null && nextEvent.url.contains(UNKNOWN_HOST)) {
            val host = resolveHost(nextEvent.headers, fix)
            if (host != null) {
                nextEvent = nextEvent.copy(url = nextEvent.url.replace(UNKNOWN_HOST, "://$host"))
            }
        }

        if (nextBody == null || nextBody.isEmpty()) return nextEvent to nextBody
        val decoded = DeclarativeCodecEngine.decode(nextBody, nextEvent.headers, config.responseCodecs)
            ?: return nextEvent to nextBody

        val originalSize = nextBody.size
        nextBody = decoded.bytes

        val wantedType = decoded.contentType
            ?: if (DeclarativeCodecEngine.looksLikeJson(nextBody)) "application/json; charset=utf-8" else null
        if (wantedType != null &&
            (nextEvent.mimeType.isNullOrBlank() ||
                nextEvent.mimeType.equals("application/octet-stream", ignoreCase = true))
        ) {
            nextEvent = nextEvent.copy(mimeType = wantedType)
        }
        if (nextEvent.headers.none { it.name.equals(DeclarativeCodecEngine.DECODE_HINT_HEADER, ignoreCase = true) }) {
            val hint = "${decoded.trace}:$originalSize->${nextBody.size}"
            nextEvent = nextEvent.copy(
                headers = nextEvent.headers + HttpHeader(DeclarativeCodecEngine.DECODE_HINT_HEADER, hint)
            )
        }
        return nextEvent to nextBody
    }

    private fun resolveHost(headers: List<HttpHeader>, fix: HostFixRule): String? =
        fix.headerPriority.asSequence()
            .mapNotNull { headers.getIgnoreCase(it)?.trim()?.takeIf(String::isNotEmpty) }
            .firstOrNull()
            ?: fix.defaultHost?.takeIf { it.isNotBlank() }

    private companion object {
        const val UNKNOWN_HOST = "://unknown-host"
    }
}
