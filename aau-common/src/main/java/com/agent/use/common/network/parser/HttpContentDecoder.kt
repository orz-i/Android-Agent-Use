package com.agent.use.common.network.parser

import com.agent.use.common.network.HttpHeader
import com.agent.use.common.network.getIgnoreCase
import com.github.luben.zstd.ZstdInputStream
import org.brotli.dec.BrotliInputStream
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.nio.charset.Charset
import java.nio.charset.StandardCharsets
import java.util.zip.GZIPInputStream
import java.util.zip.Inflater
import java.util.zip.InflaterInputStream

/**
 * Shared HTTP transfer-decoding (`chunked`), content-decoding (`gzip`, `deflate`, `br`, `zstd`),
 * and charset resolution helpers.
 */
object HttpContentDecoder {

    private const val DEFAULT_MAX_DECOMPRESSED_BYTES = 16 * 1024 * 1024

    data class ChunkedResult(
        val decoded: ByteArray,
        val isComplete: Boolean,
        val consumedBytes: Int
    )

    data class ZstdFrameInfo(
        val isZstdMagic: Boolean,
        val hasDictionaryId: Boolean,
        val dictId: Long?
    )

    /**
     * Parses HTTP/1.1 `Transfer-Encoding: chunked` wire bytes starting at [offset].
     *
     * @return decoded payload, whether the terminating `0\r\n...\r\n` trailer finished,
     *         and total wire bytes consumed from [offset].
     */
    fun decodeChunked(
        bytes: ByteArray,
        offset: Int = 0,
        length: Int = bytes.size - offset,
        maxBodyBytes: Long = 10 * 1024 * 1024L
    ): ChunkedResult {
        if (offset < 0 || length <= 0 || offset + length > bytes.size) {
            return ChunkedResult(ByteArray(0), isComplete = false, consumedBytes = 0)
        }
        val end = offset + length
        val out = ByteArrayOutputStream()
        var pos = offset

        while (pos < end) {
            val lineEnd = indexOfCrlfOrLf(bytes, pos, end) ?: break
            val delimLen = if (bytes[lineEnd] == '\r'.code.toByte()) 2 else 1
            val rawSizeLine = String(bytes, pos, lineEnd - pos, StandardCharsets.ISO_8859_1).trim()
            val hexToken = rawSizeLine.substringBefore(';').trim()
            val chunkSize = hexToken.toIntOrNull(16) ?: break

            val chunkDataStart = lineEnd + delimLen
            if (chunkSize == 0) {
                // Consume trailer headers until empty line (\r\n or \n)
                var trailerPos = chunkDataStart
                while (trailerPos < end) {
                    val trEnd = indexOfCrlfOrLf(bytes, trailerPos, end)
                    if (trEnd == null) {
                        return ChunkedResult(out.toByteArray(), isComplete = false, consumedBytes = pos - offset)
                    }
                    val trDelimLen = if (bytes[trEnd] == '\r'.code.toByte()) 2 else 1
                    val nextPos = trEnd + trDelimLen
                    if (trEnd == trailerPos) {
                        return ChunkedResult(out.toByteArray(), isComplete = true, consumedBytes = nextPos - offset)
                    }
                    trailerPos = nextPos
                }
                return ChunkedResult(out.toByteArray(), isComplete = false, consumedBytes = pos - offset)
            }

            val chunkDataEnd = chunkDataStart + chunkSize
            if (chunkDataEnd >= end) {
                // Need at least 1 byte for trailing \n (or \r\n)
                break
            }
            val trailingLen = when {
                chunkDataEnd + 1 < end &&
                    bytes[chunkDataEnd] == '\r'.code.toByte() &&
                    bytes[chunkDataEnd + 1] == '\n'.code.toByte() -> 2
                bytes[chunkDataEnd] == '\n'.code.toByte() -> 1
                else -> break
            }

            if (out.size() < maxBodyBytes) {
                val allowed = (maxBodyBytes - out.size()).toInt().coerceAtLeast(0)
                val toWrite = minOf(chunkSize, allowed)
                if (toWrite > 0) {
                    out.write(bytes, chunkDataStart, toWrite)
                }
            }
            pos = chunkDataEnd + trailingLen
        }

        return ChunkedResult(out.toByteArray(), isComplete = false, consumedBytes = pos - offset)
    }

    /**
     * Decompresses [body] according to `Content-Encoding` (`gzip`, `x-gzip`, `deflate`, `br`, `zstd`),
     * supporting comma-separated multi-stage encodings applied in reverse HTTP order.
     * Falls back to original [body] if uncompressed or if decompression fails on partial/dictionary data.
     */
    @JvmOverloads
    fun decompressIfNeeded(
        body: ByteArray,
        headers: List<HttpHeader>,
        maxDecompressedBytes: Int = DEFAULT_MAX_DECOMPRESSED_BYTES
    ): ByteArray {
        if (body.isEmpty()) return body
        val encoding = headers.getIgnoreCase("Content-Encoding")?.trim() ?: return body
        return decompressByEncoding(body, encoding, maxDecompressedBytes)
    }

    /**
     * Decompresses [body] according to a comma-separated [encodingHeader] (e.g. `br`, `zstd`, `gzip, deflate`).
     */
    @JvmOverloads
    fun decompressByEncoding(
        body: ByteArray,
        encodingHeader: String?,
        maxDecompressedBytes: Int = DEFAULT_MAX_DECOMPRESSED_BYTES
    ): ByteArray {
        if (body.isEmpty() || encodingHeader.isNullOrBlank()) return body
        val tokens = encodingHeader.split(',')
            .map { it.trim().lowercase() }
            .filter { it.isNotEmpty() && it != "identity" }
        if (tokens.isEmpty()) return body

        var current = body
        for (enc in tokens.asReversed()) {
            current = when {
                enc == "gzip" || enc == "x-gzip" -> gunzip(current, maxDecompressedBytes)
                enc == "deflate" -> inflate(current, maxDecompressedBytes)
                enc == "br" || enc == "brotli" -> unbrotli(current, maxDecompressedBytes)
                enc == "zstd" || enc == "x-zstd" -> decompressZstd(current, maxDecompressedBytes = maxDecompressedBytes) ?: current
                else -> current
            }
        }
        return current
    }

    /**
     * Attempts decompression based on known wire magic headers (`gzip`, `zstd`, `zlib`) first,
     * falling back to [encodingHint] (e.g. `br`, `deflate`) when magic headers are absent.
     */
    @JvmOverloads
    fun decompressByMagicOrEncoding(
        bytes: ByteArray,
        encodingHint: String? = null,
        maxDecompressedBytes: Int = DEFAULT_MAX_DECOMPRESSED_BYTES
    ): ByteArray {
        if (bytes.isEmpty()) return bytes
        if (hasGzipMagic(bytes)) {
            val out = gunzip(bytes, maxDecompressedBytes)
            if (!out.contentEquals(bytes)) return out
        }
        if (hasZstdMagic(bytes)) {
            decompressZstd(bytes, maxDecompressedBytes = maxDecompressedBytes)?.let { return it }
        }
        if (hasZlibMagic(bytes)) {
            val out = inflate(bytes, maxDecompressedBytes)
            if (!out.contentEquals(bytes)) return out
        }
        if (!encodingHint.isNullOrBlank()) {
            return decompressByEncoding(bytes, encodingHint, maxDecompressedBytes)
        }
        return bytes
    }

    fun hasGzipMagic(bytes: ByteArray): Boolean =
        bytes.size >= 2 && (bytes[0].toInt() and 0xFF) == 0x1F && (bytes[1].toInt() and 0xFF) == 0x8B

    fun hasZstdMagic(bytes: ByteArray): Boolean =
        bytes.size >= 4 &&
            (bytes[0].toInt() and 0xFF) == 0x28 &&
            (bytes[1].toInt() and 0xFF) == 0xB5 &&
            (bytes[2].toInt() and 0xFF) == 0x2F &&
            (bytes[3].toInt() and 0xFF) == 0xFD

    fun hasZlibMagic(bytes: ByteArray): Boolean {
        if (bytes.size < 2) return false
        val cmf = bytes[0].toInt() and 0xFF
        val flg = bytes[1].toInt() and 0xFF
        return (cmf and 0x0F) == 8 && ((cmf shl 8) or flg) % 31 == 0
    }

    /**
     * Inspects RFC 8878 Zstandard frame header for dictionary ID presence (`Dictionary_ID_flag`).
     */
    fun inspectZstdFrame(bytes: ByteArray): ZstdFrameInfo {
        if (!hasZstdMagic(bytes) || bytes.size < 5) {
            return ZstdFrameInfo(isZstdMagic = false, hasDictionaryId = false, dictId = null)
        }
        val descriptor = bytes[4].toInt() and 0xFF
        val singleSegment = ((descriptor ushr 5) and 0x01) == 1
        val windowDescLen = if (singleSegment) 0 else 1
        val dictFlag = descriptor and 0x03
        val dictLen = when (dictFlag) {
            0 -> 0
            1 -> 1
            2 -> 2
            else -> 4
        }
        if (dictLen == 0) {
            return ZstdFrameInfo(isZstdMagic = true, hasDictionaryId = false, dictId = null)
        }
        val dictOffset = 5 + windowDescLen
        if (bytes.size < dictOffset + dictLen) {
            return ZstdFrameInfo(isZstdMagic = true, hasDictionaryId = true, dictId = null)
        }
        var dictId = 0L
        for (i in 0 until dictLen) {
            dictId = dictId or ((bytes[dictOffset + i].toLong() and 0xFFL) shl (i * 8))
        }
        return ZstdFrameInfo(isZstdMagic = true, hasDictionaryId = true, dictId = dictId)
    }

    /**
     * Resolves JVM [Charset] from a `Content-Type` header (`charset=gbk`, `charset=utf-8`, etc.),
     * mapping `gb2312`/`gbk` to `GB18030` when supported and falling back to UTF-8.
     */
    fun resolveCharset(contentType: String?): Charset {
        if (contentType.isNullOrBlank()) return StandardCharsets.UTF_8
        val parts = contentType.split(';')
        for (i in 1 until parts.size) {
            val attr = parts[i].trim()
            if (attr.startsWith("charset=", ignoreCase = true)) {
                val raw = attr.substringAfter('=')
                    .trim()
                    .trim('"', '\'')
                    .uppercase()
                if (raw.isEmpty()) continue
                val normalized = when (raw) {
                    "GB2312", "GBK" -> if (Charset.isSupported("GB18030")) "GB18030" else raw
                    else -> raw
                }
                if (Charset.isSupported(normalized)) {
                    return runCatching { Charset.forName(normalized) }.getOrDefault(StandardCharsets.UTF_8)
                }
            }
        }
        return StandardCharsets.UTF_8
    }

    @JvmOverloads
    fun gunzip(compressed: ByteArray, maxDecompressedBytes: Int = DEFAULT_MAX_DECOMPRESSED_BYTES): ByteArray {
        return try {
            GZIPInputStream(ByteArrayInputStream(compressed)).use { gis ->
                readBounded(gis, maxDecompressedBytes)
            }
        } catch (_: Throwable) {
            compressed
        }
    }

    @JvmOverloads
    fun inflate(compressed: ByteArray, maxDecompressedBytes: Int = DEFAULT_MAX_DECOMPRESSED_BYTES): ByteArray {
        return try {
            InflaterInputStream(ByteArrayInputStream(compressed)).use { iis ->
                readBounded(iis, maxDecompressedBytes)
            }
        } catch (_: Throwable) {
            // Raw deflate without zlib header
            try {
                val inflater = Inflater(true)
                InflaterInputStream(ByteArrayInputStream(compressed), inflater).use { iis ->
                    try {
                        readBounded(iis, maxDecompressedBytes)
                    } finally {
                        inflater.end()
                    }
                }
            } catch (_: Throwable) {
                compressed
            }
        }
    }

    @JvmOverloads
    fun decompressBrotli(compressed: ByteArray, maxDecompressedBytes: Int = DEFAULT_MAX_DECOMPRESSED_BYTES): ByteArray? {
        if (compressed.isEmpty()) return compressed
        return try {
            BrotliInputStream(ByteArrayInputStream(compressed)).use { bis ->
                readBounded(bis, maxDecompressedBytes)
            }
        } catch (_: Throwable) {
            null
        }
    }

    @JvmOverloads
    fun unbrotli(compressed: ByteArray, maxDecompressedBytes: Int = DEFAULT_MAX_DECOMPRESSED_BYTES): ByteArray =
        decompressBrotli(compressed, maxDecompressedBytes) ?: compressed

    @JvmOverloads
    fun decompressZstd(
        compressed: ByteArray,
        dict: ByteArray? = null,
        maxDecompressedBytes: Int = DEFAULT_MAX_DECOMPRESSED_BYTES
    ): ByteArray? {
        if (compressed.isEmpty()) return compressed
        return try {
            ZstdInputStream(ByteArrayInputStream(compressed)).use { zis ->
                if (dict != null && dict.isNotEmpty()) {
                    zis.setDict(dict)
                }
                readBounded(zis, maxDecompressedBytes)
            }
        } catch (_: Throwable) {
            null
        }
    }

    @JvmOverloads
    fun unzstd(
        compressed: ByteArray,
        dict: ByteArray? = null,
        maxDecompressedBytes: Int = DEFAULT_MAX_DECOMPRESSED_BYTES
    ): ByteArray = decompressZstd(compressed, dict, maxDecompressedBytes) ?: compressed

    private fun readBounded(stream: InputStream, maxBytes: Int): ByteArray {
        val out = ByteArrayOutputStream()
        val buf = ByteArray(4096)
        while (out.size() < maxBytes) {
            val remaining = maxBytes - out.size()
            val toRead = minOf(buf.size, remaining)
            val read = stream.read(buf, 0, toRead)
            if (read <= 0) break
            out.write(buf, 0, read)
        }
        return out.toByteArray()
    }

    private fun indexOfCrlfOrLf(bytes: ByteArray, start: Int, end: Int): Int? {
        for (i in start until end) {
            if (bytes[i] == '\r'.code.toByte() && i + 1 < end && bytes[i + 1] == '\n'.code.toByte()) {
                return i
            }
            if (bytes[i] == '\n'.code.toByte()) {
                return i
            }
        }
        return null
    }
}

internal fun isUsableHost(host: String?): Boolean {
    if (host.isNullOrBlank()) return false
    val trimmed = host.trim()
    if (trimmed.equals("unknown-host", ignoreCase = true) ||
        trimmed.equals("localhost", ignoreCase = true) ||
        trimmed.equals("null", ignoreCase = true) ||
        trimmed == "*"
    ) {
        return false
    }
    return trimmed.none { it.isWhitespace() || it.isISOControl() }
}

internal fun extractHost(urlOrHost: String?): String? {
    if (urlOrHost.isNullOrBlank()) return null
    val trimmed = urlOrHost.trim()
    val extracted = try {
        if (trimmed.startsWith("http://", ignoreCase = true) || trimmed.startsWith("https://", ignoreCase = true)) {
            val uri = java.net.URI(trimmed)
            uri.host?.takeIf { it.isNotEmpty() }
        } else {
            val cleaned = trimmed.substringBefore('/').substringBefore(':')
            cleaned.takeIf { it.isNotEmpty() }
        }
    } catch (_: Exception) {
        val noScheme = trimmed.substringAfter("://", "")
        if (noScheme.isNotEmpty()) {
            noScheme.substringBefore('/').substringBefore(':').takeIf { it.isNotEmpty() }
        } else {
            trimmed.substringBefore('/').substringBefore(':').takeIf { it.isNotEmpty() }
        }
    }
    return extracted?.takeIf { isUsableHost(it) }
}

internal fun extractHostFromHeaders(headers: List<HttpHeader>): String? {
    val directHeaderNames = listOf(
        ":authority",
        "host",
        "x-forwarded-host",
        "origin",
        "referer",
        "location",
        "content-location",
        "access-control-allow-origin"
    )
    for (headerName in directHeaderNames) {
        for (h in headers) {
            if (h.name.equals(headerName, ignoreCase = true)) {
                val candidate = extractHost(h.value)
                if (candidate != null) return candidate
            }
        }
    }
    for (h in headers) {
        if (h.name.equals("set-cookie", ignoreCase = true)) {
            val attrs = h.value.split(';')
            for (attr in attrs) {
                val trimmed = attr.trim()
                if (trimmed.startsWith("domain=", ignoreCase = true)) {
                    val rawDomain = trimmed.substringAfter('=')
                        .trim()
                        .trim('"', '\'')
                        .trimStart('.')
                    val candidate = extractHost(rawDomain)
                    if (candidate != null) return candidate
                }
            }
        }
    }
    return null
}
