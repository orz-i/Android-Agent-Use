package com.agent.use.common.network.parser

import com.agent.use.common.network.HttpHeader
import com.agent.use.common.network.getIgnoreCase
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets
import java.util.zip.GZIPInputStream
import java.util.zip.Inflater
import java.util.zip.InflaterInputStream

/**
 * Shared HTTP/1.x transfer-decoding (`chunked`) and content-decoding (`gzip`, `deflate`) helpers.
 */
object HttpContentDecoder {

    data class ChunkedResult(
        val decoded: ByteArray,
        val isComplete: Boolean,
        val consumedBytes: Int
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
     * Decompresses [body] according to `Content-Encoding` (`gzip` / `x-gzip` / `deflate`) when present.
     * Falls back to original [body] if uncompressed or if decompression fails on partial/invalid data.
     */
    fun decompressIfNeeded(body: ByteArray, headers: List<HttpHeader>): ByteArray {
        if (body.isEmpty()) return body
        val encoding = headers.getIgnoreCase("Content-Encoding")?.lowercase()?.trim() ?: return body
        return when {
            encoding.contains("gzip") -> gunzip(body)
            encoding.contains("deflate") -> inflate(body)
            else -> body
        }
    }

    fun gunzip(compressed: ByteArray): ByteArray {
        return try {
            GZIPInputStream(ByteArrayInputStream(compressed)).use { gis ->
                val out = ByteArrayOutputStream()
                val buf = ByteArray(4096)
                while (true) {
                    val read = gis.read(buf)
                    if (read <= 0) break
                    out.write(buf, 0, read)
                }
                out.toByteArray()
            }
        } catch (_: Exception) {
            compressed
        }
    }

    fun inflate(compressed: ByteArray): ByteArray {
        return try {
            InflaterInputStream(ByteArrayInputStream(compressed)).use { iis ->
                val out = ByteArrayOutputStream()
                val buf = ByteArray(4096)
                while (true) {
                    val read = iis.read(buf)
                    if (read <= 0) break
                    out.write(buf, 0, read)
                }
                out.toByteArray()
            }
        } catch (_: Exception) {
            // Raw deflate without zlib header
            try {
                val inflater = Inflater(true)
                InflaterInputStream(ByteArrayInputStream(compressed), inflater).use { iis ->
                    val out = ByteArrayOutputStream()
                    val buf = ByteArray(4096)
                    while (true) {
                        val read = iis.read(buf)
                        if (read <= 0) break
                        out.write(buf, 0, read)
                    }
                    out.toByteArray()
                }
            } catch (_: Exception) {
                compressed
            }
        }
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
