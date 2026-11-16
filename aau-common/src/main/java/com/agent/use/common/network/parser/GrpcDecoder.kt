package com.agent.use.common.network.parser

import com.agent.use.common.network.HttpHeader
import java.io.ByteArrayOutputStream
import java.net.URLDecoder
import java.nio.ByteBuffer
import java.nio.charset.Charset
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.util.Base64

/**
 * Decoder for standard gRPC (`application/grpc`, `application/grpc+proto`, `application/grpc+json`)
 * and gRPC-Web (`application/grpc-web*`, `application/grpc-web-text*`) length-prefixed frames.
 */
object GrpcDecoder {

    private const val FRAME_HEADER_SIZE = 5
    private const val FLAG_COMPRESSED = 0x01
    private const val FLAG_TRAILERS = 0x80
    private const val MAX_FRAME_BYTES = 16 * 1024 * 1024

    data class DecodedGrpcPayload(
        val protocol: String,
        val contentType: String?,
        val grpcStatus: String?,
        val grpcMessage: String?,
        val grpcEncoding: String?,
        val frameCount: Int,
        val messageJsonFragments: List<String>,
        val trailingHeaders: Map<String, String>
    )

    /**
     * Returns true when [contentType] identifies gRPC or gRPC-Web traffic.
     */
    fun isGrpcContentType(contentType: String?): Boolean {
        if (contentType.isNullOrBlank()) return false
        val mediaType = contentType.substringBefore(';').trim().lowercase()
        return mediaType == "application/grpc" ||
            mediaType.startsWith("application/grpc+") ||
            mediaType.startsWith("application/grpc-web")
    }

    /**
     * Returns true when [contentType] identifies a raw Protobuf payload.
     */
    fun isProtobufContentType(contentType: String?): Boolean {
        if (contentType.isNullOrBlank()) return false
        val mediaType = contentType.substringBefore(';').trim().lowercase()
        return mediaType == "application/x-protobuf" ||
            mediaType == "application/protobuf" ||
            mediaType == "application/vnd.google.protobuf" ||
            mediaType == "application/x-tt-pb" ||
            mediaType.endsWith("+proto") ||
            mediaType.endsWith("+protobuf")
    }

    /**
     * Returns true when [contentType] identifies an Apache Thrift payload.
     */
    fun isThriftContentType(contentType: String?): Boolean {
        if (contentType.isNullOrBlank()) return false
        val mediaType = contentType.substringBefore(';').trim().lowercase()
        return mediaType == "application/x-thrift" ||
            mediaType == "application/thrift" ||
            mediaType.startsWith("application/vnd.apache.thrift") ||
            mediaType.endsWith("+thrift")
    }

    /**
     * Formats captured outbound request body bytes for [HttpRequestEvent.postData],
     * decoding gRPC, Protobuf, Thrift, and charset-aware text without emitting binary mojibake.
     */
    fun formatRequestPostData(body: ByteArray, headers: List<HttpHeader>): String? {
        if (body.isEmpty()) return null
        val contentType = findHeader(headers, "content-type")
        val contentEncoding = findHeader(headers, "content-encoding")
        if (isGrpcContentType(contentType)) {
            return decodeToJson(body, contentType, headers)
        }
        return formatNonGrpcBytes(
            body = body,
            contentType = contentType,
            contentEncoding = contentEncoding
        )
    }

    /**
     * Formats captured inbound response body bytes as readable text for callers:
     * decodes gRPC / gRPC-Web frames, charset-aware text (`UTF-8` / `GBK` / `GB18030`),
     * compressed leftovers (`gzip`, `deflate`, `br`, `zstd`), wire Protobuf/Thrift payloads,
     * and emits structured binary diagnostics instead of mojibake when still binary/encrypted.
     */
    @JvmOverloads
    fun formatResponseBodyAsString(
        body: ByteArray?,
        contentType: String?,
        grpcEncoding: String? = null,
        grpcStatus: String? = null,
        grpcMessage: String? = null,
        contentEncoding: String? = null
    ): String? {
        if (isGrpcContentType(contentType)) {
            if (body == null && grpcStatus == null && grpcMessage == null) return null
            return decodeToJson(
                body = body ?: ByteArray(0),
                contentType = contentType,
                grpcEncodingOverride = grpcEncoding,
                grpcStatusOverride = grpcStatus,
                grpcMessageOverride = grpcMessage
            )
        }
        if (body == null) return null
        if (body.isEmpty()) return ""
        return formatNonGrpcBytes(
            body = body,
            contentType = contentType,
            contentEncoding = contentEncoding
        )
    }

    private fun formatNonGrpcBytes(
        body: ByteArray,
        contentType: String?,
        contentEncoding: String?
    ): String {
        val candidate = if (needsDecompressionPass(body, contentType, contentEncoding)) {
            HttpContentDecoder.decompressByMagicOrEncoding(body, contentEncoding)
        } else {
            body
        }

        if (isProtobufContentType(contentType)) {
            ProtobufWireDecoder.decodeToJson(candidate)?.let { return it }
            ProtobufWireDecoder.decodeToJson(body)?.let { return it }
        }
        if (isThriftContentType(contentType)) {
            ThriftWireDecoder.decodeToJson(candidate)?.let { return it }
            ThriftWireDecoder.decodeToJson(body)?.let { return it }
        }

        val charset = HttpContentDecoder.resolveCharset(contentType)
        decodeReadableText(candidate, charset)?.let { return it }

        // If header claimed br/deflate/zstd but initial sniff missed or payload was mislabeled as binary
        val secondPass = if (candidate.contentEquals(body) && !contentEncoding.isNullOrBlank()) {
            HttpContentDecoder.decompressByMagicOrEncoding(body, contentEncoding)
        } else {
            candidate
        }
        if (!secondPass.contentEquals(candidate)) {
            decodeReadableText(secondPass, charset)?.let { return it }
        }

        ProtobufWireDecoder.decodeToJsonIfLikely(secondPass)?.let { return it }
        ThriftWireDecoder.decodeToJson(secondPass, requireStrongHeuristic = true)?.let { return it }

        return formatBinaryDiagnosticJson(
            rawBody = body,
            decodedCandidate = secondPass,
            contentType = contentType,
            contentEncoding = contentEncoding
        )
    }

    private fun needsDecompressionPass(
        body: ByteArray,
        contentType: String?,
        contentEncoding: String?
    ): Boolean {
        if (HttpContentDecoder.hasGzipMagic(body) || HttpContentDecoder.hasZstdMagic(body)) {
            return true
        }
        if (!contentEncoding.isNullOrBlank()) {
            val charset = HttpContentDecoder.resolveCharset(contentType)
            if (decodeReadableText(body, charset) == null) {
                return true
            }
        }
        return false
    }

    /**
     * Decodes a captured gRPC request or response body along with headers/trailers into a structured payload.
     */
    fun decode(
        body: ByteArray,
        contentType: String?,
        headers: List<HttpHeader> = emptyList(),
        grpcEncodingOverride: String? = null,
        grpcStatusOverride: String? = null,
        grpcMessageOverride: String? = null
    ): DecodedGrpcPayload {
        val mediaType = contentType?.substringBefore(';')?.trim()?.lowercase()
        val isGrpcWeb = mediaType?.startsWith("application/grpc-web") == true
        val isGrpcWebText = mediaType?.startsWith("application/grpc-web-text") == true
        val isJsonPayload = mediaType?.endsWith("+json") == true

        var encoding = grpcEncodingOverride ?: findHeader(headers, "grpc-encoding")
        var status = grpcStatusOverride ?: findHeader(headers, "grpc-status")
        var message = grpcMessageOverride ?: findHeader(headers, "grpc-message")?.let(::percentDecodeSafe)

        val wireBytes = if (isGrpcWebText && body.isNotEmpty()) {
            decodeGrpcWebText(body)
        } else {
            body
        }

        val messageFragments = ArrayList<String>()
        val trailingHeaders = LinkedHashMap<String, String>()
        var frameCount = 0
        var offset = 0

        while (offset + FRAME_HEADER_SIZE <= wireBytes.size) {
            val flags = wireBytes[offset].toInt() and 0xFF
            val len = ((wireBytes[offset + 1].toInt() and 0xFF) shl 24) or
                ((wireBytes[offset + 2].toInt() and 0xFF) shl 16) or
                ((wireBytes[offset + 3].toInt() and 0xFF) shl 8) or
                (wireBytes[offset + 4].toInt() and 0xFF)
            if (len < 0 || len > MAX_FRAME_BYTES || offset + FRAME_HEADER_SIZE + len > wireBytes.size) {
                break
            }

            val payload = wireBytes.copyOfRange(offset + FRAME_HEADER_SIZE, offset + FRAME_HEADER_SIZE + len)
            offset += FRAME_HEADER_SIZE + len
            frameCount++

            if ((flags and FLAG_TRAILERS) != 0) {
                parseInlineTrailers(payload, trailingHeaders)
                trailingHeaders["grpc-status"]?.let { if (status == null) status = it }
                trailingHeaders["grpc-message"]?.let { if (message == null) message = percentDecodeSafe(it) }
                continue
            }

            val decompressed = if ((flags and FLAG_COMPRESSED) != 0) {
                decompressGrpcFrame(payload, encoding)
            } else {
                payload
            }
            messageFragments.add(decodeMessageFragment(decompressed, isJsonPayload))
        }

        // Preserve leftover/non-framed bytes if framing wasn't valid (e.g. proxy error body)
        if (offset < wireBytes.size) {
            val remaining = wireBytes.copyOfRange(offset, wireBytes.size)
            if (remaining.isNotEmpty()) {
                val asText = remaining.toString(StandardCharsets.UTF_8)
                if (frameCount == 0 && asText.isNotBlank() && isPrintableJsonOrText(remaining)) {
                    messageFragments.add(toJsonLiteralOrObject(asText, isJsonPayload))
                } else {
                    val b64 = Base64.getEncoder().encodeToString(remaining)
                    val sb = StringBuilder()
                    sb.append("{\"_unframedBytes\":").append(remaining.size)
                    sb.append(",\"base64\":")
                    ProtobufWireDecoder.appendJsonString(sb, b64)
                    sb.append('}')
                    messageFragments.add(sb.toString())
                }
            }
        }

        return DecodedGrpcPayload(
            protocol = if (isGrpcWeb) "grpc-web" else "grpc",
            contentType = contentType,
            grpcStatus = status,
            grpcMessage = message,
            grpcEncoding = encoding,
            frameCount = frameCount,
            messageJsonFragments = messageFragments,
            trailingHeaders = trailingHeaders
        )
    }

    /**
     * Convenience wrapper that returns a formatted JSON summary for tools and callers.
     */
    fun decodeToJson(
        body: ByteArray,
        contentType: String?,
        headers: List<HttpHeader> = emptyList(),
        grpcEncodingOverride: String? = null,
        grpcStatusOverride: String? = null,
        grpcMessageOverride: String? = null
    ): String {
        val decoded = decode(
            body = body,
            contentType = contentType,
            headers = headers,
            grpcEncodingOverride = grpcEncodingOverride,
            grpcStatusOverride = grpcStatusOverride,
            grpcMessageOverride = grpcMessageOverride
        )
        val sb = StringBuilder(256)
        sb.append("{\"protocol\":")
        ProtobufWireDecoder.appendJsonString(sb, decoded.protocol)
        decoded.contentType?.let {
            sb.append(",\"contentType\":")
            ProtobufWireDecoder.appendJsonString(sb, it)
        }
        decoded.grpcStatus?.let {
            sb.append(",\"grpcStatus\":")
            ProtobufWireDecoder.appendJsonString(sb, it)
        }
        decoded.grpcMessage?.let {
            sb.append(",\"grpcMessage\":")
            ProtobufWireDecoder.appendJsonString(sb, it)
        }
        decoded.grpcEncoding?.let {
            sb.append(",\"grpcEncoding\":")
            ProtobufWireDecoder.appendJsonString(sb, it)
        }
        sb.append(",\"frameCount\":").append(decoded.frameCount)
        sb.append(",\"messages\":[")
        for (i in decoded.messageJsonFragments.indices) {
            if (i > 0) sb.append(',')
            sb.append(decoded.messageJsonFragments[i])
        }
        sb.append(']')
        if (decoded.trailingHeaders.isNotEmpty()) {
            sb.append(",\"trailers\":{")
            var first = true
            for ((k, v) in decoded.trailingHeaders) {
                if (!first) sb.append(',')
                first = false
                ProtobufWireDecoder.appendJsonString(sb, k)
                sb.append(':')
                ProtobufWireDecoder.appendJsonString(sb, v)
            }
            sb.append('}')
        }
        sb.append('}')
        return sb.toString()
    }

    private fun decodeMessageFragment(bytes: ByteArray, isJsonPayload: Boolean): String {
        if (isJsonPayload) {
            val text = bytes.toString(StandardCharsets.UTF_8).trim()
            return toJsonLiteralOrObject(text, isJson = true)
        }
        val protoJson = ProtobufWireDecoder.decodeToJson(bytes)
        if (protoJson != null) {
            return protoJson
        }
        val sb = StringBuilder()
        sb.append("{\"_type\":\"binary\",\"size\":").append(bytes.size)
        sb.append(",\"base64\":")
        ProtobufWireDecoder.appendJsonString(sb, Base64.getEncoder().encodeToString(bytes))
        sb.append('}')
        return sb.toString()
    }

    private fun toJsonLiteralOrObject(text: String, isJson: Boolean): String {
        val trimmed = text.trim()
        if (isJson && ((trimmed.startsWith("{") && trimmed.endsWith("}")) || (trimmed.startsWith("[") && trimmed.endsWith("]")))) {
            return trimmed
        }
        val sb = StringBuilder(text.length + 8)
        ProtobufWireDecoder.appendJsonString(sb, text)
        return sb.toString()
    }

    private fun decompressGrpcFrame(payload: ByteArray, encoding: String?): ByteArray {
        val enc = encoding?.trim()?.lowercase() ?: return payload
        return when {
            enc == "gzip" || enc == "x-gzip" -> HttpContentDecoder.gunzip(payload)
            enc == "deflate" -> HttpContentDecoder.inflate(payload)
            enc == "br" || enc == "brotli" -> HttpContentDecoder.unbrotli(payload)
            enc == "zstd" || enc == "x-zstd" -> HttpContentDecoder.unzstd(payload)
            else -> payload
        }
    }

    private fun decodeGrpcWebText(body: ByteArray): ByteArray {
        val text = body.toString(StandardCharsets.US_ASCII).replace("\\s+".toRegex(), "")
        if (text.isEmpty()) return ByteArray(0)
        // Standard gRPC-Web-Text concatenates padded Base64 chunks; split on '=' padding boundaries.
        val out = ByteArrayOutputStream()
        var start = 0
        while (start < text.length) {
            var end = text.indexOf('=', start)
            if (end < 0) {
                end = text.length
            } else {
                while (end < text.length && text[end] == '=') {
                    end++
                }
            }
            val chunk = text.substring(start, end)
            val decoded = runCatching { Base64.getDecoder().decode(chunk) }.getOrNull()
            if (decoded != null) {
                out.write(decoded)
            } else {
                return runCatching { Base64.getDecoder().decode(text) }.getOrElse { body }
            }
            start = end
        }
        return out.toByteArray()
    }

    private fun parseInlineTrailers(payload: ByteArray, out: MutableMap<String, String>) {
        val text = payload.toString(StandardCharsets.UTF_8)
        for (line in text.split("\r\n", "\n")) {
            val idx = line.indexOf(':')
            if (idx > 0) {
                val key = line.substring(0, idx).trim().lowercase()
                val value = line.substring(idx + 1).trim()
                out[key] = value
            }
        }
    }

    private fun findHeader(headers: List<HttpHeader>, name: String): String? =
        headers.lastOrNull { it.name.equals(name, ignoreCase = true) }?.value?.trim()

    private fun percentDecodeSafe(value: String): String =
        runCatching { URLDecoder.decode(value, StandardCharsets.UTF_8.name()) }.getOrElse { value }

    private fun isPrintableJsonOrText(bytes: ByteArray): Boolean {
        for (b in bytes) {
            val u = b.toInt() and 0xFF
            if (u < 0x20 && u != 0x09 && u != 0x0A && u != 0x0D) return false
        }
        return true
    }

    private fun decodeReadableText(bytes: ByteArray, charset: Charset): String? {
        if (bytes.isEmpty()) return ""
        return try {
            val decoder = charset.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
            val charBuf = decoder.decode(ByteBuffer.wrap(bytes))
            val len = charBuf.length
            var badCtrl = 0
            for (i in 0 until len) {
                val ch = charBuf[i]
                if (ch == '\uFFFD' || ch == '\u0000') return null
                if ((ch.code < 0x20 && ch != '\n' && ch != '\r' && ch != '\t') || ch.code == 0x7F) {
                    badCtrl++
                }
            }
            if (len > 0 && badCtrl * 20 > len) return null
            charBuf.toString()
        } catch (_: Exception) {
            null
        }
    }

    private fun formatBinaryDiagnosticJson(
        rawBody: ByteArray,
        decodedCandidate: ByteArray,
        contentType: String?,
        contentEncoding: String?
    ): String {
        val sample = if (decodedCandidate.isNotEmpty()) decodedCandidate else rawBody
        val zstdInfo = HttpContentDecoder.inspectZstdFrame(sample)
        val detectedFormat = when {
            zstdInfo.isZstdMagic && zstdInfo.hasDictionaryId -> {
                val dictHex = zstdInfo.dictId?.let { "0x" + it.toString(16) } ?: "unknown"
                "zstd_dictionary_frame(dictId=$dictHex)"
            }
            zstdInfo.isZstdMagic -> "zstd_frame"
            HttpContentDecoder.hasGzipMagic(sample) -> "gzip_frame"
            HttpContentDecoder.hasZlibMagic(sample) -> "zlib_frame"
            contentEncoding?.contains("br", ignoreCase = true) == true -> "brotli_or_corrupt_stream"
            else -> "binary_or_encrypted_payload"
        }
        val hexCount = minOf(sample.size, 24)
        val hexSb = StringBuilder(hexCount * 2)
        val hexDigits = "0123456789abcdef"
        for (i in 0 until hexCount) {
            val b = sample[i].toInt() and 0xFF
            hexSb.append(hexDigits[b ushr 4]).append(hexDigits[b and 0x0F])
            if (i + 1 < hexCount) hexSb.append(' ')
        }
        val b64Slice = sample.copyOfRange(0, minOf(sample.size, 256))
        val b64Preview = Base64.getEncoder().encodeToString(b64Slice)

        val sb = StringBuilder(256)
        sb.append("{\"_binaryPayload\":true,\"byteLength\":").append(rawBody.size)
        contentType?.let {
            sb.append(",\"contentType\":")
            ProtobufWireDecoder.appendJsonString(sb, it)
        }
        contentEncoding?.let {
            sb.append(",\"contentEncoding\":")
            ProtobufWireDecoder.appendJsonString(sb, it)
        }
        sb.append(",\"detectedFormat\":")
        ProtobufWireDecoder.appendJsonString(sb, detectedFormat)
        sb.append(",\"magicHex\":")
        ProtobufWireDecoder.appendJsonString(sb, hexSb.toString())
        sb.append(",\"base64Preview\":")
        ProtobufWireDecoder.appendJsonString(sb, b64Preview)
        sb.append(",\"hint\":\"Binary, encrypted, or dictionary-compressed payload; call phone_get_network_response with asString=false for raw Base64.\"}")
        return sb.toString()
    }
}
