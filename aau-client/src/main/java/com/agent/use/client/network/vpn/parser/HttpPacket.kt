package com.agent.use.client.network.vpn.parser

import com.agent.use.common.network.HttpHeader
import com.agent.use.common.network.getIgnoreCase

/**
 * 解析出的 HTTP 请求详情。
 */
data class HttpRequestData(
    val method: String,
    val uri: String,
    val version: String,
    val headers: List<HttpHeader>,
    val body: ByteArray,
    val contentLength: Long,
    val isChunked: Boolean,
    val headerEndOffset: Int
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as HttpRequestData
        return method == other.method && uri == other.uri && version == other.version &&
                headers == other.headers && body.contentEquals(other.body)
    }

    override fun hashCode(): Int {
        var result = method.hashCode()
        result = 31 * result + uri.hashCode()
        result = 31 * result + version.hashCode()
        result = 31 * result + headers.hashCode()
        result = 31 * result + body.contentHashCode()
        return result
    }
}

/**
 * 解析出的 HTTP 响应详情。
 */
data class HttpResponseData(
    val version: String,
    val statusCode: Int,
    val statusText: String,
    val headers: List<HttpHeader>,
    val body: ByteArray,
    val contentLength: Long,
    val mimeType: String?,
    val isChunked: Boolean,
    val headerEndOffset: Int
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as HttpResponseData
        return version == other.version && statusCode == other.statusCode &&
                statusText == other.statusText && headers == other.headers &&
                body.contentEquals(other.body)
    }

    override fun hashCode(): Int {
        var result = version.hashCode()
        result = 31 * result + statusCode
        result = 31 * result + statusText.hashCode()
        result = 31 * result + headers.hashCode()
        result = 31 * result + body.contentHashCode()
        return result
    }
}

/**
 * HTTP/1.x 报文解析器。
 */
object HttpPacket {

    private val KNOWN_METHODS = setOf(
        "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"
    )

    /**
     * 判断载荷是否形如 HTTP 请求报文。
     */
    fun isHttpRequest(buffer: ByteArray, offset: Int = 0, length: Int = buffer.size - offset): Boolean {
        if (length < 10 || offset < 0 || offset + length > buffer.size) return false
        val firstSpace = findByte(buffer, offset, minOf(offset + 12, offset + length), ' '.code.toByte())
        if (firstSpace == -1) return false
        val method = String(buffer, offset, firstSpace - offset, Charsets.US_ASCII)
        return KNOWN_METHODS.contains(method)
    }

    /**
     * 判断载荷是否形如 HTTP 响应报文 (以 "HTTP/1." 或 "HTTP/2" 开头)。
     */
    fun isHttpResponse(buffer: ByteArray, offset: Int = 0, length: Int = buffer.size - offset): Boolean {
        if (length < 12 || offset < 0 || offset + length > buffer.size) return false
        val prefix = String(buffer, offset, minOf(7, length), Charsets.US_ASCII)
        return prefix.startsWith("HTTP/1.") || prefix.startsWith("HTTP/2")
    }

    /**
     * 解析 HTTP 请求报文。
     */
    fun parseRequest(
        buffer: ByteArray,
        offset: Int = 0,
        length: Int = buffer.size - offset,
        maxBodyBytes: Long = 10 * 1024 * 1024L
    ): HttpRequestData? {
        val headerDelimiter = findHeaderDelimiter(buffer, offset, length) ?: return null
        val (headerEnd, delimiterLen) = headerDelimiter

        val headerText = String(buffer, offset, headerEnd - offset, Charsets.UTF_8)
        val lines = headerText.split("\r\n", "\n")
        if (lines.isEmpty()) return null

        val requestLine = lines[0].trim()
        val parts = requestLine.split(" ")
        if (parts.size < 2) return null

        val method = parts[0].uppercase()
        if (!KNOWN_METHODS.contains(method)) return null
        val uri = parts[1]
        val version = if (parts.size >= 3) parts[2] else "HTTP/1.1"

        val headers = parseHeaders(lines.subList(1, lines.size))
        val contentLength = headers.getIgnoreCase("Content-Length")?.toLongOrNull() ?: -1L
        val transferEncoding = headers.getIgnoreCase("Transfer-Encoding")
        val isChunked = transferEncoding?.contains("chunked", ignoreCase = true) == true

        val bodyStart = headerEnd + delimiterLen
        val totalAvailableBody = (offset + length) - bodyStart
        val bodyLimit = if (contentLength >= 0) {
            minOf(contentLength, totalAvailableBody.toLong()).toInt()
        } else {
            maxOf(0, totalAvailableBody)
        }
        val clampedBodyLength = minOf(bodyLimit.toLong(), maxBodyBytes).toInt()

        val bodyBytes = if (clampedBodyLength > 0 && bodyStart + clampedBodyLength <= buffer.size) {
            buffer.copyOfRange(bodyStart, bodyStart + clampedBodyLength)
        } else {
            ByteArray(0)
        }

        return HttpRequestData(
            method = method,
            uri = uri,
            version = version,
            headers = headers,
            body = bodyBytes,
            contentLength = contentLength,
            isChunked = isChunked,
            headerEndOffset = bodyStart
        )
    }

    /**
     * 解析 HTTP 响应报文。
     */
    fun parseResponse(
        buffer: ByteArray,
        offset: Int = 0,
        length: Int = buffer.size - offset,
        maxBodyBytes: Long = 10 * 1024 * 1024L
    ): HttpResponseData? {
        val headerDelimiter = findHeaderDelimiter(buffer, offset, length) ?: return null
        val (headerEnd, delimiterLen) = headerDelimiter

        val headerText = String(buffer, offset, headerEnd - offset, Charsets.UTF_8)
        val lines = headerText.split("\r\n", "\n")
        if (lines.isEmpty()) return null

        val statusLine = lines[0].trim()
        val parts = statusLine.split(" ", limit = 3)
        if (parts.size < 2) return null

        val version = parts[0]
        val statusCode = parts[1].toIntOrNull() ?: return null
        val statusText = if (parts.size >= 3) parts[2] else ""

        val headers = parseHeaders(lines.subList(1, lines.size))
        val contentType = headers.getIgnoreCase("Content-Type")
        val mimeType = contentType?.split(";")?.firstOrNull()?.trim()

        val contentLength = headers.getIgnoreCase("Content-Length")?.toLongOrNull() ?: -1L
        val transferEncoding = headers.getIgnoreCase("Transfer-Encoding")
        val isChunked = transferEncoding?.contains("chunked", ignoreCase = true) == true

        val bodyStart = headerEnd + delimiterLen
        val totalAvailableBody = (offset + length) - bodyStart
        val bodyLimit = if (contentLength >= 0) {
            minOf(contentLength, totalAvailableBody.toLong()).toInt()
        } else {
            maxOf(0, totalAvailableBody)
        }
        val clampedBodyLength = minOf(bodyLimit.toLong(), maxBodyBytes).toInt()

        val bodyBytes = if (clampedBodyLength > 0 && bodyStart + clampedBodyLength <= buffer.size) {
            buffer.copyOfRange(bodyStart, bodyStart + clampedBodyLength)
        } else {
            ByteArray(0)
        }

        return HttpResponseData(
            version = version,
            statusCode = statusCode,
            statusText = statusText,
            headers = headers,
            body = bodyBytes,
            contentLength = contentLength,
            mimeType = mimeType,
            isChunked = isChunked,
            headerEndOffset = bodyStart
        )
    }

    private fun parseHeaders(lines: List<String>): List<HttpHeader> {
        val headers = mutableListOf<HttpHeader>()
        for (line in lines) {
            val colonIdx = line.indexOf(':')
            if (colonIdx > 0) {
                val name = line.substring(0, colonIdx).trim()
                val value = line.substring(colonIdx + 1).trim()
                if (name.isNotEmpty()) {
                    headers.add(HttpHeader(name, value))
                }
            }
        }
        return headers
    }

    /**
     * 寻找 HTTP 头部与正文分隔符 (\r\n\r\n 或 \n\n)。
     * 返回 Pair(分隔符起始下标, 分隔符字节长度)
     */
    fun findHeaderDelimiter(buffer: ByteArray, offset: Int, length: Int): Pair<Int, Int>? {
        val end = offset + length
        for (i in offset until end - 1) {
            if (i + 3 < end &&
                buffer[i] == '\r'.code.toByte() &&
                buffer[i + 1] == '\n'.code.toByte() &&
                buffer[i + 2] == '\r'.code.toByte() &&
                buffer[i + 3] == '\n'.code.toByte()
            ) {
                return Pair(i, 4)
            }
            if (buffer[i] == '\n'.code.toByte() && buffer[i + 1] == '\n'.code.toByte()) {
                return Pair(i, 2)
            }
        }
        return null
    }

    private fun findByte(buffer: ByteArray, start: Int, end: Int, target: Byte): Int {
        for (i in start until end) {
            if (buffer[i] == target) return i
        }
        return -1
    }
}
