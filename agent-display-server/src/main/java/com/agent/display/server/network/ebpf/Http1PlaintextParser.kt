package com.agent.display.server.network.ebpf

import com.agent.display.common.network.HttpHeader
import com.agent.display.common.network.HttpRequestEvent
import com.agent.display.common.network.HttpResponseEvent
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets

/**
 * HTTP/1.1 明文流式报文解析器。
 *
 * 维护双向流式缓冲区，支持：
 * 1. 分块到达的数据拼接与请求/响应行切分；
 * 2. Header 逐行解析 (包含 Host 提取与完整 URL 拼接)；
 * 3. Content-Length 与 Transfer-Encoding: chunked 分块传输解码；
 * 4. 自动关联对应请求与响应，生成标准的 HttpRequestEvent 与 HttpResponseEvent。
 */
class Http1PlaintextParser(
    private val maxBodySizeBytes: Long = 10 * 1024 * 1024L,
    private val onParsedRequest: (HttpRequestEvent) -> Unit,
    private val onParsedResponse: (HttpResponseEvent) -> Unit,
    private val onBodyChunk: (requestId: String, chunk: ByteArray) -> Unit
) {

    // 出站请求缓冲区 (SSL_write)
    private val outboundBuffer = ByteArrayOutputStream()
    private var pendingRequest: PendingRequest? = null

    // 入站响应缓冲区 (SSL_read)
    private val inboundBuffer = ByteArrayOutputStream()
    private var pendingResponse: PendingResponse? = null

    private data class PendingRequest(
        val requestId: String,
        val method: String,
        val url: String,
        val headers: List<HttpHeader>,
        val contentLength: Long,
        val isChunked: Boolean,
        val bodyStream: ByteArrayOutputStream = ByteArrayOutputStream()
    )

    private data class PendingResponse(
        val requestId: String,
        val url: String,
        val statusCode: Int,
        val statusText: String,
        val headers: List<HttpHeader>,
        val mimeType: String?,
        val contentLength: Long,
        val isChunked: Boolean,
        val bodyStream: ByteArrayOutputStream = ByteArrayOutputStream()
    )

    /**
     * 接收出站明文数据块 (SSL_write -> Request)。
     */
    @Synchronized
    fun feedOutbound(data: ByteArray, connectionId: String) {
        outboundBuffer.write(data)
        processOutbound(connectionId)
    }

    /**
     * 接收入站明文数据块 (SSL_read -> Response)。
     */
    @Synchronized
    fun feedInbound(data: ByteArray, connectionId: String) {
        inboundBuffer.write(data)
        processInbound(connectionId)
    }

    private fun processOutbound(connectionId: String) {
        val bytes = outboundBuffer.toByteArray()
        if (pendingRequest == null) {
            val headerEnd = findHeaderBoundary(bytes)
            if (headerEnd == -1) {
                return // 头部尚未完整接收，等待后续数据
            }

            val headerBytes = bytes.copyOfRange(0, headerEnd)
            val headerText = String(headerBytes, StandardCharsets.ISO_8859_1)
            val lines = headerText.split("\r\n").filter { it.isNotEmpty() }
            if (lines.isEmpty()) return

            val requestLine = lines[0].split(" ")
            if (requestLine.size < 2) return

            val method = requestLine[0].trim().uppercase()
            val rawPath = requestLine[1].trim()

            val headers = mutableListOf<HttpHeader>()
            for (i in 1 until lines.size) {
                val colonIdx = lines[i].indexOf(':')
                if (colonIdx != -1) {
                    val name = lines[i].substring(0, colonIdx).trim()
                    val value = lines[i].substring(colonIdx + 1).trim()
                    headers.add(HttpHeader(name, value))
                }
            }

            val host = headers.firstOrNull { it.name.equals("Host", ignoreCase = true) }?.value ?: "localhost"
            val fullUrl = if (rawPath.startsWith("http://") || rawPath.startsWith("https://")) {
                rawPath
            } else {
                "https://$host$rawPath"
            }

            val contentLength = headers.firstOrNull { it.name.equals("Content-Length", ignoreCase = true) }
                ?.value?.toLongOrNull() ?: 0L
            val isChunked = headers.any {
                it.name.equals("Transfer-Encoding", ignoreCase = true) &&
                        it.value.contains("chunked", ignoreCase = true)
            }

            val requestId = "${connectionId}_req_${System.currentTimeMillis()}"
            val req = PendingRequest(
                requestId = requestId,
                method = method,
                url = fullUrl,
                headers = headers,
                contentLength = contentLength,
                isChunked = isChunked
            )
            pendingRequest = req

            // 清理已处理的 header 字节
            val remainingOffset = if (bytes.size > headerEnd + 4 && bytes[headerEnd] == '\r'.code.toByte()) {
                headerEnd + 4
            } else if (bytes.size > headerEnd + 2 && bytes[headerEnd] == '\n'.code.toByte()) {
                headerEnd + 2
            } else {
                headerEnd + 4
            }

            outboundBuffer.reset()
            if (remainingOffset < bytes.size) {
                outboundBuffer.write(bytes, remainingOffset, bytes.size - remainingOffset)
            }
        }

        // 处理请求体
        val curReq = pendingRequest ?: return
        val bodyBytes = outboundBuffer.toByteArray()

        if (curReq.isChunked) {
            val (decoded, complete) = parseChunkedBody(bodyBytes)
            if (decoded != null && decoded.isNotEmpty()) {
                curReq.bodyStream.write(decoded)
            }
            if (complete || curReq.bodyStream.size() >= maxBodySizeBytes) {
                finishRequest(curReq)
            }
        } else if (curReq.contentLength > 0) {
            if (bodyBytes.size >= curReq.contentLength) {
                curReq.bodyStream.write(bodyBytes, 0, curReq.contentLength.toInt().coerceAtMost(maxBodySizeBytes.toInt()))
                finishRequest(curReq)
            }
        } else {
            // GET, HEAD 或没有请求体的请求
            finishRequest(curReq)
        }
    }

    private fun finishRequest(req: PendingRequest) {
        val postDataStr = if (req.bodyStream.size() > 0) {
            req.bodyStream.toByteArray().toString(StandardCharsets.UTF_8)
        } else null

        val event = HttpRequestEvent(
            requestId = req.requestId,
            timestamp = System.currentTimeMillis(),
            url = req.url,
            method = req.method,
            headers = req.headers,
            postData = postDataStr,
            isTls = true
        )
        onParsedRequest(event)
        outboundBuffer.reset()
        pendingRequest = null
    }

    private fun processInbound(connectionId: String) {
        val bytes = inboundBuffer.toByteArray()
        if (pendingResponse == null) {
            val headerEnd = findHeaderBoundary(bytes)
            if (headerEnd == -1) return

            val headerBytes = bytes.copyOfRange(0, headerEnd)
            val headerText = String(headerBytes, StandardCharsets.ISO_8859_1)
            val lines = headerText.split("\r\n").filter { it.isNotEmpty() }
            if (lines.isEmpty()) return

            val statusLine = lines[0].split(" ", limit = 3)
            val statusCode = if (statusLine.size >= 2) statusLine[1].toIntOrNull() ?: 200 else 200
            val statusText = if (statusLine.size >= 3) statusLine[2] else "OK"

            val headers = mutableListOf<HttpHeader>()
            for (i in 1 until lines.size) {
                val colonIdx = lines[i].indexOf(':')
                if (colonIdx != -1) {
                    val name = lines[i].substring(0, colonIdx).trim()
                    val value = lines[i].substring(colonIdx + 1).trim()
                    headers.add(HttpHeader(name, value))
                }
            }

            val mimeType = headers.firstOrNull { it.name.equals("Content-Type", ignoreCase = true) }?.value
            val contentLength = headers.firstOrNull { it.name.equals("Content-Length", ignoreCase = true) }
                ?.value?.toLongOrNull() ?: -1L
            val isChunked = headers.any {
                it.name.equals("Transfer-Encoding", ignoreCase = true) &&
                        it.value.contains("chunked", ignoreCase = true)
            }

            val reqId = pendingRequest?.requestId ?: "${connectionId}_res_${System.currentTimeMillis()}"
            val reqUrl = pendingRequest?.url ?: "https://unknown"

            val resp = PendingResponse(
                requestId = reqId,
                url = reqUrl,
                statusCode = statusCode,
                statusText = statusText,
                headers = headers,
                mimeType = mimeType,
                contentLength = contentLength,
                isChunked = isChunked
            )
            pendingResponse = resp

            val responseEvent = HttpResponseEvent(
                requestId = reqId,
                timestamp = System.currentTimeMillis(),
                url = reqUrl,
                statusCode = statusCode,
                statusText = statusText,
                headers = headers,
                mimeType = mimeType,
                contentLength = contentLength,
                fromCache = false
            )
            onParsedResponse(responseEvent)

            val remainingOffset = if (bytes.size > headerEnd + 4 && bytes[headerEnd] == '\r'.code.toByte()) {
                headerEnd + 4
            } else if (bytes.size > headerEnd + 2 && bytes[headerEnd] == '\n'.code.toByte()) {
                headerEnd + 2
            } else {
                headerEnd + 4
            }

            inboundBuffer.reset()
            if (remainingOffset < bytes.size) {
                inboundBuffer.write(bytes, remainingOffset, bytes.size - remainingOffset)
            }
        }

        // 处理响应体数据
        val curResp = pendingResponse ?: return
        val bodyBytes = inboundBuffer.toByteArray()
        if (bodyBytes.isNotEmpty()) {
            val toEmit = if (curResp.bodyStream.size() + bodyBytes.size <= maxBodySizeBytes) {
                bodyBytes
            } else {
                val allowed = (maxBodySizeBytes - curResp.bodyStream.size()).toInt().coerceAtLeast(0)
                bodyBytes.copyOfRange(0, allowed)
            }

            if (toEmit.isNotEmpty()) {
                curResp.bodyStream.write(toEmit)
                onBodyChunk(curResp.requestId, toEmit)
            }
            inboundBuffer.reset()

            if (curResp.contentLength in 0..curResp.bodyStream.size().toLong()) {
                pendingResponse = null
            }
        }
    }

    /**
     * 查找 \r\n\r\n 或 \n\n 头部结束边界索引。
     */
    private fun findHeaderBoundary(bytes: ByteArray): Int {
        for (i in 0 until bytes.size - 3) {
            if (bytes[i] == '\r'.code.toByte() &&
                bytes[i + 1] == '\n'.code.toByte() &&
                bytes[i + 2] == '\r'.code.toByte() &&
                bytes[i + 3] == '\n'.code.toByte()
            ) {
                return i
            }
        }
        for (i in 0 until bytes.size - 1) {
            if (bytes[i] == '\n'.code.toByte() && bytes[i + 1] == '\n'.code.toByte()) {
                return i
            }
        }
        return -1
    }

    /**
     * 简易 chunked 块解码。
     */
    private fun parseChunkedBody(bytes: ByteArray): Pair<ByteArray?, Boolean> {
        val out = ByteArrayOutputStream()
        var offset = 0
        var isDone = false

        try {
            while (offset < bytes.size) {
                val crlf = indexOfCrlf(bytes, offset)
                if (crlf == -1) break

                val line = String(bytes, offset, crlf - offset, StandardCharsets.ISO_8859_1).trim()
                val chunkSize = line.split(";")[0].toIntOrNull(16) ?: break
                if (chunkSize == 0) {
                    isDone = true
                    break
                }

                val dataStart = crlf + 2
                val dataEnd = dataStart + chunkSize
                if (dataEnd > bytes.size) break

                out.write(bytes, dataStart, chunkSize)
                offset = dataEnd + 2 // 跳过尾部 \r\n
            }
        } catch (_: Exception) {
            // 忽略格式解析残损
        }

        return out.toByteArray() to isDone
    }

    private fun indexOfCrlf(bytes: ByteArray, start: Int): Int {
        for (i in start until bytes.size - 1) {
            if (bytes[i] == '\r'.code.toByte() && bytes[i + 1] == '\n'.code.toByte()) {
                return i
            }
        }
        return -1
    }
}
