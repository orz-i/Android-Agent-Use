package com.agent.use.common.network.parser

import com.agent.use.common.network.HttpHeader
import com.agent.use.common.network.HttpRequestEvent
import com.agent.use.common.network.HttpResponseEvent
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets
import java.util.concurrent.atomic.AtomicLong

/**
 * Streaming HTTP/1.x parser supporting keep-alive / pipelined requests,
 * accurate request-to-response `requestId` & URL pairing, `Transfer-Encoding: chunked`,
 * `Content-Encoding: gzip` / `deflate` decompression, and completion-ordered response events.
 */
class Http1PlaintextParser(
    private val maxBodySizeBytes: Long = 10 * 1024 * 1024L,
    private val isTls: Boolean = true,
    private val defaultScheme: String = if (isTls) "https" else "http",
    private val onParsedRequest: (HttpRequestEvent) -> Unit,
    private val onParsedResponse: (HttpResponseEvent) -> Unit,
    private val onBodyChunk: (requestId: String, chunk: ByteArray) -> Unit
) {
    private val seq = AtomicLong(0L)

    private data class RequestMeta(
        val requestId: String,
        val method: String,
        val url: String
    )

    private data class PendingRequest(
        val meta: RequestMeta,
        val headers: List<HttpHeader>,
        val contentLength: Long,
        val isChunked: Boolean,
        val bodyStream: ByteArrayOutputStream = ByteArrayOutputStream()
    )

    private data class PendingResponse(
        val requestId: String,
        val method: String,
        val url: String,
        val statusCode: Int,
        val statusText: String,
        val headers: List<HttpHeader>,
        val mimeType: String?,
        val contentLength: Long,
        val isChunked: Boolean,
        val bodyStream: ByteArrayOutputStream = ByteArrayOutputStream()
    )

    private val outboundBuffer = ByteArrayOutputStream()
    private val inboundBuffer = ByteArrayOutputStream()
    private val awaitingResponseQueue = ArrayDeque<RequestMeta>()

    private var pendingRequest: PendingRequest? = null
    private var pendingResponse: PendingResponse? = null

    @Synchronized
    fun feedOutbound(data: ByteArray, connectionId: String) {
        if (data.isEmpty()) return
        outboundBuffer.write(data)
        processOutbound(connectionId)
    }

    @Synchronized
    fun feedInbound(data: ByteArray, connectionId: String) {
        if (data.isEmpty()) return
        inboundBuffer.write(data)
        processInbound(connectionId)
    }

    /**
     * Finalizes an open connection-close response (`Content-Length < 0` and not chunked) when EOF/FIN arrives.
     */
    @Synchronized
    fun finishOnEof() {
        val cur = pendingResponse ?: return
        if (cur.contentLength < 0 && !cur.isChunked) {
            val remaining = inboundBuffer.toByteArray()
            if (remaining.isNotEmpty()) {
                appendLimited(cur.bodyStream, remaining, remaining.size)
                inboundBuffer.reset()
            }
            emitCompletedResponse(cur, cur.bodyStream.toByteArray())
            pendingResponse = null
        }
    }

    private fun processOutbound(connectionId: String) {
        while (true) {
            var bytes = outboundBuffer.toByteArray()

            if (pendingRequest == null) {
                if (bytes.isEmpty()) return
                val boundary = findHeaderBoundary(bytes) ?: return
                val headerText = String(bytes, 0, boundary.first, StandardCharsets.ISO_8859_1)
                val lines = headerText.split("\r\n", "\n").filter { it.isNotEmpty() }
                if (lines.isEmpty()) {
                    consumePrefix(outboundBuffer, bytes, boundary.first + boundary.second)
                    continue
                }

                val requestLine = lines[0].trim().split(" ")
                if (requestLine.size < 2) {
                    consumePrefix(outboundBuffer, bytes, boundary.first + boundary.second)
                    continue
                }

                val method = requestLine[0].trim().uppercase()
                val rawPath = requestLine[1].trim()
                val headers = parseHeaders(lines, 1)
                val host = headers.firstOrNull { it.name.equals("Host", ignoreCase = true) }?.value ?: "localhost"
                val fullUrl = if (rawPath.startsWith("http://") || rawPath.startsWith("https://")) {
                    rawPath
                } else {
                    "$defaultScheme://$host$rawPath"
                }

                val contentLength = headers.firstOrNull { it.name.equals("Content-Length", ignoreCase = true) }
                    ?.value?.trim()?.toLongOrNull() ?: 0L
                val isChunked = headers.any {
                    it.name.equals("Transfer-Encoding", ignoreCase = true) &&
                        it.value.contains("chunked", ignoreCase = true)
                }

                val meta = RequestMeta(
                    requestId = "${connectionId}_req_${System.currentTimeMillis()}_${seq.incrementAndGet()}",
                    method = method,
                    url = fullUrl
                )
                awaitingResponseQueue.addLast(meta)
                pendingRequest = PendingRequest(
                    meta = meta,
                    headers = headers,
                    contentLength = contentLength,
                    isChunked = isChunked
                )

                consumePrefix(outboundBuffer, bytes, boundary.first + boundary.second)
                bytes = outboundBuffer.toByteArray()
            }

            val curReq = pendingRequest ?: return
            if (curReq.isChunked) {
                if (bytes.isEmpty()) return
                val chunked = HttpContentDecoder.decodeChunked(bytes, maxBodyBytes = maxBodySizeBytes)
                if (chunked.consumedBytes > 0) {
                    if (chunked.decoded.isNotEmpty()) {
                        appendLimited(curReq.bodyStream, chunked.decoded, chunked.decoded.size)
                    }
                    consumePrefix(outboundBuffer, bytes, chunked.consumedBytes)
                }
                if (chunked.isComplete || curReq.bodyStream.size() >= maxBodySizeBytes) {
                    emitCompletedRequest(curReq)
                    pendingRequest = null
                    continue
                }
                return
            } else if (curReq.contentLength > 0) {
                if (bytes.isEmpty()) return
                val need = (curReq.contentLength - curReq.bodyStream.size()).coerceAtLeast(0L)
                val take = minOf(need, bytes.size.toLong()).toInt()
                if (take > 0) {
                    appendLimited(curReq.bodyStream, bytes, take)
                    consumePrefix(outboundBuffer, bytes, take)
                }
                if (curReq.bodyStream.size() >= curReq.contentLength || curReq.bodyStream.size() >= maxBodySizeBytes) {
                    emitCompletedRequest(curReq)
                    pendingRequest = null
                    continue
                }
                return
            } else {
                emitCompletedRequest(curReq)
                pendingRequest = null
                // Continue loop in case another pipelined request sits in outboundBuffer
            }
        }
    }

    private fun processInbound(connectionId: String) {
        while (true) {
            var bytes = inboundBuffer.toByteArray()

            if (pendingResponse == null) {
                if (bytes.isEmpty()) return
                val boundary = findHeaderBoundary(bytes) ?: return
                val headerText = String(bytes, 0, boundary.first, StandardCharsets.ISO_8859_1)
                val lines = headerText.split("\r\n", "\n").filter { it.isNotEmpty() }
                if (lines.isEmpty()) {
                    consumePrefix(inboundBuffer, bytes, boundary.first + boundary.second)
                    continue
                }

                val statusLine = lines[0].trim().split(" ", limit = 3)
                val statusCode = if (statusLine.size >= 2) statusLine[1].toIntOrNull() ?: 200 else 200
                val statusText = if (statusLine.size >= 3) statusLine[2] else "OK"

                val headers = parseHeaders(lines, 1)
                val mimeType = headers.firstOrNull { it.name.equals("Content-Type", ignoreCase = true) }?.value
                val contentLength = headers.firstOrNull { it.name.equals("Content-Length", ignoreCase = true) }
                    ?.value?.trim()?.toLongOrNull() ?: -1L
                val isChunked = headers.any {
                    it.name.equals("Transfer-Encoding", ignoreCase = true) &&
                        it.value.contains("chunked", ignoreCase = true)
                }

                consumePrefix(inboundBuffer, bytes, boundary.first + boundary.second)

                // Ignore 1xx interim responses (e.g. 100 Continue / 103 Early Hints) without consuming request meta
                if (statusCode in 100..199 && statusCode != 101) {
                    continue
                }

                val matchedReq = awaitingResponseQueue.removeFirstOrNull()
                val reqId = matchedReq?.requestId
                    ?: "${connectionId}_res_${System.currentTimeMillis()}_${seq.incrementAndGet()}"
                val reqUrl = matchedReq?.url ?: "https://unknown"
                val reqMethod = matchedReq?.method ?: "GET"

                pendingResponse = PendingResponse(
                    requestId = reqId,
                    method = reqMethod,
                    url = reqUrl,
                    statusCode = statusCode,
                    statusText = statusText,
                    headers = headers,
                    mimeType = mimeType,
                    contentLength = contentLength,
                    isChunked = isChunked
                )
                bytes = inboundBuffer.toByteArray()
            }

            val curResp = pendingResponse ?: return
            val hasNoBody = curResp.method.equals("HEAD", ignoreCase = true) ||
                curResp.statusCode == 204 ||
                curResp.statusCode == 304 ||
                (curResp.contentLength == 0L && !curResp.isChunked)

            if (hasNoBody) {
                emitCompletedResponse(curResp, ByteArray(0))
                pendingResponse = null
                continue
            }

            if (bytes.isEmpty()) return

            if (curResp.isChunked) {
                val chunked = HttpContentDecoder.decodeChunked(bytes, maxBodyBytes = maxBodySizeBytes)
                if (chunked.consumedBytes > 0) {
                    if (chunked.decoded.isNotEmpty()) {
                        appendLimited(curResp.bodyStream, chunked.decoded, chunked.decoded.size)
                    }
                    consumePrefix(inboundBuffer, bytes, chunked.consumedBytes)
                }
                if (chunked.isComplete || curResp.bodyStream.size() >= maxBodySizeBytes) {
                    emitCompletedResponse(curResp, curResp.bodyStream.toByteArray())
                    pendingResponse = null
                    continue
                }
                return
            }

            if (curResp.contentLength > 0) {
                val need = (curResp.contentLength - curResp.bodyStream.size()).coerceAtLeast(0L)
                val take = minOf(need, bytes.size.toLong()).toInt()
                if (take > 0) {
                    appendLimited(curResp.bodyStream, bytes, take)
                    consumePrefix(inboundBuffer, bytes, take)
                }
                if (curResp.bodyStream.size() >= curResp.contentLength || curResp.bodyStream.size() >= maxBodySizeBytes) {
                    emitCompletedResponse(curResp, curResp.bodyStream.toByteArray())
                    pendingResponse = null
                    continue
                }
                return
            }

            // Unknown Content-Length, not chunked (Connection: close): buffer until EOF or maxBodySizeBytes
            if (bytes.isNotEmpty()) {
                appendLimited(curResp.bodyStream, bytes, bytes.size)
                inboundBuffer.reset()
                if (curResp.bodyStream.size() >= maxBodySizeBytes) {
                    emitCompletedResponse(curResp, curResp.bodyStream.toByteArray())
                    pendingResponse = null
                    return
                }
            }
            return
        }
    }

    private fun emitCompletedRequest(req: PendingRequest) {
        val rawBody = req.bodyStream.toByteArray()
        val decodedBody = HttpContentDecoder.decompressIfNeeded(rawBody, req.headers)
        val postDataStr = if (decodedBody.isNotEmpty()) {
            decodedBody.toString(StandardCharsets.UTF_8)
        } else null

        onParsedRequest(
            HttpRequestEvent(
                requestId = req.meta.requestId,
                timestamp = System.currentTimeMillis(),
                url = req.meta.url,
                method = req.meta.method,
                headers = req.headers,
                postData = postDataStr,
                isTls = isTls
            )
        )
    }

    private fun emitCompletedResponse(resp: PendingResponse, rawBody: ByteArray) {
        val finalBody = HttpContentDecoder.decompressIfNeeded(rawBody, resp.headers)
        if (finalBody.isNotEmpty()) {
            onBodyChunk(resp.requestId, finalBody)
        }
        val effectiveLength = if (resp.contentLength >= 0) resp.contentLength else finalBody.size.toLong()
        onParsedResponse(
            HttpResponseEvent(
                requestId = resp.requestId,
                timestamp = System.currentTimeMillis(),
                url = resp.url,
                statusCode = resp.statusCode,
                statusText = resp.statusText,
                headers = resp.headers,
                mimeType = resp.mimeType,
                contentLength = effectiveLength,
                fromCache = false
            )
        )
    }

    private fun appendLimited(target: ByteArrayOutputStream, data: ByteArray, count: Int) {
        val remainingCap = (maxBodySizeBytes - target.size()).toInt().coerceAtLeast(0)
        val toWrite = minOf(count, remainingCap)
        if (toWrite > 0) {
            target.write(data, 0, toWrite)
        }
    }

    private fun consumePrefix(buffer: ByteArrayOutputStream, fullBytes: ByteArray, consumed: Int) {
        buffer.reset()
        if (consumed < fullBytes.size) {
            buffer.write(fullBytes, consumed, fullBytes.size - consumed)
        }
    }

    private fun parseHeaders(lines: List<String>, startIndex: Int): List<HttpHeader> {
        val headers = mutableListOf<HttpHeader>()
        for (i in startIndex until lines.size) {
            val colonIdx = lines[i].indexOf(':')
            if (colonIdx > 0) {
                val name = lines[i].substring(0, colonIdx).trim()
                val value = lines[i].substring(colonIdx + 1).trim()
                if (name.isNotEmpty()) {
                    headers.add(HttpHeader(name, value))
                }
            }
        }
        return headers
    }

    private fun findHeaderBoundary(bytes: ByteArray): Pair<Int, Int>? {
        for (i in 0 until bytes.size - 1) {
            if (i + 3 < bytes.size &&
                bytes[i] == '\r'.code.toByte() &&
                bytes[i + 1] == '\n'.code.toByte() &&
                bytes[i + 2] == '\r'.code.toByte() &&
                bytes[i + 3] == '\n'.code.toByte()
            ) {
                return i to 4
            }
            if (bytes[i] == '\n'.code.toByte() && bytes[i + 1] == '\n'.code.toByte()) {
                return i to 2
            }
        }
        return null
    }
}
