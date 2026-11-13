package com.agent.use.client.network.vpn.session

import com.agent.use.client.network.vpn.parser.HttpPacket
import com.agent.use.client.network.vpn.parser.HttpRequestData
import com.agent.use.client.network.vpn.parser.HttpResponseData
import com.agent.use.client.network.vpn.parser.TlsPacket
import com.agent.use.common.network.parser.HttpContentDecoder
import java.io.ByteArrayOutputStream
import java.util.UUID

/**
 * 标识一条 TCP 连接的双向四元组。
 */
data class TcpConnectionKey(
    val clientIp: String,
    val clientPort: Int,
    val serverIp: String,
    val serverPort: Int
) {
    fun reversed(): TcpConnectionKey =
        TcpConnectionKey(serverIp, serverPort, clientIp, clientPort)
}

/**
 * 维护单条 TCP 会话的双向状态、流式重组缓冲区及请求-响应上下文。
 */
class TcpSession(
    val key: TcpConnectionKey,
    val startTimeMs: Long = System.currentTimeMillis()
) {
    @Volatile
    var lastActiveTimeMs: Long = startTimeMs

    @Volatile
    var sniDomain: String? = null

    @Volatile
    var isTls: Boolean = false

    @Volatile
    var activeRequestId: String? = null

    @Volatile
    var activeRequestUrl: String? = null

    @Volatile
    var activeRequestMethod: String? = null

    private val uplinkBuffer = ByteArrayOutputStream()
    private val downlinkBuffer = ByteArrayOutputStream()
    private val lock = Any()

    /**
     * 追加客户端向上发送的上行数据，并尝试提取 HTTP 请求或 TLS 握手。
     */
    fun appendUplink(
        payload: ByteArray,
        maxBodyBytes: Long = 10 * 1024 * 1024L
    ): UplinkParseResult {
        synchronized(lock) {
            lastActiveTimeMs = System.currentTimeMillis()

            // 1. 检查是否为 TLS Client Hello
            if (!isTls && TlsPacket.isClientHello(payload)) {
                val clientHello = TlsPacket.parseClientHello(payload)
                if (clientHello != null) {
                    isTls = true
                    sniDomain = clientHello.sni
                    val reqId = "vpn_tls_${UUID.randomUUID().toString().substring(0, 8)}"
                    activeRequestId = reqId
                    val host = sniDomain ?: key.serverIp
                    val url = "https://$host:${key.serverPort}/"
                    activeRequestUrl = url
                    return UplinkParseResult.TlsHandshake(
                        requestId = reqId,
                        sni = clientHello.sni,
                        url = url
                    )
                }
            }

            // 2. HTTP 明文请求重组与解析
            if (!isTls) {
                uplinkBuffer.write(payload)
                val currentBytes = uplinkBuffer.toByteArray()
                if (HttpPacket.isHttpRequest(currentBytes)) {
                    val req = HttpPacket.parseRequest(currentBytes, maxBodyBytes = maxBodyBytes)
                    if (req != null) {
                        val expectedBodyLen = req.contentLength
                        val rawTailLen = currentBytes.size - req.headerEndOffset
                        val isChunked = req.headers.any {
                            it.name.equals("Transfer-Encoding", ignoreCase = true) &&
                                it.value.contains("chunked", ignoreCase = true)
                        }

                        var decodedReqBody = req.body
                        var consumed = 0
                        val isComplete = if (isChunked) {
                            val tail = currentBytes.copyOfRange(req.headerEndOffset, currentBytes.size)
                            val chunkRes = HttpContentDecoder.decodeChunked(tail, maxBodyBytes = maxBodyBytes)
                            decodedReqBody = HttpContentDecoder.decompressIfNeeded(chunkRes.decoded, req.headers)
                            consumed = req.headerEndOffset + chunkRes.consumedBytes
                            chunkRes.isComplete
                        } else if (expectedBodyLen > 0) {
                            if (rawTailLen >= expectedBodyLen) {
                                val rawBody = currentBytes.copyOfRange(
                                    req.headerEndOffset,
                                    (req.headerEndOffset + expectedBodyLen.toInt()).coerceAtMost(currentBytes.size)
                                )
                                decodedReqBody = HttpContentDecoder.decompressIfNeeded(rawBody, req.headers)
                                consumed = minOf(currentBytes.size, req.headerEndOffset + expectedBodyLen.toInt())
                                true
                            } else {
                                false
                            }
                        } else {
                            consumed = req.headerEndOffset
                            true
                        }

                        if (isComplete) {
                            consumePrefix(uplinkBuffer, currentBytes, consumed)
                            val reqId = "vpn_http_${UUID.randomUUID().toString().substring(0, 8)}"
                            activeRequestId = reqId
                            activeRequestMethod = req.method
                            return UplinkParseResult.HttpRequest(
                                requestId = reqId,
                                data = req.copy(body = decodedReqBody)
                            )
                        }
                    }
                } else if (uplinkBuffer.size() > 65536) {
                    // 若积累过多仍无法识别为 HTTP 请求，清理缓冲
                    uplinkBuffer.reset()
                }
            }

            return UplinkParseResult.None
        }
    }

    /**
     * 追加服务端下发的下行数据，并尝试提取完整 HTTP 响应（支持 chunked 与 gzip/deflate 解码）。
     */
    fun appendDownlink(
        payload: ByteArray,
        maxBodyBytes: Long = 10 * 1024 * 1024L
    ): DownlinkParseResult {
        synchronized(lock) {
            lastActiveTimeMs = System.currentTimeMillis()
            if (isTls) return DownlinkParseResult.None

            downlinkBuffer.write(payload)
            while (true) {
                val currentBytes = downlinkBuffer.toByteArray()
                if (currentBytes.isEmpty()) break

                if (!HttpPacket.isHttpResponse(currentBytes)) {
                    if (downlinkBuffer.size() > 10 * 1024 * 1024) {
                        downlinkBuffer.reset()
                    }
                    break
                }

                val resp = HttpPacket.parseResponse(currentBytes, maxBodyBytes = maxBodyBytes) ?: break
                // Ignore 1xx interim responses (e.g. 100 Continue)
                if (resp.statusCode in 100..199 && resp.statusCode != 101) {
                    consumePrefix(downlinkBuffer, currentBytes, resp.headerEndOffset)
                    continue
                }

                val hasNoBody = activeRequestMethod.equals("HEAD", ignoreCase = true) ||
                    resp.statusCode == 204 ||
                    resp.statusCode == 304 ||
                    (resp.contentLength == 0L && !resp.isChunked)

                val rawTail = currentBytes.copyOfRange(resp.headerEndOffset, currentBytes.size)
                var decodedBody = ByteArray(0)
                var consumed = 0
                val isComplete: Boolean

                if (hasNoBody) {
                    consumed = resp.headerEndOffset
                    isComplete = true
                } else if (resp.isChunked) {
                    val chunkRes = HttpContentDecoder.decodeChunked(rawTail, maxBodyBytes = maxBodyBytes)
                    decodedBody = HttpContentDecoder.decompressIfNeeded(chunkRes.decoded, resp.headers)
                    consumed = resp.headerEndOffset + chunkRes.consumedBytes
                    isComplete = chunkRes.isComplete
                } else if (resp.contentLength > 0) {
                    if (rawTail.size.toLong() >= resp.contentLength) {
                        val take = minOf(resp.contentLength, maxBodyBytes).toInt()
                        val rawBody = rawTail.copyOfRange(0, take)
                        decodedBody = HttpContentDecoder.decompressIfNeeded(rawBody, resp.headers)
                        consumed = minOf(currentBytes.size, resp.headerEndOffset + resp.contentLength.toInt())
                        isComplete = true
                    } else {
                        consumed = 0
                        isComplete = false
                    }
                } else {
                    // Connection: close without Content-Length; wait for finishDownlinkOnEof()
                    consumed = 0
                    isComplete = false
                }

                val reqId = activeRequestId ?: "vpn_resp_${UUID.randomUUID().toString().substring(0, 8)}"
                if (isComplete) {
                    consumePrefix(downlinkBuffer, currentBytes, consumed)
                    return DownlinkParseResult.HttpResponse(
                        requestId = reqId,
                        data = resp.copy(body = decodedBody),
                        isComplete = true
                    )
                }

                return DownlinkParseResult.HttpResponse(
                    requestId = reqId,
                    data = resp,
                    isComplete = false
                )
            }

            return DownlinkParseResult.None
        }
    }

    /**
     * Finalizes any pending HTTP response (`Connection: close`) when TCP FIN/EOF closes the downlink stream.
     */
    fun finishDownlinkOnEof(maxBodyBytes: Long = 10 * 1024 * 1024L): DownlinkParseResult {
        synchronized(lock) {
            if (isTls) return DownlinkParseResult.None
            val currentBytes = downlinkBuffer.toByteArray()
            if (currentBytes.isEmpty() || !HttpPacket.isHttpResponse(currentBytes)) {
                return DownlinkParseResult.None
            }
            val resp = HttpPacket.parseResponse(currentBytes, maxBodyBytes = maxBodyBytes)
                ?: return DownlinkParseResult.None
            val rawTail = currentBytes.copyOfRange(resp.headerEndOffset, currentBytes.size)
            val decoded = if (resp.isChunked) {
                val chunkRes = HttpContentDecoder.decodeChunked(rawTail, maxBodyBytes = maxBodyBytes)
                HttpContentDecoder.decompressIfNeeded(chunkRes.decoded, resp.headers)
            } else {
                HttpContentDecoder.decompressIfNeeded(rawTail, resp.headers)
            }
            val reqId = activeRequestId ?: "vpn_resp_${UUID.randomUUID().toString().substring(0, 8)}"
            downlinkBuffer.reset()
            return DownlinkParseResult.HttpResponse(
                requestId = reqId,
                data = resp.copy(body = decoded),
                isComplete = true
            )
        }
    }

    private fun consumePrefix(stream: ByteArrayOutputStream, snapshot: ByteArray, consumed: Int) {
        val safeConsumed = consumed.coerceIn(0, snapshot.size)
        stream.reset()
        if (safeConsumed < snapshot.size) {
            stream.write(snapshot, safeConsumed, snapshot.size - safeConsumed)
        }
    }

    /**
     * 重置会话流缓冲区。
     */
    fun reset() {
        synchronized(lock) {
            uplinkBuffer.reset()
            downlinkBuffer.reset()
            activeRequestId = null
            activeRequestUrl = null
            activeRequestMethod = null
        }
    }
}

sealed class UplinkParseResult {
    object None : UplinkParseResult()
    data class TlsHandshake(val requestId: String, val sni: String?, val url: String) : UplinkParseResult()
    data class HttpRequest(val requestId: String, val data: HttpRequestData) : UplinkParseResult()
}

sealed class DownlinkParseResult {
    object None : DownlinkParseResult()
    data class HttpResponse(
        val requestId: String,
        val data: HttpResponseData,
        val isComplete: Boolean
    ) : DownlinkParseResult()
}
