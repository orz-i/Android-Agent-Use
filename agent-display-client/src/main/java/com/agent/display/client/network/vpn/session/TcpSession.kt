package com.agent.display.client.network.vpn.session

import com.agent.display.client.network.vpn.parser.HttpPacket
import com.agent.display.client.network.vpn.parser.HttpRequestData
import com.agent.display.client.network.vpn.parser.HttpResponseData
import com.agent.display.client.network.vpn.parser.TlsPacket
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
                        // 检查请求体是否已满足 Content-Length
                        val expectedBodyLen = req.contentLength
                        val actualBodyLen = currentBytes.size - req.headerEndOffset
                        val isComplete = if (expectedBodyLen >= 0) {
                            actualBodyLen >= expectedBodyLen
                        } else {
                            true
                        }

                        if (isComplete) {
                            uplinkBuffer.reset()
                            val reqId = "vpn_http_${UUID.randomUUID().toString().substring(0, 8)}"
                            activeRequestId = reqId
                            return UplinkParseResult.HttpRequest(requestId = reqId, data = req)
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
     * 追加服务端下发的下行数据，并尝试提取 HTTP 响应。
     */
    fun appendDownlink(
        payload: ByteArray,
        maxBodyBytes: Long = 10 * 1024 * 1024L
    ): DownlinkParseResult {
        synchronized(lock) {
            lastActiveTimeMs = System.currentTimeMillis()

            if (!isTls) {
                downlinkBuffer.write(payload)
                val currentBytes = downlinkBuffer.toByteArray()

                if (HttpPacket.isHttpResponse(currentBytes)) {
                    val resp = HttpPacket.parseResponse(currentBytes, maxBodyBytes = maxBodyBytes)
                    if (resp != null) {
                        val expectedBodyLen = resp.contentLength
                        val actualBodyLen = currentBytes.size - resp.headerEndOffset
                        val isComplete = if (expectedBodyLen >= 0) {
                            actualBodyLen >= expectedBodyLen
                        } else if (resp.isChunked) {
                            currentBytes.size >= 5 &&
                                    currentBytes[currentBytes.size - 5] == '0'.code.toByte() &&
                                    currentBytes[currentBytes.size - 4] == '\r'.code.toByte() &&
                                    currentBytes[currentBytes.size - 3] == '\n'.code.toByte() &&
                                    currentBytes[currentBytes.size - 2] == '\r'.code.toByte() &&
                                    currentBytes[currentBytes.size - 1] == '\n'.code.toByte()
                        } else {
                            false
                        }

                        val reqId = activeRequestId ?: "vpn_resp_${UUID.randomUUID().toString().substring(0, 8)}"
                        if (isComplete) {
                            downlinkBuffer.reset()
                        }
                        return DownlinkParseResult.HttpResponse(
                            requestId = reqId,
                            data = resp,
                            isComplete = isComplete
                        )
                    }
                } else if (downlinkBuffer.size() > 10 * 1024 * 1024) {
                    downlinkBuffer.reset()
                }
            }

            return DownlinkParseResult.None
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
