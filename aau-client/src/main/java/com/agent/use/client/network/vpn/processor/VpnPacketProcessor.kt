package com.agent.use.client.network.vpn.processor

import android.util.Log
import com.agent.use.client.network.vpn.parser.DnsPacket
import com.agent.use.client.network.vpn.parser.IpPacket
import com.agent.use.client.network.vpn.parser.TcpPacket
import com.agent.use.client.network.vpn.parser.UdpPacket
import com.agent.use.client.network.vpn.session.DnsSessionCache
import com.agent.use.client.network.vpn.session.DownlinkParseResult
import com.agent.use.client.network.vpn.session.TcpSessionTracker
import com.agent.use.client.network.vpn.session.UplinkParseResult
import com.agent.use.common.network.HttpHeader
import com.agent.use.common.network.HttpRequestEvent
import com.agent.use.common.network.HttpResponseEvent
import com.agent.use.common.network.INetworkEventListener
import com.agent.use.common.network.NetworkCaptureConfig
import com.agent.use.common.network.getIgnoreCase

/**
 * TUN 虚拟网卡原始 IP 数据包分发与拦截处理引擎。
 *
 * 职责：
 * 1. 拆解 IPv4 / IPv6 数据报报头；
 * 2. 识别并拦截 DNS 查询与应答，填充域名-IP 映射账本；
 * 3. 跟踪 TCP 会话，对 TLS Client Hello (SNI) 进行无侵入嗅探；
 * 4. 重组并解析 HTTP/1.x 请求与响应流，构造 [HttpRequestEvent] / [HttpResponseEvent]；
 * 5. 将事件按 [NetworkCaptureConfig.matchesUrl] 过滤后分发给 [INetworkEventListener]。
 */
class VpnPacketProcessor(
    private val config: NetworkCaptureConfig,
    private val listener: INetworkEventListener,
    val dnsCache: DnsSessionCache = DnsSessionCache(),
    val sessionTracker: TcpSessionTracker = TcpSessionTracker()
) {
    companion object {
        private const val TAG = "VpnPacketProcessor"
    }

    /**
     * 处理从 TUN 虚拟网卡读取的一个原始 IP 数据包。
     *
     * @param buffer 包含 IP 数据包的缓冲区
     * @param length 数据包有效字节数
     */
    fun processPacket(buffer: ByteArray, length: Int) {
        if (length <= 0) return

        try {
            val ipPacket = IpPacket.parse(buffer, 0, length) ?: return

            when (ipPacket.protocol) {
                IpPacket.PROTOCOL_UDP -> processUdpPacket(ipPacket)
                IpPacket.PROTOCOL_TCP -> processTcpPacket(ipPacket)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error processing packet: ${e.message}", e)
        }
    }

    private fun processUdpPacket(ipPacket: IpPacket) {
        val udpPacket = UdpPacket.parse(ipPacket) ?: return

        // 仅拦截并嗅探 DNS 查询与应答 (端口 53)
        if (udpPacket.srcPort == UdpPacket.DNS_PORT || udpPacket.dstPort == UdpPacket.DNS_PORT) {
            val dns = DnsPacket.parse(udpPacket) ?: return
            if (dns.isResponse) {
                for (ans in dns.answers) {
                    val addr = ans.address
                    if (addr != null && ans.name.isNotEmpty()) {
                        dnsCache.record(addr, ans.name)
                    }
                }
            } else {
                val qName = dns.primaryQuestionName
                if (!qName.isNullOrEmpty()) {
                    dnsCache.record(ipPacket.dstAddress, qName)
                }
            }
        }
    }

    private fun processTcpPacket(ipPacket: IpPacket) {
        val tcpPacket = TcpPacket.parse(ipPacket) ?: return

        val srcIp = ipPacket.srcAddress
        val srcPort = tcpPacket.srcPort
        val dstIp = ipPacket.dstAddress
        val dstPort = tcpPacket.dstPort

        // 1. 握手与终止管理
        if (tcpPacket.isSyn && !tcpPacket.isAck) {
            sessionTracker.getOrCreateSession(srcIp, srcPort, dstIp, dstPort)
            return
        }

        if (tcpPacket.isFin || tcpPacket.isRst) {
            sessionTracker.removeSession(srcIp, srcPort, dstIp, dstPort)
            sessionTracker.removeSession(dstIp, dstPort, srcIp, srcPort)
            return
        }

        val payload = tcpPacket.getPayload()
        if (payload.isEmpty()) return

        // 2. 查找所属会话
        val sessionPair = sessionTracker.findSession(srcIp, srcPort, dstIp, dstPort)
        val session = sessionPair?.first ?: sessionTracker.getOrCreateSession(srcIp, srcPort, dstIp, dstPort)
        val isUplink = sessionPair?.second ?: true

        if (isUplink) {
            handleUplinkPayload(session, ipPacket, tcpPacket, payload)
        } else {
            handleDownlinkPayload(session, ipPacket, tcpPacket, payload)
        }
    }

    private fun handleUplinkPayload(
        session: com.agent.use.client.network.vpn.session.TcpSession,
        ipPacket: IpPacket,
        tcpPacket: TcpPacket,
        payload: ByteArray
    ) {
        val result = session.appendUplink(payload, config.maxBodySizeBytes)
        when (result) {
            is UplinkParseResult.TlsHandshake -> {
                // 嗅探到 TLS Client Hello 握手报文，提取 SNI 域名
                val host = result.sni ?: dnsCache.getDomain(ipPacket.dstAddress) ?: ipPacket.dstAddress
                val portSuffix = if (tcpPacket.dstPort == 443) "" else ":${tcpPacket.dstPort}"
                val url = "https://$host$portSuffix/"
                session.activeRequestUrl = url

                if (config.matchesUrl(url)) {
                    val requestEvent = HttpRequestEvent(
                        requestId = result.requestId,
                        timestamp = System.currentTimeMillis(),
                        url = url,
                        method = "CONNECT",
                        headers = listOf(
                            HttpHeader("Host", host),
                            HttpHeader("X-Capture-Mode", "VpnService-SNI")
                        ),
                        postData = null,
                        isTls = true
                    )
                    safeDispatch { listener.onRequestWillBeSent(requestEvent) }
                }
            }
            is UplinkParseResult.HttpRequest -> {
                // 嗅探到 HTTP/1.x 请求
                val req = result.data
                val host = req.headers.getIgnoreCase("Host")
                    ?: dnsCache.getDomain(ipPacket.dstAddress)
                    ?: ipPacket.dstAddress
                val portSuffix = if (tcpPacket.dstPort == 80) "" else ":${tcpPacket.dstPort}"
                val url = if (req.uri.startsWith("http://") || req.uri.startsWith("https://")) {
                    req.uri
                } else {
                    "http://$host$portSuffix${req.uri}"
                }
                session.activeRequestUrl = url

                if (config.matchesUrl(url)) {
                    val postDataText = if (req.body.isNotEmpty()) {
                        try {
                            String(req.body, Charsets.UTF_8)
                        } catch (_: Exception) {
                            null
                        }
                    } else null

                    val requestEvent = HttpRequestEvent(
                        requestId = result.requestId,
                        timestamp = System.currentTimeMillis(),
                        url = url,
                        method = req.method,
                        headers = req.headers,
                        postData = postDataText,
                        isTls = false
                    )
                    safeDispatch { listener.onRequestWillBeSent(requestEvent) }
                }
            }
            is UplinkParseResult.None -> {
                // 尚在缓冲或非 HTTP 请求
            }
        }
    }

    private fun handleDownlinkPayload(
        session: com.agent.use.client.network.vpn.session.TcpSession,
        ipPacket: IpPacket,
        tcpPacket: TcpPacket,
        payload: ByteArray
    ) {
        val result = session.appendDownlink(payload, config.maxBodySizeBytes)
        when (result) {
            is DownlinkParseResult.HttpResponse -> {
                val resp = result.data
                val url = session.activeRequestUrl
                    ?: "http://${dnsCache.getDomain(ipPacket.srcAddress) ?: ipPacket.srcAddress}:${tcpPacket.srcPort}/"

                if (config.matchesUrl(url)) {
                    val responseEvent = HttpResponseEvent(
                        requestId = result.requestId,
                        timestamp = System.currentTimeMillis(),
                        url = url,
                        statusCode = resp.statusCode,
                        statusText = resp.statusText,
                        headers = resp.headers,
                        mimeType = resp.mimeType,
                        contentLength = resp.contentLength,
                        fromCache = false
                    )
                    safeDispatch { listener.onResponseReceived(responseEvent) }

                    if (resp.body.isNotEmpty()) {
                        safeDispatch { listener.onDataChunkReceived(result.requestId, resp.body) }
                        sessionTracker.cacheResponseBody(result.requestId, resp.body)
                    }
                }
            }
            is DownlinkParseResult.None -> {
                // 尚在缓冲或非 HTTP 响应
            }
        }
    }

    /**
     * 获取指定请求关联的完整响应体缓存。
     */
    fun getResponseBody(requestId: String): ByteArray? =
        sessionTracker.getResponseBody(requestId)

    /**
     * 重置并清空所有状态。
     */
    fun reset() {
        sessionTracker.clear()
        dnsCache.clear()
    }

    private inline fun safeDispatch(action: () -> Unit) {
        try {
            action()
        } catch (e: Exception) {
            Log.w(TAG, "Listener callback error: ${e.message}", e)
        }
    }
}
