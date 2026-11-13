package com.agent.use.client.network.vpn

import com.agent.use.client.network.vpn.parser.DnsPacket
import com.agent.use.client.network.vpn.parser.HttpPacket
import com.agent.use.client.network.vpn.parser.IpPacket
import com.agent.use.client.network.vpn.parser.TcpPacket
import com.agent.use.client.network.vpn.parser.TlsPacket
import com.agent.use.client.network.vpn.parser.UdpPacket
import com.agent.use.client.network.vpn.processor.VpnPacketProcessor
import com.agent.use.common.network.CaptureMode
import com.agent.use.common.network.HttpRequestEvent
import com.agent.use.common.network.HttpResponseEvent
import com.agent.use.common.network.INetworkEventListener
import com.agent.use.common.network.NetworkCaptureConfig
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.net.InetAddress

class VpnPacketCaptureTest {

    // ==========================================
    // 1. IP 数据包解析测试 (IPv4 & IPv6)
    // ==========================================

    @Test
    fun testIpPacketParseIPv4() {
        val payload = "Hello IPv4".toByteArray()
        val packetBytes = buildIpv4Packet("10.0.0.2", "93.184.216.34", IpPacket.PROTOCOL_TCP, payload)

        val packet = IpPacket.parse(packetBytes, 0, packetBytes.size)
        assertNotNull(packet)
        assertEquals(4, packet!!.version)
        assertEquals(IpPacket.PROTOCOL_TCP, packet.protocol)
        assertEquals("10.0.0.2", packet.srcAddress)
        assertEquals("93.184.216.34", packet.dstAddress)
        assertEquals(20, packet.headerLength)
        assertEquals(packetBytes.size, packet.totalLength)
        assertEquals(payload.size, packet.payloadLength)
    }

    @Test
    fun testIpPacketParseIPv6() {
        val payload = "Hello IPv6".toByteArray()
        val packetBytes = buildIpv6Packet("2001:db8::1", "2001:db8::2", IpPacket.PROTOCOL_UDP, payload)

        val packet = IpPacket.parse(packetBytes, 0, packetBytes.size)
        assertNotNull(packet)
        assertEquals(6, packet!!.version)
        assertEquals(IpPacket.PROTOCOL_UDP, packet.protocol)
        assertTrue(packet.srcAddress.contains("2001:db8"))
        assertTrue(packet.dstAddress.contains("2001:db8"))
        assertEquals(40, packet.headerLength)
        assertEquals(payload.size, packet.payloadLength)
    }

    @Test
    fun testIpPacketMalformedReturnsNull() {
        val malformed = ByteArray(10) // 长度不足 20 字节
        assertNull(IpPacket.parse(malformed, 0, malformed.size))
    }

    // ==========================================
    // 2. TCP 数据包解析测试
    // ==========================================

    @Test
    fun testTcpPacketParse() {
        val tcpPayload = "GET / HTTP/1.1\r\n\r\n".toByteArray()
        val tcpBytes = buildTcpSegment(12345, 80, 1001L, 2001L, TcpPacket.FLAG_ACK or TcpPacket.FLAG_PSH, tcpPayload)
        val ipBytes = buildIpv4Packet("10.0.0.2", "93.184.216.34", IpPacket.PROTOCOL_TCP, tcpBytes)

        val ipPacket = IpPacket.parse(ipBytes, 0, ipBytes.size)
        assertNotNull(ipPacket)

        val tcpPacket = TcpPacket.parse(ipPacket!!)
        assertNotNull(tcpPacket)
        assertEquals(12345, tcpPacket!!.srcPort)
        assertEquals(80, tcpPacket.dstPort)
        assertEquals(1001L, tcpPacket.seqNumber)
        assertEquals(2001L, tcpPacket.ackNumber)
        assertTrue(tcpPacket.isAck)
        assertTrue(tcpPacket.isPsh)
        assertFalse(tcpPacket.isSyn)
        assertFalse(tcpPacket.isFin)
        assertEquals(tcpPayload.size, tcpPacket.payloadLength)
        assertArrayEquals(tcpPayload, tcpPacket.getPayload())
    }

    // ==========================================
    // 3. UDP 数据包解析测试
    // ==========================================

    @Test
    fun testUdpPacketParse() {
        val udpPayload = "DNS Query".toByteArray()
        val udpBytes = buildUdpDatagram(54321, 53, udpPayload)
        val ipBytes = buildIpv4Packet("10.0.0.2", "8.8.8.8", IpPacket.PROTOCOL_UDP, udpBytes)

        val ipPacket = IpPacket.parse(ipBytes, 0, ipBytes.size)
        assertNotNull(ipPacket)

        val udpPacket = UdpPacket.parse(ipPacket!!)
        assertNotNull(udpPacket)
        assertEquals(54321, udpPacket!!.srcPort)
        assertEquals(53, udpPacket.dstPort)
        assertEquals(udpPayload.size, udpPacket.payloadLength)
        assertArrayEquals(udpPayload, udpPacket.getPayload())
    }

    // ==========================================
    // 4. DNS 解析与 IP-域名绑定测试
    // ==========================================

    @Test
    fun testDnsQueryAndResponse() {
        val domain = "api.github.com"
        val resolvedIp = "140.82.112.22"

        // 构造 DNS 查询
        val queryBytes = buildDnsQuery(0x1234, domain)
        val queryDns = DnsPacket.parse(queryBytes, 0, queryBytes.size)
        assertNotNull(queryDns)
        assertEquals(0x1234, queryDns!!.transactionId)
        assertFalse(queryDns.isResponse)
        assertEquals(1, queryDns.questions.size)
        assertEquals(domain, queryDns.primaryQuestionName)

        // 构造 DNS 应答 (含指针压缩 0xC0)
        val respBytes = buildDnsResponse(0x1234, domain, resolvedIp)
        val respDns = DnsPacket.parse(respBytes, 0, respBytes.size)
        assertNotNull(respDns)
        assertTrue(respDns!!.isResponse)
        assertEquals(1, respDns.answers.size)
        assertEquals(domain, respDns.answers[0].name)
        assertEquals(resolvedIp, respDns.answers[0].address)
    }

    // ==========================================
    // 5. TLS Client Hello (SNI) 嗅探测试
    // ==========================================

    @Test
    fun testTlsClientHelloSniExtraction() {
        val sniHost = "api.anthropic.com"
        val tlsRecord = buildTlsClientHello(sniHost)

        assertTrue(TlsPacket.isClientHello(tlsRecord))
        val hello = TlsPacket.parseClientHello(tlsRecord)
        assertNotNull(hello)
        assertEquals(sniHost, hello!!.sni)
        assertEquals(0x0303, hello.tlsVersion)
    }

    @Test
    fun testNonTlsReturnsNull() {
        val httpData = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".toByteArray()
        assertFalse(TlsPacket.isClientHello(httpData))
        assertNull(TlsPacket.parseClientHello(httpData))
    }

    // ==========================================
    // 6. HTTP/1.x 请求与响应解析测试
    // ==========================================

    @Test
    fun testHttpRequestParsing() {
        val rawHttp = "POST /api/v1/chat HTTP/1.1\r\n" +
                "Host: api.example.com\r\n" +
                "Content-Type: application/json\r\n" +
                "Content-Length: 18\r\n" +
                "\r\n" +
                "{\"prompt\":\"hello\"}"
        val bytes = rawHttp.toByteArray(Charsets.UTF_8)

        assertTrue(HttpPacket.isHttpRequest(bytes))
        val req = HttpPacket.parseRequest(bytes)
        assertNotNull(req)
        assertEquals("POST", req!!.method)
        assertEquals("/api/v1/chat", req.uri)
        assertEquals("HTTP/1.1", req.version)
        assertEquals(18L, req.contentLength)
        assertEquals("{\"prompt\":\"hello\"}", String(req.body, Charsets.UTF_8))
    }

    @Test
    fun testHttpResponseParsing() {
        val rawHttp = "HTTP/1.1 200 OK\r\n" +
                "Content-Type: application/json; charset=utf-8\r\n" +
                "Content-Length: 20\r\n" +
                "\r\n" +
                "{\"status\":\"success\"}"
        val bytes = rawHttp.toByteArray(Charsets.UTF_8)

        assertTrue(HttpPacket.isHttpResponse(bytes))
        val resp = HttpPacket.parseResponse(bytes)
        assertNotNull(resp)
        assertEquals(200, resp!!.statusCode)
        assertEquals("OK", resp.statusText)
        assertEquals("application/json", resp.mimeType)
        assertEquals("{\"status\":\"success\"}", String(resp.body, Charsets.UTF_8))
    }

    // ==========================================
    // 7. VpnPacketProcessor 端到端完整流水线测试
    // ==========================================

    @Test
    fun testVpnPacketProcessorEndToEnd() {
        val capturedRequests = mutableListOf<HttpRequestEvent>()
        val capturedResponses = mutableListOf<HttpResponseEvent>()
        val capturedChunks = mutableListOf<Pair<String, ByteArray>>()

        val listener = object : INetworkEventListener.Stub() {
            override fun onRequestWillBeSent(request: HttpRequestEvent) {
                capturedRequests.add(request)
            }
            override fun onResponseReceived(response: HttpResponseEvent) {
                capturedResponses.add(response)
            }
            override fun onDataChunkReceived(requestId: String, chunk: ByteArray) {
                capturedChunks.add(Pair(requestId, chunk))
            }
            override fun onErrorOccurred(requestId: String, errorMsg: String) {}
        }

        val config = NetworkCaptureConfig(
            targetPackage = "com.example.testapp",
            urlFilterPattern = ".*example\\.com.*"
        )
        val processor = VpnPacketProcessor(config = config, listener = listener)

        // 阶段 1：模拟接收 DNS 应答，将 93.184.216.34 映射到 example.com
        val dnsResp = buildDnsResponse(0x4321, "example.com", "93.184.216.34")
        val udpDns = buildUdpDatagram(53, 49152, dnsResp)
        val ipDns = buildIpv4Packet("8.8.8.8", "10.0.0.2", IpPacket.PROTOCOL_UDP, udpDns)
        processor.processPacket(ipDns, ipDns.size)
        assertEquals("example.com", processor.dnsCache.getDomain("93.184.216.34"))

        // 阶段 2：模拟 TLS 握手 (Client Hello 到 93.184.216.34:443)
        val tlsHello = buildTlsClientHello("api.example.com")
        val tcpTls = buildTcpSegment(49153, 443, 100L, 0L, TcpPacket.FLAG_PSH or TcpPacket.FLAG_ACK, tlsHello)
        val ipTls = buildIpv4Packet("10.0.0.2", "93.184.216.34", IpPacket.PROTOCOL_TCP, tcpTls)
        processor.processPacket(ipTls, ipTls.size)

        assertEquals(1, capturedRequests.size)
        val tlsReq = capturedRequests[0]
        assertEquals("CONNECT", tlsReq.method)
        assertEquals("https://api.example.com/", tlsReq.url)
        assertTrue(tlsReq.isTls)

        // 阶段 3：模拟 HTTP 明文请求与响应
        val httpRequest = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n".toByteArray()
        val tcpHttpReq = buildTcpSegment(49154, 80, 200L, 0L, TcpPacket.FLAG_PSH or TcpPacket.FLAG_ACK, httpRequest)
        val ipHttpReq = buildIpv4Packet("10.0.0.2", "93.184.216.34", IpPacket.PROTOCOL_TCP, tcpHttpReq)
        processor.processPacket(ipHttpReq, ipHttpReq.size)

        assertEquals(2, capturedRequests.size)
        val httpReq = capturedRequests[1]
        assertEquals("GET", httpReq.method)
        assertEquals("http://example.com/index.html", httpReq.url)
        assertFalse(httpReq.isTls)

        // 响应到来 (由服务端 93.184.216.34:80 下发给 10.0.0.2:49154)
        val httpResponseBody = "<html>Hello AAU</html>".toByteArray()
        val httpResponse = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: ${httpResponseBody.size}\r\n\r\n"
            .toByteArray() + httpResponseBody
        val tcpHttpResp = buildTcpSegment(80, 49154, 1000L, 200L + httpRequest.size, TcpPacket.FLAG_PSH or TcpPacket.FLAG_ACK, httpResponse)
        val ipHttpResp = buildIpv4Packet("93.184.216.34", "10.0.0.2", IpPacket.PROTOCOL_TCP, tcpHttpResp)
        processor.processPacket(ipHttpResp, ipHttpResp.size)

        assertEquals(1, capturedResponses.size)
        val resp = capturedResponses[0]
        assertEquals(httpReq.requestId, resp.requestId)
        assertEquals(200, resp.statusCode)
        assertEquals("OK", resp.statusText)
        assertEquals("text/html", resp.mimeType)

        // 验证响应体缓存与 getResponseBody
        val cachedBody = processor.getResponseBody(httpReq.requestId)
        assertNotNull(cachedBody)
        assertEquals("<html>Hello AAU</html>", String(cachedBody!!))
    }

    // ==========================================
    // 8. VpnCaptureEngine 契约与生命周期测试
    // ==========================================

    @Test
    fun testVpnCaptureEngineLifecycle() {
        val engine = VpnCaptureEngine()
        assertEquals(CaptureMode.ACTIVE_MODE_NONE, engine.activeMode)
        assertFalse(engine.isCapturing())

        var errorReceived: String? = null
        val listener = object : INetworkEventListener.Stub() {
            override fun onRequestWillBeSent(request: HttpRequestEvent) {}
            override fun onResponseReceived(response: HttpResponseEvent) {}
            override fun onDataChunkReceived(requestId: String, chunk: ByteArray) {}
            override fun onErrorOccurred(requestId: String, errorMsg: String) {
                errorReceived = errorMsg
            }
        }

        // 测试包名为空时拒绝启动
        val emptyConfig = NetworkCaptureConfig(targetPackage = "")
        val startedFail = engine.startCapture(emptyConfig, listener)
        assertFalse(startedFail)
        assertNotNull(errorReceived)

        // 正常测试模式启动
        val config = NetworkCaptureConfig(targetPackage = "com.test.app")
        val started = engine.startCapture(config, listener)
        assertTrue(started)
        assertTrue(engine.isCapturing())
        assertEquals(CaptureMode.ACTIVE_MODE_VPN_SERVICE, engine.activeMode)

        // 停止
        engine.stopCapture()
        assertFalse(engine.isCapturing())
        assertEquals(CaptureMode.ACTIVE_MODE_NONE, engine.activeMode)
    }

    // ==========================================
    // 9. 分片流式 TCP 重组测试
    // ==========================================

    @Test
    fun testFragmentedTcpStreamReassembly() {
        val capturedRequests = mutableListOf<HttpRequestEvent>()
        val listener = object : INetworkEventListener.Stub() {
            override fun onRequestWillBeSent(request: HttpRequestEvent) {
                capturedRequests.add(request)
            }
            override fun onResponseReceived(response: HttpResponseEvent) {}
            override fun onDataChunkReceived(requestId: String, chunk: ByteArray) {}
            override fun onErrorOccurred(requestId: String, errorMsg: String) {}
        }

        val config = NetworkCaptureConfig(targetPackage = "com.fragment.test")
        val processor = VpnPacketProcessor(config = config, listener = listener)

        // 分片 1：仅包含请求行及部分 Header，未遇到 \r\n\r\n
        val part1 = "POST /api/v2/stream HTTP/1.1\r\nHost: fragment.example.com\r\n".toByteArray()
        val tcp1 = buildTcpSegment(50001, 80, 100L, 0L, TcpPacket.FLAG_ACK, part1)
        val ip1 = buildIpv4Packet("10.0.0.2", "93.184.216.34", IpPacket.PROTOCOL_TCP, tcp1)
        processor.processPacket(ip1, ip1.size)

        // 此时流未完成，不应触发回调
        assertEquals(0, capturedRequests.size)

        // 分片 2：包含剩余 Header 与 \r\n\r\n 以及正文
        val part2 = "Content-Length: 5\r\n\r\nhello".toByteArray()
        val tcp2 = buildTcpSegment(50001, 80, 100L + part1.size, 0L, TcpPacket.FLAG_ACK or TcpPacket.FLAG_PSH, part2)
        val ip2 = buildIpv4Packet("10.0.0.2", "93.184.216.34", IpPacket.PROTOCOL_TCP, tcp2)
        processor.processPacket(ip2, ip2.size)

        // 两段拼接完成后，成功解析出完整请求并触发回调
        assertEquals(1, capturedRequests.size)
        val req = capturedRequests[0]
        assertEquals("POST", req.method)
        assertEquals("http://fragment.example.com/api/v2/stream", req.url)
        assertEquals("hello", req.postData)
    }

    // ==========================================
    // 10. URL 正则匹配过滤测试
    // ==========================================

    @Test
    fun testUrlPatternFiltering() {
        val capturedUrls = mutableListOf<String>()
        val listener = object : INetworkEventListener.Stub() {
            override fun onRequestWillBeSent(request: HttpRequestEvent) {
                capturedUrls.add(request.url)
            }
            override fun onResponseReceived(response: HttpResponseEvent) {}
            override fun onDataChunkReceived(requestId: String, chunk: ByteArray) {}
            override fun onErrorOccurred(requestId: String, errorMsg: String) {}
        }

        // 仅匹配 *.allowed.com 的流量
        val config = NetworkCaptureConfig(
            targetPackage = "com.filter.test",
            urlFilterPattern = ".*\\.allowed\\.com/.*"
        )
        val processor = VpnPacketProcessor(config = config, listener = listener)

        // 发送未被白名单匹配的请求 (blocked.com)
        val reqBlocked = "GET /index HTTP/1.1\r\nHost: blocked.com\r\n\r\n".toByteArray()
        val tcpBlocked = buildTcpSegment(50002, 80, 10L, 0L, TcpPacket.FLAG_PSH or TcpPacket.FLAG_ACK, reqBlocked)
        val ipBlocked = buildIpv4Packet("10.0.0.2", "1.1.1.1", IpPacket.PROTOCOL_TCP, tcpBlocked)
        processor.processPacket(ipBlocked, ipBlocked.size)

        assertEquals(0, capturedUrls.size)

        // 发送匹配白名单的请求 (api.allowed.com)
        val reqAllowed = "GET /api/v1 HTTP/1.1\r\nHost: api.allowed.com\r\n\r\n".toByteArray()
        val tcpAllowed = buildTcpSegment(50003, 80, 20L, 0L, TcpPacket.FLAG_PSH or TcpPacket.FLAG_ACK, reqAllowed)
        val ipAllowed = buildIpv4Packet("10.0.0.2", "2.2.2.2", IpPacket.PROTOCOL_TCP, tcpAllowed)
        processor.processPacket(ipAllowed, ipAllowed.size)

        assertEquals(1, capturedUrls.size)
        assertEquals("http://api.allowed.com/api/v1", capturedUrls[0])
    }

    // ==========================================
    // 11. TCP 会话关闭清理测试 (FIN / RST)
    // ==========================================

    @Test
    fun testTcpSessionFinRstCleanup() {
        val listener = object : INetworkEventListener.Stub() {
            override fun onRequestWillBeSent(request: HttpRequestEvent) {}
            override fun onResponseReceived(response: HttpResponseEvent) {}
            override fun onDataChunkReceived(requestId: String, chunk: ByteArray) {}
            override fun onErrorOccurred(requestId: String, errorMsg: String) {}
        }

        val config = NetworkCaptureConfig(targetPackage = "com.cleanup.test")
        val processor = VpnPacketProcessor(config = config, listener = listener)

        // 1. 发起握手 SYN
        val tcpSyn = buildTcpSegment(50010, 80, 1L, 0L, TcpPacket.FLAG_SYN, ByteArray(0))
        val ipSyn = buildIpv4Packet("10.0.0.2", "3.3.3.3", IpPacket.PROTOCOL_TCP, tcpSyn)
        processor.processPacket(ipSyn, ipSyn.size)

        assertEquals(1, processor.sessionTracker.activeSessionCount)

        // 2. 发送 FIN 终止连接
        val tcpFin = buildTcpSegment(50010, 80, 2L, 1L, TcpPacket.FLAG_FIN or TcpPacket.FLAG_ACK, ByteArray(0))
        val ipFin = buildIpv4Packet("10.0.0.2", "3.3.3.3", IpPacket.PROTOCOL_TCP, tcpFin)
        processor.processPacket(ipFin, ipFin.size)

        assertEquals(0, processor.sessionTracker.activeSessionCount)
    }

    // ==========================================
    // 12. DNS 关联与 Host Hint 传播测试 (消除 localhost)
    // ==========================================

    @Test
    fun testDnsAssociationAndHostHintPropagationWithoutSni() {
        val capturedRequests = mutableListOf<HttpRequestEvent>()
        val listener = object : INetworkEventListener.Stub() {
            override fun onRequestWillBeSent(request: HttpRequestEvent) {
                capturedRequests.add(request)
            }
            override fun onResponseReceived(response: HttpResponseEvent) {}
            override fun onDataChunkReceived(requestId: String, chunk: ByteArray) {}
            override fun onErrorOccurred(requestId: String, errorMsg: String) {}
        }

        val config = NetworkCaptureConfig(targetPackage = "com.xingin.xhs")
        val processor = VpnPacketProcessor(config = config, listener = listener)

        // 1. 模拟 DNS 解析 110.242.68.66 -> api.xiaohongshu.com
        val dnsResp = buildDnsResponse(0x7788, "api.xiaohongshu.com", "110.242.68.66")
        val udpDns = buildUdpDatagram(53, 52100, dnsResp)
        val ipDns = buildIpv4Packet("8.8.8.8", "10.0.0.2", IpPacket.PROTOCOL_UDP, udpDns)
        processor.processPacket(ipDns, ipDns.size)
        assertEquals("api.xiaohongshu.com", processor.dnsCache.getDomain("110.242.68.66"))

        // 2. 模拟客户端发送无 SNI 的 TLS ClientHello 到 110.242.68.66:443
        val tlsNoSni = buildTlsClientHelloWithoutSni()
        val tcpTls = buildTcpSegment(52101, 443, 100L, 0L, TcpPacket.FLAG_PSH or TcpPacket.FLAG_ACK, tlsNoSni)
        val ipTls = buildIpv4Packet("10.0.0.2", "110.242.68.66", IpPacket.PROTOCOL_TCP, tcpTls)
        processor.processPacket(ipTls, ipTls.size)

        assertEquals(1, capturedRequests.size)
        val tlsReq = capturedRequests[0]
        assertEquals("CONNECT", tlsReq.method)
        // 必须优先使用从 DNS 继承的 HostHint，绝不能变成 https://localhost/ 或纯 IP
        assertEquals("https://api.xiaohongshu.com/", tlsReq.url)
        assertTrue(tlsReq.isTls)
    }

    // ==========================================
    // 13. HTTP Host 带端口及 HTTP/2 Preface 识别测试
    // ==========================================

    @Test
    fun testHttpHostWithPortAndHttp2PrefaceRecognition() {
        val capturedRequests = mutableListOf<HttpRequestEvent>()
        val listener = object : INetworkEventListener.Stub() {
            override fun onRequestWillBeSent(request: HttpRequestEvent) {
                capturedRequests.add(request)
            }
            override fun onResponseReceived(response: HttpResponseEvent) {}
            override fun onDataChunkReceived(requestId: String, chunk: ByteArray) {}
            override fun onErrorOccurred(requestId: String, errorMsg: String) {}
        }

        val config = NetworkCaptureConfig(targetPackage = "com.xingin.xhs")
        val processor = VpnPacketProcessor(config = config, listener = listener)

        // 0. 先模拟 DNS 解析绑定 110.242.68.66 -> api.xiaohongshu.com
        val dnsResp = buildDnsResponse(0x9988, "api.xiaohongshu.com", "110.242.68.66")
        val udpDns = buildUdpDatagram(53, 53000, dnsResp)
        val ipDns = buildIpv4Packet("8.8.8.8", "10.0.0.2", IpPacket.PROTOCOL_UDP, udpDns)
        processor.processPacket(ipDns, ipDns.size)

        // 1. 发送带有端口的 Host 头 (api.xiaohongshu.com:8080) 到 8080 端口
        val rawHttpWithPort = "GET /api/v1/feed HTTP/1.1\r\nHost: api.xiaohongshu.com:8080\r\n\r\n".toByteArray()
        val tcpReqWithPort = buildTcpSegment(53001, 8080, 10L, 0L, TcpPacket.FLAG_PSH or TcpPacket.FLAG_ACK, rawHttpWithPort)
        val ipReqWithPort = buildIpv4Packet("10.0.0.2", "110.242.68.66", IpPacket.PROTOCOL_TCP, tcpReqWithPort)
        processor.processPacket(ipReqWithPort, ipReqWithPort.size)

        assertEquals(1, capturedRequests.size)
        // 绝不应该出现 :8080:8080 重复端口
        assertEquals("http://api.xiaohongshu.com:8080/api/v1/feed", capturedRequests[0].url)

        // 2. 发送 HTTP/2 Client Preface
        val h2Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".toByteArray(Charsets.US_ASCII)
        val tcpH2 = buildTcpSegment(53002, 80, 1L, 0L, TcpPacket.FLAG_PSH or TcpPacket.FLAG_ACK, h2Preface)
        val ipH2 = buildIpv4Packet("10.0.0.2", "110.242.68.66", IpPacket.PROTOCOL_TCP, tcpH2)
        processor.processPacket(ipH2, ipH2.size)

        assertEquals(2, capturedRequests.size)
        val h2Req = capturedRequests[1]
        assertEquals("PRI", h2Req.method)
        assertEquals("http://api.xiaohongshu.com/", h2Req.url)
        assertTrue(h2Req.headers.any { it.name == "X-Capture-Mode" && it.value == "VpnService-H2C" })
    }

    // ==========================================
    // 14. QUIC (UDP 443) ICMP Port Unreachable 测试
    // ==========================================

    @Test
    fun testQuicUdp443IcmpPortUnreachable() {
        val quicPayload = ByteArray(64) { 0x42 }
        val udpQuic = buildUdpDatagram(49999, 443, quicPayload)
        val ipQuic = buildIpv4Packet("10.0.0.2", "142.250.190.46", IpPacket.PROTOCOL_UDP, udpQuic)

        val icmpPkt = VpnTunForwarder.buildIpv4IcmpPortUnreachable(ipQuic, ipQuic.size)
        assertNotNull(icmpPkt)

        val parsedIp = IpPacket.parse(icmpPkt!!, 0, icmpPkt.size)
        assertNotNull(parsedIp)
        assertEquals(4, parsedIp!!.version)
        assertEquals(IpPacket.PROTOCOL_ICMP, parsedIp.protocol)
        // 源地址与目的地址对调
        assertEquals("142.250.190.46", parsedIp.srcAddress)
        assertEquals("10.0.0.2", parsedIp.dstAddress)

        // ICMP Type 3, Code 3
        val icmpType = icmpPkt[20].toInt() and 0xFF
        val icmpCode = icmpPkt[21].toInt() and 0xFF
        assertEquals(3, icmpType) // Destination Unreachable
        assertEquals(3, icmpCode) // Port Unreachable
    }

    // ==========================================
    // 辅助合成数据包函数
    // ==========================================

    private fun buildIpv4Packet(srcIp: String, dstIp: String, protocol: Int, payload: ByteArray): ByteArray {
        val totalLength = 20 + payload.size
        val out = ByteArrayOutputStream()
        out.write(0x45) // Version 4, IHL 5 (20 bytes)
        out.write(0x00) // DSCP/ECN
        out.write((totalLength ushr 8) and 0xFF)
        out.write(totalLength and 0xFF)
        out.write(0x12) // ID
        out.write(0x34)
        out.write(0x40) // Flags (DF)
        out.write(0x00)
        out.write(64)   // TTL
        out.write(protocol and 0xFF)
        out.write(0x00) // Checksum
        out.write(0x00)
        out.write(InetAddress.getByName(srcIp).address)
        out.write(InetAddress.getByName(dstIp).address)
        out.write(payload)
        return out.toByteArray()
    }

    private fun buildIpv6Packet(srcIp: String, dstIp: String, nextHeader: Int, payload: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(0x60) // Version 6
        out.write(0x00)
        out.write(0x00)
        out.write(0x00)
        out.write((payload.size ushr 8) and 0xFF)
        out.write(payload.size and 0xFF)
        out.write(nextHeader and 0xFF)
        out.write(64)   // Hop Limit
        out.write(InetAddress.getByName(srcIp).address)
        out.write(InetAddress.getByName(dstIp).address)
        out.write(payload)
        return out.toByteArray()
    }

    private fun buildTcpSegment(
        srcPort: Int,
        dstPort: Int,
        seq: Long,
        ack: Long,
        flags: Int,
        payload: ByteArray
    ): ByteArray {
        val out = ByteArrayOutputStream()
        out.write((srcPort ushr 8) and 0xFF)
        out.write(srcPort and 0xFF)
        out.write((dstPort ushr 8) and 0xFF)
        out.write(dstPort and 0xFF)
        // Seq
        out.write(((seq ushr 24) and 0xFF).toInt())
        out.write(((seq ushr 16) and 0xFF).toInt())
        out.write(((seq ushr 8) and 0xFF).toInt())
        out.write((seq and 0xFF).toInt())
        // Ack
        out.write(((ack ushr 24) and 0xFF).toInt())
        out.write(((ack ushr 16) and 0xFF).toInt())
        out.write(((ack ushr 8) and 0xFF).toInt())
        out.write((ack and 0xFF).toInt())
        // Data offset (5 words = 20 bytes)
        out.write(0x50)
        out.write(flags and 0xFF)
        // Window size (65535)
        out.write(0xFF)
        out.write(0xFF)
        // Checksum
        out.write(0x00)
        out.write(0x00)
        // Urgent pointer
        out.write(0x00)
        out.write(0x00)
        out.write(payload)
        return out.toByteArray()
    }

    private fun buildUdpDatagram(srcPort: Int, dstPort: Int, payload: ByteArray): ByteArray {
        val totalLength = 8 + payload.size
        val out = ByteArrayOutputStream()
        out.write((srcPort ushr 8) and 0xFF)
        out.write(srcPort and 0xFF)
        out.write((dstPort ushr 8) and 0xFF)
        out.write(dstPort and 0xFF)
        out.write((totalLength ushr 8) and 0xFF)
        out.write(totalLength and 0xFF)
        out.write(0x00)
        out.write(0x00)
        out.write(payload)
        return out.toByteArray()
    }

    private fun buildTlsClientHello(sni: String): ByteArray {
        val sniBytes = sni.toByteArray(Charsets.US_ASCII)
        val sniExtData = ByteArrayOutputStream().apply {
            write(((3 + sniBytes.size) ushr 8) and 0xFF)
            write((3 + sniBytes.size) and 0xFF)
            write(0) // HostName type
            write((sniBytes.size ushr 8) and 0xFF)
            write(sniBytes.size and 0xFF)
            write(sniBytes)
        }.toByteArray()

        val extensionsData = ByteArrayOutputStream().apply {
            write(0x00) // Type 0x0000 (SNI)
            write(0x00)
            write((sniExtData.size ushr 8) and 0xFF)
            write(sniExtData.size and 0xFF)
            write(sniExtData)
        }.toByteArray()

        val clientHelloBody = ByteArrayOutputStream().apply {
            write(0x03) // Version 0x0303
            write(0x03)
            write(ByteArray(32)) // Random
            write(0) // Session ID length
            write(0x00) // Cipher Suites length = 2
            write(0x02)
            write(0x13)
            write(0x01)
            write(0x01) // Compression length = 1
            write(0x00)
            write((extensionsData.size ushr 8) and 0xFF)
            write(extensionsData.size and 0xFF)
            write(extensionsData)
        }.toByteArray()

        val handshakeLen = clientHelloBody.size
        val handshakeRecord = ByteArrayOutputStream().apply {
            write(0x01) // Client Hello
            write((handshakeLen ushr 16) and 0xFF)
            write((handshakeLen ushr 8) and 0xFF)
            write(handshakeLen and 0xFF)
            write(clientHelloBody)
        }.toByteArray()

        val tlsRecord = ByteArrayOutputStream().apply {
            write(0x16) // Handshake
            write(0x03) // TLS 1.0 record version
            write(0x01)
            write((handshakeRecord.size ushr 8) and 0xFF)
            write(handshakeRecord.size and 0xFF)
            write(handshakeRecord)
        }.toByteArray()

        return tlsRecord
    }

    private fun buildTlsClientHelloWithoutSni(): ByteArray {
        val clientHelloBody = ByteArrayOutputStream().apply {
            write(0x03) // Version 0x0303
            write(0x03)
            write(ByteArray(32)) // Random
            write(0) // Session ID length
            write(0x00) // Cipher Suites length = 2
            write(0x02)
            write(0x13)
            write(0x01)
            write(0x01) // Compression length = 1
            write(0x00)
            write(0x00) // Extensions length = 0
            write(0x00)
        }.toByteArray()

        val handshakeLen = clientHelloBody.size
        val handshakeRecord = ByteArrayOutputStream().apply {
            write(0x01) // Client Hello
            write((handshakeLen ushr 16) and 0xFF)
            write((handshakeLen ushr 8) and 0xFF)
            write(handshakeLen and 0xFF)
            write(clientHelloBody)
        }.toByteArray()

        val tlsRecord = ByteArrayOutputStream().apply {
            write(0x16) // Handshake
            write(0x03) // TLS 1.0 record version
            write(0x01)
            write((handshakeRecord.size ushr 8) and 0xFF)
            write(handshakeRecord.size and 0xFF)
            write(handshakeRecord)
        }.toByteArray()

        return tlsRecord
    }

    private fun buildDnsQuery(id: Int, domain: String): ByteArray {
        val out = ByteArrayOutputStream()
        out.write((id ushr 8) and 0xFF)
        out.write(id and 0xFF)
        out.write(0x01) // Flags (Standard query, RD = 1)
        out.write(0x00)
        out.write(0x00) // QDCOUNT = 1
        out.write(0x01)
        out.write(0x00) // ANCOUNT = 0
        out.write(0x00)
        out.write(0x00) // NSCOUNT = 0
        out.write(0x00)
        out.write(0x00) // ARCOUNT = 0
        out.write(0x00)
        for (part in domain.split(".")) {
            val bytes = part.toByteArray(Charsets.US_ASCII)
            out.write(bytes.size)
            out.write(bytes)
        }
        out.write(0)
        out.write(0x00) // QTYPE = 1 (A)
        out.write(0x01)
        out.write(0x00) // QCLASS = 1 (IN)
        out.write(0x01)
        return out.toByteArray()
    }

    private fun buildDnsResponse(id: Int, domain: String, ip: String): ByteArray {
        val out = ByteArrayOutputStream()
        out.write((id ushr 8) and 0xFF)
        out.write(id and 0xFF)
        out.write(0x81) // Flags (Response, RD = 1, RA = 1)
        out.write(0x80)
        out.write(0x00) // QDCOUNT = 1
        out.write(0x01)
        out.write(0x00) // ANCOUNT = 1
        out.write(0x01)
        out.write(0x00) // NSCOUNT = 0
        out.write(0x00)
        out.write(0x00) // ARCOUNT = 0
        out.write(0x00)
        for (part in domain.split(".")) {
            val bytes = part.toByteArray(Charsets.US_ASCII)
            out.write(bytes.size)
            out.write(bytes)
        }
        out.write(0)
        out.write(0x00) // QTYPE = 1 (A)
        out.write(0x01)
        out.write(0x00) // QCLASS = 1 (IN)
        out.write(0x01)

        // Answer
        out.write(0xC0) // Name Pointer to 0x000C
        out.write(0x0C)
        out.write(0x00) // TYPE = 1 (A)
        out.write(0x01)
        out.write(0x00) // CLASS = 1 (IN)
        out.write(0x01)
        out.write(0x00) // TTL = 300
        out.write(0x00)
        out.write(0x01)
        out.write(0x2C)
        out.write(0x00) // RDLENGTH = 4
        out.write(0x04)
        out.write(InetAddress.getByName(ip).address)
        return out.toByteArray()
    }
}
