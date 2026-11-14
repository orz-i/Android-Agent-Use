package com.agent.use.client.network

import com.agent.use.client.network.ebpf.LocalRootEbpfCaptureEngine
import com.agent.use.client.network.vpn.VpnTunForwarder
import com.agent.use.client.network.vpn.parser.IpPacket
import com.agent.use.client.network.vpn.parser.TcpPacket
import com.agent.use.client.network.vpn.parser.UdpPacket
import com.agent.use.client.network.vpn.processor.VpnPacketProcessor
import com.agent.use.common.network.CaptureMode
import com.agent.use.common.network.HttpRequestEvent
import com.agent.use.common.network.HttpResponseEvent
import com.agent.use.common.network.INetworkCapture
import com.agent.use.common.network.INetworkEventListener
import com.agent.use.common.network.NetworkCaptureConfig
import com.agent.use.common.network.plugin.NetworkCapturePluginRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.zip.GZIPOutputStream

class VpnTunForwarderAndLocalEbpfTest {

    private fun aaueFrame(pid: Int, uid: Int, direction: Int, sslPtr: Long, payload: ByteArray): ByteArray {
        val hdr = ByteBuffer.allocate(LocalRootEbpfCaptureEngine.WIRE_HEADER_SIZE)
            .order(ByteOrder.LITTLE_ENDIAN)
            .putInt(LocalRootEbpfCaptureEngine.WIRE_MAGIC_AAUE)
            .putInt(pid)
            .putInt(uid)
            .putInt(direction)
            .putInt(payload.size)
            .putLong(sslPtr)
            .array()
        return hdr + payload
    }

    private fun gzip(text: String): ByteArray {
        val out = ByteArrayOutputStream()
        GZIPOutputStream(out).use { it.write(text.toByteArray(StandardCharsets.UTF_8)) }
        return out.toByteArray()
    }

    @Test
    fun testVpnTunForwarderChecksumsQuicAndIpv6FastFail() {
        val emitted = CopyOnWriteArrayList<ByteArray>()
        val forwarder = VpnTunForwarder(
            protectSocket = { true },
            protectDatagram = { true },
            writeToTun = { pkt, len -> emitted.add(pkt.copyOf(len)) }
        )
        forwarder.start()
        try {
            val clientIp = InetAddress.getByName("10.244.0.1").address
            val serverIp = InetAddress.getByName("1.2.3.4").address

            // 1. QUIC UDP 443 -> ICMP Destination/Port Unreachable
            val quicPkt = VpnTunForwarder.buildIpv4UdpPacket(
                srcIp = clientIp,
                srcPort = 54321,
                dstIp = serverIp,
                dstPort = 443,
                payload = byteArrayOf(1, 2, 3, 4)
            )
            val parsedUdp = IpPacket.parse(quicPkt)!!
            assertEquals(0, VpnTunForwarder.computeChecksum(quicPkt, 0, parsedUdp.headerLength))
            forwarder.handleOutboundIpPacket(quicPkt, quicPkt.size)

            assertEquals(1, emitted.size)
            val icmpIp = IpPacket.parse(emitted[0])!!
            assertEquals(IpPacket.PROTOCOL_ICMP, icmpIp.protocol)
            assertEquals(3, emitted[0][icmpIp.payloadOffset].toInt() and 0xFF)     // Type 3
            assertEquals(3, emitted[0][icmpIp.payloadOffset + 1].toInt() and 0xFF) // Code 3

            // 2. IPv6 TCP SYN -> TCPv6 RST+ACK
            emitted.clear()
            val src6 = InetAddress.getByName("fd00:244::1").address
            val dst6 = InetAddress.getByName("2001:4860:4860::8888").address
            val ipv6Syn = ByteArray(60).apply {
                this[0] = 0x60.toByte()
                this[4] = 0
                this[5] = 20
                this[6] = IpPacket.PROTOCOL_TCP.toByte()
                this[7] = 64
                System.arraycopy(src6, 0, this, 8, 16)
                System.arraycopy(dst6, 0, this, 24, 16)
                this[40] = (50000 ushr 8).toByte()
                this[41] = (50000 and 0xFF).toByte()
                this[42] = 0
                this[43] = 80
                this[52] = 0x50.toByte()
                this[53] = VpnTunForwarder.TCP_FLAG_SYN.toByte()
            }
            forwarder.handleOutboundIpPacket(ipv6Syn, ipv6Syn.size)

            assertEquals(1, emitted.size)
            val v6Ip = IpPacket.parse(emitted[0])!!
            assertEquals(6, v6Ip.version)
            val v6Tcp = TcpPacket.parse(v6Ip)!!
            assertTrue(v6Tcp.isRst)
            assertTrue(v6Tcp.isAck)
            assertEquals(80, v6Tcp.srcPort)
            assertEquals(50000, v6Tcp.dstPort)
        } finally {
            forwarder.stop()
        }
    }

    @Test
    fun testVpnTunForwarderLiveLocalTcpHttpRoundtrip() {
        val server = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))
        val serverPort = server.localPort
        val serverThread = Thread {
            server.accept().use { sock ->
                val br = sock.getInputStream().bufferedReader(StandardCharsets.ISO_8859_1)
                while (true) {
                    val line = br.readLine() ?: break
                    if (line.isEmpty()) break
                }
                val body = """{"hello":"vpn_nat"}"""
                val resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n$body"
                sock.getOutputStream().write(resp.toByteArray(StandardCharsets.ISO_8859_1))
                sock.getOutputStream().flush()
            }
        }.apply { isDaemon = true; start() }

        val requests = CopyOnWriteArrayList<HttpRequestEvent>()
        val responses = CopyOnWriteArrayList<HttpResponseEvent>()
        val respLatch = CountDownLatch(1)

        val listener = object : INetworkEventListener.Stub() {
            override fun onRequestWillBeSent(event: HttpRequestEvent) {
                requests.add(event)
            }
            override fun onResponseReceived(event: HttpResponseEvent) {
                responses.add(event)
                respLatch.countDown()
            }
            override fun onDataChunkReceived(requestId: String, chunk: ByteArray) {}
            override fun onErrorOccurred(requestId: String, error: String) {}
        }

        val config = NetworkCaptureConfig(targetPackage = "com.example.app", mode = CaptureMode.VPN_SERVICE)
        val processor = VpnPacketProcessor(config, listener)

        val synAckLatch = CountDownLatch(1)
        val finOrBodyPackets = CopyOnWriteArrayList<ByteArray>()
        var capturedSynAckSeq = 0L

        val forwarder = VpnTunForwarder(
            protectSocket = { true },
            protectDatagram = { true },
            writeToTun = { pkt, len ->
                val copy = pkt.copyOf(len)
                finOrBodyPackets.add(copy)
                val ip = IpPacket.parse(copy)
                val tcp = ip?.let { TcpPacket.parse(it) }
                if (tcp != null && tcp.isSyn && tcp.isAck) {
                    capturedSynAckSeq = tcp.seqNumber
                    synAckLatch.countDown()
                }
            },
            packetProcessor = processor
        )
        forwarder.start()

        try {
            val clientIp = InetAddress.getByName("10.244.0.1").address
            val loopbackIp = InetAddress.getByName("127.0.0.1").address
            val clientPort = 41234
            val clientIsn = 1000L

            // Step 1: SYN
            val synPkt = VpnTunForwarder.buildIpv4TcpPacket(
                srcIp = clientIp, srcPort = clientPort,
                dstIp = loopbackIp, dstPort = serverPort,
                seqNum = clientIsn, ackNum = 0L,
                flags = VpnTunForwarder.TCP_FLAG_SYN
            )
            forwarder.handleOutboundIpPacket(synPkt, synPkt.size)
            assertTrue("Must receive SYN+ACK from NAT forwarder", synAckLatch.await(3, TimeUnit.SECONDS))

            // Step 2: ACK + HTTP GET
            val ackSeq = (capturedSynAckSeq + 1L) and 0xFFFFFFFFL
            val httpGet = "GET /api/ping HTTP/1.1\r\nHost: 127.0.0.1:$serverPort\r\n\r\n".toByteArray(StandardCharsets.ISO_8859_1)
            val dataPkt = VpnTunForwarder.buildIpv4TcpPacket(
                srcIp = clientIp, srcPort = clientPort,
                dstIp = loopbackIp, dstPort = serverPort,
                seqNum = clientIsn + 1L, ackNum = ackSeq,
                flags = VpnTunForwarder.TCP_FLAG_PSH or VpnTunForwarder.TCP_FLAG_ACK,
                payload = httpGet
            )
            forwarder.handleOutboundIpPacket(dataPkt, dataPkt.size)

            assertTrue("VpnPacketProcessor must emit complete HTTP response", respLatch.await(3, TimeUnit.SECONDS))
            assertEquals(1, requests.size)
            assertEquals(1, responses.size)
            assertEquals(200, responses[0].statusCode)

            val cachedBody = processor.getResponseBody(responses[0].requestId)
            assertNotNull("Cached body must already exist when onResponseReceived fires", cachedBody)
            assertEquals("""{"hello":"vpn_nat"}""", String(cachedBody!!, StandardCharsets.UTF_8))

            // Confirm at least one response data packet was actually written back to TUN
            var tunHasHttpBody = false
            for (i in 0 until 20) {
                tunHasHttpBody = finOrBodyPackets.any { pkt ->
                    val ip = IpPacket.parse(pkt)
                    val tcp = ip?.let { TcpPacket.parse(it) }
                    tcp != null && tcp.getPayload().toString(StandardCharsets.UTF_8).contains("vpn_nat")
                }
                if (tunHasHttpBody) break
                Thread.sleep(50)
            }
            assertTrue("TUN output must contain forwarded HTTP response segment", tunHasHttpBody)
        } finally {
            forwarder.stop()
            server.close()
            serverThread.interrupt()
        }
    }

    @Test
    fun testLocalRootEbpfHandshakeFailureAndAaueFrameParsing() {
        val tmpBin = File.createTempFile("libaau_ebpf_test", ".so").apply { deleteOnExit() }

        // Case 1: Honest failure when native binary prints ERR:
        val errors = mutableListOf<String>()
        val failingEngine = LocalRootEbpfCaptureEngine(
            context = null,
            binaryPathResolver = { tmpBin },
            uidResolver = { 10123 },
            processStarter = { _, _ ->
                FakeProcess(
                    stdoutBytes = ByteArray(0),
                    stderrText = "ERR:bpf_prog_load:errno=1(Operation not permitted)\n",
                    exitCode = 5
                )
            }
        )
        val failListener = object : INetworkEventListener.Stub() {
            override fun onRequestWillBeSent(event: HttpRequestEvent) {}
            override fun onResponseReceived(event: HttpResponseEvent) {}
            override fun onDataChunkReceived(requestId: String, chunk: ByteArray) {}
            override fun onErrorOccurred(requestId: String, error: String) { errors.add(error) }
        }
        val startedFail = failingEngine.startCapture(
            NetworkCaptureConfig(targetPackage = "com.example.target", mode = CaptureMode.EBPF),
            failListener
        )
        assertFalse("Must refuse false start when helper emits ERR:", startedFail)
        assertTrue(failingEngine.lastError?.contains("bpf_prog_load") == true)
        assertTrue(errors.any { it.contains("bpf_prog_load") })

        // Case 2: READY + AAUE binary frames (with wrong UID filtered out, and gzip HTTP/1.1 decoded)
        val targetUid = 10250
        val reqFrame = aaueFrame(
            pid = 4321,
            uid = targetUid,
            direction = LocalRootEbpfCaptureEngine.DIRECTION_OUTBOUND_WRITE,
            sslPtr = 0x7A001000L,
            payload = "GET /v1/profile HTTP/1.1\r\nHost: api.ebpf.test\r\n\r\n".toByteArray(StandardCharsets.ISO_8859_1)
        )
        val wrongUidFrame = aaueFrame(
            pid = 9999,
            uid = 10999,
            direction = LocalRootEbpfCaptureEngine.DIRECTION_OUTBOUND_WRITE,
            sslPtr = 0x7B001000L,
            payload = "GET /leak HTTP/1.1\r\nHost: leak.test\r\n\r\n".toByteArray(StandardCharsets.ISO_8859_1)
        )
        val gzBody = gzip("""{"user":"alice"}""")
        val respHeaders = "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: ${gzBody.size}\r\n\r\n".toByteArray(StandardCharsets.ISO_8859_1)
        val respFrame = aaueFrame(
            pid = 4321,
            uid = targetUid,
            direction = LocalRootEbpfCaptureEngine.DIRECTION_INBOUND_READ,
            sslPtr = 0x7A001000L,
            payload = respHeaders + gzBody
        )

        val requests = CopyOnWriteArrayList<HttpRequestEvent>()
        val responses = CopyOnWriteArrayList<HttpResponseEvent>()
        val respLatch = CountDownLatch(1)

        val okEngine = LocalRootEbpfCaptureEngine(
            context = null,
            binaryPathResolver = { tmpBin },
            uidResolver = { targetUid },
            processStarter = { _, _ ->
                FakeProcess(
                    stdoutBytes = reqFrame + wrongUidFrame + respFrame,
                    stderrText = "READY:/apex/com.android.conscrypt/lib64/libssl.so\n",
                    exitCode = 0
                )
            }
        )
        val okListener = object : INetworkEventListener.Stub() {
            override fun onRequestWillBeSent(event: HttpRequestEvent) { requests.add(event) }
            override fun onResponseReceived(event: HttpResponseEvent) {
                responses.add(event)
                respLatch.countDown()
            }
            override fun onDataChunkReceived(requestId: String, chunk: ByteArray) {}
            override fun onErrorOccurred(requestId: String, error: String) {}
        }

        val startedOk = okEngine.startCapture(
            NetworkCaptureConfig(targetPackage = "com.example.target", mode = CaptureMode.EBPF),
            okListener
        )
        assertTrue(startedOk)
        assertEquals(CaptureMode.ACTIVE_MODE_EBPF, okEngine.activeMode)
        assertTrue(respLatch.await(3, TimeUnit.SECONDS))
        assertEquals("Only target UID request should be captured", 1, requests.size)
        assertEquals("https://api.ebpf.test/v1/profile", requests[0].url)
        assertEquals("""{"user":"alice"}""", String(okEngine.getResponseBody(responses[0].requestId)!!, StandardCharsets.UTF_8))
        okEngine.stopCapture()
    }

    @Test
    fun testAgentNetworkManagerUsesLocalEbpfFallbackAndTracksLastError() {
        val localEngine = object : INetworkCapture.Stub() {
            var started = false
            override fun startCapture(config: NetworkCaptureConfig, listener: INetworkEventListener): Boolean {
                started = true
                return true
            }
            override fun stopCapture() { started = false }
            override fun getResponseBody(requestId: String?): ByteArray? = null
            override fun getActiveMode(): Int = if (started) CaptureMode.ACTIVE_MODE_EBPF else CaptureMode.ACTIVE_MODE_NONE
        }

        val mgr = AgentNetworkManager(
            context = null,
            shell = null, // No server binder -> must try localEbpfProvider!
            serverCaptureProvider = { null },
            localEbpfProvider = { localEngine },
            rootChecker = { true },
            kernelChecker = { true }
        )

        assertTrue(mgr.enable("com.target.app", CaptureMode.AUTO))
        assertEquals(CaptureMode.EBPF, mgr.getActiveMode())
        assertTrue(localEngine.started)
        mgr.close()

        // Also check error propagation when both engines fail
        val failingMgr = AgentNetworkManager(
            context = null,
            shell = null,
            vpnEngineProvider = {
                object : INetworkCapture.Stub() {
                    override fun startCapture(config: NetworkCaptureConfig, listener: INetworkEventListener): Boolean {
                        listener.onErrorOccurred("", "vpn_permission_not_granted")
                        return false
                    }
                    override fun stopCapture() {}
                    override fun getResponseBody(requestId: String?): ByteArray? = null
                    override fun getActiveMode(): Int = CaptureMode.ACTIVE_MODE_NONE
                }
            },
            rootChecker = { false },
            kernelChecker = { false }
        )
        assertFalse(failingMgr.enable("com.target.app", CaptureMode.AUTO))
        assertEquals("vpn_permission_not_granted", failingMgr.lastError)
        failingMgr.close()
    }

    @Test
    fun testLocalRootEbpfSniFrameBackfillsHttp2HostAndIgnoresWarnLines() {
        val tmpBin = File.createTempFile("libaau_ebpf_sni_test", ".so").apply { deleteOnExit() }
        val targetUid = 10333
        val sslPtr = 0x7C002000L

        // 256-byte NUL-padded SNI hostname matching probe_ssl_set_sni output
        val sniPayload = ByteArray(256)
        val sniAscii = "edith.xiaohongshu.com".toByteArray(StandardCharsets.US_ASCII)
        System.arraycopy(sniAscii, 0, sniPayload, 0, sniAscii.size)
        val sniFrame = aaueFrame(
            pid = 5678,
            uid = targetUid,
            direction = LocalRootEbpfCaptureEngine.DIRECTION_SNI_HOSTNAME,
            sslPtr = sslPtr,
            payload = sniPayload
        )

        // HTTP/2 preface + HEADERS frame omitting :authority (dynamic miss 0x80|62), path=/api/sns/v2/comment/page
        fun h2FrameLocal(type: Int, flags: Int, streamId: Int, payload: ByteArray): ByteArray {
            val out = ByteArrayOutputStream(9 + payload.size)
            out.write((payload.size ushr 16) and 0xFF)
            out.write((payload.size ushr 8) and 0xFF)
            out.write(payload.size and 0xFF)
            out.write(type and 0xFF)
            out.write(flags and 0xFF)
            out.write((streamId ushr 24) and 0x7F)
            out.write((streamId ushr 16) and 0xFF)
            out.write((streamId ushr 8) and 0xFF)
            out.write(streamId and 0xFF)
            out.write(payload)
            return out.toByteArray()
        }
        val pathStr = "/api/sns/v2/comment/page".toByteArray(StandardCharsets.UTF_8)
        val reqHeaders = ByteArrayOutputStream().apply {
            write(0x82) // :method: GET
            write(0x87) // :scheme: https
            write(0x80 or 62) // :authority dynamic miss
            write(0x40 or 4) // :path literal inc
            write(pathStr.size)
            write(pathStr)
        }.toByteArray()
        val reqBytes = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".toByteArray(StandardCharsets.ISO_8859_1) +
            h2FrameLocal(0x1, 0x05, 1, reqHeaders)
        val outFrame = aaueFrame(
            pid = 5678,
            uid = targetUid,
            direction = LocalRootEbpfCaptureEngine.DIRECTION_OUTBOUND_WRITE,
            sslPtr = sslPtr,
            payload = reqBytes
        )

        val jsonBody = """{"comments":[{"id":"c1"}]}""".toByteArray(StandardCharsets.UTF_8)
        val inBytes = h2FrameLocal(0x1, 0x04, 1, byteArrayOf(0x88.toByte())) +
            h2FrameLocal(0x0, 0x01, 1, jsonBody)
        val inFrame = aaueFrame(
            pid = 5678,
            uid = targetUid,
            direction = LocalRootEbpfCaptureEngine.DIRECTION_INBOUND_READ,
            sslPtr = sslPtr,
            payload = inBytes
        )

        val requests = CopyOnWriteArrayList<HttpRequestEvent>()
        val responses = CopyOnWriteArrayList<HttpResponseEvent>()
        val respLatch = CountDownLatch(1)

        val engine = LocalRootEbpfCaptureEngine(
            context = null,
            binaryPathResolver = { tmpBin },
            uidResolver = { targetUid },
            processStarter = { _, _ ->
                FakeProcess(
                    stdoutBytes = sniFrame + outFrame + inFrame,
                    stderrText = "WARN:perf_event_open_tp(/apex/com.android.conscrypt/lib/libssl.so):errno=22(Invalid argument)\nREADY:/apex/com.android.conscrypt/lib64/libssl.so\n",
                    exitCode = 0
                )
            }
        )
        val listener = object : INetworkEventListener.Stub() {
            override fun onRequestWillBeSent(event: HttpRequestEvent) { requests.add(event) }
            override fun onResponseReceived(event: HttpResponseEvent) {
                responses.add(event)
                respLatch.countDown()
            }
            override fun onDataChunkReceived(requestId: String, chunk: ByteArray) {}
            override fun onErrorOccurred(requestId: String, error: String) {}
        }

        val started = engine.startCapture(
            NetworkCaptureConfig(targetPackage = "com.xingin.xhs", mode = CaptureMode.EBPF),
            listener
        )
        assertTrue("WARN before READY must not abort eBPF capture", started)
        assertEquals(CaptureMode.ACTIVE_MODE_EBPF, engine.activeMode)
        assertEquals(null, engine.lastError)
        assertTrue(respLatch.await(3, TimeUnit.SECONDS))
        assertEquals(1, requests.size)
        assertEquals("https://edith.xiaohongshu.com/api/sns/v2/comment/page", requests[0].url)
        assertEquals("""{"comments":[{"id":"c1"}]}""", String(engine.getResponseBody(responses[0].requestId)!!, StandardCharsets.UTF_8))
        engine.stopCapture()
    }

    @Test
    fun testLocalRootEbpfCronetFramesAndAttachedLibraries() {
        val tmpBin = File.createTempFile("libaau_ebpf_cronet_test", ".so").apply { deleteOnExit() }
        val targetUid = 10429
        val adapterPtr = 0x7D004000L

        val reqUrl = "https://edith.xiaohongshu.com/api/sns/v10/comment/page".toByteArray(StandardCharsets.UTF_8)
        val reqFrame = aaueFrame(
            pid = 7788,
            uid = targetUid,
            direction = LocalRootEbpfCaptureEngine.DIRECTION_CRONET_REQ,
            sslPtr = adapterPtr,
            payload = reqUrl
        )

        val rawHeaders = "HTTP/1.1 200 OK\u0000content-type: application/json\u0000\u0000"
            .toByteArray(StandardCharsets.ISO_8859_1)
        val hdrPayload = ByteArray(4 + rawHeaders.size)
        hdrPayload[0] = (200 and 0xFF).toByte()
        hdrPayload[1] = 0
        hdrPayload[2] = 0
        hdrPayload[3] = 0
        System.arraycopy(rawHeaders, 0, hdrPayload, 4, rawHeaders.size)
        val hdrFrame = aaueFrame(
            pid = 7788,
            uid = targetUid,
            direction = LocalRootEbpfCaptureEngine.DIRECTION_CRONET_RESP_HDR,
            sslPtr = adapterPtr,
            payload = hdrPayload
        )

        val bodyBytes = """{"comments":[{"id":"c_cronet"}]}""".toByteArray(StandardCharsets.UTF_8)
        val bodyFrame = aaueFrame(
            pid = 7788,
            uid = targetUid,
            direction = LocalRootEbpfCaptureEngine.DIRECTION_CRONET_BODY,
            sslPtr = adapterPtr,
            payload = bodyBytes
        )

        val finishFrame = aaueFrame(
            pid = 7788,
            uid = targetUid,
            direction = LocalRootEbpfCaptureEngine.DIRECTION_CRONET_FINISH,
            sslPtr = adapterPtr,
            payload = ByteArray(4)
        )

        val requests = CopyOnWriteArrayList<HttpRequestEvent>()
        val responses = CopyOnWriteArrayList<HttpResponseEvent>()
        val respLatch = CountDownLatch(1)

        val engine = LocalRootEbpfCaptureEngine(
            context = null,
            binaryPathResolver = { tmpBin },
            uidResolver = { targetUid },
            processStarter = { _, _ ->
                FakeProcess(
                    stdoutBytes = reqFrame + hdrFrame + bodyFrame + finishFrame,
                    stderrText = "ATTACHED:/data/app/com.xingin.xhs/lib/arm64/libcronet.114.0.5735.38.so\n" +
                        "ATTACHED_CRONET:/data/app/com.xingin.xhs/lib/arm64/libcronet.114.0.5735.38.so\n" +
                        "READY:/apex/com.android.conscrypt/lib64/libssl.so\n",
                    exitCode = 0
                )
            }
        )
        val listener = object : INetworkEventListener.Stub() {
            override fun onRequestWillBeSent(event: HttpRequestEvent) { requests.add(event) }
            override fun onResponseReceived(event: HttpResponseEvent) {
                responses.add(event)
                respLatch.countDown()
            }
            override fun onDataChunkReceived(requestId: String, chunk: ByteArray) {}
            override fun onErrorOccurred(requestId: String, error: String) {}
        }

        val started = engine.startCapture(
            NetworkCaptureConfig(targetPackage = "com.xingin.xhs", mode = CaptureMode.EBPF),
            listener
        )
        assertTrue(started)
        assertTrue(respLatch.await(3, TimeUnit.SECONDS))
        val libs = engine.attachedLibrariesSnapshot()
        assertTrue(libs.any { it.contains("libcronet.114.0.5735.38.so") })
        assertTrue(libs.any { it.startsWith("cronet:") && it.contains("libcronet.114.0.5735.38.so") })
        assertEquals(1, requests.size)
        assertEquals("https://edith.xiaohongshu.com/api/sns/v10/comment/page", requests[0].url)
        assertEquals(200, responses[0].statusCode)
        assertEquals(
            """{"comments":[{"id":"c_cronet"}]}""",
            String(engine.getResponseBody(responses[0].requestId)!!, StandardCharsets.UTF_8)
        )
        engine.stopCapture()
    }

    @Test
    fun testBuildSuCommandQuotesCronetSignatureAndPluginArgs() {
        val pluginArgs = NetworkCapturePluginRegistry.resolveCliArgs("com.xingin.xhs")
        val suCmd = LocalRootEbpfCaptureEngine.buildSuCommand(
            binaryPath = "/data/local/tmp/libaau_ebpf_helper.so",
            uid = 10234,
            libDir = "/data/app/com.xingin.xhs/lib/arm64",
            extraArgs = pluginArgs
        )
        assertTrue(suCmd.startsWith("\"/data/local/tmp/libaau_ebpf_helper.so\" '--uid' '10234' '--lib-dir' '/data/app/com.xingin.xhs/lib/arm64'"))
        assertTrue(suCmd.contains("'--cronet-sig' '(Ljava/lang/Object;JLjava/lang/String;IZZZIZIIJ)J'"))
        assertTrue(suCmd.contains("'--cronet-abi' '0x20,0x10,0'"))
    }

    private class FakeProcess(
        stdoutBytes: ByteArray,
        stderrText: String,
        private val exitCode: Int
    ) : Process() {
        private val outStream = ByteArrayInputStream(stdoutBytes)
        private val errStream = ByteArrayInputStream(stderrText.toByteArray(StandardCharsets.UTF_8))
        private val inSink = ByteArrayOutputStream()

        override fun getOutputStream(): OutputStream = inSink
        override fun getInputStream(): InputStream = outStream
        override fun getErrorStream(): InputStream = errStream
        override fun waitFor(): Int = exitCode
        override fun exitValue(): Int = exitCode
        override fun destroy() {}
    }
}
