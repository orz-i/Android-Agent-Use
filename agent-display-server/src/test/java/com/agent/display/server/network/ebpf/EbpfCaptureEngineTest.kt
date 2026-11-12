package com.agent.display.server.network.ebpf

import com.agent.display.common.network.CaptureMode
import com.agent.display.common.network.HttpRequestEvent
import com.agent.display.common.network.HttpResponseEvent
import com.agent.display.common.network.INetworkEventListener
import com.agent.display.common.network.NetworkCaptureConfig
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.charset.StandardCharsets

class EbpfCaptureEngineTest {

    private class MockEventListener : INetworkEventListener.Stub() {
        val requests = mutableListOf<HttpRequestEvent>()
        val responses = mutableListOf<HttpResponseEvent>()
        val dataChunks = mutableListOf<Pair<String, ByteArray>>()
        val errors = mutableListOf<Pair<String, String>>()

        override fun onRequestWillBeSent(request: HttpRequestEvent) {
            requests.add(request)
        }

        override fun onResponseReceived(response: HttpResponseEvent) {
            responses.add(response)
        }

        override fun onDataChunkReceived(requestId: String, chunk: ByteArray) {
            dataChunks.add(requestId to chunk)
        }

        override fun onErrorOccurred(requestId: String, errorMsg: String) {
            errors.add(requestId to errorMsg)
        }
    }

    @Test
    fun testEngineLifecycleAndTargetUidIsolation() {
        val mockDetector = object : EbpfCapabilityProvider {
            override fun detect(): EbpfCapabilityDetector.EbpfCapabilityResult =
                EbpfCapabilityDetector.EbpfCapabilityResult(
                    isSupported = true,
                    isRoot = true,
                    kernelVersion = "5.10.0",
                    kernelMajor = 5,
                    kernelMinor = 10,
                    kernelPatch = 0,
                    isKernelSupported = true,
                    bpfFsMounted = true,
                    traceFsAvailable = true,
                    libSslPath = "/apex/com.android.conscrypt/lib64/libssl.so"
                )
        }

        val engine = EbpfCaptureEngine(null, mockDetector)
        assertEquals(CaptureMode.ACTIVE_MODE_NONE, engine.activeMode)
        assertFalse(engine.isRunning)

        val listener = MockEventListener()
        val targetUid = 10150
        val config = NetworkCaptureConfig(
            targetPackage = "com.agent.sample",
            targetUid = targetUid,
            captureMode = CaptureMode.MODE_EBPF
        )

        // 启动抓包引擎
        val started = engine.startCapture(config, listener)
        assertTrue("Engine must successfully start when capability is satisfied", started)
        assertTrue(engine.isRunning)
        assertEquals(CaptureMode.ACTIVE_MODE_EBPF, engine.activeMode)
        assertEquals(targetUid, engine.filter.currentTargetUid)

        // 1. 尝试注入非目标 UID (如微信 10123) 流量 -> 必须被严格隔离，绝不触发 listener
        val wechatRequest = "GET /wechat/sync HTTP/1.1\r\nHost: mm.qq.com\r\n\r\n"
        engine.injectTlsDataForTest("conn_wechat", 1, wechatRequest.toByteArray(StandardCharsets.UTF_8), uid = 10123)

        assertEquals("Non-target UID must be completely bypassed", 0, listener.requests.size)

        // 2. 注入目标应用 UID 流量 -> 成功触发 listener
        val sampleRequest = "GET /api/agent/task HTTP/1.1\r\nHost: agent.ai\r\n\r\n"
        engine.injectTlsDataForTest("conn_target", 1, sampleRequest.toByteArray(StandardCharsets.UTF_8), uid = targetUid)

        assertEquals("Target UID request must be parsed and dispatched", 1, listener.requests.size)
        assertEquals("GET", listener.requests[0].method)
        assertEquals("https://agent.ai/api/agent/task", listener.requests[0].url)

        // 3. 注入响应
        val sampleResponse = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 13\r\n\r\n{\"ok\":true}"
        engine.injectTlsDataForTest("conn_target", 2, sampleResponse.toByteArray(StandardCharsets.UTF_8), uid = targetUid)

        assertEquals("Target UID response must be dispatched", 1, listener.responses.size)
        assertEquals(200, listener.responses[0].statusCode)

        val cachedBody = engine.getResponseBody(listener.responses[0].requestId)
        assertNotNull("Response body should be cached", cachedBody)
        assertEquals("{\"ok\":true}", String(cachedBody!!, StandardCharsets.UTF_8))

        // 4. 停止引擎
        engine.stopCapture()
        assertFalse(engine.isRunning)
        assertEquals(CaptureMode.ACTIVE_MODE_NONE, engine.activeMode)
        assertEquals(EbpfTargetFilter.UID_UNSET, engine.filter.currentTargetUid)
    }

    @Test
    fun testEngineGracefulFallbackWhenUnsupported() {
        val mockDetector = object : EbpfCapabilityProvider {
            override fun detect(): EbpfCapabilityDetector.EbpfCapabilityResult =
                EbpfCapabilityDetector.EbpfCapabilityResult(
                    isSupported = false,
                    isRoot = false,
                    kernelVersion = "4.19.0",
                    kernelMajor = 4,
                    kernelMinor = 19,
                    kernelPatch = 0,
                    isKernelSupported = false,
                    bpfFsMounted = false,
                    traceFsAvailable = false,
                    libSslPath = null,
                    failureReason = "Kernel 4.19 unsupported and no root"
                )
        }

        val engine = EbpfCaptureEngine(null, mockDetector)
        val listener = MockEventListener()
        val config = NetworkCaptureConfig(
            targetPackage = "com.agent.sample",
            targetUid = 10150,
            captureMode = CaptureMode.MODE_EBPF
        )

        val started = engine.startCapture(config, listener)
        assertFalse("Engine must return false when unsupported", started)
        assertEquals(CaptureMode.ACTIVE_MODE_NONE, engine.activeMode)
        assertEquals(1, listener.errors.size)
        assertTrue(listener.errors[0].second.contains("Kernel 4.19 unsupported"))
    }
}
