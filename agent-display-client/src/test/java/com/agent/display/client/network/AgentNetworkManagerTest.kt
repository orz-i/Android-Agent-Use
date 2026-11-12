package com.agent.display.client.network

import android.content.Context
import com.agent.display.common.network.CaptureMode
import com.agent.display.common.network.HttpHeader
import com.agent.display.common.network.HttpRequestEvent
import com.agent.display.common.network.HttpResponseEvent
import com.agent.display.common.network.INetworkCapture
import com.agent.display.common.network.INetworkEventListener
import com.agent.display.common.network.NetworkCaptureConfig
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.lang.reflect.Proxy
import java.nio.charset.StandardCharsets

class AgentNetworkManagerTest {

    private class MockEngine(
        val mode: Int,
        var shouldSucceed: Boolean = true
    ) : INetworkCapture.Stub() {
        var startCount = 0
        var stopCount = 0
        var lastConfig: NetworkCaptureConfig? = null
        var lastListener: INetworkEventListener? = null
        val responseBodies = mutableMapOf<String, ByteArray>()

        override fun startCapture(config: NetworkCaptureConfig, listener: INetworkEventListener): Boolean {
            startCount++
            lastConfig = config
            lastListener = listener
            return shouldSucceed
        }

        override fun stopCapture() {
            stopCount++
            lastListener = null
        }

        override fun getResponseBody(requestId: String): ByteArray? {
            return responseBodies[requestId]
        }

        override fun getActiveMode(): Int = if (startCount > stopCount) mode else CaptureMode.ACTIVE_MODE_NONE

        fun emitRequest(request: HttpRequestEvent) {
            lastListener?.onRequestWillBeSent(request)
        }

        fun emitResponse(response: HttpResponseEvent) {
            lastListener?.onResponseReceived(response)
        }

        fun emitError(requestId: String, errorMsg: String) {
            lastListener?.onErrorOccurred(requestId, errorMsg)
        }
    }

    @Test
    fun testAutoSelection_EbpfSupported_SelectsEbpf() {
        val mockEbpf = MockEngine(CaptureMode.ACTIVE_MODE_EBPF, shouldSucceed = true)
        val mockVpn = MockEngine(CaptureMode.ACTIVE_MODE_VPN_SERVICE, shouldSucceed = true)

        val manager = AgentNetworkManager(
            context = null,
            shell = null,
            vpnEngineProvider = { mockVpn },
            serverCaptureProvider = { mockEbpf },
            rootChecker = { true },
            kernelChecker = { true }
        )

        val started = manager.enable("com.example.target", CaptureMode.AUTO)

        assertTrue(started)
        assertTrue(manager.isCapturing)
        assertEquals(CaptureMode.EBPF, manager.getActiveMode())
        assertEquals(1, mockEbpf.startCount)
        assertEquals(0, mockVpn.startCount)
        assertEquals("com.example.target", manager.targetPackage)
    }

    @Test
    fun testAutoSelection_EbpfFails_FallsBackToVpn() {
        // eBPF 环境支持但 startCapture 启动失败 (e.g. uprobe 挂载失败)
        val mockEbpf = MockEngine(CaptureMode.ACTIVE_MODE_EBPF, shouldSucceed = false)
        val mockVpn = MockEngine(CaptureMode.ACTIVE_MODE_VPN_SERVICE, shouldSucceed = true)

        val manager = AgentNetworkManager(
            context = null,
            shell = null,
            vpnEngineProvider = { mockVpn },
            serverCaptureProvider = { mockEbpf },
            rootChecker = { true },
            kernelChecker = { true }
        )

        val started = manager.enable("com.example.target", CaptureMode.AUTO)

        assertTrue(started)
        assertTrue(manager.isCapturing)
        assertEquals(CaptureMode.VPN_SERVICE, manager.getActiveMode())
        assertEquals(1, mockEbpf.startCount)
        assertEquals(1, mockVpn.startCount)
    }

    @Test
    fun testAutoSelection_EbpfUnsupported_DirectlySelectsVpn() {
        // 未 Root 或旧内核
        val mockEbpf = MockEngine(CaptureMode.ACTIVE_MODE_EBPF, shouldSucceed = true)
        val mockVpn = MockEngine(CaptureMode.ACTIVE_MODE_VPN_SERVICE, shouldSucceed = true)

        val manager = AgentNetworkManager(
            context = null,
            shell = null,
            vpnEngineProvider = { mockVpn },
            serverCaptureProvider = { mockEbpf },
            rootChecker = { false }, // 未 Root
            kernelChecker = { true }
        )

        val started = manager.enable("com.example.target", CaptureMode.AUTO)

        assertTrue(started)
        assertTrue(manager.isCapturing)
        assertEquals(CaptureMode.VPN_SERVICE, manager.getActiveMode())
        assertEquals(0, mockEbpf.startCount) // 不应尝试 eBPF
        assertEquals(1, mockVpn.startCount)
    }

    @Test
    fun testExplicitOverride_EbpfOnly_DoesNotFallbackOnFailure() {
        val mockEbpf = MockEngine(CaptureMode.ACTIVE_MODE_EBPF, shouldSucceed = false)
        val mockVpn = MockEngine(CaptureMode.ACTIVE_MODE_VPN_SERVICE, shouldSucceed = true)

        val manager = AgentNetworkManager(
            context = null,
            shell = null,
            vpnEngineProvider = { mockVpn },
            serverCaptureProvider = { mockEbpf },
            rootChecker = { true },
            kernelChecker = { true }
        )

        val started = manager.enable("com.example.target", CaptureMode.EBPF)

        assertFalse(started)
        assertFalse(manager.isCapturing)
        assertEquals(1, mockEbpf.startCount)
        assertEquals(0, mockVpn.startCount) // 严格遵循显式覆盖，不 fallback
    }

    @Test
    fun testExplicitOverride_VpnOnly_DoesNotAttemptEbpf() {
        val mockEbpf = MockEngine(CaptureMode.ACTIVE_MODE_EBPF, shouldSucceed = true)
        val mockVpn = MockEngine(CaptureMode.ACTIVE_MODE_VPN_SERVICE, shouldSucceed = true)

        val manager = AgentNetworkManager(
            context = null,
            shell = null,
            vpnEngineProvider = { mockVpn },
            serverCaptureProvider = { mockEbpf },
            rootChecker = { true },
            kernelChecker = { true }
        )

        val started = manager.enable("com.example.target", CaptureMode.VPN_SERVICE)

        assertTrue(started)
        assertEquals(CaptureMode.VPN_SERVICE, manager.getActiveMode())
        assertEquals(0, mockEbpf.startCount) // 严格指定 VPN，不调用 eBPF
        assertEquals(1, mockVpn.startCount)
    }

    @Test
    fun testOnRequest_WithAndWithoutFilter_AndUnsubscribe() {
        val mockEngine = MockEngine(CaptureMode.ACTIVE_MODE_VPN_SERVICE, shouldSucceed = true)
        val manager = AgentNetworkManager(
            context = null,
            vpnEngineProvider = { mockEngine },
            rootChecker = { false }
        )
        manager.enable("com.example.target", CaptureMode.VPN_SERVICE)

        val allRequests = mutableListOf<HttpRequestEvent>()
        val filteredRequests = mutableListOf<HttpRequestEvent>()

        val subAll = manager.onRequest { allRequests.add(it) }
        val subFiltered = manager.onRequest(Regex(".*/api/user/.*")) { filteredRequests.add(it) }

        val req1 = HttpRequestEvent("req-1", System.currentTimeMillis(), "https://api.example.com/api/user/info", "GET")
        val req2 = HttpRequestEvent("req-2", System.currentTimeMillis(), "https://api.example.com/static/style.css", "GET")

        mockEngine.emitRequest(req1)
        mockEngine.emitRequest(req2)

        assertEquals(2, allRequests.size)
        assertEquals(1, filteredRequests.size)
        assertEquals("req-1", filteredRequests[0].requestId)

        // 测试注销监听
        subFiltered.close()
        val req3 = HttpRequestEvent("req-3", System.currentTimeMillis(), "https://api.example.com/api/user/profile", "GET")
        mockEngine.emitRequest(req3)

        assertEquals(3, allRequests.size)
        assertEquals(1, filteredRequests.size) // 已注销，数量不变
    }

    @Test
    fun testOnResponse_WithAndWithoutFilter_AndUnsubscribe() {
        val mockEngine = MockEngine(CaptureMode.ACTIVE_MODE_VPN_SERVICE, shouldSucceed = true)
        val manager = AgentNetworkManager(
            context = null,
            vpnEngineProvider = { mockEngine },
            rootChecker = { false }
        )
        manager.enable("com.example.target", CaptureMode.VPN_SERVICE)

        val allResponses = mutableListOf<HttpResponseEvent>()
        val filteredResponses = mutableListOf<HttpResponseEvent>()

        val subAll = manager.onResponse { allResponses.add(it) }
        val subFiltered = manager.onResponse(Regex(".*order/create.*")) { filteredResponses.add(it) }

        val res1 = HttpResponseEvent("req-1", System.currentTimeMillis(), "https://api.example.com/order/create", 200, "OK")
        val res2 = HttpResponseEvent("req-2", System.currentTimeMillis(), "https://api.example.com/config", 200, "OK")

        mockEngine.emitResponse(res1)
        mockEngine.emitResponse(res2)

        assertEquals(2, allResponses.size)
        assertEquals(1, filteredResponses.size)
        assertEquals("req-1", filteredResponses[0].requestId)

        subAll.close()
        val res3 = HttpResponseEvent("req-3", System.currentTimeMillis(), "https://api.example.com/order/create", 200, "OK")
        mockEngine.emitResponse(res3)

        assertEquals(2, allResponses.size) // all 已注销
        assertEquals(2, filteredResponses.size) // filtered 仍有效
    }

    @Test
    fun testWaitForResponse_MatchingUrlAndRegex() = runTest {
        val mockEngine = MockEngine(CaptureMode.ACTIVE_MODE_VPN_SERVICE, shouldSucceed = true)
        val manager = AgentNetworkManager(
            context = null,
            vpnEngineProvider = { mockEngine },
            rootChecker = { false }
        )
        manager.enable("com.example.target", CaptureMode.VPN_SERVICE)

        val deferredStringWait = async {
            manager.waitForResponse("api/v1/auth/login", timeoutMs = 2000L)
        }

        val deferredRegexWait = async {
            manager.waitForResponse(Regex("https://.*auth/login"), timeoutMs = 2000L)
        }

        delay(50)
        val response = HttpResponseEvent(
            requestId = "auth-123",
            timestamp = System.currentTimeMillis(),
            url = "https://example.com/api/v1/auth/login",
            statusCode = 200,
            statusText = "OK"
        )
        mockEngine.emitResponse(response)

        val result1 = deferredStringWait.await()
        val result2 = deferredRegexWait.await()

        assertEquals("auth-123", result1.requestId)
        assertEquals("auth-123", result2.requestId)
        assertEquals(200, result1.statusCode)
    }

    @Test
    fun testWaitForResponse_TimeoutThrowsException() = runTest {
        val mockEngine = MockEngine(CaptureMode.ACTIVE_MODE_VPN_SERVICE, shouldSucceed = true)
        val manager = AgentNetworkManager(
            context = null,
            vpnEngineProvider = { mockEngine },
            rootChecker = { false }
        )
        manager.enable("com.example.target", CaptureMode.VPN_SERVICE)

        try {
            manager.waitForResponse("non/existent/endpoint", timeoutMs = 100L)
            fail("Expected TimeoutCancellationException")
        } catch (_: TimeoutCancellationException) {
            // Success
        }
    }

    @Test
    fun testGetResponseBody_DelegatesToActiveEngine() {
        val mockEngine = MockEngine(CaptureMode.ACTIVE_MODE_VPN_SERVICE, shouldSucceed = true)
        val expectedBytes = "{\"status\":\"success\",\"token\":\"abc123xyz\"}".toByteArray(StandardCharsets.UTF_8)
        mockEngine.responseBodies["req-999"] = expectedBytes

        val manager = AgentNetworkManager(
            context = null,
            vpnEngineProvider = { mockEngine },
            rootChecker = { false }
        )
        manager.enable("com.example.target", CaptureMode.VPN_SERVICE)

        val bodyBytes = manager.getResponseBody("req-999")
        assertNotNull(bodyBytes)
        assertEquals("{\"status\":\"success\",\"token\":\"abc123xyz\"}", manager.getResponseBodyAsString("req-999"))

        assertNull(manager.getResponseBody("req-not-found"))
    }

    @Test
    fun testDisableAndClose() {
        val mockEngine = MockEngine(CaptureMode.ACTIVE_MODE_VPN_SERVICE, shouldSucceed = true)
        val manager = AgentNetworkManager(
            context = null,
            vpnEngineProvider = { mockEngine },
            rootChecker = { false }
        )

        manager.enable("com.example.target", CaptureMode.VPN_SERVICE)
        assertTrue(manager.isCapturing)
        assertEquals(1, mockEngine.startCount)

        manager.disable()
        assertFalse(manager.isCapturing)
        assertEquals(1, mockEngine.stopCount)
        assertNull(manager.targetPackage)

        manager.close()
        // close 后再次 enable 应直接返回 false
        assertFalse(manager.enable("com.example.target", CaptureMode.VPN_SERVICE))
    }
}
