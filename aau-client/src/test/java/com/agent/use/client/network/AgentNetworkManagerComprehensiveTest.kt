package com.agent.use.client.network

import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleObserver
import androidx.lifecycle.LifecycleOwner
import com.agent.use.common.network.CaptureMode
import com.agent.use.common.network.HttpHeader
import com.agent.use.common.network.HttpRequestEvent
import com.agent.use.common.network.HttpResponseEvent
import com.agent.use.common.network.INetworkCapture
import com.agent.use.common.network.INetworkEventListener
import com.agent.use.common.network.NetworkCaptureConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.take
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger

/**
 * 深入验证 AgentNetworkManager 的复杂事件流订阅、超时控制、竞态时间窗口、
 * 容错降级分支与并发线程安全性。
 */
class AgentNetworkManagerComprehensiveTest {

    private class MockEngine(
        val mode: Int,
        var shouldSucceed: Boolean = true,
        var throwOnStart: Boolean = false
    ) : INetworkCapture.Stub() {
        val startCount = AtomicInteger(0)
        val stopCount = AtomicInteger(0)
        var lastListener: INetworkEventListener? = null
        val responseBodies = mutableMapOf<String, ByteArray>()

        override fun startCapture(config: NetworkCaptureConfig, listener: INetworkEventListener): Boolean {
            if (throwOnStart) {
                throw RuntimeException("Simulated Binder RemoteException in startCapture")
            }
            startCount.incrementAndGet()
            lastListener = listener
            return shouldSucceed
        }

        override fun stopCapture() {
            stopCount.incrementAndGet()
            lastListener = null
        }

        override fun getResponseBody(requestId: String): ByteArray? = responseBodies[requestId]

        override fun getActiveMode(): Int =
            if (startCount.get() > stopCount.get()) mode else CaptureMode.ACTIVE_MODE_NONE

        fun emitRequest(request: HttpRequestEvent) {
            lastListener?.onRequestWillBeSent(request)
        }

        fun emitResponse(response: HttpResponseEvent) {
            lastListener?.onResponseReceived(response)
        }

        fun emitChunk(requestId: String, chunk: ByteArray) {
            lastListener?.onDataChunkReceived(requestId, chunk)
        }

        fun emitError(requestId: String, errorMsg: String) {
            lastListener?.onErrorOccurred(requestId, errorMsg)
        }
    }

    @Test
    fun testWaitForResponse_CustomPredicateMatcher() = runTest {
        val mockVpn = MockEngine(CaptureMode.ACTIVE_MODE_VPN_SERVICE, shouldSucceed = true)
        val manager = AgentNetworkManager(
            vpnEngineProvider = { mockVpn },
            rootChecker = { false }
        )
        manager.enable("com.example.app", CaptureMode.VPN_SERVICE)

        val deferredWait = async {
            manager.waitForResponse(timeoutMs = 2000L) { resp ->
                resp.statusCode == 201 && resp.getHeader("X-Custom-Status") == "CreatedSuccessfully"
            }
        }

        delay(50)
        // 先发送一个不匹配的 200
        mockVpn.emitResponse(HttpResponseEvent(
            requestId = "r-1",
            timestamp = System.currentTimeMillis(),
            url = "https://api.example.com/items",
            statusCode = 200,
            statusText = "OK"
        ))

        // 再发送满足自定义谓词的 201
        val targetResp = HttpResponseEvent(
            requestId = "r-2",
            timestamp = System.currentTimeMillis(),
            url = "https://api.example.com/items",
            statusCode = 201,
            statusText = "Created",
            headers = mapOf("X-Custom-Status" to "CreatedSuccessfully")
        )
        mockVpn.emitResponse(targetResp)

        val result = deferredWait.await()
        assertEquals("r-2", result.requestId)
        assertEquals(201, result.statusCode)
        assertEquals("CreatedSuccessfully", result.getHeader("X-Custom-Status"))
    }

    @Test
    fun testWaitForResponse_AntiRaceWindowCatchesPriorResponse() = runTest {
        val mockVpn = MockEngine(CaptureMode.ACTIVE_MODE_VPN_SERVICE, shouldSucceed = true)
        val manager = AgentNetworkManager(
            vpnEngineProvider = { mockVpn },
            rootChecker = { false }
        )
        manager.enable("com.example.app", CaptureMode.VPN_SERVICE)

        // 模拟响应在调用 waitForResponse 之前 50ms 到达 (在 200ms 防先发窗口内)
        val now = System.currentTimeMillis()
        val priorResponse = HttpResponseEvent(
            requestId = "prior-1",
            timestamp = now - 50L,
            url = "https://api.example.com/fast/reply",
            statusCode = 200,
            statusText = "OK"
        )
        mockVpn.emitResponse(priorResponse)

        // 随后立即调用 waitForResponse
        val result = manager.waitForResponse("fast/reply", timeoutMs = 1000L)
        assertEquals("prior-1", result.requestId)
    }

    @Test
    fun testDataChunkFlowAndErrorFlowDistribution() = runTest {
        val mockVpn = MockEngine(CaptureMode.ACTIVE_MODE_VPN_SERVICE, shouldSucceed = true)
        val manager = AgentNetworkManager(
            vpnEngineProvider = { mockVpn },
            rootChecker = { false }
        )
        manager.enable("com.example.app", CaptureMode.VPN_SERVICE)

        val receivedChunks = mutableListOf<Pair<String, ByteArray>>()
        val receivedErrors = mutableListOf<Pair<String, String>>()

        val chunkJob = launch {
            manager.chunkFlow.collect { receivedChunks.add(it) }
        }
        val errorJob = launch {
            manager.errorFlow.collect { receivedErrors.add(it) }
        }

        delay(50)
        mockVpn.emitChunk("req-c1", "partA".toByteArray())
        mockVpn.emitChunk("req-c1", "partB".toByteArray())
        mockVpn.emitError("req-c2", "Connection reset")

        delay(50)
        chunkJob.cancel()
        errorJob.cancel()

        assertEquals(2, receivedChunks.size)
        assertEquals("req-c1", receivedChunks[0].first)
        assertArrayEquals("partA".toByteArray(), receivedChunks[0].second)
        assertEquals("req-c1", receivedChunks[1].first)
        assertArrayEquals("partB".toByteArray(), receivedChunks[1].second)

        assertEquals(1, receivedErrors.size)
        assertEquals("req-c2" to "Connection reset", receivedErrors[0])
    }

    @Test
    fun testValidation_EmptyTargetPackageFails() {
        val mockVpn = MockEngine(CaptureMode.ACTIVE_MODE_VPN_SERVICE, shouldSucceed = true)
        val manager = AgentNetworkManager(
            vpnEngineProvider = { mockVpn },
            rootChecker = { false }
        )

        assertFalse(manager.enable(""))
        assertFalse(manager.enable("   "))
        assertFalse(manager.isCapturing)
        assertEquals(0, mockVpn.startCount.get())
    }

    @Test
    fun testAutoSelection_ServerProviderThrows_FallsBackToVpn() {
        val mockEbpf = MockEngine(CaptureMode.ACTIVE_MODE_EBPF, throwOnStart = true)
        val mockVpn = MockEngine(CaptureMode.ACTIVE_MODE_VPN_SERVICE, shouldSucceed = true)

        val manager = AgentNetworkManager(
            vpnEngineProvider = { mockVpn },
            serverCaptureProvider = { mockEbpf },
            rootChecker = { true },
            kernelChecker = { true }
        )

        val started = manager.enable("com.example.app", CaptureMode.AUTO)
        assertTrue(started)
        assertTrue(manager.isCapturing)
        assertEquals(CaptureMode.VPN_SERVICE, manager.getActiveMode())
        assertEquals(1, mockVpn.startCount.get())
    }

    @Test
    fun testReconfiguration_ReEnablingStopsPreviousSession() {
        val mockVpn = MockEngine(CaptureMode.ACTIVE_MODE_VPN_SERVICE, shouldSucceed = true)
        val manager = AgentNetworkManager(
            vpnEngineProvider = { mockVpn },
            rootChecker = { false }
        )

        // 第一次启动
        assertTrue(manager.enable("com.app.first", CaptureMode.VPN_SERVICE))
        assertEquals("com.app.first", manager.targetPackage)
        assertEquals(1, mockVpn.startCount.get())
        assertEquals(0, mockVpn.stopCount.get())

        // 第二次启动针对新目标：应优雅停止前一次
        assertTrue(manager.enable("com.app.second", CaptureMode.VPN_SERVICE))
        assertEquals("com.app.second", manager.targetPackage)
        assertEquals(2, mockVpn.startCount.get())
        assertEquals(1, mockVpn.stopCount.get())
    }

    @Test
    fun testLifecycleOwner_AutomaticCleanupOnDestroy() {
        val mockVpn = MockEngine(CaptureMode.ACTIVE_MODE_VPN_SERVICE, shouldSucceed = true)
        val manager = AgentNetworkManager(
            vpnEngineProvider = { mockVpn },
            rootChecker = { false }
        )
        manager.enable("com.example.app", CaptureMode.VPN_SERVICE)
        assertTrue(manager.isCapturing)

        // 构造简易 Mock LifecycleOwner
        var registeredObserver: LifecycleObserver? = null
        val mockLifecycle = object : Lifecycle() {
            override fun addObserver(observer: LifecycleObserver) {
                registeredObserver = observer
            }
            override fun removeObserver(observer: LifecycleObserver) {
                if (registeredObserver == observer) registeredObserver = null
            }
            override val currentState: State = State.RESUMED
        }
        val mockOwner = object : LifecycleOwner {
            override val lifecycle: Lifecycle = mockLifecycle
        }

        manager.bindToLifecycle(mockOwner)
        assertNotNull(registeredObserver)

        // 触发 onDestroy
        (registeredObserver as? androidx.lifecycle.DefaultLifecycleObserver)?.onDestroy(mockOwner)

        assertFalse(manager.isCapturing)
        assertEquals(1, mockVpn.stopCount.get())
    }

    @Test
    fun testConcurrentEventsThreadSafety() = runTest {
        val mockVpn = MockEngine(CaptureMode.ACTIVE_MODE_VPN_SERVICE, shouldSucceed = true)
        val manager = AgentNetworkManager(
            vpnEngineProvider = { mockVpn },
            rootChecker = { false }
        )
        manager.enable("com.example.app", CaptureMode.VPN_SERVICE)

        val totalEvents = 100
        val collectedRequests = CopyOnWriteArrayList<HttpRequestEvent>()
        val collectedResponses = CopyOnWriteArrayList<HttpResponseEvent>()

        val subReq = manager.onRequest { collectedRequests.add(it) }
        val subResp = manager.onResponse { collectedResponses.add(it) }

        // 多协程高并发同时打入请求与响应
        val jobs = (1..totalEvents).map { i ->
            launch(Dispatchers.Default) {
                mockVpn.emitRequest(HttpRequestEvent("req-$i", url = "https://api.com/$i", method = "GET"))
                mockVpn.emitResponse(HttpResponseEvent("req-$i", url = "https://api.com/$i", statusCode = 200, statusText = "OK"))
            }
        }
        jobs.forEach { it.join() }

        assertEquals(totalEvents, collectedRequests.size)
        assertEquals(totalEvents, collectedResponses.size)

        subReq.close()
        subResp.close()
    }
}
