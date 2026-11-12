package com.agent.use.common.network

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class NetworkContractTest {

    @Test
    fun testCaptureModeEnumsAndConstants() {
        assertEquals(0, CaptureMode.AUTO.value)
        assertEquals(1, CaptureMode.EBPF.value)
        assertEquals(2, CaptureMode.VPN_SERVICE.value)

        assertEquals(0, CaptureMode.MODE_AUTO)
        assertEquals(1, CaptureMode.MODE_EBPF)
        assertEquals(2, CaptureMode.MODE_VPN_SERVICE)

        assertEquals(0, CaptureMode.ACTIVE_MODE_NONE)
        assertEquals(1, CaptureMode.ACTIVE_MODE_EBPF)
        assertEquals(2, CaptureMode.ACTIVE_MODE_VPN_SERVICE)

        assertEquals(CaptureMode.AUTO, CaptureMode.fromInt(0))
        assertEquals(CaptureMode.EBPF, CaptureMode.fromInt(1))
        assertEquals(CaptureMode.VPN_SERVICE, CaptureMode.fromInt(2))
        assertEquals(CaptureMode.AUTO, CaptureMode.fromInt(99)) // default fallback
    }

    @Test
    fun testNetworkCaptureConfigDefaultsAndMethods() {
        val config = NetworkCaptureConfig(
            targetPackage = "com.tencent.mm",
            targetUid = 10123,
            mode = CaptureMode.EBPF,
            urlFilterPattern = "https://.*api\\.weixin\\.qq\\.com/.*"
        )

        assertEquals("com.tencent.mm", config.targetPackage)
        assertEquals(10123, config.targetUid)
        assertEquals(CaptureMode.EBPF, config.mode)
        assertEquals(CaptureMode.MODE_EBPF, config.captureMode)
        assertEquals(NetworkCaptureConfig.DEFAULT_MAX_BODY_SIZE_BYTES, config.maxBodySizeBytes)

        assertTrue(config.matchesUrl("https://api.weixin.qq.com/cgi-bin/token"))
        assertFalse(config.matchesUrl("https://other.domain.com/index.html"))

        val defaultConfig = NetworkCaptureConfig.createDefault("com.example.app")
        assertEquals("com.example.app", defaultConfig.targetPackage)
        assertEquals(-1, defaultConfig.targetUid)
        assertEquals(CaptureMode.AUTO, defaultConfig.mode)
        assertTrue(defaultConfig.matchesUrl("https://any.url.com"))
    }

    @Test
    fun testHttpHeadersAndExtensions() {
        val headers = listOf(
            HttpHeader("Content-Type", "application/json; charset=utf-8"),
            HttpHeader("Authorization", "Bearer token123"),
            HttpHeader("X-Custom-Header", "Value1"),
            HttpHeader("x-custom-header", "Value2")
        )

        assertEquals("application/json; charset=utf-8", headers.getIgnoreCase("content-type"))
        assertEquals("Bearer token123", headers.getIgnoreCase("AUTHORIZATION"))
        assertNull(headers.getIgnoreCase("Non-Existent"))

        val allCustom = headers.getAllIgnoreCase("x-custom-header")
        assertEquals(2, allCustom.size)
        assertEquals(listOf("Value1", "Value2"), allCustom)

        val map = mapOf("Host" to "example.com", "Accept" to "*/*")
        val convertedHeaders = map.toHttpHeaders()
        assertEquals(2, convertedHeaders.size)
        assertEquals("example.com", convertedHeaders.toMap()["Host"])
    }

    @Test
    fun testHttpRequestEvent() {
        val request = HttpRequestEvent(
            requestId = "req-001",
            timestamp = 1700000000000L,
            url = "https://api.example.com/v1/users",
            method = "POST",
            headers = mapOf("Content-Type" to "application/json"),
            postData = "{\"name\":\"test\"}",
            isTls = true
        )

        assertEquals("req-001", request.requestId)
        assertEquals(1700000000000L, request.timestamp)
        assertEquals("https://api.example.com/v1/users", request.url)
        assertEquals("POST", request.method)
        assertEquals("application/json", request.getHeader("content-type"))
        assertEquals("{\"name\":\"test\"}", request.postData)
        assertNotNull(request.postDataBytes)
        assertEquals("{\"name\":\"test\"}", request.postDataBytes?.let { String(it) })
        assertTrue(request.isTls)
    }

    @Test
    fun testHttpResponseEvent() {
        val response = HttpResponseEvent(
            requestId = "req-001",
            timestamp = 1700000001000L,
            url = "https://api.example.com/v1/users",
            statusCode = 200,
            statusText = "OK",
            headers = mapOf("Content-Type" to "application/json", "Content-Length" to "42"),
            mimeType = "application/json",
            contentLength = 42L,
            fromCache = false
        )

        assertEquals("req-001", response.requestId)
        assertEquals(200, response.statusCode)
        assertEquals("OK", response.statusText)
        assertEquals("application/json", response.mimeType)
        assertEquals(42L, response.contentLength)
        assertFalse(response.fromCache)
        assertTrue(response.isSuccess)
        assertEquals("application/json", response.getHeader("content-type"))
    }

    @Test
    fun testAidlInterfacesSubclassing() {
        var captureStarted = false
        var capturedConfig: NetworkCaptureConfig? = null

        val captureInstance = object : INetworkCapture {
            private var activeMode: Int = CaptureMode.ACTIVE_MODE_NONE

            override fun startCapture(config: NetworkCaptureConfig, listener: INetworkEventListener): Boolean {
                capturedConfig = config
                activeMode = config.captureMode
                captureStarted = true
                return true
            }

            override fun stopCapture() {
                activeMode = CaptureMode.ACTIVE_MODE_NONE
                captureStarted = false
            }

            override fun getResponseBody(requestId: String): ByteArray {
                return "{\"status\":\"ok\"}".toByteArray(Charsets.UTF_8)
            }

            override fun getActiveMode(): Int {
                return activeMode
            }

            override fun asBinder(): android.os.IBinder? = null
        }

        var receivedReqId: String? = null
        var receivedChunk: ByteArray? = null
        val listenerInstance = object : INetworkEventListener {
            override fun onRequestWillBeSent(request: HttpRequestEvent) {
                receivedReqId = request.requestId
            }

            override fun onResponseReceived(response: HttpResponseEvent) {
                receivedReqId = response.requestId
            }

            override fun onDataChunkReceived(requestId: String, chunk: ByteArray) {
                receivedChunk = chunk
            }

            override fun onErrorOccurred(requestId: String, errorMsg: String) {
            }

            override fun asBinder(): android.os.IBinder? = null
        }

        val config = NetworkCaptureConfig(targetPackage = "com.test.pkg", mode = CaptureMode.EBPF)
        val started = captureInstance.startCapture(config, listenerInstance)
        assertTrue(started)
        assertTrue(captureStarted)
        assertEquals(CaptureMode.ACTIVE_MODE_EBPF, captureInstance.activeMode)

        listenerInstance.onRequestWillBeSent(HttpRequestEvent(requestId = "r1", url = "http://a", method = "GET"))
        assertEquals("r1", receivedReqId)

        val body = captureInstance.getResponseBody("r1")
        assertEquals("{\"status\":\"ok\"}", String(body, Charsets.UTF_8))

        captureInstance.stopCapture()
        assertFalse(captureStarted)
        assertEquals(CaptureMode.ACTIVE_MODE_NONE, captureInstance.activeMode)
    }
}
