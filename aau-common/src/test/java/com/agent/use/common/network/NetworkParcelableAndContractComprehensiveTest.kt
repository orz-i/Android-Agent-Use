package com.agent.use.common.network

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 深入验证通用网络抓包契约、模型边界值、大小写不敏感检索及 AIDL 多态回调。
 */
class NetworkParcelableAndContractComprehensiveTest {

    @Test
    fun testCaptureModeValuesAndConversions() {
        // 枚举与底层 AIDL int 值的一致性映射
        assertEquals(CaptureMode.MODE_AUTO, CaptureMode.AUTO.value)
        assertEquals(CaptureMode.MODE_EBPF, CaptureMode.EBPF.value)
        assertEquals(CaptureMode.MODE_VPN_SERVICE, CaptureMode.VPN_SERVICE.value)

        // 边界值及异常值回退测试
        assertEquals(CaptureMode.AUTO, CaptureMode.fromInt(-1))
        assertEquals(CaptureMode.AUTO, CaptureMode.fromInt(999))
        assertEquals(CaptureMode.EBPF, CaptureMode.fromInt(1))
        assertEquals(CaptureMode.VPN_SERVICE, CaptureMode.fromInt(2))
    }

    @Test
    fun testNetworkCaptureConfigRegexRobustness() {
        // 1. null 规则：全匹配
        val configNullPattern = NetworkCaptureConfig(
            targetPackage = "com.test.app",
            urlFilterPattern = null
        )
        assertTrue(configNullPattern.matchesUrl("https://api.github.com/events"))
        assertTrue(configNullPattern.matchesUrl("http://localhost:8080"))

        // 2. 正常正则规则匹配
        val configRegex = NetworkCaptureConfig(
            targetPackage = "com.test.app",
            urlFilterPattern = "^https://api\\.(example|test)\\.com/v[12]/.*"
        )
        assertTrue(configRegex.matchesUrl("https://api.example.com/v1/users"))
        assertTrue(configRegex.matchesUrl("https://api.test.com/v2/items?id=10"))
        assertFalse(configRegex.matchesUrl("https://api.other.com/v1/users"))
        assertFalse(configRegex.matchesUrl("http://api.example.com/v1/users"))

        // 3. 非法正则规则容错：不崩溃且宽松放行
        val configInvalidRegex = NetworkCaptureConfig(
            targetPackage = "com.test.app",
            urlFilterPattern = "[a-z" // 缺少闭合括号的非法正则
        )
        assertTrue(configInvalidRegex.matchesUrl("https://any.domain.com/path"))
    }

    @Test
    fun testNetworkCaptureConfigConstructors() {
        val configDefault = NetworkCaptureConfig.createDefault("org.example.demo", 10050)
        assertEquals("org.example.demo", configDefault.targetPackage)
        assertEquals(10050, configDefault.targetUid)
        assertEquals(CaptureMode.AUTO, configDefault.mode)
        assertEquals(NetworkCaptureConfig.DEFAULT_MAX_BODY_SIZE_BYTES, configDefault.maxBodySizeBytes)

        val configEnumConstructor = NetworkCaptureConfig(
            targetPackage = "org.example.demo",
            mode = CaptureMode.VPN_SERVICE,
            targetUid = 2000,
            maxBodySizeBytes = 1024 * 1024L,
            urlFilterPattern = ".*\\.json$"
        )
        assertEquals(CaptureMode.VPN_SERVICE, configEnumConstructor.mode)
        assertEquals(CaptureMode.MODE_VPN_SERVICE, configEnumConstructor.captureMode)
        assertEquals(1024 * 1024L, configEnumConstructor.maxBodySizeBytes)
    }

    @Test
    fun testHttpHeaderMultiValueAndCaseInsensitivity() {
        val headerList = listOf(
            HttpHeader("Content-Type", "application/json"),
            HttpHeader("Set-Cookie", "session=abc"),
            HttpHeader("set-cookie", "token=xyz"),
            HttpHeader("X-Trace-Id", "trace-001"),
            HttpHeader("Accept", "text/html"),
            HttpHeader("ACCEPT", "application/json")
        )

        // getIgnoreCase 返回首个匹配项
        assertEquals("application/json", headerList.getIgnoreCase("content-type"))
        assertEquals("application/json", headerList.getIgnoreCase("CONTENT-TYPE"))
        assertEquals("session=abc", headerList.getIgnoreCase("set-cookie"))
        assertEquals("text/html", headerList.getIgnoreCase("accept"))
        assertNull(headerList.getIgnoreCase("authorization"))

        // getAllIgnoreCase 返回所有匹配项
        val cookies = headerList.getAllIgnoreCase("Set-Cookie")
        assertEquals(2, cookies.size)
        assertEquals("session=abc", cookies[0])
        assertEquals("token=xyz", cookies[1])

        val accepts = headerList.getAllIgnoreCase("accept")
        assertEquals(listOf("text/html", "application/json"), accepts)

        // toMap 行为：后出现的覆盖先出现的
        val headerMap = headerList.toMap()
        assertEquals("application/json", headerMap["Content-Type"])
        assertEquals("trace-001", headerMap["X-Trace-Id"])
    }

    @Test
    fun testHttpRequestEventConstructorsAndHelpers() {
        // 构造器 1: Map 传入 Headers
        val mapHeaders = mapOf(
            "Content-Type" to "application/x-www-form-urlencoded",
            "User-Agent" to "AAU-Test-Agent/1.0"
        )
        val reqFromMap = HttpRequestEvent(
            requestId = "req-101",
            timestamp = 1600000000000L,
            url = "https://example.com/login",
            method = "POST",
            headers = mapHeaders,
            postData = "user=admin&pass=123456",
            isTls = true
        )
        assertEquals("application/x-www-form-urlencoded", reqFromMap.getHeader("content-type"))
        assertEquals("AAU-Test-Agent/1.0", reqFromMap.headerMap()["User-Agent"])
        assertEquals("user=admin&pass=123456", reqFromMap.postData)
        assertArrayEquals("user=admin&pass=123456".toByteArray(Charsets.UTF_8), reqFromMap.postDataBytes)

        // 构造器 2: ByteArray 传入 PostData
        val binaryData = "binary_payload_test".toByteArray(Charsets.UTF_8)
        val reqFromBytes = HttpRequestEvent(
            requestId = "req-102",
            timestamp = 1600000001000L,
            url = "http://plain.example.com/upload",
            method = "PUT",
            headers = listOf(HttpHeader("Content-Type", "application/octet-stream")),
            postDataBytes = binaryData,
            isTls = false
        )
        assertFalse(reqFromBytes.isTls)
        assertEquals("binary_payload_test", reqFromBytes.postData)
        assertArrayEquals(binaryData, reqFromBytes.postDataBytes)

        // 无 postData 情况
        val getReq = HttpRequestEvent(
            requestId = "req-103",
            url = "https://example.com/items",
            method = "GET"
        )
        assertNull(getReq.postData)
        assertNull(getReq.postDataBytes)
        assertTrue(getReq.isTls)
        assertTrue(getReq.headers.isEmpty())
    }

    @Test
    fun testHttpResponseEventStatusRangeAndMime() {
        fun createResp(status: Int) = HttpResponseEvent(
            requestId = "resp-1",
            url = "https://example.com",
            statusCode = status,
            statusText = "Status-$status"
        )

        assertFalse(createResp(101).isSuccess)
        assertFalse(createResp(199).isSuccess)
        assertTrue(createResp(200).isSuccess)
        assertTrue(createResp(204).isSuccess)
        assertTrue(createResp(299).isSuccess)
        assertFalse(createResp(301).isSuccess)
        assertFalse(createResp(400).isSuccess)
        assertFalse(createResp(404).isSuccess)
        assertFalse(createResp(500).isSuccess)

        val jsonResp = HttpResponseEvent(
            requestId = "resp-2",
            timestamp = 1700000005000L,
            url = "https://example.com/api",
            statusCode = 200,
            statusText = "OK",
            headers = mapOf("Content-Type" to "application/json; charset=UTF-8"),
            mimeType = "application/json",
            contentLength = 128L,
            fromCache = true
        )
        assertTrue(jsonResp.fromCache)
        assertEquals(128L, jsonResp.contentLength)
        assertEquals("application/json", jsonResp.mimeType)
        assertEquals("application/json; charset=UTF-8", jsonResp.getHeader("Content-Type"))
    }

    @Test
    fun testNetworkEventListenerCompleteFlow() {
        val events = mutableListOf<String>()
        val dataChunks = mutableMapOf<String, MutableList<ByteArray>>()

        val listener = object : INetworkEventListener {
            override fun onRequestWillBeSent(request: HttpRequestEvent) {
                events.add("REQ:${request.requestId}:${request.method}:${request.url}")
            }

            override fun onResponseReceived(response: HttpResponseEvent) {
                events.add("RESP:${response.requestId}:${response.statusCode}")
            }

            override fun onDataChunkReceived(requestId: String, chunk: ByteArray) {
                dataChunks.getOrPut(requestId) { mutableListOf() }.add(chunk)
                events.add("CHUNK:$requestId:${chunk.size}")
            }

            override fun onErrorOccurred(requestId: String, errorMsg: String) {
                events.add("ERR:$requestId:$errorMsg")
            }

            override fun asBinder(): android.os.IBinder? = null
        }

        // 模拟请求发送 -> 响应到达 -> 分块数据到达 -> 完成
        listener.onRequestWillBeSent(HttpRequestEvent(requestId = "r-1", url = "https://example.com", method = "GET"))
        listener.onResponseReceived(HttpResponseEvent(requestId = "r-1", url = "https://example.com", statusCode = 200, statusText = "OK"))
        listener.onDataChunkReceived("r-1", "chunk1".toByteArray())
        listener.onDataChunkReceived("r-1", "chunk2".toByteArray())

        // 模拟异常请求
        listener.onRequestWillBeSent(HttpRequestEvent(requestId = "r-2", url = "https://fail.example.com", method = "POST"))
        listener.onErrorOccurred("r-2", "Connection reset by peer")

        assertEquals(6, events.size)
        assertEquals("REQ:r-1:GET:https://example.com", events[0])
        assertEquals("RESP:r-1:200", events[1])
        assertEquals("CHUNK:r-1:6", events[2])
        assertEquals("CHUNK:r-1:6", events[3])
        assertEquals("REQ:r-2:POST:https://fail.example.com", events[4])
        assertEquals("ERR:r-2:Connection reset by peer", events[5])

        val chunks = dataChunks["r-1"]
        assertNotNull(chunks)
        assertEquals(2, chunks?.size)
    }
}
