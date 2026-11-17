package com.agent.use.common.network.parser

import com.agent.use.common.network.HttpRequestEvent
import com.agent.use.common.network.HttpResponseEvent
import com.agent.use.common.network.INetworkEventListener
import com.agent.use.common.network.NetworkCaptureConfig
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.charset.StandardCharsets
import java.util.Base64
import kotlin.random.Random

/**
 * HTTP/2 + HPACK 一致性测试。
 *
 * 所有字节流来自 [H2ConformanceFixtures]，由 `python-hpack` 编码、`python-h2` 反向校验，
 * 因此这里断言的不是"实现能解析自己造的数据"，而是"实现与第三方参考栈互操作"。
 *
 * 每个用例跑两遍：整块喂入，以及逐字节喂入。后者用来打掉所有
 * "假设一次回调拿到完整帧"的隐含前提——真实抓包里 TLS 分片可以切在任何位置。
 */
class Http2ConformanceTest {

    private class Captured {
        val requests = mutableListOf<HttpRequestEvent>()
        val responses = mutableListOf<HttpResponseEvent>()
        val bodies = mutableMapOf<String, ByteArray>()

        fun listener(): INetworkEventListener = object : INetworkEventListener.Stub() {
            override fun onRequestWillBeSent(event: HttpRequestEvent) {
                requests.add(event)
            }

            override fun onResponseReceived(event: HttpResponseEvent) {
                responses.add(event)
            }

            override fun onDataChunkReceived(requestId: String, chunk: ByteArray) {
                bodies[requestId] = chunk
            }

            override fun onErrorOccurred(requestId: String, error: String) {}
        }
    }

    private fun streamOf(requestId: String): Int =
        requestId.substringAfter("_h2_s", "").toIntOrNull() ?: -1

    private fun decode(b64: String): ByteArray = Base64.getDecoder().decode(b64)

    private fun newParser(captured: Captured): Http2PlaintextParser =
        Http2PlaintextParser(
            maxBodySizeBytes = 4L * 1024 * 1024,
            connectionHostHint = null,
            onParsedRequest = { captured.requests.add(it) },
            onParsedResponse = { captured.responses.add(it) },
            onBodyChunk = { id, chunk -> captured.bodies[id] = chunk },
        )

    private fun feedInChunks(parser: Http2PlaintextParser, data: ByteArray, chunkSize: Int, outbound: Boolean) {
        if (chunkSize <= 0 || chunkSize >= data.size) {
            if (outbound) parser.feedOutbound(data, "c") else parser.feedInbound(data, "c")
            return
        }
        var off = 0
        while (off < data.size) {
            val end = minOf(off + chunkSize, data.size)
            val slice = data.copyOfRange(off, end)
            if (outbound) parser.feedOutbound(slice, "c") else parser.feedInbound(slice, "c")
            off = end
        }
    }

    private fun runCase(case: H2ConformanceFixtures.Case, chunkSize: Int) {
        val captured = Captured()
        val parser = newParser(captured)

        // 真实抓包里两个方向是交织到达的；这里按"出站切片 → 入站切片"交替推进，
        // 保证任一方向的缓冲都可能在任意字节处被截断。
        val outbound = decode(case.outboundB64)
        val inbound = decode(case.inboundB64)
        feedInChunks(parser, outbound, chunkSize, outbound = true)
        feedInChunks(parser, inbound, chunkSize, outbound = false)

        assertEquals(
            "${case.name}: 请求数量",
            case.requests.size,
            captured.requests.size,
        )
        for (expected in case.requests) {
            val actual = captured.requests.firstOrNull { streamOf(it.requestId) == expected.stream }
            assertNotNull(
                "${case.name}: 缺少 stream ${expected.stream} 的请求，实际有 " +
                    captured.requests.map { streamOf(it.requestId) },
                actual,
            )
            assertEquals("${case.name}: stream ${expected.stream} method", expected.method, actual!!.method)
            assertEquals("${case.name}: stream ${expected.stream} url", expected.url, actual.url)
            if (expected.postContains != null) {
                assertTrue(
                    "${case.name}: stream ${expected.stream} postData=${actual.postData}",
                    actual.postData.orEmpty().contains(expected.postContains),
                )
            }
        }

        assertEquals(
            "${case.name}: 响应数量，实际 " + captured.responses.map { it.url },
            case.responses.size,
            captured.responses.size,
        )
        for (expected in case.responses) {
            val actual = captured.responses.firstOrNull { streamOf(it.requestId) == expected.stream }
            assertNotNull("${case.name}: 缺少 stream ${expected.stream} 的响应", actual)
            assertEquals("${case.name}: stream ${expected.stream} status", expected.status, actual!!.statusCode)
            if (expected.contentType != null) {
                assertTrue(
                    "${case.name}: stream ${expected.stream} contentType=${actual.mimeType}",
                    actual.mimeType.orEmpty().startsWith(expected.contentType),
                )
            }
            if (expected.extraHeader != null) {
                assertTrue(
                    "${case.name}: stream ${expected.stream} 缺少响应头 ${expected.extraHeader}，" +
                        actual.headers.map { it.name },
                    actual.headers.any { it.name.equals(expected.extraHeader, ignoreCase = true) },
                )
            }
            val body = captured.bodies[actual.requestId]
            assertNotNull("${case.name}: stream ${expected.stream} 没有响应体", body)
            assertEquals(
                "${case.name}: stream ${expected.stream} 响应体",
                expected.body,
                String(body!!, StandardCharsets.UTF_8),
            )
        }
    }

    @Test
    fun testReferenceStreamsFedWhole() {
        for (case in H2ConformanceFixtures.CASES) {
            runCase(case, chunkSize = Int.MAX_VALUE)
        }
    }

    @Test
    fun testReferenceStreamsFedByteByByte() {
        for (case in H2ConformanceFixtures.CASES) {
            runCase(case, chunkSize = 1)
        }
    }

    @Test
    fun testReferenceStreamsFedAtAwkwardBoundaries() {
        // 3 / 7 字节这类与帧头、HPACK 整数边界都错位的切片
        for (size in intArrayOf(3, 7, 13)) {
            for (case in H2ConformanceFixtures.CASES) {
                runCase(case, chunkSize = size)
            }
        }
    }

    @Test
    fun testFixtureTrafficIsDetectedAsHttp2() {
        for (case in H2ConformanceFixtures.CASES) {
            val outbound = decode(case.outboundB64)
            assertTrue(
                "${case.name}: 出站应被识别为 HTTP/2",
                TlsStreamParser.isHttp2Traffic(outbound),
            )
            val inbound = decode(case.inboundB64)
            assertTrue(
                "${case.name}: 入站应被识别为 HTTP/2",
                TlsStreamParser.startsWithHttp2Frame(inbound),
            )
        }
    }

    @Test
    fun testTlsStreamParserDecodesHttp2EndToEnd() {
        for (case in H2ConformanceFixtures.CASES) {
            val captured = Captured()
            val config = NetworkCaptureConfig(targetPackage = "com.example.h2conformance")
            val parser = TlsStreamParser(config, captured.listener())

            parser.onOutboundData("conn_${case.name}", decode(case.outboundB64))
            parser.onInboundData("conn_${case.name}", decode(case.inboundB64))

            assertEquals(
                "${case.name}: TlsStreamParser 请求数量",
                case.requests.size,
                captured.requests.size,
            )
            assertEquals(
                "${case.name}: TlsStreamParser 响应数量",
                case.responses.size,
                captured.responses.size,
            )
            for (expected in case.responses) {
                val actual = captured.responses.firstOrNull { streamOf(it.requestId) == expected.stream }
                assertNotNull("${case.name}: TlsStreamParser 缺少 stream ${expected.stream}", actual)
                assertEquals(expected.status, actual!!.statusCode)
                val body = parser.getResponseBody(actual.requestId)
                assertNotNull("${case.name}: TlsStreamParser 未缓存响应体", body)
                assertEquals(expected.body, String(body!!, StandardCharsets.UTF_8))
            }
            parser.finishConnection("conn_${case.name}")
        }
    }

    @Test
    fun testTruncatedStreamEmitsNothingInsteadOfThrowing() {
        val case = H2ConformanceFixtures.CASES.first { it.name == "continuation_split" }
        val captured = Captured()
        val parser = newParser(captured)
        val inbound = decode(case.inboundB64)

        // 只喂前 40% 的入站字节：帧与 HPACK 头块都必然被截断
        parser.feedInbound(inbound.copyOfRange(0, inbound.size * 4 / 10), "c")

        assertTrue(
            "截断的响应不应触发任何响应事件，实际 " + captured.responses.map { it.url },
            captured.responses.isEmpty(),
        )
        assertTrue("截断的响应不应触发请求事件", captured.requests.isEmpty())
    }

    @Test
    fun testRandomGarbageDoesNotThrow() {
        val random = Random(20261117)
        repeat(200) {
            val captured = Captured()
            val parser = newParser(captured)
            val garbage = ByteArray(random.nextInt(0, 512)).also { random.nextBytes(it) }
            parser.feedOutbound(garbage, "c")
            parser.feedInbound(garbage, "c")
            // 只要不抛异常即通过；同时不应产生"看起来正常"的空 URL 事件
            for (response in captured.responses) {
                assertFalse("随机数据不应产生空 URL 响应", response.url.isBlank())
            }
        }
    }

    @Test
    fun testHpackDynamicTableEvictionMatchesReference() {
        // dynamic_table_reuse 夹具的第 2 个请求会触发 Dynamic Table Size Update(256)，
        // 若解码器没有正确驱逐，第 3 个请求的索引会指向被丢弃的条目并解析出错误 :path。
        val case = H2ConformanceFixtures.CASES.first { it.name == "dynamic_table_reuse" }
        val captured = Captured()
        val parser = newParser(captured)
        parser.feedOutbound(decode(case.outboundB64), "c")

        val paths = captured.requests.map { it.url.substringAfter("api.example.com") }
        assertEquals(
            listOf("/v1/items?page=1", "/v1/items?page=2", "/v1/items?page=3"),
            paths,
        )
    }

    @Test
    fun testHpackIndexedFieldReuseAcrossHeaderBlocks() {
        // 同一连接内第二个请求应命中动态表索引；解码错位会表现为 header 名字变成上一个值
        val case = H2ConformanceFixtures.CASES.first { it.name == "dynamic_table_reuse" }
        val captured = Captured()
        val parser = newParser(captured)
        parser.feedOutbound(decode(case.outboundB64), "c")

        for (request in captured.requests) {
            assertTrue(
                "请求 ${request.url} 缺少 x-session 头",
                request.headers.any { it.name.equals("x-session", ignoreCase = true) },
            )
        }
    }

    @Test
    fun testGoawayFlushesTruncatedResponse() {
        // 服务端发完响应头和数据就 GOAWAY，没给 END_STREAM。
        // 不处理 GOAWAY 的话这条响应会连同连接一起消失。
        val case = H2ConformanceFixtures.CASES.first { it.name == "goaway_truncated" }
        val captured = Captured()
        val parser = newParser(captured)
        parser.feedOutbound(decode(case.outboundB64), "c")
        parser.feedInbound(decode(case.inboundB64), "c")

        assertEquals(1, captured.responses.size)
        val body = captured.bodies[captured.responses[0].requestId]
        assertNotNull("GOAWAY 之前收到的数据必须保留", body)
        assertEquals("partial-body-truncated", String(body!!, StandardCharsets.UTF_8))
    }

    @Test
    fun testFinishFlushesStreamsThatNeverSawEndStream() {
        val case = H2ConformanceFixtures.CASES.first { it.name == "goaway_truncated" }
        val captured = Captured()
        val parser = newParser(captured)
        parser.feedOutbound(decode(case.outboundB64), "c")

        // 去掉末尾 17 字节的 GOAWAY（9 字节帧头 + 8 字节载荷），
        // 于是这条流既没有 END_STREAM 也没有 GOAWAY，处于"悬空"状态。
        val inbound = decode(case.inboundB64)
        parser.feedInbound(inbound.copyOfRange(0, inbound.size - 17), "c")

        assertTrue(
            "既无 END_STREAM 也无 GOAWAY 时不应提前派发，实际 " + captured.responses.map { it.url },
            captured.responses.isEmpty(),
        )

        parser.finish()

        assertEquals("连接收尾时应把悬空流排空", 1, captured.responses.size)
        val body = captured.bodies[captured.responses[0].requestId]
        assertNotNull(body)
        assertEquals("partial-body-truncated", String(body!!, StandardCharsets.UTF_8))
    }

    @Test
    fun testTlsStreamParserFinishConnectionFlushesPendingHttp2() {
        val case = H2ConformanceFixtures.CASES.first { it.name == "goaway_truncated" }
        val captured = Captured()
        val config = NetworkCaptureConfig(targetPackage = "com.example.h2conformance")
        val parser = TlsStreamParser(config, captured.listener())

        parser.onOutboundData("conn", decode(case.outboundB64))
        val inbound = decode(case.inboundB64)
        parser.onInboundData("conn", inbound.copyOfRange(0, inbound.size - 17))
        assertTrue(captured.responses.isEmpty())

        parser.finishConnection("conn")

        assertEquals(1, captured.responses.size)
        assertNotNull(parser.getResponseBody(captured.responses[0].requestId))
    }

    @Test
    fun testPushPromiseAssignsRealUrlToPromisedStream() {
        val case = H2ConformanceFixtures.CASES.first { it.name == "push_promise" }
        val captured = Captured()
        val parser = newParser(captured)
        parser.feedOutbound(decode(case.outboundB64), "c")
        parser.feedInbound(decode(case.inboundB64), "c")

        val pushedResponse = captured.responses.firstOrNull { streamOf(it.requestId) == 2 }
        assertNotNull("promised stream 2 应产出响应", pushedResponse)
        assertEquals("https://api.example.com/v1/pushed", pushedResponse!!.url)

        // 推送资源没有客户端请求，必须有合成请求配对，否则响应在 UI 上会变成孤儿
        val pushedRequest = captured.requests.firstOrNull { streamOf(it.requestId) == 2 }
        assertNotNull("promised stream 2 应有配对的合成请求", pushedRequest)
        assertEquals("GET", pushedRequest!!.method)
        assertEquals("https://api.example.com/v1/pushed", pushedRequest.url)
    }

    @Test
    fun testNonPayloadFramesCreateNoStreamContexts() {
        val case = H2ConformanceFixtures.CASES.first { it.name == "priority_no_phantom" }
        val captured = Captured()
        val parser = newParser(captured)
        parser.feedOutbound(decode(case.outboundB64), "c")
        parser.feedInbound(decode(case.inboundB64), "c")

        // PRIORITY(stream 99) 与孤立的 CONTINUATION(stream 77) 都不承载 HTTP 语义
        assertEquals(1, captured.requests.size)
        assertEquals(1, captured.responses.size)
        assertEquals(
            "PRIORITY / 孤立 CONTINUATION 不应留下 StreamContext",
            0,
            liveStreamCount(parser),
        )
    }

    private fun liveStreamCount(parser: Http2PlaintextParser): Int {
        val field = Http2PlaintextParser::class.java.getDeclaredField("streams")
        field.isAccessible = true
        return (field.get(parser) as Map<*, *>).size
    }
}
