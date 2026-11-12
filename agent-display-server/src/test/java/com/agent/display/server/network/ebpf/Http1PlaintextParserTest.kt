package com.agent.display.server.network.ebpf

import com.agent.display.common.network.HttpRequestEvent
import com.agent.display.common.network.HttpResponseEvent
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.charset.StandardCharsets

class Http1PlaintextParserTest {

    @Test
    fun testParseHttp1GetRequest() {
        var parsedReq: HttpRequestEvent? = null

        val parser = Http1PlaintextParser(
            onParsedRequest = { parsedReq = it },
            onParsedResponse = {},
            onBodyChunk = { _, _ -> }
        )

        val rawRequest = "GET /api/v1/user/info?id=42 HTTP/1.1\r\n" +
                "Host: api.example.com\r\n" +
                "User-Agent: AAU-Agent/1.0\r\n" +
                "Accept: application/json\r\n\r\n"

        parser.feedOutbound(rawRequest.toByteArray(StandardCharsets.UTF_8), "conn_1")

        assertNotNull("Request should be parsed", parsedReq)
        assertEquals("GET", parsedReq!!.method)
        assertEquals("https://api.example.com/api/v1/user/info?id=42", parsedReq!!.url)
        assertEquals("AAU-Agent/1.0", parsedReq!!.getHeader("User-Agent"))
        assertTrue("isTls should be true for SSL_write", parsedReq!!.isTls)
    }

    @Test
    fun testParseHttp1PostWithBody() {
        var parsedReq: HttpRequestEvent? = null

        val parser = Http1PlaintextParser(
            onParsedRequest = { parsedReq = it },
            onParsedResponse = {},
            onBodyChunk = { _, _ -> }
        )

        val postPayload = """{"query":"test_agent"}"""
        val rawRequest = "POST /v1/chat/completions HTTP/1.1\r\n" +
                "Host: api.openai.com\r\n" +
                "Content-Type: application/json\r\n" +
                "Content-Length: ${postPayload.toByteArray().size}\r\n\r\n" +
                postPayload

        // 模拟分块到达
        val bytes = rawRequest.toByteArray(StandardCharsets.UTF_8)
        val chunk1 = bytes.copyOfRange(0, 40)
        val chunk2 = bytes.copyOfRange(40, bytes.size)

        parser.feedOutbound(chunk1, "conn_2")
        parser.feedOutbound(chunk2, "conn_2")

        assertNotNull("POST request should be parsed after body arrival", parsedReq)
        assertEquals("POST", parsedReq!!.method)
        assertEquals("https://api.openai.com/v1/chat/completions", parsedReq!!.url)
        assertEquals(postPayload, parsedReq!!.postData)
    }

    @Test
    fun testParseHttp1Response() {
        var parsedResp: HttpResponseEvent? = null
        val bodyChunks = mutableListOf<ByteArray>()

        val parser = Http1PlaintextParser(
            onParsedRequest = {},
            onParsedResponse = { parsedResp = it },
            onBodyChunk = { _, chunk -> bodyChunks.add(chunk) }
        )

        val responseBody = """{"status":"success","code":0}"""
        val rawResponse = "HTTP/1.1 200 OK\r\n" +
                "Content-Type: application/json; charset=utf-8\r\n" +
                "Content-Length: ${responseBody.toByteArray().size}\r\n" +
                "Server: nginx\r\n\r\n" +
                responseBody

        parser.feedInbound(rawResponse.toByteArray(StandardCharsets.UTF_8), "conn_3")

        assertNotNull("Response should be parsed", parsedResp)
        assertEquals(200, parsedResp!!.statusCode)
        assertEquals("OK", parsedResp!!.statusText)
        assertEquals("application/json; charset=utf-8", parsedResp!!.mimeType)
        assertTrue(parsedResp!!.isSuccess)

        val fullBody = bodyChunks.reduce { acc, b -> acc + b }
        assertEquals(responseBody, String(fullBody, StandardCharsets.UTF_8))
    }
}
