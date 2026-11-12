package com.agent.display.server.network.ebpf

import com.agent.display.common.network.HttpRequestEvent
import com.agent.display.common.network.HttpResponseEvent
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets

class Http2PlaintextParserTest {

    @Test
    fun testHpackStaticTableDecoding() {
        val decoder = Http2HpackDecoder()

        // 构造带索引字段的二进制数据:
        // 0x82 -> 索引 2 (:method: GET)
        // 0x87 -> 索引 7 (:scheme: https)
        // 0x84 -> 索引 4 (:path: /)
        val headerBlock = byteArrayOf(
            0x82.toByte(),
            0x87.toByte(),
            0x84.toByte()
        )

        val headers = decoder.decode(headerBlock)
        assertEquals(3, headers.size)
        assertEquals(":method", headers[0].name)
        assertEquals("GET", headers[0].value)
        assertEquals(":scheme", headers[1].name)
        assertEquals("https", headers[1].value)
        assertEquals(":path", headers[2].name)
        assertEquals("/", headers[2].value)
    }

    @Test
    fun testHttp2FrameParsing() {
        var parsedReq: HttpRequestEvent? = null
        var parsedResp: HttpResponseEvent? = null
        val bodyChunks = mutableListOf<ByteArray>()

        val parser = Http2PlaintextParser(
            onParsedRequest = { parsedReq = it },
            onParsedResponse = { parsedResp = it },
            onBodyChunk = { _, chunk -> bodyChunks.add(chunk) }
        )

        // 构造出站 Client Preface + HEADERS Frame
        val preface = Http2PlaintextParser.CLIENT_PREFACE

        // HEADERS Frame:
        // Length = 3 (0x000003), Type = 0x1 (HEADERS), Flags = 0x5 (END_STREAM | END_HEADERS), StreamID = 1
        val hpackBlock = byteArrayOf(
            0x82.toByte(), // :method: GET
            0x87.toByte(), // :scheme: https
            0x84.toByte()  // :path: /
        )

        val frameOut = ByteArrayOutputStream()
        frameOut.write(preface)
        // 9 字节 Frame Header
        frameOut.write(byteArrayOf(0x00, 0x00, 0x03)) // Length: 3
        frameOut.write(0x01) // Type: HEADERS
        frameOut.write(0x05) // Flags: END_STREAM | END_HEADERS
        frameOut.write(byteArrayOf(0x00, 0x00, 0x00, 0x01)) // StreamID: 1
        frameOut.write(hpackBlock)

        parser.feedOutbound(frameOut.toByteArray(), "h2_conn_1")

        assertNotNull("HTTP/2 request should be parsed", parsedReq)
        assertEquals("GET", parsedReq!!.method)
        assertEquals("https://localhost/", parsedReq!!.url)

        // 构造入站响应 HEADERS Frame + DATA Frame
        // HEADERS Frame: Length = 1, Type = 0x1 (HEADERS), Flags = 0x4 (END_HEADERS), StreamID = 1
        // HPACK: 0x88 -> :status: 200
        val respHeadersFrame = ByteArrayOutputStream()
        respHeadersFrame.write(byteArrayOf(0x00, 0x00, 0x01))
        respHeadersFrame.write(0x01) // HEADERS
        respHeadersFrame.write(0x04) // END_HEADERS
        respHeadersFrame.write(byteArrayOf(0x00, 0x00, 0x00, 0x01)) // StreamID: 1
        respHeadersFrame.write(0x88) // :status: 200

        // DATA Frame: Length = 5 ("hello"), Type = 0x0 (DATA), Flags = 0x1 (END_STREAM), StreamID = 1
        val dataPayload = "hello".toByteArray(StandardCharsets.UTF_8)
        val respDataFrame = ByteArrayOutputStream()
        respDataFrame.write(byteArrayOf(0x00, 0x00, 0x05))
        respDataFrame.write(0x00) // DATA
        respDataFrame.write(0x01) // END_STREAM
        respDataFrame.write(byteArrayOf(0x00, 0x00, 0x00, 0x01)) // StreamID: 1
        respDataFrame.write(dataPayload)

        parser.feedInbound(respHeadersFrame.toByteArray(), "h2_conn_1")
        parser.feedInbound(respDataFrame.toByteArray(), "h2_conn_1")

        assertNotNull("HTTP/2 response should be parsed", parsedResp)
        assertEquals(200, parsedResp!!.statusCode)
        assertEquals(1, bodyChunks.size)
        assertEquals("hello", String(bodyChunks[0], StandardCharsets.UTF_8))
    }
}
