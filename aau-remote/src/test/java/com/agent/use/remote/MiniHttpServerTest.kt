package com.agent.use.remote

import com.agent.use.remote.http.HttpRequest
import com.agent.use.remote.http.HttpResponse
import com.agent.use.remote.http.MiniHttpServer
import java.io.ByteArrayOutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * keep-alive 流水线、正文超限、100-continue 的字节级断言。
 *
 * 只喂字节、不连端口：本机（开发沙箱）的透明代理会往回流环 HTTP 里塞 502 拦截页，或者把流水线合并成一条，
 * 那不是服务端行为。真连接只留一条冒烟用例，证明 accept→serve→close 的接线还在。
 */
class MiniHttpServerTest {
    private val loopback: InetAddress = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))

    private class Exchange(val reply: String, val served: Int)

    private fun exchange(
        request: String,
        handler: (HttpRequest) -> HttpResponse = { req -> HttpResponse(200, req.path.toByteArray(Charsets.UTF_8)) },
    ): Exchange {
        val output = ByteArrayOutputStream()
        val served = MiniHttpServer.serveRequests(
            input = request.byteInputStream(Charsets.ISO_8859_1),
            output = output,
            remote = loopback,
            handler = handler,
        )
        return Exchange(String(output.toByteArray(), Charsets.ISO_8859_1), served)
    }

    /** 放在关闭请求之后：它要是也被处理了，说明连接没关。 */
    private val afterClose = "GET /after HTTP/1.1\r\nHost: localhost\r\n\r\n"

    @Test fun keepsTheConnectionWhenCloseIsOnlyPartOfAnotherToken() {
        val sent = exchange(
            "GET /first HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive, x-close, close-extra\r\n\r\n" +
                "GET /second HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n$afterClose",
        )
        with(sent.reply) {
            assertEquals(this, 2, sent.served)
            assertTrue(this, startsWith("HTTP/1.1 200 "))
            assertTrue(this, contains("/firstHTTP/1.1 200 "))
            assertTrue(this, endsWith("/second"))
        }
    }

    @Test fun oversizeChunkIsRejectedAndTheServerKeepsServing() {
        val sent = exchange(
            "POST /mcp HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n7fffffff\r\n" +
                "POST /mcp HTTP/1.1\r\nHost: localhost\r\n\r\n",
        )
        assertEquals(sent.reply, 0, sent.served)
        assertTrue(sent.reply, sent.reply.startsWith("HTTP/1.1 413 "))
        assertTrue(sent.reply, sent.reply.contains("Connection: close"))
        assertFalse(sent.reply, sent.reply.contains("HTTP/1.1 200 "))
    }

    @Test fun rejectsBodiesAboveTheLimitBeforeReadingThem() {
        val sent = exchange("POST /mcp HTTP/1.1\r\nHost: localhost\r\nContent-Length: 999999\r\n\r\n")
        assertTrue(sent.reply, sent.reply.startsWith("HTTP/1.1 413 "))
    }

    @Test fun answersContinueThenTheRealResponse() {
        val sent = exchange(
            "POST /mcp HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n{}",
        )
        assertTrue(sent.reply, sent.reply.startsWith("HTTP/1.1 100 Continue"))
        assertTrue(sent.reply, sent.reply.contains("HTTP/1.1 200 "))
        assertEquals(sent.reply, 1, sent.served)
    }

    @Test fun reportsThePortTheSystemChose() {
        val server = MiniHttpServer(InetSocketAddress(loopback, 0), handler = { HttpResponse.empty(200) })
        server.start()
        try {
            assertTrue(server.port in 1..65535)
        } finally {
            server.stop()
        }
        assertEquals(-1, server.port)
    }

    /**
     * 真连接冒烟：accept → serve → 回字节。只断言第一个字节，字节级语义全在上面几条里。
     * 回环被过滤类代理接管时，第一个字节仍是它转发的响应首字节，这条用例不会因此变红。
     */
    @Test fun answersOnARealConnection() {
        val server = MiniHttpServer(InetSocketAddress(loopback, 0), handler = { HttpResponse.empty(200) })
        server.start()
        try {
            Socket(loopback, server.port).use { socket ->
                socket.soTimeout = 5_000
                socket.getOutputStream().write(
                    "GET /ping HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".toByteArray(Charsets.US_ASCII),
                )
                assertEquals('H'.code, socket.getInputStream().read())
            }
        } finally {
            server.stop()
        }
    }
}
