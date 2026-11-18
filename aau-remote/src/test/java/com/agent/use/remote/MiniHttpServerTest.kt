package com.agent.use.remote

import com.agent.use.remote.http.HttpResponse
import com.agent.use.remote.http.MiniHttpServer
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeFalse
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * 真连一次本地端口：keep-alive 流水线、正文超限、100-continue。
 *
 * 注意：本机（开发沙箱）的透明代理会往回环 HTTP 流里塞一张 502 阻塞页，那不是服务端行为。
 * 这类环境下相关用例跳过，干净环境里照常断言。
 */
class MiniHttpServerTest {
    private val loopback: InetAddress = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))

    private fun exchange(request: String, maxConnections: Int = 16): String {
        val server = MiniHttpServer(
            InetSocketAddress(loopback, 0),
            handler = { req -> HttpResponse(200, req.path.toByteArray(Charsets.UTF_8)) },
            maxConnections = maxConnections,
        )
        return Socket().use { socket ->
            server.start()
            try {
                socket.connect(InetSocketAddress(loopback, server.port), 2_000)
                socket.soTimeout = 2_000
                socket.getOutputStream().write(request.toByteArray(Charsets.ISO_8859_1))
                socket.getInputStream().bufferedReader().readText()
            } finally {
                server.stop()
            }
        }
    }

    /** 被代理插过手的响应不能拿来断言。 */
    private fun String.notIntercepted(): String {
        assumeFalse("loopback HTTP is intercepted here", contains("AdGuard") || contains("502 Bad Gateway"))
        return this
    }

    @Test fun keepsTheConnectionWhenCloseIsOnlyPartOfAnotherToken() {
        val reply = exchange(
            "GET /first HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive, x-close, close-extra\r\n\r\n" +
                "GET /second HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        ).notIntercepted()
        assertTrue(reply, reply.startsWith("HTTP/1.1 200 "))
        assertTrue(reply, reply.contains("/firstHTTP/1.1 200 "))
        assertTrue(reply, reply.endsWith("/second"))
    }

    @Test fun oversizeChunkIsRejectedAndTheServerKeepsServing() {
        val reply = runCatching {
            exchange("POST /mcp HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n7fffffff\r\n")
        }.getOrElse {
            assumeTrue("loopback HTTP is intercepted here: ${it.message}", false)
            ""
        }.notIntercepted()
        assertTrue(reply, reply.startsWith("HTTP/1.1 413 "))
        assertTrue(reply, reply.contains("Connection: close"))
    }

    @Test fun rejectsBodiesAboveTheLimitBeforeReadingThem() {
        val reply = exchange(
            "POST /mcp HTTP/1.1\r\nHost: localhost\r\nContent-Length: 999999\r\n\r\n",
        ).notIntercepted()
        assertTrue(reply, reply.startsWith("HTTP/1.1 413 "))
    }

    @Test fun answersContinueThenTheRealResponse() {
        val reply = runCatching {
            exchange("POST /mcp HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n{}")
        }.getOrElse {
            assumeTrue("loopback HTTP is intercepted here: ${it.message}", false)
            ""
        }.notIntercepted()
        assertTrue(reply, reply.startsWith("HTTP/1.1 100 Continue"))
        assertTrue(reply, reply.contains("HTTP/1.1 200 "))
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
}
