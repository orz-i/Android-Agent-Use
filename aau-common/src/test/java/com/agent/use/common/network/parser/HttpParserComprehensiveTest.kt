package com.agent.use.common.network.parser

import com.agent.use.common.network.HttpHeader
import com.agent.use.common.network.HttpRequestEvent
import com.agent.use.common.network.HttpResponseEvent
import com.agent.use.common.network.INetworkEventListener
import com.agent.use.common.network.NetworkCaptureConfig
import com.agent.use.common.network.plugin.NetworkCapturePluginRegistry
import com.agent.use.common.network.plugin.NetworkTrafficMiddleware
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets
import java.util.zip.GZIPOutputStream

class HttpParserComprehensiveTest {

    private fun huffmanEncode(text: String): ByteArray {
        val bytes = text.toByteArray(StandardCharsets.UTF_8)
        val out = ByteArrayOutputStream()
        var current = 0
        var nbits = 0
        for (b in bytes) {
            val sym = b.toInt() and 0xFF
            val code = Http2Huffman.CODES[sym]
            val bits = Http2Huffman.CODE_LENGTHS[sym]
            for (i in bits - 1 downTo 0) {
                current = (current shl 1) or ((code ushr i) and 1)
                nbits++
                if (nbits == 8) {
                    out.write(current)
                    current = 0
                    nbits = 0
                }
            }
        }
        if (nbits > 0) {
            current = (current shl (8 - nbits)) or ((1 shl (8 - nbits)) - 1)
            out.write(current)
        }
        return out.toByteArray()
    }

    private fun gzipCompress(text: String): ByteArray {
        val out = ByteArrayOutputStream()
        GZIPOutputStream(out).use { it.write(text.toByteArray(StandardCharsets.UTF_8)) }
        return out.toByteArray()
    }

    private fun h2Frame(type: Int, flags: Int, streamId: Int, payload: ByteArray): ByteArray {
        val out = ByteArrayOutputStream(9 + payload.size)
        val len = payload.size
        out.write((len ushr 16) and 0xFF)
        out.write((len ushr 8) and 0xFF)
        out.write(len and 0xFF)
        out.write(type and 0xFF)
        out.write(flags and 0xFF)
        out.write((streamId ushr 24) and 0x7F)
        out.write((streamId ushr 16) and 0xFF)
        out.write((streamId ushr 8) and 0xFF)
        out.write(streamId and 0xFF)
        out.write(payload)
        return out.toByteArray()
    }

    private fun hpackLiteralInc(nameIdx: Int, value: String, huffman: Boolean = false): ByteArray {
        val raw = if (huffman) huffmanEncode(value) else value.toByteArray(StandardCharsets.UTF_8)
        val out = ByteArrayOutputStream()
        // Assumes nameIdx < 63 for concise test encoding
        out.write(0x40 or (nameIdx and 0x3F))
        val hFlag = if (huffman) 0x80 else 0x00
        if (raw.size < 127) {
            out.write(hFlag or raw.size)
        } else {
            out.write(hFlag or 127)
            var rem = raw.size - 127
            while (rem >= 128) {
                out.write((rem and 0x7F) or 0x80)
                rem = rem ushr 7
            }
            out.write(rem)
        }
        out.write(raw)
        return out.toByteArray()
    }

    @Test
    fun testRfc7541HuffmanKraftSumAndQueryUrlRoundtrip() {
        var kraftSum = 0L
        for (len in Http2Huffman.CODE_LENGTHS) {
            kraftSum += 1L shl (30 - len)
        }
        assertEquals("RFC 7541 Huffman prefix tree must be complete (Kraft sum == 2^30)", 1L shl 30, kraftSum)

        val queryUrl = "/v2/search?q=coffee+tea&page=1&sort=desc#top"
        val encoded = huffmanEncode(queryUrl)
        assertEquals(queryUrl, Http2Huffman.decodeToString(encoded))
    }

    @Test
    fun testHttp2SeparateHpackDynamicTableAndBodyBeforeResponseEvent() {
        val requests = mutableListOf<HttpRequestEvent>()
        val responses = mutableListOf<HttpResponseEvent>()
        val cachedBodies = HashMap<String, ByteArray>()

        val parser = Http2PlaintextParser(
            onParsedRequest = { requests.add(it) },
            onParsedResponse = { resp ->
                assertTrue(
                    "Response body must be delivered via onBodyChunk BEFORE onParsedResponse fires",
                    cachedBodies.containsKey(resp.requestId)
                )
                responses.add(resp)
            },
            onBodyChunk = { reqId, chunk ->
                val prev = cachedBodies[reqId] ?: ByteArray(0)
                cachedBodies[reqId] = prev + chunk
            }
        )

        // Client preface + Stream 1 GET /v1/feed?tag=a+b (Huffman + incremental indexing)
        val req1Headers = ByteArrayOutputStream().apply {
            write(0x82) // :method: GET
            write(0x87) // :scheme: https
            write(hpackLiteralInc(1, "api.example.com", huffman = true)) // dyn[62] = :authority: api.example.com
            write(hpackLiteralInc(4, "/v1/feed?tag=a+b", huffman = true)) // dyn[63] = :path
        }.toByteArray()
        parser.feedOutbound(
            Http2PlaintextParser.CLIENT_PREFACE +
                h2Frame(Http2PlaintextParser.FRAME_TYPE_HEADERS, Http2PlaintextParser.FLAG_END_HEADERS or Http2PlaintextParser.FLAG_END_STREAM, 1, req1Headers),
            "conn_h2"
        )

        assertEquals(1, requests.size)
        assertEquals("https://api.example.com/v1/feed?tag=a+b", requests[0].url)

        // Server response on Stream 1: HEADERS (indexes :authority/server in INBOUND dynamic table!) + gzip DATA (END_STREAM)
        val gzBody = gzipCompress("""{"items":[1,2,3]}""")
        val resp1Headers = ByteArrayOutputStream().apply {
            write(0x88) // :status: 200
            write(hpackLiteralInc(26, "gzip")) // content-encoding: gzip
            write(hpackLiteralInc(31, "application/json")) // content-type: application/json
        }.toByteArray()

        // First deliver HEADERS without END_STREAM: response event must NOT fire yet!
        parser.feedInbound(
            h2Frame(Http2PlaintextParser.FRAME_TYPE_HEADERS, Http2PlaintextParser.FLAG_END_HEADERS, 1, resp1Headers),
            "conn_h2"
        )
        assertEquals("HEADERS alone without END_STREAM must not emit response", 0, responses.size)

        // Now deliver DATA with END_STREAM: must decompress gzip, emit chunk, then emit response
        parser.feedInbound(
            h2Frame(Http2PlaintextParser.FRAME_TYPE_DATA, Http2PlaintextParser.FLAG_END_STREAM, 1, gzBody),
            "conn_h2"
        )
        assertEquals(1, responses.size)
        assertEquals(requests[0].requestId, responses[0].requestId)
        assertEquals(requests[0].url, responses[0].url)
        assertEquals("""{"items":[1,2,3]}""", String(cachedBodies[responses[0].requestId]!!, StandardCharsets.UTF_8))

        // Stream 3 reuses dynamic table entry in outbound HPACK (index 63 -> :authority: api.example.com because index 62 is :path now)
        val req3Headers = ByteArrayOutputStream().apply {
            write(0x82) // :method: GET
            write(0x87) // :scheme: https
            write(0x80 or 63) // dynamic :authority: api.example.com
            write(hpackLiteralInc(4, "/v1/next"))
        }.toByteArray()
        parser.feedOutbound(
            h2Frame(Http2PlaintextParser.FRAME_TYPE_HEADERS, Http2PlaintextParser.FLAG_END_HEADERS or Http2PlaintextParser.FLAG_END_STREAM, 3, req3Headers),
            "conn_h2"
        )
        assertEquals(2, requests.size)
        assertEquals("https://api.example.com/v1/next", requests[1].url)
    }

    @Test
    fun testHttp1KeepAliveUrlPairingChunkedGzipAndEofFinalization() {
        val requests = mutableListOf<HttpRequestEvent>()
        val responses = mutableListOf<HttpResponseEvent>()
        val bodies = HashMap<String, ByteArray>()

        val parser = Http1PlaintextParser(
            isTls = true,
            onParsedRequest = { requests.add(it) },
            onParsedResponse = { resp ->
                assertTrue("Body must be emitted before onParsedResponse", bodies.containsKey(resp.requestId))
                responses.add(resp)
            },
            onBodyChunk = { reqId, chunk -> bodies[reqId] = (bodies[reqId] ?: ByteArray(0)) + chunk }
        )

        // Two keep-alive GET requests
        val rawReq1 = "GET /first?k=v HTTP/1.1\r\nHost: api.test\r\n\r\n".toByteArray(StandardCharsets.ISO_8859_1)
        val rawReq2 = "GET /second HTTP/1.1\r\nHost: api.test\r\n\r\n".toByteArray(StandardCharsets.ISO_8859_1)
        parser.feedOutbound(rawReq1, "c1")
        parser.feedOutbound(rawReq2, "c1")

        assertEquals(2, requests.size)
        assertEquals("https://api.test/first?k=v", requests[0].url)
        assertEquals("https://api.test/second", requests[1].url)

        // Response 1: chunked + gzip split across two chunks
        val gz1 = gzipCompress("""{"ok":true}""")
        val half = gz1.size / 2
        val chunk1Hex = Integer.toHexString(half)
        val chunk2Hex = Integer.toHexString(gz1.size - half)
        val resp1Bytes = ByteArrayOutputStream().apply {
            write("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Encoding: gzip\r\n\r\n".toByteArray(StandardCharsets.ISO_8859_1))
            write("$chunk1Hex\r\n".toByteArray(StandardCharsets.ISO_8859_1))
            write(gz1, 0, half)
            write("\r\n$chunk2Hex\r\n".toByteArray(StandardCharsets.ISO_8859_1))
            write(gz1, half, gz1.size - half)
            write("\r\n0\r\n\r\n".toByteArray(StandardCharsets.ISO_8859_1))
        }.toByteArray()
        parser.feedInbound(resp1Bytes, "c1")

        assertEquals(1, responses.size)
        assertEquals(requests[0].requestId, responses[0].requestId)
        assertEquals("https://api.test/first?k=v", responses[0].url)
        assertEquals("""{"ok":true}""", String(bodies[responses[0].requestId]!!, StandardCharsets.UTF_8))

        // Response 2: Connection: close with no Content-Length, finalized on EOF
        parser.feedInbound("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nhello-eof".toByteArray(StandardCharsets.ISO_8859_1), "c1")
        assertEquals("Response without Content-Length should wait for EOF", 1, responses.size)
        parser.finishOnEof()
        assertEquals(2, responses.size)
        assertEquals(requests[1].requestId, responses[1].requestId)
        assertEquals("https://api.test/second", responses[1].url)
        assertEquals("hello-eof", String(bodies[responses[1].requestId]!!, StandardCharsets.UTF_8))
    }

    @Test
    fun testTlsStreamParserUrlFilterAndBodyCacheLookup() {
        val seenResponses = mutableListOf<HttpResponseEvent>()
        val listener = object : INetworkEventListener.Stub() {
            override fun onRequestWillBeSent(event: HttpRequestEvent) {}
            override fun onResponseReceived(event: HttpResponseEvent) {
                seenResponses.add(event)
            }
            override fun onDataChunkReceived(requestId: String, chunk: ByteArray) {}
            override fun onErrorOccurred(requestId: String, error: String) {}
        }
        val config = NetworkCaptureConfig(
            targetPackage = "com.example.keep",
            urlFilterPattern = ".*api\\.keep\\.com.*"
        )
        val tlsParser = TlsStreamParser(config, listener)

        tlsParser.onOutboundData("c1", "GET /ping HTTP/1.1\r\nHost: api.keep.com\r\n\r\n".toByteArray())
        tlsParser.onInboundData("c1", "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\npong".toByteArray())

        tlsParser.onOutboundData("c2", "GET /ignored HTTP/1.1\r\nHost: other.com\r\n\r\n".toByteArray())
        tlsParser.onInboundData("c2", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nno".toByteArray())

        assertEquals(1, seenResponses.size)
        assertEquals("https://api.keep.com/ping", seenResponses[0].url)
        val cached = tlsParser.getResponseBody(seenResponses[0].requestId)
        assertNotNull(cached)
        assertArrayEquals("pong".toByteArray(StandardCharsets.UTF_8), cached)
    }

    @Test
    fun testMidStreamHttp2WithoutPrefaceSettingsAndHeaders() {
        val requests = mutableListOf<HttpRequestEvent>()
        val responses = mutableListOf<HttpResponseEvent>()
        val listener = object : INetworkEventListener.Stub() {
            override fun onRequestWillBeSent(event: HttpRequestEvent) {
                requests.add(event)
            }
            override fun onResponseReceived(event: HttpResponseEvent) {
                responses.add(event)
            }
            override fun onDataChunkReceived(requestId: String, chunk: ByteArray) {}
            override fun onErrorOccurred(requestId: String, error: String) {}
        }
        val config = NetworkCaptureConfig(targetPackage = "com.xingin.xhs")
        val tlsParser = TlsStreamParser(config, listener, defaultConnectionHostHint = "edith.xiaohongshu.com")

        // 1. Mid-stream attach: Outbound SETTINGS frame on stream 0 (NO CLIENT_PREFACE!)
        val settingsPayload = byteArrayOf(0x00, 0x01, 0x00, 0x00, 0x10, 0x00) // SETTINGS_HEADER_TABLE_SIZE = 4096
        val settingsFrame = h2Frame(Http2PlaintextParser.FRAME_TYPE_SETTINGS, 0, 0, settingsPayload)
        tlsParser.onOutboundData("conn_xhs", settingsFrame)

        // 2. Outbound HEADERS frame on stream 1 without preface
        val reqHeaders = ByteArrayOutputStream().apply {
            write(0x82) // :method: GET
            write(0x87) // :scheme: https
            write(hpackLiteralInc(1, "edith.xiaohongshu.com")) // :authority
            write(hpackLiteralInc(4, "/api/v1/user")) // :path
        }.toByteArray()
        val headersFrame = h2Frame(
            Http2PlaintextParser.FRAME_TYPE_HEADERS,
            Http2PlaintextParser.FLAG_END_HEADERS or Http2PlaintextParser.FLAG_END_STREAM,
            1,
            reqHeaders
        )
        tlsParser.onOutboundData("conn_xhs", headersFrame)

        assertEquals("Mid-stream HTTP/2 request must be parsed without preface", 1, requests.size)
        assertEquals("GET", requests[0].method)
        assertEquals("https://edith.xiaohongshu.com/api/v1/user", requests[0].url)

        // 3. Inbound HEADERS (stream 1) + DATA (stream 1)
        val respHeaders = ByteArrayOutputStream().apply {
            write(0x88) // :status: 200
            write(hpackLiteralInc(31, "application/json"))
        }.toByteArray()
        val respHeadersFrame = h2Frame(Http2PlaintextParser.FRAME_TYPE_HEADERS, Http2PlaintextParser.FLAG_END_HEADERS, 1, respHeaders)
        val dataPayload = """{"code":0,"msg":"Success"}""".toByteArray(StandardCharsets.UTF_8)
        val respDataFrame = h2Frame(Http2PlaintextParser.FRAME_TYPE_DATA, Http2PlaintextParser.FLAG_END_STREAM, 1, dataPayload)

        tlsParser.onInboundData("conn_xhs", respHeadersFrame)
        tlsParser.onInboundData("conn_xhs", respDataFrame)

        assertEquals("Mid-stream HTTP/2 response must be parsed", 1, responses.size)
        assertEquals(200, responses[0].statusCode)
        assertEquals("https://edith.xiaohongshu.com/api/v1/user", responses[0].url)
        val body = tlsParser.getResponseBody(responses[0].requestId)
        assertNotNull(body)
        assertEquals("""{"code":0,"msg":"Success"}""", String(body!!, StandardCharsets.UTF_8))
    }

    @Test
    fun testMidStreamHpackDynamicTableMissFallsBackWhileKeepingPath() {
        val requests = mutableListOf<HttpRequestEvent>()
        val parser = Http2PlaintextParser(
            connectionHostHint = null,
            onParsedRequest = { requests.add(it) },
            onParsedResponse = {},
            onBodyChunk = { _, _ -> }
        )

        // Request 1 establishes lastSeenAuthority = "api.xiaohongshu.com"
        val req1Headers = ByteArrayOutputStream().apply {
            write(0x82) // :method: GET
            write(0x87) // :scheme: https
            write(hpackLiteralInc(1, "api.xiaohongshu.com")) // :authority
            write(hpackLiteralInc(4, "/feed"))
        }.toByteArray()
        parser.feedOutbound(
            h2Frame(Http2PlaintextParser.FRAME_TYPE_HEADERS, Http2PlaintextParser.FLAG_END_HEADERS or Http2PlaintextParser.FLAG_END_STREAM, 1, req1Headers),
            "conn_miss"
        )
        assertEquals(1, requests.size)
        assertEquals("https://api.xiaohongshu.com/feed", requests[0].url)

        // Request 2 has dynamic table miss (0xBE = index 62 in dynamic table), but specifies path /api/sns/v1/note
        val req2Headers = ByteArrayOutputStream().apply {
            write(0x83) // :method: POST
            write(0x87) // :scheme: https
            write(0x80 or 62) // Unknown dynamic index 62 (:authority miss)
            write(hpackLiteralInc(4, "/api/sns/v1/note"))
        }.toByteArray()
        parser.feedOutbound(
            h2Frame(Http2PlaintextParser.FRAME_TYPE_HEADERS, Http2PlaintextParser.FLAG_END_HEADERS or Http2PlaintextParser.FLAG_END_STREAM, 3, req2Headers),
            "conn_miss"
        )
        assertEquals(2, requests.size)
        assertEquals("POST", requests[1].method)
        // Must fall back to lastSeenAuthority while keeping decoded :path (NEVER localhost!)
        assertEquals("https://api.xiaohongshu.com/api/sns/v1/note", requests[1].url)

        // Request on fresh parser without lastSeenAuthority or hint: falls back to unknown-host, keeping path
        val freshRequests = mutableListOf<HttpRequestEvent>()
        val freshParser = Http2PlaintextParser(
            onParsedRequest = { freshRequests.add(it) },
            onParsedResponse = {},
            onBodyChunk = { _, _ -> }
        )
        freshParser.feedOutbound(
            h2Frame(Http2PlaintextParser.FRAME_TYPE_HEADERS, Http2PlaintextParser.FLAG_END_HEADERS or Http2PlaintextParser.FLAG_END_STREAM, 1, req2Headers),
            "conn_fresh"
        )
        assertEquals(1, freshRequests.size)
        assertEquals("https://unknown-host/api/sns/v1/note", freshRequests[0].url)
    }

    @Test
    fun testHttp1WithoutHostHeaderFallsBackWithoutLocalhost() {
        val requests = mutableListOf<HttpRequestEvent>()
        val parserWithHint = Http1PlaintextParser(
            connectionHostHint = "mobile.xiaohongshu.com",
            onParsedRequest = { requests.add(it) },
            onParsedResponse = {},
            onBodyChunk = { _, _ -> }
        )

        // Request without Host header on parser with connectionHostHint
        val reqNoHost = "GET /api/v2/items HTTP/1.1\r\n\r\n".toByteArray(StandardCharsets.ISO_8859_1)
        parserWithHint.feedOutbound(reqNoHost, "c_hint")
        assertEquals(1, requests.size)
        assertEquals("https://mobile.xiaohongshu.com/api/v2/items", requests[0].url)

        // Fresh parser without Host header and without hint
        val noHintRequests = mutableListOf<HttpRequestEvent>()
        val freshParser = Http1PlaintextParser(
            onParsedRequest = { noHintRequests.add(it) },
            onParsedResponse = {},
            onBodyChunk = { _, _ -> }
        )
        freshParser.feedOutbound(reqNoHost, "c_nohint")
        assertEquals(1, noHintRequests.size)
        assertEquals("https://unknown-host/api/v2/items", noHintRequests[0].url)

        // Sequential requests: first establishes Host, second lacks Host header
        val req1WithHost = "GET /first HTTP/1.1\r\nHost: service.example.com\r\n\r\n".toByteArray(StandardCharsets.ISO_8859_1)
        val req2WithoutHost = "GET /second HTTP/1.1\r\n\r\n".toByteArray(StandardCharsets.ISO_8859_1)
        freshParser.feedOutbound(req1WithHost, "c_seq")
        freshParser.feedOutbound(req2WithoutHost, "c_seq")
        assertEquals(3, noHintRequests.size)
        assertEquals("https://service.example.com/first", noHintRequests[1].url)
        assertEquals("https://service.example.com/second", noHintRequests[2].url)
    }

    @Test
    fun testTlsStreamParserBackfillsUnknownHostAcrossConnectionsAndSetCookie() {
        val requests = mutableListOf<HttpRequestEvent>()
        val responses = mutableListOf<HttpResponseEvent>()
        val listener = object : INetworkEventListener.Stub() {
            override fun onRequestWillBeSent(event: HttpRequestEvent) { requests.add(event) }
            override fun onResponseReceived(event: HttpResponseEvent) { responses.add(event) }
            override fun onDataChunkReceived(requestId: String, chunk: ByteArray) {}
            override fun onErrorOccurred(requestId: String, error: String) {}
        }

        // URL filter specifically requires both host + path ("xiaohongshu.*comment") to prove backfill occurs BEFORE filtering.
        val streamParser = TlsStreamParser(
            config = NetworkCaptureConfig(
                targetPackage = "com.xingin.xhs",
                urlFilterPattern = "xiaohongshu.*comment"
            ),
            listener = listener
        )

        // Connection 1 sends a request whose path (/user) does NOT match filter, but establishes host edith.xiaohongshu.com
        val conn1Headers = ByteArrayOutputStream().apply {
            write(0x82) // :method: GET
            write(0x87) // :scheme: https
            write(hpackLiteralInc(1, "edith.xiaohongshu.com")) // :authority
            write(hpackLiteralInc(4, "/api/sns/v1/user")) // :path
        }.toByteArray()
        val conn1Payload = Http2PlaintextParser.CLIENT_PREFACE + h2Frame(
            Http2PlaintextParser.FRAME_TYPE_HEADERS,
            Http2PlaintextParser.FLAG_END_HEADERS or Http2PlaintextParser.FLAG_END_STREAM,
            1,
            conn1Headers
        )
        streamParser.onOutboundData("ebpf_1_0x1000", conn1Payload)
        assertEquals("Filtered-out path must still update lastKnownHost, not dispatch yet", 0, requests.size)

        // Connection 2 sends HTTP/2 request with dynamic-miss :authority and path /api/sns/v2/comment/page
        val conn2Headers = ByteArrayOutputStream().apply {
            write(0x82) // :method: GET
            write(0x87) // :scheme: https
            write(0x80 or 62) // dynamic miss (:authority omitted)
            write(hpackLiteralInc(4, "/api/sns/v2/comment/page")) // :path
        }.toByteArray()
        val conn2Payload = Http2PlaintextParser.CLIENT_PREFACE + h2Frame(
            Http2PlaintextParser.FRAME_TYPE_HEADERS,
            Http2PlaintextParser.FLAG_END_HEADERS or Http2PlaintextParser.FLAG_END_STREAM,
            1,
            conn2Headers
        )
        streamParser.onOutboundData("ebpf_1_0x2000", conn2Payload)
        assertEquals(1, requests.size)
        assertEquals("https://edith.xiaohongshu.com/api/sns/v2/comment/page", requests[0].url)

        // Fresh parser with NO prior connection learns host from Set-Cookie Domain= in HTTP/2 response
        val cookieRequests = mutableListOf<HttpRequestEvent>()
        val cookieResponses = mutableListOf<HttpResponseEvent>()
        val cookieStreamParser = TlsStreamParser(
            config = NetworkCaptureConfig(targetPackage = "com.xingin.xhs"),
            listener = object : INetworkEventListener.Stub() {
                override fun onRequestWillBeSent(event: HttpRequestEvent) { cookieRequests.add(event) }
                override fun onResponseReceived(event: HttpResponseEvent) { cookieResponses.add(event) }
                override fun onDataChunkReceived(requestId: String, chunk: ByteArray) {}
                override fun onErrorOccurred(requestId: String, error: String) {}
            }
        )
        cookieStreamParser.onOutboundData("ebpf_1_0x3000", conn2Payload)
        assertEquals(1, cookieRequests.size)
        assertEquals("https://unknown-host/api/sns/v2/comment/page", cookieRequests[0].url)

        val respHeaders = ByteArrayOutputStream().apply {
            write(0x88) // :status: 200
            write(hpackLiteralInc(55, "sid=abc; Domain=.xiaohongshu.com; Path=/")) // static 55 = set-cookie
        }.toByteArray()
        val respFrame = h2Frame(
            Http2PlaintextParser.FRAME_TYPE_HEADERS,
            Http2PlaintextParser.FLAG_END_HEADERS or Http2PlaintextParser.FLAG_END_STREAM,
            1,
            respHeaders
        )
        cookieStreamParser.onInboundData("ebpf_1_0x3000", respFrame)
        assertEquals(1, cookieResponses.size)
        assertEquals("https://xiaohongshu.com/api/sns/v2/comment/page", cookieResponses[0].url)
    }

    @Test
    fun testCronetStreamEventsAndPreDecompressedGzipBody() {
        val requests = mutableListOf<HttpRequestEvent>()
        val responses = mutableListOf<HttpResponseEvent>()
        val listener = object : INetworkEventListener.Stub() {
            override fun onRequestWillBeSent(event: HttpRequestEvent) { requests.add(event) }
            override fun onResponseReceived(event: HttpResponseEvent) { responses.add(event) }
            override fun onDataChunkReceived(requestId: String, chunk: ByteArray) {}
            override fun onErrorOccurred(requestId: String, error: String) {}
        }
        val tlsParser = TlsStreamParser(NetworkCaptureConfig(targetPackage = "com.xingin.xhs"), listener)
        val connId = "ebpf_1001_0x70001000"

        tlsParser.onCronetRequest(
            connId,
            "https://edith.xiaohongshu.com/api/sns/v10/comment/page?note_id=123".toByteArray(StandardCharsets.UTF_8)
        )
        assertEquals(1, requests.size)
        assertEquals("https://edith.xiaohongshu.com/api/sns/v10/comment/page?note_id=123", requests[0].url)

        val rawHeaders = "HTTP/1.1 200 OK\u0000content-type: application/json\u0000content-encoding: br\u0000\u0000"
            .toByteArray(StandardCharsets.ISO_8859_1)
        val hdrPayload = ByteArray(4 + rawHeaders.size)
        hdrPayload[0] = (200 and 0xFF).toByte()
        hdrPayload[1] = ((200 ushr 8) and 0xFF).toByte()
        hdrPayload[2] = 0
        hdrPayload[3] = 0
        System.arraycopy(rawHeaders, 0, hdrPayload, 4, rawHeaders.size)
        tlsParser.onCronetResponseStarted(connId, hdrPayload)

        val jsonPart1 = """{"code":0,"data":{"comments":["""
        val jsonPart2 = """{"id":"c1","content":"test"}]}}"""
        tlsParser.onCronetReadCompleted(connId, jsonPart1.toByteArray(StandardCharsets.UTF_8))
        tlsParser.onCronetReadCompleted(connId, jsonPart2.toByteArray(StandardCharsets.UTF_8))
        tlsParser.onCronetFinish(connId)

        assertEquals(1, responses.size)
        assertEquals(200, responses[0].statusCode)
        assertEquals("application/json", responses[0].mimeType)
        assertEquals(requests[0].requestId, responses[0].requestId)
        val cached = tlsParser.getResponseBody(responses[0].requestId)
        assertNotNull(cached)
        assertEquals(jsonPart1 + jsonPart2, String(cached!!, StandardCharsets.UTF_8))
    }

    @Test
    fun testHttp2ResponseDispatchedWhenContentLengthReachedBeforeEndStream() {
        val requests = mutableListOf<HttpRequestEvent>()
        val responses = mutableListOf<HttpResponseEvent>()
        val listener = object : INetworkEventListener.Stub() {
            override fun onRequestWillBeSent(event: HttpRequestEvent) { requests.add(event) }
            override fun onResponseReceived(event: HttpResponseEvent) { responses.add(event) }
            override fun onDataChunkReceived(requestId: String, chunk: ByteArray) {}
            override fun onErrorOccurred(requestId: String, error: String) {}
        }
        val tlsParser = TlsStreamParser(NetworkCaptureConfig(targetPackage = "com.xingin.xhs"), listener)
        val connId = "ebpf_1001_0x70002000"

        val reqHeaders = ByteArrayOutputStream().apply {
            write(0x82) // :method: GET
            write(0x87) // :scheme: https
            write(hpackLiteralInc(1, "edith.xiaohongshu.com"))
            write(hpackLiteralInc(4, "/api/sns/v1/note/feed"))
        }.toByteArray()
        tlsParser.onOutboundData(
            connId,
            Http2PlaintextParser.CLIENT_PREFACE + h2Frame(
                Http2PlaintextParser.FRAME_TYPE_HEADERS,
                Http2PlaintextParser.FLAG_END_HEADERS or Http2PlaintextParser.FLAG_END_STREAM,
                1,
                reqHeaders
            )
        )
        assertEquals(1, requests.size)

        val bodyBytes = """{"ok":1}""".toByteArray(StandardCharsets.UTF_8)
        val clName = "content-length".toByteArray(StandardCharsets.ISO_8859_1)
        val clVal = bodyBytes.size.toString().toByteArray(StandardCharsets.ISO_8859_1)
        val respHeaders = ByteArrayOutputStream().apply {
            write(0x88) // :status: 200
            write(0x00) // literal without indexing, new name
            write(clName.size)
            write(clName)
            write(clVal.size)
            write(clVal)
        }.toByteArray()
        tlsParser.onInboundData(
            connId,
            h2Frame(Http2PlaintextParser.FRAME_TYPE_HEADERS, Http2PlaintextParser.FLAG_END_HEADERS, 1, respHeaders)
        )
        assertEquals(0, responses.size)

        // DATA frame WITHOUT FLAG_END_STREAM, but byte count == Content-Length
        tlsParser.onInboundData(
            connId,
            h2Frame(Http2PlaintextParser.FRAME_TYPE_DATA, 0, 1, bodyBytes)
        )
        assertEquals(1, responses.size)
        assertEquals(200, responses[0].statusCode)
        val cached = tlsParser.getResponseBody(responses[0].requestId)
        assertNotNull(cached)
        assertArrayEquals(bodyBytes, cached)
    }

    @Test
    fun testNetworkCapturePluginRegistryCliArgsAndJsonOverrides() {
        NetworkCapturePluginRegistry.clearJsonProfileOverrides()
        try {
            val xhsArgs = NetworkCapturePluginRegistry.resolveCliArgs("com.xingin.xhs")
            assertTrue(xhsArgs.contains("--ssl-offsets"))
            assertTrue(xhsArgs.contains("libcronet.114.0.5735.38.so:0x4ea720:0x4ea438:0x4eb0c8"))
            assertTrue(xhsArgs.contains("--cronet-offsets"))
            assertTrue(xhsArgs.contains("libcronet.114.0.5735.38.so:0x226c34:0x206dd4:0x206f34:0x206ffc"))
            assertTrue(xhsArgs.contains("--cronet-abi"))
            assertTrue(xhsArgs.contains("0x20,0x10,0"))
            assertTrue(xhsArgs.contains("--cronet-slots"))
            assertTrue(xhsArgs.contains("3,4,5"))
            assertTrue(xhsArgs.contains("(Ljava/lang/Object;JLjava/lang/String;IZZZIZIIJ)J"))

            val otherArgs = NetworkCapturePluginRegistry.resolveCliArgs("com.example.other")
            assertTrue(!otherArgs.contains("--ssl-offsets"))
            assertTrue(!otherArgs.contains("--cronet-offsets"))
            assertTrue(otherArgs.contains("--cronet-abi"))
            assertTrue(otherArgs.contains("0x20,0x10,0"))
            assertTrue(otherArgs.contains("(Ljava/lang/Object;JLjava/lang/String;IZZZIZIIJ)J"))

            val json = """
                {
                  "com.example.other": {
                    "sslOffsetRules": [
                      {
                        "libSubstring": "libcronet.130.0.0.1.so",
                        "writeOffset": "0x1234",
                        "readOffset": "0x5678",
                        "sniOffset": "0x9abc"
                      }
                    ],
                    "cronetOffsetRules": [
                      {
                        "libSubstring": "libcronet.130.0.0.1.so",
                        "createOffset": "0x1110",
                        "responseStartedOffset": "0x2220",
                        "readCompletedOffset": "0x3330",
                        "succeededOffset": "0x4440"
                      }
                    ],
                    "cronetAbiRule": {
                      "rawHeadersOffset": "0x28",
                      "ioBufferDataOffset": "0x18",
                      "stringLayoutMode": 1,
                      "vtableSlots": [4, 5, 6],
                      "jniSignatures": ["(Ljava/lang/Object;JLjava/lang/String;I)J"]
                    }
                  }
                }
            """.trimIndent()
            val count = NetworkCapturePluginRegistry.loadJsonOverrides(json)
            assertEquals(1, count)

            val overriddenArgs = NetworkCapturePluginRegistry.resolveCliArgs("com.example.other")
            assertTrue(overriddenArgs.contains("libcronet.130.0.0.1.so:0x1234:0x5678:0x9abc"))
            assertTrue(overriddenArgs.contains("libcronet.130.0.0.1.so:0x1110:0x2220:0x3330:0x4440"))
            assertTrue(overriddenArgs.contains("0x28,0x18,1"))
            assertTrue(overriddenArgs.contains("4,5,6"))
            assertTrue(overriddenArgs.contains("(Ljava/lang/Object;JLjava/lang/String;I)J"))
        } finally {
            NetworkCapturePluginRegistry.clearJsonProfileOverrides()
        }
    }

    @Test
    fun testTlsStreamParserRunsPluginMiddlewaresForRequestAndResponse() {
        // 1. Built-in XiaohongshuTrafficMiddleware resolves remaining /api/sns/ unknown-host only for com.xingin.xhs
        val xhsRequests = ArrayList<HttpRequestEvent>()
        val xhsResponses = ArrayList<HttpResponseEvent>()
        val xhsParser = TlsStreamParser(
            NetworkCaptureConfig(targetPackage = "com.xingin.xhs"),
            object : INetworkEventListener.Stub() {
                override fun onRequestWillBeSent(event: HttpRequestEvent) { xhsRequests.add(event) }
                override fun onResponseReceived(event: HttpResponseEvent) { xhsResponses.add(event) }
                override fun onDataChunkReceived(requestId: String, chunk: ByteArray) {}
                override fun onErrorOccurred(requestId: String, error: String) {}
            }
        )
        xhsParser.onOutboundData(
            "conn-xhs-1",
            "GET /api/sns/v10/comment/page HTTP/1.1\r\n\r\n".toByteArray(StandardCharsets.ISO_8859_1)
        )
        xhsParser.onInboundData(
            "conn-xhs-1",
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}".toByteArray(StandardCharsets.ISO_8859_1)
        )
        assertEquals(1, xhsRequests.size)
        assertEquals(1, xhsResponses.size)
        assertEquals("https://edith.xiaohongshu.com/api/sns/v10/comment/page", xhsResponses[0].url)

        val otherRequests = ArrayList<HttpRequestEvent>()
        val otherResponses = ArrayList<HttpResponseEvent>()
        val otherParser = TlsStreamParser(
            NetworkCaptureConfig(targetPackage = "com.example.other"),
            object : INetworkEventListener.Stub() {
                override fun onRequestWillBeSent(event: HttpRequestEvent) { otherRequests.add(event) }
                override fun onResponseReceived(event: HttpResponseEvent) { otherResponses.add(event) }
                override fun onDataChunkReceived(requestId: String, chunk: ByteArray) {}
                override fun onErrorOccurred(requestId: String, error: String) {}
            }
        )
        otherParser.onOutboundData(
            "conn-other-1",
            "GET /api/sns/v10/comment/page HTTP/1.1\r\n\r\n".toByteArray(StandardCharsets.ISO_8859_1)
        )
        otherParser.onInboundData(
            "conn-other-1",
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}".toByteArray(StandardCharsets.ISO_8859_1)
        )
        assertEquals(1, otherRequests.size)
        assertEquals(1, otherResponses.size)
        assertEquals("https://unknown-host/api/sns/v10/comment/page", otherResponses[0].url)

        // 2. Custom middleware transforms request, response metadata, and cached response body
        val customMw = object : NetworkTrafficMiddleware {
            override val id: String = "test.decoder"
            override fun onRequest(targetPackage: String, event: HttpRequestEvent): HttpRequestEvent =
                event.copy(url = event.url + "?mw=1")

            override fun onResponse(
                targetPackage: String,
                event: HttpResponseEvent,
                body: ByteArray?
            ): Pair<HttpResponseEvent, ByteArray?> {
                val decoded = body?.let {
                    ("decoded:" + String(it, StandardCharsets.UTF_8)).toByteArray(StandardCharsets.UTF_8)
                }
                return event.copy(statusText = "Decoded") to decoded
            }
        }

        val mwRequests = ArrayList<HttpRequestEvent>()
        val mwResponses = ArrayList<HttpResponseEvent>()
        val mwParser = TlsStreamParser(
            NetworkCaptureConfig(targetPackage = "com.example.other"),
            object : INetworkEventListener.Stub() {
                override fun onRequestWillBeSent(event: HttpRequestEvent) { mwRequests.add(event) }
                override fun onResponseReceived(event: HttpResponseEvent) { mwResponses.add(event) }
                override fun onDataChunkReceived(requestId: String, chunk: ByteArray) {}
                override fun onErrorOccurred(requestId: String, error: String) {}
            },
            middlewares = listOf(customMw)
        )
        mwParser.onOutboundData(
            "conn-mw-1",
            "GET /items HTTP/1.1\r\nHost: api.example.com\r\n\r\n".toByteArray(StandardCharsets.ISO_8859_1)
        )
        mwParser.onInboundData(
            "conn-mw-1",
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello".toByteArray(StandardCharsets.ISO_8859_1)
        )
        assertEquals(1, mwRequests.size)
        assertEquals("https://api.example.com/items?mw=1", mwRequests[0].url)
        assertEquals(1, mwResponses.size)
        assertEquals("Decoded", mwResponses[0].statusText)
        assertEquals("decoded:hello".length.toLong(), mwResponses[0].contentLength)
        val decodedBody = mwParser.getResponseBody(mwResponses[0].requestId)
        assertNotNull(decodedBody)
        assertEquals("decoded:hello", String(decodedBody!!, StandardCharsets.UTF_8))
    }
}
