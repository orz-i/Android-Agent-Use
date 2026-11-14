package com.agent.use.common.network.parser

import com.agent.use.common.network.HttpHeader
import com.agent.use.common.network.HttpRequestEvent
import com.agent.use.common.network.HttpResponseEvent
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets
import java.util.Base64
import java.util.zip.GZIPOutputStream

class GrpcDecoderTest {

    private fun writeVarint(out: ByteArrayOutputStream, value: Long) {
        var v = value
        while (true) {
            if ((v and 0x7FL.inv()) == 0L) {
                out.write(v.toInt())
                return
            }
            out.write(((v.toInt() and 0x7F) or 0x80))
            v = v ushr 7
        }
    }

    private fun pbVarint(field: Int, value: Long): ByteArray = ByteArrayOutputStream().apply {
        writeVarint(this, ((field shl 3) or 0).toLong())
        writeVarint(this, value)
    }.toByteArray()

    private fun pbBytes(field: Int, payload: ByteArray): ByteArray = ByteArrayOutputStream().apply {
        writeVarint(this, ((field shl 3) or 2).toLong())
        writeVarint(this, payload.size.toLong())
        write(payload)
    }.toByteArray()

    private fun pbString(field: Int, text: String): ByteArray =
        pbBytes(field, text.toByteArray(StandardCharsets.UTF_8))

    private fun grpcFrame(payload: ByteArray, flags: Int = 0x00): ByteArray {
        val out = ByteArrayOutputStream(5 + payload.size)
        out.write(flags and 0xFF)
        out.write((payload.size ushr 24) and 0xFF)
        out.write((payload.size ushr 16) and 0xFF)
        out.write((payload.size ushr 8) and 0xFF)
        out.write(payload.size and 0xFF)
        out.write(payload)
        return out.toByteArray()
    }

    private fun hpackLiteralWithoutIndexing(name: String, value: String): ByteArray {
        val nBytes = name.toByteArray(StandardCharsets.ISO_8859_1)
        val vBytes = value.toByteArray(StandardCharsets.ISO_8859_1)
        return ByteArrayOutputStream().apply {
            write(0x00) // Literal Header Field without Indexing - New Name
            write(nBytes.size and 0x7F)
            write(nBytes)
            write(vBytes.size and 0x7F)
            write(vBytes)
        }.toByteArray()
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

    @Test
    fun testGrpcContentTypeDetection() {
        assertTrue(GrpcDecoder.isGrpcContentType("application/grpc"))
        assertTrue(GrpcDecoder.isGrpcContentType("application/grpc+proto"))
        assertTrue(GrpcDecoder.isGrpcContentType("application/grpc+json; charset=utf-8"))
        assertTrue(GrpcDecoder.isGrpcContentType("application/grpc-web+proto"))
        assertTrue(GrpcDecoder.isGrpcContentType("application/grpc-web-text"))
        assertFalse(GrpcDecoder.isGrpcContentType("application/json"))
        assertFalse(GrpcDecoder.isGrpcContentType(null))
    }

    @Test
    fun testProtobufWireDecoderNestedAndRepeatedFields() {
        val nested = pbVarint(1, 42) + pbString(2, "成都")
        val msg = pbString(1, "小红薯69836557") +
            pbVarint(2, 125) +
            pbBytes(3, nested) +
            pbString(4, "tagA") +
            pbString(4, "tagB")

        val json = ProtobufWireDecoder.decodeToJson(msg)
        assertEquals(
            """{"1":"小红薯69836557","2":125,"3":{"1":42,"2":"成都"},"4":["tagA","tagB"]}""",
            json
        )

        // Random truncated/corrupt bytes must return null cleanly
        assertNull(ProtobufWireDecoder.decodeToJson(byteArrayOf(0x0A, 0x50, 0x01)))
    }

    @Test
    fun testGrpcDecoderGzipMultiFrameAndJsonAndGrpcWebText() {
        val pb1 = pbString(1, "item1")
        val gzOut = ByteArrayOutputStream()
        GZIPOutputStream(gzOut).use { it.write(pb1) }
        val pb2 = pbString(1, "item2") + pbVarint(2, 99)

        val compressedCombined = grpcFrame(gzOut.toByteArray(), flags = 0x01) + grpcFrame(pb2, flags = 0x00)
        val decodedJson = GrpcDecoder.decodeToJson(
            body = compressedCombined,
            contentType = "application/grpc+proto",
            headers = listOf(
                HttpHeader("grpc-encoding", "gzip"),
                HttpHeader("grpc-status", "0"),
                HttpHeader("grpc-message", "OK")
            )
        )
        assertTrue(decodedJson.contains(""""protocol":"grpc""""))
        assertTrue(decodedJson.contains(""""grpcStatus":"0""""))
        assertTrue(decodedJson.contains(""""grpcEncoding":"gzip""""))
        assertTrue(decodedJson.contains(""""frameCount":2"""))
        assertTrue(decodedJson.contains("""{"1":"item1"}"""))
        assertTrue(decodedJson.contains("""{"1":"item2","2":99}"""))

        // +json subtype
        val jsonMsg = """{"user":"alice","followers":2}""".toByteArray(StandardCharsets.UTF_8)
        val grpcJsonOut = GrpcDecoder.decodeToJson(grpcFrame(jsonMsg), "application/grpc+json")
        assertTrue(grpcJsonOut.contains("""{"user":"alice","followers":2}"""))

        // grpc-web-text with inline trailer frame
        val webBody = grpcFrame(pbString(1, "hello")) +
            grpcFrame("grpc-status: 0\r\ngrpc-message: done\r\n".toByteArray(StandardCharsets.UTF_8), flags = 0x80)
        val webTextB64 = Base64.getEncoder().encodeToString(webBody).toByteArray(StandardCharsets.US_ASCII)
        val webDecoded = GrpcDecoder.decodeToJson(webTextB64, "application/grpc-web-text+proto")
        assertTrue(webDecoded.contains(""""protocol":"grpc-web""""))
        assertTrue(webDecoded.contains(""""grpcStatus":"0""""))
        assertTrue(webDecoded.contains(""""grpcMessage":"done""""))
        assertTrue(webDecoded.contains("""{"1":"hello"}"""))
    }

    @Test
    fun testHttp2PlaintextParserPreservesHeadersAcrossGrpcTrailers() {
        val requests = mutableListOf<HttpRequestEvent>()
        val responses = mutableListOf<HttpResponseEvent>()
        val bodies = HashMap<String, ByteArray>()

        val parser = Http2PlaintextParser(
            onParsedRequest = { requests.add(it) },
            onParsedResponse = { responses.add(it) },
            onBodyChunk = { id, chunk ->
                bodies[id] = (bodies[id] ?: ByteArray(0)) + chunk
            }
        )

        // Outbound: Preface + gRPC POST HEADERS + DATA (END_STREAM)
        val reqHeadersBlock = ByteArrayOutputStream().apply {
            write(0x83) // :method: POST
            write(0x87) // :scheme: https
            write(hpackLiteralWithoutIndexing(":authority", "api.example.com"))
            write(hpackLiteralWithoutIndexing(":path", "/feed.v1.FeedService/ListNotes"))
            write(hpackLiteralWithoutIndexing("content-type", "application/grpc"))
        }.toByteArray()
        val reqBody = grpcFrame(pbString(1, "me_tab") + pbVarint(2, 20))

        val outBytes = ByteArrayOutputStream().apply {
            write(Http2PlaintextParser.CLIENT_PREFACE)
            write(h2Frame(0x01, 0x04, 1, reqHeadersBlock)) // HEADERS (END_HEADERS)
            write(h2Frame(0x00, 0x01, 1, reqBody))         // DATA (END_STREAM)
        }.toByteArray()
        parser.feedOutbound(outBytes, "h2_grpc_1")

        assertEquals(1, requests.size)
        assertEquals("POST", requests[0].method)
        assertEquals("https://api.example.com/feed.v1.FeedService/ListNotes", requests[0].url)
        assertNotNull(requests[0].postData)
        assertTrue(requests[0].postData!!.contains(""""1":"me_tab""""))

        // Inbound: Initial response HEADERS (:status 200, content-type: application/grpc) -> DATA -> Trailing HEADERS (grpc-status: 0)
        val respInitHeaders = ByteArrayOutputStream().apply {
            write(0x88) // :status: 200
            write(hpackLiteralWithoutIndexing("content-type", "application/grpc+proto"))
        }.toByteArray()
        val respBody = grpcFrame(pbString(1, "note_123") + pbVarint(2, 8131))
        val respTrailers = ByteArrayOutputStream().apply {
            write(hpackLiteralWithoutIndexing("grpc-status", "0"))
            write(hpackLiteralWithoutIndexing("grpc-message", "OK"))
        }.toByteArray()

        val inBytes = ByteArrayOutputStream().apply {
            write(h2Frame(0x01, 0x04, 1, respInitHeaders)) // Initial HEADERS
            write(h2Frame(0x00, 0x00, 1, respBody))        // DATA (not END_STREAM)
            write(h2Frame(0x01, 0x05, 1, respTrailers))    // Trailing HEADERS (END_STREAM | END_HEADERS)
        }.toByteArray()
        parser.feedInbound(inBytes, "h2_grpc_1")

        assertEquals(1, responses.size)
        val resp = responses[0]
        assertEquals(200, resp.statusCode)
        assertEquals("application/grpc+proto", resp.mimeType)
        assertTrue(resp.headers.any { it.name.equals("content-type", true) && it.value == "application/grpc+proto" })
        assertTrue(resp.headers.any { it.name.equals("grpc-status", true) && it.value == "0" })
        assertTrue(resp.headers.any { it.name.equals("grpc-message", true) && it.value == "OK" })

        val rawBody = bodies[resp.requestId]
        assertNotNull(rawBody)
        val decodedResp = GrpcDecoder.decodeToJson(rawBody!!, resp.mimeType, resp.headers)
        assertTrue(decodedResp.contains(""""grpcStatus":"0""""))
        assertTrue(decodedResp.contains(""""1":"note_123""""))
        assertTrue(decodedResp.contains(""""2":8131"""))
    }
}
