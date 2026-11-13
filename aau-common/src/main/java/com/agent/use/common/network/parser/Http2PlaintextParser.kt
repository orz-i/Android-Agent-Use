package com.agent.use.common.network.parser

import com.agent.use.common.network.HttpHeader
import com.agent.use.common.network.HttpRequestEvent
import com.agent.use.common.network.HttpResponseEvent
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets
import java.util.concurrent.ConcurrentHashMap

/**
 * Streaming HTTP/2 binary frame parser (RFC 7540 & RFC 7541) with separate outbound/inbound HPACK decoders,
 * `CONTINUATION` assembly, response body gzip/deflate decompression, and completion-ordered response events.
 */
class Http2PlaintextParser(
    private val maxBodySizeBytes: Long = 10 * 1024 * 1024L,
    private val onParsedRequest: (HttpRequestEvent) -> Unit,
    private val onParsedResponse: (HttpResponseEvent) -> Unit,
    private val onBodyChunk: (requestId: String, chunk: ByteArray) -> Unit
) {

    companion object {
        const val FRAME_TYPE_DATA = 0x0
        const val FRAME_TYPE_HEADERS = 0x1
        const val FRAME_TYPE_PRIORITY = 0x2
        const val FRAME_TYPE_RST_STREAM = 0x3
        const val FRAME_TYPE_SETTINGS = 0x4
        const val FRAME_TYPE_PUSH_PROMISE = 0x5
        const val FRAME_TYPE_PING = 0x6
        const val FRAME_TYPE_GOAWAY = 0x7
        const val FRAME_TYPE_WINDOW_UPDATE = 0x8
        const val FRAME_TYPE_CONTINUATION = 0x9

        const val FLAG_END_STREAM = 0x01
        const val FLAG_END_HEADERS = 0x04
        const val FLAG_PADDED = 0x08
        const val FLAG_PRIORITY = 0x20

        val CLIENT_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".toByteArray(StandardCharsets.ISO_8859_1)
    }

    private val outboundHpack = Http2HpackDecoder()
    private val inboundHpack = Http2HpackDecoder()

    private val outboundBuffer = ByteArrayOutputStream()
    private val inboundBuffer = ByteArrayOutputStream()
    private var outboundPrefaceChecked = false

    private var outboundContinuationStreamId: Int = -1
    private var outboundContinuationEndStream: Boolean = false
    private val outboundContinuationBuffer = ByteArrayOutputStream()

    private var inboundContinuationStreamId: Int = -1
    private var inboundContinuationEndStream: Boolean = false
    private val inboundContinuationBuffer = ByteArrayOutputStream()

    private data class StreamContext(
        val streamId: Int,
        val requestId: String,
        var url: String = "https://localhost/",
        var method: String = "GET",
        var requestHeaders: List<HttpHeader> = emptyList(),
        val postDataStream: ByteArrayOutputStream = ByteArrayOutputStream(),
        var requestDispatched: Boolean = false,
        var statusCode: Int = 200,
        var mimeType: String? = null,
        var contentLength: Long = -1L,
        var responseHeaders: List<HttpHeader> = emptyList(),
        var responseHeadersReceived: Boolean = false,
        val responseBodyStream: ByteArrayOutputStream = ByteArrayOutputStream(),
        var responseDispatched: Boolean = false
    )

    private val streams = ConcurrentHashMap<Int, StreamContext>()

    @Synchronized
    fun feedOutbound(data: ByteArray, connectionId: String) {
        if (data.isEmpty()) return
        outboundBuffer.write(data)
        processFrames(outboundBuffer, connectionId, isOutbound = true)
    }

    @Synchronized
    fun feedInbound(data: ByteArray, connectionId: String) {
        if (data.isEmpty()) return
        inboundBuffer.write(data)
        processFrames(inboundBuffer, connectionId, isOutbound = false)
    }

    private fun processFrames(buffer: ByteArrayOutputStream, connectionId: String, isOutbound: Boolean) {
        val bytes = buffer.toByteArray()
        if (bytes.isEmpty()) return

        var offset = 0
        if (isOutbound && !outboundPrefaceChecked) {
            if (bytes.size >= CLIENT_PREFACE.size) {
                var matches = true
                for (i in CLIENT_PREFACE.indices) {
                    if (bytes[i] != CLIENT_PREFACE[i]) {
                        matches = false
                        break
                    }
                }
                if (matches) {
                    offset += CLIENT_PREFACE.size
                }
                outboundPrefaceChecked = true
            } else {
                // Wait for full preface before scanning frame headers
                return
            }
        }

        while (offset + 9 <= bytes.size) {
            val length = ((bytes[offset].toInt() and 0xFF) shl 16) or
                ((bytes[offset + 1].toInt() and 0xFF) shl 8) or
                (bytes[offset + 2].toInt() and 0xFF)
            val type = bytes[offset + 3].toInt() and 0xFF
            val flags = bytes[offset + 4].toInt() and 0xFF
            val streamId = ((bytes[offset + 5].toInt() and 0x7F) shl 24) or
                ((bytes[offset + 6].toInt() and 0xFF) shl 16) or
                ((bytes[offset + 7].toInt() and 0xFF) shl 8) or
                (bytes[offset + 8].toInt() and 0xFF)

            if (length < 0 || length > 16 * 1024 * 1024) {
                // Resync guard against malformed frame lengths
                buffer.reset()
                return
            }

            val totalFrameSize = 9 + length
            if (offset + totalFrameSize > bytes.size) {
                break
            }

            val payload = bytes.copyOfRange(offset + 9, offset + totalFrameSize)
            handleFrame(type, flags, streamId, payload, connectionId, isOutbound)
            offset += totalFrameSize
        }

        buffer.reset()
        if (offset < bytes.size) {
            buffer.write(bytes, offset, bytes.size - offset)
        }
    }

    private fun handleFrame(
        type: Int,
        flags: Int,
        streamId: Int,
        payload: ByteArray,
        connectionId: String,
        isOutbound: Boolean
    ) {
        if (streamId == 0) return

        val stream = streams.computeIfAbsent(streamId) {
            StreamContext(
                streamId = streamId,
                requestId = "${connectionId}_h2_s${streamId}"
            )
        }

        when (type) {
            FRAME_TYPE_HEADERS -> {
                val block = extractHeaderBlock(payload, flags)
                val endStream = (flags and FLAG_END_STREAM) != 0
                val endHeaders = (flags and FLAG_END_HEADERS) != 0
                if (endHeaders) {
                    applyDecodedHeaders(stream, block, endStream, isOutbound)
                } else {
                    if (isOutbound) {
                        outboundContinuationStreamId = streamId
                        outboundContinuationEndStream = endStream
                        outboundContinuationBuffer.reset()
                        outboundContinuationBuffer.write(block)
                    } else {
                        inboundContinuationStreamId = streamId
                        inboundContinuationEndStream = endStream
                        inboundContinuationBuffer.reset()
                        inboundContinuationBuffer.write(block)
                    }
                }
            }

            FRAME_TYPE_CONTINUATION -> {
                val endHeaders = (flags and FLAG_END_HEADERS) != 0
                if (isOutbound && outboundContinuationStreamId == streamId) {
                    outboundContinuationBuffer.write(payload)
                    if (endHeaders) {
                        val block = outboundContinuationBuffer.toByteArray()
                        val endStream = outboundContinuationEndStream
                        outboundContinuationStreamId = -1
                        outboundContinuationBuffer.reset()
                        applyDecodedHeaders(stream, block, endStream, isOutbound = true)
                    }
                } else if (!isOutbound && inboundContinuationStreamId == streamId) {
                    inboundContinuationBuffer.write(payload)
                    if (endHeaders) {
                        val block = inboundContinuationBuffer.toByteArray()
                        val endStream = inboundContinuationEndStream
                        inboundContinuationStreamId = -1
                        inboundContinuationBuffer.reset()
                        applyDecodedHeaders(stream, block, endStream, isOutbound = false)
                    }
                }
            }

            FRAME_TYPE_DATA -> {
                val dataPayload = extractDataPayload(payload, flags)
                val endStream = (flags and FLAG_END_STREAM) != 0
                if (isOutbound) {
                    appendLimited(stream.postDataStream, dataPayload)
                    if (endStream) {
                        dispatchRequestIfNeeded(stream)
                    }
                } else {
                    appendLimited(stream.responseBodyStream, dataPayload)
                    if (endStream) {
                        dispatchResponseIfNeeded(stream)
                        streams.remove(streamId)
                    }
                }
            }

            FRAME_TYPE_RST_STREAM -> {
                if (stream.responseHeadersReceived && !stream.responseDispatched) {
                    dispatchResponseIfNeeded(stream)
                }
                streams.remove(streamId)
            }
        }
    }

    private fun applyDecodedHeaders(
        stream: StreamContext,
        headerBlock: ByteArray,
        isEndStream: Boolean,
        isOutbound: Boolean
    ) {
        val decoder = if (isOutbound) outboundHpack else inboundHpack
        val headers = decoder.decode(headerBlock)

        if (isOutbound) {
            var method = "GET"
            var scheme = "https"
            var authority = "localhost"
            var path = "/"

            for (h in headers) {
                when (h.name.lowercase()) {
                    ":method" -> method = h.value
                    ":scheme" -> scheme = h.value
                    ":authority", "host" -> if (h.value.isNotEmpty()) authority = h.value
                    ":path" -> path = h.value
                }
            }

            stream.method = method
            stream.url = "$scheme://$authority$path"
            stream.requestHeaders = headers
            if (isEndStream) {
                dispatchRequestIfNeeded(stream)
            }
        } else {
            var statusCode = 200
            for (h in headers) {
                if (h.name == ":status") {
                    statusCode = h.value.toIntOrNull() ?: 200
                }
            }
            // Ignore 1xx informational header blocks (except 101)
            if (statusCode in 100..199 && statusCode != 101) return

            stream.statusCode = statusCode
            stream.mimeType = headers.firstOrNull { it.name.equals("content-type", ignoreCase = true) }?.value
            stream.contentLength = headers.firstOrNull { it.name.equals("content-length", ignoreCase = true) }
                ?.value?.trim()?.toLongOrNull() ?: -1L
            stream.responseHeaders = headers
            stream.responseHeadersReceived = true

            if (isEndStream) {
                dispatchResponseIfNeeded(stream)
                streams.remove(stream.streamId)
            }
        }
    }

    private fun dispatchRequestIfNeeded(stream: StreamContext) {
        if (stream.requestDispatched) return
        stream.requestDispatched = true
        val rawPost = stream.postDataStream.toByteArray()
        val decodedPost = HttpContentDecoder.decompressIfNeeded(rawPost, stream.requestHeaders)
        val postStr = if (decodedPost.isNotEmpty()) decodedPost.toString(StandardCharsets.UTF_8) else null
        onParsedRequest(
            HttpRequestEvent(
                requestId = stream.requestId,
                timestamp = System.currentTimeMillis(),
                url = stream.url,
                method = stream.method,
                headers = stream.requestHeaders,
                postData = postStr,
                isTls = true
            )
        )
    }

    private fun dispatchResponseIfNeeded(stream: StreamContext) {
        if (stream.responseDispatched || !stream.responseHeadersReceived) return
        stream.responseDispatched = true
        dispatchRequestIfNeeded(stream)

        val rawBody = stream.responseBodyStream.toByteArray()
        val finalBody = HttpContentDecoder.decompressIfNeeded(rawBody, stream.responseHeaders)
        if (finalBody.isNotEmpty()) {
            onBodyChunk(stream.requestId, finalBody)
        }
        val effectiveLength = if (stream.contentLength >= 0) stream.contentLength else finalBody.size.toLong()
        onParsedResponse(
            HttpResponseEvent(
                requestId = stream.requestId,
                timestamp = System.currentTimeMillis(),
                url = stream.url,
                statusCode = stream.statusCode,
                statusText = if (stream.statusCode in 200..299) "OK" else "",
                headers = stream.responseHeaders,
                mimeType = stream.mimeType,
                contentLength = effectiveLength,
                fromCache = false
            )
        )
    }

    private fun appendLimited(target: ByteArrayOutputStream, data: ByteArray) {
        if (data.isEmpty() || target.size() >= maxBodySizeBytes) return
        val remaining = (maxBodySizeBytes - target.size()).toInt().coerceAtLeast(0)
        val toWrite = minOf(data.size, remaining)
        if (toWrite > 0) {
            target.write(data, 0, toWrite)
        }
    }

    private fun extractHeaderBlock(payload: ByteArray, flags: Int): ByteArray {
        var start = 0
        var end = payload.size

        if ((flags and FLAG_PADDED) != 0 && payload.isNotEmpty()) {
            val padLength = payload[0].toInt() and 0xFF
            start += 1
            end -= padLength
        }
        if ((flags and FLAG_PRIORITY) != 0 && end - start >= 5) {
            start += 5
        }

        return if (start in 0..end && end <= payload.size) {
            payload.copyOfRange(start, end)
        } else {
            ByteArray(0)
        }
    }

    private fun extractDataPayload(payload: ByteArray, flags: Int): ByteArray {
        var start = 0
        var end = payload.size
        if ((flags and FLAG_PADDED) != 0 && payload.isNotEmpty()) {
            val padLength = payload[0].toInt() and 0xFF
            start += 1
            end -= padLength
        }
        return if (start in 0..end && end <= payload.size) {
            payload.copyOfRange(start, end)
        } else {
            payload
        }
    }
}
