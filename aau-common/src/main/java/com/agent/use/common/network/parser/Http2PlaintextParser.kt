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
    private val connectionHostHint: String? = null,
    private val onParsedRequest: (HttpRequestEvent) -> Unit,
    private val onParsedResponse: (HttpResponseEvent) -> Unit,
    private val onBodyChunk: (requestId: String, chunk: ByteArray) -> Unit
) {
    constructor(
        maxBodySizeBytes: Long = 10 * 1024 * 1024L,
        onParsedRequest: (HttpRequestEvent) -> Unit,
        onParsedResponse: (HttpResponseEvent) -> Unit,
        onBodyChunk: (requestId: String, chunk: ByteArray) -> Unit
    ) : this(
        maxBodySizeBytes = maxBodySizeBytes,
        connectionHostHint = null,
        onParsedRequest = onParsedRequest,
        onParsedResponse = onParsedResponse,
        onBodyChunk = onBodyChunk
    )

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

    @Volatile
    private var lastSeenAuthority: String? = connectionHostHint

    fun setConnectionHostHint(host: String) {
        if (host.isNotBlank() && !host.equals("localhost", ignoreCase = true) && !host.equals("unknown-host", ignoreCase = true)) {
            lastSeenAuthority = host
        }
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
        var url: String,
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
                // Check if the partial buffer could match CLIENT_PREFACE
                var prefixMatches = true
                for (i in bytes.indices) {
                    if (bytes[i] != CLIENT_PREFACE[i]) {
                        prefixMatches = false
                        break
                    }
                }
                if (prefixMatches) {
                    // Wait for full preface before scanning frame headers
                    return
                } else {
                    // Mid-stream attach: bytes do not match preface prefix, start parsing frames directly
                    outboundPrefaceChecked = true
                }
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
        when (type) {
            // GOAWAY 表示服务端不会再为更高的 stream id 产出响应。把已经收到响应头的
            // 半截响应放出去，别让它们随连接一起消失——eBPF 抓到的连接十有八九是被切断的。
            FRAME_TYPE_GOAWAY -> {
                handleGoaway(payload)
                return
            }

            // SETTINGS / PING 固定在 stream 0，与任何请求无关
            FRAME_TYPE_SETTINGS, FRAME_TYPE_PING -> return

            // PRIORITY 描述依赖树，WINDOW_UPDATE 描述流量控制窗口。两者都可能落在
            // "从未承载过请求"的 stream id 上；若在此建 StreamContext，长连接跑久了
            // 会攒下一堆永不派发的空流上下文（每个还带一个 ByteArrayOutputStream）。
            FRAME_TYPE_PRIORITY, FRAME_TYPE_WINDOW_UPDATE -> return

            FRAME_TYPE_RST_STREAM -> {
                streams.remove(streamId)?.let { reset ->
                    if (reset.responseHeadersReceived && !reset.responseDispatched) {
                        dispatchResponseIfNeeded(reset)
                    } else if (!reset.requestDispatched && reset.requestHeaders.isNotEmpty()) {
                        dispatchRequestIfNeeded(reset)
                    }
                }
                return
            }

            FRAME_TYPE_PUSH_PROMISE -> {
                handlePushPromise(flags, streamId, payload, connectionId)
                return
            }

            // CONTINUATION 只有紧随其 HEADERS 时才有意义。孤立的要丢弃，
            // 否则会为一个不存在的头块凭空造出 stream。
            FRAME_TYPE_CONTINUATION -> {
                val matches = if (isOutbound) {
                    outboundContinuationStreamId == streamId
                } else {
                    inboundContinuationStreamId == streamId
                }
                if (!matches) return
            }

            FRAME_TYPE_HEADERS, FRAME_TYPE_DATA -> Unit

            else -> return // 0xA 以上的扩展帧不对应 HTTP 语义，不该驱动流状态机
        }

        if (streamId == 0) return

        val stream = streams.computeIfAbsent(streamId) {
            val fallbackHost = lastSeenAuthority ?: connectionHostHint ?: "unknown-host"
            StreamContext(
                streamId = streamId,
                requestId = "${connectionId}_h2_s${streamId}",
                url = "https://$fallbackHost/"
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
                    } else if (
                        stream.responseHeadersReceived &&
                        stream.contentLength > 0L &&
                        stream.responseBodyStream.size().toLong() >= stream.contentLength
                    ) {
                        dispatchResponseIfNeeded(stream)
                    }
                }
            }

            // RST_STREAM / GOAWAY / PUSH_PROMISE 已在入口处处理
        }
    }

    /**
     * GOAWAY 的 lastStreamId 之上的 stream 永远不会再有响应了。
     * 把这些流收掉并放出已拿到的部分数据，避免响应凭空消失。
     */
    private fun handleGoaway(payload: ByteArray) {
        if (payload.size < 8) return
        val lastStreamId = ((payload[0].toInt() and 0x7F) shl 24) or
            ((payload[1].toInt() and 0xFF) shl 16) or
            ((payload[2].toInt() and 0xFF) shl 8) or
            (payload[3].toInt() and 0xFF)

        val abandoned = streams.values.filter { it.streamId > lastStreamId }
        for (stream in abandoned) {
            streams.remove(stream.streamId)
            if (stream.responseHeadersReceived && !stream.responseDispatched) {
                dispatchResponseIfNeeded(stream)
            } else if (!stream.requestDispatched && stream.requestHeaders.isNotEmpty()) {
                dispatchRequestIfNeeded(stream)
            }
        }
    }

    /**
     * 服务端推送。promised stream 上的响应没有对应的客户端请求，
     * 这里用 PUSH_PROMISE 携带的伪头补出一个合成请求，
     * 否则后续 HEADERS 只能落到 `https://<host>/` 这种没有路径的 URL 上。
     */
    private fun handlePushPromise(flags: Int, streamId: Int, payload: ByteArray, connectionId: String) {
        if (streamId == 0 || payload.isEmpty()) return

        var start = 0
        var end = payload.size
        if ((flags and FLAG_PADDED) != 0) {
            val padLength = payload[0].toInt() and 0xFF
            start = 1
            end -= padLength
        }
        if (end - start < 4) return

        val promisedId = ((payload[start].toInt() and 0x7F) shl 24) or
            ((payload[start + 1].toInt() and 0xFF) shl 16) or
            ((payload[start + 2].toInt() and 0xFF) shl 8) or
            (payload[start + 3].toInt() and 0xFF)
        start += 4
        if (start >= end || promisedId == 0) return

        val headers = inboundHpack.decode(payload.copyOfRange(start, end))
        if (headers.isEmpty()) return

        var scheme = "https"
        var authority: String? = null
        var path = "/"
        for (header in headers) {
            when (header.name.lowercase()) {
                ":scheme" -> scheme = header.value
                ":authority" -> if (isUsableHost(header.value)) authority = header.value.trim()
                ":path" -> path = header.value
            }
        }
        val resolvedAuthority = authority ?: extractHostFromHeaders(headers) ?: lastSeenAuthority
            ?: connectionHostHint ?: "unknown-host"
        if (isUsableHost(resolvedAuthority)) {
            lastSeenAuthority = resolvedAuthority
        }

        val normalizedPath = if (path.startsWith("/")) path else "/$path"
        val pushed = streams.computeIfAbsent(promisedId) {
            StreamContext(
                streamId = promisedId,
                requestId = "${connectionId}_h2_s$promisedId",
                url = "$scheme://$resolvedAuthority$normalizedPath"
            )
        }
        pushed.url = "$scheme://$resolvedAuthority$normalizedPath"
        pushed.method = "GET"
        pushed.requestHeaders = headers
        dispatchRequestIfNeeded(pushed)
    }

    /**
     * 连接终止时排空所有还在等待 END_STREAM 的流。
     *
     * 不排空的话，凡是没等到 END_STREAM 的响应都会静默丢失——而被 uprobe 截获的连接
     * 大多是被 App 主动关闭或进程退出的，本来就拿不到 END_STREAM。
     */
    @Synchronized
    fun finish() {
        val pending = streams.values.toList()
        streams.clear()
        for (stream in pending) {
            if (stream.responseHeadersReceived && !stream.responseDispatched) {
                dispatchResponseIfNeeded(stream)
            } else if (!stream.requestDispatched && stream.requestHeaders.isNotEmpty()) {
                dispatchRequestIfNeeded(stream)
            }
        }
        outboundBuffer.reset()
        inboundBuffer.reset()
        outboundContinuationStreamId = -1
        inboundContinuationStreamId = -1
        outboundContinuationBuffer.reset()
        inboundContinuationBuffer.reset()
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
            var authority: String? = null
            var path = "/"

            for (h in headers) {
                when (h.name.lowercase()) {
                    ":method" -> method = h.value
                    ":scheme" -> scheme = h.value
                    ":authority" -> if (isUsableHost(h.value)) authority = h.value.trim()
                    "host" -> if (authority == null && isUsableHost(h.value)) authority = h.value.trim()
                    ":path" -> path = h.value
                }
            }

            if (authority == null) {
                authority = extractHostFromHeaders(headers)
            }

            if (authority == null) {
                authority = lastSeenAuthority ?: connectionHostHint ?: "unknown-host"
            } else {
                lastSeenAuthority = authority
            }

            val normalizedPath = if (path.startsWith("/")) path else "/$path"
            stream.method = method
            stream.url = "$scheme://$authority$normalizedPath"
            stream.requestHeaders = headers
            if (isEndStream) {
                dispatchRequestIfNeeded(stream)
            }
        } else {
            if (!stream.responseHeadersReceived) {
                var statusCode = 200
                for (h in headers) {
                    if (h.name == ":status") {
                        statusCode = h.value.toIntOrNull() ?: 200
                    }
                }
                // Ignore 1xx informational header blocks (except 101)
                if (statusCode in 100..199 && statusCode != 101) return

                val respHost = extractHostFromHeaders(headers)
                if (respHost != null) {
                    lastSeenAuthority = respHost
                }
                val resolvedHost = respHost ?: lastSeenAuthority ?: connectionHostHint
                if (resolvedHost != null && isUsableHost(resolvedHost)) {
                    if (stream.url.contains("://unknown-host")) {
                        stream.url = stream.url.replace("://unknown-host", "://$resolvedHost")
                    } else if (stream.requestHeaders.isEmpty() && stream.url.isEmpty()) {
                        stream.url = "https://$resolvedHost/"
                    }
                } else if (stream.requestHeaders.isEmpty() && stream.url.isEmpty()) {
                    stream.url = "https://unknown-host/"
                }

                stream.statusCode = statusCode
                stream.mimeType = headers.firstOrNull { it.name.equals("content-type", ignoreCase = true) }?.value
                stream.contentLength = headers.firstOrNull { it.name.equals("content-length", ignoreCase = true) }
                    ?.value?.trim()?.toLongOrNull() ?: -1L
                stream.responseHeaders = headers
                stream.responseHeadersReceived = true
            } else {
                // HTTP/2 trailing HEADERS (e.g., gRPC Trailers with grpc-status / grpc-message):
                // preserve initial :status / content-type / headers and append trailers.
                stream.responseHeaders = stream.responseHeaders + headers
            }

            if (isEndStream) {
                dispatchResponseIfNeeded(stream)
                streams.remove(stream.streamId)
            }
        }
    }

    private fun resolveStreamHostIfUnknown(stream: StreamContext) {
        if (!stream.url.contains("://unknown-host")) return
        val fallbackHost = lastSeenAuthority ?: connectionHostHint
        if (fallbackHost != null && isUsableHost(fallbackHost)) {
            stream.url = stream.url.replace("://unknown-host", "://$fallbackHost")
        }
    }

    private fun dispatchRequestIfNeeded(stream: StreamContext) {
        if (stream.requestDispatched) return
        stream.requestDispatched = true
        resolveStreamHostIfUnknown(stream)
        val rawPost = stream.postDataStream.toByteArray()
        val decodedPost = HttpContentDecoder.decompressIfNeeded(rawPost, stream.requestHeaders)
        val postStr = GrpcDecoder.formatRequestPostData(decodedPost, stream.requestHeaders)
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
        resolveStreamHostIfUnknown(stream)
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
