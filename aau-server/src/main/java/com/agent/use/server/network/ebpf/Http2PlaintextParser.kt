package com.agent.use.server.network.ebpf

import com.agent.use.common.network.HttpHeader
import com.agent.use.common.network.HttpRequestEvent
import com.agent.use.common.network.HttpResponseEvent
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets
import java.util.concurrent.ConcurrentHashMap

/**
 * HTTP/2 二进制帧流式解析器 (RFC 7540 & RFC 7541)。
 *
 * 维护 HTTP/2 连接状态与 Stream 流多路复用会话：
 * 1. 识别 24 字节 Client Connection Preface (PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n)；
 * 2. 解析 9 字节标准 Frame Header (Length, Type, Flags, StreamID)；
 * 3. 提取 HEADERS 帧并调用 HPACK 解码器解析伪头部 (:method, :path, :status)；
 * 4. 提取 DATA 帧分发明文分块数据，并支持根据 END_STREAM 标志位判断流关闭。
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

    private val hpackDecoder = Http2HpackDecoder()

    // 针对每个 connectionId 和流向维护拼包流
    private val outboundBuffer = ByteArrayOutputStream()
    private val inboundBuffer = ByteArrayOutputStream()

    // 记录 StreamID 对应的当前元数据
    private data class StreamContext(
        val streamId: Int,
        var requestId: String,
        var url: String = "https://unknown",
        var method: String = "GET",
        var requestHeaders: List<HttpHeader> = emptyList(),
        var postDataStream: ByteArrayOutputStream = ByteArrayOutputStream(),
        var responseHeaders: List<HttpHeader> = emptyList(),
        var responseBodyStream: ByteArrayOutputStream = ByteArrayOutputStream()
    )

    private val streams = ConcurrentHashMap<Int, StreamContext>()

    @Synchronized
    fun feedOutbound(data: ByteArray, connectionId: String) {
        outboundBuffer.write(data)
        processFrames(outboundBuffer, connectionId, isOutbound = true)
    }

    @Synchronized
    fun feedInbound(data: ByteArray, connectionId: String) {
        inboundBuffer.write(data)
        processFrames(inboundBuffer, connectionId, isOutbound = false)
    }

    private fun processFrames(buffer: ByteArrayOutputStream, connectionId: String, isOutbound: Boolean) {
        var bytes = buffer.toByteArray()
        if (bytes.isEmpty()) return

        var offset = 0

        // 检查出站前导 Preface
        if (isOutbound && bytes.size >= CLIENT_PREFACE.size) {
            var matchPreface = true
            for (i in CLIENT_PREFACE.indices) {
                if (bytes[i] != CLIENT_PREFACE[i]) {
                    matchPreface = false
                    break
                }
            }
            if (matchPreface) {
                offset += CLIENT_PREFACE.size
            }
        }

        while (offset + 9 <= bytes.size) {
            val length = ((bytes[offset].toInt() and 0xFF) shl 16) or
                    ((bytes[offset + 1].toInt() and 0xFF) shl 8) or
                    (bytes[offset + 2].toInt() and 0xFF)
            val type = bytes[offset + 3].toInt() and 0xFF
            val flags = bytes[offset + 4].toInt() and 0xFF
            val streamId = (((bytes[offset + 5].toInt() and 0x7F) shl 24) or
                    ((bytes[offset + 6].toInt() and 0xFF) shl 16) or
                    ((bytes[offset + 7].toInt() and 0xFF) shl 8) or
                    (bytes[offset + 8].toInt() and 0xFF))

            val totalFrameSize = 9 + length
            if (offset + totalFrameSize > bytes.size) {
                // 帧内容尚未完整到达，退出循环等待后续数据
                break
            }

            val payloadStart = offset + 9
            val payload = bytes.copyOfRange(payloadStart, payloadStart + length)

            handleFrame(type, flags, streamId, payload, connectionId, isOutbound)
            offset += totalFrameSize
        }

        // 保留未处理的残余字节
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
        if (streamId == 0) {
            // 控制帧 (如 SETTINGS, PING, WINDOW_UPDATE)，忽略
            return
        }

        val stream = streams.computeIfAbsent(streamId) {
            StreamContext(
                streamId = streamId,
                requestId = "${connectionId}_h2_s${streamId}"
            )
        }

        when (type) {
            FRAME_TYPE_HEADERS -> {
                val headerBlock = extractHeaderBlock(payload, flags)
                val headers = hpackDecoder.decode(headerBlock)

                val isEndStream = (flags and FLAG_END_STREAM) != 0

                if (isOutbound) {
                    // 请求 Headers
                    var method = "GET"
                    var scheme = "https"
                    var authority = "localhost"
                    var path = "/"

                    for (h in headers) {
                        when (h.name) {
                            ":method" -> method = h.value
                            ":scheme" -> scheme = h.value
                            ":authority" -> authority = h.value
                            ":path" -> path = h.value
                        }
                    }

                    val fullUrl = "$scheme://$authority$path"
                    stream.method = method
                    stream.url = fullUrl
                    stream.requestHeaders = headers

                    val reqEvent = HttpRequestEvent(
                        requestId = stream.requestId,
                        timestamp = System.currentTimeMillis(),
                        url = fullUrl,
                        method = method,
                        headers = headers,
                        postData = null,
                        isTls = true
                    )
                    onParsedRequest(reqEvent)
                } else {
                    // 响应 Headers
                    var statusCode = 200
                    for (h in headers) {
                        if (h.name == ":status") {
                            statusCode = h.value.toIntOrNull() ?: 200
                        }
                    }
                    val mimeType = headers.firstOrNull { it.name.equals("content-type", ignoreCase = true) }?.value
                    val contentLength = headers.firstOrNull { it.name.equals("content-length", ignoreCase = true) }
                        ?.value?.toLongOrNull() ?: -1L

                    stream.responseHeaders = headers

                    val respEvent = HttpResponseEvent(
                        requestId = stream.requestId,
                        timestamp = System.currentTimeMillis(),
                        url = stream.url,
                        statusCode = statusCode,
                        statusText = "OK",
                        headers = headers,
                        mimeType = mimeType,
                        contentLength = contentLength,
                        fromCache = false
                    )
                    onParsedResponse(respEvent)
                }

                if (isEndStream) {
                    streams.remove(streamId)
                }
            }

            FRAME_TYPE_DATA -> {
                val dataPayload = extractDataPayload(payload, flags)
                val isEndStream = (flags and FLAG_END_STREAM) != 0

                if (isOutbound) {
                    if (dataPayload.isNotEmpty() && stream.postDataStream.size() < maxBodySizeBytes) {
                        stream.postDataStream.write(dataPayload)
                    }
                } else {
                    if (dataPayload.isNotEmpty()) {
                        if (stream.responseBodyStream.size() < maxBodySizeBytes) {
                            stream.responseBodyStream.write(dataPayload)
                        }
                        onBodyChunk(stream.requestId, dataPayload)
                    }
                }

                if (isEndStream) {
                    streams.remove(streamId)
                }
            }
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
            start += 5 // 4 字节 Stream Dependency + 1 字节 Weight
        }

        return if (start < end && end <= payload.size) {
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
        return if (start < end && end <= payload.size) {
            payload.copyOfRange(start, end)
        } else {
            payload
        }
    }
}
