package com.agent.use.server.network.ebpf

import android.os.RemoteException
import android.util.Log
import com.agent.use.common.network.HttpRequestEvent
import com.agent.use.common.network.HttpResponseEvent
import com.agent.use.common.network.INetworkEventListener
import com.agent.use.common.network.NetworkCaptureConfig
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets
import java.util.concurrent.ConcurrentHashMap

/**
 * TLS 明文数据流多路复用与协议自适应解析分发器。
 *
 * 核心功能：
 * 1. 协议自动探测：识别 Client Connection Preface (PRI * HTTP/2.0)，自动在 HTTP/1.1 与 HTTP/2 解析器间切换；
 * 2. 多会话隔离：按 connectionId 隔离维护各个 TCP/TLS 会话的流式缓冲区；
 * 3. URL 正则过滤：严格根据 NetworkCaptureConfig.matchesUrl(url) 筛选事件；
 * 4. 响应体全量缓存：维护 LRU/并发缓存，供给 getResponseBody(requestId) 快速直读；
 * 5. 安全事件广播：将解析完成的事件安全分发到 INetworkEventListener (捕获 RemoteException 防崩溃)。
 */
class TlsStreamParser(
    private val config: NetworkCaptureConfig,
    private val listener: INetworkEventListener
) {

    companion object {
        private const val TAG = "TlsStreamParser"
        val HTTP2_PREFACE_PREFIX = "PRI ".toByteArray(StandardCharsets.ISO_8859_1)
    }

    private enum class Protocol {
        UNKNOWN,
        HTTP_1_1,
        HTTP_2
    }

    private val connectionProtocols = ConcurrentHashMap<String, Protocol>()
    private val http1Parsers = ConcurrentHashMap<String, Http1PlaintextParser>()
    private val http2Parsers = ConcurrentHashMap<String, Http2PlaintextParser>()

    // 全量响应体暂存缓存 (requestId -> ByteArray)
    private val responseBodies = ConcurrentHashMap<String, ByteArrayOutputStream>()

    /**
     * 接收出站明文数据 (SSL_write -> Request)。
     */
    fun onOutboundData(connectionId: String, data: ByteArray) {
        if (data.isEmpty()) return

        val protocol = resolveProtocol(connectionId, data)
        when (protocol) {
            Protocol.HTTP_2 -> {
                val parser = http2Parsers.computeIfAbsent(connectionId) { createHttp2Parser() }
                parser.feedOutbound(data, connectionId)
            }
            else -> {
                val parser = http1Parsers.computeIfAbsent(connectionId) { createHttp1Parser() }
                parser.feedOutbound(data, connectionId)
            }
        }
    }

    /**
     * 接收入站明文数据 (SSL_read -> Response)。
     */
    fun onInboundData(connectionId: String, data: ByteArray) {
        if (data.isEmpty()) return

        val protocol = connectionProtocols[connectionId] ?: Protocol.UNKNOWN
        when (protocol) {
            Protocol.HTTP_2 -> {
                val parser = http2Parsers.computeIfAbsent(connectionId) { createHttp2Parser() }
                parser.feedInbound(data, connectionId)
            }
            else -> {
                val parser = http1Parsers.computeIfAbsent(connectionId) { createHttp1Parser() }
                parser.feedInbound(data, connectionId)
            }
        }
    }

    /**
     * 获取指定请求对应的完整 HTTP 响应体数据。
     */
    fun getResponseBody(requestId: String): ByteArray? {
        val stream = responseBodies[requestId] ?: return null
        return synchronized(stream) {
            stream.toByteArray()
        }
    }

    /**
     * 清理会话与缓存。
     */
    fun clear() {
        connectionProtocols.clear()
        http1Parsers.clear()
        http2Parsers.clear()
        responseBodies.clear()
    }

    private fun resolveProtocol(connectionId: String, data: ByteArray): Protocol {
        val existing = connectionProtocols[connectionId]
        if (existing != null && existing != Protocol.UNKNOWN) {
            return existing
        }

        val isHttp2 = startsWithHttp2Preface(data)
        val determined = if (isHttp2) Protocol.HTTP_2 else Protocol.HTTP_1_1
        connectionProtocols[connectionId] = determined
        return determined
    }

    private fun startsWithHttp2Preface(data: ByteArray): Boolean {
        if (data.size < HTTP2_PREFACE_PREFIX.size) return false
        for (i in HTTP2_PREFACE_PREFIX.indices) {
            if (data[i] != HTTP2_PREFACE_PREFIX[i]) {
                return false
            }
        }
        return true
    }

    private fun createHttp1Parser(): Http1PlaintextParser {
        return Http1PlaintextParser(
            maxBodySizeBytes = config.maxBodySizeBytes,
            onParsedRequest = ::dispatchRequest,
            onParsedResponse = ::dispatchResponse,
            onBodyChunk = ::dispatchBodyChunk
        )
    }

    private fun createHttp2Parser(): Http2PlaintextParser {
        return Http2PlaintextParser(
            maxBodySizeBytes = config.maxBodySizeBytes,
            onParsedRequest = ::dispatchRequest,
            onParsedResponse = ::dispatchResponse,
            onBodyChunk = ::dispatchBodyChunk
        )
    }

    private fun dispatchRequest(request: HttpRequestEvent) {
        if (!config.matchesUrl(request.url)) {
            Log.d(TAG, "Request URL dropped by filter pattern: ${request.url}")
            return
        }

        try {
            listener.onRequestWillBeSent(request)
        } catch (e: RemoteException) {
            Log.w(TAG, "RemoteException dispatching onRequestWillBeSent: ${e.message}")
        }
    }

    private fun dispatchResponse(response: HttpResponseEvent) {
        if (!config.matchesUrl(response.url)) {
            Log.d(TAG, "Response URL dropped by filter pattern: ${response.url}")
            return
        }

        try {
            listener.onResponseReceived(response)
        } catch (e: RemoteException) {
            Log.w(TAG, "RemoteException dispatching onResponseReceived: ${e.message}")
        }
    }

    private fun dispatchBodyChunk(requestId: String, chunk: ByteArray) {
        // 累积存入响应体缓存
        val bodyStream = responseBodies.computeIfAbsent(requestId) { ByteArrayOutputStream() }
        synchronized(bodyStream) {
            if (bodyStream.size() + chunk.size <= config.maxBodySizeBytes) {
                bodyStream.write(chunk)
            }
        }

        try {
            listener.onDataChunkReceived(requestId, chunk)
        } catch (e: RemoteException) {
            Log.w(TAG, "RemoteException dispatching onDataChunkReceived: ${e.message}")
        }
    }
}
