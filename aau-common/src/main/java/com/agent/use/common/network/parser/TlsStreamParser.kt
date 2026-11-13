package com.agent.use.common.network.parser

import android.os.RemoteException
import android.util.Log
import com.agent.use.common.network.HttpRequestEvent
import com.agent.use.common.network.HttpResponseEvent
import com.agent.use.common.network.INetworkEventListener
import com.agent.use.common.network.NetworkCaptureConfig
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap

/**
 * Shared plaintext TLS/HTTP stream demultiplexer that auto-detects HTTP/2 vs HTTP/1.x,
 * buffers response bodies before firing `onResponseReceived`, and applies [NetworkCaptureConfig] URL filtering.
 */
class TlsStreamParser(
    private val config: NetworkCaptureConfig,
    private val listener: INetworkEventListener
) {

    companion object {
        private const val TAG = "TlsStreamParser"
        private const val MAX_CACHED_BODIES = 200
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

    private val responseBodies = Collections.synchronizedMap(
        object : LinkedHashMap<String, ByteArrayOutputStream>(64, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, ByteArrayOutputStream>?): Boolean {
                return size > MAX_CACHED_BODIES
            }
        }
    )

    fun onOutboundData(connectionId: String, data: ByteArray) {
        if (data.isEmpty()) return
        when (resolveProtocol(connectionId, data)) {
            Protocol.HTTP_2 -> http2Parsers.computeIfAbsent(connectionId) { createHttp2Parser() }.feedOutbound(data, connectionId)
            else -> http1Parsers.computeIfAbsent(connectionId) { createHttp1Parser() }.feedOutbound(data, connectionId)
        }
    }

    fun onInboundData(connectionId: String, data: ByteArray) {
        if (data.isEmpty()) return
        when (connectionProtocols[connectionId] ?: Protocol.UNKNOWN) {
            Protocol.HTTP_2 -> http2Parsers.computeIfAbsent(connectionId) { createHttp2Parser() }.feedInbound(data, connectionId)
            else -> http1Parsers.computeIfAbsent(connectionId) { createHttp1Parser() }.feedInbound(data, connectionId)
        }
    }

    fun finishConnection(connectionId: String) {
        http1Parsers[connectionId]?.finishOnEof()
        http1Parsers.remove(connectionId)
        http2Parsers.remove(connectionId)
        connectionProtocols.remove(connectionId)
    }

    fun getResponseBody(requestId: String): ByteArray? {
        val stream = synchronized(responseBodies) { responseBodies[requestId] } ?: return null
        return synchronized(stream) { stream.toByteArray() }
    }

    fun clear() {
        connectionProtocols.clear()
        http1Parsers.clear()
        http2Parsers.clear()
        synchronized(responseBodies) { responseBodies.clear() }
    }

    private fun resolveProtocol(connectionId: String, data: ByteArray): Protocol {
        val existing = connectionProtocols[connectionId]
        if (existing != null && existing != Protocol.UNKNOWN) {
            return existing
        }
        val determined = if (startsWithHttp2Preface(data)) Protocol.HTTP_2 else Protocol.HTTP_1_1
        connectionProtocols[connectionId] = determined
        return determined
    }

    private fun startsWithHttp2Preface(data: ByteArray): Boolean {
        if (data.size < HTTP2_PREFACE_PREFIX.size) return false
        for (i in HTTP2_PREFACE_PREFIX.indices) {
            if (data[i] != HTTP2_PREFACE_PREFIX[i]) return false
        }
        return true
    }

    private fun createHttp1Parser(): Http1PlaintextParser =
        Http1PlaintextParser(
            maxBodySizeBytes = config.maxBodySizeBytes,
            onParsedRequest = ::dispatchRequest,
            onParsedResponse = ::dispatchResponse,
            onBodyChunk = ::dispatchBodyChunk
        )

    private fun createHttp2Parser(): Http2PlaintextParser =
        Http2PlaintextParser(
            maxBodySizeBytes = config.maxBodySizeBytes,
            onParsedRequest = ::dispatchRequest,
            onParsedResponse = ::dispatchResponse,
            onBodyChunk = ::dispatchBodyChunk
        )

    private fun dispatchRequest(request: HttpRequestEvent) {
        if (!config.matchesUrl(request.url)) return
        try {
            listener.onRequestWillBeSent(request)
        } catch (e: RemoteException) {
            Log.w(TAG, "RemoteException dispatching onRequestWillBeSent: ${e.message}")
        }
    }

    private fun dispatchResponse(response: HttpResponseEvent) {
        if (!config.matchesUrl(response.url)) return
        try {
            listener.onResponseReceived(response)
        } catch (e: RemoteException) {
            Log.w(TAG, "RemoteException dispatching onResponseReceived: ${e.message}")
        }
    }

    private fun dispatchBodyChunk(requestId: String, chunk: ByteArray) {
        val bodyStream = synchronized(responseBodies) {
            responseBodies.getOrPut(requestId) { ByteArrayOutputStream() }
        }
        synchronized(bodyStream) {
            if (bodyStream.size() < config.maxBodySizeBytes) {
                val allowed = (config.maxBodySizeBytes - bodyStream.size()).toInt().coerceAtLeast(0)
                val toWrite = minOf(chunk.size, allowed)
                if (toWrite > 0) bodyStream.write(chunk, 0, toWrite)
            }
        }
        try {
            listener.onDataChunkReceived(requestId, chunk)
        } catch (e: RemoteException) {
            Log.w(TAG, "RemoteException dispatching onDataChunkReceived: ${e.message}")
        }
    }
}
