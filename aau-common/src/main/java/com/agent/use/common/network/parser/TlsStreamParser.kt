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
    private val listener: INetworkEventListener,
    private val defaultConnectionHostHint: String? = null
) {

    companion object {
        private const val TAG = "TlsStreamParser"
        private const val MAX_CACHED_BODIES = 200
        val HTTP2_PREFACE_PREFIX = "PRI ".toByteArray(StandardCharsets.ISO_8859_1)

        /**
         * Reliable frame-level HTTP/2 detection per RFC 7540:
         * 9-byte frame header (length: 24-bit, type: 0x0..0x9, flags: 8-bit, streamId: 31-bit),
         * streamId bit constraints (0 for SETTINGS/PING/GOAWAY, >0 for DATA/HEADERS),
         * length constraints, and not starting with ASCII HTTP/1.x method/status.
         */
        fun startsWithHttp2Frame(data: ByteArray, offset: Int = 0): Boolean {
            if (data.size - offset < 9) return false

            val b0 = data[offset].toInt() and 0xFF
            val b1 = data[offset + 1].toInt() and 0xFF
            val b2 = data[offset + 2].toInt() and 0xFF
            val b3 = data[offset + 3].toInt() and 0xFF

            // Quick check against common ASCII HTTP/1.x prefixes
            if (b0 == 'G'.code && b1 == 'E'.code && b2 == 'T'.code && b3 == ' '.code) return false
            if (b0 == 'P'.code && b1 == 'O'.code && b2 == 'S'.code && b3 == 'T'.code) return false
            if (b0 == 'H'.code && b1 == 'E'.code && b2 == 'A'.code && b3 == 'D'.code) return false
            if (b0 == 'P'.code && b1 == 'U'.code && b2 == 'T'.code && b3 == ' '.code) return false
            if (b0 == 'D'.code && b1 == 'E'.code && b2 == 'L'.code && b3 == 'E'.code) return false
            if (b0 == 'O'.code && b1 == 'P'.code && b2 == 'T'.code && b3 == 'I'.code) return false
            if (b0 == 'P'.code && b1 == 'A'.code && b2 == 'T'.code && b3 == 'C'.code) return false
            if (b0 == 'C'.code && b1 == 'O'.code && b2 == 'N'.code && b3 == 'N'.code) return false
            if (b0 == 'T'.code && b1 == 'R'.code && b2 == 'A'.code && b3 == 'C'.code) return false
            if (b0 == 'H'.code && b1 == 'T'.code && b2 == 'T'.code && b3 == 'P'.code) return false

            val length = (b0 shl 16) or (b1 shl 8) or b2
            val type = b3
            val streamId = ((data[offset + 5].toInt() and 0x7F) shl 24) or
                ((data[offset + 6].toInt() and 0xFF) shl 16) or
                ((data[offset + 7].toInt() and 0xFF) shl 8) or
                (data[offset + 8].toInt() and 0xFF)

            if (type !in 0x0..0x9) return false
            if (length < 0 || length > 16 * 1024 * 1024) return false

            when (type) {
                0x0 -> if (streamId == 0) return false // DATA
                0x1 -> if (streamId == 0) return false // HEADERS
                0x2 -> if (streamId == 0 || length != 5) return false // PRIORITY
                0x3 -> if (streamId == 0 || length != 4) return false // RST_STREAM
                0x4 -> if (streamId != 0 || (length % 6) != 0) return false // SETTINGS
                0x5 -> if (streamId == 0 || length < 4) return false // PUSH_PROMISE
                0x6 -> if (streamId != 0 || length != 8) return false // PING
                0x7 -> if (streamId != 0 || length < 8) return false // GOAWAY
                0x8 -> if (length != 4) return false // WINDOW_UPDATE
                0x9 -> if (streamId == 0) return false // CONTINUATION
            }

            val nextOffset = offset + 9 + length
            if (data.size >= nextOffset + 9) {
                val nextType = data[nextOffset + 3].toInt() and 0xFF
                if (nextType !in 0x0..0x9) return false
            }

            return true
        }

        fun startsWithHttp2Preface(data: ByteArray): Boolean {
            if (data.size < HTTP2_PREFACE_PREFIX.size) return false
            for (i in HTTP2_PREFACE_PREFIX.indices) {
                if (data[i] != HTTP2_PREFACE_PREFIX[i]) return false
            }
            return true
        }

        fun isHttp2Traffic(data: ByteArray): Boolean =
            startsWithHttp2Preface(data) || startsWithHttp2Frame(data)
    }

    private enum class Protocol {
        UNKNOWN,
        HTTP_1_1,
        HTTP_2
    }

    private val connectionProtocols = ConcurrentHashMap<String, Protocol>()
    private val connectionHostHints = ConcurrentHashMap<String, String>()
    private val http1Parsers = ConcurrentHashMap<String, Http1PlaintextParser>()
    private val http2Parsers = ConcurrentHashMap<String, Http2PlaintextParser>()

    private val responseBodies = Collections.synchronizedMap(
        object : LinkedHashMap<String, ByteArrayOutputStream>(64, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, ByteArrayOutputStream>?): Boolean {
                return size > MAX_CACHED_BODIES
            }
        }
    )

    fun setConnectionHostHint(connectionId: String, hostHint: String) {
        if (hostHint.isNotBlank() && !hostHint.equals("localhost", ignoreCase = true) && !hostHint.equals("unknown-host", ignoreCase = true)) {
            connectionHostHints[connectionId] = hostHint
            http1Parsers[connectionId]?.setConnectionHostHint(hostHint)
            http2Parsers[connectionId]?.setConnectionHostHint(hostHint)
        }
    }

    fun onOutboundData(connectionId: String, data: ByteArray, hostHint: String? = null) {
        if (data.isEmpty()) return
        if (hostHint != null) setConnectionHostHint(connectionId, hostHint)
        when (resolveOrUpgradeProtocol(connectionId, data)) {
            Protocol.HTTP_2 -> http2Parsers.computeIfAbsent(connectionId) { createHttp2Parser(connectionId) }.feedOutbound(data, connectionId)
            else -> http1Parsers.computeIfAbsent(connectionId) { createHttp1Parser(connectionId) }.feedOutbound(data, connectionId)
        }
    }

    fun onInboundData(connectionId: String, data: ByteArray, hostHint: String? = null) {
        if (data.isEmpty()) return
        if (hostHint != null) setConnectionHostHint(connectionId, hostHint)
        when (resolveOrUpgradeProtocol(connectionId, data)) {
            Protocol.HTTP_2 -> http2Parsers.computeIfAbsent(connectionId) { createHttp2Parser(connectionId) }.feedInbound(data, connectionId)
            else -> http1Parsers.computeIfAbsent(connectionId) { createHttp1Parser(connectionId) }.feedInbound(data, connectionId)
        }
    }

    fun finishConnection(connectionId: String) {
        http1Parsers[connectionId]?.finishOnEof()
        http1Parsers.remove(connectionId)
        http2Parsers.remove(connectionId)
        connectionProtocols.remove(connectionId)
        connectionHostHints.remove(connectionId)
    }

    fun getResponseBody(requestId: String): ByteArray? {
        val stream = synchronized(responseBodies) { responseBodies[requestId] } ?: return null
        return synchronized(stream) { stream.toByteArray() }
    }

    fun clear() {
        connectionProtocols.clear()
        connectionHostHints.clear()
        http1Parsers.clear()
        http2Parsers.clear()
        synchronized(responseBodies) { responseBodies.clear() }
    }

    private fun resolveOrUpgradeProtocol(connectionId: String, data: ByteArray): Protocol {
        val existing = connectionProtocols[connectionId]
        if (existing == Protocol.HTTP_2) {
            return Protocol.HTTP_2
        }

        val isH2 = isHttp2Traffic(data)

        if (existing == Protocol.HTTP_1_1) {
            if (isH2) {
                val h1 = http1Parsers[connectionId]
                if (h1 == null || !h1.hasDispatched()) {
                    // Upgrade cleanly to HTTP/2
                    val bufferedOut = h1?.getUnconsumedOutbound() ?: ByteArray(0)
                    val bufferedIn = h1?.getUnconsumedInbound() ?: ByteArray(0)
                    http1Parsers.remove(connectionId)
                    connectionProtocols[connectionId] = Protocol.HTTP_2

                    val h2 = http2Parsers.computeIfAbsent(connectionId) { createHttp2Parser(connectionId) }
                    if (bufferedOut.isNotEmpty()) {
                        h2.feedOutbound(bufferedOut, connectionId)
                    }
                    if (bufferedIn.isNotEmpty()) {
                        h2.feedInbound(bufferedIn, connectionId)
                    }
                    return Protocol.HTTP_2
                }
            }
            return Protocol.HTTP_1_1
        }

        // existing was null or Protocol.UNKNOWN
        val determined = if (isH2) Protocol.HTTP_2 else Protocol.HTTP_1_1
        connectionProtocols[connectionId] = determined
        return determined
    }

    private fun createHttp1Parser(connectionId: String): Http1PlaintextParser =
        Http1PlaintextParser(
            maxBodySizeBytes = config.maxBodySizeBytes,
            connectionHostHint = connectionHostHints[connectionId] ?: defaultConnectionHostHint,
            onParsedRequest = ::dispatchRequest,
            onParsedResponse = ::dispatchResponse,
            onBodyChunk = ::dispatchBodyChunk
        )

    private fun createHttp2Parser(connectionId: String): Http2PlaintextParser =
        Http2PlaintextParser(
            maxBodySizeBytes = config.maxBodySizeBytes,
            connectionHostHint = connectionHostHints[connectionId] ?: defaultConnectionHostHint,
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
