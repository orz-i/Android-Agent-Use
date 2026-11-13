package com.agent.use.common.network.parser

import com.agent.use.common.network.HttpHeader
import java.io.ByteArrayInputStream

/**
 * Full RFC 7541 HPACK header decoder with static + dynamic table support and RFC 7541 Huffman decoding.
 * Maintain one instance per direction (`outbound` and `inbound`) for each HTTP/2 connection.
 */
class Http2HpackDecoder(
    private var maxDynamicTableSize: Int = 4096
) {
    private val dynamicTable = ArrayDeque<HttpHeader>()
    private var dynamicTableBytes = 0

    companion object {
        private val STATIC_TABLE = arrayOf(
            "", "",
            ":authority", "",
            ":method", "GET",
            ":method", "POST",
            ":path", "/",
            ":path", "/index.html",
            ":scheme", "http",
            ":scheme", "https",
            ":status", "200",
            ":status", "204",
            ":status", "206",
            ":status", "304",
            ":status", "400",
            ":status", "404",
            ":status", "500",
            "accept-charset", "",
            "accept-encoding", "gzip, deflate",
            "accept-language", "",
            "accept-ranges", "",
            "accept", "",
            "access-control-allow-origin", "",
            "age", "",
            "allow", "",
            "authorization", "",
            "cache-control", "",
            "content-disposition", "",
            "content-encoding", "",
            "content-language", "",
            "content-length", "",
            "content-location", "",
            "content-range", "",
            "content-type", "",
            "cookie", "",
            "date", "",
            "etag", "",
            "expect", "",
            "expires", "",
            "from", "",
            "host", "",
            "if-match", "",
            "if-modified-since", "",
            "if-none-match", "",
            "if-range", "",
            "if-unmodified-since", "",
            "last-modified", "",
            "link", "",
            "location", "",
            "max-forwards", "",
            "proxy-authenticate", "",
            "proxy-authorization", "",
            "range", "",
            "referer", "",
            "refresh", "",
            "retry-after", "",
            "server", "",
            "set-cookie", "",
            "strict-transport-security", "",
            "transfer-encoding", "",
            "user-agent", "",
            "vary", "",
            "via", "",
            "www-authenticate", ""
        )

        private const val STATIC_TABLE_SIZE = 61
    }

    @Synchronized
    fun decode(headerBlock: ByteArray): List<HttpHeader> {
        val headers = mutableListOf<HttpHeader>()
        val input = ByteArrayInputStream(headerBlock)

        while (input.available() > 0) {
            val b = input.read()
            if (b == -1) break

            when {
                // 1. Indexed Header Field Representation (1xxxxxxx)
                (b and 0x80) != 0 -> {
                    val index = readInteger(b, 0x7F, input)
                    getEntry(index)?.let { headers.add(it) }
                }
                // 2. Literal Header Field with Incremental Indexing (01xxxxxx)
                (b and 0x40) != 0 -> {
                    val index = readInteger(b, 0x3F, input)
                    val name = if (index != 0) getEntry(index)?.name.orEmpty() else readString(input)
                    val value = readString(input)
                    if (name.isNotEmpty()) {
                        val header = HttpHeader(name, value)
                        headers.add(header)
                        insertDynamicEntry(header)
                    }
                }
                // 3. Dynamic Table Size Update (001xxxxx)
                (b and 0x20) != 0 -> {
                    val newMax = readInteger(b, 0x1F, input).coerceAtLeast(0)
                    maxDynamicTableSize = newMax
                    evictToMaxSize()
                }
                // 4. Literal Header Field without Indexing / Never Indexed (0000xxxx / 0001xxxx)
                else -> {
                    val index = readInteger(b, 0x0F, input)
                    val name = if (index != 0) getEntry(index)?.name.orEmpty() else readString(input)
                    val value = readString(input)
                    if (name.isNotEmpty()) {
                        headers.add(HttpHeader(name, value))
                    }
                }
            }
        }

        return headers
    }

    private fun getEntry(index: Int): HttpHeader? {
        if (index <= 0) return null
        if (index <= STATIC_TABLE_SIZE) {
            val name = STATIC_TABLE[index * 2]
            val value = STATIC_TABLE[index * 2 + 1]
            return HttpHeader(name, value)
        }
        val dynIndex = index - STATIC_TABLE_SIZE - 1
        return dynamicTable.getOrNull(dynIndex)
    }

    private fun entrySize(header: HttpHeader): Int =
        header.name.toByteArray(Charsets.UTF_8).size +
            header.value.toByteArray(Charsets.UTF_8).size + 32

    private fun insertDynamicEntry(header: HttpHeader) {
        val size = entrySize(header)
        if (size > maxDynamicTableSize) {
            dynamicTable.clear()
            dynamicTableBytes = 0
            return
        }
        dynamicTable.addFirst(header)
        dynamicTableBytes += size
        evictToMaxSize()
    }

    private fun evictToMaxSize() {
        while (dynamicTableBytes > maxDynamicTableSize && dynamicTable.isNotEmpty()) {
            val removed = dynamicTable.removeLast()
            dynamicTableBytes = (dynamicTableBytes - entrySize(removed)).coerceAtLeast(0)
        }
    }

    private fun readInteger(firstByte: Int, prefixMask: Int, input: ByteArrayInputStream): Int {
        var value = firstByte and prefixMask
        if (value < prefixMask) {
            return value
        }
        var m = 0
        while (input.available() > 0) {
            val b = input.read()
            if (b == -1) break
            value += (b and 0x7F) shl m
            m += 7
            if ((b and 0x80) == 0 || m > 28) {
                break
            }
        }
        return value
    }

    private fun readString(input: ByteArrayInputStream): String {
        if (input.available() == 0) return ""
        val first = input.read()
        val isHuffman = (first and 0x80) != 0
        val length = readInteger(first, 0x7F, input).coerceAtLeast(0)
        if (length == 0) return ""
        val safeLen = length.coerceAtMost(input.available())
        if (safeLen == 0) return ""
        val bytes = ByteArray(safeLen)
        val readBytes = input.read(bytes, 0, safeLen)
        if (readBytes <= 0) return ""
        return if (isHuffman) {
            Http2Huffman.decodeToString(bytes, readBytes)
        } else {
            String(bytes, 0, readBytes, Charsets.UTF_8)
        }
    }
}
