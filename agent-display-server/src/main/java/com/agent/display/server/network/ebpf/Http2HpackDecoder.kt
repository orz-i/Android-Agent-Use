package com.agent.display.server.network.ebpf

import com.agent.display.common.network.HttpHeader
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets

/**
 * HTTP/2 HPACK 头部解码器 (RFC 7541 实现)。
 *
 * 支持：
 * 1. 静态索引表查找 (Static Table Indices 1..61)；
 * 2. 伪头部 (:method, :path, :authority, :scheme, :status) 解析；
 * 3. 带增量索引 / 不带索引 / 从不索引的字面量头部解析；
 * 4. RFC 7541 霍夫曼解码 (Huffman Decoding) 与普通字面量解码。
 */
class Http2HpackDecoder {

    companion object {
        // RFC 7541 静态表 (索引 1..61)
        private val STATIC_TABLE = arrayOf(
            "", // 0 占位
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
    }

    /**
     * 解码包含在 HEADERS / CONTINUATION 帧中的 HPACK 编码头部块。
     */
    fun decode(headerBlock: ByteArray): List<HttpHeader> {
        val headers = mutableListOf<HttpHeader>()
        val input = ByteArrayInputStream(headerBlock)

        while (input.available() > 0) {
            val b = input.read()
            if (b == -1) break

            when {
                // 1. 索引头部字段 (1xxxxxxx, 7-bit prefix)
                (b and 0x80) != 0 -> {
                    val index = readInteger(b, 0x7F, input)
                    val header = getFromStaticTable(index)
                    if (header != null) {
                        headers.add(header)
                    }
                }
                // 2. 带增量索引的字面量头部字段 (01xxxxxx, 6-bit prefix)
                (b and 0x40) != 0 -> {
                    val index = readInteger(b, 0x3F, input)
                    val name = if (index != 0) {
                        getFromStaticTable(index)?.name ?: ""
                    } else {
                        readString(input)
                    }
                    val value = readString(input)
                    if (name.isNotEmpty()) {
                        headers.add(HttpHeader(name, value))
                    }
                }
                // 3. 动态表大小更新 (001xxxxx, 5-bit prefix)
                (b and 0x20) != 0 -> {
                    readInteger(b, 0x1F, input) // 忽略动态表大小更新
                }
                // 4. 不带索引 / 从不索引的字面量头部字段 (0000xxxx, 4-bit prefix)
                else -> {
                    val index = readInteger(b, 0x0F, input)
                    val name = if (index != 0) {
                        getFromStaticTable(index)?.name ?: ""
                    } else {
                        readString(input)
                    }
                    val value = readString(input)
                    if (name.isNotEmpty()) {
                        headers.add(HttpHeader(name, value))
                    }
                }
            }
        }

        return headers
    }

    private fun getFromStaticTable(index: Int): HttpHeader? {
        if (index <= 0 || index * 2 >= STATIC_TABLE.size) {
            return null
        }
        val name = STATIC_TABLE[index * 2 - 1]
        val value = STATIC_TABLE[index * 2]
        return HttpHeader(name, value)
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
            if ((b and 0x80) == 0) {
                break
            }
        }
        return value
    }

    private fun readString(input: ByteArrayInputStream): String {
        if (input.available() == 0) return ""
        val first = input.read()
        val isHuffman = (first and 0x80) != 0
        val length = readInteger(first, 0x7F, input)
        if (length <= 0) return ""

        val bytes = ByteArray(length)
        val readBytes = input.read(bytes, 0, length)
        if (readBytes <= 0) return ""

        return if (isHuffman) {
            decodeHuffman(bytes, readBytes)
        } else {
            String(bytes, 0, readBytes, StandardCharsets.UTF_8)
        }
    }

    /**
     * 基础霍夫曼解码 fallback 实现：若遇到复杂树结构异常则优雅容错。
     */
    private fun decodeHuffman(data: ByteArray, length: Int): String {
        return try {
            Http2Huffman.decode(data, length)
        } catch (_: Exception) {
            String(data, 0, length, StandardCharsets.ISO_8859_1)
        }
    }
}
