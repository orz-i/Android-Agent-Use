package com.agent.use.common.network.parser

import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.util.Base64

/**
 * Schema-less Protobuf wire-format decoder that converts binary protobuf payloads into a structured JSON representation.
 * Used for decoding gRPC (`application/grpc`) and raw protobuf traffic without requiring `.proto` descriptors.
 */
object ProtobufWireDecoder {

    private const val MAX_DEPTH = 16
    private const val MAX_FIELDS = 10_000
    private const val MAX_HEX_PREVIEW_BYTES = 32

    private const val WIRE_VARINT = 0
    private const val WIRE_FIXED64 = 1
    private const val WIRE_LENGTH_DELIMITED = 2
    private const val WIRE_FIXED32 = 5

    private sealed interface DecodedValue {
        data class Varint(val value: Long) : DecodedValue
        data class Fixed64(val value: Long) : DecodedValue
        data class Fixed32(val value: Int) : DecodedValue
        data class Str(val text: String) : DecodedValue
        data class SubMessage(val message: DecodedMessage) : DecodedValue
        data class RawBytes(val bytes: ByteArray) : DecodedValue
    }

    private class DecodedMessage {
        val fields = LinkedHashMap<Int, MutableList<DecodedValue>>()

        fun add(fieldNumber: Int, value: DecodedValue) {
            fields.getOrPut(fieldNumber) { ArrayList(1) }.add(value)
        }
    }

    /**
     * Decodes a protobuf wire-format byte array into structured JSON, or returns null if [data] is not valid protobuf.
     */
    fun decodeToJson(data: ByteArray): String? {
        if (data.isEmpty()) return "{}"
        val parsed = tryParseMessage(data, 0, data.size, depth = 0) ?: return null
        val sb = StringBuilder(256)
        appendMessageJson(sb, parsed)
        return sb.toString()
    }

    private fun tryParseMessage(data: ByteArray, start: Int, end: Int, depth: Int): DecodedMessage? {
        if (depth > MAX_DEPTH || start > end) return null
        val msg = DecodedMessage()
        var pos = start
        var count = 0

        while (pos < end) {
            if (++count > MAX_FIELDS) return null
            val tagRes = readVarint(data, pos, end) ?: return null
            val tag = tagRes.first
            pos = tagRes.second
            if (tag <= 0L) return null

            val fieldNumberLong = tag ushr 3
            if (fieldNumberLong <= 0L || fieldNumberLong > 536_870_911L) return null
            val fieldNumber = fieldNumberLong.toInt()
            val wireType = (tag and 0x07L).toInt()

            when (wireType) {
                WIRE_VARINT -> {
                    val v = readVarint(data, pos, end) ?: return null
                    pos = v.second
                    msg.add(fieldNumber, DecodedValue.Varint(v.first))
                }
                WIRE_FIXED64 -> {
                    if (end - pos < 8) return null
                    val v = readLittleEndian64(data, pos)
                    pos += 8
                    msg.add(fieldNumber, DecodedValue.Fixed64(v))
                }
                WIRE_FIXED32 -> {
                    if (end - pos < 4) return null
                    val v = readLittleEndian32(data, pos)
                    pos += 4
                    msg.add(fieldNumber, DecodedValue.Fixed32(v))
                }
                WIRE_LENGTH_DELIMITED -> {
                    val lenRes = readVarint(data, pos, end) ?: return null
                    val lenLong = lenRes.first
                    pos = lenRes.second
                    if (lenLong < 0L || lenLong > (end - pos).toLong()) return null
                    val len = lenLong.toInt()
                    if (len == 0) {
                        msg.add(fieldNumber, DecodedValue.Str(""))
                    } else {
                        val slice = data.copyOfRange(pos, pos + len)
                        val decoded = decodeLengthDelimited(slice, depth)
                        msg.add(fieldNumber, decoded)
                    }
                    pos += len
                }
                else -> return null
            }
        }

        return if (pos == end) msg else null
    }

    private fun decodeLengthDelimited(slice: ByteArray, depth: Int): DecodedValue {
        val text = decodeUtf8TextIfClean(slice)
        if (text != null) {
            return DecodedValue.Str(text)
        }
        if (depth < MAX_DEPTH) {
            val nested = tryParseMessage(slice, 0, slice.size, depth + 1)
            if (nested != null) {
                return DecodedValue.SubMessage(nested)
            }
        }
        return DecodedValue.RawBytes(slice)
    }

    private fun decodeUtf8TextIfClean(bytes: ByteArray): String? {
        if (bytes.isEmpty()) return ""
        return try {
            val decoder = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
            val charBuf = decoder.decode(ByteBuffer.wrap(bytes))
            for (i in 0 until charBuf.length) {
                val ch = charBuf[i]
                if (ch == '\uFFFD') return null
                if (ch.code < 0x20 && ch != '\n' && ch != '\r' && ch != '\t') return null
                if (ch.code == 0x7F) return null
            }
            charBuf.toString()
        } catch (_: Exception) {
            null
        }
    }

    private fun readVarint(data: ByteArray, start: Int, end: Int): Pair<Long, Int>? {
        var result = 0L
        var shift = 0
        var pos = start
        for (i in 0 until 10) {
            if (pos >= end) return null
            val b = data[pos++].toInt() and 0xFF
            if (i == 9 && b > 1) return null
            result = result or ((b.toLong() and 0x7FL) shl shift)
            if ((b and 0x80) == 0) {
                return result to pos
            }
            shift += 7
        }
        return null
    }

    private fun readLittleEndian32(data: ByteArray, offset: Int): Int {
        return (data[offset].toInt() and 0xFF) or
            ((data[offset + 1].toInt() and 0xFF) shl 8) or
            ((data[offset + 2].toInt() and 0xFF) shl 16) or
            ((data[offset + 3].toInt() and 0xFF) shl 24)
    }

    private fun readLittleEndian64(data: ByteArray, offset: Int): Long {
        var result = 0L
        for (i in 0 until 8) {
            result = result or ((data[offset + i].toLong() and 0xFFL) shl (i * 8))
        }
        return result
    }

    private fun appendMessageJson(sb: StringBuilder, msg: DecodedMessage) {
        sb.append('{')
        var first = true
        for ((fieldNum, values) in msg.fields) {
            if (!first) sb.append(',')
            first = false
            appendJsonString(sb, fieldNum.toString())
            sb.append(':')
            if (values.size == 1) {
                appendValueJson(sb, values[0])
            } else {
                sb.append('[')
                for (i in values.indices) {
                    if (i > 0) sb.append(',')
                    appendValueJson(sb, values[i])
                }
                sb.append(']')
            }
        }
        sb.append('}')
    }

    private fun appendValueJson(sb: StringBuilder, value: DecodedValue) {
        when (value) {
            is DecodedValue.Varint -> sb.append(value.value)
            is DecodedValue.Fixed64 -> sb.append(value.value)
            is DecodedValue.Fixed32 -> sb.append(value.value.toLong() and 0xFFFFFFFFL)
            is DecodedValue.Str -> appendJsonString(sb, value.text)
            is DecodedValue.SubMessage -> appendMessageJson(sb, value.message)
            is DecodedValue.RawBytes -> {
                val b64 = Base64.getEncoder().encodeToString(value.bytes)
                val hexPreview = buildHexPreview(value.bytes)
                sb.append("{\"_type\":\"bytes\",\"size\":")
                sb.append(value.bytes.size)
                sb.append(",\"base64\":")
                appendJsonString(sb, b64)
                sb.append(",\"hex\":")
                appendJsonString(sb, hexPreview)
                sb.append('}')
            }
        }
    }

    private fun buildHexPreview(bytes: ByteArray): String {
        val count = minOf(bytes.size, MAX_HEX_PREVIEW_BYTES)
        val sb = StringBuilder(count * 2 + 3)
        for (i in 0 until count) {
            val v = bytes[i].toInt() and 0xFF
            sb.append(HEX_DIGITS[v ushr 4])
            sb.append(HEX_DIGITS[v and 0x0F])
        }
        if (bytes.size > count) sb.append("...")
        return sb.toString()
    }

    internal fun appendJsonString(sb: StringBuilder, text: String) {
        sb.append('"')
        for (ch in text) {
            when (ch) {
                '"' -> sb.append("\\\"")
                '\\' -> sb.append("\\\\")
                '\b' -> sb.append("\\b")
                '\u000C' -> sb.append("\\f")
                '\n' -> sb.append("\\n")
                '\r' -> sb.append("\\r")
                '\t' -> sb.append("\\t")
                else -> {
                    if (ch.code < 0x20) {
                        sb.append(String.format("\\u%04x", ch.code))
                    } else {
                        sb.append(ch)
                    }
                }
            }
        }
        sb.append('"')
    }

    private const val HEX_DIGITS = "0123456789abcdef"
}
