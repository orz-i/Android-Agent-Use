package com.agent.use.common.network.parser

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.util.Base64

/**
 * Schema-less Apache Thrift binary decoder (`TBinaryProtocol` and `TCompactProtocol`)
 * that converts serialized Thrift struct/message payloads into structured JSON without `.thrift` IDL files.
 */
object ThriftWireDecoder {

    private const val MAX_DEPTH = 16
    private const val MAX_FIELDS = 10_000
    private const val MAX_COLLECTION_ELEMENTS = 4096
    private const val MAX_HEX_PREVIEW_BYTES = 32
    private const val HEX_DIGITS = "0123456789abcdef"

    private sealed interface DecodedValue {
        data class Bool(val value: Boolean) : DecodedValue
        data class Num(val value: Long) : DecodedValue
        data class Flt(val value: Double) : DecodedValue
        data class Str(val text: String) : DecodedValue
        data class RawBytes(val bytes: ByteArray) : DecodedValue
        data class StructVal(val fields: LinkedHashMap<String, DecodedValue>) : DecodedValue
        data class ArrVal(val items: List<DecodedValue>) : DecodedValue
        data class MapVal(val entries: List<Pair<DecodedValue, DecodedValue>>) : DecodedValue
    }

    /**
     * Decodes a Thrift `TBinaryProtocol` or `TCompactProtocol` payload to JSON,
     * returning `null` if [data] does not strictly match either format.
     */
    fun decodeToJson(data: ByteArray, requireStrongHeuristic: Boolean = false): String? {
        if (data.size < 2) return null

        val compact = tryParseCompact(data)
        if (compact != null && (!requireStrongHeuristic || isStronglyPlausible(compact))) {
            return formatRootJson(compact.first, compact.second)
        }

        val binary = tryParseBinary(data)
        if (binary != null && (!requireStrongHeuristic || isStronglyPlausible(binary))) {
            return formatRootJson(binary.first, binary.second)
        }

        return null
    }

    private fun isStronglyPlausible(root: Pair<String, LinkedHashMap<String, DecodedValue>>): Boolean {
        val fields = root.second
        if (fields.size >= 2) return true
        return fields.values.any { v ->
            when (v) {
                is DecodedValue.Str -> v.text.length >= 2
                is DecodedValue.StructVal -> v.fields.isNotEmpty()
                is DecodedValue.ArrVal -> v.items.isNotEmpty()
                is DecodedValue.MapVal -> v.entries.isNotEmpty()
                else -> false
            }
        }
    }

    // ------------------------------------------------------------------
    // TBinaryProtocol
    // ------------------------------------------------------------------

    private object BinType {
        const val STOP = 0
        const val BOOL = 2
        const val BYTE = 3
        const val DOUBLE = 4
        const val I16 = 6
        const val I32 = 8
        const val I64 = 10
        const val STRING = 11
        const val STRUCT = 12
        const val MAP = 13
        const val SET = 14
        const val LIST = 15

        fun isValidValueType(t: Int): Boolean = t in setOf(
            BOOL, BYTE, DOUBLE, I16, I32, I64, STRING, STRUCT, MAP, SET, LIST
        )
    }

    private class Cursor(val data: ByteArray, var pos: Int = 0) {
        var fieldCounter: Int = 0
        val remaining: Int get() = data.size - pos

        fun nextByte(): Int? = if (pos < data.size) (data[pos++].toInt() and 0xFF) else null

        fun nextI16(): Int? {
            if (remaining < 2) return null
            val v = ((data[pos].toInt() and 0xFF) shl 8) or (data[pos + 1].toInt() and 0xFF)
            pos += 2
            return v.toShort().toInt()
        }

        fun nextI32(): Int? {
            if (remaining < 4) return null
            val v = ((data[pos].toInt() and 0xFF) shl 24) or
                ((data[pos + 1].toInt() and 0xFF) shl 16) or
                ((data[pos + 2].toInt() and 0xFF) shl 8) or
                (data[pos + 3].toInt() and 0xFF)
            pos += 4
            return v
        }

        fun nextI64(): Long? {
            if (remaining < 8) return null
            var v = 0L
            for (i in 0 until 8) {
                v = (v shl 8) or (data[pos + i].toLong() and 0xFFL)
            }
            pos += 8
            return v
        }

        fun nextLittleEndian64(): Long? {
            if (remaining < 8) return null
            var v = 0L
            for (i in 0 until 8) {
                v = v or ((data[pos + i].toLong() and 0xFFL) shl (i * 8))
            }
            pos += 8
            return v
        }

        fun readSlice(len: Int): ByteArray? {
            if (len < 0 || len > remaining) return null
            val slice = data.copyOfRange(pos, pos + len)
            pos += len
            return slice
        }

        fun readVarint32(): Int? {
            var result = 0
            var shift = 0
            for (i in 0 until 5) {
                val b = nextByte() ?: return null
                result = result or ((b and 0x7F) shl shift)
                if ((b and 0x80) == 0) return result
                shift += 7
            }
            return null
        }

        fun readVarint64(): Long? {
            var result = 0L
            var shift = 0
            for (i in 0 until 10) {
                val b = nextByte() ?: return null
                if (i == 9 && b > 1) return null
                result = result or ((b.toLong() and 0x7FL) shl shift)
                if ((b and 0x80) == 0) return result
                shift += 7
            }
            return null
        }
    }

    private fun tryParseBinary(data: ByteArray): Pair<String, LinkedHashMap<String, DecodedValue>>? {
        val c = Cursor(data)
        // Support strict TBinaryProtocol TMessage header (VERSION_1 = 0x8001xxxx)
        if (c.remaining >= 12) {
            val b0 = data[0].toInt() and 0xFF
            val b1 = data[1].toInt() and 0xFF
            if (b0 == 0x80 && b1 == 0x01) {
                val ver = c.nextI32() ?: return null
                val msgType = ver and 0xFF
                if (msgType !in 1..4) return null
                val nameLen = c.nextI32() ?: return null
                if (nameLen < 1 || nameLen > 256 || nameLen > c.remaining) return null
                val nameBytes = c.readSlice(nameLen) ?: return null
                val name = decodeUtf8TextIfClean(nameBytes) ?: return null
                val seqId = c.nextI32() ?: return null
                val body = parseBinaryStruct(c, depth = 0) ?: return null
                if (c.pos != data.size || body.isEmpty()) return null
                body["_thriftMethod"] = DecodedValue.Str(name)
                body["_thriftSeqId"] = DecodedValue.Num(seqId.toLong())
                return "binary" to body
            }
        }
        c.pos = 0
        val fields = parseBinaryStruct(c, depth = 0) ?: return null
        if (c.pos != data.size || fields.isEmpty()) return null
        return "binary" to fields
    }

    private fun parseBinaryStruct(c: Cursor, depth: Int): LinkedHashMap<String, DecodedValue>? {
        if (depth > MAX_DEPTH) return null
        val fields = LinkedHashMap<String, DecodedValue>()
        while (true) {
            val type = c.nextByte() ?: return null
            if (type == BinType.STOP) {
                return fields
            }
            if (!BinType.isValidValueType(type)) return null
            if (++c.fieldCounter > MAX_FIELDS) return null
            val fieldId = c.nextI16() ?: return null
            if (fieldId < 0) return null
            val value = parseBinaryValue(c, type, depth) ?: return null
            fields[fieldId.toString()] = value
        }
    }

    private fun parseBinaryValue(c: Cursor, type: Int, depth: Int): DecodedValue? {
        return when (type) {
            BinType.BOOL -> {
                val b = c.nextByte() ?: return null
                if (b != 0 && b != 1) return null
                DecodedValue.Bool(b == 1)
            }
            BinType.BYTE -> {
                val b = c.nextByte() ?: return null
                DecodedValue.Num(b.toByte().toLong())
            }
            BinType.I16 -> DecodedValue.Num((c.nextI16() ?: return null).toLong())
            BinType.I32 -> DecodedValue.Num((c.nextI32() ?: return null).toLong())
            BinType.I64 -> DecodedValue.Num(c.nextI64() ?: return null)
            BinType.DOUBLE -> {
                val bits = c.nextI64() ?: return null
                val d = java.lang.Double.longBitsToDouble(bits)
                if (d.isNaN()) return null
                DecodedValue.Flt(d)
            }
            BinType.STRING -> {
                val len = c.nextI32() ?: return null
                if (len < 0 || len > c.remaining) return null
                val slice = c.readSlice(len) ?: return null
                decodeBinaryPayload(slice)
            }
            BinType.STRUCT -> {
                val sub = parseBinaryStruct(c, depth + 1) ?: return null
                DecodedValue.StructVal(sub)
            }
            BinType.LIST, BinType.SET -> {
                val elemType = c.nextByte() ?: return null
                if (!BinType.isValidValueType(elemType)) return null
                val size = c.nextI32() ?: return null
                if (size < 0 || size > MAX_COLLECTION_ELEMENTS) return null
                val items = ArrayList<DecodedValue>(minOf(size, 64))
                for (i in 0 until size) {
                    items.add(parseBinaryValue(c, elemType, depth + 1) ?: return null)
                }
                DecodedValue.ArrVal(items)
            }
            BinType.MAP -> {
                val keyType = c.nextByte() ?: return null
                val valType = c.nextByte() ?: return null
                if (!BinType.isValidValueType(keyType) || !BinType.isValidValueType(valType)) return null
                val size = c.nextI32() ?: return null
                if (size < 0 || size > MAX_COLLECTION_ELEMENTS) return null
                val entries = ArrayList<Pair<DecodedValue, DecodedValue>>(minOf(size, 64))
                for (i in 0 until size) {
                    val k = parseBinaryValue(c, keyType, depth + 1) ?: return null
                    val v = parseBinaryValue(c, valType, depth + 1) ?: return null
                    entries.add(k to v)
                }
                DecodedValue.MapVal(entries)
            }
            else -> null
        }
    }

    // ------------------------------------------------------------------
    // TCompactProtocol
    // ------------------------------------------------------------------

    private object CompactType {
        const val STOP = 0
        const val BOOL_TRUE = 1
        const val BOOL_FALSE = 2
        const val BYTE = 3
        const val I16 = 4
        const val I32 = 5
        const val I64 = 6
        const val DOUBLE = 7
        const val BINARY = 8
        const val LIST = 9
        const val SET = 10
        const val MAP = 11
        const val STRUCT = 12

        fun isValidFieldType(t: Int): Boolean = t in BOOL_TRUE..STRUCT
    }

    private fun tryParseCompact(data: ByteArray): Pair<String, LinkedHashMap<String, DecodedValue>>? {
        val c = Cursor(data)
        // Optional TCompactProtocol TMessage envelope (PROTOCOL_ID = 0x82)
        if (c.remaining >= 4 && (data[0].toInt() and 0xFF) == 0x82) {
            c.pos = 1
            val verAndType = c.nextByte() ?: return null
            if ((verAndType and 0x1F) == 1) {
                val msgType = (verAndType ushr 5) and 0x07
                if (msgType in 1..4) {
                    val seqId = c.readVarint32() ?: return null
                    val nameLen = c.readVarint32() ?: return null
                    if (nameLen in 1..256 && nameLen <= c.remaining) {
                        val nameBytes = c.readSlice(nameLen) ?: return null
                        val name = decodeUtf8TextIfClean(nameBytes)
                        if (name != null) {
                            val body = parseCompactStruct(c, depth = 0)
                            if (body != null && c.pos == data.size && body.isNotEmpty()) {
                                body["_thriftMethod"] = DecodedValue.Str(name)
                                body["_thriftSeqId"] = DecodedValue.Num(seqId.toLong())
                                return "compact" to body
                            }
                        }
                    }
                }
            }
            c.pos = 0
            c.fieldCounter = 0
        }

        val fields = parseCompactStruct(c, depth = 0) ?: return null
        if (c.pos != data.size || fields.isEmpty()) return null
        return "compact" to fields
    }

    private fun parseCompactStruct(c: Cursor, depth: Int): LinkedHashMap<String, DecodedValue>? {
        if (depth > MAX_DEPTH) return null
        val fields = LinkedHashMap<String, DecodedValue>()
        var lastFieldId = 0

        while (true) {
            val header = c.nextByte() ?: return null
            if (header == CompactType.STOP) {
                return fields
            }
            if (++c.fieldCounter > MAX_FIELDS) return null

            val modifier = (header ushr 4) and 0x0F
            val compactType = header and 0x0F
            if (!CompactType.isValidFieldType(compactType)) return null

            val fieldId = if (modifier == 0) {
                val zz = c.readVarint32() ?: return null
                zigzagToInt(zz)
            } else {
                lastFieldId + modifier
            }
            if (fieldId < 0 || fieldId > Short.MAX_VALUE) return null
            lastFieldId = fieldId

            val value = when (compactType) {
                CompactType.BOOL_TRUE -> DecodedValue.Bool(true)
                CompactType.BOOL_FALSE -> DecodedValue.Bool(false)
                else -> parseCompactElement(c, compactType, depth) ?: return null
            }
            fields[fieldId.toString()] = value
        }
    }

    private fun parseCompactElement(c: Cursor, type: Int, depth: Int): DecodedValue? {
        if (depth > MAX_DEPTH) return null
        return when (type) {
            CompactType.BOOL_TRUE -> {
                val b = c.nextByte() ?: return null
                if (b != 0 && b != 1) return null
                DecodedValue.Bool(b == 1)
            }
            CompactType.BOOL_FALSE -> DecodedValue.Bool(false)
            CompactType.BYTE -> {
                val b = c.nextByte() ?: return null
                DecodedValue.Num(b.toByte().toLong())
            }
            CompactType.I16, CompactType.I32 -> {
                val zz = c.readVarint32() ?: return null
                DecodedValue.Num(zigzagToInt(zz).toLong())
            }
            CompactType.I64 -> {
                val zz = c.readVarint64() ?: return null
                DecodedValue.Num(zigzagToLong(zz))
            }
            CompactType.DOUBLE -> {
                val bits = c.nextLittleEndian64() ?: return null
                val d = java.lang.Double.longBitsToDouble(bits)
                if (d.isNaN()) return null
                DecodedValue.Flt(d)
            }
            CompactType.BINARY -> {
                val len = c.readVarint32() ?: return null
                if (len < 0 || len > c.remaining) return null
                val slice = c.readSlice(len) ?: return null
                decodeBinaryPayload(slice)
            }
            CompactType.STRUCT -> {
                val sub = parseCompactStruct(c, depth + 1) ?: return null
                DecodedValue.StructVal(sub)
            }
            CompactType.LIST, CompactType.SET -> {
                val sizeAndType = c.nextByte() ?: return null
                val headerSize = (sizeAndType ushr 4) and 0x0F
                val elemType = sizeAndType and 0x0F
                if (!CompactType.isValidFieldType(elemType)) return null
                val size = if (headerSize == 15) (c.readVarint32() ?: return null) else headerSize
                if (size < 0 || size > MAX_COLLECTION_ELEMENTS) return null
                val items = ArrayList<DecodedValue>(minOf(size, 64))
                for (i in 0 until size) {
                    val elem = if (elemType == CompactType.BOOL_TRUE || elemType == CompactType.BOOL_FALSE) {
                        val b = c.nextByte() ?: return null
                        if (b != 0 && b != 1) return null
                        DecodedValue.Bool(b == 1)
                    } else {
                        parseCompactElement(c, elemType, depth + 1) ?: return null
                    }
                    items.add(elem)
                }
                DecodedValue.ArrVal(items)
            }
            CompactType.MAP -> {
                val size = c.readVarint32() ?: return null
                if (size < 0 || size > MAX_COLLECTION_ELEMENTS) return null
                if (size == 0) {
                    DecodedValue.MapVal(emptyList())
                } else {
                    val kvType = c.nextByte() ?: return null
                    val keyType = (kvType ushr 4) and 0x0F
                    val valType = kvType and 0x0F
                    if (!CompactType.isValidFieldType(keyType) || !CompactType.isValidFieldType(valType)) return null
                    val entries = ArrayList<Pair<DecodedValue, DecodedValue>>(minOf(size, 64))
                    for (i in 0 until size) {
                        val k = parseCompactElement(c, keyType, depth + 1) ?: return null
                        val v = parseCompactElement(c, valType, depth + 1) ?: return null
                        entries.add(k to v)
                    }
                    DecodedValue.MapVal(entries)
                }
            }
            else -> null
        }
    }

    private fun zigzagToInt(n: Int): Int = (n ushr 1) xor -(n and 1)

    private fun zigzagToLong(n: Long): Long = (n ushr 1) xor -(n and 1L)

    // ------------------------------------------------------------------
    // Formatting helpers
    // ------------------------------------------------------------------

    private fun decodeBinaryPayload(slice: ByteArray): DecodedValue {
        decodeUtf8TextIfClean(slice)?.let { return DecodedValue.Str(it) }
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

    private fun formatRootJson(protocol: String, fields: LinkedHashMap<String, DecodedValue>): String {
        val sb = StringBuilder(256)
        sb.append("{\"_protocol\":")
        ProtobufWireDecoder.appendJsonString(sb, "thrift-$protocol")
        for ((k, v) in fields) {
            sb.append(',')
            ProtobufWireDecoder.appendJsonString(sb, k)
            sb.append(':')
            appendValueJson(sb, v)
        }
        sb.append('}')
        return sb.toString()
    }

    private fun appendStructJson(sb: StringBuilder, fields: LinkedHashMap<String, DecodedValue>) {
        sb.append('{')
        var first = true
        for ((k, v) in fields) {
            if (!first) sb.append(',')
            first = false
            ProtobufWireDecoder.appendJsonString(sb, k)
            sb.append(':')
            appendValueJson(sb, v)
        }
        sb.append('}')
    }

    private fun appendValueJson(sb: StringBuilder, value: DecodedValue) {
        when (value) {
            is DecodedValue.Bool -> sb.append(value.value)
            is DecodedValue.Num -> sb.append(value.value)
            is DecodedValue.Flt -> {
                if (value.value.isFinite()) sb.append(value.value)
                else ProtobufWireDecoder.appendJsonString(sb, value.value.toString())
            }
            is DecodedValue.Str -> ProtobufWireDecoder.appendJsonString(sb, value.text)
            is DecodedValue.StructVal -> appendStructJson(sb, value.fields)
            is DecodedValue.ArrVal -> {
                sb.append('[')
                for (i in value.items.indices) {
                    if (i > 0) sb.append(',')
                    appendValueJson(sb, value.items[i])
                }
                sb.append(']')
            }
            is DecodedValue.MapVal -> {
                sb.append('{')
                for (i in value.entries.indices) {
                    if (i > 0) sb.append(',')
                    val (k, v) = value.entries[i]
                    val keyStr = when (k) {
                        is DecodedValue.Str -> k.text
                        is DecodedValue.Num -> k.value.toString()
                        is DecodedValue.Bool -> k.value.toString()
                        is DecodedValue.Flt -> k.value.toString()
                        else -> "k$i"
                    }
                    ProtobufWireDecoder.appendJsonString(sb, keyStr)
                    sb.append(':')
                    appendValueJson(sb, v)
                }
                sb.append('}')
            }
            is DecodedValue.RawBytes -> {
                val b64 = Base64.getEncoder().encodeToString(value.bytes)
                sb.append("{\"_type\":\"bytes\",\"size\":")
                sb.append(value.bytes.size)
                sb.append(",\"base64\":")
                ProtobufWireDecoder.appendJsonString(sb, b64)
                sb.append(",\"hex\":")
                ProtobufWireDecoder.appendJsonString(sb, buildHexPreview(value.bytes))
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
}
