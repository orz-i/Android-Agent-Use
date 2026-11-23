package com.agent.use.common.network.parser

/**
 * LZ4 **block** 格式解码器（不是 frame：没有魔数、没有帧头、没有 xxhash 校验）。
 *
 * 序列结构：`token(1B) [额外 literal 长度...][literal 数据] [offset(2B LE)][额外 match 长度...]`
 *
 * 两个使用方：[com.agent.use.common.network.plugin.BzpBlockCodec]（BOSS 的 `BZPBlock` 容器）
 * 与声明式解码管道（`op = "decompress", algo = "lz4-block"`）。抽出来是为了让"新 App 用
 * 同样的压缩"不必再抄一遍解码循环。
 */
object Lz4BlockDecoder {

    /** 解压输出的上限，防止畸形输入把内存打爆。 */
    const val MAX_OUTPUT_BYTES = 32 * 1024 * 1024

    /**
     * @param expectedSize 头部声明的解压后长度；未知时传 0，由解码器自行扩容。
     * @return 解出的字节；输入非法或完全不可解时返回 null。
     *         输入被截断时返回已解出的前缀（宁可给出半份明文，也不要整段丢掉）。
     */
    fun decode(
        src: ByteArray,
        srcOffset: Int = 0,
        srcLength: Int = src.size - srcOffset,
        expectedSize: Int = 0,
        maxOutputBytes: Int = MAX_OUTPUT_BYTES,
    ): ByteArray? {
        val end = srcOffset + srcLength
        if (srcLength <= 0 || srcOffset < 0 || end > src.size) return null
        val cap = maxOutputBytes.coerceIn(64, MAX_OUTPUT_BYTES)

        val sink = ExpandingSink(
            if (expectedSize in 1..cap) expectedSize else minOf(cap, srcLength * 8 + 64),
            cap,
        )
        var i = srcOffset

        while (i < end) {
            val token = src[i].toInt() and 0xFF
            i++

            var literalLength = token ushr 4
            if (literalLength == 15) {
                while (i < end) {
                    val b = src[i].toInt() and 0xFF
                    i++
                    literalLength += b
                    if (b != 255) break
                }
            }
            if (literalLength > 0) {
                if (i + literalLength > end) {
                    // 输入被截断：把还能拿到的 literal 写出去就收工
                    val partial = end - i
                    if (partial > 0 && sink.ensure(partial)) {
                        sink.put(src, i, partial)
                    }
                    break
                }
                if (!sink.ensure(literalLength)) return null
                sink.put(src, i, literalLength)
                i += literalLength
            }

            // literal 段刚好用完输入 = 正常的最后一个序列
            if (i >= end) break
            if (i + 2 > end) break

            val matchOffset = (src[i].toInt() and 0xFF) or ((src[i + 1].toInt() and 0xFF) shl 8)
            i += 2
            if (matchOffset == 0 || matchOffset > sink.length) return null

            var matchLength = token and 0x0F
            if (matchLength == 15) {
                while (i < end) {
                    val b = src[i].toInt() and 0xFF
                    i++
                    matchLength += b
                    if (b != 255) break
                }
            }
            matchLength += 4

            if (!sink.ensure(matchLength)) return null
            sink.copyWithin(matchOffset, matchLength)
        }

        return sink.takeIf { it.length > 0 }?.toByteArray()
    }

    /** LZ4 允许 match 段与输出区重叠，必须逐字节复制，不能走 System.arraycopy。 */
    private class ExpandingSink(initialCapacity: Int, private val maxBytes: Int) {
        private var buf = ByteArray(initialCapacity.coerceIn(64, maxBytes))
        var length: Int = 0
            private set

        fun ensure(extra: Int): Boolean {
            if (extra < 0) return false
            if (length + extra <= buf.size) return true
            if (length + extra > maxBytes) return false
            var next = buf.size
            while (next < length + extra) {
                next = if (next >= maxBytes / 2) maxBytes else next * 2
            }
            buf = buf.copyOf(next)
            return true
        }

        fun put(src: ByteArray, offset: Int, count: Int) {
            System.arraycopy(src, offset, buf, length, count)
            length += count
        }

        fun copyWithin(matchOffset: Int, count: Int) {
            var read = length - matchOffset
            for (k in 0 until count) {
                buf[length + k] = buf[read + k]
            }
            length += count
        }

        fun toByteArray(): ByteArray = if (length == buf.size) buf else buf.copyOf(length)
    }
}
