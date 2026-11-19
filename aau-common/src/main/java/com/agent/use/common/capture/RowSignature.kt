package com.agent.use.common.capture

import android.graphics.Bitmap
import kotlin.math.abs

/**
 * 单帧的行特征集合。
 *
 * 长截图拼接的核心不是「找出两帧哪一行完全相同」，而是「在允许噪声的前提下，
 * 判断上一帧的某一段与新帧的某一段是不是同一块画面」。因此这里不复用整行哈希：
 * 整行哈希一旦有一位不同就判为不同行，真机上滚动一屏后会有 2%~5% 的行因为
 * 抗锯齿、亚像素位移、OLED 调光而差一个色阶，精确匹配会直接退化到零。
 *
 * 改用**分段亮度**：
 * - 每行横向等分 [SEGMENTS] 段，每段取平均灰度（0..255），打包进一个 Long；
 * - 额外记录该行的**纹强**（段亮度极差），用于给匹配加权——纯色行几乎不携带信息，
 *   若不加权，大片黑底会让任意位移都拿到极低分，从而被误判成「完全重叠」。
 *
 * @property rows 长度等于帧高，每个 Long 承载 8 段亮度（低 8 位是第 0 段）
 * @property texture 长度等于帧高，每行的段亮度极差（0..255）
 */
class FrameSignature(
    @JvmField val rows: LongArray,
    @JvmField val texture: IntArray,
) {
    val height: Int get() = rows.size

    /**
     * 两帧是否可视为「画面未变化」。
     *
     * 逐行比较归一化距离，纹理越高的行权重越大；平均偏差低于 [tolerance] 即认为没变。
     */
    fun similarTo(other: FrameSignature, tolerance: Int = DEFAULT_TOLERANCE): Boolean {
        if (rows.size != other.rows.size) return false
        if (rows.isEmpty()) return true
        var sum = 0L
        var weight = 0L
        for (i in rows.indices) {
            val w = 1 + texture[i]
            sum += RowSignature.rowDistance(rows[i], other.rows[i]).toLong() * w
            weight += RowSignature.MAX_ROW_DISTANCE.toLong() * w
        }
        if (weight <= 0L) return true
        return sum * 1000L / weight <= tolerance
    }

    companion object {
        /** 默认「未变化」判定阈值（千分比，8 ≈ 0.8% 平均偏差）。 */
        const val DEFAULT_TOLERANCE = 8
    }
}

/**
 * 行特征提取器。
 *
 * 一条重要的取舍：这里**不**追求「把一行压成一个高熵哈希」，而是刻意降维到 8 段灰度。
 * 降维换来的是可度量的距离，而距离才能容忍真机上的像素抖动。8 段对 1080~1440 宽的
 * 手机屏幕足够区分「同一块内容」与「不同内容」——横幅、列表项、分隔线都会让相邻段
 * 产生不同亮度，只有整片纯色才会退化成全零向量，而那种行本来也不该参与判定。
 */
object RowSignature {

    /** 每行横向分段数；8 段正好塞进一个 Long 的 8 个字节。 */
    const val SEGMENTS = 8

    /** 每行 8 段、每段最大差 255 时的理论上界。 */
    const val MAX_ROW_DISTANCE = SEGMENTS * 255

    private const val CHUNK_ROWS = 32
    private const val SEGMENT_MASK = 0xFFL

    /**
     * 提取整帧特征。
     *
     * @param bitmap 待处理帧，不会被修改
     * @param sampleStep 段内横向采样步长，越大越快但越容易漏掉细线
     */
    @JvmStatic
    @JvmOverloads
    fun of(bitmap: Bitmap, sampleStep: Int = 4): FrameSignature {
        val width = bitmap.width
        val height = bitmap.height
        if (width <= 0 || height <= 0) return FrameSignature(LongArray(0), IntArray(0))

        val step = sampleStep.coerceIn(1, maxOf(1, width / SEGMENTS))
        val rows = LongArray(height)
        val texture = IntArray(height)
        val buffer = IntArray(width * minOf(CHUNK_ROWS, height))

        var y = 0
        while (y < height) {
            val chunk = minOf(CHUNK_ROWS, height - y)
            bitmap.getPixels(buffer, 0, width, 0, y, width, chunk)
            for (r in 0 until chunk) {
                val base = r * width
                var packed = 0L
                var minSeg = 255
                var maxSeg = 0
                for (seg in 0 until SEGMENTS) {
                    val x0 = width * seg / SEGMENTS
                    val x1 = width * (seg + 1) / SEGMENTS
                    var sum = 0
                    var count = 0
                    var x = x0
                    while (x < x1) {
                        val px = buffer[base + x]
                        // 整数灰度：ITU-R BT.601 权重的定点近似
                        val gray = ((px ushr 16 and 0xFF) * 299 +
                            (px ushr 8 and 0xFF) * 587 +
                            (px and 0xFF) * 114) / 1000
                        sum += gray
                        count++
                        x += step
                    }
                    val avg = if (count > 0) sum / count else 0
                    packed = packed or ((avg.toLong() and SEGMENT_MASK) shl (seg * 8))
                    if (avg < minSeg) minSeg = avg
                    if (avg > maxSeg) maxSeg = avg
                }
                rows[y + r] = packed
                texture[y + r] = maxSeg - minSeg
            }
            y += chunk
        }
        return FrameSignature(rows, texture)
    }

    /** 两个行特征的距离：8 段绝对差之和，范围 0..[MAX_ROW_DISTANCE]。 */
    @JvmStatic
    fun rowDistance(a: Long, b: Long): Int {
        var distance = 0
        for (seg in 0 until SEGMENTS) {
            val shift = seg * 8
            val va = ((a ushr shift) and SEGMENT_MASK).toInt()
            val vb = ((b ushr shift) and SEGMENT_MASK).toInt()
            distance += abs(va - vb)
        }
        return distance
    }
}
