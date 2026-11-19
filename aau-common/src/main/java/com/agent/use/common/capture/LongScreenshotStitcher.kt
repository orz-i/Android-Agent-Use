package com.agent.use.common.capture

import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.Rect

/**
 * 长图缝合画布。
 *
 * 按行追加帧内容，内部使用**倍增扩容**而不是一次性按 [maxHeight] 分配：
 * 12,000 行的 1080p 输出需要约 51 MB 连续位图，但多数页面的真实高度只有 2~4 屏，
 * 预分配会把一次「只需要 12 MB」的截图变成一次 51 MB 的峰值分配。
 *
 * 非线程安全：长截图是单通道串行流程，不需要加锁。
 */
class LongScreenshotStitcher(
    private val width: Int,
    private val maxHeight: Int,
) {

    private val paint = Paint(Paint.FILTER_BITMAP_FLAG)
    private var buffer: Bitmap = Bitmap.createBitmap(
        width,
        minOf(maxHeight, INITIAL_CAPACITY_ROWS),
        Bitmap.Config.ARGB_8888,
    )

    /** 当前已写入的行数。 */
    var height: Int = 0
        private set

    /** 是否因为超过 [maxHeight] 而被截断。 */
    var truncated: Boolean = false
        private set

    /**
     * 追加一帧的指定行区间。
     *
     * @param frame 新帧
     * @param srcTop 起始行（含）
     * @param srcBottom 结束行（不含）
     * @return 实际写入的行数；触顶截断时可能小于请求行数
     */
    fun append(frame: Bitmap, srcTop: Int, srcBottom: Int): Int {
        val top = srcTop.coerceIn(0, frame.height)
        val bottom = srcBottom.coerceIn(top, frame.height)
        var rows = bottom - top
        if (rows <= 0) return 0
        if (height >= maxHeight) {
            truncated = true
            return 0
        }
        if (height + rows > maxHeight) {
            rows = maxHeight - height
            truncated = true
        }
        ensureCapacity(height + rows)
        Canvas(buffer).drawBitmap(
            frame,
            Rect(0, top, frame.width, top + rows),
            Rect(0, height, width, height + rows),
            paint,
        )
        height += rows
        return rows
    }

    /** 收尾并交出成品位图（已裁剪到实际高度）；调用方负责 recycle。 */
    fun finish(): Bitmap? {
        if (height <= 0) return null
        if (height == buffer.height) return buffer
        val result = Bitmap.createBitmap(buffer, 0, 0, width, height)
        buffer.recycle()
        buffer = result
        return result
    }

    /**
     * 丢弃已拼内容，从空画布重新开始。
     *
     * 用于「布局在第一次滚动后发生变化」的场景：可折叠大标题收起时，第二帧的内容原点
     * 会比首帧上移一两百像素，两帧根本无法按纯垂直平移对齐。此时正确做法是丢掉首帧、
     * 以当前帧为新起点重来，而不是硬拼出一张错位的图。
     *
     * 保留已分配的缓冲区容量，避免重新申请内存。
     */
    fun reset() {
        height = 0
        truncated = false
    }

    /** 放弃本次拼接并释放内存。 */
    fun close() {
        if (!buffer.isRecycled) buffer.recycle()
        height = 0
    }

    private fun ensureCapacity(required: Int) {
        if (required <= buffer.height) return
        var capacity = buffer.height
        while (capacity < required) capacity = minOf(maxHeight, capacity * 2)
        if (capacity < required) capacity = required
        val grown = Bitmap.createBitmap(width, capacity, Bitmap.Config.ARGB_8888)
        Canvas(grown).drawBitmap(buffer, 0f, 0f, null)
        buffer.recycle()
        buffer = grown
    }

    companion object {
        /** 初始容量：两屏左右，覆盖大多数「不长的长图」。 */
        const val INITIAL_CAPACITY_ROWS = 4_096
    }
}
