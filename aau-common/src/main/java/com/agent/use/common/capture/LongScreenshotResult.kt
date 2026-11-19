package com.agent.use.common.capture

import android.os.Bundle
import android.os.ParcelFileDescriptor

/**
 * 长截图终止原因。
 *
 * 之所以要把「为什么停」带回客户端，是因为长截图的失败大多是**正常**的：
 * 列表真的到底了、页面根本没动、撞到高度上限……这些都不该当成错误弹给用户，
 * 但需要让上层知道这张图完不完整。
 */
enum class LongScreenshotStop(val wire: String) {
    /** 只抓到首屏就结束（内容不足一屏）。 */
    SINGLE_SCREEN("single"),

    /** 已滚到底：相邻两帧完全一致。 */
    REACHED_END("end"),

    /** 达到 [LongScreenshotOptions.maxScrolls]。 */
    MAX_SCROLLS("max_scrolls"),

    /** 达到 [LongScreenshotOptions.maxHeightPx]，输出图被截断。 */
    MAX_HEIGHT("max_height"),

    /** 相邻两帧找不到足够重叠，拼接会错位，主动停下（宁可少拼也不错拼）。 */
    NO_OVERLAP("no_overlap"),

    /** 页面滚动无响应（手势被拦截或本页不可滚动）。 */
    NO_PROGRESS("no_progress"),

    /** 抓帧失败（`screencap` 异常、安全图层等）。 */
    CAPTURE_FAILED("capture_failed"),

    /** 调用方中途取消。 */
    CANCELLED("cancelled");

    companion object {
        @JvmStatic
        fun fromWire(wire: String?): LongScreenshotStop =
            entries.firstOrNull { it.wire == wire } ?: CAPTURE_FAILED
    }
}

/**
 * 长截图结果。
 *
 * 图像以 [ParcelFileDescriptor] 回传而不是 `ByteArray`：一张 1080×12000 的 PNG 通常 2~8 MB，
 * 直接塞进 Binder 事务会撞上 1 MB 的 `TransactionTooLargeException` 上限。
 * 服务端把字节写进临时文件后 **打开 fd 并 unlink**，客户端从 fd 读到的是已被删除的 inode，
 * 既能流式读完，也不会在设备上留下任何截图残片。
 */
data class LongScreenshotResult(
    /** 指向 PNG 字节流的只读 fd；失败时为 null。 */
    val png: ParcelFileDescriptor?,
    val width: Int,
    val height: Int,
    /** 实际参与拼接的帧数（含首帧）。 */
    val frames: Int,
    /** 实际滚动次数。 */
    val scrolls: Int,
    val stop: LongScreenshotStop,
    val elapsedMs: Long,
    /** 实际使用的通道，便于端上排查走的是 Shell 还是 Root。 */
    val mode: ScreenCaptureMode? = null,
    val note: String? = null,
) {

    val isComplete: Boolean
        get() = stop == LongScreenshotStop.REACHED_END || stop == LongScreenshotStop.SINGLE_SCREEN

    fun toBundle(): Bundle = Bundle().apply {
        putParcelable(KEY_PNG, png)
        putInt(KEY_WIDTH, width)
        putInt(KEY_HEIGHT, height)
        putInt(KEY_FRAMES, frames)
        putInt(KEY_SCROLLS, scrolls)
        putString(KEY_STOP, stop.wire)
        putLong(KEY_ELAPSED, elapsedMs)
        putInt(KEY_MODE, mode?.wire ?: -1)
        putString(KEY_NOTE, note)
    }

    companion object {
        private const val KEY_PNG = "png"
        private const val KEY_WIDTH = "width"
        private const val KEY_HEIGHT = "height"
        private const val KEY_FRAMES = "frames"
        private const val KEY_SCROLLS = "scrolls"
        private const val KEY_STOP = "stop"
        private const val KEY_ELAPSED = "elapsedMs"
        private const val KEY_MODE = "mode"
        private const val KEY_NOTE = "note"

        @Suppress("DEPRECATION")
        @JvmStatic
        fun fromBundle(bundle: Bundle?): LongScreenshotResult {
            if (bundle == null) return failed("服务端未返回长截图结果")
            val modeWire = bundle.getInt(KEY_MODE, -1)
            return LongScreenshotResult(
                png = bundle.getParcelable(KEY_PNG),
                width = bundle.getInt(KEY_WIDTH, 0),
                height = bundle.getInt(KEY_HEIGHT, 0),
                frames = bundle.getInt(KEY_FRAMES, 0),
                scrolls = bundle.getInt(KEY_SCROLLS, 0),
                stop = LongScreenshotStop.fromWire(bundle.getString(KEY_STOP)),
                elapsedMs = bundle.getLong(KEY_ELAPSED, 0L),
                mode = if (modeWire < 0) null else ScreenCaptureMode.fromWire(modeWire),
                note = bundle.getString(KEY_NOTE),
            )
        }

        @JvmStatic
        fun failed(note: String?): LongScreenshotResult = LongScreenshotResult(
            png = null, width = 0, height = 0, frames = 0, scrolls = 0,
            stop = LongScreenshotStop.CAPTURE_FAILED, elapsedMs = 0L, note = note,
        )
    }
}
