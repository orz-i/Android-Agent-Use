package com.agent.use.common.capture

import android.graphics.Bitmap
import android.os.SystemClock

/**
 * 长截图的取像原语。
 *
 * 只暴露三个动作：抓一帧、滚一下、等一会。拼接策略全部由 [LongScreenshotRunner] 决定，
 * 这样服务端（`screencap` + `input swipe`）与无障碍端（`takeScreenshot` + 手势注入）
 * 能共用同一套拼接逻辑，只需要各自实现这三个原语。
 */
interface ScreenFrameSource {

    /** 抓一帧；失败返回 null（不要抛异常）。 */
    fun capture(): Bitmap?

    /** 触发一次向上滚动；手势未能下发时返回 false。 */
    fun scroll(frameWidth: Int, frameHeight: Int): Boolean

    /** 阻塞等待指定毫秒。 */
    fun sleep(ms: Long)

    /** 释放底层资源。 */
    fun close() {}
}

/** 长截图进度回调，用于端上显示「正在拼接第 N 屏」。 */
data class LongScreenshotProgress(
    val frames: Int,
    val scrolls: Int,
    val height: Int,
)

/** 长截图执行结果（位图级）。 */
data class LongScreenshotOutput(
    val bitmap: Bitmap?,
    val width: Int,
    val height: Int,
    val frames: Int,
    val scrolls: Int,
    val stop: LongScreenshotStop,
    val elapsedMs: Long,
    val note: String? = null,
) {
    companion object {
        @JvmStatic
        fun failed(note: String?, elapsedMs: Long = 0L): LongScreenshotOutput = LongScreenshotOutput(
            bitmap = null, width = 0, height = 0, frames = 0, scrolls = 0,
            stop = LongScreenshotStop.CAPTURE_FAILED, elapsedMs = elapsedMs, note = note,
        )
    }
}

/**
 * 长截图执行器。
 *
 * 流程：抓首帧 → 循环「滚动 → 等稳定 → 抓帧 → 求重叠 → 拼入」→ 按终止原因收尾。
 *
 * 四个终止条件是刻意分开的，因为它们对用户意味着不同的事：
 * - 滚到底（[LongScreenshotStop.REACHED_END]）：完整长图，可直接交付；
 * - 找不到重叠（[LongScreenshotStop.NO_OVERLAP]）：页面整屏换了内容（如跳转/刷新），
 *   此时**停止拼接并保留已拼部分**，因为继续拼必然错位；
 * - 撞高度上限（[LongScreenshotStop.MAX_HEIGHT]）：图被截断，需提示「已截取前 N 屏」；
 * - 手势无效（[LongScreenshotStop.NO_PROGRESS]）：页面本来就不能滚，等价于单屏截图。
 */
object LongScreenshotRunner {

    private const val POLL_MS = 120L
    private const val MAX_CAPTURE_FAILURES = 3

    /**
     * 执行一次长截图。
     *
     * @param source 取像原语；本方法不负责 close，调用方用 `use` 语义自行释放
     * @param options 参数（内部会做一次 [LongScreenshotOptions.clamped]）
     * @param onProgress 每拼入一帧回调一次
     * @param isCancelled 取消检查，命中后返回已拼部分并标记 [LongScreenshotStop.CANCELLED]
     */
    @JvmStatic
    fun run(
        source: ScreenFrameSource,
        options: LongScreenshotOptions = LongScreenshotOptions(),
        onProgress: ((LongScreenshotProgress) -> Unit)? = null,
        isCancelled: () -> Boolean = { false },
    ): LongScreenshotOutput {
        val startedAt = SystemClock.uptimeMillis()
        val opts = options.clamped()

        val first = source.capture()
            ?: return LongScreenshotOutput.failed("首帧抓取失败", SystemClock.uptimeMillis() - startedAt)

        val width = first.width
        val frameHeight = first.height
        val bottomInset = opts.bottomInsetOf(frameHeight)
        val stitcher = LongScreenshotStitcher(width, opts.maxHeightPx)
        // 首帧保留顶部固定区（状态栏/标题栏只出现一次），但去掉底部固定栏
        stitcher.append(first, 0, frameHeight - bottomInset)
        // 只有一屏时没有「后续帧」来补底部固定栏，先留一条窄切片，收尾时贴回去
        var bottomStrip = if (bottomInset > 0 && frameHeight - bottomInset > 0) {
            runCatching { Bitmap.createBitmap(first, 0, frameHeight - bottomInset, width, bottomInset) }.getOrNull()
        } else {
            null
        }
        var previousSignature = RowSignature.of(first)
        first.recycle()

        var frames = 1
        var scrolls = 0
        var stop: LongScreenshotStop? = null
        var note: String? = null
        // 是否已经因为「布局变化」重启过。真机上这只发生一次：第一次滚动时大标题收起，
        // 之后所有帧的内容原点都稳定在吸顶态。
        var restarted = false

        while (stop == null) {
            if (isCancelled()) {
                stop = LongScreenshotStop.CANCELLED
                break
            }
            if (scrolls >= opts.maxScrolls) {
                stop = LongScreenshotStop.MAX_SCROLLS
                break
            }
            if (!source.scroll(width, frameHeight)) {
                stop = LongScreenshotStop.NO_PROGRESS
                note = "滚动手势未能下发"
                break
            }
            scrolls++

            when (val settled = awaitChangedFrame(source, previousSignature, opts)) {
                Settle.Unchanged -> {
                    stop = LongScreenshotStop.REACHED_END
                }
                Settle.Failed -> {
                    stop = LongScreenshotStop.CAPTURE_FAILED
                    note = "滚动后连续抓帧失败"
                }
                is Settle.Changed -> {
                    val match = OverlapFinder.match(
                        prev = previousSignature,
                        next = settled.signature,
                        options = opts,
                        frameHeight = frameHeight,
                    )
                    if (!match.found) {
                        // 首帧与当前帧对不上，最常见的原因是「可折叠标题栏在第一次滚动时收起」：
                        // 大标题 + 搜索栏整体上移一两百像素，两帧不再是纯垂直平移关系。
                        // 此时以当前帧为新起点重启拼接，而不是把错位的内容硬拼进去。
                        if (!restarted && frames == 1) {
                            stitcher.reset()
                            stitcher.append(settled.bitmap, 0, frameHeight - bottomInset)
                            previousSignature = settled.signature
                            restarted = true
                            note = "布局在首次滚动后变化，已以稳定后的画面为新起点"
                            // 底栏切片也要换成新帧的，否则单屏收尾会贴回旧帧的底栏
                            if (bottomInset > 0) {
                                bottomStrip?.recycle()
                                bottomStrip = runCatching {
                                    Bitmap.createBitmap(
                                        settled.bitmap,
                                        0,
                                        frameHeight - bottomInset,
                                        width,
                                        bottomInset,
                                    )
                                }.getOrNull()
                            }
                            settled.bitmap.recycle()
                            continue
                        }
                        settled.bitmap.recycle()
                        stop = LongScreenshotStop.NO_OVERLAP
                        note = "相邻两帧无可信重叠（页面可能发生跳转或刷新）"
                        break
                    }
                    if (!match.scrolled) {
                        settled.bitmap.recycle()
                        stop = LongScreenshotStop.REACHED_END
                        break
                    }
                    val appended = stitcher.append(
                        settled.bitmap,
                        match.skipRows,
                        frameHeight - bottomInset,
                    )
                    settled.bitmap.recycle()
                    frames++
                    previousSignature = settled.signature
                    onProgress?.invoke(LongScreenshotProgress(frames, scrolls, stitcher.height))
                    if (appended <= 0 || stitcher.truncated) {
                        stop = LongScreenshotStop.MAX_HEIGHT
                        note = "已达最大高度 ${opts.maxHeightPx}px"
                        break
                    }
                }
            }
        }

        val finalStop = stop ?: LongScreenshotStop.SINGLE_SCREEN
        // 只拼到一屏时，把首帧被剔掉的底部固定栏补回去，避免「单屏截图少了导航条」
        if (frames == 1 && bottomStrip != null) {
            runCatching { stitcher.append(bottomStrip, 0, bottomStrip.height) }
        }
        bottomStrip?.recycle()
        if (stitcher.height <= 0) {
            stitcher.close()
            return LongScreenshotOutput.failed(note ?: "未产生有效像素", SystemClock.uptimeMillis() - startedAt)
        }
        val bitmap = stitcher.finish()
        return LongScreenshotOutput(
            bitmap = bitmap,
            width = width,
            height = bitmap?.height ?: 0,
            frames = frames,
            scrolls = scrolls,
            stop = if (frames == 1 && finalStop == LongScreenshotStop.NO_PROGRESS) {
                LongScreenshotStop.SINGLE_SCREEN
            } else {
                finalStop
            },
            elapsedMs = SystemClock.uptimeMillis() - startedAt,
            note = note,
        )
    }

    /**
     * 等待画面相对上一帧发生变化，最多等 [LongScreenshotOptions.maxSettleMs]。
     */
    /**
     * 等到「画面已经变了，并且稳定下来」再交付。
     *
     * 分两段是必要的：真机上 `input swipe` 之后列表会因为惯性继续滑，随后又有一次
     * overscroll 回弹，如果只等一个固定时长后抓帧，很可能抓到回弹途中的位置——
     * 实测就出现过「滚动后新帧比上一帧内容还靠下」的反向位移。因此这里在检测到变化后
     * 继续轮询，直到连续两帧互相相似（稳定）才返回最后那一帧。
     */
    private fun awaitChangedFrame(
        source: ScreenFrameSource,
        previous: FrameSignature,
        options: LongScreenshotOptions,
    ): Settle {
        val deadline = SystemClock.uptimeMillis() + options.maxSettleMs
        var failures = 0
        var first = true
        // 阶段一：等到画面与上一帧不同
        var changed: Settle.Changed? = null
        while (changed == null) {
            source.sleep(if (first) options.settleMs else POLL_MS)
            first = false
            val bitmap = source.capture()
            if (bitmap == null) {
                if (++failures >= MAX_CAPTURE_FAILURES) return Settle.Failed
                if (SystemClock.uptimeMillis() >= deadline) return Settle.Failed
                continue
            }
            val signature = RowSignature.of(bitmap)
            if (signature.similarTo(previous)) {
                bitmap.recycle()
                if (SystemClock.uptimeMillis() >= deadline) return Settle.Unchanged
            } else {
                changed = Settle.Changed(bitmap, signature)
            }
        }

        // 阶段二：等到画面稳定（连续两帧相似），最多再等一个 maxSettleMs
        val settleDeadline = SystemClock.uptimeMillis() + options.maxSettleMs
        var stable: Settle.Changed = changed ?: return Settle.Failed
        while (SystemClock.uptimeMillis() < settleDeadline) {
            source.sleep(POLL_MS)
            val bitmap = source.capture() ?: break
            val signature = RowSignature.of(bitmap)
            if (signature.similarTo(stable.signature)) {
                // 新抓的这一帧与上一帧一致：说明停下来了，用它作为最终帧更准
                stable.bitmap.recycle()
                stable = Settle.Changed(bitmap, signature)
                break
            }
            stable.bitmap.recycle()
            stable = Settle.Changed(bitmap, signature)
        }
        return stable
    }

    private sealed interface Settle {
        class Changed(val bitmap: Bitmap, val signature: FrameSignature) : Settle
        data object Unchanged : Settle
        data object Failed : Settle
    }
}
