package com.agent.use.common.capture

import android.os.Parcel
import android.os.Parcelable

/**
 * 长截图（滚动拼接）参数契约。
 *
 * 设计取舍：AAU 不用系统 `ScrollCapture`（那是应用自己响应 `AssistStructure` 的主动行为，
 * 第三方无法触发），也不依赖 OEM 私有长截屏接口，而是「滚动 → 抓帧 → 按重叠行缝合」，
 * 因此所有影响拼接质量的旋钮都必须可调：滚动比例决定帧间重叠度，稳定等待决定会不会抓到惯性动画中间态。
 *
 * @property maxScrolls 最多滚动次数，超过即停（防止无限列表把内存吃穿）
 * @property maxHeightPx 输出图最大高度，触碰后截断并返回 [LongScreenshotStop.MAX_HEIGHT]
 * @property minOverlapPx 判定「两帧连续」所需的最小重叠行数，太小会把重复内容当重叠
 * @property minNewRowsPx 每帧至少要带来的新行数，低于该值视为已经到底
 * @property settleMs 滚动后首次等待时长
 * @property maxSettleMs 等待画面稳定的上限，超时取最后一帧
 * @property scrollFromRatio 滑动起点（占屏高比例）
 * @property scrollToRatio 滑动终点（占屏高比例），两者之差决定单次滚动量
 * @property scrollDurationMs 单次滑动时长，过短会触发惯性回弹
 * @property topInsetRatio 顶部固定区（状态栏/标题栏）占屏高比例，不参与匹配、只拼一次
 * @property bottomInsetRatio 底部固定区（输入框/导航栏）占屏高比例，不参与匹配也不拼入
 * @property privilege 特权级策略，见 [ScreenCapturePrivilege]
 */
data class LongScreenshotOptions(
    val maxScrolls: Int = DEFAULT_MAX_SCROLLS,
    val maxHeightPx: Int = DEFAULT_MAX_HEIGHT_PX,
    val minOverlapPx: Int = DEFAULT_MIN_OVERLAP_PX,
    val minNewRowsPx: Int = DEFAULT_MIN_NEW_ROWS_PX,
    val settleMs: Long = DEFAULT_SETTLE_MS,
    val maxSettleMs: Long = DEFAULT_MAX_SETTLE_MS,
    val scrollFromRatio: Float = DEFAULT_SCROLL_FROM_RATIO,
    val scrollToRatio: Float = DEFAULT_SCROLL_TO_RATIO,
    val scrollDurationMs: Long = DEFAULT_SCROLL_DURATION_MS,
    val topInsetRatio: Float = 0f,
    val bottomInsetRatio: Float = 0f,
    val privilege: Int = ScreenCapturePrivilege.AUTO,
) : Parcelable {

    constructor(parcel: Parcel) : this(
        maxScrolls = parcel.readInt(),
        maxHeightPx = parcel.readInt(),
        minOverlapPx = parcel.readInt(),
        minNewRowsPx = parcel.readInt(),
        settleMs = parcel.readLong(),
        maxSettleMs = parcel.readLong(),
        scrollFromRatio = parcel.readFloat(),
        scrollToRatio = parcel.readFloat(),
        scrollDurationMs = parcel.readLong(),
        topInsetRatio = parcel.readFloat(),
        bottomInsetRatio = parcel.readFloat(),
        privilege = parcel.readInt(),
    )

    override fun writeToParcel(parcel: Parcel, flags: Int) {
        parcel.writeInt(maxScrolls)
        parcel.writeInt(maxHeightPx)
        parcel.writeInt(minOverlapPx)
        parcel.writeInt(minNewRowsPx)
        parcel.writeLong(settleMs)
        parcel.writeLong(maxSettleMs)
        parcel.writeFloat(scrollFromRatio)
        parcel.writeFloat(scrollToRatio)
        parcel.writeLong(scrollDurationMs)
        parcel.writeFloat(topInsetRatio)
        parcel.writeFloat(bottomInsetRatio)
        parcel.writeInt(privilege)
    }

    override fun describeContents(): Int = 0

    /** 顶部固定区的像素高度。 */
    fun topInsetOf(height: Int): Int = (height * topInsetRatio).toInt().coerceIn(0, height / 4)

    /** 底部固定区的像素高度。 */
    fun bottomInsetOf(height: Int): Int = (height * bottomInsetRatio).toInt().coerceIn(0, height / 4)

    /**
     * 把外部传入的参数收拢到安全区间。
     *
     * 服务端一定会在执行前调用一次：这些数值直接决定内存分配（[maxHeightPx]）与
     * 进程内循环次数（[maxScrolls]），不能被调用方单方面放大。
     */
    fun clamped(): LongScreenshotOptions {
        val safeSettle = settleMs.coerceIn(0L, MAX_SETTLE_BOUND_MS)
        val safeFrom = scrollFromRatio.coerceIn(0.30f, 0.95f)
        val safeTo = scrollToRatio.coerceIn(0.05f, 0.70f)
        return copy(
            maxScrolls = maxScrolls.coerceIn(1, MAX_SCROLLS_BOUND),
            maxHeightPx = maxHeightPx.coerceIn(MIN_HEIGHT_BOUND_PX, MAX_HEIGHT_BOUND_PX),
            minOverlapPx = minOverlapPx.coerceIn(MIN_OVERLAP_BOUND_PX, MAX_OVERLAP_BOUND_PX),
            minNewRowsPx = minNewRowsPx.coerceIn(MIN_NEW_ROWS_BOUND_PX, MAX_NEW_ROWS_BOUND_PX),
            settleMs = safeSettle,
            maxSettleMs = maxSettleMs.coerceIn(safeSettle, MAX_SETTLE_BOUND_MS),
            scrollFromRatio = safeFrom,
            // 终点必须留在起点上方，否则等于没滚
            scrollToRatio = safeTo.coerceAtMost(safeFrom - MIN_SCROLL_GAP_RATIO),
            scrollDurationMs = scrollDurationMs.coerceIn(MIN_SCROLL_DURATION_MS, MAX_SCROLL_DURATION_MS),
            topInsetRatio = topInsetRatio.coerceIn(0f, MAX_INSET_RATIO),
            bottomInsetRatio = bottomInsetRatio.coerceIn(0f, MAX_INSET_RATIO),
            privilege = privilege.coerceIn(ScreenCapturePrivilege.AUTO, ScreenCapturePrivilege.ROOT_ONLY),
        )
    }

    /** 单次滚动距离（像素）。 */
    fun scrollDistanceOf(height: Int): Int = (height * (scrollFromRatio - scrollToRatio)).toInt().coerceAtLeast(1)

    companion object CREATOR : Parcelable.Creator<LongScreenshotOptions> {
        const val DEFAULT_MAX_SCROLLS = 12
        const val DEFAULT_MAX_HEIGHT_PX = 12_000
        const val DEFAULT_MIN_OVERLAP_PX = 48
        const val DEFAULT_MIN_NEW_ROWS_PX = 32
        const val DEFAULT_SETTLE_MS = 320L
        const val DEFAULT_MAX_SETTLE_MS = 1_600L
        // 单次滚动约 30% 屏高。真机实测 `input swipe` 的 fling 惯性会把实际位移推到
        // 手势距离的 1.5~1.8 倍（1275px 的手势滚了 2273px），重叠只剩 156 行时锚点投票必然失效。
        // 缩到 832px 后即使翻倍也有千行以上重叠。
        const val DEFAULT_SCROLL_FROM_RATIO = 0.72f
        const val DEFAULT_SCROLL_TO_RATIO = 0.42f
        // 手势放慢到 900ms：速度降到 ~900px/s，fling 显著减弱，「滚完即停」
        const val DEFAULT_SCROLL_DURATION_MS = 900L

        const val MAX_SCROLLS_BOUND = 40
        const val MIN_HEIGHT_BOUND_PX = 1_000
        const val MAX_HEIGHT_BOUND_PX = 40_000
        const val MIN_OVERLAP_BOUND_PX = 16
        const val MAX_OVERLAP_BOUND_PX = 2_000
        const val MIN_NEW_ROWS_BOUND_PX = 8
        const val MAX_NEW_ROWS_BOUND_PX = 4_000
        const val MAX_SETTLE_BOUND_MS = 8_000L
        const val MIN_SCROLL_DURATION_MS = 50L
        const val MAX_SCROLL_DURATION_MS = 2_000L
        const val MAX_INSET_RATIO = 0.30f
        const val MIN_SCROLL_GAP_RATIO = 0.10f

        override fun createFromParcel(parcel: Parcel): LongScreenshotOptions = LongScreenshotOptions(parcel)
        override fun newArray(size: Int): Array<LongScreenshotOptions?> = arrayOfNulls(size)

        /** 通用网页/信息流默认参数。 */
        @JvmStatic
        fun standard(): LongScreenshotOptions = LongScreenshotOptions()

        /** 聊天记录类：滚动量小、帧数多、允许更高输出。 */
        @JvmStatic
        fun chat(): LongScreenshotOptions = LongScreenshotOptions(
            maxScrolls = 20,
            maxHeightPx = 20_000,
            scrollFromRatio = 0.70f,
            scrollToRatio = 0.40f,
            settleMs = 220L,
        )

        /** 带顶部固定标题栏的页面：把顶部 8% 排除在拼接之外。 */
        @JvmStatic
        fun withStickyHeader(): LongScreenshotOptions = LongScreenshotOptions(
            topInsetRatio = 0.08f,
            bottomInsetRatio = 0.04f,
        )

        /**
         * 无障碍通道专用：`takeScreenshot` 有 1 秒系统冷却，
         * 把稳定等待放到 1.1 秒可以避免「等 300ms → 撞冷却 → 再等 1 秒」的双倍开销。
         */
        @JvmStatic
        fun accessibility(): LongScreenshotOptions = LongScreenshotOptions(
            maxScrolls = 8,
            maxHeightPx = 10_000,
            settleMs = 1_100L,
            maxSettleMs = 2_400L,
            scrollDurationMs = 320L,
        )
    }
}
