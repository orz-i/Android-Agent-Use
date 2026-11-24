package com.agent.use.a11y

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.GestureDescription
import android.graphics.Path
import android.graphics.PathMeasure
import android.util.Log
import android.view.Display
import com.agent.use.common.input.EvdevTouch
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlin.coroutines.resume
import kotlin.math.roundToInt

/**
 * 屏幕无障碍手势分发器。
 *
 * 核心特性：
 * 1. 协程挂起 API：消除异步回调嵌套，以同步编写手势调用并获取最终完成状态；
 * 2. 屏幕定向分发：通过 GestureDescription.Builder.setDisplayId 精准向指定虚拟屏注入输入；
 * 3. 丰富手势原语：支持精准单击、连击、长按、直线滑动与任意平滑轨迹手势；
 * 4. 主屏优先走内核注入：见下。
 *
 * ## 为什么主屏要换通道
 *
 * `dispatchGesture` 的事件由 `AccessibilityManagerService$MotionEventInjector` 用
 * `MotionEvent.obtain(downTime, when, action, x, y, 0)` 构造，注入到目标应用时
 * `deviceId = 0`、`toolType = TOOL_TYPE_UNKNOWN(0)`、`eventId = -1`。这三个字段与真手指
 * 完全不同源，任何反自动化检测只要读一次 `MotionEvent` 就能分辨。
 *
 * 主屏（[Display.DEFAULT_DISPLAY]）因此优先交给 [EvdevTouch]：事件直接写 `/dev/input/eventN`，
 * 内核派发、InputReader 推导，`toolType = TOOL_TYPE_FINGER`、`deviceId` 是真实输入设备、`eventId` 每帧递增。
 * 路径仍按调用方给的形状与时长走（系统手势本来就是沿路径匀速，这里用同样的时间轴采样），
 * 只是换了注入通道，观感与原来一致。
 *
 * 虚拟屏没有对应的 evdev 节点，多指手势也无法用单点注入表达，这两种情况照旧走 `dispatchGesture`。
 */
class DisplayGestureDispatcher(
    private val serviceProvider: () -> AgentAccessibilityService? = { AgentAccessibilityService.instance.value },
    private val kernelTouchProvider: (android.content.Context) -> EvdevTouch? = { EvdevTouch.get(it) },
) {

    /**
     * 底层手势挂起分发（系统通道，多指与虚拟屏用）
     */
    suspend fun dispatch(displayId: Int, strokes: List<GestureDescription.StrokeDescription>): Boolean {
        val service = serviceProvider() ?: run {
            Log.w(TAG, "Cannot dispatch gesture: AgentAccessibilityService is not connected.")
            return false
        }

        if (strokes.isEmpty()) return true

        val builder = GestureDescription.Builder()
        builder.setDisplayId(displayId)
        for (stroke in strokes) {
            builder.addStroke(stroke)
        }
        val gesture = builder.build()

        suspend fun send(): Boolean = suspendCancellableCoroutine { cont ->
            val callback = object : AccessibilityService.GestureResultCallback() {
                override fun onCompleted(gestureDescription: GestureDescription) {
                    if (cont.isActive) cont.resume(true)
                }

                override fun onCancelled(gestureDescription: GestureDescription) {
                    if (cont.isActive) cont.resume(false)
                }
            }
            val dispatched = service.dispatchGesture(gesture, callback, null)
            if (!dispatched && cont.isActive) {
                cont.resume(false)
            }
        }
        return service.passInjectedGestureThrough { send() }
    }

    /**
     * 沿着单个 Path 执行单指手势
     */
    suspend fun gesture(displayId: Int, path: Path, durationMs: Long): Boolean {
        val points = pathPoints(path)
        if (points != null) {
            kernelStroke(displayId, points, durationMs)?.let { return it }
        }
        val stroke = GestureDescription.StrokeDescription(path, 0, durationMs.coerceAtLeast(1L))
        return dispatch(displayId, listOf(stroke))
    }

    /**
     * 沿着多个 Path 并行执行多指手势（只有系统通道能表达多指）
     */
    suspend fun gesture(displayId: Int, paths: List<Path>, durationMs: Long): Boolean =
        dispatch(displayId, paths.map { GestureDescription.StrokeDescription(it, 0, durationMs.coerceAtLeast(1L)) })

    /**
     * 在指定屏幕坐标执行单点点击
     */
    suspend fun tap(displayId: Int, x: Float, y: Float, durationMs: Long = 50L): Boolean {
        kernelTap(displayId, x, y, durationMs)?.let { return it }
        val path = Path().apply { moveTo(x, y) }
        val stroke = GestureDescription.StrokeDescription(path, 0, durationMs.coerceAtLeast(1L))
        return dispatch(displayId, listOf(stroke))
    }

    /**
     * 在同一点执行多次连续点击（如双击）
     */
    suspend fun taps(
        displayId: Int,
        x: Float,
        y: Float,
        count: Int = 2,
        holdMs: Long = 50L,
        gapMs: Long = 100L
    ): Boolean {
        if (count <= 1) return tap(displayId, x, y, holdMs)
        kernelMultiTap(displayId, x, y, count, holdMs, gapMs)?.let { return it }
        val path = Path().apply { moveTo(x, y) }
        val strokes = (0 until count).map { i ->
            val startTime = i * (holdMs + gapMs)
            GestureDescription.StrokeDescription(path, startTime, holdMs.coerceAtLeast(1L))
        }
        return dispatch(displayId, strokes)
    }

    /**
     * 在指定屏幕坐标执行长按
     */
    suspend fun longPress(displayId: Int, x: Float, y: Float, durationMs: Long = 600L): Boolean {
        return tap(displayId, x, y, durationMs)
    }

    /**
     * 在指定屏幕上执行滑动（如向上滑动、翻页）
     */
    suspend fun swipe(
        displayId: Int,
        startX: Float,
        startY: Float,
        endX: Float,
        endY: Float,
        durationMs: Long = 300L
    ): Boolean {
        val points = listOf(startX to startY, endX to endY)
        kernelStroke(displayId, points, durationMs)?.let { return it }
        val path = Path().apply {
            moveTo(startX, startY)
            lineTo(endX, endY)
        }
        val stroke = GestureDescription.StrokeDescription(path, 0, durationMs.coerceAtLeast(1L))
        return dispatch(displayId, listOf(stroke))
    }

    /**
     * 沿着多点轨迹平滑分发连续手势
     */
    suspend fun smoothStroke(
        displayId: Int,
        points: List<Pair<Float, Float>>,
        durationMs: Long = 400L
    ): Boolean {
        if (points.isEmpty()) return false
        if (points.size == 1) return tap(displayId, points[0].first, points[0].second)

        kernelStroke(displayId, points, durationMs)?.let { return it }
        val path = Path().apply {
            moveTo(points[0].first, points[0].second)
            for (i in 1 until points.size) {
                lineTo(points[i].first, points[i].second)
            }
        }
        val stroke = GestureDescription.StrokeDescription(path, 0, durationMs.coerceAtLeast(1L))
        return dispatch(displayId, listOf(stroke))
    }

    // ------------------------------------------------------------ 内核注入通道

    /** 返回 null 表示这条手势不归内核通道管（虚拟屏 / 未就绪），调用方走系统手势。 */
    private suspend fun kernelTap(displayId: Int, x: Float, y: Float, durationMs: Long): Boolean? {
        val touch = kernelTouch(displayId) ?: return null
        val hold = durationMs.coerceIn(1L, 5_000L)
        val ok = isolated {
            withContext(Dispatchers.IO) { touch.tap(x, y, hold) }
        }
        settle()
        return ok
    }

    private suspend fun kernelMultiTap(
        displayId: Int,
        x: Float,
        y: Float,
        count: Int,
        holdMs: Long,
        gapMs: Long
    ): Boolean? {
        val touch = kernelTouch(displayId) ?: return null
        val hold = holdMs.coerceIn(1L, 5_000L)
        return isolated {
            withContext(Dispatchers.IO) {
                for (i in 0 until count) {
                    if (i > 0) delay(gapMs.coerceAtLeast(0L))
                    // 每一击落点略有不同：既符合真人，也避开「同一坐标反复点击」的计数
                    val jx = if (i == 0) x else x + (i * 2 - 1)
                    val jy = if (i == 0) y else y + (1 - i)
                    if (!touch.tap(jx, jy, hold)) return@withContext false
                }
                true
            }
        }.also { settle() }
    }

    /** 折线按时间轴重采样后交给内核；形状与总时长不变。 */
    private suspend fun kernelStroke(
        displayId: Int,
        points: List<Pair<Float, Float>>,
        durationMs: Long
    ): Boolean? {
        if (points.size < 2) {
            return points.singleOrNull()?.let { kernelTap(displayId, it.first, it.second, durationMs) }
        }
        val touch = kernelTouch(displayId) ?: return null
        val duration = durationMs.coerceIn(MIN_STROKE_MS, MAX_STROKE_MS)
        val frames = (duration / FRAME_MS).toInt().coerceIn(2, MAX_FRAMES - 1)

        val xs = IntArray(frames + 1)
        val ys = IntArray(frames + 1)
        val ts = LongArray(frames + 1)

        val cumulative = DoubleArray(points.size)
        for (i in 1 until points.size) {
            val dx = (points[i].first - points[i - 1].first).toDouble()
            val dy = (points[i].second - points[i - 1].second).toDouble()
            cumulative[i] = cumulative[i - 1] + kotlin.math.sqrt(dx * dx + dy * dy)
        }
        val total = cumulative.last()
        var seg = 0
        for (f in 0..frames) {
            val tsMs = duration * f / frames
            ts[f] = tsMs
            if (total <= 0.0) {
                xs[f] = points[0].first.roundToInt()
                ys[f] = points[0].second.roundToInt()
                continue
            }
            val target = total * f / frames
            while (seg < points.size - 2 && cumulative[seg + 1] < target) seg++
            val segLen = cumulative[seg + 1] - cumulative[seg]
            val ratio = if (segLen <= 0.0) 0.0 else (target - cumulative[seg]) / segLen
            xs[f] = (points[seg].first + (points[seg + 1].first - points[seg].first) * ratio).roundToInt()
            ys[f] = (points[seg].second + (points[seg + 1].second - points[seg].second) * ratio).roundToInt()
        }

        val ok = isolated {
            withContext(Dispatchers.IO) { touch.stroke(xs, ys, ts) }
        }
        settle()
        return ok
    }

    private suspend fun kernelTouch(displayId: Int): EvdevTouch? {
        if (displayId != Display.DEFAULT_DISPLAY) return null
        val context = serviceProvider()?.applicationContext ?: return null
        return kernelTouchProvider(context)?.takeIf { it.isReady }
    }

    /** 浮层隔离：内核注入同样会打到 Mika 自己的浮层上，必须和系统手势走同一套遮挡。 */
    private suspend fun <T> isolated(block: suspend () -> T): T {
        val service = serviceProvider() ?: return block()
        return service.passInjectedGestureThrough { block() }
    }

    /** 抬起事件写入后给输入管线一点时间，避免调用方紧接着读界面时还是旧状态。 */
    private suspend fun settle() {
        delay(SETTLE_MS)
    }

    /** 把 Path 抽成折线；多轮廓或抽不出来时返回 null（交回系统手势）。 */
    private fun pathPoints(path: Path): List<Pair<Float, Float>>? {
        val measure = PathMeasure(path, false)
        val length = measure.length
        if (length <= 0f) {
            val pos = FloatArray(2)
            if (!measure.getPosTan(0f, pos, null)) return null
            return listOf(pos[0] to pos[1])
        }
        if (measure.nextContour()) return null
        val steps = (length / PATH_SAMPLE_PX).toInt().coerceIn(1, MAX_FRAMES - 1)
        val out = ArrayList<Pair<Float, Float>>(steps + 1)
        val pos = FloatArray(2)
        for (i in 0..steps) {
            if (!measure.getPosTan(length * i / steps, pos, null)) return null
            out += pos[0] to pos[1]
        }
        return out
    }

    companion object {
        private const val TAG = "DisplayGestureDispatcher"

        /** 轨迹按时间重采样的帧间隔。真手指的触摸采样也就 8–12ms 一帧。 */
        private const val FRAME_MS = 10L
        private const val MAX_FRAMES = 600
        private const val PATH_SAMPLE_PX = 6f
        private const val MIN_STROKE_MS = 16L
        private const val MAX_STROKE_MS = 10_000L
        private const val SETTLE_MS = 15L
    }
}
