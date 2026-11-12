package com.agent.use.a11y

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.GestureDescription
import android.graphics.Path
import android.util.Log
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume

/**
 * 屏幕无障碍手势分发器。
 *
 * 核心特性：
 * 1. 协程挂起 API：消除异步回调嵌套，以同步编写手势调用并获取最终完成状态；
 * 2. 屏幕定向分发：通过 GestureDescription.Builder.setDisplayId 精准向指定虚拟屏注入输入；
 * 3. 丰富手势原语：支持精准单击、连击、长按、直线滑动与任意平滑轨迹手势。
 */
class DisplayGestureDispatcher(
    private val serviceProvider: () -> AgentAccessibilityService? = { AgentAccessibilityService.instance.value }
) {

    /**
     * 底层手势挂起分发
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

        return suspendCancellableCoroutine { cont ->
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
    }

    /**
     * 在指定屏幕坐标执行单点点击
     */
    suspend fun tap(displayId: Int, x: Float, y: Float, durationMs: Long = 50L): Boolean {
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

        val path = Path().apply {
            moveTo(points[0].first, points[0].second)
            for (i in 1 until points.size) {
                lineTo(points[i].first, points[i].second)
            }
        }
        val stroke = GestureDescription.StrokeDescription(path, 0, durationMs.coerceAtLeast(1L))
        return dispatch(displayId, listOf(stroke))
    }

    companion object {
        private const val TAG = "DisplayGestureDispatcher"
    }
}
