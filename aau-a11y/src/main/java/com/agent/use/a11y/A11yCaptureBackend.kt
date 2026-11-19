package com.agent.use.a11y

import android.graphics.Bitmap
import com.agent.use.common.capture.LongScreenshotOptions
import com.agent.use.common.capture.ScreenCaptureBackend
import com.agent.use.common.capture.ScreenCaptureMode
import kotlinx.coroutines.runBlocking

/**
 * 无障碍截屏通道（兜底）。
 *
 * 定位很明确：当设备既没有 Root、宿主也不便常驻 Shell 守护进程时，
 * 这是唯一还能用的取像手段。它只需要用户在系统设置里手动开启无障碍服务，
 * 不需要任何弹窗授权。
 *
 * 两个固有限制决定了它只能当兜底：
 * 1. `takeScreenshot` 有 **1 秒系统冷却**，长截图必然慢（每屏 ≥1s）；
 * 2. 命中 `FLAG_SECURE` 的页面直接返回错误码，拿不到黑图也拿不到内容。
 *
 * 本类把挂起的无障碍 API 适配成 [ScreenCaptureBackend] 的同步契约，
 * 因此可以直接塞进 `ScreenCaptureChannel` 与特权通道排在同一个优先级链上。
 */
class A11yCaptureBackend(
    /**
     * 调用方未显式指定参数时使用的默认值。
     *
     * 用「是否等于通用默认值」来判定「没指定」，是刻意的取舍：
     * [ScreenCaptureBackend.captureLong] 无法表达可空参数，
     * 而通道层用 `LongScreenshotOptions()` 当占位符；对无障碍通道来说，
     * 这个占位符必须换成带 1.1 秒稳定等待的版本，否则每帧都会撞冷却重试。
     */
    private val defaultOptions: LongScreenshotOptions = LongScreenshotOptions.accessibility(),
) : ScreenCaptureBackend {

    override val mode: ScreenCaptureMode = ScreenCaptureMode.ACCESSIBILITY

    override fun isAvailable(): Boolean = AgentAccessibilityService.isConnected

    override fun capture(displayId: Int): Bitmap? {
        val service = AgentAccessibilityService.instance.value ?: return null
        return runBlocking {
            (service.captureScreenshot(displayId) as? AgentAccessibilityService.ScreenshotOutcome.Ok)?.bitmap
        }
    }

    override fun captureLong(displayId: Int, options: LongScreenshotOptions): Bitmap? {
        val service = AgentAccessibilityService.instance.value ?: return null
        val effective = if (options == LongScreenshotOptions()) defaultOptions else options
        return runBlocking { service.captureLongScreenshot(displayId, effective).bitmap }
    }
}
