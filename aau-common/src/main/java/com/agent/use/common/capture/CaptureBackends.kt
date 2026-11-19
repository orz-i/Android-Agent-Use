package com.agent.use.common.capture

import android.graphics.Bitmap
import com.agent.use.common.IAgentShell
import com.agent.use.common.api.AgentVirtualDisplay

/**
 * 虚拟屏直读通道：从 [AgentVirtualDisplay] 的 ImageReader 缓冲取最后一帧。
 *
 * 成本最低（无进程调用、无跨进程），但有两个前提：屏幕必须是自己创建的虚拟屏，
 * 且画面必须还在流动（息屏或长时间无重绘时，最后一帧可能已经过时）。
 */
class VirtualDisplayBackend(
    private val display: AgentVirtualDisplay,
) : ScreenCaptureBackend {

    override val mode: ScreenCaptureMode = ScreenCaptureMode.VIRTUAL_DISPLAY

    override fun isAvailable(): Boolean = true

    override fun capture(displayId: Int): Bitmap? = display.latestBitmap()
}

/**
 * 特权通道：经 Binder 让服务端以 Shell / Root 身份 `screencap`。
 *
 * 这是 AAU 里唯一能「免授权抓主屏」的通道，也是 [ScreenCaptureChannel] 的默认主力。
 * 服务端内部会在抓到纯黑帧时自动升级到 [ScreenCaptureMode.SECURE_PRIVILEGED]
 * （Android 17 的 secure 内容策略通道），因此 FLAG_SECURE 页面同样能出图，
 * 客户端不需要为此单独换一条 backend。
 */
class ShellCaptureBackend(
    private val shell: IAgentShell,
    private val timeoutMs: Int = 5_000,
) : ScreenCaptureBackend {

    override val mode: ScreenCaptureMode = ScreenCaptureMode.SHELL_PRIVILEGED

    /** 能力探测会真实抓一帧，缓存一次即可，避免每次截图前多跑 300ms。 */
    private val capability: ScreenCaptureCapability by lazy { PrivilegedCapture.capability(shell) }

    override fun isAvailable(): Boolean =
        capability.screencapAvailable || capability.rootAvailable || capability.secureCaptureAvailable

    override fun capture(displayId: Int): Bitmap? =
        PrivilegedCapture.captureBitmap(shell, displayId, timeoutMs)

    override fun captureLong(displayId: Int, options: LongScreenshotOptions): Bitmap? =
        PrivilegedCapture.captureLong(shell, displayId, options).bitmap
}
