package com.agent.use.common.capture

/**
 * 截屏通道类型。
 *
 * AAU 的取像能力按「权限代价从低到高、覆盖面从窄到宽」排列：
 * 1. [VIRTUAL_DISPLAY]：客户端 ImageReader 直读自己持有的虚拟屏，零权限、零延迟，但看不到主屏；
 * 2. [SHELL_PRIVILEGED]：服务端以 Shell (UID 2000) 身份调用 `screencap -d`，**免 MediaProjection 授权**，
 *    可抓任意 display（含主屏），是替代系统截屏的默认特权通道；
 * 3. [ROOT_PRIVILEGED]：在 Shell 通道被 OEM 策略拦截时，经 `su` 提权重试同一份 `screencap`，
 *    用于个别 ROM 把 `screencap` 限死在 UID 0 的场景；
 * 4. [ACCESSIBILITY]：`AccessibilityService.takeScreenshot` 兜底，只需用户手动开启无障碍，
 *    代价是 1 秒系统冷却且无法抓取安全图层；
 * 5. [SECURE_PRIVILEGED]：Android 17 起可用的 `ScreenCapture` 策略通道，显式声明
 *    `SECURE_CONTENT_POLICY_CAPTURE`，**能抓到 FLAG_SECURE 窗口的真实像素**。
 *    与 2/3 同权限级（UID 2000 即可，不需要 Root），但单次成本约 300~500ms，
 *    因此只在 `screencap` 判定为纯黑时才升级过来。
 *
 * 注意 5 与 2/3 不是替代关系而是互补：`screencap` 更快且对普通页面完全够用，
 * [SECURE_PRIVILEGED] 专治「页面声明了 FLAG_SECURE」这一种情况。
 */
enum class ScreenCaptureMode(val wire: Int, val label: String) {
    VIRTUAL_DISPLAY(0, "virtual-display"),
    SHELL_PRIVILEGED(1, "shell"),
    ROOT_PRIVILEGED(2, "root"),
    ACCESSIBILITY(3, "accessibility"),
    SECURE_PRIVILEGED(4, "secure");

    /** 该通道是否能在 `screencap` 返回黑帧之后挽救画面。 */
    val bypassesSecureFlag: Boolean get() = this == SECURE_PRIVILEGED

    companion object {
        @JvmStatic
        fun fromWire(wire: Int): ScreenCaptureMode =
            entries.firstOrNull { it.wire == wire } ?: VIRTUAL_DISPLAY
    }
}

/**
 * 特权级选择策略，用于 [LongScreenshotOptions.privilege]。
 *
 * - [AUTO]：先 Shell，失败再提权 Root（默认，绝大多数设备一次成功）；
 *   若抓到纯黑帧且本机支持 secure 通道，会自动升级到 [ScreenCaptureMode.SECURE_PRIVILEGED]；
 * - [SHELL_ONLY]：只走 Shell，不触碰 `su`，适合对 Root 有合规顾虑的宿主；
 * - [ROOT_ONLY]：强制经 `su` 执行，用于排查「Shell 通道被拦截」的对拍验证；
 * - [SECURE_ONLY]：强制只走 secure 通道，用于验证策略是否真的生效。
 */
object ScreenCapturePrivilege {
    const val AUTO = 0
    const val SHELL_ONLY = 1
    const val ROOT_ONLY = 2
    const val SECURE_ONLY = 3
}
