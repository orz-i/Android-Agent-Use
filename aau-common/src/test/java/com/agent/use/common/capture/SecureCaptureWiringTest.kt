package com.agent.use.common.capture

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * 安全图层通道（[ScreenCaptureMode.SECURE_PRIVILEGED]）的接线测试。
 *
 * 只覆盖纯逻辑：wire 映射、能力快照的派生属性。
 * 真正的抓帧行为依赖 SurfaceFlinger 合成，只能在真机上验证
 * （见 `output/securecap/README.md` 的对照数据）。
 */
class SecureCaptureWiringTest {

    @Test
    fun `secure mode round trips through wire`() {
        assertEquals(
            ScreenCaptureMode.SECURE_PRIVILEGED,
            ScreenCaptureMode.fromWire(ScreenCaptureMode.SECURE_PRIVILEGED.wire),
        )
    }

    @Test
    fun `only secure mode claims to bypass the flag`() {
        assertTrue(ScreenCaptureMode.SECURE_PRIVILEGED.bypassesSecureFlag)
        assertFalse(ScreenCaptureMode.SHELL_PRIVILEGED.bypassesSecureFlag)
        assertFalse(ScreenCaptureMode.ROOT_PRIVILEGED.bypassesSecureFlag)
        assertFalse(ScreenCaptureMode.VIRTUAL_DISPLAY.bypassesSecureFlag)
        assertFalse(ScreenCaptureMode.ACCESSIBILITY.bypassesSecureFlag)
    }

    @Test
    fun `unknown wire value falls back to virtual display`() {
        assertEquals(ScreenCaptureMode.VIRTUAL_DISPLAY, ScreenCaptureMode.fromWire(99))
    }

    @Test
    fun `capability lists secure mode only when the device supports it`() {
        val withoutSecure = capability(secureCaptureAvailable = false)
        assertFalse(ScreenCaptureMode.SECURE_PRIVILEGED in withoutSecure.privilegedModes)

        val withSecure = capability(secureCaptureAvailable = true)
        assertTrue(ScreenCaptureMode.SECURE_PRIVILEGED in withSecure.privilegedModes)
    }

    @Test
    fun `secure channel alone still counts as permission free`() {
        // Android 17 上 screencap 被 OEM 拦掉、只剩 secure 通道时，依然算「免授权可用」
        val onlySecure = capability(screencapAvailable = false, secureCaptureAvailable = true)
        assertTrue(onlySecure.canCaptureWithoutPermission)
        // 但覆盖不全：普通页面仍抓不到
        assertFalse(onlySecure.canCaptureAnyContent)
    }

    @Test
    fun `both channels are required for full coverage`() {
        val full = capability(screencapAvailable = true, secureCaptureAvailable = true)
        assertTrue(full.canCaptureAnyContent)
        assertTrue(full.privilegedModesContainBoth())
    }

    private fun ScreenCaptureCapability.privilegedModesContainBoth(): Boolean =
        ScreenCaptureMode.SHELL_PRIVILEGED in privilegedModes &&
            ScreenCaptureMode.SECURE_PRIVILEGED in privilegedModes

    private fun capability(
        screencapAvailable: Boolean = true,
        secureCaptureAvailable: Boolean = false,
    ) = ScreenCaptureCapability(
        uid = 2000,
        screencapPath = "/system/bin/screencap",
        screencapAvailable = screencapAvailable,
        rootAvailable = false,
        supportsDisplayArg = true,
        supportsDisplaySwipe = true,
        secureCaptureAvailable = secureCaptureAvailable,
    )
}
