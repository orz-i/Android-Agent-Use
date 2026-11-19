package com.agent.use.common.capture

import android.graphics.Bitmap
import android.graphics.ColorSpace
import android.hardware.HardwareBuffer
import android.os.Build
import android.os.IBinder
import android.util.Log
import java.lang.reflect.Method

/**
 * Android 14~16 的 secure 抓取分支（旧版 `SurfaceControl` API）。
 *
 * 与 Android 17 的差别：
 * - 17 走 `android.window.ScreenCapture.capture()` + 显式 `SECURE_CONTENT_POLICY_*` 策略；
 * - 14~16 走 `SurfaceControl.captureDisplay(ScreenCaptureArgs)`，开关是
 *   `ScreenCaptureArgs.Builder.setCaptureSecureLayers(true)`，同步返回 `ScreenshotHardwareBuffer`。
 *
 * **本分支未在真机验证。** 手头只有 Android 17 设备，而
 * `SurfaceControl.ScreenCaptureArgs` 在公开 SDK 里连符号都没有（hidden API），
 * 只能按 AOSP 源码的形状反射调用。因此这里所有调用都做了容错：
 * 任何一步对不上就返回 null，由上层退化成「抓不到」，不会崩溃、也不会拖慢主路径。
 *
 * 将来拿到 14~16 设备时，先用 `CaptureSelfCheck <dir> SECURE` 跑一次；
 * 如果返回 null，把 `Log.w` 里的失败点对一遍 AOSP 源码即可 —— 探测顺序是按
 * 「最可能先失败的环节」排的，日志会直接指出断在哪。
 */
internal object LegacySecureCapture {

    /** 旧版 API 的起始版本：`ScreenCaptureArgs` 与 `captureSecureLayers` 是 Android 14 引入的。 */
    const val MIN_API = 34

    private const val TAG = "LegacySecureCapture"

    @Volatile
    private var probed = false

    @Volatile
    private var supportReason: String? = null

    fun isSupported(): Boolean {
        if (Build.VERSION.SDK_INT < MIN_API) return false
        if (probed) return supportReason == null
        probed = true
        supportReason = try {
            Class.forName(CLS_SURFACE_CONTROL)
                .getMethod("getInternalDisplayToken")
            Class.forName(CLS_ARGS)
            Class.forName(CLS_BUILDER)
            null
        } catch (t: Throwable) {
            "旧版 ScreenCaptureArgs 不可用：${t.javaClass.simpleName}: ${t.message}"
        }
        supportReason?.let { Log.i(TAG, it) }
        return supportReason == null
    }

    /**
     * 抓主屏一帧。旧版 API 只实现了主屏：非主屏需要
     * `getPhysicalDisplayToken(long)`，那套 id 换算在 14~16 上又和 17 不同，没有设备无法验证，
     * 与其猜一个可能抓错屏的实现，不如明确不支持。
     */
    fun capture(displayId: Int, timeoutMs: Long): Bitmap? {
        if (!isSupported()) return null
        if (displayId != 0) {
            Log.w(TAG, "旧版通道只支持主屏，displayId=$displayId 跳过")
            return null
        }
        return try {
            val token = displayToken() ?: return null
            val args = buildArgs(token) ?: return null
            val result = invokeCapture(args) ?: return null
            toBitmap(result)
        } catch (t: Throwable) {
            Log.w(TAG, "旧版通道抓帧失败：${t.javaClass.simpleName}: ${t.message}")
            null
        }
    }

    private fun displayToken(): IBinder? {
        val token = Class.forName(CLS_SURFACE_CONTROL)
            .getMethod("getInternalDisplayToken")
            .invoke(null) as? IBinder
        if (token == null) Log.w(TAG, "getInternalDisplayToken 返回 null")
        return token
    }

    private fun buildArgs(token: IBinder): Any? {
        val builderClass = Class.forName(CLS_BUILDER)
        // 构造签名在不同 minor 版本上有过 (IBinder) 与 (IBinder, Rect) 两种，按参数个数挑
        val ctor = builderClass.declaredConstructors
            .firstOrNull { it.parameterCount >= 1 && it.parameterTypes[0] == IBinder::class.java }
            ?: run {
                Log.w(TAG, "找不到 ScreenCaptureArgs.Builder(IBinder) 构造器")
                return null
            }
        ctor.isAccessible = true
        val builder = ctor.newInstance(token)

        val setSecure = builderClass.declaredMethods
            .firstOrNull { it.name == "setCaptureSecureLayers" && it.parameterCount == 1 }
            ?: run {
                Log.w(TAG, "找不到 setCaptureSecureLayers")
                return null
            }
        setSecure.isAccessible = true
        setSecure.invoke(builder, true)

        return builderClass.getMethod("build").invoke(builder)
    }

    private fun invokeCapture(args: Any): Any? {
        val method: Method = Class.forName(CLS_SURFACE_CONTROL)
            .declaredMethods
            .firstOrNull { it.name == "captureDisplay" && it.parameterCount == 1 }
            ?: run {
                Log.w(TAG, "找不到 SurfaceControl.captureDisplay(ScreenCaptureArgs)")
                return null
            }
        method.isAccessible = true
        return method.invoke(null, args)
    }

    private fun toBitmap(result: Any): Bitmap? {
        val buffer = runCatching { result.javaClass.getMethod("getHardwareBuffer").invoke(result) }
            .getOrNull() as? HardwareBuffer ?: return null
        val colorSpace = runCatching { result.javaClass.getMethod("getColorSpace").invoke(result) }
            .getOrNull() as? ColorSpace
        var wrapped: Bitmap? = null
        return try {
            wrapped = Bitmap.wrapHardwareBuffer(buffer, colorSpace) ?: return null
            wrapped.copy(Bitmap.Config.ARGB_8888, false)
        } catch (t: Throwable) {
            Log.w(TAG, "转换位图失败：${t.message}")
            null
        } finally {
            runCatching { wrapped?.recycle() }
            runCatching { buffer.close() }
        }
    }

    private const val CLS_SURFACE_CONTROL = "android.view.SurfaceControl"
    private const val CLS_ARGS = "android.view.SurfaceControl\$ScreenCaptureArgs"
    private const val CLS_BUILDER = "android.view.SurfaceControl\$ScreenCaptureArgs\$Builder"
}
