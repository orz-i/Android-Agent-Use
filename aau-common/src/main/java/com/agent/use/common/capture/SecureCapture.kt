package com.agent.use.common.capture

import android.graphics.Bitmap
import android.graphics.ColorSpace
import android.hardware.HardwareBuffer
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
import android.util.Log
import java.lang.reflect.Method
import java.lang.reflect.Proxy
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.TimeUnit

/**
 * Android 17 的「安全内容直取」通道。
 *
 * 背景：从 Android 12 起，`screencap` / `MediaProjection` / `AccessibilityService.takeScreenshot`
 * 对声明了 `FLAG_SECURE` 的窗口一律返回黑帧 —— secure 层在合成阶段就被排除出截屏输出，
 * 不是「打了码」，而是**根本没生成像素**。所以任何「先截再处理」的路子都不成立。
 *
 * Android 17 把这件事改成了显式策略：`android.window.ScreenCapture.capture()` 接受一个
 * [SecureContentPolicy]，取值 `CAPTURE / REDACT / THROW_EXCEPTION`。系统默认 REDACT，
 * 也就是上面那些黑帧；显式要求 CAPTURE 时，secure 层会被正常合成进结果。
 *
 * 实测（PLK110 / Android 17 / ColorOS）：
 * - `screencap -p` → 内容区纯黑，PNG 35441 字节，nonBlackRatio≈0.0035
 * - 本通道 + CAPTURE → 完整内容，PNG 148068 字节，nonBlackRatio≈0.95
 * - 本通道 + REDACT → 与系统 screencap **字节数完全相同**，证明默认行为就是 REDACT，
 *   而 CAPTURE 确实把内容放了出来
 * - UID 2000 与 UID 0 都能跑通，**不需要 Root**
 *
 * 三个实现上的硬约束（都是实测踩出来的，改动前先看清楚）：
 *
 * 1. **编译期不能引用**：`android.window.ScreenCapture` 是 API 37 的类，而本模块
 *    `compileSdk = 36`，因此整套调用全走反射。这同时保证了低版本设备上安全退化。
 * 2. **必须先注入 `sWindowManagerService`**：裸 `app_process` 进程里
 *    `ApplicationSharedMemory` 没有初始化，`capture()` 内部调
 *    `WindowManagerGlobal.getWindowManagerService()` 会抛
 *    `IllegalStateException: ApplicationSharedMemory not initialized`。
 *    把真 WMS 代理塞进那个私有静态字段即可绕开。
 * 3. **回调要靠 Looper 投递**：调用线程若阻塞等待且没有 Looper，进程会被看门狗 SIGKILL
 *    （表现为只打印一句 `Killed`，没有任何堆栈）。这里用一个专用 HandlerThread 承载调用，
 *    调用方在外部等 latch，两边互不阻塞。
 *
 * 边界：DRM protected buffer（Widevine L1 之类）在 DPU 的安全通路里解密，
 * 非 secure 输出拿不到明文。本通道对它们同样无效。
 */
class SecureCapture(private val tag: String = "SecureCapture") {

    /** 本机是否具备该通道（API 37+ 且相关类/字段齐备）。首次调用后缓存。 */
    fun isSupported(): Boolean = supportState

    /** 通道不可用的原因，便于诊断；可用时为 null。 */
    val unavailableReason: String? get() = supportNote

    /**
     * 抓取指定屏幕的一帧，显式要求捕获 secure 内容。
     *
     * @param displayId **逻辑** display id（DisplayManager 那套小整数），主屏为 0。
     * @param timeoutMs 等待回调的上限；超时返回 null。
     * @return 软件位图（ARGB_8888），调用方负责 recycle；失败返回 null。
     */
    fun capture(displayId: Int, timeoutMs: Long = DEFAULT_TIMEOUT_MS): Bitmap? {
        if (!supportState) {
            Log.w(tag, "通道不可用：$supportNote")
            return null
        }
        // Android 14~16：同步的 SurfaceControl 路径，没有回调，也就没有 Looper 约束
        if (Build.VERSION.SDK_INT < API_ANDROID_17) {
            return LegacySecureCapture.capture(displayId, timeoutMs)
        }
        val refs = this.refs ?: return null

        val latch = CountDownLatch(1)
        // 0 = ScreenCaptureResult，1 = 错误（Throwable 或系统错误码）
        val slot = arrayOfNulls<Any>(2)

        val receiver = Proxy.newProxyInstance(
            SecureCapture::class.java.classLoader,
            arrayOf(refs.receiverClass),
        ) { _, method, args ->
            when (method.name) {
                "onResult" -> {
                    slot[0] = args?.getOrNull(0)
                    latch.countDown()
                }
                "onError" -> {
                    slot[1] = args?.getOrNull(0)
                    latch.countDown()
                }
                else -> Unit
            }
            null
        }

        handler.post {
            try {
                val params = refs.buildParams(displayId)
                refs.captureMethod.invoke(null, params, DIRECT_EXECUTOR, receiver)
            } catch (t: Throwable) {
                slot[1] = t
                latch.countDown()
            }
        }

        if (!latch.await(timeoutMs, TimeUnit.MILLISECONDS)) {
            Log.w(tag, "capture display=$displayId 等待回调超时（${timeoutMs}ms）")
            return null
        }
        slot[1]?.let { err ->
            Log.w(tag, "capture display=$displayId 失败：${describe(err)}")
            return null
        }
        val result = slot[0] ?: run {
            Log.w(tag, "capture display=$displayId 无结果")
            return null
        }
        return toBitmap(refs, result)
    }

    /** 释放专用线程；进程退出前调用即可，重复调用安全。 */
    fun close() {
        runCatching { thread.quitSafely() }
    }

    // ==========================================
    // 结果转换
    // ==========================================

    private fun toBitmap(refs: Refs, result: Any): Bitmap? {
        val buffer = runCatching { refs.getBuffer.invoke(result) as? HardwareBuffer }.getOrNull()
        if (buffer == null) {
            Log.w(tag, "结果里没有 HardwareBuffer")
            return null
        }
        val colorSpace = runCatching { refs.getColorSpace.invoke(result) as? ColorSpace }.getOrNull()
        var wrapped: Bitmap? = null
        return try {
            wrapped = Bitmap.wrapHardwareBuffer(buffer, colorSpace) ?: run {
                Log.w(tag, "wrapHardwareBuffer 返回 null")
                return null
            }
            // HARDWARE 位图不能直接 compress，必须拷成软件位图
            wrapped.copy(Bitmap.Config.ARGB_8888, false)
        } catch (t: Throwable) {
            Log.w(tag, "转换位图失败：${describe(t)}")
            null
        } finally {
            runCatching { wrapped?.recycle() }
            // HardwareBuffer 由我们持有，必须关闭，否则 GraphicBuffer 泄漏
            runCatching { buffer.close() }
        }
    }

    // ==========================================
    // 反射引用与一次性初始化
    // ==========================================

    private class Refs {
        private val paramsClass = Class.forName(CLS_PARAMS)
        private val builderClass = Class.forName(CLS_BUILDER)
        private val resultClass = Class.forName(CLS_RESULT)
        val receiverClass: Class<*> = Class.forName(CLS_RECEIVER)

        private val builderCtor = builderClass
            .getDeclaredConstructor(Int::class.javaPrimitiveType)
            .apply { isAccessible = true }

        private val setSecurePolicy = builderClass
            .getMethod("setSecureContentPolicy", Int::class.javaPrimitiveType)

        private val setProtectedPolicy = builderClass
            .getMethod("setProtectedContentPolicy", Int::class.javaPrimitiveType)

        private val buildMethod = builderClass.getMethod("build")

        private val securePolicyCapture = paramsClass
            .getField("SECURE_CONTENT_POLICY_CAPTURE").getInt(null)

        private val protectedPolicyCapture = paramsClass
            .getField("PROTECTED_CONTENT_POLICY_CAPTURE").getInt(null)

        val captureMethod: Method = Class.forName(CLS_SCREEN_CAPTURE)
            .declaredMethods
            .firstOrNull { it.name == "capture" }
            ?.apply { isAccessible = true }
            ?: error("ScreenCapture.capture 不存在")

        val getBuffer: Method = resultClass.getMethod("getHardwareBuffer")
        val getColorSpace: Method = resultClass.getMethod("getColorSpace")

        fun buildParams(displayId: Int): Any {
            val builder = builderCtor.newInstance(displayId)
            setSecurePolicy.invoke(builder, securePolicyCapture)
            setProtectedPolicy.invoke(builder, protectedPolicyCapture)
            return buildMethod.invoke(builder)
        }
    }

    private val supportState: Boolean
    private val supportNote: String?

    init {
        var ok = false
        var note: String? = null
        when {
            Build.VERSION.SDK_INT >= API_ANDROID_17 -> {
                try {
                    // 只验证类与关键字段存在，不做真实抓帧（探测不应有副作用）
                    val params = Class.forName(CLS_PARAMS)
                    params.getField("SECURE_CONTENT_POLICY_CAPTURE")
                    Class.forName(CLS_SCREEN_CAPTURE).declaredMethods.firstOrNull { it.name == "capture" }
                        ?: error("ScreenCapture.capture 缺失")
                    ok = true
                } catch (t: Throwable) {
                    note = "设备缺少安全内容策略 API：${describe(t)}"
                }
            }
            // Android 14~16 走另一套 hidden API，实现与验证情况见 LegacySecureCapture
            Build.VERSION.SDK_INT >= LegacySecureCapture.MIN_API -> {
                ok = LegacySecureCapture.isSupported()
                if (!ok) note = "旧版 SurfaceControl 安全图层通道不可用"
            }
            else -> note = "需要 Android 14（API ${LegacySecureCapture.MIN_API}）以上，当前 API ${Build.VERSION.SDK_INT}"
        }
        supportState = ok
        supportNote = note
        if (ok) Log.i(tag, "安全内容直取通道可用") else Log.i(tag, "安全内容直取通道不可用：$note")
    }

    private val refs: Refs? by lazy {
        if (!supportState) return@lazy null
        try {
            exemptHiddenApi()
            primeWindowManager()
            Refs()
        } catch (t: Throwable) {
            Log.w(tag, "初始化失败：${describe(t)}")
            null
        }
    }

    private val thread: HandlerThread by lazy {
        HandlerThread("$tag-looper").apply { start() }
    }

    private val handler: Handler by lazy { Handler(thread.looper) }

    /**
     * 关掉 hidden API 限制。反射调用系统私有成员时必需；
     * app_process 进程里通常本就宽松，但真机 ROM 可能收紧，显式设置更稳。
     */
    private fun exemptHiddenApi() {
        runCatching {
            val vm = Class.forName("dalvik.system.VMRuntime")
            val runtime = vm.getMethod("getRuntime").invoke(null)
            vm.getMethod("setHiddenApiExemptions", Array<String>::class.java)
                .invoke(runtime, arrayOf("L"))
        }.onFailure { Log.d(tag, "hidden API 豁免跳过：${it.message}") }
    }

    /**
     * 往 `WindowManagerGlobal.sWindowManagerService` 里塞一个真 WMS 代理。
     *
     * 不做这一步，`capture()` 会在 `getWindowManagerService()` 里因为
     * `ApplicationSharedMemory` 未初始化而直接抛异常 —— 这是 app_process 裸进程的固有问题。
     */
    private fun primeWindowManager() {
        val wmg = Class.forName("android.view.WindowManagerGlobal")
        val field = wmg.getDeclaredField("sWindowManagerService").apply { isAccessible = true }
        if (field.get(null) != null) return

        val serviceManager = Class.forName("android.os.ServiceManager")
        val binder = serviceManager.getMethod("getService", String::class.java)
            .invoke(null, "window")
            ?: error("window 服务不存在")

        val stub = Class.forName("android.view.IWindowManager\$Stub")
        val wms = stub.getMethod("asInterface", Class.forName("android.os.IBinder"))
            .invoke(null, binder)

        field.set(null, wms)
        Log.i(tag, "已注入 WindowManagerGlobal.sWindowManagerService")
    }

    companion object {
        private const val API_ANDROID_17 = 37
        private const val DEFAULT_TIMEOUT_MS = 6_000L

        private const val CLS_SCREEN_CAPTURE = "android.window.ScreenCapture"
        private const val CLS_PARAMS = "android.window.ScreenCapture\$ScreenCaptureParams"
        private const val CLS_BUILDER = "android.window.ScreenCapture\$ScreenCaptureParams\$Builder"
        private const val CLS_RESULT = "android.window.ScreenCapture\$ScreenCaptureResult"
        private const val CLS_RECEIVER = "android.os.OutcomeReceiver"

        /** 回调直接在当前线程执行，避免再引入一个 Executor 线程池。 */
        private val DIRECT_EXECUTOR = Executor { it.run() }

        private fun describe(err: Any): String {
            if (err !is Throwable) return err.toString()
            val sb = StringBuilder(err.javaClass.name)
            err.message?.let { sb.append(": ").append(it) }
            var cause = err.cause
            var depth = 0
            while (cause != null && depth++ < 4) {
                sb.append(" ← ").append(cause.javaClass.simpleName)
                cause.message?.let { sb.append(": ").append(it) }
                cause = cause.cause
            }
            return sb.toString()
        }
    }
}
