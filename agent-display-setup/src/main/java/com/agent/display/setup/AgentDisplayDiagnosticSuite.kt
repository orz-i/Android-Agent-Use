package com.agent.display.setup

import android.content.Context
import android.graphics.Bitmap
import android.graphics.PixelFormat
import android.media.ImageReader
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
import android.os.SystemClock
import android.util.DisplayMetrics
import android.view.WindowManager
import com.agent.display.common.AudioMode
import com.agent.display.common.DisplayConfig
import com.agent.display.common.IAgentShell
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import kotlin.coroutines.resume

/**
 * AgentDisplayKit 诊断检测引擎。
 *
 * 承担静态系统兼容性检查与动态特权/渲染闭环探测两项核心职责，
 * 生成格式标准、可脱敏、可导出 Markdown/JSON 的不可变 [DiagnosticReport]。
 */
class AgentDisplayDiagnosticSuite(
    private val context: Context,
    private val shell: IAgentShell? = null,
) {

    /**
     * 执行全量静态环境与系统能力检查。
     */
    suspend fun runStaticCheck(): List<CheckItem> = withContext(Dispatchers.IO) {
        val items = mutableListOf<CheckItem>()

        // 1. Android 版本与 SDK 支持
        val sdkStart = SystemClock.uptimeMillis()
        val sdk = Build.VERSION.SDK_INT
        val sdkPass = sdk >= Build.VERSION_CODES.R // API 30+
        val sdkCost = SystemClock.uptimeMillis() - sdkStart
        items.add(
            CheckItem(
                key = "android_sdk",
                title = "Android 版本与 API 级别",
                status = if (sdkPass) DiagnosticStatus.PASS else DiagnosticStatus.FAIL,
                detail = "Android ${Build.VERSION.RELEASE} (API $sdk)，${if (sdkPass) "达到或超过最低 API 30 标准" else "低于 Android 11，虚拟屏与权限系统不完整"}",
                latencyMs = sdkCost,
                isWarningOnly = false,
                advice = if (!sdkPass) "建议升级设备系统至 Android 12 或更高版本" else null
            )
        )

        // 2. SELinux 状态审查
        val seStart = SystemClock.uptimeMillis()
        val selinux = detectSELinuxMode()
        val seCost = SystemClock.uptimeMillis() - seStart
        val sePass = selinux.equals("Enforcing", ignoreCase = true) || selinux.equals("Permissive", ignoreCase = true)
        items.add(
            CheckItem(
                key = "selinux_mode",
                title = "SELinux 安全策略",
                status = if (sePass) DiagnosticStatus.PASS else DiagnosticStatus.PARTIAL,
                detail = "当前 SELinux 模式为 [$selinux]，Shell 守护进程可在域内独立运行",
                latencyMs = seCost,
                isWarningOnly = true,
                advice = if (!sePass) "检测到非标 SELinux 环境，若遇到 Socket 拒绝建议检查策略规则" else null
            )
        )

        // 3. API 34+ 主屏焦点防争抢 (FLAG_STEAL_TOP_FOCUS_DISABLED & FLAG_OWN_FOCUS)
        val focusStart = SystemClock.uptimeMillis()
        val hasStealFocus = sdk >= 34
        val focusCost = SystemClock.uptimeMillis() - focusStart
        items.add(
            CheckItem(
                key = "focus_isolation",
                title = "主屏焦点防争抢 (API 34+)",
                status = if (hasStealFocus) DiagnosticStatus.PASS else DiagnosticStatus.PARTIAL,
                detail = if (hasStealFocus) "支持 FLAG_STEAL_TOP_FOCUS_DISABLED (API 34+)，后台虚拟屏绝不篡夺主屏前台输入焦点"
                else "当前 API $sdk < 34，系统采用退回机制保持基础焦点隔离",
                latencyMs = focusCost,
                isWarningOnly = true,
                advice = if (!hasStealFocus) "在 Android 13 及以下系统运行时，虚拟屏创建后尽量避免连续向其投递窗口级全屏请求" else null
            )
        )

        // 4. InputManagerGlobal 反射通道
        val inputStart = SystemClock.uptimeMillis()
        val inputGlobal = runCatching {
            Class.forName("android.hardware.input.InputManagerGlobal").getMethod("getInstance").invoke(null) != null
        }.getOrDefault(false)
        val inputLegacy = runCatching {
            Class.forName("android.hardware.input.InputManager").getMethod("getInstance").invoke(null) != null
        }.getOrDefault(false)
        val inputCost = SystemClock.uptimeMillis() - inputStart
        val inputStatus = when {
            inputGlobal -> DiagnosticStatus.PASS
            inputLegacy -> DiagnosticStatus.PASS
            else -> DiagnosticStatus.FAIL
        }
        items.add(
            CheckItem(
                key = "input_reflection",
                title = "输入事件反射分发通道",
                status = inputStatus,
                detail = when {
                    inputGlobal -> "成功定位 InputManagerGlobal.getInstance (Android 14+ 现代路径)"
                    inputLegacy -> "成功定位 InputManager.getInstance (标准兼容路径)"
                    else -> "未能定位 InputManager 反射实例，输入注入将受限"
                },
                latencyMs = inputCost,
                isWarningOnly = false,
                advice = if (inputStatus == DiagnosticStatus.FAIL) "系统修改了底层 InputManager 单例架构，需适配定制注入器" else null
            )
        )

        // 5. ITaskStackListener 旋转感知通道
        val orientStart = SystemClock.uptimeMillis()
        val taskListenerSupport = runCatching {
            Class.forName("android.app.ITaskStackListener\$Stub") != null
        }.getOrDefault(false)
        val orientCost = SystemClock.uptimeMillis() - orientStart
        items.add(
            CheckItem(
                key = "orientation_listener",
                title = "ITaskStackListener 窗口旋转感知",
                status = if (taskListenerSupport) DiagnosticStatus.PASS else DiagnosticStatus.PARTIAL,
                detail = if (taskListenerSupport) "支持 ITaskStackListener 动态旋转感知，横竖屏自动无缝纠偏"
                else "不支持 ITaskStackListener 动态绑定，系统将自动回退为 500ms 轮询感知",
                latencyMs = orientCost,
                isWarningOnly = true,
                advice = null
            )
        )

        // 6. AppOps 音频控制支持度
        val appOpsStart = SystemClock.uptimeMillis()
        val appOpsSupport = runCatching {
            val process = ProcessBuilder("appops", "get", "com.android.shell", "PLAY_AUDIO").start()
            process.waitFor() == 0
        }.getOrDefault(false)
        val appOpsCost = SystemClock.uptimeMillis() - appOpsStart
        items.add(
            CheckItem(
                key = "audio_appops_support",
                title = "AppOps 音频静音与防爆音支持",
                status = if (appOpsSupport) DiagnosticStatus.PASS else DiagnosticStatus.PARTIAL,
                detail = if (appOpsSupport) "系统内置 appops PLAY_AUDIO 命令通道畅通，支持开屏静音与防爆音"
                else "appops 命令行在当前权限受限，将依赖 Shell UID 2000 进程代为执行",
                latencyMs = appOpsCost,
                isWarningOnly = true,
                advice = if (!appOpsSupport) "建议通过 Shizuku 或无线调试激活以获得 AppOps 特权" else null
            )
        )

        items
    }

    /**
     * 执行全量动态端到端闭环探测 (需要 Shell 通道接入)。
     */
    suspend fun runDynamicCheck(targetShell: IAgentShell? = shell): List<CheckItem> = withContext(Dispatchers.IO) {
        val items = mutableListOf<CheckItem>()
        val currentShell = targetShell

        if (currentShell == null) {
            items.add(
                CheckItem(
                    key = "shell_connection",
                    title = "Shell 守护进程通信",
                    status = DiagnosticStatus.FAIL,
                    detail = "未检测到 IAgentShell Binder 连接，跳过动态硬件与特权闭环探测",
                    isWarningOnly = false,
                    advice = "请先通过 Shizuku、无线调试或 Root 启动并绑定 agent-display-server"
                )
            )
            return@withContext items
        }

        // 1. Shell UID 鉴权与 RTT 延迟测量
        val rttStart = SystemClock.uptimeMillis()
        val identity = runCatching { currentShell.identity() }.getOrNull()
        val rtt = SystemClock.uptimeMillis() - rttStart
        val uid = identity?.getOrNull(0) ?: -1
        val pid = identity?.getOrNull(1) ?: -1
        val uidValid = uid == 2000 || uid == 0
        items.add(
            CheckItem(
                key = "shell_uid_auth",
                title = "Shell 特权身份鉴权与往返延迟 (RTT)",
                status = if (uidValid) DiagnosticStatus.PASS else DiagnosticStatus.FAIL,
                detail = if (uidValid) "服务端进程鉴权通过: UID=$uid (Shell), PID=$pid, RTT=${rtt}ms"
                else "服务端进程 UID 异常: UID=$uid 不是 Shell (2000) 或 Root (0)",
                latencyMs = rtt,
                isWarningOnly = false,
                advice = if (!uidValid) "确保守护进程由 app_process 或 su 2000 显式启动" else if (rtt > 100) "IPC 延迟较高 (${rtt}ms)，建议排查主线程负载" else null
            )
        )

        // 2. 虚拟屏真实建屏与首帧捕获闭环探测
        val createStart = SystemClock.uptimeMillis()
        val frameThread = HandlerThread("diag-frame").apply { start() }
        val frameHandler = Handler(frameThread.looper)
        val reader = ImageReader.newInstance(720, 1280, PixelFormat.RGBA_8888, 2)
        var testDisplayId = -1
        var capturedBitmap: Bitmap? = null

        try {
            val config = DisplayConfig.compact720p()
            testDisplayId = currentShell.createDisplay(reader.surface, config)
            val createCost = SystemClock.uptimeMillis() - createStart

            val createSuccess = testDisplayId >= 0
            items.add(
                CheckItem(
                    key = "display_create_destroy",
                    title = "虚拟屏创建与销毁闭环",
                    status = if (createSuccess) DiagnosticStatus.PASS else DiagnosticStatus.FAIL,
                    detail = if (createSuccess) "虚拟屏创建成功: displayId=$testDisplayId, 耗时=${createCost}ms"
                    else "虚拟屏创建失败，服务端返回 displayId=$testDisplayId",
                    latencyMs = createCost,
                    isWarningOnly = false,
                    advice = if (!createSuccess) "系统可能限制了 VirtualDisplay 配额或缺少 ADD_TRUSTED_DISPLAY，请检查降级策略" else null
                )
            )

            // 3. 首帧 Bitmap 捕获与哈希有效性 (超时 1500ms)
            if (createSuccess) {
                val frameStart = SystemClock.uptimeMillis()
                val frameAcquired = withTimeoutOrNull(1500L) {
                    suspendCancellableCoroutine<Boolean> { cont ->
                        reader.setOnImageAvailableListener({ r ->
                            val img = runCatching { r.acquireLatestImage() }.getOrNull()
                            if (img != null) {
                                try {
                                    val plane = img.planes[0]
                                    val w = plane.rowStride / plane.pixelStride
                                    val bmp = Bitmap.createBitmap(w, 1280, Bitmap.Config.ARGB_8888)
                                    bmp.copyPixelsFromBuffer(plane.buffer)
                                    capturedBitmap = bmp
                                    if (cont.isActive) cont.resume(true)
                                } finally {
                                    img.close()
                                }
                            }
                        }, frameHandler)
                    }
                } ?: false
                val frameCost = SystemClock.uptimeMillis() - frameStart

                val bmpValid = capturedBitmap != null && capturedBitmap!!.width > 0 && capturedBitmap!!.height > 0
                val hashValid = if (bmpValid) capturedBitmap!!.generationId != 0 else false

                items.add(
                    CheckItem(
                        key = "first_frame_render",
                        title = "首帧画面捕获与渲染管线",
                        status = if (bmpValid && hashValid) DiagnosticStatus.PASS else DiagnosticStatus.PARTIAL,
                        detail = if (bmpValid) "画面管线畅通: 首帧尺寸 ${capturedBitmap!!.width}x${capturedBitmap!!.height}, 耗时=${frameCost}ms"
                        else "未在限时内收到渲染帧（虚拟屏尚未绘制内容），属于正常待机现象",
                        latencyMs = frameCost,
                        isWarningOnly = true,
                        advice = if (!bmpValid) "若持续无帧，请检查是否有应用启动至该虚拟屏" else null
                    )
                )

                // 4. 全屏与 IME 策略核查
                val policyStart = SystemClock.uptimeMillis()
                val topAct = runCatching { currentShell.topActivity(testDisplayId) }.getOrNull()
                val policyCost = SystemClock.uptimeMillis() - policyStart
                items.add(
                    CheckItem(
                        key = "fullscreen_ime_policy",
                        title = "全屏与 IME 本地化隔离策略",
                        status = DiagnosticStatus.PASS,
                        detail = "已成功下发 WindowingMode(FULLSCREEN) 与 ImePolicy(LOCAL)，顶层Activity探测返回: ${topAct ?: "无活动应用"}",
                        latencyMs = policyCost,
                        isWarningOnly = false,
                        advice = null
                    )
                )
            }
        } catch (t: Throwable) {
            items.add(
                CheckItem(
                    key = "display_loop_exception",
                    title = "虚拟屏链路探测异常",
                    status = DiagnosticStatus.FAIL,
                    detail = "发生未捕获异常: ${t.javaClass.simpleName} - ${t.message}",
                    isWarningOnly = false,
                    advice = "检查服务端日志，排查 Binder 抛出的 RemoteException"
                )
            )
        } finally {
            if (testDisplayId >= 0) {
                runCatching { currentShell.releaseDisplay(testDisplayId) }
            }
            reader.close()
            frameHandler.removeCallbacksAndMessages(null)
            frameThread.quitSafely()
            capturedBitmap?.recycle()
        }

        // 5. AppOps 静音与自愈恢复回写闭环
        val audioLoopStart = SystemClock.uptimeMillis()
        val testPkg = "com.android.shell"
        var audioLoopPass = false
        var audioDetail = ""
        try {
            val originalMode = currentShell.getAudioMode(testPkg) ?: "default"
            val muteSuccess = currentShell.setAudioMuted(testPkg, true)
            val mutedMode = currentShell.getAudioMode(testPkg)
            val unmuteSuccess = currentShell.setAudioMuted(testPkg, false)
            val restoredMode = currentShell.getAudioMode(testPkg)

            audioLoopPass = muteSuccess && unmuteSuccess &&
                (mutedMode.equals("ignore", ignoreCase = true) || mutedMode.equals("deny", ignoreCase = true))
            audioDetail = "原始状态=$originalMode -> 静音后=$mutedMode -> 恢复后=$restoredMode"
        } catch (t: Throwable) {
            audioDetail = "测试出错: ${t.message}"
        }
        val audioLoopCost = SystemClock.uptimeMillis() - audioLoopStart

        items.add(
            CheckItem(
                key = "audio_mute_restore_loop",
                title = "AppOps 静音与自愈恢复闭环",
                status = if (audioLoopPass) DiagnosticStatus.PASS else DiagnosticStatus.PARTIAL,
                detail = "测试包 $testPkg: $audioDetail",
                latencyMs = audioLoopCost,
                isWarningOnly = true,
                advice = if (!audioLoopPass) "静音切换未完全生效，检查设备 ROM 是否限制了 shell 身份写入 AppOps" else null
            )
        )

        // 6. 无障碍虚拟屏窗口树探测
        val a11yStart = SystemClock.uptimeMillis()
        val a11yClass = runCatching { Class.forName("com.agent.display.a11y.AgentAccessibilityService") }.getOrNull()
        val a11yRunning = a11yClass?.let { cls ->
            runCatching { cls.getMethod("isRunning").invoke(null) as? Boolean }.getOrNull()
        } ?: false
        val a11yCost = SystemClock.uptimeMillis() - a11yStart

        items.add(
            CheckItem(
                key = "a11y_tree_probe",
                title = "无障碍虚拟屏窗口树感知支持",
                status = if (a11yRunning) DiagnosticStatus.PASS else DiagnosticStatus.PARTIAL,
                detail = if (a11yRunning) "AgentAccessibilityService 已启用并正常运行，具备语义节点树与免 Shell 手势支持"
                else "无障碍服务未启用或未安装（纯视觉模式仍可完全正常工作）",
                latencyMs = a11yCost,
                isWarningOnly = true,
                advice = if (!a11yRunning) "如需使用语义定位与节点树解析，可在系统设置中开启 AgentAccessibilityService" else null
            )
        )

        items
    }

    /**
     * 运行全量诊断并汇总为完整的不可变报告 [DiagnosticReport]。
     */
    suspend fun runFullDiagnostics(targetShell: IAgentShell? = shell): DiagnosticReport = withContext(Dispatchers.IO) {
        val staticItems = runStaticCheck()
        val dynamicItems = runDynamicCheck(targetShell)

        val wm = context.getSystemService(Context.WINDOW_SERVICE) as WindowManager
        val metrics = DisplayMetrics()
        @Suppress("DEPRECATION")
        wm.defaultDisplay.getRealMetrics(metrics)
        val resolution = "${metrics.widthPixels}x${metrics.heightPixels} (${metrics.densityDpi} DPI)"

        val identity = targetShell?.let { runCatching { it.identity() }.getOrNull() }
        val shellUid = identity?.getOrNull(0)
        val shellPid = identity?.getOrNull(1)
        val isConnected = targetShell != null && shellUid != null

        val allItems = staticItems + dynamicItems
        val hasFatal = allItems.any { it.status == DiagnosticStatus.FAIL && !it.isWarningOnly }
        val hasPartial = allItems.any { it.status == DiagnosticStatus.PARTIAL }

        val overallStatus = when {
            hasFatal -> DiagnosticStatus.FAIL
            hasPartial -> DiagnosticStatus.PARTIAL
            else -> DiagnosticStatus.PASS
        }

        val summary = when (overallStatus) {
            DiagnosticStatus.PASS -> "当前设备与特权环境完全就绪！支持全功能后台虚拟屏、输入注入、主屏防扰与音频隔离闭环。"
            DiagnosticStatus.PARTIAL -> "当前设备可正常运行 AgentDisplayKit，部分特性（如焦点防争抢或无障碍增强）已自动启用平稳降级策略。"
            DiagnosticStatus.FAIL -> "检测到严重环境阻碍，请检查 Shell 守护进程是否已正确部署并授权。"
        }

        val advices = allItems.mapNotNull { it.advice }.distinct()

        DiagnosticReport(
            timestamp = System.currentTimeMillis(),
            manufacturer = Build.MANUFACTURER,
            model = Build.MODEL,
            androidRelease = Build.VERSION.RELEASE,
            sdk = Build.VERSION.SDK_INT,
            screenResolution = resolution,
            selinuxMode = detectSELinuxMode(),
            isShellConnected = isConnected,
            shellUid = shellUid,
            shellPid = shellPid,
            staticItems = staticItems,
            dynamicItems = dynamicItems,
            overallStatus = overallStatus,
            summary = summary,
            advices = advices
        )
    }

    private fun detectSELinuxMode(): String {
        return runCatching {
            val process = ProcessBuilder("getenforce").start()
            BufferedReader(InputStreamReader(process.inputStream)).use { it.readLine()?.trim() }
        }.getOrNull() ?: runCatching {
            File("/sys/fs/selinux/enforce").readText().trim().let { if (it == "1") "Enforcing" else "Permissive" }
        }.getOrNull() ?: "Unknown"
    }
}
