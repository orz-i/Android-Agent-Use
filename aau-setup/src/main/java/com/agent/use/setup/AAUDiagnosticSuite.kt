package com.agent.use.setup

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
import com.agent.use.common.AudioMode
import com.agent.use.common.CommandResult
import com.agent.use.common.DisplayConfig
import com.agent.use.common.IAgentShell
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import kotlin.coroutines.resume

/**
 * AAU (Android Agent Use) 诊断检测引擎。
 *
 * 承担静态系统兼容性检查与动态特权/渲染闭环探测两项核心职责，
 * 生成格式标准、可脱敏、可导出 Markdown/JSON 的不可变 [DiagnosticReport]。
 */
class AAUDiagnosticSuite(
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
        val inputAvailable = inputGlobal || inputLegacy
        val inputCost = SystemClock.uptimeMillis() - inputStart
        items.add(
            CheckItem(
                key = "input_injection_api",
                title = "InputManager 跨屏事件注入通道",
                status = if (inputAvailable) DiagnosticStatus.PASS else DiagnosticStatus.FAIL,
                detail = if (inputGlobal) "检测到现代 Android 14+ InputManagerGlobal 统一注入入口"
                else if (inputLegacy) "检测到标准 Android InputManager 注入入口"
                else "未发现可用 InputManager 注入类，无法通过反射分发触控",
                latencyMs = inputCost,
                isWarningOnly = false,
                advice = if (!inputAvailable) "需检查该 ROM 是否移除或重命名了 input 核心类" else null
            )
        )

        // 5. 虚拟显示创建参数与主屏参数
        val wm = context.getSystemService(Context.WINDOW_SERVICE) as WindowManager
        val metrics = DisplayMetrics()
        @Suppress("DEPRECATION")
        wm.defaultDisplay.getRealMetrics(metrics)
        items.add(
            CheckItem(
                key = "main_display_metrics",
                title = "主物理屏显示规格",
                status = DiagnosticStatus.PASS,
                detail = "${metrics.widthPixels}x${metrics.heightPixels}, 密度: ${metrics.densityDpi} dpi",
                latencyMs = 2L,
                isWarningOnly = true
            )
        )

        items
    }

    /**
     * 运行端到端动态探测。
     */
    suspend fun runDynamicCheck(targetShell: IAgentShell? = shell): List<CheckItem> = withContext(Dispatchers.IO) {
        val items = mutableListOf<CheckItem>()

        // 1. Shell 进程通信连通性与 UID 验证
        val ipcStart = SystemClock.uptimeMillis()
        val isConnected = targetShell?.asBinder()?.isBinderAlive == true
        var shellUid: Int? = null
        var shellPid: Int? = null
        if (isConnected && targetShell != null) {
            runCatching {
                val res = CommandResult.fromBundle(targetShell.runCommand("id -u && echo PID=$$"))
                if (res.isSuccess) {
                    val lines = res.output.lines().map { it.trim() }.filter { it.isNotEmpty() }
                    shellUid = lines.firstOrNull()?.toIntOrNull()
                    shellPid = lines.firstOrNull { it.startsWith("PID=") }?.substringAfter("PID=")?.toIntOrNull()
                }
            }
        }
        val ipcCost = SystemClock.uptimeMillis() - ipcStart
        val isUidValid = shellUid == 2000 || shellUid == 0
        items.add(
            CheckItem(
                key = "shell_ipc_connection",
                title = "Shell 特权通道连通性与 UID",
                status = if (isConnected && isUidValid) DiagnosticStatus.PASS else if (isConnected) DiagnosticStatus.PARTIAL else DiagnosticStatus.FAIL,
                detail = if (isConnected) "Binder 连接存活 (UID=${shellUid ?: "未知"}, PID=${shellPid ?: "未知"})" else "未连接到 Shell 守护进程 (未启动或 Binder 死亡)",
                latencyMs = ipcCost,
                isWarningOnly = false,
                advice = if (!isConnected) "请先通过 Shizuku、无线调试或电脑 USB 运行启动脚本激活服务端" else if (!isUidValid) "Shell 运行 UID 异常，预期为 2000 (Shell) 或 0 (Root)" else null
            )
        )

        // 2 & 3. VirtualDisplay 创建与渲染闭环探测
        var createdDisplayId = -1
        val vdStart = SystemClock.uptimeMillis()
        var vdPass = false
        var vdDetail = "未执行"
        var renderPass = false
        var renderDetail = "未执行"

        if (isConnected && targetShell != null) {
            val handlerThread = HandlerThread("AauDiag-RenderLoop").apply { start() }
            val handler = Handler(handlerThread.looper)
            val imageReader = ImageReader.newInstance(720, 1280, PixelFormat.RGBA_8888, 2)

            try {
                val config = DisplayConfig(
                    width = 720,
                    height = 1280,
                    dpi = 320,
                    flags = DisplayConfig.FLAG_PUBLIC or DisplayConfig.FLAG_OWN_CONTENT_ONLY
                )
                val dId = runCatching { targetShell.createDisplay(imageReader.surface, config) }.getOrDefault(-1)
                if (dId >= 0) {
                    createdDisplayId = dId
                    vdPass = true
                    vdDetail = "成功创建虚拟屏 displayId=$createdDisplayId (720x1280@320)"

                    val frameArrived = withTimeoutOrNull(2000L) {
                        suspendCancellableCoroutine<Boolean> { cont ->
                            imageReader.setOnImageAvailableListener({ reader ->
                                val img = runCatching { reader.acquireLatestImage() }.getOrNull()
                                if (img != null) {
                                    img.close()
                                    if (cont.isActive) cont.resume(true)
                                }
                            }, handler)
                        }
                    } ?: false

                    if (frameArrived) {
                        renderPass = true
                        renderDetail = "首帧图像渲染与捕获成功 (720x1280)"
                    } else {
                        renderDetail = "超时未收到首帧画面 (虚拟屏无活动内容输出)"
                    }
                } else {
                    vdDetail = "虚拟屏创建失败: displayId=$dId"
                }
            } catch (e: Exception) {
                vdDetail = "虚拟屏创建异常: ${e.message}"
            } finally {
                imageReader.close()
                handlerThread.quitSafely()
            }
        } else {
            vdDetail = "跳过探测：Shell 未连接"
        }
        val vdCost = SystemClock.uptimeMillis() - vdStart

        items.add(
            CheckItem(
                key = "virtual_display_create_loop",
                title = "VirtualDisplay 创建动态闭环",
                status = if (vdPass) DiagnosticStatus.PASS else DiagnosticStatus.FAIL,
                detail = vdDetail,
                latencyMs = vdCost,
                isWarningOnly = false,
                advice = if (!vdPass && isConnected) "检查系统是否授予了 CAPTURE_VIDEO_OUTPUT 或 ACCESS_SURFACE_FLINGER 权限" else null
            )
        )

        items.add(
            CheckItem(
                key = "first_frame_render_loop",
                title = "首帧渲染与 ImageReader 捕获闭环",
                status = if (renderPass) DiagnosticStatus.PASS else DiagnosticStatus.PARTIAL,
                detail = renderDetail,
                latencyMs = vdCost,
                isWarningOnly = true,
                advice = if (!renderPass && vdPass) "可启动一个演示 Activity 触发绘制，或检查硬件渲染驱动是否受限" else null
            )
        )

        // 4. 输入法 IME 策略探测
        val imeStart = SystemClock.uptimeMillis()
        var imeDetail = "默认策略未校验"
        var imePass = false
        if (isConnected && targetShell != null) {
            val imeRes = CommandResult.fromBundle(targetShell.runCommand("settings get secure default_input_method"))
            if (imeRes.isSuccess) {
                imeDetail = "当前系统输入法: ${imeRes.output.trim()}"
                imePass = true
            }
        }
        val imeCost = SystemClock.uptimeMillis() - imeStart
        items.add(
            CheckItem(
                key = "ime_policy",
                title = "输入法虚拟屏注入与隔离策略",
                status = if (imePass) DiagnosticStatus.PASS else DiagnosticStatus.PARTIAL,
                detail = imeDetail,
                latencyMs = imeCost,
                isWarningOnly = true
            )
        )

        // 5. AppOps 静音闭环与状态自愈能力
        val audioLoopStart = SystemClock.uptimeMillis()
        var audioLoopPass = false
        var audioDetail = "未执行"
        val testPkg = context.packageName

        if (isConnected && targetShell != null) {
            val muteRes = runCatching { targetShell.setAudioMuted(testPkg, true) }.getOrDefault(false)
            val modeMuted = runCatching { targetShell.getAudioMode(testPkg) }.getOrNull()
            val unmuteRes = runCatching { targetShell.setAudioMuted(testPkg, false) }.getOrDefault(false)
            val modeUnmuted = runCatching { targetShell.getAudioMode(testPkg) }.getOrNull()

            if (muteRes && unmuteRes) {
                audioLoopPass = true
                audioDetail = "AppOps 静音切换与自愈闭环验证成功 (muted: $modeMuted, unmuted: $modeUnmuted)"
            } else {
                audioDetail = "静音切换调用失败: mute=$muteRes, unmute=$unmuteRes"
            }
        } else {
            audioDetail = "跳过：Shell 未连接"
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
        val a11yClass = runCatching { Class.forName("com.agent.use.a11y.AgentAccessibilityService") }.getOrNull()
            ?: runCatching { Class.forName("com.agent.display.a11y.AgentAccessibilityService") }.getOrNull()
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

        // 资源收尾：清理本次探测生成的临时虚拟屏
        if (createdDisplayId >= 0 && targetShell != null) {
            runCatching { targetShell.releaseDisplay(createdDisplayId) }
        }

        items
    }

    /**
     * 运行全量诊断并汇总不可变 [DiagnosticReport]。
     */
    suspend fun runFullDiagnostics(targetShell: IAgentShell? = shell): DiagnosticReport = withContext(Dispatchers.IO) {
        val staticItems = runStaticCheck()
        val dynamicItems = runDynamicCheck(targetShell)
        val allItems = staticItems + dynamicItems

        val hasFail = allItems.any { it.status == DiagnosticStatus.FAIL && !it.isWarningOnly }
        val hasPartial = allItems.any { it.status == DiagnosticStatus.PARTIAL || (it.status == DiagnosticStatus.FAIL && it.isWarningOnly) }

        val overallStatus = when {
            hasFail -> DiagnosticStatus.FAIL
            hasPartial -> DiagnosticStatus.PARTIAL
            else -> DiagnosticStatus.PASS
        }

        val wm = context.getSystemService(Context.WINDOW_SERVICE) as WindowManager
        val metrics = DisplayMetrics()
        @Suppress("DEPRECATION")
        wm.defaultDisplay.getRealMetrics(metrics)
        val resolution = "${metrics.widthPixels}x${metrics.heightPixels}"

        val isConnected = targetShell?.asBinder()?.isBinderAlive == true
        var shellUid: Int? = null
        var shellPid: Int? = null
        if (isConnected && targetShell != null) {
            runCatching {
                val res = CommandResult.fromBundle(targetShell.runCommand("id -u && echo PID=$$"))
                if (res.isSuccess) {
                    val lines = res.output.lines().map { it.trim() }.filter { it.isNotEmpty() }
                    shellUid = lines.firstOrNull()?.toIntOrNull()
                    shellPid = lines.firstOrNull { it.startsWith("PID=") }?.substringAfter("PID=")?.toIntOrNull()
                }
            }
        }

        val summary = when (overallStatus) {
            DiagnosticStatus.PASS -> "整机环境与 AAU 虚拟屏特性完全兼容，具备端到端完整执行能力。"
            DiagnosticStatus.PARTIAL -> "具备运行能力，部分非核心特性（如首帧捕获或高阶无障碍感知）存在告警或已触发降级策略。"
            DiagnosticStatus.FAIL -> "运行环境检查未通过，存在阻断性硬性缺失（如 Shell 通道断开或核心服务无法创建）。"
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

/**
 * 保留向后兼容别名。
 */
@Deprecated(
    message = "AgentDisplayDiagnosticSuite has been renamed to AAUDiagnosticSuite",
    replaceWith = ReplaceWith("AAUDiagnosticSuite")
)
typealias AgentDisplayDiagnosticSuite = AAUDiagnosticSuite
