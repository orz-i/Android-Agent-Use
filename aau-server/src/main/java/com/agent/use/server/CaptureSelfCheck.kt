package com.agent.use.server

import android.os.Looper
import com.agent.use.common.capture.ScreenCapturePrivilege
import com.agent.use.common.capture.ShellScreencap
import java.io.File
import kotlin.system.exitProcess

/**
 * 截屏通道自检入口。
 *
 * 为什么要单独一个 main：完整的 [AgentServerMain] 需要客户端 Provider 握手，
 * 只为了验证「截屏这条链路」去拉起整套守护进程太重，而且失败时很难判断是握手问题
 * 还是截屏问题。这个入口只做三件事：探测能力、抓一帧、落盘，输出可以直接对着看。
 *
 * 启动：
 * ```
 * CLASSPATH=/data/local/tmp/aau-server.jar app_process /system/bin \
 *   com.agent.use.server.CaptureSelfCheck /data/local/tmp [AUTO|SHELL|ROOT|SECURE]
 * ```
 *
 * 第二个参数对应 [ScreenCapturePrivilege]：`SECURE` 会强制只走安全图层通道，
 * 用来确认「策略是否真的生效」；默认 `AUTO` 走生产路径（先 screencap，黑帧才升级）。
 */
object CaptureSelfCheck {

    @JvmStatic
    fun main(args: Array<String>) {
        val outDir = args.getOrNull(0) ?: "/data/local/tmp"
        var allowSecure = true
        val privilege = when (args.getOrNull(1)?.uppercase()) {
            "SHELL" -> ScreenCapturePrivilege.SHELL_ONLY
            "ROOT" -> ScreenCapturePrivilege.ROOT_ONLY
            "SECURE" -> ScreenCapturePrivilege.SECURE_ONLY
            // 对照用：只走 screencap 且明确禁止升级，用来证明「黑帧确实来自 FLAG_SECURE」
            "NOSECURE" -> {
                allowSecure = false
                ScreenCapturePrivilege.SHELL_ONLY
            }
            else -> ScreenCapturePrivilege.AUTO
        }

        // 与守护进程保持一致：主线程必须有 Looper，secure 通道的回调要靠它投递
        Looper.prepareMainLooper()

        Thread({
            try {
                run(outDir, privilege, allowSecure)
            } catch (t: Throwable) {
                println("[check] EXCEPTION ${t.javaClass.name}: ${t.message}")
                t.printStackTrace(System.out)
            } finally {
                System.out.flush()
                exitProcess(0)
            }
        }, "capture-selfcheck").start()

        Looper.loop()
    }

    private fun run(outDir: String, privilege: Int, allowSecure: Boolean) {
        val screencap = ShellScreencap()

        val probeStart = System.currentTimeMillis()
        val capability = screencap.capability(forceRefresh = true)
        println("[check] probe ${System.currentTimeMillis() - probeStart}ms")
        println("[check] ${capability.summary}")
        println("[check] secureCaptureAvailable=${capability.secureCaptureAvailable}")
        println("[check] privilegedModes=${capability.privilegedModes.joinToString { it.label }}")

        val startedAt = System.currentTimeMillis()
        val bytes = screencap.capturePng(
            displayId = ShellScreencap.MAIN_DISPLAY,
            timeoutMs = 6_000L,
            privilege = privilege,
            allowSecure = allowSecure,
        )
        val cost = System.currentTimeMillis() - startedAt

        if (bytes == null) {
            println("[check] FAILED cost=${cost}ms reason=${screencap.failure}")
            return
        }

        val file = File(outDir, "selfcheck-${screencap.lastMode?.label ?: "unknown"}.png")
        file.writeBytes(bytes)
        println(
            "[check] OK mode=${screencap.lastMode?.label} bytes=${bytes.size} " +
                "cost=${cost}ms path=${file.absolutePath}"
        )
    }
}
