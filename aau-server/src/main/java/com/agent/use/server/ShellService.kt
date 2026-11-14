package com.agent.use.server

import android.annotation.SuppressLint
import android.content.Intent
import android.os.Binder
import android.os.Bundle
import android.os.Parcel
import android.os.Process
import android.view.Surface
import com.agent.use.common.DisplayConfig
import com.agent.use.common.IAgentShell
import com.agent.use.common.network.INetworkCapture
import com.agent.use.common.shell.AgentShellEngine
import com.agent.use.server.network.ebpf.EbpfCaptureEngine
import java.io.File

/**
 * AAU Shell 后台 Binder 服务端，复用 [AgentShellEngine] 提供隔离虚拟屏、输入注入、音频静音与命令执行能力。
 */
@SuppressLint("PrivateApi")
class ShellService(
    private val allowedUid: Int,
    stateDir: File = File("/data/local/tmp"),
) : IAgentShell.Stub() {

    private val engine = AgentShellEngine(
        allowedUid = allowedUid,
        stateDir = stateDir,
        exitProcessFn = { Process.killProcess(Process.myPid()) },
    )

    override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
        if (code in FIRST_CALL_TRANSACTION..LAST_CALL_TRANSACTION && allowedUid > 0 && Binder.getCallingUid() != allowedUid) {
            throw SecurityException("Unauthorized caller uid=${Binder.getCallingUid()}")
        }
        return super.onTransact(code, data, reply, flags)
    }

    fun ownDisplay(displayId: Int): Boolean = engine.ownDisplay(displayId)

    fun recoverMuted() = engine.recoverMuted()

    // ==========================================
    // 1. 虚拟屏生命周期
    // ==========================================

    override fun createDisplay(surface: Surface, config: DisplayConfig): Int =
        engine.createDisplay(surface, config)

    override fun releaseDisplay(displayId: Int) =
        engine.releaseDisplay(displayId)

    override fun releaseAll() =
        engine.releaseAll()

    override fun destroy() =
        engine.destroy()

    // ==========================================
    // 2. 应用与任务生命周期
    // ==========================================

    override fun startApp(displayId: Int, packageName: String): Int =
        engine.startApp(displayId, packageName)

    override fun restartApp(displayId: Int, packageName: String): Int =
        engine.restartApp(displayId, packageName)

    override fun startAppInUser(displayId: Int, packageName: String, userId: Int, cold: Boolean): Int =
        engine.startAppInUser(displayId, packageName, userId, cold)

    override fun startIntent(displayId: Int, intent: Intent): Int =
        engine.startIntent(displayId, intent)

    override fun startView(displayId: Int, action: String?, uri: String?, packageName: String?): Int =
        engine.startView(displayId, action, uri, packageName)

    override fun startShare(displayId: Int, packageName: String, text: String): Int =
        engine.startShare(displayId, packageName, text)

    override fun finishDisplay(displayId: Int, keepPackages: Array<String>?, closePackages: Array<String>?): Bundle =
        engine.finishDisplay(displayId, keepPackages, closePackages) ?: Bundle()

    // ==========================================
    // 3. 任务栈查询与迁移
    // ==========================================

    override fun topTaskId(displayId: Int): Int = engine.topTaskId(displayId)
    override fun topActivity(displayId: Int): String? = engine.topActivity(displayId)
    override fun packageOfTask(taskId: Int): String? = engine.packageOfTask(taskId)
    override fun displayOfTask(taskId: Int): Int = engine.displayOfTask(taskId)
    override fun displayOfPackage(packageName: String): Int = engine.displayOfPackage(packageName)
    override fun displayOfPackageInUser(packageName: String, userId: Int): Int =
        engine.displayOfPackageInUser(packageName, userId)
    override fun userOfTask(taskId: Int): Int = engine.userOfTask(taskId)
    override fun moveTask(taskId: Int, displayId: Int): Boolean = engine.moveTask(taskId, displayId)

    // ==========================================
    // 4. 主屏监控与防碰撞
    // ==========================================

    override fun visibleOnMainScreen(packageName: String, userId: Int): Boolean =
        engine.visibleOnMainScreen(packageName, userId)

    override fun watchMainScreen(windowMs: Int): Int =
        engine.watchMainScreen(windowMs)

    override fun mainArrivals(sinceUptimeMs: Long): Bundle =
        engine.mainArrivals(sinceUptimeMs) ?: Bundle()

    // ==========================================
    // 5. 事件与输入注入
    // ==========================================

    override fun injectTap(displayId: Int, x: Int, y: Int): Boolean =
        engine.injectTap(displayId, x, y)

    override fun injectStroke(displayId: Int, xs: IntArray, ys: IntArray, times: LongArray): Boolean =
        engine.injectStroke(displayId, xs, ys, times)

    override fun injectKey(displayId: Int, keyCode: Int): Boolean =
        engine.injectKey(displayId, keyCode)

    override fun injectCtrlKey(displayId: Int, keyCode: Int): Int =
        engine.injectCtrlKey(displayId, keyCode)

    override fun injectAsciiText(displayId: Int, taskId: Int, packageName: String, text: String): Int =
        engine.injectAsciiText(displayId, taskId, packageName, text)

    // ==========================================
    // 6. 音频静音隔离与恢复
    // ==========================================

    override fun setAudioMuted(packageName: String, muted: Boolean): Boolean =
        engine.setAudioMuted(packageName, muted)

    override fun getAudioMode(packageName: String): String? =
        engine.getAudioMode(packageName)

    override fun setAudioMode(packageName: String, mode: String): Boolean =
        engine.setAudioMode(packageName, mode)

    override fun setAudioMutedInUser(packageName: String, userId: Int, muted: Boolean): Boolean =
        engine.setAudioMutedInUser(packageName, userId, muted)

    override fun getAudioModeInUser(packageName: String, userId: Int): String? =
        engine.getAudioModeInUser(packageName, userId)

    override fun setAudioModeInUser(packageName: String, userId: Int, mode: String): Boolean =
        engine.setAudioModeInUser(packageName, userId, mode)

    // ==========================================
    // 7. 剪贴板隔离
    // ==========================================

    override fun setClipText(text: String): Int = engine.setClipText(text)
    override fun restoreClip(): Boolean = engine.restoreClip()
    override fun savedClipText(): String? = engine.savedClipText()
    override fun restoreClipText(original: String, ours: String): Boolean = engine.restoreClipText(original, ours)

    // ==========================================
    // 8. 多用户支持
    // ==========================================

    override fun listUsers(): String? = engine.listUsers()
    override fun listPackages(userId: Int): String? = engine.listPackages(userId)
    override fun isSystemPackage(packageName: String): Boolean = engine.isSystemPackage(packageName)
    override fun appCopyUsers(): Bundle? = engine.appCopyUsers()

    // ==========================================
    // 9. 设备唤醒与主屏准备
    // ==========================================

    override fun wakeDevice(): Boolean = engine.wakeDevice()
    override fun dismissDeviceKeyguard(): Boolean = engine.dismissDeviceKeyguard()
    override fun revealDeviceCredential(): Boolean = engine.revealDeviceCredential()
    override fun revealDeviceCredentialTap(x: Int, y: Int): Boolean = engine.revealDeviceCredentialTap(x, y)
    override fun enterDeviceCredential(kind: Int, credential: ByteArray, clear: Int): Boolean =
        engine.enterDeviceCredential(kind, credential, clear)

    // ==========================================
    // 10. 系统命令与进程标识
    // ==========================================

    override fun identity(): IntArray = engine.identity()
    override fun runCommand(command: String): Bundle = engine.runCommand(command)
    override fun runSystemCommand(displayId: Int, command: String): Bundle =
        engine.runSystemCommand(displayId, command)

    // ==========================================
    // 11. 原生网络嗅探与抓包 (Native Network Capture)
    // ==========================================

    override fun getNetworkCapture(): INetworkCapture =
        EbpfCaptureEngine.getInstance(engine.context)
}
