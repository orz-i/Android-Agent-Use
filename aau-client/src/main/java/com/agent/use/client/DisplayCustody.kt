package com.agent.use.client

import android.os.Bundle
import android.util.Log
import com.agent.use.common.CustodyArrival
import com.agent.use.common.IAgentCustodyListener
import com.agent.use.common.IAgentShell
import com.agent.use.common.LaunchOrigin
import java.io.Closeable
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList

/**
 * 虚拟屏任务常驻托管客户端（替代旧版 6 秒冲突窗口机制）。
 *
 * 职责：
 * 1. 向 Shell 注册/注销虚拟屏托管监听 (`startCustody` / `stopCustody`)；
 * 2. 接收主屏及托管屏的任务到达与消失事件，派发强类型 [CustodyArrival] 给业务侧；
 * 3. 提供任务启动来源查询 (`launchOrigin`)、主屏占用检查及跨屏回捞 (`moveTaskToDisplay`) 能力。
 */
class DisplayCustody(
    private val shell: IAgentShell,
) : Closeable, AutoCloseable {

    interface Listener {
        fun onTaskArrived(arrival: CustodyArrival) {}
        fun onTaskVanished(taskId: Int, lastDisplayId: Int, at: Long) {}
    }

    private val listeners = CopyOnWriteArrayList<Listener>()
    private val managedDisplays = ConcurrentHashMap.newKeySet<Int>()

    private val binderListener = object : IAgentCustodyListener.Stub() {
        override fun onTaskArrived(e: Bundle?) {
            val arrival = CustodyArrival.fromBundle(e) ?: run {
                Log.w(TAG, "Ignoring malformed custody arrival bundle")
                return
            }
            for (listener in listeners) {
                runCatching { listener.onTaskArrived(arrival) }
                    .onFailure { Log.w(TAG, "Custody listener onTaskArrived error", it) }
            }
        }

        override fun onTaskVanished(taskId: Int, lastDisplayId: Int, at: Long) {
            for (listener in listeners) {
                runCatching { listener.onTaskVanished(taskId, lastDisplayId, at) }
                    .onFailure { Log.w(TAG, "Custody listener onTaskVanished error", it) }
            }
        }
    }

    fun addListener(listener: Listener) {
        listeners.addIfAbsent(listener)
    }

    fun removeListener(listener: Listener) {
        listeners.remove(listener)
    }

    /**
     * 为指定虚拟屏 [displayId] 开启常驻托管，可选同时挂载 [listener]。
     */
    fun startCustody(displayId: Int, listener: Listener? = null): Boolean {
        if (displayId <= CustodyArrival.MAIN_DISPLAY) return false
        if (listener != null) addListener(listener)
        return try {
            val ok = shell.startCustody(displayId, binderListener)
            if (ok) {
                managedDisplays.add(displayId)
            }
            ok
        } catch (t: Throwable) {
            Log.w(TAG, "Failed to startCustody for display $displayId", t)
            false
        }
    }

    /** 停止指定虚拟屏 [displayId] 的任务托管。 */
    fun stopCustody(displayId: Int) {
        managedDisplays.remove(displayId)
        try {
            shell.stopCustody(displayId)
        } catch (t: Throwable) {
            Log.w(TAG, "Failed to stopCustody for display $displayId", t)
        }
    }

    /** 查询任务 [taskId] 的真实启动来源及归属托管屏信息。 */
    fun launchOrigin(taskId: Int): LaunchOrigin =
        LaunchOrigin.fromBundle(launchOriginBundle(taskId))

    /** 查询任务 [taskId] 的启动来源原始 Bundle 契约（含 `managedDisplay`）。 */
    fun launchOriginBundle(taskId: Int): Bundle =
        try {
            shell.launchOrigin(taskId) ?: LaunchOrigin.unknown().toBundle(taskId)
        } catch (t: Throwable) {
            Log.w(TAG, "Failed to query launchOrigin for task $taskId", t)
            LaunchOrigin.unknown().toBundle(taskId)
        }

    /** 方案 1：查询跳转确认弹窗在系统侧记录的真实目标应用包名，无法确定时返回 null。 */
    fun resolveJumpTarget(
        taskId: Int,
        interstitialPackage: String? = null,
        initiatorPackage: String? = null,
    ): String? =
        try {
            shell.resolveJumpTarget(taskId, interstitialPackage, initiatorPackage)
        } catch (t: Throwable) {
            Log.w(TAG, "Failed to resolveJumpTarget for task $taskId", t)
            null
        }

    /** 检查目标应用 [packageName] 在用户 [userId] 下是否当前正在主屏幕运行。 */
    fun isPackageInUseOnMainScreen(packageName: String, userId: Int = 0): Boolean =
        try {
            shell.visibleOnMainScreen(packageName, userId)
        } catch (t: Throwable) {
            Log.w(TAG, "Failed to check visibleOnMainScreen for $packageName", t)
            false
        }

    /** 将指定任务 [taskId] 移回目标虚拟屏 [displayId]。 */
    fun moveTaskToDisplay(taskId: Int, displayId: Int): Boolean =
        try {
            shell.moveTask(taskId, displayId)
        } catch (t: Throwable) {
            Log.w(TAG, "Failed to moveTask $taskId to display $displayId", t)
            false
        }

    /** 停止本客户端已注册的全部虚拟屏托管并清空本地监听器。 */
    fun stopAll() {
        val displays = managedDisplays.toList()
        managedDisplays.clear()
        listeners.clear()
        for (d in displays) {
            runCatching { shell.stopCustody(d) }
                .onFailure { Log.w(TAG, "Failed to stopCustody for display $d", it) }
        }
    }

    override fun close() {
        stopAll()
    }

    companion object {
        private const val TAG = "DisplayCustody"
    }
}
