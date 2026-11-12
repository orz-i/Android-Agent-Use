package com.agent.use.common.api

import android.content.Context
import android.hardware.display.DisplayManager
import android.os.IBinder
import android.os.RemoteException
import android.util.Log
import com.agent.use.common.CommandResult
import com.agent.use.common.DisplayConfig
import com.agent.use.common.IAgentShell
import com.agent.use.common.MainArrivalsResult
import java.io.Closeable
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList

/**
 * 通用 AAU (Android Agent Use) 虚拟屏与系统调度顶层入口管理外观。
 *
 * 核心职责：
 * 1. 管理与 Shell 守护进程 Binder 通道的长连接与生命周期（支持 DeathRecipient 监听与断线通知）；
 * 2. 虚拟屏工厂：根据 [DisplayConfig] 生产 [AgentVirtualDisplay] 并维护本地活动屏幕映射；
 * 3. 主屏防扰前置查询与冲突探测；
 * 4. 全局剪贴板防干扰隔离、设备状态准备与特权命令透传；
 * 5. 会话清理与进程资源释放。
 */
class AAUManager private constructor(
    private val context: Context,
    val shell: IAgentShell,
) : Closeable {

    private val displayManager = context.getSystemService(Context.DISPLAY_SERVICE) as? DisplayManager
    private val activeDisplays = ConcurrentHashMap<Int, AgentVirtualDisplay>()
    private val deathListeners = CopyOnWriteArrayList<() -> Unit>()

    private val deathRecipient = IBinder.DeathRecipient {
        Log.e(TAG, "AgentShell daemon process died unexpectedly.")
        activeDisplays.values.forEach { it.release() }
        activeDisplays.clear()
        deathListeners.forEach { runCatching { it() } }
    }

    init {
        try {
            shell.asBinder().linkToDeath(deathRecipient, 0)
        } catch (e: RemoteException) {
            Log.w(TAG, "Failed to linkToDeath on shell binder: ${e.message}")
        }
    }

    // ==========================================
    // 虚拟屏管理与构建
    // ==========================================

    /**
     * 根据配置创建并启动一个新的虚拟屏实例。
     */
    fun createVirtualDisplay(config: DisplayConfig = DisplayConfig.standard1080p()): AgentVirtualDisplay {
        val virtualDisplay = AgentVirtualDisplay(shell, config, displayManager)
        activeDisplays[virtualDisplay.displayId] = virtualDisplay
        return virtualDisplay
    }

    /**
     * 获取当前处于活动状态的所有虚拟屏实例列表。
     */
    fun getActiveDisplays(): List<AgentVirtualDisplay> =
        activeDisplays.values.toList()

    /**
     * 根据 displayId 查询虚拟屏实例。
     */
    fun getDisplay(displayId: Int): AgentVirtualDisplay? =
        activeDisplays[displayId]

    /**
     * 释放指定编号的虚拟屏。
     */
    fun releaseDisplay(displayId: Int) {
        activeDisplays.remove(displayId)?.release()
    }


    // ==========================================
    // 主屏冲突探测与任务回捞原语
    // ==========================================

    /**
     * 检查目标应用在主屏是否可见，防止打扰正在使用主屏的用户。
     */
    fun isVisibleOnMainScreen(packageName: String, userId: Int = 0): Boolean =
        try {
            shell.visibleOnMainScreen(packageName, userId)
        } catch (e: RemoteException) {
            Log.w(TAG, "isVisibleOnMainScreen failed: ${e.message}")
            true // 无法探测时默认视为占用，严格遵循宁可不启动也不打扰用户的安全原则
        }

    /**
     * 跨屏幕迁移任务（如将逃逸到主屏的任务拉回虚拟屏）。
     */
    fun moveTask(taskId: Int, displayId: Int): Boolean =
        try {
            shell.moveTask(taskId, displayId)
        } catch (e: RemoteException) {
            Log.w(TAG, "moveTask failed: ${e.message}")
            false
        }

    /**
     * 开启主屏监控窗口，记录未来 windowMs 毫秒内主屏顶层任务变动。
     */
    fun watchMainScreen(windowMs: Int): Int =
        try {
            shell.watchMainScreen(windowMs)
        } catch (e: RemoteException) {
            Log.w(TAG, "watchMainScreen failed: ${e.message}")
            -1
        }

    /**
     * 获取 sinceUptimeMs 之后主屏新冒出的任务列表。
     */
    fun getMainArrivals(sinceUptimeMs: Long): MainArrivalsResult =
        try {
            MainArrivalsResult.fromBundle(shell.mainArrivals(sinceUptimeMs))
        } catch (e: RemoteException) {
            Log.w(TAG, "getMainArrivals failed: ${e.message}")
            MainArrivalsResult(emptyList(), emptyList())
        }


    // ==========================================
    // 剪贴板安全与隔离
    // ==========================================

    /**
     * 以 Shell 身份设置剪贴板纯文本（自动附带不弹主屏已复制提示与敏感标记）。
     */
    fun setClipboardText(text: String): Int =
        try {
            shell.setClipText(text)
        } catch (e: RemoteException) {
            Log.w(TAG, "setClipboardText failed: ${e.message}")
            2
        }

    /**
     * 恢复设置之前的原剪贴板内容。
     */
    fun restoreClipboard(): Boolean =
        try {
            shell.restoreClip()
        } catch (e: RemoteException) {
            Log.w(TAG, "restoreClipboard failed: ${e.message}")
            false
        }


    // ==========================================
    // 系统命令透传与设备状态准备
    // ==========================================

    /**
     * 以 Shell 身份执行命令。
     */
    fun executeCommand(command: String): CommandResult =
        try {
            CommandResult.fromBundle(shell.runCommand(command))
        } catch (e: RemoteException) {
            CommandResult(-1, "RemoteException: ${e.message}")
        }

    /**
     * 点亮屏幕并尝试解除无密码锁屏。
     */
    fun wakeAndDismissKeyguard(): Boolean =
        try {
            shell.wakeDevice() && shell.dismissDeviceKeyguard()
        } catch (e: RemoteException) {
            Log.w(TAG, "wakeAndDismissKeyguard failed: ${e.message}")
            false
        }

    /**
     * 注册服务端死亡监听器。
     */
    fun addOnServerDiedListener(listener: () -> Unit) {
        deathListeners.add(listener)
    }

    fun removeOnServerDiedListener(listener: () -> Unit) {
        deathListeners.remove(listener)
    }


    // ==========================================
    // 全局清理与释放
    // ==========================================

    /**
     * 释放所有虚拟屏，还原剪贴板与静音设置。
     */
    fun releaseAll() {
        activeDisplays.values.forEach { it.release() }
        activeDisplays.clear()
        runCatching { shell.releaseAll() }
    }

    /**
     * 彻底销毁并停止服务端进程。
     */
    fun destroyServer() {
        releaseAll()
        runCatching { shell.destroy() }
    }

    override fun close() {
        releaseAll()
    }

    companion object {
        private const val TAG = "AAUManager"

        /**
         * 通过 Binder 对象构造外观管理器。
         */
        @JvmStatic
        fun fromBinder(context: Context, binder: IBinder): AAUManager {
            val shell = IAgentShell.Stub.asInterface(binder)
                ?: throw IllegalArgumentException("Binder is not a valid IAgentShell interface")
            return AAUManager(context.applicationContext ?: context, shell)
        }

        /**
         * 通过 IAgentShell 接口实例直接构造外观管理器。
         */
        @JvmStatic
        fun fromInterface(context: Context, shell: IAgentShell): AAUManager =
            AAUManager(context.applicationContext ?: context, shell)
    }
}

/**
 * 兼容旧命名的类型别名。
 */
@Deprecated("Renamed to AAUManager", ReplaceWith("AAUManager"))
typealias AgentDisplayManager = AAUManager
