package com.agent.display.client

import android.hardware.display.DisplayManager
import android.os.IBinder
import android.util.Log
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import com.agent.display.common.DisplayConfig
import com.agent.display.common.IAgentShell
import java.io.Closeable
import java.util.concurrent.atomic.AtomicBoolean

/**
 * 面向对象的端到端 Agent 显示会话（DisplaySession）。
 *
 * 核心职责：
 * 统一编排 AgentDisplay、DisplayAwakeClient、MainScreenConflictManager 与 AgentAudioManager，
 * 支持优雅的 AutoCloseable / Kotlin use 作用域、与 Android Lifecycle 深度绑定、以及远程 Binder 崩溃监听。
 */
class DisplaySession(
    val display: AgentDisplay,
    val awakeClient: DisplayAwakeClient,
    val conflictManager: MainScreenConflictManager,
    val audioManager: AgentAudioManager,
    private val onRelease: (AgentDisplay) -> Unit = { it.close() }
) : Closeable, AutoCloseable {

    private val isClosed = AtomicBoolean(false)
    private var deathRecipient: IBinder.DeathRecipient? = null
    private var binderRef: IBinder? = null

    init {
        // 会话创建时自动开启定向防休眠保活
        awakeClient.startKeepAwake(display.displayId)
    }

    /**
     * 注册服务端 Binder 死亡监听，当 Shell 守护进程异常终止时自动清理客户端本地会话
     */
    fun attachDeathRecipient(binder: IBinder) {
        if (isClosed.get()) return
        binderRef = binder
        deathRecipient = IBinder.DeathRecipient {
            Log.w(TAG, "Remote Shell binder died, auto-closing session for display ${display.displayId}")
            close()
        }.also {
            runCatching { binder.linkToDeath(it, 0) }
        }
    }

    /**
     * 绑定至 Android Activity / Service / ViewModel 的生命周期，在宿主 onDestroy 时自动销毁释放
     */
    fun bindToLifecycle(lifecycleOwner: LifecycleOwner) {
        lifecycleOwner.lifecycle.addObserver(object : DefaultLifecycleObserver {
            override fun onDestroy(owner: LifecycleOwner) {
                Log.d(TAG, "Host LifecycleOwner destroyed, closing DisplaySession for display ${display.displayId}")
                this@DisplaySession.close()
            }
        })
    }

    override fun close() {
        if (isClosed.compareAndSet(false, true)) {
            Log.i(TAG, "Closing DisplaySession for display ${display.displayId}")
            deathRecipient?.let { recipient ->
                runCatching { binderRef?.unlinkToDeath(recipient, 0) }
                deathRecipient = null
                binderRef = null
            }
            awakeClient.stopKeepAwake(display.displayId)
            audioManager.close()
            onRelease(display)
        }
    }

    companion object {
        private const val TAG = "DisplaySession"

        /**
         * 便捷构建 DisplaySession 的工厂方法
         */
        @JvmStatic
        fun create(
            shell: IAgentShell,
            displayManager: DisplayManager,
            config: DisplayConfig = DisplayConfig.compact720p(),
            pool: AgentDisplayPool? = null
        ): DisplaySession {
            val display = pool?.acquire(config) ?: AgentDisplay(shell, config, displayManager)
            val awake = DisplayAwakeClient(shell)
            val conflict = MainScreenConflictManager(shell)
            val audio = AgentAudioManager(shell)

            val session = DisplaySession(
                display = display,
                awakeClient = awake,
                conflictManager = conflict,
                audioManager = audio,
                onRelease = { disp ->
                    if (pool != null) {
                        pool.recycle(disp)
                    } else {
                        disp.close()
                    }
                }
            )

            // 自动关联 Binder 死亡监听
            shell.asBinder()?.let { session.attachDeathRecipient(it) }

            return session
        }
    }
}
