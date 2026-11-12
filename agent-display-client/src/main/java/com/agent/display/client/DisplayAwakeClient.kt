package com.agent.display.client

import android.os.Handler
import android.os.Looper
import android.util.Log
import com.agent.display.common.IAgentShell
import java.io.Closeable

/**
 * 针对 Android 12+ 独立显示组 (OWN_DISPLAY_GROUP) 虚拟屏的防休眠心跳客户端。
 *
 * 核心原理：
 * 1. 独立显示组虚拟屏在无真实物理触摸时，系统经过屏幕超时后会将其置为休眠停更态；
 * 2. 客户端每隔 [periodMs]（默认 4000ms）执行一次定向活动刷新，使 SurfaceFlinger 持续合成；
 * 3. 严格避让主屏：不调用全局广播式亮屏，避免误唤醒用户实体手机主屏幕。
 */
class DisplayAwakeClient(
    private val shell: IAgentShell,
    private val periodMs: Long = PERIOD_MS,
    private val pokeAction: ((displayId: Int) -> Boolean)? = null
) : Closeable, AutoCloseable {

    private val handler = Handler(Looper.getMainLooper())
    private val activeDisplays = HashSet<Int>()
    @Volatile private var isUnavailable = false

    private val heartbeatTask = object : Runnable {
        override fun run() {
            if (isUnavailable) return
            synchronized(activeDisplays) {
                val iterator = activeDisplays.iterator()
                while (iterator.hasNext()) {
                    val displayId = iterator.next()
                    val success = poke(displayId)
                    if (!success) {
                        Log.w(TAG, "Keep-awake heartbeat failed on display $displayId, stopping heartbeats.")
                        isUnavailable = true
                        activeDisplays.clear()
                        break
                    }
                }
            }
            if (!isUnavailable && activeDisplays.isNotEmpty()) {
                handler.postDelayed(this, periodMs)
            }
        }
    }

    private fun poke(displayId: Int): Boolean {
        return try {
            if (pokeAction != null) {
                pokeAction.invoke(displayId)
            } else {
                // 默认通过查询该屏顶层任务状态作为轻量级 Binder 心跳活动触达
                shell.topTaskId(displayId)
                true
            }
        } catch (t: Throwable) {
            Log.w(TAG, "Failed to poke display $displayId", t)
            false
        }
    }

    /** 开始对指定虚拟屏进行防休眠保活 */
    fun startKeepAwake(displayId: Int) {
        if (isUnavailable || displayId < 0) return
        synchronized(activeDisplays) {
            val wasEmpty = activeDisplays.isEmpty()
            if (activeDisplays.add(displayId) && wasEmpty) {
                handler.post(heartbeatTask)
                Log.d(TAG, "Started keep-awake heartbeats for display $displayId")
            }
        }
    }

    /** 停止对指定虚拟屏的防休眠保活 */
    fun stopKeepAwake(displayId: Int) {
        synchronized(activeDisplays) {
            if (activeDisplays.remove(displayId) && activeDisplays.isEmpty()) {
                handler.removeCallbacks(heartbeatTask)
                Log.d(TAG, "Stopped keep-awake heartbeats for display $displayId")
            }
        }
    }

    /** 停止所有屏幕的防休眠保活 */
    fun stopAll() {
        synchronized(activeDisplays) {
            activeDisplays.clear()
            handler.removeCallbacks(heartbeatTask)
        }
    }

    override fun close() {
        stopAll()
    }

    companion object {
        private const val TAG = "DisplayAwakeClient"
        const val PERIOD_MS = 4000L
    }
}
