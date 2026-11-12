package com.agent.use.client

import android.hardware.display.DisplayManager
import android.os.SystemClock
import android.util.Log
import com.agent.use.common.DisplayConfig
import com.agent.use.common.IAgentShell
import java.io.Closeable
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue

/**
 * 客户端 AgentDisplay 连接复用池。
 *
 * 避免频繁创建和销毁 VirtualDisplay 导致的 SurfaceFlinger 与系统窗口管理器资源颠簸。
 * 支持根据 DisplayConfig 规格复用，并具备空闲超时自动清理机制。
 */
class AgentDisplayPool(
    private val shell: IAgentShell,
    private val displayManager: DisplayManager,
    private val maxIdleMs: Long = DEFAULT_MAX_IDLE_MS
) : Closeable, AutoCloseable {

    private data class PooledItem(
        val display: AgentDisplay,
        var recycledAt: Long
    )

    private val pool = ConcurrentHashMap<DisplayConfig, ConcurrentLinkedQueue<PooledItem>>()

    /**
     * 从连接池获取符合配置规格的虚拟屏，若无可用缓存则创建新屏
     */
    fun acquire(config: DisplayConfig): AgentDisplay {
        val queue = pool.computeIfAbsent(config) { ConcurrentLinkedQueue() }
        while (true) {
            val item = queue.poll() ?: break
            val now = SystemClock.uptimeMillis()
            if (now - item.recycledAt < maxIdleMs) {
                Log.d(TAG, "Reusing virtual display ${item.display.displayId} from pool (config: $config)")
                return item.display
            } else {
                Log.d(TAG, "Cached display ${item.display.displayId} expired after ${now - item.recycledAt}ms, closing.")
                item.display.close()
            }
        }

        Log.i(TAG, "Creating new virtual display for config: $config")
        return AgentDisplay(shell, config, displayManager)
    }

    /**
     * 将使用完毕的虚拟屏归还至连接池
     */
    fun recycle(display: AgentDisplay) {
        val queue = pool.computeIfAbsent(display.config) { ConcurrentLinkedQueue() }
        queue.offer(PooledItem(display, SystemClock.uptimeMillis()))
        Log.d(TAG, "Recycled virtual display ${display.displayId} back to pool")
    }

    /**
     * 关闭连接池并释放所有缓存的虚拟屏
     */
    override fun close() {
        for ((_, queue) in pool) {
            while (true) {
                val item = queue.poll() ?: break
                item.display.close()
            }
        }
        pool.clear()
        Log.i(TAG, "AgentDisplayPool closed, all cached displays released.")
    }

    companion object {
        private const val TAG = "AgentDisplayPool"
        const val DEFAULT_MAX_IDLE_MS = 60_000L // 默认 60 秒空闲超时
    }
}
