package com.agent.use.client

import com.agent.use.common.DisplayConfig
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.io.Closeable

/**
 * 协程安全的延迟建屏代理。
 *
 * 设计意图：
 * 1. 预暴露目标宽、高与 DPI，供 Agent 在未实际亮屏前推算布局或文本尺寸；
 * 2. 纯对话交互、检索问答等不需要界面的任务，全程不创建虚拟屏，系统开销为 0；
 * 3. 首次调用 [get] 时通过 Mutex 线程安全地创建屏幕，创建失败可重试。
 */
class LazyAgentDisplay(
    val config: DisplayConfig,
    private val creator: suspend () -> AgentDisplay
) : Closeable, AutoCloseable {

    constructor(
        width: Int,
        height: Int,
        dpi: Int,
        creator: suspend () -> AgentDisplay
    ) : this(
        config = DisplayConfig(width, height, dpi),
        creator = creator
    )

    val width: Int get() = config.width
    val height: Int get() = config.height
    val dpi: Int get() = config.dpi

    private val mutex = Mutex()
    @Volatile private var instance: AgentDisplay? = null

    /** 已经建好的虚拟屏；未初始化时为 null */
    val current: AgentDisplay? get() = instance

    /**
     * 获取虚拟屏实例。首次调用时真正建屏，后续直接返回同一实例。
     */
    suspend fun get(): AgentDisplay = instance ?: mutex.withLock {
        instance ?: creator().also { instance = it }
    }

    override fun close() {
        instance?.close()
        instance = null
    }
}
