package com.agent.use.server

import com.agent.use.common.shell.DisplayOrientationWatch

/**
 * 虚拟屏任务旋转动态监听器（委托给 [DisplayOrientationWatch]）。
 */
class DisplayOrientationWatcher(
    taskManager: Any,
    isDisplayActive: () -> Boolean,
    onRequestedOrientation: (taskId: Int, orientation: Int) -> Unit = { _, _ -> },
    onTaskRemoved: (taskId: Int) -> Unit = {},
    sync: () -> Unit,
) {
    private val delegate = DisplayOrientationWatch(
        taskManager = taskManager,
        active = isDisplayActive,
        onRequestedOrientation = onRequestedOrientation,
        onTaskRemoved = onTaskRemoved,
        sync = sync,
    )

    fun close() {
        delegate.close()
    }

    companion object {
        fun transactionCode(callback: String): Int? = DisplayOrientationWatch.transactionCode(callback)
    }
}

typealias CoalescedScan = com.agent.use.common.shell.CoalescedScan
typealias DisplayOrientation = com.agent.use.common.shell.DisplayOrientation
