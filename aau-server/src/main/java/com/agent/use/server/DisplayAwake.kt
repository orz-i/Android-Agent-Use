package com.agent.use.server

import java.lang.reflect.Method

/**
 * 虚拟屏防休眠心跳控制器。
 *
 * 在 Android 12+ 独占显示组（FLAG_OWN_DISPLAY_GROUP）中，若无用户触摸系统可能让该屏进入休眠。
 * 本组件周期性触发虚拟触控事件以保持该屏幕处于唤醒活跃状态。
 */
class DisplayAwake(
    private val poke: (displayId: Int) -> Boolean,
    private val schedule: (Runnable) -> () -> Unit,
) {
    private val locks = HashMap<Int, () -> Unit>()

    fun start(displayId: Int) = synchronized(locks) {
        if (displayId in locks) return
        var giveUp = false
        val stop = schedule(object : Runnable {
            override fun run() {
                if (giveUp) return
                if (!poke(displayId)) {
                    giveUp = true
                    stop(displayId)
                }
            }
        })
        locks[displayId] = stop
    }

    fun stop(displayId: Int) = synchronized(locks) {
        locks.remove(displayId)?.invoke()
    }

    fun stopAll() = synchronized(locks) {
        val targets = locks.values.toList()
        locks.clear()
        targets.forEach { it.invoke() }
    }

    companion object {
        const val PERIOD_MS = 4_000L
        const val EVENT_TOUCH = 0

        /** 检查是否需要保持常亮（当开启独占组且属于非主显示组时） */
        fun needed(flags: Int, ownGroupFlag: Int, displayGroupId: Int?): Boolean =
            (flags and ownGroupFlag != 0) && (displayGroupId == null || displayGroupId != 0)

        /** 解析 IPowerManager 的 userActivity 方法重载 */
        fun userActivityMethod(cls: Class<*>): Method? = cls.methods.firstOrNull { m ->
            m.name == "userActivity" && m.parameterTypes.size >= 4 &&
                    m.parameterTypes[0] == Int::class.javaPrimitiveType &&
                    m.parameterTypes[1] == Long::class.javaPrimitiveType
        }
    }
}
