package com.agent.display.a11y

import com.agent.display.a11y.model.DisplayEvent
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.filter

/**
 * 屏幕无障碍事件总线。
 *
 * 提供基于 displayId 的事件流过滤，供 Agent 实时感知目标虚拟屏内的界面跳转、弹框、键盘弹出等状态跃迁。
 */
object DisplayEventStream {

    private const val BUFFER_CAPACITY = 128

    private val _events = MutableSharedFlow<DisplayEvent>(
        extraBufferCapacity = BUFFER_CAPACITY,
        onBufferOverflow = BufferOverflow.DROP_OLDEST
    )

    val allEvents = _events.asSharedFlow()

    internal fun emitEvent(event: DisplayEvent) {
        _events.tryEmit(event)
    }

    /**
     * 订阅指定虚拟屏的全部无障碍事件
     */
    fun eventsFor(displayId: Int): Flow<DisplayEvent> =
        _events.filter { it.displayId == displayId }

    /**
     * 订阅指定虚拟屏的窗口状态变化（页面跳转、浮层出现或关闭）
     */
    fun windowStateEventsFor(displayId: Int): Flow<DisplayEvent> =
        _events.filter { it.displayId == displayId && it.isWindowStateChange }

    /**
     * 订阅指定虚拟屏的控件点击事件
     */
    fun clickEventsFor(displayId: Int): Flow<DisplayEvent> =
        _events.filter { it.displayId == displayId && it.isViewClicked }
}
