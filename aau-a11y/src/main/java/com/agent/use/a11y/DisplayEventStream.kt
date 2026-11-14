package com.agent.use.a11y

import android.view.accessibility.AccessibilityEvent
import com.agent.use.a11y.model.DisplayEvent
import com.agent.use.a11y.model.NotificationEvent
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.filter
import kotlinx.coroutines.flow.map
import java.util.concurrent.atomic.AtomicLong

/**
 * 屏幕无障碍事件总线。
 *
 * 提供基于 displayId 的事件流过滤，供 Agent 实时感知目标虚拟屏内的界面跳转、弹框、键盘弹出等状态跃迁。
 */
object DisplayEventStream {

    private const val BUFFER_CAPACITY = 128
    private const val RAW_BUFFER_CAPACITY = 64

    private class RawDisplayEvent(val displayId: Int, val event: AccessibilityEvent)

    private val _events = MutableSharedFlow<DisplayEvent>(
        extraBufferCapacity = BUFFER_CAPACITY,
        onBufferOverflow = BufferOverflow.DROP_OLDEST
    )

    private val _rawEvents = MutableSharedFlow<RawDisplayEvent>(
        extraBufferCapacity = RAW_BUFFER_CAPACITY,
        onBufferOverflow = BufferOverflow.DROP_OLDEST
    )

    private val _windowChanges = MutableSharedFlow<Unit>(
        extraBufferCapacity = 1,
        onBufferOverflow = BufferOverflow.DROP_OLDEST
    )

    private val _notifications = MutableSharedFlow<NotificationEvent>(
        extraBufferCapacity = RAW_BUFFER_CAPACITY,
        onBufferOverflow = BufferOverflow.DROP_OLDEST
    )

    private val _windowGeneration = AtomicLong()

    val allEvents = _events.asSharedFlow()

    val hasDisplaySubscribers: Boolean
        get() = _events.subscriptionCount.value > 0

    val hasRawSubscribers: Boolean
        get() = _rawEvents.subscriptionCount.value > 0

    val hasNotificationSubscribers: Boolean
        get() = _notifications.subscriptionCount.value > 0

    internal fun emitEvent(event: DisplayEvent) {
        _events.tryEmit(event)
    }

    internal fun emitRawEvent(displayId: Int, event: AccessibilityEvent) {
        // API 33 以下系统会在回调返回后回收事件对象，订阅方异步读取前先复制一份
        _rawEvents.tryEmit(RawDisplayEvent(displayId, AccessibilityEvent(event)))
    }

    internal fun emitWindowChanged() {
        _windowChanges.tryEmit(Unit)
    }

    internal fun incrementWindowGeneration(): Long = _windowGeneration.incrementAndGet()

    internal fun emitNotification(packageName: String?, text: String) {
        _notifications.tryEmit(NotificationEvent(packageName, text))
    }

    /**
     * 订阅指定虚拟屏的结构化无障碍事件
     */
    fun eventsFor(displayId: Int): Flow<DisplayEvent> =
        _events.filter { it.displayId == displayId }

    /**
     * 订阅指定虚拟屏的原始 AccessibilityEvent 事件
     */
    fun rawEventsFor(displayId: Int): Flow<AccessibilityEvent> =
        _rawEvents.filter { it.displayId == displayId }.map { it.event }

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

    /**
     * 窗口变化的信号流（添加、移除、移动，包含输入法弹出收起）
     */
    fun windowChanges(): Flow<Unit> = _windowChanges

    /**
     * 通知事件流
     */
    fun notificationEvents(): Flow<NotificationEvent> = _notifications

    /**
     * 窗口每加上、拿掉、换页一次就加一（任何屏上的都算）；只用来判断「窗口自上次以来变没变」。
     */
    @JvmStatic
    fun windowGeneration(): Long = _windowGeneration.get()
}
