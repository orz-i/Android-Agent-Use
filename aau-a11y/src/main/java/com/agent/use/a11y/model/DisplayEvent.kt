package com.agent.use.a11y.model

import android.view.accessibility.AccessibilityEvent

/**
 * 屏幕无障碍事件封装模型。
 *
 * 携带所属 displayId，供订阅方按屏幕过滤窗口与控件状态跃迁。
 */
data class DisplayEvent(
    val displayId: Int,
    val eventType: Int,
    val packageName: String?,
    val className: String?,
    val text: String?,
    val timestamp: Long = System.currentTimeMillis()
) {
    val isWindowStateChange: Boolean
        get() = eventType == AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED ||
            eventType == AccessibilityEvent.TYPE_WINDOWS_CHANGED

    val isViewClicked: Boolean
        get() = eventType == AccessibilityEvent.TYPE_VIEW_CLICKED

    companion object {
        @JvmStatic
        fun from(displayId: Int, event: AccessibilityEvent): DisplayEvent {
            val textStr = event.text.joinToString(" ").ifBlank { null }
                ?: event.contentDescription?.toString()
            return DisplayEvent(
                displayId = displayId,
                eventType = event.eventType,
                packageName = event.packageName?.toString(),
                className = event.className?.toString(),
                text = textStr,
                timestamp = System.currentTimeMillis()
            )
        }
    }
}

/**
 * 通知事件模型。
 */
data class NotificationEvent(
    val packageName: String?,
    val text: String,
    val timestamp: Long = System.currentTimeMillis()
)
