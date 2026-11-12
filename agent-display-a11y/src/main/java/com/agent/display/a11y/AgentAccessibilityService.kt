package com.agent.display.a11y

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.AccessibilityServiceInfo
import android.content.Intent
import android.os.Build
import android.util.Log
import android.view.Display
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityWindowInfo
import com.agent.display.a11y.model.DisplayEvent
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * 通用 Agent 无障碍基础服务。
 *
 * 核心特性：
 * 1. 自动打上 FLAG_INCLUDE_NOT_IMPORTANT_VIEWS，防止宿主 App 将关键控件标为不重要而漏读；
 * 2. 具备完整的单例生命周期追踪与重连自愈机制；
 * 3. 多屏感知：自适应 Android 13+ 与早期系统的 displayId 解析，将事件分发至 DisplayEventStream。
 */
class AgentAccessibilityService : AccessibilityService() {

    override fun onServiceConnected() {
        super.onServiceConnected()
        serviceInfo?.let { info ->
            var flags = info.flags
            flags = flags or AccessibilityServiceInfo.FLAG_INCLUDE_NOT_IMPORTANT_VIEWS
            flags = flags or AccessibilityServiceInfo.FLAG_RETRIEVE_INTERACTIVE_WINDOWS
            flags = flags or AccessibilityServiceInfo.FLAG_REPORT_VIEW_IDS
            info.flags = flags
            serviceInfo = info
        }
        _instance.value = this
        Log.i(TAG, "AgentAccessibilityService connected.")
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent) {
        if (_instance.value !== this) return
        val displayId = resolveDisplayId(event)
        if (displayId == Display.INVALID_DISPLAY) return

        val displayEvent = DisplayEvent.from(displayId, event)
        DisplayEventStream.emitEvent(displayEvent)
    }

    override fun onInterrupt() {
        Log.w(TAG, "AgentAccessibilityService interrupted.")
    }

    override fun onUnbind(intent: Intent?): Boolean {
        Log.i(TAG, "AgentAccessibilityService unbound.")
        clearInstance()
        return super.onUnbind(intent)
    }

    override fun onDestroy() {
        Log.i(TAG, "AgentAccessibilityService destroyed.")
        clearInstance()
        super.onDestroy()
    }

    private fun clearInstance() {
        _instance.compareAndSet(this, null)
    }

    /**
     * 获取指定虚拟屏上的顶层窗口列表
     */
    fun windowsOn(displayId: Int): List<AccessibilityWindowInfo> {
        val allDisplays = windowsOnAllDisplays
        return allDisplays?.get(displayId).orEmpty()
    }

    /**
     * 解析无障碍事件所属的屏幕编号
     */
    private fun resolveDisplayId(event: AccessibilityEvent): Int {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            return event.displayId
        }
        val targetWindowId = event.windowId
        if (targetWindowId == -1) return Display.INVALID_DISPLAY

        val allDisplays = windowsOnAllDisplays ?: return Display.INVALID_DISPLAY
        for (i in 0 until allDisplays.size()) {
            val dId = allDisplays.keyAt(i)
            val windows = allDisplays.valueAt(i)
            if (windows.any { it.id == targetWindowId }) {
                return dId
            }
        }
        return Display.INVALID_DISPLAY
    }

    companion object {
        private const val TAG = "AgentA11yService"

        private val _instance = MutableStateFlow<AgentAccessibilityService?>(null)
        val instance: StateFlow<AgentAccessibilityService?> = _instance.asStateFlow()

        val isConnected: Boolean
            get() = _instance.value != null

        fun requireService(): AgentAccessibilityService =
            _instance.value ?: error("AgentAccessibilityService is not connected or enabled.")
    }
}
