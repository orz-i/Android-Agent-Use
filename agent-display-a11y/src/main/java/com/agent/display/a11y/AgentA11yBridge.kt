package com.agent.display.a11y

import android.content.Context
import android.content.Intent
import android.provider.Settings
import com.agent.display.a11y.model.A11yNode

/**
 * Agent 无障碍扩展统一外观门面。
 *
 * 为第三方 Agent 开发者提供极简的一站式接口：
 * 随时获取虚拟屏上的语义树、按文本或 ID 定位控件并直接分发手势，
 * 作为大模型视觉定位的免截图/轻量级辅助通道。
 */
class AgentA11yBridge(
    val windowInspector: DisplayWindowInspector = DisplayWindowInspector(),
    val gestureDispatcher: DisplayGestureDispatcher = DisplayGestureDispatcher(),
    val eventStream: DisplayEventStream = DisplayEventStream
) {

    /**
     * 无障碍服务当前是否已开启并正常连接
     */
    val isConnected: Boolean
        get() = AgentAccessibilityService.isConnected

    /**
     * 构建跳转至系统无障碍设置页的 Intent
     */
    fun createSettingsIntent(): Intent =
        Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }

    /**
     * 引导用户打开系统无障碍设置页面
     */
    fun openSettingsPage(context: Context) {
        context.startActivity(createSettingsIntent())
    }

    /**
     * 获取指定虚拟屏当前完整的无障碍语义层级树
     */
    fun dumpHierarchy(displayId: Int): List<A11yNode> =
        windowInspector.inspect(displayId)

    /**
     * 在指定屏幕上查找包含目标文本的节点
     */
    fun findByText(displayId: Int, textQuery: String, exact: Boolean = false): A11yNode? =
        windowInspector.findFirstByText(displayId, textQuery, exact)

    /**
     * 在指定屏幕上查找包含目标资源 ID 的节点
     */
    fun findById(displayId: Int, idQuery: String): A11yNode? =
        windowInspector.findFirstById(displayId, idQuery)

    /**
     * 点击目标语义节点（以节点的中心坐标执行精准点击）
     */
    suspend fun clickNode(displayId: Int, node: A11yNode): Boolean =
        gestureDispatcher.tap(displayId, node.centerX.toFloat(), node.centerY.toFloat())

    /**
     * 在指定屏幕中通过文本检索并直接点击该节点
     */
    suspend fun clickText(displayId: Int, textQuery: String, exact: Boolean = false): Boolean {
        val targetNode = findByText(displayId, textQuery, exact) ?: return false
        return clickNode(displayId, targetNode)
    }

    /**
     * 在指定屏幕中通过 ID 检索并直接点击该节点
     */
    suspend fun clickId(displayId: Int, idQuery: String): Boolean {
        val targetNode = findById(displayId, idQuery) ?: return false
        return clickNode(displayId, targetNode)
    }

    /**
     * 向上滑动屏幕（通用手势快捷封装）
     */
    suspend fun swipeUp(displayId: Int, screenWidth: Int = 720, screenHeight: Int = 1600): Boolean {
        val midX = screenWidth / 2f
        val startY = screenHeight * 0.75f
        val endY = screenHeight * 0.25f
        return gestureDispatcher.swipe(displayId, midX, startY, midX, endY, durationMs = 300L)
    }

    /**
     * 向下滑动屏幕（通用手势快捷封装）
     */
    suspend fun swipeDown(displayId: Int, screenWidth: Int = 720, screenHeight: Int = 1600): Boolean {
        val midX = screenWidth / 2f
        val startY = screenHeight * 0.25f
        val endY = screenHeight * 0.75f
        return gestureDispatcher.swipe(displayId, midX, startY, midX, endY, durationMs = 300L)
    }

    companion object {
        @JvmStatic
        val default = AgentA11yBridge()

        @JvmStatic
        fun getInstance(): AgentA11yBridge = default
    }
}
