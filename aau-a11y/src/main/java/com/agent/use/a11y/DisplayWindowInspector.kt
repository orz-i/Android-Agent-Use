package com.agent.use.a11y

import android.graphics.Rect
import android.util.Log
import android.view.accessibility.AccessibilityNodeInfo
import android.view.accessibility.AccessibilityWindowInfo
import com.agent.use.a11y.model.A11yNode

/**
 * 屏幕窗口与节点树遍历探测器。
 *
 * 核心功能：
 * 1. 按 displayId 获取并过滤屏幕上的有效内容窗口；
 * 2. 将易受系统回收影响的 AccessibilityNodeInfo 转换为不可变、结构扁平安全的 A11yNode 树；
 * 3. 提供按文本、ID、类名等多维度极速查询能力与屏幕绝对坐标 (bounds) 映射。
 */
class DisplayWindowInspector(
    private val serviceProvider: () -> AgentAccessibilityService? = { AgentAccessibilityService.instance.value }
) {

    /**
     * 获取指定屏幕上按层级由高到低排序的内容窗口列表
     */
    fun getContentWindows(displayId: Int): List<AccessibilityWindowInfo> {
        val service = serviceProvider() ?: return emptyList()
        val windows = service.windowsOn(displayId)
        return windows
            .filter { it.type !in SKIPPED_WINDOW_TYPES }
            .sortedByDescending { it.layer }
    }

    /**
     * 抓取并构建指定屏幕的完整语义节点树
     */
    fun inspect(displayId: Int): List<A11yNode> {
        val contentWindows = getContentWindows(displayId)
        val result = mutableListOf<A11yNode>()

        for (window in contentWindows) {
            val root = window.root ?: continue
            try {
                val node = convertNode(root, depth = 0)
                if (node != null) {
                    result.add(node)
                }
            } finally {
                // 安全回收节点引用，避免无障碍服务内存泄漏
                runCatching { root.recycle() }
            }
        }
        return result
    }

    /**
     * 在指定屏幕上根据自定义条件检索所有匹配的节点
     */
    fun findNodes(displayId: Int, predicate: (A11yNode) -> Boolean): List<A11yNode> {
        val roots = inspect(displayId)
        val matches = mutableListOf<A11yNode>()
        for (root in roots) {
            matches.addAll(root.findNodes(predicate))
        }
        return matches
    }

    /**
     * 查找指定屏幕中第一个匹配文本内容的节点
     */
    fun findFirstByText(displayId: Int, textQuery: String, exact: Boolean = false): A11yNode? {
        val roots = inspect(displayId)
        for (root in roots) {
            val list = root.findByText(textQuery, exact)
            if (list.isNotEmpty()) return list.first()
        }
        return null
    }

    /**
     * 查找指定屏幕中第一个匹配资源 ID 的节点
     */
    fun findFirstById(displayId: Int, idQuery: String): A11yNode? {
        val roots = inspect(displayId)
        for (root in roots) {
            val list = root.findById(idQuery)
            if (list.isNotEmpty()) return list.first()
        }
        return null
    }

    /**
     * 获取指定屏幕中所有具备可交互能力的节点列表（可点击、可编辑、可滑动）
     */
    fun findInteractiveNodes(displayId: Int): List<A11yNode> {
        return findNodes(displayId) { it.isClickable || it.isEditable || it.isScrollable }
    }

    private fun convertNode(info: AccessibilityNodeInfo, depth: Int): A11yNode? {
        if (depth > MAX_INSPECT_DEPTH) return null
        if (!info.isVisibleToUser) return null

        val rect = Rect()
        info.getBoundsInScreen(rect)

        val childNodes = mutableListOf<A11yNode>()
        val count = info.childCount
        for (i in 0 until count) {
            val child = info.getChild(i) ?: continue
            try {
                val parsedChild = convertNode(child, depth + 1)
                if (parsedChild != null) {
                    childNodes.add(parsedChild)
                }
            } finally {
                runCatching { child.recycle() }
            }
        }

        return A11yNode(
            text = info.text?.toString(),
            contentDescription = info.contentDescription?.toString(),
            viewId = info.viewIdResourceName,
            className = info.className?.toString(),
            packageName = info.packageName?.toString(),
            bounds = rect,
            isClickable = info.isClickable,
            isEditable = info.isEditable,
            isScrollable = info.isScrollable,
            isFocused = info.isFocused,
            isSelected = info.isSelected,
            isEnabled = info.isEnabled,
            isPassword = info.isPassword,
            children = childNodes
        )
    }

    companion object {
        private const val TAG = "DisplayWindowInspector"
        private const val MAX_INSPECT_DEPTH = 60

        private val SKIPPED_WINDOW_TYPES = setOf(
            AccessibilityWindowInfo.TYPE_ACCESSIBILITY_OVERLAY,
            AccessibilityWindowInfo.TYPE_MAGNIFICATION_OVERLAY,
            AccessibilityWindowInfo.TYPE_SPLIT_SCREEN_DIVIDER
        )
    }
}
