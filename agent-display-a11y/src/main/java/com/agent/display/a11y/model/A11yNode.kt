package com.agent.display.a11y.model

import android.graphics.Rect

/**
 * 无障碍无状态节点语义模型。
 *
 * 将系统层频繁复用/回收的 AccessibilityNodeInfo 转换为不可变、内存安全的快照结构，
 * 供 Agent 算法做元素定位、语义解析与手势决策，避免并发回收导致的 IllegalStateException。
 */
data class A11yNode(
    val text: String? = null,
    val contentDescription: String? = null,
    val viewId: String? = null,
    val className: String? = null,
    val packageName: String? = null,
    val bounds: Rect = Rect(),
    val isClickable: Boolean = false,
    val isEditable: Boolean = false,
    val isScrollable: Boolean = false,
    val isFocused: Boolean = false,
    val isSelected: Boolean = false,
    val isEnabled: Boolean = true,
    val isPassword: Boolean = false,
    val children: List<A11yNode> = emptyList()
) {
    val centerX: Int get() = bounds.centerX()
    val centerY: Int get() = bounds.centerY()

    /** 最佳可读标签：优先取 text，若为空取 contentDescription */
    val label: String
        get() = text?.takeIf { it.isNotBlank() }
            ?: contentDescription?.takeIf { it.isNotBlank() }
            ?: ""

    /**
     * 递归检索满足条件的全部节点
     */
    fun findNodes(predicate: (A11yNode) -> Boolean): List<A11yNode> {
        val result = mutableListOf<A11yNode>()
        fun walk(node: A11yNode) {
            if (predicate(node)) result.add(node)
            for (child in node.children) {
                walk(child)
            }
        }
        walk(this)
        return result
    }

    /**
     * 根据文字内容查找匹配的节点列表
     */
    fun findByText(query: String, exact: Boolean = false): List<A11yNode> = findNodes { node ->
        val candidate = node.label
        if (exact) candidate == query else candidate.contains(query, ignoreCase = true)
    }

    /**
     * 根据资源 ID (例如 "com.example.app:id/submit_button") 查找匹配的节点
     */
    fun findById(idQuery: String): List<A11yNode> = findNodes { node ->
        node.viewId?.contains(idQuery, ignoreCase = true) == true
    }

    /**
     * 根据类名 (例如 "android.widget.Button") 查找匹配的节点
     */
    fun findByClass(classQuery: String): List<A11yNode> = findNodes { node ->
        node.className?.contains(classQuery, ignoreCase = true) == true
    }
}
