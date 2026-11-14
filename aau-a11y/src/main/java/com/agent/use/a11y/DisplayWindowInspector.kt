package com.agent.use.a11y

import android.graphics.Rect
import android.view.accessibility.AccessibilityNodeInfo
import android.view.accessibility.AccessibilityWindowInfo
import com.agent.use.a11y.model.A11yNode

/**
 * 屏幕窗口与节点树遍历探测器。
 *
 * 核心功能：
 * 1. 按 displayId 获取并过滤屏幕上的有效内容窗口；
 * 2. 将易受系统回收影响的 AccessibilityNodeInfo 转换为不可变、结构扁平安全的 A11yNode 树；
 * 3. 提供按文本、ID、类名等多维度极速查询能力、64 位界面指纹计算与屏幕绝对坐标 (bounds) 映射。
 */
class DisplayWindowInspector(
    private val serviceProvider: () -> AgentAccessibilityService? = { AgentAccessibilityService.instance.value }
) {

    /**
     * 获取指定屏幕上按层级由高到低排序的内容窗口列表
     */
    fun getContentWindows(displayId: Int): List<AccessibilityWindowInfo> {
        val service = serviceProvider() ?: return emptyList()
        return contentWindows(service.windowsOn(displayId))
    }

    /**
     * 获取指定屏幕上最顶层应用窗口的包名
     */
    fun topPackage(displayId: Int): String? {
        val service = serviceProvider() ?: return null
        return topPackage(service.windowsOn(displayId))
    }

    /**
     * 计算指定屏幕当前窗口的 64 位 FNV-1a 界面指纹
     */
    fun windowHash(displayId: Int): Long {
        val service = serviceProvider() ?: return FNV_OFFSET
        return hash(service.windowsOn(displayId))
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

    @Suppress("DEPRECATION")
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
            children = childNodes,
            hintText = info.hintText?.toString(),
            stateDescription = info.stateDescription?.toString(),
            isShowingHintText = showingHint(info),
            isCheckable = info.isCheckable,
            isChecked = info.isChecked,
            canSetText = canSetText(info)
        )
    }

    companion object {
        private const val TAG = "DisplayWindowInspector"
        private const val MAX_INSPECT_DEPTH = 60
        private const val DEFAULT_MAX_DEPTH = 80
        private const val DEFAULT_AGGREGATE_MAX = 60
        private const val DEFAULT_AGGREGATE_DEPTH = 6
        const val FNV_OFFSET = -0x340d631b7bdddcdbL
        private const val FNV_PRIME = 0x100000001b3L

        private val READABLE_ID_CHARS = Regex("^[A-Za-z0-9_]{4,}$")
        private val READABLE_ID_LETTERS = Regex("[A-Za-z]{3}")

        private val SKIPPED_WINDOW_TYPES = setOf(
            AccessibilityWindowInfo.TYPE_INPUT_METHOD,
            AccessibilityWindowInfo.TYPE_ACCESSIBILITY_OVERLAY,
            AccessibilityWindowInfo.TYPE_MAGNIFICATION_OVERLAY,
            AccessibilityWindowInfo.TYPE_SPLIT_SCREEN_DIVIDER
        )

        /**
         * 从上到下排好的、属于界面内容的窗口（跳过输入法与无障碍浮层）。
         */
        fun contentWindows(windows: List<AccessibilityWindowInfo>): List<AccessibilityWindowInfo> =
            windows.filter { it.type !in SKIPPED_WINDOW_TYPES }.sortedByDescending { it.layer }

        /**
         * 最上面的应用窗口包名（跳过读不到根节点的浮层窗口）。
         */
        fun topPackage(windows: List<AccessibilityWindowInfo>): String? =
            contentWindows(windows)
                .filter { it.type == AccessibilityWindowInfo.TYPE_APPLICATION }
                .firstNotNullOfOrNull { it.root?.packageName?.toString() }

        /**
         * 控件的简短角色名。
         */
        fun roleOf(n: AccessibilityNodeInfo): String =
            n.className?.toString()?.substringAfterLast('.')?.ifEmpty { null } ?: "View"

        /**
         * 节点自己的可读名字：文字、内容描述或提示语。
         */
        fun ownLabel(n: AccessibilityNodeInfo): String? {
            val text = n.text?.toString()?.trim()
            if (!text.isNullOrEmpty()) return text
            val desc = n.contentDescription?.toString()?.trim()
            if (!desc.isNullOrEmpty()) return desc
            return n.hintText?.toString()?.trim()?.ifEmpty { null }
        }

        /**
         * 节点上显示的是提示语：系统标了 showingHintText，或没有实际文字且名字来自提示语，
         * 或报出的文字就是提示语本身。
         */
        fun showingHint(n: AccessibilityNodeInfo): Boolean {
            if (n.isShowingHintText) return true
            val hint = n.hintText?.toString()?.trim()
            if (hint.isNullOrEmpty()) return false
            val text = n.text?.toString()?.trim()
            return if (text.isNullOrEmpty()) n.contentDescription.isNullOrBlank() else text == hint
        }

        /**
         * 输入框正在显示的提示语；没在显示提示语时为 null。
         */
        fun placeholderOf(n: AccessibilityNodeInfo): String? =
            if (showingHint(n)) n.text?.toString()?.trim()?.ifEmpty { null } ?: n.hintText?.toString()?.trim() else null

        /**
         * 节点是否支持写入文本（isEditable 或暴露 ACTION_SET_TEXT）。
         */
        fun canSetText(n: AccessibilityNodeInfo): Boolean =
            n.isEditable || n.actionList.any { it.id == AccessibilityNodeInfo.ACTION_SET_TEXT }

        /**
         * 没名字的可点容器聚合子节点的文字当名字。
         */
        fun descendantLabel(
            n: AccessibilityNodeInfo,
            maxDepth: Int = DEFAULT_AGGREGATE_DEPTH,
            maxLength: Int = DEFAULT_AGGREGATE_MAX
        ): String {
            val parts = mutableListOf<String>()
            fun walk(c: AccessibilityNodeInfo, depth: Int) {
                if (depth > maxDepth || parts.joinToString(" ").length > maxLength) return
                for (i in 0 until c.childCount) {
                    val child = c.getChild(i) ?: continue
                    if (!child.isVisibleToUser) continue
                    ownLabel(child)?.let { if (it !in parts) parts += it }
                    walk(child, depth + 1)
                }
            }
            walk(n, 0)
            val joined = parts.joinToString(" ")
            return if (joined.length > maxLength) joined.take(maxLength) + "…" else joined
        }

        /**
         * 获取节点可读标签：优先取自身标签，若自身无标签且可点击则聚合子孙文本。
         */
        fun labelOf(n: AccessibilityNodeInfo, own: String? = ownLabel(n)): String =
            own ?: if (n.isClickable) descendantLabel(n) else ""

        /**
         * 提取可读的短资源 ID（如 `com.x:id/cart_icon` -> `cart_icon`；过滤混淆短名）。
         */
        fun readableResourceId(id: String?): String? {
            val short = id?.substringAfterLast('/') ?: return null
            return short.takeIf { READABLE_ID_CHARS.matches(it) && READABLE_ID_LETTERS.containsMatchIn(it) }
        }

        /**
         * 判断容器是否为列表类控件（子项会复用）。
         */
        fun isList(n: AccessibilityNodeInfo): Boolean {
            if (n.collectionInfo != null) return true
            val cls = n.className?.toString() ?: return false
            return cls.endsWith("RecyclerView") || cls.endsWith("ListView") || cls.endsWith("GridView")
        }

        /**
         * 判断节点是否位于列表类容器内。
         */
        fun inList(n: AccessibilityNodeInfo, maxDepth: Int = DEFAULT_MAX_DEPTH): Boolean {
            var p = n.parent
            var depth = 0
            while (p != null && depth++ < maxDepth) {
                if (isList(p)) return true
                p = p.parent
            }
            return false
        }

        /**
         * 判动作效果用的节点状态签名（覆盖勾选、选中、可用、焦点、光标选区）。
         */
        @Suppress("DEPRECATION")
        fun nodeStateSignature(n: AccessibilityNodeInfo): String =
            "${n.isChecked}${n.isSelected}${n.isEnabled}${n.isFocused}${n.textSelectionStart}:${n.textSelectionEnd}"

        /**
         * 计算 64 位 FNV-1a 指纹混合步进。
         */
        fun mixHash(h0: Long, vararg parts: Any?): Long {
            var h = h0
            for (p in parts) {
                val s = p?.toString() ?: "\u0000"
                for (c in s) h = (h xor c.code.toLong()) * FNV_PRIME
                h = (h xor 0x1f) * FNV_PRIME
            }
            return h
        }

        /**
         * 只算界面指纹，不建元素表（动作前后比对用）。
         */
        fun hash(windows: List<AccessibilityWindowInfo>, maxDepth: Int = DEFAULT_MAX_DEPTH): Long {
            var hash = FNV_OFFSET
            val rect = Rect()
            fun visit(n: AccessibilityNodeInfo, depth: Int) {
                if (depth > maxDepth) return
                if (n.isVisibleToUser) {
                    n.getBoundsInScreen(rect)
                    hash = mixHash(
                        hash,
                        n.className,
                        n.text,
                        n.contentDescription,
                        rect.flattenToString(),
                        nodeStateSignature(n)
                    )
                }
                for (i in 0 until n.childCount) n.getChild(i)?.let { visit(it, depth + 1) }
            }
            for (w in contentWindows(windows)) w.root?.let { visit(it, 0) }
            return hash
        }
    }
}
