package com.agent.use.a11y

import android.view.accessibility.AccessibilityNodeInfo
import android.view.accessibility.AccessibilityWindowInfo
import com.agent.use.a11y.model.A11yNode
import android.graphics.Rect

/**
 * 页面结构签名提取器。
 *
 * 支持三类输入源，共享同一套静态骨架分离与 64 位 SimHash 算法：
 * 1. [ScreenNodeDescriptor]：轻量纯 JVM 描述器（供 Mika `ScreenReader` 等已完成树过滤的调用方直接复用，无需二次遍历系统树）；
 * 2. [A11yNode]：AAU 无障碍不可变快照树；
 * 3. [AccessibilityWindowInfo] / [AccessibilityNodeInfo]：原生系统无障碍窗口与节点树。
 */
object ScreenSignatureExtractor {
    private const val DEFAULT_MAX_DEPTH = 80
    private const val MAX_STATIC_TEXT_LEN = 24
    private const val MAX_ANCHORS = 16
    private const val MAX_RESOURCE_IDS = 24
    private const val SYSTEM_UI_PACKAGE = "com.android.systemui"

    private const val FNV_OFFSET = -0x340d631b7bdddcdbL
    private const val FNV_PRIME = 0x100000001b3L

    /** 剥离末尾括号或加号形式的未读角标，例如 `微信(3)`、`微信 (99+)`、`消息[5]`、`消息 99+`。 */
    private val TRAILING_BADGE_PAREN = Regex("\\s*[(\\[（【]\\s*[0-9０-９]+\\+?\\s*[)\\]）】]$")
    private val TRAILING_BADGE_PLUS = Regex("[\\s·•]+\\+?[0-9０-９]+\\+$")

    /** 含数字、货币符号、百分比等易变内容不进入静态锚点与结构指纹。 */
    private val VOLATILE_CHARS = Regex("[0-9０-９¥￥$€£%]")

    /** 纯分隔符或标点占位不作为锚点文本。 */
    private val SEPARATOR_ONLY = Regex("^[\\s·•|/\\\\,:;。，、\\-_]+$")

    /** 常见相对时间词。 */
    private val RELATIVE_TIME_WORDS = setOf("刚刚", "昨天", "前天", "just now", "yesterday")

    private val LIST_ROLE_SUFFIXES = arrayOf("recyclerview", "listview", "gridview", "lazycolumn", "lazyrow", "lazyverticalgrid", "lazyhorizontalgrid")

    /** 将单个 [ScreenNodeDescriptor] 树提取为 [ScreenSignature]。 */
    fun extract(
        root: ScreenNodeDescriptor,
        packageName: String? = null,
        activityName: String? = null,
        screenWidth: Int = 0,
        screenHeight: Int = 0,
    ): ScreenSignature = extract(
        nodes = listOf(root),
        packageName = packageName,
        activityName = activityName,
        screenWidth = screenWidth,
        screenHeight = screenHeight,
    )

    /** 将 [ScreenNodeDescriptor] 森林或扁平节点列表提取为 [ScreenSignature]。 */
    fun extract(
        nodes: List<ScreenNodeDescriptor>,
        packageName: String? = null,
        activityName: String? = null,
        screenWidth: Int = 0,
        screenHeight: Int = 0,
    ): ScreenSignature {
        val normPkg = packageName?.trim()?.takeIf { it.isNotEmpty() }
        val normAct = ScreenSignature.normalizeActivityName(normPkg, activityName)
        val shortAct = shortActivityName(normPkg, activityName)

        if (nodes.isEmpty()) {
            return blankSignature(normPkg, normAct, shortAct, totalNodeCount = 0)
        }

        val (effW, effH) = resolveDimensions(nodes, screenWidth, screenHeight)
        val flatListContainers = collectFlatListContainerBounds(nodes, effW, effH)

        var totalNodeCount = 0
        val records = mutableListOf<ExtractedRecord>()

        fun visit(
            node: ScreenNodeDescriptor,
            depth: Int,
            inScrollable: Boolean,
            inheritedSelected: Boolean,
        ) {
            if (depth > DEFAULT_MAX_DEPTH) return
            totalNodeCount++

            if (!node.visible) {
                for (child in node.children) {
                    visit(child, depth + 1, inScrollable, inheritedSelected)
                }
                return
            }

            if (inScrollable) return
            if (node.children.isEmpty() && isContainedInFlatList(node, flatListContainers)) return

            val isContainer = isScrollableContentContainer(node, effW, effH)
            val effectiveSelected = node.selected || node.checked || inheritedSelected
            val normRole = normalizeRole(node.role)
            val rid = DisplayWindowInspector.readableResourceId(node.resourceId)
            val (region, bucket, centerXBucket) = computeLayoutBucket(node.bounds, effW, effH)

            if (isContainer) {
                records += ExtractedRecord(
                    isContainer = true,
                    normRole = normRole,
                    rid = rid,
                    label = null,
                    region = region,
                    bucket = bucket,
                    centerXBucket = centerXBucket,
                    clickable = node.clickable,
                    editable = false,
                    checkable = false,
                    effectiveSelected = false,
                )
                return
            }

            val label = extractStaticLabel(node)
            val meaningful = label != null || rid != null || node.clickable || node.editable || node.checkable || effectiveSelected
            if (meaningful) {
                records += ExtractedRecord(
                    isContainer = false,
                    normRole = normRole,
                    rid = rid,
                    label = label,
                    region = region,
                    bucket = bucket,
                    centerXBucket = centerXBucket,
                    clickable = node.clickable,
                    editable = node.editable,
                    checkable = node.checkable,
                    effectiveSelected = effectiveSelected,
                )
            }

            for (child in node.children) {
                visit(child, depth + 1, inScrollable = false, inheritedSelected = effectiveSelected)
            }
        }

        for (root in nodes) {
            visit(root, depth = 0, inScrollable = false, inheritedSelected = false)
        }

        if (records.isEmpty()) {
            return blankSignature(normPkg, normAct, shortAct, totalNodeCount = totalNodeCount)
        }

        val bottomRecords = records.filter { !it.isContainer && it.region == "BOT" }
        val hasEditableInBottom = bottomRecords.any { it.editable }
        val hasSelectedBottom = bottomRecords.any { it.effectiveSelected }
        val hasTabRoleInBottom = bottomRecords.any { "tab" in it.normRole.lowercase() }
        val distinctBottomSlots = bottomRecords
            .filter { it.clickable || it.effectiveSelected || it.label != null }
            .map { it.centerXBucket }
            .distinct()
            .size
        val isBottomNav = !hasEditableInBottom &&
            (hasSelectedBottom || hasTabRoleInBottom || distinctBottomSlots in 3..6)

        val features = LinkedHashMap<String, Double>()
        fun addFeature(token: String, weight: Double) {
            val prev = features[token]
            if (prev == null || weight > prev) {
                features[token] = weight
            }
        }

        val prioritizedAnchors = mutableListOf<AnchorCandidate>()
        val fallbackBottomAnchors = mutableListOf<String>()
        val collectedResourceIds = LinkedHashSet<String>()

        for ((index, rec) in records.withIndex()) {
            if (rec.isContainer) {
                addFeature("container:${rec.normRole}@${rec.bucket}", 2.0)
                rec.rid?.let {
                    collectedResourceIds += it
                    addFeature("container_id:$it", 3.0)
                }
                continue
            }

            val isUnselectedBottomNav = isBottomNav && rec.region == "BOT" && !rec.effectiveSelected

            rec.label?.let { lbl ->
                when {
                    isUnselectedBottomNav -> {
                        addFeature("bot_txt:$lbl", 0.5)
                        fallbackBottomAnchors += lbl
                    }
                    rec.effectiveSelected -> {
                        addFeature("sel_txt:$lbl", 6.0)
                        addFeature("txt:$lbl", 2.5)
                        prioritizedAnchors += AnchorCandidate(lbl, priority = 0, order = index)
                    }
                    rec.region == "TOP" -> {
                        if (!rec.clickable && !rec.editable) {
                            addFeature("title:$lbl", 4.5)
                            addFeature("txt:$lbl", 2.5)
                            prioritizedAnchors += AnchorCandidate(lbl, priority = 0, order = index)
                        } else {
                            addFeature("txt:$lbl", 3.5)
                            prioritizedAnchors += AnchorCandidate(lbl, priority = 1, order = index)
                        }
                    }
                    else -> {
                        addFeature("txt:$lbl", 2.5)
                        val p = if (rec.rid != null) 1 else 2
                        prioritizedAnchors += AnchorCandidate(lbl, priority = p, order = index)
                    }
                }
            }

            rec.rid?.let { rid ->
                collectedResourceIds += rid
                if (rec.effectiveSelected) {
                    addFeature("sel_id:$rid", 4.5)
                }
                addFeature("id:$rid", if (isUnselectedBottomNav) 0.8 else 3.0)
                addFeature("id_loc:$rid@${rec.bucket}", if (isUnselectedBottomNav) 0.4 else 1.5)
            }

            val flags = buildString {
                if (rec.clickable) append('C')
                if (rec.editable) append('E')
                if (rec.checkable) append('K')
                if (rec.effectiveSelected) append('S')
            }.ifEmpty { "V" }
            addFeature("struct:${rec.normRole}:$flags@${rec.bucket}", if (isUnselectedBottomNav) 0.4 else 1.2)
            if (rec.editable) {
                addFeature("input@${rec.bucket}", 2.5)
            }
        }

        if (features.isEmpty()) {
            return blankSignature(normPkg, normAct, shortAct, totalNodeCount = totalNodeCount)
        }

        val fingerprint = computeSimHash64(features)
        val anchors = if (prioritizedAnchors.isNotEmpty()) {
            prioritizedAnchors
                .sortedWith(compareBy<AnchorCandidate> { it.priority }.thenBy { it.order })
                .map { it.text }
                .distinct()
                .take(MAX_ANCHORS)
                .sorted()
        } else {
            fallbackBottomAnchors.distinct().take(MAX_ANCHORS).sorted()
        }
        val resourceIds = collectedResourceIds.sorted().take(MAX_RESOURCE_IDS)

        return ScreenSignature(
            fingerprint = fingerprint,
            sigId = ScreenSignature.formatSigId(shortAct, fingerprint, isBlank = false),
            packageName = normPkg,
            activity = normAct,
            shortActivity = shortAct,
            anchors = anchors,
            resourceIds = resourceIds,
            staticNodeCount = records.size,
            totalNodeCount = totalNodeCount,
            isBlank = false,
        )
    }

    /** 将单个 [A11yNode] 转换为 [ScreenNodeDescriptor]。 */
    fun A11yNode.toScreenNodeDescriptor(): ScreenNodeDescriptor = ScreenNodeDescriptor(
        role = role,
        text = if (isPassword) null else text,
        resourceId = viewId,
        bounds = ScreenBounds(bounds.left, bounds.top, bounds.right, bounds.bottom),
        clickable = isClickable,
        editable = isEditable || canSetText,
        scrollable = isScrollable,
        children = children.map { it.toScreenNodeDescriptor() },
        contentDescription = if (isPassword) null else contentDescription,
        hintText = hintText,
        isHint = isShowingHintText,
        checkable = isCheckable,
        checked = isChecked,
        selected = isSelected,
        enabled = isEnabled,
        password = isPassword,
        visible = true,
        isListContainer = isListRole(role),
    )

    /** 从单个 [A11yNode] 树提取 [ScreenSignature]。 */
    fun extractFromA11yNode(
        root: A11yNode,
        packageName: String? = null,
        activityName: String? = null,
        screenWidth: Int = 0,
        screenHeight: Int = 0,
    ): ScreenSignature = extractFromA11yNodes(
        roots = listOf(root),
        packageName = packageName,
        activityName = activityName,
        screenWidth = screenWidth,
        screenHeight = screenHeight,
    )

    /** 从一组 [A11yNode] 根节点提取 [ScreenSignature]。 */
    fun extractFromA11yNodes(
        roots: List<A11yNode>,
        packageName: String? = null,
        activityName: String? = null,
        screenWidth: Int = 0,
        screenHeight: Int = 0,
    ): ScreenSignature {
        val pkg = packageName ?: roots.firstNotNullOfOrNull { it.packageName?.takeIf(String::isNotBlank) }
        return extract(
            nodes = roots.map { it.toScreenNodeDescriptor() },
            packageName = pkg,
            activityName = activityName,
            screenWidth = screenWidth,
            screenHeight = screenHeight,
        )
    }

    /** 直接从原生 [AccessibilityNodeInfo] 根节点提取 [ScreenSignature]（不回收调用方传入的 [root] 本身）。 */
    fun extractFromAccessibilityNode(
        root: AccessibilityNodeInfo,
        packageName: String? = null,
        activityName: String? = null,
        screenWidth: Int = 0,
        screenHeight: Int = 0,
        maxDepth: Int = DEFAULT_MAX_DEPTH,
    ): ScreenSignature {
        val descriptor = convertAccessibilityNode(root, depth = 0, maxDepth = maxDepth)
        val pkg = packageName ?: root.packageName?.toString()?.takeIf { it.isNotBlank() }
        return extract(
            root = descriptor,
            packageName = pkg,
            activityName = activityName,
            screenWidth = screenWidth,
            screenHeight = screenHeight,
        )
    }

    /**
     * 直接从无障碍内容窗口列表提取 [ScreenSignature]。
     * 自动过滤输入法/浮层及非焦点系统状态栏/导航栏窗口，避免 SystemUI 干扰应用页面签名。
     */
    @Suppress("DEPRECATION")
    fun extractFromWindows(
        windows: List<AccessibilityWindowInfo>,
        activityName: String? = null,
        maxDepth: Int = DEFAULT_MAX_DEPTH,
    ): ScreenSignature {
        val content = DisplayWindowInspector.contentWindows(windows)
        if (content.isEmpty()) {
            return if (activityName.isNullOrBlank()) ScreenSignature.EMPTY
            else blankSignature(null, ScreenSignature.normalizeActivityName(null, activityName), shortActivityName(null, activityName), 0)
        }

        val topPkg = DisplayWindowInspector.topPackage(windows)
        var maxW = 0
        var maxH = 0
        val winRect = Rect()
        val descriptors = mutableListOf<ScreenNodeDescriptor>()
        var fallbackPkg: String? = null

        for (window in content) {
            val root = window.root ?: continue
            try {
                val rootPkg = root.packageName?.toString()?.takeIf { it.isNotBlank() }
                // 跳过未聚焦的 SystemUI（如状态栏/导航栏），但保留系统权限弹窗等聚焦窗口
                if ((window.type == AccessibilityWindowInfo.TYPE_SYSTEM || rootPkg == SYSTEM_UI_PACKAGE) &&
                    !window.isFocused && !window.isActive
                ) {
                    continue
                }
                if (fallbackPkg == null) fallbackPkg = rootPkg
                window.getBoundsInScreen(winRect)
                if (winRect.right > maxW) maxW = winRect.right
                if (winRect.bottom > maxH) maxH = winRect.bottom
                descriptors += convertAccessibilityNode(root, depth = 0, maxDepth = maxDepth)
            } finally {
                runCatching { root.recycle() }
            }
        }

        val pkg = topPkg ?: fallbackPkg
        return extract(
            nodes = descriptors,
            packageName = pkg,
            activityName = activityName,
            screenWidth = maxW,
            screenHeight = maxH,
        )
    }

    /** 清洗并归一化节点静态文本；遇到用户输入、长正文或易变数字/日期/金额/纯角标时返回 null。 */
    internal fun normalizeStaticText(raw: String?): String? {
        val collapsed = raw?.trim()?.replace(Regex("\\s+"), " ")?.takeIf { it.isNotEmpty() } ?: return null
        if (collapsed.length > MAX_STATIC_TEXT_LEN) return null

        var cleaned = collapsed
        while (true) {
            val next = cleaned
                .replace(TRAILING_BADGE_PAREN, "")
                .replace(TRAILING_BADGE_PLUS, "")
                .trim()
            if (next == cleaned) break
            cleaned = next
        }
        if (cleaned.isEmpty() || cleaned.length > MAX_STATIC_TEXT_LEN) return null
        if (cleaned.lowercase() in RELATIVE_TIME_WORDS) return null
        if (SEPARATOR_ONLY.matches(cleaned)) return null
        if (VOLATILE_CHARS.containsMatchIn(cleaned)) return null
        return cleaned
    }

    @Suppress("DEPRECATION")
    private fun convertAccessibilityNode(
        info: AccessibilityNodeInfo,
        depth: Int,
        maxDepth: Int,
    ): ScreenNodeDescriptor {
        val rect = Rect()
        info.getBoundsInScreen(rect)
        val childDescriptors = if (depth < maxDepth) {
            val count = info.childCount
            buildList(count) {
                for (i in 0 until count) {
                    val child = info.getChild(i) ?: continue
                    try {
                        add(convertAccessibilityNode(child, depth + 1, maxDepth))
                    } finally {
                        runCatching { child.recycle() }
                    }
                }
            }
        } else {
            emptyList()
        }

        val isPwd = info.isPassword
        return ScreenNodeDescriptor(
            role = DisplayWindowInspector.roleOf(info),
            text = if (isPwd) null else info.text?.toString(),
            resourceId = info.viewIdResourceName,
            bounds = ScreenBounds(rect.left, rect.top, rect.right, rect.bottom),
            clickable = info.isClickable,
            editable = DisplayWindowInspector.canSetText(info),
            scrollable = info.isScrollable,
            children = childDescriptors,
            contentDescription = if (isPwd) null else info.contentDescription?.toString(),
            hintText = info.hintText?.toString(),
            isHint = DisplayWindowInspector.showingHint(info),
            checkable = info.isCheckable,
            checked = info.isChecked,
            selected = info.isSelected,
            enabled = info.isEnabled,
            password = isPwd,
            visible = info.isVisibleToUser,
            isListContainer = DisplayWindowInspector.isList(info),
        )
    }

    private fun extractStaticLabel(node: ScreenNodeDescriptor): String? {
        if (node.password) {
            return normalizeStaticText(node.hintText)
        }
        if (node.editable) {
            val trimmedText = node.text?.trim()
            val trimmedHint = node.hintText?.trim()
            val showingPlaceholder = node.isHint ||
                (!trimmedText.isNullOrEmpty() && trimmedText == trimmedHint)
            val candidate = if (showingPlaceholder) trimmedText ?: trimmedHint else trimmedHint
            return normalizeStaticText(candidate)
        }
        val raw = node.text?.trim()?.takeIf { it.isNotEmpty() }
            ?: node.contentDescription?.trim()?.takeIf { it.isNotEmpty() }
            ?: node.hintText?.trim()?.takeIf { it.isNotEmpty() }
        return normalizeStaticText(raw)
    }

    private fun resolveDimensions(
        nodes: List<ScreenNodeDescriptor>,
        screenWidth: Int,
        screenHeight: Int,
    ): Pair<Int, Int> {
        if (screenWidth > 0 && screenHeight > 0) return screenWidth to screenHeight
        var maxR = 0
        var maxB = 0
        fun walk(n: ScreenNodeDescriptor) {
            if (n.visible && !n.bounds.isEmpty) {
                if (n.bounds.right > maxR) maxR = n.bounds.right
                if (n.bounds.bottom > maxB) maxB = n.bounds.bottom
            }
            for (c in n.children) walk(c)
        }
        for (n in nodes) walk(n)
        return (if (screenWidth > 0) screenWidth else maxR) to (if (screenHeight > 0) screenHeight else maxB)
    }

    private fun collectFlatListContainerBounds(
        nodes: List<ScreenNodeDescriptor>,
        effW: Int,
        effH: Int,
    ): List<FlatContainer> {
        val out = mutableListOf<FlatContainer>()
        for (n in nodes) {
            if (n.visible && n.children.isEmpty() && !n.bounds.isEmpty && isScrollableContentContainer(n, effW, effH)) {
                out += FlatContainer(n, n.bounds)
            }
        }
        return out
    }

    private fun isContainedInFlatList(
        node: ScreenNodeDescriptor,
        containers: List<FlatContainer>,
    ): Boolean {
        if (node.bounds.isEmpty || containers.isEmpty()) return false
        for (c in containers) {
            if (c.node !== node && c.bounds.contains(node.bounds)) return true
        }
        return false
    }

    private fun isScrollableContentContainer(
        node: ScreenNodeDescriptor,
        effW: Int,
        effH: Int,
    ): Boolean {
        if (!node.visible) return false
        if (node.isListContainer || isListRole(node.role)) return true
        if (!node.scrollable) return false
        if (isPagerRole(node.role)) return false
        if (isHorizontalTabStrip(node, effW, effH)) return false
        return true
    }

    private fun isListRole(role: String): Boolean {
        val lower = role.substringAfterLast('.').lowercase()
        return LIST_ROLE_SUFFIXES.any { lower.endsWith(it) || lower == it }
    }

    private fun isPagerRole(role: String): Boolean =
        "viewpager" in role.lowercase()

    private fun isHorizontalTabStrip(node: ScreenNodeDescriptor, effW: Int, effH: Int): Boolean {
        val lower = node.role.lowercase()
        if ("tab" in lower) return true
        if ("horizontalscrollview" in lower) return true
        if (effW > 0 && effH > 0 && !node.bounds.isEmpty && !isListRole(node.role)) {
            val thinHeight = node.bounds.height <= effH * 0.14
            val wideWidth = node.bounds.width >= effW * 0.50
            if (thinHeight && wideWidth) return true
        }
        return false
    }

    private fun normalizeRole(role: String): String {
        val short = role.substringAfterLast('.').trim().ifEmpty { "View" }
        return when {
            short.startsWith("AppCompat") && short.length > "AppCompat".length ->
                short.removePrefix("AppCompat")
            short.startsWith("Material") && short.length > "Material".length ->
                short.removePrefix("Material")
            else -> short
        }
    }

    private fun computeLayoutBucket(bounds: ScreenBounds, effW: Int, effH: Int): Triple<String, String, Int> {
        if (bounds.isEmpty || effW <= 0 || effH <= 0) {
            return Triple("ANY", "ANY", -1)
        }
        val cxRatio = (bounds.centerX.toDouble() / effW).coerceIn(0.0, 1.0)
        val cyRatio = (bounds.centerY.toDouble() / effH).coerceIn(0.0, 1.0)
        val region = when {
            cyRatio < 0.18 -> "TOP"
            cyRatio >= 0.85 -> "BOT"
            cyRatio < 0.50 -> "UP"
            else -> "LOW"
        }
        val xBand = when {
            cxRatio < 0.33 -> "L"
            cxRatio < 0.67 -> "C"
            else -> "R"
        }
        val slot = (cxRatio * 10).toInt().coerceIn(0, 9)
        return Triple(region, "$region-$xBand", slot)
    }

    private fun computeSimHash64(features: Map<String, Double>): Long {
        val bits = DoubleArray(64)
        for ((token, weight) in features) {
            val h = stableHash64(token)
            for (i in 0 until 64) {
                if (((h ushr i) and 1L) != 0L) bits[i] += weight else bits[i] -= weight
            }
        }
        var fp = 0L
        for (i in 0 until 64) {
            if (bits[i] > 0.0) fp = fp or (1L shl i)
        }
        return fp
    }

    /** 64 位 FNV-1a + SplitMix64 混洗，保证所有 64 位均具备强雪崩分布。 */
    private fun stableHash64(token: String): Long {
        var h = FNV_OFFSET
        for (c in token) {
            h = (h xor c.code.toLong()) * FNV_PRIME
        }
        h = (h xor (h ushr 30)) * -0x40a7b892e31b1a47L
        h = (h xor (h ushr 27)) * -0x6b2fb644ecceee15L
        return h xor (h ushr 31)
    }

    private fun blankSignature(
        packageName: String?,
        normActivity: String?,
        shortActivity: String?,
        totalNodeCount: Int,
    ): ScreenSignature {
        if (packageName == null && normActivity == null && shortActivity == null && totalNodeCount == 0) {
            return ScreenSignature.EMPTY
        }
        return ScreenSignature(
            fingerprint = 0L,
            sigId = ScreenSignature.formatSigId(shortActivity, 0L, isBlank = true),
            packageName = packageName,
            activity = normActivity,
            shortActivity = shortActivity,
            anchors = emptyList(),
            resourceIds = emptyList(),
            staticNodeCount = 0,
            totalNodeCount = totalNodeCount,
            isBlank = true,
        )
    }

    private class FlatContainer(val node: ScreenNodeDescriptor, val bounds: ScreenBounds)

    private class ExtractedRecord(
        val isContainer: Boolean,
        val normRole: String,
        val rid: String?,
        val label: String?,
        val region: String,
        val bucket: String,
        val centerXBucket: Int,
        val clickable: Boolean,
        val editable: Boolean,
        val checkable: Boolean,
        val effectiveSelected: Boolean,
    )

    private class AnchorCandidate(
        val text: String,
        val priority: Int,
        val order: Int,
    )
}
