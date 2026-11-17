package com.agent.use.a11y

/**
 * 纯 JVM 矩形边界，兼容像素坐标与归一化坐标（如 0–999），避免单元测试受限于 Android `Rect` 桩实现。
 */
data class ScreenBounds(
    val left: Int = 0,
    val top: Int = 0,
    val right: Int = 0,
    val bottom: Int = 0,
) {
    val width: Int get() = (right - left).coerceAtLeast(0)
    val height: Int get() = (bottom - top).coerceAtLeast(0)
    val centerX: Int get() = (left + right) / 2
    val centerY: Int get() = (top + bottom) / 2
    val isEmpty: Boolean get() = right <= left || bottom <= top

    /** 判断当前边界是否完整包含另一个非空边界。 */
    fun contains(other: ScreenBounds): Boolean =
        !isEmpty && !other.isEmpty &&
            other.left >= left && other.top >= top &&
            other.right <= right && other.bottom <= bottom

    companion object {
        @JvmField
        val EMPTY = ScreenBounds()

        /** 从 `[left, top, right, bottom]` 列表构建边界；长度不足 4 时返回 [EMPTY]。 */
        @JvmStatic
        fun fromList(bounds: List<Int>): ScreenBounds =
            if (bounds.size >= 4) ScreenBounds(bounds[0], bounds[1], bounds[2], bounds[3]) else EMPTY
    }
}

/**
 * 轻量级无障碍节点描述器，用于与底层 `AccessibilityNodeInfo` 解耦计算界面结构签名。
 * 调用方（如已完成树过滤与归一化的读屏器）可直接构造该描述器，无需重复遍历系统窗口树。
 */
data class ScreenNodeDescriptor(
    val role: String,
    val text: String? = null,
    val resourceId: String? = null,
    val bounds: ScreenBounds = ScreenBounds.EMPTY,
    val clickable: Boolean = false,
    val editable: Boolean = false,
    val scrollable: Boolean = false,
    val children: List<ScreenNodeDescriptor> = emptyList(),
    val contentDescription: String? = null,
    val hintText: String? = null,
    val isHint: Boolean = false,
    val checkable: Boolean = false,
    val checked: Boolean = false,
    val selected: Boolean = false,
    val enabled: Boolean = true,
    val password: Boolean = false,
    val visible: Boolean = true,
    val isListContainer: Boolean = false,
) {
    constructor(
        role: String,
        text: String? = null,
        resourceId: String? = null,
        bounds: List<Int>,
        clickable: Boolean = false,
        editable: Boolean = false,
        scrollable: Boolean = false,
        children: List<ScreenNodeDescriptor> = emptyList(),
        contentDescription: String? = null,
        hintText: String? = null,
        isHint: Boolean = false,
        checkable: Boolean = false,
        checked: Boolean = false,
        selected: Boolean = false,
        enabled: Boolean = true,
        password: Boolean = false,
        visible: Boolean = true,
        isListContainer: Boolean = false,
    ) : this(
        role = role,
        text = text,
        resourceId = resourceId,
        bounds = ScreenBounds.fromList(bounds),
        clickable = clickable,
        editable = editable,
        scrollable = scrollable,
        children = children,
        contentDescription = contentDescription,
        hintText = hintText,
        isHint = isHint,
        checkable = checkable,
        checked = checked,
        selected = selected,
        enabled = enabled,
        password = password,
        visible = visible,
        isListContainer = isListContainer,
    )
}

/**
 * 页面结构签名，用于识别应用内的页面/标签页状态。
 *
 * 将页面静态骨架（顶栏标题、标签选中态、底部导航、非滚动区按钮与静态标签、可读资源 ID 与粗粒度布局桶）
 * 聚合为 64 位 SimHash 指纹与排序去重的静态锚点，同时剔除列表动态条目、用户输入内容及数字/日期/金额/未读角标等易变文本。
 */
data class ScreenSignature(
    val fingerprint: Long,
    val sigId: String,
    val packageName: String? = null,
    val activity: String? = null,
    val shortActivity: String? = null,
    val anchors: List<String> = emptyList(),
    val resourceIds: List<String> = emptyList(),
    val staticNodeCount: Int = 0,
    val totalNodeCount: Int = 0,
    val isBlank: Boolean = fingerprint == 0L && staticNodeCount == 0 && anchors.isEmpty() && resourceIds.isEmpty(),
) {
    /** 计算与另一个签名的 64 位 SimHash 汉明距离（0–64）。 */
    fun hammingDistance(other: ScreenSignature): Int = hammingDistance(fingerprint, other.fingerprint)

    /** 仅基于 64 位 SimHash 汉明距离的纯结构相似度（0.0–1.0）。 */
    fun simHashSimilarity(other: ScreenSignature): Double = simHashSimilarity(fingerprint, other.fingerprint)

    /**
     * 计算与另一个界面的综合相似度（0.0–1.0）。
     * - 任一为空白/无窗口签名时返回 0.0；
     * - 双方包名均已知且不同，或规范化 Activity 均已知且不同时返回 0.0；
     * - 结合 64 位 SimHash 汉明相似度与静态锚点/资源 ID 的 Jaccard 一致性，准确区分单 Activity 多标签页（如微信 LauncherUI / Compose）。
     */
    fun similarity(other: ScreenSignature): Double = computeSimilarity(
        fpA = fingerprint,
        pkgA = packageName,
        actA = activity,
        anchorsA = anchors,
        resourceIdsA = resourceIds,
        isBlankA = isBlank,
        fpB = other.fingerprint,
        pkgB = other.packageName,
        actB = other.activity,
        anchorsB = other.anchors,
        resourceIdsB = other.resourceIds,
        isBlankB = other.isBlank,
    )

    /** 判断当前界面是否与 [other] 匹配（综合相似度不低于 [threshold]）。 */
    fun matches(other: ScreenSignature, threshold: Double = DEFAULT_MATCH_THRESHOLD): Boolean {
        if (isBlank || other.isBlank) return false
        return similarity(other) >= threshold
    }

    companion object {
        const val DEFAULT_MATCH_THRESHOLD = 0.82
        const val SIMHASH_WEIGHT = 0.75
        const val TOKEN_JACCARD_WEIGHT = 0.25

        @JvmField
        val EMPTY = ScreenSignature(
            fingerprint = 0L,
            sigId = "empty",
            isBlank = true,
        )

        /** 计算两个 64 位 SimHash 的汉明距离。 */
        @JvmStatic
        fun hammingDistance(a: Long, b: Long): Int = java.lang.Long.bitCount(a xor b)

        /** 将 64 位 SimHash 汉明距离转换为 [0.0, 1.0] 相似度。 */
        @JvmStatic
        fun simHashSimilarity(a: Long, b: Long): Double = 1.0 - hammingDistance(a, b) / 64.0

        /** 计算两个页面签名信息的综合相似度，供跨模块纯 JVM 逻辑保持完全一致的判定。 */
        @JvmStatic
        fun computeSimilarity(
            fpA: Long,
            pkgA: String?,
            actA: String?,
            anchorsA: Collection<String>,
            resourceIdsA: Collection<String>,
            isBlankA: Boolean,
            fpB: Long,
            pkgB: String?,
            actB: String?,
            anchorsB: Collection<String>,
            resourceIdsB: Collection<String>,
            isBlankB: Boolean,
        ): Double {
            if (isBlankA || isBlankB) return 0.0
            val normPkgA = pkgA?.trim()?.takeIf { it.isNotEmpty() }
            val normPkgB = pkgB?.trim()?.takeIf { it.isNotEmpty() }
            if (normPkgA != null && normPkgB != null && normPkgA != normPkgB) return 0.0

            val normActA = normalizeActivityName(normPkgA, actA)
            val normActB = normalizeActivityName(normPkgB, actB)
            if (normActA != null && normActB != null && !activitiesMatch(normActA, normActB)) return 0.0

            val simHash = simHashSimilarity(fpA, fpB)
            if (anchorsA.isEmpty() && resourceIdsA.isEmpty() && anchorsB.isEmpty() && resourceIdsB.isEmpty()) {
                return simHash
            }
            val tokensA = buildTokenSet(anchorsA, resourceIdsA)
            val tokensB = buildTokenSet(anchorsB, resourceIdsB)
            if (tokensA.isEmpty() || tokensB.isEmpty()) {
                return simHash
            }
            val unionSize = (tokensA union tokensB).size
            val jaccard = if (unionSize == 0) 1.0 else tokensA.intersect(tokensB).size.toDouble() / unionSize
            return SIMHASH_WEIGHT * simHash + TOKEN_JACCARD_WEIGHT * jaccard
        }

        private fun buildTokenSet(anchors: Collection<String>, resourceIds: Collection<String>): Set<String> {
            val out = HashSet<String>(anchors.size + resourceIds.size)
            for (a in anchors) out.add("a:$a")
            for (r in resourceIds) out.add("r:$r")
            return out
        }

        private fun activitiesMatch(normA: String, normB: String): Boolean {
            if (normA == normB) return true
            val clsA = normA.substringAfterLast('/')
            val clsB = normB.substringAfterLast('/')
            // 仅当其中一侧仅给出无点号的裸短名时，回退比较类名末段
            val bareA = '.' !in clsA
            val bareB = '.' !in clsB
            return (bareA || bareB) && clsA.substringAfterLast('.') == clsB.substringAfterLast('.')
        }

        /**
         * 提取可读的 Activity 短名，例如 `com.tencent.mm/.ui.LauncherUI` -> `LauncherUI`。
         */
        @JvmStatic
        fun shortActivityName(packageName: String?, activityName: String?): String? =
            com.agent.use.a11y.shortActivityName(packageName, activityName)

        /**
         * 规范化 Activity 全名（如 `com.pkg/.ui.Main` 与 `com.pkg.ui.Main` 统一为 `com.pkg/com.pkg.ui.Main`）。
         */
        @JvmStatic
        fun normalizeActivityName(packageName: String?, activityName: String?): String? {
            val raw = activityName?.trim()?.takeIf { it.isNotEmpty() } ?: return null
            val pkg = packageName?.trim()?.takeIf { it.isNotEmpty() }
            if (raw == pkg) return null
            val slash = raw.indexOf('/')
            if (slash >= 0) {
                val rawPkg = raw.substring(0, slash).trim().ifEmpty { pkg.orEmpty() }
                val rawCls = raw.substring(slash + 1).trim()
                if (rawCls.isEmpty()) return null
                val fullCls = when {
                    rawCls.startsWith(".") && rawPkg.isNotEmpty() -> "$rawPkg$rawCls"
                    else -> rawCls
                }
                return if (rawPkg.isNotEmpty()) "$rawPkg/$fullCls" else fullCls
            }
            val fullCls = when {
                raw.startsWith(".") && pkg != null -> "$pkg$raw"
                '.' !in raw && pkg != null -> "$pkg.$raw"
                else -> raw
            }
            return if (pkg != null) "$pkg/$fullCls" else fullCls
        }

        internal fun formatSigId(shortActivity: String?, fingerprint: Long, isBlank: Boolean): String {
            if (isBlank && shortActivity.isNullOrBlank() && fingerprint == 0L) return EMPTY.sigId
            val hex = java.lang.Long.toUnsignedString(fingerprint, 16).padStart(16, '0')
            val prefix = shortActivity?.takeIf { it.isNotBlank() } ?: ""
            return "$prefix#$hex"
        }
    }
}

/**
 * 提取 Activity 短名（例如 `com.tencent.mm/.ui.LauncherUI` -> `LauncherUI`，`com.a.MainActivity` -> `MainActivity`）。
 * 若 [activityName] 为空、空白或与 [packageName] 完全相同，则返回 null。
 */
fun shortActivityName(packageName: String?, activityName: String?): String? {
    val raw = activityName?.trim()?.takeIf { it.isNotEmpty() } ?: return null
    val pkg = packageName?.trim()?.takeIf { it.isNotEmpty() }
    if (pkg != null && raw == pkg) return null
    val classPart = raw.substringAfterLast('/').trim()
    if (classPart.isEmpty()) return null
    val short = classPart.substringAfterLast('.').trim()
    return short.ifEmpty { null }
}
