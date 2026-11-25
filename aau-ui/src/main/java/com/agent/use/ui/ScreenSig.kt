package com.agent.use.ui

import kotlinx.serialization.Serializable

/**
 * 界面结构签名（纯 JVM 模型，与 Android 无障碍树解耦）。
 *
 * 与 `aau-a11y` 的 `ScreenSignature` 保持同口径：
 * - [fingerprint]：64 位 SimHash 结构指纹；
 * - [sigId]：形如 `LauncherUI#0123456789abcdef`（无 Activity 短名时 `#<hex>`，空屏为 `empty`）；
 * - [anchors] / [resourceIds]：剥离动态列表项与易变数字/金额后的静态骨架锚点与可读资源 ID；
 * - [isBlank]：空白/无窗口屏标记，空白屏不参与结构匹配。
 */
@Serializable
data class ScreenSig(
    val sigId: String,
    val activity: String? = null,
    val fingerprint: Long,
    val anchors: List<String> = emptyList(),
    val resourceIds: List<String> = emptyList(),
    val packageName: String? = null,
    val shortActivity: String? = null,
    val isBlank: Boolean = fingerprint == 0L && anchors.isEmpty() && resourceIds.isEmpty(),
) {
    /** 计算与另一个签名的 64 位 SimHash 汉明距离（0–64）。 */
    fun hammingDistance(other: ScreenSig): Int = hammingDistance(fingerprint, other.fingerprint)

    /** 仅基于 64 位 SimHash 汉明距离的纯结构相似度（0.0–1.0）。 */
    fun simHashSimilarity(other: ScreenSig): Double = simHashSimilarity(fingerprint, other.fingerprint)

    /**
     * 计算与另一个界面的综合相似度（0.0–1.0），与 `aau-a11y` 的 `ScreenSignature.computeSimilarity` 对齐：
     * - 任一为空白签名时返回 0.0；
     * - 双方包名均已知且不同，或规范化 Activity 均已知且不同时返回 0.0；
     * - 结合 64 位 SimHash 汉明相似度（0.75）与静态锚点/资源 ID 的 Jaccard 一致性（0.25）。
     */
    fun similarity(other: ScreenSig): Double = computeSimilarity(
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
    fun matches(other: ScreenSig, threshold: Double = DEFAULT_MATCH_THRESHOLD): Boolean {
        if (isBlank || other.isBlank) return false
        return similarity(other) >= threshold
    }

    companion object {
        const val DEFAULT_MATCH_THRESHOLD = 0.82
        const val SIMHASH_WEIGHT = 0.75
        const val TOKEN_JACCARD_WEIGHT = 0.25
        const val EMPTY_SIG_ID = "empty"

        /** 计算两个 64 位 SimHash 的汉明距离。 */
        fun hammingDistance(a: Long, b: Long): Int = java.lang.Long.bitCount(a xor b)

        /** 将 64 位 SimHash 汉明距离转换为 [0.0, 1.0] 相似度。 */
        fun simHashSimilarity(a: Long, b: Long): Double = 1.0 - hammingDistance(a, b) / 64.0

        /** 计算两个界面签名的综合相似度，与 `ScreenSignature.computeSimilarity` 保持一致。 */
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

        /** 判断两个 Activity（含一方为 null 或裸短名情形）是否兼容。 */
        fun activitiesCompatible(packageName: String?, actA: String?, actB: String?): Boolean {
            val normA = normalizeActivityName(packageName, actA) ?: return true
            val normB = normalizeActivityName(packageName, actB) ?: return true
            return activitiesMatch(normA, normB)
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
            val bareA = '.' !in clsA
            val bareB = '.' !in clsB
            return (bareA || bareB) && clsA.substringAfterLast('.') == clsB.substringAfterLast('.')
        }

        /**
         * 提取可读的 Activity 短名，例如 `com.tencent.mm/.ui.LauncherUI` -> `LauncherUI`。
         * 若 [activityName] 为空、空白或与 [packageName] 完全相同，则返回 null。
         */
        fun shortActivityName(packageName: String?, activityName: String?): String? {
            val raw = activityName?.trim()?.takeIf { it.isNotEmpty() } ?: return null
            val pkg = packageName?.trim()?.takeIf { it.isNotEmpty() }
            if (pkg != null && raw == pkg) return null
            val classPart = raw.substringAfterLast('/').trim()
            if (classPart.isEmpty()) return null
            return classPart.substringAfterLast('.').trim().ifEmpty { null }
        }

        /**
         * 规范化 Activity 全名（如 `com.pkg/.ui.Main` 与 `com.pkg.ui.Main` 统一为 `com.pkg/com.pkg.ui.Main`）。
         */
        fun normalizeActivityName(packageName: String?, activityName: String?): String? {
            val raw = activityName?.trim()?.takeIf { it.isNotEmpty() } ?: return null
            val pkg = packageName?.trim()?.takeIf { it.isNotEmpty() }
            if (raw == pkg) return null
            val slash = raw.indexOf('/')
            if (slash >= 0) {
                val rawPkg = raw.substring(0, slash).trim().ifEmpty { pkg.orEmpty() }
                val rawCls = raw.substring(slash + 1).trim()
                if (rawCls.isEmpty()) return null
                val fullCls = if (rawCls.startsWith(".") && rawPkg.isNotEmpty()) "$rawPkg$rawCls" else rawCls
                return if (rawPkg.isNotEmpty()) "$rawPkg/$fullCls" else fullCls
            }
            val fullCls = when {
                raw.startsWith(".") && pkg != null -> "$pkg$raw"
                '.' !in raw && pkg != null -> "$pkg.$raw"
                else -> raw
            }
            return if (pkg != null) "$pkg/$fullCls" else fullCls
        }

        /** 生成规范化的签名 ID（`<shortActivity>#<16位hex>` 或 `#<16位hex>`）。 */
        fun formatSigId(shortActivity: String?, fingerprint: Long, isBlank: Boolean = false): String {
            if (isBlank && shortActivity.isNullOrBlank() && fingerprint == 0L) return EMPTY_SIG_ID
            val hex = java.lang.Long.toUnsignedString(fingerprint, 16).padStart(16, '0')
            val prefix = shortActivity?.takeIf { it.isNotBlank() } ?: ""
            return "$prefix#$hex"
        }

        /** 取 [sigId] 中的短哈希展示串（`#<6位>`），无已知短名时作为兜底页面名。 */
        fun shortHashTag(sigId: String): String {
            val hash = sigId.substringAfter('#', sigId).trim().ifEmpty { EMPTY_SIG_ID }
            return "#${hash.take(6)}"
        }
    }
}
