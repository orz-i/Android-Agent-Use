package com.agent.use.ui

import com.agent.use.ui.RouteStep
import com.agent.use.ui.Selector
import com.agent.use.ui.ScreenSig
import com.agent.use.ui.ScreenSnapshot
import com.agent.use.ui.UiElement
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlin.math.abs
import kotlin.math.hypot
import kotlin.math.ln

/** 每个 App 在 Atlas 中保留的上限配置。 */
const val MAX_ATLAS_SCREENS = 200
const val MAX_ATLAS_EDGES = 1000
const val MAX_SCREEN_CONTROLS = 40
const val MAX_ATLAS_ANCHORS = 16
const val MAX_ATLAS_RESOURCE_IDS = 24
const val MAX_ATLAS_VERSIONS = 16
const val MAX_ATLAS_SHORTCUTS = 50
const val MAX_SHORTCUT_CANDIDATES = 40
const val MAX_SHORTCUT_STEPS = 10
const val MAX_SHORTCUT_CONSECUTIVE_MISSES = 3
const val MAX_ATLAS_CAPABILITIES = 8

/**
 * 虚拟入口节点 ID：表示「还没进入这个 App」的状态（桌面、另一个 App、或刚启动）。
 * 只把实际观察到的启动动作记成 `__entry__ --launch--> 落地页`，外链/通知不能代替启动证据。
 */
const val ENTRY_SIG_ID = "__entry__"

/** 入口边固定使用的工具：从外部进入 App 只能靠启动，target 为空、执行时补包名。 */
const val ATLAS_ENTRY_TOOL = "phone_launch_app"

/**
 * 单个页面上的高频/关键控件统计与语义说明。
 * [selector] 不包含敏感原文；[meaning] 由轻量模型补充或留空。
 */
@Serializable
data class AtlasControl(
    val selector: Selector,
    val meaning: String = "",
    val used: Int = 0,
    val noEffect: Int = 0,
    val lastUsedMs: Long = 0L,
)

/**
 * 单个页面节点。
 * - [sigId]：稳定节点主键（合并同类页时保留已有节点的 `sigId` 以维系边引用）；
 * - [titleSource]：标题来源（[TITLE_LLM] / [TITLE_ACTIVITY] / [TITLE_USER]）；
 * - [unverifiedAfterUpgrade]：检测到 App 升级到新版本后，旧版本遗留节点在被新版本命中前标为待核实。
 */
@Serializable
data class AtlasScreen(
    val sigId: String,
    val activity: String? = null,
    val shortActivity: String? = null,
    val fingerprint: Long = 0L,
    val anchors: List<String> = emptyList(),
    val resourceIds: List<String> = emptyList(),
    val title: String = "",
    val titleSource: String = TITLE_ACTIVITY,
    val appVersion: String? = null,
    val hits: Int = 1,
    val lastSeenMs: Long = 0L,
    val unverifiedAfterUpgrade: Boolean = false,
    val controls: List<AtlasControl> = emptyList(),
    /**
     * 在这一页上整段跑成功过的自动化工具名（`phone_watch_reward_videos` 这类），只记工具名，
     * 不记参数、不记页面内容。与 [controls] 不同：控件是「能点哪儿」，这里是「这一页有整段做法」。
     */
    val capabilities: List<String> = emptyList(),
) {
    /** 优先展示已有标题；空白时退回 Activity 短名或 `#<短哈希>`。 */
    fun displayTitle(): String = title.ifBlank { fallbackTitle() }

    /** 兜底标题：Activity 短名（如 `LauncherUI`），未知时为 `#<短哈希>`。 */
    fun fallbackTitle(): String =
        shortActivity?.takeIf { it.isNotBlank() } ?: ScreenSig.shortHashTag(sigId)

    /** 尚未由模型或用户命名，等待批量命名。 */
    fun needsNaming(): Boolean =
        title.isBlank() || (titleSource != TITLE_LLM && titleSource != TITLE_USER)

    /** 转为通用 [ScreenSig]，供结构相似度计算复用同一套口径。 */
    fun toScreenSig(packageName: String? = null): ScreenSig = ScreenSig(
        sigId = sigId,
        activity = activity,
        fingerprint = fingerprint,
        anchors = anchors,
        resourceIds = resourceIds,
        packageName = packageName,
        shortActivity = shortActivity,
        isBlank = fingerprint == 0L && anchors.isEmpty() && resourceIds.isEmpty(),
    )

    /** 按 LRU + 使用频次裁剪当前页面下保存的控件列表。 */
    fun compactedControls(maxControls: Int = MAX_SCREEN_CONTROLS): AtlasScreen {
        if (controls.size <= maxControls) return this
        val kept = AtlasEviction.evict(
            items = controls,
            limit = maxControls,
            recencyOf = { it.lastUsedMs },
            hitsOf = { it.used },
            tieKeyOf = { "${it.selector.role}|${it.selector.resourceId.orEmpty()}|${it.selector.name}|${it.selector.ordinal}" },
        )
        return copy(controls = kept)
    }

    /**
     * 记下「这一页上，[tool] 整段跑成功过」。只收形如 `phone_xxx` 的工具名（图谱存的是工具本身的
     * 身份，不是某次调用的参数），重复记只刷新时间，超过 [limit] 个时丢掉最旧的。
     */
    fun withCapability(tool: String, atMs: Long = 0L, limit: Int = MAX_ATLAS_CAPABILITIES): AtlasScreen {
        val clean = tool.trim()
        if (clean.length !in 3..40 || !CAPABILITY_NAME.matches(clean)) return this
        val bumped = copy(lastSeenMs = maxOf(lastSeenMs, atMs))
        if (clean in capabilities) return bumped
        return bumped.copy(capabilities = (capabilities + clean).takeLast(limit))
    }

    /** 图谱裁剪时同一条规则：能力列表也有上限，导入进来的超长列表在这里削掉。 */
    fun compactedCapabilities(limit: Int = MAX_ATLAS_CAPABILITIES): AtlasScreen =
        if (capabilities.size <= limit) this else copy(capabilities = capabilities.takeLast(limit))

    companion object {
        const val TITLE_LLM = "llm"
        const val TITLE_ACTIVITY = "activity"
        const val TITLE_USER = "user"

        /** 工具名：小写字母开头，只含小写字母、数字和下划线。挡掉任何像用户原文的东西。 */
        private val CAPABILITY_NAME = Regex("^[a-z][a-z0-9_]{2,39}$")
    }
}

/**
 * 页面之间的有向操作跳转边（同包内页面，或以 [ENTRY_SIG_ID] 为起点的入口边）。
 * [ok] 仅在任务通过 `LearnGate.done` 语义完成时累加；[weakOk] 在任务整体成功（`TaskState.Succeeded`）
 * 但未达到 Done 门禁时累加，用于让图谱在真实使用中能长出边；[miss] 在后续运行触发无效果/失败时累加。
 */
@Serializable
data class AtlasEdge(
    val fromSigId: String,
    val toSigId: String,
    val tool: String,
    val target: Selector? = null,
    val ok: Int = 0,
    val weakOk: Int = 0,
    val miss: Int = 0,
    val lastOkMs: Long = 0L,
    val lastAttemptMs: Long = 0L,
    val appVersion: String? = null,
    /** 本机是否实际观察过启动抵达该页；旧入口及导入入口默认未验证。 */
    val launchObserved: Boolean = false,
) {
    /** 是否是从 App 外部进入首页的入口边。 */
    fun isEntry(): Boolean = fromSigId == ENTRY_SIG_ID

    /** 成功强度：强成功计 1，弱成功计 0.5；用于提示排序与寻路边权。 */
    fun strength(): Double = ok + weakOk * 0.5

    /** 可靠边：至少一次成功，且成功强度不低于失败次数。 */
    fun isReliable(): Boolean = strength() > 0.0 && miss <= strength()
}

/**
 * L2 跨屏可复用子流程快捷（2–10 步，支持 `{1}`/`{2}` 槽位参数化）。
 * 从特定入口页 [entrySigId] 出发安全回放，遇到不可逆/支付、守卫告警或页面偏离时立即交还模型。
 */
@Serializable
data class AtlasShortcut(
    val id: String,
    val name: String,
    val description: String = "",
    val slots: Int = 0,
    val entrySigId: String,
    val steps: List<RouteStep>,
    val successes: Int = 0,
    val consecutiveMisses: Int = 0,
    val missStep: Int? = null,
    val disabled: Boolean = false,
    val appVersion: String? = null,
    val lastUsedMs: Long = 0L,
)

/**
 * 跨多次运行统计的候选子序列观测记录（仅用于挖掘 >= 2 次共现后晋升为 [AtlasShortcut]；导出分享包时剥离）。
 */
@Serializable
data class ShortcutCandidate(
    val signatureKey: String,
    val entrySigId: String,
    val steps: List<RouteStep>,
    val slots: Int = 0,
    val seenCount: Int = 1,
    val appVersion: String? = null,
    val lastSeenMs: Long = 0L,
)

/** 单个 App（按 [packageName] 划分）的离线页面导航地图。 */
@Serializable
data class AppAtlas(
    val packageName: String,
    val appLabel: String = "",
    val versionsSeen: List<String> = emptyList(),
    val screens: List<AtlasScreen> = emptyList(),
    val edges: List<AtlasEdge> = emptyList(),
    val lastUsedMs: Long = 0L,
    val shortcuts: List<AtlasShortcut> = emptyList(),
    val candidatePatterns: List<ShortcutCandidate> = emptyList(),
) {
    fun findScreen(sigId: String): AtlasScreen? = screens.firstOrNull { it.sigId == sigId }

    fun outgoingEdges(sigId: String): List<AtlasEdge> = edges.filter { it.fromSigId == sigId }

    /** 所有入口边（从 App 外部进入首页的边）。 */
    fun entryEdges(): List<AtlasEdge> = edges.filter { it.isEntry() }

    fun findShortcut(id: String): AtlasShortcut? = shortcuts.firstOrNull { it.id == id }

    /** 删除一个页面节点，同时清掉与之相关的边、候选序列和以它为入口的快捷流程。 */
    fun withoutScreen(sigId: String): AppAtlas = copy(
        screens = screens.filterNot { it.sigId == sigId },
        edges = edges.filterNot { it.fromSigId == sigId || it.toSigId == sigId },
        shortcuts = shortcuts.filterNot { it.entrySigId == sigId },
        candidatePatterns = candidatePatterns.filterNot { it.entrySigId == sigId },
    )

    fun activeShortcutsFor(sigId: String): List<AtlasShortcut> =
        shortcuts.filter { !it.disabled && it.entrySigId == sigId && it.steps.isNotEmpty() }

    /** 切换指定快捷流程的启停状态（重新启用时清零连续失败计数）。 */
    fun withShortcutDisabled(shortcutId: String, disabled: Boolean): AppAtlas = copy(
        shortcuts = shortcuts.map { sc ->
            if (sc.id != shortcutId) sc
            else if (disabled) sc.copy(disabled = true)
            else sc.copy(disabled = false, consecutiveMisses = 0, missStep = null)
        },
    )

    /** 删除指定快捷流程。 */
    fun withoutShortcut(shortcutId: String): AppAtlas = copy(
        shortcuts = shortcuts.filterNot { it.id == shortcutId },
    )

    /** 记录快捷流程一次执行的结果；连续偏离达到阈值后自动停用，交还确认时不计入偏离。 */
    fun recordShortcutOutcome(
        shortcutId: String,
        succeeded: Boolean,
        missStep: Int? = null,
        nowMs: Long = System.currentTimeMillis(),
    ): AppAtlas = copy(
        shortcuts = shortcuts.map { sc ->
            if (sc.id != shortcutId) sc
            else if (succeeded) {
                sc.copy(
                    successes = sc.successes + 1,
                    consecutiveMisses = 0,
                    missStep = null,
                    lastUsedMs = maxOf(sc.lastUsedMs, nowMs),
                )
            } else {
                val misses = sc.consecutiveMisses + 1
                sc.copy(
                    consecutiveMisses = misses,
                    missStep = missStep,
                    disabled = sc.disabled || misses >= MAX_SHORTCUT_CONSECUTIVE_MISSES,
                    lastUsedMs = maxOf(sc.lastUsedMs, nowMs),
                )
            }
        },
        lastUsedMs = maxOf(lastUsedMs, nowMs),
    )

    /** 记录单条导航边的失败/偏离次数（绝不递增 [AtlasEdge.ok]）。 */
    fun recordEdgeMiss(
        fromSigId: String,
        toSigId: String,
        tool: String,
        target: Selector?,
        nowMs: Long = System.currentTimeMillis(),
    ): AppAtlas = copy(
        edges = edges.map { e ->
            if (e.fromSigId == fromSigId && e.toSigId == toSigId && e.tool == tool && AtlasEviction.sameEdgeTarget(tool, e.target, target)) {
                e.copy(miss = e.miss + 1, lastAttemptMs = maxOf(e.lastAttemptMs, nowMs))
            } else e
        },
    )

    /**
     * 执行上限淘汰（默认每 App 最多 200 页、1000 条边、每页 40 个控件、50 个快捷流程）：
     * - 先对每页控件做 LRU + 频次裁剪；
     * - 超过上限的页面按 LRU + 命中数混合评分淘汰，同时自动移除悬空边与失效入口快捷流程；
     * - 超过上限的边与快捷流程按 LRU + 成功次数混合评分淘汰。
     */
    fun compacted(
        maxScreens: Int = MAX_ATLAS_SCREENS,
        maxEdges: Int = MAX_ATLAS_EDGES,
        maxControls: Int = MAX_SCREEN_CONTROLS,
        maxShortcuts: Int = MAX_ATLAS_SHORTCUTS,
        maxCandidates: Int = MAX_SHORTCUT_CANDIDATES,
    ): AppAtlas {
        val compactedScreens = screens.map { it.compactedControls(maxControls).compactedCapabilities() }
        val keptScreens = if (compactedScreens.size <= maxScreens) compactedScreens else {
            AtlasEviction.evict(
                items = compactedScreens,
                limit = maxScreens,
                recencyOf = { it.lastSeenMs },
                hitsOf = { it.hits },
                tieKeyOf = { it.sigId },
            )
        }
        val keptIds = keptScreens.mapTo(HashSet(keptScreens.size)) { it.sigId }
        val validEdges = edges.filter {
            (it.fromSigId == ENTRY_SIG_ID || it.fromSigId in keptIds) && it.toSigId in keptIds
        }
        val keptEdges = if (validEdges.size <= maxEdges) validEdges else {
            AtlasEviction.evict(
                items = validEdges,
                limit = maxEdges,
                recencyOf = { maxOf(it.lastOkMs, it.lastAttemptMs) },
                hitsOf = { it.ok * 2 + it.weakOk },
                tieKeyOf = { "${it.fromSigId}|${it.toSigId}|${it.tool}|${it.target?.name.orEmpty()}" },
            )
        }
        val validShortcuts = shortcuts.filter { it.entrySigId in keptIds && it.steps.isNotEmpty() }
        val keptShortcuts = if (validShortcuts.size <= maxShortcuts) validShortcuts else {
            AtlasEviction.evict(
                items = validShortcuts,
                limit = maxShortcuts,
                recencyOf = { it.lastUsedMs },
                hitsOf = { if (it.disabled) 0 else it.successes + 1 },
                tieKeyOf = { it.id },
            )
        }
        val validCandidates = candidatePatterns.filter { it.entrySigId in keptIds && it.steps.isNotEmpty() }
        val keptCandidates = if (validCandidates.size <= maxCandidates) validCandidates else {
            AtlasEviction.evict(
                items = validCandidates,
                limit = maxCandidates,
                recencyOf = { it.lastSeenMs },
                hitsOf = { it.seenCount },
                tieKeyOf = { it.signatureKey },
            )
        }
        return copy(
            screens = keptScreens,
            edges = keptEdges,
            shortcuts = keptShortcuts,
            candidatePatterns = keptCandidates,
        )
    }
}

/** [AppAtlas] 的 JSON 编解码器（忽略未知字段并输出默认值，保持前后向兼容）。 */
object AtlasCodec {
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }
    fun encode(atlas: AppAtlas): String = json.encodeToString(AppAtlas.serializer(), atlas)
    fun decode(raw: String): AppAtlas = json.decodeFromString(AppAtlas.serializer(), raw)
}

/** 控件选择器匹配与 LRU + 命中频次混合淘汰公共逻辑。 */
object AtlasEviction {
    private const val RECENCY_WEIGHT = 0.4
    private const val HIT_WEIGHT = 0.6
    private const val MIN_HIT_SCALE = 16
    private const val COARSE_CENTER_TOLERANCE = 60

    fun sameControl(a: Selector, b: Selector): Boolean {
        if (a.role != b.role || a.resourceId != b.resourceId || a.name != b.name) return false
        if (a.name.isNotBlank() || !a.resourceId.isNullOrBlank()) {
            return a.ordinal == b.ordinal || (a.uniqueAtRecord && b.uniqueAtRecord)
        }
        if (a.ordinal != b.ordinal) return false
        if (a.bounds.size == 4 && b.bounds.size == 4) {
            val ax = (a.bounds[0] + a.bounds[2]) / 2
            val ay = (a.bounds[1] + a.bounds[3]) / 2
            val bx = (b.bounds[0] + b.bounds[2]) / 2
            val by = (b.bounds[1] + b.bounds[3]) / 2
            return abs(ax - bx) <= COARSE_CENTER_TOLERANCE && abs(ay - by) <= COARSE_CENTER_TOLERANCE
        }
        return true
    }

    fun sameOptionalTarget(a: Selector?, b: Selector?): Boolean = when {
        a == null && b == null -> true
        a == null || b == null -> false
        else -> sameControl(a, b)
    }

    /** 输入值不参与身份；未知 resourceId 不是通配符，无 id 时还必须有位置证据。 */
    fun sameTextInputTarget(a: Selector?, b: Selector?): Boolean {
        if (a == null || b == null || a.role != b.role) return false
        val aId = a.resourceId?.takeIf { it.isNotBlank() }
        val bId = b.resourceId?.takeIf { it.isNotBlank() }
        if (aId != bId) return false
        if (aId == null && (a.bounds.size != 4 || b.bounds.size != 4)) return false
        return sameControl(a.copy(name = ""), b.copy(name = ""))
    }

    /** 输入类工具只比输入框本身,输入值不参与身份;其余工具按控件身份比。 */
    fun sameEdgeTarget(tool: String, a: Selector?, b: Selector?): Boolean =
        if (isTextInputTool(tool)) sameTextInputTarget(a, b) else sameOptionalTarget(a, b)

    /**
     * 按工具名认「这是往输入框里写字」。库不定义工具名,只认宿主普遍采用的 `*_type_text` / `*_clear_text` 后缀;
     * 宿主工具名不这么叫时,自己覆盖这段判断(见 README「图谱接入」)。
     */
    fun isTextInputTool(tool: String): Boolean = tool.endsWith("_type_text") || tool.endsWith("_clear_text")

    private const val NEAR_BOUNDS_DISTANCE = 150.0
    private val SLOT_REF = Regex("\\{(\\d+)\\}")

    /** 填入 `{n}` 槽位占位符；越界时返回 null。 */
    fun fillSlots(raw: String, slots: List<String>): String? {
        var invalid = false
        val replaced = SLOT_REF.replace(raw) { m ->
            val idx = m.groupValues[1].toIntOrNull()?.minus(1) ?: -1
            slots.getOrNull(idx) ?: run { invalid = true; "" }
        }
        return replaced.takeUnless { invalid }
    }

    /** 在当前快照 [snapshot] 上按与 Replayer 一致的严格唯一性/邻近坐标策略查找目标元素。 */
    fun findMatchingElement(snapshot: ScreenSnapshot, sel: Selector, slots: List<String> = emptyList()): UiElement? {
        val expectedName = fillSlots(sel.name, slots)?.trim() ?: return null
        val same = snapshot.elements.filter {
            it.role == sel.role &&
                it.resourceId == sel.resourceId &&
                (expectedName.isEmpty() || it.name.trim() == expectedName)
        }
        if (same.size == 1) return same.single()
        if (same.isEmpty() || sel.uniqueAtRecord || sel.bounds.size != 4) return null
        fun cx(b: List<Int>) = (b[0] + b[2]) / 2.0
        fun cy(b: List<Int>) = (b[1] + b[3]) / 2.0
        fun near(e: UiElement) =
            e.bounds.size == 4 && hypot(cx(e.bounds) - cx(sel.bounds), cy(e.bounds) - cy(sel.bounds)) <= NEAR_BOUNDS_DISTANCE
        val pick = same.getOrNull(sel.ordinal)?.takeIf(::near) ?: return null
        return pick.takeIf { same.count(::near) == 1 }
    }

    /** 按精确 `sigId` 或综合结构相似度（>= [threshold]）在 [screens] 中查找最佳匹配下标；无匹配返回 -1。 */
    fun findMatchingScreenIndex(
        screens: List<AtlasScreen>,
        pkg: String,
        sig: ScreenSig,
        threshold: Double = ScreenSig.DEFAULT_MATCH_THRESHOLD,
    ): Int {
        if (sig.isBlank) return -1
        if (sig.packageName != null && sig.packageName != pkg) return -1
        val exactIdx = screens.indexOfFirst {
            it.sigId == sig.sigId && ScreenSig.activitiesCompatible(pkg, it.activity, sig.activity)
        }
        if (exactIdx >= 0) return exactIdx

        var bestIdx = -1
        var bestScore = threshold
        for (i in screens.indices) {
            val score = sig.similarity(screens[i].toScreenSig(pkg))
            if (score >= bestScore) {
                bestScore = score
                bestIdx = i
            }
        }
        return bestIdx
    }

    fun <T> evict(
        items: List<T>,
        limit: Int,
        recencyOf: (T) -> Long,
        hitsOf: (T) -> Int,
        tieKeyOf: (T) -> String,
    ): List<T> {
        if (limit <= 0) return emptyList()
        if (items.size <= limit) return items
        val minT = items.minOf(recencyOf)
        val maxT = items.maxOf(recencyOf)
        val spanT = (maxT - minT).coerceAtLeast(1L).toDouble()
        val maxHits = items.maxOf(hitsOf).coerceAtLeast(MIN_HIT_SCALE)
        val logDenom = ln(maxHits.toDouble() + 1.0).coerceAtLeast(1e-9)

        fun score(item: T): Double {
            val recency = if (maxT == minT) 0.5 else (recencyOf(item) - minT).toDouble() / spanT
            val hit = ln(hitsOf(item).coerceAtLeast(0).toDouble() + 1.0) / logDenom
            return RECENCY_WEIGHT * recency + HIT_WEIGHT * hit
        }

        val keepIndices = items.indices.sortedWith(
            compareByDescending<Int> { score(items[it]) }
                .thenByDescending { recencyOf(items[it]) }
                .thenByDescending { hitsOf(items[it]) }
                .thenBy { tieKeyOf(items[it]) },
        ).take(limit).toHashSet()
        return items.filterIndexed { i, _ -> i in keepIndices }
    }
}
