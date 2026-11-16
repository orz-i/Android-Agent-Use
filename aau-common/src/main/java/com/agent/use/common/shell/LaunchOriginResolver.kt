package com.agent.use.common.shell

import com.agent.use.common.LaunchOrigin

/**
 * 通过 `dumpsys activity activities`（及必要时 `dumpsys activity starter`）解析指定任务的真实启动来源。
 *
 * 已针对真机（含 ColorOS 14 / Android 14）`dumpsys` 格式校验：
 * - 不使用 `-p` 过滤（`-p` 在后会被忽略，在前会触发 App 级 dump 造成秒级卡顿；全量仅 ~30-60ms）；
 * - 显式隔离嵌套子 `Task{... #id}` 与 `dumpsys activity starter` 中的 `mLastHomeActivityStartRecord`，绝不跨任务串读或盲猜。
 */
object LaunchOriginResolver {
    private val TASK_HEADER = Regex("""^(\s*)(?:\*\s*)?(?:Task|TaskRecord)\{[^#]*#(\d+)\b""")
    private val ACTIVITY_HEADER = Regex("""^(\s*)(?:\*\s*Hist\s+#\d+:\s*)?ActivityRecord\{""")
    private val HIST_TASK_TAG = Regex("""ActivityRecord\{[^}]*\bt(\d+)\b""")
    private val LAST_STARTER_HEADER = Regex("""^\s*mLastStarter\s*:""")
    private val HOME_STARTER_HEADER = Regex("""^\s*mLastHomeActivityStartRecord\s*:""")
    private val LAUNCHED_FROM_UID = Regex("""\b(?:mLaunchedFromUid|launchedFromUid)=(-?\d+)\b""")
    private val LAUNCHED_FROM_PKG = Regex("""\b(?:mLaunchedFromPackage|launchedFromPackage)=([^\s,}]+)""")
    private val REAL_CALLING_UID = Regex("""\b(?:realCallingUid|mRealCallingUid)=(-?\d+)\b""")
    private val CALLING_UID = Regex("""\b(?:mCallingUid|callingUid)=(-?\d+)\b""")
    private val CALLING_PKG = Regex("""\b(?:callingPackage|mCallingPackage)=([^\s,}]+)""")
    private val TASK_ID_INLINE = Regex("""\btaskId=(-?\d+)\b|\b(?:Task|TaskRecord)\{[^#]*#(\d+)\b|ActivityRecord\{[^}]*\bt(\d+)\b""")

    private data class RecordLines(
        val origin: RecordOrigin?,
        val callingOrigin: RecordOrigin?,
    )

    private data class RecordOrigin(
        val uid: Int,
        val packageName: String?,
    )

    /**
     * 解析 `dumpsys activity activities` 输出中指定 [taskId] 的启动来源。
     * 优先取任务内顶层 ActivityRecord 的 `launchedFromUid`/`launchedFromPackage`（高置信度），
     * 缺失时回退至其余 ActivityRecord / 根 ActivityRecord（中置信度），最后尝试 Record 内 Intent `mCallingUid`（低置信度）。
     */
    @JvmStatic
    fun parse(dump: String, taskId: Int): LaunchOrigin =
        parse(activitiesDump = dump, starterDump = null, taskId = taskId)

    /**
     * 结合 `dumpsys activity activities` 与可选 `dumpsys activity starter` 输出解析 [taskId] 的启动来源。
     */
    @JvmStatic
    fun parse(activitiesDump: String, starterDump: String?, taskId: Int): LaunchOrigin {
        if (taskId < 0) return LaunchOrigin.unknown()
        if (activitiesDump.isNotBlank()) {
            val fromActivities = parseActivitiesDump(activitiesDump, taskId)
            if (fromActivities.isKnown) return fromActivities
        }
        if (!starterDump.isNullOrBlank()) {
            val fromStarter = parseStarter(starterDump, taskId)
            if (fromStarter.isKnown) return fromStarter
        }
        return LaunchOrigin.unknown()
    }

    private fun parseActivitiesDump(dump: String, taskId: Int): LaunchOrigin {
        val taskLines = extractTaskLines(dump, taskId)
        if (taskLines.isEmpty()) return LaunchOrigin.unknown()

        val records = extractRecords(taskLines, taskId)
        if (records.isEmpty()) {
            val fallback = parseLaunchedOrigin(taskLines)
            if (fallback != null) {
                return LaunchOrigin(fallback.uid, fallback.packageName, LaunchOrigin.CONFIDENCE_MEDIUM)
            }
            val callingFallback = parseCallingOrigin(taskLines)
            if (callingFallback != null) {
                return LaunchOrigin(callingFallback.uid, callingFallback.packageName, LaunchOrigin.CONFIDENCE_LOW)
            }
            return LaunchOrigin.unknown()
        }

        // dumpsys activity activities 中 Hist 按从顶到底 (#N .. #0) 排列；index 0 为顶层，last 为根 ActivityRecord
        val top = records.first().origin
        if (top != null) {
            return LaunchOrigin(top.uid, top.packageName, LaunchOrigin.CONFIDENCE_HIGH)
        }
        val root = records.last().origin
        if (root != null) {
            return LaunchOrigin(root.uid, root.packageName, LaunchOrigin.CONFIDENCE_MEDIUM)
        }
        for (i in 1 until (records.size - 1)) {
            val middle = records[i].origin
            if (middle != null) {
                return LaunchOrigin(middle.uid, middle.packageName, LaunchOrigin.CONFIDENCE_MEDIUM)
            }
        }
        val topCalling = records.firstNotNullOfOrNull { it.callingOrigin }
        if (topCalling != null) {
            return LaunchOrigin(topCalling.uid, topCalling.packageName, LaunchOrigin.CONFIDENCE_LOW)
        }
        return LaunchOrigin.unknown()
    }

    internal fun extractTaskLines(dump: String, taskId: Int): List<String> {
        val lines = dump.lineSequence().toList()
        var taskStart = -1
        var taskIndent = -1
        for (i in lines.indices) {
            val match = TASK_HEADER.find(lines[i]) ?: continue
            val id = match.groupValues[2].toIntOrNull() ?: continue
            if (id == taskId) {
                taskStart = i
                taskIndent = match.groupValues[1].length
                break
            }
        }
        if (taskStart < 0) return emptyList()

        val collected = ArrayList<String>()
        collected += lines[taskStart]
        var skipChildTaskIndent = Int.MAX_VALUE
        for (i in (taskStart + 1) until lines.size) {
            val line = lines[i]
            if (line.isBlank()) {
                if (skipChildTaskIndent == Int.MAX_VALUE) collected += line
                continue
            }
            val indent = leadingSpaces(line)
            if (indent <= taskIndent) break

            val subTask = TASK_HEADER.find(line)
            if (subTask != null) {
                val subId = subTask.groupValues[2].toIntOrNull()
                if (subId != null && subId != taskId) {
                    if (indent < skipChildTaskIndent) {
                        skipChildTaskIndent = indent
                    }
                    continue
                } else {
                    skipChildTaskIndent = Int.MAX_VALUE
                }
            } else if (skipChildTaskIndent != Int.MAX_VALUE) {
                if (indent > skipChildTaskIndent) {
                    continue
                }
                skipChildTaskIndent = Int.MAX_VALUE
            }

            collected += line
        }
        return collected
    }

    private fun extractRecords(taskLines: List<String>, taskId: Int): List<RecordLines> {
        val recordStarts = ArrayList<Int>()
        for (i in taskLines.indices) {
            val line = taskLines[i]
            if (!ACTIVITY_HEADER.containsMatchIn(line)) continue
            val taggedTask = HIST_TASK_TAG.find(line)?.groupValues?.get(1)?.toIntOrNull()
            if (taggedTask != null && taggedTask != taskId) continue
            recordStarts += i
        }
        if (recordStarts.isEmpty()) return emptyList()

        val result = ArrayList<RecordLines>(recordStarts.size)
        for (idx in recordStarts.indices) {
            val start = recordStarts[idx]
            val end = if (idx + 1 < recordStarts.size) recordStarts[idx + 1] else taskLines.size
            val slice = taskLines.subList(start, end)
            result += RecordLines(
                origin = parseLaunchedOrigin(slice),
                callingOrigin = parseCallingOrigin(slice),
            )
        }
        return result
    }

    private fun parseLaunchedOrigin(lines: List<String>): RecordOrigin? {
        var uid = LaunchOrigin.UNKNOWN_UID
        var pkg: String? = null
        for (line in lines) {
            if (uid < 0) {
                LAUNCHED_FROM_UID.find(line)?.groupValues?.get(1)?.toIntOrNull()?.let {
                    if (it >= 0) uid = it
                }
            }
            if (pkg == null) {
                LAUNCHED_FROM_PKG.find(line)?.groupValues?.get(1)?.let { raw ->
                    pkg = normalizePackage(raw)
                }
            }
        }
        return RecordOrigin(uid, pkg).takeIf(::isValidOrigin)
    }

    private fun parseCallingOrigin(lines: List<String>): RecordOrigin? {
        var realCallingUid = LaunchOrigin.UNKNOWN_UID
        var callingUid = LaunchOrigin.UNKNOWN_UID
        var callingPkg: String? = null
        for (line in lines) {
            if (realCallingUid < 0) {
                REAL_CALLING_UID.find(line)?.groupValues?.get(1)?.toIntOrNull()?.takeIf { it >= 0 }?.let {
                    realCallingUid = it
                }
            }
            if (callingUid < 0) {
                CALLING_UID.find(line)?.groupValues?.get(1)?.toIntOrNull()?.takeIf { it >= 0 }?.let {
                    callingUid = it
                }
            }
            if (callingPkg == null) {
                CALLING_PKG.find(line)?.groupValues?.get(1)?.let { callingPkg = normalizePackage(it) }
            }
        }
        val uid = if (realCallingUid >= 0) realCallingUid else callingUid
        return RecordOrigin(uid, callingPkg).takeIf(::isValidOrigin)
    }

    /**
     * 解析 `dumpsys activity starter` 输出。
     * 优先提取 `mLastStarter:` 块（避免误读前置的 `mLastHomeActivityStartRecord:`），
     * 仅当块内明确归属 [taskId] 时返回来源，不盲猜。
     */
    @JvmStatic
    fun parseStarter(starterDump: String, taskId: Int): LaunchOrigin {
        if (taskId < 0 || starterDump.isBlank()) return LaunchOrigin.unknown()
        val lines = extractStarterSection(starterDump)
        if (lines.isEmpty()) return LaunchOrigin.unknown()

        var mentionsTask = false
        for (line in lines) {
            val taskMatch = TASK_ID_INLINE.find(line) ?: continue
            val id = (
                taskMatch.groupValues[1].ifEmpty {
                    taskMatch.groupValues[2].ifEmpty { taskMatch.groupValues[3] }
                }
                ).toIntOrNull()
            if (id == taskId) {
                mentionsTask = true
                break
            }
        }
        if (!mentionsTask) return LaunchOrigin.unknown()

        val launched = parseLaunchedOrigin(lines)
        if (launched != null) {
            return LaunchOrigin(launched.uid, launched.packageName, LaunchOrigin.CONFIDENCE_MEDIUM)
        }
        val calling = parseCallingOrigin(lines)
        if (calling != null) {
            return LaunchOrigin(calling.uid, calling.packageName, LaunchOrigin.CONFIDENCE_LOW)
        }
        return LaunchOrigin.unknown()
    }

    internal fun extractStarterSection(starterDump: String): List<String> {
        val lines = starterDump.lineSequence().toList()
        val lastStarterIdx = lines.indexOfFirst { LAST_STARTER_HEADER.containsMatchIn(it) }
        if (lastStarterIdx >= 0) {
            val baseIndent = leadingSpaces(lines[lastStarterIdx])
            val collected = ArrayList<String>()
            collected += lines[lastStarterIdx]
            for (i in (lastStarterIdx + 1) until lines.size) {
                val line = lines[i]
                if (line.isNotBlank() && leadingSpaces(line) <= baseIndent) break
                collected += line
            }
            return collected
        }
        // 兼容不包含 mLastStarter 标题的精简片段，但仍剔除 mLastHomeActivityStartRecord 区块
        val homeIdx = lines.indexOfFirst { HOME_STARTER_HEADER.containsMatchIn(it) }
        if (homeIdx < 0) return lines
        val baseIndent = leadingSpaces(lines[homeIdx])
        val filtered = ArrayList<String>(lines.size)
        var skippingHome = false
        for (i in lines.indices) {
            val line = lines[i]
            if (i == homeIdx) {
                skippingHome = true
                continue
            }
            if (skippingHome) {
                if (line.isBlank() || leadingSpaces(line) > baseIndent) continue
                skippingHome = false
            }
            filtered += line
        }
        return filtered
    }

    /**
     * 通过 Shell 执行全量 `dumpsys` 命令获取并解析 [taskId] 的启动来源。
     * 不传递 `-p`，避免 ColorOS/Android 触发 App 级转储造成秒级 Binder 阻塞。
     */
    fun resolve(
        taskId: Int,
        @Suppress("UNUSED_PARAMETER") packageName: String? = null,
        runShell: (Array<String>) -> Pair<Int, String>,
    ): LaunchOrigin {
        if (taskId < 0) return LaunchOrigin.unknown()

        val (actCode, actOut) = runShell(arrayOf("dumpsys", "activity", "activities"))
        val activitiesDump = if (actCode == 0) actOut else ""
        val fromActivities = if (activitiesDump.isNotBlank()) parse(activitiesDump, taskId) else LaunchOrigin.unknown()
        if (fromActivities.isKnown) return fromActivities

        val (starterCode, starterOut) = runShell(arrayOf("dumpsys", "activity", "starter"))
        if (starterCode == 0 && starterOut.isNotBlank()) {
            return parseStarter(starterOut, taskId)
        }
        return LaunchOrigin.unknown()
    }

    private fun isValidOrigin(origin: RecordOrigin): Boolean =
        origin.uid >= 0 || !origin.packageName.isNullOrBlank()

    private fun normalizePackage(raw: String): String? {
        val trimmed = raw.trim().trim('"', '\'')
        return if (trimmed.isEmpty() || trimmed == "null") null else trimmed
    }

    private fun leadingSpaces(line: String): Int {
        var count = 0
        while (count < line.length && line[count] == ' ') count++
        return count
    }
}
