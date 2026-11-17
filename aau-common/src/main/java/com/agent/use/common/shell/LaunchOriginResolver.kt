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
    private val LOGCAT_EPOCH_LINE = Regex("""^\s*(\d+)\.(\d{3})\s+\d+\s+\d+\s+[A-Z]\s+([^:\s(]+)\s*(?:\([^)]*\))?:\s*(.*)$""")
    private val ATM_START_LINE = Regex("""\bSTART\s+u\d+\s+\{([^}]*)\}.*?\bfrom\s+uid\s+(-?\d+)\s+\(([^),\s:]+)""")
    private val BAL_CALLER_UID_LINE = Regex("""\bcallingPackage:\s*([A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+);\s*callingPackageTargetSdk:\s*-?\d+;\s*callingUid:\s*(-?\d+)""")
    private val BAL_CALLER_TASK_LINE = Regex("""\bcallingPackage:\s*([A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+).*?\bmTargetRootTask:Task\{[^#]*#(\d+)\b""")
    private val ABORTED_RESULT_CODE = Regex("""\bresult\s+code=-\d+\b""")
    private val INTENT_CMP_PKG = Regex("""\bcmp=([a-zA-Z0-9_.]+)/""")
    private val INTENT_PKG = Regex("""\bpkg=([a-zA-Z0-9_.]+)""")

    private const val SYSTEM_UID = 1_000
    private const val ROOT_UID = 0
    private const val RECENT_LOG_WINDOW_MS = 5_000L

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
        parse(activitiesDump = dump, starterDump = null, taskId = taskId, targetPackage = null)

    /**
     * 结合 `dumpsys activity activities` 与可选 `dumpsys activity starter` 输出解析 [taskId] 的启动来源。
     */
    @JvmStatic
    fun parse(activitiesDump: String, starterDump: String?, taskId: Int): LaunchOrigin =
        parse(activitiesDump = activitiesDump, starterDump = starterDump, taskId = taskId, targetPackage = null)

    /**
     * 结合 `dumpsys activity activities` 与可选 `dumpsys activity starter` 解析 [taskId] 的启动来源，
     * 传入 [targetPackage] 时识别自启动遮蔽以便后续结合日志定位真实发起方。
     */
    @JvmStatic
    fun parse(activitiesDump: String, starterDump: String?, taskId: Int, targetPackage: String?): LaunchOrigin {
        if (taskId < 0) return LaunchOrigin.unknown()
        if (activitiesDump.isNotBlank()) {
            val fromActivities = parseActivitiesDump(activitiesDump, taskId, targetPackage)
            if (fromActivities.isKnown) return fromActivities
        }
        if (!starterDump.isNullOrBlank()) {
            val fromStarter = parseStarter(starterDump, taskId)
            if (fromStarter.isKnown) return fromStarter
        }
        return LaunchOrigin.unknown()
    }

    private fun parseActivitiesDump(dump: String, taskId: Int, targetPackage: String? = null): LaunchOrigin {
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

        // dumpsys activity activities 中 Hist 按从顶到底 (#N .. #0) 排列；优先选择非自启动、非系统、非桌面的外部发起方
        val top = records.first().origin
        if (top != null && !isSelfOrSystemOrigin(top, targetPackage) && !isLauncherLikePackage(top.packageName)) {
            return LaunchOrigin(top.uid, top.packageName, LaunchOrigin.CONFIDENCE_HIGH)
        }
        for (i in 1 until records.size) {
            val recOrigin = records[i].origin ?: continue
            if (!isSelfOrSystemOrigin(recOrigin, targetPackage) && !isLauncherLikePackage(recOrigin.packageName)) {
                return LaunchOrigin(recOrigin.uid, recOrigin.packageName, LaunchOrigin.CONFIDENCE_MEDIUM)
            }
        }
        // 若栈顶是目标自身自启动（如 WXBizEntryActivity）且栈底为历史桌面 Launcher，保留栈顶自启动交由 starter/logcat 追查
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
     * 解析 `logcat -b system -v epoch` 中的 `ActivityTaskManager` 启动与 PendingIntent 审计日志，
     * 在 `activities` / `starter` 被目标自启动或历史根记录遮蔽时找出最近 [maxAgeMs] 内的真实外部发起方。
     */
    @JvmStatic
    fun parseSystemLogcat(
        logcatDump: String,
        taskId: Int,
        targetPackage: String?,
        nowEpochMs: Long = -1L,
        maxAgeMs: Long = RECENT_LOG_WINDOW_MS,
    ): LaunchOrigin {
        if (logcatDump.isBlank()) return LaunchOrigin.unknown()
        val cleanTarget = targetPackage?.trim()?.takeIf { it.isNotEmpty() }
        if (cleanTarget == null && taskId < 0) return LaunchOrigin.unknown()

        val lines = logcatDump.lineSequence().toList()
        var refEpochMs = nowEpochMs
        if (refEpochMs <= 0L) {
            for (i in lines.indices.reversed()) {
                val epochMatch = LOGCAT_EPOCH_LINE.find(lines[i]) ?: continue
                val sec = epochMatch.groupValues[1].toLongOrNull() ?: continue
                val ms = epochMatch.groupValues[2].toLongOrNull() ?: continue
                val ts = sec * 1_000L + ms
                if (ts > refEpochMs) refEpochMs = ts
                break
            }
        }

        for (i in lines.indices.reversed()) {
            val rawLine = lines[i]
            val parsed = LOGCAT_EPOCH_LINE.find(rawLine)
            if (parsed != null && refEpochMs > 0L) {
                val sec = parsed.groupValues[1].toLongOrNull() ?: continue
                val ms = parsed.groupValues[2].toLongOrNull() ?: continue
                val ageMs = refEpochMs - (sec * 1_000L + ms)
                if (ageMs < -1_500L || ageMs > maxAgeMs) continue
            }
            val tag = parsed?.groupValues?.get(3).orEmpty()
            val body = parsed?.groupValues?.get(4) ?: rawLine
            if (tag.isNotEmpty() && !tag.startsWith("ActivityTaskManager")) continue
            if (ABORTED_RESULT_CODE.containsMatchIn(body)) continue

            ATM_START_LINE.find(body)?.let { m ->
                val intentSpec = m.groupValues[1]
                val callerUid = m.groupValues[2].toIntOrNull() ?: LaunchOrigin.UNKNOWN_UID
                val callerPkg = normalizePackage(m.groupValues[3])
                if (matchesTargetLine(body, intentSpec, taskId, cleanTarget) &&
                    isExternalNonSystemCaller(callerUid, callerPkg, cleanTarget)
                ) {
                    return LaunchOrigin(
                        uid = callerUid,
                        packageName = callerPkg,
                        confidence = if (callerUid >= 0) LaunchOrigin.CONFIDENCE_HIGH else LaunchOrigin.CONFIDENCE_MEDIUM,
                    )
                }
            }

            BAL_CALLER_UID_LINE.find(body)?.let { m ->
                val callerPkg = normalizePackage(m.groupValues[1])
                val callerUid = m.groupValues[2].toIntOrNull() ?: LaunchOrigin.UNKNOWN_UID
                if (matchesTargetLine(body, body, taskId, cleanTarget) &&
                    isExternalNonSystemCaller(callerUid, callerPkg, cleanTarget)
                ) {
                    return LaunchOrigin(
                        uid = callerUid,
                        packageName = callerPkg,
                        confidence = if (callerUid >= 0) LaunchOrigin.CONFIDENCE_HIGH else LaunchOrigin.CONFIDENCE_MEDIUM,
                    )
                }
            }

            BAL_CALLER_TASK_LINE.find(body)?.let { m ->
                val callerPkg = normalizePackage(m.groupValues[1])
                val targetTaskId = m.groupValues[2].toIntOrNull() ?: -1
                val matchesTask = taskId >= 0 && targetTaskId == taskId
                if ((matchesTask || matchesTargetLine(body, body, taskId, cleanTarget)) &&
                    isExternalNonSystemCaller(LaunchOrigin.UNKNOWN_UID, callerPkg, cleanTarget)
                ) {
                    return LaunchOrigin(
                        uid = LaunchOrigin.UNKNOWN_UID,
                        packageName = callerPkg,
                        confidence = LaunchOrigin.CONFIDENCE_MEDIUM,
                    )
                }
            }
        }
        return LaunchOrigin.unknown()
    }

    /**
     * 通过 Shell 执行全量 `dumpsys` 与近期 `ActivityTaskManager` 日志解析 [taskId] 的启动来源。
     * 不传递 `-p`，避免 ColorOS/Android 触发 App 级转储造成秒级 Binder 阻塞。
     */
    fun resolve(
        taskId: Int,
        packageName: String? = null,
        runShell: (Array<String>) -> Pair<Int, String>,
    ): LaunchOrigin = resolve(
        taskId = taskId,
        packageName = packageName,
        nowEpochMs = System.currentTimeMillis(),
        runShell = runShell,
    )

    fun resolve(
        taskId: Int,
        packageName: String? = null,
        nowEpochMs: Long,
        runShell: (Array<String>) -> Pair<Int, String>,
    ): LaunchOrigin {
        if (taskId < 0) return LaunchOrigin.unknown()

        val (actCode, actOut) = runShell(arrayOf("dumpsys", "activity", "activities"))
        val activitiesDump = if (actCode == 0) actOut else ""
        val fromActivities = if (activitiesDump.isNotBlank()) {
            parse(activitiesDump, starterDump = null, taskId = taskId, targetPackage = packageName)
        } else {
            LaunchOrigin.unknown()
        }
        if (fromActivities.isKnown &&
            !isSelfOrSystemOrigin(fromActivities, packageName) &&
            !isLauncherLikePackage(fromActivities.packageName)
        ) {
            return fromActivities
        }

        val (starterCode, starterOut) = runShell(arrayOf("dumpsys", "activity", "starter"))
        val fromStarter = if (starterCode == 0 && starterOut.isNotBlank()) {
            parseStarter(starterOut, taskId)
        } else {
            LaunchOrigin.unknown()
        }
        if (fromStarter.isKnown &&
            !isSelfOrSystemOrigin(fromStarter, packageName) &&
            !isLauncherLikePackage(fromStarter.packageName)
        ) {
            return fromStarter
        }

        val (logCode, logOut) = runShell(
            arrayOf(
                "logcat", "-b", "system", "-v", "epoch", "-d", "-t", "3000",
                "-s", "ActivityTaskManager:I", "*:S",
            ),
        )
        val fromLogcat = if (logCode == 0 && logOut.isNotBlank()) {
            parseSystemLogcat(logOut, taskId, packageName, nowEpochMs = nowEpochMs)
        } else {
            LaunchOrigin.unknown()
        }
        if (fromLogcat.isKnown) return fromLogcat

        if (fromStarter.isKnown && !isSelfOrSystemOrigin(fromStarter, packageName)) {
            return fromStarter
        }
        return if (fromActivities.isKnown) fromActivities else fromStarter
    }

    private fun isSelfOrSystemOrigin(origin: RecordOrigin, targetPackage: String?): Boolean {
        val pkg = origin.packageName
        if (!targetPackage.isNullOrBlank() && pkg.equals(targetPackage, ignoreCase = true)) return true
        return pkg == "android" || origin.uid == SYSTEM_UID
    }

    private fun isSelfOrSystemOrigin(origin: LaunchOrigin, targetPackage: String?): Boolean {
        val pkg = origin.packageName
        if (!targetPackage.isNullOrBlank() && pkg.equals(targetPackage, ignoreCase = true)) return true
        return pkg == "android" || origin.uid == SYSTEM_UID
    }

    private fun isLauncherLikePackage(pkg: String?): Boolean {
        val lower = pkg?.lowercase() ?: return false
        return "launcher" in lower || ".home" in lower
    }

    private fun isExternalNonSystemCaller(callerUid: Int, callerPkg: String?, targetPackage: String?): Boolean {
        if (callerPkg.isNullOrBlank()) return false
        if (!targetPackage.isNullOrBlank() && callerPkg.equals(targetPackage, ignoreCase = true)) return false
        if (callerPkg == "android" || callerPkg == "system") return false
        if (callerUid == SYSTEM_UID || callerUid == ROOT_UID) return false
        return true
    }

    private fun matchesTargetLine(fullLine: String, intentSpec: String, taskId: Int, targetPackage: String?): Boolean {
        if (taskId >= 0) {
            if (fullLine.contains("#$taskId ") ||
                fullLine.contains("#$taskId}") ||
                fullLine.contains(" t$taskId ") ||
                fullLine.contains(" t$taskId}")
            ) {
                return true
            }
        }
        if (targetPackage.isNullOrBlank()) return false
        val cmpPkg = INTENT_CMP_PKG.find(intentSpec)?.groupValues?.get(1)
        if (cmpPkg.equals(targetPackage, ignoreCase = true)) return true
        val explicitPkg = INTENT_PKG.find(intentSpec)?.groupValues?.get(1)
        if (explicitPkg.equals(targetPackage, ignoreCase = true)) return true
        return fullLine.contains(":$targetPackage")
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
