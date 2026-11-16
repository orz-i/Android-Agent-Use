package com.agent.use.common.shell

import com.agent.use.common.LaunchOrigin

/**
 * 方案 1：当系统跳转确认/选择器文案本身未能写出目标应用包名（如「“微信读书”想要打开“微信读书”小程序」）时，
 * 从系统侧多源核验被挂起拦截的真实目标应用包名，绝不凭应用名字符串猜测。
 *
 * 数据源优先级（只读、零 UI 绕过，按最新且显式定向的线索命中即停）：
 * 1. [IntentSummary]（当前任务 `TaskInfo.baseIntent` 中的组件 / 包名 / 唯一自定义 Scheme URI）；
 * 2. `dumpsys activity activities`（按 [TargetLookupContext.taskId] 隔离）与 `dumpsys activity starter`（`mLastStarter`）；
 * 3. 近 [TargetLookupContext.windowMs]（默认 4s）内的系统日志（`ActivityTaskManager: START` / `OplusAppStartupManager`），须精确匹配发起方；
 * 4. `dumpsys activity intents`（仅限归属 `interstitialPackage` 或发起方的活跃 `startActivity` `PendingIntentRecord`）。
 */
object JumpTargetResolver {
    private const val FIRST_APPLICATION_UID = 10_000
    const val DEFAULT_LOG_WINDOW_MS: Long = 4_000L

    data class IntentSummary(
        val packageName: String? = null,
        val componentPackage: String? = null,
        val dataUri: String? = null,
    )

    data class TargetLookupContext(
        val taskId: Int,
        val interstitialPackage: String? = null,
        val initiatorPackage: String? = null,
        val initiatorUid: Int = LaunchOrigin.UNKNOWN_UID,
        val windowMs: Long = DEFAULT_LOG_WINDOW_MS,
    )

    private val PACKAGE_NAME_REGEX = Regex("""^[a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_]+)+$""")
    private val INTENT_BODY_REGEX = Regex("""(?:Intent\s*\{|intent\s*=\s*\{|requestIntent\s*=)([^\n}]+(?:\}|(?=\s*$)))""")
    private val CMP_REGEX = Regex("""\bcmp=([a-zA-Z0-9_.]+)/[^\s,}]+""")
    private val PKG_REGEX = Regex("""\bpkg=([a-zA-Z0-9_.]+)""")
    private val DAT_REGEX = Regex("""\bdat=([^\s,}]+)""")
    private val COMPONENT_INFO_REGEX = Regex("""ComponentInfo\{([a-zA-Z0-9_.]+)/[^}]+\}""")
    private val TARGET_PKG_KV_REGEX = Regex("""\btarget(?:Pkg|Package)=([a-zA-Z0-9_.]+)""")
    private val CALLING_UID_INLINE_REGEX = Regex("""\b(?:callingUid|mCallingUid)\s*=?\s*(-?\d+)\b""")
    private val CALLING_PKG_INLINE_REGEX = Regex("""\b(?:callingPackage|mCallingPackage)\s*=([^\s,}]+)""")

    private val LOGCAT_EPOCH_REGEX = Regex("""^\s*(\d+)\.(\d{3})\s+\d+\s+\d+\s+[A-Z]\s+([^:\s(]+)\s*(?:\([^)]*\))?:\s*(.*)$""")
    private val ATM_START_REGEX = Regex("""\bSTART\s+u\d+\s+\{([^}]+)\}.*?\bfrom\s+uid\s+(-?\d+)(?:\s*\(([^)]+)\))?""")
    private val OPLUS_BY_REGEX = Regex("""\bby\s+([a-zA-Z0-9_.]+)(?:\s+callingUid\s+(-?\d+))?""")
    private val OPLUS_PREVENT_REGEX = Regex("""\bprevent\s+start\s+([a-zA-Z0-9_.]+)""")

    private val PENDING_HEADER_REGEX = Regex("""^\s*#\d+:\s*PendingIntentRecord\{[^\s]+\s+([a-zA-Z0-9_.]+)\s+([^\s}]+)""")
    private val PENDING_UID_PKG_REGEX = Regex("""^\s*uid=(\d+)\s+packageName=([^\s]+)""")
    private val PENDING_REQUEST_INTENT_REGEX = Regex("""^\s*requestIntent=(.+)$""")

    private val IGNORED_PACKAGES = setOf("android", "null", "system", "com.android.shell")
    private val GENERIC_URI_SCHEMES = setOf(
        "http", "https", "content", "file", "package", "android-app",
        "about", "javascript", "data", "tel", "mailto", "sms", "smsto", "geo",
    )

    fun resolve(
        ctx: TargetLookupContext,
        baseIntent: IntentSummary? = null,
        nowEpochMs: Long = System.currentTimeMillis(),
        runShell: (Array<String>) -> Pair<Int, String>,
        resolveSchemeUri: (String) -> String? = { null },
        isPackageInstalled: (String) -> Boolean = { true },
    ): String? {
        fromIntentSummary(ctx, baseIntent, resolveSchemeUri, isPackageInstalled)?.let { return it }

        val activitiesDump = if (ctx.taskId >= 0) {
            runShell(arrayOf("dumpsys", "activity", "activities")).takeIf { it.first == 0 }?.second.orEmpty()
        } else {
            ""
        }
        val starterDump = runShell(arrayOf("dumpsys", "activity", "starter"))
            .takeIf { it.first == 0 }?.second.orEmpty()
        fromActivitiesOrStarter(ctx, activitiesDump, starterDump, resolveSchemeUri, isPackageInstalled)?.let { return it }

        val logcatDump = runShell(
            arrayOf(
                "logcat", "-b", "system", "-b", "main", "-v", "epoch", "-d", "-t", "150",
                "-s", "ActivityTaskManager:I", "OplusAppStartupManager:*", "SP.AppStartConfirmActivity:*", "*:S",
            ),
        ).takeIf { it.first == 0 }?.second.orEmpty()
        fromLogcat(ctx, logcatDump, nowEpochMs, resolveSchemeUri, isPackageInstalled)?.let { return it }

        val intentsDump = runShell(arrayOf("dumpsys", "activity", "intents"))
            .takeIf { it.first == 0 }?.second.orEmpty()
        return fromPendingIntents(ctx, intentsDump, resolveSchemeUri, isPackageInstalled)
    }

    @JvmStatic
    fun parseFromSources(
        ctx: TargetLookupContext,
        baseIntent: IntentSummary? = null,
        activitiesDump: String = "",
        starterDump: String = "",
        intentsDump: String = "",
        logcatDump: String = "",
        nowEpochMs: Long = 0L,
        resolveSchemeUri: (String) -> String? = { null },
        isPackageInstalled: (String) -> Boolean = { true },
    ): String? {
        fromIntentSummary(ctx, baseIntent, resolveSchemeUri, isPackageInstalled)?.let { return it }
        fromActivitiesOrStarter(ctx, activitiesDump, starterDump, resolveSchemeUri, isPackageInstalled)?.let { return it }
        fromLogcat(ctx, logcatDump, nowEpochMs, resolveSchemeUri, isPackageInstalled)?.let { return it }
        return fromPendingIntents(ctx, intentsDump, resolveSchemeUri, isPackageInstalled)
    }

    private fun fromIntentSummary(
        ctx: TargetLookupContext,
        summary: IntentSummary?,
        resolveSchemeUri: (String) -> String?,
        isPackageInstalled: (String) -> Boolean,
    ): String? {
        if (summary == null) return null
        acceptCandidate(summary.componentPackage, ctx, isPackageInstalled)?.let { return it }
        acceptCandidate(summary.packageName, ctx, isPackageInstalled)?.let { return it }
        return resolveCustomScheme(summary.dataUri, ctx, resolveSchemeUri, isPackageInstalled)
    }

    private fun fromActivitiesOrStarter(
        ctx: TargetLookupContext,
        activitiesDump: String,
        starterDump: String,
        resolveSchemeUri: (String) -> String?,
        isPackageInstalled: (String) -> Boolean,
    ): String? {
        if (ctx.taskId >= 0 && activitiesDump.isNotBlank()) {
            val taskLines = LaunchOriginResolver.extractTaskLines(activitiesDump, ctx.taskId)
            scanScopedIntentLines(taskLines, ctx, resolveSchemeUri, isPackageInstalled)?.let { return it }
        }
        if (starterDump.isNotBlank()) {
            val starterLines = LaunchOriginResolver.extractStarterSection(starterDump)
            if (starterMatchesContext(starterLines, ctx)) {
                scanScopedIntentLines(starterLines, ctx, resolveSchemeUri, isPackageInstalled)?.let { return it }
            }
        }
        return null
    }

    private fun fromLogcat(
        ctx: TargetLookupContext,
        logcatDump: String,
        nowEpochMs: Long,
        resolveSchemeUri: (String) -> String?,
        isPackageInstalled: (String) -> Boolean,
    ): String? {
        if (logcatDump.isBlank()) return null
        val lines = logcatDump.lineSequence().toList()
        for (i in lines.indices.reversed()) {
            val line = lines[i]
            val parsed = LOGCAT_EPOCH_REGEX.find(line)
            val lineEpochMs = if (parsed != null) {
                val sec = parsed.groupValues[1].toLongOrNull() ?: continue
                val ms = parsed.groupValues[2].toLongOrNull() ?: continue
                sec * 1_000L + ms
            } else {
                0L
            }
            if (parsed != null && nowEpochMs > 0L) {
                val ageMs = nowEpochMs - lineEpochMs
                if (ageMs < -1_500L || ageMs > ctx.windowMs) continue
            }
            val tag = parsed?.groupValues?.get(3).orEmpty()
            val body = parsed?.groupValues?.get(4) ?: line

            if (tag == "ActivityTaskManager" || body.contains("START u")) {
                val m = ATM_START_REGEX.find(body)
                if (m != null) {
                    val intentSpec = m.groupValues[1]
                    val uid = m.groupValues[2].toIntOrNull() ?: LaunchOrigin.UNKNOWN_UID
                    val callerPkg = m.groupValues[3].trim().takeIf { it.isNotEmpty() && it != "null" }
                    if (callerMatchesInitiator(uid, callerPkg, ctx)) {
                        extractFromIntentSpec(intentSpec, ctx, resolveSchemeUri, isPackageInstalled)?.let { return it }
                    }
                }
            }

            if (tag.contains("Startup") || tag.contains("AppStartConfirm") || body.contains("CHECK_ALLOW_START")) {
                val byMatch = OPLUS_BY_REGEX.find(body)
                val callerPkg = byMatch?.groupValues?.get(1)?.trim()
                val callerUid = byMatch?.groupValues?.get(2)?.toIntOrNull()
                    ?: CALLING_UID_INLINE_REGEX.find(body)?.groupValues?.get(1)?.toIntOrNull()
                    ?: LaunchOrigin.UNKNOWN_UID
                val hasCallerSignal = callerPkg != null || callerUid >= 0
                val callerOk = if (hasCallerSignal) {
                    callerMatchesInitiator(callerUid, callerPkg, ctx)
                } else {
                    ctx.interstitialPackage != null && body.contains(ctx.interstitialPackage)
                }
                if (!callerOk) continue

                TARGET_PKG_KV_REGEX.find(body)?.groupValues?.get(1)?.let { kv ->
                    acceptCandidate(kv, ctx, isPackageInstalled)?.let { return it }
                }
                COMPONENT_INFO_REGEX.find(body)?.groupValues?.get(1)?.let { compPkg ->
                    acceptCandidate(compPkg, ctx, isPackageInstalled)?.let { return it }
                }
                OPLUS_PREVENT_REGEX.find(body)?.groupValues?.get(1)?.let { preventPkg ->
                    acceptCandidate(preventPkg, ctx, isPackageInstalled)?.let { return it }
                }
                extractFromIntentSpec(body, ctx, resolveSchemeUri, isPackageInstalled)?.let { return it }
            }
        }
        return null
    }

    private fun fromPendingIntents(
        ctx: TargetLookupContext,
        intentsDump: String,
        resolveSchemeUri: (String) -> String?,
        isPackageInstalled: (String) -> Boolean,
    ): String? {
        if (intentsDump.isBlank()) return null
        if (ctx.interstitialPackage == null && ctx.initiatorPackage == null && ctx.initiatorUid < FIRST_APPLICATION_UID) {
            return null
        }

        var recordPkg: String? = null
        var recordType: String? = null
        var recordUid = LaunchOrigin.UNKNOWN_UID
        var requestIntentSpec: String? = null
        var canceled = false

        fun flushRecord(): String? {
            if (recordType == "startActivity" && !canceled && requestIntentSpec != null) {
                val ownerIsInterstitial = !ctx.interstitialPackage.isNullOrBlank() &&
                    recordPkg == ctx.interstitialPackage
                val ownerIsInitiator = (!ctx.initiatorPackage.isNullOrBlank() && recordPkg == ctx.initiatorPackage) ||
                    (ctx.initiatorUid >= FIRST_APPLICATION_UID && recordUid == ctx.initiatorUid)
                if (ownerIsInterstitial || ownerIsInitiator) {
                    extractFromIntentSpec(requestIntentSpec!!, ctx, resolveSchemeUri, isPackageInstalled)
                        ?.let { return it }
                }
            }
            recordPkg = null
            recordType = null
            recordUid = LaunchOrigin.UNKNOWN_UID
            requestIntentSpec = null
            canceled = false
            return null
        }

        for (rawLine in intentsDump.lineSequence()) {
            val header = PENDING_HEADER_REGEX.find(rawLine)
            if (header != null) {
                flushRecord()?.let { return it }
                recordPkg = header.groupValues[1]
                recordType = header.groupValues[2]
                continue
            }
            if (recordPkg == null) continue
            val uidMatch = PENDING_UID_PKG_REGEX.find(rawLine)
            if (uidMatch != null) {
                recordUid = uidMatch.groupValues[1].toIntOrNull() ?: LaunchOrigin.UNKNOWN_UID
                recordPkg = uidMatch.groupValues[2]
                continue
            }
            val intentMatch = PENDING_REQUEST_INTENT_REGEX.find(rawLine)
            if (intentMatch != null) {
                requestIntentSpec = intentMatch.groupValues[1]
                continue
            }
            if (rawLine.contains("canceled=true")) {
                canceled = true
            }
        }
        return flushRecord()
    }

    private fun starterMatchesContext(starterLines: List<String>, ctx: TargetLookupContext): Boolean {
        if (starterLines.isEmpty()) return false
        for (line in starterLines) {
            if (ctx.taskId >= 0 && (line.contains("taskId=${ctx.taskId}") || line.contains("#${ctx.taskId}") || line.contains(" t${ctx.taskId}"))) {
                return true
            }
            if (!ctx.interstitialPackage.isNullOrBlank() && line.contains(ctx.interstitialPackage)) {
                return true
            }
            val uid = CALLING_UID_INLINE_REGEX.find(line)?.groupValues?.get(1)?.toIntOrNull()
            val pkg = CALLING_PKG_INLINE_REGEX.find(line)?.groupValues?.get(1)
            if ((uid != null && ctx.initiatorUid >= FIRST_APPLICATION_UID && uid == ctx.initiatorUid) ||
                (!pkg.isNullOrBlank() && pkg == ctx.initiatorPackage)
            ) {
                return true
            }
        }
        return false
    }

    private fun scanScopedIntentLines(
        lines: List<String>,
        ctx: TargetLookupContext,
        resolveSchemeUri: (String) -> String?,
        isPackageInstalled: (String) -> Boolean,
    ): String? {
        for (line in lines) {
            TARGET_PKG_KV_REGEX.find(line)?.groupValues?.get(1)?.let { kv ->
                acceptCandidate(kv, ctx, isPackageInstalled)?.let { return it }
            }
            COMPONENT_INFO_REGEX.find(line)?.groupValues?.get(1)?.let { pkg ->
                acceptCandidate(pkg, ctx, isPackageInstalled)?.let { return it }
            }
            val intentBody = INTENT_BODY_REGEX.find(line)?.groupValues?.get(1)
            if (intentBody != null) {
                extractFromIntentSpec(intentBody, ctx, resolveSchemeUri, isPackageInstalled)?.let { return it }
            }
        }
        return null
    }

    private fun extractFromIntentSpec(
        spec: String,
        ctx: TargetLookupContext,
        resolveSchemeUri: (String) -> String?,
        isPackageInstalled: (String) -> Boolean,
    ): String? {
        CMP_REGEX.find(spec)?.groupValues?.get(1)?.let { pkg ->
            acceptCandidate(pkg, ctx, isPackageInstalled)?.let { return it }
        }
        PKG_REGEX.find(spec)?.groupValues?.get(1)?.let { pkg ->
            acceptCandidate(pkg, ctx, isPackageInstalled)?.let { return it }
        }
        val uri = DAT_REGEX.find(spec)?.groupValues?.get(1)
        return resolveCustomScheme(uri, ctx, resolveSchemeUri, isPackageInstalled)
    }

    private fun resolveCustomScheme(
        uri: String?,
        ctx: TargetLookupContext,
        resolveSchemeUri: (String) -> String?,
        isPackageInstalled: (String) -> Boolean,
    ): String? {
        val raw = uri?.trim()?.takeIf { it.isNotEmpty() } ?: return null
        val scheme = raw.substringBefore(':', missingDelimiterValue = "").lowercase()
        if (scheme.isEmpty() || scheme in GENERIC_URI_SCHEMES) return null
        val resolved = resolveSchemeUri(raw) ?: return null
        return acceptCandidate(resolved, ctx, isPackageInstalled)
    }

    private fun callerMatchesInitiator(uid: Int, callerPkg: String?, ctx: TargetLookupContext): Boolean {
        if (!ctx.initiatorPackage.isNullOrBlank()) {
            if (callerPkg == ctx.initiatorPackage) return true
            if (ctx.initiatorUid >= FIRST_APPLICATION_UID && uid == ctx.initiatorUid) return true
            return false
        }
        if (ctx.initiatorUid >= FIRST_APPLICATION_UID) {
            return uid == ctx.initiatorUid
        }
        return false
    }

    private fun acceptCandidate(
        rawPkg: String?,
        ctx: TargetLookupContext,
        isPackageInstalled: (String) -> Boolean,
    ): String? {
        val pkg = rawPkg?.trim()?.trim('"', '\'') ?: return null
        if (!PACKAGE_NAME_REGEX.matches(pkg)) return null
        if (pkg in IGNORED_PACKAGES) return null
        if (pkg == ctx.interstitialPackage || pkg == ctx.initiatorPackage) return null
        return pkg.takeIf(isPackageInstalled)
    }
}
