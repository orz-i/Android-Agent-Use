package com.agent.use.common.network.plugin

import com.agent.use.common.network.HttpRequestEvent
import com.agent.use.common.network.HttpResponseEvent
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList

/** 插件包注册进注册表时使用的 id 前缀。内置包与用户放的包只差这个前缀。 */
const val EXTERNAL_PLUGIN_ID_PREFIX = "external."

/** 随 APK 分发、由 assets 安装到私有目录的插件包前缀。 */
const val BUILTIN_PLUGIN_ID_PREFIX = "builtin."

data class EbpfSslOffsetRule(
    val libSubstring: String,
    val writeOffset: Long,
    val readOffset: Long,
    val sniOffset: Long = 0L
)

data class EbpfCronetOffsetRule(
    val libSubstring: String,
    val createOffset: Long,
    val responseStartedOffset: Long,
    val readCompletedOffset: Long,
    val succeededOffset: Long
)

data class EbpfCronetAbiRule(
    val rawHeadersOffset: Int = 0x20,
    val ioBufferDataOffset: Int = 0x10,
    val stringLayoutMode: Int = 0,
    val vtableSlots: Triple<Int, Int, Int> = Triple(3, 4, 5),
    val jniSignatures: List<String> = emptyList()
)

/**
 * Declares a JNI bridge rule: intercept `RegisterNatives` in libart, resolve the
 * requested methods, and read their return value straight out of the ART heap.
 *
 * This is an observation-only channel — no injection, no code patching in the
 * target process. It is the only way to see plaintext that an app encrypts above
 * the TLS layer.
 *
 * @param libSubstring fragment of the owning library path, e.g. "libyzwg.so"
 * @param methodNames dynamically registered native methods to watch
 * @param captureReturn read the jobject returned by the method (assumed byte[]).
 *                      Return capture is the only mode the loader implements today;
 *                      the flag is reserved for argument-only rules.
 * @param expectJson reject payloads that do not start with '{' or '['
 * @param magic optional container magic (e.g. "BZPBlock") accepted in addition to JSON
 * @param maxBytes upper bound for a single array, guards against bad offsets
 */
data class JniHookRule(
    val libSubstring: String,
    val methodNames: List<String>,
    val captureReturn: Boolean = true,
    val expectJson: Boolean = true,
    val magic: String? = null,
    val maxBytes: Int = 4 * 1024 * 1024
) {
    fun toCliArgs(): List<String> {
        if (libSubstring.isBlank()) return emptyList()
        val names = methodNames.filter { it.isNotBlank() }
        if (names.isEmpty()) return emptyList()
        val args = ArrayList<String>(6)
        // Argument order is a contract with aau_ebpf_loader.c: `--jni-magic` and
        // `--jni-no-json` bind to the **most recent** `--jni-hook`, so the hook pair
        // must always be emitted first.
        args.add("--jni-hook")
        args.add("$libSubstring:${names.joinToString(",")}")
        if (!expectJson) args.add("--jni-no-json")
        magic?.takeIf { it.isNotBlank() }?.let {
            args.add("--jni-magic")
            args.add(it)
        }
        if (maxBytes in 1..(4 * 1024 * 1024)) {
            args.add("--jni-max-bytes")
            args.add(maxBytes.toString())
        }
        return args
    }
}

data class EbpfProbeProfile(
    val sslOffsetRules: List<EbpfSslOffsetRule> = emptyList(),
    val cronetOffsetRules: List<EbpfCronetOffsetRule> = emptyList(),
    val cronetAbiRule: EbpfCronetAbiRule? = null,
    val jniHookRules: List<JniHookRule> = emptyList(),
    val replaceBuiltinOffsets: Boolean = false,
    /**
     * 数据的另一半：`unknown-host` 补全与响应体解码管道。
     *
     * 探测规则（偏移、JNI 入口）只决定"能不能看到字节"，这里决定"看到之后怎么读"。
     * 两者都来自同一份 JSON，所以一个新 App 可以纯配置接入，不必重编 aau。
     */
    val declarative: DeclarativeConfig = DeclarativeConfig.EMPTY
) {
    fun toCliArgs(): List<String> {
        val args = ArrayList<String>()
        for (rule in sslOffsetRules) {
            if (rule.libSubstring.isNotBlank() && rule.writeOffset > 0 && rule.readOffset > 0) {
                args.add("--ssl-offsets")
                args.add(
                    "${rule.libSubstring}:0x${rule.writeOffset.toString(16)}:" +
                        "0x${rule.readOffset.toString(16)}:0x${rule.sniOffset.toString(16)}"
                )
            }
        }
        for (rule in cronetOffsetRules) {
            if (rule.libSubstring.isNotBlank() &&
                rule.createOffset > 0 &&
                rule.responseStartedOffset > 0 &&
                rule.readCompletedOffset > 0 &&
                rule.succeededOffset > 0
            ) {
                args.add("--cronet-offsets")
                args.add(
                    "${rule.libSubstring}:0x${rule.createOffset.toString(16)}:" +
                        "0x${rule.responseStartedOffset.toString(16)}:" +
                        "0x${rule.readCompletedOffset.toString(16)}:" +
                        "0x${rule.succeededOffset.toString(16)}"
                )
            }
        }
        cronetAbiRule?.let { abi ->
            args.add("--cronet-abi")
            args.add(
                "0x${abi.rawHeadersOffset.toString(16)}," +
                    "0x${abi.ioBufferDataOffset.toString(16)}," +
                    "${abi.stringLayoutMode}"
            )
            args.add("--cronet-slots")
            args.add("${abi.vtableSlots.first},${abi.vtableSlots.second},${abi.vtableSlots.third}")
            for (sig in abi.jniSignatures) {
                if (sig.isNotBlank()) {
                    args.add("--cronet-sig")
                    args.add(sig)
                }
            }
        }
        for (rule in jniHookRules) {
            args.addAll(rule.toCliArgs())
        }
        return args
    }

    fun toAbiCliArgs(): List<String> {
        val abi = cronetAbiRule ?: return emptyList()
        val args = ArrayList<String>()
        args.add("--cronet-abi")
        args.add(
            "0x${abi.rawHeadersOffset.toString(16)}," +
                "0x${abi.ioBufferDataOffset.toString(16)}," +
                "${abi.stringLayoutMode}"
        )
        args.add("--cronet-slots")
        args.add("${abi.vtableSlots.first},${abi.vtableSlots.second},${abi.vtableSlots.third}")
        for (sig in abi.jniSignatures) {
            if (sig.isNotBlank()) {
                args.add("--cronet-sig")
                args.add(sig)
            }
        }
        return args
    }

    companion object {
        fun fromJson(json: String): Map<String, EbpfProbeProfile> {
            val root = SimpleJsonReader(json).parseValue() as? Map<String, Any?> ?: return emptyMap()
            val result = LinkedHashMap<String, EbpfProbeProfile>()
            for ((pkg, rawProfile) in root) {
                val obj = rawProfile as? Map<String, Any?> ?: continue
                result[pkg] = parseProfileObject(obj)
            }
            return result
        }

        /**
         * 解析「单个包」的配置对象。
         *
         * 插件包（L3）里的 `ebpfProfile` 也走这条路——两处各写一份字段解读，迟早会出现
         * "文件里写了、加载时没读到" 这种最难查的偏差。
         */
        @Suppress("UNCHECKED_CAST")
        internal fun parseProfileObject(obj: Map<String, Any?>): EbpfProbeProfile {
            val sslRules = (obj["sslOffsetRules"] as? List<Any?>).orEmpty().mapNotNull { item ->
                val m = item as? Map<String, Any?> ?: return@mapNotNull null
                val sub = m["libSubstring"] as? String ?: return@mapNotNull null
                val write = parseLongValue(m["writeOffset"]) ?: return@mapNotNull null
                val read = parseLongValue(m["readOffset"]) ?: return@mapNotNull null
                val sni = parseLongValue(m["sniOffset"]) ?: 0L
                EbpfSslOffsetRule(sub, write, read, sni)
            }
            val cronetRules = (obj["cronetOffsetRules"] as? List<Any?>).orEmpty().mapNotNull { item ->
                val m = item as? Map<String, Any?> ?: return@mapNotNull null
                val sub = m["libSubstring"] as? String ?: return@mapNotNull null
                val create = parseLongValue(m["createOffset"]) ?: return@mapNotNull null
                val hdr = parseLongValue(m["responseStartedOffset"]) ?: return@mapNotNull null
                val body = parseLongValue(m["readCompletedOffset"]) ?: return@mapNotNull null
                val fin = parseLongValue(m["succeededOffset"]) ?: return@mapNotNull null
                EbpfCronetOffsetRule(sub, create, hdr, body, fin)
            }
            val abiObj = obj["cronetAbiRule"] as? Map<String, Any?>
            val abiRule = abiObj?.let { m ->
                val rawHdr = (parseLongValue(m["rawHeadersOffset"]) ?: 0x20L).toInt()
                val iobuf = (parseLongValue(m["ioBufferDataOffset"]) ?: 0x10L).toInt()
                val strMode = (parseLongValue(m["stringLayoutMode"]) ?: 0L).toInt()
                val slotsRaw = (m["vtableSlots"] as? List<Any?>).orEmpty().mapNotNull { parseLongValue(it)?.toInt() }
                val slots = if (slotsRaw.size >= 3) Triple(slotsRaw[0], slotsRaw[1], slotsRaw[2]) else Triple(3, 4, 5)
                val sigs = (m["jniSignatures"] as? List<Any?>).orEmpty().mapNotNull { it as? String }
                EbpfCronetAbiRule(rawHdr, iobuf, strMode, slots, sigs)
            }
            val replaceBuiltins = (obj["replaceBuiltinOffsets"] as? Boolean) ?: false
            // JSON 覆盖里也能写 jniHookRules:漏读它会让一份"看起来完整"的覆盖配置
            // 静默丢掉进程内明文通道,而抓包本身照常工作——最难查的那种。
            val jniRules = (obj["jniHookRules"] as? List<Any?>).orEmpty().mapNotNull { item ->
                val m = item as? Map<String, Any?> ?: return@mapNotNull null
                val sub = m["libSubstring"] as? String ?: return@mapNotNull null
                val names = (m["methodNames"] as? List<Any?>).orEmpty()
                    .mapNotNull { it as? String }
                    .filter { it.isNotBlank() }
                if (sub.isBlank() || names.isEmpty()) return@mapNotNull null
                JniHookRule(
                    libSubstring = sub,
                    methodNames = names,
                    captureReturn = (m["captureReturn"] as? Boolean) ?: true,
                    expectJson = (m["expectJson"] as? Boolean) ?: true,
                    magic = (m["magic"] as? String)?.takeIf { it.isNotBlank() },
                    maxBytes = ((parseLongValue(m["maxBytes"]) ?: (4L * 1024 * 1024)).toInt())
                        .coerceIn(1, 4 * 1024 * 1024)
                )
            }
                return EbpfProbeProfile(
                    sslOffsetRules = sslRules,
                    cronetOffsetRules = cronetRules,
                    cronetAbiRule = abiRule,
                    jniHookRules = jniRules,
                    replaceBuiltinOffsets = replaceBuiltins,
                    // 同一份 JSON 里的解码管道；漏读它会让"配置看起来生效、明文始终出不来"
                    declarative = DeclarativeCodecJson.parseConfig(obj)
                )
        }

        fun parseOffset(raw: String): Long? = parseLongValue(raw)

        fun formatOffset(value: Long): String = "0x${value.toString(16)}"

        fun toJson(profiles: Map<String, EbpfProbeProfile>): String {
            val sb = StringBuilder()
            sb.append("{\n")
            val entries = profiles.entries.toList()
            entries.forEachIndexed { idx, (pkg, profile) ->
                sb.append("  \"").append(escapeJson(pkg)).append("\": {\n")
                var needComma = false
                if (profile.replaceBuiltinOffsets) {
                    sb.append("    \"replaceBuiltinOffsets\": true")
                    needComma = true
                }
                if (profile.sslOffsetRules.isNotEmpty()) {
                    if (needComma) sb.append(",\n")
                    sb.append("    \"sslOffsetRules\": [\n")
                    profile.sslOffsetRules.forEachIndexed { rIdx, rule ->
                        sb.append("      {\n")
                        sb.append("        \"libSubstring\": \"").append(escapeJson(rule.libSubstring)).append("\",\n")
                        sb.append("        \"writeOffset\": \"").append(formatOffset(rule.writeOffset)).append("\",\n")
                        sb.append("        \"readOffset\": \"").append(formatOffset(rule.readOffset)).append("\",\n")
                        sb.append("        \"sniOffset\": \"").append(formatOffset(rule.sniOffset)).append("\"\n")
                        sb.append("      }")
                        if (rIdx + 1 < profile.sslOffsetRules.size) sb.append(",")
                        sb.append("\n")
                    }
                    sb.append("    ]")
                    needComma = true
                }
                if (profile.cronetOffsetRules.isNotEmpty()) {
                    if (needComma) sb.append(",\n")
                    sb.append("    \"cronetOffsetRules\": [\n")
                    profile.cronetOffsetRules.forEachIndexed { rIdx, rule ->
                        sb.append("      {\n")
                        sb.append("        \"libSubstring\": \"").append(escapeJson(rule.libSubstring)).append("\",\n")
                        sb.append("        \"createOffset\": \"").append(formatOffset(rule.createOffset)).append("\",\n")
                        sb.append("        \"responseStartedOffset\": \"").append(formatOffset(rule.responseStartedOffset)).append("\",\n")
                        sb.append("        \"readCompletedOffset\": \"").append(formatOffset(rule.readCompletedOffset)).append("\",\n")
                        sb.append("        \"succeededOffset\": \"").append(formatOffset(rule.succeededOffset)).append("\"\n")
                        sb.append("      }")
                        if (rIdx + 1 < profile.cronetOffsetRules.size) sb.append(",")
                        sb.append("\n")
                    }
                    sb.append("    ]")
                    needComma = true
                }
                profile.cronetAbiRule?.let { abi ->
                    if (needComma) sb.append(",\n")
                    sb.append("    \"cronetAbiRule\": {\n")
                    sb.append("      \"rawHeadersOffset\": \"").append(formatOffset(abi.rawHeadersOffset.toLong())).append("\",\n")
                    sb.append("      \"ioBufferDataOffset\": \"").append(formatOffset(abi.ioBufferDataOffset.toLong())).append("\",\n")
                    sb.append("      \"stringLayoutMode\": ").append(abi.stringLayoutMode).append(",\n")
                    sb.append("      \"vtableSlots\": [")
                        .append(abi.vtableSlots.first).append(", ")
                        .append(abi.vtableSlots.second).append(", ")
                        .append(abi.vtableSlots.third).append("],\n")
                    sb.append("      \"jniSignatures\": [")
                    abi.jniSignatures.forEachIndexed { sIdx, sig ->
                        if (sIdx > 0) sb.append(", ")
                        sb.append("\"").append(escapeJson(sig)).append("\"")
                    }
                    sb.append("]\n")
                    sb.append("    }")
                    needComma = true
                }
                if (profile.jniHookRules.isNotEmpty()) {
                    if (needComma) sb.append(",\n")
                    sb.append("    \"jniHookRules\": [\n")
                    profile.jniHookRules.forEachIndexed { rIdx, rule ->
                        sb.append("      {\n")
                        sb.append("        \"libSubstring\": \"").append(escapeJson(rule.libSubstring)).append("\",\n")
                        sb.append("        \"methodNames\": [")
                        rule.methodNames.forEachIndexed { mIdx, name ->
                            if (mIdx > 0) sb.append(", ")
                            sb.append("\"").append(escapeJson(name)).append("\"")
                        }
                        sb.append("],\n")
                        sb.append("        \"captureReturn\": ").append(rule.captureReturn).append(",\n")
                        sb.append("        \"expectJson\": ").append(rule.expectJson).append(",\n")
                        rule.magic?.takeIf { it.isNotBlank() }?.let {
                            sb.append("        \"magic\": \"").append(escapeJson(it)).append("\",\n")
                        }
                        sb.append("        \"maxBytes\": ").append(rule.maxBytes).append("\n")
                        sb.append("      }")
                        if (rIdx + 1 < profile.jniHookRules.size) sb.append(",")
                        sb.append("\n")
                    }
                    sb.append("    ]")
                    needComma = true
                }
                profile.declarative.hostFix?.let { fix ->
                    if (needComma) sb.append(",\n")
                    sb.append("    \"hostFix\": ")
                    sb.append(DeclarativeCodecJson.render(DeclarativeCodecJson.hostFixValue(fix), "    "))
                    needComma = true
                }
                if (profile.declarative.responseCodecs.isNotEmpty()) {
                    if (needComma) sb.append(",\n")
                    sb.append("    \"responseCodecs\": ")
                    sb.append(
                        DeclarativeCodecJson.render(
                            DeclarativeCodecJson.codecRulesValue(profile.declarative.responseCodecs),
                            "    "
                        )
                    )
                    needComma = true
                }
                if (profile.declarative.diagnose.isNotEmpty()) {
                    if (needComma) sb.append(",\n")
                    sb.append("    \"diagnose\": ")
                    sb.append(
                        DeclarativeCodecJson.render(
                            DeclarativeCodecJson.diagnoseValue(profile.declarative.diagnose),
                            "    "
                        )
                    )
                    needComma = true
                }
                if (needComma) sb.append("\n")
                sb.append("  }")
                if (idx + 1 < entries.size) sb.append(",")
                sb.append("\n")
            }
            sb.append("}")
            return sb.toString()
        }

        private fun escapeJson(raw: String): String = buildString(raw.length) {
            for (c in raw) {
                when (c) {
                    '\\' -> append("\\\\")
                    '"' -> append("\\\"")
                    '\n' -> append("\\n")
                    '\r' -> append("\\r")
                    '\t' -> append("\\t")
                    else -> append(c)
                }
            }
        }

        private fun parseLongValue(raw: Any?): Long? = when (raw) {
            is Number -> raw.toLong()
            is String -> {
                val s = raw.trim()
                if (s.startsWith("0x", ignoreCase = true)) {
                    s.substring(2).toLongOrNull(16)
                } else {
                    s.toLongOrNull()
                }
            }
            else -> null
        }
    }
}

interface NetworkTrafficMiddleware {
    val id: String

    fun onRequest(targetPackage: String, event: HttpRequestEvent): HttpRequestEvent = event

    fun onResponse(
        targetPackage: String,
        event: HttpResponseEvent,
        body: ByteArray?
    ): Pair<HttpResponseEvent, ByteArray?> = event to body
}

interface NetworkCapturePlugin {
    val id: String

    val defaultPackages: List<String> get() = emptyList()

    /**
     * 兜底插件：匹配所有包，只在没有任何专项规则时才起作用。
     *
     * 由 `plugin.json` 的 `"fallback": true` 声明，注册表靠它区分"通用能力"与"这个 App 的
     * 专属规则"——用户要求替换内置偏移时，兜底能力必须留着，否则连 TLS 都看不到了。
     */
    val fallback: Boolean get() = false

    fun matchesPackage(targetPackage: String): Boolean

    fun provideEbpfProfile(targetPackage: String): EbpfProbeProfile? = null

    fun provideMiddlewares(targetPackage: String): List<NetworkTrafficMiddleware> = emptyList()
}

object NetworkCapturePluginRegistry {
    /**
     * 启动时为空。
     *
     * 内置 App 规则（BOSS / 抖音 / 小红书 / cronet 兜底）全部是插件包，由 assets 安装后
     * 走 [com.agent.use.common.network.plugin.external.ExternalCapturePluginLoader] 注册。
     * 这里再写一份 Kotlin 对象就等于又开了"改一个 App 要重编 aau"的口子。
     */
    private val plugins = CopyOnWriteArrayList<NetworkCapturePlugin>()

    private val jsonProfileOverrides = ConcurrentHashMap<String, EbpfProbeProfile>()

    fun register(plugin: NetworkCapturePlugin) {
        plugins.removeAll { it.id == plugin.id }
        plugins.add(plugin)
    }

    fun unregister(pluginId: String) {
        plugins.removeAll { it.id == pluginId }
    }

    fun listBuiltinProfiles(): Map<String, EbpfProbeProfile> {
        val result = LinkedHashMap<String, EbpfProbeProfile>()
        for (plugin in plugins) {
            for (pkg in plugin.defaultPackages) {
                plugin.provideEbpfProfile(pkg)?.let { profile ->
                    result[pkg] = profile
                }
            }
        }
        return result
    }

    fun listJsonProfileOverrides(): Map<String, EbpfProbeProfile> =
        LinkedHashMap(jsonProfileOverrides)

    /** 该包是否由用户放的插件包提供，用于设置页区分「随 APK 内置」与「外部」。 */
    fun isExternalPluginPackage(targetPackage: String): Boolean =
        plugins.any { it.id.startsWith(EXTERNAL_PLUGIN_ID_PREFIX) && it.matchesPackage(targetPackage) }

    /** 该包是否由随 APK 分发、由 assets 安装的插件包提供。 */
    fun isBuiltinPluginPackage(targetPackage: String): Boolean =
        plugins.any { it.id.startsWith(BUILTIN_PLUGIN_ID_PREFIX) && it.matchesPackage(targetPackage) }

    /** 诊断用：当前注册了哪些插件包（id 前缀能看出内置/外部）。 */
    fun listPluginIds(): List<String> = plugins.map { it.id }

    fun registerJsonProfileOverride(packageName: String, profile: EbpfProbeProfile) {
        jsonProfileOverrides[packageName] = profile
    }

    fun removeJsonProfileOverride(packageName: String): Boolean =
        jsonProfileOverrides.remove(packageName) != null

    fun clearJsonProfileOverrides() {
        jsonProfileOverrides.clear()
    }

    fun loadJsonOverrides(jsonText: String): Int {
        val parsed = EbpfProbeProfile.fromJson(jsonText)
        for ((pkg, profile) in parsed) {
            jsonProfileOverrides[pkg] = profile
        }
        return parsed.size
    }

    fun replaceJsonOverrides(jsonText: String): Int {
        val parsed = EbpfProbeProfile.fromJson(jsonText)
        jsonProfileOverrides.clear()
        for ((pkg, profile) in parsed) {
            jsonProfileOverrides[pkg] = profile
        }
        return parsed.size
    }

    fun resolveEbpfProfile(targetPackage: String): EbpfProbeProfile {
        val pkgOverride = jsonProfileOverrides[targetPackage]
        val wildcardOverride = if (targetPackage != "*") jsonProfileOverrides["*"] else null
        val replaceBuiltin = (pkgOverride?.replaceBuiltinOffsets == true) ||
            (wildcardOverride?.replaceBuiltinOffsets == true)

        val matchedProfiles = ArrayList<EbpfProbeProfile>()
        val specificProfiles = ArrayList<EbpfProbeProfile>()
        for (plugin in plugins) {
            if (!plugin.matchesPackage(targetPackage)) continue
            // 兜底插件（`*` + fallback）在用户要求替换内置偏移时必须留着：
            // 它是最底层的 TLS 能力，拆掉它连"抓得到"都做不到。
            if (replaceBuiltin && !plugin.fallback) continue
            val profile = plugin.provideEbpfProfile(targetPackage) ?: continue
            matchedProfiles.add(profile)
            if (!plugin.fallback) {
                specificProfiles.add(profile)
            }
        }
        pkgOverride?.let { overrideProfile ->
            matchedProfiles.add(overrideProfile)
            specificProfiles.add(overrideProfile)
        }
        wildcardOverride?.let { wildcard ->
            matchedProfiles.add(wildcard)
        }

        // Put overrides/specific rules first so libaau_ebpf.so checks them before generic fallbacks.
        val prioritized = (specificProfiles.asReversed() + matchedProfiles.filterNot { specificProfiles.contains(it) })
        val sslRules = ArrayList<EbpfSslOffsetRule>()
        val cronetRules = ArrayList<EbpfCronetOffsetRule>()
        val jniRules = ArrayList<JniHookRule>()
        val jniSigs = LinkedHashSet<String>()
        var chosenAbi: EbpfCronetAbiRule? = null
        var chosenHostFix: HostFixRule? = null
        val declarativeRules = ArrayList<ResponseCodecRule>()
        val diagnoseRules = ArrayList<DiagnoseRule>()

        for (p in prioritized) {
            sslRules.addAll(p.sslOffsetRules)
            cronetRules.addAll(p.cronetOffsetRules)
            jniRules.addAll(p.jniHookRules)
            if (chosenHostFix == null) chosenHostFix = p.declarative.hostFix
            declarativeRules.addAll(p.declarative.responseCodecs)
            diagnoseRules.addAll(p.declarative.diagnose)
            p.cronetAbiRule?.let { abi ->
                if (chosenAbi == null) {
                    chosenAbi = abi
                }
                jniSigs.addAll(abi.jniSignatures)
            }
        }

        val finalAbi = chosenAbi?.copy(jniSignatures = jniSigs.toList())
        return EbpfProbeProfile(
            sslOffsetRules = sslRules.distinct(),
            cronetOffsetRules = cronetRules.distinct(),
            cronetAbiRule = finalAbi,
            jniHookRules = jniRules.distinct(),
            declarative = DeclarativeConfig(
                hostFix = chosenHostFix,
                responseCodecs = declarativeRules.distinct(),
                diagnose = diagnoseRules.distinct(),
            )
        )
    }

    fun resolveCliArgs(targetPackage: String): List<String> =
        resolveEbpfProfile(targetPackage).toCliArgs()

    fun resolveDiscoveryAbiCliArgs(targetPackage: String): List<String> =
        resolveEbpfProfile(targetPackage).toAbiCliArgs()

    fun resolveMiddlewares(targetPackage: String): List<NetworkTrafficMiddleware> {
        val seen = LinkedHashSet<String>()
        val result = ArrayList<NetworkTrafficMiddleware>()
        for (plugin in plugins) {
            if (!plugin.matchesPackage(targetPackage)) continue
            for (mw in plugin.provideMiddlewares(targetPackage)) {
                if (seen.add(mw.id)) {
                    result.add(mw)
                }
            }
        }
        // 配置驱动的解码排在内置中间件之后：内置的精确逻辑优先，声明式管道作为补充/兜底，
        // 这样给一个已有内置插件的 App 加规则不会改变它原有的行为。
        val declarative = resolveEbpfProfile(targetPackage).declarative
        if (!declarative.isEmpty) {
            val id = declarativeMiddlewareId(targetPackage)
            if (seen.add(id)) {
                result.add(DeclarativeTrafficMiddleware(id, declarative))
            }
        }
        return result
    }

    fun declarativeMiddlewareId(targetPackage: String): String = "declarative:$targetPackage"

    /** 当前解析出的声明式配置（解码管道 + host 补全），供设置页与诊断使用。 */
    fun resolveDeclarativeConfig(targetPackage: String): DeclarativeConfig =
        resolveEbpfProfile(targetPackage).declarative
}

data class DiscoveredLibraryProbe(
    val path: String,
    val name: String,
    val inAppDir: Boolean,
    val sslSource: String,
    val sslWriteOffset: Long?,
    val sslReadOffset: Long?,
    val sslSniOffset: Long?,
    val cronetSource: String,
    val cronetCreateOffset: Long?,
    val cronetResponseStartedOffset: Long?,
    val cronetReadCompletedOffset: Long?,
    val cronetSucceededOffset: Long?
) {
    val hasSsl: Boolean
        get() = sslSource != "none" && (sslWriteOffset ?: 0L) > 0L && (sslReadOffset ?: 0L) > 0L

    val hasCronet: Boolean
        get() = cronetSource != "none" &&
            (cronetCreateOffset ?: 0L) > 0L &&
            (cronetResponseStartedOffset ?: 0L) > 0L &&
            (cronetReadCompletedOffset ?: 0L) > 0L &&
            (cronetSucceededOffset ?: 0L) > 0L
}

data class EbpfDiscoveryReport(
    val uid: Int,
    val arch: String,
    val scannedLibrariesCount: Int,
    val rawHeadersOffset: Int,
    val ioBufferDataOffset: Int,
    val stringLayoutMode: Int,
    val vtableSlots: Triple<Int, Int, Int>,
    val libraries: List<DiscoveredLibraryProbe>,
    val unmatchedAppLibs: List<String> = emptyList()
) {
    fun toSuggestedProfile(
        jniSignatures: List<String> = listOf("(Ljava/lang/Object;JLjava/lang/String;IZZZIZIIJ)J"),
        replaceBuiltinOffsets: Boolean = true
    ): EbpfProbeProfile? {
        val sortedLibs = libraries.sortedWith(
            compareByDescending<DiscoveredLibraryProbe> { it.inAppDir }
                .thenByDescending { it.hasCronet }
                .thenByDescending { it.hasSsl }
        )
        val sslRules = sortedLibs
            .filter { it.hasSsl && (it.inAppDir || it.sslSource == "stripped_heuristic") }
            .map {
                EbpfSslOffsetRule(
                    libSubstring = it.name,
                    writeOffset = it.sslWriteOffset!!,
                    readOffset = it.sslReadOffset!!,
                    sniOffset = it.sslSniOffset ?: 0L
                )
            }
        val cronetRules = sortedLibs
            .filter { it.hasCronet }
            .map {
                EbpfCronetOffsetRule(
                    libSubstring = it.name,
                    createOffset = it.cronetCreateOffset!!,
                    responseStartedOffset = it.cronetResponseStartedOffset!!,
                    readCompletedOffset = it.cronetReadCompletedOffset!!,
                    succeededOffset = it.cronetSucceededOffset!!
                )
            }
        if (sslRules.isEmpty() && cronetRules.isEmpty()) {
            return null
        }
        return EbpfProbeProfile(
            sslOffsetRules = sslRules,
            cronetOffsetRules = cronetRules,
            cronetAbiRule = EbpfCronetAbiRule(
                rawHeadersOffset = rawHeadersOffset,
                ioBufferDataOffset = ioBufferDataOffset,
                stringLayoutMode = stringLayoutMode,
                vtableSlots = vtableSlots,
                jniSignatures = jniSignatures
            ),
            replaceBuiltinOffsets = replaceBuiltinOffsets
        )
    }

    companion object {
        @Suppress("UNCHECKED_CAST")
        fun fromJson(json: String): EbpfDiscoveryReport? {
            val trimmed = json.trim()
            val jsonStart = trimmed.indexOf('{')
            if (jsonStart < 0) return null
            val root = SimpleJsonReader(trimmed.substring(jsonStart)).parseValue() as? Map<String, Any?>
                ?: return null
            val uid = (root["uid"] as? Number)?.toInt() ?: 0
            val arch = root["arch"] as? String ?: "unknown"
            val scannedCount = (root["scannedLibrariesCount"] as? Number)?.toInt() ?: 0

            val abiObj = root["abi"] as? Map<String, Any?>
            val rawHeaders = (abiObj?.get("rawHeadersOffset")?.let { parseAnyLong(it) } ?: 0x20L).toInt()
            val ioBufferData = (abiObj?.get("ioBufferDataOffset")?.let { parseAnyLong(it) } ?: 0x10L).toInt()
            val strMode = (abiObj?.get("stringLayoutMode") as? Number)?.toInt() ?: 0
            val slotList = (abiObj?.get("vtableSlots") as? List<Any?>).orEmpty()
                .mapNotNull { (it as? Number)?.toInt() }
            val slots = if (slotList.size >= 3) {
                Triple(slotList[0], slotList[1], slotList[2])
            } else {
                Triple(3, 4, 5)
            }

            val libs = (root["libraries"] as? List<Any?>).orEmpty().mapNotNull { item ->
                val m = item as? Map<String, Any?> ?: return@mapNotNull null
                val path = m["path"] as? String ?: return@mapNotNull null
                val name = m["name"] as? String ?: path.substringAfterLast('/')
                val inAppDir = (m["inAppDir"] as? Boolean) ?: false
                val sslSource = m["sslSource"] as? String ?: "none"
                val cronetSource = m["cronetSource"] as? String ?: "none"
                DiscoveredLibraryProbe(
                    path = path,
                    name = name,
                    inAppDir = inAppDir,
                    sslSource = sslSource,
                    sslWriteOffset = parsePositiveHex(m["sslWriteOffset"]),
                    sslReadOffset = parsePositiveHex(m["sslReadOffset"]),
                    sslSniOffset = parseNonNegativeHex(m["sslSniOffset"]),
                    cronetSource = cronetSource,
                    cronetCreateOffset = parsePositiveHex(m["cronetCreateOffset"]),
                    cronetResponseStartedOffset = parsePositiveHex(m["cronetResponseStartedOffset"]),
                    cronetReadCompletedOffset = parsePositiveHex(m["cronetReadCompletedOffset"]),
                    cronetSucceededOffset = parsePositiveHex(m["cronetSucceededOffset"])
                )
            }
            val unmatched = (root["unmatchedAppLibs"] as? List<Any?>).orEmpty()
                .mapNotNull { it as? String }
            return EbpfDiscoveryReport(
                uid = uid,
                arch = arch,
                scannedLibrariesCount = scannedCount,
                rawHeadersOffset = rawHeaders,
                ioBufferDataOffset = ioBufferData,
                stringLayoutMode = strMode,
                vtableSlots = slots,
                libraries = libs,
                unmatchedAppLibs = unmatched
            )
        }

        private fun parseAnyLong(raw: Any?): Long? = when (raw) {
            is Number -> raw.toLong()
            is String -> EbpfProbeProfile.parseOffset(raw)
            else -> null
        }

        private fun parsePositiveHex(raw: Any?): Long? =
            parseAnyLong(raw)?.takeIf { it > 0L }

        private fun parseNonNegativeHex(raw: Any?): Long? =
            parseAnyLong(raw)?.takeIf { it >= 0L }
    }
}

/**
 * 极简 JSON 读取器。
 *
 * [strict] = false 时保持历史上"读到哪儿算哪儿"的宽松行为（发现报告这类带前后日志的输出要用）；
 * [strict] = true 时语法错误直接抛异常——配置文件必须这样，否则一条写错的规则会被静默解析成
 * 空配置，用户以为配好了、实际什么都没生效。
 */
internal class SimpleJsonReader(private val input: String, private val strict: Boolean = false) {
    private var pos = 0

    fun parseValue(): Any? {
        skipWhitespace()
        if (pos >= input.length) {
            if (strict) fail("unexpected_end")
            return null
        }
        return when (val c = input[pos]) {
            '{' -> parseObject()
            '[' -> parseArray()
            '"' -> parseString()
            't', 'f' -> parseBoolean()
            'n' -> parseNull()
            '-', in '0'..'9' -> parseNumber()
            else -> fail("unexpected_char:$c")
        }
    }

    private fun parseObject(): Map<String, Any?> {
        pos++ // '{'
        val map = LinkedHashMap<String, Any?>()
        skipWhitespace()
        if (pos < input.length && input[pos] == '}') {
            pos++
            return map
        }
        while (pos < input.length) {
            skipWhitespace()
            if (pos >= input.length || input[pos] != '"') {
                if (strict) fail("object_key")
                return map
            }
            val key = parseString()
            skipWhitespace()
            if (pos >= input.length || input[pos] != ':') {
                if (strict) fail("object_colon")
                return map
            }
            pos++
            map[key] = parseValue()
            skipWhitespace()
            if (pos < input.length && input[pos] == ',') {
                pos++
                continue
            }
            if (pos < input.length && input[pos] == '}') {
                pos++
                return map
            }
            if (strict) fail("object_separator")
            return map
        }
        if (strict) fail("object_unterminated")
        return map
    }

    private fun parseArray(): List<Any?> {
        pos++ // '['
        val list = ArrayList<Any?>()
        skipWhitespace()
        if (pos < input.length && input[pos] == ']') {
            pos++
            return list
        }
        while (pos < input.length) {
            list.add(parseValue())
            skipWhitespace()
            if (pos < input.length && input[pos] == ',') {
                pos++
                continue
            }
            if (pos < input.length && input[pos] == ']') {
                pos++
                return list
            }
            if (strict) fail("array_separator")
            return list
        }
        if (strict) fail("array_unterminated")
        return list
    }

    private fun parseString(): String {
        pos++ // '"'
        val sb = StringBuilder()
        while (pos < input.length) {
            val c = input[pos++]
            if (c == '"') return sb.toString()
            if (c == '\\' && pos < input.length) {
                when (val esc = input[pos++]) {
                    '"', '\\', '/' -> sb.append(esc)
                    'b' -> sb.append('\b')
                    'f' -> sb.append('\u000C')
                    'n' -> sb.append('\n')
                    'r' -> sb.append('\r')
                    't' -> sb.append('\t')
                    'u' -> {
                        if (pos + 4 <= input.length) {
                            val code = input.substring(pos, pos + 4).toIntOrNull(16)
                            if (code != null) sb.append(code.toChar())
                            pos += 4
                        }
                    }
                    else -> sb.append(esc)
                }
            } else {
                sb.append(c)
            }
        }
        return sb.toString()
    }

    private fun parseNumber(): Number {
        val start = pos
        if (input[pos] == '-') pos++
        while (pos < input.length && input[pos] in '0'..'9') pos++
        var isFloat = false
        if (pos < input.length && input[pos] == '.') {
            isFloat = true
            pos++
            while (pos < input.length && input[pos] in '0'..'9') pos++
        }
        if (pos < input.length && (input[pos] == 'e' || input[pos] == 'E')) {
            isFloat = true
            pos++
            if (pos < input.length && (input[pos] == '+' || input[pos] == '-')) pos++
            while (pos < input.length && input[pos] in '0'..'9') pos++
        }
        val numStr = input.substring(start, pos)
        return if (isFloat) numStr.toDouble() else numStr.toLong()
    }

    private fun parseBoolean(): Boolean {
        return if (input.startsWith("true", pos)) {
            pos += 4
            true
        } else {
            pos += 5
            false
        }
    }

    private fun parseNull(): Any? {
        pos += 4
        return null
    }

    private fun skipWhitespace() {
        while (pos < input.length && input[pos].isWhitespace()) pos++
    }

    /** 严格模式下用于确认整份文本都被消费掉（尾部多出来的字符也算语法错误）。 */
    fun ensureFullyConsumed() {
        skipWhitespace()
        if (pos < input.length) fail("trailing_content")
    }

    private fun fail(reason: String): Nothing =
        throw IllegalArgumentException("$reason@$pos")
}
