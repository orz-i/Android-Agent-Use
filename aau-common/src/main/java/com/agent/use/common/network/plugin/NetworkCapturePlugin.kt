package com.agent.use.common.network.plugin

import com.agent.use.common.network.HttpRequestEvent
import com.agent.use.common.network.HttpResponseEvent
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList

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

data class EbpfProbeProfile(
    val sslOffsetRules: List<EbpfSslOffsetRule> = emptyList(),
    val cronetOffsetRules: List<EbpfCronetOffsetRule> = emptyList(),
    val cronetAbiRule: EbpfCronetAbiRule? = null,
    val replaceBuiltinOffsets: Boolean = false
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
        return args
    }

    companion object {
        @Suppress("UNCHECKED_CAST")
        fun fromJson(json: String): Map<String, EbpfProbeProfile> {
            val root = SimpleJsonReader(json).parseValue() as? Map<String, Any?> ?: return emptyMap()
            val result = LinkedHashMap<String, EbpfProbeProfile>()
            for ((pkg, rawProfile) in root) {
                val obj = rawProfile as? Map<String, Any?> ?: continue
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
                result[pkg] = EbpfProbeProfile(
                    sslOffsetRules = sslRules,
                    cronetOffsetRules = cronetRules,
                    cronetAbiRule = abiRule,
                    replaceBuiltinOffsets = replaceBuiltins
                )
            }
            return result
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

    fun matchesPackage(targetPackage: String): Boolean

    fun provideEbpfProfile(targetPackage: String): EbpfProbeProfile? = null

    fun provideMiddlewares(targetPackage: String): List<NetworkTrafficMiddleware> = emptyList()
}

object GenericCronetCapturePlugin : NetworkCapturePlugin {
    override val id: String = "builtin.generic_cronet"

    override val defaultPackages: List<String> = listOf("*")

    override fun matchesPackage(targetPackage: String): Boolean = true

    override fun provideEbpfProfile(targetPackage: String): EbpfProbeProfile =
        EbpfProbeProfile(
            cronetAbiRule = EbpfCronetAbiRule(
                rawHeadersOffset = 0x20,
                ioBufferDataOffset = 0x10,
                stringLayoutMode = 0,
                vtableSlots = Triple(3, 4, 5),
                jniSignatures = listOf("(Ljava/lang/Object;JLjava/lang/String;IZZZIZIIJ)J")
            )
        )
}

object XiaohongshuTrafficMiddleware : NetworkTrafficMiddleware {
    override val id: String = "builtin.xiaohongshu.middleware"

    override fun onResponse(
        targetPackage: String,
        event: HttpResponseEvent,
        body: ByteArray?
    ): Pair<HttpResponseEvent, ByteArray?> {
        if (targetPackage != "com.xingin.xhs") return event to body
        if (event.url.contains("://unknown-host/api/sns/")) {
            return event.copy(
                url = event.url.replace("://unknown-host", "://edith.xiaohongshu.com")
            ) to body
        }
        return event to body
    }
}

object XiaohongshuCapturePlugin : NetworkCapturePlugin {
    override val id: String = "builtin.xiaohongshu"

    override val defaultPackages: List<String> = listOf("com.xingin.xhs")

    private const val XHS_CRONET_LIB = "libcronet.114.0.5735.38.so"

    override fun matchesPackage(targetPackage: String): Boolean = targetPackage == "com.xingin.xhs"

    override fun provideEbpfProfile(targetPackage: String): EbpfProbeProfile =
        EbpfProbeProfile(
            sslOffsetRules = listOf(
                EbpfSslOffsetRule(
                    libSubstring = XHS_CRONET_LIB,
                    writeOffset = 0x4ea720L,
                    readOffset = 0x4ea438L,
                    sniOffset = 0x4eb0c8L
                )
            ),
            cronetOffsetRules = listOf(
                EbpfCronetOffsetRule(
                    libSubstring = XHS_CRONET_LIB,
                    createOffset = 0x226c34L,
                    responseStartedOffset = 0x206dd4L,
                    readCompletedOffset = 0x206f34L,
                    succeededOffset = 0x206ffcL
                )
            ),
            cronetAbiRule = EbpfCronetAbiRule(
                rawHeadersOffset = 0x20,
                ioBufferDataOffset = 0x10,
                stringLayoutMode = 0,
                vtableSlots = Triple(3, 4, 5),
                jniSignatures = listOf("(Ljava/lang/Object;JLjava/lang/String;IZZZIZIIJ)J")
            )
        )

    override fun provideMiddlewares(targetPackage: String): List<NetworkTrafficMiddleware> =
        listOf(XiaohongshuTrafficMiddleware)
}

object NetworkCapturePluginRegistry {
    private val plugins = CopyOnWriteArrayList<NetworkCapturePlugin>().apply {
        add(GenericCronetCapturePlugin)
        add(XiaohongshuCapturePlugin)
    }

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
            val isGeneric = plugin.id == GenericCronetCapturePlugin.id
            if (replaceBuiltin && !isGeneric) continue
            val profile = plugin.provideEbpfProfile(targetPackage) ?: continue
            matchedProfiles.add(profile)
            if (!isGeneric) {
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
        val jniSigs = LinkedHashSet<String>()
        var chosenAbi: EbpfCronetAbiRule? = null

        for (p in prioritized) {
            sslRules.addAll(p.sslOffsetRules)
            cronetRules.addAll(p.cronetOffsetRules)
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
            cronetAbiRule = finalAbi
        )
    }

    fun resolveCliArgs(targetPackage: String): List<String> =
        resolveEbpfProfile(targetPackage).toCliArgs()

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
        return result
    }
}

private class SimpleJsonReader(private val input: String) {
    private var pos = 0

    fun parseValue(): Any? {
        skipWhitespace()
        if (pos >= input.length) return null
        return when (val c = input[pos]) {
            '{' -> parseObject()
            '[' -> parseArray()
            '"' -> parseString()
            't', 'f' -> parseBoolean()
            'n' -> parseNull()
            '-', in '0'..'9' -> parseNumber()
            else -> throw IllegalArgumentException("Unexpected JSON char '$c' at $pos")
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
            if (pos >= input.length || input[pos] != '"') break
            val key = parseString()
            skipWhitespace()
            if (pos >= input.length || input[pos] != ':') break
            pos++
            map[key] = parseValue()
            skipWhitespace()
            if (pos < input.length && input[pos] == ',') {
                pos++
            } else if (pos < input.length && input[pos] == '}') {
                pos++
                break
            } else {
                break
            }
        }
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
            } else if (pos < input.length && input[pos] == ']') {
                pos++
                break
            } else {
                break
            }
        }
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
}
