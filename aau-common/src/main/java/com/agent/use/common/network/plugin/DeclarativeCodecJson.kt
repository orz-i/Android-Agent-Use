package com.agent.use.common.network.plugin

/**
 * 声明式解码配置的 JSON 读写。
 *
 * 读：同时支持「插件包里那个对象」和「设置页里那段文本」两种来源，语法错误返回 null，
 * 让调用方决定是拒绝保存（界面）还是跳过这个包（加载）。
 *
 * 写：输出带缩进的多行 JSON，因为这份文件是给人改的——压成一行等于把可维护性丢了。
 */
internal object DeclarativeCodecJson {

    private val OPS = setOf("container", "decompress", "base64", "stripprefix")
    private val ALGOS = setOf("gzip", "zlib", "lz4-block", "zstd", "br", "brotli")

    // ------------------------------------------------------------------ 读

    /** @return 语法错误返回 null；空文本返回 [DeclarativeConfig.EMPTY]。 */
    fun parseConfigText(text: String): DeclarativeConfig? {
        val trimmed = text.trim()
        if (trimmed.isEmpty()) return DeclarativeConfig.EMPTY
        val root = try {
            val reader = SimpleJsonReader(trimmed, strict = true)
            val parsed = reader.parseValue()
            reader.ensureFullyConsumed()
            parsed as? Map<String, Any?>
        } catch (t: Throwable) {
            null
        } ?: return null
        return parseConfig(root)
    }

    @Suppress("UNCHECKED_CAST")
    fun parseConfig(root: Map<String, Any?>?): DeclarativeConfig {
        if (root == null) return DeclarativeConfig.EMPTY
        val hostFix = (root["hostFix"] as? Map<String, Any?>)?.let { parseHostFix(it) }
        val rules = (root["responseCodecs"] as? List<Any?>).orEmpty()
            .mapNotNull { parseRule(it as? Map<String, Any?>) }
        val inlineRule = parseRule(root["responseCodec"] as? Map<String, Any?>)
        val diagnose = (root["diagnose"] as? List<Any?>).orEmpty()
            .mapNotNull { parseDiagnose(it as? Map<String, Any?>) }
        return DeclarativeConfig(
            hostFix = hostFix,
            responseCodecs = if (inlineRule != null) rules + inlineRule else rules,
            diagnose = diagnose,
        )
    }

    private fun parseHostFix(obj: Map<String, Any?>): HostFixRule? {
        val headers = (obj["headerPriority"] as? List<Any?>).orEmpty()
            .mapNotNull { (it as? String)?.trim()?.takeIf(String::isNotEmpty) }
        val defaultHost = (obj["defaultHost"] as? String)?.trim()?.takeIf { it.isNotEmpty() }
        val pathContains = (obj["defaultHostPathContains"] as? String)?.trim()?.takeIf { it.isNotEmpty() }
        if (headers.isEmpty() && defaultHost == null) return null
        return HostFixRule(
            headerPriority = if (headers.isEmpty()) HostFixRule.DEFAULT_HEADERS else headers,
            defaultHost = defaultHost,
            defaultHostPathContains = pathContains,
            applyOnRequest = (obj["onRequest"] as? Boolean) ?: true,
        )
    }

    private fun parseDiagnose(obj: Map<String, Any?>?): DiagnoseRule? {
        if (obj == null) return null
        val label = (obj["label"] as? String)?.trim()?.takeIf { it.isNotEmpty() } ?: return null
        val rawWhen = obj["when"] ?: obj["conditions"]
        val conditions = when (rawWhen) {
            is List<Any?> -> rawWhen.mapNotNull { parseCondition(it as? Map<String, Any?>) }
            is Map<*, *> -> listOfNotNull(parseCondition(rawWhen as? Map<String, Any?>))
            else -> emptyList()
        }
        val headers = (obj["headers"] as? List<Any?>).orEmpty()
            .mapNotNull { (it as? String)?.trim()?.takeIf(String::isNotEmpty) }
        return DiagnoseRule(whenConditions = conditions, label = label, headers = headers)
    }

    private fun parseRule(obj: Map<String, Any?>?): ResponseCodecRule? {
        if (obj == null) return null
        val steps = (obj["steps"] as? List<Any?>).orEmpty()
            .mapNotNull { parseStep(it as? Map<String, Any?>) }
        if (steps.isEmpty()) return null
        val rawWhen = obj["when"] ?: obj["conditions"]
        val conditions = when (rawWhen) {
            is List<Any?> -> rawWhen.mapNotNull { parseCondition(it as? Map<String, Any?>) }
            is Map<*, *> -> listOfNotNull(parseCondition(rawWhen as? Map<String, Any?>))
            else -> emptyList()
        }
        return ResponseCodecRule(
            id = (obj["id"] as? String)?.trim()?.takeIf { it.isNotEmpty() },
            whenConditions = conditions,
            steps = steps,
            stopWhenJson = (obj["stopWhenJson"] as? Boolean) ?: true,
        )
    }

    private fun parseCondition(obj: Map<String, Any?>?): CodecCondition? {
        if (obj == null) return null
        val header = (obj["header"] as? String)?.trim()?.takeIf { it.isNotEmpty() }
        val magic = (obj["magic"] as? String)?.takeIf { it.isNotEmpty() }
        val magicHex = (obj["magicHex"] as? String)?.takeIf { it.isNotEmpty() }
        if (header == null && magic == null && magicHex == null) return null
        return CodecCondition(
            header = header,
            equals = (obj["equals"] as? String) ?: (obj["eq"] as? String),
            contains = (obj["contains"] as? String) ?: (obj["has"] as? String),
            absent = (obj["absent"] as? Boolean) ?: false,
            magic = magic,
            magicHex = magicHex,
        )
    }

    private fun parseStep(obj: Map<String, Any?>?): CodecStep? {
        if (obj == null) return null
        val op = (obj["op"] as? String)?.trim()?.lowercase() ?: return null
        if (op !in OPS) return null
        val algo = (obj["algo"] as? String)?.trim()?.lowercase()
        if (op == "decompress" && (algo == null || algo !in ALGOS)) return null
        return CodecStep(
            op = op,
            magic = (obj["magic"] as? String)?.takeIf { it.isNotEmpty() },
            magicHex = (obj["magicHex"] as? String)?.takeIf { it.isNotEmpty() },
            magicOffset = ((obj["magicOffset"] as? Number)?.toInt() ?: 0).coerceAtLeast(0),
            headerSize = ((obj["headerSize"] as? Number)?.toInt() ?: 0).coerceAtLeast(0),
            payloadLen = parseFieldRef(obj["payloadLen"]),
            rawLen = parseFieldRef(obj["rawLen"]),
            algo = algo,
            prefixBytes = ((obj["prefixBytes"] as? Number)?.toInt() ?: 0).coerceAtLeast(0),
            label = (obj["label"] as? String)?.trim()?.takeIf { it.isNotEmpty() },
            contentType = (obj["contentType"] as? String)?.trim()?.takeIf { it.isNotEmpty() },
        )
    }

    private fun parseFieldRef(raw: Any?): CodecFieldRef? {
        val obj = raw as? Map<String, Any?> ?: return null
        val at = (obj["at"] as? Number)?.toInt() ?: return null
        val width = (obj["width"] as? Number)?.toInt() ?: 4
        if (at < 0 || width !in 1..8) return null
        val endian = ((obj["endian"] as? String) ?: "le").trim().lowercase()
        return CodecFieldRef(at = at, width = width, endian = if (endian == "be") "be" else "le")
    }

    // ------------------------------------------------------------------ 写

    /** `"hostFix": <这个值>`；[indent] 是键所在的缩进。 */
    fun hostFixValue(rule: HostFixRule): J = J.Obj(
        buildList {
            add("headerPriority" to J.Arr(rule.headerPriority.map(J::Str)))
            rule.defaultHost?.takeIf { it.isNotBlank() }?.let { add("defaultHost" to J.Str(it)) }
            rule.defaultHostPathContains?.takeIf { it.isNotBlank() }
                ?.let { add("defaultHostPathContains" to J.Str(it)) }
            if (!rule.applyOnRequest) add("onRequest" to J.Bool(false))
        }
    )

    /** `"diagnose": <这个值>`。 */
    fun diagnoseValue(rules: List<DiagnoseRule>): J = J.Arr(
        rules.map { rule ->
            J.Obj(
                buildList {
                    if (rule.whenConditions.isNotEmpty()) {
                        add("when" to J.Arr(rule.whenConditions.map(::conditionValue)))
                    }
                    add("label" to J.Str(rule.label))
                    if (rule.headers.isNotEmpty()) {
                        add("headers" to J.Arr(rule.headers.map(J::Str)))
                    }
                }
            )
        }
    )

    /** `"responseCodecs": <这个值>`。 */
    fun codecRulesValue(rules: List<ResponseCodecRule>): J = J.Arr(rules.map(::ruleValue))

    private fun ruleValue(rule: ResponseCodecRule): J = J.Obj(
        buildList {
            rule.id?.let { add("id" to J.Str(it)) }
            if (rule.whenConditions.isNotEmpty()) {
                add("when" to J.Arr(rule.whenConditions.map(::conditionValue)))
            }
            if (!rule.stopWhenJson) add("stopWhenJson" to J.Bool(false))
            add("steps" to J.Arr(rule.steps.map(::stepValue)))
        }
    )

    private fun conditionValue(condition: CodecCondition): J = J.Obj(
        buildList {
            condition.header?.let { add("header" to J.Str(it)) }
            condition.equals?.let { add("equals" to J.Str(it)) }
            condition.contains?.let { add("contains" to J.Str(it)) }
            if (condition.absent) add("absent" to J.Bool(true))
            condition.magic?.let { add("magic" to J.Str(it)) }
            condition.magicHex?.let { add("magicHex" to J.Str(it)) }
        }
    )

    private fun stepValue(step: CodecStep): J = J.Obj(
        buildList {
            add("op" to J.Str(step.op))
            step.algo?.let { add("algo" to J.Str(it)) }
            step.magic?.let { add("magic" to J.Str(it)) }
            step.magicHex?.let { add("magicHex" to J.Str(it)) }
            if (step.magicOffset > 0) add("magicOffset" to J.Num(step.magicOffset.toLong()))
            if (step.headerSize > 0) add("headerSize" to J.Num(step.headerSize.toLong()))
            step.payloadLen?.let { add("payloadLen" to fieldRefValue(it)) }
            step.rawLen?.let { add("rawLen" to fieldRefValue(it)) }
            if (step.prefixBytes > 0) add("prefixBytes" to J.Num(step.prefixBytes.toLong()))
            step.label?.let { add("label" to J.Str(it)) }
            step.contentType?.let { add("contentType" to J.Str(it)) }
        }
    )

    private fun fieldRefValue(ref: CodecFieldRef): J = J.Obj(
        buildList {
            add("at" to J.Num(ref.at.toLong()))
            if (ref.width != 4) add("width" to J.Num(ref.width.toLong()))
            if (ref.endian != "le") add("endian" to J.Str(ref.endian))
        }
    )

    fun render(value: J, indent: String = ""): String = when (value) {
        is J.Str -> quote(value.v)
        is J.Num -> value.v.toString()
        is J.Bool -> value.v.toString()
        is J.Arr -> {
            if (value.items.isEmpty()) {
                "[]"
            } else if (value.items.all { it is J.Str || it is J.Num || it is J.Bool }) {
                "[" + value.items.joinToString(", ") { render(it) } + "]"
            } else {
                val inner = indent + "  "
                "[\n" + value.items.joinToString(",\n") { inner + render(it, inner) } + "\n$indent]"
            }
        }
        is J.Obj -> {
            if (value.entries.isEmpty()) {
                "{}"
            } else {
                val inner = indent + "  "
                "{\n" + value.entries.joinToString(",\n") {
                    "$inner${quote(it.first)}: ${render(it.second, inner)}"
                } + "\n$indent}"
            }
        }
    }

    private fun quote(raw: String): String = buildString(raw.length + 2) {
        append('"')
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
        append('"')
    }

    /** 极简 JSON 值树：只为了让"写"这一段不变成字符串拼接。 */
    internal sealed interface J {
        data class Str(val v: String) : J
        data class Num(val v: Long) : J
        data class Bool(val v: Boolean) : J
        data class Arr(val items: List<J>) : J
        data class Obj(val entries: List<Pair<String, J>>) : J
    }
}

/** 解析一份 JSON 对象；语法错误或根不是对象时抛异常，由调用方决定怎么拒绝。 */
internal fun parseJsonObject(text: String): Map<String, Any?> {
    val reader = SimpleJsonReader(text, strict = true)
    val parsed = reader.parseValue()
    reader.ensureFullyConsumed()
    @Suppress("UNCHECKED_CAST")
    return parsed as? Map<String, Any?> ?: throw IllegalArgumentException("json_root_not_object")
}
