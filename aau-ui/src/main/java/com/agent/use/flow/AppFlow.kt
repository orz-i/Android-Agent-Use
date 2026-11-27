package com.agent.use.flow

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * 插件包里的**应用脚本**。
 *
 * 抓包插件解决「看得见请求」，这一层解决「点得动界面」：同一个 `plugin.json` 里多一个
 * `flows` 数组，就能把一个 App 的操作流程写成数据，不用为每个 App 重编宿主。
 *
 * 脚本只描述「找什么、点什么、等多久」，不描述「怎么读屏、怎么落指」——后者由宿主实现
 * [FlowHost]。所以同一份脚本在无障碍树、OCR 文字、甚至未来的视觉定位上都能跑。
 */
data class AppFlow(
    val id: String,
    val title: String?,
    val description: String?,
    /** 这条脚本适用于哪些包名；为空表示跟随插件包的 `packages`。 */
    val packages: List<String>,
    val params: List<FlowParam>,
    val steps: List<FlowStep>,
    /** 来自哪个插件包（`builtin.qidian` / `external.foo`），排错时要知道是谁写的。 */
    val packId: String,
) {
    fun matchesPackage(pkg: String?): Boolean =
        pkg != null && packages.any { it == "*" || it.equals(pkg, ignoreCase = true) }
}

/** 脚本参数：只用来做默认值和说明，真正的值由调用方传。 */
data class FlowParam(
    val name: String,
    val type: String,
    val default: String?,
    val description: String?,
)

/**
 * 一步。`op` 决定用哪些字段，其余原样留在 [raw] 里。
 *
 * 控制流步骤（`if` / `repeat`）把子步骤放在 [then] / [otherwise] / [body]。
 */
data class FlowStep(
    val op: String,
    val raw: JsonObject,
    val then: List<FlowStep> = emptyList(),
    val otherwise: List<FlowStep> = emptyList(),
    val body: List<FlowStep> = emptyList(),
)

/**
 * 选择器：在无障碍树（`a11y`）或屏上文字（`text`）里找元素。
 *
 * - `text` / `textAny`：包含匹配，忽略大小写；
 * - `role` / `id`：无障碍类名、资源 ID 的子串；
 * - `source`：`a11y`（默认，能拿到 ref）或 `text`（OCR 行，只有坐标）；
 * - `pick`：多个命中时取哪个。`maxY` 用来点「卡片底部那个按钮」，
 *   `nearest` 配合 `near` 取离锚点最近的一个（同一块卡片里的「去完成」）。
 */
data class FlowSelector(
    val text: String? = null,
    val textAny: List<String> = emptyList(),
    val role: String? = null,
    val id: String? = null,
    val source: Source = Source.A11Y,
    val pick: Pick = Pick.FIRST,
    val near: String? = null,
    /** 名字里含这些词的命中一律不算（`领取` 要排除 `已领取`）。 */
    val exclude: List<String> = emptyList(),
) {
    enum class Source { A11Y, TEXT }

    enum class Pick { FIRST, LAST, MAX_Y, MIN_Y, NEAREST }

    val texts: List<String> get() = (listOfNotNull(text?.takeIf { it.isNotBlank() }) + textAny).distinct()

    val isEmpty: Boolean get() = texts.isEmpty() && role.isNullOrBlank() && id.isNullOrBlank()

    /** 给 trace 用的一行说明。 */
    val label: String
        get() = texts.joinToString("|").ifEmpty { role ?: id.orEmpty() }
}

/** 一次命中的元素。 */
data class FlowHit(
    val name: String,
    /** 无障碍元素的可点编号；OCR 行没有。 */
    val ref: String? = null,
    /** 产生这个 ref 的那次读屏；点之前原样带回去，过期会被宿主拒绝。 */
    val snapshotId: String? = null,
    /** 像素坐标（无障碍）或空（OCR）。只用于排序。 */
    val bounds: List<Int> = emptyList(),
    /** 落指用的千分比坐标。 */
    val center: Pair<Int, Int>,
)

/**
 * 脚本能对宿主做的事，刻意只有六个。
 *
 * 不给「随便调一个工具」的口子：脚本来自插件包，能力越大越难审。要新能力就加一个 op，
 * 让所有脚本一起受益，也让审查只需要看一处。
 */
interface FlowHost {
    /** 按选择器找元素；一次调用只返回同一份读屏快照里的结果。 */
    suspend fun find(selector: FlowSelector): List<FlowHit>

    /** 按元素点（有 ref 走 ref，没有走坐标）。 */
    suspend fun tap(hit: FlowHit): Boolean

    /** 按千分比坐标点。 */
    suspend fun tapAt(x: Int, y: Int): Boolean

    /** 按一次返回键。 */
    suspend fun back(): Boolean

    /** 当前前台包名；读不到为 null。 */
    suspend fun foreground(): String?

    /** 记一行日志（进 trace，给人和模型看）。 */
    suspend fun log(text: String) {}
}

/** 一次脚本运行的完整回执。 */
data class FlowResult(
    val ok: Boolean,
    val stopped: String,
    val steps: Int,
    val trace: List<FlowTrace>,
    val vars: Map<String, String>,
)

/** trace 的一条：和 `phone_watch_reward_videos` 的 `rounds` 同形，排错时不用换脑子。 */
data class FlowTrace(
    val round: Int,
    val op: String,
    val on: String,
    val ok: Boolean = true,
)

/** 解析结果：能用的脚本 + 每条失败的原因。坏一条不影响同包里的其它脚本。 */
data class FlowParseResult(
    val flows: List<AppFlow>,
    val errors: List<String> = emptyList(),
)

/**
 * `plugin.json` 里 `flows` 的解析器。
 *
 * 宽容但不装作没看见：不认识的 `op` 直接判这条脚本坏掉，而不是悄悄跳过——脚本是行为，
 * 静默跳过等于「跑了一半」，比明确报错更难查。未知的**字段**则忽略，方便以后加参数。
 */
object AppFlowSpec {

    /** 脚本格式版本。加字段不涨，改语义才涨。 */
    const val API_VERSION = 1

    private val OPS = setOf("tap", "wait", "sleep", "back", "if", "repeat", "stop", "log", "returnto")

    fun parsePack(text: String, packId: String): FlowParseResult {
        val root = try {
            Json.parseToJsonElement(text).jsonObject
        } catch (t: Throwable) {
            return FlowParseResult(emptyList(), listOf("$packId: invalid_json"))
        }
        val api = root.int("apiVersion") ?: 1
        if (api != API_VERSION) return FlowParseResult(emptyList(), listOf("$packId: unsupported_api_$api"))
        val packPackages = root.stringList("packages")
        val flows = root["flows"] as? JsonArray ?: return FlowParseResult(emptyList())
        val parsed = ArrayList<AppFlow>(flows.size)
        val errors = ArrayList<String>()
        for (element in flows) {
            val obj = element as? JsonObject ?: continue
            val id = obj.string("id")?.takeIf { it.isNotBlank() }
            if (id == null) {
                errors += "$packId: flow_without_id"
                continue
            }
            try {
                parsed += parseFlow(obj, id, packId, packPackages)
            } catch (t: Throwable) {
                errors += "$packId/$id: ${t.message ?: "invalid"}"
            }
        }
        return FlowParseResult(parsed, errors)
    }

    private fun parseFlow(obj: JsonObject, id: String, packId: String, packPackages: List<String>): AppFlow {
        val steps = parseSteps(obj["steps"], "$packId/$id")
        if (steps.isEmpty()) throw IllegalArgumentException("no_steps")
        return AppFlow(
            id = id,
            title = obj.string("title"),
            description = obj.string("description"),
            packages = obj.stringList("packages").ifEmpty { packPackages },
            params = parseParams(obj["params"]),
            steps = steps,
            packId = packId,
        )
    }

    private fun parseParams(raw: kotlinx.serialization.json.JsonElement?): List<FlowParam> {
        val map = raw as? JsonObject ?: return emptyList()
        return map.mapNotNull { (name, value) ->
            val o = value as? JsonObject ?: return@mapNotNull FlowParam(name, "string", null, null)
            FlowParam(
                name = name,
                type = o.string("type") ?: "string",
                default = o["default"]?.jsonPrimitive?.contentOrNull,
                description = o.string("description"),
            )
        }
    }

    private fun parseSteps(raw: kotlinx.serialization.json.JsonElement?, path: String): List<FlowStep> {
        val array = raw as? JsonArray ?: return emptyList()
        return array.mapNotNull { element ->
            val obj = element as? JsonObject ?: return@mapNotNull null
            val op = obj.string("op")?.trim()?.lowercase()
                ?: throw IllegalArgumentException("step_without_op")
            if (op !in OPS) throw IllegalArgumentException("unknown_op:$op")
            val stepPath = "$path/$op"
            when (op) {
                "if" -> FlowStep(
                    op = op,
                    raw = obj,
                    then = parseSteps(obj["then"], "$stepPath.then"),
                    otherwise = parseSteps(obj["else"], "$stepPath.else"),
                )
                "repeat" -> FlowStep(
                    op = op,
                    raw = obj,
                    body = parseSteps(obj["steps"], "$stepPath.steps"),
                )
                else -> FlowStep(op = op, raw = obj)
            }
        }
    }

    /** 把 `{"query": {...}}` 解析成选择器；没有 query 时返回 null（`tap` 可以用 `at`）。 */
    fun selector(raw: JsonObject?): FlowSelector? {
        val obj = raw ?: return null
        val texts = buildList {
            obj.string("text")?.let(::add)
            addAll(obj.stringList("textAny"))
        }
        val selector = FlowSelector(
            text = texts.firstOrNull(),
            textAny = texts.drop(1),
            role = obj.string("role"),
            id = obj.string("id"),
            source = when (obj.string("source")?.lowercase()) {
                "text" -> FlowSelector.Source.TEXT
                else -> FlowSelector.Source.A11Y
            },
            pick = when (obj.string("pick")?.lowercase()) {
                "last" -> FlowSelector.Pick.LAST
                "maxy" -> FlowSelector.Pick.MAX_Y
                "miny" -> FlowSelector.Pick.MIN_Y
                "nearest" -> FlowSelector.Pick.NEAREST
                else -> FlowSelector.Pick.FIRST
            },
            near = obj.string("near"),
            exclude = obj.stringList("exclude"),
        )
        return selector.takeUnless { it.isEmpty }
    }

    private fun JsonObject.string(key: String): String? = (this[key] as? JsonPrimitive)?.contentOrNull?.trim()

    private fun JsonObject.int(key: String): Int? = (this[key] as? JsonPrimitive)?.intOrNull

    private fun JsonObject.stringList(key: String): List<String> = when (val v = this[key]) {
        is JsonArray -> v.mapNotNull { (it as? JsonPrimitive)?.contentOrNull?.trim()?.takeIf(String::isNotEmpty) }
        is JsonPrimitive -> v.contentOrNull?.split(',')?.map(String::trim)?.filter(String::isNotEmpty).orEmpty()
        else -> emptyList()
    }
}
