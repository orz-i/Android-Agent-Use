package com.agent.use.flow

import kotlinx.coroutines.delay
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull

/**
 * 跑一条 [AppFlow]。
 *
 * 解释器只认九个 op，全部是「屏幕上发生的事」，没有变量运算、没有表达式、没有脚本注入：
 * 插件包里的脚本能力越少越好审，缺什么再加一个 op，比放一个通用求值器安全得多。
 *
 * 每个 op 都通过 [FlowHost] 落到宿主：宿主负责读屏、落指、取前台，解释器只负责顺序、
 * 重试、选择器和控制流。所以同一份脚本换一套读屏实现（无障碍 / OCR / 视觉）照样能跑。
 */
class FlowRunner(
    private val host: FlowHost,
    /** 轮询间隔。读屏本身有成本，太快只会把同一帧读很多遍。 */
    private val pollMs: Long = 450,
) {

    suspend fun run(flow: AppFlow, params: Map<String, String> = emptyMap()): FlowResult {
        val state = State(flow, params)
        try {
            state.exec(flow.steps, round = 0)
        } catch (t: Throwable) {
            state.failed("error:${t.message ?: t::class.simpleName}")
        }
        return FlowResult(
            ok = !state.failed,
            stopped = state.stopped,
            steps = state.steps,
            trace = state.trace.toList(),
            vars = state.vars.toMap(),
        )
    }

    private inner class State(flow: AppFlow, params: Map<String, String>) {
        val vars = LinkedHashMap<String, String>()
        val trace = ArrayList<FlowTrace>()
        var steps = 0
        var stopped = "done"
        var failed = false

        init {
            flow.params.forEach { p -> p.default?.let { vars[p.name] = it } }
            params.forEach { (k, v) -> vars[k] = v }
        }

        fun failed(reason: String) {
            failed = true
            stopped = reason
        }

        fun stop(reason: String) {
            stopped = reason
        }

        /** 返回 false 表示整条脚本到此为止。 */
        suspend fun exec(list: List<FlowStep>, round: Int): Boolean {
            for (step in list) {
                if (!execOne(step, round)) return false
            }
            return true
        }

        private suspend fun execOne(step: FlowStep, round: Int): Boolean {
            steps++
            return when (step.op) {
                "tap" -> tap(step, round)
                "wait" -> wait(step, round)
                "sleep" -> {
                    val ms = number(step.raw["ms"]) ?: 0L
                    delay(ms.coerceIn(0, 120_000))
                    note(round, step.op, "${ms}ms")
                    true
                }
                "back" -> {
                    val times = (number(step.raw["times"]) ?: 1).toInt().coerceIn(1, 5)
                    var done = 0
                    while (done < times) {
                        if (!host.back()) {
                            note(round, step.op, "failed", ok = false)
                            failed("back_failed")
                            return false
                        }
                        done++
                        delay(600)
                    }
                    note(round, step.op, "$done")
                    true
                }
                "returnto" -> returnTo(step, round)
                "if" -> branch(step, round)
                "repeat" -> repeat(step, round)
                "stop" -> {
                    val reason = text(step.raw["reason"]) ?: "stopped"
                    note(round, step.op, reason)
                    stop(reason)
                    false
                }
                "log" -> {
                    val line = text(step.raw["text"]).orEmpty()
                    host.log(line)
                    note(round, step.op, line)
                    true
                }
                else -> {
                    failed("unknown_op:${step.op}")
                    false
                }
            }
        }

        private suspend fun tap(step: FlowStep, round: Int): Boolean {
            val at = points(step.raw["at"])
            if (at != null) {
                val ok = host.tapAt(at.first, at.second)
                note(round, step.op, "${at.first},${at.second}", ok)
                if (!ok && !optional(step)) failed("tap_failed")
                return ok || optional(step)
            }
            val selector = AppFlowSpec.selector(step.raw["query"] as? JsonObject)
            if (selector == null) {
                failed("tap_without_query")
                return false
            }
            val label = fillSelector(selector).label
            val hit = pick(selector)
            if (hit == null) {
                note(round, step.op, "miss:$label", ok = false)
                if (optional(step)) return true
                failed("not_found:$label")
                return false
            }
            val ok = host.tap(hit)
            note(round, step.op, hit.name.take(24).ifEmpty { label }, ok)
            if (!ok) {
                if (optional(step)) return true
                failed("tap_failed:$label")
                return false
            }
            return true
        }

        private suspend fun wait(step: FlowStep, round: Int): Boolean {
            val selector = AppFlowSpec.selector(step.raw["query"] as? JsonObject)
            if (selector == null) {
                failed("wait_without_query")
                return false
            }
            val label = fillSelector(selector).label
            val gone = step.raw.bool("gone") ?: false
            val timeout = (number(step.raw["timeoutMs"]) ?: 8_000L).coerceIn(0, 120_000)
            val rounds = (timeout / pollMs).coerceAtLeast(1).toInt()
            repeat(rounds) {
                val found = pick(selector) != null
                if (found != gone) {
                    note(round, step.op, label)
                    return true
                }
                delay(pollMs)
            }
            note(round, step.op, "timeout:$label", ok = false)
            val stopReason = text(step.raw["stop"])
            if (!stopReason.isNullOrBlank()) {
                stop(stopReason)
                return false
            }
            if (optional(step)) return true
            failed("timeout:$label")
            return false
        }

        private suspend fun branch(step: FlowStep, round: Int): Boolean {
            val condition = condition(step.raw) ?: run {
                failed("if_without_condition")
                return false
            }
            return if (condition) exec(step.then, round) else exec(step.otherwise, round)
        }

        private suspend fun condition(raw: JsonObject): Boolean? {
            (AppFlowSpec.selector(raw["query"] as? JsonObject))?.let { return pick(it) != null }
            (AppFlowSpec.selector(raw["not"] as? JsonObject))?.let { return pick(it) == null }
            text(raw["foreground"])?.let { want ->
                val actual = host.foreground() ?: return false
                return if (want.startsWith("!")) !actual.equals(want.drop(1), ignoreCase = true)
                else actual.equals(want, ignoreCase = true)
            }
            return null
        }

        private suspend fun repeat(step: FlowStep, round: Int): Boolean {
            val times = (number(step.raw["times"]) ?: 1).toInt().coerceIn(0, 50)
            if (times == 0) return true
            val name = text(step.raw["as"]) ?: "round"
            for (i in 1..times) {
                vars[name] = i.toString()
                if (!exec(step.body, i)) return false
            }
            return true
        }

        private suspend fun returnTo(step: FlowStep, round: Int): Boolean {
            val pkg = text(step.raw["package"])
            if (pkg.isNullOrBlank()) {
                failed("returnTo_without_package")
                return false
            }
            val max = (number(step.raw["max"]) ?: 3).toInt().coerceIn(1, 8)
            val settle = (number(step.raw["settleMs"]) ?: 700L).coerceIn(0, 5_000)
            var backs = 0
            while (backs < max && host.foreground() != pkg) {
                if (!host.back()) {
                    failed("back_failed")
                    return false
                }
                backs++
                delay(settle)
            }
            note(round, step.op, "$backs")
            if (host.foreground() != pkg) {
                failed("stuck_outside")
                return false
            }
            return true
        }

        /**
         * 挑一个命中。
         *
         * `nearest` 的锚点必须**先查**：`phone_query` 每查一次刷新一次快照，先查目标再查锚点，
         * 目标那批 ref 就过期了。这里先读锚点（只要坐标）、再读目标（ref 是新的），顺序和作用与
         * `phone_watch_reward_videos` 里一样。
         */
        private fun fillSelector(raw: FlowSelector): FlowSelector = raw.copy(
            text = raw.text?.let { fill(it) },
            textAny = raw.textAny.map { fill(it) },
            role = raw.role?.let { fill(it) },
            id = raw.id?.let { fill(it) },
            near = raw.near?.let { fill(it) },
            exclude = raw.exclude.map { fill(it) },
        )

        private suspend fun pick(raw: FlowSelector): FlowHit? {
            val selector = fillSelector(raw)
            var anchor: FlowHit? = null
            if (selector.pick == FlowSelector.Pick.NEAREST && !selector.near.isNullOrBlank()) {
                anchor = host.find(selector.copy(text = selector.near, textAny = emptyList(), near = null, pick = FlowSelector.Pick.FIRST))
                    .firstOrNull()
            }
            val hits = host.find(selector.copy(near = null)).filter { h ->
                selector.exclude.none { h.name.contains(it, ignoreCase = true) }
            }
            if (hits.isEmpty()) return null
            return when (selector.pick) {
                FlowSelector.Pick.FIRST -> hits.first()
                FlowSelector.Pick.LAST -> hits.last()
                FlowSelector.Pick.MAX_Y -> hits.maxByOrNull { it.center.second }
                FlowSelector.Pick.MIN_Y -> hits.minByOrNull { it.center.second }
                FlowSelector.Pick.NEAREST -> {
                    if (anchor == null) hits.first()
                    else hits.minByOrNull { h ->
                        val dx = (h.center.first - anchor.center.first).toLong()
                        val dy = (h.center.second - anchor.center.second).toLong()
                        dx * dx + dy * dy
                    }
                }
            }
        }

        private fun note(round: Int, op: String, on: String, ok: Boolean = true) {
            trace += FlowTrace(round, op, on, ok)
        }

        private fun optional(step: FlowStep): Boolean = step.raw.bool("optional") ?: false

        private fun text(value: kotlinx.serialization.json.JsonElement?): String? {
            val raw = (value as? JsonPrimitive)?.contentOrNull ?: return null
            return fill(raw)
        }

        /** 把 `${name}` 换成参数；缺参数直接报错，别拿空串去点屏幕。 */
        private fun fill(raw: String): String {
            if (!raw.contains("\${")) return raw
            return PLACEHOLDER.replace(raw) { m ->
                val key = m.groupValues[1]
                vars[key] ?: throw IllegalArgumentException("missing_var:$key")
            }
        }

        private fun number(value: kotlinx.serialization.json.JsonElement?): Long? {
            val prim = value as? JsonPrimitive ?: return null
            prim.intOrNull?.let { return it.toLong() }
            return prim.contentOrNull?.let { fill(it).trim().toLongOrNull() }
        }

        private fun points(value: kotlinx.serialization.json.JsonElement?): Pair<Int, Int>? {
            val array = value as? JsonArray ?: return null
            val nums = array.mapNotNull { (it as? JsonPrimitive)?.intOrNull }
            if (nums.size < 2) return null
            return nums[0].coerceIn(0, 999) to nums[1].coerceIn(0, 999)
        }

        private fun JsonObject.bool(key: String): Boolean? =
            (this[key] as? JsonPrimitive)?.booleanOrNull
    }

    private companion object {
        // `}` 在 Android 的 ICU 正则里必须转义，否则类加载就抛 PatternSyntaxException。
        val PLACEHOLDER = Regex("\\$\\{([A-Za-z0-9_.-]+)\\}")
    }
}
