package com.agent.use.ui

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.delay

/** 一次「等界面出现/消失/到达某个 App」的条件。不给的项不看。 */
data class Until(
    val appears: String? = null,
    val gone: String? = null,
    val place: String? = null,
    val stable: Boolean = false,
    val timeoutMs: Long = DEFAULT_MS,
) {
    companion object {
        const val DEFAULT_MS = 8_000L
        const val MAX_MS = 20_000L
    }
}

/**
 * 等的结局:[met] 条件成立;没成立时 [stopped] 说明为什么不再等——[TIMEOUT] 到了时限,或提前看出的意外:
 * [POPUP] 同一 App 多了一个窗口(弹框)或页面弹了框,[SYSTEM_DIALOG] 别的包的窗口盖了上来(权限、系统对话框),
 * [APP_SWITCHED] 前台换成了别的 App,[NEW_MESSAGE] 宿主插了话。[waitedMs] 是等了多久。
 */
data class UntilOutcome(val met: Boolean, val stopped: String?, val waitedMs: Long) {
    companion object {
        const val TIMEOUT = "timeout"
        const val POPUP = "popup"
        const val SYSTEM_DIALOG = "system_dialog"
        const val APP_SWITCHED = "app_switched"
        const val NEW_MESSAGE = "new_message"
    }
}

/**
 * 等待期间能不能被打断:宿主把人插话、任务取消一类的信号包在这里,等待就提前结束(撤掉不丢任何东西)。
 * [OPEN] 是不打断(照常等满)。
 */
interface WaitGate {
    /** 跑 [block];打断已到或在它进行中到达就撤掉它、返回 null。 */
    suspend fun <T : Any> guard(block: suspend () -> T): T?

    companion object {
        val OPEN: WaitGate = object : WaitGate {
            override suspend fun <T : Any> guard(block: suspend () -> T): T? = block()
        }
    }
}

/** 两次读屏至少隔这么久:界面事件一阵一阵来,不必每条都读一遍。 */
private const val MIN_GAP_MS = 200L
/** 端口不报界面事件时,隔这么久重读一次;也是两次看有没有被打断的最长间隔。 */
private const val POLL_MS = 500L
/** 等「界面稳定」时每次交给端口等的上限(端口按自己的安静时长判)。 */
private const val STABLE_SLICE_MS = 1_500L
/** 意外要连着读到几次才算数(页面换页时新旧窗口会短暂同时在)。 */
private const val CONFIRM_READS = 2

/**
 * 一批动作里一步做完后的等待:按 [Until] 逐次读屏(不登记编号)做字面比较,手机、网页同一套,只经 [ScreenSurface] 与读屏结果。
 * 端口有界面事件时提前醒来([ScreenSurface.awaitChange]),否则隔一会儿重读。看出意外(弹框、别的包盖上来、换了 App)、
 * 被打断、到了时限就不再等,交回去由调用方判断。基准是开始等时的那一屏:这一步本身引起的切换由执行入口另外核对。
 */
class ScreenWaiter(
    private val screen: ScreenSurface,
    private val read: suspend () -> ScreenSnapshot?,
    private val clock: () -> Long,
    private val interrupted: () -> Boolean = { false },
    private val gate: WaitGate = WaitGate.OPEN,
) {
    suspend fun run(until: Until): UntilOutcome {
        val start = clock()
        val timeout = until.timeoutMs.coerceIn(0, Until.MAX_MS)
        // 时钟不走(测试、时钟出错)时也一定结束:每轮至少花 MIN_GAP_MS
        val maxRounds = timeout / MIN_GAP_MS + 2
        var base: ScreenSnapshot? = null
        var stableNow = false
        var suspect: String? = null
        var seen = 0
        fun done(met: Boolean, stopped: String?) = UntilOutcome(met, stopped, (clock() - start).coerceAtLeast(0))
        repeat(maxRounds.toInt()) {
            val snap = read()
            if (snap != null) {
                val first = base ?: snap.also { base = it }
                // 有意外时这一轮不算成立:弹框后面露出的字不代表能接着做
                val odd = unexpected(first, snap, until)
                if (odd == null && (!until.stable || stableNow) && holds(until, snap)) return done(true, null)
                if (odd != null && odd == suspect) seen++ else { suspect = odd; seen = if (odd == null) 0 else 1 }
                // 页面弹框挂着时页面停着,不必再读一次确认
                if (suspect != null && (seen >= CONFIRM_READS || snap.web?.dialog != null)) return done(false, suspect)
            }
            if (interrupted()) return done(false, UntilOutcome.NEW_MESSAGE)
            val left = timeout - (clock() - start)
            if (left <= 0) return done(false, UntilOutcome.TIMEOUT)
            // 每段等待都在被打断时立刻结束,不等到下一轮才看
            if (until.stable) {
                stableNow = gate.guard { waitStable(minOf(left, STABLE_SLICE_MS)) } ?: return done(false, UntilOutcome.NEW_MESSAGE)
            } else if (gate.guard { awaitChange(minOf(left, POLL_MS)) } ?: return done(false, UntilOutcome.NEW_MESSAGE)) {
                delay(MIN_GAP_MS)
            }
        }
        return done(false, UntilOutcome.TIMEOUT)
    }

    private suspend fun waitStable(ms: Long): Boolean =
        try { screen.waitStable(ms) } catch (e: CancellationException) { throw e } catch (e: Exception) { delay(ms); false }

    private suspend fun awaitChange(ms: Long): Boolean =
        try { screen.awaitChange(ms) } catch (e: CancellationException) { throw e } catch (e: Exception) { delay(ms); false }

    companion object {
        /** 条件此刻是否成立(只看给了的几项);和动作结果里 expect 的核对一样按元素名字比,不分大小写。 */
        fun holds(until: Until, s: ScreenSnapshot): Boolean {
            val names = s.elements.map { it.name }
            until.appears?.trim()?.let { want -> if (names.none { it.contains(want, ignoreCase = true) }) return false }
            // 什么都没读到(受保护、读不到)不算「已经没了」
            until.gone?.trim()?.let { gone -> if (names.isEmpty() || names.any { it.contains(gone, ignoreCase = true) }) return false }
            until.place?.trim()?.let { p -> if (!inPlace(s, p)) return false }
            return true
        }

        private fun inPlace(s: ScreenSnapshot, p: String) =
            s.packageName?.contains(p, ignoreCase = true) == true || s.web?.url?.contains(p, ignoreCase = true) == true

        /**
         * 和开始等时那一屏 [base] 比,此刻 [now] 有没有明显的意外;没有为 null。
         * 页面弹框挂着、同一 App 多出一个应用窗口为 [UntilOutcome.POPUP];多出别的包的应用或系统窗口为 [UntilOutcome.SYSTEM_DIALOG];
         * 前台换成别的 App(且不是 [until] 要等的那个)为 [UntilOutcome.APP_SWITCHED]。网页换站点是正常的跳转,不算换了 App。
         */
        fun unexpected(base: ScreenSnapshot, now: ScreenSnapshot, until: Until): String? {
            if (now.web?.dialog != null && base.web?.dialog == null) return UntilOutcome.POPUP
            val top = now.packageName
            val foreign = { s: ScreenSnapshot ->
                s.windows.filter { it.type in OVERLAY_TYPES && it.packageName != null && it.packageName != s.packageName }.map { it.id }.toSet()
            }
            if ((foreign(now) - foreign(base)).isNotEmpty()) return UntilOutcome.SYSTEM_DIALOG
            if (now.web == null && top != null && top != base.packageName && until.place?.let { inPlace(now, it.trim()) } != true) return UntilOutcome.APP_SWITCHED
            val own = { s: ScreenSnapshot -> s.windows.count { it.type == APPLICATION && it.packageName == top } }
            if (top == base.packageName && own(now) > own(base)) return UntilOutcome.POPUP
            return null
        }

        private const val APPLICATION = "application"
        private val OVERLAY_TYPES = setOf(APPLICATION, "system")
    }
}
