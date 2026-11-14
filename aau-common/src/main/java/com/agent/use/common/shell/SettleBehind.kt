package com.agent.use.common.shell

/**
 * Pure state machine governing how moved tasks settle behind the main screen stack during
 * `finishDisplay`, retrying back-reordering until transitions finish or closing visible leftovers.
 */
object SettleBehind {
    const val TIMEOUT_MS = 2_000L
    const val REORDER_EVERY_MS = 750L
    const val POLL_MS = 100L

    /** Observed state of a moved task on the main display. */
    data class Seen(val id: Int, val onMain: Boolean, val visible: Boolean)

    sealed interface Plan {
        /** Tasks are still transitioning; reorder any visible ones on schedule and stop tracking gone ones. */
        data class Wait(val reorder: Set<Int>, val gone: Set<Int>) : Plan

        /** Final decision after transitions completed or [TIMEOUT_MS] elapsed. */
        data class Done(val kept: Set<Int>, val fallback: Set<Int>, val gone: Set<Int>) : Plan
    }

    /** Evaluates one polling step while waiting for [moved] tasks to become invisible on main. */
    fun plan(moved: Set<Int>, seen: List<Seen>, elapsedMs: Long, sinceReorderMs: Long?): Plan {
        val byId = seen.associateBy { it.id }
        val gone = moved.filterTo(LinkedHashSet()) { byId[it]?.onMain != true }
        val front = moved.filterTo(LinkedHashSet()) { byId[it]?.let { s -> s.onMain && s.visible } == true }
        val behind = moved - gone - front
        if (front.isEmpty()) return Plan.Done(behind, emptySet(), gone)
        if (elapsedMs >= TIMEOUT_MS) return Plan.Done(behind, front, gone)
        val due = sinceReorderMs == null || sinceReorderMs >= REORDER_EVERY_MS
        return Plan.Wait(if (due) front else emptySet(), gone)
    }

    /** Re-evaluates settled tasks back under lock so user-reopened or already-closed tasks are untouched. */
    fun closeOut(moved: Set<Int>, fallback: Set<Int>, seen: List<Seen>): Plan.Done {
        val byId = seen.associateBy { it.id }
        val gone = moved.filterTo(LinkedHashSet()) { byId[it]?.onMain != true }
        val front = (fallback intersect moved).filterTo(LinkedHashSet()) { byId[it]?.let { s -> s.onMain && s.visible } == true }
        return Plan.Done(moved - gone - front, front, gone)
    }
}
