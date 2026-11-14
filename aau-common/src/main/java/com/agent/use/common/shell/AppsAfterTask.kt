package com.agent.use.common.shell

import com.agent.use.common.AppAudioKey

/**
 * Policy engine deciding which tasks on a virtual display should be kept behind on the main
 * display stack vs closed when finishing the display.
 */
object AppsAfterTask {
    /** Wire reason written into `finishDisplay` closed entries and diagnostics. */
    enum class Why(val wire: String) {
        Marked("marked"),
        Playing("playing"),
        PlaybackUnknown("playback_unknown"),
        Default("default"),
        Own("mika"),
        NotApp("not_app"),
        MoveUnsupported("move_not_supported"),
        StillInFront("still_in_front"),
    }

    /** Snapshot of a task on the virtual display evaluated by [decide]. */
    data class Task(
        val id: Int,
        val keys: List<String>,
        val standard: Boolean,
        val own: Boolean,
        val playing: Boolean?,
        val muted: Boolean = false,
    )

    /** Outcome computed for a single [task]. */
    data class Fate(val task: Task, val keep: Boolean, val why: Why) {
        val key: String get() = task.keys.firstOrNull().orEmpty()
    }

    /** Canonical key matching [AppAudioKey] (`packageName` for [myUser], `packageName@userId` otherwise). */
    fun keyOf(packageName: String, userId: Int, myUser: Int): String =
        AppAudioKey.of(packageName, userId.takeIf { it != myUser && it >= 0 })

    /** Normalizes caller-supplied keep/close keys relative to [myUser], discarding invalid entries. */
    fun normalize(keys: Array<String>?, myUser: Int): Set<String> = keys.orEmpty().mapNotNull { k ->
        AppAudioKey.parse(k)?.let { (pkg, user) -> AppAudioKey.of(pkg, user?.takeIf { it != myUser }) }
    }.toSet()

    /** Computes keep/close fate for each task on the display. */
    fun decide(tasks: List<Task>, keep: Set<String>, close: Set<String>): List<Fate> = tasks.map { t ->
        when {
            t.own -> Fate(t, false, Why.Own)
            !t.standard -> Fate(t, false, Why.NotApp)
            t.keys.any { it in close } -> Fate(t, false, Why.Marked)
            t.keys.any { it in keep } -> Fate(t, true, Why.Marked)
            t.playing == true -> Fate(t, false, Why.Playing)
            t.playing == null && t.muted -> Fate(t, false, Why.PlaybackUnknown)
            else -> Fate(t, true, Why.Default)
        }
    }

    /** Re-evaluates a kept task after moving it; closes unmarked tasks that started playing before unmute. */
    fun recheck(fate: Fate, playingNow: Boolean?): Fate =
        if (fate.keep && fate.why != Why.Marked && playingNow == true) fate.copy(keep = false, why = Why.Playing) else fate

    /** Extracts actively playing UIDs from `dumpsys audio`, or `null` if playback monitor output is missing. */
    fun playingUids(dumpsys: String): Set<Int>? {
        if (!dumpsys.contains(PLAYBACK_SECTION)) return null
        return dumpsys.lineSequence()
            .filter { "AudioPlaybackConfiguration" in it }
            .mapNotNull { PLAYER.find(it) }
            .filter { it.groupValues[2] == "started" }
            .mapNotNull { it.groupValues[1].toIntOrNull() }
            .filter { it >= 0 }
            .toSet()
    }

    /** Formats a closed entry as `key:reason`. */
    fun closedEntry(f: Fate): String = "${f.key}:${f.why.wire}"

    /** Builds a package-free diagnostic summary line counting kept/closed tasks by reason. */
    fun diagnosticsLine(kept: Int, closed: List<String>, note: String?): String {
        if (kept == 0 && closed.isEmpty()) return note?.let { "none ($it)" } ?: "none"
        val reasons = closed.map { it.substringAfterLast(':') }.groupingBy { it }.eachCount()
            .entries.sortedBy { it.key }.joinToString(", ") { "${it.key.replace('_', ' ')} ${it.value}" }
        val parts = listOfNotNull(
            "kept $kept".takeIf { kept > 0 },
            if (closed.isEmpty()) null else "closed ${closed.size}" + (if (reasons.isEmpty()) "" else " ($reasons)"),
        )
        return parts.joinToString(", ") + (note?.let { "; $it" } ?: "")
    }

    const val KEY_KEPT = "kept"
    const val KEY_CLOSED = "closed"
    const val KEY_NOTE = "note"

    const val NOTE_MOVE_UNSUPPORTED = "move not supported"
    const val NOTE_PLAYBACK_UNKNOWN = "playback unknown"
    const val NOTE_STILL_IN_FRONT = "still visible on main, closed"
    const val NOTE_LEFT_HIDDEN = "left hidden on main"
    const val NOTE_SETTLE_UNKNOWN = "behind check unavailable"

    const val PLAYER_STATE_STARTED = 2
    private const val PLAYBACK_SECTION = "PlaybackActivityMonitor"
    private val PLAYER = Regex("""u/pid:(-?\d+)/-?\d+\s+state:(\w+)""")
}
