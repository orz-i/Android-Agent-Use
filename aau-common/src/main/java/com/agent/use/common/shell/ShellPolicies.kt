package com.agent.use.common.shell

/**
 * Whitelist of navigation and editing keycodes permitted on virtual displays.
 */
object ShellPressKeys {
    val BY_NAME: Map<String, Int> = linkedMapOf(
        "KEYCODE_DPAD_UP" to 19,
        "KEYCODE_DPAD_DOWN" to 20,
        "KEYCODE_DPAD_LEFT" to 21,
        "KEYCODE_DPAD_RIGHT" to 22,
        "KEYCODE_DPAD_CENTER" to 23,
        "KEYCODE_ENTER" to 66,
        "KEYCODE_NUMPAD_ENTER" to 160,
        "KEYCODE_DEL" to 67,
        "KEYCODE_FORWARD_DEL" to 112,
        "KEYCODE_TAB" to 61,
        "KEYCODE_SPACE" to 62,
        "KEYCODE_ESCAPE" to 111,
        "KEYCODE_PAGE_UP" to 92,
        "KEYCODE_PAGE_DOWN" to 93,
        "KEYCODE_MOVE_HOME" to 122,
        "KEYCODE_MOVE_END" to 123,
        "KEYCODE_BACK" to 4,
        "KEYCODE_MENU" to 82,
    )
    private val CODES: Set<Int> = BY_NAME.values.toSet()

    /** Returns `true` if [keyCode] is in the safe navigation/editing whitelist. */
    fun isAllowed(keyCode: Int): Boolean = keyCode in CODES

    /** Resolves a key name or integer code if permitted, otherwise `null`. */
    fun resolve(key: String): Int? {
        val k = key.trim()
        val code = k.toIntOrNull() ?: BY_NAME[k] ?: return null
        return code.takeIf(::isAllowed)
    }
}

/**
 * Safety policy for opening links, deep links, and Android settings actions from shell.
 */
object ShellLinkPolicy {
    const val APP_DETAILS = "android.settings.APPLICATION_DETAILS_SETTINGS"

    val SETTINGS_ACTIONS: Set<String> = setOf(
        "android.settings.SETTINGS",
        "android.settings.WIFI_SETTINGS",
        "android.settings.BLUETOOTH_SETTINGS",
        "android.settings.DISPLAY_SETTINGS",
        "android.settings.SOUND_SETTINGS",
        "android.settings.BATTERY_SAVER_SETTINGS",
        APP_DETAILS,
        "android.settings.APPLICATION_SETTINGS",
        "android.settings.DATE_SETTINGS",
        "android.settings.LOCALE_SETTINGS",
        "android.settings.DEVICE_INFO_SETTINGS",
        "android.settings.LOCATION_SOURCE_SETTINGS",
        "android.settings.INTERNAL_STORAGE_SETTINGS",
        "android.settings.ACCESSIBILITY_SETTINGS",
    )

    private val BLOCKED_SCHEMES = setOf("intent", "file", "content", "javascript")
    private val SCHEME = Regex("^([A-Za-z][A-Za-z0-9+.-]*):")
    val PACKAGE = Regex("^[A-Za-z0-9_]+(?:\\.[A-Za-z0-9_]+)+$")
    private const val MAX_URI = 2000

    /** Returns `null` if permitted, or a descriptive error reason if rejected. */
    fun check(action: String?, uri: String?, pkg: String?): String? {
        if (action == null && uri == null) return "Give uri, or action for an Android settings page."
        if (pkg != null && !PACKAGE.matches(pkg)) return "package must be an Android package name."
        if (uri != null && (uri.length > MAX_URI || uri.any { it.isWhitespace() || it.isISOControl() })) {
            return "uri must be at most $MAX_URI characters without spaces."
        }
        if (action != null) {
            if (action !in SETTINGS_ACTIONS) return "action must be one of the Android settings actions: ${SETTINGS_ACTIONS.joinToString()}."
            if (pkg != null) return "package is not used with action."
            if (action == APP_DETAILS) {
                val target = uri?.takeIf { it.startsWith("package:") }?.removePrefix("package:")
                if (target == null || !PACKAGE.matches(target)) {
                    return "$APP_DETAILS needs uri package:<package name>, e.g. package:com.example.app."
                }
            } else if (uri != null) {
                return "Only $APP_DETAILS takes a uri; open other settings pages with action alone."
            }
            return null
        }
        val scheme = SCHEME.find(uri!!)?.groupValues?.get(1)?.lowercase()
            ?: return "uri must start with a scheme, e.g. https:// or app://."
        if (scheme in BLOCKED_SCHEMES) return "$scheme: links are not supported."
        if (scheme == "package") return "package: uris are only for action $APP_DETAILS."
        if ((scheme == "http" || scheme == "https") && pkg == null) {
            return "A web link needs package (the app that should open it); otherwise it would open in a browser."
        }
        return null
    }
}

/**
 * Shell-side link validation and main-screen conflict helpers.
 */
object ShellLinks {
    const val START_INVALID_LINK = 6

    /** Returns [START_INVALID_LINK] if the link/action violates [ShellLinkPolicy], or `null` when allowed. */
    fun refuse(action: String?, uri: String?, pkg: String?): Int? =
        if (ShellLinkPolicy.check(action, uri, pkg) != null) START_INVALID_LINK else null

    /** Returns `true` if candidates cannot be resolved or any candidate currently owns a main-screen task. */
    fun inUse(candidates: List<String>, onMainScreen: Set<String>): Boolean =
        candidates.isEmpty() || candidates.any { it in onMainScreen }
}

/**
 * Identifies safe multi-user app copies (clone/managed/parallel profiles) while strictly excluding
 * private spaces, guest/demo/ephemeral/disabled profiles, or locked/quiet profiles.
 */
object ShellAppCopies {
    const val FLAG_GUEST = 0x4
    const val FLAG_DISABLED = 0x40
    const val FLAG_QUIET_MODE = 0x80
    const val FLAG_EPHEMERAL = 0x100
    const val FLAG_DEMO = 0x200
    private const val EXCLUDED_FLAGS = FLAG_GUEST or FLAG_DISABLED or FLAG_EPHEMERAL or FLAG_DEMO
    private val EXCLUDED_NAMES = setOf("GUEST", "DEMO", "EPHEMERAL", "DISABLED")

    const val NO_PROFILE_GROUP = -10000
    const val TYPE_MANAGED = "android.os.usertype.profile.MANAGED"

    /** User profile metadata read from UserManager/UserInfo/UserProperties. */
    data class User(
        val id: Int,
        val flags: Int,
        val type: String?,
        val profileGroupId: Int,
        val running: Boolean,
        val unlocked: Boolean = running,
        val quiet: Boolean = false,
        val mediaShared: Boolean? = null,
        val hidden: Boolean? = null,
        val flagNames: List<String>? = null,
        val parentId: Int? = null,
    )

    enum class Verdict {
        Copy,
        Self,
        Private,
        Flags,
        Stopped,
        Locked,
        Quiet,
        NotLinked,
        NotCopy,
    }

    /** Evaluates whether user [u] is an eligible app-copy profile linked to [current]/[group]. */
    fun verdict(u: User, current: Int, group: Int): Verdict {
        val type = u.type.orEmpty()
        val names = u.flagNames.orEmpty().map { it.uppercase() }
        return when {
            u.id == current -> Verdict.Self
            type.contains("private", ignoreCase = true) || u.hidden == true ||
                names.any { "HIDDEN" in it || "PRIVATE" in it } -> Verdict.Private

            (if (u.flagNames != null) names.any { it in EXCLUDED_NAMES } else u.flags and EXCLUDED_FLAGS != 0) -> Verdict.Flags
            !u.running -> Verdict.Stopped
            !u.unlocked -> Verdict.Locked
            u.quiet || u.flags and FLAG_QUIET_MODE != 0 || "QUIET_MODE" in names -> Verdict.Quiet
            !(u.profileGroupId == group && group != NO_PROFILE_GROUP) && u.parentId != current -> Verdict.NotLinked
            type.contains("clone", ignoreCase = true) || names.any { "CLONE" in it } || u.mediaShared == true || type == TYPE_MANAGED -> Verdict.Copy
            else -> Verdict.NotCopy
        }
    }

    /** Profile group ID of [current], falling back to [current] when ungrouped. */
    fun groupOf(current: Int, users: List<User>): Int =
        users.firstOrNull { it.id == current }?.profileGroupId?.takeIf { it != NO_PROFILE_GROUP } ?: current

    /** IDs of other users eligible for running app copies. */
    fun usable(current: Int, users: List<User>): List<Int> {
        val group = groupOf(current, users)
        return users.filter { verdict(it, current, group) == Verdict.Copy }.map { it.id }
    }

    /** Compact diagnostic summary across non-current users. */
    fun summary(current: Int, users: List<User>): String {
        val group = groupOf(current, users)
        val others = users.filter { it.id != current }
        val usableCount = others.count { verdict(it, current, group) == Verdict.Copy }
        if (others.isEmpty()) return "no other users"
        return "${others.size} other, $usableCount usable: " + others.joinToString("; ") { u ->
            "${u.id} flags=0x${Integer.toHexString(u.flags)}" + (u.flagNames?.let { " (${it.joinToString("|")})" } ?: "") +
                " type=${u.type ?: "?"} group=${u.profileGroupId}" + (u.parentId?.let { " parent=$it" } ?: "") +
                (if (!u.running) " stopped" else if (u.unlocked) " unlocked" else " locked") +
                " -> ${verdict(u, current, group).name.lowercase()}"
        }
    }

    data class Dumped(val flagNames: List<String>?, val parentId: Int?)

    private val DUMP_USER = Regex("""UserInfo\{(\d+):""")
    private val DUMP_PARENT = Regex("""parentId=(-?\d+)""")
    private val DUMP_FLAGS = Regex("""^\s*Flags:\s*-?\d+\s*\(([^)]*)\)""")

    /** Parses `dumpsys user` output to recover flag names and `parentId` when reflection omits them. */
    fun parseDumpsys(output: String): Map<Int, Dumped> {
        val out = linkedMapOf<Int, Dumped>()
        var id: Int? = null
        for (line in output.lineSequence()) {
            val user = DUMP_USER.find(line)
            if (user != null) {
                val u = user.groupValues[1].toInt()
                id = u
                out[u] = Dumped(null, DUMP_PARENT.find(line)?.groupValues?.get(1)?.toInt())
                continue
            }
            val u = id ?: continue
            val flags = DUMP_FLAGS.find(line) ?: continue
            out[u] = out.getValue(u).copy(flagNames = flags.groupValues[1].split('|').map(String::trim).filter(String::isNotEmpty))
        }
        return out
    }
}

/**
 * Validates WebView DevTools abstract Unix socket names and `/proc/<pid>/status` UID ownership.
 */
object ShellDevtoolsSocket {
    private const val PREFIX = "webview_devtools_remote_"
    private val NAME = Regex("""webview_devtools_remote_([1-9][0-9]{0,9})""")

    fun name(pid: Int): String = "$PREFIX$pid"

    /** Extracts a positive PID from `webview_devtools_remote_<pid>`, or `null` if malformed. */
    fun pidOf(name: String): Int? = NAME.matchEntire(name)?.groupValues?.get(1)?.toIntOrNull()?.takeIf { it > 0 }

    /** Extracts the real UID from the `Uid:` line in `/proc/<pid>/status`. */
    fun procUid(status: String): Int? =
        status.lineSequence().firstOrNull { it.startsWith("Uid:") }
            ?.removePrefix("Uid:")?.trim()?.split(Regex("\\s+"))?.firstOrNull()?.toIntOrNull()
}
