package com.agent.use.common.shell

import android.content.Intent
import android.content.pm.ActivityInfo
import java.io.File
import java.lang.reflect.Method
import java.nio.file.Files
import java.nio.file.StandardCopyOption

/**
 * Queries resolvable activities via `cmd package query-activities` when the Binder PM path
 * is restricted in privileged shell processes.
 */
object ActivityQuery {
    /** Builds `cmd package query-activities` CLI arguments for the given intent attributes. */
    fun args(
        action: String,
        type: String? = null,
        uri: String? = null,
        category: String? = null,
        packageName: String? = null,
        user: String = "current",
    ): List<String> =
        listOf("cmd", "package", "query-activities", "--brief", "--user", user, "-a", action) +
            listOfNotNull(type?.let { "-t" }, type) +
            listOfNotNull(uri?.let { "-d" }, uri) +
            listOfNotNull(category?.let { "-c" }, category) +
            listOfNotNull(packageName?.let { "-p" }, packageName)

    /** Extracts `(packageName, fullClassName)` pairs from `query-activities --brief` output. */
    fun parse(output: String): List<Pair<String, String>> = output.lineSequence().mapNotNull { line ->
        val m = COMPONENT.matchEntire(line.trim()) ?: return@mapNotNull null
        val (pkg, cls) = m.destructured
        pkg to if (cls.startsWith(".")) pkg + cls else cls
    }.distinct().toList()

    private val COMPONENT = Regex("""([A-Za-z][\w.]*)/([\w.$]+)""")
}

/**
 * Result states and printable-ASCII guard for synchronous text/modifier injection.
 */
object AsciiTextKeys {
    const val NOT_SENT = 0
    const val DISPATCHED = 1
    const val UNCONFIRMED = 2

    /** Accepts 1..256 printable ASCII characters (`0x20..0x7E`), rejecting control characters. */
    fun supports(text: String): Boolean = text.length in 1..256 && text.all { it in ' '..'~' }
}

/**
 * Cold-start decision policy when restarting an app on a virtual display.
 */
enum class ColdStart {
    RESTART,
    WARM,
    IN_USE,
    ;

    companion object {
        /** Avoids force-stopping if the app is visible on the main screen or has tasks on other displays. */
        fun decide(taskDisplays: List<Int>, agentDisplay: Int, visibleOnMain: Boolean): ColdStart = when {
            visibleOnMain -> IN_USE
            taskDisplays.any { it != agentDisplay } -> WARM
            else -> RESTART
        }
    }
}

/**
 * Coalesces bursts of scan requests so a scheduled scan is neither duplicated nor starved.
 */
class CoalescedScan(
    private val schedule: (Runnable) -> Unit,
    private val cancel: (Runnable) -> Unit,
    private val scan: () -> Unit,
) {
    private val lock = Any()
    private var queued = false
    private var closed = false
    private val work = Runnable {
        synchronized(lock) {
            if (closed) return@Runnable
            queued = false
        }
        scan()
    }

    /** Schedules a scan if one is not already queued and this instance has not been closed. */
    fun request() = synchronized(lock) {
        if (!closed && !queued) {
            queued = true
            schedule(work)
        }
    }

    /** Marks closed and cancels any pending scan callback. */
    fun close() = synchronized(lock) {
        closed = true
        cancel(work)
    }
}

/**
 * Plain-text `ACTION_SEND` intent builder and `am start` argument formatter.
 */
object ShareIntent {
    const val TYPE = "text/plain"

    /** Creates an `ACTION_SEND` intent targeting [packageName] with [text]. */
    fun of(packageName: String, text: String): Intent =
        Intent(Intent.ACTION_SEND)
            .setType(TYPE)
            .putExtra(Intent.EXTRA_TEXT, text)
            .setPackage(packageName)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)

    /** Builds `am start` arguments avoiding shell splitting on arbitrary [text]. */
    fun amArgs(displayId: Int, packageName: String, text: String, component: String?): List<String> =
        listOf("am", "start", "--display", "$displayId", "-a", Intent.ACTION_SEND, "-t", TYPE, "--es", Intent.EXTRA_TEXT, text) +
            (component?.let { listOf("-n", it) } ?: listOf("-p", packageName))
}

/**
 * Pure state machine for reading and safely restoring the user's clipboard.
 */
object ShellClip {
    enum class Read {
        Empty,
        Has,
        Unreadable,
    }

    /** Distinguishes an empty clipboard from one where content exists but background read is blocked. */
    fun read(clipPresent: Boolean, hasPrimaryClip: Boolean, descriptionPresent: Boolean): Read = when {
        clipPresent -> Read.Has
        hasPrimaryClip || descriptionPresent -> Read.Unreadable
        else -> Read.Empty
    }

    enum class Now {
        Ours,
        Empty,
        Other,
        Unreadable,
    }

    enum class Restore {
        PutBack,
        Clear,
        Leave,
    }

    /** Determines how to restore the clipboard without overwriting user changes or unreadable data. */
    fun restore(priorEmpty: Boolean, now: Now): Restore = when (now) {
        Now.Ours -> if (priorEmpty) Restore.Clear else Restore.PutBack
        Now.Empty -> if (priorEmpty) Restore.Leave else Restore.PutBack
        Now.Other, Now.Unreadable -> Restore.Leave
    }
}

/**
 * Computes target display rotation (0 or 1) from letterboxed bounds or requested orientation.
 */
object DisplayOrientation {
    /** Returns the target surface rotation when the current display axes conflict with the app axes, or `null`. */
    fun rotation(
        bufferWidth: Int,
        bufferHeight: Int,
        current: Int,
        appWidth: Int,
        appHeight: Int,
        requestedOrientation: Int = ActivityInfo.SCREEN_ORIENTATION_UNSPECIFIED,
    ): Int? {
        if (bufferWidth == bufferHeight) return null
        val appLandscape = when {
            appWidth > 0 && appHeight > 0 && appWidth != appHeight -> appWidth > appHeight
            else -> requestedLandscape(requestedOrientation) ?: return null
        }
        val naturalLandscape = bufferWidth > bufferHeight
        val currentLandscape = if (current % 2 == 0) naturalLandscape else !naturalLandscape
        if (currentLandscape == appLandscape) return null
        return if (naturalLandscape == appLandscape) 0 else 1
    }

    private fun requestedLandscape(orientation: Int): Boolean? = when (orientation) {
        ActivityInfo.SCREEN_ORIENTATION_LANDSCAPE,
        ActivityInfo.SCREEN_ORIENTATION_SENSOR_LANDSCAPE,
        ActivityInfo.SCREEN_ORIENTATION_REVERSE_LANDSCAPE,
        ActivityInfo.SCREEN_ORIENTATION_USER_LANDSCAPE,
        -> true

        ActivityInfo.SCREEN_ORIENTATION_PORTRAIT,
        ActivityInfo.SCREEN_ORIENTATION_SENSOR_PORTRAIT,
        ActivityInfo.SCREEN_ORIENTATION_REVERSE_PORTRAIT,
        ActivityInfo.SCREEN_ORIENTATION_USER_PORTRAIT,
        -> false

        else -> null
    }
}

/**
 * Keeps own-display-group virtual displays awake using strictly per-display `IPowerManager.userActivity`.
 */
class DisplayAwake(
    private val poke: (Int) -> Boolean,
    private val repeat: (Runnable) -> () -> Unit,
) {
    private val running = HashMap<Int, () -> Unit>()
    @Volatile
    private var unavailable = false

    /** Starts periodic per-display keep-awake pokes; replaces any existing timer for [displayId]. */
    fun start(displayId: Int) {
        if (unavailable) return
        val cancel = repeat(Runnable { if (!poke(displayId)) giveUp() })
        synchronized(running) { running.put(displayId, cancel) }?.invoke()
        if (unavailable) stopAll()
    }

    /** Stops the keep-awake timer for [displayId]. */
    fun stop(displayId: Int) {
        synchronized(running) { running.remove(displayId) }?.invoke()
    }

    /** Stops all active keep-awake timers. */
    fun stopAll() {
        synchronized(running) { running.values.toList().also { running.clear() } }.forEach { it() }
    }

    private fun giveUp() {
        unavailable = true
        stopAll()
    }

    companion object {
        const val PERIOD_MS = 4_000L
        const val EVENT_TOUCH = 2 // PowerManager.USER_ACTIVITY_EVENT_TOUCH
        private const val DEFAULT_DISPLAY_GROUP = 0

        /** Keep-awake is only safe and needed when the virtual display owns a non-default display group. */
        fun needed(flags: Int, ownGroupFlag: Int, groupId: Int?): Boolean =
            flags and ownGroupFlag != 0 && groupId != DEFAULT_DISPLAY_GROUP

        /** Resolves `userActivity(int displayId, long time, int event, int flags)`, rejecting the legacy main-screen overload. */
        fun userActivityMethod(cls: Class<*>): Method? = cls.methods.firstOrNull {
            it.name == "userActivity" && it.parameterTypes.contentEquals(PER_DISPLAY)
        }

        private val PER_DISPLAY = arrayOf<Class<*>>(
            Int::class.javaPrimitiveType!!,
            Long::class.javaPrimitiveType!!,
            Int::class.javaPrimitiveType!!,
            Int::class.javaPrimitiveType!!,
        )
    }
}

/**
 * Persistent ledger mapping `packageName[@userId]` keys to their prior `PLAY_AUDIO` AppOps mode.
 */
class AudioMuteLedger(private val file: File?) {
    private val modes = LinkedHashMap<String, String>()

    init {
        val text = runCatching { file?.takeIf { it.isFile }?.readText() }.getOrNull().orEmpty()
        modes.putAll(parse(text))
    }

    fun contains(key: String): Boolean = synchronized(this) { key in modes }
    operator fun get(key: String): String? = synchronized(this) { modes[key] }
    fun packages(): List<String> = synchronized(this) { modes.keys.toList() }

    /** Records [mode] for [key] and persists the ledger atomically when possible. */
    fun put(key: String, mode: String) = synchronized(this) {
        modes[key] = mode
        save()
    }

    /** Removes [key] and updates or deletes the backing file. */
    fun remove(key: String) = synchronized(this) {
        if (modes.remove(key) != null) save()
    }

    /** Restores every recorded entry via [write], keeping only failed entries for retry. */
    fun restoreAll(write: (key: String, restoreMode: String) -> Boolean): Boolean = synchronized(this) {
        packages().forEach { key ->
            val mode = restoreMode(modes.getValue(key))
            if (write(key, mode)) remove(key)
        }
        modes.isEmpty()
    }

    private fun save() {
        val f = file ?: return
        runCatching {
            if (modes.isEmpty()) {
                f.delete()
            } else {
                val tmp = File(f.parentFile, f.name + ".tmp")
                tmp.writeText(format(modes))
                try {
                    Files.move(
                        tmp.toPath(),
                        f.toPath(),
                        StandardCopyOption.REPLACE_EXISTING,
                        StandardCopyOption.ATOMIC_MOVE,
                    )
                } catch (_: Exception) {
                    Files.move(
                        tmp.toPath(),
                        f.toPath(),
                        StandardCopyOption.REPLACE_EXISTING,
                    )
                }
            }
        }
    }

    companion object {
        private val LINE = Regex("""([A-Za-z0-9_.]+(?:@[0-9]+)?) ([a-z_]+)""")

        /** Normalizes `"default"` or blank prior modes to `"allow"` so Android unmutes playback reliably. */
        fun restoreMode(prior: String?): String = if (prior.isNullOrEmpty() || prior == "default") "allow" else prior

        /** Extracts the mode string from `appops get <pkg> PLAY_AUDIO`, or `null` when unset. */
        fun parseSetMode(output: String): String? = Regex("""PLAY_AUDIO:\s*([a-z_]+)""").find(output)?.groupValues?.get(1)

        /** Parses `appops get` output returning `"default"` when unset. */
        fun parsePlayAudioMode(output: String): String = parseSetMode(output) ?: "default"

        fun format(modes: Map<String, String>): String = modes.entries.joinToString("") { "${it.key} ${it.value}\n" }

        fun parse(text: String): Map<String, String> =
            text.lineSequence()
                .mapNotNull { LINE.matchEntire(it.trim())?.destructured }
                .associate { (pkg, mode) -> pkg to mode }
    }
}
