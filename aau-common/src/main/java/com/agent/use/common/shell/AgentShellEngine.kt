package com.agent.use.common.shell

import android.annotation.SuppressLint
import android.app.ActivityOptions
import android.app.PendingIntent
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.ActivityInfo
import android.content.pm.PackageManager
import android.content.pm.ResolveInfo
import android.hardware.display.DisplayManager
import android.hardware.display.VirtualDisplay
import android.media.AudioManager
import android.media.AudioPlaybackConfiguration
import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.ParcelFileDescriptor
import android.os.Process
import android.os.SystemClock
import android.os.UserHandle
import android.os.UserManager
import android.util.Log
import android.view.Display
import android.view.InputDevice
import android.view.InputEvent
import android.view.KeyCharacterMap
import android.view.KeyEvent
import android.view.MotionEvent
import android.view.Surface
import com.agent.use.common.AppAudioKey
import com.agent.use.common.DisplayConfig
import java.io.ByteArrayOutputStream
import java.io.File
import java.lang.reflect.Method
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.system.exitProcess

/**
 * Reusable shell-privileged (UID 2000) core engine shared by `:aau-server` and host shell services.
 *
 * Encapsulates virtual display lifecycle & keep-awake, per-display orientation correction,
 * multi-user app launching & collision guards, task settling via `WindowContainerTransaction`,
 * AppOps audio isolation, Binder-direct clipboard swap/restore, main-screen watch, targeted unlock
 * input, DevTools abstract socket proxying, and bounded `sh -c` command execution.
 */
@SuppressLint("PrivateApi", "DiscouragedPrivateApi")
open class AgentShellEngine(
    val allowedUid: Int,
    stateDir: File = File("/data/local/tmp"),
    ledgerFileName: String = "agent_audio_mute_$allowedUid.ledger",
    val displayName: String = DisplayConfig.DEFAULT_DISPLAY_NAME,
    val envDisplayVarName: String = DEFAULT_ENV_DISPLAY_ID,
    clipLabel: String = ShellClipboard.DEFAULT_CLIP_LABEL,
    private val tag: String = DEFAULT_TAG,
    private val ownPageClass: String? = null,
    private val allowSystemIntent: (action: String?, data: String?) -> Boolean = { _, _ -> false },
    private val exitProcessFn: () -> Unit = { exitProcess(0) },
) {
    val context: Context = ShellContext.create()
    private val displays = HashMap<Int, VirtualDisplay>()
    private var orientationWatch: DisplayOrientationWatch? = null
    private val requestedOrientations = ConcurrentHashMap<Int, Int>()
    private val muted = AudioMuteLedger(File(stateDir, ledgerFileName))
    private val myUser = if (allowedUid >= 0) allowedUid / PER_USER_RANGE else 0

    private val displayManager: DisplayManager =
        DisplayManager::class.java.getDeclaredConstructor(Context::class.java)
            .apply { isAccessible = true }.newInstance(context)

    val clipboard = ShellClipboard(context, clipLabel)
    private val launchLock = Any()

    val taskManager: Any by lazy {
        Class.forName("android.app.ActivityTaskManager").getMethod("getService").invoke(null)!!
    }

    private val launcherApps: Any? by lazy {
        runCatching {
            val binder = Class.forName("android.os.ServiceManager").getMethod("getService", String::class.java).invoke(null, "launcherapps")
            Class.forName("android.content.pm.ILauncherApps\$Stub").getMethod("asInterface", android.os.IBinder::class.java).invoke(null, binder)
        }.onFailure { Log.w(tag, "launcherapps service unavailable", it) }.getOrNull()
    }

    private val awake by lazy {
        val timer = Executors.newSingleThreadScheduledExecutor { Thread(it, "agent-display-awake").apply { isDaemon = true } }
        DisplayAwake(::pokeDisplay) { r ->
            val f = timer.scheduleWithFixedDelay(r, 0, DisplayAwake.PERIOD_MS, TimeUnit.MILLISECONDS)
            return@DisplayAwake { f.cancel(false) }
        }
    }

    private val userActivity: Pair<Any, Method>? by lazy {
        runCatching {
            val binder = Class.forName("android.os.ServiceManager").getMethod("getService", String::class.java).invoke(null, "power")
            val power = Class.forName("android.os.IPowerManager\$Stub").getMethod("asInterface", android.os.IBinder::class.java).invoke(null, binder)!!
            power to (DisplayAwake.userActivityMethod(power.javaClass) ?: error("no per-display userActivity"))
        }.onFailure { Log.w(tag, "display keep-awake unavailable: ${it.message}") }.getOrNull()
    }

    private val kept = HashMap<Int, String>()
    private val ownPackages: Set<String> by lazy {
        if (allowedUid <= 0) emptySet()
        else runCatching { context.packageManager.getPackagesForUid(allowedUid)?.toSet() }.getOrNull().orEmpty()
    }

    private val mainWatch by lazy { MainScreenWatch({ taskManager }, ::taskRows, tag) }
    private val deviceUnlock by lazy {
        DeviceUnlockInput(
            context = context,
            inject = { inject(it, Display.DEFAULT_DISPLAY, waitForFinish = true) },
            injectTo = { event, uid -> injectTo(event, Display.DEFAULT_DISPLAY, uid) },
            command = { exec(*it.toTypedArray()) == 0 },
        )
    }

    /** Returns `true` if the virtual display ID belongs to this engine instance. */
    fun ownDisplay(displayId: Int): Boolean = synchronized(displays) { displayId in displays }

    // ==========================================
    // 1. Virtual Display Lifecycle
    // ==========================================

    fun createDisplay(surface: Surface, width: Int, height: Int, dpi: Int, flags: Int = 0, name: String = displayName): Int =
        try {
            val resolvedFlags = if (flags != 0) flags else displayFlags(Build.VERSION.SDK_INT, trusted = true)
            createVirtualDisplay(surface, width, height, dpi, resolvedFlags, name)
        } catch (t: Throwable) {
            if (!retryWithoutTrust(t)) {
                Log.e(tag, "createDisplay failed", t)
                -1
            } else {
                Log.w(tag, "createDisplay without trusted display flags, retrying", t)
                try {
                    val untrustedFlags = if (flags != 0) stripTrustedFlags(flags) else displayFlags(Build.VERSION.SDK_INT, trusted = false)
                    createVirtualDisplay(surface, width, height, dpi, untrustedFlags, name)
                } catch (fallbackErr: Throwable) {
                    Log.e(tag, "createDisplay failed", fallbackErr)
                    -1
                }
            }
        }

    fun createDisplay(surface: Surface, config: DisplayConfig): Int =
        createDisplay(
            surface = surface,
            width = config.width,
            height = config.height,
            dpi = config.dpi,
            flags = config.flags,
            name = config.name.ifEmpty { displayName },
        )

    private fun createVirtualDisplay(
        surface: Surface,
        width: Int,
        height: Int,
        dpi: Int,
        flags: Int,
        name: String,
    ): Int {
        val vd = displayManager.createVirtualDisplay(name, width, height, dpi, surface, flags)
        val id = vd.display.displayId
        synchronized(displays) { displays[id] = vd }
        setFullscreenWindowingMode(id)
        ensureOrientationWatch()
        setImePolicy(id)
        if (DisplayAwake.needed(flags, FLAG_OWN_DISPLAY_GROUP, displayGroup(id))) awake.start(id)
        return id
    }

    /** Resizes an existing managed virtual display. */
    fun resizeDisplay(displayId: Int, width: Int, height: Int, dpi: Int): Boolean {
        val vd = synchronized(displays) { displays[displayId] } ?: return false
        return runCatching { vd.resize(width, height, dpi) }.isSuccess
    }

    fun releaseDisplay(displayId: Int) {
        awake.stop(displayId)
        val (vd, watch) = synchronized(displays) {
            displays.remove(displayId) to (if (displays.isEmpty()) orientationWatch.also { orientationWatch = null } else null)
        }
        watch?.close()
        if (watch != null) requestedOrientations.clear()
        vd?.release()
    }

    fun releaseAll() {
        clipboard.restoreClip()
        synchronized(muted) { muted.packages() }.forEach { key ->
            AppAudioKey.parse(key)?.let { (pkg, user) -> audioMuted(pkg, user, false) }
                ?: synchronized(muted) { muted.remove(key) }
        }
        awake.stopAll()
        val (all, watch) = synchronized(displays) {
            displays.values.toList().also { displays.clear() } to orientationWatch.also { orientationWatch = null }
        }
        requestedOrientations.clear()
        watch?.close()
        all.forEach { runCatching { it.release() } }
    }

    fun destroy() {
        releaseAll()
        exitProcessFn()
    }

    private fun pokeDisplay(displayId: Int): Boolean {
        val (power, method) = userActivity ?: return false
        return try {
            method.invoke(power, displayId, SystemClock.uptimeMillis(), DisplayAwake.EVENT_TOUCH, 0)
            true
        } catch (t: Throwable) {
            Log.w(tag, "userActivity failed, display keep-awake off", t)
            false
        }
    }

    private fun displayGroup(displayId: Int): Int? = runCatching {
        val global = Class.forName("android.hardware.display.DisplayManagerGlobal").getMethod("getInstance").invoke(null)!!
        val info = global.javaClass.getMethod("getDisplayInfo", Int::class.javaPrimitiveType).invoke(global, displayId)!!
        info.javaClass.getField("displayGroupId").getInt(info)
    }.getOrNull()

    private fun ensureOrientationWatch() {
        if (Build.VERSION.SDK_INT < 34 || synchronized(displays) { orientationWatch != null }) return
        val watch = runCatching {
            DisplayOrientationWatch(
                taskManager,
                active = { synchronized(displays) { displays.isNotEmpty() } },
                onRequestedOrientation = { taskId, orientation -> requestedOrientations[taskId] = orientation },
                onTaskRemoved = { taskId -> requestedOrientations.remove(taskId) },
                sync = ::syncDisplayOrientations,
            )
        }.onFailure { Log.w(tag, "display orientation watcher unavailable", it) }.getOrNull() ?: return
        val spare = synchronized(displays) {
            if (orientationWatch == null && displays.isNotEmpty()) {
                orientationWatch = watch
                null
            } else watch
        }
        spare?.close()
    }

    private fun syncDisplayOrientations() {
        val ours = synchronized(displays) { displays.toMap() }
        if (ours.isEmpty()) return
        val top = allTasks().groupBy { TASK_INFO.getField("displayId").getInt(it) }
        for ((id, vd) in ours) runCatching {
            val task = top[id]?.firstOrNull() ?: return@runCatching
            val taskId = TASK_INFO.getField("taskId").getInt(task)
            val compat = runCatching { TASK_INFO.getField("appCompatTaskInfo").get(task) }.getOrNull() ?: task
            val cls = compat.javaClass
            if (runCatching { cls.getField("topActivityBoundsLetterboxed").getBoolean(compat) }.getOrDefault(true).not()) return@runCatching
            val width = runCatching { cls.getField("topActivityLetterboxWidth").getInt(compat) }.getOrDefault(0)
            val height = runCatching { cls.getField("topActivityLetterboxHeight").getInt(compat) }.getOrDefault(0)
            val display = vd.display
            val mode = display.mode
            val rotation = DisplayOrientation.rotation(
                mode.physicalWidth,
                mode.physicalHeight,
                display.rotation,
                width,
                height,
                requestedOrientations[taskId] ?: ActivityInfo.SCREEN_ORIENTATION_UNSPECIFIED,
            ) ?: return@runCatching
            if (!ownDisplay(id)) return@runCatching
            val ok = runCatching {
                val wm = Class.forName("android.view.WindowManagerGlobal").getMethod("getWindowManagerService").invoke(null)!!
                val method = wm.javaClass.methods.first { it.name == "freezeDisplayRotation" }
                if (method.parameterTypes.size == 3) method.invoke(wm, id, rotation, "agent") else method.invoke(wm, id, rotation)
            }.isSuccess
            if (!ok) exec("wm", "user-rotation", "-d", "$id", "lock", "$rotation")
        }.onFailure { Log.w(tag, "orientation sync failed on display $id", it) }
    }

    private fun setFullscreenWindowingMode(displayId: Int) {
        runCatching {
            val wm = Class.forName("android.view.WindowManagerGlobal").getMethod("getWindowManagerService").invoke(null)!!
            wm.javaClass.getMethod("setWindowingMode", Int::class.javaPrimitiveType, Int::class.javaPrimitiveType)
                .invoke(wm, displayId, WINDOWING_MODE_FULLSCREEN)
        }.onFailure {
            Log.w(tag, "setWindowingMode failed, falling back to wm", it)
            if (exec("wm", "set-display-windowing-mode", "-d", "$displayId", "$WINDOWING_MODE_FULLSCREEN") != 0) {
                Log.w(tag, "could not set fullscreen windowing mode on display $displayId")
            }
        }
    }

    private fun setImePolicy(displayId: Int) {
        runCatching {
            val wm = Class.forName("android.view.WindowManagerGlobal").getMethod("getWindowManagerService").invoke(null)!!
            wm.javaClass.getMethod("setDisplayImePolicy", Int::class.javaPrimitiveType, Int::class.javaPrimitiveType)
                .invoke(wm, displayId, IME_POLICY_LOCAL)
        }.onFailure { Log.w(tag, "setDisplayImePolicy failed", it) }
    }

    // ==========================================
    // 2. App & Task Lifecycle
    // ==========================================

    fun startApp(displayId: Int, packageName: String): Int = start(displayId, packageName, myUser)

    fun restartApp(displayId: Int, packageName: String): Int = restart(displayId, packageName, myUser)

    fun startAppInUser(displayId: Int, packageName: String, userId: Int, cold: Boolean): Int {
        if (userId == myUser) return if (cold) restartApp(displayId, packageName) else startApp(displayId, packageName)
        if (!ownDisplay(displayId)) return START_ERROR
        val usable = try {
            users()?.let { ShellAppCopies.usable(myUser, it) }
        } catch (t: Throwable) {
            Log.e(tag, "cannot read users", t)
            null
        } ?: return START_ERROR
        if (userId !in usable) {
            Log.w(tag, "refused to start $packageName in user $userId")
            return START_USER_NOT_ALLOWED
        }
        return if (cold) restart(displayId, packageName, userId) else start(displayId, packageName, userId)
    }

    fun startIntent(displayId: Int, intent: Intent): Int = synchronized(launchLock) {
        if (!ownDisplay(displayId)) return START_ERROR
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        val options = ActivityOptions.makeBasic().setLaunchDisplayId(displayId).toBundle()
        val ok = startActivityAsUser(intent, intent.type, options, USER_CURRENT) ||
            runCatching { context.startActivity(intent, options); true }.getOrDefault(false)
        if (ok) START_OK else START_ERROR
    }

    fun startView(displayId: Int, action: String?, uri: String?, packageName: String?): Int = synchronized(launchLock) {
        if (!ownDisplay(displayId)) return START_ERROR
        val normalizedAction = action?.ifBlank { null }
        val normalizedUri = uri?.ifBlank { null }
        val normalizedPkg = packageName?.ifBlank { null }
        ShellLinks.refuse(normalizedAction, normalizedUri, normalizedPkg)?.let { return it }
        val intent = Intent(normalizedAction ?: Intent.ACTION_VIEW).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        normalizedUri?.let { intent.data = Uri.parse(it) }
        normalizedPkg?.let { intent.setPackage(it) }
        if (normalizedAction == null) intent.addCategory(Intent.CATEGORY_BROWSABLE)
        val candidates = activitiesFor(intent, null) ?: return START_ERROR
        if (candidates.isEmpty()) return START_UNRESOLVED
        try {
            val onMain = tasksOn(Display.DEFAULT_DISPLAY).flatMap(::packagesOf).toSet()
            if (ShellLinks.inUse(candidates.map { it.first }.distinct(), onMain)) return START_IN_USE_ON_MAIN
            if (onOtherOwnDisplay(candidates.map { it.first }.distinct(), displayId)) return START_IN_USE_BY_OTHER
        } catch (t: Throwable) {
            Log.e(tag, "cannot inspect main-screen tasks", t)
            return START_ERROR
        }
        candidates.singleOrNull()?.let { (pkg, cls) -> intent.component = ComponentName(pkg, cls) }
        val options = ActivityOptions.makeBasic().setLaunchDisplayId(displayId).toBundle()
        val ok = startActivityAsUser(intent, null, options, USER_CURRENT) || run {
            val target = intent.component?.let { listOf("-n", it.flattenToShortString()) }
                ?: (listOf("-a", intent.action!!) + listOfNotNull(normalizedUri?.let { "-d" }, normalizedUri) +
                    listOfNotNull(normalizedPkg?.let { "-p" }, normalizedPkg) +
                    (if (normalizedAction == null) listOf("-c", Intent.CATEGORY_BROWSABLE) else emptyList()))
            exec("am", "start", "--display", "$displayId", *target.toTypedArray()) == 0
        }
        if (ok) START_OK else START_ERROR
    }

    fun startShare(displayId: Int, packageName: String, text: String): Int = synchronized(launchLock) {
        if (!ownDisplay(displayId)) return START_ERROR
        val intent = ShareIntent.of(packageName, text)
        val candidates = activitiesFor(intent, ShareIntent.TYPE) ?: return START_ERROR
        if (candidates.isEmpty()) return START_UNRESOLVED
        try {
            if (inUseOnMainScreen(packageName)) return START_IN_USE_ON_MAIN
            if (onOtherOwnDisplay(listOf(packageName), displayId)) return START_IN_USE_BY_OTHER
        } catch (t: Throwable) {
            Log.e(tag, "cannot inspect main-screen tasks", t)
            return START_ERROR
        }
        candidates.singleOrNull()?.let { (pkg, cls) -> intent.component = ComponentName(pkg, cls) }
        val options = ActivityOptions.makeBasic().setLaunchDisplayId(displayId).toBundle()
        val ok = startActivityAsUser(intent, ShareIntent.TYPE, options, USER_CURRENT) ||
            exec(*ShareIntent.amArgs(displayId, packageName, text, intent.component?.flattenToShortString()).toTypedArray()) == 0
        if (ok) START_OK else START_ERROR
    }

    fun startSystemAction(displayId: Int, intent: Intent, asMika: PendingIntent?): Int = synchronized(launchLock) {
        if (!ownDisplay(displayId)) return START_ERROR
        if (ownPageClass != null && intent.component?.className == ownPageClass) return startOwnPage(displayId, intent)
        if (!allowSystemIntent(intent.action, intent.dataString)) return START_INVALID_LINK
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        val candidates = activitiesFor(intent, intent.type) ?: return START_ERROR
        if (candidates.isEmpty()) return START_UNRESOLVED
        try {
            val onMain = tasksOn(Display.DEFAULT_DISPLAY).flatMap(::packagesOf).toSet()
            if (ShellLinks.inUse(candidates.map { it.first }.distinct(), onMain)) return START_IN_USE_ON_MAIN
            if (onOtherOwnDisplay(candidates.map { it.first }.distinct(), displayId)) return START_IN_USE_BY_OTHER
        } catch (t: Throwable) {
            Log.e(tag, "cannot inspect main-screen tasks", t)
            return START_ERROR
        }
        val options = ActivityOptions.makeBasic().setLaunchDisplayId(displayId)
        val asShell = startActivityAsUser(intent, intent.type, options.toBundle(), USER_CURRENT)
        if (asShell) return START_OK
        if (asMika == null) return START_ERROR
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            options.setPendingIntentBackgroundActivityStartMode(ActivityOptions.MODE_BACKGROUND_ACTIVITY_START_ALLOWED)
        }
        return try {
            asMika.send(context, 0, null, null, null, null, options.toBundle())
            START_OK
        } catch (t: Throwable) {
            Log.w(tag, "sending ${intent.action} via PendingIntent failed", t)
            START_ERROR
        }
    }

    private fun startOwnPage(displayId: Int, intent: Intent): Int {
        val component = intent.component ?: return START_INVALID_LINK
        val mine = ownPackages
        if (component.className != ownPageClass || (mine.isNotEmpty() && component.packageName !in mine)) {
            return START_INVALID_LINK
        }
        val page = Intent().setComponent(component).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
        val options = ActivityOptions.makeBasic().setLaunchDisplayId(displayId).toBundle()
        val ok = startActivityAsUser(page, null, options, USER_CURRENT) ||
            exec("am", "start", "--display", "$displayId", "--activity-clear-task", "-n", component.flattenToShortString()) == 0
        return if (ok) START_OK else START_ERROR
    }

    private fun start(displayId: Int, packageName: String, userId: Int): Int = synchronized(launchLock) {
        if (!ownDisplay(displayId)) return START_ERROR
        try {
            if (inUseOnMainScreen(packageName, userId)) return START_IN_USE_ON_MAIN
            if (onOtherOwnDisplay(listOf(packageName), displayId, userId)) return START_IN_USE_BY_OTHER
        } catch (t: Throwable) {
            Log.e(tag, "cannot inspect main-screen tasks", t)
            return START_ERROR
        }
        if (resumeKept(displayId, packageName, userId)) return START_OK
        val intent = launchIntent(packageName, userId) ?: return START_NOT_FOUND
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        val options = ActivityOptions.makeBasic().setLaunchDisplayId(displayId).toBundle()
        val component = intent.component
        if (userId != myUser && component != null && startAsLauncher(component, userId, options)) return START_OK
        val resolvedUser = if (userId == myUser) USER_CURRENT else userId
        val ok = startActivityAsUser(intent, null, options, resolvedUser) || run {
            val comp = intent.component?.flattenToShortString() ?: return START_NOT_FOUND
            val userArgs = if (userId == myUser) emptyArray() else arrayOf("--user", "$userId")
            exec("am", "start", *userArgs, "--display", "$displayId", "-n", comp) == 0
        }
        if (ok) START_OK else START_ERROR
    }

    private fun restart(displayId: Int, packageName: String, userId: Int): Int = synchronized(launchLock) {
        if (!ownDisplay(displayId)) return START_ERROR
        val decision = try {
            if (onOtherOwnDisplay(listOf(packageName), displayId, userId)) return START_IN_USE_BY_OTHER
            dropKept(packageName, userId)
            val displayField = TASK_INFO.getField("displayId")
            val taskDisplays = allTasks().filter { isCopy(it, packageName, userId) }.map { displayField.getInt(it) }
            ColdStart.decide(taskDisplays, displayId, inUseOnMainScreen(packageName, userId))
        } catch (t: Throwable) {
            Log.e(tag, "cannot inspect tasks", t)
            return START_ERROR
        }
        if (launchIntent(packageName, userId) == null) return START_NOT_FOUND
        when (decision) {
            ColdStart.IN_USE -> START_IN_USE_ON_MAIN
            ColdStart.WARM -> start(displayId, packageName, userId).let { if (it == START_OK) START_OK_COLD_IGNORED else it }
            ColdStart.RESTART -> {
                val user = if (userId == myUser) "current" else "$userId"
                if (exec("am", "force-stop", "--user", user, packageName) != 0) return START_ERROR
                start(displayId, packageName, userId)
            }
        }
    }

    private fun startActivityAsUser(intent: Intent, resolvedType: String?, options: Bundle, userId: Int): Boolean = try {
        val start = taskManager.javaClass.methods.first { it.name == "startActivityAsUser" && it.parameterTypes.size == 12 }
        val result = start.invoke(
            taskManager,
            null,
            ShellContext.SHELL_PACKAGE,
            null,
            intent,
            resolvedType,
            null,
            null,
            0,
            0,
            null,
            options,
            userId,
        ) as Int
        if (result < 0) Log.w(tag, "startActivityAsUser(${intent.action ?: intent.component}) -> $result")
        result >= 0
    } catch (t: Throwable) {
        Log.w(tag, "startActivityAsUser unavailable, falling back", t)
        false
    }

    private fun startAsLauncher(component: ComponentName, userId: Int, options: Bundle): Boolean = try {
        val la = launcherApps ?: throw IllegalStateException("no launcherapps service")
        val user = UserHandle.getUserHandleForUid(userId * PER_USER_RANGE)
        val m = la.javaClass.methods.first {
            it.name == "startActivityAsUser" && it.parameterTypes.size in 6..7 && ComponentName::class.java in it.parameterTypes
        }
        val args: Array<Any?> = if (m.parameterTypes.size == 7) {
            arrayOf(null, ShellContext.SHELL_PACKAGE, null, component, null, options, user)
        } else {
            arrayOf(null, ShellContext.SHELL_PACKAGE, component, null, options, user)
        }
        m.invoke(la, *args)
        true
    } catch (t: Throwable) {
        Log.w(tag, "launcher-style start of ${component.flattenToShortString()} in user $userId failed", t)
        false
    }

    private fun launchIntent(packageName: String, userId: Int): Intent? {
        if (userId == myUser) return context.packageManager.getLaunchIntentForPackage(packageName)
        val query = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER).setPackage(packageName)
        val found = try {
            val pm = context.packageManager
            val m = pm.javaClass.getMethod("queryIntentActivitiesAsUser", Intent::class.java, Int::class.javaPrimitiveType, Int::class.javaPrimitiveType)
            (m.invoke(pm, query, 0, userId) as List<*>).filterIsInstance<ResolveInfo>().map { it.activityInfo.packageName to it.activityInfo.name }
        } catch (t: Throwable) {
            Log.w(tag, "queryIntentActivitiesAsUser failed, asking the package service", t)
            val args = ActivityQuery.args(Intent.ACTION_MAIN, category = Intent.CATEGORY_LAUNCHER, packageName = packageName, user = "$userId")
            sh(*args.toTypedArray()).takeIf { it.first == 0 }?.second?.let(ActivityQuery::parse)
        }
        val (pkg, cls) = found?.firstOrNull { it.first == packageName } ?: return null
        return Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER).setComponent(ComponentName(pkg, cls))
    }

    private fun activitiesFor(intent: Intent, type: String?): List<Pair<String, String>>? = try {
        context.packageManager.queryIntentActivities(intent, PackageManager.MATCH_DEFAULT_ONLY)
            .map { it.activityInfo.packageName to it.activityInfo.name }
    } catch (t: Throwable) {
        Log.w(tag, "queryIntentActivities failed, asking the package service", t)
        val args = ActivityQuery.args(intent.action!!, type, intent.dataString, intent.categories?.firstOrNull(), intent.`package`)
        sh(*args.toTypedArray()).takeIf { it.first == 0 }?.second?.let(ActivityQuery::parse)
            .also { if (it == null) Log.e(tag, "cannot resolve ${intent.action}") }
    }

    // ==========================================
    // 3. Task Inspection & Finish Display
    // ==========================================

    private fun packagesOf(task: Any): List<String> = listOf("baseActivity", "topActivity").mapNotNull {
        (TASK_INFO.getField(it).get(task) as? ComponentName)?.packageName
    }

    private fun isCopy(task: Any, packageName: String, userId: Int?): Boolean =
        sameCopy(packagesOf(task), runCatching { TASK_INFO.getField("userId").getInt(task) }.getOrNull(), packageName, userId)

    private fun onOtherOwnDisplay(packages: Collection<String>, displayId: Int, userId: Int? = null): Boolean {
        val others = synchronized(displays) { displays.keys.toSet() } - displayId
        if (others.isEmpty()) return false
        val displayField = TASK_INFO.getField("displayId")
        return allTasks().any { t -> displayField.getInt(t) in others && packages.any { isCopy(t, it, userId) } }
    }

    private fun inUseOnMainScreen(packageName: String, userId: Int? = null): Boolean {
        val visibleField = runCatching { TASK_INFO.getField("isVisible") }.getOrNull()
        return tasksOn(Display.DEFAULT_DISPLAY).withIndex().any { (index, task) ->
            isCopy(task, packageName, userId) && (visibleField?.getBoolean(task) ?: (index == 0))
        }
    }

    fun tasksOn(displayId: Int): List<Any> {
        val methods = taskManager.javaClass.methods.filter { it.name == "getTasks" }
        val withDisplay = methods.firstOrNull { it.parameterTypes.size == 4 }
        val tasks = if (withDisplay != null) {
            withDisplay.invoke(taskManager, MAX_TASKS, false, false, displayId)
        } else {
            methods.first { it.parameterTypes.size == 3 }.invoke(taskManager, MAX_TASKS, false, false)
        } as List<*>
        val displayField = TASK_INFO.getField("displayId")
        return tasks.filterNotNull().filter { displayField.getInt(it) == displayId }
    }

    fun allTasks(): List<Any> {
        val methods = taskManager.javaClass.methods.filter { it.name == "getTasks" }
        val withDisplay = methods.firstOrNull { it.parameterTypes.size == 4 }
        val tasks = if (withDisplay != null) {
            withDisplay.invoke(taskManager, MAX_TASKS, false, false, Display.INVALID_DISPLAY)
        } else {
            methods.first { it.parameterTypes.size == 3 }.invoke(taskManager, MAX_TASKS, false, false)
        } as List<*>
        return tasks.filterNotNull()
    }

    private fun task(taskId: Int): Any? {
        val idField = TASK_INFO.getField("taskId")
        return allTasks().firstOrNull { idField.getInt(it) == taskId }
    }

    fun displayOfTask(taskId: Int): Int = try {
        task(taskId)?.let { TASK_INFO.getField("displayId").getInt(it) } ?: -1
    } catch (t: Throwable) {
        Log.e(tag, "displayOfTask failed", t)
        -1
    }

    fun displayOfPackage(packageName: String): Int = try {
        val ours = synchronized(displays) { displays.keys.toSet() }
        val displayField = TASK_INFO.getField("displayId")
        allTasks().filter { packageName in packagesOf(it) }.map { displayField.getInt(it) }.firstOrNull { it in ours } ?: -1
    } catch (t: Throwable) {
        Log.e(tag, "displayOfPackage failed", t)
        -1
    }

    fun displayOfPackageInUser(packageName: String, userId: Int): Int = try {
        val ours = synchronized(displays) { displays.keys.toSet() }
        val displayField = TASK_INFO.getField("displayId")
        allTasks().filter { isCopy(it, packageName, userId) }.map { displayField.getInt(it) }.firstOrNull { it in ours } ?: -1
    } catch (t: Throwable) {
        Log.e(tag, "displayOfPackageInUser failed", t)
        -1
    }

    fun packageOfTask(taskId: Int): String? = try {
        task(taskId)?.let { t ->
            listOf("topActivity", "baseActivity").firstNotNullOfOrNull { (TASK_INFO.getField(it).get(t) as? ComponentName)?.packageName }
        }
    } catch (t: Throwable) {
        Log.e(tag, "packageOfTask failed", t)
        null
    }

    fun topTaskId(displayId: Int): Int = try {
        tasksOn(displayId).firstOrNull()?.let { TASK_INFO.getField("taskId").getInt(it) } ?: -1
    } catch (t: Throwable) {
        Log.e(tag, "topTaskId failed", t)
        -1
    }

    fun topActivity(displayId: Int): String? = try {
        if (!ownDisplay(displayId)) null else tasksOn(displayId).firstOrNull()?.let {
            (TASK_INFO.getField("topActivity").get(it) as? ComponentName)?.className
        }
    } catch (t: Throwable) {
        Log.e(tag, "topActivity failed", t)
        null
    }

    fun userOfTask(taskId: Int): Int = try {
        task(taskId)?.let { TASK_INFO.getField("userId").getInt(it) } ?: -1
    } catch (t: Throwable) {
        Log.e(tag, "userOfTask failed", t)
        -1
    }

    fun moveTask(taskId: Int, displayId: Int): Boolean = try {
        taskManager.javaClass.getMethod("moveRootTaskToDisplay", Int::class.javaPrimitiveType, Int::class.javaPrimitiveType)
            .invoke(taskManager, taskId, displayId)
        true
    } catch (t: Throwable) {
        Log.w(tag, "moveRootTaskToDisplay unavailable, falling back to am", t)
        exec("am", "display", "move-stack", "$taskId", "$displayId") == 0
    }

    fun finishDisplay(displayId: Int, keep: Array<String>?, close: Array<String>?): Bundle? {
        val sorting = synchronized(launchLock) {
            if (!ownDisplay(displayId)) return null
            sortAndMove(displayId, keep, close)
        }
        val settled = settleBehind(sorting.moved.mapTo(LinkedHashSet()) { it.task.id })
        return synchronized(launchLock) { closeOut(displayId, sorting, settled) }
    }

    private class Sorting(
        val moved: MutableList<AppsAfterTask.Fate>,
        val closed: MutableList<String>,
        val notes: MutableSet<String>,
        val hidden: Set<Int>,
    )

    private enum class Behind { OK, HIDDEN, UNSUPPORTED }

    private fun sortAndMove(displayId: Int, keep: Array<String>?, close: Array<String>?): Sorting {
        val closed = ArrayList<String>()
        val notes = LinkedHashSet<String>()
        val moved = ArrayList<AppsAfterTask.Fate>()
        val hidden = HashSet<Int>()
        try {
            val playing = playingUids()
            if (playing == null) notes += AppsAfterTask.NOTE_PLAYBACK_UNKNOWN
            val rows = tasksOn(displayId)
            val idField = TASK_INFO.getField("taskId")
            val byId = rows.associateBy { idField.getInt(it) }
            val fates = AppsAfterTask.decide(
                rows.map { afterTaskRow(it, playing) },
                AppsAfterTask.normalize(keep, myUser),
                AppsAfterTask.normalize(close, myUser),
            )
            var supported = true
            for (f in fates) {
                if (!f.keep) {
                    closed += AppsAfterTask.closedEntry(f)
                    continue
                }
                if (!supported) {
                    closed += AppsAfterTask.closedEntry(f.copy(keep = false, why = AppsAfterTask.Why.MoveUnsupported))
                    continue
                }
                when (keepBehind(byId.getValue(f.task.id))) {
                    Behind.OK -> moved += f
                    Behind.HIDDEN -> {
                        moved += f
                        hidden += f.task.id
                    }
                    Behind.UNSUPPORTED -> {
                        supported = false
                        notes += AppsAfterTask.NOTE_MOVE_UNSUPPORTED
                        closed += AppsAfterTask.closedEntry(f.copy(keep = false, why = AppsAfterTask.Why.MoveUnsupported))
                    }
                }
            }
            val playingNow = if (moved.isEmpty()) null else playingUids()
            val nowLoud = moved.map { f -> AppsAfterTask.recheck(f, task(f.task.id)?.let { playingIn(it, playingNow) }) }
                .filter { !it.keep }
            for (f in nowLoud) {
                sendBackToClose(f.task.id, displayId)
                moved.removeAll { it.task.id == f.task.id }
                closed += AppsAfterTask.closedEntry(f)
            }
        } catch (t: Throwable) {
            Log.e(tag, "finishDisplay: cannot inspect tasks, closing the rest with the display", t)
            notes += "error ${t.javaClass.simpleName}"
        }
        return Sorting(moved, closed, notes, hidden)
    }

    private fun closeOut(displayId: Int, sorting: Sorting, settled: SettleBehind.Plan.Done?): Bundle {
        val (moved, closed, notes) = Triple(sorting.moved, sorting.closed, sorting.notes)
        if (settled == null) {
            notes += AppsAfterTask.NOTE_SETTLE_UNKNOWN
        } else {
            try {
                val ids = moved.mapTo(LinkedHashSet()) { it.task.id }
                val final = SettleBehind.closeOut(ids, settled.fallback, seenOnMain(ids))
                for (f in moved.filter { it.task.id in final.fallback }) {
                    Log.w(tag, "task ${f.task.id} is still in front on the main screen, closing it with display $displayId")
                    sendBackToClose(f.task.id, displayId)
                    closed += AppsAfterTask.closedEntry(f.copy(keep = false, why = AppsAfterTask.Why.StillInFront))
                }
                if (final.fallback.isNotEmpty()) notes += AppsAfterTask.NOTE_STILL_IN_FRONT
                if (final.gone.isNotEmpty()) Log.i(tag, "tasks ${final.gone} left the main screen while settling; not keeping them")
                moved.removeAll { it.task.id !in final.kept }
            } catch (t: Throwable) {
                Log.e(tag, "finishDisplay: cannot recheck the main screen", t)
                notes += "error ${t.javaClass.simpleName}"
            }
        }
        val hidden = moved.count { it.task.id in sorting.hidden }
        if (hidden > 0) notes += "$hidden ${AppsAfterTask.NOTE_LEFT_HIDDEN}"
        synchronized(kept) { moved.forEach { kept[it.task.id] = it.key } }
        releaseDisplay(displayId)
        return Bundle().apply {
            putStringArray(AppsAfterTask.KEY_KEPT, moved.map { it.key }.toTypedArray())
            putStringArray(AppsAfterTask.KEY_CLOSED, closed.toTypedArray())
            putString(AppsAfterTask.KEY_NOTE, notes.joinToString("; ").ifEmpty { null })
        }
    }

    private fun sendBackToClose(taskId: Int, displayId: Int) {
        if (!moveTask(taskId, displayId)) removeTask(taskId)
    }

    private fun afterTaskRow(t: Any, playing: Map<Int, Set<String>>?): AppsAfterTask.Task {
        val user = runCatching { TASK_INFO.getField("userId").getInt(t) }.getOrDefault(myUser)
        val pkgs = packagesOf(t).distinct()
        val type = runCatching { TASK_INFO.getField("topActivityType").getInt(t) }.getOrNull()
        return AppsAfterTask.Task(
            id = TASK_INFO.getField("taskId").getInt(t),
            keys = pkgs.map { AppsAfterTask.keyOf(it, user, myUser) },
            standard = type == null || type == ACTIVITY_TYPE_UNDEFINED || type == ACTIVITY_TYPE_STANDARD,
            own = pkgs.any { it in ownPackages },
            playing = playingIn(t, playing),
            muted = synchronized(muted) { pkgs.any { muted.contains(AppsAfterTask.keyOf(it, user, myUser)) } },
        )
    }

    private fun playingIn(task: Any, playing: Map<Int, Set<String>>?): Boolean? {
        playing ?: return null
        val user = runCatching { TASK_INFO.getField("userId").getInt(task) }.getOrNull()
        val pkgs = packagesOf(task)
        return playing.any { (uid, owners) -> (user == null || uid / PER_USER_RANGE == user) && pkgs.any { it in owners } }
    }

    private fun playingUids(): Map<Int, Set<String>>? {
        val uids = runCatching {
            val configs = context.getSystemService(AudioManager::class.java).activePlaybackConfigurations
            val uidOf = AudioPlaybackConfiguration::class.java.getMethod("getClientUid")
            val stateOf = AudioPlaybackConfiguration::class.java.getMethod("getPlayerState")
            val rows = configs.map { (uidOf.invoke(it) as Int) to (stateOf.invoke(it) as Int) }
            if (rows.any { it.first < 0 }) null
            else rows.filter { it.second == AppsAfterTask.PLAYER_STATE_STARTED }.map { it.first }.toSet()
        }.onFailure { Log.w(tag, "playback configurations unavailable", it) }.getOrNull()
            ?: sh("dumpsys", "audio").takeIf { it.first == 0 }?.second?.let(AppsAfterTask::playingUids)
            ?: return null
        return uids.associateWith { uid ->
            runCatching { context.packageManager.getPackagesForUid(uid)?.toSet() }.getOrNull().orEmpty()
        }
    }

    private fun keepBehind(row: Any): Behind {
        val id = TASK_INFO.getField("taskId").getInt(row)
        val token = runCatching { TASK_INFO.getField("token").get(row) }.getOrNull() ?: return Behind.UNSUPPORTED
        if (!transact { wct -> wctCall(wct, "setHidden", token, true) }) return Behind.UNSUPPORTED
        if (!moveTask(id, Display.DEFAULT_DISPLAY)) {
            transact { wct -> wctCall(wct, "setHidden", token, false) }
            return Behind.UNSUPPORTED
        }
        val placed = transact { wct ->
            wctCall(wct, "reorder", token, false)
            wctCall(wct, "setHidden", token, false)
        }
        if (placed) return Behind.OK
        if (transact { wct -> wctCall(wct, "setHidden", token, false) }) return Behind.OK
        Log.w(tag, "task $id is still hidden on the main screen; resumeKept will unhide it")
        return Behind.HIDDEN
    }

    private fun seenOnMain(ids: Set<Int>): List<SettleBehind.Seen> {
        if (ids.isEmpty()) return emptyList()
        val idField = TASK_INFO.getField("taskId")
        val visibleField = runCatching { TASK_INFO.getField("isVisible") }.getOrNull()
        return tasksOn(Display.DEFAULT_DISPLAY).withIndex().mapNotNull { (index, row) ->
            val id = idField.getInt(row)
            if (id !in ids) null else SettleBehind.Seen(id, onMain = true, visible = visibleField?.getBoolean(row) ?: (index == 0))
        }
    }

    private fun settleBehind(moved: Set<Int>): SettleBehind.Plan.Done? = try {
        val start = SystemClock.uptimeMillis()
        var lastReorder: Long? = null
        var watching = moved
        val gone = LinkedHashSet<Int>()
        var done: SettleBehind.Plan.Done? = null
        while (done == null) {
            val now = SystemClock.uptimeMillis()
            when (val plan = SettleBehind.plan(watching, seenOnMain(watching), now - start, lastReorder?.let { now - it })) {
                is SettleBehind.Plan.Done -> done = plan.copy(gone = plan.gone + gone)
                is SettleBehind.Plan.Wait -> {
                    gone += plan.gone
                    watching = watching - plan.gone
                    if (plan.reorder.isNotEmpty()) {
                        lastReorder = now
                        sendToBack(plan.reorder)
                    }
                    Thread.sleep(SettleBehind.POLL_MS)
                }
            }
        }
        if (done.fallback.isNotEmpty()) {
            Log.w(tag, "moved tasks ${done.fallback} are still visible on the main screen after ${SettleBehind.TIMEOUT_MS}ms")
        }
        done
    } catch (t: Throwable) {
        Log.e(tag, "cannot watch moved tasks settle on the main screen", t)
        null
    }

    private fun sendToBack(ids: Set<Int>) {
        val idField = TASK_INFO.getField("taskId")
        for (row in tasksOn(Display.DEFAULT_DISPLAY)) {
            val id = idField.getInt(row)
            if (id !in ids) continue
            Log.w(tag, "moved task $id is still visible on the main screen, sending it back")
            val token = runCatching { TASK_INFO.getField("token").get(row) }.getOrNull() ?: continue
            transact { wct -> wctCall(wct, "reorder", token, false) }
        }
    }

    private fun removeTask(taskId: Int): Boolean = try {
        taskManager.javaClass.getMethod("removeTask", Int::class.javaPrimitiveType).invoke(taskManager, taskId) as Boolean
    } catch (t: Throwable) {
        Log.w(tag, "removeTask unavailable, falling back to am", t)
        exec("am", "stack", "remove", "$taskId") == 0
    }

    private fun transact(build: (Any) -> Unit): Boolean = try {
        val wct = WCT.getConstructor().newInstance()
        build(wct)
        val controller = taskManager.javaClass.getMethod("getWindowOrganizerController").invoke(taskManager)!!
        controller.javaClass.methods.first { it.name == "applyTransaction" && it.parameterTypes.size == 1 }.invoke(controller, wct)
        true
    } catch (t: Throwable) {
        Log.w(tag, "window container transaction failed", t)
        false
    }

    private fun wctCall(wct: Any, method: String, token: Any, flag: Boolean) {
        WCT.getMethod(method, Class.forName("android.window.WindowContainerToken"), Boolean::class.javaPrimitiveType)
            .invoke(wct, token, flag)
    }

    private fun keptOnMain(packageName: String, userId: Int): List<Any> {
        val ids = synchronized(kept) { kept.keys.toSet() }
        if (ids.isEmpty()) return emptyList()
        val idField = TASK_INFO.getField("taskId")
        val displayField = TASK_INFO.getField("displayId")
        val visibleField = runCatching { TASK_INFO.getField("isVisible") }.getOrNull()
        val all = allTasks()
        synchronized(kept) { kept.keys.retainAll(all.map { idField.getInt(it) }.toSet()) }
        return all.filter { t ->
            idField.getInt(t) in ids && displayField.getInt(t) == Display.DEFAULT_DISPLAY &&
                isCopy(t, packageName, userId) && visibleField?.getBoolean(t) != true
        }
    }

    private fun resumeKept(displayId: Int, packageName: String, userId: Int): Boolean {
        val row = runCatching { keptOnMain(packageName, userId).firstOrNull() }.getOrNull() ?: return false
        val id = TASK_INFO.getField("taskId").getInt(row)
        if (!moveTask(id, displayId)) return false
        val token = runCatching { TASK_INFO.getField("token").get(row) }.getOrNull()
        if (token != null && !transact { wct -> wctCall(wct, "setHidden", token, false) }) {
            Log.w(tag, "task $id is still hidden after moving it back to display $displayId")
        }
        synchronized(kept) { kept.remove(id) }
        return true
    }

    private fun dropKept(packageName: String, userId: Int) {
        keptOnMain(packageName, userId).forEach { t ->
            val id = TASK_INFO.getField("taskId").getInt(t)
            if (removeTask(id)) synchronized(kept) { kept.remove(id) }
        }
    }

    // ==========================================
    // 4. Main Screen Conflict Guard
    // ==========================================

    fun visibleOnMainScreen(packageName: String, userId: Int): Boolean = try {
        inUseOnMainScreen(packageName, userId)
    } catch (t: Throwable) {
        Log.e(tag, "cannot inspect main-screen tasks", t)
        true
    }

    fun watchMainScreen(windowMs: Int): Int = try {
        mainWatch.watch(windowMs)
    } catch (t: Throwable) {
        Log.e(tag, "watchMainScreen failed", t)
        -1
    }

    fun mainArrivals(sinceUptimeMs: Long): Bundle? = try {
        mainWatch.arrivals(sinceUptimeMs)
    } catch (t: Throwable) {
        Log.e(tag, "mainArrivals failed", t)
        null
    }

    private fun taskRows(): List<MainScreenLog.Task> {
        val id = TASK_INFO.getField("taskId")
        val display = TASK_INFO.getField("displayId")
        val user = runCatching { TASK_INFO.getField("userId") }.getOrNull()
        val type = runCatching { TASK_INFO.getField("topActivityType") }.getOrNull()
        return allTasks().map { t ->
            val top = TASK_INFO.getField("topActivity").get(t) as? ComponentName
            MainScreenLog.Task(
                taskId = id.getInt(t),
                displayId = display.getInt(t),
                packageName = top?.packageName ?: (TASK_INFO.getField("baseActivity").get(t) as? ComponentName)?.packageName,
                userId = user?.getInt(t) ?: -1,
                topActivity = top?.className,
                standard = type?.getInt(t)?.let { it == ACTIVITY_TYPE_UNDEFINED || it == ACTIVITY_TYPE_STANDARD } ?: true,
            )
        }
    }

    // ==========================================
    // 5. Input Injection
    // ==========================================

    fun injectKey(displayId: Int, keyCode: Int): Boolean {
        if (!ShellPressKeys.isAllowed(keyCode)) {
            Log.w(tag, "refused key $keyCode")
            return false
        }
        val now = SystemClock.uptimeMillis()
        val down = KeyEvent(now, now, KeyEvent.ACTION_DOWN, keyCode, 0, 0, VIRTUAL_KEYBOARD, 0, 0, InputDevice.SOURCE_KEYBOARD)
        val up = KeyEvent.changeAction(down, KeyEvent.ACTION_UP)
        return injectPair(down, up, displayId) { exec("input", "-d", "$displayId", "keyevent", "$keyCode") == 0 }
    }

    fun injectCtrlKey(displayId: Int, keyCode: Int): Int {
        if (!ownDisplay(displayId)) return AsciiTextKeys.NOT_SENT
        if (keyCode != KeyEvent.KEYCODE_A && keyCode != KeyEvent.KEYCODE_V) {
            Log.w(tag, "refused ctrl key $keyCode")
            return AsciiTextKeys.NOT_SENT
        }
        val now = SystemClock.uptimeMillis()
        val meta = KeyEvent.META_CTRL_ON or KeyEvent.META_CTRL_LEFT_ON
        fun event(code: Int, action: Int, modifiers: Int) = KeyEvent(
            now,
            SystemClock.uptimeMillis(),
            action,
            code,
            0,
            modifiers,
            VIRTUAL_KEYBOARD,
            0,
            0,
            InputDevice.SOURCE_KEYBOARD,
        )
        var modifierDown = false
        try {
            if (!inject(event(KeyEvent.KEYCODE_CTRL_LEFT, KeyEvent.ACTION_DOWN, 0), displayId)) return AsciiTextKeys.NOT_SENT
            modifierDown = true
            if (!inject(event(keyCode, KeyEvent.ACTION_DOWN, meta), displayId)) return AsciiTextKeys.NOT_SENT
            val up = event(keyCode, KeyEvent.ACTION_UP, meta)
            return if (inject(up, displayId) || inject(up, displayId)) AsciiTextKeys.DISPATCHED else AsciiTextKeys.UNCONFIRMED
        } finally {
            if (modifierDown) {
                val up = event(KeyEvent.KEYCODE_CTRL_LEFT, KeyEvent.ACTION_UP, 0)
                if (ownDisplay(displayId) && !inject(up, displayId) && !inject(up, displayId)) {
                    Log.w(tag, "could not release Ctrl on display $displayId")
                }
            }
        }
    }

    fun injectAsciiText(displayId: Int, taskId: Int, packageName: String, text: String): Int {
        if (displayId <= Display.DEFAULT_DISPLAY || !ownDisplay(displayId) || taskId < 0 || !AsciiTextKeys.supports(text)) {
            return AsciiTextKeys.NOT_SENT
        }
        val (events, targetUid) = runCatching {
            val task = tasksOn(displayId).firstOrNull() ?: return AsciiTextKeys.NOT_SENT
            val top = TASK_INFO.getField("topActivity").get(task) as? ComponentName
            if (TASK_INFO.getField("taskId").getInt(task) != taskId || top?.packageName != packageName) {
                return AsciiTextKeys.NOT_SENT
            }
            val uid = if (Build.VERSION.SDK_INT >= 33) {
                val user = TASK_INFO.getField("userId").getInt(task)
                val pm = context.packageManager
                (pm.javaClass.getMethod("getPackageUidAsUser", String::class.java, Int::class.javaPrimitiveType, Int::class.javaPrimitiveType)
                    .invoke(pm, packageName, 0, user) as Int).takeIf { it >= 0 } ?: return AsciiTextKeys.NOT_SENT
            } else {
                null
            }
            val keys = KeyCharacterMap.load(KeyCharacterMap.VIRTUAL_KEYBOARD).getEvents(text.toCharArray())
                ?.takeIf { it.isNotEmpty() } ?: return AsciiTextKeys.NOT_SENT
            keys to uid
        }.getOrElse { return AsciiTextKeys.NOT_SENT }

        for (event in events) {
            if (!ownDisplay(displayId) || (targetUid == null && topTaskId(displayId) != taskId)) {
                return AsciiTextKeys.UNCONFIRMED
            }
            event.source = InputDevice.SOURCE_KEYBOARD
            val sent = if (targetUid != null) injectTo(event, displayId, targetUid) else inject(event, displayId, waitForFinish = true)
            if (!sent) return AsciiTextKeys.UNCONFIRMED
        }
        return AsciiTextKeys.DISPATCHED
    }

    fun injectTap(displayId: Int, x: Int, y: Int): Boolean {
        val now = SystemClock.uptimeMillis()
        val down = MotionEvent.obtain(now, now, MotionEvent.ACTION_DOWN, x.toFloat(), y.toFloat(), 0)
        val up = MotionEvent.obtain(now, now + TAP_MS, MotionEvent.ACTION_UP, x.toFloat(), y.toFloat(), 0)
        return try {
            down.source = InputDevice.SOURCE_TOUCHSCREEN
            up.source = InputDevice.SOURCE_TOUCHSCREEN
            injectPair(down, up, displayId) { exec("input", "-d", "$displayId", "tap", "$x", "$y") == 0 }
        } finally {
            down.recycle()
            up.recycle()
        }
    }

    fun injectStroke(displayId: Int, xs: IntArray, ys: IntArray, times: LongArray): Boolean {
        if (!ownDisplay(displayId)) return false
        val n = times.size
        if (n < 2 || n > STROKE_MAX_POINTS || xs.size != n || ys.size != n || times[0] != 0L ||
            times.last() > STROKE_MAX_MS || (1 until n).any { times[it] < times[it - 1] }
        ) {
            return false
        }
        val down = SystemClock.uptimeMillis()
        fun event(i: Int, action: Int): MotionEvent {
            val props = MotionEvent.PointerProperties().apply {
                id = 0
                toolType = MotionEvent.TOOL_TYPE_FINGER
            }
            val coords = MotionEvent.PointerCoords().apply {
                x = xs[i].toFloat()
                y = ys[i].toFloat()
                pressure = 1f
                size = 1f
            }
            return MotionEvent.obtain(
                down,
                down + times[i],
                action,
                1,
                arrayOf(props),
                arrayOf(coords),
                0,
                0,
                1f,
                1f,
                0,
                0,
                InputDevice.SOURCE_TOUCHSCREEN,
                0,
            )
        }

        fun send(i: Int, action: Int): Boolean {
            val wait = down + times[i] - SystemClock.uptimeMillis()
            if (wait > 0) SystemClock.sleep(wait)
            val e = event(i, action)
            return try {
                inject(e, displayId)
            } finally {
                e.recycle()
            }
        }
        if (!send(0, MotionEvent.ACTION_DOWN)) return false
        for (i in 1 until n) send(i, MotionEvent.ACTION_MOVE)
        return send(n - 1, MotionEvent.ACTION_UP) || send(n - 1, MotionEvent.ACTION_UP)
    }

    private inline fun injectPair(down: InputEvent, up: InputEvent, displayId: Int, fallback: () -> Boolean): Boolean =
        sendPair({ inject(down, displayId) }, { inject(up, displayId) }, fallback)

    private fun inject(event: InputEvent, displayId: Int, waitForFinish: Boolean = false): Boolean = try {
        event.javaClass.getMethod("setDisplayId", Int::class.javaPrimitiveType).invoke(event, displayId)
        val manager = inputManager()
        manager.javaClass.getMethod("injectInputEvent", InputEvent::class.java, Int::class.javaPrimitiveType)
            .invoke(manager, event, injectMode(event is KeyEvent, waitForFinish)) as Boolean
    } catch (t: Throwable) {
        Log.w(tag, "injectInputEvent failed", t)
        false
    }

    private fun injectTo(event: InputEvent, displayId: Int, targetUid: Int): Boolean = try {
        event.javaClass.getMethod("setDisplayId", Int::class.javaPrimitiveType).invoke(event, displayId)
        val manager = inputManager()
        manager.javaClass.getMethod("injectInputEvent", InputEvent::class.java, Int::class.javaPrimitiveType, Int::class.javaPrimitiveType)
            .invoke(manager, event, INJECT_MODE_WAIT_FOR_FINISH, targetUid) as Boolean
    } catch (t: Throwable) {
        Log.w(tag, "targeted injectInputEvent failed: ${(t.cause ?: t).javaClass.simpleName}")
        false
    }

    private fun inputManager(): Any = runCatching {
        Class.forName("android.hardware.input.InputManagerGlobal").getMethod("getInstance").invoke(null)
    }.getOrNull() ?: Class.forName("android.hardware.input.InputManager").getMethod("getInstance").invoke(null)!!

    // ==========================================
    // 6. Audio Muting & AppOps Isolation
    // ==========================================

    fun setAudioMuted(packageName: String, muted: Boolean): Boolean = audioMuted(packageName, null, muted)

    fun setAudioMutedInUser(packageName: String, userId: Int, muted: Boolean): Boolean {
        if (userId == myUser) return audioMuted(packageName, null, muted)
        return audioMuted(packageName, otherUser(userId) ?: return false, muted)
    }

    fun getAudioMode(packageName: String): String? = audioMode(packageName, null)

    fun getAudioModeInUser(packageName: String, userId: Int): String? {
        if (userId == myUser) return audioMode(packageName, null)
        return audioMode(packageName, otherUser(userId) ?: return null)
    }

    fun setAudioMode(packageName: String, mode: String): Boolean = audioMode(packageName, null, mode)

    fun setAudioModeInUser(packageName: String, userId: Int, mode: String): Boolean {
        if (userId == myUser) return audioMode(packageName, null, mode)
        return audioMode(packageName, otherUser(userId) ?: return false, mode)
    }

    /** Restores any audio mutes recorded in the persistent ledger on startup. */
    fun recoverMuted() {
        synchronized(muted) { muted.restoreAll(::writeRecorded) }
    }

    private fun audioMuted(packageName: String, user: Int?, muted: Boolean): Boolean = synchronized(this.muted) {
        val key = AppAudioKey.of(packageName, user)
        if (muted) {
            if (!this.muted.contains(key)) {
                val (code, out) = appops("get", packageName, user)
                if (code != 0) return false
                this.muted.put(key, parsePlayAudioMode(out))
            }
            appops("set", packageName, user, "ignore").first == 0
        } else {
            val ok = appops("set", packageName, user, AudioMuteLedger.restoreMode(this.muted[key])).first == 0
            if (ok) this.muted.remove(key)
            ok
        }
    }

    private fun writeRecorded(key: String, mode: String): Boolean {
        val parsed = AppAudioKey.parse(key) ?: return true
        return appops("set", parsed.packageName, parsed.userId, mode).first == 0
    }

    private fun audioMode(packageName: String, user: Int?): String? {
        val (code, out) = appops("get", packageName, user)
        return if (code == 0) parsePlayAudioMode(out) else null
    }

    private fun audioMode(packageName: String, user: Int?, mode: String): Boolean {
        if (!MODE_RE.matches(mode)) return false
        val ok = appops("set", packageName, user, AudioMuteLedger.restoreMode(mode)).first == 0
        if (ok) synchronized(muted) { muted.remove(AppAudioKey.of(packageName, user)) }
        return ok
    }

    private fun appops(verb: String, packageName: String, user: Int?, mode: String? = null): Pair<Int, String> {
        val u = (user ?: myUser).toString()
        return if (mode == null) sh("appops", verb, "--user", u, packageName, "PLAY_AUDIO")
        else sh("appops", verb, "--user", u, packageName, "PLAY_AUDIO", mode)
    }

    private fun otherUser(userId: Int): Int? = userId.takeIf { it >= 0 && it != myUser }

    // ==========================================
    // 7. Clipboard Isolation
    // ==========================================

    fun setClipText(text: String): Int = clipboard.setClipText(text)
    fun restoreClip(): Boolean = clipboard.restoreClip()
    fun savedClipText(): String? = clipboard.savedClipText()
    fun restoreClipText(original: String, ours: String): Boolean = clipboard.restoreClipText(original, ours)

    // ==========================================
    // 8. Multi-User & Packages
    // ==========================================

    fun listUsers(): String? = sh("pm", "list", "users").takeIf { it.first == 0 }?.second

    fun listPackages(userId: Int): String? = sh("pm", "list", "packages", "--user", "$userId").takeIf { it.first == 0 }?.second

    fun isSystemPackage(packageName: String): Boolean = try {
        val flags = context.packageManager.getApplicationInfo(packageName, 0).flags
        flags and (android.content.pm.ApplicationInfo.FLAG_SYSTEM or android.content.pm.ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
    } catch (_: PackageManager.NameNotFoundException) {
        false
    }

    fun appCopyUsers(): Bundle? = try {
        users()?.let { users ->
            Bundle().apply {
                putIntArray(KEY_COPY_USERS, ShellAppCopies.usable(myUser, users).toIntArray())
                putString(KEY_COPY_SUMMARY, ShellAppCopies.summary(myUser, users))
            }
        }
    } catch (t: Throwable) {
        Log.e(tag, "appCopyUsers failed", t)
        null
    }

    private fun users(): List<ShellAppCopies.User>? {
        val um = runCatching { context.getSystemService(UserManager::class.java) }.getOrNull()
            ?: UserManager::class.java.getMethod("get", Context::class.java).invoke(null, context) as UserManager
        val list = (runCatching { um.javaClass.getMethod("getAliveUsers").invoke(um) }.getOrNull()
            ?: runCatching { um.javaClass.getMethod("getUsers").invoke(um) }.getOrNull()) as? List<*> ?: return null
        val info = Class.forName("android.content.pm.UserInfo")
        val flagsToString = runCatching { info.getMethod("flagsToString", Int::class.javaPrimitiveType) }.getOrNull()
        val dumped by lazy { sh("dumpsys", "user").takeIf { it.first == 0 }?.second?.let(ShellAppCopies::parseDumpsys).orEmpty() }
        return list.filterNotNull().map { u ->
            val id = info.getField("id").getInt(u)
            val flags = info.getField("flags").getInt(u)
            val handle = UserHandle.getUserHandleForUid(id * PER_USER_RANGE)
            val props = runCatching { um.javaClass.getMethod("getUserProperties", UserHandle::class.java).invoke(um, handle) }.getOrNull()
            fun prop(name: String): Any? = props?.let { p -> runCatching { p.javaClass.getMethod(name).invoke(p) }.getOrNull() }
            val names = flagsToString?.let { m -> runCatching { (m.invoke(null, flags) as? String)?.let(::flagNames) }.getOrNull() }
                ?: dumped[id]?.flagNames
            val group = runCatching { info.getField("profileGroupId").getInt(u) }.getOrDefault(ShellAppCopies.NO_PROFILE_GROUP)
            val running = runCatching { um.isUserRunning(handle) }.getOrDefault(false)
            ShellAppCopies.User(
                id = id,
                flags = flags,
                type = runCatching { info.getField("userType").get(u) as? String }.getOrNull(),
                profileGroupId = group,
                running = running,
                unlocked = running && runCatching { um.isUserUnlocked(handle) }.getOrDefault(false),
                quiet = runCatching { um.isQuietModeEnabled(handle) }.getOrDefault(false),
                mediaShared = prop("isMediaSharedWithParent") as? Boolean,
                hidden = (prop("getProfileApiVisibility") as? Int)?.let { it == PROFILE_API_VISIBILITY_HIDDEN },
                flagNames = names,
                parentId = group.takeIf { it != id && it != ShellAppCopies.NO_PROFILE_GROUP }
                    ?: if (flagsToString == null) dumped[id]?.parentId else null,
            )
        }
    }

    private fun flagNames(s: String): List<String> = s.trim('{', '}', ' ').split('|', ' ', ',').map(String::trim).filter(String::isNotEmpty)

    // ==========================================
    // 9. Device Wakeup & Unlock
    // ==========================================

    fun wakeDevice(): Boolean = deviceUnlock.wake()
    fun dismissDeviceKeyguard(): Boolean = deviceUnlock.dismiss()
    fun revealDeviceCredential(): Boolean = deviceUnlock.reveal()
    fun revealDeviceCredentialTap(x: Int, y: Int): Boolean = deviceUnlock.tap(x, y)
    fun enterDeviceCredential(kind: Int, credential: ByteArray, clear: Int): Boolean = deviceUnlock.enter(kind, credential, clear)

    // ==========================================
    // 10. System Commands, Identity & DevTools Socket
    // ==========================================

    fun identity(): IntArray = intArrayOf(Process.myUid(), Process.myPid())

    fun runSystemCommand(displayId: Int, command: String): Bundle {
        if (!ownDisplay(displayId)) return commandResult(-1, "No task display is active.")
        return execShellCommand(command, displayId)
    }

    fun runCommand(command: String): Bundle = execShellCommand(command, null)

    fun openDevtoolsSocket(name: String): ParcelFileDescriptor? {
        val pid = ShellDevtoolsSocket.pidOf(name) ?: return null
        val uid = runCatching { ShellDevtoolsSocket.procUid(File("/proc/$pid/status").readText()) }.getOrNull()
        if (allowedUid > 0 && uid != allowedUid) {
            Log.w(tag, "devtools socket refused: pid $pid UID $uid != allowed $allowedUid")
            return null
        }
        val socket = LocalSocket()
        return try {
            socket.connect(LocalSocketAddress(name, LocalSocketAddress.Namespace.ABSTRACT))
            ParcelFileDescriptor.dup(socket.fileDescriptor)
        } catch (e: Exception) {
            Log.w(tag, "devtools socket $name: ${e.message}")
            null
        } finally {
            runCatching { socket.close() }
        }
    }

    private fun commandResult(code: Int, output: String): Bundle = Bundle().apply {
        putInt("exitCode", code)
        putString("output", output)
    }

    private fun execShellCommand(command: String, displayId: Int?): Bundle {
        if (command.isBlank() || command.length > 4_000) return commandResult(-1, "Invalid command length.")
        val process = try {
            ProcessBuilder("/system/bin/sh", "-c", command).redirectErrorStream(true).apply {
                if (displayId != null) {
                    val value = displayId.toString()
                    environment()[DEFAULT_ENV_DISPLAY_ID] = value
                    if (envDisplayVarName.isNotBlank()) environment()[envDisplayVarName] = value
                }
            }.start()
        } catch (t: Throwable) {
            return commandResult(-1, t.message ?: "Command could not start.")
        }
        val bytes = ByteArrayOutputStream()
        val reader = Thread {
            runCatching {
                process.inputStream.use { input ->
                    val buffer = ByteArray(4096)
                    while (true) {
                        val count = input.read(buffer)
                        if (count < 0) break
                        if (bytes.size() < COMMAND_OUTPUT_MAX) {
                            bytes.write(buffer, 0, minOf(count, COMMAND_OUTPUT_MAX - bytes.size()))
                        }
                    }
                }
            }
        }.apply {
            isDaemon = true
            start()
        }
        val finished = process.waitFor(CMD_TIMEOUT_S, TimeUnit.SECONDS)
        if (!finished) process.destroyForcibly()
        reader.join(READER_JOIN_MS)
        val output = bytes.toString(Charsets.UTF_8.name()) + if (bytes.size() >= COMMAND_OUTPUT_MAX) "\n[output truncated]" else ""
        return commandResult(if (finished) process.exitValue() else -1, output)
    }

    private fun exec(vararg cmd: String): Int = sh(*cmd).first

    fun sh(vararg cmd: String): Pair<Int, String> {
        val p = try {
            ProcessBuilder(*cmd).redirectErrorStream(true).start()
        } catch (t: Throwable) {
            Log.w(tag, "exec ${cmd.joinToString(" ")} failed", t)
            return -1 to ""
        }
        val output = AtomicReference("")
        val reader = Thread { output.set(runCatching { p.inputStream.bufferedReader().readText() }.getOrDefault("")) }
            .apply {
                isDaemon = true
                start()
            }
        if (!p.waitFor(CMD_TIMEOUT_S, TimeUnit.SECONDS)) {
            p.destroyForcibly()
            Log.w(tag, "exec ${cmd.joinToString(" ")} timed out")
            return -1 to ""
        }
        reader.join(READER_JOIN_MS)
        return p.exitValue() to output.get()
    }

    companion object {
        private const val DEFAULT_TAG = "AgentShell"
        private const val DEFAULT_ENV_DISPLAY_ID = "AGENT_DISPLAY_ID"
        private const val MAX_TASKS = 100
        private const val TAP_MS = 50L
        private const val STROKE_MAX_POINTS = 1_024
        private const val STROKE_MAX_MS = 10_000L
        private const val CMD_TIMEOUT_S = 10L
        private const val COMMAND_OUTPUT_MAX = 64 * 1024
        private const val READER_JOIN_MS = 1_000L
        private val MODE_RE = Regex("[a-z_]+")
        private const val PER_USER_RANGE = 100_000

        const val START_OK = 0
        const val START_IN_USE_ON_MAIN = 1
        const val START_NOT_FOUND = 2
        const val START_ERROR = 3
        const val START_OK_COLD_IGNORED = 4
        const val START_UNRESOLVED = 5
        const val START_INVALID_LINK = 6
        const val START_IN_USE_BY_OTHER = 7
        const val START_USER_NOT_ALLOWED = 8

        const val KEY_COPY_USERS = "users"
        const val KEY_COPY_SUMMARY = "summary"
        private const val PROFILE_API_VISIBILITY_HIDDEN = 1

        const val CLIP_SET = ShellClipboard.CLIP_SET
        const val CLIP_UNREADABLE = ShellClipboard.CLIP_UNREADABLE
        const val CLIP_FAILED = ShellClipboard.CLIP_FAILED

        private val TASK_INFO: Class<*> by lazy { Class.forName("android.app.TaskInfo") }
        private val WCT: Class<*> by lazy { Class.forName("android.window.WindowContainerTransaction") }
        const val INJECT_MODE_ASYNC = 0
        const val INJECT_MODE_WAIT_FOR_RESULT = 1
        const val INJECT_MODE_WAIT_FOR_FINISH = 2
        private const val VIRTUAL_KEYBOARD = -1
        private const val USER_CURRENT = -2
        private const val ACTIVITY_TYPE_UNDEFINED = 0
        private const val ACTIVITY_TYPE_STANDARD = 1
        private const val WINDOWING_MODE_FULLSCREEN = 1
        private const val IME_POLICY_LOCAL = 0

        private const val FLAG_PUBLIC = DisplayConfig.FLAG_PUBLIC
        private const val FLAG_OWN_CONTENT_ONLY = DisplayConfig.FLAG_OWN_CONTENT_ONLY
        private const val FLAG_SUPPORTS_TOUCH = DisplayConfig.FLAG_SUPPORTS_TOUCH
        private const val FLAG_ROTATES_WITH_CONTENT = DisplayConfig.FLAG_ROTATES_WITH_CONTENT
        private const val FLAG_DESTROY_CONTENT_ON_REMOVAL = DisplayConfig.FLAG_DESTROY_CONTENT_ON_REMOVAL
        private const val FLAG_TRUSTED = DisplayConfig.FLAG_TRUSTED
        private const val FLAG_OWN_DISPLAY_GROUP = DisplayConfig.FLAG_OWN_DISPLAY_GROUP
        private const val FLAG_ALWAYS_UNLOCKED = DisplayConfig.FLAG_ALWAYS_UNLOCKED
        private const val FLAG_TOUCH_FEEDBACK_DISABLED = DisplayConfig.FLAG_TOUCH_FEEDBACK_DISABLED
        private const val FLAG_OWN_FOCUS = DisplayConfig.FLAG_OWN_FOCUS
        private const val FLAG_STEAL_TOP_FOCUS_DISABLED = DisplayConfig.FLAG_STEAL_TOP_FOCUS_DISABLED

        /** Computes virtual display flags for [sdk] with optional trusted-display capabilities. */
        fun displayFlags(sdk: Int, trusted: Boolean): Int {
            var flags = FLAG_PUBLIC or FLAG_OWN_CONTENT_ONLY or FLAG_SUPPORTS_TOUCH or
                FLAG_ROTATES_WITH_CONTENT or FLAG_DESTROY_CONTENT_ON_REMOVAL
            if (sdk >= Build.VERSION_CODES.TIRAMISU) {
                flags = flags or FLAG_TOUCH_FEEDBACK_DISABLED
                if (trusted) flags = flags or FLAG_TRUSTED or FLAG_OWN_DISPLAY_GROUP or FLAG_ALWAYS_UNLOCKED
            }
            if (sdk >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE && trusted) {
                flags = flags or FLAG_OWN_FOCUS or FLAG_STEAL_TOP_FOCUS_DISABLED
            }
            return flags
        }

        private fun stripTrustedFlags(flags: Int): Int =
            flags and (FLAG_TRUSTED or FLAG_OWN_DISPLAY_GROUP or FLAG_ALWAYS_UNLOCKED or FLAG_OWN_FOCUS or FLAG_STEAL_TOP_FOCUS_DISABLED).inv()

        /** Chooses InputManager injection mode (`WAIT_FOR_FINISH` > `WAIT_FOR_RESULT` for keys > `ASYNC` for touch). */
        fun injectMode(key: Boolean, waitForFinish: Boolean): Int = when {
            waitForFinish -> INJECT_MODE_WAIT_FOR_FINISH
            key -> INJECT_MODE_WAIT_FOR_RESULT
            else -> INJECT_MODE_ASYNC
        }

        /** Sends a down/up pair, falling back to [fallback] only if [down] failed; retries [up] once if [down] succeeded. */
        inline fun sendPair(down: () -> Boolean, up: () -> Boolean, fallback: () -> Boolean): Boolean {
            if (!down()) return fallback()
            return up() || up()
        }

        /** Retries display creation without trusted flags only on [SecurityException]. */
        fun retryWithoutTrust(t: Throwable): Boolean = t is SecurityException

        /** Checks whether a task (packages + optional user) belongs to the same copy `[packageName, userId]`. */
        fun sameCopy(taskPackages: Collection<String>, taskUser: Int?, packageName: String, userId: Int?): Boolean =
            packageName in taskPackages && (userId == null || taskUser == null || taskUser == userId)

        /** Parses `appops get <pkg> PLAY_AUDIO` returning `"default"` when unset. */
        fun parsePlayAudioMode(output: String): String = AudioMuteLedger.parsePlayAudioMode(output)
    }
}
