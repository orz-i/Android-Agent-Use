package com.agent.display.server

import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.hardware.display.DisplayManager
import android.hardware.display.VirtualDisplay
import android.os.Build
import android.os.Bundle
import android.os.Parcel
import android.os.PowerManager
import android.os.Process
import android.os.SystemClock
import android.util.Log
import android.view.Surface
import com.agent.display.common.DisplayConfig
import com.agent.display.common.IAgentShell
import java.io.File
import java.lang.reflect.Method
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

@SuppressLint("PrivateApi")
class ShellService(
    private val allowedUid: Int,
    stateDir: File = File("/data/local/tmp"),
) : IAgentShell.Stub() {

    companion object {
        private const val TAG = "AgentShellService"
        private const val CMD_TIMEOUT_S = 10L
        private const val IME_POLICY_LOCAL = 0
        private const val WINDOWING_MODE_FULLSCREEN = 1
        private val TASK_INFO: Class<*> by lazy { Class.forName("android.app.TaskInfo") }
    }

    private val context: Context = ShellContext.create()
    private val displays = HashMap<Int, VirtualDisplay>()
    private var orientationWatch: DisplayOrientationWatcher? = null
    private val requestedOrientations = ConcurrentHashMap<Int, Int>()

    private val muted = AudioMuteLedger(File(stateDir, "agent_audio_mute_$allowedUid.ledger"))
    private val myUser = allowedUid / 100_000

    private val displayManager: DisplayManager =
        DisplayManager::class.java.getDeclaredConstructor(Context::class.java)
            .apply { isAccessible = true }.newInstance(context)

    private val clipboard = ShellClipboard(context)
    private val taskManagerFacade = TaskManagerFacade(context, ::ownDisplay) { cmd -> sh(*cmd) }
    private val inputInjector = InputInjector(::ownDisplay) { cmd -> sh(*cmd) }

    private val powerManager: PowerManager by lazy {
        context.getSystemService(Context.POWER_SERVICE) as PowerManager
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
        }.onFailure { Log.w(TAG, "display keep-awake unavailable: ${it.message}") }.getOrNull()
    }

    fun ownDisplay(displayId: Int): Boolean = synchronized(displays) { displayId in displays }

    private fun pokeDisplay(displayId: Int): Boolean {
        val (power, method) = userActivity ?: return false
        return try {
            method.invoke(power, displayId, SystemClock.uptimeMillis(), DisplayAwake.EVENT_TOUCH, 0)
            true
        } catch (t: Throwable) {
            Log.w(TAG, "userActivity poke failed: ${t.message}")
            false
        }
    }

    private fun displayGroup(displayId: Int): Int? = runCatching {
        val global = Class.forName("android.hardware.display.DisplayManagerGlobal").getMethod("getInstance").invoke(null)!!
        val info = global.javaClass.getMethod("getDisplayInfo", Int::class.javaPrimitiveType).invoke(global, displayId)!!
        info.javaClass.getField("displayGroupId").getInt(info)
    }.getOrNull()

    // ==========================================
    // 1. 虚拟屏生命周期
    // ==========================================

    override fun createDisplay(surface: Surface, config: DisplayConfig): Int {
        val name = config.name.ifEmpty { DisplayConfig.DEFAULT_DISPLAY_NAME }
        return try {
            createVirtualDisplayInternal(surface, config, name, trusted = true)
        } catch (se: SecurityException) {
            Log.w(TAG, "Shell lacks ADD_TRUSTED_DISPLAY, retrying with untrusted flags: ${se.message}")
            try {
                createVirtualDisplayInternal(surface, config, name, trusted = false)
            } catch (t: Throwable) {
                Log.e(TAG, "createDisplay failed on fallback", t)
                -1
            }
        } catch (t: Throwable) {
            Log.e(TAG, "createDisplay failed", t)
            -1
        }
    }

    private fun createVirtualDisplayInternal(
        surface: Surface,
        config: DisplayConfig,
        name: String,
        trusted: Boolean,
    ): Int {
        val flags = if (config.flags != 0) config.flags
        else DisplayConfig.resolveRecommendedFlags(Build.VERSION.SDK_INT, trusted)

        val vd = displayManager.createVirtualDisplay(name, config.width, config.height, config.dpi, surface, flags)
        val id = vd.display.displayId
        synchronized(displays) { displays[id] = vd }

        setFullscreenWindowingMode(id)
        setImePolicy(id)
        ensureOrientationWatch()

        if (DisplayAwake.needed(flags, DisplayConfig.FLAG_OWN_DISPLAY_GROUP, displayGroup(id))) {
            awake.start(id)
        }
        return id
    }

    override fun releaseDisplay(displayId: Int) {
        awake.stop(displayId)
        val (vd, watch) = synchronized(displays) {
            displays.remove(displayId) to (if (displays.isEmpty()) orientationWatch.also { orientationWatch = null } else null)
        }
        watch?.close()
        if (watch != null) requestedOrientations.clear()
        vd?.release()
    }

    override fun releaseAll() {
        awake.stopAll()
        val targets = synchronized(displays) {
            val list = displays.values.toList()
            displays.clear()
            orientationWatch?.close()
            orientationWatch = null
            requestedOrientations.clear()
            list
        }
        targets.forEach { runCatching { it.release() } }
        clipboard.restoreClip()
        recoverMuted()
    }

    override fun destroy() {
        releaseAll()
        android.os.Process.killProcess(android.os.Process.myPid())
    }

    private fun setFullscreenWindowingMode(displayId: Int) {
        runCatching {
            val wm = Class.forName("android.view.WindowManagerGlobal").getMethod("getWindowManagerService").invoke(null)!!
            wm.javaClass.getMethod("setWindowingMode", Int::class.javaPrimitiveType, Int::class.javaPrimitiveType)
                .invoke(wm, displayId, WINDOWING_MODE_FULLSCREEN)
        }.onFailure {
            sh("wm", "set-display-windowing-mode", "-d", "$displayId", "$WINDOWING_MODE_FULLSCREEN")
        }
    }

    private fun setImePolicy(displayId: Int) {
        runCatching {
            val wm = Class.forName("android.view.WindowManagerGlobal").getMethod("getWindowManagerService").invoke(null)!!
            wm.javaClass.getMethod("setDisplayImePolicy", Int::class.javaPrimitiveType, Int::class.javaPrimitiveType)
                .invoke(wm, displayId, IME_POLICY_LOCAL)
        }.onFailure {
            Log.w(TAG, "setDisplayImePolicy failed: ${it.message}")
        }
    }

    private fun ensureOrientationWatch() {
        if (Build.VERSION.SDK_INT < 34 || synchronized(displays) { orientationWatch != null }) return
        val watch = runCatching {
            DisplayOrientationWatcher(
                taskManagerFacade.taskManager,
                isDisplayActive = { synchronized(displays) { displays.isNotEmpty() } },
                onRequestedOrientation = { taskId, orientation -> requestedOrientations[taskId] = orientation },
                onTaskRemoved = { taskId -> requestedOrientations.remove(taskId) },
                sync = ::syncDisplayOrientations,
            )
        }.getOrNull() ?: return

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
        val top = taskManagerFacade.allTasks().groupBy {
            runCatching { TASK_INFO.getField("displayId").getInt(it) }.getOrDefault(-1)
        }
        for ((id, vd) in ours) runCatching {
            val task = top[id]?.firstOrNull() ?: return@runCatching
            val taskId = TASK_INFO.getField("taskId").getInt(task)
            val compat = runCatching { TASK_INFO.getField("appCompatTaskInfo").get(task) }.getOrNull() ?: task
            val cls = compat.javaClass

            val width = runCatching { cls.getField("topActivityLetterboxWidth").getInt(compat) }.getOrDefault(0)
            val height = runCatching { cls.getField("topActivityLetterboxHeight").getInt(compat) }.getOrDefault(0)
            val display = vd.display
            val mode = display.mode
            val rotation = DisplayOrientation.rotation(
                mode.physicalWidth, mode.physicalHeight, display.rotation, width, height,
                requestedOrientations[taskId] ?: -1
            ) ?: return@runCatching

            if (!ownDisplay(id)) return@runCatching
            val ok = runCatching {
                val wm = Class.forName("android.view.WindowManagerGlobal").getMethod("getWindowManagerService").invoke(null)!!
                val method = wm.javaClass.methods.first { it.name == "freezeDisplayRotation" }
                if (method.parameterTypes.size == 3) method.invoke(wm, id, rotation, "agent")
                else method.invoke(wm, id, rotation)
            }.isSuccess
            if (!ok) sh("wm", "user-rotation", "-d", "$id", "lock", "$rotation")
        }
    }

    // ==========================================
    // 2. 应用与任务生命周期
    // ==========================================

    override fun startApp(displayId: Int, packageName: String): Int =
        taskManagerFacade.startApp(displayId, packageName, myUser)

    override fun restartApp(displayId: Int, packageName: String): Int =
        taskManagerFacade.restartApp(displayId, packageName, myUser)

    override fun startAppInUser(displayId: Int, packageName: String, userId: Int, cold: Boolean): Int =
        if (cold) taskManagerFacade.restartApp(displayId, packageName, userId)
        else taskManagerFacade.startApp(displayId, packageName, userId)

    override fun startIntent(displayId: Int, intent: Intent): Int =
        taskManagerFacade.startIntent(displayId, intent)

    override fun startView(displayId: Int, action: String?, uri: String?, packageName: String?): Int =
        taskManagerFacade.startView(displayId, action, uri, packageName)

    override fun startShare(displayId: Int, packageName: String, text: String): Int =
        taskManagerFacade.startShare(displayId, packageName, text)

    override fun finishDisplay(displayId: Int, keepPackages: Array<String>?, closePackages: Array<String>?): Bundle =
        taskManagerFacade.finishDisplay(displayId, keepPackages, closePackages)

    // ==========================================
    // 3. 任务与层级查询
    // ==========================================

    override fun topTaskId(displayId: Int): Int = taskManagerFacade.topTaskId(displayId)
    override fun topActivity(displayId: Int): String? = taskManagerFacade.topActivity(displayId)
    override fun packageOfTask(taskId: Int): String? = taskManagerFacade.packageOfTask(taskId)
    override fun displayOfTask(taskId: Int): Int = taskManagerFacade.displayOfTask(taskId)
    override fun displayOfPackage(packageName: String): Int = taskManagerFacade.displayOfPackage(packageName)
    override fun displayOfPackageInUser(packageName: String, userId: Int): Int = taskManagerFacade.displayOfPackage(packageName, userId)
    override fun userOfTask(taskId: Int): Int = taskManagerFacade.userOfTask(taskId)
    override fun moveTask(taskId: Int, displayId: Int): Boolean = taskManagerFacade.moveTask(taskId, displayId)

    // ==========================================
    // 4. 主屏冲突避让
    // ==========================================

    override fun visibleOnMainScreen(packageName: String, userId: Int): Boolean =
        taskManagerFacade.visibleOnMainScreen(packageName, userId)

    override fun watchMainScreen(windowMs: Int): Int =
        taskManagerFacade.watchMainScreen(windowMs)

    override fun mainArrivals(sinceUptimeMs: Long): Bundle =
        taskManagerFacade.mainArrivals(sinceUptimeMs)

    // ==========================================
    // 5. 输入注入
    // ==========================================

    override fun injectTap(displayId: Int, x: Int, y: Int): Boolean =
        inputInjector.injectTap(displayId, x, y)

    override fun injectStroke(displayId: Int, xs: IntArray, ys: IntArray, times: LongArray): Boolean =
        inputInjector.injectStroke(displayId, xs, ys, times)

    override fun injectKey(displayId: Int, keyCode: Int): Boolean =
        inputInjector.injectKey(displayId, keyCode)

    override fun injectCtrlKey(displayId: Int, keyCode: Int): Int =
        inputInjector.injectCtrlKey(displayId, keyCode)

    override fun injectAsciiText(displayId: Int, taskId: Int, packageName: String, text: String): Int =
        inputInjector.injectAsciiText(displayId, taskId, packageName, text)

    // ==========================================
    // 6. 音频静音控制与恢复
    // ==========================================

    override fun setAudioMuted(packageName: String, muted: Boolean): Boolean =
        setAudioMutedInUser(packageName, myUser, muted)

    override fun getAudioMode(packageName: String): String? =
        getAudioModeInUser(packageName, myUser)

    override fun setAudioMode(packageName: String, mode: String): Boolean =
        setAudioModeInUser(packageName, myUser, mode)

    override fun setAudioMutedInUser(packageName: String, userId: Int, muted: Boolean): Boolean = synchronized(this.muted) {
        val key = AppAudioKey.of(packageName, userId)
        if (muted) {
            if (!this.muted.contains(key)) {
                val (code, out) = appops("get", packageName, userId)
                if (code != 0) return false
                val prior = AudioMuteLedger.parseSetMode(out) ?: "default"
                this.muted.put(key, prior)
            }
            appops("set", packageName, userId, "ignore").first == 0
        } else {
            val prior = this.muted[key] ?: return true
            val restore = AudioMuteLedger.restoreMode(prior)
            val ok = appops("set", packageName, userId, restore).first == 0
            if (ok) this.muted.remove(key)
            ok
        }
    }

    override fun getAudioModeInUser(packageName: String, userId: Int): String? {
        val (code, out) = appops("get", packageName, userId)
        return if (code == 0) AudioMuteLedger.parseSetMode(out) ?: "default" else null
    }

    override fun setAudioModeInUser(packageName: String, userId: Int, mode: String): Boolean =
        appops("set", packageName, userId, mode).first == 0

    fun recoverMuted() {
        muted.restoreAll { key, mode ->
            val pair = AppAudioKey.parse(key) ?: return@restoreAll false
            appops("set", pair.first, pair.second ?: 0, mode).first == 0
        }
    }

    private fun appops(op: String, pkg: String, user: Int?, vararg extras: String): Pair<Int, String> {
        val cmd = mutableListOf("appops", op)
        if (user != null && user != 0) cmd.addAll(listOf("--user", "$user"))
        cmd.addAll(listOf(pkg, "PLAY_AUDIO"))
        cmd.addAll(extras)
        return sh(*cmd.toTypedArray())
    }

    // ==========================================
    // 7. 剪贴板隔离
    // ==========================================

    override fun setClipText(text: String): Int = clipboard.setClipText(text)
    override fun restoreClip(): Boolean = clipboard.restoreClip()
    override fun savedClipText(): String? = clipboard.savedClipText()
    override fun restoreClipText(original: String, ours: String): Boolean = clipboard.restoreClipText(original, ours)

    // ==========================================
    // 8. 多用户支持
    // ==========================================

    override fun listUsers(): String? = sh("pm", "list", "users").takeIf { it.first == 0 }?.second
    override fun listPackages(userId: Int): String? = sh("pm", "list", "packages", "--user", "$userId").takeIf { it.first == 0 }?.second

    override fun isSystemPackage(packageName: String): Boolean = try {
        val flags = context.packageManager.getApplicationInfo(packageName, 0).flags
        flags and (android.content.pm.ApplicationInfo.FLAG_SYSTEM or android.content.pm.ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
    } catch (_: PackageManager.NameNotFoundException) {
        false
    }

    override fun appCopyUsers(): Bundle? = runCatching {
        val out = listUsers().orEmpty()
        val users = Regex("""UserInfo\{([0-9]+):""").findAll(out).map { it.groupValues[1].toInt() }.toList()
        Bundle().apply {
            putIntArray("users", users.toIntArray())
            putString("summary", out.lines().firstOrNull().orEmpty())
        }
    }.getOrNull()

    // ==========================================
    // 9. 设备唤醒与主屏准备
    // ==========================================

    override fun wakeDevice(): Boolean = runCatching {
        sh("input", "keyevent", "26") // KEYCODE_POWER
        true
    }.getOrDefault(false)

    override fun dismissDeviceKeyguard(): Boolean = runCatching {
        sh("wm", "dismiss-keyguard")
        true
    }.getOrDefault(false)

    override fun revealDeviceCredential(): Boolean = runCatching {
        sh("input", "swipe", "500", "1500", "500", "500")
        true
    }.getOrDefault(false)

    override fun revealDeviceCredentialTap(x: Int, y: Int): Boolean = runCatching {
        sh("input", "tap", "$x", "$y")
        true
    }.getOrDefault(false)

    override fun enterDeviceCredential(kind: Int, credential: ByteArray, clear: Int): Boolean = runCatching {
        val text = String(credential, Charsets.UTF_8)
        sh("input", "text", text)
        true
    }.getOrDefault(false)

    // ==========================================
    // 10. 系统命令与进程标识
    // ==========================================

    override fun identity(): IntArray = intArrayOf(Process.myUid(), Process.myPid())

    override fun runCommand(command: String): Bundle = commandResult(sh(command))

    override fun runSystemCommand(displayId: Int, command: String): Bundle =
        commandResult(sh("sh", "-c", "export AGENT_DISPLAY_ID=$displayId; $command"))

    private fun commandResult(pair: Pair<Int, String>): Bundle =
        Bundle().apply {
            putInt("exitCode", pair.first)
            putString("output", pair.second)
        }

    private fun sh(vararg cmd: String): Pair<Int, String> {
        val p = try {
            ProcessBuilder(*cmd).redirectErrorStream(true).start()
        } catch (t: Throwable) {
            Log.w(TAG, "exec ${cmd.joinToString(" ")} failed", t)
            return -1 to ""
        }
        val output = AtomicReference("")
        val reader = Thread { output.set(runCatching { p.inputStream.bufferedReader().readText() }.getOrDefault("")) }
            .apply { isDaemon = true; start() }
        if (!p.waitFor(CMD_TIMEOUT_S, TimeUnit.SECONDS)) {
            p.destroyForcibly()
            return -1 to ""
        }
        reader.join(1000L)
        return p.exitValue() to output.get()
    }
}
