package com.agent.use.common.shell

import android.annotation.SuppressLint
import android.os.Binder
import android.os.Bundle
import android.os.Handler
import android.os.HandlerThread
import android.os.IBinder
import android.os.Parcel
import android.os.SystemClock
import android.util.Log
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Watches main-screen top task transitions during active agent action windows using
 * `ITaskStackListener` (with polling fallback) and exports arrivals as parallel Bundle arrays.
 */
class MainScreenWatch(
    private val taskManager: () -> Any,
    private val tasks: () -> List<MainScreenLog.Task>,
    private val tag: String = DEFAULT_TAG,
) {
    private val log = MainScreenLog()
    private val thread = HandlerThread("agent-main-watch").apply { start() }
    private val handler = Handler(thread.looper)

    @Volatile
    private var until = 0L

    @Volatile
    private var listening: Boolean? = null
    private val queued = AtomicBoolean(false)
    private val polling = AtomicBoolean(false)
    private val signal = StackSignal()

    /** Opens or extends a main-screen watch window for [windowMs] and returns the current main top task ID. */
    fun watch(windowMs: Int): Int {
        val now = SystemClock.uptimeMillis()
        val top = synchronized(log) {
            scanLocked(now, record = now < until)
            until = maxOf(until, now + windowMs.coerceIn(0, MAX_WINDOW_MS))
            log.topTaskId
        }
        if (listening == null) listening = register()
        if (listening == false && polling.compareAndSet(false, true)) handler.post(::poll)
        return top
    }

    /** Returns recorded main-screen arrivals since [sinceUptimeMs] packed as parallel arrays. */
    fun arrivals(sinceUptimeMs: Long): Bundle = synchronized(log) {
        val now = SystemClock.uptimeMillis()
        if (now < until + GRACE_MS) scanLocked(now, record = true)
        toBundle(log.since(sinceUptimeMs), log::displayOf, listening == true)
    }

    /** Unregisters the task stack listener and stops the background handler thread. */
    fun close() {
        if (listening == true) {
            runCatching {
                taskManager().javaClass.methods.first { it.name == "unregisterTaskStackListener" }.invoke(taskManager(), listener())
            }
        }
        listening = null
        thread.quitSafely()
    }

    private fun scanLocked(now: Long, record: Boolean) {
        val list = try {
            tasks()
        } catch (t: Throwable) {
            Log.w(tag, "cannot list tasks", t)
            return
        }
        log.scan(list, now, record)
    }

    private fun scan() {
        val now = SystemClock.uptimeMillis()
        if (now >= until) return
        synchronized(log) { scanLocked(now, record = true) }
    }

    private fun onSignal() {
        if (SystemClock.uptimeMillis() >= until) return
        if (queued.compareAndSet(false, true)) {
            handler.postDelayed({ queued.set(false); scan() }, COALESCE_MS)
        }
    }

    private fun poll() {
        if (SystemClock.uptimeMillis() >= until) {
            polling.set(false)
            return
        }
        scan()
        handler.postDelayed(::poll, POLL_MS)
    }

    @SuppressLint("PrivateApi")
    private fun listener(): Any =
        Class.forName("android.app.ITaskStackListener\$Stub").getMethod("asInterface", IBinder::class.java).invoke(null, signal)!!

    private fun register(): Boolean = try {
        val am = taskManager()
        am.javaClass.methods.first { it.name == "registerTaskStackListener" && it.parameterTypes.size == 1 }.invoke(am, listener())
        Log.i(tag, "task stack listener registered")
        true
    } catch (t: Throwable) {
        Log.w(tag, "task stack listener unavailable, polling instead", t)
        false
    }

    private inner class StackSignal : Binder() {
        init {
            attachInterface(null, DESCRIPTOR)
        }

        override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
            if (code in FIRST_CALL_TRANSACTION..LAST_CALL_TRANSACTION) {
                onSignal()
                return true
            }
            return super.onTransact(code, data, reply, flags)
        }
    }

    companion object {
        private const val DEFAULT_TAG = "AgentShell"
        private const val DESCRIPTOR = "android.app.ITaskStackListener"
        const val POLL_MS = 100L
        private const val COALESCE_MS = 30L
        private const val GRACE_MS = 2_000L
        private const val MAX_WINDOW_MS = 30_000

        const val KEY_TASK = "task"
        const val KEY_PACKAGE = "package"
        const val KEY_USER = "user"
        const val KEY_AT = "at"
        const val KEY_FROM = "from"
        const val KEY_SAME_TASK = "sameTask"
        const val KEY_STANDARD = "standard"
        const val KEY_ACTIVITY = "activity"
        const val KEY_NOW = "now"
        const val KEY_LISTENING = "listening"

        /** Packs [list] of arrivals into a Binder-safe Bundle of parallel arrays. */
        fun toBundle(list: List<MainScreenLog.Arrival>, now: (Int) -> Int, listening: Boolean): Bundle = Bundle().apply {
            putIntArray(KEY_TASK, list.map { it.taskId }.toIntArray())
            putStringArray(KEY_PACKAGE, list.map { it.packageName }.toTypedArray())
            putIntArray(KEY_USER, list.map { it.userId }.toIntArray())
            putLongArray(KEY_AT, list.map { it.at }.toLongArray())
            putIntArray(KEY_FROM, list.map { it.from }.toIntArray())
            putBooleanArray(KEY_SAME_TASK, list.map { it.sameTask }.toBooleanArray())
            putBooleanArray(KEY_STANDARD, list.map { it.standard }.toBooleanArray())
            putStringArray(KEY_ACTIVITY, list.map { it.topActivity }.toTypedArray())
            putIntArray(KEY_NOW, list.map { now(it.taskId) }.toIntArray())
            putBoolean(KEY_LISTENING, listening)
        }
    }
}
