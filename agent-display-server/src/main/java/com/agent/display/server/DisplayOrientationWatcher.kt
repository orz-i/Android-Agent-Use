package com.agent.display.server

import android.annotation.SuppressLint
import android.content.pm.ActivityInfo
import android.os.Binder
import android.os.Handler
import android.os.HandlerThread
import android.os.IBinder
import android.os.Parcel
import android.util.Log

/**
 * 虚拟屏任务旋转动态监听器。
 *
 * 当设置了 FLAG_STEAL_TOP_FOCUS_DISABLED 时，后台虚拟屏不会抢夺主屏焦点，但部分系统因此不再自动旋转虚拟屏，
 * 导致横屏应用缩在竖屏顶部留黑边。本监听器只纠偏自己持有的虚拟屏，不干扰主屏。
 */
@SuppressLint("PrivateApi")
class DisplayOrientationWatcher(
    private val taskManager: Any,
    private val isDisplayActive: () -> Boolean,
    private val onRequestedOrientation: (taskId: Int, orientation: Int) -> Unit = { _, _ -> },
    private val onTaskRemoved: (taskId: Int) -> Unit = {},
    private val sync: () -> Unit,
) {
    private val thread = HandlerThread("agent-display-orientation").apply { start() }
    private val handler = Handler(thread.looper)
    @Volatile private var closed = false

    private val scan = CoalescedScan(
        schedule = { handler.postDelayed(it, 50) },
        cancel = { handler.removeCallbacks(it) },
        scan = { runCatching(sync).onFailure { Log.w(TAG, "display orientation sync failed", it) } }
    )

    private val requestedOrientationTransactions = setOfNotNull(
        transactionCode("onActivityRequestedOrientationChanged"),
        transactionCode("onTaskRequestedOrientationChanged"),
    )
    private val taskRemovedTransaction = transactionCode("onTaskRemoved")

    private val signal = object : Binder() {
        init { attachInterface(null, TASK_LISTENER) }
        override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
            if (code in requestedOrientationTransactions) {
                runCatching {
                    data.enforceInterface(TASK_LISTENER)
                    onRequestedOrientation(data.readInt(), data.readInt())
                }.onFailure { Log.w(TAG, "display orientation callback rejected", it) }
                scan.request()
                return true
            }
            if (code == taskRemovedTransaction) {
                runCatching {
                    data.enforceInterface(TASK_LISTENER)
                    onTaskRemoved(data.readInt())
                }.onFailure { Log.w(TAG, "task removal callback rejected", it) }
                scan.request()
                return true
            }
            if (code in FIRST_CALL_TRANSACTION..LAST_CALL_TRANSACTION) {
                scan.request()
                return true
            }
            return super.onTransact(code, data, reply, flags)
        }
    }

    private val listener = runCatching {
        Class.forName("android.app.ITaskStackListener\$Stub")
            .getMethod("asInterface", IBinder::class.java).invoke(null, signal)
    }.getOrNull()

    private val listening = listener != null && runCatching {
        taskManager.javaClass.methods.first { it.name == "registerTaskStackListener" }.invoke(taskManager, listener)
    }.isSuccess

    private val poll = object : Runnable {
        override fun run() {
            if (closed || !isDisplayActive()) return
            scan.request()
            handler.postDelayed(this, POLL_MS)
        }
    }

    init {
        if (listening) {
            scan.request()
        } else {
            Log.w(TAG, "ITaskStackListener unavailable, falling back to polling")
            handler.post(poll)
        }
    }

    fun close() {
        closed = true
        scan.close()
        if (listening) {
            runCatching {
                taskManager.javaClass.methods.first { it.name == "unregisterTaskStackListener" }.invoke(taskManager, listener)
            }
        }
        handler.removeCallbacksAndMessages(null)
        thread.quitSafely()
    }

    companion object {
        private const val TAG = "DisplayOrientation"
        private const val POLL_MS = 500L
        private const val TASK_LISTENER = "android.app.ITaskStackListener"

        fun transactionCode(callback: String): Int? = runCatching {
            Class.forName("android.app.ITaskStackListener\$Stub")
                .getDeclaredField("TRANSACTION_$callback").apply { isAccessible = true }.getInt(null)
        }.getOrNull()
    }
}

/** 一批连续事件只排一次扫描，去抖动合并 */
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

    fun request() = synchronized(lock) {
        if (!closed && !queued) {
            queued = true
            schedule(work)
        }
    }

    fun close() = synchronized(lock) {
        closed = true
        cancel(work)
    }
}

/** 旋转方向几何推导计算 */
object DisplayOrientation {
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
        ActivityInfo.SCREEN_ORIENTATION_USER_LANDSCAPE -> true
        ActivityInfo.SCREEN_ORIENTATION_PORTRAIT,
        ActivityInfo.SCREEN_ORIENTATION_SENSOR_PORTRAIT,
        ActivityInfo.SCREEN_ORIENTATION_REVERSE_PORTRAIT,
        ActivityInfo.SCREEN_ORIENTATION_USER_PORTRAIT -> false
        else -> null
    }
}
