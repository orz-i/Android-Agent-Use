package com.agent.use.common.shell

import android.annotation.SuppressLint
import android.os.Binder
import android.os.Handler
import android.os.HandlerThread
import android.os.IBinder
import android.os.Parcel
import android.util.Log

/**
 * Watches task requested-orientation and letterbox changes while virtual displays are active
 * and invokes [sync] to align display rotation without stealing main-screen focus.
 */
@SuppressLint("PrivateApi")
class DisplayOrientationWatch(
    private val taskManager: Any,
    private val active: () -> Boolean,
    private val onRequestedOrientation: (taskId: Int, orientation: Int) -> Unit = { _, _ -> },
    private val onTaskRemoved: (taskId: Int) -> Unit = {},
    private val sync: () -> Unit,
) {
    private val thread = HandlerThread("agent-display-orientation").apply { start() }
    private val handler = Handler(thread.looper)

    @Volatile
    private var closed = false
    private val scan = CoalescedScan(
        schedule = { handler.postDelayed(it, 50) },
        cancel = { handler.removeCallbacks(it) },
        scan = { runCatching(sync).onFailure { Log.w(TAG, "display orientation scan failed", it) } },
    )
    private val requestedOrientationTransactions = setOfNotNull(
        transactionCode("onActivityRequestedOrientationChanged"),
        transactionCode("onTaskRequestedOrientationChanged"),
    )
    private val taskRemovedTransaction = transactionCode("onTaskRemoved")
    private val signal = object : Binder() {
        init {
            attachInterface(null, TASK_LISTENER)
        }

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
            .getMethod("asInterface", IBinder::class.java)
            .invoke(null, signal)
    }.getOrNull()
    private val listening = listener != null && runCatching {
        taskManager.javaClass.methods.first { it.name == "registerTaskStackListener" }.invoke(taskManager, listener)
    }.isSuccess
    private val poll = object : Runnable {
        override fun run() {
            if (closed || !active()) return
            scan.request()
            handler.postDelayed(this, POLL_MS)
        }
    }

    init {
        if (listening) scan.request() else handler.post(poll)
    }

    /** Stops listening/polling and releases background threads. */
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
        private const val TAG = "DisplayOrientationWatch"
        private const val POLL_MS = 500L
        private const val TASK_LISTENER = "android.app.ITaskStackListener"

        fun transactionCode(callback: String): Int? = runCatching {
            Class.forName("android.app.ITaskStackListener\$Stub")
                .getDeclaredField("TRANSACTION_$callback").apply { isAccessible = true }.getInt(null)
        }.getOrNull()
    }
}
