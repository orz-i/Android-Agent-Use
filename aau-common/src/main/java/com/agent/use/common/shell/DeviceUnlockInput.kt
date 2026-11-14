package com.agent.use.common.shell

import android.app.KeyguardManager
import android.content.Context
import android.os.PowerManager
import android.os.SystemClock
import android.view.InputDevice
import android.view.InputEvent
import android.view.KeyCharacterMap
import android.view.KeyEvent
import android.view.MotionEvent
import android.view.WindowManager

/**
 * Main-screen lockscreen preparation and targeted credential input.
 *
 * Credentials are never logged, placed on command lines, or written to the clipboard;
 * every swipe, tap, and key event is targeted strictly to `com.android.systemui`'s UID via
 * [injectTo] so events are rejected if another window is in focus.
 */
class DeviceUnlockInput(
    private val context: Context,
    private val inject: (InputEvent) -> Boolean,
    private val injectTo: (InputEvent, Int) -> Boolean,
    private val command: (List<String>) -> Boolean,
) {
    private val keyguard = context.getSystemService(KeyguardManager::class.java)
    private val power = context.getSystemService(PowerManager::class.java)
    private val systemUiUid: Int? by lazy { runCatching { context.packageManager.getPackageUid(SYSTEM_UI, 0) }.getOrNull() }

    /** Wakes the main display without toggling it off if already awake. */
    fun wake(): Boolean = key(KeyEvent.KEYCODE_WAKEUP, send = inject) || command(listOf("input", "keyevent", "224"))

    /** Dismisses an insecure swipe keyguard via `wm dismiss-keyguard`. */
    fun dismiss(): Boolean = command(listOf("wm", "dismiss-keyguard"))

    /** Swipes upward strictly targeting `com.android.systemui` to reveal the credential prompt. */
    fun reveal(): Boolean {
        val target = systemUiUid ?: return false
        if (!power.isInteractive || !keyguard.isKeyguardLocked || !keyguard.isDeviceLocked) return false
        val bounds = runCatching { context.getSystemService(WindowManager::class.java).currentWindowMetrics.bounds }.getOrNull()
            ?: return false
        val x = bounds.exactCenterX()
        val startY = bounds.bottom - bounds.height() * 0.15f
        val endY = bounds.top + bounds.height() * 0.45f
        val downAt = SystemClock.uptimeMillis()

        fun send(action: Int, at: Long, y: Float): Boolean {
            val event = MotionEvent.obtain(downAt, at, action, x, y, 0)
            return try {
                event.source = InputDevice.SOURCE_TOUCHSCREEN
                injectTo(event, target)
            } finally {
                event.recycle()
            }
        }
        if (!send(MotionEvent.ACTION_DOWN, downAt, startY)) return false
        var completed = false
        try {
            repeat(6) { step ->
                if (!power.isInteractive || !keyguard.isKeyguardLocked || !keyguard.isDeviceLocked) return false
                SystemClock.sleep(24)
                val progress = (step + 1) / 6f
                if (!send(MotionEvent.ACTION_MOVE, SystemClock.uptimeMillis(), startY + (endY - startY) * progress)) return false
            }
            if (!power.isInteractive || !keyguard.isKeyguardLocked || !keyguard.isDeviceLocked) return false
            completed = send(MotionEvent.ACTION_UP, SystemClock.uptimeMillis(), endY)
            return completed
        } finally {
            if (!completed) send(MotionEvent.ACTION_CANCEL, SystemClock.uptimeMillis(), endY)
        }
    }

    /** Sends a SystemUI-targeted tap (e.g., "Use password" fallback button). */
    fun tap(x: Int, y: Int): Boolean {
        val target = systemUiUid ?: return false
        if (!power.isInteractive || !keyguard.isKeyguardLocked || !keyguard.isDeviceLocked) return false
        val downAt = SystemClock.uptimeMillis()
        fun send(action: Int, eventTime: Long): Boolean {
            val event = MotionEvent.obtain(downAt, eventTime, action, x.toFloat(), y.toFloat(), 0)
            return try {
                event.source = InputDevice.SOURCE_TOUCHSCREEN
                injectTo(event, target)
            } finally {
                event.recycle()
            }
        }
        if (!send(MotionEvent.ACTION_DOWN, downAt)) return false
        return send(MotionEvent.ACTION_UP, downAt + TAP_MS)
    }

    /** Enters a PIN (`kind=0`) or Password (`kind=1`) strictly to SystemUI and wipes the byte buffer afterwards. */
    fun enter(kind: Int, bytes: ByteArray, clear: Int = 0): Boolean {
        var chars = CharArray(0)
        var sent = false
        val target = systemUiUid
        val deadline = SystemClock.uptimeMillis() + 8_000
        fun toKeyguard(event: InputEvent): Boolean {
            sent = true
            return injectTo(event, target!!)
        }
        try {
            if (target == null || !power.isInteractive || !keyguard.isKeyguardLocked || !keyguard.isDeviceLocked) return false
            if (!isSupportedKind(kind)) return false
            if (bytes.any { it.toInt() !in 32..126 }) return false
            chars = CharArray(bytes.size) { bytes[it].toInt().toChar() }
            if (!isValidCredential(kind, chars)) return false
            val map = KeyCharacterMap.load(KeyCharacterMap.VIRTUAL_KEYBOARD)
            val events = if (kind == KIND_PASSWORD) map.getEvents(chars) ?: return false else null
            if (kind == KIND_PIN) {
                repeat(clear.coerceIn(0, MAX_CLEAR)) {
                    if (!key(KeyEvent.KEYCODE_DEL, send = ::toKeyguard)) return false
                }
            } else if (!key(KeyEvent.KEYCODE_A, KeyEvent.META_CTRL_ON or KeyEvent.META_CTRL_LEFT_ON, ::toKeyguard) ||
                !key(KeyEvent.KEYCODE_DEL, send = ::toKeyguard)
            ) {
                return false
            }
            if (kind == KIND_PIN) {
                for (c in chars) {
                    if (SystemClock.uptimeMillis() > deadline || !keyguard.isKeyguardLocked || !power.isInteractive) return false
                    if (!key(KeyEvent.KEYCODE_0 + (c - '0'), send = ::toKeyguard)) return false
                }
            } else {
                for (event in events!!) {
                    event.source = InputDevice.SOURCE_KEYBOARD
                    if (SystemClock.uptimeMillis() > deadline || !keyguard.isKeyguardLocked || !power.isInteractive || !toKeyguard(event)) {
                        return false
                    }
                }
            }
            SystemClock.sleep(200)
            return !keyguard.isKeyguardLocked || !keyguard.isDeviceLocked || key(KeyEvent.KEYCODE_ENTER, send = ::toKeyguard)
        } finally {
            bytes.fill(0)
            chars.fill('\u0000')
            if (sent && target != null) {
                for (code in MODIFIERS) {
                    val now = SystemClock.uptimeMillis()
                    injectTo(
                        KeyEvent(now, now, KeyEvent.ACTION_UP, code, 0, 0, KeyCharacterMap.VIRTUAL_KEYBOARD, 0, 0, InputDevice.SOURCE_KEYBOARD),
                        target,
                    )
                }
            }
        }
    }

    private fun key(code: Int, meta: Int = 0, send: (InputEvent) -> Boolean): Boolean {
        val now = SystemClock.uptimeMillis()
        val down = KeyEvent(
            now, now, KeyEvent.ACTION_DOWN, code, 0, meta, KeyCharacterMap.VIRTUAL_KEYBOARD, 0, 0,
            InputDevice.SOURCE_KEYBOARD,
        )
        return send(down) && send(KeyEvent.changeAction(down, KeyEvent.ACTION_UP))
    }

    companion object {
        const val KIND_PIN = 0
        const val KIND_PASSWORD = 1
        private const val SYSTEM_UI = "com.android.systemui"
        private const val MAX_CLEAR = 16
        private const val TAP_MS = 30L
        private val MODIFIERS = intArrayOf(
            KeyEvent.KEYCODE_SHIFT_LEFT,
            KeyEvent.KEYCODE_SHIFT_RIGHT,
            KeyEvent.KEYCODE_ALT_LEFT,
            KeyEvent.KEYCODE_ALT_RIGHT,
        )

        /** Returns `true` if [kind] is PIN or Password. */
        fun isSupportedKind(kind: Int): Boolean = kind == KIND_PIN || kind == KIND_PASSWORD

        /** Validates credential length and character set according to [kind]. */
        fun isValidCredential(kind: Int, value: CharArray): Boolean = when (kind) {
            KIND_PIN -> value.size in 4..16 && value.all { it in '0'..'9' }
            KIND_PASSWORD -> value.size in 4..64 && value.all { it in ' '..'~' }
            else -> false
        }
    }
}
