package com.agent.use.server

import android.annotation.SuppressLint
import android.os.Build
import android.os.SystemClock
import android.util.Log
import android.view.InputDevice
import android.view.InputEvent
import android.view.KeyCharacterMap
import android.view.KeyEvent
import android.view.MotionEvent

@SuppressLint("PrivateApi")
class InputInjector(
    private val ownDisplay: (displayId: Int) -> Boolean,
    private val execCmd: ShellExecutor,
) {
    companion object {
        private const val TAG = "InputInjector"

        const val INJECT_MODE_ASYNC = 0
        const val INJECT_MODE_WAIT_FOR_RESULT = 1
        const val INJECT_MODE_WAIT_FOR_FINISH = 2

        private const val VIRTUAL_KEYBOARD = -1
        private const val TAP_INTERVAL_MS = 50L
        private const val STROKE_MAX_POINTS = 1024
        private const val STROKE_MAX_MS = 10_000L

        // 按键注入白名单，防止误触全局关机/音量等物理键
        private val ALLOWED_KEYS = setOf(
            KeyEvent.KEYCODE_BACK,
            KeyEvent.KEYCODE_DEL,
            KeyEvent.KEYCODE_FORWARD_DEL,
            KeyEvent.KEYCODE_DPAD_UP,
            KeyEvent.KEYCODE_DPAD_DOWN,
            KeyEvent.KEYCODE_DPAD_LEFT,
            KeyEvent.KEYCODE_DPAD_RIGHT,
            KeyEvent.KEYCODE_DPAD_CENTER,
            KeyEvent.KEYCODE_ENTER,
            KeyEvent.KEYCODE_TAB,
            KeyEvent.KEYCODE_SPACE,
            KeyEvent.KEYCODE_ESCAPE,
            KeyEvent.KEYCODE_PAGE_UP,
            KeyEvent.KEYCODE_PAGE_DOWN,
            KeyEvent.KEYCODE_MOVE_HOME,
            KeyEvent.KEYCODE_MOVE_END,
        )
    }

    /** API 34+ (Android 14) 使用 InputManagerGlobal，低版本使用 InputManager */
    private val inputManager: Any by lazy {
        runCatching {
            Class.forName("android.hardware.input.InputManagerGlobal").getMethod("getInstance").invoke(null)
        }.getOrNull() ?: Class.forName("android.hardware.input.InputManager").getMethod("getInstance").invoke(null)!!
    }

    /** 核心底层注入：反射 setDisplayId 并调用 injectInputEvent */
    fun inject(event: InputEvent, displayId: Int, mode: Int): Boolean = try {
        event.javaClass.getMethod("setDisplayId", Int::class.javaPrimitiveType).invoke(event, displayId)
        inputManager.javaClass.getMethod("injectInputEvent", InputEvent::class.java, Int::class.javaPrimitiveType)
            .invoke(inputManager, event, mode) as Boolean
    } catch (t: Throwable) {
        Log.w(TAG, "injectInputEvent failed on display $displayId: ${t.message}")
        false
    }

    /** Android 13+ 支持定向注入给指定 targetUid 的焦点窗口 */
    fun injectTargeted(event: InputEvent, displayId: Int, targetUid: Int): Boolean = try {
        event.javaClass.getMethod("setDisplayId", Int::class.javaPrimitiveType).invoke(event, displayId)
        inputManager.javaClass.getMethod(
            "injectInputEvent", InputEvent::class.java, Int::class.javaPrimitiveType, Int::class.javaPrimitiveType
        ).invoke(inputManager, event, INJECT_MODE_WAIT_FOR_FINISH, targetUid) as Boolean
    } catch (t: Throwable) {
        Log.w(TAG, "targeted injectInputEvent failed: ${t.message}")
        false
    }

    /** 单击注入 (Down + Up)，Down 失败时回退 shell input tap */
    fun injectTap(displayId: Int, x: Int, y: Int): Boolean {
        val now = SystemClock.uptimeMillis()
        val down = MotionEvent.obtain(now, now, MotionEvent.ACTION_DOWN, x.toFloat(), y.toFloat(), 0).apply {
            source = InputDevice.SOURCE_TOUCHSCREEN
        }
        val up = MotionEvent.obtain(now, now + TAP_INTERVAL_MS, MotionEvent.ACTION_UP, x.toFloat(), y.toFloat(), 0).apply {
            source = InputDevice.SOURCE_TOUCHSCREEN
        }
        return try {
            if (!inject(down, displayId, INJECT_MODE_ASYNC)) {
                execCmd.exec("input", "-d", "$displayId", "tap", "$x", "$y").first == 0
            } else {
                inject(up, displayId, INJECT_MODE_ASYNC) || inject(up, displayId, INJECT_MODE_ASYNC)
            }
        } finally {
            down.recycle()
            up.recycle()
        }
    }

    /** 平滑单指手势轨迹流注入 */
    fun injectStroke(displayId: Int, xs: IntArray, ys: IntArray, times: LongArray): Boolean {
        if (!ownDisplay(displayId)) return false
        val n = times.size
        if (n < 2 || n > STROKE_MAX_POINTS || xs.size != n || ys.size != n || times[0] != 0L ||
            times.last() > STROKE_MAX_MS || (1 until n).any { times[it] < times[it - 1] }
        ) return false

        val downTime = SystemClock.uptimeMillis()
        fun createEvent(i: Int, action: Int): MotionEvent {
            val props = MotionEvent.PointerProperties().apply { id = 0; toolType = MotionEvent.TOOL_TYPE_FINGER }
            val coords = MotionEvent.PointerCoords().apply { x = xs[i].toFloat(); y = ys[i].toFloat(); pressure = 1f; size = 1f }
            return MotionEvent.obtain(
                downTime, downTime + times[i], action, 1,
                arrayOf(props), arrayOf(coords), 0, 0, 1f, 1f, 0, 0,
                InputDevice.SOURCE_TOUCHSCREEN, 0
            )
        }

        fun sendPoint(i: Int, action: Int): Boolean {
            val scheduled = downTime + times[i]
            val wait = scheduled - SystemClock.uptimeMillis()
            if (wait > 0) SystemClock.sleep(wait)
            val e = createEvent(i, action)
            return try { inject(e, displayId, INJECT_MODE_ASYNC) } finally { e.recycle() }
        }

        if (!sendPoint(0, MotionEvent.ACTION_DOWN)) return false
        for (i in 1 until n - 1) {
            sendPoint(i, MotionEvent.ACTION_MOVE)
        }
        return sendPoint(n - 1, MotionEvent.ACTION_UP) || sendPoint(n - 1, MotionEvent.ACTION_UP)
    }

    /** 基础按键事件注入 */
    fun injectKey(displayId: Int, keyCode: Int): Boolean {
        if (keyCode !in ALLOWED_KEYS && keyCode !in KeyEvent.KEYCODE_0..KeyEvent.KEYCODE_9 &&
            keyCode !in KeyEvent.KEYCODE_A..KeyEvent.KEYCODE_Z
        ) {
            Log.w(TAG, "Key $keyCode not in allowed whitelist")
            return false
        }
        val now = SystemClock.uptimeMillis()
        val down = KeyEvent(now, now, KeyEvent.ACTION_DOWN, keyCode, 0, 0, VIRTUAL_KEYBOARD, 0, 0, InputDevice.SOURCE_KEYBOARD)
        val up = KeyEvent.changeAction(down, KeyEvent.ACTION_UP)
        return if (!inject(down, displayId, INJECT_MODE_WAIT_FOR_RESULT)) {
            execCmd.exec("input", "-d", "$displayId", "keyevent", "$keyCode").first == 0
        } else {
            inject(up, displayId, INJECT_MODE_WAIT_FOR_RESULT) || inject(up, displayId, INJECT_MODE_WAIT_FOR_RESULT)
        }
    }

    /** 组合键注入 (Ctrl+A, Ctrl+V) */
    fun injectCtrlKey(displayId: Int, keyCode: Int): Int {
        if (!ownDisplay(displayId)) return 0
        if (keyCode != KeyEvent.KEYCODE_A && keyCode != KeyEvent.KEYCODE_V) return 0

        val now = SystemClock.uptimeMillis()
        val meta = KeyEvent.META_CTRL_ON or KeyEvent.META_CTRL_LEFT_ON
        fun event(code: Int, action: Int, modifiers: Int) = KeyEvent(
            now, SystemClock.uptimeMillis(), action, code, 0, modifiers,
            VIRTUAL_KEYBOARD, 0, 0, InputDevice.SOURCE_KEYBOARD
        )

        var modifierDown = false
        try {
            if (!inject(event(KeyEvent.KEYCODE_CTRL_LEFT, KeyEvent.ACTION_DOWN, 0), displayId, INJECT_MODE_WAIT_FOR_RESULT)) return 0
            modifierDown = true
            if (!inject(event(keyCode, KeyEvent.ACTION_DOWN, meta), displayId, INJECT_MODE_WAIT_FOR_RESULT)) return 0
            val up = event(keyCode, KeyEvent.ACTION_UP, meta)
            return if (inject(up, displayId, INJECT_MODE_WAIT_FOR_RESULT) || inject(up, displayId, INJECT_MODE_WAIT_FOR_RESULT)) 1 else 2
        } finally {
            if (modifierDown) {
                val up = event(KeyEvent.KEYCODE_CTRL_LEFT, KeyEvent.ACTION_UP, 0)
                inject(up, displayId, INJECT_MODE_WAIT_FOR_RESULT)
            }
        }
    }

    /** 定向输入 ASCII 字符流 */
    fun injectAsciiText(displayId: Int, taskId: Int, packageName: String, text: String): Int {
        if (!ownDisplay(displayId) || taskId < 0 || text.isEmpty()) return 0
        val kcm = KeyCharacterMap.load(KeyCharacterMap.VIRTUAL_KEYBOARD)
        val events = kcm.getEvents(text.toCharArray()) ?: return 0

        for (event in events) {
            event.source = InputDevice.SOURCE_KEYBOARD
            val sent = inject(event, displayId, INJECT_MODE_WAIT_FOR_FINISH)
            if (!sent) return 2 // 投递不确定
        }
        return 1 // 全部成功
    }
}
