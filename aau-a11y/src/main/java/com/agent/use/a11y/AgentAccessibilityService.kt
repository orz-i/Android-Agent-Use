package com.agent.use.a11y

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.AccessibilityServiceInfo
import android.app.Notification
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Path
import android.os.Build
import android.util.Log
import android.view.Display
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityWindowInfo
import com.agent.use.a11y.model.DisplayEvent
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume

/**
 * 通用 Agent 无障碍基础服务。
 *
 * 核心特性：
 * 1. 自动补齐 FLAG_INCLUDE_NOT_IMPORTANT_VIEWS 等必要标志，防止宿主 App 将关键控件标为不重要而漏读；
 * 2. 具备完整的单例生命周期追踪、跨实例重连转发与自愈机制；
 * 3. 多屏感知：自适应 Android 13+ 与早期系统的 displayId 解析，将事件分发至 DisplayEventStream；
 * 4. 内置多路径手势分发、浮层触摸隔离钩子与带频控重试的截图能力。
 */
open class AgentAccessibilityService : AccessibilityService() {

    private val gestureDispatcher = DisplayGestureDispatcher { _instance.value }

    /**
     * 截屏结果：成功位图、受防截屏保护、或失败错误码。
     */
    sealed interface ScreenshotOutcome {
        class Ok(val bitmap: Bitmap) : ScreenshotOutcome
        data object Secure : ScreenshotOutcome
        data class Failed(val code: Int) : ScreenshotOutcome
    }

    override fun onServiceConnected() {
        super.onServiceConnected()
        serviceInfo?.let { info ->
            val requiredFlags = AccessibilityServiceInfo.FLAG_INCLUDE_NOT_IMPORTANT_VIEWS or
                AccessibilityServiceInfo.FLAG_RETRIEVE_INTERACTIVE_WINDOWS or
                AccessibilityServiceInfo.FLAG_REPORT_VIEW_IDS
            if ((info.flags and requiredFlags) != requiredFlags) {
                info.flags = info.flags or requiredFlags
                serviceInfo = info
            }
        }
        _instance.value = this
        onServiceConnectedHook()
        Log.i(TAG, "AgentAccessibilityService connected.")
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent) {
        if (_instance.value !== this) return

        if (event.eventType == AccessibilityEvent.TYPE_WINDOWS_CHANGED) {
            DisplayEventStream.emitWindowChanged()
        }
        if (event.eventType == AccessibilityEvent.TYPE_WINDOWS_CHANGED ||
            event.eventType == AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED
        ) {
            DisplayEventStream.incrementWindowGeneration()
        }

        if (!shouldProcessEvent(event)) return

        if (event.eventType == AccessibilityEvent.TYPE_NOTIFICATION_STATE_CHANGED &&
            DisplayEventStream.hasNotificationSubscribers
        ) {
            val notification = event.parcelableData as? Notification
            val title = notification?.extras?.getCharSequence(Notification.EXTRA_TITLE)?.toString()
            val body = notification?.extras?.getCharSequence(Notification.EXTRA_TEXT)?.toString()
            val text = listOfNotNull(title, body).joinToString(" ").ifBlank { event.text.joinToString(" ") }
            DisplayEventStream.emitNotification(
                packageName = event.packageName?.toString(),
                text = text.take(MAX_NOTIFICATION_TEXT_LEN)
            )
        }

        if (!DisplayEventStream.hasDisplaySubscribers && !DisplayEventStream.hasRawSubscribers) return
        val displayId = displayOf(event)
        if (displayId == Display.INVALID_DISPLAY) return

        if (DisplayEventStream.hasDisplaySubscribers) {
            DisplayEventStream.emitEvent(DisplayEvent.from(displayId, event))
        }
        if (DisplayEventStream.hasRawSubscribers) {
            DisplayEventStream.emitRawEvent(displayId, event)
        }
    }

    override fun onInterrupt() {
        Log.w(TAG, "AgentAccessibilityService interrupted.")
    }

    override fun onUnbind(intent: Intent?): Boolean {
        Log.i(TAG, "AgentAccessibilityService unbound.")
        clearInstance()
        return super.onUnbind(intent)
    }

    override fun onDestroy() {
        Log.i(TAG, "AgentAccessibilityService destroyed.")
        clearInstance()
        super.onDestroy()
    }

    private fun clearInstance() {
        _instance.compareAndSet(this, null)
        onServiceCleared()
    }

    /**
     * 子类生命周期钩子：服务连接完成后回调。
     */
    protected open fun onServiceConnectedHook() {}

    /**
     * 子类生命周期钩子：服务断开或销毁清理时回调。
     */
    protected open fun onServiceCleared() {}

    /**
     * 子类事件过滤与旁路观察钩子；返回 false 时跳过后续事件分发。
     */
    protected open fun shouldProcessEvent(event: AccessibilityEvent): Boolean = true

    /**
     * 注入手势期间隔离宿主浮层触摸的钩子；默认直接执行。
     */
    open suspend fun <T> passInjectedGestureThrough(block: suspend () -> T): T = block()

    /**
     * 获取指定虚拟屏上的顶层窗口列表（委托给当前已连接实例，兼容重连恢复）。
     */
    fun windowsOn(displayId: Int): List<AccessibilityWindowInfo> =
        _instance.value?.windowsOnAllDisplays?.get(displayId).orEmpty()

    /**
     * 解析无障碍事件所属的屏幕编号。
     */
    fun displayOf(event: AccessibilityEvent): Int {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            return event.displayId
        }
        val targetWindowId = event.windowId
        if (targetWindowId == -1) return Display.INVALID_DISPLAY
        val allDisplays = windowsOnAllDisplays ?: return Display.INVALID_DISPLAY
        for (i in 0 until allDisplays.size()) {
            if (allDisplays.valueAt(i).any { it.id == targetWindowId }) {
                return allDisplays.keyAt(i)
            }
        }
        return Display.INVALID_DISPLAY
    }

    /**
     * 在指定屏上沿 [path] 执行单指手势。
     */
    suspend fun gesture(displayId: Int, path: Path, durationMs: Long): Boolean =
        gestureDispatcher.gesture(displayId, path, durationMs)

    /**
     * 在指定屏上沿多条 [paths] 并行执行手势。
     */
    suspend fun gesture(displayId: Int, paths: List<Path>, durationMs: Long): Boolean =
        gestureDispatcher.gesture(displayId, paths, durationMs)

    /**
     * 在同一点上连点 [count] 下。
     */
    suspend fun taps(
        displayId: Int,
        x: Float,
        y: Float,
        count: Int = 2,
        holdMs: Long = 50L,
        gapMs: Long = 100L
    ): Boolean = gestureDispatcher.taps(displayId, x, y, count, holdMs, gapMs)

    /**
     * 截取指定屏幕画面；遇到系统截图冷却限制时自动等待后重试一次。
     */
    suspend fun captureScreenshot(displayId: Int = Display.DEFAULT_DISPLAY): ScreenshotOutcome {
        val first = screenshotOnce(displayId)
        if (first !is ScreenshotOutcome.Failed || first.code != ERROR_TAKE_SCREENSHOT_INTERVAL_TIME_SHORT) {
            return first
        }
        delay(SCREENSHOT_INTERVAL_MS)
        return screenshotOnce(displayId)
    }

    private suspend fun screenshotOnce(displayId: Int): ScreenshotOutcome = suspendCancellableCoroutine { cont ->
        val service = _instance.value
        if (service == null) {
            cont.resume(ScreenshotOutcome.Failed(ERROR_TAKE_SCREENSHOT_NO_ACCESSIBILITY_ACCESS))
            return@suspendCancellableCoroutine
        }
        service.takeScreenshot(displayId, service.mainExecutor, object : TakeScreenshotCallback {
            override fun onSuccess(result: ScreenshotResult) {
                val shot = runCatching {
                    result.hardwareBuffer.use { buffer ->
                        val hw = Bitmap.wrapHardwareBuffer(buffer, result.colorSpace) ?: return@runCatching null
                        hw.copy(Bitmap.Config.ARGB_8888, false).also { hw.recycle() }
                    }
                }.getOrNull()
                if (cont.isActive) {
                    cont.resume(
                        shot?.let(ScreenshotOutcome::Ok)
                            ?: ScreenshotOutcome.Failed(ERROR_TAKE_SCREENSHOT_INTERNAL_ERROR)
                    )
                }
            }

            override fun onFailure(errorCode: Int) {
                val secure = Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE &&
                    errorCode == ERROR_TAKE_SCREENSHOT_SECURE_WINDOW
                if (cont.isActive) {
                    cont.resume(if (secure) ScreenshotOutcome.Secure else ScreenshotOutcome.Failed(errorCode))
                }
            }
        })
    }

    /**
     * 发生在指定屏上的原始无障碍事件流（跨服务重连实例保留）。
     */
    fun eventsFor(displayId: Int): Flow<AccessibilityEvent> = DisplayEventStream.rawEventsFor(displayId)

    /**
     * 窗口变化的信号流（跨服务重连实例保留）。
     */
    fun windowChanges(): Flow<Unit> = DisplayEventStream.windowChanges()

    companion object {
        private const val TAG = "AgentA11yService"
        private const val SCREENSHOT_INTERVAL_MS = 1_000L
        private const val MAX_NOTIFICATION_TEXT_LEN = 2_000

        private val _instance = MutableStateFlow<AgentAccessibilityService?>(null)
        val instance: StateFlow<AgentAccessibilityService?> = _instance.asStateFlow()

        @JvmStatic
        val isConnected: Boolean
            get() = _instance.value != null

        @JvmStatic
        fun isRunning(): Boolean = isConnected

        @JvmStatic
        fun windowGeneration(): Long = DisplayEventStream.windowGeneration()

        fun requireService(): AgentAccessibilityService =
            _instance.value ?: error("AgentAccessibilityService is not connected or enabled.")
    }
}
