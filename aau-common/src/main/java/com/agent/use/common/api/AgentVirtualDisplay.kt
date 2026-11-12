package com.agent.use.common.api

import android.graphics.Bitmap
import android.graphics.Paint
import android.graphics.PixelFormat
import android.hardware.display.DisplayManager
import android.media.ImageReader
import android.os.Handler
import android.os.HandlerThread
import android.os.SystemClock
import android.util.Log
import android.view.KeyEvent
import android.view.Surface
import com.agent.use.common.AudioMode
import com.agent.use.common.DisplayConfig
import com.agent.use.common.DisplayGeometry
import com.agent.use.common.FinishDisplayResult
import com.agent.use.common.IAgentShell
import com.agent.use.common.LaunchResult
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.io.ByteArrayOutputStream
import java.io.Closeable

/**
 * 面向第三方 Agent 开发者的虚拟屏核心操作外观。
 *
 * 核心特性：
 * 1. 独占式虚拟屏生命周期与 Surface / ImageReader 缓冲区绑定；
 * 2. 高性能双缓冲零拷贝渲染，动态节流限速至 ≤10 fps，避免高频丢帧积压与过度耗电；
 * 3. 屏幕旋转反向纠偏，保证逻辑坐标与视觉画面绝对对齐；
 * 4. 内置应用启动、触摸手势、按键、ASCII 输入、静音隔离与安全沉底收尾能力；
 * 5. 实现 [Closeable]，支持在 Kotlin `use { ... }` 作用域中安全自动释放。
 */
class AgentVirtualDisplay internal constructor(
    private val shell: IAgentShell,
    val config: DisplayConfig,
    private val displayManager: DisplayManager?,
) : Closeable {

    private val thread = HandlerThread("agent-display-${config.name}").apply { start() }
    private val handler = Handler(thread.looper)

    // RGBA_8888 双缓冲 ImageReader
    private val reader = ImageReader.newInstance(
        config.width,
        config.height,
        PixelFormat.RGBA_8888,
        2
    )

    /** 系统分配的真实 displayId */
    val displayId: Int

    /** 实时物理与逻辑几何信息 */
    val geometry: DisplayGeometry
        get() {
            val rotation = displayManager?.getDisplay(displayId)?.rotation ?: Surface.ROTATION_0
            return DisplayGeometry(config.width, config.height, rotation)
        }

    val logicalWidth: Int get() = geometry.logicalWidth
    val logicalHeight: Int get() = geometry.logicalHeight

    val width: Int get() = logicalWidth
    val height: Int get() = logicalHeight

    private val _frames = MutableStateFlow<Bitmap?>(null)
    /** 响应式画面帧流：经反向旋转纠偏后的最新画面（等比缩放到短边 ≤360，限速 ≤10fps） */
    val frames: StateFlow<Bitmap?> = _frames.asStateFlow()

    private val frameLock = Any()
    private var fullFrame: Bitmap? = null
    private var hasFrame = false
    private var cachedGeometry = DisplayGeometry(config.width, config.height, Surface.ROTATION_0)
    private var lastProcessedAt = 0L
    private var pendingSchedule = false
    private var frameTimestampNanos = 0L

    @Volatile
    private var isReleased = false

    private val paint = Paint(Paint.FILTER_BITMAP_FLAG)

    private val processRunnable = Runnable {
        pendingSchedule = false
        lastProcessedAt = SystemClock.uptimeMillis()
        processLatestFrame()
    }

    init {
        val id = try {
            shell.createDisplay(reader.surface, config)
        } catch (t: Throwable) {
            closeLocalResources()
            throw IllegalStateException("Failed to create virtual display on shell server", t)
        }

        if (id < 0) {
            closeLocalResources()
            throw IllegalStateException("Shell returned invalid displayId: $id")
        }
        displayId = id

        reader.setOnImageAvailableListener({ scheduleNextFrame() }, handler)
        handler.post { scheduleNextFrame() }
    }

    // ==========================================
    // 图像帧管线与截图 API
    // ==========================================

    private fun scheduleNextFrame() {
        if (pendingSchedule || isReleased) return
        pendingSchedule = true
        val delay = lastProcessedAt + FRAME_INTERVAL_MS - SystemClock.uptimeMillis()
        if (delay > 0) {
            handler.postDelayed(processRunnable, delay)
        } else {
            handler.post(processRunnable)
        }
    }

    private fun processLatestFrame() {
        if (isReleased) return
        val image = try {
            reader.acquireLatestImage()
        } catch (t: Throwable) {
            Log.w(TAG, "acquireLatestImage failed: ${t.javaClass.simpleName}", t)
            null
        } ?: return

        try {
            val plane = image.planes[0]
            val strideWidth = plane.rowStride / plane.pixelStride
            val currentGeometry = geometry

            synchronized(frameLock) {
                var bmp = fullFrame
                if (bmp == null || bmp.width != strideWidth) {
                    bmp?.recycle()
                    bmp = Bitmap.createBitmap(strideWidth, config.height, Bitmap.Config.ARGB_8888)
                    fullFrame = bmp
                }
                bmp!!.copyPixelsFromBuffer(plane.buffer.rewind())
                hasFrame = true
                frameTimestampNanos = image.timestamp
                cachedGeometry = currentGeometry

                _frames.value = DisplayFrameProcessor.renderUprightBitmap(
                    buffer = bmp,
                    geometry = currentGeometry,
                    maxWidth = currentGeometry.previewWidth(PREVIEW_SHORT_SIDE),
                    paint = paint
                )
            }
        } finally {
            image.close()
        }
    }

    /**
     * 获取当前屏幕最新一帧原始分辨率位图（已反向纠正旋转角度）。
     * 调用方在使用完毕后负责主动调用 bitmap.recycle()。
     */
    fun latestBitmap(): Bitmap? = synchronized(frameLock) {
        val bmp = fullFrame
        if (!hasFrame || bmp == null || isReleased) return null
        DisplayFrameProcessor.renderUprightBitmap(
            buffer = bmp,
            geometry = cachedGeometry,
            maxWidth = cachedGeometry.logicalWidth,
            paint = paint
        )
    }

    /**
     * 获取最新一帧压缩为 PNG 字节流的数据。
     */
    fun latestPng(): ByteArray? {
        val bmp = latestBitmap() ?: return null
        return try {
            ByteArrayOutputStream().use { out ->
                bmp.compress(Bitmap.CompressFormat.PNG, 100, out)
                out.toByteArray()
            }
        } finally {
            bmp.recycle()
        }
    }

    /**
     * 最新帧的硬件单调时钟纳秒时间戳。
     */
    fun lastFrameTimestamp(): Long? = synchronized(frameLock) {
        frameTimestampNanos.takeIf { !isReleased && it > 0 }
    }


    // ==========================================
    // 应用调度与启动控制
    // ==========================================

    /**
     * 在虚拟屏启动目标应用。自动检查主屏冲突，防打扰保护。
     */
    fun startApp(packageName: String): LaunchResult =
        LaunchResult.fromCode(shell.startApp(displayId, packageName))

    /**
     * 冷启动目标应用（安全结束无外部任务的应用进程后重新打开）。
     */
    fun restartApp(packageName: String): LaunchResult =
        LaunchResult.fromCode(shell.restartApp(displayId, packageName))

    /**
     * 在指定多用户（分身/工作资料）环境下启动应用。
     */
    fun startAppInUser(packageName: String, userId: Int, cold: Boolean = false): LaunchResult =
        LaunchResult.fromCode(shell.startAppInUser(displayId, packageName, userId, cold))

    /**
     * 打开安全链接或应用深度跳转。
     */
    fun startView(uri: String, action: String? = null, packageName: String? = null): LaunchResult =
        LaunchResult.fromCode(shell.startView(displayId, action, uri, packageName))

    /**
     * 发送文本分享至虚拟屏内应用。
     */
    fun startShare(packageName: String, text: String): LaunchResult =
        LaunchResult.fromCode(shell.startShare(displayId, packageName, text))


    // ==========================================
    // 输入事件精准注入
    // ==========================================

    /**
     * 注入单击触摸操作（逻辑坐标）。
     */
    fun injectTap(x: Int, y: Int): Boolean =
        shell.injectTap(displayId, x, y)

    /**
     * 注入一笔完整平滑滑动轨迹。
     *
     * @param xs 坐标点 X 序列
     * @param ys 坐标点 Y 序列
     * @param times 相对时间戳毫秒序列（首元素必须为 0）
     */
    fun injectStroke(xs: IntArray, ys: IntArray, times: LongArray): Boolean =
        shell.injectStroke(displayId, xs, ys, times)

    /**
     * 注入按键（如 KeyEvent.KEYCODE_BACK, KEYCODE_ENTER）。
     */
    fun injectKey(keyCode: Int): Boolean =
        shell.injectKey(displayId, keyCode)

    /**
     * 注入系统组合键（如 Ctrl+A, Ctrl+V）。
     */
    fun injectCtrlKey(keyCode: Int): Boolean =
        shell.injectCtrlKey(displayId, keyCode) == 1

    /**
     * 针对当前虚拟屏前台任务注入 ASCII 纯文本。
     */
    fun injectAsciiText(text: String): Boolean {
        val taskId = getTopTaskId()
        val pkg = getTopPackage() ?: return false
        if (taskId < 0) return false
        return shell.injectAsciiText(displayId, taskId, pkg, text) == 1
    }


    // ==========================================
    // 状态查询与音频控制
    // ==========================================

    fun getTopTaskId(): Int = shell.topTaskId(displayId)

    fun getTopActivity(): String? = shell.topActivity(displayId)

    fun getTopPackage(): String? {
        val taskId = getTopTaskId()
        return if (taskId >= 0) shell.packageOfTask(taskId) else null
    }

    /**
     * 对虚拟屏内的指定应用设置后台静音。
     */
    fun setAudioMuted(packageName: String, muted: Boolean): Boolean =
        shell.setAudioMuted(packageName, muted)

    /**
     * 查询指定应用的音频模式。
     */
    fun getAudioMode(packageName: String): AudioMode =
        AudioMode.fromRaw(shell.getAudioMode(packageName))

    /**
     * 显式设置应用音频模式。
     */
    fun setAudioMode(packageName: String, mode: AudioMode): Boolean =
        shell.setAudioMode(packageName, mode.raw)


    // ==========================================
    // 生命周期与安全收尾
    // ==========================================

    /**
     * 优雅结束虚拟屏会话：
     * 将期望保留的应用 (keepPackages) 迁移沉入主屏任务栈最底端（不打扰用户当前界面），
     * 将随屏销毁的应用 (closePackages) 连同发声应用一并清理。
     */
    fun finish(
        keepPackages: List<String> = emptyList(),
        closePackages: List<String> = emptyList(),
    ): FinishDisplayResult {
        if (isReleased) return FinishDisplayResult(emptyList(), emptyMap(), "Already released")
        val resultBundle = shell.finishDisplay(
            displayId,
            keepPackages.toTypedArray(),
            closePackages.toTypedArray()
        )
        closeLocalResources()
        return FinishDisplayResult.fromBundle(resultBundle)
    }

    /**
     * 彻底释放虚拟屏及底层图像缓冲。
     */
    fun release() {
        if (isReleased) return
        isReleased = true
        runCatching { shell.releaseDisplay(displayId) }
        closeLocalResources()
    }

    override fun close() {
        release()
    }

    private fun closeLocalResources() {
        isReleased = true
        handler.removeCallbacksAndMessages(null)
        handler.post {
            reader.close()
            synchronized(frameLock) {
                fullFrame?.recycle()
                fullFrame = null
                hasFrame = false
            }
        }
        thread.quitSafely()
        _frames.value = null
    }

    companion object {
        private const val TAG = "AgentVirtualDisplay"
        private const val PREVIEW_SHORT_SIDE = 360
        private const val FRAME_INTERVAL_MS = 100L // 10 fps
    }
}
