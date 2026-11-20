package com.agent.use.client

import android.graphics.Bitmap
import android.graphics.Paint
import android.graphics.PixelFormat
import android.hardware.display.DisplayManager
import android.media.ImageReader
import android.os.Handler
import android.os.HandlerThread
import android.os.SystemClock
import android.util.Log
import android.view.Display
import android.view.Surface
import com.agent.use.common.DisplayConfig
import com.agent.use.common.DisplayGeometry
import com.agent.use.common.IAgentShell
import com.agent.use.common.api.DisplayFrameProcessor
import com.agent.use.common.capture.LongScreenshotCapture
import com.agent.use.common.capture.LongScreenshotOptions
import com.agent.use.common.capture.PrivilegedCapture
import com.agent.use.common.capture.ScreenCaptureCapability
import com.agent.use.common.capture.ScreenCapturePrivilege
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.io.ByteArrayOutputStream
import java.io.Closeable

/**
 * 运行在 Agent 接入方进程的高性能虚拟屏客户端。
 *
 * 核心技术实现：
 * 1. 零拷贝直读：画面由服务端直接输出至本进程的 ImageReader RGBA_8888 缓冲区，规避无障碍截屏与权限提示；
 * 2. 动态限速丢帧队列：严格限制帧处理频率 <= 10fps（100ms 动态窗口合并），未消费旧帧通过 acquireLatestImage 自动跳帧丢弃；
 * 3. 几何模型与坐标纠偏：读取逻辑旋转角度（ROTATION_0/90/180/270），通过单次 Canvas 渲染完成 Stride 裁剪与反向旋转；
 * 4. 图像抽取接口：提供 Bitmap、PNG、WebP/JPEG 抽取及响应式 StateFlow 预览流。
 */
class AgentDisplay(
    private val shell: IAgentShell,
    val config: DisplayConfig,
    private val displayManager: DisplayManager,
) : Closeable, AutoCloseable {

    constructor(
        shell: IAgentShell,
        width: Int,
        height: Int,
        dpi: Int,
        displayManager: DisplayManager
    ) : this(
        shell = shell,
        config = DisplayConfig(width, height, dpi),
        displayManager = displayManager
    )

    private val thread = HandlerThread("agent-display-render").apply { start() }
    private val handler = Handler(thread.looper)
    private val reader = ImageReader.newInstance(config.width, config.height, PixelFormat.RGBA_8888, 2)

    val displayId: Int

    /** 当前屏幕几何与旋转信息 */
    val geometry: DisplayGeometry
        get() = DisplayGeometry(
            bufferWidth = config.width,
            bufferHeight = config.height,
            rotation = displayManager.getDisplay(displayId)?.rotation ?: Surface.ROTATION_0
        )

    val width: Int get() = geometry.logicalWidth
    val height: Int get() = geometry.logicalHeight

    private val _frames = MutableStateFlow<Bitmap?>(null)
    /** 实时预览画面流：限速 <= 10 帧/秒，短边等比缩放至 <= 360px */
    val frames: StateFlow<Bitmap?> = _frames.asStateFlow()

    private val frameLock = Any()
    private var fullFrameBuffer: Bitmap? = null // 带行填充 (rowStride) 的底层完整缓冲
    private var hasFrame = false
    private var frameGeometry = DisplayGeometry(config.width, config.height, Surface.ROTATION_0)
    private var lastProcessedAt = 0L
    private var pendingSchedule = false
    private var frameTimestampNanos = 0L
    @Volatile private var newerFramePending = false
    @Volatile private var isReleased = false

    private val paint = Paint(Paint.FILTER_BITMAP_FLAG)

    private val processTask = Runnable {
        pendingSchedule = false
        lastProcessedAt = SystemClock.uptimeMillis()
        processLatestFrame()
    }

    init {
        val id = try {
            shell.createDisplay(reader.surface, config)
        } catch (t: Throwable) {
            closeLocalResources()
            throw t
        }
        if (id < 0) {
            closeLocalResources()
            throw IllegalStateException("Failed to create remote virtual display, returned: $id")
        }
        displayId = id
        reader.setOnImageAvailableListener({
            newerFramePending = true
            scheduleNextFrame()
        }, handler)
        handler.post { scheduleNextFrame() }
    }

    private fun scheduleNextFrame() {
        if (pendingSchedule || isReleased) return
        pendingSchedule = true
        val waitMs = lastProcessedAt + MIN_FRAME_INTERVAL_MS - SystemClock.uptimeMillis()
        if (waitMs > 0) {
            handler.postDelayed(processTask, waitMs)
        } else {
            handler.post(processTask)
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
            val capturedGeometry = geometry

            synchronized(frameLock) {
                var bmp = fullFrameBuffer
                if (bmp == null || bmp.width != strideWidth || bmp.height != config.height) {
                    bmp?.recycle()
                    bmp = Bitmap.createBitmap(strideWidth, config.height, Bitmap.Config.ARGB_8888)
                    fullFrameBuffer = bmp
                }
                // 零拷贝直读：将原生 DirectByteBuffer 数据直接写入 Bitmap
                bmp.copyPixelsFromBuffer(plane.buffer.rewind())
                hasFrame = true
                frameTimestampNanos = image.timestamp
                frameGeometry = capturedGeometry
                newerFramePending = false

                // 提取预览图供 StateFlow 订阅
                val previewWidth = capturedGeometry.previewWidth(PREVIEW_SHORT_SIDE)
                _frames.value = DisplayFrameProcessor.renderUprightBitmap(bmp, capturedGeometry, previewWidth, paint)
            }
        } finally {
            image.close()
        }
    }

    /**
     * 获取最新一帧的应用逻辑坐标系 Bitmap（已纠偏旋转并去除 Stride 填充）。
     * 调用方在使用完毕后负责 recycle()。
     */
    fun latestFrameBitmap(): Bitmap? = synchronized(frameLock) {
        val bmp = fullFrameBuffer
        if (!hasFrame || bmp == null) null else DisplayFrameProcessor.renderUprightBitmap(bmp, frameGeometry, paint = paint)
    }

    /** 最新一帧整幅 PNG 字节数组；无画面时返回 null */
    fun latestFramePng(): ByteArray? {
        val bmp = latestFrameBitmap() ?: return null
        return try {
            ByteArrayOutputStream().use { os ->
                bmp.compress(Bitmap.CompressFormat.PNG, 100, os)
                os.toByteArray()
            }
        } finally {
            bmp.recycle()
        }
    }

    /** 支持 WebP/JPEG 抽取，显著降低视觉模型网络传输带宽 */
    fun latestFrameCompressed(format: Bitmap.CompressFormat, quality: Int = 85): ByteArray? {
        val bmp = latestFrameBitmap() ?: return null
        return try {
            ByteArrayOutputStream().use { os ->
                bmp.compress(format, quality.coerceIn(1, 100), os)
                os.toByteArray()
            }
        } finally {
            bmp.recycle()
        }
    }

    /** 获取最新一帧的硬件时间戳（纳秒，来自 SurfaceFlinger） */
    fun lastFrameTimestampNanos(): Long? = synchronized(frameLock) {
        frameTimestampNanos.takeIf { !isReleased && it > 0 }
    }

    /**
     * Current virtual-display frame identity. A trusted display may advertise
     * FLAG_SECURE even while showing an ordinary window; protected-window
     * handling belongs to the screen layer, not to this display capability bit.
     * Null during rotation or while a newer frame is pending.
     */
    data class VisibleFrameStamp(val timestampNanos: Long, val geometry: DisplayGeometry)

    fun visibleFrameStamp(): VisibleFrameStamp? {
        if (displayId == Display.DEFAULT_DISPLAY) return null
        val target = displayManager.getDisplay(displayId) ?: return null
        return synchronized(frameLock) {
            if (isReleased || newerFramePending || frameTimestampNanos <= 0 || frameGeometry.rotation != target.rotation) null
            else VisibleFrameStamp(frameTimestampNanos, frameGeometry)
        }
    }

    // ==========================================
    // 特权截屏与长截图（免 MediaProjection 授权）
    // ==========================================

    /**
     * 以 Shell / Root 身份直接抓取本虚拟屏的一帧 PNG。
     *
     * 与 [latestFramePng] 的区别：后者来自 ImageReader 的实时流，零成本但可能滞后一帧；
     * 本条走 `screencap`，是**当下这一刻**的像素，适合需要与点击严格对齐的证据留存。
     *
     * @param timeoutMs 抓帧超时
     * @param privilege [ScreenCapturePrivilege] 策略，默认先 Shell 后 Root
     */
    fun capturePrivilegedPng(
        timeoutMs: Int = 5_000,
        privilege: Int = ScreenCapturePrivilege.AUTO,
    ): ByteArray? = PrivilegedCapture.capturePng(shell, displayId, timeoutMs, privilege)

    /**
     * 以特权通道抓取本虚拟屏一帧并解码为位图；调用方负责 recycle。
     */
    fun capturePrivilegedBitmap(
        timeoutMs: Int = 5_000,
        privilege: Int = ScreenCapturePrivilege.AUTO,
    ): Bitmap? = PrivilegedCapture.captureBitmap(shell, displayId, timeoutMs, privilege)

    /**
     * 对本虚拟屏做滚动拼接长截图。
     *
     * 整个滚动周期同步占用一个 Binder 线程（默认最多 12 屏），**必须在工作线程调用**。
     * 返回的 [LongScreenshotCapture.bitmap] 由调用方 recycle。
     */
    fun captureLongScreenshot(
        options: LongScreenshotOptions = LongScreenshotOptions(),
    ): LongScreenshotCapture = PrivilegedCapture.captureLong(shell, displayId, options)

    /**
     * 查询本机可用的截屏通道（Shell / Root / 是否支持 `input -d` 滚动）。
     */
    fun captureCapability(): ScreenCaptureCapability = PrivilegedCapture.capability(shell)

    override fun close() {
        release()
    }

    fun release() {
        if (isReleased) return
        isReleased = true
        runCatching { shell.releaseDisplay(displayId) }
        closeLocalResources()
        _frames.value = null
    }

    private fun closeLocalResources() {
        isReleased = true
        handler.removeCallbacksAndMessages(null)
        handler.post {
            reader.close()
            synchronized(frameLock) {
                fullFrameBuffer?.recycle()
                fullFrameBuffer = null
                hasFrame = false
            }
        }
        thread.quitSafely()
    }

    companion object {
        private const val TAG = "AgentDisplay"
        const val PREVIEW_SHORT_SIDE = 360
        const val MIN_FRAME_INTERVAL_MS = 100L // 限速 <= 10fps
    }
}
