package com.agent.use.common.capture

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.os.ParcelFileDescriptor
import com.agent.use.common.IAgentShell

/**
 * 特权截屏的客户端门面。
 *
 * 把「调 Binder → 读 fd → 解码位图」这三步收在一处，避免每个调用点各写一遍 fd 生命周期管理。
 * 所有方法都不会抛异常：跨进程调用失败一律降级为 null / 不可用能力快照，
 * 因为截屏属于「尽力而为」的能力，调用方需要的是「有没有图」，而不是异常栈。
 */
object PrivilegedCapture {

    /**
     * 抓一帧 PNG 字节（主屏或任意 display，免授权）。
     */
    @JvmStatic
    fun capturePng(
        shell: IAgentShell,
        displayId: Int = 0,
        timeoutMs: Int = DEFAULT_TIMEOUT_MS,
        privilege: Int = ScreenCapturePrivilege.AUTO,
    ): ByteArray? = runCatching {
        val pfd = shell.capturePng(displayId, timeoutMs, privilege) ?: return null
        readAndClose(pfd)
    }.getOrNull()

    /**
     * 抓一帧并解码为位图；调用方负责 recycle。
     */
    @JvmStatic
    fun captureBitmap(
        shell: IAgentShell,
        displayId: Int = 0,
        timeoutMs: Int = DEFAULT_TIMEOUT_MS,
        privilege: Int = ScreenCapturePrivilege.AUTO,
    ): Bitmap? = capturePng(shell, displayId, timeoutMs, privilege)?.let(::decode)

    /**
     * 长截图：一次跨进程调用拿到整张长图与元信息。
     *
     * 返回对象里的 [LongScreenshotResult.png] 已被消费并置空，只保留统计字段，
     * 位图在 [LongScreenshotCapture.bitmap] 中。
     */
    @JvmStatic
    fun captureLong(
        shell: IAgentShell,
        displayId: Int = 0,
        options: LongScreenshotOptions = LongScreenshotOptions(),
    ): LongScreenshotCapture {
        val bundle = runCatching { shell.captureLongPng(displayId, options) }.getOrNull()
        val result = LongScreenshotResult.fromBundle(bundle)
        val bytes = result.png?.let { runCatching { readAndClose(it) }.getOrNull() }
        val bitmap = bytes?.let(::decode)
        return LongScreenshotCapture(bitmap, result.copy(png = null))
    }

    /**
     * 查询本机截屏能力；失败时返回 [ScreenCaptureCapability.unavailable]。
     */
    @JvmStatic
    fun capability(shell: IAgentShell): ScreenCaptureCapability = runCatching {
        ScreenCaptureCapability.fromBundle(shell.captureCapability())
    }.getOrNull() ?: ScreenCaptureCapability.unavailable("服务端未响应能力探测")

    /** 解码 PNG；失败返回 null。 */
    @JvmStatic
    fun decode(bytes: ByteArray): Bitmap? =
        runCatching { BitmapFactory.decodeByteArray(bytes, 0, bytes.size) }.getOrNull()

    private fun readAndClose(pfd: ParcelFileDescriptor): ByteArray =
        ParcelFileDescriptor.AutoCloseInputStream(pfd).use { it.readBytes() }

    private const val DEFAULT_TIMEOUT_MS = 5_000
}

/**
 * 长截图回执：位图 + 统计信息。
 */
data class LongScreenshotCapture(
    val bitmap: Bitmap?,
    val meta: LongScreenshotResult,
) {
    val ok: Boolean get() = bitmap != null

    val summary: String
        get() = "mode=${meta.mode?.label ?: "-"} frames=${meta.frames} scrolls=${meta.scrolls} " +
            "size=${meta.width}x${meta.height} stop=${meta.stop.wire} cost=${meta.elapsedMs}ms" +
            (meta.note?.let { " note=$it" } ?: "")
}
