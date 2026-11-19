package com.agent.use.common.capture

import android.graphics.Bitmap
import android.os.Bundle
import java.io.ByteArrayOutputStream
import java.io.File

/**
 * 截屏结果的 Binder 打包器。
 *
 * 服务端拿到 [LongScreenshotOutput] 后要做的三件事完全固定：压缩成 PNG、发布成 fd、拼成 Bundle。
 * 两个 Shell 守护进程（AAU 自带的 `aau-server` 与宿主自建的 shell 进程）都需要这段逻辑，
 * 放在这里可以保证两边返回的字段完全一致——客户端只认这一份契约。
 */
object CaptureDelivery {

    /**
     * 把位图级长截图结果打包成可直接从 AIDL 返回的 Bundle。
     *
     * 位图在方法内被回收，调用方不需要（也不应该）再碰它。
     *
     * @param failure 失败时补充的兜底原因（通常是引擎的 `failure`/`lastFailure`）
     */
    @JvmStatic
    fun longResult(
        output: LongScreenshotOutput,
        stateDir: File,
        mode: ScreenCaptureMode?,
        failure: String? = null,
    ): Bundle {
        val bitmap = output.bitmap
            ?: return LongScreenshotResult.failed(output.note ?: failure).toBundle()
        return try {
            val bytes = ByteArrayOutputStream().use { out ->
                bitmap.compress(Bitmap.CompressFormat.PNG, 100, out)
                out.toByteArray()
            }
            LongScreenshotResult(
                png = CaptureFd.publish(stateDir, bytes),
                width = output.width,
                height = output.height,
                frames = output.frames,
                scrolls = output.scrolls,
                stop = output.stop,
                elapsedMs = output.elapsedMs,
                mode = mode,
                note = output.note,
            ).toBundle()
        } finally {
            bitmap.recycle()
        }
    }
}
