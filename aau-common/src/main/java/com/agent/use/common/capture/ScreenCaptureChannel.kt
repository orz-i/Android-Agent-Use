package com.agent.use.common.capture

import android.graphics.Bitmap

/**
 * 单条截屏通道。
 *
 * 实现方各自回答两个问题：我还能不能用（[isAvailable]），以及给我一张图（[capture]）。
 * 通道之间不做互相调用，优先级由 [ScreenCaptureChannel] 统一裁决。
 */
interface ScreenCaptureBackend {

    val mode: ScreenCaptureMode

    /** 当前是否可用；允许实现里做轻量探测，但不要阻塞超过几十毫秒。 */
    fun isAvailable(): Boolean

    /** 抓取指定屏的一帧；失败返回 null，不抛异常。 */
    fun capture(displayId: Int): Bitmap?

    /**
     * 抓取长截图；不支持长图的通道返回 null，此时通道会退化为一帧。
     */
    fun captureLong(displayId: Int, options: LongScreenshotOptions): Bitmap? = null
}

/** 单次通道尝试的结果，用于解释「为什么最后用的是这条通道」。 */
data class CaptureAttempt(
    val mode: ScreenCaptureMode,
    val ok: Boolean,
    val elapsedMs: Long,
    val note: String? = null,
)

/** 一次取像的完整回执：图 + 实际通道 + 所有尝试记录。 */
data class CaptureReport(
    val bitmap: Bitmap?,
    val mode: ScreenCaptureMode?,
    val attempts: List<CaptureAttempt>,
) {
    val ok: Boolean get() = bitmap != null

    /** 供日志/诊断使用的一行摘要。 */
    val summary: String
        get() = attempts.joinToString(" → ") { "${it.mode.label}${if (it.ok) "✓" else "✗"}(${it.elapsedMs}ms)" }
            .ifEmpty { "no-backend" }
}

/**
 * 多通道截屏调度器：按注册顺序逐个尝试，第一个成功的通道胜出。
 *
 * AAU 的推荐顺序是 `VIRTUAL_DISPLAY → SHELL_PRIVILEGED → ACCESSIBILITY`：
 * 虚拟屏直读零成本但要自己有屏；Shell 免授权且能抓主屏；无障碍只在前两者都不可用时才上，
 * 因为它有 1 秒系统冷却，且需要用户手动开启服务。
 *
 * 这个类刻意不持有任何 Android 服务引用，只吃 [ScreenCaptureBackend] 列表，
 * 因此宿主可以自由增删通道（例如在已 Root 的设备上把 Root 通道插到 Shell 之前）。
 */
class ScreenCaptureChannel(
    private val backends: List<ScreenCaptureBackend>,
) {

    constructor(vararg backends: ScreenCaptureBackend) : this(backends.toList())

    /** 当前可用通道。 */
    fun availableModes(): List<ScreenCaptureMode> = backends.filter { it.isAvailable() }.map { it.mode }

    /**
     * 抓一帧；按优先级尝试，全部失败返回 null 的 [CaptureReport]。
     */
    fun capture(displayId: Int): CaptureReport = run(displayId, null)

    /**
     * 抓长图；不支持长图的通道会被跳过（不会退化成单帧冒充长图）。
     */
    fun captureLong(displayId: Int, options: LongScreenshotOptions = LongScreenshotOptions()): CaptureReport =
        run(displayId, options)

    private fun run(displayId: Int, options: LongScreenshotOptions?): CaptureReport {
        val attempts = ArrayList<CaptureAttempt>(backends.size)
        for (backend in backends) {
            if (!backend.isAvailable()) {
                attempts += CaptureAttempt(backend.mode, ok = false, elapsedMs = 0L, note = "unavailable")
                continue
            }
            val startedAt = System.currentTimeMillis()
            val bitmap = try {
                if (options == null) backend.capture(displayId) else backend.captureLong(displayId, options)
            } catch (t: Throwable) {
                null
            }
            val cost = System.currentTimeMillis() - startedAt
            if (bitmap != null && bitmap.width > 0 && bitmap.height > 0) {
                attempts += CaptureAttempt(backend.mode, ok = true, elapsedMs = cost)
                return CaptureReport(bitmap, backend.mode, attempts)
            }
            attempts += CaptureAttempt(
                backend.mode,
                ok = false,
                elapsedMs = cost,
                note = if (options != null) "long-unsupported-or-failed" else "null",
            )
        }
        return CaptureReport(null, null, attempts)
    }
}

/** 把 Bitmap 压成 PNG；调用方负责 recycle。 */
fun Bitmap.encodePng(): ByteArray = java.io.ByteArrayOutputStream().use { out ->
    compress(Bitmap.CompressFormat.PNG, 100, out)
    out.toByteArray()
}
