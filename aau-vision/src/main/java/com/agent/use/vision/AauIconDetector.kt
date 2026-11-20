package com.agent.use.vision

import android.content.res.AssetManager
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.Rect
import java.io.Closeable
import kotlin.math.abs
import kotlin.math.max
import kotlin.math.min
import kotlin.math.roundToInt
import kotlin.math.sqrt

enum class IconGlyph { Search, Close, More }

sealed interface IconDetection {
    /** Exclusive right/bottom, in source bitmap pixels. Score is correlation, not a calibrated probability. */
    data class Match(val bounds: Rect, val score: Float) : IconDetection
    enum class Miss : IconDetection { NotFound, Ambiguous }
}

internal const val SIDE = 160
internal const val KERNEL = 19
internal const val MAP = SIDE - KERNEL + 1
internal const val CHANNELS = 11 // 3 sizes per glyph, then sum and sum of squares
internal const val ASSET = "aau_icon_glyphs_v1"

/** A CPU-only, memory-only detector. Call [detect] off the main thread. Caller owns the source bitmap. */
class AauIconDetector(private val assets: AssetManager) : Closeable {
    private var runtime: CpuIconModel? = null
    private var closed = false

    @Synchronized
    fun detect(bitmap: Bitmap, glyph: IconGlyph, region: Rect = Rect(0, 0, bitmap.width, bitmap.height)): IconDetection {
        check(!closed)
        require(bitmap.config != Bitmap.Config.HARDWARE && !region.isEmpty &&
            region.left >= 0 && region.top >= 0 && region.right <= bitmap.width && region.bottom <= bitmap.height)
        val scale = min(SIDE.toFloat() / region.width(), SIDE.toFloat() / region.height())
        val width = (region.width() * scale).roundToInt().coerceIn(1, SIDE)
        val height = (region.height() * scale).roundToInt().coerceIn(1, SIDE)
        if (width < KERNEL || height < KERNEL) return IconDetection.Miss.NotFound
        val left = (SIDE - width) / 2
        val top = (SIDE - height) / 2
        val input = FloatArray(SIDE * SIDE * 2)
        val scaled = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888)
        try {
            Canvas(scaled).drawBitmap(bitmap, region, Rect(0, 0, width, height), Paint(Paint.FILTER_BITMAP_FLAG))
            val pixels = IntArray(width * height)
            scaled.getPixels(pixels, 0, width, 0, 0, width, height)
            for (y in 0 until height) for (x in 0 until width) {
                val p = pixels[y * width + x]
                val luma = (((p ushr 16 and 255) * 77) + ((p ushr 8 and 255) * 150) + ((p and 255) * 29)) / 65280f
                val i = ((top + y) * SIDE + left + x) * 2
                input[i] = luma
                input[i + 1] = luma * luma
            }
        } finally {
            scaled.recycle()
        }
        val engine = runtime ?: CpuIconModel(assets, ASSET).also { runtime = it }
        return decode(engine.infer(input), glyph, region, left, top, width, height)
    }

    @Synchronized
    override fun close() {
        closed = true
        runtime?.close()
        runtime = null
    }

    companion object {
        val backend: String get() = CpuIconModel.NAME
        val supported: Boolean get() = CpuIconModel.isSupported()
    }
}

private data class Peak(val x: Int, val y: Int, val radius: Int, val score: Float)
private val radii = intArrayOf(4, 6, 8)
private const val MIN_SCORE = .76f
private const val PIXELS = KERNEL * KERNEL

private fun decode(out: FloatArray, glyph: IconGlyph, region: Rect, left: Int, top: Int, width: Int, height: Int): IconDetection {
    check(out.size == MAP * MAP * CHANNELS) { "Unexpected icon model output shape" }
    val wanted = glyph.ordinal * radii.size
    val peaks = mutableListOf<Peak>()
    // Only scan receptive fields that are entirely inside the actual image, never across padding.
    for (y in top..(top + height - KERNEL)) for (x in left..(left + width - KERNEL)) {
        val i = (y * MAP + x) * CHANNELS
        val sum = out[i + CHANNELS - 2]
        val varianceSum = out[i + CHANNELS - 1] - sum * sum / PIXELS
        if (!varianceSum.isFinite() || varianceSum < PIXELS * .025f * .025f) continue
        val inv = 1 / sqrt(varianceSum)
        var best = 0f
        var radius = 0
        var other = 0f
        for (channel in 0 until CHANNELS - 2) {
            val score = abs(out[i + channel]) * inv // same template works in dark and light themes
            if (channel in wanted until wanted + radii.size) {
                if (score > best) {
                    best = score
                    radius = radii[channel - wanted]
                }
            } else other = max(other, score)
        }
        if (best >= MIN_SCORE && best >= other + .06f) peaks += Peak(x + KERNEL / 2, y + KERNEL / 2, radius, min(1f, best))
    }
    val best = peaks.maxByOrNull { it.score } ?: return IconDetection.Miss.NotFound
    if (peaks.any { abs(it.x - best.x) > max(it.radius, best.radius) || abs(it.y - best.y) > max(it.radius, best.radius) }) {
        return IconDetection.Miss.Ambiguous
    }
    fun x(px: Int) = region.left + ((px - left).toFloat() * region.width() / width).roundToInt()
    fun y(px: Int) = region.top + ((px - top).toFloat() * region.height() / height).roundToInt()
    return IconDetection.Match(Rect(x(best.x - best.radius), y(best.y - best.radius), x(best.x + best.radius + 1), y(best.y + best.radius + 1)), best.score)
}
