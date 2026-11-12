package com.agent.use.common.api

import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.Rect
import android.view.Surface
import com.agent.use.common.DisplayGeometry

/**
 * 虚拟屏图像帧旋转与裁剪渲染处理器。
 *
 * 核心功能：
 * 将底层固定尺寸物理缓冲（可能为顺时针旋转存储）反向旋转并裁剪行填充，
 * 直接输出符合应用逻辑方向与坐标系的 Bitmap 画面，供预览或 OCR 算法消费。
 */
object DisplayFrameProcessor {

    /**
     * 将物理缓冲位图反向旋转校正为符合逻辑方向的位图。
     *
     * @param buffer 物理缓冲位图 (可能包含 rowStride 填充)
     * @param geometry 屏幕几何与旋转元数据
     * @param maxWidth 目标位图最大宽度 (默认等于逻辑宽度，支持下采样缩放)
     * @param paint 绘制画笔
     * @return 校正后的新 Bitmap 实例（调用方负责 recycle）
     */
    @JvmStatic
    fun renderUprightBitmap(
        buffer: Bitmap,
        geometry: DisplayGeometry,
        maxWidth: Int = geometry.logicalWidth,
        paint: Paint = Paint(Paint.FILTER_BITMAP_FLAG),
    ): Bitmap {
        val (targetWidth, targetHeight) = geometry.calculatePreviewSize(maxWidth)
        val result = Bitmap.createBitmap(targetWidth, targetHeight, Bitmap.Config.ARGB_8888)
        val canvas = Canvas(result)

        canvas.scale(
            targetWidth.toFloat() / geometry.logicalWidth,
            targetHeight.toFloat() / geometry.logicalHeight
        )

        when (geometry.rotation) {
            Surface.ROTATION_90 -> {
                canvas.translate(0f, geometry.bufferWidth.toFloat())
                canvas.rotate(-90f)
            }
            Surface.ROTATION_180 -> {
                canvas.translate(geometry.bufferWidth.toFloat(), geometry.bufferHeight.toFloat())
                canvas.rotate(180f)
            }
            Surface.ROTATION_270 -> {
                canvas.translate(geometry.bufferHeight.toFloat(), 0f)
                canvas.rotate(90f)
            }
        }

        val srcContent = Rect(0, 0, geometry.bufferWidth, geometry.bufferHeight)
        canvas.drawBitmap(buffer, srcContent, srcContent, paint)
        return result
    }
}
