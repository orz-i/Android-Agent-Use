package com.agent.use.common

import android.view.Surface

/**
 * 屏幕旋转与几何坐标转换契约。
 *
 * 核心原理：
 * 物理渲染缓冲区（如 ImageReader）的宽高在创建后保持固定（bufferWidth x bufferHeight）。
 * 当应用在虚拟屏内发生转屏（横屏 / 竖屏）时，系统通过逻辑旋转角度进行渲染映射。
 * 本类负责将逻辑屏幕尺寸、坐标与底层缓冲进行双向映射。
 */
data class DisplayGeometry(
    val bufferWidth: Int,
    val bufferHeight: Int,
    val rotation: Int = Surface.ROTATION_0,
) {
    /** 是否处于 90° 或 270° 侧翻旋转状态 */
    val isSideways: Boolean
        get() = rotation == Surface.ROTATION_90 || rotation == Surface.ROTATION_270

    /** 应用面对的当前逻辑屏幕宽度 */
    val logicalWidth: Int
        get() = if (isSideways) bufferHeight else bufferWidth

    /** 应用面对的当前逻辑屏幕高度 */
    val logicalHeight: Int
        get() = if (isSideways) bufferWidth else bufferHeight

    /**
     * 计算限制最大宽度下的等比缩放尺寸 (例如用于 UI 悬浮窗或调试预览)
     */
    fun calculatePreviewSize(maxWidth: Int): Pair<Int, Int> {
        val targetWidth = minOf(maxWidth, logicalWidth)
        val targetHeight = maxOf(1, (logicalHeight.toLong() * targetWidth / logicalWidth).toInt())
        return targetWidth to targetHeight
    }

    /**
     * 根据短边目标像素限制，计算保持横竖屏像素量均衡的预览宽度
     */
    fun previewWidth(shortSide: Int): Int =
        if (logicalWidth > logicalHeight) {
            maxOf(1, (logicalWidth.toLong() * shortSide / logicalHeight).toInt())
        } else {
            shortSide
        }

    /**
     * 将应用逻辑坐标 (例如 Agent 决策的点击坐标 x, y) 转换为底层物理缓冲坐标
     */
    fun mapLogicalToBuffer(logicalX: Float, logicalY: Float): Pair<Float, Float> =
        when (rotation) {
            Surface.ROTATION_90 -> (bufferWidth - 1 - logicalY) to logicalX
            Surface.ROTATION_180 -> (bufferWidth - 1 - logicalX) to (bufferHeight - 1 - logicalY)
            Surface.ROTATION_270 -> logicalY to (bufferHeight - 1 - logicalX)
            else -> logicalX to logicalY
        }

    /**
     * 将底层物理缓冲坐标转换回逻辑坐标
     */
    fun mapBufferToLogical(bufferX: Float, bufferY: Float): Pair<Float, Float> =
        when (rotation) {
            Surface.ROTATION_90 -> bufferY to (bufferWidth - 1 - bufferX)
            Surface.ROTATION_180 -> (bufferWidth - 1 - bufferX) to (bufferHeight - 1 - bufferY)
            Surface.ROTATION_270 -> (bufferHeight - 1 - bufferY) to bufferX
            else -> bufferX to bufferY
        }
}
