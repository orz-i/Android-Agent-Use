package com.agent.display.common.api

import android.content.Context
import android.graphics.Bitmap
import android.os.IBinder
import android.view.KeyEvent
import com.agent.display.common.DisplayConfig
import com.agent.display.common.IAgentShell
import com.agent.display.common.LaunchResult
import java.io.Closeable

/**
 * =========================================================================
 * Android Agent Use (AAU)
 * 移动智能体屏幕使用与自主操作统一框架门面
 * =========================================================================
 *
 * 对应桌面端 "Computer Use" 理念，在 Android 端侧提供了一套完整的 "Android Agent Use" 标准规范：
 * 1. 独立沙盒虚拟屏 (Headless Sandbox Virtual Display)：无人打扰、防抢主屏焦点、防弹软键盘、防音频外放爆音；
 * 2. 零编解码原生图像流 (Zero-Encoding Screen Vision)：ImageReader 双缓冲直读，供给多模态视觉模型 (VLM) 与端侧 OCR；
 * 3. 双轨操作套件 (Dual-Track Action Suite)：
 *    - 物理坐标/按键操作套件 (Physical Action Suite)：精准坐标点击、连击、长按、贝塞尔多点轨迹、物理按键、组合键、ASCII键盘模拟；
 *    - 语义控件操作套件 (Semantic Action Suite)：无需计算坐标，直接按文本、资源ID查找并点击控件，自动抓取UI语义树；
 * 4. 应用与环境调度套件 (App & Environment Suite)：前后台应用无感调度、文本分享直通填表、静默剪贴板与自动还原。
 */
object AndroidAgentUse {

    const val VERSION = "1.0.0"
    const val NAME = "Android Agent Use"

    /**
     * 连接本地守护进程并构建 Android Agent Use 控制器
     */
    fun connect(context: Context, shellBinder: IBinder): AgentUseClient {
        val manager = AgentDisplayManager.fromBinder(context, shellBinder)
        return AgentUseClient(context, manager)
    }

    fun connect(context: Context, shell: IAgentShell): AgentUseClient {
        val manager = AgentDisplayManager.fromInterface(context, shell)
        return AgentUseClient(context, manager)
    }

    /**
     * Android Agent Use 客户端外观
     */
    class AgentUseClient internal constructor(
        private val context: Context,
        val manager: AgentDisplayManager
    ) : Closeable {

        /**
         * 开启一个独占的 Android Agent Use 操作会话 (Session)
         */
        fun openSession(
            config: DisplayConfig = DisplayConfig.standard1080p()
        ): AgentUseSession {
            val virtualDisplay = manager.createVirtualDisplay(config)
            return AgentUseSession(virtualDisplay)
        }

        inline fun <R> withSession(
            config: DisplayConfig = DisplayConfig.standard1080p(),
            block: (AgentUseSession) -> R
        ): R {
            val session = openSession(config)
            return try {
                block(session)
            } finally {
                session.close()
            }
        }

        override fun close() {
            manager.close()
        }
    }

    /**
     * 具备全套操作套件的交互会话
     */
    class AgentUseSession internal constructor(
        val display: AgentVirtualDisplay
    ) : Closeable {

        val displayId: Int get() = display.displayId
        val width: Int get() = display.width
        val height: Int get() = display.height

        // =========================================================================
        // 1. 屏幕感知套件 (Screen Vision & Perception Suite)
        // =========================================================================

        /**
         * 捕获当前屏幕最新原生高保真位图（Bitmap，自动反向旋转纠偏）
         */
        fun captureBitmap(): Bitmap? = display.latestBitmap()

        /**
         * 捕获当前屏幕最新 PNG 格式字节流（直接供给多模态视觉大模型 VLM）
         */
        fun capturePng(): ByteArray? = display.latestPng()

        // =========================================================================
        // 2. 物理坐标与按键操作套件 (Physical Action Suite)
        // =========================================================================

        /**
         * 单点轻触 (Tap)
         */
        fun tap(x: Int, y: Int): Boolean = display.injectTap(x, y)

        /**
         * 平滑直线滑动 (Swipe)
         */
        fun swipe(fromX: Int, fromY: Int, toX: Int, toY: Int, durationMs: Long = 300L): Boolean {
            val steps = 15
            val xs = IntArray(steps)
            val ys = IntArray(steps)
            val times = LongArray(steps)
            for (i in 0 until steps) {
                val t = i.toFloat() / (steps - 1)
                xs[i] = (fromX + (toX - fromX) * t).toInt()
                ys[i] = (fromY + (toY - fromY) * t).toInt()
                times[i] = (durationMs * t).toLong()
            }
            return display.injectStroke(xs, ys, times)
        }

        /**
         * 多点连续手势或贝塞尔曲线轨迹 (Stroke)
         */
        fun stroke(xs: IntArray, ys: IntArray, times: LongArray): Boolean =
            display.injectStroke(xs, ys, times)

        /**
         * 按键注入 (Key)
         */
        fun pressKey(keyCode: Int): Boolean = display.injectKey(keyCode)

        /**
         * 返回键 (Back)
         */
        fun pressBack(): Boolean = pressKey(KeyEvent.KEYCODE_BACK)

        /**
         * 主页键 (Home)
         */
        fun pressHome(): Boolean = pressKey(KeyEvent.KEYCODE_HOME)

        /**
         * 组合快捷键 (如 Ctrl+A 全选, Ctrl+V 粘贴)
         */
        fun pressCtrlKey(keyCode: Int): Boolean = display.injectCtrlKey(keyCode)

        /**
         * 模拟物理键盘键入 ASCII 纯文本
         */
        fun typeText(text: String): Boolean = display.injectAsciiText(text)

        // =========================================================================
        // 3. 应用与任务生命周期套件 (App Lifecycle Suite)
        // =========================================================================

        /**
         * 在虚拟屏启动目标应用（带主屏可见冲突检测与避让）
         */
        fun launchApp(packageName: String): LaunchResult = display.startApp(packageName)

        /**
         * 冷启动目标应用
         */
        fun restartApp(packageName: String): LaunchResult = display.restartApp(packageName)

        /**
         * 打开深度跳转 DeepLink 或系统页面
         */
        fun openUri(uri: String, action: String? = null, packageName: String? = null): LaunchResult =
            display.startView(uri, action, packageName)

        /**
         * 通过系统分享快速将文本灌入目标应用
         */
        fun shareText(packageName: String, text: String): LaunchResult =
            display.startShare(packageName, text)

        /**
         * 获取当前虚拟屏顶层活动包名
         */
        fun foregroundPackage(): String? = display.getTopPackage()

        // =========================================================================
        // 4. 环境与安全隔离套件 (Isolation & Safety Suite)
        // =========================================================================

        /**
         * 设置目标应用静音
         */
        fun muteApp(packageName: String): Boolean = display.setAudioMuted(packageName, true)

        /**
         * 解除目标应用静音
         */
        fun unmuteApp(packageName: String): Boolean = display.setAudioMuted(packageName, false)

        override fun close() {
            display.release()
        }
    }
}
