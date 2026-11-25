package com.agent.use.ui

import kotlinx.coroutines.delay

/**
 * 读一屏所需的最小端口：快照、画面、屏上文字、等待与诊断。
 *
 * 库只经由这几个方法判断界面，不关心下面是无障碍、WebView 还是别的东西。宿主的完整端口
 * （点按、输入、启动 App 等动作，以及自己产品语义的字段）在库外继承它即可，等待与诊断照旧复用。
 *
 * 约定：
 * - [snapshot] 的一次结果自洽：元素与它对应的那一帧画面一致；端口自己负责编号，库不改写它。
 * - [waitStable] / [awaitChange] 的时限只约束「最多等多久」，不保证等到；端口不支持时返回 false 由调用方按间隔重读。
 * - [checkScreen] 是可选的高质量诊断；为 null 时库按元素列表自己粗判（见 [ScreenDiagnosis]）。
 */
interface ScreenSurface {
    suspend fun snapshot(): ScreenSnapshot

    /** 读一屏但不登记编号(模型手里的 ref 不受影响);不可逆判定用。默认等同 [snapshot]。 */
    suspend fun peek(): ScreenSnapshot = snapshot()

    /** 当前画面;拿不到为 null。 */
    suspend fun screenshotPng(): ByteArray? = null

    /** 可选的本机文字识别；null 表示当前画面不可读或端口没有 OCR。 */
    suspend fun readVisibleText(): List<VisibleTextLine>? = null

    /** 等到界面安静下来；到时限仍在动返回 false。 */
    suspend fun waitStable(timeoutMs: Long): Boolean

    /**
     * 等这块屏的下一次界面变化,最多 [timeoutMs];等到返回 true。事件驱动的端口在有界面事件(无障碍事件、页面变动)时醒来,
     * 不支持的端口等满时限返回 false,由调用方按间隔重读。
     */
    suspend fun awaitChange(timeoutMs: Long): Boolean {
        delay(timeoutMs.coerceAtLeast(0))
        return false
    }

    /** 等待事件驱动的界面条件；condition: appear/disappear/activity/stable。 */
    suspend fun waitFor(condition: String, value: String?, timeoutMs: Long): Boolean = false

    /** 监听虚拟屏的界面事件，或全局通知；仅在调用期间订阅。 */
    suspend fun nextEvent(kind: String, packageName: String?, timeoutMs: Long): ScreenEvent? = null

    /** 在一段时间内持续收集事件；单次订阅不会漏掉两次事件间的变化。 */
    suspend fun watchEvents(kind: String, packageName: String?, durationMs: Long, maxEvents: Int): List<ScreenEvent> =
        listOfNotNull(nextEvent(kind, packageName, durationMs))

    /** 屏幕诊断;端口不支持时为 null,由调用方按元素列表粗判。 */
    suspend fun checkScreen(): ScreenCheck? = null

    /** 当前页面是否受系统防截屏保护。 */
    suspend fun isProtected(): Boolean = false
}
