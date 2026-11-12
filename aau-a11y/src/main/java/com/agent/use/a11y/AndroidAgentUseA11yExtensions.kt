package com.agent.use.a11y

import com.agent.use.a11y.model.A11yNode
import com.agent.use.common.api.AndroidAgentUse

/**
 * Android Agent Use (AAU) 的无障碍语义操作扩展套件 (Semantic Action Extensions)
 * 为 AgentUseSession 注入免坐标计算的控件级自主操作能力
 */

/**
 * 抓取当前虚拟屏的完整无障碍 UI 语义树
 */
fun AndroidAgentUse.AgentUseSession.dumpHierarchy(): List<A11yNode> =
    AgentA11yBridge.getInstance().dumpHierarchy(displayId)

/**
 * 根据可见文本自动寻找控件并点击其中心位置
 */
suspend fun AndroidAgentUse.AgentUseSession.clickText(text: String, exact: Boolean = false): Boolean =
    AgentA11yBridge.getInstance().clickText(displayId, text, exact)

/**
 * 根据资源 ID 自动寻找控件并点击其中心位置
 */
suspend fun AndroidAgentUse.AgentUseSession.clickId(viewId: String): Boolean =
    AgentA11yBridge.getInstance().clickId(displayId, viewId)

/**
 * 页面上滑
 */
suspend fun AndroidAgentUse.AgentUseSession.swipeUp(): Boolean =
    AgentA11yBridge.getInstance().swipeUp(displayId, width, height)

/**
 * 页面下滑
 */
suspend fun AndroidAgentUse.AgentUseSession.swipeDown(): Boolean =
    AgentA11yBridge.getInstance().swipeDown(displayId, width, height)
