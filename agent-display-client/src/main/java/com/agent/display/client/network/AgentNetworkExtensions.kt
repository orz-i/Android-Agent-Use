package com.agent.display.client.network

import android.content.Context
import com.agent.display.client.DisplaySession
import com.agent.display.common.api.AgentDisplayManager

/**
 * 为 [AgentDisplayManager] 扩展原生网络捕获管理器构建入口。
 *
 * @param context Android 上下文环境
 * @return 绑定当前 [AgentDisplayManager.shell] 的 [AgentNetworkManager] 实例
 */
fun AgentDisplayManager.createNetworkManager(context: Context): AgentNetworkManager =
    AgentNetworkManager(context = context, shell = shell)

/**
 * 为现有的 [DisplaySession] 附加或创建 [AgentNetworkManager]。
 *
 * @param context Android 上下文
 * @return 构造并关联好的 [AgentNetworkManager]
 */
fun DisplaySession.attachNetwork(context: Context): AgentNetworkManager =
    networkManager ?: AgentNetworkManager(context = context, shell = null)
