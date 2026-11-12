package com.agent.use.client.network

import android.content.Context
import com.agent.use.client.DisplaySession
import com.agent.use.common.api.AAUManager

/**
 * 为 [AAUManager] 扩展原生网络捕获管理器构建入口。
 *
 * @param context Android 上下文环境
 * @return 绑定当前 [AAUManager.shell] 的 [AgentNetworkManager] 实例
 */
fun AAUManager.createNetworkManager(context: Context): AgentNetworkManager =
    AgentNetworkManager(context = context, shell = shell)

/**
 * 为现有的 [DisplaySession] 附加或创建 [AgentNetworkManager]。
 *
 * @param context Android 上下文
 * @return 构造并关联好的 [AgentNetworkManager]
 */
fun DisplaySession.attachNetwork(context: Context): AgentNetworkManager =
    networkManager ?: AgentNetworkManager(context = context, shell = null)
