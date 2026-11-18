package com.agent.use.remote

/**
 * 品牌与命名。协议本身不依赖这些值：路径、状态、字段名都是固定的，只有给人看的名字和工具前缀走这里。
 *
 * 工具名前缀是唯一的协议可见项。改动它等于换一套工具名，现成的 CLI / Skill / 连接器都要跟着改，
 * 所以默认保持 `mika`，让既有客户端零成本驱动新接入方。
 */
data class RemoteBrand(
    /** 出现在提示语、工具描述里的产品名。 */
    val appName: String = "Mika",
    /** MCP serverInfo.name 与 serverInfo.title。 */
    val serverName: String = "mika",
    val serverTitle: String = "Mika",
    /** MCP 工具名前缀，生成 `${toolPrefix}_run_task` 这一族。 */
    val toolPrefix: String = "mika",
)
