package com.agent.use.remote.spi

import kotlinx.serialization.json.JsonObject

/**
 * 设备主屏能力。返回的就是协议里那段 JSON，AAU 不解释字段含义——不同接入方的设备实现能报的东西不一样。
 * 实现方必须自己保证：凭据只在端侧、失败即封、不能绕过系统认证。
 */
interface RemoteDevicePort {
    suspend fun state(): JsonObject

    suspend fun wake(): JsonObject

    suspend fun unlock(): JsonObject
}

/** 只读投影：手机上已保存的对话与运行记录，由机主单独开关。 */
interface RemoteHistoryPort {
    val enabled: Boolean

    fun conversations(offset: Int, limit: Int): JsonObject

    fun turns(conversation: String, offset: Int, limit: Int): JsonObject?

    fun run(conversation: String, runId: String, offset: Int, limit: Int): JsonObject?

    fun body(conversation: String, runId: String, spanId: String, offset: Int, limit: Int): JsonObject?
}

/**
 * 运行记录导出。宿主自己决定记录长什么样、怎么脱敏，AAU 只把渲染好的 json/jsonl 交给电脑。
 * 手机上自行发起的运行不在此列。
 */
interface RemoteExportPort {
    fun scope(owner: String): RemoteExportPort = this

    fun load(id: String): ExportLookup
}

sealed interface ExportLookup {
    /** 没有这个电脑任务，也没有可导出的运行记录。 */
    data object Missing : ExportLookup

    /** 任务还记着运行编号，记录文件已经不在了。 */
    data class Gone(val taskId: String, val runId: String) : ExportLookup

    /** [json] 与 [jsonl] 是同一份数据的两种排布，都已经脱敏。 */
    data class Found(val json: JsonObject, val jsonl: String) : ExportLookup
}
