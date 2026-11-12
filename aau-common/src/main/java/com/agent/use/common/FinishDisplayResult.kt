package com.agent.use.common

import android.os.Bundle

/**
 * 虚拟屏销毁与任务收尾结果契约。
 *
 * 封装 finishDisplay 调用后的结构化返回值，
 * 明确区分哪些应用已被成功迁移沉底保活、哪些应用已被关闭及其具体原因。
 */
data class FinishDisplayResult(
    /** 成功迁移并沉入主屏任务栈底部的应用包名列表 */
    val keptPackages: List<String>,

    /**
     * 随屏关闭或主动清理的应用列表，映射：包名 -> 关闭原因
     * 例如："com.foo.app" -> "loud" (正在发声), "closed_by_request" (主动要求关闭)
     */
    val closedPackagesWithReasons: Map<String, String>,

    /** 降级或特殊备注信息（如部分 ROM 不支持隐藏沉底、落定超时等） */
    val note: String? = null,
) {
    companion object {
        const val KEY_KEPT = "kept"
        const val KEY_CLOSED = "closed"
        const val KEY_NOTE = "note"

        @JvmStatic
        fun fromBundle(bundle: Bundle?): FinishDisplayResult {
            if (bundle == null) return FinishDisplayResult(emptyList(), emptyMap(), null)
            val kept = bundle.getStringArray(KEY_KEPT)?.toList().orEmpty()
            val closedRaw = bundle.getStringArray(KEY_CLOSED)?.toList().orEmpty()
            val closedMap = closedRaw.associate { entry ->
                val parts = entry.split(":", limit = 2)
                if (parts.size == 2) parts[0].trim() to parts[1].trim()
                else entry to "unknown"
            }
            val note = bundle.getString(KEY_NOTE)
            return FinishDisplayResult(kept, closedMap, note)
        }
    }
}
