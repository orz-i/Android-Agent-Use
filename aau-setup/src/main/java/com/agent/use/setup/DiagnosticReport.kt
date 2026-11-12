package com.agent.use.setup

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * 诊断检测单项状态。
 */
enum class DiagnosticStatus {
    /** 检查完全通过 */
    PASS,
    /** 部分满足或触发降级策略 (不阻断基础功能) */
    PARTIAL,
    /** 致命错误或关键能力缺失 */
    FAIL;

    val icon: String
        get() = when (this) {
            PASS -> "✅"
            PARTIAL -> "⚠️"
            FAIL -> "❌"
        }
}

/**
 * 诊断检测单项结果。
 */
data class CheckItem(
    val key: String,
    val title: String,
    val status: DiagnosticStatus,
    val detail: String,
    val latencyMs: Long? = null,
    val isWarningOnly: Boolean = false,
    val advice: String? = null,
) {
    val passed: Boolean get() = status == DiagnosticStatus.PASS
}

/**
 * 不可变整机与运行环境诊断报告模型。
 *
 * 覆盖静态系统参数、SELinux、特权通信链路、虚拟屏创建/首帧渲染闭环、
 * IME与全屏策略、AppOps静音闭环及大白话建议。支持脱敏与一键导出 Markdown / JSON。
 */
data class DiagnosticReport(
    val timestamp: Long = System.currentTimeMillis(),
    val manufacturer: String,
    val model: String,
    val androidRelease: String,
    val sdk: Int,
    val screenResolution: String,
    val selinuxMode: String,
    val isShellConnected: Boolean,
    val shellUid: Int? = null,
    val shellPid: Int? = null,
    val staticItems: List<CheckItem>,
    val dynamicItems: List<CheckItem>,
    val overallStatus: DiagnosticStatus,
    val summary: String,
    val advices: List<String>,
) {
    val allItems: List<CheckItem>
        get() = staticItems + dynamicItems

    /**
     * 生成脱敏报告，消除具体硬件序列号或特定设备识别信息。
     */
    fun desensitize(): DiagnosticReport {
        val maskedModel = if (model.length > 4) model.substring(0, 3) + "***" else model
        return copy(
            model = maskedModel,
            advices = advices.map { it.replace(model, maskedModel) }
        )
    }

    /**
     * 导出为格式优雅的 Markdown 诊断报告。
     */
    fun toMarkdown(): String = buildString {
        val dateFormat = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault())
        appendLine("# AAU (Android Agent Use) 环境与运行时诊断报告")
        appendLine()
        appendLine("> 生成时间: ${dateFormat.format(Date(timestamp))}")
        appendLine()
        appendLine("## 1. 设备与环境概况")
        appendLine("- **设备**: $manufacturer $model (Android $androidRelease, API $sdk)")
        appendLine("- **主屏分辨率**: $screenResolution")
        appendLine("- **SELinux 模式**: $selinuxMode")
        appendLine("- **Shell 特权连接**: ${if (isShellConnected) "已连接 (UID $shellUid, PID $shellPid)" else "未连接"}")
        appendLine("- **总体评估状态**: ${overallStatus.icon} **$overallStatus**")
        appendLine()
        appendLine("## 2. 静态环境与兼容性检查")
        appendLine("| 项目 | 状态 | 耗时 | 详细说明 | 处置建议 |")
        appendLine("| :--- | :---: | :---: | :--- | :--- |")
        for (item in staticItems) {
            val latency = item.latencyMs?.let { "${it}ms" } ?: "-"
            val adv = item.advice ?: "-"
            appendLine("| ${item.title} | ${item.status.icon} | $latency | ${item.detail} | $adv |")
        }
        appendLine()
        if (dynamicItems.isNotEmpty()) {
            appendLine("## 3. 动态端到端闭环探测")
            appendLine("| 项目 | 状态 | 耗时 | 详细说明 | 处置建议 |")
            appendLine("| :--- | :---: | :---: | :--- | :--- |")
            for (item in dynamicItems) {
                val latency = item.latencyMs?.let { "${it}ms" } ?: "-"
                val adv = item.advice ?: "-"
                appendLine("| ${item.title} | ${item.status.icon} | $latency | ${item.detail} | $adv |")
            }
            appendLine()
        }
        appendLine("## 4. 结论与专家建议")
        appendLine("**总体结论**: $summary")
        appendLine()
        if (advices.isNotEmpty()) {
            appendLine("### 操作建议:")
            for ((idx, adv) in advices.withIndex()) {
                appendLine("${idx + 1}. $adv")
            }
        }
    }

    /**
     * 导出为轻量 JSON 字符串。
     */
    fun toJson(): String = buildString {
        append("{")
        append("\"timestamp\":$timestamp,")
        append("\"manufacturer\":\"${escape(manufacturer)}\",")
        append("\"model\":\"${escape(model)}\",")
        append("\"androidRelease\":\"${escape(androidRelease)}\",")
        append("\"sdk\":$sdk,")
        append("\"screenResolution\":\"${escape(screenResolution)}\",")
        append("\"selinuxMode\":\"${escape(selinuxMode)}\",")
        append("\"isShellConnected\":$isShellConnected,")
        append("\"shellUid\":${shellUid ?: "null"},")
        append("\"shellPid\":${shellPid ?: "null"},")
        append("\"overallStatus\":\"$overallStatus\",")
        append("\"summary\":\"${escape(summary)}\",")
        append("\"items\":[")
        val all = allItems
        for ((index, item) in all.withIndex()) {
            append("{")
            append("\"key\":\"${escape(item.key)}\",")
            append("\"title\":\"${escape(item.title)}\",")
            append("\"status\":\"${item.status}\",")
            append("\"detail\":\"${escape(item.detail)}\",")
            append("\"latencyMs\":${item.latencyMs ?: "null"},")
            append("\"isWarningOnly\":${item.isWarningOnly},")
            append("\"advice\":${item.advice?.let { "\"${escape(it)}\"" } ?: "null"}")
            append("}")
            if (index < all.size - 1) append(",")
        }
        append("],")
        append("\"advices\":[")
        for ((index, adv) in advices.withIndex()) {
            append("\"${escape(adv)}\"")
            if (index < advices.size - 1) append(",")
        }
        append("]")
        append("}")
    }

    private fun escape(text: String): String =
        text.replace("\\", "\\\\")
            .replace("\"", "\\\"")
            .replace("\b", "\\b")
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\t", "\\t")
}
