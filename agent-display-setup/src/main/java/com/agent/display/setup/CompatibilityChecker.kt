package com.agent.display.setup

import android.content.Context
import com.agent.display.common.IAgentShell
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * 虚拟屏运行环境兼容性自检门面。
 *
 * 保持向后兼容性，内部委托给功能完备的 [AgentDisplayDiagnosticSuite] 进行静态与动态综合检测。
 */
class CompatibilityChecker(
    private val context: Context,
    private val shell: IAgentShell? = null,
) {
    private val suite = AgentDisplayDiagnosticSuite(context, shell)

    data class CheckItem(
        val key: String,
        val title: String,
        val passed: Boolean,
        val detail: String,
        val isWarningOnly: Boolean = false,
        val advice: String? = null,
    )

    data class CompatibilityReport(
        val manufacturer: String,
        val model: String,
        val androidRelease: String,
        val sdk: Int,
        val screenResolution: String,
        val items: List<CheckItem>,
        val overallPassed: Boolean,
        val summary: String,
        val rawDiagnosticReport: DiagnosticReport? = null,
    ) {
        fun formatText(): String = buildString {
            appendLine("=== AgentDisplayKit 兼容性自检报告 ===")
            appendLine("设备: $manufacturer $model (Android $androidRelease, SDK $sdk)")
            appendLine("主屏分辨率: $screenResolution")
            appendLine("总体状态: ${if (overallPassed) "✅ 完全兼容" else "⚠️ 具备降级运行能力"}")
            appendLine("--------------------------------------")
            for (item in items) {
                val icon = if (item.passed) "✅" else if (item.isWarningOnly) "⚠️" else "❌"
                appendLine("$icon ${item.title}: ${item.detail}")
            }
            appendLine("--------------------------------------")
            appendLine("结论: $summary")
        }

        fun toMarkdown(): String = rawDiagnosticReport?.toMarkdown() ?: formatText()
        fun toJson(): String = rawDiagnosticReport?.toJson() ?: "{}"
    }

    /**
     * 运行标准兼容性检查（兼容旧接口）。
     */
    suspend fun runCheck(): CompatibilityReport = withContext(Dispatchers.IO) {
        val report = suite.runFullDiagnostics(shell)

        val compatItems = report.allItems.map { item ->
            CheckItem(
                key = item.key,
                title = item.title,
                passed = item.status == DiagnosticStatus.PASS,
                detail = item.detail,
                isWarningOnly = item.isWarningOnly || item.status == DiagnosticStatus.PARTIAL,
                advice = item.advice
            )
        }

        CompatibilityReport(
            manufacturer = report.manufacturer,
            model = report.model,
            androidRelease = report.androidRelease,
            sdk = report.sdk,
            screenResolution = report.screenResolution,
            items = compatItems,
            overallPassed = report.overallStatus != DiagnosticStatus.FAIL,
            summary = report.summary,
            rawDiagnosticReport = report
        )
    }

    /**
     * 运行包含动态 Shell 通道测试的深度诊断。
     */
    suspend fun runFullDiagnostics(targetShell: IAgentShell? = shell): DiagnosticReport =
        suite.runFullDiagnostics(targetShell)
}
