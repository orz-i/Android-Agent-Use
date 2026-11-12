package com.agent.display.setup

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DiagnosticReportUnitTest {

    @Test
    fun testDiagnosticReportDataModelAndExport() {
        val staticChecks = listOf(
            CheckItem(
                key = "sdk_version",
                title = "Android SDK 门槛",
                status = DiagnosticStatus.PASS,
                detail = "API 35 (Android 15)",
                advice = null
            )
        )
        val dynamicChecks = listOf(
            CheckItem(
                key = "shell_ipc",
                title = "Shell 特权通道",
                status = DiagnosticStatus.PASS,
                detail = "UID=2000",
                latencyMs = 12L
            )
        )

        val report = DiagnosticReport(
            manufacturer = "Google",
            model = "Pixel 8",
            androidRelease = "15",
            sdk = 35,
            screenResolution = "1080x2400",
            selinuxMode = "Enforcing",
            isShellConnected = true,
            shellUid = 2000,
            shellPid = 12345,
            staticItems = staticChecks,
            dynamicItems = dynamicChecks,
            overallStatus = DiagnosticStatus.PASS,
            summary = "系统环境完美适配",
            advices = emptyList()
        )

        assertEquals(DiagnosticStatus.PASS, report.overallStatus)
        assertEquals(2, report.allItems.size)

        // 验证 Markdown 格式输出
        val md = report.toMarkdown()
        assertTrue(md.contains("AgentDisplayKit 环境与运行时诊断报告"))
        assertTrue(md.contains("Pixel 8"))
        assertTrue(md.contains("Enforcing"))

        // 验证 JSON 格式输出与字段完备性
        val json = report.toJson()
        assertTrue(json.contains("\"overallStatus\":\"PASS\""))
        assertTrue(json.contains("\"manufacturer\":\"Google\""))

        // 验证脱敏输出
        val desensitized = report.desensitize()
        val desensitizedJson = desensitized.toJson()
        assertTrue(desensitizedJson.contains("***"))
    }
}
