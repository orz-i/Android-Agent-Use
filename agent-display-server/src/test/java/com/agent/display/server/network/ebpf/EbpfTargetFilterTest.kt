package com.agent.display.server.network.ebpf

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class EbpfTargetFilterTest {

    @Test
    fun testTargetUidStrictFilter() {
        val filter = EbpfTargetFilter()
        assertEquals(EbpfTargetFilter.UID_UNSET, filter.currentTargetUid)

        // 未配置前，拒绝所有 UID 流量以保证安全
        assertFalse(filter.shouldCapture(10145))
        assertFalse(filter.shouldCapture(10123))

        // 配置目标应用 UID (假设 10145)
        val targetUid = 10145
        filter.configureTarget("com.example.targetapp", targetUid)
        assertEquals(targetUid, filter.currentTargetUid)
        assertEquals("com.example.targetapp", filter.currentTargetPackage)

        // 1. 目标应用流量必须允许放行
        assertTrue("Target app UID must pass filter", filter.shouldCapture(10145))

        // 2. 宿主其它应用 (如微信 UID 10123) 必须被完全丢弃
        assertFalse("WeChat UID 10123 must be completely bypassed", filter.shouldCapture(10123))

        // 3. 系统进程 (UID 1000) 必须被完全丢弃
        assertFalse("System UID 1000 must be completely bypassed", filter.shouldCapture(1000))

        // 4. Root 自身进程 (UID 0) 亦被丢弃
        assertFalse("Root UID 0 must be bypassed", filter.shouldCapture(0))

        // 清理规则后，拒绝所有放行
        filter.clearTarget()
        assertEquals(EbpfTargetFilter.UID_UNSET, filter.currentTargetUid)
        assertFalse(filter.shouldCapture(10145))
    }
}
