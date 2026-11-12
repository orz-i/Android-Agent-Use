package com.agent.display.server.network.ebpf

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class EbpfCapabilityDetectorTest {

    @Test
    fun testKernelVersionParsing_5_10() {
        val versionStr = "Linux version 5.10.101-android12-9-g8a3fc42 (build-user@build-host) #1 SMP PREEMPT Wed Jan 12 12:00:00 UTC 2022"
        val info = EbpfCapabilityDetector.parseKernelVersion(versionStr)

        assertEquals(5, info.major)
        assertEquals(10, info.minor)
        assertEquals(101, info.patch)

        val isSupported = (info.major > 5) || (info.major == 5 && info.minor >= 4)
        assertTrue("Kernel 5.10 should be supported", isSupported)
    }

    @Test
    fun testKernelVersionParsing_6_1() {
        val versionStr = "Linux version 6.1.25-android14-11-g1234567 #1 SMP PREEMPT 2023"
        val info = EbpfCapabilityDetector.parseKernelVersion(versionStr)

        assertEquals(6, info.major)
        assertEquals(1, info.minor)
        assertEquals(25, info.patch)

        val isSupported = (info.major > 5) || (info.major == 5 && info.minor >= 4)
        assertTrue("Kernel 6.1 should be supported", isSupported)
    }

    @Test
    fun testKernelVersionParsing_5_4_minimum() {
        val versionStr = "Linux version 5.4.0-android11 #1 SMP 2020"
        val info = EbpfCapabilityDetector.parseKernelVersion(versionStr)

        assertEquals(5, info.major)
        assertEquals(4, info.minor)
        assertEquals(0, info.patch)

        val isSupported = (info.major > 5) || (info.major == 5 && info.minor >= 4)
        assertTrue("Kernel 5.4 should be supported as baseline", isSupported)
    }

    @Test
    fun testKernelVersionParsing_4_19_unsupported() {
        val versionStr = "Linux version 4.19.113-perf+ #1 SMP PREEMPT 2019"
        val info = EbpfCapabilityDetector.parseKernelVersion(versionStr)

        assertEquals(4, info.major)
        assertEquals(19, info.minor)
        assertEquals(113, info.patch)

        val isSupported = (info.major > 5) || (info.major == 5 && info.minor >= 4)
        assertFalse("Kernel 4.19 must NOT be supported for modern eBPF uprobes", isSupported)
    }

    @Test
    fun testKernelVersionParsing_5_2_unsupported() {
        val versionStr = "Linux version 5.2.14 #1 SMP 2019"
        val info = EbpfCapabilityDetector.parseKernelVersion(versionStr)

        val isSupported = (info.major > 5) || (info.major == 5 && info.minor >= 4)
        assertFalse("Kernel 5.2 is below 5.4 and should not be supported", isSupported)
    }
}
