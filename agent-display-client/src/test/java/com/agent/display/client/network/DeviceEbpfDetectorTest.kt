package com.agent.display.client.network

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DeviceEbpfDetectorTest {

    @Test
    fun testKernelVersionParsing() {
        // >= 5.4 GKI 内核应判定为支持
        assertTrue(DeviceEbpfDetector.isKernelVersionSupported("Linux version 5.4.0-android12-9-gki (android-build)"))
        assertTrue(DeviceEbpfDetector.isKernelVersionSupported("Linux version 5.10.136-android13-4-gki"))
        assertTrue(DeviceEbpfDetector.isKernelVersionSupported("Linux version 5.15.78-gki"))
        assertTrue(DeviceEbpfDetector.isKernelVersionSupported("Linux version 6.1.25-android14-gki"))
        assertTrue(DeviceEbpfDetector.isKernelVersionSupported("5.4.0"))
        assertTrue(DeviceEbpfDetector.isKernelVersionSupported("5.10"))
        assertTrue(DeviceEbpfDetector.isKernelVersionSupported("6.6.0-perf"))

        // < 5.4 旧内核应判定为不支持
        assertFalse(DeviceEbpfDetector.isKernelVersionSupported("Linux version 4.19.157-perf+ (android-build)"))
        assertFalse(DeviceEbpfDetector.isKernelVersionSupported("Linux version 4.14.180-perf"))
        assertFalse(DeviceEbpfDetector.isKernelVersionSupported("Linux version 4.9.227"))
        assertFalse(DeviceEbpfDetector.isKernelVersionSupported("Linux version 3.18.140"))
        assertFalse(DeviceEbpfDetector.isKernelVersionSupported("Linux version 5.3.18"))
        assertFalse(DeviceEbpfDetector.isKernelVersionSupported("5.3.9"))
        assertFalse(DeviceEbpfDetector.isKernelVersionSupported("invalid-kernel-string"))
        assertFalse(DeviceEbpfDetector.isKernelVersionSupported(""))
    }
}
