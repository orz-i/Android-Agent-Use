package com.agent.use.client.network

import com.agent.use.common.IAgentShell
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.lang.reflect.Proxy

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

    @Test
    fun testActualRootVerificationIndependentOfShellUidAndManagerPaths() {
        val shellUid2000 = Proxy.newProxyInstance(
            IAgentShell::class.java.classLoader,
            arrayOf(IAgentShell::class.java)
        ) { _, method, _ ->
            if (method.name == "identity") intArrayOf(2000, 2000) else null
        } as IAgentShell

        val shellUid0 = Proxy.newProxyInstance(
            IAgentShell::class.java.classLoader,
            arrayOf(IAgentShell::class.java)
        ) { _, method, _ ->
            if (method.name == "identity") intArrayOf(0, 0) else null
        } as IAgentShell

        // 1. Shell running as UID 0 immediately satisfies root
        assertTrue(DeviceEbpfDetector.isDeviceRooted(shellUid0, { false }))

        // 2. Shell running as UID 2000, but app itself has working `su -c id` -> true
        assertTrue(DeviceEbpfDetector.isDeviceRooted(shellUid2000, { candidate -> candidate == "su" }))

        // 3. No su grants uid=0 -> false
        assertFalse(DeviceEbpfDetector.isDeviceRooted(shellUid2000, { false }))
    }
}
