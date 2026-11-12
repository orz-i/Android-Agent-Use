package com.agent.display.client.network

import android.util.Log
import com.agent.display.common.IAgentShell
import java.io.File
import java.util.regex.Pattern

/**
 * 客户端轻量级 eBPF 与 Root 运行环境探测器。
 *
 * 用于在 [com.agent.display.common.network.CaptureMode.AUTO] 模式下快速裁决设备是否具备
 * 进入 Root eBPF 捕获的前提条件（需具备 Root 权限且 Linux 内核版本 >= 5.4）。
 */
object DeviceEbpfDetector {
    private const val TAG = "DeviceEbpfDetector"

    const val MIN_KERNEL_MAJOR = 5
    const val MIN_KERNEL_MINOR = 4

    private val KERNEL_REGEX = Pattern.compile("(?:Linux version |^)(\\d+)\\.(\\d+)(?:\\.(\\d+))?")

    private val KNOWN_SU_PATHS = arrayOf(
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/data/local/tmp/su",
        "/data/adb/ksu/bin/su",
        "/data/adb/ap/bin/su",
        "/system/sd/xbin/su",
        "/data/local/xbin/su",
        "/data/local/bin/su",
        "/data/local/su"
    )

    /**
     * 判断当前环境是否支持 eBPF (Root 权限且内核 >= 5.4)。
     */
    fun isSupported(shell: IAgentShell? = null): Boolean {
        val rootOk = isDeviceRooted(shell)
        val kernelOk = isKernelSupported()
        Log.d(TAG, "DeviceEbpfDetector.isSupported: rootOk=$rootOk, kernelOk=$kernelOk")
        return rootOk && kernelOk
    }

    /**
     * 判断设备是否拥有 Root 权限。
     *
     * 判定优先级：
     * 1. 若已有 shell 连接，直接校验服务端守护进程的 UID 是否为 0 (Root)；
     * 2. 检查常见 su 二进制可执行路径；
     * 3. 尝试通过 which su 探测。
     */
    fun isDeviceRooted(shell: IAgentShell? = null): Boolean {
        // 1. 若已有 shell 连接，检查其 UID 是否为 0
        if (shell != null) {
            try {
                val id = shell.identity()
                if (id.isNotEmpty() && id[0] == 0) {
                    return true
                }
            } catch (e: Exception) {
                Log.w(TAG, "shell.identity() check failed: ${e.message}")
            }
        }

        // 2. 检查常见 su 路径
        for (path in KNOWN_SU_PATHS) {
            if (File(path).exists()) {
                return true
            }
        }

        // 3. 尝试 which su 探测
        return try {
            val process = ProcessBuilder("which", "su").start()
            process.waitFor() == 0
        } catch (_: Exception) {
            false
        }
    }

    /**
     * 检查 Linux 内核版本是否 >= 5.4。
     */
    fun isKernelSupported(): Boolean {
        val versionStr = readKernelVersion()
        return isKernelVersionSupported(versionStr)
    }

    /**
     * 解析给定版本字符串并判断是否满足内核主次版本 >= 5.4。
     */
    fun isKernelVersionSupported(versionStr: String): Boolean {
        val match = KERNEL_REGEX.matcher(versionStr)
        if (match.find()) {
            val major = match.group(1)?.toIntOrNull() ?: 0
            val minor = match.group(2)?.toIntOrNull() ?: 0
            return (major > MIN_KERNEL_MAJOR) || (major == MIN_KERNEL_MAJOR && minor >= MIN_KERNEL_MINOR)
        }
        return false
    }

    /**
     * 读取内核版本字符串（优先 /proc/version，兜底使用系统属性 os.version）。
     */
    fun readKernelVersion(): String {
        return try {
            File("/proc/version").readText().trim()
        } catch (_: Exception) {
            System.getProperty("os.version") ?: ""
        }
    }
}
