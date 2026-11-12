package com.agent.display.server.network.ebpf

import android.os.Build
import android.os.Process
import android.util.Log
import java.io.File
import java.util.regex.Pattern

/**
 * eBPF 运行环境与挂载能力探测契约。
 */
interface EbpfCapabilityProvider {
    fun detect(): EbpfCapabilityDetector.EbpfCapabilityResult
}

/**
 * eBPF 抓包能力与运行环境检测器。
 *
 * 检测 Android 设备是否具备执行 Root eBPF TLS 挂载的前提条件：
 * 1. Root 权限检查 (UID 0 或可用 su 提权执行)；
 * 2. Linux 内核版本检查 (从 /proc/version 读取，要求内核主次版本 >= 5.4，以支持 BPF uprobe 与 ring buffer)；
 * 3. eBPF 文件系统检查 (/sys/fs/bpf 挂载点有效性)；
 * 4. Tracefs 挂载点检查 (/sys/kernel/debug/tracing 或 /sys/kernel/tracing)；
 * 5. Conscrypt / BoringSSL 原生库路径探测 (/apex/com.android.conscrypt/lib64/libssl.so 或 /system/lib64/libssl.so)。
 */
object EbpfCapabilityDetector : EbpfCapabilityProvider {

    private const val TAG = "EbpfCapabilityDetector"
    private const val MIN_KERNEL_MAJOR = 5
    private const val MIN_KERNEL_MINOR = 4

    private val KERNEL_VERSION_REGEX = Pattern.compile("Linux version (\\d+)\\.(\\d+)(?:\\.(\\d+))?")

    private val KNOWN_SU_PATHS = arrayOf(
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/data/local/tmp/su",
        "/data/adb/ksu/bin/su",
        "/data/adb/ap/bin/su",
        "/system/xbin/daemonsu"
    )

    private val KNOWN_LIBSSL_64_PATHS = arrayOf(
        "/apex/com.android.conscrypt/lib64/libssl.so",
        "/system/lib64/libssl.so",
        "/apex/com.android.conscrypt/lib64/libcrypto.so",
        "/system/lib64/libcrypto.so"
    )

    private val KNOWN_LIBSSL_32_PATHS = arrayOf(
        "/apex/com.android.conscrypt/lib/libssl.so",
        "/system/lib/libssl.so",
        "/apex/com.android.conscrypt/lib/libcrypto.so",
        "/system/lib/libcrypto.so"
    )

    /**
     * eBPF 环境检测结果契约。
     */
    data class EbpfCapabilityResult(
        val isSupported: Boolean,
        val isRoot: Boolean,
        val kernelVersion: String,
        val kernelMajor: Int,
        val kernelMinor: Int,
        val kernelPatch: Int,
        val isKernelSupported: Boolean,
        val bpfFsMounted: Boolean,
        val traceFsAvailable: Boolean,
        val libSslPath: String?,
        val failureReason: String? = null
    ) {
        val summary: String
            get() = "eBPF Supported=$isSupported (Root=$isRoot, Kernel=$kernelMajor.$kernelMinor.$kernelPatch, " +
                    "BpfFs=$bpfFsMounted, TraceFs=$traceFsAvailable, LibSsl=$libSslPath, Reason=${failureReason ?: "OK"})"
    }

    /**
     * 执行全量 eBPF 运行环境与挂载能力探测。
     */
    override fun detect(): EbpfCapabilityResult {
        val rootStatus = checkRoot()
        val kernelInfo = parseKernelVersion()
        val bpfFsStatus = checkBpfFs()
        val traceFsStatus = checkTraceFs()
        val libSsl = detectLibSslPath()

        val isKernelSupported = (kernelInfo.major > MIN_KERNEL_MAJOR) ||
                (kernelInfo.major == MIN_KERNEL_MAJOR && kernelInfo.minor >= MIN_KERNEL_MINOR)

        val failureReasons = mutableListOf<String>()
        if (!rootStatus) {
            failureReasons.add("Device is not rooted or su binary is inaccessible (UID=${Process.myUid()})")
        }
        if (!isKernelSupported) {
            failureReasons.add("Kernel version ${kernelInfo.raw} is below minimum requirement 5.4")
        }
        if (!bpfFsStatus) {
            failureReasons.add("/sys/fs/bpf is not mounted")
        }
        if (libSsl == null) {
            failureReasons.add("Conscrypt/BoringSSL libssl.so not found in standard apex/system paths")
        }

        val isSupported = rootStatus && isKernelSupported && bpfFsStatus && (libSsl != null)
        val failureReason = if (failureReasons.isNotEmpty()) failureReasons.joinToString("; ") else null

        val result = EbpfCapabilityResult(
            isSupported = isSupported,
            isRoot = rootStatus,
            kernelVersion = kernelInfo.raw,
            kernelMajor = kernelInfo.major,
            kernelMinor = kernelInfo.minor,
            kernelPatch = kernelInfo.patch,
            isKernelSupported = isKernelSupported,
            bpfFsMounted = bpfFsStatus,
            traceFsAvailable = traceFsStatus,
            libSslPath = libSsl,
            failureReason = failureReason
        )

        Log.i(TAG, "Detection completed: ${result.summary}")
        return result
    }

    /**
     * 快速检查当前环境是否支持 eBPF TLS 抓包。
     */
    fun isSupported(): Boolean = detect().isSupported

    /**
     * 检测设备 Root 权限状态。
     */
    fun checkRoot(): Boolean {
        // 1. 若当前服务端守护进程已经直接以 UID 0 (Root) 启动
        if (Process.myUid() == 0) {
            return true
        }

        // 2. 检查常见 su 提权执行路径是否存在
        for (path in KNOWN_SU_PATHS) {
            val file = File(path)
            if (file.exists() && (file.canExecute() || file.length() > 0)) {
                return true
            }
        }

        // 3. 尝试探测 which su
        return try {
            val proc = Runtime.getRuntime().exec(arrayOf("which", "su"))
            proc.waitFor() == 0
        } catch (_: Exception) {
            false
        }
    }

    /**
     * 解析内核主次版本信息。
     */
    data class KernelVersionInfo(
        val raw: String,
        val major: Int,
        val minor: Int,
        val patch: Int
    )

    fun parseKernelVersion(customProcVersion: String? = null): KernelVersionInfo {
        val versionText = customProcVersion ?: readProcVersion()
        val matcher = KERNEL_VERSION_REGEX.matcher(versionText)
        return if (matcher.find()) {
            val major = matcher.group(1)?.toIntOrNull() ?: 0
            val minor = matcher.group(2)?.toIntOrNull() ?: 0
            val patch = matcher.group(3)?.toIntOrNull() ?: 0
            KernelVersionInfo(versionText.trim(), major, minor, patch)
        } else {
            KernelVersionInfo(versionText.trim(), 0, 0, 0)
        }
    }

    private fun readProcVersion(): String {
        return try {
            File("/proc/version").readText()
        } catch (e: Exception) {
            Log.w(TAG, "Failed to read /proc/version: ${e.message}")
            System.getProperty("os.version") ?: "unknown"
        }
    }

    /**
     * 检查 /sys/fs/bpf 挂载点。
     */
    fun checkBpfFs(): Boolean {
        val bpfDir = File("/sys/fs/bpf")
        if (bpfDir.exists() && bpfDir.isDirectory) {
            return true
        }
        return try {
            val mounts = File("/proc/mounts")
            if (mounts.exists()) {
                mounts.useLines { lines ->
                    lines.any { line -> line.contains("/sys/fs/bpf") && line.contains("bpf") }
                }
            } else {
                false
            }
        } catch (_: Exception) {
            false
        }
    }

    /**
     * 检查 Tracefs 挂载点 (/sys/kernel/debug/tracing 或 /sys/kernel/tracing)。
     */
    fun checkTraceFs(): Boolean {
        val traceDirs = arrayOf("/sys/kernel/debug/tracing", "/sys/kernel/tracing")
        return traceDirs.any { path ->
            val dir = File(path)
            dir.exists() && dir.isDirectory
        }
    }

    /**
     * 探测 BoringSSL / Conscrypt 的 libssl.so 绝对路径。
     */
    fun detectLibSslPath(): String? {
        val is64Bit = is64BitAbi()
        val candidatePaths = if (is64Bit) {
            KNOWN_LIBSSL_64_PATHS + KNOWN_LIBSSL_32_PATHS
        } else {
            KNOWN_LIBSSL_32_PATHS + KNOWN_LIBSSL_64_PATHS
        }

        for (path in candidatePaths) {
            val file = File(path)
            if (file.exists() && file.isFile) {
                return path
            }
        }
        return null
    }

    private fun is64BitAbi(): Boolean {
        return try {
            Process.is64Bit()
        } catch (_: Throwable) {
            val supportedAbis = Build.SUPPORTED_ABIS ?: emptyArray()
            supportedAbis.any { it.contains("64") }
        }
    }
}
