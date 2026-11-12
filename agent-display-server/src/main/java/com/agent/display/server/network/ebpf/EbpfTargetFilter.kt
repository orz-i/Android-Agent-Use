package com.agent.display.server.network.ebpf

import android.content.Context
import android.util.Log
import java.io.File
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.atomic.AtomicInteger

/**
 * eBPF 目标应用 UID 内核级与用户级严格过滤控制器。
 *
 * 核心安全与隔离设计原则：
 * 1. 严格过滤目标 UID：在 Linux 内核态 (eBPF Map) 和用户态事件分发层双重校验 targetUid；
 * 2. 绝对零干扰：非目标应用（例如用户的微信、支付宝、电话、系统服务等）流量在内核挂载点直接返回 0，
 *    完全绕过数据拷贝、环形缓冲区 (ring buffer) 投递与用户态解析，保证宿主应用零卡顿、零隐私泄露；
 * 3. 动态 UID 决议：支持根据包名从 PackageManager 或 /data/system/packages.xml 自动决议 Android UID。
 */
class EbpfTargetFilter(
    private val context: Context? = null
) {
    companion object {
        private const val TAG = "EbpfTargetFilter"
        const val BPF_TARGET_UID_MAP_PATH = "/sys/fs/bpf/aau_target_uid_map"
        const val UID_UNSET = -1
    }

    private val activeTargetUid = AtomicInteger(UID_UNSET)
    private var activeTargetPackage: String? = null

    /**
     * 配置当前抓包目标应用的 Package 与 UID。
     *
     * @param packageName 目标包名
     * @param uid 目标 UID，若 <= 0 则自动解析
     * @return 最终生效的目标 UID
     */
    fun configureTarget(packageName: String, uid: Int = UID_UNSET): Int {
        activeTargetPackage = packageName
        val resolvedUid = if (uid > 0) uid else resolveUidFromPackage(packageName)
        activeTargetUid.set(resolvedUid)

        Log.i(TAG, "Configured target: package=$packageName, targetUid=$resolvedUid")
        syncToKernelBpfMap(resolvedUid)
        return resolvedUid
    }

    /**
     * 清理目标过滤规则，重置为 UID_UNSET，禁止任何流量采集。
     */
    fun clearTarget() {
        Log.i(TAG, "Clearing target filter (targetUid=$UID_UNSET)")
        activeTargetUid.set(UID_UNSET)
        activeTargetPackage = null
        syncToKernelBpfMap(UID_UNSET)
    }

    /**
     * 获取当前生效的 targetUid。
     */
    val currentTargetUid: Int
        get() = activeTargetUid.get()

    /**
     * 获取当前生效的 targetPackage。
     */
    val currentTargetPackage: String?
        get() = activeTargetPackage

    /**
     * 用户态双重校验 (Defense-in-depth)：
     * 校验捕获到的原始数据事件的 UID 是否与目标 UID 严格匹配。
     *
     * @param eventUid 来源进程 UID
     * @return true 表示允许放行，false 表示必须无条件丢弃
     */
    fun shouldCapture(eventUid: Int): Boolean {
        val target = activeTargetUid.get()
        if (target <= 0) {
            // 未设定有效目标 UID 时，默认丢弃所有流量以确保安全
            return false
        }
        return eventUid == target
    }

    /**
     * 同步当前 targetUid 至内核态 eBPF Array/Hash Map 文件系统节点。
     *
     * 在 Linux/Android GKI 中，固定到 /sys/fs/bpf/aau_target_uid_map 的 BPF Map
     * 存储了内核挂载点读取的目标 UID。
     */
    fun syncToKernelBpfMap(targetUid: Int): Boolean {
        val mapFile = File(BPF_TARGET_UID_MAP_PATH)
        if (!mapFile.exists()) {
            Log.d(TAG, "BPF map node $BPF_TARGET_UID_MAP_PATH does not exist yet (map not pinned).")
            return false
        }

        return try {
            val buffer = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
            buffer.putInt(0) // key: 0
            buffer.putInt(if (targetUid > 0) targetUid else 0) // value: targetUid

            FileOutputStream(mapFile).use { out ->
                out.write(buffer.array())
                out.flush()
            }
            Log.d(TAG, "Successfully synced targetUid=$targetUid to $BPF_TARGET_UID_MAP_PATH")
            true
        } catch (e: Exception) {
            Log.w(TAG, "Failed to write targetUid to BPF map: ${e.message}")
            false
        }
    }

    /**
     * 从系统 PackageManager 或 /data/system/packages.xml 动态解析应用包名的 UID。
     */
    fun resolveUidFromPackage(packageName: String): Int {
        // 1. 尝试直接从 Context.packageManager 获取
        if (context != null) {
            try {
                val packageInfo = context.packageManager.getPackageInfo(packageName, 0)
                val uid = packageInfo.applicationInfo?.uid ?: -1
                if (uid > 0) return uid
            } catch (_: Exception) {
                // 忽略，回退到后续手段
            }
        }

        // 2. 尝试从 /data/system/packages.xml 中检索 (Root/Shell 守护进程具备读取权限)
        try {
            val packagesXml = File("/data/system/packages.xml")
            if (packagesXml.exists() && packagesXml.canRead()) {
                val pattern = Regex("""<package\s+name="$packageName"[^>]*userId="(\d+)"""")
                packagesXml.useLines { lines ->
                    for (line in lines) {
                        val match = pattern.find(line)
                        if (match != null) {
                            val uid = match.groupValues[1].toIntOrNull() ?: -1
                            if (uid > 0) return uid
                        }
                    }
                }
            }
        } catch (e: Exception) {
            Log.d(TAG, "packages.xml lookup failed: ${e.message}")
        }

        // 3. 尝试通过 pm list packages -U 命令行解析
        try {
            val proc = Runtime.getRuntime().exec(arrayOf("pm", "list", "packages", "-U", packageName))
            proc.inputStream.bufferedReader().useLines { lines ->
                for (line in lines) {
                    // 格式如: package:com.example.app uid:10123
                    if (line.startsWith("package:$packageName ") || line == "package:$packageName") {
                        val uidIndex = line.indexOf("uid:")
                        if (uidIndex != -1) {
                            val uidStr = line.substring(uidIndex + 4).trim().takeWhile { it.isDigit() }
                            val uid = uidStr.toIntOrNull() ?: -1
                            if (uid > 0) return uid
                        }
                    }
                }
            }
        } catch (e: Exception) {
            Log.d(TAG, "pm list command lookup failed: ${e.message}")
        }

        Log.w(TAG, "Unable to resolve UID for package: $packageName")
        return UID_UNSET
    }
}
