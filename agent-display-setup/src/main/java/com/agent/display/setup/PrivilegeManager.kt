package com.agent.display.setup

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Process
import android.provider.Settings
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

/**
 * 设备特权状态统一管理器。
 *
 * 检测并按优先级（Shizuku > 无线调试 > Root > USB 引导）识别当前设备可用的特权拉起途径。
 */
class PrivilegeManager(private val context: Context) {

    enum class PrivilegeType {
        SHIZUKU,
        WIRELESS_ADB,
        ROOT,
        NONE
    }

    data class PrivilegeStatus(
        val type: PrivilegeType,
        val isReady: Boolean,
        val details: String,
        val suggestedAction: String? = null
    )

    /**
     * 异步检测当前环境最高可用特权
     */
    suspend fun detectPrivilege(): PrivilegeStatus = withContext(Dispatchers.IO) {
        // 1. 检测 Shizuku / Sui 授权
        val shizuku = checkShizuku()
        if (shizuku.isReady) return@withContext shizuku

        // 2. 检测本地无线调试
        val wireless = checkWirelessAdb()
        if (wireless.isReady) return@withContext wireless

        // 3. 检测 Root 权限 (su 2000)
        val root = checkRoot()
        if (root.isReady) return@withContext root

        // 4. 未激活：返回最优降级建议
        when {
            shizuku.type == PrivilegeType.SHIZUKU -> shizuku
            wireless.type == PrivilegeType.WIRELESS_ADB -> wireless
            root.type == PrivilegeType.ROOT -> root
            else -> PrivilegeStatus(
                type = PrivilegeType.NONE,
                isReady = false,
                details = "未检测到可用特权环境，需要 Shizuku、无线调试、Root 或电脑 USB 激活",
                suggestedAction = "推荐安装并启动 Shizuku 或开启系统开发者选项中的无线调试"
            )
        }
    }

    /** 检查 Shizuku 运行状态与权限 */
    fun checkShizuku(): PrivilegeStatus {
        return try {
            val shizukuClass = Class.forName("moe.shizuku.api.Shizuku")
            val pingBinder = shizukuClass.getMethod("pingBinder").invoke(null) as Boolean
            if (!pingBinder) {
                return PrivilegeStatus(
                    type = PrivilegeType.SHIZUKU,
                    isReady = false,
                    details = "Shizuku 服务未运行",
                    suggestedAction = "请打开 Shizuku 应用并启动服务"
                )
            }

            val checkPermission = shizukuClass.getMethod("checkSelfPermission").invoke(null) as Int
            if (checkPermission == PackageManager.PERMISSION_GRANTED) {
                PrivilegeStatus(
                    type = PrivilegeType.SHIZUKU,
                    isReady = true,
                    details = "Shizuku 已运行并授权 (UID 2000)",
                    suggestedAction = "可直接通过 Shizuku 一键秒级拉起服务端"
                )
            } else {
                PrivilegeStatus(
                    type = PrivilegeType.SHIZUKU,
                    isReady = false,
                    details = "Shizuku 服务正在运行但当前应用尚未授权",
                    suggestedAction = "请在 Shizuku 授权弹窗中允许当前应用访问"
                )
            }
        } catch (_: ClassNotFoundException) {
            // 未引入 Shizuku 依赖或未安装
            PrivilegeStatus(
                type = PrivilegeType.SHIZUKU,
                isReady = false,
                details = "未检测到 Shizuku API 环境"
            )
        } catch (t: Throwable) {
            PrivilegeStatus(
                type = PrivilegeType.SHIZUKU,
                isReady = false,
                details = "检测 Shizuku 异常: ${t.message}"
            )
        }
    }

    /** 检查本机无线调试状态 */
    fun checkWirelessAdb(): PrivilegeStatus {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
            return PrivilegeStatus(
                type = PrivilegeType.WIRELESS_ADB,
                isReady = false,
                details = "当前 Android 版本低于 Android 11，不支持原生无线调试配对"
            )
        }

        val enabled = runCatching {
            Settings.Global.getInt(context.contentResolver, "adb_wifi_enabled", 0) == 1
        }.getOrDefault(false)

        return if (enabled) {
            PrivilegeStatus(
                type = PrivilegeType.WIRELESS_ADB,
                isReady = true,
                details = "系统无线调试总开关已开启",
                suggestedAction = "可通过 mDNS 自动发现本地无线调试端口并连接"
            )
        } else {
            PrivilegeStatus(
                type = PrivilegeType.WIRELESS_ADB,
                isReady = false,
                details = "无线调试处于关闭状态",
                suggestedAction = "请在开发者选项中开启「无线调试」并连接同一 Wi-Fi"
            )
        }
    }

    /** 检查 Root 权限与 su 2000 执行能力 */
    fun checkRoot(): PrivilegeStatus {
        val suPaths = arrayOf(
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/data/local/su"
        )
        val hasSuBinary = suPaths.any { File(it).exists() } || runCatching {
            ProcessBuilder("which", "su").start().waitFor() == 0
        }.getOrDefault(false)

        if (!hasSuBinary) {
            return PrivilegeStatus(
                type = PrivilegeType.ROOT,
                isReady = false,
                details = "设备未发现 su 二进制文件 (未 Root)"
            )
        }

        // 测试 su 2000 -c id -u
        val canSwitchToShell = runCatching {
            val p = ProcessBuilder("su", "2000", "-c", "id -u").redirectErrorStream(true).start()
            val out = p.inputStream.bufferedReader().readText().trim()
            p.waitFor() == 0 && out == "2000"
        }.getOrDefault(false)

        return if (canSwitchToShell) {
            PrivilegeStatus(
                type = PrivilegeType.ROOT,
                isReady = true,
                details = "设备已 Root，支持通过 su 2000 以 Shell 身份启动",
                suggestedAction = "可通过 Root 静默拉起守护进程"
            )
        } else {
            PrivilegeStatus(
                type = PrivilegeType.ROOT,
                isReady = false,
                details = "设备存在 su，但无法切换到 Shell (UID 2000) 运行环境",
                suggestedAction = "请在 Root 授权管理工具（如 Magisk/KernelSU/APatch）中授予本应用 Root 权限"
            )
        }
    }
}
