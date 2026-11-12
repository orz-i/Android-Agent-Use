package com.agent.display.common.network

import android.os.Parcelable
import kotlinx.parcelize.Parcelize

/**
 * 原生网络捕获配置契约。
 *
 * 封装抓包目标、捕获模式、体量上限及 URL 过滤规则，支持跨进程 Binder 传输。
 *
 * @property targetPackage 目标应用包名 (必须精确过滤，以避免干扰宿主或用户其它应用)
 * @property targetUid 目标应用 Linux UID (eBPF 模式下在内核态快速丢弃无关流量，若为 -1 则由服务端根据包名自动解析)
 * @property captureMode 捕获模式常数值 [CaptureMode.MODE_AUTO], [CaptureMode.MODE_EBPF], [CaptureMode.MODE_VPN_SERVICE]
 * @property maxBodySizeBytes 单个请求/响应体最大暂存与截取字节数 (默认 10MB)
 * @property urlFilterPattern 针对请求 URL 的过滤正则表达式，null 表示捕获全部流量
 */
@Parcelize
data class NetworkCaptureConfig(
    val targetPackage: String,
    val targetUid: Int = -1,
    val captureMode: Int = CaptureMode.MODE_AUTO,
    val maxBodySizeBytes: Long = DEFAULT_MAX_BODY_SIZE_BYTES,
    val urlFilterPattern: String? = null
) : Parcelable {

    /**
     * 辅助构造函数：支持直接指定 [CaptureMode] 枚举。
     */
    constructor(
        targetPackage: String,
        mode: CaptureMode,
        targetUid: Int = -1,
        maxBodySizeBytes: Long = DEFAULT_MAX_BODY_SIZE_BYTES,
        urlFilterPattern: String? = null
    ) : this(
        targetPackage = targetPackage,
        targetUid = targetUid,
        captureMode = mode.value,
        maxBodySizeBytes = maxBodySizeBytes,
        urlFilterPattern = urlFilterPattern
    )

    /**
     * 获取对应的枚举类型捕获模式。
     */
    val mode: CaptureMode
        get() = CaptureMode.fromInt(captureMode)

    /**
     * 检查给定的 URL 是否匹配配置中的过滤规则。
     */
    fun matchesUrl(url: String): Boolean {
        val pattern = urlFilterPattern ?: return true
        return try {
            Regex(pattern).containsMatchIn(url)
        } catch (_: Exception) {
            true
        }
    }

    companion object {
        const val DEFAULT_MAX_BODY_SIZE_BYTES: Long = 10 * 1024 * 1024L // 10 MB

        /**
         * 快速为指定包名创建默认抓包配置。
         */
        @JvmStatic
        fun createDefault(targetPackage: String, targetUid: Int = -1): NetworkCaptureConfig =
            NetworkCaptureConfig(targetPackage = targetPackage, targetUid = targetUid)
    }
}
