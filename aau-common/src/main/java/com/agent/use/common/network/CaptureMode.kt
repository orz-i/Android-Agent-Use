package com.agent.use.common.network

/**
 * 抓包模式定义与状态常量。
 */
enum class CaptureMode(val value: Int) {
    /**
     * 自动选择模式：优先尝试 Root eBPF 无侵入抓包，不可用或失败时自动降级到 VpnService 局部代理。
     */
    AUTO(0),

    /**
     * 强制使用 Root eBPF 模式：仅在具有 Root 权限且内核支持 eBPF (>= 5.4) 的设备上生效。
     */
    EBPF(1),

    /**
     * 强制使用局部 VpnService 模式：基于 Android VpnService 构建局部 TUN 虚拟网卡，无需 Root。
     */
    VPN_SERVICE(2);

    companion object {
        const val MODE_AUTO = 0
        const val MODE_EBPF = 1
        const val MODE_VPN_SERVICE = 2

        // 底层活动模式常量 (对应 INetworkCapture.getActiveMode())
        const val ACTIVE_MODE_NONE = 0
        const val ACTIVE_MODE_EBPF = 1
        const val ACTIVE_MODE_VPN_SERVICE = 2

        @JvmStatic
        fun fromInt(value: Int): CaptureMode =
            entries.firstOrNull { it.value == value } ?: AUTO
    }
}
