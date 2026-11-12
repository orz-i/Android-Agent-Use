package com.agent.display.client.network.vpn

import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.util.Log
import com.agent.display.client.network.vpn.processor.VpnPacketProcessor
import com.agent.display.common.network.CaptureMode
import com.agent.display.common.network.INetworkCapture
import com.agent.display.common.network.INetworkEventListener
import com.agent.display.common.network.NetworkCaptureConfig
import java.util.concurrent.atomic.AtomicBoolean

/**
 * AAU 基于 Android VpnService 的免 Root 局部网络捕获引擎。
 *
 * 实现了 [INetworkCapture] AIDL 契约，支持在无 Root 环境下（如无线调试、Shizuku、或者用户直接运行）
 * 建立零干扰 TUN 虚拟网卡，捕获指定包名的 DNS 解析、TLS Client Hello (SNI) 以及 HTTP 明文流量。
 */
class VpnCaptureEngine(
    private val context: Context? = null
) : INetworkCapture.Stub() {

    private val isRunning = AtomicBoolean(false)

    @Volatile
    private var activeConfig: NetworkCaptureConfig? = null

    @Volatile
    private var activeListener: INetworkEventListener? = null

    @Volatile
    private var packetProcessor: VpnPacketProcessor? = null

    /**
     * 启动免 Root VpnService 网络捕获。
     *
     * @param config 抓包配置（包含目标包名、最大体量、URL 过滤正则等）
     * @param listener 网络事件接收回调
     * @return 是否成功启动
     */
    override fun startCapture(
        config: NetworkCaptureConfig,
        listener: INetworkEventListener
    ): Boolean {
        if (config.targetPackage.isBlank()) {
            Log.e(TAG, "Cannot start VpnCapture: targetPackage is empty")
            listener.onErrorOccurred("", "targetPackage cannot be blank")
            return false
        }

        if (isRunning.get()) {
            stopCapture()
        }

        val processor = VpnPacketProcessor(config = config, listener = listener)
        this.packetProcessor = processor
        this.activeConfig = config
        this.activeListener = listener

        if (context != null) {
            val prepareIntent = VpnService.prepare(context)
            if (prepareIntent != null) {
                val msg = "VpnService permission not granted. Please prepare VPN intent first."
                Log.w(TAG, msg)
                listener.onErrorOccurred("", msg)
                return false
            }

            AauVpnService.start(
                context = context,
                targetPackage = config.targetPackage,
                processor = processor,
                listener = listener
            )
        } else {
            Log.i(TAG, "VpnCaptureEngine started in headless/test mode (context is null)")
        }

        isRunning.set(true)
        Log.i(TAG, "VpnCaptureEngine started successfully for ${config.targetPackage}")
        return true
    }

    /**
     * 停止网络捕获并释放底层资源。
     */
    override fun stopCapture() {
        if (!isRunning.getAndSet(false)) return

        if (context != null) {
            AauVpnService.stop(context)
        }

        packetProcessor?.reset()
        packetProcessor = null
        activeConfig = null
        activeListener = null

        Log.i(TAG, "VpnCaptureEngine stopped")
    }

    /**
     * 获取指定请求关联的完整 HTTP 响应体数据。
     */
    override fun getResponseBody(requestId: String): ByteArray? {
        return packetProcessor?.getResponseBody(requestId)
    }

    /**
     * 获取当前生效的抓包模式。
     */
    override fun getActiveMode(): Int {
        return if (isRunning.get()) {
            CaptureMode.ACTIVE_MODE_VPN_SERVICE
        } else {
            CaptureMode.ACTIVE_MODE_NONE
        }
    }

    /**
     * 判断当前引擎是否正在运行抓包。
     */
    fun isCapturing(): Boolean = isRunning.get()

    /**
     * 获取当前的包处理器（供高级调试或测试直接喂包）。
     */
    fun getPacketProcessor(): VpnPacketProcessor? = packetProcessor

    /**
     * 直接向引擎注入一个原始 IP 数据包（用于单元测试或模拟数据源）。
     */
    fun processPacket(buffer: ByteArray, length: Int) {
        packetProcessor?.processPacket(buffer, length)
    }

    companion object {
        private const val TAG = "VpnCaptureEngine"

        /**
         * 辅助检查当前应用是否已获得 VpnService 授权。
         * 若返回 null，说明已授权；若返回 Intent，需引导用户确认授权。
         */
        @JvmStatic
        fun checkVpnPermission(context: Context): Intent? {
            return VpnService.prepare(context)
        }
    }
}
