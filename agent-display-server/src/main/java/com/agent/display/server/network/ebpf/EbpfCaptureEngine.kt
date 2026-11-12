package com.agent.display.server.network.ebpf

import android.content.Context
import android.os.IBinder
import android.os.RemoteException
import android.util.Log
import com.agent.display.common.network.CaptureMode
import com.agent.display.common.network.INetworkCapture
import com.agent.display.common.network.INetworkEventListener
import com.agent.display.common.network.NetworkCaptureConfig
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Root-mode eBPF TLS 抓包引擎核心服务端实现 (实现 INetworkCapture AIDL 接口)。
 *
 * 核心架构：
 * 1. 运行在 Shell UID 2000 / Root 权限的服务端守护进程中；
 * 2. 启动前调用 EbpfCapabilityDetector 执行严格的环境探测 (Root, 内核 >= 5.4, /sys/fs/bpf, libssl.so)；
 * 3. 严格遵循 targetUid 内核过滤，保证非目标应用绝对零干扰；
 * 4. 接入 TlsStreamParser 实现 HTTP/1.1 与 HTTP/2 的自适应解包分发；
 * 5. 支持 Client Binder 死亡监听 (DeathRecipient)，客户端异常退出时自动注销探针自愈。
 */
class EbpfCaptureEngine(
    private val context: Context? = null,
    private val capabilityDetector: EbpfCapabilityProvider = EbpfCapabilityDetector
) : INetworkCapture.Stub() {

    companion object {
        private const val TAG = "EbpfCaptureEngine"

        @Volatile
        private var instance: EbpfCaptureEngine? = null

        @JvmStatic
        fun getInstance(context: Context? = null): EbpfCaptureEngine {
            return instance ?: synchronized(this) {
                instance ?: EbpfCaptureEngine(context).also { instance = it }
            }
        }
    }

    private val isCapturing = AtomicBoolean(false)
    private val targetFilter = EbpfTargetFilter(context)

    private var activeConfig: NetworkCaptureConfig? = null
    private var activeListener: INetworkEventListener? = null
    private var streamParser: TlsStreamParser? = null
    private var attacher: EbpfUprobeAttacher? = null

    private val deathRecipient = IBinder.DeathRecipient {
        Log.w(TAG, "Client died, auto stopping eBPF network capture session...")
        stopCapture()
    }

    /**
     * 启动 eBPF 网络抓包。
     */
    @Synchronized
    override fun startCapture(config: NetworkCaptureConfig, listener: INetworkEventListener): Boolean {
        Log.i(TAG, "startCapture called: targetPackage=${config.targetPackage}, mode=${config.mode}")

        // 1. 若当前已有会话在运行，先停止旧会话
        if (isCapturing.get()) {
            stopCapture()
        }

        // 2. 检测运行环境与内核 eBPF 支持度
        val capability = capabilityDetector.detect()
        if (!capability.isSupported) {
            val errMsg = "eBPF capture unsupported: ${capability.failureReason}"
            Log.e(TAG, errMsg)
            try {
                listener.onErrorOccurred("system", errMsg)
            } catch (e: RemoteException) {
                Log.w(TAG, "Failed to deliver error to listener: ${e.message}")
            }
            return false
        }

        val libSslPath = capability.libSslPath
        if (libSslPath == null) {
            val errMsg = "Conscrypt/BoringSSL libssl.so not found"
            Log.e(TAG, errMsg)
            try {
                listener.onErrorOccurred("system", errMsg)
            } catch (_: RemoteException) {}
            return false
        }

        // 3. 配置目标 UID 过滤器 (严格隔离)
        val resolvedUid = targetFilter.configureTarget(config.targetPackage, config.targetUid)
        if (resolvedUid <= 0) {
            Log.w(TAG, "Warning: targetUid could not be resolved for ${config.targetPackage}, filtering by runtime binder")
        }

        // 4. 初始化解析器与 Uprobe 挂载器
        val parser = TlsStreamParser(config, listener)
        val uprobeAttacher = EbpfUprobeAttacher(libSslPath, targetFilter, parser)

        val attachSuccess = uprobeAttacher.start()
        if (!attachSuccess) {
            val errMsg = "Failed to attach eBPF uprobes to $libSslPath"
            Log.e(TAG, errMsg)
            try {
                listener.onErrorOccurred("system", errMsg)
            } catch (_: RemoteException) {}
            targetFilter.clearTarget()
            return false
        }

        // 5. 绑定 Binder 死亡监听
        try {
            listener.asBinder().linkToDeath(deathRecipient, 0)
        } catch (e: Exception) {
            Log.w(TAG, "Failed to link to death recipient: ${e.message}")
        }

        streamParser = parser
        attacher = uprobeAttacher
        activeConfig = config
        activeListener = listener
        isCapturing.set(true)

        Log.i(TAG, "eBPF capture engine successfully started for target: ${config.targetPackage} (UID=$resolvedUid)")
        return true
    }

    /**
     * 停止网络抓包并清理资源。
     */
    @Synchronized
    override fun stopCapture() {
        if (!isCapturing.getAndSet(false)) {
            return
        }

        Log.i(TAG, "Stopping eBPF capture engine...")

        // 解除死亡监听
        try {
            activeListener?.asBinder()?.unlinkToDeath(deathRecipient, 0)
        } catch (_: Exception) {}

        // 停止探针
        try {
            attacher?.stop()
        } catch (e: Exception) {
            Log.w(TAG, "Error stopping uprobe attacher: ${e.message}")
        }

        targetFilter.clearTarget()
        streamParser?.clear()

        attacher = null
        streamParser = null
        activeListener = null
        activeConfig = null

        Log.i(TAG, "eBPF capture engine stopped successfully.")
    }

    /**
     * 获取指定请求对应的完整 HTTP 响应体数据。
     */
    override fun getResponseBody(requestId: String): ByteArray? {
        return streamParser?.getResponseBody(requestId)
    }

    /**
     * 获取当前生效的底层抓包模式。
     */
    override fun getActiveMode(): Int {
        return if (isCapturing.get()) {
            CaptureMode.ACTIVE_MODE_EBPF
        } else {
            CaptureMode.ACTIVE_MODE_NONE
        }
    }

    /**
     * 供测试注入或内部调试使用的辅助通道。
     */
    fun injectTlsDataForTest(connectionId: String, direction: Int, data: ByteArray, uid: Int? = null) {
        val targetUid = uid ?: targetFilter.currentTargetUid
        attacher?.injectTlsData(connectionId, direction, data, targetUid)
    }

    /**
     * 获取当前目标过滤器。
     */
    val filter: EbpfTargetFilter
        get() = targetFilter

    /**
     * 判断引擎当前是否在运行。
     */
    val isRunning: Boolean
        get() = isCapturing.get()
}
