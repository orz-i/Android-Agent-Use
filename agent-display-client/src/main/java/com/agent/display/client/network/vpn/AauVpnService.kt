package com.agent.display.client.network.vpn

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import com.agent.display.client.network.vpn.processor.VpnPacketProcessor
import com.agent.display.common.network.INetworkEventListener
import com.agent.display.common.network.NetworkCaptureConfig
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.util.concurrent.atomic.AtomicBoolean

/**
 * AAU 局部隔离网络嗅探与抓包 VpnService。
 *
 * 核心机制（严格零干扰隔离）：
 * 强制使用 [VpnService.Builder.addAllowedApplication]，确保仅有 AAU 虚拟屏中运行的
 * 指定目标应用流量进入 TUN 虚拟网卡；宿主应用及主屏全部用户应用（如微信、银行、浏览器等）
 * 完全绕过 VPN，享受 100% 原始网络速率与零代理干扰。
 */
class AauVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private var workerThread: Thread? = null
    private val isRunning = AtomicBoolean(false)

    override fun onCreate() {
        super.onCreate()
        instance = this
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action ?: ACTION_START
        when (action) {
            ACTION_START -> {
                val targetPackage = intent?.getStringExtra(EXTRA_TARGET_PACKAGE)
                if (targetPackage.isNullOrEmpty()) {
                    Log.e(TAG, "Cannot start VPN: targetPackage is empty")
                    stopSelf()
                    return START_NOT_STICKY
                }
                startVpnCapture(targetPackage)
            }
            ACTION_STOP -> {
                stopVpnCapture()
                stopSelf()
            }
        }
        return START_NOT_STICKY
    }

    /**
     * 建立 TUN 虚拟网卡并启动数据包读取循环。
     */
    @Synchronized
    fun startVpnCapture(targetPackage: String): Boolean {
        if (isRunning.get()) {
            Log.w(TAG, "VPN is already running")
            return true
        }

        try {
            val builder = Builder()
                .setSession("AAU-VpnCapture-$targetPackage")
                .setMtu(DEFAULT_MTU)
                .addAddress("10.244.0.1", 32)
                .addRoute("0.0.0.0", 0)
                .addDnsServer("8.8.8.8")

            // ==========================================
            // 核心隔离保障：严格限制仅目标包进入 TUN
            // ==========================================
            try {
                builder.addAllowedApplication(targetPackage)
                Log.i(TAG, "Successfully isolated VPN traffic strictly to target package: $targetPackage")
            } catch (e: PackageManager.NameNotFoundException) {
                Log.e(TAG, "Target package '$targetPackage' not found on system: ${e.message}", e)
                activeListener?.onErrorOccurred("", "Target package '$targetPackage' is not installed: ${e.message}")
                return false
            }

            val pfd = builder.establish()
            if (pfd == null) {
                Log.e(TAG, "Failed to establish VPN interface: Builder.establish() returned null")
                activeListener?.onErrorOccurred("", "VPN establish failed (permission may not be prepared)")
                return false
            }

            vpnInterface = pfd
            isRunning.set(true)

            // 启动数据包读取循环线程
            val thread = Thread({
                runPacketLoop(pfd)
            }, "AAU-VpnPacketReader")
            workerThread = thread
            thread.isDaemon = true
            thread.start()

            Log.i(TAG, "AAU VpnService started successfully for package: $targetPackage")
            return true
        } catch (e: Exception) {
            Log.e(TAG, "Exception while establishing AAU VPN: ${e.message}", e)
            activeListener?.onErrorOccurred("", "VPN start failed: ${e.message}")
            stopVpnCapture()
            return false
        }
    }

    private fun runPacketLoop(pfd: ParcelFileDescriptor) {
        val inputStream = FileInputStream(pfd.fileDescriptor)
        val buffer = ByteArray(BUFFER_SIZE)

        try {
            while (isRunning.get() && !Thread.currentThread().isInterrupted) {
                val length = inputStream.read(buffer)
                if (length > 0) {
                    activeProcessor?.processPacket(buffer, length)
                } else if (length < 0) {
                    break
                }
            }
        } catch (e: IOException) {
            if (isRunning.get()) {
                Log.w(TAG, "TUN inputStream closed or read error: ${e.message}")
            }
        } finally {
            try {
                inputStream.close()
            } catch (_: Exception) {}
        }
    }

    /**
     * 停止 VPN 嗅探并释放 TUN 资源。
     */
    @Synchronized
    fun stopVpnCapture() {
        if (!isRunning.getAndSet(false)) return

        try {
            workerThread?.interrupt()
            workerThread = null

            vpnInterface?.close()
            vpnInterface = null

            Log.i(TAG, "AAU VpnService stopped and TUN released")
        } catch (e: Exception) {
            Log.e(TAG, "Error closing VPN interface: ${e.message}", e)
        }
    }

    override fun onRevoke() {
        super.onRevoke()
        Log.w(TAG, "VPN permission revoked by system or user")
        stopVpnCapture()
        activeListener?.onErrorOccurred("", "VPN permission revoked by user or system")
    }

    override fun onDestroy() {
        stopVpnCapture()
        if (instance === this) {
            instance = null
        }
        super.onDestroy()
    }

    companion object {
        private const val TAG = "AauVpnService"
        private const val DEFAULT_MTU = 1500
        private const val BUFFER_SIZE = 32768

        const val ACTION_START = "com.agent.display.client.network.vpn.START"
        const val ACTION_STOP = "com.agent.display.client.network.vpn.STOP"
        const val EXTRA_TARGET_PACKAGE = "extra_target_package"

        @Volatile
        var instance: AauVpnService? = null
            private set

        @Volatile
        var activeProcessor: VpnPacketProcessor? = null

        @Volatile
        var activeListener: INetworkEventListener? = null

        /**
         * 启动 AAU 局部 VPN 服务。
         */
        fun start(
            context: Context,
            targetPackage: String,
            processor: VpnPacketProcessor,
            listener: INetworkEventListener
        ) {
            activeProcessor = processor
            activeListener = listener

            val intent = Intent(context, AauVpnService::class.java).apply {
                action = ACTION_START
                putExtra(EXTRA_TARGET_PACKAGE, targetPackage)
            }
            context.startService(intent)
        }

        /**
         * 停止 AAU 局部 VPN 服务。
         */
        fun stop(context: Context) {
            instance?.stopVpnCapture()
            val intent = Intent(context, AauVpnService::class.java).apply {
                action = ACTION_STOP
            }
            context.startService(intent)

            activeProcessor = null
            activeListener = null
        }

        /**
         * 检查当前 VPN 是否处于活动运行状态。
         */
        fun isRunning(): Boolean = instance?.isRunning?.get() == true
    }
}
