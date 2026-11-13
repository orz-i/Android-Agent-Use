package com.agent.use.client.network.vpn

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.util.Log
import com.agent.use.client.network.vpn.processor.VpnPacketProcessor
import com.agent.use.common.network.INetworkEventListener
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.net.Inet4Address
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * AAU 局部隔离网络嗅探与 NAT 转发 VpnService。
 *
 * 核心机制：
 * 1. 强制使用 [VpnService.Builder.addAllowedApplication]，仅将指定目标应用流量路由至 TUN；
 * 2. 通过 [VpnTunForwarder] 将 TUN 读取的 UDP/TCP 报文使用 `protect(...)` Socket 真正转发至外网并回写响应；
 * 3. 在转发同时将上/下行 IP 包同步分发至 [VpnPacketProcessor] 提取 DNS、TLS SNI 与 HTTP 明文。
 */
class AauVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private var workerThread: Thread? = null
    private var tunOutputStream: FileOutputStream? = null
    private var forwarder: VpnTunForwarder? = null
    private val isRunning = AtomicBoolean(false)

    override fun onCreate() {
        super.onCreate()
        instance = this
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action ?: ACTION_START
        val reqGen = intent?.getLongExtra(EXTRA_SESSION_GEN, 0L) ?: 0L

        when (action) {
            ACTION_START -> {
                if (reqGen > 0L && reqGen < latestRequestedGeneration.get()) {
                    completePendingStart(reqGen, false, "superseded_by_newer_session")
                    return START_NOT_STICKY
                }
                val targetPackage = intent?.getStringExtra(EXTRA_TARGET_PACKAGE)
                if (targetPackage.isNullOrBlank()) {
                    val msg = "Cannot start VPN: targetPackage is empty"
                    Log.e(TAG, msg)
                    completePendingStart(reqGen, false, msg)
                    stopSelf()
                    return START_NOT_STICKY
                }
                if (isRunning.get()) {
                    stopVpnCapture()
                }
                val (ok, err) = startVpnCaptureInternal(targetPackage)
                if (ok) {
                    activeGeneration.set(reqGen)
                }
                completePendingStart(reqGen, ok, err)
                if (!ok) {
                    stopSelf()
                }
            }
            ACTION_STOP -> {
                if (reqGen == 0L || reqGen >= activeGeneration.get()) {
                    stopVpnCapture()
                    stopSelf()
                }
            }
        }
        return START_NOT_STICKY
    }

    @Synchronized
    fun startVpnCapture(targetPackage: String): Boolean {
        if (isRunning.get()) {
            Log.w(TAG, "VPN is already running")
            return true
        }
        return startVpnCaptureInternal(targetPackage).first
    }

    @Synchronized
    private fun startVpnCaptureInternal(targetPackage: String): Pair<Boolean, String?> {
        if (isRunning.get()) {
            stopVpnCapture()
        }

        try {
            val builder = Builder()
                .setSession("AAU-VpnCapture-$targetPackage")
                .setMtu(DEFAULT_MTU)
                .addAddress("10.244.0.1", 32)
                .addRoute("0.0.0.0", 0)
                // Guard dual-stack apps so IPv6 SYN gets immediate RST and falls back to IPv4
                .addAddress("fd00:244::1", 128)
                .addRoute("::", 0)

            val dnsServers = resolveUpstreamIpv4DnsServers()
            for (dns in dnsServers) {
                try {
                    builder.addDnsServer(dns)
                } catch (_: Throwable) {
                }
            }

            try {
                builder.addAllowedApplication(targetPackage)
                Log.i(TAG, "Successfully isolated VPN traffic strictly to target package: $targetPackage")
            } catch (e: PackageManager.NameNotFoundException) {
                val msg = "Target package '$targetPackage' is not installed: ${e.message}"
                Log.e(TAG, msg, e)
                activeListener?.onErrorOccurred("", msg)
                return false to msg
            }

            val pfd = builder.establish()
            if (pfd == null) {
                val msg = "VPN establish failed (permission may not be prepared)"
                Log.e(TAG, msg)
                activeListener?.onErrorOccurred("", msg)
                return false to msg
            }

            val outStream = FileOutputStream(pfd.fileDescriptor)
            val natForwarder = VpnTunForwarder(
                protectSocket = { sock -> protect(sock) },
                protectDatagram = { dgram -> protect(dgram) },
                writeToTun = { pkt, len -> outStream.write(pkt, 0, len) },
                packetProcessor = activeProcessor
            )
            natForwarder.start()

            vpnInterface = pfd
            tunOutputStream = outStream
            forwarder = natForwarder
            isRunning.set(true)

            val thread = Thread({
                runPacketLoop(pfd, natForwarder)
            }, "AAU-VpnPacketReader")
            workerThread = thread
            thread.isDaemon = true
            thread.start()

            Log.i(TAG, "AAU VpnService NAT forwarder started successfully for package: $targetPackage")
            return true to null
        } catch (e: Exception) {
            val msg = "VPN start failed: ${e.message}"
            Log.e(TAG, msg, e)
            activeListener?.onErrorOccurred("", msg)
            stopVpnCapture()
            return false to msg
        }
    }

    private fun resolveUpstreamIpv4DnsServers(): List<String> {
        val discovered = LinkedHashSet<String>()
        try {
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            val linkProps = cm?.activeNetwork?.let { cm.getLinkProperties(it) }
            if (linkProps != null) {
                for (addr in linkProps.dnsServers) {
                    if (addr is Inet4Address && !addr.isLoopbackAddress) {
                        addr.hostAddress?.let { discovered.add(it) }
                    }
                }
            }
        } catch (t: Throwable) {
            Log.d(TAG, "Active network DNS query fallback: ${t.message}")
        }
        if (discovered.isEmpty()) {
            discovered.addAll(FALLBACK_DNS_SERVERS)
        }
        return discovered.toList()
    }

    private fun runPacketLoop(pfd: ParcelFileDescriptor, natForwarder: VpnTunForwarder) {
        val inputStream = FileInputStream(pfd.fileDescriptor)
        val buffer = ByteArray(BUFFER_SIZE)

        try {
            while (isRunning.get() && !Thread.currentThread().isInterrupted) {
                val length = inputStream.read(buffer)
                if (length > 0) {
                    natForwarder.handleOutboundIpPacket(buffer, length)
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
            } catch (_: Exception) {
            }
        }
    }

    @Synchronized
    fun stopVpnCapture() {
        val wasRunning = isRunning.getAndSet(false)
        forwarder?.stop()
        forwarder = null

        workerThread?.interrupt()
        workerThread = null

        try {
            tunOutputStream?.close()
        } catch (_: Exception) {
        }
        tunOutputStream = null

        try {
            vpnInterface?.close()
        } catch (e: Exception) {
            Log.e(TAG, "Error closing VPN interface: ${e.message}", e)
        }
        vpnInterface = null

        if (wasRunning) {
            Log.i(TAG, "AAU VpnService stopped and TUN released")
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
        private const val START_WAIT_TIMEOUT_MS = 3000L
        private val FALLBACK_DNS_SERVERS = listOf("223.5.5.5", "114.114.114.114", "8.8.8.8")

        const val ACTION_START = "com.agent.use.client.network.vpn.START"
        const val ACTION_STOP = "com.agent.use.client.network.vpn.STOP"
        const val EXTRA_TARGET_PACKAGE = "extra_target_package"
        const val EXTRA_SESSION_GEN = "extra_session_gen"

        @Volatile
        var instance: AauVpnService? = null
            private set

        @Volatile
        var activeProcessor: VpnPacketProcessor? = null

        @Volatile
        var activeListener: INetworkEventListener? = null

        private val latestRequestedGeneration = AtomicLong(0L)
        private val activeGeneration = AtomicLong(0L)

        private data class PendingStart(
            val generation: Long,
            val latch: CountDownLatch = CountDownLatch(1),
            @Volatile var success: Boolean = false,
            @Volatile var error: String? = null
        )

        @Volatile
        private var pendingStart: PendingStart? = null

        private fun completePendingStart(gen: Long, success: Boolean, error: String?) {
            val pending = pendingStart ?: return
            if (pending.generation == gen) {
                pending.success = success
                pending.error = error
                pending.latch.countDown()
            }
        }

        /**
         * 启动 AAU 局部 VPN 服务。当从后台线程调用时，同步等待 `Builder.establish()` 结果。
         */
        fun start(
            context: Context,
            targetPackage: String,
            processor: VpnPacketProcessor,
            listener: INetworkEventListener
        ): Pair<Boolean, String?> {
            val gen = latestRequestedGeneration.incrementAndGet()
            activeProcessor = processor
            activeListener = listener

            val pending = PendingStart(gen)
            pendingStart = pending

            val intent = Intent(context, AauVpnService::class.java).apply {
                action = ACTION_START
                putExtra(EXTRA_TARGET_PACKAGE, targetPackage)
                putExtra(EXTRA_SESSION_GEN, gen)
            }
            try {
                context.startService(intent)
            } catch (t: Throwable) {
                pendingStart = null
                return false to "vpn_service_start_failed:${t.message}"
            }

            val isMainThread = try {
                Looper.myLooper() == Looper.getMainLooper()
            } catch (_: Throwable) {
                false
            }
            if (isMainThread) {
                return true to null
            }

            val completed = try {
                pending.latch.await(START_WAIT_TIMEOUT_MS, TimeUnit.MILLISECONDS)
            } catch (_: InterruptedException) {
                false
            }
            if (!completed) {
                return if (isRunning()) true to null else false to "vpn_start_timeout"
            }
            return pending.success to pending.error
        }

        /**
         * 停止 AAU 局部 VPN 服务。
         */
        fun stop(context: Context) {
            val gen = latestRequestedGeneration.incrementAndGet()
            instance?.stopVpnCapture()
            val intent = Intent(context, AauVpnService::class.java).apply {
                action = ACTION_STOP
                putExtra(EXTRA_SESSION_GEN, gen)
            }
            try {
                context.startService(intent)
            } catch (_: Throwable) {
            }

            activeProcessor = null
            activeListener = null
        }

        fun isRunning(): Boolean = instance?.isRunning?.get() == true
    }
}
