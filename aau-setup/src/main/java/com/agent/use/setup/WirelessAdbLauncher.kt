package com.agent.use.setup

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.os.Process
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.net.InetAddress
import java.net.NetworkInterface

/**
 * 本地无线调试发现与拉起器。
 *
 * 结合 Android NsdManager (mDNS) 发现本机 adbd 无线调试端口（只接受网卡地址属于本机、经过 settle 窗口收敛后的条目），
 * 并提供守护进程启动脚本生成。
 */
class WirelessAdbLauncher(context: Context) {

    private val appContext = context.applicationContext ?: context

    companion object {
        private const val TAG = "WirelessAdbLauncher"
        const val SERVICE_TYPE_TLS_CONNECT = "_adb-tls-connect._tcp."
        const val SERVICE_TYPE_TLS_PAIRING = "_adb-tls-pairing._tcp."
        private const val DISCOVERY_TIMEOUT_MS = 6_000L
        private const val DEFAULT_PORTS_TIMEOUT_MS = 3_000L
        private const val SETTLE_MS = 400L
        private const val RESOLVE_MS = 1_500L

        /**
         * 通过 mDNS 发现当前设备本机开放的所有无线调试端口（按发现顺序去重）。
         */
        suspend fun findLocalAdbPorts(
            context: Context,
            serviceType: String = SERVICE_TYPE_TLS_CONNECT,
            timeoutMs: Long = DEFAULT_PORTS_TIMEOUT_MS,
        ): List<Int> = WirelessAdbLauncher(context).findLocalAdbPorts(serviceType, timeoutMs)

        internal fun isLocalAddress(host: InetAddress?): Boolean {
            if (host == null) return false
            if (host.isAnyLocalAddress || host.isLoopbackAddress) return true
            return runCatching {
                NetworkInterface.getByInetAddress(host) != null ||
                    NetworkInterface.getNetworkInterfaces().asSequence()
                        .any { nic -> nic.inetAddresses.asSequence().any { it == host } }
            }.getOrDefault(false)
        }
    }

    private val nsdManager: NsdManager by lazy {
        appContext.getSystemService(NsdManager::class.java)
            ?: appContext.getSystemService(Context.NSD_SERVICE) as NsdManager
    }

    data class DiscoveredAdbPort(
        val host: String,
        val port: Int,
        val isPairing: Boolean,
    )

    /**
     * 通过 mDNS 监听发现当前设备本机开放的无线调试端口列表，只在确认属于本机网卡后返回。
     * 查到第一个本机端口后再多等 [SETTLE_MS] 收齐同时公布的记录，并逐个解析（兼容旧版系统 NsdManager 单并发限制）。
     */
    suspend fun findLocalAdbPorts(
        serviceType: String = SERVICE_TYPE_TLS_CONNECT,
        timeoutMs: Long = DEFAULT_PORTS_TIMEOUT_MS,
    ): List<Int> = findLocalAdbEndpoints(
        serviceType = serviceType,
        timeoutMs = timeoutMs,
        pairingMode = serviceType == SERVICE_TYPE_TLS_PAIRING,
    ).map { it.port }.distinct()

    /**
     * 通过 mDNS 监听发现当前设备本机开放的首个无线调试端口
     */
    suspend fun discoverLocalAdbPort(pairingMode: Boolean = false): DiscoveredAdbPort? {
        val serviceType = if (pairingMode) SERVICE_TYPE_TLS_PAIRING else SERVICE_TYPE_TLS_CONNECT
        return findLocalAdbEndpoints(serviceType, DISCOVERY_TIMEOUT_MS, pairingMode).firstOrNull()
    }

    private suspend fun findLocalAdbEndpoints(
        serviceType: String,
        timeoutMs: Long,
        pairingMode: Boolean,
    ): List<DiscoveredAdbPort> = withContext(Dispatchers.IO) {
        val services = Channel<NsdServiceInfo>(Channel.UNLIMITED)
        val listener = object : NsdManager.DiscoveryListener {
            override fun onServiceFound(info: NsdServiceInfo) {
                services.trySend(info)
            }

            override fun onServiceLost(info: NsdServiceInfo) {}
            override fun onDiscoveryStarted(serviceType: String) {}
            override fun onDiscoveryStopped(serviceType: String) {}

            override fun onStartDiscoveryFailed(serviceType: String, errorCode: Int) {
                Log.w(TAG, "Discovery start failed: $errorCode")
                services.close()
            }

            override fun onStopDiscoveryFailed(serviceType: String, errorCode: Int) {}
        }

        nsdManager.discoverServices(serviceType, NsdManager.PROTOCOL_DNS_SD, listener)
        val endpoints = mutableListOf<DiscoveredAdbPort>()
        try {
            withTimeoutOrNull(timeoutMs) {
                var settleUntil = Long.MAX_VALUE
                while (System.currentTimeMillis() < settleUntil) {
                    val remaining = (settleUntil - System.currentTimeMillis()).coerceAtMost(timeoutMs)
                    if (remaining <= 0L) break
                    val info = withTimeoutOrNull(remaining) {
                        services.receiveCatching().getOrNull()
                    } ?: break
                    resolveLocal(info, pairingMode)?.let { resolved ->
                        if (endpoints.none { it.port == resolved.port && it.host == resolved.host }) {
                            endpoints += resolved
                        }
                        if (settleUntil == Long.MAX_VALUE) {
                            settleUntil = System.currentTimeMillis() + SETTLE_MS
                        }
                    }
                }
            }
        } finally {
            services.close()
            runCatching { nsdManager.stopServiceDiscovery(listener) }
        }
        endpoints
    }

    private suspend fun resolveLocal(info: NsdServiceInfo, pairingMode: Boolean): DiscoveredAdbPort? {
        val done = Channel<DiscoveredAdbPort?>(1)
        @Suppress("DEPRECATION")
        nsdManager.resolveService(info, object : NsdManager.ResolveListener {
            override fun onResolveFailed(serviceInfo: NsdServiceInfo, errorCode: Int) {
                done.trySend(null)
            }

            override fun onServiceResolved(resolvedInfo: NsdServiceInfo) {
                @Suppress("DEPRECATION")
                val hostAddr = resolvedInfo.host
                if (!isLocalAddress(hostAddr)) {
                    done.trySend(null)
                    return
                }
                val host = hostAddr?.hostAddress ?: "127.0.0.1"
                val port = resolvedInfo.port
                done.trySend(DiscoveredAdbPort(host, port, pairingMode))
            }
        })
        return withTimeoutOrNull(RESOLVE_MS) { done.receive() }
    }

    /**
     * 生成电脑 USB / 本地 ADB shell 启动脚本
     */
    fun generateLaunchScript(token: String): String {
        val packageName = appContext.packageName
        val uid = Process.myUid()
        val jarPath = "/data/local/tmp/aau-server.jar"
        return """
            |#!/system/bin/sh
            |# AAU (Android Agent Use) 守护进程启动脚本
            |if [ ! -f $jarPath ]; then
            |  if [ -f /data/local/tmp/agent-display-server.jar ]; then
            |    jarPath="/data/local/tmp/agent-display-server.jar"
            |  else
            |    echo "Error: $jarPath not found. Please push aau-server.jar first."
            |    exit 1
            |  fi
            |fi
            |CLASSPATH=$jarPath nohup setsid app_process /system/bin \
            |  --nice-name=aau_server \
            |  com.agent.use.server.AgentServerMain \
            |  $packageName $uid $token provider >/dev/null 2>&1 &
            |sleep 1
            |if pidof aau_server >/dev/null 2>&1 || pidof agent_display_server >/dev/null 2>&1; then
            |  echo "aau-server started successfully!"
            |else
            |  echo "Failed to start aau-server."
            |  exit 1
            |fi
        """.trimMargin()
    }
}
