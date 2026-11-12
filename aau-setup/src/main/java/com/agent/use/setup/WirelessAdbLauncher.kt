package com.agent.use.setup

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.os.Process
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.coroutines.resume

/**
 * 本地无线调试发现与拉起器。
 *
 * 结合 Android NsdManager (mDNS) 发现本机 adbd 无线调试端口，执行守护进程启动命令。
 */
class WirelessAdbLauncher(private val context: Context) {

    companion object {
        private const val TAG = "WirelessAdbLauncher"
        private const val SERVICE_TYPE_TLS_CONNECT = "_adb-tls-connect._tcp."
        private const val SERVICE_TYPE_TLS_PAIRING = "_adb-tls-pairing._tcp."
        private const val DISCOVERY_TIMEOUT_MS = 6_000L
    }

    private val nsdManager: NsdManager by lazy {
        context.getSystemService(Context.NSD_SERVICE) as NsdManager
    }

    data class DiscoveredAdbPort(
        val host: String,
        val port: Int,
        val isPairing: Boolean
    )

    /**
     * 通过 mDNS 监听发现当前设备本机开放的无线调试端口
     */
    suspend fun discoverLocalAdbPort(pairingMode: Boolean = false): DiscoveredAdbPort? =
        withContext(Dispatchers.IO) {
            withTimeoutOrNull(DISCOVERY_TIMEOUT_MS) {
                suspendCancellableCoroutine { cont ->
                    val serviceType = if (pairingMode) SERVICE_TYPE_TLS_PAIRING else SERVICE_TYPE_TLS_CONNECT
                    val listener = object : NsdManager.DiscoveryListener {
                        override fun onStartDiscoveryFailed(serviceType: String, errorCode: Int) {
                            Log.w(TAG, "Discovery start failed: $errorCode")
                            if (cont.isActive) cont.resume(null)
                        }

                        override fun onStopDiscoveryFailed(serviceType: String, errorCode: Int) {}
                        override fun onDiscoveryStarted(serviceType: String) {}
                        override fun onDiscoveryStopped(serviceType: String) {}

                        override fun onServiceFound(serviceInfo: NsdServiceInfo) {
                            nsdManager.resolveService(serviceInfo, object : NsdManager.ResolveListener {
                                override fun onResolveFailed(serviceInfo: NsdServiceInfo, errorCode: Int) {}

                                override fun onServiceResolved(resolvedInfo: NsdServiceInfo) {
                                    val host = resolvedInfo.host?.hostAddress ?: "127.0.0.1"
                                    val port = resolvedInfo.port
                                    if (cont.isActive) {
                                        cont.resume(DiscoveredAdbPort(host, port, pairingMode))
                                    }
                                }
                            })
                        }

                        override fun onServiceLost(serviceInfo: NsdServiceInfo) {}
                    }

                    nsdManager.discoverServices(serviceType, NsdManager.PROTOCOL_DNS_SD, listener)

                    cont.invokeOnCancellation {
                        runCatching { nsdManager.stopServiceDiscovery(listener) }
                    }
                }
            }
        }

    /**
     * 生成电脑 USB / 本地 ADB shell 启动脚本
     */
    fun generateLaunchScript(token: String): String {
        val packageName = context.packageName
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
