package com.agent.use.server

import android.annotation.SuppressLint
import android.app.ActivityManager
import android.content.AttributionSource
import android.content.Context
import android.content.pm.ProviderInfo
import android.net.LocalServerSocket
import android.net.LocalSocket
import android.os.Binder
import android.os.Bundle
import android.os.Handler
import android.os.HandlerThread
import android.os.IBinder
import android.os.Looper
import android.os.Process
import android.util.Log
import java.io.File
import java.lang.reflect.Proxy
import kotlin.system.exitProcess

/**
 * aau-server 独立守护进程主入口。
 *
 * 启动命令：
 * `CLASSPATH=/data/local/tmp/aau-server.jar app_process /system/bin \
 *   --nice-name=aau_server com.agent.use.server.AgentServerMain <package> <uid> <token> [mode]`
 */
object AgentServerMain {
    private const val TAG = "AgentServerMain"
    private const val METHOD_ATTACH = "attach"

    @JvmStatic
    fun main(args: Array<String>) {
        if (args.size < 3) {
            Log.e(TAG, "Usage: AgentServerMain <packageName> <clientUid> <token> [mode]")
            exitProcess(2)
        }

        val packageName = args[0]
        val clientUid = args[1].toIntOrNull() ?: exitProcess(2)
        val token = args[2]
        val mode = if (args.size >= 4) args[3] else "provider"

        // 初始化主线程 Looper
        Looper.prepareMainLooper()

        val service = ShellService(allowedUid = clientUid)
        // 崩溃自愈：启动时优先恢复可能残留的静音状态
        service.recoverMuted()

        val server = Daemon(service, packageName, clientUid, token, mode)
        server.start()

        Looper.loop()
    }

    private class Daemon(
        private val service: ShellService,
        private val packageName: String,
        private val clientUid: Int,
        private val token: String,
        private val mode: String,
    ) {
        private val context: Context = ShellContext.create()
        private val userId = clientUid / 100_000
        private val authorityCandidates = listOf("$packageName.aau", "$packageName.agent_display")
        private val worker = Handler(HandlerThread("aau-server-handoff").apply { start() }.looper)

        private var clientToken: IBinder? = null
        private var socketServer: LocalServerSocket? = null

        fun start() = worker.post {
            killOtherInstances()
            if (mode == "socket") {
                startSocketServer()
            } else {
                deliverToProvider()
                watchClientUid()
            }
        }

        /** 杀死残留的旧守护进程实例，保持单例 */
        private fun killOtherInstances() {
            val myPid = Process.myPid()
            val targetNames = setOf("aau_server", "agent_display_server")
            File("/proc").listFiles()?.forEach { dir ->
                val pid = dir.name.toIntOrNull() ?: return@forEach
                if (pid == myPid) return@forEach
                val cmdline = runCatching { File(dir, "cmdline").readBytes() }.getOrNull() ?: return@forEach
                val name = String(cmdline.takeWhile { it != 0.toByte() }.toByteArray())
                if (name in targetNames) {
                    Log.i(TAG, "Terminating older daemon instance: $pid ($name)")
                    Process.killProcess(pid)
                }
            }
        }

        /** 基于 LocalSocket 模式监听通信 */
        private fun startSocketServer() {
            val socketName = "aau_$token"
            runCatching {
                socketServer = LocalServerSocket(socketName)
                Log.i(TAG, "LocalServerSocket listening on $socketName")
                Thread({
                    while (true) {
                        val client: LocalSocket = socketServer?.accept() ?: break
                        handleSocketClient(client)
                    }
                }, "aau-socket-acceptor").apply { isDaemon = true; start() }
            }.onFailure {
                Log.e(TAG, "Failed to bind LocalServerSocket $socketName, trying legacy fallback", it)
                val legacySocketName = "agent_display_$token"
                runCatching {
                    socketServer = LocalServerSocket(legacySocketName)
                    Log.i(TAG, "LocalServerSocket listening on $legacySocketName")
                    Thread({
                        while (true) {
                            val client: LocalSocket = socketServer?.accept() ?: break
                            handleSocketClient(client)
                        }
                    }, "aau-socket-acceptor").apply { isDaemon = true; start() }
                }
            }
        }

        private fun handleSocketClient(socket: LocalSocket) {
            runCatching {
                val input = socket.inputStream.bufferedReader().readLine()
                if (input == token) {
                    Log.i(TAG, "Socket client authenticated successfully")
                } else {
                    socket.close()
                }
            }
        }

        /** 基于 ActivityManager ProviderExternal 握手传递 Binder */
        @SuppressLint("PrivateApi", "DiscouragedPrivateApi")
        private fun deliverToProvider() {
            for (auth in authorityCandidates) {
                if (deliverToSpecificProvider(auth)) {
                    return
                }
            }
        }

        private fun deliverToSpecificProvider(auth: String): Boolean {
            val am = Class.forName("android.app.ActivityManager").getMethod("getService").invoke(null)!!
            val binderToken = Binder()

            val holder = try {
                am.javaClass.getMethod(
                    "getContentProviderExternal",
                    String::class.java,
                    Int::class.javaPrimitiveType,
                    IBinder::class.java,
                    String::class.java
                ).invoke(am, auth, userId, binderToken, TAG)
            } catch (t: Throwable) {
                Log.w(TAG, "getContentProviderExternal failed for $auth", t)
                null
            } ?: return false

            var attached = false
            try {
                val info = holder.javaClass.getField("info").get(holder) as? ProviderInfo
                if (info == null || info.packageName != packageName) {
                    Log.w(TAG, "Provider $auth rejected: belongs to ${info?.packageName}, expected $packageName")
                    return false
                }

                val provider = holder.javaClass.getField("provider").get(holder)!!
                val extras = Bundle().apply {
                    putString("token", token)
                    putBinder("binder", service)
                    putInt("uid", Process.myUid())
                    putInt("pid", Process.myPid())
                }

                val callMethod = provider.javaClass.methods.first {
                    it.name == "call" && it.parameterTypes.size == 5 && it.parameterTypes[0] == AttributionSource::class.java
                }
                val caller = AttributionSource.Builder(Process.myUid()).setPackageName(ShellContext.SHELL_PACKAGE).build()
                val result = callMethod.invoke(provider, caller, auth, METHOD_ATTACH, null, extras) as? Bundle

                val clientBinder = result?.getBinder("clientToken")
                if (clientBinder != null) {
                    clientToken = clientBinder
                    clientBinder.linkToDeath({ worker.post { onClientDied(clientBinder) } }, 0)
                    Log.i(TAG, "Successfully attached to client $packageName (UID $clientUid, authority $auth)")
                    attached = true
                }
            } catch (t: Throwable) {
                Log.w(TAG, "Handoff to provider $auth failed", t)
            } finally {
                runCatching {
                    am.javaClass.getMethod(
                        "removeContentProviderExternalAsUser",
                        String::class.java,
                        IBinder::class.java,
                        Int::class.javaPrimitiveType
                    ).invoke(am, auth, binderToken, userId)
                }
            }
            return attached
        }

        /** 客户端退出或崩溃时的资源自愈清理 */
        private fun onClientDied(token: IBinder) {
            if (clientToken !== token) return
            clientToken = null
            Log.i(TAG, "Client $packageName disconnected, releasing all display sessions and audio mutes")
            runCatching { service.releaseAll() }
        }

        /** 监听客户端 UID 重新进入前台，自动重连 */
        @SuppressLint("PrivateApi", "DiscouragedPrivateApi")
        private fun watchClientUid() {
            runCatching {
                val amClass = ActivityManager::class.java
                val manager = amClass.getDeclaredConstructor(Context::class.java, Handler::class.java)
                    .apply { isAccessible = true }.newInstance(context, worker)

                val listenerClass = Class.forName("android.app.ActivityManager\$OnUidImportanceListener")
                val proxy = Proxy.newProxyInstance(AgentServerMain::class.java.classLoader, arrayOf(listenerClass)) { _, method, args ->
                    if (method.name == "onUidImportance") {
                        val uid = args[0] as Int
                        val importance = args[1] as Int
                        if (uid == clientUid && importance != ActivityManager.RunningAppProcessInfo.IMPORTANCE_GONE) {
                            worker.post { if (clientToken == null) deliverToProvider() }
                        }
                    }
                    null
                }

                amClass.getMethod("addOnUidImportanceListener", listenerClass, Int::class.javaPrimitiveType)
                    .invoke(manager, proxy, ActivityManager.RunningAppProcessInfo.IMPORTANCE_CACHED)
            }.onFailure {
                Log.w(TAG, "Failed to register OnUidImportanceListener: ${it.message}")
            }
        }
    }
}
