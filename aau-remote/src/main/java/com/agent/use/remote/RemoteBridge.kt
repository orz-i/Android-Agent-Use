package com.agent.use.remote

import com.agent.use.remote.api.EndpointRouter
import com.agent.use.remote.api.RemoteActivity
import com.agent.use.remote.http.AccessGate
import com.agent.use.remote.http.HttpRequest
import com.agent.use.remote.http.HttpResponse
import com.agent.use.remote.http.MiniHttpServer
import com.agent.use.remote.spi.RemoteDevicePort
import com.agent.use.remote.spi.RemoteExportPort
import com.agent.use.remote.spi.RemoteHistoryPort
import com.agent.use.remote.spi.RemoteTaskPort
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.net.InetAddress
import java.net.InetSocketAddress

/** 监听范围由开关推导，不是开关直接绑地址。 */
enum class ListenScope {
    /** 全关：不绑端口。 */
    Off,

    /** 只绑 IPv4 回环 127.0.0.1：USB（`adb forward` 进来就是回环）与测试。 */
    LoopbackOnly,

    /** 绑所有网卡，但只收两端都是私有地址的连接：局域网、私有组网。公网来的当场断开。 */
    PrivateNetworks,
}

data class RemoteConfig(
    val port: Int = DEFAULT_PORT,
    val listen: ListenScope = ListenScope.Off,
    val serverVersion: String,
    val brand: RemoteBrand = RemoteBrand(),
    val maxConnections: Int = 16,
    val readTimeoutMs: Int = 30_000,
    val clock: () -> Long = System::currentTimeMillis,
) {
    init {
        // 0 表示让系统挑一个（测试与首次绑定用）；其余必须落在非特权端口段
        require(port == 0 || port in MIN_PORT..MAX_PORT) { "port must be 0 or between $MIN_PORT and $MAX_PORT" }
        require(maxConnections > 0)
    }

    companion object {
        const val MIN_PORT = 1024
        const val MAX_PORT = 65535

        /** 8765 会被系统服务占用（issue #392），但仍是双方默认值，保持兼容。 */
        const val DEFAULT_PORT = 8765
    }
}

sealed interface BridgeState {
    data object Off : BridgeState
    data class Listening(val port: Int) : BridgeState
    data class Failed(val message: String) : BridgeState
}

/**
 * 外部编排的入口门面：共用 HTTP 监听与鉴权，任务 API 与 MCP 并列接入同一份用例。
 *
 * 只活在接入方进程里——任务编排必须就近访问宿主的模型、工具与 UI 状态，把它放进特权守护进程
 * 会让守护进程变成 agent runtime，破坏「只提供动作原语」的边界。
 */
class RemoteBridge(
    private val config: RemoteConfig,
    private val tasks: RemoteTaskPort,
    private val token: () -> String?,
    private val loopbackToken: () -> String? = { null },
    private val device: RemoteDevicePort? = null,
    private val history: RemoteHistoryPort? = null,
    private val exports: RemoteExportPort? = null,
    private val onError: (Throwable) -> Unit = {},
    /**
     * 宿主已经自己装配好的路由（想让本地监听与出站网关共用同一份 activity 计数时用）。
     * 传了就忽略 [device]、[history]、[exports]——那三个已经进到 [router] 里了。
     */
    router: EndpointRouter? = null,
) {
    private val access = AccessGate(token, config.clock, loopbackToken = loopbackToken)
    private val endpoints = router ?: EndpointRouter(
        tasks, config.serverVersion, config.brand, config.clock, device, history, exports,
    )
    private val mutable = MutableStateFlow<BridgeState>(BridgeState.Off)
    private var server: MiniHttpServer? = null

    val state: StateFlow<BridgeState> = mutable.asStateFlow()
    val activity: StateFlow<RemoteActivity> get() = endpoints.activity

    val boundPort: Int get() = server?.port ?: -1

    /** 网关适配器等复用：已经认证过的请求直接走同一套路由。 */
    fun handle(req: HttpRequest): HttpResponse = access.handle(req, endpoints::handle)

    /** 开始监听；端口被占等绑定失败时抛出异常（同时把状态置为 [BridgeState.Failed]）。 */
    @Synchronized fun start() {
        if (config.listen == ListenScope.Off) {
            mutable.value = BridgeState.Off
            return
        }
        stop()
        val s = MiniHttpServer(
            bindAddress(config.listen, config.port),
            ::handle,
            accept = { local, remote -> accepts(config.listen, local, remote) },
            maxConnections = config.maxConnections,
            readTimeoutMs = config.readTimeoutMs,
            onError = onError,
        )
        try {
            s.start()
        } catch (e: Exception) {
            mutable.value = BridgeState.Failed(e.message ?: e::class.simpleName.orEmpty())
            throw e
        }
        server = s
        mutable.value = BridgeState.Listening(s.port)
    }

    @Synchronized fun stop() {
        server?.stop()
        server = null
        mutable.value = BridgeState.Off
    }

    /** 热重绑端口：停旧绑新，成功后由宿主重发连接信息（USB 连接信息里写着端口）。 */
    @Synchronized fun rebind(port: Int) {
        require(port in RemoteConfig.MIN_PORT..RemoteConfig.MAX_PORT) { "port out of range" }
        stop()
        val next = config.copy(port = port)
        val s = MiniHttpServer(
            bindAddress(next.listen, port),
            ::handle,
            accept = { local, remote -> accepts(next.listen, local, remote) },
            maxConnections = next.maxConnections,
            readTimeoutMs = next.readTimeoutMs,
            onError = onError,
        )
        s.start()
        server = s
        mutable.value = BridgeState.Listening(s.port)
    }

    companion object {
        /**
         * 监听的地址：所有网卡，或只有 IPv4 回环 127.0.0.1。回环写死成 IPv4：安卓上 `InetAddress.getLoopbackAddress()`
         * 可能给 ::1，而 `adb forward` 连的是 127.0.0.1。
         */
        fun bindAddress(listen: ListenScope, port: Int): InetSocketAddress =
            if (listen == ListenScope.PrivateNetworks) InetSocketAddress(port)
            else InetSocketAddress(InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)), port)

        fun accepts(listen: ListenScope, local: InetAddress, remote: InetAddress): Boolean = when (listen) {
            ListenScope.Off -> false
            ListenScope.LoopbackOnly -> remote.isLoopbackAddress
            ListenScope.PrivateNetworks -> AccessGate.privateAddress(local) && AccessGate.privateAddress(remote)
        }
    }
}
