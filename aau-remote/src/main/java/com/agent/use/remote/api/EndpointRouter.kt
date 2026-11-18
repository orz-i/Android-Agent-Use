package com.agent.use.remote.api

import com.agent.use.remote.RemoteBrand
import com.agent.use.remote.mcp.McpRpc
import com.agent.use.remote.mcp.ToolCatalog
import com.agent.use.remote.spi.RemoteDevicePort
import com.agent.use.remote.spi.RemoteExportPort
import com.agent.use.remote.spi.RemoteHistoryPort
import com.agent.use.remote.spi.RemoteTaskPort
import com.agent.use.remote.http.HttpRequest
import com.agent.use.remote.http.HttpResponse
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.net.InetAddress

/** 设置页上显示的一点点动静：最近连过的客户端有几个、最后一次请求是什么时候。 */
data class RemoteActivity(val recentClients: Int = 0, val lastRequestAtMs: Long? = null)

/**
 * HTTP 与 MCP 每次请求都从同一个已认证归属构造任务服务，避免某条协议路径绕过任务、文件或导出权限。
 * 两条协议因此共享同一份业务规则，也共享同一份 owner 隔离。
 */
class EndpointRouter(
    private val tasks: RemoteTaskPort,
    private val serverVersion: String,
    private val brand: RemoteBrand = RemoteBrand(),
    private val clock: () -> Long = System::currentTimeMillis,
    private val device: RemoteDevicePort? = null,
    private val history: RemoteHistoryPort? = null,
    private val exports: RemoteExportPort? = null,
) {
    private val clients = LinkedHashMap<String, Long>()
    private val mutable = MutableStateFlow(RemoteActivity())
    val activity: StateFlow<RemoteActivity> = mutable.asStateFlow()

    fun handle(req: HttpRequest, deviceAccess: Boolean = true, historyAccess: Boolean = true): HttpResponse {
        // Relay adapters do not carry the phone's bearer token. They still get one isolated task namespace,
        // never the internal unscoped view and never local history.
        val owner = req.accessOwner ?: RELAY_OWNER
        val scopedTasks = tasks.scope(owner)
        val service = TaskUseCases(scopedTasks, records = exports?.scope(owner))
        val rpc = McpRpc(ToolCatalog(service, brand, device.takeIf { deviceAccess }), serverVersion, brand) { remote, name ->
            seen(remote, name)
        }
        if (req.path == McpRpc.PATH) return rpc.handle(req)
        if (req.path == TaskApi.ROOT || req.path.startsWith("${TaskApi.ROOT}/")) {
            seen(req.remote, req.header(CLIENT_HEADER)?.take(64))
            val api = TaskApi(service, serverVersion, device.takeIf { deviceAccess }, history.takeIf { historyAccess })
            return api.handle(req)
        }
        return TaskApi.error(404, "not_found", "No such endpoint")
    }

    private fun seen(remote: InetAddress, name: String?) {
        val now = clock()
        synchronized(this) {
            val who = remote.hostAddress ?: "?"
            val key = if (name != null) "$who|$name" else clients.keys.lastOrNull { it.startsWith("$who|") } ?: "$who|"
            clients.remove(key); clients[key] = now
            clients.entries.removeAll { now - it.value > RECENT_MS }
            mutable.value = RemoteActivity(clients.size, now)
        }
    }

    companion object {
        const val RECENT_MS = 10 * 60_000L
        const val RELAY_OWNER = "relay"

        /** 电脑自称的客户端名。协议冻结在 `x-mika-client` 上，改名会让现成的 CLI 与任务台失去「是谁连的」这条信息。 */
        const val CLIENT_HEADER = "x-mika-client"
    }
}
