package com.agent.use.remote

import com.agent.use.remote.api.TaskApi
import com.agent.use.remote.http.HttpRequest
import com.agent.use.remote.spi.RemoteTask
import com.agent.use.remote.spi.RemoteTaskDetail
import com.agent.use.remote.spi.RemoteTaskPage
import com.agent.use.remote.spi.RemoteTaskPort
import com.agent.use.remote.spi.RemoteTaskState
import com.agent.use.remote.spi.StartOutcome
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.net.InetAddress
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

private val LOOPBACK: InetAddress = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
private val LAN: InetAddress = InetAddress.getByAddress(byteArrayOf(192.toByte(), 168.toByte(), 1, 9))
private val INTERNET: InetAddress = InetAddress.getByAddress(byteArrayOf(8, 8, 8, 8))

private const val TOKEN = "network-token-0123456789abcdefghijklm"
private const val USB_TOKEN = "usb-token-0123456789abcdefghijklmno"

/** 内存版任务端口：验证 AAU 的协议面，不掺宿主逻辑。 */
private class FakeTasks : RemoteTaskPort {
    val tasks = LinkedHashMap<String, RemoteTask>()

    override fun scope(owner: String): RemoteTaskPort = object : RemoteTaskPort by this@FakeTasks {
        override fun get(id: String) = this@FakeTasks.get(id)?.takeIf { it.owner == owner || it.owner == null }
        override fun list(limit: Int) = this@FakeTasks.list(limit).filter { it.owner == owner || it.owner == null }
        override fun page(limit: Int, before: String?) = RemoteTaskPage(list(limit).take(limit))

        override fun start(goal: String, conversation: String?, requestId: String?, attachments: List<String>) =
            startOwned(goal, conversation, requestId, owner)
    }

    override fun start(goal: String, conversation: String?, requestId: String?, attachments: List<String>) =
        startOwned(goal, conversation, requestId, null)

    fun startOwned(goal: String, conversation: String?, requestId: String?, owner: String?): StartOutcome {
        val id = requestId ?: "task-${tasks.size + 1}"
        val task = RemoteTask(
            id = id, conversation = conversation ?: "mcp-00000000-0000-0000-0000-000000000001",
            goal = goal, createdAtMs = 1_700_000_000_000, state = RemoteTaskState.Running,
            owner = owner, detail = RemoteTaskDetail(step = 2, progress = "opening the app"),
        )
        tasks[id] = task
        return StartOutcome.Started(task)
    }

    override fun get(id: String) = tasks[id]
    override fun list(limit: Int) = tasks.values.toList().takeLast(limit).reversed()
    override fun answer(id: String, text: String) = setState(id, RemoteTaskState.Running)
    override fun steer(id: String, text: String): String? {
        tasks[id] = tasks.getValue(id).copy(steers = tasks.getValue(id).steers + com.agent.use.remote.spi.RemoteSteer("m1", "queued"))
        return "m1"
    }

    override fun cancel(id: String) = setState(id, RemoteTaskState.Cancelled)

    fun setState(id: String, state: RemoteTaskState, detail: RemoteTaskDetail? = null): Boolean {
        val task = tasks[id] ?: return false
        tasks[id] = task.copy(state = state, detail = detail ?: task.detail)
        return true
    }
}

class RemoteBridgeTest {
    private fun bridge(tasks: FakeTasks = FakeTasks(), clock: () -> Long = System::currentTimeMillis) = RemoteBridge(
        RemoteConfig(port = 0, listen = ListenScope.LoopbackOnly, serverVersion = "test-1", clock = clock),
        tasks,
        token = { TOKEN },
        loopbackToken = { USB_TOKEN },
    )

    private fun req(
        method: String, path: String, body: String = "", token: String? = TOKEN,
        remote: InetAddress = LOOPBACK, headers: Map<String, String> = emptyMap(), query: String = "",
    ) = HttpRequest(
        method = method, path = path, query = query,
        headers = (if (token != null) mapOf("authorization" to "Bearer $token") else emptyMap()) +
            (if (body.isNotEmpty()) mapOf("content-type" to "application/json") else emptyMap()) + headers,
        body = body.toByteArray(), remote = remote,
    )

    private fun json(text: ByteArray) = Json.parseToJsonElement(text.toString(Charsets.UTF_8)).jsonObject

    // ---- 鉴权 ----------------------------------------------------------------

    @Test fun browserRequestsAreRejected() {
        val r = bridge().handle(req("GET", TaskApi.ROOT, headers = mapOf("origin" to "https://evil.example")))
        assertEquals(403, r.status)
    }

    @Test fun missingTokenIsUnauthorized() {
        val r = bridge().handle(req("GET", TaskApi.ROOT, token = null))
        assertEquals(401, r.status)
        assertEquals("Bearer", r.headers["WWW-Authenticate"])
    }

    @Test fun fiveFailuresLockTheSourceEvenForTheCorrectToken() {
        var now = 1_000L
        val b = bridge(clock = { now })
        repeat(5) { assertEquals(401, b.handle(req("GET", TaskApi.ROOT, token = "wrong-token")).status) }
        // 冷却期内正确令牌也不放行：放行等于告诉猜的人「这回猜对了」
        val locked = b.handle(req("GET", TaskApi.ROOT))
        assertEquals(429, locked.status)
        assertNotNull(locked.headers["Retry-After"])
        now += 61_000
        assertEquals(200, b.handle(req("GET", TaskApi.ROOT)).status)
    }

    @Test fun usbTokenOnlyWorksFromLoopback() {
        val b = bridge()
        assertEquals(200, b.handle(req("GET", TaskApi.ROOT, token = USB_TOKEN)).status)
        assertEquals(401, b.handle(req("GET", TaskApi.ROOT, token = USB_TOKEN, remote = LAN)).status)
        assertEquals(200, b.handle(req("GET", TaskApi.ROOT, token = TOKEN, remote = LAN)).status)
    }

    @Test fun mcpRejectionsAreJsonRpcShaped() {
        val r = bridge().handle(req("GET", "/mcp", token = null))
        assertEquals(401, r.status)
        assertEquals("2.0", json(r.body)["jsonrpc"]?.jsonPrimitive?.content)
    }

    // ---- 任务 API ------------------------------------------------------------

    @Test fun capabilitiesAndLimits() {
        val body = json(bridge().handle(req("GET", TaskApi.ROOT)).body)
        assertEquals(1, body["api_version"]?.jsonPrimitive?.content?.toInt())
        assertEquals("test-1", body["server_version"]?.jsonPrimitive?.content)
        assertEquals(50, body["limits"]?.jsonObject?.get("max_wait_s")?.jsonPrimitive?.content?.toInt())
        assertFalse(body["capabilities"].toString().contains("history"))
    }

    @Test fun submitThenReadWaitSteerCancel() {
        val tasks = FakeTasks()
        val b = bridge(tasks)
        val created = b.handle(req("POST", "${TaskApi.ROOT}/tasks", """{"goal":"order coffee"}"""))
        assertEquals(201, created.status)
        val taskId = json(created.body)["task_id"]!!.jsonPrimitive.content
        assertEquals("running", json(created.body)["status"]!!.jsonPrimitive.content)

        assertEquals(200, b.handle(req("GET", "${TaskApi.ROOT}/tasks/$taskId")).status)

        val steered = b.handle(req("POST", "${TaskApi.ROOT}/tasks/$taskId/steer", """{"text":"small cup"}"""))
        assertEquals(202, steered.status)
        assertEquals("m1", json(steered.body)["message_id"]!!.jsonPrimitive.content)

        // 问一句就走：状态没变时 changed 为 false，不会把超时当失败
        val waited = b.handle(req("POST", "${TaskApi.ROOT}/tasks/$taskId/wait", """{"timeout_s":1}"""))
        assertEquals(200, waited.status)
        assertFalse(json(waited.body)["changed"]!!.jsonPrimitive.content.toBoolean())

        val cancelled = b.handle(req("POST", "${TaskApi.ROOT}/tasks/$taskId/cancel", "{}"))
        assertEquals(202, cancelled.status)
        assertEquals(RemoteTaskState.Cancelled, tasks.get(taskId)!!.state)
    }

    @Test fun waitingOnPhoneCannotBeAnsweredOrSteered() {
        val tasks = FakeTasks()
        val b = bridge(tasks)
        val created = b.handle(req("POST", "${TaskApi.ROOT}/tasks", """{"goal":"pay the bill"}"""))
        val taskId = json(created.body)["task_id"]!!.jsonPrimitive.content
        tasks.setState(taskId, RemoteTaskState.WaitingOnPhone, RemoteTaskDetail(waitingFor = "confirmation", app = "Bank"))

        val answered = b.handle(req("POST", "${TaskApi.ROOT}/tasks/$taskId/answer", """{"text":"yes"}"""))
        assertEquals(409, answered.status)
        val steered = b.handle(req("POST", "${TaskApi.ROOT}/tasks/$taskId/steer", """{"text":"go ahead"}"""))
        assertEquals(409, steered.status)

        val status = json(b.handle(req("GET", "${TaskApi.ROOT}/tasks/$taskId")).body)
        assertEquals("waiting_on_phone", status["status"]!!.jsonPrimitive.content)
        assertNotNull(status["note"])
    }

    @Test fun answerOnlyWhenWaitingForAnswer() {
        val tasks = FakeTasks()
        val b = bridge(tasks)
        val created = b.handle(req("POST", "${TaskApi.ROOT}/tasks", """{"goal":"pick a seat"}"""))
        val taskId = json(created.body)["task_id"]!!.jsonPrimitive.content
        tasks.setState(taskId, RemoteTaskState.WaitingForAnswer, RemoteTaskDetail(question = "Window or aisle?"))
        assertEquals(200, b.handle(req("POST", "${TaskApi.ROOT}/tasks/$taskId/answer", """{"text":"window"}""")).status)
        assertEquals(409, b.handle(req("POST", "${TaskApi.ROOT}/tasks/$taskId/answer", """{"text":"again"}""")).status)
    }

    @Test fun listAndPaginationBounds() {
        val b = bridge()
        repeat(3) { b.handle(req("POST", "${TaskApi.ROOT}/tasks", """{"goal":"task $it"}""")) }
        val page = json(b.handle(req("GET", "${TaskApi.ROOT}/tasks", query = "limit=2")).body)
        assertEquals(2, (page["tasks"] as kotlinx.serialization.json.JsonArray).size)
        assertEquals(400, b.handle(req("GET", "${TaskApi.ROOT}/tasks", query = "limit=99")).status)
        assertEquals(400, b.handle(req("GET", "${TaskApi.ROOT}/tasks", query = "nope=1")).status)
    }

    @Test fun protocolNits() {
        val b = bridge()
        assertEquals(415, b.handle(req("POST", "${TaskApi.ROOT}/tasks", """{"goal":"x"}""", headers = mapOf("content-type" to "text/plain"))).status)
        assertEquals(405, b.handle(req("POST", TaskApi.ROOT)).status)
        assertEquals(404, b.handle(req("GET", "${TaskApi.ROOT}/nope")).status)
        assertEquals(400, b.handle(req("POST", "${TaskApi.ROOT}/tasks", """{"goal":"x","extra":1}""")).status)
        assertEquals(400, b.handle(req("POST", "${TaskApi.ROOT}/tasks", """{"goal":""}""")).status)
        assertEquals(400, b.handle(req("POST", "${TaskApi.ROOT}/tasks", """{"goal":"x","request_id":"not-a-uuid"}""")).status)
        assertEquals(400, b.handle(req("POST", "${TaskApi.ROOT}/tasks", """{"goal":"x","conversation":"mcp-nope"}""")).status)
    }

    @Test fun exportAndFilesAreAbsentWhenUnsupported() {
        val b = bridge()
        val created = b.handle(req("POST", "${TaskApi.ROOT}/tasks", """{"goal":"x"}"""))
        val taskId = json(created.body)["task_id"]!!.jsonPrimitive.content
        assertEquals(404, b.handle(req("GET", "${TaskApi.ROOT}/tasks/$taskId/export")).status)
        // 没接附件能力：上传入口按「不支持」拒绝，而不是假装成功
        assertEquals(404, b.handle(req("POST", "${TaskApi.ROOT}/uploads", """{"name":"a.txt","size":10}""")).status)
    }

    // ---- MCP -----------------------------------------------------------------

    private val initBody = """{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"probe"}}}"""

    @Test fun legacyHandshakeThenToolsList() {
        val b = bridge()
        val init = b.handle(req("POST", "/mcp", initBody))
        assertEquals(200, init.status)
        assertEquals("2025-06-18", json(init.body)["result"]!!.jsonObject["protocolVersion"]!!.jsonPrimitive.content)

        val list = b.handle(req("POST", "/mcp", """{"jsonrpc":"2.0","id":2,"method":"tools/list"}"""))
        val names = json(list.body)["result"]!!.jsonObject["tools"].toString()
        assertTrue(names.contains("mika_run_task"))
        assertTrue(names.contains("mika_wait_task"))
        assertFalse(names.contains("mika_unlock_device")) // 没接设备能力就不该出现
    }

    @Test fun modernCallsRequireMatchingHeaders() {
        val b = bridge()
        val meta = "\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\"," +
            "\"io.modelcontextprotocol/clientCapabilities\":{}}"
        val body = """{"jsonrpc":"2.0","id":7,"method":"tools/list","params":{$meta}}"""
        val headers = mapOf(
            "mcp-protocol-version" to "2026-07-28",
            "mcp-method" to "tools/list",
            "accept" to "application/json",
        )
        val ok = b.handle(req("POST", "/mcp", body, headers = headers))
        assertEquals(200, ok.status)
        assertEquals("complete", json(ok.body)["result"]!!.jsonObject["resultType"]!!.jsonPrimitive.content)
        assertEquals("300000", json(ok.body)["result"]!!.jsonObject["ttlMs"]!!.jsonPrimitive.content)

        val mismatched = b.handle(req("POST", "/mcp", body, headers = headers + ("mcp-method" to "tools/call")))
        assertEquals(400, mismatched.status)

        val missing = b.handle(req("POST", "/mcp", body, headers = headers - "mcp-method"))
        assertEquals(400, missing.status)
    }

    @Test fun modernToolCallRoundTrip() {
        val b = bridge()
        val meta = "\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\"," +
            "\"io.modelcontextprotocol/clientCapabilities\":{}}"
        val body = """{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{$meta,"name":"mika_run_task","arguments":{"goal":"book a table"}}}"""
        val r = b.handle(
            req(
                "POST", "/mcp", body,
                headers = mapOf(
                    "mcp-protocol-version" to "2026-07-28",
                    "mcp-method" to "tools/call",
                    "mcp-name" to "mika_run_task",
                ),
            ),
        )
        assertEquals(200, r.status)
        val result = json(r.body)["result"]!!.jsonObject
        assertEquals("false", result["isError"]!!.jsonPrimitive.content)
        val structured = result["structuredContent"]!!.jsonObject
        assertEquals("running", structured["status"]!!.jsonPrimitive.content)
        assertEquals("task-1", structured["task_id"]!!.jsonPrimitive.content)
    }

    @Test fun unknownToolIsAProtocolError() {
        val b = bridge()
        val r = b.handle(req("POST", "/mcp", """{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"nope","arguments":{}}}"""))
        // 工具名不认得属于协议错误（参数结构就不对），不是工具执行失败。
        // 老一代握手路径按 JSON-RPC 的惯例把这类错误放在 HTTP 200 的 error 里。
        assertEquals(200, r.status)
        assertEquals("-32602", json(r.body)["error"]!!.jsonObject["code"]!!.jsonPrimitive.content)
    }

    @Test fun badArgumentsAreToolErrors() {
        val b = bridge()
        val r = b.handle(req("POST", "/mcp", """{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"mika_run_task","arguments":{"goal":123}}}"""))
        assertEquals(200, r.status)
        assertEquals("true", json(r.body)["result"]!!.jsonObject["isError"]!!.jsonPrimitive.content)
    }

    @Test fun mcpTransportRejections() {
        val b = bridge()
        assertEquals(405, b.handle(req("GET", "/mcp")).status)
        assertEquals(415, b.handle(req("POST", "/mcp", """{"jsonrpc":"2.0","id":1,"method":"ping"}""", headers = mapOf("content-type" to "text/plain"))).status)
        assertEquals(400, b.handle(req("POST", "/mcp", "{oops")).status)
        assertEquals(400, b.handle(req("POST", "/mcp", "[]")).status)
        assertEquals(400, b.handle(req("POST", "/mcp", """{"jsonrpc":"1.0","id":1,"method":"ping"}""")).status)
        // 通知：收下，不回内容
        assertEquals(202, b.handle(req("POST", "/mcp", """{"jsonrpc":"2.0","method":"notifications/initialized"}""")).status)
    }

    // ---- 监听范围 ------------------------------------------------------------

    @Test fun listenScopeDecidesAccept() {
        assertTrue(RemoteBridge.accepts(ListenScope.LoopbackOnly, LOOPBACK, LOOPBACK))
        assertFalse(RemoteBridge.accepts(ListenScope.LoopbackOnly, LAN, LAN))
        assertTrue(RemoteBridge.accepts(ListenScope.PrivateNetworks, LAN, LAN))
        assertFalse(RemoteBridge.accepts(ListenScope.PrivateNetworks, LAN, INTERNET))
        assertFalse(RemoteBridge.accepts(ListenScope.Off, LOOPBACK, LOOPBACK))
    }

    @Test fun bindsOnlyOnLoopbackWhenAsking() {
        val b = bridge()
        b.start()
        try {
            assertTrue(b.state.value is BridgeState.Listening)
            assertTrue(b.boundPort > 0)
        } finally {
            b.stop()
        }
        assertEquals(BridgeState.Off, b.state.value)
    }
}
