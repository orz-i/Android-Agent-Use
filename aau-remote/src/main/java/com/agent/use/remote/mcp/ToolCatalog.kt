package com.agent.use.remote.mcp

import com.agent.use.remote.RemoteBrand
import com.agent.use.remote.api.TaskUseCases
import com.agent.use.remote.spi.RemoteDevicePort
import com.agent.use.remote.spi.RemoteStatus
import com.agent.use.remote.spi.RemoteTask
import com.agent.use.remote.spi.RemoteTaskError
import com.agent.use.remote.spi.RemoteTaskPort
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonObjectBuilder
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject

/**
 * 电脑能用的工具：只给高层的「把事交给手机」，具体怎么做由手机上的 Agent 自己决定。
 * 设备工具另算：它只做唤醒与解锁，凭据永远不经过这条协议。
 */
class ToolCatalog(
    private val service: TaskUseCases,
    private val brand: RemoteBrand = RemoteBrand(),
    private val device: RemoteDevicePort? = null,
) {
    constructor(tasks: RemoteTaskPort, pollMs: Long = 250, brand: RemoteBrand = RemoteBrand(), device: RemoteDevicePort? = null) :
        this(TaskUseCases(tasks, pollMs), brand, device)

    private val app = brand.appName
    private val prefix = brand.toolPrefix

    class ToolError(message: String) : Exception(message)

    data class Tool(val name: String, val description: String, val schema: JsonObject, val readOnly: Boolean)

    val RUN = "${prefix}_run_task"
    val STEER = "${prefix}_steer_task"
    val STATUS = "${prefix}_task_status"
    val WAIT = "${prefix}_wait_task"
    val ANSWER = "${prefix}_answer"
    val CANCEL = "${prefix}_cancel_task"
    val LIST = "${prefix}_list_tasks"

    val DEVICE_STATE = "${prefix}_device_state"
    val DEVICE_WAKE = "${prefix}_wake_device"
    val DEVICE_UNLOCK = "${prefix}_unlock_device"

    private val emptySchema = buildJsonObject {
        put("type", "object"); put("properties", JsonObject(emptyMap()))
        put("required", buildJsonArray {}); put("additionalProperties", false)
    }

    private val taskIdProp: JsonObject = buildJsonObject {
        put("type", "string"); put("description", "The task_id returned by $RUN.")
    }

    private fun schema(required: List<String>, props: JsonObjectBuilder.() -> Unit) = buildJsonObject {
        put("type", "object")
        putJsonObject("properties", props)
        putJsonArray("required") { required.forEach { add(it) } }
        put("additionalProperties", false)
    }

    private fun JsonObjectBuilder.taskIdProp() = put("task_id", taskIdProp)

    private val deviceTools: List<Tool> = if (device == null) emptyList() else listOf(
        Tool(
            DEVICE_STATE,
            "Read phone screen/lock state and whether local remote-unlock permission is enabled. No credentials are returned.",
            emptySchema, true,
        ),
        Tool(
            DEVICE_WAKE,
            "Wake the main phone screen. Requires the phone's remote wake/unlock setting. Does not unlock it.",
            emptySchema, false,
        ),
        Tool(
            DEVICE_UNLOCK,
            "Wake and unlock the phone using only permission and credentials configured locally on the phone. " +
                "Call before $RUN, or when a task is paused because the phone is locked. A failed credential attempt blocks further " +
                "attempts until reconfigured on the phone. Cannot approve payments or bypass authentication.",
            emptySchema, false,
        ),
    )

    val tools: List<Tool> = listOf(
        Tool(
            RUN,
            "Hand $app a task to do on the Android phone. $app runs its own agent on the phone (apps, web, files) " +
                "and records the task in a conversation the user can see in the app. Returns a task_id right away; " +
                "follow it with $WAIT. Payments and confirmations are never approved over MCP.",
            schema(required = listOf("goal")) {
                putJsonObject("goal") {
                    put("type", "string")
                    put("description", "What to get done, in plain words, as you would tell a person.")
                }
                putJsonObject("request_id") {
                    put("type", "string"); put("format", "uuid")
                    put(
                        "description",
                        "Choose a lowercase UUID before submitting. It is also the task_id for status after a lost reply. " +
                            "Reuse only for the same request.",
                    )
                }
                putJsonObject("conversation") {
                    put("type", "string")
                    put("description", "Optional: continue a conversation returned by an earlier task so $app keeps its context.")
                }
            },
            readOnly = false,
        ),
        Tool(
            STATUS,
            "Current state of a task: status, latest progress note, the question it is waiting on, or the final answer.",
            schema(required = listOf("task_id")) { taskIdProp() }, readOnly = true,
        ),
        Tool(
            WAIT,
            "Wait until the task's status changes or it finishes, up to timeout_s seconds " +
                "(default ${TaskUseCases.DEFAULT_WAIT_S}, at most ${TaskUseCases.MAX_WAIT_S}), then return its state. Call again to keep waiting.",
            schema(required = listOf("task_id")) {
                taskIdProp()
                putJsonObject("timeout_s") {
                    put("type", "integer"); put("minimum", 1); put("maximum", TaskUseCases.MAX_WAIT_S)
                    put("description", "Longest wait in seconds.")
                }
            },
            readOnly = true,
        ),
        Tool(
            ANSWER,
            "Answer the question $app asked in this task (status waiting_for_answer). " +
                "Cannot approve payments, confirmations or steps handed to the user; those stay on the phone.",
            schema(required = listOf("task_id", "text")) {
                taskIdProp()
                putJsonObject("text") { put("type", "string"); put("description", "The answer.") }
            },
            readOnly = false,
        ),
        Tool(
            STEER,
            "Add instructions to a running remote task, keeping its task_id and context. " +
                "Accepted means queued, not executed; check steers in $STATUS for the message_id. " +
                "Does not answer questions, approve payments, resume paused tasks, or start a new task.",
            schema(required = listOf("task_id", "text")) {
                taskIdProp()
                putJsonObject("text") {
                    put("type", "string"); put("minLength", 1); put("maxLength", TaskUseCases.MAX_STEER)
                }
            },
            readOnly = false,
        ),
        Tool(CANCEL, "Stop a remote task.", schema(required = listOf("task_id")) { taskIdProp() }, readOnly = false),
        Tool(
            LIST, "Recent remote tasks, newest first.",
            schema(required = emptyList()) {
                putJsonObject("limit") {
                    put("type", "integer"); put("minimum", 1); put("maximum", TaskUseCases.MAX_LIST)
                    put("description", "How many (default ${TaskUseCases.DEFAULT_LIST}).")
                }
            },
            readOnly = true,
        ),
    ) + deviceTools

    /** MCP 的工具定义（tools/list 的一项）。 */
    fun definitions(): JsonArray = buildJsonArray {
        tools.forEach { t ->
            add(buildJsonObject {
                put("name", t.name)
                put("description", t.description)
                put("inputSchema", t.schema)
                putJsonObject("annotations") {
                    put("readOnlyHint", t.readOnly)
                    if (!t.readOnly) put("destructiveHint", t.name != ANSWER)
                    put("openWorldHint", t.name == RUN || t.name == STEER)
                }
            })
        }
    }

    fun has(name: String) = tools.any { it.name == name }

    /** 只做协议参数转换和 MCP 展示；业务规则由两个入口共用的 service 执行。 */
    suspend fun call(name: String, args: JsonObject): JsonObject = try {
        when (name) {
            RUN -> {
                val requestId = if ("request_id" in args) string(args, "request_id").orEmpty() else null
                describe(service.start(string(args, "goal").orEmpty(), optString(args, "conversation"), requestId))
            }
            STATUS -> describe(service.get(taskId(args)))
            WAIT -> service.wait(taskId(args), optInt(args, "timeout_s") ?: TaskUseCases.DEFAULT_WAIT_S).let { r ->
                buildJsonObject {
                    describe(r.task).forEach { (k, v) -> put(k, v) }
                    put("changed", r.changed)
                }
            }
            ANSWER -> buildJsonObject {
                put("task_id", service.answer(taskId(args), string(args, "text").orEmpty()))
                put("accepted", true)
            }
            STEER -> service.steer(taskId(args), string(args, "text").orEmpty()).let { r ->
                buildJsonObject {
                    put("task_id", r.taskId); put("message_id", r.messageId); put("accepted", true)
                }
            }
            CANCEL -> service.cancel(taskId(args)).let { r ->
                buildJsonObject {
                    put("task_id", r.taskId); put("cancelled", r.accepted)
                    r.status?.let { put("status", it) }
                }
            }
            LIST -> buildJsonObject {
                putJsonArray("tasks") {
                    service.list(optInt(args, "limit") ?: TaskUseCases.DEFAULT_LIST).forEach { t ->
                        add(buildJsonObject {
                            put("task_id", t.id); put("status", RemoteStatus.of(t.state)); put("goal", t.goal)
                            put("conversation", t.conversation); put("started_at_ms", t.createdAtMs)
                        })
                    }
                }
            }
            DEVICE_STATE, DEVICE_WAKE, DEVICE_UNLOCK -> callDevice(name, args)
            else -> throw ToolError("Unknown tool: $name")
        }
    } catch (e: RemoteTaskError) {
        // 按错误类型换回原 MCP 客户端看到的说法（带 MCP 工具名）；共用服务不包含 MCP 命令名。
        throw ToolError(
            when (e) {
                is RemoteTaskError.NoSuchTask -> "No MCP task with id ${e.id}"
                is RemoteTaskError.NoSuchRecord -> e.message.orEmpty()
                is RemoteTaskError.BadConversation ->
                    "conversation must be one returned by an earlier MCP task (looks like mcp-<uuid>)"
                is RemoteTaskError.NeedsPhone -> onPhoneNote
                is RemoteTaskError.QuestionClosed -> "The question is no longer open; check $STATUS."
                is RemoteTaskError.General -> e.message.orEmpty()
            },
        )
    }

    private suspend fun callDevice(name: String, args: JsonObject): JsonObject {
        val port = device ?: throw ToolError("Unknown tool: $name")
        if (args.isNotEmpty()) throw ToolError("Device tools accept no arguments; configure credentials on the phone.")
        return when (name) {
            DEVICE_STATE -> port.state()
            DEVICE_WAKE -> port.wake()
            DEVICE_UNLOCK -> port.unlock()
            else -> throw ToolError("Unknown tool: $name")
        }
    }

    private fun taskId(args: JsonObject) = string(args, "task_id").orEmpty()

    private fun describe(task: RemoteTask): JsonObject = buildJsonObject {
        RemoteStatus.describe(task).forEach { (k, v) -> put(k, v) }
        when (RemoteStatus.of(task.state)) {
            RemoteStatus.WAITING_ON_PHONE -> put("note", onPhoneNote)
            RemoteStatus.WAITING_FOR_ANSWER ->
                put("note", "$app is asking a question. Reply with $ANSWER; the user can also answer on the phone.")
        }
    }

    private val onPhoneNote: String
        get() = "This step needs the user on the phone and cannot be answered over MCP. " +
            "$app has shown its usual notification there; keep waiting with $WAIT or cancel the task."

    private fun string(args: JsonObject, key: String): String? = when (val v = args[key]) {
        null, JsonNull -> null
        is JsonPrimitive -> if (v.isString) v.content else throw ToolError("$key must be a string")
        else -> throw ToolError("$key must be a string")
    }

    private fun optString(args: JsonObject, key: String) = string(args, key)

    private fun optInt(args: JsonObject, key: String): Int? = when (val v = args[key]) {
        null, JsonNull -> null
        is JsonPrimitive -> if (v.isString) throw ToolError("$key must be an integer")
        else v.intOrNull ?: v.contentOrNull?.toDoubleOrNull()?.takeIf { it % 1.0 == 0.0 && it in -1e9..1e9 }?.toInt()
        ?: throw ToolError("$key must be an integer")
        else -> throw ToolError("$key must be an integer")
    }
}
