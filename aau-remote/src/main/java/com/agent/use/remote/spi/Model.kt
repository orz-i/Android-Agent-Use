package com.agent.use.remote.spi

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import java.security.MessageDigest

/**
 * 远端（电脑或外部编排器）看到的一个任务。
 *
 * [state] 为 null 表示已受理、宿主还没把它登记上（马上就会有）。[detail] 是宿主可选的补充说明，
 * 只用于让远端看懂「现在卡在哪」，不参与任何判断——判断一律看 [state]。
 */
data class RemoteTask(
    val id: String,
    val conversation: String,
    val goal: String,
    val createdAtMs: Long,
    val state: RemoteTaskState?,
    val steers: List<RemoteSteer> = emptyList(),
    val runId: String? = null,
    val files: List<RemoteFile> = emptyList(),
    /** 访问令牌的不可逆摘要；只用于归属判断，从不出现在响应里。 */
    val owner: String? = null,
    val detail: RemoteTaskDetail? = null,
)

/**
 * 对外只有这 9 个状态。映射的关键是「要不要人」：付款、确认、接管一律落到 [WaitingOnPhone]，
 * 因为这几步只能由人在手机上做完。
 */
enum class RemoteTaskState {
    Starting, Running, Queued, Paused, WaitingForAnswer, WaitingOnPhone, Done, Failed, Cancelled;

    val finished: Boolean get() = this == Done || this == Failed || this == Cancelled
}

/**
 * 宿主对任务状态的补充说明。字段都由宿主决定填不填，AAU 只负责按协议放进响应里。
 * 全部是可选的，缺字段就不输出——契约里这些字段本来就是可缺的。
 */
data class RemoteTaskDetail(
    /** 运行到第几步（仅 [RemoteTaskState.Running]）。 */
    val step: Int? = null,
    /** 进度说明，一句话，给远端看。 */
    val progress: String? = null,
    /** 在等什么，宿主自己的代码（`confirmed`、`network` 之类）。 */
    val waitingFor: String? = null,
    /** 宿主提的问题（仅 [RemoteTaskState.WaitingForAnswer]）。 */
    val question: String? = null,
    val options: List<String> = emptyList(),
    /** 需要确认时是哪个 App。 */
    val app: String? = null,
    /** 需要接管或失败的原因原文。 */
    val reason: String? = null,
    /** 需要接管时给用户看的那句话。 */
    val message: String? = null,
    val answer: String? = null,
    val verified: Boolean? = null,
    val verificationNote: String? = null,
    val unconfirmed: List<String> = emptyList(),
    val failureReason: String? = null,
    val failureKind: String? = null,
    /** 覆盖默认提示语；不填时由 AAU 按状态给标准说法。 */
    val note: String? = null,
)

data class RemoteTaskPage(val tasks: List<RemoteTask>, val nextBefore: String? = null)

/** 只报告电脑追加的消息；joined 表示进入当前任务上下文，不是执行成功。 */
data class RemoteSteer(val messageId: String, val state: String)

sealed interface StartOutcome {
    data class Started(val task: RemoteTask) : StartOutcome
    data class Refused(val message: String) : StartOutcome
}

/** 访问令牌只以 SHA-256 摘要进入任务层；接口、日志和导出都不保存或暴露原令牌。 */
object RemoteOwnership {
    const val UNSCOPED = "unscoped"

    /** USB 任务随本机连接方式保留，认证仍使用当前开机生成的令牌。 */
    const val USB = "usb"

    fun of(token: String): String = MessageDigest.getInstance("SHA-256").digest(token.toByteArray(Charsets.UTF_8))
        .joinToString("") { "%02x".format(it.toInt() and 0xff) }
}

/**
 * 宿主 Agent 的任务出入口。[scope] 是每次已认证请求的唯一归属入口；HTTP 与 MCP 都必须使用它，
 * 使同一个访问令牌才能读、改、上传、下载或导出自己创建的任务。
 *
 * 实现方负责：按 [scope] 隔离数据、把宿主自己的状态映射成 [RemoteTaskState]、权威判定谁能回答谁不能。
 */
interface RemoteTaskPort {
    val fileAccess: RemoteFileAccess? get() = null

    fun scope(owner: String): RemoteTaskPort = this

    fun start(goal: String, conversation: String?, requestId: String? = null, attachments: List<String> = emptyList()): StartOutcome

    fun get(id: String): RemoteTask?

    /** 新的在前。 */
    fun list(limit: Int): List<RemoteTask>

    /** 稳定的游标页；不支持游标的实现仍可按原有列表工作。 */
    fun page(limit: Int, before: String? = null): RemoteTaskPage = RemoteTaskPage(list(limit))

    /** 只在任务正等着回答追问时调用；交给任务时返回 true。 */
    fun answer(id: String, text: String): Boolean

    /** 原子确认消息进入当前任务的收件箱；不能转成新任务。返回消息编号，拒绝为 null。 */
    fun steer(id: String, text: String): String?

    fun cancel(id: String): Boolean
}

/** 任务状态对远端的说法；只读任务自己的状态，不另记。 */
object RemoteStatus {
    const val STARTING = "starting"
    const val RUNNING = "running"
    const val QUEUED = "queued"
    const val PAUSED = "paused"
    const val WAITING_FOR_ANSWER = "waiting_for_answer"
    const val WAITING_ON_PHONE = "waiting_on_phone"
    const val DONE = "done"
    const val FAILED = "failed"
    const val CANCELLED = "cancelled"

    const val ON_PHONE_NOTE = "This step needs the user on the phone and cannot be answered remotely. " +
        "The phone has shown its usual notification there; keep waiting or cancel the task."

    fun of(state: RemoteTaskState?): String = when (state) {
        null, RemoteTaskState.Starting -> STARTING
        RemoteTaskState.Running -> RUNNING
        RemoteTaskState.Queued -> QUEUED
        RemoteTaskState.Paused -> PAUSED
        RemoteTaskState.WaitingForAnswer -> WAITING_FOR_ANSWER
        RemoteTaskState.WaitingOnPhone -> WAITING_ON_PHONE
        RemoteTaskState.Done -> DONE
        RemoteTaskState.Failed -> FAILED
        RemoteTaskState.Cancelled -> CANCELLED
    }

    fun finished(status: String) = status == DONE || status == FAILED || status == CANCELLED

    /** 一个任务此刻的样子：状态、最近的进度说明、等什么、结果。 */
    fun describe(t: RemoteTask): JsonObject = buildJsonObject {
        val status = of(t.state)
        val d = t.detail
        put("task_id", t.id)
        put("status", status)
        put("conversation", t.conversation)
        put("goal", t.goal)
        put("started_at_ms", t.createdAtMs)
        t.runId?.let { put("run_id", it) }
        when (t.state) {
            RemoteTaskState.Running -> {
                d?.step?.let { put("step", it) }
                d?.progress?.takeIf { it.isNotBlank() }?.let { put("progress", it) }
            }
            RemoteTaskState.Queued, RemoteTaskState.Paused, RemoteTaskState.WaitingOnPhone -> {
                d?.waitingFor?.let { put("waiting_for", it) }
                d?.progress?.takeIf { it.isNotBlank() }?.let { put("progress", it) }
                d?.app?.let { put("app", it) }
                d?.reason?.takeIf { it.isNotBlank() }?.let { put("reason", it) }
                d?.message?.takeIf { it.isNotBlank() }?.let { put("message", it) }
                if (t.state == RemoteTaskState.WaitingOnPhone) put("note", d?.note ?: ON_PHONE_NOTE)
                else d?.note?.let { put("note", it) }
            }
            RemoteTaskState.WaitingForAnswer -> {
                d?.question?.let { put("question", it) }
                d?.options?.takeIf { it.isNotEmpty() }?.let { o -> putJsonArray("options") { o.forEach { add(it) } } }
                put("note", d?.note ?: "The phone is asking a question. Answer this question remotely or on the phone.")
            }
            RemoteTaskState.Done -> {
                d?.answer?.let { put("answer", it) }
                d?.verified?.let { put("verified", it) }
                d?.verificationNote?.let { put("verification_note", it) }
                d?.unconfirmed?.takeIf { it.isNotEmpty() }?.let { u -> putJsonArray("unconfirmed") { u.forEach { add(it) } } }
            }
            RemoteTaskState.Failed -> {
                d?.failureReason?.let { put("reason", it) }
                d?.failureKind?.let { put("failure_kind", it) }
            }
            null, RemoteTaskState.Starting, RemoteTaskState.Cancelled -> Unit
        }
        if (t.files.isNotEmpty()) putJsonArray("files") {
            t.files.forEach { file -> add(buildJsonObject {
                put("id", file.id); put("name", file.name); put("size", file.size)
                file.sha256?.let { put("sha256", it) }
            }) }
        }
        put("answerable", t.state == RemoteTaskState.WaitingForAnswer)
        if (t.steers.isNotEmpty()) putJsonArray("steers") {
            t.steers.forEach { add(buildJsonObject {
                put("message_id", it.messageId); put("state", it.state)
            }) }
        }
    }
}
