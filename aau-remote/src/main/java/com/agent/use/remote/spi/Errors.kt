package com.agent.use.remote.spi

/** 远程入口共用的业务错误；HTTP 状态和 MCP isError 由各自适配器决定。 */
sealed class RemoteTaskError(val code: Code, message: String) : Exception(message) {
    enum class Code { INVALID_ARGUMENT, NOT_FOUND, GONE, CONFLICT, UNAVAILABLE }

    class General(code: Code, message: String) : RemoteTaskError(code, message)

    class NoSuchTask(val id: String) : RemoteTaskError(Code.NOT_FOUND, "No remote task with id $id")

    class NoSuchRecord(val id: String) : RemoteTaskError(Code.NOT_FOUND, "No remote task or run record with id $id")

    class BadConversation : RemoteTaskError(
        Code.INVALID_ARGUMENT,
        "conversation must be one returned by an earlier remote task (looks like mcp-<uuid>)",
    )

    class NeedsPhone : RemoteTaskError(Code.CONFLICT, RemoteStatus.ON_PHONE_NOTE)

    class QuestionClosed : RemoteTaskError(Code.CONFLICT, "The question is no longer open; check the task's status.")
}
