package com.agent.display.server

/**
 * Shell 命令执行函数式接口，支持变长参数执行并返回 (exitCode, output)
 */
fun interface ShellExecutor {
    fun exec(vararg cmd: String): Pair<Int, String>
}
