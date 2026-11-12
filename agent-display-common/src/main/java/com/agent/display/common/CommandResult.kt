package com.agent.display.common

import android.os.Bundle

/**
 * Shell 命令执行结果契约。
 */
data class CommandResult(
    val exitCode: Int,
    val output: String,
) {
    val isSuccess: Boolean
        get() = exitCode == 0

    companion object {
        const val KEY_EXIT_CODE = "exitCode"
        const val KEY_OUTPUT = "output"

        @JvmStatic
        fun fromBundle(bundle: Bundle?): CommandResult {
            if (bundle == null) return CommandResult(-1, "Null result bundle")
            return CommandResult(
                exitCode = bundle.getInt(KEY_EXIT_CODE, -1),
                output = bundle.getString(KEY_OUTPUT).orEmpty()
            )
        }
    }
}
