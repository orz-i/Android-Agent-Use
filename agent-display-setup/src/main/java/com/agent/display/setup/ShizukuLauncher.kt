package com.agent.display.setup

import android.content.Context
import android.os.Process
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream

/**
 * 基于 Shizuku / Sui 规范的免命令拉起器。
 *
 * 通过 Shizuku 的特权进程创建能力执行 app_process，将 agent-display-server 作为独立守护进程拉起。
 */
class ShizukuLauncher(private val context: Context) {

    companion object {
        private const val TAG = "ShizukuLauncher"
        const val SERVER_JAR_PATH = "/data/local/tmp/agent-display-server.jar"
        const val SERVER_CLASS = "com.agent.display.server.AgentServerMain"
    }

    /**
     * 将 assets/agent-display-server.jar 释放并推送到 /data/local/tmp/，然后通过 Shizuku 拉起
     *
     * @param token 握手安全令牌
     * @return 是否成功拉起守护进程
     */
    suspend fun launch(token: String): Result<Boolean> = withContext(Dispatchers.IO) {
        runCatching {
            // 1. 确保服务端 JAR 已放置在 /data/local/tmp/
            deployServerJar()

            val packageName = context.packageName
            val uid = Process.myUid()

            val cmd = arrayOf(
                "sh", "-c",
                "CLASSPATH=$SERVER_JAR_PATH nohup setsid app_process /system/bin " +
                        "--nice-name=agent_display_server $SERVER_CLASS " +
                        "$packageName $uid $token provider >/dev/null 2>&1 &"
            )

            Log.i(TAG, "Launching server via Shizuku: ${cmd[2]}")

            val shizukuClass = Class.forName("moe.shizuku.api.Shizuku")
            val newProcessMethod = shizukuClass.getMethod(
                "newProcess",
                Array<String>::class.java,
                Array<String>::class.java,
                String::class.java
            )

            val proc = newProcessMethod.invoke(null, cmd, null, null) as java.lang.Process
            val exitCode = proc.waitFor()
            if (exitCode != 0) {
                val err = proc.errorStream.bufferedReader().readText()
                error("Shizuku newProcess exited with code $exitCode: $err")
            }

            Log.i(TAG, "agent-display-server successfully detached and launched via Shizuku")
            true
        }
    }

    /**
     * 尝试将 assets 里的 server.jar 写入内部存储或临时文件，并通过 shell 拷入 /data/local/tmp
     */
    private fun deployServerJar() {
        val assetName = "agent-display-server.jar"
        val internalFile = File(context.cacheDir, assetName)

        runCatching {
            context.assets.open(assetName).use { input ->
                FileOutputStream(internalFile).use { output ->
                    input.copyTo(output)
                }
            }
            internalFile.setReadable(true, false)

            // 如果已在 /data/local/tmp 且相同大小则无需重写
            val target = File(SERVER_JAR_PATH)
            if (target.exists() && target.length() == internalFile.length()) {
                return
            }

            // 通过 Shizuku 复制文件到 /data/local/tmp
            val shizukuClass = Class.forName("moe.shizuku.api.Shizuku")
            val newProcessMethod = shizukuClass.getMethod(
                "newProcess",
                Array<String>::class.java,
                Array<String>::class.java,
                String::class.java
            )
            val cpCmd = arrayOf("cp", internalFile.absolutePath, SERVER_JAR_PATH)
            val p = newProcessMethod.invoke(null, cpCmd, null, null) as java.lang.Process
            p.waitFor()

            val chmodCmd = arrayOf("chmod", "644", SERVER_JAR_PATH)
            (newProcessMethod.invoke(null, chmodCmd, null, null) as java.lang.Process).waitFor()
        }.onFailure {
            Log.w(TAG, "deployServerJar notice: ${it.message}. Assuming jar already pre-deployed at $SERVER_JAR_PATH")
        }
    }
}
