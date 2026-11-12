package com.agent.use.setup

import android.content.Context
import android.os.Process
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream

/**
 * Root 权限拉起器。
 *
 * 严格使用 `su 2000 -c ...` 将执行身份切换为 Shell (UID 2000)，确保运行环境与 ADB 完全对齐。
 */
class RootLauncher(private val context: Context) {

    companion object {
        private const val TAG = "RootLauncher"
        const val SERVER_JAR_PATH = "/data/local/tmp/aau-server.jar"
        const val LEGACY_SERVER_JAR_PATH = "/data/local/tmp/agent-display-server.jar"
        const val SERVER_CLASS = "com.agent.use.server.AgentServerMain"
    }

    /**
     * 以 Root 权限将 server.jar 部署到 /data/local/tmp/ 并以 su 2000 启动守护进程
     */
    suspend fun launch(token: String): Result<Boolean> = withContext(Dispatchers.IO) {
        runCatching {
            deployServerJarWithRoot()

            val packageName = context.packageName
            val uid = Process.myUid()

            val jarToUse = if (File(SERVER_JAR_PATH).exists() || !File(LEGACY_SERVER_JAR_PATH).exists()) {
                SERVER_JAR_PATH
            } else {
                LEGACY_SERVER_JAR_PATH
            }

            val innerCmd = "CLASSPATH=$jarToUse nohup setsid app_process /system/bin " +
                    "--nice-name=aau_server $SERVER_CLASS " +
                    "$packageName $uid $token provider >/dev/null 2>&1 &"

            val suCmd = arrayOf("su", "2000", "-c", innerCmd)
            Log.i(TAG, "Executing root launch: ${suCmd.joinToString(" ")}")

            val p = ProcessBuilder(*suCmd).redirectErrorStream(true).start()
            val exitCode = p.waitFor()
            if (exitCode != 0) {
                val err = p.inputStream.bufferedReader().readText()
                error("su command failed with exitCode $exitCode: $err")
            }

            // 检查进程是否已在后台常驻 (支持 aau_server 与 agent_display_server 双探测)
            val check = ProcessBuilder("su", "2000", "-c", "pidof aau_server || pidof agent_display_server").start()
            val pid = check.inputStream.bufferedReader().readText().trim()
            check.waitFor()

            if (pid.isNotEmpty()) {
                Log.i(TAG, "aau-server running with PID $pid via Root")
                true
            } else {
                Log.w(TAG, "Process not detected in pidof, but launch command completed successfully")
                true
            }
        }
    }

    private fun deployServerJarWithRoot() {
        val assetNames = listOf("aau-server.jar", "agent-display-server.jar")
        var deployed = false

        for (assetName in assetNames) {
            val internalFile = File(context.cacheDir, assetName)
            val ok = runCatching {
                context.assets.open(assetName).use { input ->
                    FileOutputStream(internalFile).use { output ->
                        input.copyTo(output)
                    }
                }
                internalFile.setReadable(true, false)

                val targetPath = if (assetName.startsWith("aau")) SERVER_JAR_PATH else LEGACY_SERVER_JAR_PATH
                val p = ProcessBuilder("su", "0", "-c", "cp ${internalFile.absolutePath} $targetPath && chmod 644 $targetPath").start()
                p.waitFor() == 0
            }.getOrDefault(false)

            if (ok) {
                deployed = true
                break
            }
        }

        if (!deployed) {
            Log.w(TAG, "deployServerJarWithRoot notice: No asset found. Expecting pre-deployed jar at $SERVER_JAR_PATH")
        }
    }
}
