package com.agent.use.server

import android.annotation.SuppressLint
import android.app.ActivityOptions
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.util.Log
import com.agent.use.common.shell.AgentShellEngine
import com.agent.use.common.shell.ColdStart
import com.agent.use.common.shell.MainScreenLog
import com.agent.use.common.shell.MainScreenWatch
import com.agent.use.common.shell.ShareIntent
import com.agent.use.common.shell.ShellLinks

@SuppressLint("PrivateApi")
class TaskManagerFacade(
    private val context: Context,
    private val ownDisplay: (displayId: Int) -> Boolean,
    private val execCmd: ShellExecutor,
) {
    companion object {
        private const val TAG = "TaskManagerFacade"
        private const val MAX_TASKS = 100
        private val TASK_INFO: Class<*> by lazy { Class.forName("android.app.TaskInfo") }
    }

    val taskManager: Any by lazy {
        Class.forName("android.app.ActivityTaskManager").getMethod("getService").invoke(null)!!
    }

    private val mainScreenWatch: MainScreenWatch by lazy {
        MainScreenWatch(
            taskManager = { taskManager },
            tasks = ::mainLogTasks,
            tag = TAG,
        )
    }

    data class RecordedArrival(
        val taskId: Int,
        val packageName: String,
        val userId: Int,
        val uptimeMs: Long,
    )

    @Deprecated("Handled automatically by MainScreenWatch", ReplaceWith("watchMainScreen(windowMs)"))
    fun recordMainArrival(taskId: Int, packageName: String, userId: Int) {
        // Kept for binary/source compatibility; MainScreenWatch records arrivals via ITaskStackListener.
    }

    fun watchMainScreen(windowMs: Int): Int = mainScreenWatch.watch(windowMs)

    fun mainArrivals(sinceUptimeMs: Long): Bundle = mainScreenWatch.arrivals(sinceUptimeMs)

    fun allTasks(): List<Any> = runCatching {
        val method = taskManager.javaClass.methods.first {
            it.name == "getTasks" && it.parameterTypes.size >= 3
        }
        val result = if (method.parameterTypes.size == 3) {
            method.invoke(taskManager, MAX_TASKS, false, false)
        } else {
            method.invoke(taskManager, MAX_TASKS, false, false, 0)
        }
        (result as? List<*>)?.filterNotNull() ?: emptyList()
    }.getOrElse {
        Log.w(TAG, "getTasks failed", it)
        emptyList()
    }

    fun tasksOn(displayId: Int): List<Any> =
        allTasks().filter { runCatching { TASK_INFO.getField("displayId").getInt(it) == displayId }.getOrDefault(false) }

    fun topTaskId(displayId: Int): Int =
        tasksOn(displayId).firstOrNull()?.let { runCatching { TASK_INFO.getField("taskId").getInt(it) }.getOrNull() } ?: -1

    fun topActivity(displayId: Int): String? =
        tasksOn(displayId).firstOrNull()?.let {
            runCatching {
                (TASK_INFO.getField("topActivity").get(it) as? ComponentName)?.className
            }.getOrNull()
        }

    fun packageOfTask(taskId: Int): String? =
        allTasks().firstOrNull { runCatching { TASK_INFO.getField("taskId").getInt(it) == taskId }.getOrDefault(false) }
            ?.let {
                runCatching {
                    (TASK_INFO.getField("topActivity").get(it) as? ComponentName)?.packageName
                }.getOrNull()
            }

    fun displayOfTask(taskId: Int): Int =
        allTasks().firstOrNull { runCatching { TASK_INFO.getField("taskId").getInt(it) == taskId }.getOrDefault(false) }
            ?.let { runCatching { TASK_INFO.getField("displayId").getInt(it) }.getOrNull() } ?: -1

    fun displayOfPackage(packageName: String, userId: Int? = null): Int =
        allTasks().firstOrNull {
            runCatching {
                val pkgs = taskPackages(it)
                val u = TASK_INFO.getField("userId").getInt(it)
                AgentShellEngine.sameCopy(pkgs, u, packageName, userId)
            }.getOrDefault(false)
        }?.let { runCatching { TASK_INFO.getField("displayId").getInt(it) }.getOrNull() } ?: -1

    fun userOfTask(taskId: Int): Int =
        allTasks().firstOrNull { runCatching { TASK_INFO.getField("taskId").getInt(it) == taskId }.getOrDefault(false) }
            ?.let { runCatching { TASK_INFO.getField("userId").getInt(it) }.getOrNull() } ?: -1

    fun visibleOnMainScreen(packageName: String, userId: Int): Boolean =
        tasksOn(MainScreenLog.MAIN).any {
            runCatching {
                val pkgs = taskPackages(it)
                val u = TASK_INFO.getField("userId").getInt(it)
                AgentShellEngine.sameCopy(pkgs, u, packageName, userId)
            }.getOrDefault(false)
        }

    fun moveTask(taskId: Int, displayId: Int): Boolean = try {
        val method = taskManager.javaClass.methods.firstOrNull {
            it.name == "moveRootTaskToDisplay" && it.parameterTypes.size == 2
        } ?: taskManager.javaClass.methods.first {
            it.name == "moveTaskToDisplay" && it.parameterTypes.size == 2
        }
        method.invoke(taskManager, taskId, displayId)
        true
    } catch (t: Throwable) {
        Log.w(TAG, "moveTask $taskId to $displayId failed, trying fallback am", t)
        execCmd.exec("am", "display", "move-task", "$taskId", "$displayId").first == 0
    }

    /** 启动应用到虚拟屏 */
    fun startApp(displayId: Int, packageName: String, userId: Int): Int {
        if (!ownDisplay(displayId)) return AgentShellEngine.START_ERROR
        if (visibleOnMainScreen(packageName, userId)) return AgentShellEngine.START_IN_USE_ON_MAIN

        val pm = context.packageManager
        val intent = pm.getLaunchIntentForPackage(packageName) ?: return AgentShellEngine.START_NOT_FOUND
        return startIntent(displayId, intent)
    }

    /** 冷启动应用（按 ColdStart 策略避免误杀其他屏幕上的同副本） */
    fun restartApp(displayId: Int, packageName: String, userId: Int): Int {
        if (!ownDisplay(displayId)) return AgentShellEngine.START_ERROR
        val displays = allTasks().mapNotNull { t ->
            runCatching {
                val pkgs = taskPackages(t)
                val u = TASK_INFO.getField("userId").getInt(t)
                if (AgentShellEngine.sameCopy(pkgs, u, packageName, userId)) TASK_INFO.getField("displayId").getInt(t) else null
            }.getOrNull()
        }
        return when (ColdStart.decide(displays, displayId, visibleOnMainScreen(packageName, userId))) {
            ColdStart.IN_USE -> AgentShellEngine.START_IN_USE_ON_MAIN
            ColdStart.WARM -> startApp(displayId, packageName, userId)
            ColdStart.RESTART -> {
                execCmd.exec("am", "force-stop", "--user", "$userId", packageName)
                startApp(displayId, packageName, userId)
            }
        }
    }

    /** 启动 Intent */
    fun startIntent(displayId: Int, intent: Intent): Int = try {
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        val options = ActivityOptions.makeBasic().apply {
            val setDisplay = ActivityOptions::class.java.getMethod("setLaunchDisplayId", Int::class.javaPrimitiveType)
            setDisplay.invoke(this, displayId)
        }.toBundle()

        context.startActivity(intent, options)
        AgentShellEngine.START_OK
    } catch (t: Throwable) {
        Log.w(TAG, "startIntent failed", t)
        AgentShellEngine.START_ERROR
    }

    /** 打开 URI */
    fun startView(displayId: Int, action: String?, uri: String?, packageName: String?): Int {
        ShellLinks.refuse(action, uri, packageName)?.let { return it }
        val intent = Intent(action ?: Intent.ACTION_VIEW).apply {
            if (uri != null) data = Uri.parse(uri)
            if (packageName != null) setPackage(packageName)
        }
        return startIntent(displayId, intent)
    }

    /** 文本分享 */
    fun startShare(displayId: Int, packageName: String, text: String): Int =
        startIntent(displayId, ShareIntent.of(packageName, text))

    /** 优雅完成并清理虚拟屏上的任务 */
    fun finishDisplay(displayId: Int, keepPackages: Array<String>?, closePackages: Array<String>?): Bundle {
        val b = Bundle()
        val keptList = mutableListOf<String>()
        val closedList = mutableListOf<String>()

        val tasks = tasksOn(displayId)
        for (task in tasks) {
            val taskId = runCatching { TASK_INFO.getField("taskId").getInt(task) }.getOrNull() ?: continue
            val pkg = runCatching { (TASK_INFO.getField("topActivity").get(task) as? ComponentName)?.packageName }.getOrNull() ?: continue

            if (keepPackages != null && pkg in keepPackages) {
                moveTask(taskId, 0)
                keptList.add(pkg)
            } else if (closePackages != null && pkg in closePackages) {
                execCmd.exec("am", "force-stop", pkg)
                closedList.add(pkg)
            }
        }
        b.putStringArray("kept", keptList.toTypedArray())
        b.putStringArray("closed", closedList.toTypedArray())
        b.putString("note", "Cleaned up display $displayId")
        return b
    }

    private fun mainLogTasks(): List<MainScreenLog.Task> = allTasks().mapNotNull { t ->
        runCatching {
            val top = TASK_INFO.getField("topActivity").get(t) as? ComponentName
            val base = runCatching { TASK_INFO.getField("baseActivity").get(t) as? ComponentName }.getOrNull()
            MainScreenLog.Task(
                taskId = TASK_INFO.getField("taskId").getInt(t),
                displayId = TASK_INFO.getField("displayId").getInt(t),
                packageName = top?.packageName ?: base?.packageName,
                userId = TASK_INFO.getField("userId").getInt(t),
                topActivity = top?.className,
            )
        }.getOrNull()
    }

    private fun taskPackages(task: Any): List<String> = listOfNotNull(
        runCatching { (TASK_INFO.getField("topActivity").get(task) as? ComponentName)?.packageName }.getOrNull(),
        runCatching { (TASK_INFO.getField("baseActivity").get(task) as? ComponentName)?.packageName }.getOrNull(),
    )
}
