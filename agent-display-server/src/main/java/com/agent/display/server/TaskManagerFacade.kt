package com.agent.display.server

import android.annotation.SuppressLint
import android.app.ActivityOptions
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.SystemClock
import android.util.Log
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList

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

    // 主屏任务变更监听与监控
    private var watchUntilUptimeMs: Long = 0L
    private val recordedArrivals = CopyOnWriteArrayList<RecordedArrival>()

    data class RecordedArrival(
        val taskId: Int,
        val packageName: String,
        val userId: Int,
        val uptimeMs: Long,
    )

    fun recordMainArrival(taskId: Int, packageName: String, userId: Int) {
        val now = SystemClock.uptimeMillis()
        if (now <= watchUntilUptimeMs) {
            recordedArrivals.add(RecordedArrival(taskId, packageName, userId, now))
        }
    }

    fun watchMainScreen(windowMs: Int): Int {
        val topTask = topTaskId(0)
        watchUntilUptimeMs = SystemClock.uptimeMillis() + windowMs
        return topTask
    }

    fun mainArrivals(sinceUptimeMs: Long): Bundle {
        val b = Bundle()
        val list = recordedArrivals.filter { it.uptimeMs >= sinceUptimeMs }
        b.putIntArray("taskIds", list.map { it.taskId }.toIntArray())
        b.putStringArray("packages", list.map { it.packageName }.toTypedArray())
        b.putIntArray("users", list.map { it.userId }.toIntArray())
        b.putLongArray("times", list.map { it.uptimeMs }.toLongArray())
        return b
    }

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
                (TASK_INFO.getField("topActivity").get(it) as? ComponentName)?.flattenToShortString()
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
                val pkg = (TASK_INFO.getField("topActivity").get(it) as? ComponentName)?.packageName
                val u = TASK_INFO.getField("userId").getInt(it)
                pkg == packageName && (userId == null || u == userId)
            }.getOrDefault(false)
        }?.let { runCatching { TASK_INFO.getField("displayId").getInt(it) }.getOrNull() } ?: -1

    fun userOfTask(taskId: Int): Int =
        allTasks().firstOrNull { runCatching { TASK_INFO.getField("taskId").getInt(it) == taskId }.getOrDefault(false) }
            ?.let { runCatching { TASK_INFO.getField("userId").getInt(it) }.getOrNull() } ?: -1

    fun visibleOnMainScreen(packageName: String, userId: Int): Boolean {
        val mainTasks = tasksOn(0)
        return mainTasks.any {
            runCatching {
                val pkg = (TASK_INFO.getField("topActivity").get(it) as? ComponentName)?.packageName
                val u = TASK_INFO.getField("userId").getInt(it)
                pkg == packageName && (userId == 0 || u == userId)
            }.getOrDefault(false)
        }
    }

    fun moveTask(taskId: Int, displayId: Int): Boolean = try {
        // 调用 IActivityTaskManager.moveRootTaskToDisplay 或 moveTaskToDisplay
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
        if (!ownDisplay(displayId)) return 3 // START_ERROR
        if (visibleOnMainScreen(packageName, userId)) return 1 // START_IN_USE_ON_MAIN

        val pm = context.packageManager
        val intent = pm.getLaunchIntentForPackage(packageName) ?: return 2 // START_NOT_FOUND
        return startIntent(displayId, intent)
    }

    /** 冷启动应用 */
    fun restartApp(displayId: Int, packageName: String, userId: Int): Int {
        if (!ownDisplay(displayId)) return 3
        if (visibleOnMainScreen(packageName, userId)) return 1

        execCmd.exec("am", "force-stop", "--user", "$userId", packageName)
        return startApp(displayId, packageName, userId)
    }

    /** 启动 Intent */
    fun startIntent(displayId: Int, intent: Intent): Int = try {
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        val options = ActivityOptions.makeBasic().apply {
            val setDisplay = ActivityOptions::class.java.getMethod("setLaunchDisplayId", Int::class.javaPrimitiveType)
            setDisplay.invoke(this, displayId)
        }.toBundle()

        context.startActivity(intent, options)
        0 // START_OK
    } catch (t: Throwable) {
        Log.w(TAG, "startIntent failed", t)
        3 // START_ERROR
    }

    /** 打开 URI */
    fun startView(displayId: Int, action: String?, uri: String?, packageName: String?): Int {
        val intent = Intent(action ?: Intent.ACTION_VIEW).apply {
            if (uri != null) data = Uri.parse(uri)
            if (packageName != null) setPackage(packageName)
        }
        return startIntent(displayId, intent)
    }

    /** 文本分享 */
    fun startShare(displayId: Int, packageName: String, text: String): Int {
        val intent = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_TEXT, text)
            setPackage(packageName)
        }
        return startIntent(displayId, intent)
    }

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
}
