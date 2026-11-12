package com.agent.display.client

import android.os.SystemClock
import android.util.Log
import com.agent.display.common.IAgentShell
import com.agent.display.common.MainArrivalsResult

/**
 * 主屏冲突避让与任务回捞管理器。
 *
 * 核心设计：
 * 1. 启动前避让检查：通过 visibleOnMainScreen 探测目标应用是否正在主屏前台使用，若在用则拒绝打扰用户；
 * 2. 操作期间监控：开启 6000ms 的任务跳变观察窗口 (watchMainScreen)；
 * 3. 动作后溢出回捞：若检测到目标应用意外在主屏 (Display 0) 冒出，自动通过 moveTask 安全将其挪回虚拟屏 (PullBack)。
 */
class MainScreenConflictManager(
    private val shell: IAgentShell,
    private val defaultWatchWindowMs: Int = 6000
) {

    /**
     * 检查目标包名是否正在物理主屏可见运行
     */
    fun isPackageInUseOnMainScreen(packageName: String, userId: Int = 0): Boolean {
        return try {
            shell.visibleOnMainScreen(packageName, userId)
        } catch (t: Throwable) {
            Log.w(TAG, "Failed to check main screen visibility for $packageName", t)
            false
        }
    }

    /**
     * 在受冲突保护的上下文中执行可能导致窗口溢出的操作（如启动应用、打开链接）。
     *
     * @param targetDisplayId 期望承载任务的虚拟屏 ID
     * @param targetPackage 目标应用包名
     * @param action 具体操作逻辑
     */
    suspend fun <T> executeWithConflictGuard(
        targetDisplayId: Int,
        targetPackage: String,
        action: suspend () -> T
    ): ConflictGuardedResult<T> {
        // 1. 启动前主屏在用排查
        if (isPackageInUseOnMainScreen(targetPackage)) {
            Log.w(TAG, "Package $targetPackage is actively in use on the main screen. Aborting to prevent disturbance.")
            return ConflictGuardedResult.AbortedInUse(targetPackage)
        }

        // 2. 开启主屏监控窗口
        val startTime = SystemClock.uptimeMillis()
        val topBefore = try {
            shell.watchMainScreen(defaultWatchWindowMs)
        } catch (t: Throwable) {
            Log.w(TAG, "Failed to start watchMainScreen", t)
            -1
        }

        // 3. 执行动作
        val actionResult = action()

        // 4. 分析动作期间主屏新增任务并执行必要的回捞
        val pulledBackTasks = mutableListOf<Int>()
        try {
            val arrivalsBundle = shell.mainArrivals(startTime)
            val arrivals = MainArrivalsResult.fromBundle(arrivalsBundle)
            val tasks = arrivals.arrivedTaskIds
            val packages = arrivals.arrivedPackages

            for (i in tasks.indices) {
                val taskId = tasks[i]
                val pkg = packages.getOrNull(i)

                // 若是目标包名的新任务，且非动作前主屏原有的顶层任务，将其回捞至虚拟屏
                if (pkg == targetPackage && taskId != topBefore) {
                    Log.i(TAG, "Spill detected: Task $taskId ($pkg) landed on main display. Pulling back to display $targetDisplayId.")
                    val moved = shell.moveTask(taskId, targetDisplayId)
                    if (moved) {
                        pulledBackTasks.add(taskId)
                        Log.i(TAG, "Successfully pulled back task $taskId to display $targetDisplayId")
                    } else {
                        Log.w(TAG, "Failed to move task $taskId back to display $targetDisplayId")
                    }
                }
            }
        } catch (t: Throwable) {
            Log.w(TAG, "Failed to query or resolve mainArrivals", t)
        }

        return ConflictGuardedResult.Success(actionResult, pulledBackTasks)
    }

    sealed interface ConflictGuardedResult<out T> {
        data class Success<T>(val result: T, val pulledBackTaskIds: List<Int>) : ConflictGuardedResult<T>
        data class AbortedInUse(val inUsePackage: String) : ConflictGuardedResult<Nothing>
    }

    companion object {
        private const val TAG = "MainScreenConflictMgr"
    }
}
