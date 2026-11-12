package com.agent.display.common

import android.os.Bundle

/**
 * 任务快照信息契约。
 *
 * 封装在特定屏幕（主屏或虚拟屏）上运行的任务信息，用于任务层级观察、
 * 前后台状态判断和任务迁移调度。
 */
data class TaskSnapshotInfo(
    val taskId: Int,
    val displayId: Int,
    val packageName: String,
    val topActivity: String? = null,
    val userId: Int = 0,
    val isVisible: Boolean = false,
    val isStandardActivity: Boolean = true,
) {
    fun toBundle(): Bundle = Bundle().apply {
        putInt(KEY_TASK_ID, taskId)
        putInt(KEY_DISPLAY_ID, displayId)
        putString(KEY_PACKAGE_NAME, packageName)
        putString(KEY_TOP_ACTIVITY, topActivity)
        putInt(KEY_USER_ID, userId)
        putBoolean(KEY_IS_VISIBLE, isVisible)
        putBoolean(KEY_IS_STANDARD, isStandardActivity)
    }

    companion object {
        const val KEY_TASK_ID = "taskId"
        const val KEY_DISPLAY_ID = "displayId"
        const val KEY_PACKAGE_NAME = "packageName"
        const val KEY_TOP_ACTIVITY = "topActivity"
        const val KEY_USER_ID = "userId"
        const val KEY_IS_VISIBLE = "isVisible"
        const val KEY_IS_STANDARD = "isStandard"

        @JvmStatic
        fun fromBundle(bundle: Bundle): TaskSnapshotInfo = TaskSnapshotInfo(
            taskId = bundle.getInt(KEY_TASK_ID, -1),
            displayId = bundle.getInt(KEY_DISPLAY_ID, -1),
            packageName = bundle.getString(KEY_PACKAGE_NAME).orEmpty(),
            topActivity = bundle.getString(KEY_TOP_ACTIVITY),
            userId = bundle.getInt(KEY_USER_ID, 0),
            isVisible = bundle.getBoolean(KEY_IS_VISIBLE, false),
            isStandardActivity = bundle.getBoolean(KEY_IS_STANDARD, true)
        )
    }
}
