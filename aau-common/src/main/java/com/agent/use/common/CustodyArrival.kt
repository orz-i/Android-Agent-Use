package com.agent.use.common

import android.os.Bundle

/**
 * 托管体系的任务到达事件契约，对应 `IAgentCustodyListener.onTaskArrived(Bundle)`。
 */
data class CustodyArrival(
    val taskId: Int,
    val packageName: String,
    val userId: Int,
    val activity: String?,
    val displayId: Int,
    val fromDisplayId: Int,
    val newTask: Boolean,
    val sameTask: Boolean,
    val originUid: Int = LaunchOrigin.UNKNOWN_UID,
    val originPackage: String? = null,
    val originConfidence: Int = LaunchOrigin.CONFIDENCE_UNKNOWN,
    val managedDisplayId: Int = NO_MANAGED_DISPLAY,
    val at: Long,
    val standard: Boolean = true,
    val uid: Int = LaunchOrigin.UNKNOWN_UID,
) {
    val origin: LaunchOrigin
        get() = LaunchOrigin(originUid, originPackage, originConfidence)

    fun toBundle(): Bundle = Bundle().apply {
        putInt(KEY_TASK, taskId)
        putString(KEY_PACKAGE, packageName)
        putInt(KEY_USER, userId)
        putString(KEY_ACTIVITY, activity)
        putInt(KEY_DISPLAY, displayId)
        putInt(KEY_FROM, fromDisplayId)
        putBoolean(KEY_NEW_TASK, newTask)
        putBoolean(KEY_SAME_TASK, sameTask)
        putInt(KEY_ORIGIN_UID, originUid)
        putString(KEY_ORIGIN_PACKAGE, originPackage)
        putInt(KEY_ORIGIN_CONFIDENCE, originConfidence)
        putInt(KEY_MANAGED_DISPLAY, managedDisplayId)
        putLong(KEY_AT, at)
        putBoolean(KEY_STANDARD, standard)
        putInt(KEY_UID, uid)
    }

    companion object {
        const val MAIN_DISPLAY = 0
        const val FROM_NEW = -1
        const val NO_MANAGED_DISPLAY = LaunchOrigin.NO_MANAGED_DISPLAY

        const val KEY_TASK = "task"
        const val KEY_PACKAGE = "package"
        const val KEY_USER = "user"
        const val KEY_ACTIVITY = "activity"
        const val KEY_DISPLAY = "display"
        const val KEY_FROM = "from"
        const val KEY_NEW_TASK = "newTask"
        const val KEY_SAME_TASK = "sameTask"
        const val KEY_ORIGIN_UID = LaunchOrigin.KEY_ORIGIN_UID
        const val KEY_ORIGIN_PACKAGE = LaunchOrigin.KEY_ORIGIN_PACKAGE
        const val KEY_ORIGIN_CONFIDENCE = LaunchOrigin.KEY_ORIGIN_CONFIDENCE
        const val KEY_MANAGED_DISPLAY = LaunchOrigin.KEY_MANAGED_DISPLAY
        const val KEY_AT = "at"
        const val KEY_STANDARD = "standard"
        const val KEY_UID = "uid"

        @JvmStatic
        fun fromBundle(bundle: Bundle?): CustodyArrival? {
            if (bundle == null || !bundle.containsKey(KEY_TASK)) return null
            val taskId = bundle.getInt(KEY_TASK, -1)
            if (taskId < 0) return null
            return CustodyArrival(
                taskId = taskId,
                packageName = bundle.getString(KEY_PACKAGE).orEmpty(),
                userId = bundle.getInt(KEY_USER, -1),
                activity = bundle.getString(KEY_ACTIVITY),
                displayId = bundle.getInt(KEY_DISPLAY, -1),
                fromDisplayId = bundle.getInt(KEY_FROM, FROM_NEW),
                newTask = bundle.getBoolean(KEY_NEW_TASK, false),
                sameTask = bundle.getBoolean(KEY_SAME_TASK, false),
                originUid = bundle.getInt(KEY_ORIGIN_UID, LaunchOrigin.UNKNOWN_UID),
                originPackage = bundle.getString(KEY_ORIGIN_PACKAGE),
                originConfidence = bundle.getInt(KEY_ORIGIN_CONFIDENCE, LaunchOrigin.CONFIDENCE_UNKNOWN),
                managedDisplayId = bundle.getInt(KEY_MANAGED_DISPLAY, NO_MANAGED_DISPLAY),
                at = bundle.getLong(KEY_AT, 0L),
                standard = bundle.getBoolean(KEY_STANDARD, true),
                uid = bundle.getInt(KEY_UID, LaunchOrigin.UNKNOWN_UID),
            )
        }
    }
}
