package com.agent.use.common

import android.os.Bundle

/**
 * 启动来源解析结果（从系统 ActivityRecord / ActivityStarter 解析得到）。
 */
data class LaunchOrigin(
    val uid: Int = UNKNOWN_UID,
    val packageName: String? = null,
    val confidence: Int = CONFIDENCE_UNKNOWN,
) {
    val isKnown: Boolean
        get() = confidence > CONFIDENCE_UNKNOWN && (uid >= 0 || !packageName.isNullOrBlank())

    fun toBundle(taskId: Int = -1, managedDisplayId: Int = NO_MANAGED_DISPLAY): Bundle = Bundle().apply {
        if (taskId >= 0) putInt(KEY_TASK, taskId)
        putInt(KEY_ORIGIN_UID, uid)
        putString(KEY_ORIGIN_PACKAGE, packageName)
        putInt(KEY_ORIGIN_CONFIDENCE, confidence)
        putInt(KEY_MANAGED_DISPLAY, managedDisplayId)
    }

    companion object {
        const val UNKNOWN_UID = -1
        const val NO_MANAGED_DISPLAY = -1

        const val CONFIDENCE_UNKNOWN = 0
        const val CONFIDENCE_LOW = 1
        const val CONFIDENCE_MEDIUM = 2
        const val CONFIDENCE_HIGH = 3

        const val KEY_TASK = "task"
        const val KEY_ORIGIN_UID = "originUid"
        const val KEY_ORIGIN_PACKAGE = "originPackage"
        const val KEY_ORIGIN_CONFIDENCE = "originConfidence"
        const val KEY_MANAGED_DISPLAY = "managedDisplay"

        @JvmStatic
        fun unknown(): LaunchOrigin = LaunchOrigin()

        @JvmStatic
        fun fromBundle(bundle: Bundle?): LaunchOrigin {
            if (bundle == null) return unknown()
            return LaunchOrigin(
                uid = bundle.getInt(KEY_ORIGIN_UID, UNKNOWN_UID),
                packageName = bundle.getString(KEY_ORIGIN_PACKAGE),
                confidence = bundle.getInt(KEY_ORIGIN_CONFIDENCE, CONFIDENCE_UNKNOWN),
            )
        }
    }
}
