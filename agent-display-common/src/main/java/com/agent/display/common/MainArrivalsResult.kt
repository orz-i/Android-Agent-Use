package com.agent.display.common

import android.os.Bundle

/**
 * 主屏任务监听结果契约。
 *
 * 封装在监测窗口期间主屏新冒出的任务，
 * 供 Agent 检查是否有应用从虚拟屏后台弹框逃逸到了主屏，并将其自动挪回。
 */
data class MainArrivalsResult(
    val arrivedTaskIds: List<Int>,
    val arrivedPackages: List<String>,
) {
    companion object {
        const val KEY_TASK_IDS = "taskIds"
        const val KEY_PACKAGES = "packages"

        @JvmStatic
        fun fromBundle(bundle: Bundle?): MainArrivalsResult {
            if (bundle == null) return MainArrivalsResult(emptyList(), emptyList())
            val ids = bundle.getIntArray(KEY_TASK_IDS)?.toList().orEmpty()
            val pkgs = bundle.getStringArrayList(KEY_PACKAGES)?.toList()
                ?: bundle.getStringArray(KEY_PACKAGES)?.toList().orEmpty()
            return MainArrivalsResult(ids, pkgs)
        }
    }
}
