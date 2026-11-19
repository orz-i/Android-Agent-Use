package com.agent.use.common.capture

import android.os.Bundle

/**
 * 截屏能力快照。
 *
 * 由服务端在真实设备上探测后回传，回答四个问题：
 * 1. 这台机器上 `screencap` 能不能用（[screencapAvailable]）；
 * 2. 能不能提权到 Root 重试（[rootAvailable]）；
 * 3. 能不能抓 FLAG_SECURE 页面（[secureCaptureAvailable]，Android 17 起）；
 * 4. 当前进程身份是什么（[uid]，2000 = Shell、0 = Root）。
 *
 * 客户端据此决定「走哪条通道、要不要给用户提示、长截图最多敢滚几次」，
 * 而不是靠 `Build.MANUFACTURER` 之类的机型猜测。
 */
data class ScreenCaptureCapability(
    /** 服务端进程 UID，2000 为 Shell，0 为 Root，其他值说明降级运行。 */
    val uid: Int,
    /** `screencap` 可执行文件路径，null 表示未找到。 */
    val screencapPath: String?,
    /** `screencap` 实测可用（探测时真实抓过一帧）。 */
    val screencapAvailable: Boolean,
    /** `su -c id -u` 返回 0，具备提权能力。 */
    val rootAvailable: Boolean,
    /** `screencap` 支持 `-d <displayId>` 参数（Android 7+ 恒为 true，保留给定制 ROM）。 */
    val supportsDisplayArg: Boolean,
    /** `input -d <displayId> swipe` 可用，长截图才能靠服务端自己滚动。 */
    val supportsDisplaySwipe: Boolean,
    /**
     * 能否抓取声明了 `FLAG_SECURE` 的窗口。
     *
     * 成立条件是 Android 17+ 且设备具备 `ScreenCapture` 的安全内容策略 API。
     * 注意它**不需要 Root** —— UID 2000 就能用；[rootAvailable] 与它无关。
     */
    val secureCaptureAvailable: Boolean = false,
    /** 探测耗时，便于客户端判断是否需要缓存。 */
    val detectMs: Long = 0L,
    /** 探测失败原因，成功时为 null。 */
    val note: String? = null,
) {

    /** 当前可用的特权通道列表（不含虚拟屏直读）。 */
    val privilegedModes: List<ScreenCaptureMode>
        get() = buildList {
            if (screencapAvailable) add(ScreenCaptureMode.SHELL_PRIVILEGED)
            if (rootAvailable) add(ScreenCaptureMode.ROOT_PRIVILEGED)
            if (secureCaptureAvailable) add(ScreenCaptureMode.SECURE_PRIVILEGED)
        }

    /** 是否有任何一条「免授权」通道可用。 */
    val canCaptureWithoutPermission: Boolean
        get() = screencapAvailable || rootAvailable || secureCaptureAvailable

    /** 能否覆盖「普通页面 + FLAG_SECURE 页面」的全部场景。 */
    val canCaptureAnyContent: Boolean
        get() = screencapAvailable && secureCaptureAvailable

    val summary: String
        get() = "uid=$uid screencap=${screencapPath ?: "none"}(${if (screencapAvailable) "ok" else "unavailable"}) " +
            "root=$rootAvailable secure=$secureCaptureAvailable " +
            "displayArg=$supportsDisplayArg displaySwipe=$supportsDisplaySwipe" +
            (note?.let { " note=$it" } ?: "")

    fun toBundle(): Bundle = Bundle().apply {
        putInt(KEY_UID, uid)
        putString(KEY_SCREENCAP_PATH, screencapPath)
        putBoolean(KEY_SCREENCAP_AVAILABLE, screencapAvailable)
        putBoolean(KEY_ROOT_AVAILABLE, rootAvailable)
        putBoolean(KEY_SUPPORTS_DISPLAY_ARG, supportsDisplayArg)
        putBoolean(KEY_SUPPORTS_DISPLAY_SWIPE, supportsDisplaySwipe)
        putBoolean(KEY_SECURE_CAPTURE_AVAILABLE, secureCaptureAvailable)
        putLong(KEY_DETECT_MS, detectMs)
        putString(KEY_NOTE, note)
    }

    companion object {
        private const val KEY_UID = "uid"
        private const val KEY_SCREENCAP_PATH = "screencapPath"
        private const val KEY_SCREENCAP_AVAILABLE = "screencapAvailable"
        private const val KEY_ROOT_AVAILABLE = "rootAvailable"
        private const val KEY_SUPPORTS_DISPLAY_ARG = "supportsDisplayArg"
        private const val KEY_SUPPORTS_DISPLAY_SWIPE = "supportsDisplaySwipe"
        private const val KEY_SECURE_CAPTURE_AVAILABLE = "secureCaptureAvailable"
        private const val KEY_DETECT_MS = "detectMs"
        private const val KEY_NOTE = "note"

        @JvmStatic
        fun fromBundle(bundle: Bundle?): ScreenCaptureCapability = if (bundle == null) {
            unavailable("服务端未返回能力信息")
        } else {
            ScreenCaptureCapability(
                uid = bundle.getInt(KEY_UID, -1),
                screencapPath = bundle.getString(KEY_SCREENCAP_PATH),
                screencapAvailable = bundle.getBoolean(KEY_SCREENCAP_AVAILABLE, false),
                rootAvailable = bundle.getBoolean(KEY_ROOT_AVAILABLE, false),
                supportsDisplayArg = bundle.getBoolean(KEY_SUPPORTS_DISPLAY_ARG, false),
                supportsDisplaySwipe = bundle.getBoolean(KEY_SUPPORTS_DISPLAY_SWIPE, false),
                secureCaptureAvailable = bundle.getBoolean(KEY_SECURE_CAPTURE_AVAILABLE, false),
                detectMs = bundle.getLong(KEY_DETECT_MS, 0L),
                note = bundle.getString(KEY_NOTE),
            )
        }

        /** 探测不可用时的兜底快照，避免调用方到处判空。 */
        @JvmStatic
        fun unavailable(note: String?, uid: Int = -1): ScreenCaptureCapability =
            ScreenCaptureCapability(
                uid = uid,
                screencapPath = null,
                screencapAvailable = false,
                rootAvailable = false,
                supportsDisplayArg = false,
                supportsDisplaySwipe = false,
                secureCaptureAvailable = false,
                note = note,
            )
    }
}
