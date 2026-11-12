package com.agent.display.common

import android.os.Build
import android.os.Parcel
import android.os.Parcelable

/**
 * 虚拟屏配置契约。
 *
 * 封装屏幕分辨率、DPI、显示模式标志位及命名，支持跨进程 Binder Parcelable 传递。
 */
data class DisplayConfig(
    val width: Int,
    val height: Int,
    val dpi: Int,
    val flags: Int = 0,
    val name: String = DEFAULT_DISPLAY_NAME,
) : Parcelable {

    constructor(parcel: Parcel) : this(
        width = parcel.readInt(),
        height = parcel.readInt(),
        dpi = parcel.readInt(),
        flags = parcel.readInt(),
        name = parcel.readString() ?: DEFAULT_DISPLAY_NAME
    )

    override fun writeToParcel(parcel: Parcel, flags: Int) {
        parcel.writeInt(width)
        parcel.writeInt(height)
        parcel.writeInt(dpi)
        parcel.writeInt(this.flags)
        parcel.writeString(name)
    }

    override fun describeContents(): Int = 0

    companion object CREATOR : Parcelable.Creator<DisplayConfig> {
        const val DEFAULT_DISPLAY_NAME = "agent-virtual-display"

        // DisplayManager.VIRTUAL_DISPLAY_FLAG_* (含 Android 系统隐藏常量)
        const val FLAG_PUBLIC = 1 shl 0
        const val FLAG_OWN_CONTENT_ONLY = 1 shl 3
        const val FLAG_SUPPORTS_TOUCH = 1 shl 6
        const val FLAG_ROTATES_WITH_CONTENT = 1 shl 7
        const val FLAG_DESTROY_CONTENT_ON_REMOVAL = 1 shl 8
        const val FLAG_TRUSTED = 1 shl 10
        const val FLAG_OWN_DISPLAY_GROUP = 1 shl 11
        const val FLAG_ALWAYS_UNLOCKED = 1 shl 12
        const val FLAG_TOUCH_FEEDBACK_DISABLED = 1 shl 13
        const val FLAG_OWN_FOCUS = 1 shl 14
        const val FLAG_STEAL_TOP_FOCUS_DISABLED = 1 shl 16

        override fun createFromParcel(parcel: Parcel): DisplayConfig = DisplayConfig(parcel)
        override fun newArray(size: Int): Array<DisplayConfig?> = arrayOfNulls(size)

        /**
         * 1080P 标准主流手机纵向配置 (1080x2400, 420 DPI)
         */
        @JvmStatic
        fun standard1080p(dpi: Int = 420, name: String = DEFAULT_DISPLAY_NAME): DisplayConfig =
            DisplayConfig(width = 1080, height = 2400, dpi = dpi, name = name)

        /**
         * 720P 轻量级省资源配置 (720x1600, 320 DPI)
         */
        @JvmStatic
        fun compact720p(dpi: Int = 320, name: String = DEFAULT_DISPLAY_NAME): DisplayConfig =
            DisplayConfig(width = 720, height = 1600, dpi = dpi, name = name)

        /**
         * 平板横向配置 (2560x1600, 320 DPI)
         */
        @JvmStatic
        fun tablet(dpi: Int = 320, name: String = DEFAULT_DISPLAY_NAME): DisplayConfig =
            DisplayConfig(width = 2560, height = 1600, dpi = dpi, name = name)

        /**
         * 根据当前 Android 版本及可信权限情况动态生成推荐的虚拟屏 Flags。
         *
         * @param sdk Android SDK 版本号 (例如 Build.VERSION.SDK_INT)
         * @param trusted 是否拥有可信屏权限 (如在定制系统上可能缺少 ADD_TRUSTED_DISPLAY)
         */
        @JvmStatic
        fun resolveRecommendedFlags(sdk: Int = Build.VERSION.SDK_INT, trusted: Boolean = true): Int {
            var flags = FLAG_PUBLIC or FLAG_OWN_CONTENT_ONLY or FLAG_SUPPORTS_TOUCH or
                FLAG_ROTATES_WITH_CONTENT or FLAG_DESTROY_CONTENT_ON_REMOVAL

            if (sdk >= 33 /* TIRAMISU */) {
                flags = flags or FLAG_TOUCH_FEEDBACK_DISABLED
                if (trusted) {
                    flags = flags or FLAG_TRUSTED or FLAG_OWN_DISPLAY_GROUP or FLAG_ALWAYS_UNLOCKED
                }
            }

            // Android 14+ 关键隔离：只有带 STEAL_TOP_FOCUS_DISABLED 才不会抢走主屏正在交互的焦点
            if (sdk >= 34 /* UPSIDE_DOWN_CAKE */ && trusted) {
                flags = flags or FLAG_OWN_FOCUS or FLAG_STEAL_TOP_FOCUS_DISABLED
            }

            return flags
        }
    }
}
