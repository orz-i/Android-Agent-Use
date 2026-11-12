package com.agent.use.common

/**
 * 应用音频 AppOps PLAY_AUDIO 模式契约。
 *
 * 核心机制：
 * Android 系统通过 AppOpsManager 中的 OP_PLAY_AUDIO 控制特定包的静音策略。
 * Agent 运行时在虚拟屏运行短视频/音乐/游戏等应用时，通常将其置于后台静音模式 (ignore)，
 * 避免在用户无感知的虚拟屏后台突然发出声响。
 */
enum class AudioMode(val raw: String) {
    /** 允许播放音频（正常出声） */
    ALLOW("allow"),

    /** 忽略音频播放请求（静音模式，播放器仍在运行但不向音频混音器输出数据） */
    IGNORE("ignore"),

    /** 拒绝音频播放 */
    DENY("deny"),

    /** 系统默认未设置状态 */
    DEFAULT("default");

    val isMuted: Boolean
        get() = this == IGNORE || this == DENY

    companion object {
        private val APPOPS_REGEX = Regex("""PLAY_AUDIO:\s*([a-z_]+)""")

        @JvmStatic
        fun fromRaw(raw: String?): AudioMode = when (raw?.trim()?.lowercase()) {
            "allow" -> ALLOW
            "ignore" -> IGNORE
            "deny" -> DENY
            "default" -> DEFAULT
            else -> DEFAULT
        }

        /**
         * 解析 `appops get <pkg> PLAY_AUDIO` 命令行标准输出
         * 例如："PLAY_AUDIO: ignore; time=..." -> IGNORE；"No operations." -> DEFAULT
         */
        @JvmStatic
        fun parseAppOpsOutput(output: String): AudioMode {
            val matched = APPOPS_REGEX.find(output)?.groupValues?.get(1)
            return fromRaw(matched)
        }

        /**
         * 计算恢复静音时应写回的模式。
         *
         * 重要原理：
         * 在 Android 底层音频管道中，音频系统仅当明确为 "allow" 时才放开声音通道；
         * 如果原先未设置过（对应 DEFAULT），直接写回 "default" 在部分 OEM 定制系统中会导致持续无声，
         * 因此若原状态为 DEFAULT 或空，必须写回 ALLOW 以确保恢复正常播放。
         */
        @JvmStatic
        fun calculateRestoreMode(prior: AudioMode?): AudioMode =
            if (prior == null || prior == DEFAULT) ALLOW else prior
    }
}

/**
 * 音频应用与多用户复合键。
 * 格式：单主用户为 "packageName"，分身/工作资料为 "packageName@userId"。
 */
data class AppAudioKey(
    val packageName: String,
    val userId: Int? = null,
) {
    val first: String get() = packageName
    val second: Int? get() = userId

    override fun toString(): String =
        if (userId == null || userId == 0) packageName else "$packageName@$userId"

    companion object {
        private val REGEX = Regex("""([A-Za-z0-9_.]+)(?:@([0-9]+))?""")

        @JvmStatic
        fun of(packageName: String, user: Int?): String =
            if (user == null || user == 0) packageName else "$packageName@$user"

        @JvmStatic
        fun parse(key: String): AppAudioKey? {
            val match = REGEX.matchEntire(key.trim()) ?: return null
            val pkg = match.groupValues[1]
            val user = match.groupValues.getOrNull(2)?.takeIf { it.isNotEmpty() }?.toIntOrNull()
            return AppAudioKey(pkg, user)
        }
    }
}
