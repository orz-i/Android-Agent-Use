package com.agent.display.server

import java.io.File

/**
 * 被 Agent 静音的 App -> 静音前的 PLAY_AUDIO 模式记录（落盘于 /data/local/tmp/）。
 *
 * 在服务异常终止或系统重启后，下次启动时根据本记录把音频状态完整还给系统。
 * 静音时记录，恢复成功后删除；文件读写失败退回到内存记录。
 */
class AudioMuteLedger(private val file: File?) {
    private val modes = LinkedHashMap<String, String>()

    init {
        val text = runCatching { file?.takeIf { it.isFile }?.readText() }.getOrNull().orEmpty()
        modes.putAll(parse(text))
    }

    fun contains(key: String): Boolean = synchronized(modes) { key in modes }
    operator fun get(key: String): String? = synchronized(modes) { modes[key] }
    fun packages(): List<String> = synchronized(modes) { modes.keys.toList() }

    fun put(key: String, mode: String) = synchronized(modes) {
        modes[key] = mode
        save()
    }

    fun remove(key: String) = synchronized(modes) {
        if (modes.remove(key) != null) save()
    }

    /**
     * 将记录中的每个包恢复为其原模式（或 allow）；write 返回 true 时才删除记录。
     * @return 是否全部成功恢复
     */
    fun restoreAll(write: (key: String, restoreMode: String) -> Boolean): Boolean = synchronized(modes) {
        val keys = modes.keys.toList()
        for (k in keys) {
            val prior = modes[k]
            val restore = restoreMode(prior)
            if (write(k, restore)) {
                modes.remove(k)
            }
        }
        save()
        modes.isEmpty()
    }

    private fun save() {
        val f = file ?: return
        runCatching {
            if (modes.isEmpty()) {
                f.delete()
            } else {
                val tmp = File(f.parentFile, f.name + ".tmp")
                tmp.writeText(format(modes))
                if (!tmp.renameTo(f)) {
                    f.writeText(format(modes))
                    tmp.delete()
                }
            }
        }
    }

    companion object {
        private val LINE = Regex("""([A-Za-z0-9_.]+(?:@[0-9]+)?) ([a-z_]+)""")

        /**
         * 计算写回的模式：
         * 原来明确是 allow/ignore/deny 的照原样写回；
         * 未设置过（解析出 default 或 null）的必须写回 "allow"！
         * 安卓系统音频只认 PLAY_AUDIO 为 allow 才放音，显式的 default 会让 App 一直静音。
         */
        fun restoreMode(prior: String?): String =
            if (prior.isNullOrEmpty() || prior == "default") "allow" else prior

        /** 解析 `appops get <pkg> PLAY_AUDIO` 的输出 */
        fun parseSetMode(output: String): String? =
            Regex("""PLAY_AUDIO:\s*([a-z_]+)""").find(output)?.groupValues?.get(1)

        internal fun format(modes: Map<String, String>): String =
            modes.entries.joinToString("") { "${it.key} ${it.value}\n" }

        internal fun parse(text: String): Map<String, String> =
            text.lineSequence()
                .mapNotNull { LINE.matchEntire(it.trim())?.destructured }
                .associate { (pkg, mode) -> pkg to mode }
    }
}

typealias AppAudioKey = com.agent.display.common.AppAudioKey
