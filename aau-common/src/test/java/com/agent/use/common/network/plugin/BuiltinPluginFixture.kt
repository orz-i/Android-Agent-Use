package com.agent.use.common.network.plugin

import com.agent.use.common.network.plugin.external.ExternalCapturePluginLoader
import java.io.File

/**
 * 内置插件包的测试夹具。
 *
 * 内置包已经是**数据**（`src/main/assets/aau_capture_plugins/<id>/plugin.json`），测试直接读
 * 那份文件就够了——不需要另写一份 Kotlin 对象，否则又会出现"测试里是好的、发出去的包不是"。
 */
internal object BuiltinPluginFixture {

    /** assets 根目录本身就是合法的插件包根目录（一个子目录一份 plugin.json）。 */
    val assetsRoot: File by lazy {
        val candidates = listOf(
            File("src/main/assets/aau_capture_plugins"),
            File("aau/aau-common/src/main/assets/aau_capture_plugins"),
            File("../aau-common/src/main/assets/aau_capture_plugins"),
        )
        candidates.firstOrNull { it.isDirectory }
            ?: error("找不到内置插件包目录，尝试过: " + candidates.joinToString { it.absolutePath })
    }

    private var loaded = false

    /** 把内置包注册进全局注册表（幂等）。 */
    @Synchronized
    fun ensureLoaded() {
        if (loaded) return
        val report = ExternalCapturePluginLoader.load(
            assetsRoot,
            javaClass.classLoader,
            idPrefix = BUILTIN_PLUGIN_ID_PREFIX,
        )
        check(report.rejected.isEmpty()) { "内置插件包被拒: ${report.rejected}" }
        check(report.loaded.isNotEmpty()) { "没有加载到任何内置插件包: ${assetsRoot.absolutePath}" }
        loaded = true
    }

    fun spec(dirName: String): ExternalCapturePluginLoader.Spec =
        ExternalCapturePluginLoader.parseSpec(File(File(assetsRoot, dirName), "plugin.json").readText())

    fun declarative(dirName: String): DeclarativeConfig = spec(dirName).declarative
}
