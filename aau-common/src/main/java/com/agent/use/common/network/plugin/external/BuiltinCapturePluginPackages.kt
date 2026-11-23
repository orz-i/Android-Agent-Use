package com.agent.use.common.network.plugin.external

import android.content.res.AssetManager
import com.agent.use.common.network.plugin.parseJsonObject
import java.io.File

/**
 * 随 APK 分发的内置插件包。
 *
 * 内置与外部只差"从哪来"：都走同一份 `plugin.json`、同一个
 * [ExternalCapturePluginLoader]，注册后都是普通插件包。区别只有两点——
 *
 * - 内置包从 `assets/aau_capture_plugins/<目录>/plugin.json` 来，首启安装到
 *   `filesDir/capture_plugins_builtin/`；
 * - 内置包带 `version`，APK 升级时版本更高就覆盖，否则保留磁盘上那份。
 *
 * 这样"给 BOSS 改一个方法名"和"给一个没见过的 App 加插件"是同一条路径，
 * 不需要谁去改 Kotlin 再重编 aau。
 *
 * 想改内置规则的正确做法是**覆盖配置**（设置页保存到 `aau_capture_plugins.json`），
 * 而不是直接改内置包目录——那份目录归版本管理，升级会被覆盖。
 */
object BuiltinCapturePluginPackages {

    /** assets 下的根目录。加前缀是为了不和宿主自己的 assets 撞名。 */
    const val ASSET_DIR = "aau_capture_plugins"

    data class Package(
        /** 安装到磁盘时用的目录名（assets 里的子目录名）。 */
        val dirName: String,
        val id: String,
        val version: Int,
        val json: String,
    )

    data class InstallReport(
        val installed: List<String> = emptyList(),
        val skipped: List<String> = emptyList(),
        val failed: List<String> = emptyList(),
    ) {
        val isEmpty: Boolean get() = installed.isEmpty() && skipped.isEmpty() && failed.isEmpty()
    }

    data class LoadResult(
        val install: InstallReport,
        val load: ExternalCapturePluginLoader.Report,
    )

    /**
     * 安装 + 加载一步到位。抓包启动、设置页、discovery 三条入口都走它，
     * 免得某个入口忘了装、表现出来的症状是"这台机器上规则突然全没了"。
     */
    fun loadFromAssets(
        assets: AssetManager?,
        targetRoot: File?,
        parentClassLoader: ClassLoader,
        allowCode: Boolean = true,
    ): LoadResult {
        if (assets == null || targetRoot == null) {
            return LoadResult(InstallReport(), ExternalCapturePluginLoader.Report())
        }
        val installReport = install(fromAssets(assets), targetRoot)
        val loadReport = ExternalCapturePluginLoader.load(
            targetRoot,
            parentClassLoader,
            allowCode = allowCode,
            idPrefix = com.agent.use.common.network.plugin.BUILTIN_PLUGIN_ID_PREFIX,
        )
        return LoadResult(installReport, loadReport)
    }

    fun fromAssets(assets: AssetManager?, assetDir: String = ASSET_DIR): List<Package> {
        if (assets == null) return emptyList()
        val names = runCatching { assets.list(assetDir)?.toList() }.getOrNull().orEmpty()
        return names.filter { it.isNotBlank() }
            .sorted()
            .mapNotNull { name ->
                val text = runCatching {
                    assets.open("$assetDir/$name/${ExternalCapturePluginLoader.PLUGIN_FILE_NAME}")
                        .bufferedReader(Charsets.UTF_8)
                        .use { it.readText() }
                }.getOrNull() ?: return@mapNotNull null
                parse(name, text)
            }
    }

    /** 目录版：测试与"把内置包解到本地调试"用，布局与 assets 完全一致。 */
    fun fromDirectory(dir: File?): List<Package> {
        if (dir == null || !dir.isDirectory) return emptyList()
        return dir.listFiles()
            ?.filter { it.isDirectory && !it.name.startsWith(".") }
            ?.sortedBy { it.name }
            ?.mapNotNull { sub ->
                val spec = File(sub, ExternalCapturePluginLoader.PLUGIN_FILE_NAME)
                if (!spec.isFile) return@mapNotNull null
                val text = runCatching { spec.readText() }.getOrNull() ?: return@mapNotNull null
                parse(sub.name, text)
            }
            .orEmpty()
    }

    /**
     * 把包写到 [targetRoot]/<目录>/plugin.json。
     *
     * 覆盖规则：磁盘上那份的 `version` 不低于内置版本就跳过。等于也不覆盖，是为了让
     * "我手动调过的内置包"在一次无关的 APK 升级后还留着；真要改规则应该走覆盖配置。
     */
    fun install(packages: List<Package>, targetRoot: File?): InstallReport {
        if (targetRoot == null || packages.isEmpty()) return InstallReport()
        val installed = ArrayList<String>()
        val skipped = ArrayList<String>()
        val failed = ArrayList<String>()

        for (pkg in packages) {
            try {
                val dir = File(targetRoot, pkg.dirName)
                val target = File(dir, ExternalCapturePluginLoader.PLUGIN_FILE_NAME)
                if (target.isFile && readVersion(target) >= pkg.version) {
                    skipped += pkg.id
                    continue
                }
                if (!dir.isDirectory && !dir.mkdirs()) {
                    failed += pkg.id
                    continue
                }
                val tmp = File(dir, "${ExternalCapturePluginLoader.PLUGIN_FILE_NAME}.tmp")
                tmp.writeText(pkg.json)
                if (!tmp.renameTo(target)) {
                    target.writeText(pkg.json)
                    tmp.delete()
                }
                installed += pkg.id
            } catch (t: Throwable) {
                failed += pkg.id
            }
        }
        return InstallReport(installed, skipped, failed)
    }

    private fun parse(dirName: String, text: String): Package? {
        val root = runCatching { parseJsonObject(text) }.getOrNull() ?: return null
        val id = (root["id"] as? String)?.trim().orEmpty()
        if (id.isEmpty()) return null
        val version = (root["version"] as? Number)?.toInt() ?: 1
        return Package(dirName = dirName, id = id, version = version, json = text)
    }

    private fun readVersion(file: File): Int =
        runCatching { parse(file.parentFile?.name ?: "", file.readText())?.version }.getOrNull() ?: 0
}
