package com.agent.use.common.network.plugin.external

import com.agent.use.common.network.plugin.DeclarativeCodecJson
import com.agent.use.common.network.plugin.DeclarativeConfig
import com.agent.use.common.network.plugin.EbpfProbeProfile
import com.agent.use.common.network.plugin.NetworkCapturePlugin
import com.agent.use.common.network.plugin.NetworkCapturePluginRegistry
import com.agent.use.common.network.plugin.NetworkTrafficMiddleware
import com.agent.use.common.network.plugin.parseJsonObject
import dalvik.system.DexClassLoader
import java.io.File
import java.security.MessageDigest

/**
 * 外部抓包插件包加载器（L3）。
 *
 * 目的是把「新增一个 App」从"改代码 → 重编 aau → 重打 APK"变成"放一个目录"。一个插件包就是一个
 * 目录，里面有一份 `plugin.json`，可以再带一个 dex：
 *
 * ```
 * filesDir/capture_plugins/acme-market/
 *   plugin.json      # 必需：包名、探测规则、解码管道
 *   plugin.dex       # 可选：自定义中间件（AES / 分段 / 有状态解码）
 * ```
 *
 * `plugin.json` 是**唯一的接口契约**，纯配置也能独立工作：
 *
 * ```json
 * {
 *   "id": "acme.market",
 *   "apiVersion": 1,
 *   "packages": ["com.acme.market"],
 *   "hostFix": { "headerPriority": ["x-acme-host"], "defaultHost": "api.acme.com" },
 *   "responseCodecs": [
 *     { "when": [{"header": "x-acme-enc", "equals": "1"}],
 *       "steps": [{"op": "container", "magic": "ACME", "headerSize": 16},
 *                 {"op": "decompress", "algo": "gzip"}] }
 *   ],
 *   "ebpfProfile": { "jniHookRules": [ ... ] }
 * }
 * ```
 *
 * 需要代码时才加 `"dex": "plugin.dex"` 与 `"entryClass"` / `"middlewareClass"`
 * （分别实现 [NetworkCapturePlugin] / [NetworkTrafficMiddleware]）。
 *
 * **边界**：插件代码与宿主同进程运行，JVM 里没有真正的沙箱。这里能做的是——
 * 只认应用私有目录里的包、校验接口版本、可选校验 dex 的 sha256、拒绝路径穿越；
 * "插件只能碰响应字节与请求头"靠接口收窄（[NetworkTrafficMiddleware] 就两个方法），
 * 不靠事后审计。因此 [load] 提供 `allowCode = false`：只加载纯配置包。
 */
object ExternalCapturePluginLoader {

    /** 插件包与宿主之间的接口版本。接口变了就 +1，旧包会被明确拒绝而不是神秘崩溃。 */
    const val API_VERSION = 1

    const val PLUGIN_FILE_NAME = "plugin.json"
    const val PLUGINS_DIR_NAME = "capture_plugins"

    /** 注册进 [NetworkCapturePluginRegistry] 的插件 id 前缀，便于区分内置与外部。 */
    const val PLUGIN_ID_PREFIX = com.agent.use.common.network.plugin.EXTERNAL_PLUGIN_ID_PREFIX

    private const val MAX_SPEC_BYTES = 512 * 1024
    private val ID_PATTERN = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
    private val PACKAGE_PATTERN = Regex("^[A-Za-z0-9_*]+(\\.[A-Za-z0-9_*]+)*$")
    private val DEX_NAME_PATTERN = Regex("^[A-Za-z0-9_][A-Za-z0-9._-]*$")

    /** 把「找 dex → 造 ClassLoader」这一步留出注入点，JVM 单测里可以传空实现。 */
    fun interface DexClassLoaderFactory {
        fun create(dexFile: File, parent: ClassLoader): ClassLoader
    }

    /**
     * 默认用系统 `DexClassLoader` 加载插件 dex。
     *
     * 写成 getter 而不是常量：JVM 单测里不存在 dalvik 运行时，只要测试自己传工厂，
     * 这个 lambda 就永远不会被加载、更不会被执行。
     */
    val defaultDexLoader: DexClassLoaderFactory
        get() = DexClassLoaderFactory { dexFile, parent ->
            val optimized = File(dexFile.parentFile, ".dexopt").apply { mkdirs() }
            DexClassLoader(dexFile.absolutePath, optimized.absolutePath, null, parent)
        }

    data class LoadedPlugin(
        val id: String,
        val packages: List<String>,
        val hasCode: Boolean,
        val path: String,
    )

    data class RejectedPlugin(val path: String, val reason: String)

    data class Report(
        val loaded: List<LoadedPlugin> = emptyList(),
        val rejected: List<RejectedPlugin> = emptyList(),
    ) {
        val isEmpty: Boolean get() = loaded.isEmpty() && rejected.isEmpty()
    }

    /**
     * 扫描 [rootDir] 下每个子目录，有 `plugin.json` 的按插件包处理，其余静默跳过。
     *
     * 单个包失败只记入 [Report.rejected]，不影响其它包——一个坏配置不该让所有抓包失效。
     */
    fun load(
        rootDir: File?,
        parentClassLoader: ClassLoader,
        allowCode: Boolean = true,
        dexLoaderFactory: DexClassLoaderFactory = defaultDexLoader,
        registry: NetworkCapturePluginRegistry = NetworkCapturePluginRegistry,
    ): Report {
        val root = rootDir ?: return Report()
        if (!root.isDirectory) return Report()
        val dirs = root.listFiles()
            ?.filter { it.isDirectory && !it.name.startsWith(".") }
            ?.sortedBy { it.name }
            .orEmpty()
        if (dirs.isEmpty()) return Report()

        val loaded = ArrayList<LoadedPlugin>()
        val rejected = ArrayList<RejectedPlugin>()

        for (dir in dirs) {
            val specFile = File(dir, PLUGIN_FILE_NAME)
            if (!specFile.isFile) continue
            val outcome = runCatching { loadOne(dir, specFile, parentClassLoader, allowCode, dexLoaderFactory) }
            outcome.fold(
                onSuccess = { plugin ->
                    registry.register(plugin.plugin)
                    loaded += plugin.report
                },
                onFailure = { t ->
                    rejected += RejectedPlugin(dir.absolutePath, rejectReason(t))
                },
            )
        }
        return Report(loaded, rejected)
    }

    private class Loaded(val plugin: NetworkCapturePlugin, val report: LoadedPlugin)

    private fun loadOne(
        dir: File,
        specFile: File,
        parentClassLoader: ClassLoader,
        allowCode: Boolean,
        dexLoaderFactory: DexClassLoaderFactory,
    ): Loaded {
        if (specFile.length() > MAX_SPEC_BYTES) reject("spec_too_large:${specFile.length()}")
        val spec = parseSpec(specFile.readText())
        if (spec.apiVersion != API_VERSION) {
            reject("api_version_mismatch:${spec.apiVersion}!=$API_VERSION")
        }
        if (!spec.enabled) reject("disabled")

        val dexFile = spec.dexFile?.let { name ->
            if (!DEX_NAME_PATTERN.matches(name)) reject("dex_name_invalid:$name")
            val candidate = File(dir, name)
            if (candidate.canonicalFile.parentFile != dir.canonicalFile) {
                reject("dex_outside_package:$name")
            }
            if (!candidate.isFile) reject("dex_missing:$name")
            candidate
        }

        if (dexFile != null && !allowCode) reject("code_not_allowed:${dexFile.name}")
        val needsCode = spec.entryClass != null || spec.middlewareClass != null
        if (needsCode && dexFile == null) reject("code_without_dex")

        dexFile?.let { dex ->
            spec.sha256?.let { expected ->
                val actual = sha256(dex)
                if (!actual.equals(expected, ignoreCase = true)) {
                    reject("sha256_mismatch:${actual.take(12)}!=${expected.take(12)}")
                }
            }
        }

        val classLoader = dexFile?.let { dexLoaderFactory.create(it, parentClassLoader) } ?: parentClassLoader
        val pluginImpl = spec.entryClass?.let {
            instantiate(it, classLoader, NetworkCapturePlugin::class.java, "entry_class")
        }
        val middleware = spec.middlewareClass?.let {
            instantiate(it, classLoader, NetworkTrafficMiddleware::class.java, "middleware_class")
        }

        val plugin = ExternalCapturePlugin(spec, pluginImpl, middleware)
        return Loaded(
            plugin = plugin,
            report = LoadedPlugin(
                id = plugin.id,
                packages = spec.packages,
                hasCode = dexFile != null,
                path = dir.absolutePath,
            ),
        )
    }

    private fun <T> instantiate(name: String, loader: ClassLoader, type: Class<T>, label: String): T {
        val cls = try {
            Class.forName(name, true, loader)
        } catch (t: Throwable) {
            reject("${label}_not_found:$name")
        }
        if (!type.isAssignableFrom(cls)) reject("${label}_type_mismatch:$name")
        val instance = try {
            cls.getDeclaredConstructor().newInstance()
        } catch (t: Throwable) {
            reject("${label}_init_failed:$name")
        }
        return type.cast(instance) ?: reject("${label}_type_mismatch:$name")
    }

    // ------------------------------------------------------------------ plugin.json

    internal data class Spec(
        val id: String,
        val apiVersion: Int,
        val enabled: Boolean,
        val packages: List<String>,
        val dexFile: String?,
        val sha256: String?,
        val entryClass: String?,
        val middlewareClass: String?,
        val ebpfProfile: EbpfProbeProfile?,
        val declarative: DeclarativeConfig,
    )

    @Suppress("UNCHECKED_CAST")
    internal fun parseSpec(text: String): Spec {
        val root = try {
            parseJsonObject(text)
        } catch (t: Throwable) {
            reject("spec_invalid_json")
        }
        val id = (root["id"] as? String)?.trim().orEmpty()
        if (!ID_PATTERN.matches(id)) reject("spec_invalid_id:$id")

        val packages = (root["packages"] as? List<Any?>).orEmpty()
            .mapNotNull { (it as? String)?.trim()?.takeIf(String::isNotEmpty) }
            .distinct()
        if (packages.isEmpty()) reject("spec_no_packages")
        packages.firstOrNull { !PACKAGE_PATTERN.matches(it) }?.let { reject("spec_invalid_package:$it") }

        val ebpfRaw = root["ebpfProfile"] as? Map<String, Any?>
        return Spec(
            id = id,
            apiVersion = (root["apiVersion"] as? Number)?.toInt() ?: 1,
            enabled = (root["enabled"] as? Boolean) ?: true,
            packages = packages,
            dexFile = (root["dex"] as? String)?.trim()?.takeIf { it.isNotEmpty() },
            sha256 = (root["sha256"] as? String)?.trim()?.takeIf { it.isNotEmpty() },
            entryClass = (root["entryClass"] as? String)?.trim()?.takeIf { it.isNotEmpty() },
            middlewareClass = (root["middlewareClass"] as? String)?.trim()?.takeIf { it.isNotEmpty() },
            ebpfProfile = ebpfRaw?.let { EbpfProbeProfile.parseProfileObject(it) },
            declarative = DeclarativeCodecJson.parseConfig(root),
        )
    }

    private fun sha256(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buffer = ByteArray(64 * 1024)
            while (true) {
                val read = input.read(buffer)
                if (read <= 0) break
                digest.update(buffer, 0, read)
            }
        }
        return digest.digest().joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }
    }
}

/**
 * 一个插件包在注册表里的样子：JSON 配置打底，dex 里的类（如果有）作为补充。
 *
 * 解码管道不在这里建中间件——注册表会从 [provideEbpfProfile] 的 `declarative` 字段统一挂
 * [com.agent.use.common.network.plugin.DeclarativeTrafficMiddleware]，避免同一条规则被应用两次。
 */
private class ExternalCapturePlugin(
    private val spec: ExternalCapturePluginLoader.Spec,
    private val impl: NetworkCapturePlugin?,
    private val middleware: NetworkTrafficMiddleware?,
) : NetworkCapturePlugin {

    override val id: String = ExternalCapturePluginLoader.PLUGIN_ID_PREFIX + spec.id

    override val defaultPackages: List<String> = spec.packages

    override fun matchesPackage(targetPackage: String): Boolean =
        targetPackage in spec.packages || impl?.matchesPackage(targetPackage) == true

    override fun provideEbpfProfile(targetPackage: String): EbpfProbeProfile {
        val specProfile = spec.ebpfProfile
        val implProfile = impl?.provideEbpfProfile(targetPackage)
        return EbpfProbeProfile(
            sslOffsetRules = (specProfile?.sslOffsetRules.orEmpty() + implProfile?.sslOffsetRules.orEmpty()).distinct(),
            cronetOffsetRules = (specProfile?.cronetOffsetRules.orEmpty() +
                implProfile?.cronetOffsetRules.orEmpty()).distinct(),
            cronetAbiRule = specProfile?.cronetAbiRule ?: implProfile?.cronetAbiRule,
            jniHookRules = (specProfile?.jniHookRules.orEmpty() + implProfile?.jniHookRules.orEmpty()).distinct(),
            replaceBuiltinOffsets = specProfile?.replaceBuiltinOffsets ?: false,
            declarative = DeclarativeConfig(
                hostFix = spec.declarative.hostFix
                    ?: specProfile?.declarative?.hostFix
                    ?: implProfile?.declarative?.hostFix,
                responseCodecs = (spec.declarative.responseCodecs +
                    specProfile?.declarative?.responseCodecs.orEmpty() +
                    implProfile?.declarative?.responseCodecs.orEmpty()).distinct(),
            ),
        )
    }

    override fun provideMiddlewares(targetPackage: String): List<NetworkTrafficMiddleware> {
        val seen = LinkedHashSet<String>()
        val result = ArrayList<NetworkTrafficMiddleware>()
        middleware?.let { if (seen.add(it.id)) result.add(it) }
        impl?.provideMiddlewares(targetPackage).orEmpty().forEach { if (seen.add(it.id)) result.add(it) }
        return result
    }
}

/** 加载失败时把原因塞进异常信息，由 [ExternalCapturePluginLoader.load] 收进报告。 */
private fun reject(reason: String): Nothing = throw IllegalStateException(reason)

private fun rejectReason(t: Throwable): String =
    t.message?.takeIf { it.isNotBlank() } ?: t::class.java.simpleName
