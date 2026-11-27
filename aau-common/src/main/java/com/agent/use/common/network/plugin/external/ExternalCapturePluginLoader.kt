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
 * 抓包插件包加载器（L3）。内置包与外部包共用这一份实现，区别只在 [load] 的 `idPrefix`：
 * 内置包由 [BuiltinCapturePluginPackages] 从 assets 装到 `capture_plugins_builtin/` 后带
 * `builtin.` 前缀加载。
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

    /** 随 APK 内置的包安装到的目录。与用户放的包分开，覆盖升级时不会互相踩。 */
    const val BUILTIN_PLUGINS_DIR_NAME = "capture_plugins_builtin"

    /** 用户放的包注册进 [NetworkCapturePluginRegistry] 时用的 id 前缀。 */
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

    /**
     * 一个插件包的**声明**：包自述的用途 + 加载器从 `plugin.json` 里实际解析出来的通道。
     *
     * 两者都列出来是有意的。只看自述，一个包可以写"只读响应体"却挂了 JNI 入口；
     * 只看通道计数，用户又不知道它为什么要挂。设置页把两栏并排显示。
     */
    data class PackInfo(
        /** 注册表 id，带 `builtin.` / `external.` 前缀；启用开关按它记。 */
        val id: String,
        val dir: String,
        val version: Int,
        val apiVersion: Int,
        val packages: List<String>,
        val fallback: Boolean,
        /** `declaration.name`，没有就用 id。 */
        val title: String? = null,
        val description: String? = null,
        val author: String? = null,
        /** `declaration.notes`：包自己声明的用途，人读。 */
        val declares: List<String> = emptyList(),
        val sslRules: Int = 0,
        val cronetRules: Int = 0,
        val jniRules: Int = 0,
        val codecs: Int = 0,
        /** `flows` 里的应用脚本条数；和抓包无关，但同一个包可以两样都带。 */
        val flows: Int = 0,
        val hostFix: Boolean = false,
        val hasCode: Boolean = false,
        /** `plugin.json` 里写了自己 `"enabled": false`。 */
        val disabledInFile: Boolean = false,
        /** 用户在设置页关掉了它。文件没动，只是不加载。 */
        val disabledByUser: Boolean = false,
        /** 校验失败的原因。非空时这个包不会生效，但设置页仍然列出来。 */
        val error: String? = null,
    ) {
        val enabled: Boolean get() = !disabledInFile && !disabledByUser && error == null

        /** 这个包实际会碰的通道，给"技术声明"那一栏用。 */
        val channels: List<String>
            get() = buildList {
                if (sslRules > 0) add("ssl:$sslRules")
                if (cronetRules > 0) add("cronet:$cronetRules")
                if (jniRules > 0) add("jni:$jniRules")
                if (codecs > 0) add("codec:$codecs")
                if (flows > 0) add("flow:$flows")
                if (hostFix) add("hostfix")
                if (hasCode) add("code")
            }
    }

    data class Report(
        val loaded: List<LoadedPlugin> = emptyList(),
        val rejected: List<RejectedPlugin> = emptyList(),
        /** 目录里每一份 `plugin.json`，**包括被禁用的和坏掉的**——设置页要能看见它们。 */
        val packs: List<PackInfo> = emptyList(),
    ) {
        val isEmpty: Boolean get() = loaded.isEmpty() && rejected.isEmpty() && packs.isEmpty()

        /** 有包但没加载：被文件关了、被用户关了。 */
        val skipped: List<PackInfo> get() = packs.filter { !it.enabled && it.error == null }
    }

    /**
     * 扫描 [rootDir] 下每个子目录，有 `plugin.json` 的按插件包处理，其余静默跳过。
     *
     * 单个包失败只记入 [Report.rejected]，不影响其它包——一个坏配置不该让所有抓包失效。
     *
     * 被禁用的包（`plugin.json` 里 `"enabled": false`，或 id 在 [disabledIds] 里）不算失败：
     * 只出现在 [Report.packs] / [Report.skipped] 里，不注册、不告警。设置页靠这个把
     * 「用户自己关掉的」和「坏掉加载不了」分开显示。
     */
    fun load(
        rootDir: File?,
        parentClassLoader: ClassLoader,
        allowCode: Boolean = true,
        dexLoaderFactory: DexClassLoaderFactory = defaultDexLoader,
        idPrefix: String = PLUGIN_ID_PREFIX,
        registry: NetworkCapturePluginRegistry = NetworkCapturePluginRegistry,
        disabledIds: Set<String> = emptySet(),
    ): Report {
        val root = rootDir ?: return Report()
        if (!root.isDirectory) return Report()
        val dirs = pluginDirs(root)
        if (dirs.isEmpty()) return Report()

        val loaded = ArrayList<LoadedPlugin>()
        val rejected = ArrayList<RejectedPlugin>()
        val packs = ArrayList<PackInfo>()

        for (dir in dirs) {
            val specFile = File(dir, PLUGIN_FILE_NAME)
            if (!specFile.isFile) continue
            val spec = try {
                parseSpec(specFile.readText())
            } catch (t: Throwable) {
                rejected += RejectedPlugin(dir.absolutePath, rejectReason(t))
                packs += brokenPackInfo(dir, idPrefix, t)
                continue
            }
            val info = describe(spec, dir, idPrefix, disabledIds)
            // 禁用不是错误：不注册、不告警，但留在 packs 里让设置页能看见并重新打开。
            if (info.disabledInFile || info.disabledByUser) {
                packs += info
                continue
            }
            val outcome = runCatching { loadOne(dir, specFile, parentClassLoader, allowCode, dexLoaderFactory, idPrefix) }
            outcome.fold(
                onSuccess = { plugin ->
                    registry.register(plugin.plugin)
                    loaded += plugin.report
                    packs += info
                },
                onFailure = { t ->
                    val reason = rejectReason(t)
                    rejected += RejectedPlugin(dir.absolutePath, reason)
                    packs += info.copy(error = reason)
                },
            )
        }
        return Report(loaded, rejected, packs)
    }

    /**
     * 只看不改：[load] 的只读版本，设置页列包用。
     *
     * 不实例化 dex 里的类、不注册、不碰 dalvik——它要能在 UI 线程上跑，也不会因为一个坏包
     * 把正在跑的抓包带崩。校验只到「文件齐不齐、接口版本对不对、校验和对不对」。
     */
    fun inspect(
        rootDir: File?,
        idPrefix: String = PLUGIN_ID_PREFIX,
        disabledIds: Set<String> = emptySet(),
        verifyChecksum: Boolean = true,
    ): List<PackInfo> {
        val root = rootDir ?: return emptyList()
        if (!root.isDirectory) return emptyList()
        val packs = ArrayList<PackInfo>()
        for (dir in pluginDirs(root)) {
            val specFile = File(dir, PLUGIN_FILE_NAME)
            if (!specFile.isFile) continue
            val spec = try {
                parseSpec(specFile.readText())
            } catch (t: Throwable) {
                packs += brokenPackInfo(dir, idPrefix, t)
                continue
            }
            packs += validateOnly(describe(spec, dir, idPrefix, disabledIds), spec, dir, verifyChecksum)
        }
        return packs
    }

    private fun pluginDirs(root: File): List<File> = root.listFiles()
        ?.filter { it.isDirectory && !it.name.startsWith(".") }
        ?.sortedBy { it.name }
        .orEmpty()

    /** 连 `id` 都读不出来的包：用目录名占位，否则设置页里它会凭空消失。 */
    private fun brokenPackInfo(dir: File, idPrefix: String, t: Throwable) = PackInfo(
        id = idPrefix + dir.name,
        dir = dir.absolutePath,
        version = 0,
        apiVersion = 0,
        packages = emptyList(),
        fallback = false,
        error = rejectReason(t),
    )

    /** 把解析好的 spec 摊成声明。纯读，不校验。 */
    private fun describe(spec: Spec, dir: File, idPrefix: String, disabledIds: Set<String>): PackInfo {
        val profile = spec.ebpfProfile
        val id = idPrefix + spec.id
        val decl = spec.declaration
        return PackInfo(
            id = id,
            dir = dir.absolutePath,
            version = spec.version,
            apiVersion = spec.apiVersion,
            packages = spec.packages,
            fallback = spec.fallback || WILDCARD_PACKAGE in spec.packages,
            title = decl?.name,
            description = decl?.summary,
            author = decl?.author,
            declares = decl?.notes.orEmpty(),
            sslRules = profile?.sslOffsetRules?.size ?: 0,
            cronetRules = profile?.cronetOffsetRules?.size ?: 0,
            jniRules = profile?.jniHookRules?.size ?: 0,
            codecs = spec.declarative.responseCodecs.size,
            flows = spec.flows,
            hostFix = spec.declarative.hostFix != null,
            hasCode = spec.dexFile != null,
            disabledInFile = !spec.enabled,
            disabledByUser = id in disabledIds,
        )
    }

    /** [inspect] 用的静态校验，判定与 [loadOne] 前半段保持一致。 */
    private fun validateOnly(info: PackInfo, spec: Spec, dir: File, verifyChecksum: Boolean): PackInfo {
        if (spec.apiVersion != API_VERSION) {
            return info.copy(error = "api_version_mismatch:${spec.apiVersion}!=$API_VERSION")
        }
        val dexFile = spec.dexFile?.let { name ->
            dexProblem(dir, name)?.let { return info.copy(error = it) }
            File(dir, name)
        }
        if ((spec.entryClass != null || spec.middlewareClass != null) && dexFile == null) {
            return info.copy(error = "code_without_dex")
        }
        if (verifyChecksum && dexFile != null) {
            spec.sha256?.let { expected ->
                val actual = sha256(dexFile)
                if (!actual.equals(expected, ignoreCase = true)) {
                    return info.copy(error = "sha256_mismatch:${actual.take(12)}!=${expected.take(12)}")
                }
            }
        }
        return info
    }

    /** 名字非法 / 越界 / 不存在时返回原因；没问题返回 null。 */
    private fun dexProblem(dir: File, name: String): String? {
        if (!DEX_NAME_PATTERN.matches(name)) return "dex_name_invalid:$name"
        val candidate = File(dir, name)
        if (candidate.canonicalFile.parentFile != dir.canonicalFile) return "dex_outside_package:$name"
        if (!candidate.isFile) return "dex_missing:$name"
        return null
    }

    private class Loaded(val plugin: NetworkCapturePlugin, val report: LoadedPlugin)

    private fun loadOne(
        dir: File,
        specFile: File,
        parentClassLoader: ClassLoader,
        allowCode: Boolean,
        dexLoaderFactory: DexClassLoaderFactory,
        idPrefix: String,
    ): Loaded {
        if (specFile.length() > MAX_SPEC_BYTES) reject("spec_too_large:${specFile.length()}")
        val spec = parseSpec(specFile.readText())
        if (spec.apiVersion != API_VERSION) {
            reject("api_version_mismatch:${spec.apiVersion}!=$API_VERSION")
        }
        // enabled 在这里不再判：load() 已经把被禁用的包挡在门外，走到这里的一定是该加载的。

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

        val plugin = ExternalCapturePlugin(spec, pluginImpl, middleware, idPrefix)
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

    /**
     * `plugin.json` 的 `declaration` 段：包自己说的用途。
     *
     * 这是给**人**看的，不参与加载判定——写错了不影响抓包。但设置页会原样显示，
     * 所以它也是插件包唯一能把「我是干什么的」讲清楚的地方。
     */
    internal data class Declaration(
        val name: String?,
        val summary: String?,
        val author: String?,
        /** 逐条用途，例如「读取 BOSS 响应体的 BZPBlock 信封」。 */
        val notes: List<String>,
    )

    internal data class Spec(
        val id: String,
        val apiVersion: Int,
        /** 内置包升级/覆盖用的版本号；用户放的包可以不写。 */
        val version: Int,
        val enabled: Boolean,
        /** 兜底包：匹配所有包，只在没有专项规则时生效。 */
        val fallback: Boolean,
        val packages: List<String>,
        val dexFile: String?,
        val sha256: String?,
        val entryClass: String?,
        val middlewareClass: String?,
        val declaration: Declaration?,
        val ebpfProfile: EbpfProbeProfile?,
        val declarative: DeclarativeConfig,
        /** 应用脚本条数。脚本本身由宿主在需要时按包名取用，抓包链路只记个数。 */
        val flows: Int,
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
            version = (root["version"] as? Number)?.toInt() ?: 1,
            enabled = (root["enabled"] as? Boolean) ?: true,
            fallback = (root["fallback"] as? Boolean) ?: false,
            packages = packages,
            dexFile = (root["dex"] as? String)?.trim()?.takeIf { it.isNotEmpty() },
            sha256 = (root["sha256"] as? String)?.trim()?.takeIf { it.isNotEmpty() },
            entryClass = (root["entryClass"] as? String)?.trim()?.takeIf { it.isNotEmpty() },
            middlewareClass = (root["middlewareClass"] as? String)?.trim()?.takeIf { it.isNotEmpty() },
            declaration = parseDeclaration(root["declaration"]),
            ebpfProfile = ebpfRaw?.let { EbpfProbeProfile.parseProfileObject(it) },
            declarative = DeclarativeCodecJson.parseConfig(root),
            flows = (root["flows"] as? List<*>)?.size ?: 0,
        )
    }

    @Suppress("UNCHECKED_CAST")
    private fun parseDeclaration(raw: Any?): Declaration? {
        val map = raw as? Map<String, Any?> ?: return null
        val notes = (map["notes"] as? List<Any?>).orEmpty()
            .mapNotNull { (it as? String)?.trim()?.takeIf(String::isNotEmpty) }
            .distinct()
        val name = (map["name"] as? String)?.trim()?.takeIf { it.isNotEmpty() }
        val summary = (map["summary"] as? String)?.trim()?.takeIf { it.isNotEmpty() }
        val author = (map["author"] as? String)?.trim()?.takeIf { it.isNotEmpty() }
        if (name == null && summary == null && author == null && notes.isEmpty()) return null
        return Declaration(name, summary, author, notes)
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
    idPrefix: String,
) : NetworkCapturePlugin {

    override val id: String = idPrefix + spec.id

    override val defaultPackages: List<String> = spec.packages

    override val fallback: Boolean = spec.fallback

    /** `packages` 里写 `*` 就等于"匹配所有包"，这是插件包表达兜底能力的唯一方式。 */
    override fun matchesPackage(targetPackage: String): Boolean =
        targetPackage in spec.packages ||
            spec.packages.contains(WILDCARD_PACKAGE) ||
            impl?.matchesPackage(targetPackage) == true

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
                // 解不开时的诊断也是规则的一部分：漏了它，加密响应会安静地以密文形态流到下游。
                diagnose = (spec.declarative.diagnose +
                    specProfile?.declarative?.diagnose.orEmpty() +
                    implProfile?.declarative?.diagnose.orEmpty()).distinct(),
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

private const val WILDCARD_PACKAGE = "*"

private fun rejectReason(t: Throwable): String =
    t.message?.takeIf { it.isNotBlank() } ?: t::class.java.simpleName
