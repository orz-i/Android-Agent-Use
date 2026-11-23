package com.agent.use.common.network.plugin.external

import com.agent.use.common.network.HttpResponseEvent
import com.agent.use.common.network.plugin.EbpfProbeProfile
import com.agent.use.common.network.plugin.NetworkCapturePluginRegistry
import com.agent.use.common.network.plugin.NetworkTrafficMiddleware
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.nio.charset.StandardCharsets
import java.util.Base64

/**
 * 外部插件包加载：纯配置包要能独立工作，配置错要"明确拒绝"而不是静默半生效。
 */
class ExternalCapturePluginLoaderTest {

    @get:Rule
    val temp = TemporaryFolder()

    private val registeredIds = ArrayList<String>()

    @After
    fun tearDown() {
        registeredIds.forEach { NetworkCapturePluginRegistry.unregister(it) }
        NetworkCapturePluginRegistry.clearJsonProfileOverrides()
    }

    /** JVM 单测里没有 dalvik 运行时，dex 一律"已就绪"地交给父加载器。 */
    private val parentLoaderFactory = ExternalCapturePluginLoader.DexClassLoaderFactory { _, parent -> parent }

    private fun packageDir(name: String, spec: String, dex: ByteArray? = null): File {
        val dir = File(temp.root, name).apply { mkdirs() }
        File(dir, ExternalCapturePluginLoader.PLUGIN_FILE_NAME).writeText(spec)
        dex?.let { File(dir, "plugin.dex").writeBytes(it) }
        return dir
    }

    private fun load(
        allowCode: Boolean = true,
        dexLoaderFactory: ExternalCapturePluginLoader.DexClassLoaderFactory = parentLoaderFactory,
    ): ExternalCapturePluginLoader.Report {
        val report = ExternalCapturePluginLoader.load(
            rootDir = temp.root,
            parentClassLoader = javaClass.classLoader,
            allowCode = allowCode,
            dexLoaderFactory = dexLoaderFactory,
        )
        registeredIds += report.loaded.map { it.id }
        return report
    }

    private fun response(): HttpResponseEvent = HttpResponseEvent(
        requestId = "r1",
        url = "https://api.acme.com/v1/items",
        statusCode = 200,
        statusText = "OK",
        mimeType = "application/octet-stream",
    )

    @Test
    fun configOnlyPackageDecodesWithoutAnyCode() {
        packageDir(
            "acme-market",
            """
            {
              "id": "acme.market",
              "apiVersion": 1,
              "packages": ["com.acme.market"],
              "hostFix": { "headerPriority": ["x-acme-host"], "defaultHost": "api.acme.com" },
              "responseCodecs": [{ "id": "acme", "steps": [{ "op": "base64" }] }],
              "ebpfProfile": {
                "jniHookRules": [
                  { "libSubstring": "libacme.so", "methodNames": ["nativeDecode"] }
                ]
              }
            }
            """.trimIndent(),
        )

        val report = load()
        assertTrue(report.rejected.toString(), report.rejected.isEmpty())
        assertEquals(1, report.loaded.size)
        assertFalse(report.loaded.single().hasCode)
        assertTrue(NetworkCapturePluginRegistry.isExternalPluginPackage("com.acme.market"))

        // 声明式解码由注册表统一挂载
        val declarative = NetworkCapturePluginRegistry.resolveMiddlewares("com.acme.market")
            .firstOrNull { it.id.startsWith("declarative:") }
        assertNotNull("外部配置包应当产出声明式中间件", declarative)
        val plain = """{"ok":1}""".toByteArray(StandardCharsets.UTF_8)
        val (event, body) = declarative!!.onResponse(
            "com.acme.market",
            response(),
            Base64.getEncoder().encode(plain),
        )
        assertEquals(String(plain, StandardCharsets.UTF_8), String(body!!, StandardCharsets.UTF_8))
        assertEquals("application/json; charset=utf-8", event.mimeType)

        // 探测规则也来自同一个 plugin.json
        val profile = NetworkCapturePluginRegistry.resolveEbpfProfile("com.acme.market")
        assertTrue(profile.jniHookRules.any { it.libSubstring == "libacme.so" })
        assertEquals(
            "api.acme.com",
            NetworkCapturePluginRegistry.resolveDeclarativeConfig("com.acme.market").hostFix?.defaultHost,
        )
    }

    @Test
    fun apiVersionMismatchIsRejected() {
        packageDir("old-plugin", """{ "id": "old", "apiVersion": 99, "packages": ["com.old.app"] }""")
        val report = load()
        assertEquals(0, report.loaded.size)
        assertTrue(report.rejected.single().reason, report.rejected.single().reason.startsWith("api_version_mismatch"))
    }

    @Test
    fun sha256MismatchIsRejected() {
        packageDir(
            "bad-hash",
            """
            {
              "id": "bad.hash",
              "apiVersion": 1,
              "packages": ["com.bad.hash"],
              "dex": "plugin.dex",
              "sha256": "0000000000000000000000000000000000000000000000000000000000000000"
            }
            """.trimIndent(),
            dex = ByteArray(32) { 7 },
        )
        val report = load()
        assertEquals(0, report.loaded.size)
        assertTrue(report.rejected.single().reason, report.rejected.single().reason.startsWith("sha256_mismatch"))
    }

    @Test
    fun dexPathTraversalIsRejected() {
        packageDir(
            "escape",
            """{ "id": "escape", "apiVersion": 1, "packages": ["com.escape"], "dex": "../plugin.dex" }""",
        )
        val report = load()
        assertEquals(0, report.loaded.size)
        assertTrue(report.rejected.single().reason, report.rejected.single().reason.startsWith("dex_name_invalid"))
    }

    @Test
    fun codePackageLoadsMiddlewareFromDex() {
        packageDir(
            "acme-code",
            """
            {
              "id": "acme.code",
              "apiVersion": 1,
              "packages": ["com.acme.code"],
              "dex": "plugin.dex",
              "middlewareClass": "com.agent.use.common.network.plugin.external.StubExternalMiddleware"
            }
            """.trimIndent(),
            dex = ByteArray(8) { 1 },
        )
        val report = load()
        assertTrue(report.rejected.toString(), report.rejected.isEmpty())
        assertTrue(report.loaded.single().hasCode)
        val middlewares = NetworkCapturePluginRegistry.resolveMiddlewares("com.acme.code")
        assertTrue(middlewares.map { it.id }.toString(), middlewares.any { it.id == StubExternalMiddleware.ID })
    }

    @Test
    fun codeIsRefusedWhenDisabledByPolicy() {
        packageDir(
            "policy",
            """
            {
              "id": "policy.code",
              "apiVersion": 1,
              "packages": ["com.policy.code"],
              "dex": "plugin.dex",
              "middlewareClass": "com.agent.use.common.network.plugin.external.StubExternalMiddleware"
            }
            """.trimIndent(),
            dex = ByteArray(8) { 1 },
        )
        val report = load(allowCode = false)
        assertEquals(0, report.loaded.size)
        assertTrue(report.rejected.single().reason, report.rejected.single().reason.startsWith("code_not_allowed"))
    }

    @Test
    fun disabledAndMalformedPackagesAreReported() {
        packageDir("disabled", """{ "id": "off", "apiVersion": 1, "packages": ["com.off"], "enabled": false }""")
        packageDir("broken", "{ nope }")
        val report = load()
        assertEquals(0, report.loaded.size)
        val reasons = report.rejected.map { it.reason }.toSet()
        assertTrue(reasons.toString(), reasons.any { it == "disabled" })
        assertTrue(reasons.toString(), reasons.any { it.startsWith("spec_invalid_json") })
    }

    @Test
    fun profileWithoutDeclarativeStillRegisters() {
        packageDir(
            "plain",
            """
            {
              "id": "plain.app",
              "apiVersion": 1,
              "packages": ["com.plain.app"],
              "ebpfProfile": { "cronetAbiRule": { "rawHeadersOffset": "0x28" } }
            }
            """.trimIndent(),
        )
        val report = load()
        assertEquals(1, report.loaded.size)
        val profile: EbpfProbeProfile = NetworkCapturePluginRegistry.resolveEbpfProfile("com.plain.app")
        assertEquals(0x28, profile.cronetAbiRule!!.rawHeadersOffset)
        assertTrue(profile.declarative.isEmpty)
    }
}

/** 假的插件中间件：证明 `middlewareClass` 能被实例化并注册。 */
class StubExternalMiddleware : NetworkTrafficMiddleware {
    override val id: String = ID

    override fun onResponse(
        targetPackage: String,
        event: HttpResponseEvent,
        body: ByteArray?,
    ): Pair<HttpResponseEvent, ByteArray?> = event to body

    companion object {
        const val ID = "stub.external.middleware"
    }
}
