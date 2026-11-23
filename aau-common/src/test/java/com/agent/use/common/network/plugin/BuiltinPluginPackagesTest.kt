package com.agent.use.common.network.plugin

import com.agent.use.common.network.plugin.external.BuiltinCapturePluginPackages
import com.agent.use.common.network.plugin.external.ExternalCapturePluginLoader
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/**
 * 内置 App 规则是**数据**，不是代码。
 *
 * 这组用例守住一条边界：`app` 里出现过的每一个内置 App，都必须只是 `assets/aau_capture_plugins`
 * 下的一个目录；一旦有人为了图快又把规则写回 Kotlin，这里就只剩四个目录、注册表里也只会多出
 * `builtin.*` 的 id。
 */
class BuiltinPluginPackagesTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    @Before
    fun setUp() {
        BuiltinPluginFixture.ensureLoaded()
    }

    private fun packages() = BuiltinCapturePluginPackages.fromDirectory(BuiltinPluginFixture.assetsRoot)

    @Test
    fun builtinPackagesCoverTheAppsThatUsedToBeHardcoded() {
        val ids = packages().map { it.id }.toSet()
        assertEquals(setOf("bosszhipin", "douyin", "generic-cronet", "xiaohongshu"), ids)
    }

    @Test
    fun everyBuiltinPackageParsesThroughTheSameLoader() {
        for (pkg in packages()) {
            // 解析失败会直接抛（spec 里用 reject 表达），这里等于逐个校验了 schema。
            val spec = ExternalCapturePluginLoader.parseSpec(pkg.json)
            assertEquals(pkg.id, spec.id)
            assertEquals(1, spec.apiVersion)
            assertTrue(spec.packages.isNotEmpty())
            // 内置包都是纯配置：没有任何 dex / 入口类。
            assertEquals(null, spec.dexFile)
            assertEquals(null, spec.entryClass)
        }
    }

    @Test
    fun builtinPackagesAreRegisteredWithBuiltinPrefix() {
        val ids = NetworkCapturePluginRegistry.listPluginIds()
        assertTrue(ids.toString(), ids.contains("builtin.bosszhipin"))
        assertTrue(ids.toString(), ids.contains("builtin.douyin"))
        assertTrue(ids.toString(), ids.contains("builtin.xiaohongshu"))
        assertTrue(ids.toString(), ids.contains("builtin.generic-cronet"))
        assertTrue(NetworkCapturePluginRegistry.isBuiltinPluginPackage("com.hpbr.bosszhipin"))
        assertFalse(NetworkCapturePluginRegistry.isExternalPluginPackage("com.hpbr.bosszhipin"))
    }

    @Test
    fun fallbackPackageStillProvidesCronetAbiForUnknownApps() {
        val profile = NetworkCapturePluginRegistry.resolveEbpfProfile("com.example.nobody")
        assertNotNull("兜底包必须给任意 App 提供 cronet ABI", profile.cronetAbiRule)
        assertEquals(0x20, profile.cronetAbiRule!!.rawHeadersOffset)
        assertTrue(profile.cronetAbiRule!!.jniSignatures.isNotEmpty())
        // 兜底包不提供任何 App 专属偏移
        assertTrue(profile.sslOffsetRules.isEmpty())
    }

    @Test
    fun bossPackageCarriesDecoderAndDiagnostics() {
        val config = BuiltinPluginFixture.declarative("bosszhipin")
        assertEquals("www.zhipin.com", config.hostFix?.defaultHost)
        assertTrue(config.responseCodecs.any { it.id == "bzp-block" })
        assertTrue(config.diagnose.any { it.label == "aes" })
        // 解不开时的诊断要能一路传到注册表
        assertTrue(
            NetworkCapturePluginRegistry.resolveDeclarativeConfig("com.hpbr.bosszhipin")
                .diagnose.any { it.label == "aes" }
        )
    }

    @Test
    fun installUpgradesOnlyWhenTheVersionIsHigher() {
        val root = tempFolder.newFolder("capture_plugins_builtin")
        val packages = packages()

        val first = BuiltinCapturePluginPackages.install(packages, root)
        assertEquals(packages.size, first.installed.size)
        assertTrue(first.skipped.isEmpty())

        // 用户手动调过内置包，但没动 version：升级时不能把他的改动冲掉
        val bossFile = File(File(root, "bosszhipin"), "plugin.json")
        bossFile.writeText(bossFile.readText().replace("www.zhipin.com", "api.zhipin.com"))
        val second = BuiltinCapturePluginPackages.install(packages, root)
        assertTrue(second.installed.isEmpty())
        assertTrue(second.skipped.contains("bosszhipin"))
        assertTrue(bossFile.readText().contains("api.zhipin.com"))

        // 内置版本提高 -> 覆盖
        val bumped = packages.map { if (it.id == "bosszhipin") it.copy(version = it.version + 1) else it }
        val third = BuiltinCapturePluginPackages.install(bumped, root)
        assertEquals(listOf("bosszhipin"), third.installed)
        assertTrue(bossFile.readText().contains("www.zhipin.com"))

        // 装出来的目录就是标准插件包目录，能被同一个 loader 直接读
        val report = ExternalCapturePluginLoader.load(
            root,
            javaClass.classLoader,
            idPrefix = BUILTIN_PLUGIN_ID_PREFIX,
        )
        assertTrue(report.rejected.toString(), report.rejected.isEmpty())
        assertTrue(report.loaded.map { it.id }.toString(), report.loaded.any { it.id == "builtin.bosszhipin" })
    }
}
