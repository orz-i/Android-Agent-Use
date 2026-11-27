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
        assertEquals(setOf("bosszhipin", "douyin", "generic-cronet", "qidian", "xiaohongshu"), ids)
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
    fun replacingOffsetsKeepsTheDecoderPipeline() {
        // 真机上的常见形态：用户为了修一个偏移，把整条 profile 存在覆盖文件里，
        // 顺带把 replaceBuiltinOffsets 也置了 true。这只该让偏移以他为准，
        // 不该连内置包的解码管道一起拆掉——否则升级一次，明文解不出来还不知道为什么。
        NetworkCapturePluginRegistry.clearJsonProfileOverrides()
        try {
            NetworkCapturePluginRegistry.registerJsonProfileOverride(
                "com.hpbr.bosszhipin",
                EbpfProbeProfile(
                    sslOffsetRules = listOf(EbpfSslOffsetRule("libzp-sdk-transport.so", 0x1L, 0x2L)),
                    replaceBuiltinOffsets = true,
                ),
            )

            val resolved = NetworkCapturePluginRegistry.resolveEbpfProfile("com.hpbr.bosszhipin")
            assertEquals("偏移以覆盖为准", 0x1L, resolved.sslOffsetRules.single().writeOffset)
            assertTrue(
                "内置包的 BZPBlock 解码管道不能跟着偏移一起被拆掉",
                resolved.declarative.responseCodecs.any { it.id == "bzp-block" },
            )
            assertTrue(
                "加密诊断也得留着，不然密文流下去看着像抓包坏了",
                resolved.declarative.diagnose.any { it.label == "aes" },
            )
        } finally {
            NetworkCapturePluginRegistry.clearJsonProfileOverrides()
        }
    }

    @Test
    fun replacingOffsetsKeepsTheBuiltinJniSignatures() {
        // 真机实录（抖音 com.ss.android.ugc.aweme）：内置包给了两条 cronet JNI 签名，
        // 用户覆盖只写了自己手头那一条。签名是并集匹配——少一条只是少认一种调用形态，
        // 但覆盖把内置包整包跳过后，那条不该静默消失。
        NetworkCapturePluginRegistry.clearJsonProfileOverrides()
        try {
            NetworkCapturePluginRegistry.registerJsonProfileOverride(
                "com.ss.android.ugc.aweme",
                EbpfProbeProfile(
                    sslOffsetRules = listOf(EbpfSslOffsetRule("libttboringssl.so", 0x44bb0L, 0x4894cL)),
                    cronetAbiRule = EbpfCronetAbiRule(
                        jniSignatures = listOf("(Ljava/lang/Object;JLjava/lang/String;IZZZIZIIJ)J"),
                    ),
                    replaceBuiltinOffsets = true,
                ),
            )

            val resolved = NetworkCapturePluginRegistry.resolveEbpfProfile("com.ss.android.ugc.aweme")
            val sigs = resolved.cronetAbiRule?.jniSignatures.orEmpty()
            assertTrue(
                "覆盖自带的签名要在: $sigs",
                "(Ljava/lang/Object;JLjava/lang/String;IZZZIZIIJ)J" in sigs,
            )
            assertTrue(
                "内置包的另一条签名被覆盖吃掉了: $sigs",
                "(Ljava/lang/Object;JLjava/lang/String;IIZZZIZIIJ)J" in sigs,
            )
            assertEquals("重复的签名不该展开成两条: $sigs", 2, sigs.size)
            assertEquals("偏移仍以覆盖为准", 0x44bb0L, resolved.sslOffsetRules.single().writeOffset)
        } finally {
            NetworkCapturePluginRegistry.clearJsonProfileOverrides()
        }
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

    /**
     * 起点这个包只带脚本、不带抓包规则：`flows` 要能被 aau-ui 的解析器读出来，
     * 而且「关广告」那一步必须是按无障碍名字找，不能退回猜坐标。
     */
    @Test
    fun qidianPackageCarriesTheRewardVideoScript() {
        val pkg = packages().single { it.id == "qidian" }
        val spec = ExternalCapturePluginLoader.parseSpec(pkg.json)
        assertEquals(1, spec.flows)
        assertEquals(0, spec.declarative.responseCodecs.size)

        val parsed = com.agent.use.flow.AppFlowSpec.parsePack(pkg.json, "builtin.qidian")
        assertTrue(parsed.errors.toString(), parsed.errors.isEmpty())
        val flow = parsed.flows.single()
        assertEquals("reward-video", flow.id)
        assertTrue(flow.matchesPackage("com.qidian.QDReader"))

        val texts = mutableListOf<String>()
        val excludes = mutableListOf<String>()
        fun walk(steps: List<com.agent.use.flow.FlowStep>) {
            for (step in steps) {
                (step.raw["query"] as? kotlinx.serialization.json.JsonObject)?.let { q ->
                    (q["textAny"] as? kotlinx.serialization.json.JsonArray)?.forEach { t ->
                        (t as? kotlinx.serialization.json.JsonPrimitive)?.content?.let(texts::add)
                    }
                    (q["text"] as? kotlinx.serialization.json.JsonPrimitive)?.content?.let(texts::add)
                    (q["exclude"] as? kotlinx.serialization.json.JsonArray)?.forEach { t ->
                        (t as? kotlinx.serialization.json.JsonPrimitive)?.content?.let(excludes::add)
                    }
                }
                walk(step.then)
                walk(step.otherwise)
                walk(step.body)
            }
        }
        walk(flow.steps)
        assertTrue(texts.toString(), "退出关闭" in texts)
        assertTrue(texts.toString(), "去完成" in texts)
        assertTrue(texts.toString(), "去微信立即玩" in texts)
        // 「领取」这两个字也出现在「已领取」里：点灰按钮没用，还会把下一步带偏
        assertTrue(excludes.toString(), "已领" in excludes)
    }
}
