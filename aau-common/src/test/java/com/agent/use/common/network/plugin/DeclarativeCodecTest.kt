package com.agent.use.common.network.plugin

import com.agent.use.common.network.HttpHeader
import com.agent.use.common.network.HttpRequestEvent
import com.agent.use.common.network.HttpResponseEvent
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets
import java.util.Base64
import java.util.zip.GZIPOutputStream

/**
 * 声明式解码管道：同一个 `BZPBlock` 容器必须能被一份 JSON 解出来，而不只是靠手写 Kotlin。
 */
class DeclarativeCodecTest {

    @After
    fun tearDown() {
        NetworkCapturePluginRegistry.clearJsonProfileOverrides()
    }

    // ------------------------------------------------------------------ 样本

    private val payload = """{"code":0,"msg":"ok","zpData":{"list":["android","kotlin","ebpf"]}}"""
    private val payloadBytes: ByteArray get() = payload.toByteArray(StandardCharsets.UTF_8)

    private fun le32(value: Int): ByteArray = byteArrayOf(
        (value and 0xFF).toByte(),
        ((value ushr 8) and 0xFF).toByte(),
        ((value ushr 16) and 0xFF).toByte(),
        ((value ushr 24) and 0xFF).toByte(),
    )

    /** 全 literal 的合法 LZ4 block，够用来验证容器 + 解压两步链路。 */
    private fun lz4LiteralOnly(data: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        if (data.size < 15) {
            out.write(data.size shl 4)
        } else {
            out.write(0xF0)
            var rest = data.size - 15
            while (rest >= 255) {
                out.write(255)
                rest -= 255
            }
            out.write(rest)
        }
        out.write(data)
        return out.toByteArray()
    }

    private fun bzpBlock(raw: ByteArray): ByteArray {
        val compressed = lz4LiteralOnly(raw)
        val out = ByteArrayOutputStream()
        out.write("BZPBlock".toByteArray(StandardCharsets.US_ASCII))
        out.write(le32(0))
        out.write(le32(compressed.size))
        out.write(le32(raw.size))
        out.write(le32(1))
        out.write(compressed)
        return out.toByteArray()
    }

    private fun gzip(raw: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        GZIPOutputStream(out).use { it.write(raw) }
        return out.toByteArray()
    }

    private val bzpConfigJson = """
        {
          "hostFix": { "headerPriority": ["x-bz-host", ":authority"], "defaultHost": "www.zhipin.com" },
          "responseCodecs": [
            {
              "id": "bzp",
              "when": [{ "header": "zp-compressing", "equals": "2" }],
              "steps": [
                { "op": "container", "magic": "BZPBlock", "headerSize": 24,
                  "payloadLen": { "at": 12, "width": 4, "endian": "le" },
                  "rawLen": { "at": 16, "width": 4, "endian": "le" } },
                { "op": "decompress", "algo": "lz4-block" }
              ]
            }
          ]
        }
    """.trimIndent()

    // ------------------------------------------------------------------ 解码

    @Test
    fun configAloneDecodesBzpBlock() {
        val config = DeclarativeConfigs.parse(bzpConfigJson)
        assertNotNull(config)
        val decoded = DeclarativeCodecEngine.decode(
            body = bzpBlock(payloadBytes),
            headers = listOf(HttpHeader("zp-compressing", "2")),
            rules = config!!.responseCodecs,
        )
        assertNotNull("BZPBlock 应该能被声明式管道解开", decoded)
        assertArrayEquals(payloadBytes, decoded!!.bytes)
        assertTrue(decoded.trace, decoded.trace.contains("lz4-block"))
    }

    @Test
    fun whenConditionGatesTheRule() {
        val config = DeclarativeConfigs.parse(bzpConfigJson)!!
        // zp-compressing: 0 是明文，不该套容器解码
        assertNull(
            DeclarativeCodecEngine.decode(
                body = bzpBlock(payloadBytes),
                headers = listOf(HttpHeader("zp-compressing", "0")),
                rules = config.responseCodecs,
            )
        )
        assertNull(
            DeclarativeCodecEngine.decode(
                body = bzpBlock(payloadBytes),
                headers = emptyList(),
                rules = config.responseCodecs,
            )
        )
    }

    @Test
    fun containerThenGzipAndBase64StripPrefix() {
        val containerConfig = DeclarativeConfigs.parse(
            """
            { "responseCodecs": [{ "steps": [
                { "op": "container", "magic": "ACME", "headerSize": 16 },
                { "op": "decompress", "algo": "gzip" }
            ] }] }
            """.trimIndent()
        )!!
        val acmeBody = "ACME".toByteArray() + ByteArray(12) + gzip(payloadBytes)
        val gzDecoded = DeclarativeCodecEngine.decode(acmeBody, emptyList(), containerConfig.responseCodecs)
        assertNotNull(gzDecoded)
        assertArrayEquals(payloadBytes, gzDecoded!!.bytes)

        val textConfig = DeclarativeConfigs.parse(
            """
            { "responseCodecs": [{ "steps": [
                { "op": "stripPrefix", "prefixBytes": 4 },
                { "op": "base64" }
            ] }] }
            """.trimIndent()
        )!!
        val encoded = "SALT".toByteArray() + Base64.getEncoder().encode(payloadBytes)
        val textDecoded = DeclarativeCodecEngine.decode(encoded, emptyList(), textConfig.responseCodecs)
        assertNotNull(textDecoded)
        assertArrayEquals(payloadBytes, textDecoded!!.bytes)
    }

    @Test
    fun brokenStepKeepsOriginalBody() {
        val config = DeclarativeConfigs.parse(
            """{ "responseCodecs": [{ "steps": [{ "op": "decompress", "algo": "gzip" }] }] }"""
        )!!
        // 不是 gzip 的字节：宁可不改，也不能把乱码当明文
        assertNull(
            DeclarativeCodecEngine.decode(
                "plain text, definitely not gzip".toByteArray(StandardCharsets.UTF_8),
                emptyList(),
                config.responseCodecs,
            )
        )
    }

    @Test
    fun alreadyPlaintextBodyIsLeftAlone() {
        // 明文响应套一个"改不了"的容器规则：不该把 JSON 当成容器载荷切成垃圾
        val config = DeclarativeConfigs.parse(bzpConfigJson)!!
        assertNull(DeclarativeCodecEngine.decode(payloadBytes, emptyList(), config.responseCodecs))
    }

    @Test
    fun invalidJsonAndUnknownOpAreRejected() {
        assertNull(DeclarativeConfigs.parse("{ this is not json }"))
        val config = DeclarativeConfigs.parse(
            """{ "responseCodecs": [{ "steps": [{ "op": "aes-decrypt" }] }] }"""
        )!!
        assertTrue(config.responseCodecs.isEmpty())
    }

    // ------------------------------------------------------------------ 中间件

    @Test
    fun middlewareRewritesUnknownHostAndDecodesResponse() {
        val config = DeclarativeConfigs.parse(bzpConfigJson)!!
        val middleware = DeclarativeTrafficMiddleware("declarative:test", config)

        val request = HttpRequestEvent(
            requestId = "r1",
            url = "https://unknown-host/wapi/zpgeek/search/joblist.json",
            method = "GET",
            headers = listOf(HttpHeader(":authority", "www.zhipin.com")),
        )
        assertEquals(
            "https://www.zhipin.com/wapi/zpgeek/search/joblist.json",
            middleware.onRequest("com.hpbr.bosszhipin", request).url,
        )

        val noHeader = request.copy(headers = emptyList())
        assertEquals(
            "https://www.zhipin.com/wapi/zpgeek/search/joblist.json",
            middleware.onRequest("com.hpbr.bosszhipin", noHeader).url,
        )

        val response = HttpResponseEvent(
            requestId = "r1",
            url = "https://www.zhipin.com/wapi/zpgeek/search/joblist.json",
            statusCode = 200,
            statusText = "OK",
            headers = listOf(HttpHeader("zp-compressing", "2")),
            mimeType = "application/octet-stream",
        )
        val (event, body) = middleware.onResponse("com.hpbr.bosszhipin", response, bzpBlock(payloadBytes))
        assertArrayEquals(payloadBytes, body!!)
        assertEquals("application/json; charset=utf-8", event.mimeType)
        assertTrue(event.headers.any { it.name == DeclarativeCodecEngine.DECODE_HINT_HEADER })
    }

    // ------------------------------------------------------------------ 配置往返

    @Test
    fun profileJsonKeepsDeclarativeConfig() {
        val json = """
            {
              "com.acme.market": {
                "jniHookRules": [
                  { "libSubstring": "libacme.so", "methodNames": ["nativeDecode"], "magic": "ACME" }
                ],
                "hostFix": { "headerPriority": ["x-acme-host"], "defaultHost": "api.acme.com" },
                "responseCodecs": [
                  { "id": "acme", "steps": [
                      { "op": "container", "magic": "ACME", "headerSize": 16,
                        "rawLen": { "at": 12, "width": 4 } },
                      { "op": "decompress", "algo": "gzip" }
                  ] }
                ]
              }
            }
        """.trimIndent()

        val parsed = EbpfProbeProfile.fromJson(json)["com.acme.market"]
        assertNotNull(parsed)
        assertEquals("api.acme.com", parsed!!.declarative.hostFix?.defaultHost)
        assertEquals(2, parsed.declarative.responseCodecs.single().steps.size)

        val written = EbpfProbeProfile.toJson(mapOf("com.acme.market" to parsed))
        val reparsed = EbpfProbeProfile.fromJson(written)["com.acme.market"]
        assertNotNull(reparsed)
        assertEquals(parsed.declarative, reparsed!!.declarative)
        // 同时确认写出来的 JSON 没有把探测规则弄丢
        assertEquals("libacme.so", reparsed.jniHookRules.single().libSubstring)
        assertEquals("ACME", reparsed.jniHookRules.single().magic)
    }

    @Test
    fun registryAddsDeclarativeMiddlewareFromOverride() {
        val config = DeclarativeConfigs.parse(bzpConfigJson)!!
        NetworkCapturePluginRegistry.registerJsonProfileOverride(
            "com.acme.market",
            EbpfProbeProfile(declarative = config),
        )
        val id = NetworkCapturePluginRegistry.declarativeMiddlewareId("com.acme.market")
        val middlewares = NetworkCapturePluginRegistry.resolveMiddlewares("com.acme.market")
        assertTrue(middlewares.map { it.id }.toString(), middlewares.any { it.id == id })
        assertEquals(config, NetworkCapturePluginRegistry.resolveDeclarativeConfig("com.acme.market"))
    }
}
