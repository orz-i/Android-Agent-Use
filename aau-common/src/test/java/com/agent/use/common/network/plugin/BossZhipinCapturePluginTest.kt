package com.agent.use.common.network.plugin

import com.agent.use.common.network.HttpHeader
import com.agent.use.common.network.HttpRequestEvent
import com.agent.use.common.network.HttpResponseEvent
import com.agent.use.common.network.parser.Lz4BlockDecoder
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets
import java.util.zip.GZIPOutputStream

/**
 * 内置包 `bosszhipin`：`BZPBlock` + LZ4 的完整链路。
 *
 * 规则不再写在 Kotlin 里，测试读的是**真正随 APK 发出去的那份 `plugin.json`**，
 * 所以这里同时验证两件事：配置能被解析，解析出来的规则行为正确。
 */
class BossZhipinCapturePluginTest {

    @Before
    fun setUp() {
        BuiltinPluginFixture.ensureLoaded()
    }

    // ------------------------------------------------------------------ 样本构造

    private fun le32(value: Int): ByteArray = byteArrayOf(
        (value and 0xFF).toByte(),
        ((value ushr 8) and 0xFF).toByte(),
        ((value ushr 16) and 0xFF).toByte(),
        ((value ushr 24) and 0xFF).toByte(),
    )

    /** 全 literal 的合法 LZ4 block（不产生 match），用于验证 literal 与扩展长度分支。 */
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

    private fun bzpWrap(compressed: ByteArray, rawSize: Int): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(MAGIC.toByteArray(StandardCharsets.US_ASCII))
        out.write(le32(0))
        out.write(le32(compressed.size))
        out.write(le32(rawSize))
        out.write(le32(1))
        out.write(compressed)
        return out.toByteArray()
    }

    private fun decodeBody(body: ByteArray, headers: List<HttpHeader> = emptyList()): ByteArray? =
        DeclarativeCodecEngine.decode(body, headers, BuiltinPluginFixture.declarative("bosszhipin").responseCodecs)
            ?.bytes

    // ------------------------------------------------------------------ 容器 + LZ4

    @Test
    fun testDecodeLiteralOnlyShortPayload() {
        val payload = "{\"code\":0,\"message\":\"Success\"}".toByteArray()
        assertArrayEquals(payload, decodeBody(bzpWrap(lz4LiteralOnly(payload), payload.size)))
    }

    @Test
    fun testDecodeLiteralOnlyExtendedLength() {
        // > 15 字节触发 token 高位的扩展长度字节；> 270 触发连续 0xFF 累加
        val payload = ByteArray(1200) { ('a'.code + (it % 26)).toByte() }
        assertArrayEquals(payload, decodeBody(bzpWrap(lz4LiteralOnly(payload), payload.size)))
    }

    @Test
    fun testDecodeWithMatchCopiesWithinOutput() {
        // token 0x51 -> literal 5B "hello"，matchLen = 1 + 4 = 5，offset = 5 => "hellohello"
        val compressed = byteArrayOf(
            0x51,
            'h'.code.toByte(), 'e'.code.toByte(), 'l'.code.toByte(), 'l'.code.toByte(), 'o'.code.toByte(),
            0x05, 0x00,
        )
        assertEquals("hellohello", String(decodeBody(bzpWrap(compressed, 10))!!, StandardCharsets.US_ASCII))
    }

    @Test
    fun testDecodeMatchMayOverrunIntoNewlyWrittenBytes() {
        // matchOffset 小于 match 长度时，后半段读的是本轮刚写出的字节
        val compressed = byteArrayOf(
            0x52,
            'h'.code.toByte(), 'e'.code.toByte(), 'l'.code.toByte(), 'l'.code.toByte(), 'o'.code.toByte(),
            0x05, 0x00,
        )
        assertEquals("hellohelloh", String(decodeBody(bzpWrap(compressed, 11))!!, StandardCharsets.US_ASCII))
    }

    @Test
    fun testDecodeWithExtendedMatchLength() {
        // token 0x2F -> literal 2B "ab"，match 长度走扩展字节 179 => 15 + 179 + 4 = 198
        val compressed = byteArrayOf(
            0x2F,
            'a'.code.toByte(), 'b'.code.toByte(),
            0x02, 0x00,
            179.toByte(),
        )
        val decoded = decodeBody(bzpWrap(compressed, 200))
        assertNotNull(decoded)
        assertEquals(200, decoded!!.size)
        assertEquals("ab".repeat(100), String(decoded, StandardCharsets.US_ASCII))
    }

    @Test
    fun testDecodeRejectsImpossibleMatchOffset() {
        // offset 指向输出起点之前，属于畸形流 -> 整条规则判失败，保留原始字节
        val compressed = byteArrayOf(0x11, 'a'.code.toByte(), 0x05, 0x00)
        assertNull(decodeBody(bzpWrap(compressed, 6)))
    }

    @Test
    fun testDecodeRejectsZeroMatchOffset() {
        val compressed = byteArrayOf(0x11, 'a'.code.toByte(), 0x00, 0x00)
        assertNull(decodeBody(bzpWrap(compressed, 6)))
    }

    @Test
    fun testDecodeToleratesTruncatedPayload() {
        // 声明 64B 解压结果，实际只给了 4B literal —— 应返回已解出的前缀而不是整体失败
        val compressed = byteArrayOf(0x40, 'a'.code.toByte(), 'b'.code.toByte(), 'c'.code.toByte(), 'd'.code.toByte())
        val decoded = decodeBody(bzpWrap(compressed, 64))
        assertNotNull(decoded)
        assertEquals("abcd", String(decoded!!, StandardCharsets.US_ASCII))
    }

    @Test
    fun testLz4DecoderRejectsGarbage() {
        // 直接打解码器：容器魔数对了但内部不是 LZ4 时不能吐半截乱码
        assertNull(Lz4BlockDecoder.decode(ByteArray(0)))
        assertNull(Lz4BlockDecoder.decode(byteArrayOf(0x00, 0x00, 0x00), expectedSize = 16))
    }

    // ------------------------------------------------------------------ 中间件

    private fun responseEvent(
        headers: List<HttpHeader> = emptyList(),
        mimeType: String? = "application/octet-stream",
        url: String = "https://www.zhipin.com/wapi/zpgeek/search/joblist.json",
    ) = HttpResponseEvent(
        requestId = "req-1",
        url = url,
        statusCode = 200,
        statusText = "OK",
        headers = headers,
        mimeType = mimeType,
    )

    private fun bossMiddleware(): NetworkTrafficMiddleware =
        NetworkCapturePluginRegistry.resolveMiddlewares("com.hpbr.bosszhipin")
            .first { it.id == NetworkCapturePluginRegistry.declarativeMiddlewareId("com.hpbr.bosszhipin") }

    @Test
    fun testMiddlewareDecodesBzpBlockAndFixesMimeType() {
        val payload = "{\"code\":0,\"message\":\"Success\",\"zpData\":{\"jobList\":[]}}".toByteArray()
        val body = bzpWrap(lz4LiteralOnly(payload), payload.size)

        val (event, out) = bossMiddleware().onResponse("com.hpbr.bosszhipin", responseEvent(), body)

        assertNotNull(out)
        assertArrayEquals(payload, out)
        assertEquals("application/json; charset=utf-8", event.mimeType)
        val hint = event.headers.firstOrNull { it.name == "x-aau-decode-hint" }?.value
        assertNotNull(hint)
        assertTrue(hint!!, hint.startsWith("bzp>lz4:") && hint.endsWith("->${payload.size}"))
    }

    @Test
    fun testMiddlewareDecodesNestedGzipInsideBzpBlock() {
        val inner = "{\"code\":0,\"zpData\":{\"token\":\"abc\"}}".toByteArray()
        val gzipped = ByteArrayOutputStream().also { bos ->
            GZIPOutputStream(bos).use { it.write(inner) }
        }.toByteArray()
        val body = bzpWrap(lz4LiteralOnly(gzipped), gzipped.size)

        val (event, out) = bossMiddleware().onResponse(
            "com.hpbr.bosszhipin",
            responseEvent(headers = listOf(HttpHeader("zp-compressing", "2"))),
            body,
        )

        assertNotNull(out)
        assertArrayEquals(inner, out)
        assertTrue(event.headers.first { it.name == "x-aau-decode-hint" }.value.startsWith("bzp>lz4>gzip:"))
    }

    @Test
    fun testMiddlewareLeavesPlainJsonUntouched() {
        val payload = "{\"code\":0,\"message\":\"Success\"}".toByteArray()
        val (event, out) = bossMiddleware().onResponse(
            "com.hpbr.bosszhipin",
            responseEvent(mimeType = "application/json"),
            payload,
        )
        assertArrayEquals(payload, out)
        assertTrue(event.headers.none { it.name == "x-aau-decode-hint" })
        assertEquals("application/json", event.mimeType)
    }

    @Test
    fun testMiddlewareDecodesStandaloneGzip() {
        val inner = "{\"code\":0}".toByteArray()
        val gzipped = ByteArrayOutputStream().also { bos ->
            GZIPOutputStream(bos).use { it.write(inner) }
        }.toByteArray()
        val (_, out) = bossMiddleware().onResponse("com.hpbr.bosszhipin", responseEvent(), gzipped)
        assertArrayEquals(inner, out)
    }

    @Test
    fun testMiddlewareMarksEncryptedBody() {
        val opaque = ByteArray(42) { (it * 31 + 0xF4).toByte() }
        val (event, out) = bossMiddleware().onResponse(
            "com.hpbr.bosszhipin",
            responseEvent(
                headers = listOf(
                    HttpHeader("zp-compressing", "1"),
                    HttpHeader("zp-encrypting", "1"),
                )
            ),
            opaque,
        )
        assertArrayEquals(opaque, out)
        val hint = event.headers.firstOrNull { it.name == "x-aau-decode-hint" }?.value.orEmpty()
        assertEquals("undecoded:aes:42", hint)
    }

    @Test
    fun testMiddlewareMarksUnknownContainerWithoutEncryption() {
        val opaque = ByteArray(64) { (it * 7).toByte() }
        val (event, out) = bossMiddleware().onResponse(
            "com.hpbr.bosszhipin",
            responseEvent(headers = listOf(HttpHeader("zp-compressing", "3"))),
            opaque,
        )
        assertArrayEquals(opaque, out)
        val hint = event.headers.firstOrNull { it.name == "x-aau-decode-hint" }?.value.orEmpty()
        assertTrue(hint, hint.startsWith("undecoded:raw:") && hint.contains("zp-compressing=3"))
    }

    @Test
    fun testMiddlewareResolvesUnknownHostForBoss() {
        val request = HttpRequestEvent(
            requestId = "req-1",
            url = "https://unknown-host/wapi/zpgeek/search/joblist.json",
            method = "GET",
        )
        val fixed = bossMiddleware().onRequest("com.hpbr.bosszhipin", request)
        assertTrue(fixed.url, fixed.url.startsWith("https://www.zhipin.com/"))
    }

    // ------------------------------------------------------------------ 注册表

    @Test
    fun testPluginRegisteredInRegistry() {
        val middlewares = NetworkCapturePluginRegistry.resolveMiddlewares("com.hpbr.bosszhipin")
        assertTrue(
            middlewares.map { it.id }.toString(),
            middlewares.any { it.id == NetworkCapturePluginRegistry.declarativeMiddlewareId("com.hpbr.bosszhipin") },
        )
        assertTrue(NetworkCapturePluginRegistry.listPluginIds().contains("builtin.bosszhipin"))
        // 其它 App 不应被 BOSS 的规则污染
        val other = NetworkCapturePluginRegistry.resolveMiddlewares("com.example.other")
        assertTrue(other.none { it.id.contains("com.hpbr.bosszhipin") })
        assertTrue(NetworkCapturePluginRegistry.resolveDeclarativeConfig("com.example.other").responseCodecs.isEmpty())
    }

    @Test
    fun testPluginProvidesOpensslOffsetsForTransportLib() {
        // BOSS 的核心接口不走系统 TLS，而是 libzp-sdk-transport.so 里静态链入的 OpenSSL 1.1.1h，
        // 必须给精确偏移，否则 uprobe 挂不到任何东西
        val profile = NetworkCapturePluginRegistry.resolveEbpfProfile("com.hpbr.bosszhipin")
        val rule = profile.sslOffsetRules.singleOrNull { it.libSubstring == "libzp-sdk-transport.so" }
        assertNotNull("缺少 libzp-sdk-transport.so 的 SSL 偏移规则", rule)
        assertEquals(0x1e1ec8L, rule!!.writeOffset)  // SSL_write 入口
        assertEquals(0x1e1a6cL, rule.readOffset)      // SSL_read 入口
        // SSL_set_tlsext_host_name 被内联，没有稳定入口；host 交给 ClientHello 解析
        assertEquals(0L, rule.sniOffset)
        assertTrue(profile.cronetOffsetRules.isEmpty())

        // 规则要能真正落到 --ssl-offsets 参数上
        val args = NetworkCapturePluginRegistry.resolveCliArgs("com.hpbr.bosszhipin")
        assertTrue(
            args.toString(),
            args.contains("libzp-sdk-transport.so:0x1e1ec8:0x1e1a6c:0x0"),
        )
    }

    /**
     * 用真实抓包样本做端到端校验：设 `MIKA_BOSS_SAMPLE` 指向 base64 抓包文件才会执行，
     * 仓库里不放抓取到的业务数据。
     */
    @Test
    fun testDecodeRealCapturedSampleWhenAvailable() {
        val path = System.getenv("MIKA_BOSS_SAMPLE")?.trim().orEmpty()
        if (path.isEmpty()) return
        val file = java.io.File(path)
        if (!file.isFile) return

        val raw = java.util.Base64.getMimeDecoder().decode(file.readText(StandardCharsets.US_ASCII))
        assertTrue("样本缺少 BZPBlock 魔数: $path", raw.size > 24 && String(raw, 0, 8, StandardCharsets.US_ASCII) == MAGIC)

        val decoded = decodeBody(raw)
        assertNotNull("LZ4 解压失败: $path", decoded)

        val text = String(decoded!!, StandardCharsets.UTF_8).trim()
        assertTrue(text.take(32), text.startsWith("{"))
        assertTrue(text, text.contains("\"code\""))
        println("[boss-sample] $path raw=${raw.size} decoded=${decoded.size} jsonChars=${text.length}")
    }

    private companion object {
        const val MAGIC = "BZPBlock"
    }
}
