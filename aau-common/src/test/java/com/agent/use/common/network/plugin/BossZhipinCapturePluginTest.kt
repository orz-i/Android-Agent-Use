package com.agent.use.common.network.plugin

import com.agent.use.common.network.HttpHeader
import com.agent.use.common.network.HttpRequestEvent
import com.agent.use.common.network.HttpResponseEvent
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets

/**
 * BOSS 直聘插件：`BZPBlock` + LZ4 block 解码链路回归测试。
 *
 * 样本全部在测试内构造，不依赖抓包产物，覆盖 literal-only、match、扩展长度三种 LZ4 序列形态。
 */
class BossZhipinCapturePluginTest {

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
        out.write(BzpBlockCodec.MAGIC.toByteArray(StandardCharsets.US_ASCII))
        out.write(le32(0))
        out.write(le32(compressed.size))
        out.write(le32(rawSize))
        out.write(le32(1))
        out.write(compressed)
        return out.toByteArray()
    }

    // ------------------------------------------------------------------ 头部

    @Test
    fun testReadHeaderLittleEndian() {
        val payload = "{\"code\":0}".toByteArray()
        val wrapped = bzpWrap(lz4LiteralOnly(payload), payload.size)

        assertTrue(BzpBlockCodec.hasMagic(wrapped))
        val header = BzpBlockCodec.readHeader(wrapped)
        assertNotNull(header)
        assertEquals(0, header!!.version)
        assertEquals(wrapped.size - BzpBlockCodec.HEADER_SIZE, header.payloadSize)
        assertEquals(payload.size, header.rawSize)
    }

    @Test
    fun testHasMagicRejectsShortOrForeignBuffer() {
        assertFalse(BzpBlockCodec.hasMagic(ByteArray(0)))
        assertFalse(BzpBlockCodec.hasMagic("BZPBloc".toByteArray()))
        assertFalse(BzpBlockCodec.hasMagic("{\"code\":0,\"message\":\"ok\"}".toByteArray()))
        assertNull(BzpBlockCodec.readHeader("{\"a\":1}".toByteArray()))
    }

    // ------------------------------------------------------------------ LZ4

    @Test
    fun testDecodeLiteralOnlyShortPayload() {
        val payload = "{\"code\":0,\"message\":\"Success\"}".toByteArray()
        val decoded = BzpBlockCodec.decode(bzpWrap(lz4LiteralOnly(payload), payload.size))
        assertNotNull(decoded)
        assertArrayEquals(payload, decoded)
    }

    @Test
    fun testDecodeLiteralOnlyExtendedLength() {
        // > 15 字节触发 token 高位的扩展长度字节；> 270 触发连续 0xFF 累加
        val payload = ByteArray(1200) { ('a'.code + (it % 26)).toByte() }
        val decoded = BzpBlockCodec.decode(bzpWrap(lz4LiteralOnly(payload), payload.size))
        assertNotNull(decoded)
        assertArrayEquals(payload, decoded)
    }

    @Test
    fun testDecodeWithMatchCopiesWithinOutput() {
        // token 0x51 -> literal 5B "hello"，matchLen = 1 + 4 = 5，offset = 5 => 输出 "hellohello"
        val compressed = byteArrayOf(
            0x51,
            'h'.code.toByte(), 'e'.code.toByte(), 'l'.code.toByte(), 'l'.code.toByte(), 'o'.code.toByte(),
            0x05, 0x00,
        )
        val decoded = BzpBlockCodec.decode(bzpWrap(compressed, 10))
        assertNotNull(decoded)
        assertEquals("hellohello", String(decoded!!, StandardCharsets.US_ASCII))
    }

    @Test
    fun testDecodeMatchMayOverrunIntoNewlyWrittenBytes() {
        // matchOffset 小于 match 长度时，后半段读的是本轮刚写出的字节
        // token 0x52 -> literal 5B "hello"，matchLen = 2 + 4 = 6 => "hello" + "helloh"
        val compressed = byteArrayOf(
            0x52,
            'h'.code.toByte(), 'e'.code.toByte(), 'l'.code.toByte(), 'l'.code.toByte(), 'o'.code.toByte(),
            0x05, 0x00,
        )
        val decoded = BzpBlockCodec.decode(bzpWrap(compressed, 11))
        assertNotNull(decoded)
        assertEquals("hellohelloh", String(decoded!!, StandardCharsets.US_ASCII))
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
        val decoded = BzpBlockCodec.decode(bzpWrap(compressed, 200))
        assertNotNull(decoded)
        assertEquals(200, decoded!!.size)
        assertEquals("ab".repeat(100), String(decoded, StandardCharsets.US_ASCII))
    }

    @Test
    fun testDecodeRejectsImpossibleMatchOffset() {
        // offset 指向输出起点之前，属于畸形流 -> 整体判失败，保留原始字节
        val compressed = byteArrayOf(
            0x11, 'a'.code.toByte(),
            0x05, 0x00,
        )
        assertNull(BzpBlockCodec.decode(bzpWrap(compressed, 6)))
    }

    @Test
    fun testDecodeRejectsZeroMatchOffset() {
        val compressed = byteArrayOf(
            0x11, 'a'.code.toByte(),
            0x00, 0x00,
        )
        assertNull(BzpBlockCodec.decode(bzpWrap(compressed, 6)))
    }

    @Test
    fun testDecodeToleratesTruncatedPayload() {
        // 声明 64B 解压结果，实际只给了 4B literal —— 应返回已解出的前缀而不是整体失败
        val compressed = byteArrayOf(0x40, 'a'.code.toByte(), 'b'.code.toByte(), 'c'.code.toByte(), 'd'.code.toByte())
        val decoded = BzpBlockCodec.decode(bzpWrap(compressed, 64))
        assertNotNull(decoded)
        assertEquals("abcd", String(decoded!!, StandardCharsets.US_ASCII))
    }

    // ------------------------------------------------------------------ 中间件

    private fun responseEvent(
        pkg: String = "com.hpbr.bosszhipin",
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

    @Test
    fun testMiddlewareDecodesBzpBlockAndFixesMimeType() {
        val payload = "{\"code\":0,\"message\":\"Success\",\"zpData\":{\"jobList\":[]}}".toByteArray()
        val body = bzpWrap(lz4LiteralOnly(payload), payload.size)

        val (event, out) = BossZhipinTrafficMiddleware.onResponse(
            "com.hpbr.bosszhipin",
            responseEvent(),
            body,
        )

        assertNotNull(out)
        assertArrayEquals(payload, out)
        assertEquals("application/json; charset=utf-8", event.mimeType)
        val hint = event.headers.firstOrNull { it.name == "x-aau-decode-hint" }?.value
        assertNotNull(hint)
        assertTrue(hint!!, hint.startsWith("bzp-lz4:") && hint.endsWith("->${payload.size}"))
    }

    @Test
    fun testMiddlewareDecodesNestedGzipInsideBzpBlock() {
        val inner = "{\"code\":0,\"zpData\":{\"token\":\"abc\"}}".toByteArray()
        val gzipped = ByteArrayOutputStream().also { bos ->
            java.util.zip.GZIPOutputStream(bos).use { it.write(inner) }
        }.toByteArray()
        val body = bzpWrap(lz4LiteralOnly(gzipped), gzipped.size)

        val (event, out) = BossZhipinTrafficMiddleware.onResponse(
            "com.hpbr.bosszhipin",
            responseEvent(headers = listOf(HttpHeader("zp-compressing", "2"))),
            body,
        )

        assertNotNull(out)
        assertArrayEquals(inner, out)
        assertTrue(event.headers.first { it.name == "x-aau-decode-hint" }.value.startsWith("bzp-lz4>gzip:"))
    }

    @Test
    fun testMiddlewareLeavesPlainJsonUntouched() {
        val payload = "{\"code\":0,\"message\":\"Success\"}".toByteArray()
        val (event, out) = BossZhipinTrafficMiddleware.onResponse(
            "com.hpbr.bosszhipin",
            responseEvent(mimeType = "application/json"),
            payload,
        )
        assertArrayEquals(payload, out)
        assertTrue(event.headers.none { it.name == "x-aau-decode-hint" })
        assertEquals("application/json", event.mimeType)
    }

    @Test
    fun testMiddlewareIgnoresOtherPackages() {
        val payload = "{\"code\":0}".toByteArray()
        val body = bzpWrap(lz4LiteralOnly(payload), payload.size)
        val (event, out) = BossZhipinTrafficMiddleware.onResponse(
            "com.example.other",
            responseEvent(pkg = "com.example.other"),
            body,
        )
        assertArrayEquals(body, out)
        assertTrue(event.headers.none { it.name == "x-aau-decode-hint" })
    }

    @Test
    fun testMiddlewareMarksEncryptedBody() {
        val opaque = ByteArray(42) { (it * 31 + 0xF4).toByte() }
        val (event, out) = BossZhipinTrafficMiddleware.onResponse(
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
        assertTrue(hint, hint == "bzp-aes:42")
    }

    @Test
    fun testMiddlewareMarksUnknownContainerWithoutEncryption() {
        val opaque = ByteArray(64) { (it * 7).toByte() }
        val (event, out) = BossZhipinTrafficMiddleware.onResponse(
            "com.hpbr.bosszhipin",
            responseEvent(headers = listOf(HttpHeader("zp-compressing", "3"))),
            opaque,
        )
        assertArrayEquals(opaque, out)
        val hint = event.headers.firstOrNull { it.name == "x-aau-decode-hint" }?.value.orEmpty()
        assertTrue(hint, hint.startsWith("bzp-raw:") && hint.contains("compress=3"))
    }

    @Test
    fun testMiddlewareResolvesUnknownHostForBoss() {
        val request = HttpRequestEvent(
            requestId = "req-1",
            url = "https://unknown-host/wapi/zpgeek/search/joblist.json",
            method = "GET",
        )
        val fixed = BossZhipinTrafficMiddleware.onRequest("com.hpbr.bosszhipin", request)
        assertTrue(fixed.url, fixed.url.startsWith("https://www.zhipin.com/"))
    }

    // ------------------------------------------------------------------ 注册表

    @Test
    fun testPluginRegisteredInRegistry() {
        val middlewares = NetworkCapturePluginRegistry.resolveMiddlewares("com.hpbr.bosszhipin")
        assertTrue(
            middlewares.map { it.id }.toString(),
            middlewares.any { it.id == BossZhipinTrafficMiddleware.id },
        )
        // 其它 App 不应被 BOSS 中间件污染
        val other = NetworkCapturePluginRegistry.resolveMiddlewares("com.example.other")
        assertTrue(other.none { it.id == BossZhipinTrafficMiddleware.id })
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
        val header = BzpBlockCodec.readHeader(raw)
        assertNotNull("样本缺少 BZPBlock 头: $path", header)

        val decoded = BzpBlockCodec.decode(raw)
        assertNotNull("LZ4 解压失败: $path", decoded)
        assertEquals("解压尺寸与头部声明不一致", header!!.rawSize, decoded!!.size)

        val text = String(decoded, StandardCharsets.UTF_8).trim()
        assertTrue(text.take(32), text.startsWith("{"))
        assertTrue(text, text.contains("\"code\""))
        println("[boss-sample] $path raw=${raw.size} decoded=${decoded.size} jsonChars=${text.length}")
    }
}
