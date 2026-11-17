package com.agent.use.common.network.plugin

import com.agent.use.common.network.HttpRequestEvent
import com.agent.use.common.network.HttpResponseEvent
import com.agent.use.common.network.INetworkEventListener
import com.agent.use.common.network.NetworkCaptureConfig
import com.agent.use.common.network.parser.TlsStreamParser
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.charset.StandardCharsets

class JniBridgeTest {

    private fun cliOf(rule: JniHookRule): List<String> = rule.toCliArgs()

    @Test
    fun testJniRuleBuildsHookArgument() {
        val cli = cliOf(
            JniHookRule(
                libSubstring = "libyzwg.so",
                methodNames = listOf("nativeDecodeContent", "nativeDecodeRequestBody"),
                maxBytes = 65536
            )
        )
        assertEquals(
            listOf(
                "--jni-hook",
                "libyzwg.so:nativeDecodeContent,nativeDecodeRequestBody",
                "--jni-max-bytes",
                "65536"
            ),
            cli
        )
    }

    @Test
    fun testJniRuleRejectsIncompleteDeclarations() {
        assertTrue(cliOf(JniHookRule(libSubstring = "", methodNames = listOf("a"))).isEmpty())
        assertTrue(cliOf(JniHookRule(libSubstring = "libx.so", methodNames = emptyList())).isEmpty())
        assertTrue(cliOf(JniHookRule(libSubstring = "libx.so", methodNames = listOf(" "))).isEmpty())
    }

    @Test
    fun testJniRuleEmitsNoJsonFlag() {
        val cli = cliOf(
            JniHookRule(
                libSubstring = "libyzwg.so",
                methodNames = listOf("nativeDecodeContent"),
                expectJson = false,
                maxBytes = 1024
            )
        )
        assertTrue(cli.contains("--jni-no-json"))
    }

    @Test
    fun testJniRuleOmitsOutOfRangeMaxBytes() {
        val tooLarge = cliOf(
            JniHookRule(
                libSubstring = "libx.so",
                methodNames = listOf("m"),
                maxBytes = 8 * 1024 * 1024
            )
        )
        assertTrue(!tooLarge.contains("--jni-max-bytes"))

        val negative = cliOf(
            JniHookRule(libSubstring = "libx.so", methodNames = listOf("m"), maxBytes = -1)
        )
        assertTrue(!negative.contains("--jni-max-bytes"))
    }

    @Test
    fun testJniRuleEmitsMagicArgument() {
        val cli = cliOf(
            JniHookRule(
                libSubstring = "libyzwg.so",
                methodNames = listOf("nativeDecodeContent"),
                magic = "BZPBlock",
                maxBytes = 4096
            )
        )
        assertEquals(
            listOf(
                "--jni-hook",
                "libyzwg.so:nativeDecodeContent",
                "--jni-magic",
                "BZPBlock",
                "--jni-max-bytes",
                "4096"
            ),
            cli
        )
    }

    @Test
    fun testJniRuleOmitsBlankMagic() {
        val none = cliOf(JniHookRule(libSubstring = "libx.so", methodNames = listOf("m")))
        assertTrue(!none.contains("--jni-magic"))

        val blank = cliOf(JniHookRule(libSubstring = "libx.so", methodNames = listOf("m"), magic = "  "))
        assertTrue(!blank.contains("--jni-magic"))
    }

    @Test
    fun testProfileConcatenatesJniRules() {
        val profile = EbpfProbeProfile(
            jniHookRules = listOf(
                JniHookRule(libSubstring = "libyzwg.so", methodNames = listOf("nativeDecodeContent"))
            )
        )
        val cli = profile.toCliArgs()
        val idx = cli.indexOf("--jni-hook")
        assertTrue(idx >= 0)
        assertEquals("libyzwg.so:nativeDecodeContent", cli[idx + 1])
    }

    @Test
    fun testBossPluginDeclaresYzwgDecoder() {
        val profile = BossZhipinCapturePlugin.provideEbpfProfile("com.hpbr.bosszhipin")
        assertEquals(1, profile.jniHookRules.size)
        val rule = profile.jniHookRules.first()
        assertEquals("libyzwg.so", rule.libSubstring)
        assertTrue(rule.methodNames.contains("nativeDecodeContent"))
        assertTrue(rule.captureReturn)
        assertTrue(rule.expectJson)
    }

    @Test
    fun testBossPluginDeclaresBzpBlockMagic() {
        val rule = BossZhipinCapturePlugin.provideEbpfProfile("com.hpbr.bosszhipin")
            .jniHookRules.first()
        assertEquals("BZPBlock", rule.magic)
        val cli = rule.toCliArgs()
        val idx = cli.indexOf("--jni-magic")
        assertTrue(idx >= 0)
        assertEquals("BZPBlock", cli[idx + 1])
    }

    @Test
    fun testBossPluginIgnoresForeignPackage() {
        val profile = BossZhipinCapturePlugin.provideEbpfProfile("com.example.other")
        assertTrue(profile.jniHookRules.isEmpty())
    }

    private fun configFor(pkg: String) = NetworkCaptureConfig(
        targetPackage = pkg,
        urlFilterPattern = ".*zhipin\\.com.*"
    )

    private class RecordingListener : INetworkEventListener.Stub() {
        val responses = mutableListOf<HttpResponseEvent>()
        override fun onRequestWillBeSent(event: HttpRequestEvent) {}
        override fun onResponseReceived(event: HttpResponseEvent) {
            responses.add(event)
        }
        override fun onDataChunkReceived(requestId: String, chunk: ByteArray) {}
        override fun onErrorOccurred(requestId: String, error: String) {}
    }

    private fun cipherBytes(size: Int): ByteArray =
        ByteArray(size) { i -> (0xF4 + i * 7).toByte() }

    @Test
    fun testDecodedBodyReplacesEncryptedJsonResponse() {
        val listener = RecordingListener()
        val parser = TlsStreamParser(configFor("com.hpbr.bosszhipin"), listener)

        val cipher = cipherBytes(8)
        parser.onOutboundData(
            "c1",
            "GET /api/batch/batchRunV2 HTTP/1.1\r\nHost: api5.zhipin.com\r\n\r\n"
                .toByteArray(StandardCharsets.ISO_8859_1)
        )
        val plain = "{\"zpData\":{\"jobList\":[{\"jobName\":\"Android\"}]}}"
        parser.onDecodedJniBody(0, plain.toByteArray(StandardCharsets.UTF_8))
        parser.onInboundData(
            "c1",
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                .plus("Content-Length: ${cipher.size}\r\n\r\n")
                .toByteArray(StandardCharsets.ISO_8859_1) + cipher
        )

        assertEquals(1, listener.responses.size)
        val event = listener.responses[0]
        val hint = event.headers.firstOrNull { it.name.equals("x-aau-decode-hint", true) }?.value
        assertNotNull(hint)
        assertEquals("jni:8->${plain.length}", hint)

        val body = parser.getResponseBody(event.requestId)
        assertNotNull(body)
        assertArrayEquals(plain.toByteArray(StandardCharsets.UTF_8), body)
        assertEquals(plain.length.toLong(), event.contentLength)
    }

    @Test
    fun testDecodedBodyDoesNotClobberPlaintextJsonResponse() {
        val listener = RecordingListener()
        val parser = TlsStreamParser(configFor("com.hpbr.bosszhipin"), listener)

        val plainResponse = "{\"ok\":true}"
        parser.onOutboundData(
            "c1",
            "GET /api/plain HTTP/1.1\r\nHost: api5.zhipin.com\r\n\r\n"
                .toByteArray(StandardCharsets.ISO_8859_1)
        )
        parser.onDecodedJniBody(0, "{\"leaked\":true}".toByteArray(StandardCharsets.UTF_8))
        parser.onInboundData(
            "c1",
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                .plus("Content-Length: ${plainResponse.length}\r\n\r\n")
                .toByteArray(StandardCharsets.ISO_8859_1) + plainResponse.toByteArray(
                StandardCharsets.UTF_8
            )
        )

        assertEquals(1, listener.responses.size)
        val event = listener.responses[0]
        assertNull(event.headers.firstOrNull { it.name.equals("x-aau-decode-hint", true) })
        val body = parser.getResponseBody(event.requestId)
        assertArrayEquals(plainResponse.toByteArray(StandardCharsets.UTF_8), body)
    }

    @Test
    fun testDecodedBodyIgnoredForNonJsonResponses() {
        val listener = RecordingListener()
        val parser = TlsStreamParser(configFor("com.hpbr.bosszhipin"), listener)

        parser.onOutboundData(
            "c1",
            "GET /static/logo.png HTTP/1.1\r\nHost: img.bosszhipin.com\r\n\r\n"
                .toByteArray(StandardCharsets.ISO_8859_1)
        )
        parser.onDecodedJniBody(0, "{\"should\":\"not-apply\"}".toByteArray(StandardCharsets.UTF_8))
        parser.onInboundData(
            "c1",
            "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: 4\r\n\r\n"
                .toByteArray(StandardCharsets.ISO_8859_1) + cipherBytes(4)
        )

        assertEquals(1, listener.responses.size)
        val event = listener.responses[0]
        assertNull(event.headers.firstOrNull { it.name.equals("x-aau-decode-hint", true) })
        assertArrayEquals(cipherBytes(4), parser.getResponseBody(event.requestId))
    }

    @Test
    fun testDecodedBodyAcceptsContainerPayload() {
        val listener = RecordingListener()
        val parser = TlsStreamParser(configFor("com.hpbr.bosszhipin"), listener)

        // nativeDecodeContent 有时返回 BZPBlock 容器而非裸 JSON：
        // 头部是 ASCII 魔数，应被接受并由中间件再剥一层 LZ4。
        val container = ByteArray(24) { 0x00 }
        "BZPBlock".toByteArray(StandardCharsets.US_ASCII).copyInto(container, 0)
        val cipher = cipherBytes(8)

        parser.onOutboundData(
            "c1",
            "GET /api/batch/batchRunV2 HTTP/1.1\r\nHost: api5.zhipin.com\r\n\r\n"
                .toByteArray(StandardCharsets.ISO_8859_1)
        )
        parser.onDecodedJniBody(0, container)
        parser.onInboundData(
            "c1",
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                .plus("Content-Length: ${cipher.size}\r\n\r\n")
                .toByteArray(StandardCharsets.ISO_8859_1) + cipher
        )

        assertEquals(1, listener.responses.size)
        val event = listener.responses[0]
        val hint = event.headers.firstOrNull { it.name.equals("x-aau-decode-hint", true) }?.value
        assertEquals("jni:8->24", hint)
        assertArrayEquals(container, parser.getResponseBody(event.requestId))
    }

    @Test
    fun testDecodedBodyTranscodesUtf16() {
        val listener = RecordingListener()
        val parser = TlsStreamParser(configFor("com.hpbr.bosszhipin"), listener)

        // BOSS 的解码器有时返回 UTF-16LE 的 JSON，字节形态对但首字节后是 0x00。
        val plain = "{\"code\":0,\"zpData\":{\"jobName\":\"Android\"}}"
        val utf16 = plain.toByteArray(Charsets.UTF_16LE)
        val cipher = cipherBytes(8)

        parser.onOutboundData(
            "c1",
            "GET /api/batch/batchRunV2 HTTP/1.1\r\nHost: api5.zhipin.com\r\n\r\n"
                .toByteArray(StandardCharsets.ISO_8859_1)
        )
        parser.onDecodedJniBody(0, utf16)
        parser.onInboundData(
            "c1",
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                .plus("Content-Length: ${cipher.size}\r\n\r\n")
                .toByteArray(StandardCharsets.ISO_8859_1) + cipher
        )

        assertEquals(1, listener.responses.size)
        val event = listener.responses[0]
        assertEquals("jni:8->${plain.length}", event.headers
            .firstOrNull { it.name.equals("x-aau-decode-hint", true) }?.value)
        assertArrayEquals(plain.toByteArray(Charsets.UTF_8), parser.getResponseBody(event.requestId))
    }

    @Test
    fun testDecodedBodyRejectsTruncatedJson() {
        val listener = RecordingListener()
        val parser = TlsStreamParser(configFor("com.hpbr.bosszhipin"), listener)

        // 解码器把大字符串拆成多个数组时，第一段是合法前缀但没有闭合，
        // 这种载荷回填会比保留密文更糟，必须拒绝。
        val truncated = "{\"ipv6Priority\":true,\"mqttHttpIps\":[\"47.93.82.152:80\"],\"code\":0,\"mess"
            .toByteArray(StandardCharsets.UTF_8)
        val cipher = cipherBytes(8)

        parser.onOutboundData(
            "c1",
            "GET /api/batch/batchRunV2 HTTP/1.1\r\nHost: api5.zhipin.com\r\n\r\n"
                .toByteArray(StandardCharsets.ISO_8859_1)
        )
        parser.onDecodedJniBody(0, truncated)
        parser.onInboundData(
            "c1",
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                .plus("Content-Length: ${cipher.size}\r\n\r\n")
                .toByteArray(StandardCharsets.ISO_8859_1) + cipher
        )

        assertEquals(1, listener.responses.size)
        val event = listener.responses[0]
        assertNull(event.headers.firstOrNull { it.name.equals("x-aau-decode-hint", true) })
        assertArrayEquals(cipher, parser.getResponseBody(event.requestId))
    }

    @Test
    fun testDecodedBodyRejectsGarbagePayload() {
        val listener = RecordingListener()
        val parser = TlsStreamParser(configFor("com.hpbr.bosszhipin"), listener)

        // 误读的 jbyteArray 会读回进程里的任意内存，首字节基本不可能是可打印字符。
        // 这种帧必须被拒绝，否则会用一个更没用的垃圾覆盖掉原始密文。
        val garbage = ByteArray(16) { 0x01 }
        val cipher = cipherBytes(8)

        parser.onOutboundData(
            "c1",
            "GET /api/batch/batchRunV2 HTTP/1.1\r\nHost: api5.zhipin.com\r\n\r\n"
                .toByteArray(StandardCharsets.ISO_8859_1)
        )
        parser.onDecodedJniBody(0, garbage)
        parser.onInboundData(
            "c1",
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                .plus("Content-Length: ${cipher.size}\r\n\r\n")
                .toByteArray(StandardCharsets.ISO_8859_1) + cipher
        )

        assertEquals(1, listener.responses.size)
        val event = listener.responses[0]
        assertNull(event.headers.firstOrNull { it.name.equals("x-aau-decode-hint", true) })
        assertArrayEquals(cipher, parser.getResponseBody(event.requestId))
    }
}
