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

    /**
     * 模拟一次 native 解码回调：[sourceSize] 是喂给解码器的密文长度，也就是这条明文
     * 所属响应体的字节数——抓包通道能拿到的唯一精确身份。
     */
    private fun TlsStreamParser.decoded(
        plain: ByteArray,
        sourceSize: Int,
        method: Int = 0,
        fingerprint: IntArray? = null
    ) = onDecodedJniBody(method, plain, intArrayOf(sourceSize), fingerprint)

    /** 解码器入参数组开头 16 字节，按 loader 的格式摊成 4 个小端 u32。 */
    private fun fingerprintOf(bytes: ByteArray): IntArray {
        val out = IntArray(4)
        for (i in 0 until 4) {
            var w = 0
            for (k in 0 until 4) {
                val idx = i * 4 + k
                val b = if (idx < bytes.size) bytes[idx].toInt() and 0xFF else 0
                w = w or (b shl (k * 8))
            }
            out[i] = w
        }
        return out
    }

    @Test
    fun testFingerprintPicksTheRightCiphertextAmongEqualLengths() {
        val listener = RecordingListener()
        val parser = TlsStreamParser(configFor("com.hpbr.bosszhipin"), listener)

        // 两条响应一样长、都不是 JSON:按长度谁都不唯一,按指纹才分得清。
        val cipherA = ByteArray(8) { i -> (0x10 + i).toByte() }
        val cipherB = ByteArray(8) { i -> (0x80 + i).toByte() }
        val plainB = "{\"which\":\"b\"}"

        parser.decoded(plainB.toByteArray(StandardCharsets.UTF_8), cipherB.size, 0, fingerprintOf(cipherB))

        for ((conn, cipher) in listOf("c1" to cipherA, "c2" to cipherB)) {
            parser.onOutboundData(
                conn,
                "GET /api/batch/requests?$conn HTTP/1.1\r\nHost: api-and.zhipin.com\r\n\r\n"
                    .toByteArray(StandardCharsets.ISO_8859_1)
            )
            parser.onInboundData(
                conn,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                    .plus("Content-Length: ${cipher.size}\r\n\r\n")
                    .toByteArray(StandardCharsets.ISO_8859_1) + cipher
            )
        }

        assertEquals(2, listener.responses.size)
        val byPath = listener.responses.associateBy { it.url.substringAfter("?") }
        val hit = byPath.getValue("c2")
        assertNotNull(hit.headers.firstOrNull { it.name.equals("x-aau-decode-hint", true) })
        assertArrayEquals(
            plainB.toByteArray(StandardCharsets.UTF_8),
            parser.getResponseBody(hit.requestId)
        )
        val miss = byPath.getValue("c1")
        assertNull(miss.headers.firstOrNull { it.name.equals("x-aau-decode-hint", true) })
        assertArrayEquals(cipherA, parser.getResponseBody(miss.requestId))
    }
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
        parser.decoded(plain.toByteArray(StandardCharsets.UTF_8), cipher.size)
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
        parser.decoded("{\"leaked\":true}".toByteArray(StandardCharsets.UTF_8), plainResponse.length)
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
        parser.decoded("{\"should\":\"not-apply\"}".toByteArray(StandardCharsets.UTF_8), 4)
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
        parser.decoded(container, cipher.size)
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
        parser.decoded(utf16, cipher.size)
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
        parser.decoded(truncated, cipher.size)
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
        parser.decoded(garbage, cipher.size)
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
    fun testDecodedBodyMatchedBySourceLengthNotArrivalOrder() {
        val listener = RecordingListener()
        val parser = TlsStreamParser(configFor("com.hpbr.bosszhipin"), listener)

        // 并发的一批请求里，先到的明文不一定属于先完的响应。能对上号的是解码器入参长度，
        // 也就是它来源响应的密文长度：先来的那条属于另一个 12 字节的响应。
        val other = "{\"decoy\":true}"
        val real = "{\"ab\":1}"
        val cipher = cipherBytes(8)
        assertEquals(14, other.length)
        assertEquals(8, real.length)

        parser.onOutboundData(
            "c1",
            "GET /api/batch/batchRunV2 HTTP/1.1\r\nHost: api5.zhipin.com\r\n\r\n"
                .toByteArray(StandardCharsets.ISO_8859_1)
        )
        parser.decoded(other.toByteArray(StandardCharsets.UTF_8), other.length)
        parser.decoded(real.toByteArray(StandardCharsets.UTF_8), 8)
        parser.onInboundData(
            "c1",
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                .plus("Content-Length: ${cipher.size}\r\n\r\n")
                .toByteArray(StandardCharsets.ISO_8859_1) + cipher
        )

        assertEquals(1, listener.responses.size)
        val event = listener.responses[0]
        assertEquals("jni:8->8", event.headers.firstOrNull { it.name.equals("x-aau-decode-hint", true) }?.value)
        assertArrayEquals(real.toByteArray(StandardCharsets.UTF_8), parser.getResponseBody(event.requestId))
    }

    @Test
    fun testDecodedBodyMatchesCompressedResponseBySourceLength() {
        val listener = RecordingListener()
        val parser = TlsStreamParser(configFor("com.hpbr.bosszhipin"), listener)

        // 压缩后再加密的响应，明文比线上字节大得多（batch 接口 20KB 密文换 100KB+ JSON）。
        // 拿明文长度去配对永远对不上，只能看解码器入参的那 20KB。
        val plain = "{\"zpData\":{\"jobList\":[{\"jobName\":\"Android\"}]}}"
        val cipher = cipherBytes(20796)

        parser.onOutboundData(
            "c1",
            "GET /api/batch/requests HTTP/1.1\r\nHost: api-and.zhipin.com\r\n\r\n"
                .toByteArray(StandardCharsets.ISO_8859_1)
        )
        parser.decoded(plain.toByteArray(StandardCharsets.UTF_8), cipher.size)
        parser.onInboundData(
            "c1",
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                .plus("Content-Length: ${cipher.size}\r\n\r\n")
                .toByteArray(StandardCharsets.ISO_8859_1) + cipher
        )

        assertEquals(1, listener.responses.size)
        val event = listener.responses[0]
        assertEquals(
            "jni:${cipher.size}->${plain.length}",
            event.headers.firstOrNull { it.name.equals("x-aau-decode-hint", true) }?.value
        )
        assertArrayEquals(plain.toByteArray(StandardCharsets.UTF_8), parser.getResponseBody(event.requestId))
    }

    @Test
    fun testDecodedBodyLeftAsCipherTextWhenAmbiguous() {
        val listener = RecordingListener()
        val parser = TlsStreamParser(configFor("com.hpbr.bosszhipin"), listener)

        // 两条明文都声称来自 8 字节的响应，内容却不同：判不出来就不能贴——
        // 留着密文还能再取一次，贴上错的明文就悄悄错了。
        val cipher = cipherBytes(8)

        parser.onOutboundData(
            "c1",
            "GET /api/batch/batchRunV2 HTTP/1.1\r\nHost: api5.zhipin.com\r\n\r\n"
                .toByteArray(StandardCharsets.ISO_8859_1)
        )
        parser.decoded("{\"aa\":1}".toByteArray(StandardCharsets.UTF_8), 8)
        parser.decoded("{\"bb\":2}".toByteArray(StandardCharsets.UTF_8), 8)
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
    fun testDecodedBodyDeduplicatedReportsStillAttach() {
        val listener = RecordingListener()
        val parser = TlsStreamParser(configFor("com.hpbr.bosszhipin"), listener)

        // 同一次解码被上报两遍（chunked 写入会重放）不该把自己判成"歧义"。
        val plain = "{\"ab\":1}"
        val cipher = cipherBytes(8)

        parser.onOutboundData(
            "c1",
            "GET /api/batch/batchRunV2 HTTP/1.1\r\nHost: api5.zhipin.com\r\n\r\n"
                .toByteArray(StandardCharsets.ISO_8859_1)
        )
        parser.decoded(plain.toByteArray(StandardCharsets.UTF_8), 8)
        parser.decoded(plain.toByteArray(StandardCharsets.UTF_8), 8)
        parser.onInboundData(
            "c1",
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                .plus("Content-Length: ${cipher.size}\r\n\r\n")
                .toByteArray(StandardCharsets.ISO_8859_1) + cipher
        )

        assertEquals(1, listener.responses.size)
        val event = listener.responses[0]
        assertEquals("jni:8->8", event.headers.firstOrNull { it.name.equals("x-aau-decode-hint", true) }?.value)
        assertArrayEquals(plain.toByteArray(StandardCharsets.UTF_8), parser.getResponseBody(event.requestId))
    }

    @Test
    fun testLatePlaintextRepublishesResponse() {
        val listener = RecordingListener()
        val parser = TlsStreamParser(configFor("com.hpbr.bosszhipin"), listener)

        // 真机上的常态：解码发生在进程内、抓包按 ~250ms 批量上报，
        // 明文几乎总是比响应本身晚到。这条响应先按密文派发一次，
        // 明文到了必须补发一次，否则模型永远只看得到 _binaryPayload。
        val plain = "{\"ab\":1}"
        val cipher = cipherBytes(plain.length)

        parser.onOutboundData(
            "c1",
            "GET /api/batch/batchRunV2 HTTP/1.1\r\nHost: api5.zhipin.com\r\n\r\n"
                .toByteArray(StandardCharsets.ISO_8859_1)
        )
        parser.onInboundData(
            "c1",
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                .plus("Content-Length: ${cipher.size}\r\n\r\n")
                .toByteArray(StandardCharsets.ISO_8859_1) + cipher
        )
        assertEquals(1, listener.responses.size)
        assertNull(listener.responses[0].headers.firstOrNull { it.name.equals("x-aau-decode-hint", true) })

        parser.decoded(plain.toByteArray(StandardCharsets.UTF_8), cipher.size)

        assertEquals(2, listener.responses.size)
        val republished = listener.responses[1]
        assertEquals(listener.responses[0].requestId, republished.requestId)
        assertEquals(
            "jni-late:${plain.length}",
            republished.headers.firstOrNull { it.name.equals("x-aau-decode-hint", true) }?.value
        )
        assertEquals(plain.length.toLong(), republished.contentLength)
        assertArrayEquals(plain.toByteArray(StandardCharsets.UTF_8), parser.getResponseBody(republished.requestId))
    }

    @Test
    fun testLatePlaintextNotAppliedTwice() {
        val listener = RecordingListener()
        val parser = TlsStreamParser(configFor("com.hpbr.bosszhipin"), listener)

        // 补发过一次之后，再来的同长明文不能又贴回这条已经解好的响应。
        val plain = "{\"ab\":1}"
        val cipher = cipherBytes(plain.length)
        parser.onOutboundData(
            "c1",
            "GET /api/batch/batchRunV2 HTTP/1.1\r\nHost: api5.zhipin.com\r\n\r\n"
                .toByteArray(StandardCharsets.ISO_8859_1)
        )
        parser.onInboundData(
            "c1",
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                .plus("Content-Length: ${cipher.size}\r\n\r\n")
                .toByteArray(StandardCharsets.ISO_8859_1) + cipher
        )
        parser.decoded(plain.toByteArray(StandardCharsets.UTF_8), cipher.size)
        parser.decoded(plain.toByteArray(StandardCharsets.UTF_8), cipher.size)

        assertEquals(2, listener.responses.size)
        assertArrayEquals(plain.toByteArray(StandardCharsets.UTF_8), parser.getResponseBody(listener.responses[0].requestId))
    }

    @Test
    fun testLatePlaintextSkippedWhenTwoResponsesShareLength() {
        val listener = RecordingListener()
        val parser = TlsStreamParser(configFor("com.hpbr.bosszhipin"), listener)

        // 两条密文一样长、都还没等到明文：长度不再能区分归属，
        // 此时无论贴哪条都可能贴错，宁可两条都留密文。
        val cipher = cipherBytes(8)
        for (conn in listOf("c1", "c2")) {
            parser.onOutboundData(
                conn,
                "GET /api/batch/batchRunV2 HTTP/1.1\r\nHost: api5.zhipin.com\r\n\r\n"
                    .toByteArray(StandardCharsets.ISO_8859_1)
            )
            parser.onInboundData(
                conn,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                    .plus("Content-Length: ${cipher.size}\r\n\r\n")
                    .toByteArray(StandardCharsets.ISO_8859_1) + cipher
            )
        }
        assertEquals(2, listener.responses.size)

        parser.decoded("{\"ab\":1}".toByteArray(StandardCharsets.UTF_8), cipher.size)

        assertEquals(2, listener.responses.size)
        for (event in listener.responses) {
            assertNull(event.headers.firstOrNull { it.name.equals("x-aau-decode-hint", true) })
        }
    }

    @Test
    fun testJsonProfileKeepsJniHooks() {

        // JSON 覆盖配置里漏读 jniHookRules 会让"看起来完整"的配置静默丢掉进程内明文通道。
        val profile = BossZhipinCapturePlugin.provideEbpfProfile("com.hpbr.bosszhipin")
        val json = EbpfProbeProfile.toJson(mapOf("com.hpbr.bosszhipin" to profile))
        val parsed = EbpfProbeProfile.fromJson(json)["com.hpbr.bosszhipin"]

        assertNotNull(parsed)
        assertEquals(1, parsed!!.jniHookRules.size)
        val rule = parsed.jniHookRules.first()
        assertEquals("libyzwg.so", rule.libSubstring)
        assertEquals(listOf("nativeDecodeContent", "nativeDecodeRequestBody"), rule.methodNames)
        assertEquals("BZPBlock", rule.magic)
        assertEquals(profile.jniHookRules.first().toCliArgs(), rule.toCliArgs())
    }
}
