package com.agent.use.common.network.plugin

import android.util.Log
import com.agent.use.common.network.HttpHeader
import com.agent.use.common.network.HttpRequestEvent
import com.agent.use.common.network.HttpResponseEvent
import com.agent.use.common.network.getIgnoreCase
import com.agent.use.common.network.parser.HttpContentDecoder

/**
 * 防止畸形头部把内存打爆。文件级常量，供 [BzpBlockCodec] 与其内部 sink 共用。
 */
private const val MAX_DECODED_BYTES = 32 * 1024 * 1024

/**
 * BOSS 直聘（`com.hpbr.bosszhipin`）响应体容器解码器。
 *
 * 实测结论（见 `.work/boss/README.md`）：`zp-compressing: 2` 时代的响应体不是加密，
 * 而是自有的 `BZPBlock` 容器 + LZ4 **block** 压缩：
 *
 * ```
 * 响应体 = "BZPBlock"(8B) + 头部(16B) + LZ4 block 压缩数据
 *   +0   8B  "BZPBlock"
 *   +8   4B  version / reserved   (实测为 0)
 *   +12  4B  payload 长度          (= 总长 - 24，可据此裁掉拼接在尾部的多余字节)
 *   +16  4B  解压后长度            (LZ4 block 需要预知输出尺寸)
 *   +20  4B  checksum / block 数   (解码时不用)
 * ```
 *
 * `zp-compressing: 0` 时响应体直接是明文 JSON；
 * `zp-compressing: 1` 走标准 `Content-Encoding`（gzip / zlib / br / zstd）。
 *
 * 这里只做纯字节变换，不依赖 App 侧任何 native 符号，因此对 eBPF / VPN 两条抓包链路同样生效。
 */
internal object BzpBlockCodec {

    const val MAGIC = "BZPBlock"
    const val HEADER_SIZE = 24

    private val MAGIC_BYTES = MAGIC.toByteArray(Charsets.US_ASCII)

    data class Header(
        val version: Int,
        val payloadSize: Int,
        val rawSize: Int,
        val checksum: Int,
    )

    fun hasMagic(bytes: ByteArray, offset: Int = 0): Boolean {
        if (offset < 0 || bytes.size - offset < HEADER_SIZE) return false
        for (i in MAGIC_BYTES.indices) {
            if (bytes[offset + i] != MAGIC_BYTES[i]) return false
        }
        return true
    }

    fun readHeader(bytes: ByteArray, offset: Int = 0): Header? {
        if (!hasMagic(bytes, offset)) return null
        return Header(
            version = readLeInt(bytes, offset + 8),
            payloadSize = readLeInt(bytes, offset + 12),
            rawSize = readLeInt(bytes, offset + 16),
            checksum = readLeInt(bytes, offset + 20),
        )
    }

    /**
     * 解出 JSON 明文；头部非法或 LZ4 流完全不可解时返回 null，交由调用方保留原始字节。
     *
     * 尾部被截断时（eBPF 缓冲区上限、`maxBodySizeBytes` 截断）返回已解出前缀，
     * 这时调用方拿到的可能不是完整 JSON，但能保留可读的部分。
     */
    fun decode(bytes: ByteArray): ByteArray? {
        val header = readHeader(bytes) ?: return null
        val bodyStart = HEADER_SIZE
        val available = bytes.size - bodyStart
        if (available <= 0) return null
        val payloadSize = if (header.payloadSize in 1..available) header.payloadSize else available
        val expected = if (header.rawSize in 1..MAX_DECODED_BYTES) header.rawSize else 0
        val out = lz4BlockDecompress(bytes, bodyStart, payloadSize, expected) ?: return null
        return out.takeIf { it.isNotEmpty() }
    }

    /**
     * LZ4 block 格式解压（非 frame，无魔数、无校验和）。
     *
     * 序列结构：`token(1B) [额外 literal 长度][literal 数据] [offset(2B LE)][额外 match 长度]`
     * 结束条件：literal 段正好吃掉剩余输入。
     */
    fun lz4BlockDecompress(
        src: ByteArray,
        srcOffset: Int,
        srcLength: Int,
        expectedSize: Int,
    ): ByteArray? {
        val end = srcOffset + srcLength
        if (srcLength <= 0 || end > src.size) return null

        val sink = ExpandingSink(
            if (expectedSize in 1..MAX_DECODED_BYTES) expectedSize else minOf(MAX_DECODED_BYTES, srcLength * 8 + 64)
        )
        var i = srcOffset

        while (i < end) {
            val token = src[i].toInt() and 0xFF
            i++

            var literalLength = token ushr 4
            if (literalLength == 15) {
                while (i < end) {
                    val b = src[i].toInt() and 0xFF
                    i++
                    literalLength += b
                    if (b != 255) break
                }
            }
            if (literalLength > 0) {
                if (i + literalLength > end) {
                    // 输入被截断：把还能拿到的 literal 写出去就收工
                    val partial = end - i
                    if (partial > 0 && sink.ensure(partial)) {
                        sink.put(src, i, partial)
                    }
                    break
                }
                if (!sink.ensure(literalLength)) return null
                sink.put(src, i, literalLength)
                i += literalLength
            }

            // literal 段刚好用完输入 = 正常的最后一个序列
            if (i >= end) break
            if (i + 2 > end) break

            val matchOffset = (src[i].toInt() and 0xFF) or ((src[i + 1].toInt() and 0xFF) shl 8)
            i += 2
            if (matchOffset == 0 || matchOffset > sink.length) return null

            var matchLength = token and 0x0F
            if (matchLength == 15) {
                while (i < end) {
                    val b = src[i].toInt() and 0xFF
                    i++
                    matchLength += b
                    if (b != 255) break
                }
            }
            matchLength += 4

            if (!sink.ensure(matchLength)) return null
            sink.copyWithin(matchOffset, matchLength)
        }

        return sink.takeIf { it.length > 0 }?.toByteArray()
    }

    private fun readLeInt(bytes: ByteArray, offset: Int): Int =
        (bytes[offset].toInt() and 0xFF) or
            ((bytes[offset + 1].toInt() and 0xFF) shl 8) or
            ((bytes[offset + 2].toInt() and 0xFF) shl 16) or
            ((bytes[offset + 3].toInt() and 0xFF) shl 24)

    /** LZ4 允许 match 段与输出区重叠，必须逐字节复制，不能走 System.arraycopy。 */
    private class ExpandingSink(initialCapacity: Int) {
        private var buf = ByteArray(initialCapacity.coerceIn(256, MAX_DECODED_BYTES))
        var length: Int = 0
            private set

        fun ensure(extra: Int): Boolean {
            if (extra < 0) return false
            if (length + extra <= buf.size) return true
            if (length + extra > MAX_DECODED_BYTES) return false
            var next = buf.size
            while (next < length + extra) {
                next = if (next >= MAX_DECODED_BYTES / 2) MAX_DECODED_BYTES else next * 2
            }
            buf = buf.copyOf(next)
            return true
        }

        fun put(src: ByteArray, offset: Int, count: Int) {
            System.arraycopy(src, offset, buf, length, count)
            length += count
        }

        fun copyWithin(matchOffset: Int, count: Int) {
            var read = length - matchOffset
            for (k in 0 until count) {
                buf[length + k] = buf[read + k]
            }
            length += count
        }

        fun toByteArray(): ByteArray = if (length == buf.size) buf else buf.copyOf(length)
    }
}

/**
 * BOSS 直聘流量中间件：把 `BZPBlock` / gzip / zlib / br / zstd 统一还原成明文 JSON。
 *
 * 抖音插件干的是 TTNet 的 zstd + brotli，BOSS 这套是自家 LZ4 容器，所以单独一个中间件。
 */
object BossZhipinTrafficMiddleware : NetworkTrafficMiddleware {

    override val id: String = "builtin.bosszhipin.middleware"

    private const val TAG = "BossZhipinPlugin"
    private const val DECODE_HINT_HEADER = "x-aau-decode-hint"
    private const val DEFAULT_API_HOST = "www.zhipin.com"

    /** 单次响应最多尝试的容层层数（BZPBlock 内再套 gzip 之类）。 */
    private const val MAX_DECODE_PASSES = 3

    private val handledPackages = setOf(
        "com.hpbr.bosszhipin",
        "com.hpbr.bosszhipin.lite",
    )

    override fun onRequest(targetPackage: String, event: HttpRequestEvent): HttpRequestEvent {
        if (targetPackage !in handledPackages) return event
        if (!event.url.contains("://unknown-host")) return event
        val host = event.headers.getIgnoreCase("x-bz-host")
            ?: event.headers.getIgnoreCase(":authority")
            ?: event.headers.getIgnoreCase("host")
            ?: DEFAULT_API_HOST
        if (host.isBlank()) return event
        return event.copy(url = event.url.replace("://unknown-host", "://$host"))
    }

    override fun onResponse(
        targetPackage: String,
        event: HttpResponseEvent,
        body: ByteArray?,
    ): Pair<HttpResponseEvent, ByteArray?> {
        if (targetPackage !in handledPackages) return event to body

        var nextEvent = event
        var nextBody = body

        // 生产环境静默；排查时 adb shell setprop log.tag.BossZhipinPlugin DEBUG 打开
        if (Log.isLoggable(TAG, Log.DEBUG)) {
            Log.d(TAG, "resp len=${body?.size ?: -1} ct=${event.mimeType} url=${event.url}")
        }

        if (nextEvent.url.contains("://unknown-host")) {
            val host = nextEvent.headers.getIgnoreCase("x-bz-host")
                ?: nextEvent.headers.getIgnoreCase(":authority")
                ?: nextEvent.headers.getIgnoreCase("host")
                ?: DEFAULT_API_HOST
            if (host.isNotBlank()) {
                nextEvent = nextEvent.copy(url = nextEvent.url.replace("://unknown-host", "://$host"))
            }
        }

        if (nextBody != null && nextBody.isNotEmpty()) {
            val originalSize = nextBody.size
            var decoded: ByteArray? = nextBody
            var kind: String? = null

            for (pass in 0 until MAX_DECODE_PASSES) {
                val current = decoded ?: break
                if (looksLikeJson(current)) break
                val step = decodeOneLayer(current, nextEvent)
                if (step == null) break
                decoded = step.second
                if (kind == null) kind = step.first else kind = "$kind>${step.first}"
            }

            if (decoded != null && !decoded.contentEquals(nextBody)) {
                nextBody = decoded
                if (looksLikeJson(nextBody) &&
                    (nextEvent.mimeType.isNullOrBlank() ||
                        nextEvent.mimeType.equals("application/octet-stream", ignoreCase = true))
                ) {
                    nextEvent = nextEvent.copy(mimeType = "application/json; charset=utf-8")
                }
                val hint = "$kind:$originalSize->${nextBody.size}"
                nextEvent = nextEvent.withDecodeHint(hint)
                Log.d(TAG, "decoded [$hint] ${nextEvent.url}")
            } else {
                // 解不开：把 App 自报的加工方式记下来，方便区分"走了 AES"和"容器变种"
                val compress = nextEvent.headers.getIgnoreCase("zp-compressing")
                val encrypt = nextEvent.headers.getIgnoreCase("zp-encrypting")
                val encryptedFlag = nextEvent.headers.getIgnoreCase("content-encrypt")
                    ?.equals("yes", ignoreCase = true) == true || encrypt == "1"
                if (encryptedFlag) {
                    // AES 段只有 App 手里的 secretKey 能解，eBPF 抓到的就是密文。
                    // 需要明文时仍得回到 frida hook（见 .work/boss/serve_hook.py）。
                    nextEvent = nextEvent.withDecodeHint("bzp-aes:$originalSize")
                } else if (!compress.isNullOrBlank() || !encrypt.isNullOrBlank()) {
                    val hint = "bzp-raw:compress=${compress ?: "-"},encrypt=${encrypt ?: "-"},$originalSize"
                    nextEvent = nextEvent.withDecodeHint(hint)
                }
            }
        }

        return nextEvent to nextBody
    }

    /** 尝试剥一层容器，返回 (层名, 解出字节)。识别不了返回 null。 */
    private fun decodeOneLayer(bytes: ByteArray, event: HttpResponseEvent): Pair<String, ByteArray>? {
        if (BzpBlockCodec.hasMagic(bytes)) {
            val out = BzpBlockCodec.decode(bytes) ?: return null
            return "bzp-lz4" to out
        }
        if (HttpContentDecoder.hasGzipMagic(bytes)) {
            runCatching { HttpContentDecoder.gunzip(bytes) }.getOrNull()
                ?.takeIf { it.isNotEmpty() }
                ?.let { return "gzip" to it }
            return null
        }
        if (HttpContentDecoder.hasZstdMagic(bytes)) {
            HttpContentDecoder.decompressZstd(bytes)?.takeIf { it.isNotEmpty() }?.let { return "zstd" to it }
            return null
        }
        val encoding = event.headers.getIgnoreCase("content-encoding")?.lowercase().orEmpty()
        if (encoding.contains("br")) {
            HttpContentDecoder.decompressBrotli(bytes)?.takeIf { it.isNotEmpty() }?.let { return "br" to it }
        }
        if (HttpContentDecoder.hasZlibMagic(bytes)) {
            runCatching { HttpContentDecoder.inflate(bytes) }.getOrNull()
                ?.takeIf { it.isNotEmpty() }
                ?.let { return "zlib" to it }
        }
        return null
    }

    private fun HttpResponseEvent.withDecodeHint(hint: String): HttpResponseEvent {
        if (headers.any { it.name.equals(DECODE_HINT_HEADER, ignoreCase = true) }) return this
        return copy(headers = headers + HttpHeader(DECODE_HINT_HEADER, hint))
    }

    private fun looksLikeJson(bytes: ByteArray): Boolean {
        for (b in bytes) {
            val c = b.toInt() and 0xFF
            if (c == 0x20 || c == 0x09 || c == 0x0A || c == 0x0D) continue
            return c == '{'.code || c == '['.code
        }
        return false
    }
}

/**
 * BOSS 直聘专属抓包插件。
 *
 * 两条链路要分开看，别混在一起：
 *
 * **1. 核心 HTTP（职位列表等业务接口）**
 * 走系统 conscrypt 的 `/apex/com.android.conscrypt/lib64/libssl.so`，
 * `.dynsym` 里 SSL_read / SSL_write 都在，eBPF discovery 能直接解析，
 * 不需要任何自定义偏移。真正的障碍在协议层：业务接口是 **HTTP/2**，
 * TlsStreamParser 只重建 HTTP/1.x，所以 eBPF 只能读到 `zpCommon/batch/statistic`
 * 这类上报接口，列表数据读不出来。这跟偏移无关，是 HPACK 解析的问题。
 *
 * **2. RTC 传输（[TRANSPORT_LIB]）**
 * `libzp-sdk-transport.so` 只在通话/鹰眼场景被 `com.kanzhun.zpeaglesdk` 和
 * `nebulartc` 加载，主进程平时不载入。它静态链入了 OpenSSL 1.1.1h，
 * `.dynsym` 全被 strip，discovery 的 BoringSSL 启发式也匹配不上，
 * 所以才需要下面这组手工反查出来的偏移。
 *
 * 响应体容器解码由 [BossZhipinTrafficMiddleware] 负责，与偏移互不依赖。
 */
object BossZhipinCapturePlugin : NetworkCapturePlugin {

    override val id: String = "builtin.bosszhipin"

    private val targetPackages = setOf(
        "com.hpbr.bosszhipin",
        "com.hpbr.bosszhipin.lite",
    )

    override val defaultPackages: List<String> = listOf("com.hpbr.bosszhipin")

    override fun matchesPackage(targetPackage: String): Boolean = targetPackage in targetPackages

    /**
     * `libzp-sdk-transport.so`（OpenSSL 1.1.1h，已 strip）的 SSL 入口偏移。
     *
     * - [SSL_WRITE_OFFSET] 对应 `int SSL_write(SSL *s, const void *buf, int num)`
     * - [SSL_READ_OFFSET] 对应 `int SSL_read(SSL *s, void *buf, int num)`
     *
     * 两者都是薄封装（`SSL_read` → `SSL_read_ex` → `s->method->ssl_read`），
     * 但寄存器约定和 eBPF 侧完全一致：x0=SSL\*、x1=buf、w2=len，
     * 返回值就是实际读写的字节数，所以挂入口最稳。
     *
     * **偏移怎么来的**（可用 `.work/boss/find_ssl_offsets.py` 复现）：
     * 1. `.rodata` 定位 `"SSL_read\0"` / `"SSL_write\0"`
     * 2. `PT_DYNAMIC → DT_RELA` 里找 `R_AARCH64_RELATIVE` 且 `r_addend` 指向该字符串的条目，
     *    `r_offset` 就是 ERR_STRING_DATA.string 槽位，往前 8 字节是 error code
     * 3. 拆出 `lib=20 / func=223(SSL_read) / 208(SSL_write)`——这两个号随版本变，不能写死
     * 4. `.text` 里扫 `mov w0,#20` + `mov w1,#func` 定位 SSLerr 调用点
     * 5. 从调用点向上扫序言得到入口（不能用 BoringSSL 那套 RET 边界：
     *    SSL_write 紧跟在 SSL_write_ex 后、前一条是 B 不是 RET，会被错认成 _ex 版本）
     *
     * 交叉验证：so 内部有三处 `bl` 指向这两个入口（`0x2fe498` 写、
     * `0x2fe748` / `0x2fe880` 读），调用前都是 `x0=[x19,#0x220]` 取同一个 SSL 对象，
     * 且 `cmp w0,#1 / b.lt`，确认是真实网络读写路径。
     */
    override fun provideEbpfProfile(targetPackage: String): EbpfProbeProfile {
        if (targetPackage !in targetPackages) return EbpfProbeProfile()
        return EbpfProbeProfile(
            sslOffsetRules = listOf(
                EbpfSslOffsetRule(
                    libSubstring = TRANSPORT_LIB,
                    writeOffset = SSL_WRITE_OFFSET,
                    readOffset = SSL_READ_OFFSET,
                    // SSL_set_tlsext_host_name 被内联进调用方，没有独立入口可挂；
                    // host 由 TlsStreamParser 从 ClientHello 明文里取。
                    sniOffset = 0L,
                )
            ),
            jniHookRules = listOf(
                JniHookRule(
                    libSubstring = YZWG_LIB,
                    methodNames = listOf(
                        "nativeDecodeContent",
                        "nativeDecodeRequestBody",
                    ),
                    captureReturn = true,
                    expectJson = true,
                    // nativeDecodeContent 返回的不一定是裸 JSON：实测同一入口既可能给
                    // 明文 JSON，也可能给 BZPBlock 容器（由 BossZhipinTrafficMiddleware
                    // 再剥一层 LZ4）。把容器魔数也声明为合法形态，否则这类返回会被
                    // loader 当成误读而丢弃。
                    magic = BzpBlockCodec.MAGIC,
                    maxBytes = 4 * 1024 * 1024,
                )
            ),
            // 这是精确命中，命中后不必再跑通用探测
            replaceBuiltinOffsets = false,
        )
    }

    override fun provideMiddlewares(targetPackage: String): List<NetworkTrafficMiddleware> =
        listOf(BossZhipinTrafficMiddleware)

    private const val TRANSPORT_LIB = "libzp-sdk-transport.so"

    /**
     * 应用层加解密库。方法通过 RegisterNatives 动态注册，so 里只有 JNI_OnLoad，
     * 因此只能在运行时从 libart 拦截注册表拿到真实地址。
     */
    private const val YZWG_LIB = "libyzwg.so"

    /**
     * 偏移对应的样本指纹，BOSS 升级后 so 变了就得重跑脚本：
     * ```
     * size   3491816
     * sha256 2f867360b88451304b9034ee5db82f7b0c1ad6db14fbec130e87440ef9d39dc6
     * build  ac2cadb161d91e776df79cb5933bd552e7a3da4f
     * ```
     * loader 侧还有 `resolve_stripped_openssl_offsets()` 兜底，会自动重算，
     * 所以这里写死的值只在「库被加载 + 版本未变」时生效，不会误伤。
     */

    /** `SSL_write` 入口，文件偏移 == VMA（第一个 PT_LOAD 从 0 起） */
    private const val SSL_WRITE_OFFSET = 0x1e1ec8L

    /** `SSL_read` 入口 */
    private const val SSL_READ_OFFSET = 0x1e1a6cL
}
