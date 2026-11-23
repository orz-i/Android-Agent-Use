package com.agent.use.common.network.plugin

/**
 * 声明式响应解码：把「魔数 + 定长头 + 标准压缩」这类信封从代码变成配置。
 *
 * 目标很具体：**新 App 换了个响应容器时，不用改 aau、不用重打 APK**，在设置页里写一段 JSON
 * 就能解出来。所以这里只保留少量稳定的原子操作：
 *
 * - `container`   魔数 + 定长头，按头部声明的长度裁出载荷
 * - `decompress`  `gzip` / `zlib` / `lz4-block` / `zstd` / `br`
 * - `base64`      标准 / URL-safe base64
 * - `stripPrefix` 去掉固定前缀（有的 App 会在 JSON 前拼一段随机盐）
 *
 * 刻意不做 DSL 堆砌：声明式管道一旦写进配置文件就是对外契约，原子操作越少越不容易破。
 * 自定义 AES、有状态解码这类「本质是代码」的东西走 L3 插件包，不要塞进这里。
 *
 * JSON 形态（`aau_capture_plugins.json` 里每个包一份，或插件包的 `plugin.json`）：
 *
 * ```json
 * "hostFix": { "headerPriority": ["x-bz-host", ":authority"], "defaultHost": "www.zhipin.com" },
 * "responseCodecs": [
 *   {
 *     "id": "bzp-block",
 *     "when": [{ "header": "zp-compressing", "equals": "2" }],
 *     "steps": [
 *       { "op": "container", "magic": "BZPBlock", "headerSize": 24,
 *         "payloadLen": { "at": 12, "width": 4, "endian": "le" },
 *         "rawLen":     { "at": 16, "width": 4, "endian": "le" } },
 *       { "op": "decompress", "algo": "lz4-block" }
 *     ]
 *   }
 * ]
 * ```
 */
data class DeclarativeConfig(
    val hostFix: HostFixRule? = null,
    val responseCodecs: List<ResponseCodecRule> = emptyList(),
    /** 解不开时写进 hint 的判断，用来区分「没抓到」和「抓到了但需要 App 的密钥」。 */
    val diagnose: List<DiagnoseRule> = emptyList(),
) {
    val isEmpty: Boolean get() = hostFix == null && responseCodecs.isEmpty() && diagnose.isEmpty()

    companion object {
        val EMPTY = DeclarativeConfig()
    }
}

/**
 * 响应体解不开时的诊断标签。
 *
 * 抓包最怕的不是"解不开"，而是"解不开却看不出原因"——模型会把密文当明文读，人也会以为抓包坏了。
 * 命中第一条 [whenConditions] 就把 `undecoded:<label>[:k=v,...]:<size>` 写进
 * `x-aau-decode-hint`，明确告诉下游这条是加密/未知容器，而不是漏抓。
 */
data class DiagnoseRule(
    val whenConditions: List<CodecCondition> = emptyList(),
    val label: String,
    /** 附加到 hint 里的头部名，按顺序取 `k=v`。 */
    val headers: List<String> = emptyList(),
)

/**
 * 把 `https://unknown-host/...` 补回真实 Host。
 *
 * 抓包链路（eBPF 重建 TLS 流、VPN 层）在没有 SNI 或连接复用时拿不到域名，URL 会退化成
 * `unknown-host`。三个内置插件都在各自中间件里手写过这段逻辑，这里收成一条配置。
 */
data class HostFixRule(
    /** 依次尝试的头部名（忽略大小写），取第一个非空值。 */
    val headerPriority: List<String> = emptyList(),
    /** 所有头部都空时的兜底域名。 */
    val defaultHost: String? = null,
    /**
     * 兜底域名只在 URL 含该片段时使用。
     *
     * 有的 App 只在特定前缀下省略 Host（小红书 `/api/sns/`、抖音 `/aweme/v`），对这些之外
     * 的连接硬补一个域名会把 URL 编造成不存在的主机——比留着 `unknown-host` 更难查。
     */
    val defaultHostPathContains: String? = null,
    /**
     * 是否在**请求**阶段就补 Host。默认 `true`。
     *
     * 有的 App 请求里根本没有任何 Host 线索，补出来的域名只能靠猜；解析器本来会从响应的
     * `Set-Cookie: Domain=` 学习真实域名并在下次请求回填。提前补等于抢在证据之前下结论，
     * 这种情况要设成 `false`，只在响应阶段补。
     */
    val applyOnRequest: Boolean = true,
) {
    companion object {
        val DEFAULT_HEADERS = listOf("x-tt-host", ":authority", "host")
    }
}

data class ResponseCodecRule(
    val id: String? = null,
    /** 全部条件成立才应用这条规则；空列表表示无条件。 */
    val whenConditions: List<CodecCondition> = emptyList(),
    val steps: List<CodecStep> = emptyList(),
    /** 输入已经是明文 JSON 时跳过整条规则（不再尝试剥容器）。 */
    val stopWhenJson: Boolean = true,
)

data class CodecCondition(
    /** 头部名（忽略大小写）。为空时只看 [magic] / [magicHex]。 */
    val header: String? = null,
    /** 头部值完全相等（忽略大小写）。 */
    val equals: String? = null,
    /** 头部值包含该子串（忽略大小写）。 */
    val contains: String? = null,
    /** 该头部必须不存在。 */
    val absent: Boolean = false,
    /** 响应体前缀（UTF-8）；用于"按容器魔数分流"。 */
    val magic: String? = null,
    /** 二进制魔数（十六进制）；gzip / zstd 这类非文本魔数走这里。 */
    val magicHex: String? = null,
)

data class CodecStep(
    /** `container` / `decompress` / `base64` / `stripPrefix` */
    val op: String,
    /** container: 魔数（UTF-8 文本，如 `BZPBlock`） */
    val magic: String? = null,
    /** container: 二进制魔数，十六进制字符串（如 `1f8b08`），与 [magic] 二选一 */
    val magicHex: String? = null,
    /** container: 魔数相对响应体起点的偏移 */
    val magicOffset: Int = 0,
    /** container: 头部长度，载荷从该偏移开始（含魔数） */
    val headerSize: Int = 0,
    /** container: 载荷长度字段的位置 */
    val payloadLen: CodecFieldRef? = null,
    /** container: 解压后长度字段的位置（LZ4 block 需要预知输出尺寸） */
    val rawLen: CodecFieldRef? = null,
    /** decompress: `gzip` / `zlib` / `lz4-block` / `zstd` / `br` */
    val algo: String? = null,
    /** stripPrefix: 去掉的字节数 */
    val prefixBytes: Int = 0,
    /** trace 里显示的名字，缺省用 op/algo。 */
    val label: String? = null,
    /** 解成功后把 mimeType 改成这个值。 */
    val contentType: String? = null,
) {
    val traceName: String
        get() = label?.takeIf { it.isNotBlank() }
            ?: when (op) {
                "decompress" -> algo?.lowercase() ?: "decompress"
                "container" -> magic ?: magicHex ?: "container"
                "stripprefix" -> "strip$prefixBytes"
                else -> op
            }
}

/** 头部里的定长整数字段。 */
data class CodecFieldRef(
    val at: Int,
    val width: Int = 4,
    /** `le` / `be` */
    val endian: String = "le",
) {
    fun read(bytes: ByteArray, base: Int = 0): Long? {
        if (width !in 1..8) return null
        val start = base + at
        if (at < 0 || start < 0 || start + width > bytes.size) return null
        var value = 0L
        if (endian.equals("be", ignoreCase = true)) {
            for (i in 0 until width) {
                value = (value shl 8) or (bytes[start + i].toLong() and 0xFF)
            }
        } else {
            for (i in width - 1 downTo 0) {
                value = (value shl 8) or (bytes[start + i].toLong() and 0xFF)
            }
        }
        return value
    }
}

/**
 * 面向界面/插件包的配置编解码入口。
 *
 * 解析器本身是模块内部实现，但"把用户写的 JSON 变成配置、再变回 JSON"这件事要跨模块用
 * （设置页在 app 模块），所以在这里开一个窄口子，避免把整个 `DeclarativeCodecJson` 暴露出去。
 */
object DeclarativeConfigs {

    /** @return JSON 语法错误返回 null；空白返回 [DeclarativeConfig.EMPTY]。 */
    fun parse(text: String): DeclarativeConfig? = DeclarativeCodecJson.parseConfigText(text)

    /** 空配置返回空串，界面据此显示空白而不是 `{}`。 */
    fun toJson(config: DeclarativeConfig): String {
        if (config.isEmpty) return ""
        val entries = buildList {
            config.hostFix?.let { add("hostFix" to DeclarativeCodecJson.hostFixValue(it)) }
            if (config.responseCodecs.isNotEmpty()) {
                add("responseCodecs" to DeclarativeCodecJson.codecRulesValue(config.responseCodecs))
            }
            if (config.diagnose.isNotEmpty()) {
                add("diagnose" to DeclarativeCodecJson.diagnoseValue(config.diagnose))
            }
        }
        return DeclarativeCodecJson.render(DeclarativeCodecJson.J.Obj(entries), "")
    }
}
