package com.agent.display.common.network

import android.os.Parcelable
import kotlinx.parcelize.Parcelize

/**
 * HTTP 请求准备发送事件（对应 CDP Network.requestWillBeSent）。
 *
 * @property requestId 请求全局唯一追踪 ID
 * @property timestamp 事件触发时的时间戳 (毫秒)
 * @property url 请求目标完整 URL (含协议与查询参数)
 * @property method HTTP 请求方法 (如 GET, POST, PUT, DELETE)
 * @property headers HTTP 请求头部列表
 * @property postData 请求载荷（POST / PUT 报文正文文本，未携带或超限时为 null）
 * @property isTls 是否为 HTTPS 加密请求
 */
@Parcelize
data class HttpRequestEvent(
    val requestId: String,
    val timestamp: Long = System.currentTimeMillis(),
    val url: String,
    val method: String,
    val headers: List<HttpHeader> = emptyList(),
    val postData: String? = null,
    val isTls: Boolean = true
) : Parcelable {

    /**
     * 辅助构造函数：支持使用 Map 格式传入请求头部。
     */
    constructor(
        requestId: String,
        timestamp: Long,
        url: String,
        method: String,
        headers: Map<String, String>,
        postData: String? = null,
        isTls: Boolean = true
    ) : this(
        requestId = requestId,
        timestamp = timestamp,
        url = url,
        method = method,
        headers = headers.toHttpHeaders(),
        postData = postData,
        isTls = isTls
    )

    /**
     * 辅助构造函数：支持使用字节数组格式传入 postData。
     */
    constructor(
        requestId: String,
        timestamp: Long,
        url: String,
        method: String,
        headers: List<HttpHeader>,
        postDataBytes: ByteArray,
        isTls: Boolean = true
    ) : this(
        requestId = requestId,
        timestamp = timestamp,
        url = url,
        method = method,
        headers = headers,
        postData = postDataBytes.toString(Charsets.UTF_8),
        isTls = isTls
    )

    /**
     * postData 的字节数组形式。
     */
    val postDataBytes: ByteArray?
        get() = postData?.toByteArray(Charsets.UTF_8)

    /**
     * 快捷获取指定头部名称的值（忽略大小写）。
     */
    fun getHeader(name: String): String? =
        headers.getIgnoreCase(name)

    /**
     * 将所有头部转换为只读 Map 结构。
     */
    fun headerMap(): Map<String, String> =
        headers.toMap()
}
