package com.agent.use.common.network

import android.os.Parcelable
import kotlinx.parcelize.Parcelize

/**
 * HTTP 响应头部到达事件（对应 CDP Network.responseReceived）。
 *
 * @property requestId 关联的请求全局唯一追踪 ID
 * @property timestamp 事件触发时的时间戳 (毫秒)
 * @property url 响应对应的最终 URL (含重定向后的实际地址)
 * @property statusCode HTTP 状态码 (如 200, 404, 500)
 * @property statusText HTTP 状态短语 (如 "OK", "Not Found")
 * @property headers HTTP 响应头部列表
 * @property mimeType 资源的 MIME 类型 (如 "application/json", "image/png")
 * @property contentLength 响应体预期字节长度 (-1 表示未知或分块传输)
 * @property fromCache 是否命中本地/服务缓存
 */
@Parcelize
data class HttpResponseEvent(
    val requestId: String,
    val timestamp: Long = System.currentTimeMillis(),
    val url: String,
    val statusCode: Int,
    val statusText: String,
    val headers: List<HttpHeader> = emptyList(),
    val mimeType: String? = null,
    val contentLength: Long = -1L,
    val fromCache: Boolean = false
) : Parcelable {

    /**
     * 辅助构造函数：支持使用 Map 格式传入响应头部。
     */
    constructor(
        requestId: String,
        timestamp: Long,
        url: String,
        statusCode: Int,
        statusText: String,
        headers: Map<String, String>,
        mimeType: String? = null,
        contentLength: Long = -1L,
        fromCache: Boolean = false
    ) : this(
        requestId = requestId,
        timestamp = timestamp,
        url = url,
        statusCode = statusCode,
        statusText = statusText,
        headers = headers.toHttpHeaders(),
        mimeType = mimeType,
        contentLength = contentLength,
        fromCache = fromCache
    )

    /**
     * 快捷获取指定响应头部的值（忽略大小写）。
     */
    fun getHeader(name: String): String? =
        headers.getIgnoreCase(name)

    /**
     * 将所有头部转换为只读 Map 结构。
     */
    fun headerMap(): Map<String, String> =
        headers.toMap()

    /**
     * 判断状态码是否属于 2xx 成功范围。
     */
    val isSuccess: Boolean
        get() = statusCode in 200..299
}
