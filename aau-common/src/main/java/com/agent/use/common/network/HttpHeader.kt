package com.agent.use.common.network

import android.os.Parcelable
import kotlinx.parcelize.Parcelize

/**
 * HTTP 头部键值对模型。
 *
 * @property name 头部名称（如 Content-Type, Authorization）
 * @property value 头部对应的值
 */
@Parcelize
data class HttpHeader(
    val name: String,
    val value: String
) : Parcelable

/**
 * 快捷将头部列表转换为 Map 映射。若存在同名重复 Header，后出现的覆盖先出现的。
 */
fun List<HttpHeader>.toMap(): Map<String, String> =
    associate { it.name to it.value }

/**
 * 大小写无关查找第一个匹配的头部值。
 */
fun List<HttpHeader>.getIgnoreCase(name: String): String? =
    firstOrNull { it.name.equals(name, ignoreCase = true) }?.value

/**
 * 大小写无关查找所有匹配的头部值。
 */
fun List<HttpHeader>.getAllIgnoreCase(name: String): List<String> =
    filter { it.name.equals(name, ignoreCase = true) }.map { it.value }

/**
 * 快捷将 Map 映射转换为 HttpHeader 列表。
 */
fun Map<String, String>.toHttpHeaders(): List<HttpHeader> =
    map { HttpHeader(it.key, it.value) }
