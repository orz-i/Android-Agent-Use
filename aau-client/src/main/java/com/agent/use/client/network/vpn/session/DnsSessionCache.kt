package com.agent.use.client.network.vpn.session

import java.util.Collections
import java.util.LinkedHashMap
import java.util.concurrent.ConcurrentHashMap

/**
 * DNS 解析缓存，维护目标 IP 与主机的映射关系。
 *
 * 即使应用通过 IP 直接建立 TCP 连接，亦能回溯出原始域名。
 */
class DnsSessionCache(private val maxEntries: Int = 1000) {

    // 采用 LRU 访问排序，保证热点域名的 IP 映射始终被优先保留
    private val ipToDomainMap = Collections.synchronizedMap(
        object : LinkedHashMap<String, String>(128, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, String>?): Boolean {
                return size > maxEntries
            }
        }
    )

    private val domainToIpMap = ConcurrentHashMap<String, String>()

    /**
     * 记录一条 DNS 解析映射。
     */
    fun record(ip: String, domain: String) {
        val cleanDomain = domain.trimEnd('.')
        if (cleanDomain.isEmpty()) return

        ipToDomainMap[ip] = cleanDomain
        domainToIpMap[cleanDomain] = ip
    }

    /**
     * 根据目标 IP 地址查找对应的域名。
     */
    fun getDomain(ip: String): String? = ipToDomainMap[ip]

    /**
     * 根据域名查找对应的 IP 地址。
     */
    fun getIp(domain: String): String? = domainToIpMap[domain.trimEnd('.')]

    /**
     * 当前缓存条目数。
     */
    val size: Int get() = ipToDomainMap.size

    /**
     * 清空缓存。
     */
    fun clear() {
        ipToDomainMap.clear()
        domainToIpMap.clear()
    }
}
