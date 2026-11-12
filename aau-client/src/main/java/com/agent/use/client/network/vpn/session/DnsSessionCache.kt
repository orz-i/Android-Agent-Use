package com.agent.use.client.network.vpn.session

import java.util.concurrent.ConcurrentHashMap

/**
 * DNS 解析缓存，维护目标 IP 与主机的映射关系。
 *
 * 即使应用通过 IP 直接建立 TCP 连接，亦能回溯出原始域名。
 */
class DnsSessionCache(private val maxEntries: Int = 1000) {

    private val ipToDomainMap = ConcurrentHashMap<String, String>()
    private val domainToIpMap = ConcurrentHashMap<String, String>()

    /**
     * 记录一条 DNS 解析映射。
     */
    fun record(ip: String, domain: String) {
        if (ipToDomainMap.size >= maxEntries) {
            // 简单清理以防无界膨胀
            val keyToRemove = ipToDomainMap.keys().toList().firstOrNull()
            if (keyToRemove != null) {
                val dom = ipToDomainMap.remove(keyToRemove)
                if (dom != null) domainToIpMap.remove(dom)
            }
        }
        ipToDomainMap[ip] = domain
        domainToIpMap[domain] = ip
    }

    /**
     * 根据目标 IP 地址查找对应的域名。
     */
    fun getDomain(ip: String): String? = ipToDomainMap[ip]

    /**
     * 根据域名查找对应的 IP 地址。
     */
    fun getIp(domain: String): String? = domainToIpMap[domain]

    /**
     * 清空缓存。
     */
    fun clear() {
        ipToDomainMap.clear()
        domainToIpMap.clear()
    }
}
