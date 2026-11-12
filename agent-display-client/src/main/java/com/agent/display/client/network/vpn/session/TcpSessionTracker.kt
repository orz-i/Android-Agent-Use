package com.agent.display.client.network.vpn.session

import java.util.concurrent.ConcurrentHashMap

/**
 * 管理所有活动的 TCP 会话及 HTTP 响应体缓存。
 */
class TcpSessionTracker(
    private val maxSessions: Int = 2000,
    private val maxResponseCacheSize: Int = 200
) {
    private val sessions = ConcurrentHashMap<TcpConnectionKey, TcpSession>()
    private val responseBodies = ConcurrentHashMap<String, ByteArray>()

    /**
     * 获取或创建指定四元组对应的 TCP 会话。
     */
    fun getOrCreateSession(
        clientIp: String,
        clientPort: Int,
        serverIp: String,
        serverPort: Int
    ): TcpSession {
        val key = TcpConnectionKey(clientIp, clientPort, serverIp, serverPort)
        return sessions.computeIfAbsent(key) {
            if (sessions.size >= maxSessions) {
                cleanupExpired(30_000L)
            }
            TcpSession(key)
        }
    }

    /**
     * 根据四元组查找已存在的会话（支持正向与反向匹配）。
     */
    fun findSession(
        srcIp: String,
        srcPort: Int,
        dstIp: String,
        dstPort: Int
    ): Pair<TcpSession, Boolean>? {
        val forwardKey = TcpConnectionKey(srcIp, srcPort, dstIp, dstPort)
        val forwardSession = sessions[forwardKey]
        if (forwardSession != null) {
            return Pair(forwardSession, true) // true 表示正向 (Uplink, 客户端到服务端)
        }

        val reverseKey = TcpConnectionKey(dstIp, dstPort, srcIp, srcPort)
        val reverseSession = sessions[reverseKey]
        if (reverseSession != null) {
            return Pair(reverseSession, false) // false 表示反向 (Downlink, 服务端到客户端)
        }

        return null
    }

    /**
     * 移除指定的 TCP 会话。
     */
    fun removeSession(clientIp: String, clientPort: Int, serverIp: String, serverPort: Int) {
        sessions.remove(TcpConnectionKey(clientIp, clientPort, serverIp, serverPort))
    }

    /**
     * 暂存响应正文字节，供 getResponseBody(requestId) 提取。
     */
    fun cacheResponseBody(requestId: String, body: ByteArray) {
        if (responseBodies.size >= maxResponseCacheSize) {
            val oldestKey = responseBodies.keys().toList().firstOrNull()
            if (oldestKey != null) responseBodies.remove(oldestKey)
        }
        responseBodies[requestId] = body
    }

    /**
     * 获取已缓存的响应体。
     */
    fun getResponseBody(requestId: String): ByteArray? =
        responseBodies[requestId]

    /**
     * 清理超时空闲会话。
     */
    fun cleanupExpired(maxIdleMs: Long = 60_000L) {
        val now = System.currentTimeMillis()
        val iterator = sessions.entries.iterator()
        while (iterator.hasNext()) {
            val entry = iterator.next()
            if (now - entry.value.lastActiveTimeMs > maxIdleMs) {
                iterator.remove()
            }
        }
    }

    /**
     * 清空全部会话与缓存。
     */
    fun clear() {
        sessions.clear()
        responseBodies.clear()
    }

    val activeSessionCount: Int
        get() = sessions.size
}
