package com.agent.use.client.network.vpn.parser

/**
 * 封装 TLS Client Hello 解析结果。
 *
 * @property sni 解析出的 Server Name Indication 域名 (如 "api.github.com")，未携带时为 null
 * @property tlsVersion 声明的 TLS 协议主/次版本号 (如 0x0303 对应 TLS 1.2)
 * @property rawLength 握手记录报文长度
 */
data class TlsClientHello(
    val sni: String?,
    val tlsVersion: Int,
    val rawLength: Int
)

/**
 * TLS 报文解析工具类。
 *
 * 专门用于在无需解密或安装 CA 证书的情况下，嗅探 TLS 握手中的 Client Hello 报文，
 * 提取目标 SNI (Server Name Indication) 域名与建立连接的时间。
 */
object TlsPacket {

    private const val CONTENT_TYPE_HANDSHAKE = 0x16
    private const val HANDSHAKE_TYPE_CLIENT_HELLO = 0x01
    private const val EXTENSION_TYPE_SNI = 0x0000
    private const val SNI_TYPE_HOST_NAME = 0x00

    /**
     * 判断给定载荷开头是否为 TLS Client Hello 握手报文。
     */
    fun isClientHello(buffer: ByteArray, offset: Int = 0, length: Int = buffer.size - offset): Boolean {
        if (length < 9 || offset < 0 || offset + length > buffer.size) return false
        val contentType = buffer[offset].toInt() and 0xFF
        val majorVersion = buffer[offset + 1].toInt() and 0xFF
        val handshakeType = buffer[offset + 5].toInt() and 0xFF
        return contentType == CONTENT_TYPE_HANDSHAKE && majorVersion == 0x03 && handshakeType == HANDSHAKE_TYPE_CLIENT_HELLO
    }

    /**
     * 解析载荷中的 TLS Client Hello 报文，提取 SNI 域名。
     *
     * @param buffer 包含 TCP 载荷的字节缓冲区
     * @param offset 载荷起始偏移量
     * @param length 载荷长度
     * @return [TlsClientHello] 结构体，非 Client Hello 或解析异常时返回 null
     */
    fun parseClientHello(
        buffer: ByteArray,
        offset: Int = 0,
        length: Int = buffer.size - offset
    ): TlsClientHello? {
        if (!isClientHello(buffer, offset, length)) return null

        try {
            val recordVersion = readUInt16(buffer, offset + 1)
            val recordLength = readUInt16(buffer, offset + 3)
            val recordEnd = minOf(offset + 5 + recordLength, offset + length)

            var cur = offset + 5 // 指向 Handshake Type
            if (cur >= recordEnd) return null

            val handshakeType = buffer[cur].toInt() and 0xFF
            if (handshakeType != HANDSHAKE_TYPE_CLIENT_HELLO) return null

            cur += 4 // 跳过 Handshake Type (1) + Length (3)
            if (cur + 34 > recordEnd) return null

            val clientVersion = readUInt16(buffer, cur)
            cur += 2 // 跳过 Client Version (2)
            cur += 32 // 跳过 Random (32)

            if (cur >= recordEnd) return null
            val sessionIdLen = buffer[cur].toInt() and 0xFF
            cur += 1 + sessionIdLen // 跳过 Session ID

            if (cur + 2 > recordEnd) return null
            val cipherSuitesLen = readUInt16(buffer, cur)
            cur += 2 + cipherSuitesLen // 跳过 Cipher Suites

            if (cur >= recordEnd) return null
            val compressionLen = buffer[cur].toInt() and 0xFF
            cur += 1 + compressionLen // 跳过 Compression Methods

            // 检查是否有 Extensions
            var sni: String? = null
            if (cur + 2 <= recordEnd) {
                val extensionsLen = readUInt16(buffer, cur)
                cur += 2
                val extensionsEnd = minOf(cur + extensionsLen, recordEnd)

                while (cur + 4 <= extensionsEnd) {
                    val extType = readUInt16(buffer, cur)
                    val extLen = readUInt16(buffer, cur + 2)
                    cur += 4

                    if (extType == EXTENSION_TYPE_SNI && cur + extLen <= extensionsEnd) {
                        // 解析 SNI 扩展内部结构
                        if (extLen >= 2) {
                            val serverNameListLen = readUInt16(buffer, cur)
                            var sniCur = cur + 2
                            val sniEnd = minOf(sniCur + serverNameListLen, cur + extLen)

                            while (sniCur + 3 <= sniEnd) {
                                val nameType = buffer[sniCur].toInt() and 0xFF
                                val nameLen = readUInt16(buffer, sniCur + 1)
                                sniCur += 3

                                if (nameType == SNI_TYPE_HOST_NAME && sniCur + nameLen <= sniEnd) {
                                    sni = String(buffer, sniCur, nameLen, Charsets.US_ASCII)
                                    break
                                }
                                sniCur += nameLen
                            }
                        }
                    }

                    cur += extLen
                }
            }

            return TlsClientHello(
                sni = sni,
                tlsVersion = clientVersion.takeIf { it != 0 } ?: recordVersion,
                rawLength = recordLength
            )
        } catch (_: Exception) {
            return null
        }
    }

    private fun readUInt16(buffer: ByteArray, offset: Int): Int {
        return ((buffer[offset].toInt() and 0xFF) shl 8) or
                (buffer[offset + 1].toInt() and 0xFF)
    }
}
