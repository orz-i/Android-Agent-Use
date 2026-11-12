package com.agent.display.client.network.vpn.parser

/**
 * 封装 UDP 报头及载荷。
 *
 * @property srcPort 源端口
 * @property dstPort 目的端口
 * @property length UDP 数据报总长度 (报头 8 字节 + 载荷)
 * @property payloadOffset 载荷起始位置
 * @property payloadLength 载荷字节数
 * @property rawBuffer 原始缓冲区
 */
data class UdpPacket(
    val srcPort: Int,
    val dstPort: Int,
    val length: Int,
    val payloadOffset: Int,
    val payloadLength: Int,
    val rawBuffer: ByteArray
) {
    /**
     * 获取 UDP 载荷数据拷贝。
     */
    fun getPayload(): ByteArray {
        if (payloadLength <= 0) return ByteArray(0)
        return rawBuffer.copyOfRange(payloadOffset, payloadOffset + payloadLength)
    }

    companion object {
        const val DNS_PORT = 53

        /**
         * 从已解析的 [IpPacket] 中提取 [UdpPacket]。
         */
        fun parse(ipPacket: IpPacket): UdpPacket? {
            if (ipPacket.protocol != IpPacket.PROTOCOL_UDP) return null
            val offset = ipPacket.payloadOffset
            val totalAvailable = ipPacket.payloadLength
            val buffer = ipPacket.rawBuffer

            if (totalAvailable < 8 || offset < 0 || offset + totalAvailable > buffer.size) {
                return null
            }

            val srcPort = ((buffer[offset].toInt() and 0xFF) shl 8) or
                    (buffer[offset + 1].toInt() and 0xFF)
            val dstPort = ((buffer[offset + 2].toInt() and 0xFF) shl 8) or
                    (buffer[offset + 3].toInt() and 0xFF)
            val udpLength = ((buffer[offset + 4].toInt() and 0xFF) shl 8) or
                    (buffer[offset + 5].toInt() and 0xFF)

            if (udpLength < 8) return null

            val validLength = minOf(udpLength, totalAvailable)
            val payloadLength = validLength - 8

            return UdpPacket(
                srcPort = srcPort,
                dstPort = dstPort,
                length = validLength,
                payloadOffset = offset + 8,
                payloadLength = maxOf(0, payloadLength),
                rawBuffer = buffer
            )
        }
    }
}
