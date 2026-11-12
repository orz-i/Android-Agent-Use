package com.agent.use.client.network.vpn.parser

/**
 * 封装 TCP 报头及载荷。
 *
 * @property srcPort 源端口
 * @property dstPort 目的端口
 * @property seqNumber 序列号 (32-bit unsigned)
 * @property ackNumber 确认号 (32-bit unsigned)
 * @property dataOffset TCP 报头长度 (字节)
 * @property flags TCP 控制位组合标记
 * @property isFin FIN 标记
 * @property isSyn SYN 标记
 * @property isRst RST 标记
 * @property isPsh PSH 标记
 * @property isAck ACK 标记
 * @property isUrg URG 标记
 * @property windowSize 窗口大小
 * @property payloadOffset 载荷起始位置
 * @property payloadLength 载荷字节数
 * @property rawBuffer 原始缓冲区
 */
data class TcpPacket(
    val srcPort: Int,
    val dstPort: Int,
    val seqNumber: Long,
    val ackNumber: Long,
    val dataOffset: Int,
    val flags: Int,
    val isFin: Boolean,
    val isSyn: Boolean,
    val isRst: Boolean,
    val isPsh: Boolean,
    val isAck: Boolean,
    val isUrg: Boolean,
    val windowSize: Int,
    val payloadOffset: Int,
    val payloadLength: Int,
    val rawBuffer: ByteArray
) {
    /**
     * 获取 TCP 载荷数据拷贝。
     */
    fun getPayload(): ByteArray {
        if (payloadLength <= 0) return ByteArray(0)
        return rawBuffer.copyOfRange(payloadOffset, payloadOffset + payloadLength)
    }

    companion object {
        const val FLAG_FIN = 0x01
        const val FLAG_SYN = 0x02
        const val FLAG_RST = 0x04
        const val FLAG_PSH = 0x08
        const val FLAG_ACK = 0x10
        const val FLAG_URG = 0x20

        /**
         * 从已解析的 [IpPacket] 中提取 [TcpPacket]。
         */
        fun parse(ipPacket: IpPacket): TcpPacket? {
            if (ipPacket.protocol != IpPacket.PROTOCOL_TCP) return null
            val offset = ipPacket.payloadOffset
            val length = ipPacket.payloadLength
            val buffer = ipPacket.rawBuffer

            if (length < 20 || offset < 0 || offset + length > buffer.size) {
                return null
            }

            val srcPort = ((buffer[offset].toInt() and 0xFF) shl 8) or
                    (buffer[offset + 1].toInt() and 0xFF)
            val dstPort = ((buffer[offset + 2].toInt() and 0xFF) shl 8) or
                    (buffer[offset + 3].toInt() and 0xFF)

            val seqNumber = readUInt32(buffer, offset + 4)
            val ackNumber = readUInt32(buffer, offset + 8)

            val dataOffset = ((buffer[offset + 12].toInt() and 0xF0) ushr 4) * 4
            if (dataOffset < 20 || dataOffset > length) {
                return null
            }

            val flags = buffer[offset + 13].toInt() and 0xFF
            val isFin = (flags and FLAG_FIN) != 0
            val isSyn = (flags and FLAG_SYN) != 0
            val isRst = (flags and FLAG_RST) != 0
            val isPsh = (flags and FLAG_PSH) != 0
            val isAck = (flags and FLAG_ACK) != 0
            val isUrg = (flags and FLAG_URG) != 0

            val windowSize = ((buffer[offset + 14].toInt() and 0xFF) shl 8) or
                    (buffer[offset + 15].toInt() and 0xFF)

            val payloadOffset = offset + dataOffset
            val payloadLength = length - dataOffset

            return TcpPacket(
                srcPort = srcPort,
                dstPort = dstPort,
                seqNumber = seqNumber,
                ackNumber = ackNumber,
                dataOffset = dataOffset,
                flags = flags,
                isFin = isFin,
                isSyn = isSyn,
                isRst = isRst,
                isPsh = isPsh,
                isAck = isAck,
                isUrg = isUrg,
                windowSize = windowSize,
                payloadOffset = payloadOffset,
                payloadLength = maxOf(0, payloadLength),
                rawBuffer = buffer
            )
        }

        private fun readUInt32(buffer: ByteArray, offset: Int): Long {
            return (((buffer[offset].toLong() and 0xFF) shl 24) or
                    ((buffer[offset + 1].toLong() and 0xFF) shl 16) or
                    ((buffer[offset + 2].toLong() and 0xFF) shl 8) or
                    (buffer[offset + 3].toLong() and 0xFF)) and 0xFFFFFFFFL
        }
    }
}
