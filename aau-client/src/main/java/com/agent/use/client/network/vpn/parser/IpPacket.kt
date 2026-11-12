package com.agent.use.client.network.vpn.parser

import java.net.InetAddress

/**
 * 封装 IPv4 / IPv6 数据报报头及基础信息。
 *
 * @property version IP 协议版本 (4 或 6)
 * @property protocol 传输层协议编号 (TCP = 6, UDP = 17, ICMP = 1 等)
 * @property srcAddress 源 IP 地址文本 (如 "192.168.1.10" 或 "fe80::1")
 * @property dstAddress 目的 IP 地址文本 (如 "142.250.190.46")
 * @property headerLength IP 报头长度 (字节)
 * @property totalLength 整个 IP 数据报总长度 (包含报头与载荷)
 * @property payloadOffset 传输层载荷在 buffer 中的起始偏移量
 * @property payloadLength 传输层载荷字节长度
 * @property rawBuffer 原始字节缓冲区
 */
data class IpPacket(
    val version: Int,
    val protocol: Int,
    val srcAddress: String,
    val dstAddress: String,
    val headerLength: Int,
    val totalLength: Int,
    val payloadOffset: Int,
    val payloadLength: Int,
    val rawBuffer: ByteArray
) {
    companion object {
        const val PROTOCOL_ICMP = 1
        const val PROTOCOL_TCP = 6
        const val PROTOCOL_UDP = 17

        /**
         * 解析给定的字节缓冲区为 [IpPacket]。
         *
         * @param buffer 包含 IP 数据报的缓冲区
         * @param offset 起始偏移量
         * @param length 可用字节数
         * @return 解析成功的 [IpPacket]，若数据包损坏、截断或协议不支持则返回 null
         */
        fun parse(buffer: ByteArray, offset: Int = 0, length: Int = buffer.size): IpPacket? {
            if (length < 20 || offset < 0 || offset + length > buffer.size) {
                return null
            }

            val version = (buffer[offset].toInt() ushr 4) and 0x0F
            return when (version) {
                4 -> parseIPv4(buffer, offset, length)
                6 -> parseIPv6(buffer, offset, length)
                else -> null
            }
        }

        private fun parseIPv4(buffer: ByteArray, offset: Int, length: Int): IpPacket? {
            if (length < 20) return null

            val ihl = (buffer[offset].toInt() and 0x0F) * 4
            if (ihl < 20 || ihl > length) return null

            val totalLength = ((buffer[offset + 2].toInt() and 0xFF) shl 8) or
                    (buffer[offset + 3].toInt() and 0xFF)
            if (totalLength < ihl || totalLength > length) {
                // 如果系统截断或报告的缓冲区大小小于 totalLength，以实际 length 为准
                if (length < ihl) return null
            }
            val validTotalLength = minOf(totalLength, length)

            val protocol = buffer[offset + 9].toInt() and 0xFF

            val srcIpBytes = buffer.copyOfRange(offset + 12, offset + 16)
            val dstIpBytes = buffer.copyOfRange(offset + 16, offset + 20)
            val srcAddress = try {
                InetAddress.getByAddress(srcIpBytes).hostAddress ?: "0.0.0.0"
            } catch (_: Exception) {
                return null
            }
            val dstAddress = try {
                InetAddress.getByAddress(dstIpBytes).hostAddress ?: "0.0.0.0"
            } catch (_: Exception) {
                return null
            }

            val payloadOffset = offset + ihl
            val payloadLength = validTotalLength - ihl

            return IpPacket(
                version = 4,
                protocol = protocol,
                srcAddress = srcAddress,
                dstAddress = dstAddress,
                headerLength = ihl,
                totalLength = validTotalLength,
                payloadOffset = payloadOffset,
                payloadLength = maxOf(0, payloadLength),
                rawBuffer = buffer
            )
        }

        private fun parseIPv6(buffer: ByteArray, offset: Int, length: Int): IpPacket? {
            if (length < 40) return null

            val payloadLength = ((buffer[offset + 4].toInt() and 0xFF) shl 8) or
                    (buffer[offset + 5].toInt() and 0xFF)
            val nextHeader = buffer[offset + 6].toInt() and 0xFF

            val srcIpBytes = buffer.copyOfRange(offset + 8, offset + 24)
            val dstIpBytes = buffer.copyOfRange(offset + 24, offset + 40)
            val srcAddress = try {
                InetAddress.getByAddress(srcIpBytes).hostAddress ?: "::"
            } catch (_: Exception) {
                return null
            }
            val dstAddress = try {
                InetAddress.getByAddress(dstIpBytes).hostAddress ?: "::"
            } catch (_: Exception) {
                return null
            }

            val totalLength = minOf(40 + payloadLength, length)
            val validPayloadLength = maxOf(0, totalLength - 40)

            return IpPacket(
                version = 6,
                protocol = nextHeader,
                srcAddress = srcAddress,
                dstAddress = dstAddress,
                headerLength = 40,
                totalLength = totalLength,
                payloadOffset = offset + 40,
                payloadLength = validPayloadLength,
                rawBuffer = buffer
            )
        }
    }
}
