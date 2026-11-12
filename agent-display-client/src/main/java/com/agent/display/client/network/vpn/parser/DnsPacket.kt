package com.agent.display.client.network.vpn.parser

import java.net.InetAddress

/**
 * DNS 问询项。
 */
data class DnsQuestion(
    val name: String,
    val type: Int,
    val qClass: Int
)

/**
 * DNS 应答项。
 */
data class DnsAnswer(
    val name: String,
    val type: Int,
    val ttl: Long,
    val address: String?
)

/**
 * 封装 DNS 报文结构。
 */
data class DnsPacket(
    val transactionId: Int,
    val isResponse: Boolean,
    val opcode: Int,
    val rcode: Int,
    val questions: List<DnsQuestion>,
    val answers: List<DnsAnswer>
) {
    /**
     * 快捷获取查询的主域名（若存在）。
     */
    val primaryQuestionName: String?
        get() = questions.firstOrNull()?.name

    companion object {
        const val TYPE_A = 1
        const val TYPE_CNAME = 5
        const val TYPE_AAAA = 28

        /**
         * 解析 UDP 载荷中的 DNS 报文。
         */
        fun parse(udpPacket: UdpPacket): DnsPacket? {
            if (udpPacket.srcPort != UdpPacket.DNS_PORT && udpPacket.dstPort != UdpPacket.DNS_PORT) {
                return null
            }
            return parse(udpPacket.rawBuffer, udpPacket.payloadOffset, udpPacket.payloadLength)
        }

        /**
         * 解析原始字节中的 DNS 报文。
         */
        fun parse(buffer: ByteArray, offset: Int, length: Int): DnsPacket? {
            if (length < 12 || offset < 0 || offset + length > buffer.size) {
                return null
            }

            val id = readUInt16(buffer, offset)
            val flags = readUInt16(buffer, offset + 2)
            val isResponse = (flags and 0x8000) != 0
            val opcode = (flags ushr 11) and 0x0F
            val rcode = flags and 0x0F

            val qdCount = readUInt16(buffer, offset + 4)
            val anCount = readUInt16(buffer, offset + 6)

            var cur = offset + 12
            val end = offset + length
            val questions = mutableListOf<DnsQuestion>()

            // 解析 Questions
            try {
                for (i in 0 until qdCount) {
                    if (cur >= end) break
                    val (name, nextCur) = readDomainName(buffer, offset, cur, end)
                    cur = nextCur
                    if (cur + 4 > end) break
                    val qType = readUInt16(buffer, cur)
                    val qClass = readUInt16(buffer, cur + 2)
                    cur += 4
                    questions.add(DnsQuestion(name, qType, qClass))
                }

                // 解析 Answers
                val answers = mutableListOf<DnsAnswer>()
                if (isResponse) {
                    for (i in 0 until anCount) {
                        if (cur >= end) break
                        val (name, nextCur) = readDomainName(buffer, offset, cur, end)
                        cur = nextCur
                        if (cur + 10 > end) break
                        val aType = readUInt16(buffer, cur)
                        val ttl = readUInt32(buffer, cur + 4)
                        val rdLength = readUInt16(buffer, cur + 8)
                        cur += 10

                        if (cur + rdLength > end) break
                        var address: String? = null
                        if (aType == TYPE_A && rdLength == 4) {
                            val ipBytes = buffer.copyOfRange(cur, cur + 4)
                            address = InetAddress.getByAddress(ipBytes).hostAddress
                        } else if (aType == TYPE_AAAA && rdLength == 16) {
                            val ipBytes = buffer.copyOfRange(cur, cur + 16)
                            address = InetAddress.getByAddress(ipBytes).hostAddress
                        }
                        cur += rdLength
                        answers.add(DnsAnswer(name, aType, ttl, address))
                    }
                }

                return DnsPacket(
                    transactionId = id,
                    isResponse = isResponse,
                    opcode = opcode,
                    rcode = rcode,
                    questions = questions,
                    answers = answers
                )
            } catch (_: Exception) {
                return null
            }
        }

        private fun readDomainName(
            buffer: ByteArray,
            baseOffset: Int,
            start: Int,
            end: Int
        ): Pair<String, Int> {
            val sb = StringBuilder()
            var cur = start
            var jumped = false
            var returnCur = start
            var steps = 0
            val maxSteps = 128 // 防止压缩指针死循环

            while (cur < end && steps++ < maxSteps) {
                val len = buffer[cur].toInt() and 0xFF
                if (len == 0) {
                    cur++
                    if (!jumped) returnCur = cur
                    break
                }
                // 指针压缩 (0xC0)
                if ((len and 0xC0) == 0xC0) {
                    if (cur + 1 >= end) break
                    val offsetInDns = ((len and 0x3F) shl 8) or (buffer[cur + 1].toInt() and 0xFF)
                    if (!jumped) {
                        returnCur = cur + 2
                        jumped = true
                    }
                    cur = baseOffset + offsetInDns
                    continue
                } else {
                    cur++
                    if (cur + len > end) break
                    if (sb.isNotEmpty()) sb.append('.')
                    sb.append(String(buffer, cur, len, Charsets.US_ASCII))
                    cur += len
                    if (!jumped) returnCur = cur
                }
            }

            return Pair(sb.toString(), returnCur)
        }

        private fun readUInt16(buffer: ByteArray, offset: Int): Int {
            return ((buffer[offset].toInt() and 0xFF) shl 8) or
                    (buffer[offset + 1].toInt() and 0xFF)
        }

        private fun readUInt32(buffer: ByteArray, offset: Int): Long {
            return (((buffer[offset].toLong() and 0xFF) shl 24) or
                    ((buffer[offset + 1].toLong() and 0xFF) shl 16) or
                    ((buffer[offset + 2].toLong() and 0xFF) shl 8) or
                    (buffer[offset + 3].toLong() and 0xFF)) and 0xFFFFFFFFL
        }
    }
}
