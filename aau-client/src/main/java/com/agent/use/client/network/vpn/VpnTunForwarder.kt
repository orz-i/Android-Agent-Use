package com.agent.use.client.network.vpn

import android.util.Log
import com.agent.use.client.network.vpn.parser.IpPacket
import com.agent.use.client.network.vpn.parser.TcpPacket
import com.agent.use.client.network.vpn.parser.UdpPacket
import com.agent.use.client.network.vpn.processor.VpnPacketProcessor
import java.io.IOException
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.nio.channels.SocketChannel
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * Userspace NIO Selector-based NAT forwarder for [AauVpnService].
 *
 * Bridges target-app IP packets read from Android's TUN interface out to the real network
 * using `VpnService.protect(...)` sockets (so traffic never loops back into TUN), and writes
 * valid IPv4+UDP / IPv4+TCP response packets back to TUN while mirroring all traffic to
 * [VpnPacketProcessor] for DNS, TLS SNI, and HTTP plaintext inspection.
 */
class VpnTunForwarder(
    private val protectSocket: (Socket) -> Boolean,
    private val protectDatagram: (DatagramSocket) -> Boolean,
    private val writeToTun: (ByteArray, Int) -> Unit,
    private val packetProcessor: VpnPacketProcessor? = null
) {

    companion object {
        private const val TAG = "VpnTunForwarder"
        private const val MAX_TCP_PAYLOAD_SEGMENT = 1400
        private const val MAX_READ_CHUNK = 16384
        private const val UDP_IDLE_TIMEOUT_MS = 30_000L
        private const val TCP_IDLE_TIMEOUT_MS = 120_000L
        private const val SELECT_TIMEOUT_MS = 500L

        internal const val TCP_FLAG_FIN = 0x01
        internal const val TCP_FLAG_SYN = 0x02
        internal const val TCP_FLAG_RST = 0x04
        internal const val TCP_FLAG_PSH = 0x08
        internal const val TCP_FLAG_ACK = 0x10

        private val ipIdCounter = AtomicLong(1L)

        internal fun computeChecksum(data: ByteArray, offset: Int, length: Int, initialSum: Long = 0L): Int {
            var sum = initialSum
            var i = offset
            val end = offset + length
            while (i + 1 < end) {
                val word = ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
                sum += word.toLong()
                i += 2
            }
            if (i < end) {
                sum += ((data[i].toInt() and 0xFF) shl 8).toLong()
            }
            while ((sum ushr 16) != 0L) {
                sum = (sum and 0xFFFFL) + (sum ushr 16)
            }
            return (sum.toInt().inv()) and 0xFFFF
        }

        private fun ipv4PseudoHeaderSum(srcIp: ByteArray, dstIp: ByteArray, protocol: Int, transportLen: Int): Long {
            var sum = 0L
            for (i in 0 until 4 step 2) {
                sum += (((srcIp[i].toInt() and 0xFF) shl 8) or (srcIp[i + 1].toInt() and 0xFF)).toLong()
                sum += (((dstIp[i].toInt() and 0xFF) shl 8) or (dstIp[i + 1].toInt() and 0xFF)).toLong()
            }
            sum += (protocol and 0xFF).toLong()
            sum += (transportLen and 0xFFFF).toLong()
            return sum
        }

        internal fun buildIpv4UdpPacket(
            srcIp: ByteArray,
            srcPort: Int,
            dstIp: ByteArray,
            dstPort: Int,
            payload: ByteArray,
            payloadLen: Int = payload.size
        ): ByteArray {
            val udpLen = 8 + payloadLen
            val totalLen = 20 + udpLen
            val pkt = ByteArray(totalLen)

            // IPv4 header
            pkt[0] = 0x45.toByte()
            pkt[2] = ((totalLen ushr 8) and 0xFF).toByte()
            pkt[3] = (totalLen and 0xFF).toByte()
            val id = ipIdCounter.getAndIncrement().toInt() and 0xFFFF
            pkt[4] = ((id ushr 8) and 0xFF).toByte()
            pkt[5] = (id and 0xFF).toByte()
            pkt[6] = 0x40.toByte() // DF
            pkt[8] = 64.toByte()   // TTL
            pkt[9] = IpPacket.PROTOCOL_UDP.toByte()
            System.arraycopy(srcIp, 0, pkt, 12, 4)
            System.arraycopy(dstIp, 0, pkt, 16, 4)
            val ipCsum = computeChecksum(pkt, 0, 20)
            pkt[10] = ((ipCsum ushr 8) and 0xFF).toByte()
            pkt[11] = (ipCsum and 0xFF).toByte()

            // UDP header
            pkt[20] = ((srcPort ushr 8) and 0xFF).toByte()
            pkt[21] = (srcPort and 0xFF).toByte()
            pkt[22] = ((dstPort ushr 8) and 0xFF).toByte()
            pkt[23] = (dstPort and 0xFF).toByte()
            pkt[24] = ((udpLen ushr 8) and 0xFF).toByte()
            pkt[25] = (udpLen and 0xFF).toByte()
            if (payloadLen > 0) {
                System.arraycopy(payload, 0, pkt, 28, payloadLen)
            }

            val pseudoSum = ipv4PseudoHeaderSum(srcIp, dstIp, IpPacket.PROTOCOL_UDP, udpLen)
            var udpCsum = computeChecksum(pkt, 20, udpLen, pseudoSum)
            if (udpCsum == 0) udpCsum = 0xFFFF
            pkt[26] = ((udpCsum ushr 8) and 0xFF).toByte()
            pkt[27] = (udpCsum and 0xFF).toByte()
            return pkt
        }

        internal fun buildIpv4TcpPacket(
            srcIp: ByteArray,
            srcPort: Int,
            dstIp: ByteArray,
            dstPort: Int,
            seqNum: Long,
            ackNum: Long,
            flags: Int,
            windowSize: Int = 65535,
            mssOption: Int? = null,
            payload: ByteArray? = null,
            payloadOffset: Int = 0,
            payloadLen: Int = payload?.size ?: 0
        ): ByteArray {
            val optLen = if (mssOption != null) 4 else 0
            val tcpHeaderLen = 20 + optLen
            val tcpLen = tcpHeaderLen + payloadLen
            val totalLen = 20 + tcpLen
            val pkt = ByteArray(totalLen)

            // IPv4 header
            pkt[0] = 0x45.toByte()
            pkt[2] = ((totalLen ushr 8) and 0xFF).toByte()
            pkt[3] = (totalLen and 0xFF).toByte()
            val id = ipIdCounter.getAndIncrement().toInt() and 0xFFFF
            pkt[4] = ((id ushr 8) and 0xFF).toByte()
            pkt[5] = (id and 0xFF).toByte()
            pkt[6] = 0x40.toByte() // DF
            pkt[8] = 64.toByte()   // TTL
            pkt[9] = IpPacket.PROTOCOL_TCP.toByte()
            System.arraycopy(srcIp, 0, pkt, 12, 4)
            System.arraycopy(dstIp, 0, pkt, 16, 4)
            val ipCsum = computeChecksum(pkt, 0, 20)
            pkt[10] = ((ipCsum ushr 8) and 0xFF).toByte()
            pkt[11] = (ipCsum and 0xFF).toByte()

            // TCP header
            pkt[20] = ((srcPort ushr 8) and 0xFF).toByte()
            pkt[21] = (srcPort and 0xFF).toByte()
            pkt[22] = ((dstPort ushr 8) and 0xFF).toByte()
            pkt[23] = (dstPort and 0xFF).toByte()

            pkt[24] = ((seqNum ushr 24) and 0xFF).toByte()
            pkt[25] = ((seqNum ushr 16) and 0xFF).toByte()
            pkt[26] = ((seqNum ushr 8) and 0xFF).toByte()
            pkt[27] = (seqNum and 0xFF).toByte()

            pkt[28] = ((ackNum ushr 24) and 0xFF).toByte()
            pkt[29] = ((ackNum ushr 16) and 0xFF).toByte()
            pkt[30] = ((ackNum ushr 8) and 0xFF).toByte()
            pkt[31] = (ackNum and 0xFF).toByte()

            val dataOffsetWords = tcpHeaderLen / 4
            pkt[32] = ((dataOffsetWords and 0x0F) shl 4).toByte()
            pkt[33] = (flags and 0x3F).toByte()
            pkt[34] = ((windowSize ushr 8) and 0xFF).toByte()
            pkt[35] = (windowSize and 0xFF).toByte()

            if (mssOption != null) {
                pkt[40] = 2.toByte() // Kind = MSS
                pkt[41] = 4.toByte() // Length = 4
                pkt[42] = ((mssOption ushr 8) and 0xFF).toByte()
                pkt[43] = (mssOption and 0xFF).toByte()
            }

            if (payload != null && payloadLen > 0) {
                System.arraycopy(payload, payloadOffset, pkt, 20 + tcpHeaderLen, payloadLen)
            }

            val pseudoSum = ipv4PseudoHeaderSum(srcIp, dstIp, IpPacket.PROTOCOL_TCP, tcpLen)
            val tcpCsum = computeChecksum(pkt, 20, tcpLen, pseudoSum)
            pkt[36] = ((tcpCsum ushr 8) and 0xFF).toByte()
            pkt[37] = (tcpCsum and 0xFF).toByte()
            return pkt
        }

        internal fun buildIpv4IcmpPortUnreachable(originalPacket: ByteArray, originalLength: Int): ByteArray? {
            if (originalLength < 28) return null
            val ihl = (originalPacket[0].toInt() and 0x0F) * 4
            val quoteLen = minOf(originalLength, ihl + 8)
            val icmpLen = 8 + quoteLen
            val totalLen = 20 + icmpLen
            val pkt = ByteArray(totalLen)

            // IPv4 header (swap src & dst)
            pkt[0] = 0x45.toByte()
            pkt[2] = ((totalLen ushr 8) and 0xFF).toByte()
            pkt[3] = (totalLen and 0xFF).toByte()
            val id = ipIdCounter.getAndIncrement().toInt() and 0xFFFF
            pkt[4] = ((id ushr 8) and 0xFF).toByte()
            pkt[5] = (id and 0xFF).toByte()
            pkt[8] = 64.toByte()
            pkt[9] = IpPacket.PROTOCOL_ICMP.toByte()
            System.arraycopy(originalPacket, 16, pkt, 12, 4) // dst -> src
            System.arraycopy(originalPacket, 12, pkt, 16, 4) // src -> dst
            val ipCsum = computeChecksum(pkt, 0, 20)
            pkt[10] = ((ipCsum ushr 8) and 0xFF).toByte()
            pkt[11] = (ipCsum and 0xFF).toByte()

            // ICMP Type 3 (Destination Unreachable), Code 3 (Port Unreachable)
            pkt[20] = 3.toByte()
            pkt[21] = 3.toByte()
            System.arraycopy(originalPacket, 0, pkt, 28, quoteLen)
            val icmpCsum = computeChecksum(pkt, 20, icmpLen)
            pkt[22] = ((icmpCsum ushr 8) and 0xFF).toByte()
            pkt[23] = (icmpCsum and 0xFF).toByte()
            return pkt
        }

        internal fun buildIpv6TcpRstPacket(
            srcIp6: ByteArray,
            srcPort: Int,
            dstIp6: ByteArray,
            dstPort: Int,
            seqNum: Long,
            ackNum: Long
        ): ByteArray {
            val tcpLen = 20
            val totalLen = 40 + tcpLen
            val pkt = ByteArray(totalLen)

            // IPv6 fixed header (40 bytes)
            pkt[0] = 0x60.toByte()
            pkt[4] = ((tcpLen ushr 8) and 0xFF).toByte()
            pkt[5] = (tcpLen and 0xFF).toByte()
            pkt[6] = IpPacket.PROTOCOL_TCP.toByte()
            pkt[7] = 64.toByte()
            System.arraycopy(srcIp6, 0, pkt, 8, 16)
            System.arraycopy(dstIp6, 0, pkt, 24, 16)

            // TCP header at offset 40
            pkt[40] = ((srcPort ushr 8) and 0xFF).toByte()
            pkt[41] = (srcPort and 0xFF).toByte()
            pkt[42] = ((dstPort ushr 8) and 0xFF).toByte()
            pkt[43] = (dstPort and 0xFF).toByte()
            pkt[44] = ((seqNum ushr 24) and 0xFF).toByte()
            pkt[45] = ((seqNum ushr 16) and 0xFF).toByte()
            pkt[46] = ((seqNum ushr 8) and 0xFF).toByte()
            pkt[47] = (seqNum and 0xFF).toByte()
            pkt[48] = ((ackNum ushr 24) and 0xFF).toByte()
            pkt[49] = ((ackNum ushr 16) and 0xFF).toByte()
            pkt[50] = ((ackNum ushr 8) and 0xFF).toByte()
            pkt[51] = (ackNum and 0xFF).toByte()
            pkt[52] = 0x50.toByte()
            pkt[53] = (TCP_FLAG_RST or TCP_FLAG_ACK).toByte()

            var pseudo = 0L
            for (i in 0 until 16 step 2) {
                pseudo += (((srcIp6[i].toInt() and 0xFF) shl 8) or (srcIp6[i + 1].toInt() and 0xFF)).toLong()
                pseudo += (((dstIp6[i].toInt() and 0xFF) shl 8) or (dstIp6[i + 1].toInt() and 0xFF)).toLong()
            }
            pseudo += tcpLen.toLong()
            pseudo += IpPacket.PROTOCOL_TCP.toLong()
            val csum = computeChecksum(pkt, 40, tcpLen, pseudo)
            pkt[56] = ((csum ushr 8) and 0xFF).toByte()
            pkt[57] = (csum and 0xFF).toByte()
            return pkt
        }
    }

    private data class NatKey(
        val clientIp: String,
        val clientPort: Int,
        val serverIp: String,
        val serverPort: Int,
        val protocol: Int
    )

    private enum class TcpState {
        SYN_SENT,
        ESTABLISHED,
        CLOSED
    }

    private class UdpSession(
        val key: NatKey,
        val clientIpBytes: ByteArray,
        val serverIpBytes: ByteArray,
        val channel: DatagramChannel,
        @Volatile var lastActiveMs: Long = System.currentTimeMillis()
    )

    private class TcpNatSession(
        val key: NatKey,
        val clientIpBytes: ByteArray,
        val serverIpBytes: ByteArray,
        val channel: SocketChannel,
        var state: TcpState,
        var clientNextSeq: Long,
        var serverSeq: Long,
        val uplinkQueue: ArrayDeque<ByteBuffer> = ArrayDeque(),
        var finReceivedFromClient: Boolean = false,
        var finSentToClient: Boolean = false,
        @Volatile var lastActiveMs: Long = System.currentTimeMillis()
    )

    private val running = AtomicBoolean(false)
    @Volatile
    private var selector: Selector? = null
    @Volatile
    private var selectorThread: Thread? = null

    private val pendingTasks = ConcurrentLinkedQueue<() -> Unit>()
    private val tcpSessions = ConcurrentHashMap<NatKey, TcpNatSession>()
    private val udpSessions = ConcurrentHashMap<NatKey, UdpSession>()
    private val tunWriteLock = Any()

    fun start() {
        if (running.getAndSet(true)) return
        val sel = Selector.open()
        selector = sel
        val thread = Thread({
            runSelectorLoop(sel)
        }, "aau-vpn-nat-selector").apply {
            isDaemon = true
            start()
        }
        selectorThread = thread
    }

    fun stop() {
        if (!running.getAndSet(false)) return
        val sel = selector
        selector = null
        sel?.wakeup()

        selectorThread?.interrupt()
        selectorThread = null

        tcpSessions.values.forEach { closeTcpSessionQuietly(it) }
        tcpSessions.clear()
        udpSessions.values.forEach { closeUdpSessionQuietly(it) }
        udpSessions.clear()
        pendingTasks.clear()

        try {
            sel?.close()
        } catch (_: Throwable) {
        }
    }

    /**
     * Handles an outbound IP packet read from the TUN interface.
     */
    fun handleOutboundIpPacket(raw: ByteArray, length: Int) {
        if (!running.get() || length < 20) return
        val copy = raw.copyOf(length)
        val ipPacket = IpPacket.parse(copy, 0, length) ?: return

        if (ipPacket.version == 6) {
            // Fast-fail IPv6 TCP SYN so dual-stack clients immediately switch to IPv4
            if (ipPacket.protocol == IpPacket.PROTOCOL_TCP) {
                val tcp = TcpPacket.parse(ipPacket) ?: return
                if (tcp.isSyn && !tcp.isAck) {
                    val src6 = copy.copyOfRange(8, 24)
                    val dst6 = copy.copyOfRange(24, 40)
                    val rst = buildIpv6TcpRstPacket(
                        srcIp6 = dst6,
                        srcPort = tcp.dstPort,
                        dstIp6 = src6,
                        dstPort = tcp.srcPort,
                        seqNum = 0L,
                        ackNum = (tcp.seqNumber + 1L) and 0xFFFFFFFFL
                    )
                    emitToTun(rst, rst.size)
                }
            }
            return
        }

        if (ipPacket.version != 4) return

        when (ipPacket.protocol) {
            IpPacket.PROTOCOL_UDP -> {
                val udp = UdpPacket.parse(ipPacket) ?: return
                packetProcessor?.processPacket(copy, length)
                // Fast-fail QUIC (UDP 443) so apps fall back cleanly to TCP HTTPS
                if (udp.dstPort == 443) {
                    val icmp = buildIpv4IcmpPortUnreachable(copy, length)
                    if (icmp != null) emitToTun(icmp, icmp.size)
                    return
                }
                val payload = udp.getPayload()
                val clientBytes = copy.copyOfRange(12, 16)
                val serverBytes = copy.copyOfRange(16, 20)
                val key = NatKey(
                    clientIp = ipPacket.srcAddress,
                    clientPort = udp.srcPort,
                    serverIp = ipPacket.dstAddress,
                    serverPort = udp.dstPort,
                    protocol = IpPacket.PROTOCOL_UDP
                )
                enqueueSelectorOp {
                    processOutboundUdp(key, clientBytes, serverBytes, payload)
                }
            }

            IpPacket.PROTOCOL_TCP -> {
                val tcp = TcpPacket.parse(ipPacket) ?: return
                packetProcessor?.processPacket(copy, length)
                val payload = tcp.getPayload()
                val clientBytes = copy.copyOfRange(12, 16)
                val serverBytes = copy.copyOfRange(16, 20)
                val key = NatKey(
                    clientIp = ipPacket.srcAddress,
                    clientPort = tcp.srcPort,
                    serverIp = ipPacket.dstAddress,
                    serverPort = tcp.dstPort,
                    protocol = IpPacket.PROTOCOL_TCP
                )
                val seq = tcp.seqNumber and 0xFFFFFFFFL
                val flags = tcp.flags
                enqueueSelectorOp {
                    processOutboundTcp(key, clientBytes, serverBytes, seq, flags, payload)
                }
            }
        }
    }

    private fun enqueueSelectorOp(task: () -> Unit) {
        pendingTasks.add(task)
        selector?.wakeup()
    }

    private fun runSelectorLoop(sel: Selector) {
        val readBuf = ByteBuffer.allocate(MAX_READ_CHUNK)
        var lastPruneMs = System.currentTimeMillis()

        while (running.get() && !Thread.currentThread().isInterrupted) {
            try {
                while (true) {
                    val task = pendingTasks.poll() ?: break
                    runCatching { task() }
                        .onFailure { safeLogW("Selector task failed: ${it.message}") }
                }

                val selectedCount = sel.select(SELECT_TIMEOUT_MS)
                if (!running.get()) break

                if (selectedCount > 0) {
                    val iter = sel.selectedKeys().iterator()
                    while (iter.hasNext()) {
                        val sk = iter.next()
                        iter.remove()
                        if (!sk.isValid) continue
                        when (val att = sk.attachment()) {
                            is TcpNatSession -> handleTcpKey(sk, att, readBuf)
                            is UdpSession -> handleUdpKey(sk, att, readBuf)
                        }
                    }
                }

                val now = System.currentTimeMillis()
                if (now - lastPruneMs >= 5000L) {
                    lastPruneMs = now
                    pruneIdleSessions(now)
                }
            } catch (_: InterruptedException) {
                break
            } catch (e: Throwable) {
                if (running.get()) {
                    safeLogW("Selector loop exception: ${e.message}")
                }
            }
        }
    }

    private fun processOutboundUdp(
        key: NatKey,
        clientBytes: ByteArray,
        serverBytes: ByteArray,
        payload: ByteArray
    ) {
        val sel = selector ?: return
        var session = udpSessions[key]
        if (session == null) {
            val ch = try {
                DatagramChannel.open().apply {
                    configureBlocking(false)
                }
            } catch (e: IOException) {
                safeLogW("Failed to open DatagramChannel: ${e.message}")
                return
            }

            if (!protectDatagram(ch.socket())) {
                runCatching { ch.close() }
                return
            }

            try {
                val remoteAddr = InetSocketAddress(InetAddress.getByAddress(serverBytes), key.serverPort)
                ch.connect(remoteAddr)
                val newSession = UdpSession(key, clientBytes, serverBytes, ch)
                ch.register(sel, SelectionKey.OP_READ, newSession)
                udpSessions[key] = newSession
                session = newSession
            } catch (e: IOException) {
                runCatching { ch.close() }
                safeLogW("Failed to connect UDP ${key.serverIp}:${key.serverPort}: ${e.message}")
                return
            }
        }

        session.lastActiveMs = System.currentTimeMillis()
        if (payload.isNotEmpty()) {
            try {
                session.channel.write(ByteBuffer.wrap(payload))
            } catch (e: IOException) {
                safeLogW("UDP write error: ${e.message}")
                udpSessions.remove(key)
                closeUdpSessionQuietly(session)
            }
        }
    }

    private fun handleUdpKey(sk: SelectionKey, session: UdpSession, readBuf: ByteBuffer) {
        if (!sk.isReadable) return
        readBuf.clear()
        val n = try {
            session.channel.read(readBuf)
        } catch (_: IOException) {
            udpSessions.remove(session.key)
            closeUdpSessionQuietly(session)
            return
        }
        if (n <= 0) return

        session.lastActiveMs = System.currentTimeMillis()
        readBuf.flip()
        val data = ByteArray(n)
        readBuf.get(data)

        val respPkt = buildIpv4UdpPacket(
            srcIp = session.serverIpBytes,
            srcPort = session.key.serverPort,
            dstIp = session.clientIpBytes,
            dstPort = session.key.clientPort,
            payload = data,
            payloadLen = data.size
        )
        emitToTun(respPkt, respPkt.size)
        packetProcessor?.processPacket(respPkt, respPkt.size)
    }

    private fun processOutboundTcp(
        key: NatKey,
        clientBytes: ByteArray,
        serverBytes: ByteArray,
        tcpSeq: Long,
        flags: Int,
        payload: ByteArray
    ) {
        val sel = selector ?: return
        val isSyn = (flags and TCP_FLAG_SYN) != 0
        val isAck = (flags and TCP_FLAG_ACK) != 0
        val isFin = (flags and TCP_FLAG_FIN) != 0
        val isRst = (flags and TCP_FLAG_RST) != 0

        if (isRst) {
            tcpSessions.remove(key)?.let { closeTcpSessionQuietly(it) }
            return
        }

        if (isSyn && !isAck) {
            tcpSessions.remove(key)?.let { closeTcpSessionQuietly(it) }

            val ch = try {
                SocketChannel.open().apply {
                    configureBlocking(false)
                    socket().tcpNoDelay = true
                }
            } catch (e: IOException) {
                sendTcpRst(serverBytes, key.serverPort, clientBytes, key.clientPort, 0L, (tcpSeq + 1L) and 0xFFFFFFFFL)
                return
            }

            if (!protectSocket(ch.socket())) {
                runCatching { ch.close() }
                sendTcpRst(serverBytes, key.serverPort, clientBytes, key.clientPort, 0L, (tcpSeq + 1L) and 0xFFFFFFFFL)
                return
            }

            val initialServerSeq = ((System.nanoTime() xor 0x5A5A5A5AL) and 0x7FFFFFFFL).coerceAtLeast(1000L)
            val session = TcpNatSession(
                key = key,
                clientIpBytes = clientBytes,
                serverIpBytes = serverBytes,
                channel = ch,
                state = TcpState.SYN_SENT,
                clientNextSeq = (tcpSeq + 1L) and 0xFFFFFFFFL,
                serverSeq = initialServerSeq
            )

            try {
                val remoteAddr = InetSocketAddress(InetAddress.getByAddress(serverBytes), key.serverPort)
                val connected = ch.connect(remoteAddr)
                tcpSessions[key] = session
                if (connected) {
                    completeTcpHandshake(sel, session)
                } else {
                    ch.register(sel, SelectionKey.OP_CONNECT, session)
                }
            } catch (e: IOException) {
                tcpSessions.remove(key)
                runCatching { ch.close() }
                sendTcpRst(serverBytes, key.serverPort, clientBytes, key.clientPort, 0L, (tcpSeq + 1L) and 0xFFFFFFFFL)
            }
            return
        }

        val session = tcpSessions[key]
        if (session == null) {
            if (isAck) {
                sendTcpRst(serverBytes, key.serverPort, clientBytes, key.clientPort, 0L, tcpSeq)
            }
            return
        }

        session.lastActiveMs = System.currentTimeMillis()

        // Signed 32-bit sequence delta handles wrap-around modulo 2^32
        val seqDelta = (tcpSeq - session.clientNextSeq).toInt()
        if (payload.isNotEmpty()) {
            if (seqDelta == 0) {
                session.clientNextSeq = (session.clientNextSeq + payload.size.toLong()) and 0xFFFFFFFFL
                session.uplinkQueue.addLast(ByteBuffer.wrap(payload))
                sendTcpAck(session)
                flushTcpUplink(sel, session)
            } else if (seqDelta < 0) {
                val alreadyReceived = -seqDelta
                if (alreadyReceived < payload.size) {
                    val fresh = payload.copyOfRange(alreadyReceived, payload.size)
                    session.clientNextSeq = (session.clientNextSeq + fresh.size.toLong()) and 0xFFFFFFFFL
                    session.uplinkQueue.addLast(ByteBuffer.wrap(fresh))
                    sendTcpAck(session)
                    flushTcpUplink(sel, session)
                } else {
                    // Duplicate segment -> re-ACK current clientNextSeq
                    sendTcpAck(session)
                }
            }
        }

        if (isFin && !session.finReceivedFromClient) {
            val expectedFinSeq = (tcpSeq + payload.size.toLong()) and 0xFFFFFFFFL
            if (((expectedFinSeq - session.clientNextSeq).toInt()) <= 0) {
                session.finReceivedFromClient = true
                session.clientNextSeq = (session.clientNextSeq + 1L) and 0xFFFFFFFFL
                sendTcpAck(session)
                flushTcpUplink(sel, session)
                if (session.uplinkQueue.isEmpty()) {
                    runCatching { session.channel.shutdownOutput() }
                }
                if (session.finSentToClient) {
                    tcpSessions.remove(key)
                    closeTcpSessionQuietly(session)
                }
            }
        }
    }

    private fun completeTcpHandshake(sel: Selector, session: TcpNatSession) {
        session.state = TcpState.ESTABLISHED
        val synAck = buildIpv4TcpPacket(
            srcIp = session.serverIpBytes,
            srcPort = session.key.serverPort,
            dstIp = session.clientIpBytes,
            dstPort = session.key.clientPort,
            seqNum = session.serverSeq,
            ackNum = session.clientNextSeq,
            flags = TCP_FLAG_SYN or TCP_FLAG_ACK,
            mssOption = MAX_TCP_PAYLOAD_SEGMENT
        )
        session.serverSeq = (session.serverSeq + 1L) and 0xFFFFFFFFL
        emitToTun(synAck, synAck.size)

        val ops = if (session.uplinkQueue.isNotEmpty()) {
            SelectionKey.OP_READ or SelectionKey.OP_WRITE
        } else {
            SelectionKey.OP_READ
        }
        session.channel.register(sel, ops, session)
    }

    private fun handleTcpKey(sk: SelectionKey, session: TcpNatSession, readBuf: ByteBuffer) {
        val sel = selector ?: return
        try {
            if (sk.isConnectable) {
                if (session.channel.finishConnect()) {
                    completeTcpHandshake(sel, session)
                }
                return
            }

            if (sk.isWritable) {
                flushTcpUplink(sel, session)
            }

            if (sk.isValid && sk.isReadable) {
                readBuf.clear()
                val n = session.channel.read(readBuf)
                session.lastActiveMs = System.currentTimeMillis()
                if (n > 0) {
                    readBuf.flip()
                    val data = ByteArray(n)
                    readBuf.get(data)

                    var off = 0
                    while (off < data.size) {
                        val segLen = minOf(MAX_TCP_PAYLOAD_SEGMENT, data.size - off)
                        val tcpPkt = buildIpv4TcpPacket(
                            srcIp = session.serverIpBytes,
                            srcPort = session.key.serverPort,
                            dstIp = session.clientIpBytes,
                            dstPort = session.key.clientPort,
                            seqNum = session.serverSeq,
                            ackNum = session.clientNextSeq,
                            flags = TCP_FLAG_PSH or TCP_FLAG_ACK,
                            payload = data,
                            payloadOffset = off,
                            payloadLen = segLen
                        )
                        session.serverSeq = (session.serverSeq + segLen.toLong()) and 0xFFFFFFFFL
                        emitToTun(tcpPkt, tcpPkt.size)
                        packetProcessor?.processPacket(tcpPkt, tcpPkt.size)
                        off += segLen
                    }
                } else if (n < 0) {
                    if (!session.finSentToClient) {
                        session.finSentToClient = true
                        val finPkt = buildIpv4TcpPacket(
                            srcIp = session.serverIpBytes,
                            srcPort = session.key.serverPort,
                            dstIp = session.clientIpBytes,
                            dstPort = session.key.clientPort,
                            seqNum = session.serverSeq,
                            ackNum = session.clientNextSeq,
                            flags = TCP_FLAG_FIN or TCP_FLAG_ACK
                        )
                        session.serverSeq = (session.serverSeq + 1L) and 0xFFFFFFFFL
                        emitToTun(finPkt, finPkt.size)
                        packetProcessor?.processPacket(finPkt, finPkt.size)
                    }
                    // Stop monitoring OP_READ once server EOF is sent
                    if (sk.isValid) {
                        val newOps = sk.interestOps() and SelectionKey.OP_READ.inv()
                        if (newOps == 0 && session.finReceivedFromClient) {
                            tcpSessions.remove(session.key)
                            closeTcpSessionQuietly(session)
                        } else {
                            sk.interestOps(newOps)
                        }
                    }
                }
            }
        } catch (e: IOException) {
            safeLogW("TCP forward error for ${session.key.serverIp}:${session.key.serverPort}: ${e.message}")
            sendTcpRst(
                srcIp = session.serverIpBytes,
                srcPort = session.key.serverPort,
                dstIp = session.clientIpBytes,
                dstPort = session.key.clientPort,
                seqNum = session.serverSeq,
                ackNum = session.clientNextSeq
            )
            tcpSessions.remove(session.key)
            closeTcpSessionQuietly(session)
        }
    }

    private fun flushTcpUplink(sel: Selector, session: TcpNatSession) {
        if (session.state != TcpState.ESTABLISHED) return
        val sk = session.channel.keyFor(sel)

        while (session.uplinkQueue.isNotEmpty()) {
            val buf = session.uplinkQueue.first()
            try {
                session.channel.write(buf)
            } catch (e: IOException) {
                tcpSessions.remove(session.key)
                closeTcpSessionQuietly(session)
                return
            }
            if (buf.hasRemaining()) {
                if (sk != null && sk.isValid) {
                    sk.interestOps(sk.interestOps() or SelectionKey.OP_WRITE)
                }
                return
            }
            session.uplinkQueue.removeFirst()
        }

        if (sk != null && sk.isValid) {
            sk.interestOps(sk.interestOps() and SelectionKey.OP_WRITE.inv())
        }
        if (session.finReceivedFromClient) {
            runCatching { session.channel.shutdownOutput() }
        }
    }

    private fun sendTcpAck(session: TcpNatSession) {
        if (session.state != TcpState.ESTABLISHED) return
        val ackPkt = buildIpv4TcpPacket(
            srcIp = session.serverIpBytes,
            srcPort = session.key.serverPort,
            dstIp = session.clientIpBytes,
            dstPort = session.key.clientPort,
            seqNum = session.serverSeq,
            ackNum = session.clientNextSeq,
            flags = TCP_FLAG_ACK
        )
        emitToTun(ackPkt, ackPkt.size)
    }

    private fun sendTcpRst(
        srcIp: ByteArray,
        srcPort: Int,
        dstIp: ByteArray,
        dstPort: Int,
        seqNum: Long,
        ackNum: Long
    ) {
        val rstPkt = buildIpv4TcpPacket(
            srcIp = srcIp,
            srcPort = srcPort,
            dstIp = dstIp,
            dstPort = dstPort,
            seqNum = seqNum,
            ackNum = ackNum,
            flags = TCP_FLAG_RST or TCP_FLAG_ACK
        )
        emitToTun(rstPkt, rstPkt.size)
    }

    private fun emitToTun(pkt: ByteArray, len: Int) {
        if (!running.get()) return
        synchronized(tunWriteLock) {
            try {
                writeToTun(pkt, len)
            } catch (e: Throwable) {
                if (running.get()) {
                    safeLogW("TUN write error: ${e.message}")
                }
            }
        }
    }

    private fun pruneIdleSessions(now: Long) {
        val udpIter = udpSessions.entries.iterator()
        while (udpIter.hasNext()) {
            val entry = udpIter.next()
            if (now - entry.value.lastActiveMs > UDP_IDLE_TIMEOUT_MS) {
                udpIter.remove()
                closeUdpSessionQuietly(entry.value)
            }
        }

        val tcpIter = tcpSessions.entries.iterator()
        while (tcpIter.hasNext()) {
            val entry = tcpIter.next()
            if (now - entry.value.lastActiveMs > TCP_IDLE_TIMEOUT_MS) {
                tcpIter.remove()
                closeTcpSessionQuietly(entry.value)
            }
        }
    }

    private fun closeTcpSessionQuietly(session: TcpNatSession) {
        session.state = TcpState.CLOSED
        runCatching { session.channel.keyFor(selector)?.cancel() }
        runCatching { session.channel.close() }
    }

    private fun closeUdpSessionQuietly(session: UdpSession) {
        runCatching { session.channel.keyFor(selector)?.cancel() }
        runCatching { session.channel.close() }
    }

    private fun safeLogW(msg: String) {
        try {
            Log.w(TAG, msg)
        } catch (_: Throwable) {
        }
    }
}
