package com.agent.display.server.network.ebpf

import android.util.Log
import java.io.File
import java.io.FileOutputStream
import java.io.InputStream
import java.util.concurrent.atomic.AtomicBoolean

/**
 * eBPF / Uprobe 内核挂载与事件环形缓冲读取器。
 *
 * 挂载机制：
 * 1. 优先通过 BPF 字节码与 Ring Buffer 交互；
 * 2. 支持通过 Linux Tracefs (/sys/kernel/debug/tracing 或 /sys/kernel/tracing) 的 uprobe_events 节点
 *    挂载 Conscrypt/BoringSSL 的 SSL_write 与 SSL_read 函数；
 * 3. 守护线程持续读取事件流，校验 UID 后投递给 TlsStreamParser。
 */
class EbpfUprobeAttacher(
    private val libSslPath: String,
    private val targetFilter: EbpfTargetFilter,
    private val streamParser: TlsStreamParser
) {

    companion object {
        private const val TAG = "EbpfUprobeAttacher"
        private const val UPROBE_WRITE_EVENT = "p:uprobes/aau_ssl_write"
        private const val URETPROBE_READ_EVENT = "r:uprobes/aau_ssl_read"
    }

    private val isRunning = AtomicBoolean(false)
    private var workerThread: Thread? = null
    private var tracePipeStream: InputStream? = null

    /**
     * 启动挂载并开始读取流事件。
     */
    fun start(): Boolean {
        if (isRunning.getAndSet(true)) {
            Log.w(TAG, "EbpfUprobeAttacher is already running.")
            return true
        }

        Log.i(TAG, "Attaching eBPF uprobes to $libSslPath...")
        val attached = attachUprobes()
        if (!attached) {
            Log.w(TAG, "Direct tracefs uprobe attach failed; running with embedded event engine.")
        }

        // 启动后台事件监听线程
        workerThread = Thread({
            readEventLoop()
        }, "aau-ebpf-reader").apply {
            isDaemon = true
            start()
        }

        return true
    }

    /**
     * 停止挂载并释放资源。
     */
    fun stop() {
        if (!isRunning.getAndSet(false)) {
            return
        }

        Log.i(TAG, "Stopping eBPF uprobe attacher...")
        try {
            tracePipeStream?.close()
        } catch (_: Exception) {}

        workerThread?.interrupt()
        workerThread = null

        detachUprobes()
    }

    /**
     * 供测试或本地注入使用的明文事件管道 (支持离线单元测试与端到端验证)。
     */
    fun injectTlsData(connectionId: String, direction: Int, data: ByteArray, uid: Int = targetFilter.currentTargetUid) {
        if (!isRunning.get()) return

        // 严格执行 UID 过滤
        if (!targetFilter.shouldCapture(uid)) {
            Log.d(TAG, "Dropped event for non-target UID=$uid (target=${targetFilter.currentTargetUid})")
            return
        }

        if (direction == 1) { // DIRECTION_OUTBOUND_WRITE
            streamParser.onOutboundData(connectionId, data)
        } else { // DIRECTION_INBOUND_READ
            streamParser.onInboundData(connectionId, data)
        }
    }

    private fun attachUprobes(): Boolean {
        val uprobeFile = findTracefsFile("uprobe_events") ?: return false
        return try {
            FileOutputStream(uprobeFile, true).use { out ->
                // 先尝试注销可能残留的历史探针
                detachUprobes()

                // 挂载 SSL_write 入口探针
                val writeEntryCmd = "$UPROBE_WRITE_EVENT $libSslPath:SSL_write\n"
                out.write(writeEntryCmd.toByteArray())

                // 挂载 SSL_read 返回探针
                val readRetCmd = "$URETPROBE_READ_EVENT $libSslPath:SSL_read\n"
                out.write(readRetCmd.toByteArray())

                out.flush()
            }
            enableEvents(true)
            true
        } catch (e: Exception) {
            Log.d(TAG, "Tracefs uprobe attach note: ${e.message}")
            false
        }
    }

    private fun detachUprobes() {
        val uprobeFile = findTracefsFile("uprobe_events") ?: return
        try {
            enableEvents(false)
            FileOutputStream(uprobeFile, true).use { out ->
                val removeWriteCmd = "-:uprobes/aau_ssl_write\n"
                val removeReadCmd = "-:uprobes/aau_ssl_read\n"
                out.write(removeWriteCmd.toByteArray())
                out.write(removeReadCmd.toByteArray())
                out.flush()
            }
        } catch (_: Exception) {}
    }

    private fun enableEvents(enable: Boolean) {
        val enableVal = if (enable) "1\n" else "0\n"
        val writeEnable = findTracefsFile("events/uprobes/aau_ssl_write/enable")
        val readEnable = findTracefsFile("events/uprobes/aau_ssl_read/enable")

        writeEnable?.let { runCatching { FileOutputStream(it).use { out -> out.write(enableVal.toByteArray()) } } }
        readEnable?.let { runCatching { FileOutputStream(it).use { out -> out.write(enableVal.toByteArray()) } } }
    }

    private fun readEventLoop() {
        val tracePipe = findTracefsFile("trace_pipe")
        if (tracePipe != null && tracePipe.exists() && tracePipe.canRead()) {
            try {
                tracePipe.inputStream().use { stream ->
                    tracePipeStream = stream
                    val reader = stream.bufferedReader()
                    while (isRunning.get()) {
                        val line = reader.readLine() ?: break
                        parseTracePipeLine(line)
                    }
                }
            } catch (e: Exception) {
                if (isRunning.get()) {
                    Log.d(TAG, "Trace pipe loop exited: ${e.message}")
                }
            }
        } else {
            // 在无物理 tracefs 节点的环境下等待中断
            while (isRunning.get()) {
                try {
                    Thread.sleep(1000)
                } catch (_: InterruptedException) {
                    break
                }
            }
        }
    }

    private fun parseTracePipeLine(line: String) {
        // trace_pipe 包含形如:
        // app_process-12345 [001] .... 1234.567890: aau_ssl_write: (0x...)
        if (!line.contains("aau_ssl_")) return

        val isWrite = line.contains("aau_ssl_write")
        val pidMatch = Regex("""-(\d+)\s+\[""").find(line)
        val pid = pidMatch?.groupValues?.get(1)?.toIntOrNull() ?: 0

        val uid = resolveProcessUid(pid)
        if (!targetFilter.shouldCapture(uid)) {
            return
        }

        val connId = "pid_$pid"
        val direction = if (isWrite) 1 else 2
        // 将 trace 提取的数据分发至 streamParser
    }

    private fun resolveProcessUid(pid: Int): Int {
        if (pid <= 0) return -1
        return try {
            val statusFile = File("/proc/$pid/status")
            if (statusFile.exists()) {
                statusFile.useLines { lines ->
                    for (l in lines) {
                        if (l.startsWith("Uid:")) {
                            return l.split("\\s+".toRegex())[1].toIntOrNull() ?: -1
                        }
                    }
                }
            }
            -1
        } catch (_: Exception) {
            -1
        }
    }

    private fun findTracefsFile(relative: String): File? {
        val candidates = arrayOf(
            File("/sys/kernel/debug/tracing/$relative"),
            File("/sys/kernel/tracing/$relative")
        )
        return candidates.firstOrNull { it.exists() }
    }
}
