package com.agent.use.client.network.ebpf

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Process as AndroidProcess
import android.util.Log
import com.agent.use.common.network.CaptureMode
import com.agent.use.common.network.INetworkCapture
import com.agent.use.common.network.INetworkEventListener
import com.agent.use.common.network.NetworkCaptureConfig
import com.agent.use.common.network.parser.TlsStreamParser
import java.io.BufferedReader
import java.io.DataInputStream
import java.io.EOFException
import java.io.File
import java.io.InputStream
import java.io.InputStreamReader
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/**
 * Local root-powered eBPF TLS capture engine running directly from the client app when the device is rooted.
 *
 * Launches the bundled native `libaau_ebpf.so` helper via `su` (or directly if already UID 0),
 * waits for an explicit `READY:` kernel-attach acknowledgement before reporting success, and
 * feeds captured plaintext frames (`AAUE` wire protocol) into [TlsStreamParser].
 */
class LocalRootEbpfCaptureEngine(
    private val context: Context?,
    private val binaryPathResolver: () -> File? = { context?.let { resolveDefaultBinary(it) } },
    private val uidResolver: (String) -> Int = { pkg -> context?.let { resolveTargetUid(it, pkg) } ?: -1 },
    private val processStarter: ((binaryPath: String, uid: Int) -> Process)? = null
) : INetworkCapture.Stub() {

    private var libDirResolver: (String) -> String? = { pkg -> context?.let { resolveNativeLibraryDir(it, pkg) } }
    private var processStarterWithLib: ((binaryPath: String, uid: Int, libDir: String?) -> Process)? = null

    constructor(
        context: Context?,
        binaryPathResolver: () -> File? = { context?.let { resolveDefaultBinary(it) } },
        uidResolver: (String) -> Int = { pkg -> context?.let { resolveTargetUid(it, pkg) } ?: -1 },
        libDirResolver: (String) -> String?,
        processStarter: (binaryPath: String, uid: Int, libDir: String?) -> Process
    ) : this(context, binaryPathResolver, uidResolver, null as ((String, Int) -> Process)?) {
        this.libDirResolver = libDirResolver
        this.processStarterWithLib = processStarter
    }

    companion object {
        private const val TAG = "LocalRootEbpfEngine"
        private const val BINARY_NAME = "libaau_ebpf.so"
        internal const val WIRE_MAGIC_AAUE = 0x45554141
        internal const val WIRE_HEADER_SIZE = 28
        internal const val DIRECTION_OUTBOUND_WRITE = 1
        internal const val DIRECTION_INBOUND_READ = 2
        private const val MAX_FRAME_PAYLOAD = 64 * 1024
        private const val STARTUP_TIMEOUT_MS = 5000L

        private val KNOWN_SU_PATHS = arrayOf(
            "/system/xbin/su",
            "/system/bin/su",
            "/sbin/su",
            "/su/bin/su",
            "/magisk/.core/bin/su",
            "/data/adb/ksu/bin/su",
            "/data/adb/ap/bin/su"
        )

        fun resolveDefaultBinary(context: Context): File? {
            val nativeDir = context.applicationInfo?.nativeLibraryDir
            if (!nativeDir.isNullOrBlank()) {
                val candidate = File(nativeDir, BINARY_NAME)
                if (candidate.exists() && candidate.isFile) {
                    return candidate
                }
            }
            val filesFallback = File(context.filesDir, "bin/$BINARY_NAME")
            if (filesFallback.exists() && filesFallback.isFile) {
                return filesFallback
            }
            return null
        }

        fun resolveNativeLibraryDir(context: Context, packageName: String): String? {
            if (packageName.isBlank()) return null
            return try {
                val pm = context.packageManager
                val appInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    pm.getApplicationInfo(
                        packageName,
                        PackageManager.ApplicationInfoFlags.of(PackageManager.MATCH_ALL.toLong())
                    )
                } else {
                    @Suppress("DEPRECATION")
                    pm.getApplicationInfo(packageName, 0)
                }
                appInfo.nativeLibraryDir
            } catch (_: Throwable) {
                null
            }
        }

        fun resolveTargetUid(context: Context, packageName: String): Int {
            if (packageName.isBlank()) return -1
            return try {
                val pm = context.packageManager
                val appInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    pm.getApplicationInfo(
                        packageName,
                        PackageManager.ApplicationInfoFlags.of(PackageManager.MATCH_ALL.toLong())
                    )
                } else {
                    @Suppress("DEPRECATION")
                    pm.getApplicationInfo(packageName, 0)
                }
                appInfo.uid
            } catch (_: Throwable) {
                -1
            }
        }

        fun findSuBinary(): String? {
            for (path in KNOWN_SU_PATHS) {
                if (File(path).exists()) return path
            }
            return null
        }

        @JvmOverloads
        fun startHelperProcess(binaryPath: String, uid: Int, libDir: String? = null): Process {
            val isAlreadyRoot = try {
                AndroidProcess.myUid() == 0
            } catch (_: Throwable) {
                false
            }
            val libArgs = if (!libDir.isNullOrBlank()) listOf("--lib-dir", libDir) else emptyList()
            return if (isAlreadyRoot) {
                val cmd = mutableListOf(binaryPath, "--uid", uid.toString())
                cmd.addAll(libArgs)
                ProcessBuilder(cmd).start()
            } else {
                val suPath = findSuBinary() ?: "su"
                val safePath = binaryPath.replace("\"", "")
                val extra = if (!libDir.isNullOrBlank()) " --lib-dir \"$libDir\"" else ""
                val cmd = "\"$safePath\" --uid $uid$extra"
                ProcessBuilder(suPath, "-c", cmd).start()
            }
        }
    }

    private val running = AtomicBoolean(false)
    @Volatile
    private var currentActiveMode: Int = CaptureMode.ACTIVE_MODE_NONE

    @Volatile
    var lastError: String? = null
        private set

    @Volatile
    private var activeProcess: Process? = null
    @Volatile
    private var parser: TlsStreamParser? = null
    @Volatile
    private var stderrThread: Thread? = null
    @Volatile
    private var stdoutThread: Thread? = null

    override fun startCapture(config: NetworkCaptureConfig?, listener: INetworkEventListener?): Boolean {
        if (config == null || listener == null) {
            lastError = "invalid_config_or_listener"
            return false
        }

        stopCapture()
        lastError = null

        val targetUid = if (config.targetUid > 0) config.targetUid else uidResolver(config.targetPackage)
        if (targetUid <= 0) {
            lastError = "ebpf_target_uid_not_found:${config.targetPackage}"
            notifyError(listener, lastError!!)
            return false
        }

        val binaryFile = binaryPathResolver()
        if (binaryFile == null || !binaryFile.exists()) {
            lastError = "ebpf_binary_not_found:$BINARY_NAME"
            notifyError(listener, lastError!!)
            return false
        }

        val streamParser = TlsStreamParser(config, listener)
        parser = streamParser

        val libDir = libDirResolver(config.targetPackage)
        val process = try {
            when {
                processStarterWithLib != null -> processStarterWithLib!!.invoke(binaryFile.absolutePath, targetUid, libDir)
                processStarter != null -> processStarter.invoke(binaryFile.absolutePath, targetUid)
                else -> startHelperProcess(binaryFile.absolutePath, targetUid, libDir)
            }
        } catch (t: Throwable) {
            lastError = "ebpf_process_spawn_failed:${t.message}"
            parser = null
            notifyError(listener, lastError!!)
            return false
        }
        activeProcess = process

        val readyLatch = CountDownLatch(1)
        val readyRef = AtomicBoolean(false)
        val startupErrRef = AtomicReference<String?>(null)
        val stopSignal = AtomicBoolean(false)

        val errReader = Thread({
            val errLines = mutableListOf<String>()
            try {
                BufferedReader(InputStreamReader(process.errorStream, StandardCharsets.UTF_8)).use { br ->
                    while (!stopSignal.get()) {
                        val line = br.readLine() ?: break
                        if (line.startsWith("READY:")) {
                            readyRef.set(true)
                            readyLatch.countDown()
                        } else if (line.startsWith("ERR:")) {
                            val errCode = line.removePrefix("ERR:").trim()
                            startupErrRef.compareAndSet(null, errCode)
                            readyLatch.countDown()
                        } else if (line.isNotBlank()) {
                            synchronized(errLines) {
                                if (errLines.size < 16) errLines.add(line)
                            }
                            safeLogD("native stderr: $line")
                        }
                    }
                }
            } catch (_: Throwable) {
            } finally {
                if (!readyRef.get() && startupErrRef.get() == null) {
                    val detail = synchronized(errLines) { errLines.joinToString("; ") }
                    val exitCode = runCatching { process.exitValue() }.getOrNull()
                    startupErrRef.compareAndSet(
                        null,
                        when {
                            detail.isNotBlank() -> "ebpf_helper_failed:$detail"
                            exitCode != null -> "ebpf_helper_exited:$exitCode"
                            else -> "ebpf_helper_eof"
                        }
                    )
                }
                readyLatch.countDown()
            }
        }, "aau-ebpf-stderr").apply {
            isDaemon = true
            start()
        }
        stderrThread = errReader

        val outReader = Thread({
            try {
                readWireFramesLoop(
                    input = process.inputStream,
                    expectedUid = targetUid,
                    streamParser = streamParser,
                    stopSignal = stopSignal
                )
            } catch (t: Throwable) {
                if (running.get() && !stopSignal.get()) {
                    lastError = "ebpf_stream_read_error:${t.message}"
                }
            }
        }, "aau-ebpf-stdout").apply {
            isDaemon = true
            start()
        }
        stdoutThread = outReader

        val awaited = try {
            readyLatch.await(STARTUP_TIMEOUT_MS, TimeUnit.MILLISECONDS)
        } catch (_: InterruptedException) {
            false
        }

        if (!awaited || !readyRef.get()) {
            stopSignal.set(true)
            val err = startupErrRef.get() ?: "ebpf_startup_timeout"
            lastError = err
            cleanupProcessOnly(process)
            parser = null
            currentActiveMode = CaptureMode.ACTIVE_MODE_NONE
            running.set(false)
            notifyError(listener, err)
            return false
        }

        running.set(true)
        currentActiveMode = CaptureMode.ACTIVE_MODE_EBPF
        return true
    }

    /**
     * Parses `AAUE` binary wire frames emitted by `aau_ebpf_loader` on stdout and feeds [streamParser].
     */
    internal fun readWireFramesLoop(
        input: InputStream,
        expectedUid: Int,
        streamParser: TlsStreamParser,
        stopSignal: AtomicBoolean = AtomicBoolean(false)
    ) {
        val dis = DataInputStream(input)
        val hdrBytes = ByteArray(WIRE_HEADER_SIZE)
        val hdrBuf = ByteBuffer.wrap(hdrBytes).order(ByteOrder.LITTLE_ENDIAN)

        while (!stopSignal.get()) {
            try {
                dis.readFully(hdrBytes)
            } catch (_: EOFException) {
                break
            }

            hdrBuf.clear()
            val magic = hdrBuf.getInt(0)
            if (magic != WIRE_MAGIC_AAUE) {
                throw IllegalStateException("Unexpected AAUE frame magic: 0x${Integer.toHexString(magic)}")
            }

            val pid = hdrBuf.getInt(4)
            val uid = hdrBuf.getInt(8)
            val direction = hdrBuf.getInt(12)
            val length = hdrBuf.getInt(16)
            val sslPtr = hdrBuf.getLong(20)

            if (length <= 0 || length > MAX_FRAME_PAYLOAD) {
                throw IllegalStateException("Invalid AAUE frame length: $length")
            }

            val payload = ByteArray(length)
            dis.readFully(payload)

            if (expectedUid > 0 && uid != expectedUid) {
                continue
            }

            val connId = "ebpf_${pid}_0x${java.lang.Long.toHexString(sslPtr)}"
            when (direction) {
                DIRECTION_OUTBOUND_WRITE -> streamParser.onOutboundData(connId, payload)
                DIRECTION_INBOUND_READ -> streamParser.onInboundData(connId, payload)
            }
        }
    }

    override fun stopCapture() {
        running.set(false)
        currentActiveMode = CaptureMode.ACTIVE_MODE_NONE
        cleanupProcessOnly(activeProcess)
        activeProcess = null
        stderrThread?.interrupt()
        stderrThread = null
        stdoutThread?.interrupt()
        stdoutThread = null
        parser?.clear()
        parser = null
    }

    override fun getResponseBody(requestId: String?): ByteArray? {
        if (requestId.isNullOrBlank()) return null
        return parser?.getResponseBody(requestId)
    }

    override fun getActiveMode(): Int = currentActiveMode

    private fun cleanupProcessOnly(process: Process?) {
        if (process == null) return
        try {
            process.outputStream?.close()
        } catch (_: Throwable) {
        }
        try {
            process.destroy()
            if (!process.waitFor(300, TimeUnit.MILLISECONDS)) {
                process.destroyForcibly()
            }
        } catch (_: Throwable) {
            try {
                process.destroyForcibly()
            } catch (_: Throwable) {
            }
        }
    }

    private fun notifyError(listener: INetworkEventListener, message: String) {
        try {
            listener.onErrorOccurred("ebpf_engine", message)
        } catch (_: Throwable) {
        }
    }

    private fun safeLogD(msg: String) {
        try {
            Log.d(TAG, msg)
        } catch (_: Throwable) {
        }
    }
}
