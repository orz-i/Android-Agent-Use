package com.agent.use.client.network

import android.content.Context
import android.os.RemoteException
import android.util.Log
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import com.agent.use.client.network.ebpf.LocalRootEbpfCaptureEngine
import com.agent.use.client.network.vpn.VpnCaptureEngine
import com.agent.use.common.IAgentShell
import com.agent.use.common.network.CaptureMode
import com.agent.use.common.network.HttpRequestEvent
import com.agent.use.common.network.HttpResponseEvent
import com.agent.use.common.network.INetworkCapture
import com.agent.use.common.network.INetworkEventListener
import com.agent.use.common.network.NetworkCaptureConfig
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withTimeout
import java.io.Closeable
import java.nio.charset.Charset
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicBoolean

/**
 * AAU (Android Agent Use) 原生 CDP 风格网络嗅探与流量捕获高阶管理器。
 *
 * 作为 Mobile AI Agent 的三大核心感知支柱（画面帧流 VirtualDisplay、语义树 a11y、网络域 CDP Network）之一，
 * 提供类似 Chrome DevTools Protocol (CDP) 的声明式、流式与异步事件拦截能力。
 *
 * 核心特性：
 * 1. 优先级与自适应降级调度 (Priority & Auto-selection)：
 *    - 在 [CaptureMode.AUTO] 模式下，优先探测宿主设备的 Root 特权与内核 eBPF 支持度；
 *    - 若具备条件则通过服务端拉起零证书、零注入的 [com.agent.use.server.network.ebpf.EbpfCaptureEngine]；
 *    - 若环境不支持或 eBPF 挂载失败，则无缝且优雅地降级至客户端局部隔离的 [VpnCaptureEngine]；
 *    - 支持显式指定 [CaptureMode.EBPF] 或 [CaptureMode.VPN_SERVICE] 强制模式。
 * 2. CDP 风格开发者高层 API：
 *    - 支持协程响应等待 `waitForResponse(urlPattern, timeoutMs)`；
 *    - 支持 Kotlin 响应式流 `requestFlow` 与 `responseFlow`；
 *    - 支持基于正则与闭包的 `onRequest`、`onResponse` 事件监听；
 *    - 提供响应体跨进程拉取 `getResponseBody(requestId)`。
 * 3. 独立与托管双模生命周期：
 *    - 可独立实例化脱机运作，亦可无缝绑定至 [com.agent.use.common.api.AAUManager]、
 *      [com.agent.use.client.DisplaySession] 及 Android [LifecycleOwner]。
 */
class AgentNetworkManager(
    val context: Context? = null,
    val shell: IAgentShell? = null,
    private val vpnEngineProvider: (() -> INetworkCapture)? = null,
    private val serverCaptureProvider: (() -> INetworkCapture?)? = null,
    private val rootChecker: (() -> Boolean)? = null,
    private val kernelChecker: (() -> Boolean)? = null,
    private val localEbpfProvider: (() -> INetworkCapture?)? = null
) : Closeable, AutoCloseable {

    companion object {
        private const val TAG = "AgentNetworkManager"
        const val DEFAULT_TIMEOUT_MS = 5000L
    }

    private val isClosed = AtomicBoolean(false)

    @Volatile
    private var activeEngine: INetworkCapture? = null

    @Volatile
    private var vpnEngine: INetworkCapture? = null

    @Volatile
    private var localEbpfEngine: INetworkCapture? = null

    @Volatile
    var lastError: String? = null
        private set

    /** 当 AUTO 模式尝试 eBPF 失败并降级到 VpnService 时，保留当次 eBPF 失败原因以供诊断。 */
    @Volatile
    var lastEbpfFallbackError: String? = null
        private set

    @Volatile
    private var activeMode: CaptureMode = CaptureMode.AUTO

    @Volatile
    private var currentConfig: NetworkCaptureConfig? = null

    @Volatile
    private var currentPackage: String? = null

    // ==========================================
    // 响应式数据流 (CDP Flow APIs)
    // ==========================================

    private val _requestFlow = MutableSharedFlow<HttpRequestEvent>(
        replay = 16,
        extraBufferCapacity = 128,
        onBufferOverflow = BufferOverflow.DROP_OLDEST
    )
    val requestFlow: SharedFlow<HttpRequestEvent> = _requestFlow.asSharedFlow()

    private val _responseFlow = MutableSharedFlow<HttpResponseEvent>(
        replay = 16,
        extraBufferCapacity = 128,
        onBufferOverflow = BufferOverflow.DROP_OLDEST
    )
    val responseFlow: SharedFlow<HttpResponseEvent> = _responseFlow.asSharedFlow()

    private val _errorFlow = MutableSharedFlow<Pair<String, String>>(
        replay = 0,
        extraBufferCapacity = 64,
        onBufferOverflow = BufferOverflow.DROP_OLDEST
    )
    val errorFlow: SharedFlow<Pair<String, String>> = _errorFlow.asSharedFlow()

    private val _chunkFlow = MutableSharedFlow<Pair<String, ByteArray>>(
        replay = 32,
        extraBufferCapacity = 256,
        onBufferOverflow = BufferOverflow.DROP_OLDEST
    )
    val chunkFlow: SharedFlow<Pair<String, ByteArray>> = _chunkFlow.asSharedFlow()

    // ==========================================
    // 回调订阅队列
    // ==========================================

    private data class RequestSubscription(
        val filter: Regex?,
        val callback: (HttpRequestEvent) -> Unit
    )

    private data class ResponseSubscription(
        val filter: Regex?,
        val callback: (HttpResponseEvent) -> Unit
    )

    private val requestSubscriptions = CopyOnWriteArrayList<RequestSubscription>()
    private val responseSubscriptions = CopyOnWriteArrayList<ResponseSubscription>()
    private val chunkSubscriptions = CopyOnWriteArrayList<(String, ByteArray) -> Unit>()
    private val errorSubscriptions = CopyOnWriteArrayList<(String, String) -> Unit>()

    // ==========================================
    // AIDL 事件桥接器
    // ==========================================

    private val internalListener = object : INetworkEventListener.Stub() {
        override fun onRequestWillBeSent(request: HttpRequestEvent) {
            _requestFlow.tryEmit(request)
            for (sub in requestSubscriptions) {
                if (sub.filter == null || sub.filter.containsMatchIn(request.url)) {
                    runCatching { sub.callback(request) }.onFailure {
                        Log.e(TAG, "Error in onRequest callback for ${request.url}", it)
                    }
                }
            }
        }

        override fun onResponseReceived(response: HttpResponseEvent) {
            _responseFlow.tryEmit(response)
            for (sub in responseSubscriptions) {
                if (sub.filter == null || sub.filter.containsMatchIn(response.url)) {
                    runCatching { sub.callback(response) }.onFailure {
                        Log.e(TAG, "Error in onResponse callback for ${response.url}", it)
                    }
                }
            }
        }

        override fun onDataChunkReceived(requestId: String, chunk: ByteArray) {
            _chunkFlow.tryEmit(requestId to chunk)
            for (sub in chunkSubscriptions) {
                runCatching { sub(requestId, chunk) }.onFailure {
                    Log.e(TAG, "Error in onDataChunk callback for $requestId", it)
                }
            }
        }

        override fun onErrorOccurred(requestId: String, errorMsg: String) {
            Log.w(TAG, "Capture error occurred: requestId=$requestId, msg=$errorMsg")
            lastError = errorMsg
            _errorFlow.tryEmit(requestId to errorMsg)
            for (sub in errorSubscriptions) {
                runCatching { sub(requestId, errorMsg) }.onFailure {
                    Log.e(TAG, "Error in onError callback for $requestId", it)
                }
            }
        }
    }

    // ==========================================
    // 抓包生命周期与引擎调度 (Requirement 1)
    // ==========================================

    /**
     * 开启针对目标应用的网络抓包。
     *
     * @param targetPackage 目标应用包名 (必须精确过滤以保障隔离)
     * @param mode 抓包模式：[CaptureMode.AUTO] (优先 eBPF 失败回退 VPN), [CaptureMode.EBPF], [CaptureMode.VPN_SERVICE]
     * @return 抓包是否成功启动
     */
    @Synchronized
    fun enable(targetPackage: String, mode: CaptureMode = CaptureMode.AUTO): Boolean {
        val config = NetworkCaptureConfig(
            targetPackage = targetPackage,
            mode = mode
        )
        return enable(config)
    }

    /**
     * 完整配置启动网络抓包。
     *
     * @param config 抓包配置契约
     * @return 启动是否成功
     */
    @Synchronized
    fun enable(config: NetworkCaptureConfig): Boolean {
        if (isClosed.get()) {
            Log.e(TAG, "Cannot enable: AgentNetworkManager has already been closed")
            return false
        }

        if (isCapturing) {
            disable()
        }

        val targetPkg = config.targetPackage.trim()
        if (targetPkg.isEmpty()) {
            Log.e(TAG, "Cannot enable network capture: targetPackage is empty")
            lastError = "targetPackage cannot be empty"
            return false
        }

        this.lastError = null
        this.lastEbpfFallbackError = null
        this.currentPackage = targetPkg

        return when (config.mode) {
            CaptureMode.EBPF -> {
                Log.i(TAG, "Explicit CaptureMode.EBPF requested for $targetPkg")
                activateEbpf(config)
            }
            CaptureMode.VPN_SERVICE -> {
                Log.i(TAG, "Explicit CaptureMode.VPN_SERVICE requested for $targetPkg")
                activateVpn(config)
            }
            CaptureMode.AUTO -> {
                Log.i(TAG, "CaptureMode.AUTO requested for $targetPkg: checking eBPF capabilities...")
                val ebpfSupported = isEbpfSupported()
                if (ebpfSupported) {
                    val ebpfStarted = activateEbpf(config)
                    if (ebpfStarted) {
                        Log.i(TAG, "Successfully activated eBPF capture engine for $targetPkg")
                        return true
                    }
                    Log.w(TAG, "eBPF activation failed in AUTO mode ($lastError). Falling back gracefully to VpnCaptureEngine...")
                    lastEbpfFallbackError = lastError
                } else {
                    Log.i(TAG, "Device does not satisfy eBPF requirements. Falling back gracefully to VpnCaptureEngine...")
                }

                val vpnStarted = activateVpn(config)
                if (vpnStarted) {
                    Log.i(TAG, "Successfully activated VpnCaptureEngine fallback for $targetPkg")
                } else {
                    Log.e(TAG, "Failed to start both eBPF and VpnCaptureEngine for $targetPkg")
                }
                vpnStarted
            }
        }
    }

    /**
     * 停止当前抓包并释放底层引擎资源。
     */
    @Synchronized
    fun disable() {
        val engine = activeEngine
        if (engine != null) {
            try {
                engine.stopCapture()
            } catch (e: Exception) {
                Log.w(TAG, "Exception while stopping active capture engine: ${e.message}")
            }
        }
        activeEngine = null
        activeMode = CaptureMode.AUTO
        currentConfig = null
        currentPackage = null
        Log.i(TAG, "AgentNetworkManager disabled successfully")
    }

    /**
     * 检查当前环境是否满足使用 eBPF 的条件 (Root 权限且内核 >= 5.4)。
     */
    fun isEbpfSupported(): Boolean {
        val rootOk = rootChecker?.invoke() ?: DeviceEbpfDetector.isDeviceRooted(shell)
        val kernelOk = kernelChecker?.invoke() ?: DeviceEbpfDetector.isKernelSupported()
        Log.d(TAG, "isEbpfSupported: rootOk=$rootOk, kernelOk=$kernelOk")
        return rootOk && kernelOk
    }

    private fun activateEbpf(config: NetworkCaptureConfig): Boolean {
        val candidates = ArrayList<INetworkCapture>(3)
        fun addCandidate(candidate: INetworkCapture?) {
            if (candidate != null && candidates.none { it === candidate }) {
                candidates.add(candidate)
            }
        }

        try {
            addCandidate(serverCaptureProvider?.invoke())
            addCandidate(shell?.networkCapture)
            addCandidate(localEbpfProvider?.invoke())
            if (localEbpfProvider == null) {
                context?.let { ctx ->
                    val local = localEbpfEngine ?: LocalRootEbpfCaptureEngine(ctx).also { localEbpfEngine = it }
                    addCandidate(local)
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to obtain eBPF capture engine: ${e.message}", e)
            lastError = "ebpf_engine_error:${e.message}"
            return false
        }

        if (candidates.isEmpty()) {
            Log.w(TAG, "EbpfCaptureEngine unavailable (no shell binder and no local root helper)")
            if (lastError == null) lastError = "ebpf_engine_unavailable"
            return false
        }

        for (engine in candidates) {
            val started = try {
                val success = engine.startCapture(config, internalListener)
                if (success) {
                    activeEngine = engine
                    activeMode = CaptureMode.EBPF
                    currentConfig = config
                    lastError = null
                    lastEbpfFallbackError = null
                    return true
                }
                val engineErr = (engine as? LocalRootEbpfCaptureEngine)?.lastError
                if (!engineErr.isNullOrBlank()) {
                    lastError = engineErr
                } else if (lastError == null) {
                    lastError = "ebpf_start_failed"
                }
                Log.w(TAG, "EbpfCaptureEngine candidate ${engine.javaClass.simpleName} failed ($lastError)")
                false
            } catch (e: RemoteException) {
                Log.e(TAG, "RemoteException calling EbpfCaptureEngine.startCapture: ${e.message}", e)
                lastError = "ebpf_remote_exception:${e.message}"
                false
            } catch (e: Exception) {
                Log.e(TAG, "Exception calling EbpfCaptureEngine.startCapture: ${e.message}", e)
                lastError = "ebpf_exception:${e.message}"
                false
            }
            if (started) return true
        }
        return false
    }

    private fun activateVpn(config: NetworkCaptureConfig): Boolean {
        val vpn = vpnEngine ?: try {
            vpnEngineProvider?.invoke() ?: VpnCaptureEngine(context).also { vpnEngine = it }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to instantiate VpnCaptureEngine: ${e.message}", e)
            lastError = "vpn_init_failed:${e.message}"
            return false
        }

        return try {
            val success = vpn.startCapture(config, internalListener)
            if (success) {
                activeEngine = vpn
                activeMode = CaptureMode.VPN_SERVICE
                currentConfig = config
                lastError = null
                true
            } else {
                val vpnErr = (vpn as? VpnCaptureEngine)?.lastError
                if (!vpnErr.isNullOrBlank()) {
                    lastError = vpnErr
                } else if (lastError == null) {
                    lastError = "vpn_start_failed"
                }
                Log.w(TAG, "VpnCaptureEngine.startCapture returned false ($lastError)")
                false
            }
        } catch (e: Exception) {
            Log.e(TAG, "Exception calling VpnCaptureEngine.startCapture: ${e.message}", e)
            lastError = "vpn_exception:${e.message}"
            false
        }
    }

    // ==========================================
    // 高级 CDP 风格事件监听与响应等待 (Requirement 2)
    // ==========================================

    /**
     * 注册 HTTP 请求即将发送的监听回调。
     *
     * @param filter 可选的 URL 匹配正则表达式，为 null 时监听全部请求
     * @param callback 触发时的回调闭包
     * @return 用于快速注销该回调的 [AutoCloseable] 句柄
     */
    fun onRequest(filter: Regex? = null, callback: (HttpRequestEvent) -> Unit): AutoCloseable {
        val sub = RequestSubscription(filter, callback)
        requestSubscriptions.add(sub)
        return AutoCloseable { requestSubscriptions.remove(sub) }
    }

    /**
     * 注销指定请求监听回调。
     */
    fun removeRequestListener(callback: (HttpRequestEvent) -> Unit) {
        requestSubscriptions.removeAll { it.callback == callback }
    }

    /**
     * 注册 HTTP 响应已接收的监听回调。
     *
     * @param filter 可选的 URL 匹配正则表达式，为 null 时监听全部响应
     * @param callback 触发时的回调闭包
     * @return 用于快速注销该回调的 [AutoCloseable] 句柄
     */
    fun onResponse(filter: Regex? = null, callback: (HttpResponseEvent) -> Unit): AutoCloseable {
        val sub = ResponseSubscription(filter, callback)
        responseSubscriptions.add(sub)
        return AutoCloseable { responseSubscriptions.remove(sub) }
    }

    /**
     * 注销指定响应监听回调。
     */
    fun removeResponseListener(callback: (HttpResponseEvent) -> Unit) {
        responseSubscriptions.removeAll { it.callback == callback }
    }

    /**
     * 同步注册响应体分片到达监听，避免早期分片因异步 Flow 调度延迟而丢失。
     */
    fun onDataChunk(callback: (String, ByteArray) -> Unit): AutoCloseable {
        chunkSubscriptions.add(callback)
        return AutoCloseable { chunkSubscriptions.remove(callback) }
    }

    /**
     * 同步注册抓包/请求错误监听。
     */
    fun onError(callback: (String, String) -> Unit): AutoCloseable {
        errorSubscriptions.add(callback)
        return AutoCloseable { errorSubscriptions.remove(callback) }
    }

    /**
     * 挂起协程直到指定 URL 模式的响应到达或超时（类似 CDP Network.responseReceived）。
     *
     * @param urlPattern URL 匹配字符串或正则表达式
     * @param timeoutMs 超时时间（毫秒，默认 5000ms）
     * @return 匹配的响应事件 [HttpResponseEvent]
     * @throws kotlinx.coroutines.TimeoutCancellationException 超时未到达时抛出
     */
    suspend fun waitForResponse(urlPattern: String, timeoutMs: Long = DEFAULT_TIMEOUT_MS): HttpResponseEvent {
        val callTime = System.currentTimeMillis() - 200L // 容许 200ms 竞态时间窗口
        val regex = runCatching { Regex(urlPattern) }.getOrNull()

        return withTimeout(timeoutMs) {
            responseFlow.first { response ->
                if (response.timestamp < callTime) {
                    false
                } else if (regex != null && runCatching { regex.containsMatchIn(response.url) }.getOrDefault(false)) {
                    true
                } else {
                    response.url.contains(urlPattern)
                }
            }
        }
    }

    /**
     * 挂起协程直到正则匹配的响应到达或超时。
     */
    suspend fun waitForResponse(filter: Regex, timeoutMs: Long = DEFAULT_TIMEOUT_MS): HttpResponseEvent {
        val callTime = System.currentTimeMillis() - 200L
        return withTimeout(timeoutMs) {
            responseFlow.first { response ->
                response.timestamp >= callTime && filter.containsMatchIn(response.url)
            }
        }
    }

    /**
     * 挂起协程直到满足特定自定义条件的响应到达或超时。
     */
    suspend fun waitForResponse(
        timeoutMs: Long = DEFAULT_TIMEOUT_MS,
        predicate: (HttpResponseEvent) -> Boolean
    ): HttpResponseEvent {
        val callTime = System.currentTimeMillis() - 200L
        return withTimeout(timeoutMs) {
            responseFlow.first { response ->
                response.timestamp >= callTime && predicate(response)
            }
        }
    }

    /**
     * 获取指定请求关联的完整 HTTP 响应体数据（对应 CDP Network.getResponseBody）。
     *
     * @param requestId 请求全局唯一追踪 ID
     * @return 响应体字节数组，若尚未接收完毕或已超出缓存限制则返回 null
     */
    fun getResponseBody(requestId: String): ByteArray? {
        val engine = activeEngine ?: return null
        return try {
            engine.getResponseBody(requestId)
        } catch (e: Exception) {
            Log.e(TAG, "getResponseBody failed for $requestId: ${e.message}", e)
            null
        }
    }

    /**
     * 获取指定请求关联的 HTTP 响应体文本内容。
     */
    fun getResponseBodyAsString(requestId: String, charset: Charset = Charsets.UTF_8): String? {
        return getResponseBody(requestId)?.toString(charset)
    }

    // ==========================================
    // 状态查询与扩展属性
    // ==========================================

    /**
     * 当前是否正在进行网络抓包。
     */
    val isCapturing: Boolean
        get() = activeEngine != null

    /**
     * 获取当前底层实际生效的捕获模式。
     */
    fun getActiveMode(): CaptureMode =
        when (activeEngine?.getActiveMode()) {
            CaptureMode.ACTIVE_MODE_EBPF -> CaptureMode.EBPF
            CaptureMode.ACTIVE_MODE_VPN_SERVICE -> CaptureMode.VPN_SERVICE
            else -> CaptureMode.AUTO
        }

    /**
     * 当前抓包的目标包名。
     */
    val targetPackage: String?
        get() = currentPackage

    /**
     * 当前活跃的抓包配置契约。
     */
    val configuration: NetworkCaptureConfig?
        get() = currentConfig

    // ==========================================
    // 宿主与生命周期集成 (Requirement 3)
    // ==========================================

    /**
     * 绑定至 Android [LifecycleOwner] (Activity / Service / ViewModel)，
     * 在宿主声明周期进入 onDestroy 时自动注销并停止抓包。
     */
    fun bindToLifecycle(lifecycleOwner: LifecycleOwner) {
        lifecycleOwner.lifecycle.addObserver(object : DefaultLifecycleObserver {
            override fun onDestroy(owner: LifecycleOwner) {
                Log.d(TAG, "Host LifecycleOwner destroyed, automatically disabling AgentNetworkManager...")
                this@AgentNetworkManager.close()
            }
        })
    }

    override fun close() {
        if (isClosed.compareAndSet(false, true)) {
            Log.i(TAG, "Closing AgentNetworkManager...")
            disable()
            requestSubscriptions.clear()
            responseSubscriptions.clear()
            chunkSubscriptions.clear()
            errorSubscriptions.clear()
        }
    }
}
