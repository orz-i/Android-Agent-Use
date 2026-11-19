package com.agent.use.common.capture

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.os.Build
import android.os.Process
import android.os.SystemClock
import android.util.Log
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.concurrent.TimeUnit

/**
 * 特权截屏引擎：以 Shell (UID 2000) 或 Root 身份直接调用系统 `screencap`。
 *
 * 为什么不用 `MediaProjection`：
 * 它每次都要用户点一次「开始录制/共享屏幕」的系统弹窗，无法作为 Agent 的后台能力；
 * 而 AAU 的服务端本来就跑在 Shell UID 下，`screencap` 对它是免授权的，
 * 于是「抓主屏、抓任意 display、抓一帧就退」全部变成一次进程调用。
 *
 * 为什么不用 `AccessibilityService.takeScreenshot`：
 * 它有 1 秒系统冷却、拿不到安全图层、且要求用户手动开无障碍。它在这里只作为兜底通道。
 *
 * 设计约束：
 * - 只依赖 `ProcessBuilder` 与 `BitmapFactory`，不持有 Context，因此能在 app_process 里跑；
 * - 所有探测结果缓存，避免每次截图都 fork 一次 `su`；
 * - 抓到的 PNG 会做一次「纯黑可疑帧」判定，把 FLAG_SECURE 的黑屏显式暴露给上层，
 *   而不是让调用方拿到一张看似成功的黑图。
 */
class ShellScreencap(
    private val myUid: Int = Process.myUid(),
    private val tag: String = "ShellScreencap",
) {

    @Volatile
    private var cachedCapability: ScreenCaptureCapability? = null

    @Volatile
    private var cachedCapabilityAt: Long = 0L

    @Volatile
    private var cachedRoot: Boolean? = null

    @Volatile
    private var lastFailure: String? = null

    @Volatile
    private var lastModeUsed: ScreenCaptureMode? = null

    @Volatile
    private var cachedPhysicalIds: Map<Int, Long>? = null

    @Volatile
    private var cachedPhysicalIdsAt: Long = 0L

    /** Android 17 的 secure 内容直取通道；不可用时内部会自行短路，不做无谓分配。 */
    private val secureCapture = SecureCapture("$tag-Secure")

    /** 最近一次成功抓帧所用通道，便于端上区分 Shell 与 Root。 */
    val lastMode: ScreenCaptureMode? get() = lastModeUsed

    /** 最近一次失败原因，便于服务端日志与端上诊断。 */
    val failure: String? get() = lastFailure

    // ==========================================
    // 抓帧
    // ==========================================

    /**
     * 抓取指定屏幕的一帧 PNG。
     *
     * @param displayId 目标屏幕的**逻辑** display id，0 为主屏。
     *   注意这里用的是 DisplayManager 那套小整数 id；内部会换算成 `screencap -d`
     *   需要的物理屏 id。虚拟屏没有物理 id，无法通过本方法抓取。
     * @param timeoutMs 单次进程超时
     * @param privilege [ScreenCapturePrivilege] 策略
     * @param allowSecure `screencap` 抓到纯黑帧时，是否允许升级到
     *   [ScreenCaptureMode.SECURE_PRIVILEGED] 重抓。FLAG_SECURE 页面只有这条通道能出内容；
     *   普通页面不会触发，因此不产生额外开销。
     * @return PNG 字节；失败或命中安全图层黑屏且无法升级时返回 null，原因见 [failure]
     */
    fun capturePng(
        displayId: Int,
        timeoutMs: Long = DEFAULT_TIMEOUT_MS,
        privilege: Int = ScreenCapturePrivilege.AUTO,
        allowSecure: Boolean = true,
    ): ByteArray? {
        lastFailure = null

        // 显式只走 secure 通道：用于验证「策略是否真的生效」，也方便上层按需强制
        if (privilege == ScreenCapturePrivilege.SECURE_ONLY) {
            captureSecure(displayId, timeoutMs)?.let {
                lastModeUsed = ScreenCaptureMode.SECURE_PRIVILEGED
                return it
            }
            lastFailure = lastFailure
                ?: secureCapture.unavailableReason
                ?: "secure 通道抓帧失败或画面仍为纯黑"
            Log.w(tag, "capture display=$displayId 失败：$lastFailure")
            return null
        }

        // Shell 通道是常态；只有它失败时才会去碰 su，避免为了「可能用不上」的 Root 探测多等一次
        val primary = if (privilege == ScreenCapturePrivilege.ROOT_ONLY) {
            ScreenCaptureMode.ROOT_PRIVILEGED
        } else {
            ScreenCaptureMode.SHELL_PRIVILEGED
        }

        var blankReason: String? = null

        when (val outcome = attempt(displayId, timeoutMs, primary)) {
            is Attempt.Ok -> {
                lastModeUsed = primary
                lastFailure = null
                return outcome.bytes
            }
            is Attempt.Blank -> blankReason = outcome.reason
            is Attempt.Failed -> lastFailure = outcome.reason
        }

        // 纯黑优先升级 secure 通道，而不是先回退 Root —— `su` 跑的也是同一份 screencap，
        // secure 语义在 SurfaceFlinger 层，提权不改变结果。
        if (blankReason != null && allowSecure) {
            Log.i(tag, "display=$displayId 抓到纯黑帧，尝试 secure 通道")
            captureSecure(displayId, timeoutMs)?.let {
                lastModeUsed = ScreenCaptureMode.SECURE_PRIVILEGED
                lastFailure = null
                return it
            }
        }

        // 真正的执行失败（不是黑帧）才值得换身份重试
        if (blankReason == null &&
            privilege == ScreenCapturePrivilege.AUTO &&
            primary == ScreenCaptureMode.SHELL_PRIVILEGED &&
            rootAvailable()
        ) {
            Log.w(tag, "capture display=$displayId 回退 Root 通道")
            when (val outcome = attempt(displayId, timeoutMs, ScreenCaptureMode.ROOT_PRIVILEGED)) {
                is Attempt.Ok -> {
                    lastModeUsed = ScreenCaptureMode.ROOT_PRIVILEGED
                    lastFailure = null
                    return outcome.bytes
                }
                is Attempt.Blank -> {
                    blankReason = outcome.reason
                    if (allowSecure) {
                        captureSecure(displayId, timeoutMs)?.let {
                            lastModeUsed = ScreenCaptureMode.SECURE_PRIVILEGED
                            lastFailure = null
                            return it
                        }
                    }
                }
                is Attempt.Failed -> lastFailure = outcome.reason
            }
        }

        lastFailure = blankReason ?: lastFailure ?: "没有可用的截屏通道"
        Log.w(tag, "capture display=$displayId 失败：$lastFailure")
        return null
    }

    /**
     * 单通道尝试的三态结果。
     *
     * 必须把「抓到纯黑」和「根本没抓到」分开：前者说明页面可能声明了 FLAG_SECURE，
     * 值得升级到 [ScreenCaptureMode.SECURE_PRIVILEGED]；后者只值得换个身份重试。
     * 早期版本把两者都折成 null，导致 secure 升级永远没有触发条件。
     */
    private sealed class Attempt {
        class Ok(val bytes: ByteArray) : Attempt()
        class Blank(val reason: String) : Attempt()
        class Failed(val reason: String) : Attempt()
    }

    private fun attempt(displayId: Int, timeoutMs: Long, mode: ScreenCaptureMode): Attempt {
        val bytes = captureOnce(displayId, timeoutMs, mode)
            ?: return Attempt.Failed(lastFailure ?: "screencap 在 ${mode.label} 通道失败")
        if (isBlankFrame(bytes)) {
            return Attempt.Blank("画面为纯黑（页面可能设置了 FLAG_SECURE）")
        }
        return Attempt.Ok(bytes)
    }

    /**
     * 经 [SecureCapture] 抓一帧并编码成 PNG。
     *
     * 抓到纯黑同样判失败：真正的 DRM 保护内容即便走 CAPTURE 策略也拿不到明文，
     * 把黑图当成功返回只会让上层以为拿到了有效信息。
     */
    private fun captureSecure(displayId: Int, timeoutMs: Long): ByteArray? {
        if (!secureCapture.isSupported()) {
            lastFailure = secureCapture.unavailableReason ?: "secure 通道不可用"
            return null
        }
        val bitmap = secureCapture.capture(
            displayId = displayId,
            timeoutMs = timeoutMs.coerceAtLeast(SECURE_MIN_TIMEOUT_MS),
        ) ?: return null
        return try {
            val bytes = ByteArrayOutputStream().use { out ->
                bitmap.compress(Bitmap.CompressFormat.PNG, 100, out)
                out.toByteArray()
            }
            if (isBlankFrame(bytes)) {
                Log.w(tag, "secure 通道抓到纯黑，内容可能是 DRM 保护")
                null
            } else {
                bytes
            }
        } catch (t: Throwable) {
            Log.w(tag, "secure 通道编码失败", t)
            null
        } finally {
            bitmap.recycle()
        }
    }

    private fun captureOnce(displayId: Int, timeoutMs: Long, mode: ScreenCaptureMode): ByteArray? {
        val path = resolveScreencapPath() ?: return null
        val args = buildScreencapArgs(path, displayId) ?: run {
            lastFailure = if (displayId == MAIN_DISPLAY) {
                "screencap 路径不可用"
            } else {
                "display $displayId 不是物理屏（虚拟屏没有 PhysicalDisplayId），" +
                    "请改用 ImageReader / SurfaceControl 通道"
            }
            return null
        }
        val result = when (mode) {
            ScreenCaptureMode.ROOT_PRIVILEGED -> {
                val su = resolveSuPath() ?: return null
                // su -c 只能接一整条命令字符串
                runProcess(arrayOf(su, "-c", args.joinToString(" ")), timeoutMs)
            }
            else -> runProcess(args.toTypedArray(), timeoutMs)
        }
        if (result.timedOut || result.exitCode != 0) return null
        val bytes = result.stdout
        return bytes.takeIf { isPng(it) }
    }

    /**
     * 组装 `screencap` 参数；无法确定物理屏时返回 null（调用方应当据此失败，
     * **不能**退化为「不传 -d」，否则会把主屏画面当成目标屏静默返回）。
     */
    private fun buildScreencapArgs(path: String, displayId: Int): List<String>? {
        val args = mutableListOf(path, "-p")
        // 主屏不传 -d：screencap 不给 -d 时默认抓默认物理屏，这是跨版本最稳的路径。
        // 传 "-d 0" 在新版系统上会被判为无效 display（见 physicalDisplayId 的注释）。
        if (displayId == MAIN_DISPLAY) return args
        val physical = physicalDisplayId(displayId) ?: return null
        args += listOf("-d", physical.toString())
        return args
    }

    /**
     * 把逻辑 display id 换算成 `screencap -d` 需要的 **PhysicalDisplayId**。
     *
     * 实测（PLK110 / Android 17）：`screencap -p -d 0` 直接报
     * `Display Id '0' is not valid`，因为新版 `screencap` 的 `-d` 参数读的是
     * SurfaceFlinger 的 64 位物理屏 id（如 `4630946903293830803`），而
     * `DisplayManager` 用的是小整数逻辑 id。两者不是同一套命名空间。
     *
     * 用法提示里也写得很直白：`see "dumpsys SurfaceFlinger --display-id" for valid display IDs`。
     * 所以这里解析那份输出，按 HWC 序号建立「逻辑 id → 物理 id」映射。
     *
     * 顺带一个重要边界：虚拟屏**不在**这份列表里（它没有物理端口），
     * 因此 `screencap` 抓不到虚拟屏——虚拟屏必须继续走 ImageReader 或 SurfaceControl。
     *
     * @return 物理 display id；无法确定时返回 null（调用方应退化为「不传 -d」）
     */
    fun physicalDisplayId(displayId: Int): Long? {
        val cached = cachedPhysicalIds
        if (cached != null && SystemClock.uptimeMillis() - cachedPhysicalIdsAt < CAPABILITY_TTL_MS) {
            return cached[displayId]
        }
        val resolved = resolvePhysicalDisplayIds()
        cachedPhysicalIds = resolved
        cachedPhysicalIdsAt = SystemClock.uptimeMillis()
        return resolved[displayId]
    }

    private fun resolvePhysicalDisplayIds(): Map<Int, Long> {
        val result = runProcess(
            arrayOf("dumpsys", "SurfaceFlinger", "--display-id"),
            PROBE_TIMEOUT_MS,
            mergeStderr = true,
        )
        if (result.exitCode != 0) return emptyMap()
        val text = result.stdout.toString(Charsets.UTF_8)
        val map = HashMap<Int, Long>(4)
        for (line in text.lineSequence()) {
            // Display 4630946903293830803 (HWC display 0): port=147 ...
            val match = PHYSICAL_DISPLAY_PATTERN.find(line) ?: continue
            val physical = match.groupValues[1].toLongOrNull() ?: continue
            val logical = match.groupValues[2].toIntOrNull() ?: continue
            map[logical] = physical
        }
        return map
    }

    // ==========================================
    // 能力探测
    // ==========================================

    /**
     * 探测本机截屏能力；结果默认缓存，[forceRefresh] 为 true 时重新探测。
     *
     * 探测会真实抓一帧（约 100~400ms），因此不要在每帧循环里调用。
     */
    fun capability(forceRefresh: Boolean = false): ScreenCaptureCapability {
        val fresh = cachedCapability?.let {
            SystemClock.uptimeMillis() - cachedCapabilityAt < CAPABILITY_TTL_MS
        } == true
        if (fresh && !forceRefresh) cachedCapability?.let { return it }
        val startedAt = SystemClock.uptimeMillis()
        val path = resolveScreencapPath()
        val help = path?.let { runProcess(arrayOf(it, "-h"), PROBE_TIMEOUT_MS, mergeStderr = true) }
        val helpText = help?.stdout?.toString(Charsets.UTF_8).orEmpty()
        val supportsDisplayArg = helpText.contains("-d") || Build.VERSION.SDK_INT >= Build.VERSION_CODES.N
        val supportsSwipe = probeDisplaySwipe()
        val available = path != null && captureOnce(0, PROBE_TIMEOUT_MS, ScreenCaptureMode.SHELL_PRIVILEGED) != null
        val capability = ScreenCaptureCapability(
            uid = myUid,
            screencapPath = path,
            screencapAvailable = available,
            rootAvailable = rootAvailable(),
            supportsDisplayArg = supportsDisplayArg,
            supportsDisplaySwipe = supportsSwipe,
            secureCaptureAvailable = secureCapture.isSupported(),
            detectMs = SystemClock.uptimeMillis() - startedAt,
            note = if (available) null else "screencap 不可用或主屏抓帧失败",
        )
        cachedCapability = capability
        cachedCapabilityAt = SystemClock.uptimeMillis()
        Log.i(tag, "capability ${capability.summary}")
        return capability
    }

    /** 本机是否可用 `su` 提权到 UID 0；首次调用后缓存。 */
    fun rootAvailable(): Boolean {
        cachedRoot?.let { return it }
        val su = resolveSuPath()
        val available = if (su == null) {
            myUid == 0
        } else {
            val result = runProcess(arrayOf(su, "-c", "id -u"), PROBE_TIMEOUT_MS, mergeStderr = true)
            result.exitCode == 0 && result.stdout.toString(Charsets.UTF_8).trim().startsWith("0")
        }
        cachedRoot = available
        return available
    }

    private fun probeDisplaySwipe(): Boolean {
        val inputPath = listOf("/system/bin/input", "/system/xbin/input").firstOrNull { File(it).exists() }
            ?: return false
        val help = runProcess(arrayOf(inputPath), PROBE_TIMEOUT_MS, mergeStderr = true)
        return help.stdout.toString(Charsets.UTF_8).contains("-d")
    }

    fun resolveScreencapPath(): String? {
        KNOWN_SCREENCAP_PATHS.firstOrNull { File(it).let { f -> f.exists() && f.canExecute() } }?.let { return it }
        val which = runProcess(arrayOf("which", "screencap"), PROBE_TIMEOUT_MS, mergeStderr = true)
        return which.stdout.toString(Charsets.UTF_8).trim().takeIf { it.startsWith("/") && File(it).exists() }
    }

    private fun resolveSuPath(): String? =
        KNOWN_SU_PATHS.firstOrNull { File(it).let { f -> f.exists() && f.canExecute() } }

    // ==========================================
    // 滚动注入（长截图用）
    // ==========================================

    /**
     * 通过 `input -d <displayId> swipe` 注入一次向上滚动。
     *
     * 用 `input` 而不是引擎内的 `injectStroke`，是因为后者出于防误触只允许操作自有虚拟屏，
     * 而长截图同样需要对主屏生效；`input` 以 Shell 身份执行，两个场景都覆盖。
     *
     * 注意这里传的是**逻辑** display id（`input` 的 `-d` 语义），与 `screencap -d`
     * 需要的物理屏 id 不是一回事，不要互相代入。
     */
    fun scroll(displayId: Int, fromX: Int, fromY: Int, toX: Int, toY: Int, durationMs: Long): Boolean {
        val inputPath = listOf("/system/bin/input", "/system/xbin/input").firstOrNull { File(it).exists() }
            ?: return false
        val args = mutableListOf(inputPath)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            args += listOf("-d", displayId.toString())
        }
        args += listOf(
            "swipe",
            fromX.toString(), fromY.toString(),
            toX.toString(), toY.toString(),
            durationMs.coerceIn(50L, 2_000L).toString(),
        )
        val result = runProcess(args.toTypedArray(), SWIPE_TIMEOUT_MS)
        return result.exitCode == 0 && !result.timedOut
    }

    // ==========================================
    // 长截图
    // ==========================================

    /**
     * 执行一次滚动拼接长截图。
     *
     * @return 位图级结果；调用方负责 recycle 返回的 bitmap
     */
    fun captureLong(
        displayId: Int,
        options: LongScreenshotOptions = LongScreenshotOptions(),
        onProgress: ((LongScreenshotProgress) -> Unit)? = null,
        isCancelled: () -> Boolean = { false },
    ): LongScreenshotOutput {
        val opts = options.clamped()
        val source = ShellFrameSource(displayId, opts)
        return try {
            LongScreenshotRunner.run(source, opts, onProgress, isCancelled)
        } finally {
            source.close()
        }
    }

    private inner class ShellFrameSource(
        private val displayId: Int,
        private val options: LongScreenshotOptions,
    ) : ScreenFrameSource {

        /**
         * 一旦某一帧确认要走 secure 通道，后续帧直接沿用。
         *
         * 长截图动辄拼十几帧，如果每帧都先跑一次 `screencap` 再判定纯黑，
         * 光在「抓一张注定要丢掉的黑图」上就要多花 3~5 秒。
         */
        private var secureSticky = false

        override fun capture(): Bitmap? {
            val privilege = if (secureSticky) {
                ScreenCapturePrivilege.SECURE_ONLY
            } else {
                options.privilege
            }
            val bytes = capturePng(displayId, CAPTURE_TIMEOUT_MS, privilege) ?: return null
            if (lastMode == ScreenCaptureMode.SECURE_PRIVILEGED && !secureSticky) {
                secureSticky = true
                Log.i(tag, "长截图后续帧改走 secure 通道")
            }
            return runCatching { BitmapFactory.decodeByteArray(bytes, 0, bytes.size) }.getOrNull()
        }

        override fun scroll(frameWidth: Int, frameHeight: Int): Boolean {
            val x = frameWidth / 2
            val fromY = (frameHeight * options.scrollFromRatio).toInt()
            val toY = (frameHeight * options.scrollToRatio).toInt()
            return scroll(displayId, x, fromY, x, toY, options.scrollDurationMs)
        }

        override fun sleep(ms: Long) {
            if (ms > 0) SystemClock.sleep(ms)
        }
    }

    // ==========================================
    // 进程与图像工具
    // ==========================================

    private data class ExecResult(
        val exitCode: Int,
        val stdout: ByteArray,
        val timedOut: Boolean,
    )

    private fun runProcess(
        argv: Array<String>,
        timeoutMs: Long,
        mergeStderr: Boolean = false,
    ): ExecResult {
        val process = try {
            ProcessBuilder(*argv).redirectErrorStream(mergeStderr).start()
        } catch (t: Throwable) {
            Log.w(tag, "spawn ${argv.firstOrNull()} failed: ${t.message}")
            return ExecResult(-1, ByteArray(0), timedOut = false)
        }
        val collected = ByteArrayOutputStream()
        val reader = Thread {
            runCatching {
                process.inputStream.use { input ->
                    val buffer = ByteArray(16 * 1024)
                    while (true) {
                        val read = input.read(buffer)
                        if (read < 0) break
                        if (collected.size() < MAX_CAPTURE_BYTES) {
                            collected.write(buffer, 0, minOf(read, MAX_CAPTURE_BYTES - collected.size()))
                        }
                    }
                }
            }
        }.apply {
            isDaemon = true
            start()
        }
        // stderr 不合并时必须持续排空，否则子进程可能因管道写满而挂死
        val drain = if (mergeStderr) null else Thread {
            runCatching { process.errorStream.use { it.readBytes() } }
        }.apply {
            isDaemon = true
            start()
        }
        val finished = process.waitFor(timeoutMs, TimeUnit.MILLISECONDS)
        if (!finished) process.destroyForcibly()
        reader.join(READER_JOIN_MS)
        drain?.join(READER_JOIN_MS)
        return ExecResult(
            exitCode = if (finished) process.exitValue() else -1,
            stdout = collected.toByteArray(),
            timedOut = !finished,
        )
    }

    private fun isPng(bytes: ByteArray): Boolean =
        bytes.size > PNG_SIGNATURE.size &&
            bytes[0] == PNG_SIGNATURE[0] && bytes[1] == PNG_SIGNATURE[1] &&
            bytes[2] == PNG_SIGNATURE[2] && bytes[3] == PNG_SIGNATURE[3]

    /**
     * 纯黑帧判定。
     *
     * 阈值必须盖住「带状态栏的黑帧」：实测 1272×2772 的 FLAG_SECURE 页面，
     * 状态栏正常绘制、内容区全黑，PNG 仍有 **35441 字节**。
     * 早期按 12KB 估算，导致这类帧直接跳过检测被当成正常截图返回，
     * 上层拿到的是一张「看似成功」的黑图 —— 这是最难排查的一种失败。
     *
     * 现在按 200KB 放行上限 + 降采样抽检（约 860 个点，1~2ms），
     * 复杂页面（实测 148KB~610KB）仍会被大小直接放行，不会误伤。
     */
    private fun isBlankFrame(bytes: ByteArray): Boolean {
        if (bytes.size >= BLANK_PNG_BYTES) return false
        val options = BitmapFactory.Options().apply { inSampleSize = 16 }
        val bitmap = runCatching { BitmapFactory.decodeByteArray(bytes, 0, bytes.size, options) }.getOrNull()
            ?: return false
        return try {
            var dark = 0
            var total = 0
            var y = 0
            while (y < bitmap.height) {
                var x = 0
                while (x < bitmap.width) {
                    if ((bitmap.getPixel(x, y) and 0x00FFFFFF) == 0) dark++
                    total++
                    x += 4
                }
                y += 4
            }
            total > 0 && dark.toFloat() / total > 0.995f
        } finally {
            bitmap.recycle()
        }
    }

    companion object {
        private const val DEFAULT_TIMEOUT_MS = 5_000L
        private const val CAPTURE_TIMEOUT_MS = 4_000L
        private const val PROBE_TIMEOUT_MS = 1_500L
        private const val SWIPE_TIMEOUT_MS = 2_500L
        private const val READER_JOIN_MS = 800L
        private const val MAX_CAPTURE_BYTES = 48 * 1024 * 1024

        /**
         * 纯黑帧判定的大小上限。见 [isBlankFrame]：带状态栏的黑帧实测 35441 字节，
         * 早期按 12KB 估算会整片漏检。
         */
        private const val BLANK_PNG_BYTES = 200 * 1024

        /** secure 通道单次要跑一次跨进程合成，给不足会导致误超时。 */
        private const val SECURE_MIN_TIMEOUT_MS = 4_000L

        private const val CAPABILITY_TTL_MS = 60_000L

        /** 主屏的逻辑 display id。 */
        const val MAIN_DISPLAY = 0

        private val PHYSICAL_DISPLAY_PATTERN =
            Regex("""Display\s+(\d+)\s+\(HWC display\s+(\d+)\)""")

        private val PNG_SIGNATURE = byteArrayOf(0x89.toByte(), 0x50, 0x4E, 0x47)

        private val KNOWN_SCREENCAP_PATHS = arrayOf(
            "/system/bin/screencap",
            "/system/xbin/screencap",
            "/vendor/bin/screencap",
        )

        private val KNOWN_SU_PATHS = arrayOf(
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/su/bin/su",
            "/vendor/bin/su",
            "/debug_ramdisk/su",
            "/data/local/tmp/su",
        )
    }
}
