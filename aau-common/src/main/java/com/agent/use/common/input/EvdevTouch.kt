package com.agent.use.common.input

import android.content.Context
import android.os.Build
import android.util.Log
import android.view.WindowManager
import java.io.ByteArrayOutputStream
import java.util.concurrent.TimeUnit

/**
 * EvdevTouch —— 从 `/dev/input/eventN` 注入触摸，替代 `AccessibilityService.dispatchGesture` 的注入通道。
 *
 * 为什么要这一层：
 *   系统的 `AccessibilityManagerService$MotionEventInjector` 用
 *   `MotionEvent.obtain(downTime, when, action, x, y, 0)` 造事件，注入到应用层的三个字段是固定的：
 *     `deviceId = 0`、`toolType = TOOL_TYPE_UNKNOWN(0)`、`eventId = -1`。
 *   走 evdev 则由内核按真实触摸设备派发，InputReader 推导出
 *   `deviceId = <真实输入设备>`、`toolType = TOOL_TYPE_FINGER`、`eventId = <每帧递增>`，
 *   与真手指在事件结构上同源。行为层的抖动/节奏由调用方（GesturePacing）负责，这一层只管通道。
 *
 * 前置条件：root。二进制随 APK 打包在 `assets/evdev/evinject`，首次使用时用 `su` 部署到
 * `/data/local/tmp/evinject`，之后每次手势由 `su -c` 拉起。
 *
 * 坐标：对外是屏幕像素（和 a11y 节点 bounds 同一坐标系），内部按触摸屏的 ABS 范围换算成物理坐标。
 *
 * 能力自适应：部分机型的 `ABS_MT_PRESSURE` / `ABS_MT_TOUCH_MAJOR` maximum 为 0，
 * 写超范围值会让内核丢弃整个 DOWN 序列（write 成功但屏幕无反应），二进制内已按 capability 过滤。
 *
 * 线程：所有方法都是阻塞的，调用方必须在 IO 线程执行。同一时刻只允许一笔手势，内部串行化。
 */
class EvdevTouch private constructor(context: Context) {

    private data class Device(
        val path: String,
        val name: String,
        val maxX: Int,
        val maxY: Int,
    )

    private val appContext = context.applicationContext

    private val lock = Any()

    @Volatile
    private var device: Device? = null

    /** 探测失败后短时间内不再重试，避免每次手势都白跑一次 su。 */
    @Volatile
    private var retryAfter = 0L

    @Volatile
    private var screenW = 0

    @Volatile
    private var screenH = 0

    /** 已探测到可用的触摸屏节点。 */
    val isReady: Boolean get() = device != null

    // ------------------------------------------------------------------ 公共

    /**
     * 探测并缓存触摸屏节点。失败返回 false，并在 [FAILURE_BACKOFF_MS] 内不再重试。
     * 阻塞，需在 IO 线程调用。
     */
    fun prepare(): Boolean {
        device?.let { return true }
        if (System.currentTimeMillis() < retryAfter) return false
        synchronized(lock) {
            device?.let { return true }
            if (System.currentTimeMillis() < retryAfter) return false

            val su = resolveSu() ?: run {
                Log.i(TAG, "没有可用的 su，evdev 通道关闭")
                retryAfter = System.currentTimeMillis() + FAILURE_BACKOFF_MS
                return false
            }
            if (!deploy(su)) {
                retryAfter = System.currentTimeMillis() + FAILURE_BACKOFF_MS
                return false
            }
            val found = findTouchscreen(su)
            if (found == null) {
                Log.w(TAG, "未找到可写触摸屏节点")
                retryAfter = System.currentTimeMillis() + FAILURE_BACKOFF_MS
                return false
            }
            readScreenSize()
            device = found
            Log.i(TAG, "evdev 通道就绪: ${found.path} (${found.name}) " +
                "abs=${found.maxX}x${found.maxY} screen=${screenW}x${screenH}")
            return true
        }
    }

    /** 单击。坐标是屏幕像素；[durationMs] 是按住时长。 */
    fun tap(x: Float, y: Float, durationMs: Long): Boolean {
        if (!prepare()) return false
        val d = device ?: return false
        val hold = durationMs.coerceIn(1, 5_000)
        val cmd = "$BIN ${d.path} tap ${toPhysX(d, x)} ${toPhysY(d, y)} $hold"
        synchronized(lock) {
            return exec(resolveSu() ?: return false, cmd, hold + EXEC_SLACK_MS)
        }
    }

    /**
     * 按给定时间轴走一笔单指轨迹。[xs]/[ys] 是屏幕像素，[ts] 是相对按下时刻的毫秒偏移，
     * 必须非递减且首元素为 0；最后一个点即抬起位置与时刻。
     */
    fun stroke(xs: IntArray, ys: IntArray, ts: LongArray): Boolean {
        if (!prepare()) return false
        val d = device ?: return false
        val n = ts.size
        if (n < 2 || xs.size != n || ys.size != n) return false
        val duration = ts[n - 1]
        if (duration !in 0..MAX_STROKE_MS) return false

        val cmd = StringBuilder(n * 18 + 48)
        cmd.append(BIN).append(' ').append(d.path).append(" stroke ").append(n)
        for (i in 0 until n) {
            cmd.append(' ').append(ts[i].coerceAtLeast(0))
            cmd.append(' ').append(toPhysX(d, xs[i].toFloat()))
            cmd.append(' ').append(toPhysY(d, ys[i].toFloat()))
        }
        synchronized(lock) {
            return exec(resolveSu() ?: return false, cmd.toString(), duration + EXEC_SLACK_MS)
        }
    }

    companion object {
        private const val TAG = "EvdevTouch"
        private const val ASSET = "evdev/evinject"
        private const val BIN = "/data/local/tmp/evinject"
        private const val FAILURE_BACKOFF_MS = 60_000L
        private const val EXEC_SLACK_MS = 4_000L
        private const val MAX_STROKE_MS = 10_000L
        private const val PROBE_TIMEOUT_MS = 8_000L
        private const val MAX_OUTPUT = 64 * 1024

        private val SU_PATHS = arrayOf(
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/su/bin/su",
            "/debug_ramdisk/su",
            "/data/adb/ksu/bin/su",
        )

        @Volatile
        private var shared: EvdevTouch? = null

        fun get(context: Context): EvdevTouch =
            shared ?: synchronized(this) {
                shared ?: EvdevTouch(context).also { shared = it }
            }

        /** 后台预热，别让第一次点击承担探测开销。 */
        fun warmUp(context: Context) {
            val touch = get(context)
            if (touch.isReady) return
            Thread({
                runCatching { touch.prepare() }
            }, "evdev-warmup").apply { isDaemon = true }.start()
        }
    }

    // ------------------------------------------------------------------ 内部

    private fun toPhysX(d: Device, x: Float): Int = (x / screenW * d.maxX).toInt().coerceIn(0, d.maxX)

    private fun toPhysY(d: Device, y: Float): Int = (y / screenH * d.maxY).toInt().coerceIn(0, d.maxY)

    private fun readScreenSize() {
        if (screenW > 0 && screenH > 0) return
        val wm = appContext.getSystemService(Context.WINDOW_SERVICE) as? WindowManager
        val display = wm?.defaultDisplay
        val point = android.graphics.Point()
        if (display != null) {
            @Suppress("DEPRECATION")
            display.getRealSize(point)
        }
        if (point.x <= 0 || point.y <= 0) {
            val dm = appContext.resources.displayMetrics
            point.x = dm.widthPixels
            point.y = dm.heightPixels
        }
        screenW = point.x.coerceAtLeast(1)
        screenH = point.y.coerceAtLeast(1)
    }

    private fun resolveSu(): String? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) return null
        SU_PATHS.firstOrNull { java.io.File(it).exists() }?.let { return it }
        // 路径不固定时退回 PATH 查找，能不能拿到 root 由第一次 `id -u` 判定。
        return "su"
    }

    /** 把 assets 里的二进制写到 /data/local/tmp。每次进程首次探测都重写一遍，保证版本与 APK 一致。 */
    private fun deploy(su: String): Boolean {
        val bytes = try {
            appContext.assets.open(ASSET).use { it.readBytes() }
        } catch (t: Throwable) {
            Log.e(TAG, "读取 $ASSET 失败", t)
            return false
        }
        val result = runProcess(
            arrayOf(su, "-c", "cat > $BIN && chmod 755 $BIN"),
            stdin = bytes,
            timeoutMs = PROBE_TIMEOUT_MS,
        )
        if (!result.ok) {
            Log.w(TAG, "部署注入器失败: ${result.out}")
            return false
        }
        return true
    }

    private fun findTouchscreen(su: String): Device? {
        val result = runProcess(arrayOf(su, "-c", "$BIN -l"), timeoutMs = PROBE_TIMEOUT_MS)
        if (!result.ok) {
            Log.w(TAG, "列出输入设备失败: ${result.out}")
            return null
        }
        var best: Device? = null
        var bestArea = 0L
        for (line in result.out.lineSequence()) {
            val parts = line.split('|')
            if (parts.size < 5) continue
            val path = parts[0].trim()
            if (!path.startsWith("/dev/input/event")) continue
            val maxX = parts[2].trim().toIntOrNull() ?: continue
            val maxY = parts[3].trim().toIntOrNull() ?: continue
            val hasBtn = parts[4].trim() == "1"
            // 真触摸屏：有 MT 坐标范围且报了 BTN_TOUCH；面积取最大以排除 side button 之类
            if (!hasBtn || maxX <= 0 || maxY <= 0) continue
            val area = maxX.toLong() * maxY
            if (area > bestArea) {
                bestArea = area
                best = Device(path, parts[1].trim(), maxX, maxY)
            }
        }
        return best
    }

    private fun exec(su: String, command: String, timeoutMs: Long): Boolean {
        val result = runProcess(arrayOf(su, "-c", command), timeoutMs = timeoutMs)
        if (!result.ok) {
            Log.w(TAG, "注入失败: ${command.take(80)} -> ${result.out.take(160)}")
            // 设备节点可能被重枚举，丢掉缓存下次重探
            if (result.out.contains("No such file") || result.out.contains("Permission denied")) {
                device = null
            }
        }
        return result.ok
    }

    private class ExecResult(val exitCode: Int, val out: String) {
        val ok: Boolean get() = exitCode == 0
    }

    private fun runProcess(
        argv: Array<String>,
        stdin: ByteArray? = null,
        timeoutMs: Long,
    ): ExecResult {
        val process = try {
            ProcessBuilder(*argv).redirectErrorStream(true).start()
        } catch (t: Throwable) {
            return ExecResult(-1, "spawn failed: ${t.message}")
        }
        val collected = ByteArrayOutputStream()
        val reader = Thread {
            runCatching {
                process.inputStream.use { input ->
                    val buffer = ByteArray(8 * 1024)
                    while (true) {
                        val read = input.read(buffer)
                        if (read < 0) break
                        if (collected.size() < MAX_OUTPUT) {
                            collected.write(buffer, 0, minOf(read, MAX_OUTPUT - collected.size()))
                        }
                    }
                }
            }
        }.apply { isDaemon = true; start() }

        try {
            stdin?.let {
                runCatching {
                    process.outputStream.use { out -> out.write(it); out.flush() }
                }
            }
            if (!process.waitFor(timeoutMs, TimeUnit.MILLISECONDS)) {
                process.destroyForcibly()
                return ExecResult(-1, "timeout ${timeoutMs}ms")
            }
        } catch (t: Throwable) {
            process.destroyForcibly()
            return ExecResult(-1, "wait failed: ${t.message}")
        } finally {
            reader.join(500)
        }
        return ExecResult(process.exitValue(), collected.toString(Charsets.UTF_8.name()))
    }
}
