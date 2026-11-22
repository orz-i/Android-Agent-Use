package com.agent.use.server

import android.util.Log
import java.io.File

/**
 * 裸 `app_process` 进程的 native 库加载。
 *
 * 这种进程没有 `nativeLibraryDir`，`System.loadLibrary` 只会在 `/system/lib64`、`/system_ext/lib64`
 * 里找，随 APK 部署的库一律找不到。LiteRT 的 `TensorFlowLite` 静态块恰恰是
 * `System.loadLibrary("LiteRt")`，失败时只记在 `LOAD_LIBRARY_EXCEPTION` 里不抛出，
 * 直到构造 `Interpreter` 才炸成 `dlopen failed: library "libLiteRt.so" not found`。
 *
 * 做法是先按绝对路径 `System.load`。`libLiteRt.so` 带 SONAME，bionic 记下之后，
 * LiteRT 自己的 `loadLibrary("LiteRt")` 会命中已经载入的这份，不再去搜路径。
 * 实测（PLK110 / Android 17，uid 2000）：先 load 再构造，一窗 512 字 21.7ms；
 * 不 load 则如上失败。反射改 `DexPathList.nativeLibraryDirectories` 也行，
 * 但 Android 17 上那个字段已经是 `ArrayList` 而不是 `File[]`，跨版本更脆，所以不用。
 */
object NativeLibraries {
    private const val TAG = "AauNative"
    private const val LITE_RT = "libLiteRt.so"

    @Volatile
    private var liteRt = false

    /** 按优先级找库所在目录；部署脚本可以用 [ENV_DIR] 指定，其余是按常见位置猜。 */
    private fun candidates(): List<File> = listOfNotNull(
        System.getenv(ENV_DIR)?.takeIf { it.isNotBlank() }?.let(::File),
        jarDir()?.resolve("lib"),
        File("/data/local/tmp/aau/lib"),
        File("/data/local/tmp/ner"),
        File("/data/local/tmp/litert"),
        File("/data/local/tmp"),
    )

    /** `aau-server.jar` 所在目录，部署脚本把库放在它下面的 `lib/` 时不用设环境变量。 */
    private fun jarDir(): File? = runCatching {
        System.getProperty("java.class.path").orEmpty()
            .split(File.pathSeparator)
            .firstOrNull { it.endsWith(".jar") }
            ?.let { File(it).absoluteFile.parentFile }
    }.getOrNull()

    /**
     * 幂等；找不到或载入失败时返回 false 并留一条日志，不抛。
     * 调用方据此决定要不要提供依赖这个库的能力，而不是让整个守护进程起不来。
     */
    @Synchronized
    fun loadLiteRt(): Boolean {
        if (liteRt) return true
        val tried = candidates()
        for (dir in tried) {
            val so = File(dir, LITE_RT)
            if (!so.isFile) continue
            try {
                System.load(so.absolutePath)
                liteRt = true
                Log.i(TAG, "Loaded ${so.absolutePath}")
                return true
            } catch (t: Throwable) {
                Log.w(TAG, "Failed to load ${so.absolutePath}: ${t.message}")
            }
        }
        Log.w(TAG, "No $LITE_RT under ${tried.joinToString()}")
        return false
    }

    val liteRtLoaded: Boolean get() = liteRt

    const val ENV_DIR = "AAU_NATIVE_LIB_DIR"
}
