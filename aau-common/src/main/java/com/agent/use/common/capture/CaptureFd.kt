package com.agent.use.common.capture

import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.File

/**
 * 截屏结果的文件描述符交付器。
 *
 * 为什么不用 `ByteArray` 直接过 Binder：1080×12000 的 PNG 常有 2~8 MB，
 * 会撞上 Binder 事务 1 MB 的硬上限（`TransactionTooLargeException`）。
 *
 * 为什么不是「传路径让客户端自己读」：服务端状态目录（如 `/data/local/tmp`）归 shell 所有（0700），
 * 普通应用根本打不开，传路径必然 EACCES。
 *
 * 采用「写入 → 打开 fd → 立即 unlink」：客户端拿到的是一个已经指向未链接 inode 的 fd，
 * 可以正常流式读完，而文件在目录里瞬间消失，不会把用户屏幕内容留在设备上。
 *
 * 放在 common 而不是 server：任何自建 Shell 守护进程（宿主自己的 app_process）都可能需要它，
 * 没理由为了一个「写文件 + dup fd」重复实现两遍。
 */
object CaptureFd {

    private const val TAG = "CaptureFd"
    private const val DIR_NAME = "capture"
    private const val FILE_PREFIX = "aau-shot-"
    private const val STALE_MS = 30 * 60 * 1000L

    /**
     * 把字节写入服务端私有目录并以只读 fd 返回。
     *
     * @return 只读 fd；写入或打开失败返回 null
     */
    @JvmStatic
    fun publish(stateDir: File, bytes: ByteArray, suffix: String = ".png"): ParcelFileDescriptor? {
        if (bytes.isEmpty()) return null
        return try {
            val dir = File(stateDir, DIR_NAME).apply { if (!exists()) mkdirs() }
            if (!dir.isDirectory) {
                Log.w(TAG, "capture dir unavailable: ${dir.absolutePath}")
                return null
            }
            prune(dir)
            val file = File.createTempFile(FILE_PREFIX, suffix, dir)
            file.writeBytes(bytes)
            val pfd = ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY)
            if (!file.delete()) {
                // 删除失败不影响本次读取（fd 已独立），但会把内容留在磁盘上，需要显式记录
                Log.w(TAG, "capture file not unlinked: ${file.absolutePath}")
            }
            pfd
        } catch (t: Throwable) {
            Log.w(TAG, "publish capture failed: ${t.message}")
            null
        }
    }

    /** 清理历史遗留文件（进程被强杀时 unlink 可能没跑到）。 */
    private fun prune(dir: File) {
        val deadline = System.currentTimeMillis() - STALE_MS
        runCatching {
            dir.listFiles()?.forEach { file ->
                if (file.isFile && file.lastModified() < deadline) file.delete()
            }
        }
    }
}
