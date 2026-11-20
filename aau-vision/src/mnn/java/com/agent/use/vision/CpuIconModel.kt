package com.agent.use.vision

import android.content.res.AssetManager
import android.os.Build
import android.os.Process
import java.io.Closeable

internal class CpuIconModel(assets: AssetManager, name: String) : Closeable {
    private var handle = library.let { create(assets.open("$name.mnn").use { it.readBytes() }) }

    init { check(handle != 0L) { "Failed to initialize CPU MNN icon model" } }

    fun infer(input: FloatArray): FloatArray {
        val out = FloatArray(MAP * MAP * CHANNELS)
        check(run(handle, input, out)) { "MNN icon inference failed" }
        return out
    }

    override fun close() {
        if (handle != 0L) destroy(handle)
        handle = 0L
    }

    private external fun create(model: ByteArray): Long
    private external fun run(handle: Long, input: FloatArray, output: FloatArray): Boolean
    private external fun destroy(handle: Long)

    companion object {
        const val NAME = "mnn"
        private val library by lazy { System.loadLibrary("aau_mnn_vision") }
        fun isSupported(): Boolean = Process.is64Bit() &&
            Build.SUPPORTED_64_BIT_ABIS.orEmpty().any { it == "arm64-v8a" || it == "x86_64" }
    }
}
