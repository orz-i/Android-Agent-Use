package com.agent.use.ner

import android.content.res.AssetManager
import com.agent.use.litert.LiteRtTextModel
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * LiteRT CPU text tagger. The graph takes int32 character ids and returns int32 label ids,
 * so it cannot share the float buffers of the icon detector.
 */
internal class CpuTextModel private constructor(private val model: LiteRtTextModel) : TokenTagger {
    constructor(assets: AssetManager, name: String) : this(LiteRtTextModel(assets, name))

    override fun classify(tokens: IntArray): IntArray = model.classify(tokens)

    override fun close() = model.close()

    companion object {
        fun isSupported(): Boolean = LiteRtTextModel.isSupported()

        /** 裸 app_process 进程没有本 APK 的 assets,所以也认部署在磁盘上的模型文件。 */
        fun fromFile(file: File): CpuTextModel {
            val bytes = file.readBytes()
            val buffer = ByteBuffer.allocateDirect(bytes.size).order(ByteOrder.nativeOrder())
            buffer.put(bytes).rewind()
            return CpuTextModel(LiteRtTextModel(buffer))
        }
    }
}
