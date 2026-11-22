package com.agent.use.vision

import android.content.res.AssetManager
import com.agent.use.vision.litert.LiteRtTextModel

/**
 * LiteRT CPU text tagger. The NER graph takes int32 character ids and returns int32 label ids,
 * so it cannot share the float buffers of the icon detector.
 */
internal class CpuTextModel(assets: AssetManager, name: String) : TokenTagger {
    private val model = LiteRtTextModel(assets, name)

    override fun classify(tokens: IntArray): IntArray = model.classify(tokens)

    override fun close() = model.close()

    companion object {
        const val NAME = LiteRtTextModel.NAME

        fun isSupported(): Boolean = LiteRtTextModel.isSupported()
    }
}
