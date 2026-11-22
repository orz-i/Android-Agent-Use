package com.agent.use.ner

import android.content.res.AssetManager
import com.agent.use.litert.LiteRtTextModel

/**
 * LiteRT CPU text tagger. The graph takes int32 character ids and returns int32 label ids,
 * so it cannot share the float buffers of the icon detector.
 */
internal class CpuTextModel(assets: AssetManager, name: String) : TokenTagger {
    private val model = LiteRtTextModel(assets, name)

    override fun classify(tokens: IntArray): IntArray = model.classify(tokens)

    override fun close() = model.close()

    companion object {
        fun isSupported(): Boolean = LiteRtTextModel.isSupported()
    }
}
