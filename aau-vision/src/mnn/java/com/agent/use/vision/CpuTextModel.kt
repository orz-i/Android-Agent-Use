package com.agent.use.vision

import android.content.res.AssetManager

/**
 * The NER graph is a bidirectional LSTM that builds its own sequence length with a WHILE loop
 * and mirrors both directions with REVERSE_V2. MNNConvert rejects REVERSE_V2 for this graph,
 * and there is no MNN model to load, so NER stays a LiteRT-only capability.
 */
internal class CpuTextModel(assets: AssetManager, name: String) : TokenTagger {
    override fun classify(tokens: IntArray): IntArray = throw UnsupportedOperationException(
        "NER needs the litert backend (-PaauVisionBackend=litert); " +
            "MNNConvert cannot lower this graph",
    )

    companion object {
        const val NAME = "mnn"

        fun isSupported(): Boolean = false
    }
}
