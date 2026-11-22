# AAU optional CPU vision and text models

`-PaauVisionBackend=litert|mnn` includes `:aau-vision` (one engine per build); the default `off` does not include it. LiteRT uses standalone `CompiledModel` via its Java API; MNN uses the official 3.6.2 sources through a small CPU-only JNI bridge. For MNN pass `-PaauMnnSourceDir` and install Android NDK `28.2.13676358` and CMake `3.22.1`.

`AauIconDetector` operates on a caller-owned software `Bitmap` or an optional in-bounds region. It performs no capture, network, or actions. Call off the main thread, close when done. Callers enforce screen permissions and frame freshness. `IconDetection.Match` uses source pixels; its score is normalized correlation, not a probability. There are no runtime downloads.

`AauEntityExtractor` is the text side: it maps a string to named spans (person, phone, written and spoken addresses, administrative divisions, companies, banks, express/flight/train numbers, and so on). Offsets are half-open character indices into the caller's string, so it composes with accessibility node text or OCR output. It runs on CPU, needs no network, and takes about **25 ms per 512-character window** on a PLK110 (Android 17). Nothing here captures the screen or acts on the result.

```kotlin
AauEntityExtractor(context.assets).use { extractor ->
    extractor.extract("明天下午三点去北京朝阳区望京SOHO找张三")
    // [EntitySpan(Address, 7, 18, "北京朝阳区望京SOHO"), EntitySpan(Person, 19, 21, "张三")]
}
```

Text longer than `MAX_CHARS` (512) is split into windows, preferring a whitespace break in the last quarter. The graph emits label ids with the argmax baked in, so **spans carry no confidence** — do not threshold them. The model is character-level: whitespace maps to `[SPACE]`, and anything outside the 6054-entry table maps to `[UNK]` (including each half of a surrogate pair, so emoji degrade safely).

## NER assets are not in this repository

The NER graph and its tables come from OPPO's `com.oplus.aiunit` (`engine-nlp_ner_information_intent`, model 3.0.6), so they are git-ignored rather than redistributed. Extract the package once and provision the three assets:

```sh
python aau-vision/tools/import_ner_assets.py --source /path/to/x_ner
```

The tool validates the vocabulary (contiguous ids, `[PAD]`=0, `[UNK]`, `[SPACE]`, single-character tokens), the label table (BIOES tags, known entity classes) and the flatbuffer header before copying `aau_ner_v1.tflite`, `aau_ner_v1.vocab` and `aau_ner_v1.labels`. A newer model with different tables fails loudly here instead of silently degrading on device.

## Why NER is LiteRT-only

The graph is a bidirectional LSTM: it derives its own sequence length with a `WHILE` loop and mirrors both directions with `REVERSE_V2`. `MNNConvert` refuses `REVERSE_V2` for this graph, so an MNN build reports `AauEntityExtractor.supported == false` and the constructor fails with an explicit message.

LiteRT's `CompiledModel` also refuses it — `model_load.cc` rejects variable tensors, which is how the LSTM weights are stored. `LiteRtTextModel` therefore goes through the TFLite-compatible `Interpreter` shipped in the same artifact. That is the whole reason the two model classes look different.

## Reproducing the icon assets

`tools/export_icon_model.py` generates one fixed input FP32 convolution (luminance and its square) with programmatically generated glyph kernels; MNN's converter copies the graph into the `.mnn` format. Assets and generator are part of AAU (Apache-2.0), no pretrained weights or third-party images.

```sh
uv run --no-project --python 3.12 --with numpy==2.2.6 --with flatbuffers==25.2.10 \
  --with tflite==2.18.0 --with MNN==3.6.2 python tools/export_icon_model.py
uv run --no-project --python 3.12 --with numpy==2.2.6 --with ai-edge-litert==2.3.0 \
  --with MNN==3.6.2 python tools/compare_icon_backends.py
```

## Tests

```sh
./gradlew -PaauVisionBackend=litert :aau-vision:testDebugUnitTest          # tokenizer, windowing, BIOES decoding
./gradlew -PaauVisionBackend=litert :aau-vision:connectedDebugAndroidTest  # the real model, on a device
```

The instrumented tests skip themselves when the NER assets have not been provisioned.

See [MNN license](https://github.com/alibaba/MNN/blob/3.6.2/LICENSE.txt) and [LiteRT license](https://github.com/google-ai-edge/LiteRT/blob/v2.3.2/LICENSE). Both engines are Apache-2.0; see their upstream sources for bundled third-party notices.
