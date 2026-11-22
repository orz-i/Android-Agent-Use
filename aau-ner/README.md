# AAU on-device named entity recognition

`:aau-ner` is always in the build. Unlike `:aau-vision` it has no backend switch and no `-P` property: the only graph available for this task is LiteRT, so the module ships it directly. It depends on `:aau-litert`, the Java boundary that keeps LiteRT's Kotlin 2.4 metadata off this module's compile classpath.

`AauEntityExtractor` maps a string to named spans: person, phone, written and spoken addresses, administrative divisions, companies, banks, express/flight/train numbers, and so on — 27 classes. Offsets are half-open character indices into the caller's string, so it composes with accessibility node text or OCR output without searching for the value afterwards. It runs on CPU, needs no network, and takes about **25 ms per 512-character window** on a PLK110 (Android 17). It does not capture the screen and does not act on the result.

```kotlin
AauEntityExtractor(context.assets).use { extractor ->
    extractor.extract("明天下午三点去北京朝阳区望京SOHO找张三")
    // [EntitySpan(Address, 7, 18, "北京朝阳区望京SOHO"), EntitySpan(Person, 19, 21, "张三")]
}
```

## Behaviour worth knowing before you wire it up

Text longer than `MAX_CHARS` (512) is split into windows, preferring a whitespace break in the last quarter. Offsets stay relative to the caller's string.

The graph emits label ids with the argmax baked in, so **spans carry no confidence** — do not threshold them. There is no score to rank candidates by; if a caller needs one, it has to come from the surrounding UI, not from this model.

The tokenizer is part of the contract. The model is character-level: whitespace maps to `[SPACE]` (the 6054-entry table has no literal space; feeding `[UNK]` instead silently collapses a whole address into its last word), and anything outside the table maps to `[UNK]`, including each half of a surrogate pair, so emoji degrade safely.

Call off the main thread. The extractor is not a singleton: one instance holds one interpreter and is `@Synchronized`, so either share one instance across threads or keep one per worker.

## NER assets are not in this repository

The NER graph and its tables come from OPPO's `com.oplus.aiunit` (`engine-nlp_ner_information_intent`, model 3.0.6), so they are git-ignored rather than redistributed. Extract the package once and provision the three assets:

```sh
python aau-ner/tools/import_ner_assets.py --source /path/to/x_ner
```

The tool validates the vocabulary (contiguous ids, `[PAD]`=0, `[UNK]`, `[SPACE]`, single-character tokens), the label table (BIOES tags, known entity classes) and the flatbuffer header before copying `aau_ner_v1.tflite`, `aau_ner_v1.vocab` and `aau_ner_v1.labels`. A newer model with different tables fails loudly here instead of silently degrading on device.

Without the assets the module still compiles and unit tests still pass; only the instrumented tests skip themselves.

## Why LiteRT is the only backend

The graph is a bidirectional LSTM: it derives its own sequence length with a `WHILE` loop and mirrors both directions with `REVERSE_V2`. `MNNConvert` refuses `REVERSE_V2` for this graph, so there is no MNN artifact to load. That is why this module has no `aauVisionBackend` equivalent.

LiteRT's `CompiledModel` also refuses it — `model_load.cc` rejects variable tensors, which is how the LSTM weights are stored. `LiteRtTextModel` therefore goes through the TFLite-compatible `Interpreter` shipped in the same artifact. That is the whole reason the text path and the icon path use different LiteRT APIs.

## Running without an APK (`app_process`)

A daemon started with `app_process` has no `nativeLibraryDir`, so LiteRT's own
`System.loadLibrary("LiteRt")` fails with `dlopen failed: library "libLiteRt.so" not found`.
Load the file by absolute path first — bionic records the SONAME, and the later
`loadLibrary` hits the copy already in the process:

```kotlin
System.load("/data/local/tmp/aau/lib/libLiteRt.so")
AauEntityExtractor.fromFiles(model, vocabulary, labels).use { it.extract(text) }
```

`fromFiles` skips `AssetManager` entirely, which is the point: the daemon's context belongs to
`com.android.shell`, not to the APK that carries these assets. Measured on a PLK110
(Android 17, uid 2000): after the `System.load`, one 512-character window takes 21 ms.
`aau-server` wraps both steps in `NativeLibraries` and exposes `NerSelfCheck` for this.

## Size

The model is 1.3 MB. The LiteRT runtime dominates: `libLiteRt.so` is 5.6 MB for `arm64-v8a`, 7.8 MB for `x86_64`, 3.7 MB for `armeabi-v7a`. An APK only packages the ABIs it declares, so the usual arm64-only build grows by about 7 MB. If that is too much for a particular consumer, exclude `:aau-ner` from that build rather than swapping the backend — there is nothing to swap.

`:aau-server` takes the other trade: its standalone dex goes from 4.1 MB to 9.1 MB because the LiteRT Java classes come along, and the 5.6 MB `.so` is deployed next to the jar instead of inside it.

## Tests

```sh
./gradlew :aau-ner:testDebugUnitTest          # tokenizer, windowing, BIOES decoding
./gradlew :aau-ner:connectedDebugAndroidTest  # the real model, on a device
```

15 JVM tests cover the tokenizer, windowing and BIOES decoding (orphan I/E, type changes, out-of-range ids). 6 instrumented tests run the real model, including a span past the first window and repeated calls on one interpreter.

See [LiteRT license](https://github.com/google-ai-edge/LiteRT/blob/v2.3.2/LICENSE).
