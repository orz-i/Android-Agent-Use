# AAU optional CPU icon detector

`-PaauVisionBackend=litert|mnn` includes `:aau-vision` (one engine per build); the default `off` does not include it. LiteRT uses standalone `CompiledModel` via its Java API; MNN uses the official 3.6.2 sources through a small CPU-only JNI bridge. For MNN pass `-PaauMnnSourceDir` and install Android NDK `28.2.13676358` and CMake `3.22.1`.

`AauIconDetector` operates on a caller-owned software `Bitmap` or an optional in-bounds region. It performs no capture, network, or actions. Call off the main thread, close when done. Callers enforce screen permissions and frame freshness. `IconDetection.Match` uses source pixels; its score is normalized correlation, not a probability. There are no runtime downloads.

## Reproducing the assets

`tools/export_icon_model.py` generates one fixed input FP32 convolution (luminance and its square) with programmatically generated glyph kernels; MNN's converter copies the graph into the `.mnn` format. Assets and generator are part of AAU (Apache-2.0), no pretrained weights or third-party images.

```sh
uv run --no-project --python 3.12 --with numpy==2.2.6 --with flatbuffers==25.2.10 \
  --with tflite==2.18.0 --with MNN==3.6.2 python tools/export_icon_model.py
uv run --no-project --python 3.12 --with numpy==2.2.6 --with ai-edge-litert==2.3.0 \
  --with MNN==3.6.2 python tools/compare_icon_backends.py
```

See [MNN license](https://github.com/alibaba/MNN/blob/3.6.2/LICENSE.txt) and [LiteRT license](https://github.com/google-ai-edge/LiteRT/blob/v2.3.2/LICENSE). Both engines are Apache-2.0; see their upstream sources for bundled third-party notices.
