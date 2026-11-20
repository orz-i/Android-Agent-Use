#!/usr/bin/env python3
"""Offline smoke test for both assets with public desktop CPU runtimes.

Run with MNN==3.6.2, ai-edge-litert==2.3.0 and numpy. Android tests check the
shipped Android runtimes separately; host results are not a mobile benchmark.
"""

from pathlib import Path

import MNN
import numpy as np
from ai_edge_litert.interpreter import Interpreter


SIDE, KERNEL, CHANNELS = 160, 19, 11
BASE = Path(__file__).resolve().parents[1] / "src"


def lite_runtime():
    lite = Interpreter(model_path=str(BASE / "litert/assets/aau_icon_glyphs_v1.tflite"), num_threads=2)
    lite.allocate_tensors()
    inp, out = lite.get_input_details()[0], lite.get_output_details()[0]

    def run(x):
        lite.set_tensor(inp["index"], x)
        lite.invoke()
        return lite.get_tensor(out["index"])

    return run


def mnn_runtime():
    mnn = MNN.Interpreter(str(BASE / "mnn/assets/aau_icon_glyphs_v1.mnn"))
    sess = mnn.createSession({"backend": "CPU", "numThread": 2})
    inp, out = mnn.getSessionInput(sess, "pixels"), mnn.getSessionOutput(sess, "scores")
    dtype, order = MNN.Halide_Type_Float, MNN.Tensor_DimensionType_Tensorflow
    side = SIDE - KERNEL + 1

    def run(x):
        src = MNN.Tensor((1, SIDE, SIDE, 2), dtype, x, order)
        dest = MNN.Tensor((1, side, side, CHANNELS), dtype, np.zeros((1, side, side, CHANNELS), np.float32), order)
        inp.copyFromHostTensor(src)
        mnn.runSession(sess)
        out.copyToHostTensor(dest)
        return np.array(dest.getData(), dtype=np.float32).reshape(1, side, side, CHANNELS)

    return run


if __name__ == "__main__":
    lite, mnn = lite_runtime(), mnn_runtime()
    rng = np.random.default_rng(7)
    lumas = [np.full((SIDE, SIDE), .5, np.float32), rng.random((SIDE, SIDE), dtype=np.float32)]
    worst = 0.
    for luma in lumas:
        x = np.stack((luma, luma * luma), axis=-1)[None, ...]
        a, b = lite(x), mnn(x)
        np.testing.assert_allclose(a, b, rtol=1e-5, atol=2e-4)
        worst = max(worst, float(np.max(np.abs(a - b))))
    print(f"CPU score maps agree; max absolute difference {worst:.8f}")
