#!/usr/bin/env python3
"""Export the pilot's analytic glyph filters (no third-party images/weights).

Requires numpy, flatbuffers, tflite==2.18.0 and MNN==3.6.2. Both runtimes
receive the same Conv2D; MNNConvert consumes the serialized LiteRT graph.
"""

import subprocess
import sys
from pathlib import Path

import flatbuffers
import numpy as np
import tflite as t


SIDE, KERNEL = 160, 19
RADII = (4, 6, 8)
CLASSES = ("search", "close", "more")


def filters():
    # Supersampling gives a soft edge at small sizes. Kernels are zero mean
    # and unit norm; the last channels are sums of luma and luma squared.
    extent = (KERNEL - 1) / 2
    xy = (np.arange(KERNEL * 8) + 0.5) / 8 - extent - 0.5
    x, y = np.meshgrid(xy, xy)
    weights = []
    for glyph in CLASSES:
        for radius in RADII:
            xx, yy = x / radius, y / radius
            if glyph == "search":
                ring = np.abs(np.hypot(xx + .21, yy + .21) - .62) <= .13
                handle = (np.abs(xx - yy) < .20) & (xx + yy > .39) & (xx + yy < 1.83)
                mask = ring | handle
            elif glyph == "close":
                mask = (np.abs(xx) < .92) & (np.abs(yy) < .92) & (np.abs(np.abs(xx) - np.abs(yy)) < .22)
            else:
                mask = np.minimum.reduce([np.hypot(xx - p, yy) for p in (-.77, 0, .77)]) < .21
            pattern = mask.reshape(KERNEL, 8, KERNEL, 8).mean(axis=(1, 3))
            pattern -= pattern.mean()
            weights.append(np.stack((pattern / np.linalg.norm(pattern), np.zeros_like(pattern)), axis=-1))
    sums = np.ones((KERNEL, KERNEL), dtype=np.float32)
    zeros = np.zeros_like(sums)
    weights.extend((np.stack((sums, zeros), -1), np.stack((zeros, sums), -1)))
    return np.array(weights, dtype="<f4")


def export_litert(path):
    b = flatbuffers.Builder(16384)

    def offsets(start, objects):
        start(b, len(objects))
        for obj in reversed(objects):
            b.PrependUOffsetTRelative(obj)
        return b.EndVector()

    def ints(values):
        return b.CreateNumpyVector(np.array(values, dtype="<i4"))

    def buffer(data=b""):
        v = b.CreateByteVector(data) if data else None
        t.BufferStart(b)
        if v is not None:
            t.BufferAddData(b, v)
        return t.BufferEnd(b)

    def tensor(name, dims, buf=0):
        n, s = b.CreateString(name), ints(dims)
        t.TensorStart(b)
        t.TensorAddName(b, n)
        t.TensorAddShape(b, s)
        t.TensorAddType(b, t.TensorType.FLOAT32)
        t.TensorAddBuffer(b, buf)
        return t.TensorEnd(b)

    w = filters()
    channels = len(w)
    out_side = SIDE - KERNEL + 1
    buffers = offsets(t.ModelStartBuffersVector, [buffer(), buffer(w.tobytes()), buffer(bytes(4 * channels))])
    tensors = offsets(t.SubGraphStartTensorsVector, [
        tensor("pixels", (1, SIDE, SIDE, 2)), tensor("filters", w.shape, 1),
        tensor("bias", (channels,), 2), tensor("scores", (1, out_side, out_side, channels)),
    ])
    t.Conv2DOptionsStart(b)
    t.Conv2DOptionsAddPadding(b, t.Padding.VALID)
    t.Conv2DOptionsAddStrideW(b, 1)
    t.Conv2DOptionsAddStrideH(b, 1)
    options = t.Conv2DOptionsEnd(b)
    ins, outs = ints((0, 1, 2)), ints((3,))
    t.OperatorStart(b)
    t.OperatorAddInputs(b, ins)
    t.OperatorAddOutputs(b, outs)
    t.OperatorAddBuiltinOptionsType(b, t.BuiltinOptions.Conv2DOptions)
    t.OperatorAddBuiltinOptions(b, options)
    ops = offsets(t.SubGraphStartOperatorsVector, [t.OperatorEnd(b)])
    ins, name = ints((0,)), b.CreateString("aau_icon_glyphs_v1")
    t.SubGraphStart(b)
    t.SubGraphAddTensors(b, tensors)
    t.SubGraphAddInputs(b, ins)
    t.SubGraphAddOutputs(b, outs)
    t.SubGraphAddOperators(b, ops)
    t.SubGraphAddName(b, name)
    subgraphs = offsets(t.ModelStartSubgraphsVector, [t.SubGraphEnd(b)])
    t.OperatorCodeStart(b)
    t.OperatorCodeAddBuiltinCode(b, t.BuiltinOperator.CONV_2D)
    t.OperatorCodeAddDeprecatedBuiltinCode(b, t.BuiltinOperator.CONV_2D)
    codes = offsets(t.ModelStartOperatorCodesVector, [t.OperatorCodeEnd(b)])
    t.ModelStart(b)
    t.ModelAddVersion(b, 3)
    t.ModelAddOperatorCodes(b, codes)
    t.ModelAddSubgraphs(b, subgraphs)
    t.ModelAddBuffers(b, buffers)
    b.Finish(t.ModelEnd(b), file_identifier=b"TFL3")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b.Output())


if __name__ == "__main__":
    base = Path(__file__).resolve().parents[1] / "src"
    lite = base / "litert/assets/aau_icon_glyphs_v1.tflite"
    mnn = base / "mnn/assets/aau_icon_glyphs_v1.mnn"
    export_litert(lite)
    mnn.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run([
        sys.executable, "-c", "from MNN.tools.mnnconvert import main; main()",
        "-f", "TFLITE", "--modelFile", str(lite), "--MNNModel", str(mnn), "--bizCode", "AAU",
    ], check=True)
    if not mnn.is_file():
        raise RuntimeError("MNNConvert did not produce a model")
