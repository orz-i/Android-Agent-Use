package com.agent.use.vision.litert;

import android.content.res.AssetManager;
import android.os.Build;
import android.os.Process;
import com.google.ai.edge.litert.Accelerator;
import com.google.ai.edge.litert.CompiledModel;
import com.google.ai.edge.litert.LiteRtException;
import com.google.ai.edge.litert.TensorBuffer;
import java.io.Closeable;
import java.util.List;

/** Java API boundary: LiteRT 2.3.2's Kotlin metadata is newer than the host compiler. */
public final class LiteRtCpuModel implements Closeable {
    public static final String NAME = "litert";

    public static boolean isSupported() {
        String[] abis = Process.is64Bit() ? Build.SUPPORTED_64_BIT_ABIS : Build.SUPPORTED_32_BIT_ABIS;
        if (abis == null) return false;
        for (String abi : abis) {
            if (abi.equals("arm64-v8a") || abi.equals("x86_64") || abi.equals("armeabi-v7a")) return true;
        }
        return false;
    }

    private final CompiledModel model;
    private final List<TensorBuffer> inputs;
    private final List<TensorBuffer> outputs;

    public LiteRtCpuModel(AssetManager assets, String name) {
        CompiledModel.Options options = new CompiledModel.Options(Accelerator.CPU);
        options.setCpuOptions(new CompiledModel.CpuOptions(2, null, null));
        try {
            model = CompiledModel.create(assets, name + ".tflite", options);
            try {
                inputs = model.createInputBuffers();
                try {
                    outputs = model.createOutputBuffers();
                } catch (Exception | LinkageError e) {
                    inputs.forEach(TensorBuffer::close);
                    throw e;
                }
            } catch (Exception | LinkageError e) {
                model.close();
                throw e;
            }
        } catch (LiteRtException e) {
            throw new IllegalStateException("Failed to initialize CPU LiteRT icon model", e);
        }
    }

    public float[] infer(float[] input) {
        try {
            inputs.get(0).writeFloat(input);
            model.run(inputs, outputs);
            return outputs.get(0).readFloat();
        } catch (LiteRtException e) {
            throw new IllegalStateException("CPU LiteRT icon inference failed", e);
        }
    }

    @Override public void close() {
        outputs.forEach(TensorBuffer::close);
        inputs.forEach(TensorBuffer::close);
        model.close();
    }
}
