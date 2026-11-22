package com.agent.use.litert;

import android.content.res.AssetManager;
import android.os.Build;
import android.os.Process;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import org.tensorflow.lite.Interpreter;

/**
 * Java API boundary for the int32 NER graph: 512 character ids in, 512 label ids out.
 *
 * <p>This deliberately uses the TFLite-compatible {@link Interpreter} from the LiteRT artifact
 * rather than {@code CompiledModel}. The graph is a bidirectional LSTM whose weights are
 * variable tensors, and the compiled-model loader rejects those outright
 * ("Variable tensors not yet supported"). The compatibility interpreter accepts them and
 * exposes {@code resetVariableTensors} if a future graph turns out to be stateful.
 *
 * <p>The icon detector's {@link LiteRtCpuModel} only moves floats, so this stays separate.
 */
public final class LiteRtTextModel implements Closeable {
    public static final String NAME = "litert";

    /** Model input width. The graph is fixed-shape, so callers must pad or window to this. */
    public static final int LENGTH = 512;

    public static boolean isSupported() {
        String[] abis = Process.is64Bit() ? Build.SUPPORTED_64_BIT_ABIS : Build.SUPPORTED_32_BIT_ABIS;
        if (abis == null) return false;
        for (String abi : abis) {
            if (abi.equals("arm64-v8a") || abi.equals("x86_64") || abi.equals("armeabi-v7a")) return true;
        }
        return false;
    }

    private final Interpreter interpreter;

    /** Direct buffer: the interpreter reads the model in place, so it must outlive it. */
    private final ByteBuffer model;

    public LiteRtTextModel(AssetManager assets, String name) {
        model = readModel(assets, name + ".tflite");
        Interpreter.Options options = new Interpreter.Options();
        // A 512-step LSTM is latency-bound; more threads only add hand-off cost.
        options.setNumThreads(2);
        try {
            interpreter = new Interpreter(model, options);
        } catch (RuntimeException | LinkageError e) {
            throw new IllegalStateException("Failed to initialize CPU NER model", e);
        }
    }

    public int[] classify(int[] tokens) {
        if (tokens.length != LENGTH) {
            throw new IllegalArgumentException("Expected " + LENGTH + " tokens, got " + tokens.length);
        }
        int[][] input = new int[][] { tokens };
        int[][] output = new int[1][LENGTH];
        try {
            interpreter.run(input, output);
        } catch (RuntimeException e) {
            throw new IllegalStateException("CPU NER inference failed", e);
        }
        return output[0];
    }

    @Override public void close() {
        interpreter.close();
    }

    private static ByteBuffer readModel(AssetManager assets, String path) {
        byte[] bytes;
        try (InputStream in = assets.open(path)) {
            ByteArrayOutputStream out = new ByteArrayOutputStream(Math.max(in.available(), 1 << 16));
            byte[] chunk = new byte[1 << 16];
            for (int read; (read = in.read(chunk)) > 0; ) out.write(chunk, 0, read);
            bytes = out.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException("Missing NER model asset " + path, e);
        }
        ByteBuffer buffer = ByteBuffer.allocateDirect(bytes.length).order(ByteOrder.nativeOrder());
        buffer.put(bytes).rewind();
        return buffer;
    }
}
