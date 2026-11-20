#include <jni.h>
#include <MNN/Interpreter.hpp>
#include <MNN/Tensor.hpp>
#include <memory>
#include <vector>

namespace {
struct Model {
    explicit Model(const std::vector<jbyte>& model)
        : net(MNN::Interpreter::createFromBuffer(model.data(), model.size())) {
        if (!net) return;
        MNN::ScheduleConfig cfg;
        cfg.type = cfg.backupType = MNN_FORWARD_CPU;
        cfg.numThread = 2;
        session = net->createSession(cfg);
        if (!session) return;
        input = net->getSessionInput(session, "pixels");
        output = net->getSessionOutput(session, "scores");
        if (!input || !output) return;
        hostInput = std::make_unique<MNN::Tensor>(input, MNN::Tensor::TENSORFLOW);
        hostOutput = std::make_unique<MNN::Tensor>(output, MNN::Tensor::TENSORFLOW);
        valid = hostInput->shape() == std::vector<int>{1, 160, 160, 2} &&
                hostOutput->shape() == std::vector<int>{1, 142, 142, 11} &&
                hostInput->host<float>() && hostOutput->host<float>();
    }

    std::unique_ptr<MNN::Interpreter> net;
    MNN::Session* session = nullptr;
    MNN::Tensor* input = nullptr;
    MNN::Tensor* output = nullptr;
    std::unique_ptr<MNN::Tensor> hostInput, hostOutput;
    bool valid = false;
};
}

extern "C" JNIEXPORT jlong JNICALL
Java_com_agent_use_vision_CpuIconModel_create(JNIEnv* env, jobject, jbyteArray model) {
    const jsize size = env->GetArrayLength(model);
    std::vector<jbyte> bytes(size);
    env->GetByteArrayRegion(model, 0, size, bytes.data());
    if (env->ExceptionCheck()) return 0;
    auto result = std::make_unique<Model>(bytes);
    return result->valid ? reinterpret_cast<jlong>(result.release()) : 0;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_agent_use_vision_CpuIconModel_run(JNIEnv* env, jobject, jlong handle, jfloatArray input, jfloatArray output) {
    auto* model = reinterpret_cast<Model*>(handle);
    if (!model || env->GetArrayLength(input) != model->hostInput->elementSize() ||
        env->GetArrayLength(output) != model->hostOutput->elementSize()) return JNI_FALSE;
    env->GetFloatArrayRegion(input, 0, model->hostInput->elementSize(), model->hostInput->host<float>());
    if (env->ExceptionCheck() || !model->input->copyFromHostTensor(model->hostInput.get()) ||
        model->net->runSession(model->session) != MNN::NO_ERROR ||
        !model->output->copyToHostTensor(model->hostOutput.get())) return JNI_FALSE;
    env->SetFloatArrayRegion(output, 0, model->hostOutput->elementSize(), model->hostOutput->host<float>());
    return env->ExceptionCheck() ? JNI_FALSE : JNI_TRUE;
}

extern "C" JNIEXPORT void JNICALL
Java_com_agent_use_vision_CpuIconModel_destroy(JNIEnv*, jobject, jlong handle) {
    delete reinterpret_cast<Model*>(handle);
}
