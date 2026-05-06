#include "common/logger.h"
#include "vpn/trusttunnel/persistent_ring_buffer.h"

#include "jni_utils.h"

#include <jni.h>
#include <memory>
#include <optional>
#include <string>
#include <utility>

static ag::Logger g_logger("PersistentRingBufferJni");

class RingBufferCtx {
public:
    explicit RingBufferCtx(std::string path)
            : m_buffer(std::move(path)) {
    }

    ag::PersistentRingBuffer m_buffer;
};

static RingBufferCtx *get_ring_buffer_ctx(jlong native_ptr) {
    return (RingBufferCtx *) native_ptr;
}

extern "C" JNIEXPORT jlong JNICALL Java_com_adguard_trusttunnel_PersistentRingBuffer_nativeCreate(
        JNIEnv *env, jobject thiz, jstring path) {
    if (path == nullptr) {
        errlog(g_logger, "Ring buffer path is null");
        return 0;
    }

    const char *chars = env->GetStringUTFChars(path, nullptr);
    if (chars == nullptr) {
        errlog(g_logger, "Failed to get ring buffer path chars");
        return 0;
    }

    std::string native_path(chars, static_cast<size_t>(env->GetStringUTFLength(path)));
    env->ReleaseStringUTFChars(path, chars);

    auto ctx = std::make_unique<RingBufferCtx>(std::move(native_path));
    return (jlong) ctx.release();
}

extern "C" JNIEXPORT jboolean JNICALL Java_com_adguard_trusttunnel_PersistentRingBuffer_nativeAppend(
        JNIEnv *env, jobject thiz, jlong native_ptr, jstring record) {
    auto *ctx = get_ring_buffer_ctx(native_ptr);
    if (ctx == nullptr || record == nullptr) {
        errlog(g_logger, "Can't append, ring buffer is not initialized");
        return static_cast<jboolean>(false);
    }

    const char *chars = env->GetStringUTFChars(record, nullptr);
    if (chars == nullptr) {
        errlog(g_logger, "Failed to get record chars");
        return static_cast<jboolean>(false);
    }

    std::string_view native_record(chars, static_cast<size_t>(env->GetStringUTFLength(record)));
    bool success = ctx->m_buffer.append(native_record);
    env->ReleaseStringUTFChars(record, chars);
    return static_cast<jboolean>(success);
}

extern "C" JNIEXPORT jobjectArray JNICALL Java_com_adguard_trusttunnel_PersistentRingBuffer_nativeReadAll(
        JNIEnv *env, jobject thiz, jlong native_ptr) {
    auto *ctx = get_ring_buffer_ctx(native_ptr);
    if (ctx == nullptr) {
        errlog(g_logger, "Can't read, ring buffer is not initialized");
        return nullptr;
    }

    std::optional<ag::RingBufferReadResult> result = ctx->m_buffer.read_all();
    if (!result.has_value()) {
        return nullptr;
    }

    jclass string_class = env->FindClass("java/lang/String");
    if (string_class == nullptr) {
        errlog(g_logger, "Failed to find java/lang/String for ring buffer read");
        return nullptr;
    }

    LocalRef<jobjectArray> records{
            env, env->NewObjectArray(static_cast<jsize>(result->records.size()), string_class, nullptr)};
    if (!records) {
        errlog(g_logger, "Failed to allocate string array for ring buffer read");
        return nullptr;
    }

    for (size_t i = 0; i < result->records.size(); ++i) {
        LocalRef<jstring> record = jni_safe_new_string_utf(env, result->records[i]);
        if (!record) {
            errlog(g_logger, "Failed to convert ring buffer record to jstring");
            return nullptr;
        }
        env->SetObjectArrayElement(records.get(), static_cast<jsize>(i), record.get());
    }

    return records.release();
}

extern "C" JNIEXPORT void JNICALL Java_com_adguard_trusttunnel_PersistentRingBuffer_nativeClear(
        JNIEnv *env, jobject thiz, jlong native_ptr) {
    auto *ctx = get_ring_buffer_ctx(native_ptr);
    if (ctx == nullptr) {
        warnlog(g_logger, "Can't clear, ring buffer is not initialized");
        return;
    }

    if (!ctx->m_buffer.clear()) {
        warnlog(g_logger, "Failed to clear ring buffer file");
    }
}

extern "C" JNIEXPORT void JNICALL Java_com_adguard_trusttunnel_PersistentRingBuffer_nativeDestroy(
        JNIEnv *env, jobject thiz, jlong native_ptr) {
    auto *ctx = get_ring_buffer_ctx(native_ptr);
    if (ctx == nullptr) {
        return;
    }

    delete ctx;
}