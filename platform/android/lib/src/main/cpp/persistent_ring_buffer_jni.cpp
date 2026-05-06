#include "common/logger.h"
#include "vpn/trusttunnel/persistent_ring_buffer.h"

#include "jni_utils.h"

#include <jni.h>
#include <optional>
#include <string>

static ag::Logger g_logger("PersistentRingBufferJni");

static std::string get_path(JNIEnv *env, jstring path) {
    const char *chars = env->GetStringUTFChars(path, nullptr);
    if (chars == nullptr) {
        return {};
    }
    std::string result(chars, static_cast<size_t>(env->GetStringUTFLength(path)));
    env->ReleaseStringUTFChars(path, chars);
    return result;
}

extern "C" JNIEXPORT jboolean JNICALL Java_com_adguard_trusttunnel_PersistentRingBuffer_nativeAppend(
        JNIEnv *env, jobject thiz, jstring path, jstring record) {
    if (path == nullptr || record == nullptr) {
        errlog(g_logger, "Path or record is null");
        return static_cast<jboolean>(false);
    }

    std::string native_path = get_path(env, path);
    if (native_path.empty()) {
        return static_cast<jboolean>(false);
    }

    const char *chars = env->GetStringUTFChars(record, nullptr);
    if (chars == nullptr) {
        errlog(g_logger, "Failed to get record chars");
        return static_cast<jboolean>(false);
    }

    std::string_view native_record(chars, static_cast<size_t>(env->GetStringUTFLength(record)));
    ag::PersistentRingBuffer buffer(std::move(native_path));
    bool success = buffer.append(native_record);
    env->ReleaseStringUTFChars(record, chars);
    return static_cast<jboolean>(success);
}

extern "C" JNIEXPORT jobjectArray JNICALL Java_com_adguard_trusttunnel_PersistentRingBuffer_nativeReadAll(
        JNIEnv *env, jobject thiz, jstring path) {
    if (path == nullptr) {
        errlog(g_logger, "Path is null");
        return nullptr;
    }

    std::string native_path = get_path(env, path);
    if (native_path.empty()) {
        return nullptr;
    }

    ag::PersistentRingBuffer buffer(std::move(native_path));
    std::optional<ag::RingBufferReadResult> result = buffer.read_all();
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
        JNIEnv *env, jobject thiz, jstring path) {
    if (path == nullptr) {
        warnlog(g_logger, "Path is null");
        return;
    }

    std::string native_path = get_path(env, path);
    if (native_path.empty()) {
        return;
    }

    ag::PersistentRingBuffer buffer(std::move(native_path));
    if (!buffer.clear()) {
        warnlog(g_logger, "Failed to clear ring buffer file");
    }
}