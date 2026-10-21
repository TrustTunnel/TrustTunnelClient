#include <jni.h>
#include <string>

#include "trusttunnel_deeplink.h"

extern "C" JNIEXPORT jstring JNICALL Java_com_adguard_trusttunnel_DeepLink_decode(
        JNIEnv *env, jclass /*clazz*/, jstring uri) {
    if (uri == nullptr) {
        env->ThrowNew(env->FindClass("java/lang/IllegalArgumentException"), "URI must not be null");
        return nullptr;
    }

    const char *uri_chars = env->GetStringUTFChars(uri, nullptr);
    if (uri_chars == nullptr) {
        return nullptr;
    }

    DeepLinkError *error = nullptr;
    char *result = trusttunnel_deeplink_decode(uri_chars, &error);
    env->ReleaseStringUTFChars(uri, uri_chars);

    if (result == nullptr) {
        std::string msg = error ? trusttunnel_deeplink_error_message(error) : "Unknown deep-link decode error";
        trusttunnel_deeplink_error_free(error);
        env->ThrowNew(env->FindClass("java/lang/RuntimeException"), msg.c_str());
        return nullptr;
    }

    jstring jresult = env->NewStringUTF(result);
    trusttunnel_deeplink_string_free(result);
    return jresult;
}

extern "C" JNIEXPORT jstring JNICALL Java_com_adguard_trusttunnel_DeepLink_encode(
        JNIEnv *env, jclass /*clazz*/, jstring endpoint_toml) {
    if (endpoint_toml == nullptr) {
        env->ThrowNew(env->FindClass("java/lang/IllegalArgumentException"), "Endpoint TOML must not be null");
        return nullptr;
    }

    const char *toml_chars = env->GetStringUTFChars(endpoint_toml, nullptr);
    if (toml_chars == nullptr) {
        return nullptr;
    }

    DeepLinkError *error = nullptr;
    char *result = trusttunnel_deeplink_encode(toml_chars, &error);
    env->ReleaseStringUTFChars(endpoint_toml, toml_chars);

    if (result == nullptr) {
        std::string msg = error ? trusttunnel_deeplink_error_message(error) : "Unknown deep-link encode error";
        trusttunnel_deeplink_error_free(error);
        env->ThrowNew(env->FindClass("java/lang/RuntimeException"), msg.c_str());
        return nullptr;
    }

    jstring jresult = env->NewStringUTF(result);
    trusttunnel_deeplink_string_free(result);
    return jresult;
}
