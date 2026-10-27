#include <jni.h>
#include <string>

#include "common/logger.h"
#include "trusttunnel_subscription.h"

static ag::Logger g_logger{"SUBSCRIPTION"};

/// Return the message of `error`, or a fallback when the error object was not created.
static const char *error_text(const SubscriptionFfiError *error) {
    return error != nullptr ? trusttunnel_subscription_error_message(error) : "unknown error";
}

extern "C" JNIEXPORT jstring JNICALL Java_com_adguard_trusttunnel_Subscription_fetchAndApply(
        JNIEnv *env, jclass /*clazz*/, jstring endpoint_toml) {
    if (endpoint_toml == nullptr) {
        errlog(g_logger, "Failed to fetch a subscription: endpoint TOML is null");
        return nullptr;
    }

    const char *toml_chars = env->GetStringUTFChars(endpoint_toml, nullptr);
    if (toml_chars == nullptr) {
        errlog(g_logger, "Failed to fetch a subscription: out of memory");
        return nullptr;
    }

    SubscriptionFfiError *error = nullptr;
    char *json_raw = nullptr;
    if (trusttunnel_subscription_fetch_for_endpoint(toml_chars, &json_raw, &error) != 0) {
        errlog(g_logger, "Failed to fetch a subscription: {}", error_text(error));
        trusttunnel_subscription_error_free(error);
        env->ReleaseStringUTFChars(endpoint_toml, toml_chars);
        return nullptr;
    }

    char *result_raw = nullptr;
    if (trusttunnel_subscription_apply_endpoint(toml_chars, json_raw, &result_raw, &error) != 0) {
        errlog(g_logger, "Failed to apply a subscription: {}", error_text(error));
        trusttunnel_subscription_error_free(error);
        trusttunnel_subscription_string_free(json_raw);
        env->ReleaseStringUTFChars(endpoint_toml, toml_chars);
        return nullptr;
    }

    trusttunnel_subscription_string_free(json_raw);
    env->ReleaseStringUTFChars(endpoint_toml, toml_chars);

    jstring jresult = env->NewStringUTF(result_raw);
    trusttunnel_subscription_string_free(result_raw);
    return jresult;
}
