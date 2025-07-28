#include <jni.h>

#include "jni_utils.h"

#include "common/logger.h"

extern "C"
JNIEXPORT void JNICALL
Java_com_adguard_trusttunnel_log_NativeLogger_setDefaultLogLevel(JNIEnv *env, jclass clazz, jint level) {
    ag::Logger::set_log_level((ag::LogLevel) level);
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_adguard_trusttunnel_log_NativeLogger_getDefaultLogLevel0(JNIEnv *env, jclass clazz) {
    return ag::Logger::get_log_level();
}

extern "C"
JNIEXPORT void JNICALL
Java_com_adguard_trusttunnel_log_NativeLogger_setupSlf4j(JNIEnv *env, jclass clazz) {
    JavaVM *vm;
    env->GetJavaVM(&vm);
    GlobalRef<jclass> gtype{vm, clazz};
    jmethodID log_method = env->GetStaticMethodID(gtype.get(), "log", "(ILjava/lang/String;)V");
    ag::Logger::set_callback(
            [vm, log_method, gtype = std::move(gtype)](ag::LogLevel log_level, std::string_view message) {
                ScopedJniEnv env(vm, 8);
                LocalRef<jstring> message_str = jni_safe_new_string_utf(env.get(), message);
                env->CallStaticVoidMethod(gtype.get(), log_method, (jint) log_level, message_str.get());
            });
}