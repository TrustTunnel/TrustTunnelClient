#include "jni_utils.h"

#include "net/tls.h"

#include "common/cesu8.h"

LocalRef<jbyteArray> jni_cert_to_java_array(JNIEnv *env, X509 *cert) {
    ag::DeclPtr<ag::TlsCert, &ag::tls_free_serialized_cert> serialized{ag::tls_serialize_cert(cert)};
    if (serialized->size == 0) {
        return {};
    }

    jbyteArray result = env->NewByteArray(serialized->size);
    if (result != nullptr) {
        env->SetByteArrayRegion(result, 0, serialized->size, (jbyte *) serialized->data);
    }

    return {env, result};
}

LocalRef<jstring> jni_safe_new_string_utf(JNIEnv *env, std::string_view utf8) {
    std::string cesu8 = ag::utf8_to_cesu8(utf8);
    jstring result = env->NewStringUTF(cesu8.c_str());
    return {env, result};
}