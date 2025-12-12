#include "vpn/trusttunnel/client.h"
#include "vpn/trusttunnel/connection_info.h"
#include "net/network_manager.h"

#include "jni_utils.h"
#include <jni.h>
#include <common/cidr_range.h>

static ag::Logger g_logger("TrustTunnelJni");

class VpnCtx {
public:
    VpnCtx(JNIEnv *env, jobject callback_object, jmethodID protect_socket_callback,
           jmethodID verify_callback, jmethodID state_changed_callback, jmethodID connection_info_callback,
           ag::TrustTunnelConfig &&config)
        : m_protect_socket_callback(protect_socket_callback)
        , m_verify_callback(verify_callback)
        , m_state_changed_callback(state_changed_callback)
        , m_connection_info_callback(connection_info_callback)
        , m_native_client(std::move(config), create_callbacks()) {
            env->GetJavaVM(&m_vm);
            this->m_callback_object = {m_vm, callback_object};
        }

    ag::TrustTunnelClient &get_native_client() {
        return m_native_client;
    }
private:
    GlobalRef<jobject> m_callback_object;
    JavaVM *m_vm = nullptr;
    jmethodID m_protect_socket_callback = nullptr;
    jmethodID m_verify_callback = nullptr;
    jmethodID m_state_changed_callback = nullptr;
    jmethodID m_connection_info_callback = nullptr;

    ag::TrustTunnelClient m_native_client;

    void protectSocket(ag::SocketProtectEvent *event) {
        if (!this->m_protect_socket_callback || !m_callback_object) {
            errlog(g_logger, "`protectSocket` called but there is no handler provided on Hava side");
            assert(0);
            event->result = false;
            return;
        }
        ScopedJniEnv env{m_vm, 16};
        bool result = env->CallBooleanMethod(m_callback_object.get(), m_protect_socket_callback, event->fd);
        event->result = result ? 0 : -1;
    }

    void verifyCertificate(ag::VpnVerifyCertificateEvent *event) {
        if (!this->m_verify_callback || !m_callback_object) {
            errlog(g_logger, "`protectSocket` called but there is no handler provided on Hava side");
            assert(0);
            event->result = -1;
            return;
        }
        ScopedJniEnv env{m_vm, 16};
        LocalRef<jbyteArray> jcert = jni_cert_to_java_array(env.get(), event->cert);
        if (!jcert) {
            event->result = -1;
            errlog(g_logger, "Failed to serialize certificate");
            return;
        }

        jclass array_list = env->FindClass("java/util/ArrayList");
        if (!array_list) {
            event->result = -1;
            errlog(g_logger, "Failed to find the ArrayList Java class");
            return;
        }

        STACK_OF(X509) *chain = event->chain;
        int chain_len = sk_X509_num(chain);
        jmethodID array_ctor = env->GetMethodID(array_list, "<init>", "(I)V");
        LocalRef<jobject> jchain{env.get(), env->NewObject(array_list, array_ctor, (jint) chain_len)};
        jmethodID array_add = env->GetMethodID(array_list, "add", "(Ljava/lang/Object;)Z");
        for (int i = 0; i < chain_len; ++i) {
            LocalRef<jbyteArray> chained_cert = jni_cert_to_java_array(env.get(), sk_X509_value(chain, i));
            if (!chained_cert || !env->CallBooleanMethod(jchain.get(), array_add, chained_cert.get())) {
                event->result = -1;
                errlog(g_logger, "Failed to serialize certificate chain");
                break;
            }
        }
        bool result = env->CallBooleanMethod(m_callback_object.get(), m_verify_callback, jcert.get(), jchain.get());
        event->result = result ? 0 : -1;
    }

    void onStateChanged(ag::VpnStateChangedEvent *event) {
        if (!this->m_state_changed_callback || !m_callback_object) {
            errlog(g_logger, "`onStateChanged` called but there is no handler provided on Java side");
            assert(0);
            return;
        }
        ScopedJniEnv env{m_vm, 1};
        env->CallVoidMethod(m_callback_object.get(), m_state_changed_callback, (int) event->state);
    }

    void onConnectionInfo(ag::VpnConnectionInfoEvent *info) {
        if (!this->m_connection_info_callback || !m_callback_object) {
            errlog(g_logger, "`onConnectionInfo` called but there is no handler provided on Java side");
            assert(0);
            return;
        }
        ScopedJniEnv env{m_vm, 1};
        std::string json = ag::ConnectionInfo::to_json(info);
        LocalRef<jstring> str(env.get(), env->NewStringUTF(json.data()));
        env->CallVoidMethod(m_callback_object.get(), m_connection_info_callback, str.get());
    }

    ag::VpnCallbacks create_callbacks() {
        return {
                .protect_handler = [this] (auto event) {
                    protectSocket(event);
                },
                .verify_handler = [this] (auto event) {
                    verifyCertificate(event);
                },
                .state_changed_handler = [this] (auto event) {
                    onStateChanged(event);
                },
                .connection_info_handler = [this] (auto event) {
                    onConnectionInfo(event);
                },
        };
    }
};

extern "C"
JNIEXPORT jlong JNICALL
Java_com_adguard_trusttunnel_VpnClient_createNative(JNIEnv *env, jobject thiz, jstring config) {
    jclass callback_class = env->GetObjectClass(thiz);
    if (!callback_class) {
        errlog(g_logger, "Failed to find Java class for the Callback object");
        return 0;
    }

    jmethodID protect_socket_method_id = env->GetMethodID(callback_class, "protectSocket", "(I)Z");
    if (!protect_socket_method_id) {
        errlog(g_logger, "There is no `protectSocket` method in the Callback object");
        return 0;
    }

    jmethodID verify_certificate_method_id = env->GetMethodID(callback_class, "verifyCertificate", "([BLjava/util/List;)Z");
    if (!verify_certificate_method_id) {
        errlog(g_logger, "There is no `verifyCertificate` method in the Callback object");
        return 0;
    }

    jmethodID state_changed_method_id = env->GetMethodID(callback_class, "onStateChanged", "(I)V");
    if (!state_changed_method_id) {
        errlog(g_logger, "There is no `onStateChanged` method in the Callback object");
        return 0;
    }

    jmethodID connection_info_method_id = env->GetMethodID(callback_class, "onConnectionInfo",
                                                           "(Ljava/lang/String;)V");
    if (!connection_info_method_id) {
        errlog(g_logger, "There is no `onConnectionInfo` method in the Callback object");
        return 0;
    }

    std::string_view conf = env->GetStringUTFChars(config, nullptr);
    toml::parse_result parse_result = toml::parse(conf);
    if (!parse_result) {
        errlog(g_logger, "Failed to parse configuration: {}", parse_result.error().description());
        return 1;
    }
    auto trusttunnel_config = ag::TrustTunnelConfig::build_config(parse_result);
    if (!trusttunnel_config) {
        errlog(g_logger, "Failed to process configuration");
        return 0;
    }

    auto ctx = std::make_unique<VpnCtx>(
            env, thiz,
            protect_socket_method_id, verify_certificate_method_id, state_changed_method_id, connection_info_method_id,
            std::move(*trusttunnel_config)
    );

    return (jlong) ctx.release();
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_adguard_trusttunnel_VpnClient_startNative(JNIEnv *env, jobject thiz, jlong native_ptr, jint tun_fd) {
    if (!native_ptr) {
        errlog(g_logger, "Nothing to start, create VpnClient first");
        return (jboolean) false;
    }
    auto ctx = (VpnCtx *) native_ptr;

    auto error = ctx->get_native_client().connect(ag::TrustTunnelClient::UseTunnelFd{ag::AutoFd::adopt_fd(tun_fd)});
    if (error) {
        errlog(g_logger, "Failed to connect: {}", error->pretty_str());
        return (jboolean) false;
    }
    return (jboolean) true;
}

extern "C"
JNIEXPORT void JNICALL
Java_com_adguard_trusttunnel_VpnClient_stopNative(JNIEnv *env, jobject thiz, jlong native_ptr) {
    if (!native_ptr) {
        warnlog(g_logger, "Nothing to stop, VpnClient is not created");
        return;
    }
    auto *ctx = (VpnCtx *) native_ptr;

    ctx->get_native_client().disconnect();
}

extern "C"
JNIEXPORT void JNICALL
Java_com_adguard_trusttunnel_VpnClient_destroyNative(JNIEnv *env, jobject thiz, jlong native_ptr) {
    if (!native_ptr) {
        warnlog(g_logger, "VpnClient has been already destroyed");
        return;
    }
    delete (VpnCtx *) native_ptr;
}
extern "C"
JNIEXPORT void JNICALL
Java_com_adguard_trusttunnel_VpnClient_notifyNetworkChangeNative(JNIEnv *env, jobject thiz,
                                                                 jlong native_ptr, jboolean available) {
    if (!native_ptr) {
        errlog(g_logger, "VpnClient is not created");
        return;
    }
    auto *ctx = (VpnCtx *) native_ptr;

    ctx->get_native_client().notify_network_change(available ? ag::VpnNetworkState::VPN_NS_CONNECTED : ag::VpnNetworkState::VPN_NS_NOT_CONNECTED);
}
extern "C"
JNIEXPORT jboolean JNICALL
Java_com_adguard_trusttunnel_VpnClient_setSystemDnsServersNative(JNIEnv *env, jobject thiz,
                                                                 jobjectArray servers,
                                                                 jobjectArray bootstraps) {
    size_t num_servers = env->GetArrayLength(servers);
    size_t num_bootstraps = bootstraps != nullptr
                            ? num_bootstraps = env->GetArrayLength(bootstraps) : 0;

    ag::SystemDnsServers c_servers;
    c_servers.main.reserve(num_servers);
    c_servers.bootstrap.reserve(num_bootstraps);

    for (size_t i = 0; i < num_servers; i++) {
        LocalRef<jstring> jserver = {env, (jstring) (env->GetObjectArrayElement(servers, i))};
        const char *str = env->GetStringUTFChars(jserver.get(), nullptr);
        c_servers.main.emplace_back(ag::SystemDnsServer{
                .address = {str, size_t(env->GetStringUTFLength(jserver.get()))},
        });
        env->ReleaseStringUTFChars(jserver.get(), str);
    }

    for (size_t i = 0; i < num_bootstraps; i++) {
        LocalRef<jstring> jbootstrap = {env, (jstring) env->GetObjectArrayElement(bootstraps, i)};
        const char *str = env->GetStringUTFChars(jbootstrap.get(), nullptr);
        c_servers.bootstrap.emplace_back(std::string{str, size_t(env->GetStringUTFLength(jbootstrap.get()))});
        env->ReleaseStringUTFChars(jbootstrap.get(), str);
    }

    return ag::vpn_network_manager_update_system_dns(std::move(c_servers));
}
extern "C"
JNIEXPORT jobjectArray JNICALL
Java_com_adguard_trusttunnel_VpnClient_excludeCidr(JNIEnv *env, jclass clazz,
                                                   jobjectArray included_routes,
                                                   jobjectArray excluded_routes) {
    size_t num_included = env->GetArrayLength(included_routes);
    std::vector<ag::CidrRange> included_ranges;
    included_ranges.reserve(num_included);
    for (size_t i = 0; i < num_included; i++) {
        LocalRef<jstring> route = {env, (jstring) (env->GetObjectArrayElement(included_routes, (jsize) i))};
        if (!route) {
            errlog(g_logger, "Failed to get CIDR ranges to process");
            return nullptr;
        }
        const char *str = env->GetStringUTFChars(route.get(), nullptr);
        included_ranges.emplace_back(str);
        env->ReleaseStringUTFChars(route.get(), str);
    }
    size_t num_excluded = env->GetArrayLength(excluded_routes);
    std::vector<ag::CidrRange> excluded_ranges;
    excluded_ranges.reserve(num_excluded);
    for (size_t i = 0; i < num_excluded; i++) {
        LocalRef<jstring> route = {env, (jstring) (env->GetObjectArrayElement(excluded_routes, (jsize) i))};
        if (!route) {
            errlog(g_logger, "Failed to get CIDR ranges to process");
            return nullptr;
        }
        const char *str = env->GetStringUTFChars(route.get(), nullptr);
        excluded_ranges.emplace_back(str);
        env->ReleaseStringUTFChars(route.get(), str);
    }

    std::vector<ag::CidrRange> result = ag::CidrRange::exclude(included_ranges, excluded_ranges);

    jclass stringclass = env->FindClass("java/lang/String");
    if (!stringclass) {
        errlog(g_logger, "Failed to find string class, can't process CIDR ranges");
        return nullptr;
    }

    LocalRef<jobjectArray> jresult{env, env->NewObjectArray((jsize) result.size(), stringclass, nullptr)};
    if (!jresult) {
        errlog(g_logger, "Failed to create objectArray class, can't process CIDR ranges");
        return nullptr;
    }
    for (size_t i = 0; i < result.size(); i++) {
        LocalRef<jstring> str = jni_safe_new_string_utf(env, result[i].to_string());
        env->SetObjectArrayElement(jresult.get(), i, str.get());
    }
    return jresult.release();
}