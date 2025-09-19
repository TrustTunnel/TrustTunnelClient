#include "vpn/standalone/client.h"
#include "net/network_manager.h"

#include "jni_utils.h"
#include <jni.h>

static ag::Logger g_logger("TrustTunnelJni");

class VpnCtx {
public:
    VpnCtx(JNIEnv *env, jobject callback_object, jmethodID protect_socket_callback, jmethodID verify_callback, jmethodID state_changed_callback, ag::VpnStandaloneConfig &&config)
        : m_protect_socket_callback(protect_socket_callback)
        , m_verify_callback(verify_callback)
        , m_state_changed_callback(state_changed_callback)
        , m_standalone_client(std::move(config), create_callbacks()) {
            env->GetJavaVM(&m_vm);
            this->m_callback_object = {m_vm, callback_object};
        }

    ag::VpnStandaloneClient &get_standalone() {
        return m_standalone_client;
    }
private:
    GlobalRef<jobject> m_callback_object;
    JavaVM *m_vm = nullptr;
    jmethodID m_protect_socket_callback = nullptr;
    jmethodID m_verify_callback = nullptr;
    jmethodID m_state_changed_callback = nullptr;

    ag::VpnStandaloneClient m_standalone_client;

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

    std::string_view conf = env->GetStringUTFChars(config, nullptr);
    toml::parse_result parse_result = toml::parse(conf);
    if (!parse_result) {
        errlog(g_logger, "Failed to parse configuration: {}", parse_result.error().description());
        return 1;
    }
    auto standalone_config = ag::VpnStandaloneConfig::build_config(parse_result);
    if (!standalone_config) {
        errlog(g_logger, "Failed to process configuration");
        return 0;
    }

    auto ctx = std::make_unique<VpnCtx>(
            env, thiz,
            protect_socket_method_id, verify_certificate_method_id, state_changed_method_id,
            std::move(*standalone_config)
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

    auto error = ctx->get_standalone().connect(std::chrono::seconds(10),
                                                ag::VpnStandaloneClient::UseTunnelFd{ag::AutoFd{tun_fd}});
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

    ctx->get_standalone().disconnect();
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

    ctx->get_standalone().notify_network_change(available ? ag::VpnNetworkState::VPN_NS_CONNECTED : ag::VpnNetworkState::VPN_NS_NOT_CONNECTED);
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