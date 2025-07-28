#pragma once

#include <memory>
#include <cassert>

#include <pthread.h>
#include <jni.h>
#include <openssl/x509.h>

/**
 * Attaches the current thread, if necessary, and pushes a local reference frame. Reverses that in dtor.
 */
class ScopedJniEnv {
private:
    JavaVM *m_vm{};
    JNIEnv *m_env{};

public:
    ScopedJniEnv(JavaVM *vm, jint max_local_refs) {
        m_vm = vm;

        int64_t ret = m_vm->GetEnv((void **) &m_env, JNI_VERSION_1_2);
        assert(JNI_EDETACHED == ret || JNI_OK == ret);
        if (JNI_EDETACHED == ret) {
#if __ANDROID__
            ret = m_vm->AttachCurrentThread(&m_env, nullptr);
#else
            ret = m_vm->AttachCurrentThread((void **) &m_env, nullptr);
#endif
            assert(JNI_OK == ret);

            static pthread_key_t tls_key{};
            static pthread_once_t once_control = PTHREAD_ONCE_INIT;
            ret = pthread_once(&once_control, [] {
                [[maybe_unused]] auto ret = pthread_key_create(&tls_key, [](void *arg) {
                    auto vm = (JavaVM *) arg;
                    vm->DetachCurrentThread();
                });
                assert(0 == ret);
            });
            assert(0 == ret);

            ret = pthread_setspecific(tls_key, vm);
            assert(0 == ret);
        }

        ret = m_env->PushLocalFrame(max_local_refs);
        assert(0 == ret);
    }

    ~ScopedJniEnv() {
        m_env->PopLocalFrame(nullptr);
    }

    JNIEnv *get() const {
        return m_env;
    }

    JNIEnv *operator->() const {
        return get();
    }
};

/**
 * NewGlobalRef in ctor, DeleteGlobalRef in dtor.
 */
template <typename T>
class GlobalRef {
private:
    JavaVM *vm{};
    T ref{};

    void delete_global_ref() const {
        if (this->vm) {
            ScopedJniEnv env(this->vm, 1);
            env->DeleteGlobalRef(this->ref);
        }
    }

public:
    GlobalRef() = default;

    GlobalRef(JavaVM *vm, T ref)
            : vm{vm} {
        ScopedJniEnv env(vm, 1);
        this->ref = (T) env->NewGlobalRef(ref);
    }

    GlobalRef(const GlobalRef &other) {
        *this = other;
    }

    GlobalRef &operator=(const GlobalRef &other) {
        if (&other != this) {
            delete_global_ref();
            this->vm = other.vm;
            ScopedJniEnv env(this->vm, 1);
            this->ref = (T) env->NewGlobalRef(other.ref);
        }
        return *this;
    }

    GlobalRef(GlobalRef &&other) noexcept {
        *this = std::move(other);
    }

    GlobalRef &operator=(GlobalRef &&other) noexcept {
        if (&other != this) {
            delete_global_ref();
            this->vm = other.vm;
            this->ref = other.ref;
            other.vm = {};
            other.ref = {};
        }
        return *this;
    }

    ~GlobalRef() {
        delete_global_ref();
    }

    T get() const {
        return this->ref;
    }

    explicit operator bool() {
        return this->ref;
    }

    inline bool operator==(std::nullptr_t) {
        return this->ref == nullptr;
    }

    inline bool operator!=(std::nullptr_t) {
        return this->ref != nullptr;
    }
};

/**
 * DeleteLocalRef in dtor.
 */
template <typename T>
class LocalRef {
private:
    JNIEnv *env{};
    T ref{};

    void delete_local_ref() {
        if (this->env) {
            this->env->DeleteLocalRef(this->ref);
        }
    }

public:
    LocalRef() = default;

    LocalRef(JNIEnv *env, T ref)
            : env{env}
            , ref{ref} {
    }

    LocalRef(JNIEnv *env, const GlobalRef<T> &global)
            : env{env}
            , ref{env->NewLocalRef(global.get())} {
    }

    LocalRef(const LocalRef &) = delete;

    LocalRef &operator=(const LocalRef &) = delete;

    LocalRef(LocalRef &&other) noexcept {
        *this = std::move(other);
    }

    LocalRef &operator=(LocalRef &&other) noexcept {
        if (&other != this) {
            delete_local_ref();
            this->env = other.env;
            this->ref = other.ref;
            other.env = {};
            other.ref = {};
        }
        return *this;
    }

    ~LocalRef() {
        delete_local_ref();
    }

    T get() const {
        return this->ref;
    }

    T release() {
        return std::exchange(this->ref, nullptr);
    }

    explicit operator bool() {
        return this->ref;
    }
};

/**
 * Serialize X509 certificate and put it in java byte array
 * @param env JNI environment
 * @param cert certificate to convert
 * @return java array with serialized certificate
 */
LocalRef<jbyteArray> jni_cert_to_java_array(JNIEnv *env, X509 *cert);

/**
 * Convert c-string to java string (converting it to cesu-8)
 * @param env JNI environment
 * @param utf8 string to convert
 * @return java string
 */
LocalRef<jstring> jni_safe_new_string_utf(JNIEnv *env, std::string_view utf8);