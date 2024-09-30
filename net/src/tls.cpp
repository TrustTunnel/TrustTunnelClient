#include "net/tls.h"
#include "vpn/utils.h"

#ifndef _WIN32
#include <netinet/in.h>
#else
#include <winsock2.h>
#endif

#if defined __APPLE__ && defined __MACH__
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <TargetConditionals.h>
#endif

#include <cassert>
#include <cstring>

#include <openssl/x509v3.h>

namespace ag {

#if defined __APPLE__ && defined __MACH__ && TARGET_OS_IPHONE

X509_STORE *tls_create_ca_store() {
    assert(0);
    return nullptr;
}

#elif defined __APPLE__ && defined __MACH__

X509_STORE *tls_create_ca_store() {
    X509_STORE *store = X509_STORE_new();
    if (store == nullptr) {
        return nullptr;
    }

    CFArrayRef anchors;
    OSStatus r = SecTrustCopyAnchorCertificates(&anchors);
    if (r != errSecSuccess) {
        return nullptr;
    }

    for (CFIndex i = 0; i < CFArrayGetCount(anchors); i++) {
        SecCertificateRef current_cert = (SecCertificateRef) CFArrayGetValueAtIndex(anchors, i);
        if (current_cert == nullptr) {
            continue;
        }

        CFDataRef cert_data = SecCertificateCopyData(current_cert);
        if (cert_data == nullptr) {
            continue;
        }

        X509 *xcert = nullptr;
        const uint8_t *ptr = CFDataGetBytePtr(cert_data);
        d2i_X509(&xcert, &ptr, CFDataGetLength(cert_data));
        if (xcert != nullptr) {
            X509_STORE_add_cert(store, xcert);
            X509_free(xcert);
        }

        CFRelease(cert_data);
    }

    CFRelease(anchors);

    return store;
}

#elif defined _WIN32

X509_STORE *tls_create_ca_store() {
    X509_STORE *store = X509_STORE_new();
    X509_STORE_set_default_paths(store);
    return store;
}

#else

#include <dirent.h>

#include <cstdlib>
#include <string_view>

#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

static bool dir_exists_and_not_empty(const char *path) {
    bool ret = false;
    if (auto *dir = opendir(path)) {
        while (auto *ent = readdir(dir)) {
#ifdef __linux__
            std::string_view name{ent->d_name};
#else
            std::string_view name{ent->d_name, ent->d_namlen};
#endif
            if (name == "." || name == "..") {
                continue;
            }
            ret = true;
            break;
        }
        closedir(dir);
    }
    return ret;
}

static int add_lookup_dir(X509_LOOKUP *lookup, const char *name, int type) {
    return dir_exists_and_not_empty(name) && X509_LOOKUP_add_dir(lookup, name, type);
}

X509_STORE *tls_create_ca_store() {
    X509_STORE *store = X509_STORE_new();

    X509_LOOKUP *lookup_f = X509_STORE_add_lookup(store, X509_LOOKUP_file());
    X509_LOOKUP *lookup_d = X509_STORE_add_lookup(store, X509_LOOKUP_hash_dir());
    const char *ssl_cert_file = getenv("SSL_CERT_FILE");
    const char *ssl_cert_dir = getenv("SSL_CERT_DIR");

    // Prefer file/directory locations from environment:
    if (ssl_cert_file || ssl_cert_dir) {
        if (lookup_f && ssl_cert_file) {
            X509_LOOKUP_load_file(lookup_f, ssl_cert_file, X509_FILETYPE_PEM);
        }
        if (lookup_d && ssl_cert_dir) {
            X509_LOOKUP_add_dir(lookup_d, ssl_cert_dir, X509_FILETYPE_PEM);
        }
        // Otherwise, load the first non-empty, valid file:
    } else if (!lookup_f
            || (!X509_LOOKUP_load_file(lookup_f, "/etc/ssl/cert.pem", X509_FILETYPE_PEM)
                    && !X509_LOOKUP_load_file(lookup_f, "/etc/pki/tls/cert.pem", X509_FILETYPE_PEM)
                    && !X509_LOOKUP_load_file(lookup_f, "/opt/etc/ssl/cert.pem", X509_FILETYPE_PEM)
                    && !X509_LOOKUP_load_file(lookup_f, "/opt/etc/ssl/certs/ca-certificates.crt", X509_FILETYPE_PEM))) {
        // Otherwise, add the first non-empty dir:
        if (!lookup_d
                || (!add_lookup_dir(lookup_d, "/etc/ssl/certs/", X509_FILETYPE_PEM)
                        && !add_lookup_dir(lookup_d, "/etc/pki/tls/certs/", X509_FILETYPE_PEM)
                        && !add_lookup_dir(lookup_d, "/opt/etc/ssl/certs/", X509_FILETYPE_PEM))) {
            // Finally, use the defaults.
            X509_STORE_set_default_paths(store);
        }
    }

    return store;
}

#endif // defined __APPLE__ && defined __MACH__ && TARGET_OS_IPHONE

X509 *tls_get_cert(X509_STORE_CTX *ctx) {
    X509 *cert = X509_STORE_CTX_get0_cert(ctx);
    return cert;
}

STACK_OF(X509) * tls_get_chain(X509_STORE_CTX *ctx) {
    STACK_OF(X509) *chain = X509_STORE_CTX_get0_untrusted(ctx);
    return chain;
}

static bool tls_serialize0_cert(X509 *cert, TlsCert *out_cert) {
    int size = i2d_X509(cert, nullptr);
    if (size > 0) {
        out_cert->size = size;
        out_cert->data = new uint8_t[size];
        auto *o = (unsigned char *) out_cert->data;
        i2d_X509(cert, &o);
        return true;
    }
    return false;
}

static void tls_free_serialized0_cert(TlsCert *cert) {
    delete[] cert->data;
}

TlsCert *tls_serialize_cert(X509 *cert) {
    ag::DeclPtr<TlsCert, &tls_free_serialized_cert> out{new TlsCert{}};
    if (tls_serialize0_cert(cert, out.get())) {
        return out.release();
    }
    return nullptr;
}

void tls_free_serialized_cert(TlsCert *cert) {
    if (cert) {
        tls_free_serialized0_cert(cert);
        delete cert;
    }
}

TlsChain *tls_serialize_cert_chain(STACK_OF(X509) * chain) {
    ag::DeclPtr<TlsChain, &tls_free_serialized_chain> out{new TlsChain{}};

    out->size = sk_X509_num(chain);
    out->data = new TlsCert[out->size];

    for (size_t i = 0; i < out->size; ++i) {
        X509 *x = sk_X509_value(chain, i);
        if (!tls_serialize0_cert(x, &out->data[i])) {
            return nullptr;
        }
    }

    return out.release();
}

void tls_free_serialized_chain(TlsChain *chain) {
    if (chain) {
        for (uint32_t i = 0; i < chain->size; ++i) {
            tls_free_serialized0_cert(&chain->data[i]);
        }
        delete[] chain->data;
        delete chain;
    }
}

bool tls_verify_cert_host_name(X509 *cert, const char *host) {
    uint32_t flags = X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT;
    return 1 == X509_check_host(cert, host, strlen(host), flags, nullptr);
}

bool tls_verify_cert_ip(X509 *cert, const char *ip) {
    return 1 == X509_check_ip_asc(cert, ip, X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT);
}

const char *tls_verify_cert(X509_STORE_CTX *ctx_template, X509_STORE *orig_store) {
    const char *err = nullptr;

    X509_STORE *store = orig_store;
    if (store == nullptr) {
        store = tls_create_ca_store();
    }
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();

    if (0
            == X509_STORE_CTX_init(
                    ctx, store, X509_STORE_CTX_get0_cert(ctx_template), X509_STORE_CTX_get0_untrusted(ctx_template))) {
        err = "Can't verify certificate chain: can't initialize STORE_CTX";
        goto finish;
    }
    if (0 == X509_STORE_CTX_set_purpose(ctx, X509_PURPOSE_SSL_SERVER)) {
        err = "Can't verify certificate chain: can't set STORE_CTX purpose";
        goto finish;
    }
    if (0 >= X509_verify_cert(ctx)) {
        err = X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx));
        goto finish;
    }

finish:
    X509_STORE_CTX_free(ctx);
    if (orig_store == nullptr) {
        X509_STORE_free(store);
    }
    return err;
}

typedef enum {
    CT_HANDSHAKE = 22,
} RecType;

typedef enum {
    HS_CLIENT_HELLO = 1,
    HS_SERVER_HELLO = 2,
    HS_CERTIFICATE = 11,
    HS_SERVER_KEY_EXCHANGE = 12,
    HS_CERTIFICATE_REQUEST = 13,
    HS_SERVER_HELLO_DONE = 14,
} HshakeType;

typedef enum {
    SNI_HOST_NAME = 0, // uint8_t hostname[]
} NameType;

#pragma pack(push, 1)

typedef struct {
    uint8_t type; // enum rec_type_t
    uint16_t ver; // 3,1 - TLSv1.0
    uint16_t len;
    uint8_t data[0];
} Rec;

typedef struct {
    uint8_t type; // enum hshake_type_t
    uint8_t len[3];
    uint8_t data[0];
} Hshake;

typedef struct {
    uint8_t len; // 0..32
    uint8_t data[0];
} SessId;

typedef struct {
    uint16_t ver;
    uint8_t random[32];
    SessId session_id;
    // cipher_suites; 2-byte length + data
    // compression_methods; 2-byte length + data
    // exts; 2-byte length + data
} ClientHello;

typedef enum {
    EXT_SERVER_NAME = 0,
} ExtensionType;

typedef struct {
    uint16_t type; // enum extension_type_t
    uint16_t len;
    uint8_t data[0];
} Ext;

typedef struct {
    uint8_t type; // enum name_type_t
    uint16_t len;
    uint8_t data[0];
} ServName;

#pragma pack(pop)

static int datalen8(const uint8_t *d, const uint8_t *end) {
    if (1 > end - d) {
        return -1;
    }

    int n = d[0];
    if (d + 1 + n > end) {
        return -1;
    }

    return n;
}

static int datalen16(const uint8_t *d, const uint8_t *end) {
    if (2 > end - d) {
        return -1;
    }

    int n = ntohs(*(uint16_t *) d);
    if (d + 2 + n > end) {
        return -1;
    }

    return n;
}

static int datalen24(const uint8_t *d, const uint8_t *end) {
    if (3 > end - d) {
        return -1;
    }

    uint32_t x = 0;
    std::memcpy(&x, d, 3);
    uint32_t n = ntoh_24(x);
    if (d + 3 + n > end) {
        return -1;
    }

    return int(n);
}

/**
Return enum rec_type_t;  <=0 on error. */
static int rec_parse(TlsReader *reader, U8View data) {
    const auto *rec = (Rec *) data.data();
    if (data.size() >= 2 && rec->type != CT_HANDSHAKE) {
        return -1;
    }

    if (sizeof(Rec) > data.size()) {
        return 0;
    }

    int n = ntohs(rec->len);
    if (sizeof(Rec) + n > data.size()) {
        return 0;
    }

    int ver = ntohs(rec->ver);
    if (ver < 0x0301) {
        return -1;
    }

    reader->rec = {rec->data, size_t(n)};
    reader->in.remove_prefix(sizeof(Rec) + reader->rec.size());
    return rec->type;
}

/**
Return enum hshake_type_t;  <=0 on error. */
static int hshake_parse(TlsReader *reader, U8View data) {
    if (sizeof(Hshake) > data.size()) {
        return 0;
    }

    const auto *h = (Hshake *) data.data();
    uint32_t x = 0;
    static_assert(sizeof(std::declval<decltype(h)>()->len) == 3);
    std::memcpy(&x, (void *)h->len, 3);
    uint32_t n = ntoh_24(x);
    if (n > data.size() - 1) {
        return 0;
    }

    reader->rec.remove_prefix(sizeof(Hshake) + n);
    reader->buf = {h->data, size_t(n)};
    return h->type;
}

/**
Return 1 on success;  <=0 on error. */
static int hello_parse(TlsReader *reader, U8View data) {
    if (sizeof(ClientHello) > data.size()) {
        return 0;
    }

    const auto *c = (ClientHello *) data.data();

    const uint8_t *end = data.data() + data.size();
    if (c->session_id.len > end - c->session_id.data) {
        return 0;
    }

    const uint8_t *d = c->session_id.data + c->session_id.len;

    // cipher_suite[]
    int size = datalen16(d, end);
    if (size < 0) {
        return 0;
    }

    d += 2 + size;

    // comp_meth[]
    size = datalen8(d, end);
    if (size < 0) {
        return 0;
    }

    d += 1 + size;

    reader->buf = {d, size_t(end - d)};
    return 1;
}

/**
Return TLS_RCLIENT_HELLO_SNI or TLS_RDONE;  0 on error. */
static int ext_servname_parse(TlsReader *reader, const uint8_t *data, size_t len) {
    const uint8_t *end = data + len;
    int size = datalen16(data, end);
    if (size < 0) {
        return 0;
    }

    const uint8_t *d = data + 2;
    end = d + size;

    for (;;) {
        const auto *sn = (ServName *) d;
        if ((int) sizeof(ServName) > end - d) {
            break;
        }

        int n = ntohs(sn->len);
        if (sn->data + n > end) {
            return 0;
        }

        if (sn->type == SNI_HOST_NAME) {
            reader->tls_hostname = {(char *) sn->data, size_t(n)};
            return TLS_RCLIENT_HELLO_SNI;
        }

        d = sn->data + n;
    }

    return TLS_RDONE;
}

/** Parse TLS extension.
Return TLS_RCLIENT_HELLO_SNI or TLS_RDONE on success;  <=0 on error. */
static int ext_parse(TlsReader *reader, U8View &data) {
    const uint8_t *end = data.data() + data.size();
    if ((int) sizeof(Ext) > end - data.data()) {
        return TLS_RERR;
    }

    const auto *ext = (Ext *) data.data();
    uint16_t n = ntohs(ext->len);
    if (ext->data + n > end) {
        return TLS_RERR;
    }

    int r = TLS_RDONE;
    auto type = (ExtensionType) ntohs(ext->type);
    switch (type) {
    case EXT_SERVER_NAME:
        r = ext_servname_parse(reader, ext->data, n);
        break;
    }

    data = {ext->data + n, size_t(end - ext->data - n)};
    return r;
}

/** Get data for TLS extensions.
Return TLS_RDONE on success;  0 on error. */
static int exts_data(TlsReader *reader, U8View data) {
    const uint8_t *end = data.data() + data.size();

    int size = datalen16(data.data(), end);
    if (size < 0) {
        return 0;
    }

    data.remove_prefix(2);
    reader->buf = data;

    return TLS_RDONE;
}

/** Get X509 object from raw data. */
static X509 *ossl_cert_decode(const uint8_t *data, size_t len) {
    BIO *b = BIO_new(BIO_s_mem());
    if (b == nullptr) {
        return nullptr;
    }

    BIO_write(b, data, len);
    X509 *x = d2i_X509_bio(b, nullptr);
    BIO_free(b);
    return x;
}

/** Set subject.CN data. */
static int ossl_cert_subj_CN(TlsReader *reader, X509 *x) {
    X509_NAME *subj = X509_get_subject_name(x);
    if (subj == nullptr) {
        return -1;
    }

    reader->x509_subject_common_name.resize(1024);
    int n = X509_NAME_get_text_by_NID(subj, NID_commonName, reader->x509_subject_common_name.data(),
            int(reader->x509_subject_common_name.size()));
    if (n < 0) {
        reader->x509_subject_common_name.resize(0);
        return -1;
    }

    reader->x509_subject_common_name.resize(n);
    return 0;
}

/** Parse certificates.
Note: returns early after the first certificate.
Return TLS_RCERT or TLS_RDONE on success;  <=0 on error. */
static int certs_parse(TlsReader *reader, U8View data) {
    const uint8_t *end = data.data() + data.size();
    int size = datalen24(data.data(), end);
    if (size < 0) {
        return 0;
    }

    const uint8_t *d = data.data() + 3;
    end = d + size;

    size = datalen24(d, end);
    if (size < 0) {
        return 0;
    }

    d += 3;

    X509 *x = ossl_cert_decode(d, size);
    if (x == nullptr) {
        return -1;
    }

    int r = ossl_cert_subj_CN(reader, x);
    X509_free(x);
    if (r != 0) {
        return -1;
    }

    return TLS_RCERT;
}

TlsParseResult tls_parse(TlsReader *reader) {
    enum {
        I_REC,
        I_HSHAKE,
        I_CLIHEL,
        I_CLIHEL_EXTS,
        I_CLIHEL_EXT,
        I_CERTS,
    };
    int r;

    for (;;) {
        switch (reader->state) {

        case I_REC:
            r = rec_parse(reader, reader->in);
            if (r == 0) {
                return TLS_RMORE;
            } else if (r < 0) {
                return TLS_RERR;
            }

            switch (r) {
            case CT_HANDSHAKE:
                reader->state = I_HSHAKE;
                continue;
            default:
                return TLS_RERR; // not supported
            }
            break;

        case I_HSHAKE:
            if (reader->rec.empty()) {
                reader->state = I_REC;
                return TLS_RDONE;
            }
            r = hshake_parse(reader, reader->rec);
            if (r <= 0) {
                return TLS_RERR;
            }

            switch (r) {
            case HS_CLIENT_HELLO:
                reader->state = I_CLIHEL;
                continue;
            case HS_SERVER_HELLO:
                reader->state = I_HSHAKE;
                return TLS_RSERV_HELLO;
            case HS_CERTIFICATE:
                reader->state = I_CERTS;
                continue;
            case HS_SERVER_KEY_EXCHANGE:
            case HS_CERTIFICATE_REQUEST:
            case HS_SERVER_HELLO_DONE:
                reader->state = I_HSHAKE;
                return TLS_RDONE;
            default:
                return TLS_RERR; // not supported
            }
            break;

        case I_CLIHEL:
            r = hello_parse(reader, reader->buf);
            if (r <= 0) {
                return TLS_RERR;
            }

            reader->state = I_CLIHEL_EXTS;
            return TLS_RCLIENT_HELLO;

        case I_CLIHEL_EXTS:
            r = exts_data(reader, reader->buf);
            if (r <= 0) {
                return TLS_RERR;
            }

            reader->state = I_CLIHEL_EXT;
            break;

        case I_CLIHEL_EXT:
            if (reader->buf.empty()) {
                reader->state = I_HSHAKE;
                continue;
            }

            r = ext_parse(reader, reader->buf);
            if (r <= 0) {
                return TLS_RERR;
            } else if (r != TLS_RDONE) {
                return (TlsParseResult) r;
            }

            break;

        case I_CERTS:
            r = certs_parse(reader, reader->buf);
            if (r <= 0) {
                return TLS_RERR;
            }

            reader->state = I_HSHAKE;
            return TLS_RCERT;
        }
    }
}

} // namespace ag
