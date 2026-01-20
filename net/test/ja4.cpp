#include "ja4.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define NOCRYPT
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#endif

#include <fmt/format.h>
#include <openssl/sha.h>

// NOLINTBEGIN(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
enum TlsReaderState {
    I_REC,
    I_HSHAKE,
    I_CLIHEL,
    I_CLIHEL_EXTS,
    I_CLIHEL_EXT,
    I_CERTS,
};

using U8View = ag::Uint8View;

static uint32_t ntoh_24(uint32_t x) {
    const auto *b = (uint8_t *) &x;
    return (b[0] << 16) | (b[1] << 8) | b[2];
}

enum TlsParseResult {
    TLS_RERR = 1,
    TLS_RMORE,
    TLS_RDONE,
};

struct TlsReader {
    TlsReaderState state = I_REC;
    U8View in;
    U8View rec;
    U8View buf;
    bool sni_present = false;
    uint16_t hello_version = 0;
    std::vector<uint16_t> supported_versions;
    std::vector<uint16_t> ciphers;
    std::vector<uint16_t> extension_types;
    std::vector<uint16_t> signature_algorithms;
    std::vector<std::string> alpn_protocols;
};

enum RecType {
    CT_HANDSHAKE = 22,
};

enum HshakeType {
    HS_CLIENT_HELLO = 1,
    HS_SERVER_HELLO = 2,
    HS_CERTIFICATE = 11,
    HS_SERVER_KEY_EXCHANGE = 12,
    HS_CERTIFICATE_REQUEST = 13,
    HS_SERVER_HELLO_DONE = 14,
};

#pragma pack(push, 1)

struct Rec {
    uint8_t type; // enum rec_type_t
    uint16_t ver; // 3,1 - TLSv1.0
    uint16_t len;
    uint8_t data[0];
};

struct Hshake {
    uint8_t type; // enum hshake_type_t
    uint8_t len[3];
    uint8_t data[0];
};

struct SessId {
    uint8_t len; // 0..32
    uint8_t data[0];
};

struct ClientHello {
    uint16_t ver;
    uint8_t random[32];
    SessId session_id;
    // cipher_suites; 2-byte length + data
    // compression_methods; 2-byte length + data
    // exts; 2-byte length + data
};

enum ExtensionType : uint16_t {
    EXT_SERVER_NAME = 0,
    EXT_SIG_ALGS = 13,
    EXT_ALPN = 16,
    EXT_SUPP_VERS = 43,
};

struct Ext {
    uint16_t type;
    uint16_t len;
    uint8_t data[0];
};

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

static int read_u16(const uint8_t *d, const uint8_t *end) {
    if (d + 2 > end) {
        return -1;
    }
    uint16_t x = 0;
    std::memcpy(&x, d, 2);
    return ntohs(x);
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
    std::memcpy(&x, (void *) h->len, 3);
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

    reader->hello_version = ntohs(c->ver);

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

    d += 2;

    const uint8_t *ciphers_end = d + size;
    while (d != ciphers_end) {
        int cipher = read_u16(d, ciphers_end);
        if (cipher < 0) {
            return 0;
        }
        reader->ciphers.emplace_back((uint16_t) cipher);
        d += 2;
    }

    // comp_meth[]
    size = datalen8(d, end);
    if (size < 0) {
        return 0;
    }

    d += 1 + size;

    reader->buf = {d, size_t(end - d)};
    return 1;
}

/** Return TLS_RDONE; 0 on error. */
static int ext_servname_parse(TlsReader *reader, const uint8_t *data, size_t len) {
    const uint8_t *end = data + len;
    int size = datalen16(data, end);
    if (size < 0) {
        return 0;
    }

    reader->sni_present = true;

    return TLS_RDONE;
}

/** Get the list of ALPN protocols. Return TLS_RDONE on success;  <=0 on error. */
static int ext_alpn_parse(TlsReader *reader, const uint8_t *data, size_t len) {
    const uint8_t *end = data + len;
    int size = datalen16(data, end);
    if (size < 0) {
        return 0;
    }
    data += 2;
    end = data + size;

    while (data != end) {
        int proto_len = datalen8(data, end);
        if (proto_len < 0) {
            return 0;
        }
        data += 1;
        reader->alpn_protocols.emplace_back((const char *) data, (size_t) proto_len);
        data += proto_len;
    }

    return TLS_RDONE;
}

/** Get the list of signature algorithms. Return TLS_RDONE on success;  <=0 on error. */
static int ext_sigalgs_parse(TlsReader *reader, const uint8_t *data, size_t len) {
    const uint8_t *end = data + len;
    int size = datalen16(data, end);
    if (size < 0) {
        return 0;
    }
    data += 2;
    end = data + size;

    while (data != end) {
        int alg = read_u16(data, end);
        if (alg < 0) {
            return 0;
        }
        reader->signature_algorithms.emplace_back((uint16_t) alg);
        data += 2;
    }

    return TLS_RDONE;
}

/** Get the list of supported versions. Return TLS_RDONE on success;  <=0 on error. */
static int ext_suppvers_parse(TlsReader *reader, const uint8_t *data, size_t len) {
    const uint8_t *end = data + len;
    int size = datalen8(data, end);
    if (size < 0) {
        return 0;
    }
    data += 1;
    end = data + size;

    while (data != end) {
        int ver = read_u16(data, end);
        if (ver < 0) {
            return 0;
        }
        reader->supported_versions.emplace_back((uint16_t) ver);
        data += 2;
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
    case EXT_ALPN:
        r = ext_alpn_parse(reader, ext->data, n);
        break;
    case EXT_SIG_ALGS:
        r = ext_sigalgs_parse(reader, ext->data, n);
        break;
    case EXT_SUPP_VERS:
        r = ext_suppvers_parse(reader, ext->data, n);
        break;
    }
    reader->extension_types.emplace_back((uint16_t) type);

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

static TlsParseResult tls_parse(TlsReader *reader) {
    int r;
    for (;;) {
        switch (reader->state) {
        case I_REC:
            r = rec_parse(reader, reader->in);
            if (r == 0) {
                return TLS_RMORE;
            }
            if (r < 0) {
                return TLS_RERR;
            }

            switch (r) {
            case CT_HANDSHAKE:
                reader->state = I_HSHAKE;
                continue;
            default:
                return TLS_RERR; // not supported
            }

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
                continue;
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

        case I_CLIHEL:
            r = hello_parse(reader, reader->buf);
            if (r <= 0) {
                return TLS_RERR;
            }

            reader->state = I_CLIHEL_EXTS;
            continue;

        case I_CLIHEL_EXTS:
            r = exts_data(reader, reader->buf);
            if (r <= 0) {
                return TLS_RERR;
            }

            reader->state = I_CLIHEL_EXT;
            continue;

        case I_CLIHEL_EXT:
            if (reader->buf.empty()) {
                reader->state = I_HSHAKE;
                continue;
            }

            r = ext_parse(reader, reader->buf);
            if (r <= 0) {
                return TLS_RERR;
            }
            if (r != TLS_RDONE) {
                return (TlsParseResult) r;
            }

            continue;

        case I_CERTS:
            return TLS_RDONE;
        }
    }
}

static bool is_grease(uint16_t val) {
    return ((val >> 8) == (val & 0xff)) && (((val >> 8) & 0x0f) == 0x0a);
}

template <typename It>
static std::string to_hex_list(It begin, It end) {
    std::string ret;
    ret.reserve((end - begin) * 2);
    for (; begin != end; ++begin) {
        fmt::format_to(std::back_inserter(ret), "{:0>4x},", *begin);
    }
    ret.pop_back();
    return ret;
}

static std::string to_hex(U8View data) {
    std::string ret;
    ret.reserve(data.size() * 2);
    for (uint8_t d : data) {
        fmt::format_to(std::back_inserter(ret), "{:0>2x}", d);
    }
    return ret;
}

// https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
static std::string to_ja4(TlsReader *reader, bool quic) {
    // Remove GREASE values from ciphers, extension types, supported versions and signature algorithms.
    for (std::vector<uint16_t> *v :
            {&reader->ciphers, &reader->extension_types, &reader->signature_algorithms, &reader->supported_versions}) {
        // clang-format off
        v->erase(std::remove_if(v->begin(), v->end(), [](uint16_t value) { return is_grease(value); }), v->end());
        // clang-format on
    }

    // Sort ciphers and extension types. Signature algorithms remain in original order.
    std::sort(reader->ciphers.begin(), reader->ciphers.end());
    std::sort(reader->extension_types.begin(), reader->extension_types.end());

    std::string ja4;
    ja4.reserve(36);

    ja4 += quic ? 'q' : 't';

    uint16_t version = reader->hello_version;
    if (!reader->supported_versions.empty()) {
        version = *std::max_element(reader->supported_versions.begin(), reader->supported_versions.end());
    }
    // clang-format off
    switch (version) {
        case 0x0304: ja4 += "13"; break;
        case 0x0303: ja4 += "12"; break;
        case 0x0302: ja4 += "11"; break;
        case 0x0301: ja4 += "10"; break;
        case 0x0300: ja4 += "s3"; break;
        case 0x0200: ja4 += "s2"; break;
        case 0x0100: ja4 += "s1"; break;
        default: ja4 += "00"; break;
    }
    // clang-format on

    ja4 += reader->sni_present ? 'd' : 'i';
    fmt::format_to(std::back_inserter(ja4), "{:0>2}", std::min((size_t) 99, reader->ciphers.size()));
    fmt::format_to(std::back_inserter(ja4), "{:0>2}", std::min((size_t) 99, reader->extension_types.size()));

    if (!reader->alpn_protocols.empty() && !reader->alpn_protocols.front().empty()) {
        ja4 += reader->alpn_protocols.front().front();
        ja4 += reader->alpn_protocols.front().back();
    } else {
        ja4 += "00";
    }

    uint8_t sha_output[SHA256_DIGEST_LENGTH]{};

    ja4 += '_';

    std::string sha_input = to_hex_list(reader->ciphers.begin(), reader->ciphers.end());
    SHA256((uint8_t *) sha_input.data(), sha_input.size(), sha_output);
    std::string sha_output_hex = to_hex({sha_output, sizeof(sha_output)});
    sha_output_hex.resize(12);
    ja4 += sha_output_hex;

    ja4 += '_';

    reader->extension_types.erase(std::remove_if(reader->extension_types.begin(), reader->extension_types.end(),
                                          [](uint16_t ext) {
                                              return ext == EXT_SERVER_NAME || ext == EXT_ALPN;
                                          }),
            reader->extension_types.end());

    sha_input = to_hex_list(reader->extension_types.begin(), reader->extension_types.end());
    if (!reader->signature_algorithms.empty()) {
        sha_input += '_';
        sha_input += to_hex_list(reader->signature_algorithms.begin(), reader->signature_algorithms.end());
    }
    SHA256((uint8_t *) sha_input.data(), sha_input.size(), sha_output);
    sha_output_hex = to_hex({sha_output, sizeof(sha_output)});
    sha_output_hex.resize(12);
    ja4 += sha_output_hex;

    return ja4;
}

/** Set input data. */
#define tls_input(t, d, s) (t)->in = {(uint8_t *) (d), size_t(s)}

/** Setup to parse a handshake record. */
#define tls_input_hshake(t, d, s) (t)->rec = {(uint8_t *) (d), size_t(s)}, (t)->state = I_HSHAKE

std::string ag::ja4::compute(ag::Uint8View data, bool quic) {
    TlsReader reader{.in = data};
    if (quic) {
        tls_input_hshake(&reader, data.data(), data.size());
    } else {
        tls_input(&reader, data.data(), data.size());
    }

    if (int rr = tls_parse(&reader); rr != TLS_RDONE) {
        return "";
    }

    return to_ja4(&reader, quic);
}
// NOLINTEND(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
