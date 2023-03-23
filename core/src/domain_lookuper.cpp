#include "vpn/internal/domain_lookuper.h"

#include <cassert>
#include <memory>
#include <string_view>
#include <vector>

#include "net/tls.h"
#include "vpn/internal/utils.h"

namespace ag {

struct Parser { // NOLINT(cppcoreguidelines-special-member-functions,hicpp-special-member-functions)
    virtual ~Parser() = default;
    virtual DomainLookuperResult parse(DomainLookuperPacketDirection dir, std::vector<uint8_t> *buffer) = 0;
};

struct QuicParser : public Parser {

    TlsReader reader = {};

    ~QuicParser() override = default;

    DomainLookuperResult parse(DomainLookuperPacketDirection dir, std::vector<uint8_t> *buffer) override {

        if (dir != DLUPD_OUTGOING) {
            return {DLUS_NOTFOUND}; // not TLS
        }

        tls_input_hshake(&this->reader, buffer->data(), buffer->size());

        bool got_sni = false;
        bool stop = false;
        while (!stop) {
            TlsParseResult r = tls_parse(&this->reader);
            switch (r) {
            case TlsParseResult::TLS_RCLIENT_HELLO_SNI:
                got_sni = true;
                [[fallthrough]];
            case TlsParseResult::TLS_RERR:
            case TlsParseResult::TLS_RMORE:
            case TlsParseResult::TLS_RDONE:
                stop = true;
                break;
            default:
                continue;
            }
        }
        if (got_sni) {
            return {DLUS_FOUND, {this->reader.tls_hostname.data(), this->reader.tls_hostname.size()}};
        }
        return {DLUS_NOTFOUND};
    }
};

struct TlsParser : public Parser { // NOLINT(cppcoreguidelines-special-member-functions,hicpp-special-member-functions)
    enum State {
        TPS_IDLE,
        TPS_SERVER_HELLO,
        TPS_CERT,
    };

    State state = TPS_IDLE;
    TlsReader reader = {};
    size_t buffer_offset = 0;

    ~TlsParser() override = default;

    [[nodiscard]] DomainLookuperResult parse_cert_to_lookuper_result(TlsParseResult r) const {
        switch (r) {
        case TLS_RMORE:
            return {DLUS_PASS};
        case TLS_RCERT:
            return {DLUS_FOUND, this->reader.x509_subject_common_name};
        case TLS_RSERV_HELLO:
            return {DLUS_PASS};
        default:
            return {DLUS_NOTFOUND};
        }
    }

    DomainLookuperResult parse(DomainLookuperPacketDirection dir, std::vector<uint8_t> *buffer) override {
        switch (this->state) {
        case TPS_IDLE: {
            if (dir != DLUPD_OUTGOING) {
                break; // not TLS
            }

            tls_input(&this->reader, buffer->data(), buffer->size());
            this->buffer_offset = 0;
            TlsParseResult r = tls_parse(&this->reader);
            switch (r) {
            case TLS_RCLIENT_HELLO:
                r = tls_parse(&this->reader);
                if (r == TLS_RCLIENT_HELLO_SNI && !this->reader.tls_hostname.empty()) {
                    DomainLookuperResult result = {
                            DLUS_FOUND, {this->reader.tls_hostname.data(), this->reader.tls_hostname.size()}};
                    buffer->clear();
                    return result;
                }
                this->state = TPS_SERVER_HELLO;
                buffer->clear();
                return {DLUS_PASS};
            case TLS_RMORE:
                return {DLUS_WANT_MORE};
            default:
                break;
            }
            break;
        }
        case TPS_SERVER_HELLO: {
            if (dir == DLUPD_OUTGOING) {
                return {DLUS_PASS};
            }

            this->reader = {};
            tls_input(&this->reader, buffer->data(), buffer->size());

            TlsParseResult r = tls_parse(&this->reader);
            switch (r) {
            case TLS_RSERV_HELLO:
                this->state = TPS_CERT;
                break;
            case TLS_RMORE:
            default: // not a server hello
                return {DLUS_PASS};
            }

            this->buffer_offset = this->reader.in.data() - buffer->data();
            r = tls_parse(&this->reader);
            if (r != TLS_RDONE) {
                return parse_cert_to_lookuper_result(r);
            }
            [[fallthrough]];
        }
        case TPS_CERT: {
            if (dir == DLUPD_OUTGOING) {
                return {DLUS_PASS};
            }

            tls_input(&this->reader, buffer->data() + this->buffer_offset, buffer->size() - this->buffer_offset);
            TlsParseResult r = tls_parse(&this->reader);
            return parse_cert_to_lookuper_result(r);
        }
        }

        return {DLUS_NOTFOUND};
    }
};

struct HttpParser : public Parser {
    ~HttpParser() override = default;

    DomainLookuperResult parse(DomainLookuperPacketDirection, std::vector<uint8_t> *buffer) override {
        static constexpr size_t MIN_METHOD_LENGTH = 3;
        static constexpr size_t MAX_METHOD_LENGTH = 32;

        // check method
        size_t i;
        for (i = 0; i < buffer->size(); ++i) {
            int ch = (*buffer)[i];
            if (isspace((unsigned char) ch)) {
                break;
            }
            if (!isalpha((unsigned char) ch) || i == MAX_METHOD_LENGTH) {
                return {DLUS_NOTFOUND};
            }
        }

        if (i < MIN_METHOD_LENGTH) {
            return {DLUS_NOTFOUND};
        }

        static constexpr std::string_view HOST_MARKER = "Host:";
        std::string_view seek = {(char *) buffer->data() + i, buffer->size() - i};
        if (size_t host_header_pos, host_start, host_end; seek.npos != (host_header_pos = seek.find(HOST_MARKER))
                && host_header_pos + HOST_MARKER.length() < seek.length()
                && seek.npos != (host_start = seek.find_first_not_of(" \t", host_header_pos + HOST_MARKER.length()))
                && seek.npos != (host_end = seek.find_first_of("\r\n", host_start)) && host_start < host_end) {
            return {DLUS_FOUND, {seek.data() + host_start, seek.data() + host_end}};
        }
        if (size_t uri_start; // try extract host from uri
                seek.npos != (uri_start = seek.find_first_not_of(" \t")) && seek[uri_start] != '/') {
            static constexpr std::string_view SCHEME_MARKER = "://";
            size_t host_start = seek.find(SCHEME_MARKER, uri_start);
            if (host_start == seek.npos) {
                host_start = uri_start;
            } else if (host_start + SCHEME_MARKER.length() >= seek.length()) {
                return {DLUS_NOTFOUND};
            } else {
                host_start += SCHEME_MARKER.length();
            }
            size_t host_end = seek.find_first_of(":/ \t", host_start);
            if (host_end != seek.npos) {
                return {DLUS_FOUND, {seek.data() + host_start, seek.data() + host_end}};
            }
        }

        return {DLUS_NOTFOUND};
    }
};

struct ParserFactory {
    size_t idx = 0;
    using ParserProducer = std::unique_ptr<Parser> (*)();
    static constexpr ParserProducer PRODUCE_TABLE_TCP[] = {
            []() -> std::unique_ptr<Parser> {
                return std::make_unique<TlsParser>();
            },
            []() -> std::unique_ptr<Parser> {
                return std::make_unique<HttpParser>();
            },
    };

    static constexpr ParserProducer PRODUCE_TABLE_UDP[] = {
            []() -> std::unique_ptr<Parser> {
                return std::make_unique<QuicParser>();
            },
    };

    std::unique_ptr<Parser> produce(int proto) {
        if (proto == IPPROTO_TCP) {
            size_t TABLE_SIZE = std::size(PRODUCE_TABLE_TCP);
            if (this->idx >= TABLE_SIZE) {
                return nullptr;
            }
            return PRODUCE_TABLE_TCP[this->idx++]();
        } else {
            size_t TABLE_SIZE = std::size(PRODUCE_TABLE_UDP);
            if (this->idx >= TABLE_SIZE) {
                return nullptr;
            }
            return PRODUCE_TABLE_UDP[this->idx++]();
        }
    }
};

struct DomainLookuper::Context {
    explicit Context(int proto): proto(proto) {};
    int proto {};
    ParserFactory factory = {};
    std::unique_ptr<Parser> current_parser = factory.produce(proto);
    std::vector<uint8_t> buffer;

    DomainLookuperResult parse(DomainLookuperPacketDirection dir, const uint8_t *data, size_t length);
};

DomainLookuperResult DomainLookuper::Context::parse(
        DomainLookuperPacketDirection dir, const uint8_t *data, size_t length) {
    this->buffer.insert(this->buffer.end(), data, data + length);

    while (this->current_parser != nullptr) {
        DomainLookuperResult r = this->current_parser->parse(dir, &this->buffer);
        switch (r.status) {
        case DLUS_WANT_MORE:
        case DLUS_FOUND:
        case DLUS_PASS:
            return r;
        case DLUS_NOTFOUND:
            this->current_parser = this->factory.produce(proto);
            break;
        }
    }

    return {DLUS_NOTFOUND, ""};
}

DomainLookuperResult DomainLookuper::proceed(DomainLookuperPacketDirection dir, int proto, const uint8_t *data, size_t length) {
    if (m_context == nullptr) {
        m_context = std::make_unique<DomainLookuper::Context>(proto);
    }

    DomainLookuperResult r = m_context->parse(dir, data, length);
    return r;
}

void DomainLookuper::reset() {
    m_context.reset();
}

DomainLookuper::DomainLookuper() = default;
DomainLookuper::~DomainLookuper() = default;

} // namespace ag
