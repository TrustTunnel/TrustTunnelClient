#include "net/dns_utils.h"

#include <algorithm>
#include <atomic>
#include <cstring>

#include <ldns/ldns.h>

namespace ag {

static std::atomic<uint16_t> g_next_request_id = 1;

static std::string rdf_to_string(const ldns_rdf *rdf) {
    DeclPtr<char, &free> name{ldns_rdf2str(rdf)};

    std::string_view n = name.get();
    if (ldns_dname_str_absolute(name.get())) {
        n.remove_suffix(1); // drop trailing dot
    }

    return std::string(n);
}

static void add_name_to_answer(dns_utils::DecodedReply &answer, const ldns_rdf *rdf) {
    std::string n = rdf_to_string(rdf);

    if (std::none_of(answer.names.begin(), answer.names.end(), [n](const std::string &i) {
            return n == i;
        })) {
        answer.names.emplace_back(std::move(n));
    }
}

static std::optional<dns_utils::RecordType> ldns_to_utils_rr_type(ldns_rr_type x) {
    switch (x) {
    case LDNS_RR_TYPE_A:
        return dns_utils::RT_A;
    case LDNS_RR_TYPE_AAAA:
        return dns_utils::RT_AAAA;
    default:
        return std::nullopt;
    }
}

static dns_utils::DecodeResult decode_request(ldns_pkt *pkt) {
    const ldns_rr_list *question = ldns_pkt_question(pkt);
    if (ldns_rr_list_rr_count(question) == 0) {
        return dns_utils::InapplicablePacket{ldns_pkt_id(pkt)};
    }

    const ldns_rr *question_rr = ldns_rr_list_rr(question, 0);

    return dns_utils::DecodedRequest{
            .id = ldns_pkt_id(pkt),
            .question_type = ldns_to_utils_rr_type(ldns_rr_get_type(question_rr)),
            .name = rdf_to_string(ldns_rr_owner(question_rr)),
    };
}

static dns_utils::DecodeResult decode_reply(dns_utils::LdnsPktPtr pkt) {
    if (ldns_pkt_get_rcode(pkt.get()) != LDNS_RCODE_NOERROR) {
        return dns_utils::InapplicablePacket{ldns_pkt_id(pkt.get())};
    }

    const ldns_rr_list *question = ldns_pkt_question(pkt.get());
    if (ldns_rr_list_rr_count(question) == 0) {
        return dns_utils::InapplicablePacket{ldns_pkt_id(pkt.get())};
    }

    dns_utils::DecodedReply decoded_answer = {
            .id = ldns_pkt_id(pkt.get()),
            .question_type = ldns_to_utils_rr_type(ldns_rr_get_type(ldns_rr_list_rr(question, 0))),
    };
    const ldns_rr_list *answer = ldns_pkt_answer(pkt.get());
    for (size_t i = 0; i < ldns_rr_list_rr_count(answer); ++i) {
        switch (const ldns_rr *a = ldns_rr_list_rr(answer, i); ldns_rr_get_type(a)) {
        case LDNS_RR_TYPE_A:
        case LDNS_RR_TYPE_AAAA: {
            const ldns_rdf *rd = ldns_rr_rdf(a, 0);
            if (rd == nullptr) {
                continue;
            }
            size_t rd_size = ldns_rdf_size(rd);
            if (rd_size != 4 && rd_size != 16) {
                continue;
            }
            add_name_to_answer(decoded_answer, ldns_rr_owner(a));
            const uint8_t *ip = ldns_rdf_data(rd);
            decoded_answer.addresses.push_back({{ip, ip + rd_size}, std::chrono::seconds(ldns_rr_ttl(a))});
            break;
        }
        case LDNS_RR_TYPE_CNAME: {
            const ldns_rdf *rd = ldns_rr_rdf(a, 0);
            if (rd == nullptr) {
                continue;
            }

            add_name_to_answer(decoded_answer, ldns_rr_owner(a));
            // ignoring TTL of CNAMEs for simplicity
            add_name_to_answer(decoded_answer, rd);
            break;
        }
        case LDNS_RR_TYPE_HTTPS:
        case LDNS_RR_TYPE_SVCB:
            add_name_to_answer(decoded_answer, ldns_rr_owner(a));
            break;
        default:
            break;
        }
    }
    decoded_answer.pkt = std::move(pkt);
    return decoded_answer;
}

dns_utils::DecodeResult dns_utils::decode_packet(U8View packet) {
    LdnsPktPtr pkt;
    {
        ldns_pkt *p = nullptr;
        if (ldns_status s = ldns_wire2pkt(&p, packet.data(), packet.size()); s != LDNS_STATUS_OK) {
            return Error{ldns_get_errorstr_by_id(s)};
        }
        pkt.reset(p);
    }

    if (ldns_pkt_qr(pkt.get())) {
        return decode_reply(std::move(pkt));
    }
    return decode_request(pkt.get());
}

dns_utils::EncodeResult dns_utils::encode_request(const dns_utils::Request &request) {
    std::string name{request.name};
    if (!ldns_dname_str_absolute(name.c_str())) {
        name.push_back('.');
    }

    LdnsPktPtr pkt{ldns_pkt_query_new(ldns_dname_new_frm_str(name.c_str()),
            (request.type == RT_A) ? LDNS_RR_TYPE_A : LDNS_RR_TYPE_AAAA, LDNS_RR_CLASS_IN, LDNS_RD)};
    ldns_pkt_set_id(pkt.get(), g_next_request_id.fetch_add(1, std::memory_order::relaxed));

    uint8_t *buffer; // NOLINT(cppcoreguidelines-init-variables)
    size_t pkt_size; // NOLINT(cppcoreguidelines-init-variables)
    if (ldns_status s = ldns_pkt2wire(&buffer, pkt.get(), &pkt_size); s != LDNS_STATUS_OK) {
        return dns_utils::Error{ldns_get_errorstr_by_id(s)};
    }

    std::vector<uint8_t> raw = {buffer, buffer + pkt_size};
    free(buffer); // NOLINT(cppcoreguidelines-no-malloc,hicpp-no-malloc)
    return EncodedRequest{ldns_pkt_id(pkt.get()), std::move(raw)};
}

dns_utils::LdnsPktPtr dns_utils::decode_pkt(U8View message) {
    ldns_pkt *pkt;
    if (ldns_status status = ldns_wire2pkt(&pkt, message.data(), message.size()); status == LDNS_STATUS_OK) {
        return LdnsPktPtr{pkt};
    }
    return nullptr;
}

dns_utils::LdnsBufferPtr dns_utils::encode_pkt(const ldns_pkt *pkt) {
    LdnsBufferPtr buffer{ldns_buffer_new(ldns_pkt_size(pkt))};
    if (ldns_status status = ldns_pkt2buffer_wire(buffer.get(), pkt); status == LDNS_STATUS_OK) {
        return buffer;
    }
    return nullptr;
}

bool dns_utils::remove_svcparam_echconfig(ldns_pkt *response) {
    bool modified = false;
    for (size_t i = 0; i < ldns_pkt_ancount(response); ++i) {
        ldns_rr *rr = ldns_rr_list_rr(ldns_pkt_answer(response), i);

        if (auto type = ldns_rr_get_type(rr);
                (type != LDNS_RR_TYPE_SVCB && type != LDNS_RR_TYPE_HTTPS) || (ldns_rr_rd_count(rr) != 3)) {
            continue;
        }

        ldns_rdf *params = ldns_rr_rdf(rr, 2);

        if (ldns_rdf_get_type(params) != LDNS_RDF_TYPE_SVCPARAMS) {
            continue;
        }

        uint8_t *current_param_start = nullptr;
        uint16_t key; // NOLINT(*-init-variables)
        uint16_t len; // NOLINT(*-init-variables)
        U8View params_tail = {ldns_rdf_data(params), ldns_rdf_size(params)};
        while (params_tail.size() >= sizeof(key)) {
            current_param_start = (uint8_t *) params_tail.data();

            std::memcpy(&key, params_tail.data(), sizeof(key));
            params_tail.remove_prefix(sizeof(key));

            if (params_tail.size() < sizeof(len)) {
                break;
            }

            std::memcpy(&len, params_tail.data(), sizeof(len));
            params_tail.remove_prefix(sizeof(len));

            key = ntohs(key);
            len = ntohs(len);

            if (params_tail.size() < len) {
                break;
            }

            params_tail.remove_prefix(len);

            if (key == LDNS_SVCPARAM_KEY_ECHCONFIG) {
                std::memmove(current_param_start, params_tail.data(), params_tail.size());
                ldns_rdf_set_size(params, ldns_rdf_size(params) - sizeof(key) - sizeof(len) - len);
                modified = true;
                break;
            }
        }
    }
    return modified;
}

} // namespace ag
