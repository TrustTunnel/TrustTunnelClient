#include "vpn/platform.h"

#include "icmp_request.h"
#include "tcpip_common.h"
#include "vpn/utils.h"

namespace ag {

IcmpRequestKey icmp_request_key_create(u16_t id, u16_t seqno) {
    IcmpRequestKey key;
    key.id = id;
    key.seqno = seqno;
    return key;
}

uint64_t icmp_request_key_hash(const IcmpRequestKey *key) {
    return hash_pair_combine(key->id, key->seqno);
}

bool icmp_request_key_equals(const IcmpRequestKey *lh, const IcmpRequestKey *rh) {
    return lh->id == rh->id && lh->seqno == rh->seqno;
}

IcmpRequestDescriptor *icmp_request_create(
        const ip_addr_t *src, const ip_addr_t *dst, u16_t id, u16_t seqno, u8_t ttl, struct pbuf *buffer) {
    static_assert(std::is_trivial_v<IcmpRequestDescriptor>);
    // NOLINTNEXTLINE(cppcoreguidelines-no-malloc,hicpp-no-malloc)
    IcmpRequestDescriptor *request = (IcmpRequestDescriptor *) calloc(1, sizeof(IcmpRequestDescriptor));
    if (nullptr == request) {
        return nullptr;
    }

    request->key = icmp_request_key_create(id, seqno);
    request->ttl = ttl;
    ip_addr_copy(request->src, *src);
    ip_addr_copy(request->dst, *dst);
    request->buffer = buffer;

    return request;
}

void icmp_request_destroy(IcmpRequestDescriptor *request) {
    if (request == nullptr) {
        return;
    }

    if (request->buffer != nullptr) {
        pbuf_free(request->buffer);
        request->buffer = nullptr;
    }

    free(request); // NOLINT(cppcoreguidelines-no-malloc,hicpp-no-malloc)
}

} // namespace ag
