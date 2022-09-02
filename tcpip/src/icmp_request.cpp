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
    IcmpRequestDescriptor *request = (IcmpRequestDescriptor *) calloc(1, sizeof(IcmpRequestDescriptor));
    if (NULL == request) {
        return NULL;
    }

    request->key = icmp_request_key_create(id, seqno);
    request->ttl = ttl;
    ip_addr_copy(request->src, *src);
    ip_addr_copy(request->dst, *dst);
    request->buffer = buffer;

    return request;
}

void icmp_request_destroy(IcmpRequestDescriptor *request) {
    if (request == NULL) {
        return;
    }

    if (request->buffer != NULL) {
        pbuf_free(request->buffer);
        request->buffer = NULL;
    }

    free(request);
}

} // namespace ag
