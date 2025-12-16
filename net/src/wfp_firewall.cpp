#include "wfp_firewall.h"

// clang-format off
#include <windows.h>
#include <fwpmu.h>
// clang-format on

#include "common/logger.h"
#include "common/utils.h"
#include "net/dns_utils.h"
#include "vpn/guid_utils.h"

static ag::Logger g_log{"FIREWALL"}; // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

static constexpr uint8_t DNS_RESTRICT_DENY_WEIGHT = 1;
static constexpr uint8_t DNS_RESTRICT_ALLOW_WEIGHT = 2;
static constexpr uint8_t IPV6_BLOCK_DENY_WEIGHT = 3;
static constexpr uint8_t UNTUNNELED_BLOCK_DENY_WEIGHT = 3;
static constexpr uint8_t UNTUNNELED_BLOCK_ALLOW_WEIGHT = 4;
static constexpr uint8_t SELF_ALLOW_WEIGHT = 15; // Must be the highest weight.

static_assert(UNTUNNELED_BLOCK_ALLOW_WEIGHT > UNTUNNELED_BLOCK_DENY_WEIGHT);
static_assert(UNTUNNELED_BLOCK_DENY_WEIGHT > DNS_RESTRICT_ALLOW_WEIGHT);
static_assert(IPV6_BLOCK_DENY_WEIGHT > DNS_RESTRICT_ALLOW_WEIGHT);
static_assert(DNS_RESTRICT_ALLOW_WEIGHT > DNS_RESTRICT_DENY_WEIGHT);

template <typename Func>
ag::WfpFirewallError run_transaction(HANDLE engine_handle, Func &&func) {
    if (DWORD error = FwpmTransactionBegin0(engine_handle, 0); error != ERROR_SUCCESS) {
        return make_error(ag::FE_WFP_ERROR, AG_FMT("FwpmTransactionBegin0 failed with code {:#x}", error));
    }
    if (auto error = std::forward<Func>(func)()) {
        FwpmTransactionAbort0(engine_handle);
        return error;
    }
    if (DWORD error = FwpmTransactionCommit0(engine_handle); error != ERROR_SUCCESS) {
        return make_error(ag::FE_WFP_ERROR, AG_FMT("FwpmTransactionCommit0 failed with code {:#x}", error));
    }
    return nullptr;
}

struct ag::WfpFirewall::Impl {
    HANDLE engine_handle = INVALID_HANDLE_VALUE; // NOLINT(performance-no-int-to-ptr)
    GUID provider_key = ag::random_guid();
    GUID sublayer_key = ag::random_guid();
};

ag::WfpFirewall::WfpFirewall()
        : m_impl{std::make_unique<Impl>()} {
    std::wstring name = L"AdGuard VPN dynamic session";

    FWPM_SESSION0 session{
            .displayData =
                    {
                            .name = name.data(),
                    },
            .flags = FWPM_SESSION_FLAG_DYNAMIC,
            .txnWaitTimeoutInMSec = INFINITE,
    };

    if (DWORD error = FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, &session, &m_impl->engine_handle);
            error != ERROR_SUCCESS) {
        errlog(g_log, "FwpmEngineOpen0 failed with code {:#x}", error);
        return;
    }

    auto register_base_objects = [&]() -> WfpFirewallError { // NOLINT(cppcoreguidelines-avoid-capture-default-when-capturing-this)
        std::wstring name = L"AdGuard VPN provider";

        FWPM_PROVIDER0 provider{
                .providerKey = m_impl->provider_key,
                .displayData =
                        {
                                .name = name.data(),
                        },
        };

        if (DWORD error = FwpmProviderAdd0(m_impl->engine_handle, &provider, nullptr); error != ERROR_SUCCESS) {
            return make_error(FE_WFP_ERROR, AG_FMT("FwpmProviderAdd0 failed with code {:#x}", error));
        }

        name = L"AdGuard VPN sublayer";
        FWPM_SUBLAYER0 sublayer{
                .subLayerKey = m_impl->sublayer_key,
                .displayData =
                        {
                                .name = name.data(),
                        },
        };

        if (DWORD error = FwpmSubLayerAdd0(m_impl->engine_handle, &sublayer, nullptr); error != ERROR_SUCCESS) {
            return make_error(FE_WFP_ERROR, AG_FMT("FwpmSubLayerAdd0 failed with code {:#x}", error));
        }

        return nullptr;
    };

    auto allow_self = [&]() -> WfpFirewallError { // NOLINT(cppcoreguidelines-avoid-capture-default-when-capturing-this)
        // Allow any DNS traffic for our process. Required for, e.g., resolving exclusions through the system DNS.
        wchar_t module_name[4096]{}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        if (!GetModuleFileNameW(nullptr, &module_name[0], std::size(module_name))) {
            return make_error(FE_WINAPI_ERROR, AG_FMT("GetModuleFileNameW failed with code {:#x}", GetLastError()));
        }
        FWP_BYTE_BLOB *app_id_blob = nullptr;
        if (DWORD error = FwpmGetAppIdFromFileName(&module_name[0], &app_id_blob); error != ERROR_SUCCESS) {
            return make_error(FE_WFP_ERROR, AG_FMT("FwpmGetAppIdFromFileName failed with code {:#x}", error));
        }
        std::shared_ptr<FWP_BYTE_BLOB> app_id_blob_guard(app_id_blob, [](FWP_BYTE_BLOB *blob) {
            FwpmFreeMemory((void **) &blob);
        });
        std::vector<FWPM_FILTER_CONDITION0> allow_self_conditions;
        allow_self_conditions.reserve(1);
        allow_self_conditions.emplace_back(FWPM_FILTER_CONDITION0{
                .fieldKey = FWPM_CONDITION_ALE_APP_ID,
                .matchType = FWP_MATCH_EQUAL,
                .conditionValue =
                        {
                                .type = FWP_BYTE_BLOB_TYPE,
                                .byteBlob = app_id_blob,
                        },
        });
        FWPM_FILTER0 filter{
                .displayData =
                        {
                                .name = name.data(),
                        },
                .providerKey = &m_impl->provider_key,
                .subLayerKey = m_impl->sublayer_key,
                .weight =
                        {
                                .type = FWP_UINT8,
                                .uint8 = SELF_ALLOW_WEIGHT,
                        },
                .numFilterConditions = (UINT32) allow_self_conditions.size(),
                .filterCondition = allow_self_conditions.data(),
                .action =
                        {
                                .type = FWP_ACTION_PERMIT,
                        },
        };
        for (GUID layer_key : {FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
                     FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6}) {
            filter.layerKey = layer_key;
            if (DWORD error = FwpmFilterAdd0(m_impl->engine_handle, &filter, nullptr, nullptr);
                    error != ERROR_SUCCESS) {
                return make_error(FE_WFP_ERROR, AG_FMT("FwpmFilterAdd0 failed with code {:#x}", error));
            }
        }
        return nullptr;
    };

    if (auto error = run_transaction(m_impl->engine_handle, std::move(register_base_objects))) {
        errlog(g_log, "Failed to register base objects: {}", error->str());
        FwpmEngineClose0(m_impl->engine_handle);
        m_impl->engine_handle = INVALID_HANDLE_VALUE;
        return;
    }

    if (auto error = run_transaction(m_impl->engine_handle, std::move(allow_self))) {
        errlog(g_log, "Failed to allow self through firewall: {}", error->str());
        FwpmEngineClose0(m_impl->engine_handle);
        m_impl->engine_handle = INVALID_HANDLE_VALUE;
        return;
    }
}

ag::WfpFirewall::~WfpFirewall() {
    if (m_impl->engine_handle != INVALID_HANDLE_VALUE) {
        FwpmEngineClose0(m_impl->engine_handle);
    }
}

static FWP_V4_ADDR_AND_MASK fwp_v4_range_from_cidr_range(const ag::CidrRange &range) {
    FWP_V4_ADDR_AND_MASK value{};
    value.addr = ntohl(*(uint32_t *) range.get_address().data());
    value.mask = ntohl(*(uint32_t *) range.get_mask().data());
    return value;
}

static FWP_V6_ADDR_AND_MASK fwp_v6_range_from_cidr_range(const ag::CidrRange &range) {
    FWP_V6_ADDR_AND_MASK value{};
    std::memcpy(value.addr, range.get_address().data(), ag::IPV6_ADDRESS_SIZE);
    value.prefixLength = range.get_prefix_len();
    return value;
}

ag::WfpFirewallError ag::WfpFirewall::restrict_dns_to(std::span<const CidrRange> allowed_v4, std::span<const CidrRange> allowed_v6) {
    if (m_impl->engine_handle == INVALID_HANDLE_VALUE) {
        return make_error(FE_NOT_INITIALIZED);
    }
    return run_transaction(m_impl->engine_handle, [&]() -> WfpFirewallError { // NOLINT(cppcoreguidelines-avoid-capture-default-when-capturing-this)
        FWPM_FILTER_CONDITION0 dns_conditions[] = {
                {
                        .fieldKey = FWPM_CONDITION_IP_REMOTE_PORT,
                        .matchType = FWP_MATCH_EQUAL,
                        .conditionValue =
                                {
                                        .type = FWP_UINT16,
                                        .uint16 = ag::dns_utils::PLAIN_DNS_PORT_NUMBER,
                                },
                },
                {
                        .fieldKey = FWPM_CONDITION_IP_PROTOCOL,
                        .matchType = FWP_MATCH_EQUAL,
                        .conditionValue =
                                {
                                        .type = FWP_UINT8,
                                        .uint8 = IPPROTO_TCP,
                                },
                },
                {
                        .fieldKey = FWPM_CONDITION_IP_PROTOCOL,
                        .matchType = FWP_MATCH_EQUAL,
                        .conditionValue =
                                {
                                        .type = FWP_UINT8,
                                        .uint8 = IPPROTO_UDP,
                                },
                },
        };

        std::wstring name = L"AdGuard VPN restrict DNS";
        FWPM_FILTER0 filter{
                .displayData =
                        {
                                .name = name.data(),
                        },
                .providerKey = &m_impl->provider_key,
                .subLayerKey = m_impl->sublayer_key,
                .weight =
                        {
                                .type = FWP_UINT8,
                                .uint8 = DNS_RESTRICT_DENY_WEIGHT,
                        },
                .numFilterConditions = (UINT32) std::size(dns_conditions),
                .filterCondition = &dns_conditions[0],
                .action =
                        {
                                .type = FWP_ACTION_BLOCK,
                        },
        };

        // Block all inbound/outbound IPv4/IPv6 DNS traffic.
        for (GUID layer_key : {FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
                     FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6}) {
            filter.layerKey = layer_key;
            if (DWORD error = FwpmFilterAdd0(m_impl->engine_handle, &filter, nullptr, nullptr);
                    error != ERROR_SUCCESS) {
                return make_error(FE_WFP_ERROR, AG_FMT("FwpmFilterAdd0 failed with code {:#x}", error));
            }
        }

        filter.action = {.type = FWP_ACTION_PERMIT};
        filter.weight.uint8 = DNS_RESTRICT_ALLOW_WEIGHT;

        // Allow IPv4 inbound/outbound DNS traffic for specified addresses.
        std::vector<FWPM_FILTER_CONDITION0> allow_v4_conditions;
        allow_v4_conditions.reserve(std::size(dns_conditions) + allowed_v4.size());
        allow_v4_conditions.insert(allow_v4_conditions.end(), std::begin(dns_conditions), std::end(dns_conditions));
        std::list<FWP_V4_ADDR_AND_MASK> allow_v4_ranges;
        for (const CidrRange &range : allowed_v4) {
            if (range.get_address().size() != IPV4_ADDRESS_SIZE) {
                continue;
            }
            allow_v4_conditions.emplace_back(FWPM_FILTER_CONDITION0{
                    .fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    .matchType = FWP_MATCH_EQUAL,
                    .conditionValue =
                            {
                                    .type = FWP_V4_ADDR_MASK,
                                    .v4AddrMask = &allow_v4_ranges.emplace_back(fwp_v4_range_from_cidr_range(range)),
                            },
            });
        }
        if (allow_v4_conditions.size() > std::size(dns_conditions)) {
            filter.numFilterConditions = allow_v4_conditions.size();
            filter.filterCondition = allow_v4_conditions.data();
            for (GUID layer_key : {FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4}) {
                filter.layerKey = layer_key;
                if (DWORD error = FwpmFilterAdd0(m_impl->engine_handle, &filter, nullptr, nullptr);
                        error != ERROR_SUCCESS) {
                    return make_error(FE_WFP_ERROR, AG_FMT("FwpmFilterAdd0 failed with code {:#x}", error));
                }
            }
        }

        // Allow IPv6 inbound/outbound DNS traffic for specified addresses.
        std::vector<FWPM_FILTER_CONDITION0> allow_v6_conditions;
        allow_v6_conditions.reserve(std::size(dns_conditions) + allowed_v6.size());
        allow_v6_conditions.insert(allow_v6_conditions.end(), std::begin(dns_conditions), std::end(dns_conditions));
        std::list<FWP_V6_ADDR_AND_MASK> allow_v6_ranges;
        for (const auto &range : allowed_v6) {
            if (range.get_address().size() != IPV6_ADDRESS_SIZE) {
                continue;
            }
            allow_v6_conditions.emplace_back(FWPM_FILTER_CONDITION0{
                    .fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    .matchType = FWP_MATCH_EQUAL,
                    .conditionValue =
                            {
                                    .type = FWP_V6_ADDR_MASK,
                                    .v6AddrMask = &allow_v6_ranges.emplace_back(fwp_v6_range_from_cidr_range(range)),
                            },
            });
        }
        if (allow_v6_conditions.size() > std::size(dns_conditions)) {
            filter.numFilterConditions = allow_v6_conditions.size();
            filter.filterCondition = allow_v6_conditions.data();
            for (GUID layer_key : {FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6}) {
                filter.layerKey = layer_key;
                if (DWORD error = FwpmFilterAdd0(m_impl->engine_handle, &filter, nullptr, nullptr);
                        error != ERROR_SUCCESS) {
                    return make_error(FE_WFP_ERROR, AG_FMT("FwpmFilterAdd0 failed with code {:#x}", error));
                }
            }
        }

        return nullptr;
    });
}

ag::WfpFirewallError ag::WfpFirewall::block_ipv6() {
    if (m_impl->engine_handle == INVALID_HANDLE_VALUE) {
        return make_error(FE_NOT_INITIALIZED);
    }
    return run_transaction(m_impl->engine_handle, [&]() -> WfpFirewallError { // NOLINT(cppcoreguidelines-avoid-capture-default-when-capturing-this)
        std::wstring name = L"AdGuard VPN block IPv6";
        FWPM_FILTER0 filter{
                .displayData =
                        {
                                .name = name.data(),
                        },
                .providerKey = &m_impl->provider_key,
                .subLayerKey = m_impl->sublayer_key,
                .weight =
                        {
                                .type = FWP_UINT8,
                                .uint8 = IPV6_BLOCK_DENY_WEIGHT,
                        },
                .numFilterConditions = 0,
                .filterCondition = nullptr,
                .action =
                        {
                                .type = FWP_ACTION_BLOCK,
                        },
        };

        // Block all inbound/outbound IPv6 traffic.
        for (GUID layer_key : {FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6}) {
            filter.layerKey = layer_key;
            if (DWORD error = FwpmFilterAdd0(m_impl->engine_handle, &filter, nullptr, nullptr);
                    error != ERROR_SUCCESS) {
                return make_error(FE_WFP_ERROR, AG_FMT("FwpmFilterAdd0 failed with code {:#x}", error));
            }
        }

        return nullptr;
    });
}

ag::WfpFirewallError ag::WfpFirewall::block_untunneled(const CidrRange &tunaddr4, const CidrRange &tunaddr6,
        std::span<const CidrRange> incl4, std::span<const CidrRange> incl6, std::span<const uint16_t> excl_ports) {
    if (m_impl->engine_handle == INVALID_HANDLE_VALUE) {
        return make_error(FE_NOT_INITIALIZED);
    }
    return run_transaction(m_impl->engine_handle,
            [&]() -> WfpFirewallError { // NOLINT(cppcoreguidelines-avoid-capture-default-when-capturing-this)
                // Deny IPv4 traffic to/from addresses in `incl4`, except from/to `tunaddr4` or loopback.
                if (tunaddr4.get_address().size() == IPV4_ADDRESS_SIZE && !incl4.empty()) {
                    std::vector<FWPM_FILTER_CONDITION0> v4_conditions;
                    std::list<FWP_V4_ADDR_AND_MASK> v4_ranges;
                    v4_conditions.reserve(incl4.size() + 2);

                    // Remote address in any of `incl4`.
                    for (const CidrRange &range : incl4) {
                        if (range.get_address().size() != IPV4_ADDRESS_SIZE) {
                            continue;
                        }
                        v4_conditions.emplace_back(FWPM_FILTER_CONDITION0{
                                .fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS,
                                .matchType = FWP_MATCH_EQUAL,
                                .conditionValue =
                                        {
                                                .type = FWP_V4_ADDR_MASK,
                                                .v4AddrMask =
                                                        &v4_ranges.emplace_back(fwp_v4_range_from_cidr_range(range)),
                                        },
                        });
                    }

                    std::wstring name = L"AdGuard VPN block untunneled IPv4";
                    FWPM_FILTER0 filter{
                            .displayData = {.name = name.data()},
                            .providerKey = &m_impl->provider_key,
                            .layerKey = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
                            .subLayerKey = m_impl->sublayer_key,
                            .weight =
                                    {
                                            .type = FWP_UINT8,
                                            .uint8 = UNTUNNELED_BLOCK_DENY_WEIGHT,
                                    },
                            .numFilterConditions = (UINT32) v4_conditions.size(),
                            .filterCondition = &v4_conditions[0],
                            .action = {.type = FWP_ACTION_BLOCK},
                    };

                    for (GUID layer_key : {FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4}) {
                        filter.layerKey = layer_key;
                        if (DWORD error = FwpmFilterAdd0(m_impl->engine_handle, &filter, nullptr, nullptr);
                                error != ERROR_SUCCESS) {
                            return make_error(FE_WFP_ERROR, AG_FMT("FwpmFilterAdd0 failed with code {:#x}", error));
                        }
                    }

                    // Allow traffic to/from `tunaddr4`, loopback and excluded ports.
                    auto v4_conditions_allow = v4_conditions;

                    v4_conditions_allow.emplace_back(FWPM_FILTER_CONDITION0{
                            .fieldKey = FWPM_CONDITION_IP_LOCAL_ADDRESS,
                            .matchType = FWP_MATCH_EQUAL,
                            .conditionValue =
                                    {
                                            .type = FWP_V4_ADDR_MASK,
                                            .v4AddrMask =
                                                    &v4_ranges.emplace_back(fwp_v4_range_from_cidr_range(tunaddr4)),
                                    },
                    });
                    v4_conditions_allow.emplace_back(FWPM_FILTER_CONDITION0{
                            .fieldKey = FWPM_CONDITION_IP_LOCAL_ADDRESS,
                            .matchType = FWP_MATCH_EQUAL,
                            .conditionValue =
                                    {
                                            .type = FWP_V4_ADDR_MASK,
                                            .v4AddrMask = &v4_ranges.emplace_back(
                                                    fwp_v4_range_from_cidr_range(CidrRange{"127.0.0.1/32"})),
                                    },
                    });

                    name = L"AdGuard VPN block untunneled IPv4 (allow tunneled and loopback)";
                    filter.displayData = {.name = name.data()};
                    filter.action = {.type = FWP_ACTION_PERMIT};
                    filter.weight.uint8 = UNTUNNELED_BLOCK_ALLOW_WEIGHT;
                    filter.numFilterConditions = v4_conditions_allow.size();
                    filter.filterCondition = v4_conditions_allow.data();

                    for (GUID layer_key : {FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4}) {
                        filter.layerKey = layer_key;
                        if (DWORD error = FwpmFilterAdd0(m_impl->engine_handle, &filter, nullptr, nullptr);
                                error != ERROR_SUCCESS) {
                            return make_error(FE_WFP_ERROR, AG_FMT("FwpmFilterAdd0 failed with code {:#x}", error));
                        }
                    }

                    if (!excl_ports.empty()) {
                        auto v4_conditions_excl_ports = v4_conditions;
                        for (uint16_t port : excl_ports) {
                            v4_conditions_excl_ports.emplace_back(FWPM_FILTER_CONDITION0{
                                    .fieldKey = FWPM_CONDITION_IP_LOCAL_PORT,
                                    .matchType = FWP_MATCH_EQUAL,
                                    .conditionValue =
                                            {
                                                    .type = FWP_UINT16,
                                                    .uint16 = port,
                                            },
                            });
                        }

                        name = L"AdGuard VPN block untunneled IPv4 (allow excluded ports)";
                        filter.displayData = {.name = name.data()};
                        filter.action = {.type = FWP_ACTION_PERMIT};
                        filter.weight.uint8 = UNTUNNELED_BLOCK_ALLOW_WEIGHT;
                        filter.numFilterConditions = v4_conditions_excl_ports.size();
                        filter.filterCondition = v4_conditions_excl_ports.data();

                        for (GUID layer_key : {FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4}) {
                            filter.layerKey = layer_key;
                            if (DWORD error = FwpmFilterAdd0(m_impl->engine_handle, &filter, nullptr, nullptr);
                                    error != ERROR_SUCCESS) {
                                return make_error(FE_WFP_ERROR, AG_FMT("FwpmFilterAdd0 failed with code {:#x}", error));
                            }
                        }
                    }
                }

                // Deny IPv6 traffic to/from addresses in `incl6`, except from/to `tunnaddr6` or loopback.
                if (tunaddr6.get_address().size() == IPV6_ADDRESS_SIZE && !incl6.empty()) {
                    std::vector<FWPM_FILTER_CONDITION0> v6_conditions;
                    std::list<FWP_V6_ADDR_AND_MASK> v6_ranges;
                    v6_conditions.reserve(incl6.size() + 2);

                    // Remote address in any of `incl6`.
                    for (const CidrRange &range : incl6) {
                        if (range.get_address().size() != IPV6_ADDRESS_SIZE) {
                            continue;
                        }
                        v6_conditions.emplace_back(FWPM_FILTER_CONDITION0{
                                .fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS,
                                .matchType = FWP_MATCH_EQUAL,
                                .conditionValue =
                                        {
                                                .type = FWP_V6_ADDR_MASK,
                                                .v6AddrMask =
                                                        &v6_ranges.emplace_back(fwp_v6_range_from_cidr_range(range)),
                                        },
                        });
                    }

                    std::wstring name = L"AdGuard VPN block untunneled IPv6";
                    FWPM_FILTER0 filter{
                            .displayData = {.name = name.data()},
                            .providerKey = &m_impl->provider_key,
                            .layerKey = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
                            .subLayerKey = m_impl->sublayer_key,
                            .weight =
                                    {
                                            .type = FWP_UINT8,
                                            .uint8 = UNTUNNELED_BLOCK_DENY_WEIGHT,
                                    },
                            .numFilterConditions = (UINT32) v6_conditions.size(),
                            .filterCondition = &v6_conditions[0],
                            .action = {.type = FWP_ACTION_BLOCK},
                    };

                    for (GUID layer_key : {FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6}) {
                        filter.layerKey = layer_key;
                        if (DWORD error = FwpmFilterAdd0(m_impl->engine_handle, &filter, nullptr, nullptr);
                                error != ERROR_SUCCESS) {
                            return make_error(FE_WFP_ERROR, AG_FMT("FwpmFilterAdd0 failed with code {:#x}", error));
                        }
                    }

                    // Allow traffic to/from `tunaddr6`, loopback and excluded ports.
                    auto v6_conditions_allow = v6_conditions;

                    v6_conditions_allow.emplace_back(FWPM_FILTER_CONDITION0{
                            .fieldKey = FWPM_CONDITION_IP_LOCAL_ADDRESS,
                            .matchType = FWP_MATCH_EQUAL,
                            .conditionValue =
                                    {
                                            .type = FWP_V6_ADDR_MASK,
                                            .v6AddrMask =
                                                    &v6_ranges.emplace_back(fwp_v6_range_from_cidr_range(tunaddr6)),
                                    },
                    });
                    v6_conditions_allow.emplace_back(FWPM_FILTER_CONDITION0{
                            .fieldKey = FWPM_CONDITION_IP_LOCAL_ADDRESS,
                            .matchType = FWP_MATCH_EQUAL,
                            .conditionValue =
                                    {
                                            .type = FWP_V6_ADDR_MASK,
                                            .v6AddrMask = &v6_ranges.emplace_back(
                                                    fwp_v6_range_from_cidr_range(CidrRange{"::1/128"})),
                                    },
                    });

                    name = L"AdGuard VPN block untunneled IPv6 (allow tunneled and loopback)";
                    filter.displayData = {.name = name.data()};
                    filter.action = {.type = FWP_ACTION_PERMIT};
                    filter.weight.uint8 = UNTUNNELED_BLOCK_ALLOW_WEIGHT;
                    filter.numFilterConditions = v6_conditions_allow.size();
                    filter.filterCondition = &v6_conditions_allow[0];

                    for (GUID layer_key : {FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6}) {
                        filter.layerKey = layer_key;
                        if (DWORD error = FwpmFilterAdd0(m_impl->engine_handle, &filter, nullptr, nullptr);
                                error != ERROR_SUCCESS) {
                            return make_error(FE_WFP_ERROR, AG_FMT("FwpmFilterAdd0 failed with code {:#x}", error));
                        }
                    }

                    if (!excl_ports.empty()) {
                        auto v6_conditions_excl_ports = v6_conditions;
                        for (uint16_t port : excl_ports) {
                            v6_conditions_excl_ports.emplace_back(FWPM_FILTER_CONDITION0{
                                    .fieldKey = FWPM_CONDITION_IP_LOCAL_PORT,
                                    .matchType = FWP_MATCH_EQUAL,
                                    .conditionValue =
                                            {
                                                    .type = FWP_UINT16,
                                                    .uint16 = port,
                                            },
                            });
                        }

                        name = L"AdGuard VPN block untunneled IPv6 (allow excluded ports)";
                        filter.displayData = {.name = name.data()};
                        filter.action = {.type = FWP_ACTION_PERMIT};
                        filter.weight.uint8 = UNTUNNELED_BLOCK_ALLOW_WEIGHT;
                        filter.numFilterConditions = v6_conditions_excl_ports.size();
                        filter.filterCondition = v6_conditions_excl_ports.data();

                        for (GUID layer_key : {FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6}) {
                            filter.layerKey = layer_key;
                            if (DWORD error = FwpmFilterAdd0(m_impl->engine_handle, &filter, nullptr, nullptr);
                                    error != ERROR_SUCCESS) {
                                return make_error(FE_WFP_ERROR, AG_FMT("FwpmFilterAdd0 failed with code {:#x}", error));
                            }
                        }
                    }
                }

                return nullptr;
            });
}
