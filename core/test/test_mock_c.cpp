#include "test_mock_c.h"
#include "vpn/utils.h"

using namespace test_mock;
using namespace ag;

std::array<Info, magic_enum::enum_count<Idx>()> MockedTest::g_infos;

template <typename... Ts>
static std::vector<std::any> collect_args(const Ts &...args) {
    std::vector<std::any> vec;
    vec.reserve(sizeof...(args));
    (vec.emplace_back(args), ...);
    return vec;
}

void MockedTest::reset_infos() {
    for (auto &i : MockedTest::g_infos) {
        i.reset();
    }
}

static void free_locations_pinger_info(ag::LocationsPingerInfo *info) {
    if (info == nullptr) {
        return;
    }

    for (size_t i = 0; i < info->locations.size; ++i) {
        vpn_location_destroy((VpnLocation *) &info->locations.data[i]);
    }

    free((VpnLocation *) info->locations.data);
    free((void *) info->relay_address_parallel);

    delete info;
}

static test_mock::LocationsPingerInfo make_deep_copy(const ag::LocationsPingerInfo *src) {
    if (src == nullptr) {
        return nullptr;
    }

    test_mock::LocationsPingerInfo dst{new ag::LocationsPingerInfo{}, &free_locations_pinger_info};
    *dst = *src;

    dst->locations = {};
    dst->locations.size = src->locations.size;
    static_assert(std::is_trivial_v<VpnLocation>);
    dst->locations.data = (VpnLocation *) malloc(src->locations.size * sizeof(VpnLocation));
    if (src->relay_address_parallel) {
        auto *ss = (sockaddr_storage *) malloc(sizeof(sockaddr_storage));
        *ss = sockaddr_to_storage(src->relay_address_parallel);
        dst->relay_address_parallel = (sockaddr *) ss;
    }

    for (size_t i = 0; i < src->locations.size; ++i) {
        AutoVpnLocation location = vpn_location_clone(&src->locations.data[i]);
        std::memcpy((VpnLocation *) &dst->locations.data[i], location.get(), sizeof(*location.get()));
        location.release();
    }

    return dst;
}

LocationsPinger *ag::locations_pinger_start(
        const ag::LocationsPingerInfo *info, LocationsPingerHandler handler, VpnEventLoop *ev_loop, VpnNetworkManager *network_manager) {
    test_mock::Info &mock_info = MockedTest::g_infos[IDX_LOCATIONS_PINGER_START];
    mock_info.args = collect_args(make_deep_copy(info), handler, ev_loop, network_manager);
    mock_info.notify_called();
    return mock_info.get_return_value<LocationsPinger *>();
}
