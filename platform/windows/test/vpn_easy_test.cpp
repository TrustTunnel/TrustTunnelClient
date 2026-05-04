#include "vpn/vpn.h"
#include "vpn/vpn_easy.h"

#include <cstdio>
#include <fstream>
#include <sstream>

#include <magic_enum/magic_enum.hpp>

static void state_changed_cb(void *, int state) {
    fprintf(stderr, "VPN state changed: (%d) %s\n", state, magic_enum::enum_name((ag::VpnSessionState) state).data());
}

int main() {
    std::ifstream in("config.toml");
    std::stringstream config;
    config << in.rdbuf();
    if (in.fail()) {
        fprintf(stderr, "Failed to read config.toml");
        return -1;
    }
    in.close();

    vpn_easy_t *vpn = vpn_easy_start_ex(config.str().c_str(), state_changed_cb, nullptr, nullptr, nullptr);

    fprintf(stderr, "Type 's' to stop");
    while (getchar() != 's') {
    }

    vpn_easy_stop_ex(vpn);
    return 0;
}
