#include "vpn/vpn_easy.h"

#include <cstdio>
#include <fstream>
#include <sstream>

static void state_changed_cb(void *, const char *new_state_description) {
    fprintf(stderr, "VPN state changed: %s\n", new_state_description);
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

    vpn_easy_t *vpn = vpn_easy_start(config.str().c_str(), state_changed_cb, nullptr);

    fprintf(stderr, "Type 's' to stop");
    while (getchar() != 's') {
    }

    vpn_easy_stop(vpn);
    return 0;
}
