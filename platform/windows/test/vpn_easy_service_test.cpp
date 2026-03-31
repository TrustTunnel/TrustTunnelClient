#include "vpn/vpn_easy.h"
#include "vpn/vpn_easy_service.h"

#include <filesystem>

#include <fmt/format.h>

#include "common/logger.h"

int main() {
    ag::Logger::set_log_level(ag::LOG_LEVEL_DEBUG);
    vpn_easy_service_uninstall(L"vpn_easy_service");

    int32_t ret = vpn_easy_service_install(
        absolute(std::filesystem::path(".") / "vpn_easy_service.exe").wstring().c_str(),
        absolute(std::filesystem::path(".") / "vpn_easy_service.log").wstring().c_str(),
        L"\\\\.\\pipe\\TestPipeName",
        L"vpn_easy_service",
        L"VPN easy service",
        L"Test description");
    if (ret) {
        fmt::println(stderr, "vpn_easy_service_install: {}", ret);
        return -1;
    }

    fmt::println(stderr, "Type 's' to stop");
    while (getchar() != 's') {
    }

    ret = vpn_easy_service_uninstall(L"vpn_easy_service");
    if (ret) {
        fmt::println(stderr, "vpn_easy_service_uninstall: {}", ret);
        return -1;
    }

    return 0;
}
