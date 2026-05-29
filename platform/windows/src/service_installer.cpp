// service_installer.exe — Elevated helper for installing/uninstalling the VPN service.
//
// This executable is designed to be launched with elevated (administrator) permissions
// to perform service management operations. It links statically against vpn_easy_a
// to also get ag::Logger support.
//
// Usage:
//   service_installer.exe install <image_path> <logfile_path> <pipe_name> <name> <display_name> <description> <ring_buffer_path>
//   service_installer.exe uninstall <name>
//
// Exit codes:
//   0 — Success
//   1 — Invalid usage / arguments
//   2+ — One of the VpnEasyServiceError codes

#include "vpn/vpn_easy_service.h"

#include <string>

#include "common/logger.h"
#include <fmt/format.h>

static ag::Logger g_logger{"SERVICE_INSTALLER"};

static void print_usage() {
    fmt::print(stderr,
            "Usage:\n"
            "  service_installer.exe install <image_path> <logfile_path> <pipe_name>\n"
            "                             <name> <display_name> <description> <ring_buffer_path>\n"
            "  service_installer.exe uninstall <name>\n");
}

int wmain(int argc, wchar_t *argv[]) {
    if (argc < 2) {
        print_usage();
        return 1;
    }

    std::wstring subcommand = argv[1];

    if (subcommand == L"install") {
        if (argc != 9) {
            errlog(g_logger, "'install' requires exactly 7 arguments");
            print_usage();
            return 1;
        }

        const wchar_t *image_path = argv[2];
        const wchar_t *logfile_path = argv[3];
        const wchar_t *pipe_name = argv[4];
        const wchar_t *name = argv[5];
        const wchar_t *display_name = argv[6];
        const wchar_t *description = argv[7];
        const wchar_t *ring_buffer_path = argv[8];

        int32_t result = vpn_easy_service_install(
                image_path, logfile_path, pipe_name, name, display_name, description, ring_buffer_path);

        if (result != 0) {
            errlog(g_logger, "vpn_easy_service_install failed with error code: {}", result);
            return result;
        }

        infolog(g_logger, "Service installed successfully");
        return 0;
    }

    if (subcommand == L"uninstall") {
        if (argc != 3) {
            errlog(g_logger, "'uninstall' requires exactly 1 argument");
            print_usage();
            return 1;
        }

        const wchar_t *name = argv[2];

        int32_t result = vpn_easy_service_uninstall(name);

        if (result != 0) {
            errlog(g_logger, "vpn_easy_service_uninstall failed with error code: {}", result);
            return result;
        }

        infolog(g_logger, "Service uninstalled successfully");
        return 0;
    }

    errlog(g_logger, "Unknown subcommand");
    print_usage();
    return 1;
}
