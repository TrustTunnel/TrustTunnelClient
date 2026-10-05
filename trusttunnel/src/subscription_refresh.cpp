#include "vpn/trusttunnel/subscription_refresh.h"

#include <cerrno>
#include <common/logger.h>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <memory>
#include <optional>
#include <sstream>
#include <string>

#include "trusttunnel_subscription.h"

namespace ag {

Logger g_logger("SUBSCRIPTION_REFRESH");

using FfiString = std::unique_ptr<char, decltype(&trusttunnel_subscription_string_free)>;

/**
 * Read the whole file at `path`. On failure return an empty optional.
 */
static std::optional<std::string> read_text_file(const std::string &path) {
    errno = 0;
    std::ifstream stream(path, std::ios::binary);
    std::ostringstream content;
    if (stream) {
        content << stream.rdbuf();
    }
    if (!stream) {
        errlog(g_logger, "Failed to read file '{}': {}", path, std::strerror(errno));
        return std::nullopt;
    }
    return content.str();
}

/**
 * Print the diagnostic carried by `error` (a fallback when absent) and free it.
 */
static void print_and_free_error(SubscriptionFfiError *error) {
    const char *message = (error != nullptr) ? trusttunnel_subscription_error_message(error) : "unknown error";
    errlog(g_logger, "Refresh failed: {}", message);
    trusttunnel_subscription_error_free(error);
}

int run_subscription_refresh(const std::string &config_path) {
    std::optional<std::string> config_text = read_text_file(config_path);
    if (!config_text) {
        errlog(g_logger, "Refresh failed: Cannot read config file '{}'", config_path);
        return 1;
    }

    SubscriptionFfiError *error = nullptr;
    char *json_raw = nullptr;
    if (trusttunnel_subscription_fetch_for_config(config_text->c_str(), &json_raw, &error) != 0) {
        print_and_free_error(error);
        return 1;
    }
    FfiString json(json_raw, &trusttunnel_subscription_string_free);

    char *updated_raw = nullptr;
    if (trusttunnel_subscription_apply(config_text->c_str(), json.get(), &updated_raw, &error) != 0) {
        print_and_free_error(error);
        return 1;
    }
    FfiString updated(updated_raw, &trusttunnel_subscription_string_free);

    if (trusttunnel_subscription_replace_file_atomic(config_path.c_str(), updated.get(), &error) != 0) {
        print_and_free_error(error);
        return 1;
    }

    infolog(g_logger, "Configuration refreshed from the subscription URL");
    return 0;
}

} // namespace ag
