#include "network_monitor.h"
#include <functional>
#include <common/logger.h>
#include <string>
#include <utility>
#include <net/if.h>

#ifdef __APPLE__
#include <Network/path.h>
#include <Network/path_monitor.h>
#include <Network/interface.h>
#include <Network/nw_object.h>
#include <dispatch/dispatch.h>
#endif // __APPLE__

#ifdef __linux__
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <sys/types.h>
#endif // __linux__

#include "vpn/vpn.h"
#include "vpn/event_loop.h"

namespace ag {

NetworkMonitor::NetworkMonitor(std::function<void(const std::string &, bool)> cmd_handler)
: m_cmd_handler(std::move(cmd_handler)) {}

NetworkMonitorImpl::NetworkMonitorImpl(std::function<void(const std::string &, bool)> cmd_handler)
: NetworkMonitor(std::move(cmd_handler)) {}

void NetworkMonitorImpl::start(VpnEventLoop *loop) {
    dbglog(m_logger, "...");
    if (is_running()) {
        return;
    }
#ifdef __APPLE__
    m_nw_path_monitor = nw_path_monitor_create();
    if (!m_nw_path_monitor) {
        errlog(m_logger, "Failed to create path monitor");
        return;
    }
    m_dispatch_queue = dispatch_queue_create("set_outbound_interface", nullptr);
    if (!m_dispatch_queue) {
        errlog(m_logger, "Failed to create dispatch queue");
        nw_release(m_nw_path_monitor);
        m_nw_path_monitor = nullptr;
        return;
    }

    dispatch_group_t group = dispatch_group_create();
    dispatch_group_enter(group);

    nw_path_monitor_set_update_handler(m_nw_path_monitor, ^(nw_path_t path) {
        if (m_current_path) {
            nw_release(m_current_path);
        }
        m_current_path = (nw_path_t)nw_retain(path);
        auto old_first_update_done = m_first_update_done;
        changed_handler();
        if (!old_first_update_done && m_first_update_done) {
            dispatch_group_leave(group);
        }
    });

    nw_path_monitor_set_queue(m_nw_path_monitor, m_dispatch_queue);
    nw_path_monitor_start(m_nw_path_monitor);

    dispatch_group_wait(group, DISPATCH_TIME_FOREVER);
    dispatch_release(group);
#endif // __APPLE__

#ifdef __linux__
    if (!loop) {
        return;
    }

    if (!create_socket()) {
        return;
    }

    m_monitor_event = event_new(vpn_event_loop_get_base(loop), m_monitor_sock_fd, EV_READ | EV_PERSIST,
        [](evutil_socket_t fd, short events, void *arg) {
            auto monitor = static_cast<NetworkMonitorImpl *>(arg);
            if (fd == monitor->m_monitor_sock_fd) {
                monitor->changed_handler();
            }
        }, this);

    event_add(m_monitor_event, nullptr);
#endif // __linux__
}

void NetworkMonitorImpl::stop() {
    dbglog(m_logger, "...");
    if (!is_running()) {
        return;
    }
#ifdef __APPLE__
    nw_path_monitor_cancel(m_nw_path_monitor);
    m_nw_path_monitor = nullptr;

    dispatch_release(m_dispatch_queue);
    m_dispatch_queue = nullptr;

    m_first_update_done = false;
#endif // __APPLE__

#ifdef __linux__
    event_del(m_monitor_event);
    event_free(m_monitor_event);
    m_monitor_event = nullptr;

    close_socket();
#endif // __linux__
    m_if_name.clear();
}

#ifdef __APPLE__
static std::string get_interface_name(nw_path_t path) {
    __block std::string if_name;
    nw_path_enumerate_interfaces(path, ^(nw_interface_t iface) {
        if (std::string name = nw_interface_get_name(iface);
                !name.starts_with("utun") && !name.starts_with("ipsec")) {
            if_name = std::move(name);
            return false;
        }
        return true;
    });
    return if_name;
}
#endif // __APPLE__

std::string NetworkMonitorImpl::get_default_interface() {
#ifdef _WIN32
    uint32_t if_index = vpn_win_detect_active_if();
    if (if_index == 0) {
        errlog(m_logger, "Couldn't detect active network interface");
        return "";
    }
    char if_name[IF_NAMESIZE]{};
    if_indextoname(if_index, if_name);
    return if_name;
#endif // _WIN32

#ifdef __APPLE__
    bool needed_stop_monitor = false;

    if (!m_nw_path_monitor) {
        start(nullptr);
        needed_stop_monitor = true;
    }

    std::string if_name = get_interface_name(m_current_path);

    if (needed_stop_monitor) {
        stop();
    }

    return if_name;
#endif // __APPLE__

#ifdef __linux__
    constexpr std::string_view CMD = "ip -o route show to default";
    infolog(m_logger, "{} {}", (geteuid() == 0) ? '#' : '$', CMD);
    Result result = tunnel_utils::fsystem_with_output(CMD);
    if (result.has_error()) {
        errlog(m_logger,
                "Couldn't detect the outbound interface automatically. Please specify it manually. Error: {}",
                result.error()->str());
        return "";
    }

    dbglog(m_logger, "Command output: {}", result.value());
    std::vector parts = utils::split_by(result.value(), ' ');
    auto found = std::find(parts.begin(), parts.end(), "dev");
    if (found == parts.end() || std::next(found) == parts.end()) {
        if (!result.value().empty()) {
            warnlog(m_logger, "Couldn't find the outbound interface name automatically");
        }
        return "";
    }

    return std::string(*std::next(found));
#endif // __linux__
}

bool NetworkMonitorImpl::is_running() const {
#ifdef __APPLE__
    return m_nw_path_monitor != nullptr;
#endif // __APPLE__

#ifdef __linux__
    return m_monitor_event != nullptr;
#endif // __linux__
}

NetworkMonitorImpl::~NetworkMonitorImpl() {
    stop();
}

#ifdef __linux__
bool NetworkMonitorImpl::create_socket() {
    m_monitor_sock_fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (m_monitor_sock_fd < 0) {
        errlog(m_logger, "Couldn't create netlink socket");
        return false;
    }

    // noneblock
    int flags = fcntl(m_monitor_sock_fd, F_GETFL, 0);
    if (flags == -1) {
        errlog(m_logger, "Couldn't get socket flags");
        close_socket();
        return false;
    }
    flags |= O_NONBLOCK;
    if (fcntl(m_monitor_sock_fd, F_SETFL, flags) == -1) {
        errlog(m_logger, "Couldn't set socket to non-blocking mode");
        close_socket();
        return false;
    }

    sockaddr_nl sa{};
    sa.nl_family = AF_NETLINK;
    sa.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR;

    if (bind(m_monitor_sock_fd, (sockaddr*)&sa, sizeof(sa)) < 0) {
        errlog(m_logger, "Couldn't bind netlink socket");
        close_socket();
        return false;
    }

    return true;
}

void NetworkMonitorImpl::close_socket() {
    if (m_monitor_sock_fd != -1) {
        close(m_monitor_sock_fd);
        m_monitor_sock_fd = -1;
    }
}
#endif // __linux__

void NetworkMonitorImpl::changed_handler() {
#ifdef __APPLE__
    bool is_satisfied = nw_path_get_status(m_current_path) == nw_path_status_satisfied;
    dbglog(m_logger, "is_satisfied: {}", is_satisfied);

    std::string new_if_name = get_interface_name(m_current_path);

    if (m_first_update_done) {
        handle_network_change(new_if_name, is_satisfied);
    } else {
        m_if_name = new_if_name;
        m_first_update_done = true;
    }
#endif // __APPLE__

#ifdef __linux__
    nlmsghdr buf[8192/sizeof(struct nlmsghdr)];
    sockaddr_nl sa{};
    iovec iov = {buf, sizeof(buf)};
    msghdr msg = {
            .msg_name = (void*)&sa,
            .msg_namelen = sizeof(sa),
            .msg_iov = &iov,
            .msg_iovlen = 1,
            .msg_control = nullptr,
            .msg_controllen = 0,
            .msg_flags = 0
    };
    ssize_t len = recvmsg(m_monitor_sock_fd, &msg, 0);
    if (len < 0) {
        errlog(m_logger, "Couldn't recvmsg netlink socket");
        return;
    }

    for (auto nlh = (nlmsghdr *)buf; NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len)) {
        if (nlh->nlmsg_type == RTM_NEWADDR || nlh->nlmsg_type == RTM_DELADDR) {
            auto new_if_name = get_default_interface();
            handle_network_change(new_if_name, !new_if_name.empty());
        }
    }
#endif // __linux__
}

void NetworkMonitorImpl::handle_network_change(const std::string &new_if_name, bool is_satisfied) {
    if (!is_satisfied) {
        dbglog(m_logger, "Network not connected");
        if (m_cmd_handler) {
            m_cmd_handler("", false);
        }
        m_if_name.clear();
    } else if (m_if_name != new_if_name) {
        dbglog(m_logger, "Network connected {}", new_if_name);
        if (m_cmd_handler) {
            m_cmd_handler(new_if_name, true);
        }
        m_if_name = new_if_name;
    }
}

} // namespace ag
