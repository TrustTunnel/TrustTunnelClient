/**
 * @file test_tun_echo.cpp
 * @brief Minimal TUN echo test for tcpip module
 * 
 * This test:
 * 1. Creates a UTUN descriptor using SYS_CONTROL socket
 * 2. Configures the adapter: ifconfig utunN 1.2.3.3/24 up; route add 1.2.3.4 -iface utunN
 * 3. Creates vpn_event_loop
 * 4. Starts TcpIp instance with echo callbacks (sends client data back)
 * 5. Tests with: nc 1.2.3.4 1234; nc -u 1.2.3.4 1234; ping 1.2.3.4
 */

#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <atomic>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <thread>

#ifdef __APPLE__
#include <TargetConditionals.h>
#endif

#if defined(__APPLE__) && !TARGET_OS_IPHONE
#include <net/if_utun.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#elif defined(__linux__) && !defined(ANDROID)
#include <fcntl.h>
#include <linux/if_tun.h>
#endif

#include <event2/util.h>

#include <cxxopts.hpp>

#include "common/logger.h"
#include "tcpip/tcpip.h"
#include "vpn/event_loop.h"

using namespace ag;

static Logger g_test_log{"TUN_ECHO_TEST"};
static VpnEventLoop *g_event_loop = nullptr;
static TcpipCtx *g_tcpip = nullptr;
static std::atomic_bool g_keep_running{true};

static void signal_handler(int sig) {
    g_keep_running.store(false);
}

static void setup_signal_handler() {
    signal(SIGPIPE, SIG_IGN);
    // Block SIGINT and SIGTERM - they will be waited using sigwait()
    sigset_t sigset;
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGINT);
    sigaddset(&sigset, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &sigset, nullptr);
    
    // Create thread to wait for signals
    std::thread([sigset] {
        int signum = 0;
        while (true) {
            sigwait(&sigset, &signum);
            signal_handler(signum);
        }
    }).detach();
}

/**
 * Create TUN device (UTUN on macOS, TUN on Linux)
 * @return file descriptor or -1 on error
 */
static int create_utun_device(std::string &tun_name) {
    int fd = -1;

#if defined(__APPLE__) && !TARGET_OS_IPHONE
    fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (fd < 0) {
        errlog(g_test_log, "Failed to create socket: ({}) {}", errno, strerror(errno));
        return -1;
    }

    if (0 != evutil_make_socket_closeonexec(fd)) {
        warnlog(g_test_log, "Failed to make socket close on exec: ({}) {}", errno, strerror(errno));
    }

    struct ctl_info info{
        .ctl_name = UTUN_CONTROL_NAME
    };

    if (ioctl(fd, CTLIOCGINFO, &info) < 0) {
        errlog(g_test_log, "IOCTL system call failed: ({}) {}", errno, strerror(errno));
        close(fd);
        return -1;
    }

    struct sockaddr_ctl addr{};
    addr.sc_id = info.ctl_id;
    addr.sc_len = sizeof(addr);
    addr.sc_family = AF_SYSTEM;
    addr.ss_sysaddr = AF_SYS_CONTROL;
    addr.sc_unit = 0;

    if (connect(fd, (struct sockaddr *) &addr, sizeof(addr)) != 0) {
        errlog(g_test_log, "Failed to connect: ({}) {}", errno, strerror(errno));
        close(fd);
        return -1;
    }

    // Get assigned unit number
    socklen_t addr_len = sizeof(struct sockaddr_ctl);
    if (getpeername(fd, (struct sockaddr *) &addr, &addr_len) != 0) {
        errlog(g_test_log, "Failed to get tun number: ({}) {}", errno, strerror(errno));
        close(fd);
        return -1;
    }

    tun_name = AG_FMT("utun{}", addr.sc_unit - 1);
    dbglog(g_test_log, "Created device: {}", tun_name);

#elif defined(__linux__) && !defined(ANDROID)
    fd = open("/dev/net/tun", O_RDWR);

    if (fd == -1) {
        errlog(g_test_log, "Failed to open /dev/net/tun: {}", strerror(errno));
        return -1;
    }

    struct ifreq ifr = {};
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    if (ioctl(fd, TUNSETIFF, &ifr) == -1) {
        close(fd);
        errlog(g_test_log, "ioctl TUNSETIFF failed: {}", strerror(errno));
        return -1;
    }

    tun_name = ifr.ifr_name;
    dbglog(g_test_log, "Device {} opened", tun_name);

#else
    errlog(g_test_log, "TUN device creation not supported on this platform");
    return -1;
#endif
    return fd;
}

/**
 * Configure TUN interface with IP address and routes
 */
static bool configure_tun_interface(const std::string &tun_name) {
#if defined(__APPLE__) && !TARGET_OS_IPHONE
    // Configure interface: ifconfig utunN 1.2.3.3/24 up
    std::string cmd = AG_FMT("ifconfig {} 1.2.3.3 1.2.3.3 netmask 255.255.255.0 up", tun_name);
    dbglog(g_test_log, "Executing: {}", cmd);
    
    int result = system(cmd.c_str());
    if (result != 0) {
        errlog(g_test_log, "Failed to configure interface, exit code: {}", WEXITSTATUS(result));
        return false;
    }

    // Add route: route add 1.2.3.4 -iface utunN
    cmd = AG_FMT("route add 1.2.3.4 -iface {}", tun_name);
    dbglog(g_test_log, "Executing: {}", cmd);
    
    result = system(cmd.c_str());
    if (result != 0) {
        errlog(g_test_log, "Failed to add route, exit code: {}", WEXITSTATUS(result));
        return false;
    }

#elif defined(__linux__) && !defined(ANDROID)
    // Configure interface: ip addr add 1.2.3.3/24 dev tunN
    std::string cmd = AG_FMT("ip addr add 1.2.3.3/24 dev {}", tun_name);
    dbglog(g_test_log, "Executing: {}", cmd);
    
    int result = system(cmd.c_str());
    if (result != 0) {
        errlog(g_test_log, "Failed to configure interface, exit code: {}", WEXITSTATUS(result));
        return false;
    }

    // Bring interface up
    cmd = AG_FMT("ip link set {} up", tun_name);
    dbglog(g_test_log, "Executing: {}", cmd);
    
    result = system(cmd.c_str());
    if (result != 0) {
        errlog(g_test_log, "Failed to bring interface up, exit code: {}", WEXITSTATUS(result));
        return false;
    }

    // Add route: ip route add 1.2.3.4 dev tunN
    cmd = AG_FMT("ip route add 1.2.3.4 dev {}", tun_name);
    dbglog(g_test_log, "Executing: {}", cmd);
    
    result = system(cmd.c_str());
    if (result != 0) {
        errlog(g_test_log, "Failed to add route, exit code: {}", WEXITSTATUS(result));
        return false;
    }

#else
    errlog(g_test_log, "TUN configuration not supported on this platform");
    return false;
#endif

    dbglog(g_test_log, "Interface configured successfully");
    return true;
}

/**
 * TcpIp event handler - implements echo server
 */
static void tcpip_event_handler(void *arg, TcpipEvent event, void *data) {
    (void) arg;

    switch (event) {
    case TCPIP_EVENT_GENERATE_CONN_ID: {
        static uint64_t next_id = 1;
        *(uint64_t *) data = next_id++;
        break;
    }

    case TCPIP_EVENT_CONNECT_REQUEST: {
        auto *req = (TcpipConnectRequestEvent *) data;
        char src_str[INET6_ADDRSTRLEN];
        char dst_str[INET6_ADDRSTRLEN];
        
        const sockaddr *src_sa = req->src->c_sockaddr();
        const sockaddr *dst_sa = req->dst->c_sockaddr();
        
        inet_ntop(src_sa->sa_family,
                src_sa->sa_family == AF_INET 
                    ? (void*)&((struct sockaddr_in*)src_sa)->sin_addr
                    : (void*)&((struct sockaddr_in6*)src_sa)->sin6_addr,
                src_str, sizeof(src_str));
        
        inet_ntop(dst_sa->sa_family,
                dst_sa->sa_family == AF_INET
                    ? (void*)&((struct sockaddr_in*)dst_sa)->sin_addr
                    : (void*)&((struct sockaddr_in6*)dst_sa)->sin6_addr,
                dst_str, sizeof(dst_str));

        uint16_t src_port = ntohs(src_sa->sa_family == AF_INET
                ? ((struct sockaddr_in*)src_sa)->sin_port
                : ((struct sockaddr_in6*)src_sa)->sin6_port);
        
        uint16_t dst_port = ntohs(dst_sa->sa_family == AF_INET
                ? ((struct sockaddr_in*)dst_sa)->sin_port
                : ((struct sockaddr_in6*)dst_sa)->sin6_port);

        dbglog(g_test_log, "[{}] Connect request: {} proto={} {}:{} -> {}:{}",
                req->id,
                req->proto == IPPROTO_TCP ? "TCP" : "UDP",
                req->proto,
                src_str, src_port,
                dst_str, dst_port);

        // Accept all connections
        tcpip_complete_connect_request(g_tcpip, req->id, TCPIP_ACT_BYPASS);
        break;
    }

    case TCPIP_EVENT_CONNECTION_ACCEPTED: {
        uint64_t id = *(uint64_t *) data;
        dbglog(g_test_log, "[{}] Connection accepted", id);
        break;
    }

    case TCPIP_EVENT_READ: {
        auto *read_event = (TcpipReadEvent *) data;
        
        // Calculate total data size
        size_t total_size = 0;
        for (size_t i = 0; i < read_event->iovlen; i++) {
            total_size += read_event->iov[i].iov_len;
        }

        dbglog(g_test_log, "[{}] Read {} bytes ({} chunks)", read_event->id, total_size, read_event->iovlen);

        // Echo data back: copy all chunks and send
        size_t sent = 0;
        for (size_t i = 0; i < read_event->iovlen; i++) {
            const uint8_t *chunk_data = (const uint8_t *) read_event->iov[i].iov_base;
            size_t chunk_len = read_event->iov[i].iov_len;

            int result = tcpip_send_to_client(g_tcpip, read_event->id, chunk_data, chunk_len);
            if (result < 0) {
                errlog(g_test_log, "[{}] Failed to send data", read_event->id);
                read_event->result = result;
                return;
            }
            sent += result;
        }

        read_event->result = sent;
        break;
    }

    case TCPIP_EVENT_DATA_SENT: {
        auto *sent_event = (TcpipDataSentEvent *) data;
        tracelog(g_test_log, "[{}] Data sent: {} bytes", sent_event->id, sent_event->length);
        break;
    }

    case TCPIP_EVENT_CONNECTION_CLOSED: {
        uint64_t id = *(uint64_t *) data;
        infolog(g_test_log, "[{}] Connection closed", id);
        break;
    }

    case TCPIP_EVENT_TUN_OUTPUT: {
        // Data to be written to TUN device - handled by tcpip internally
        break;
    }

    case TCPIP_EVENT_ICMP_ECHO: {
        auto *icmp = (IcmpEchoRequestEvent *) data;
        dbglog(g_test_log, "ICMP echo request: id={} seq={}", icmp->request.id, icmp->request.seqno);
        
        // Echo ICMP reply
        IcmpEchoReply reply{};
        reply.peer = icmp->request.peer;
        reply.id = icmp->request.id;
        reply.seqno = icmp->request.seqno;
        reply.type = 0;  // ICMP Echo Reply
        reply.code = 0;
        
        tcpip_process_icmp_echo_reply(g_tcpip, &reply);
        icmp->result = 0;
        break;
    }

    case TCPIP_EVENT_STAT_NOTIFY:
        // Ignore statistics
        break;
    }
}

/**
 * Print usage instructions
 */
static void print_usage() {
    fmt::println("=================================================================");
    fmt::println("");
    fmt::println("Test commands (run in another terminal):");
    fmt::println("");
    fmt::println("  1. TCP echo test:");
    fmt::println("     echo 'Hello TCP' | nc 1.2.3.4 1234");
    fmt::println("");
    fmt::println("  2. UDP echo test:");
    fmt::println("     echo 'Hello UDP' | nc -u 1.2.3.4 1234");
    fmt::println("");
    fmt::println("  3. ICMP ping test:");
    fmt::println("     ping -c 4 1.2.3.4");
    fmt::println("");
    fmt::println("  4. HTTP test (if you have a web server):");
    fmt::println("     curl http://1.2.3.4:8080/");
    fmt::println("");
    fmt::println("Press Ctrl+C to stop the server");
    fmt::println("=================================================================");
}

int main(int argc, char *argv[]) {
    setup_signal_handler();

    // Parse command line arguments
    cxxopts::Options args("test_tun_echo", "TUN echo test utility for tcpip module");
    // clang-format off
    args.add_options()
            ("p,pcap", "Enable pcap output to file", cxxopts::value<std::string>()->default_value(""))
            ("l,loglevel", "Logging level. Possible values: error, warn, info, debug, trace.",
                cxxopts::value<std::string>()->default_value("info"))
            ("u,usage", "Print usage instructions")
            ("h,help", "Print usage");
    // clang-format on

    auto result = args.parse(argc, argv);
    if (result.count("help")) {
        fmt::println("{}", args.help());
        return 0;
    }
    if (result.count("usage")) {
        print_usage();
        return 0;
    }

    if (result.count("help")) {
        fmt::println("{}", args.help());
        return 0;
    }

    // Set log level from command line
    std::string loglevel_str = result["loglevel"].as<std::string>();
    LogLevel loglevel = LogLevel::LOG_LEVEL_INFO;
    if (loglevel_str == "error") {
        loglevel = LogLevel::LOG_LEVEL_ERROR;
    } else if (loglevel_str == "warn") {
        loglevel = LogLevel::LOG_LEVEL_WARN;
    } else if (loglevel_str == "info") {
        loglevel = LogLevel::LOG_LEVEL_INFO;
    } else if (loglevel_str == "debug") {
        loglevel = LogLevel::LOG_LEVEL_DEBUG;
    } else if (loglevel_str == "trace") {
        loglevel = LogLevel::LOG_LEVEL_TRACE;
    } else {
        fmt::println(stderr, "Invalid log level: {}", loglevel_str);
        return 1;
    }
    Logger::set_log_level(loglevel);

    // Get pcap filename if specified
    std::string pcap_file = result["pcap"].as<std::string>();
    const char *pcap_filename = pcap_file.empty() ? nullptr : pcap_file.c_str();

    dbglog(g_test_log, "Starting TUN echo test...");

    // Step 1: Create UTUN device
    std::string tun_name;
    int tun_fd = create_utun_device(tun_name);
    if (tun_fd < 0) {
        errlog(g_test_log, "Failed to create UTUN device");
        return 1;
    }

    // Step 2: Configure interface and routes
    if (!configure_tun_interface(tun_name)) {
        errlog(g_test_log, "Failed to configure TUN interface");
        close(tun_fd);
        return 1;
    }

    // Step 3: Create event loop
    g_event_loop = vpn_event_loop_create();
    if (!g_event_loop) {
        errlog(g_test_log, "Failed to create event loop");
        close(tun_fd);
        return 1;
    }

    // Step 4: Initialize TcpIp stack
    TcpipParameters params{};
    params.tun_fd = tun_fd;
    params.event_loop = g_event_loop;
    params.mtu_size = 1500;
    params.pcap_filename = pcap_filename;
    params.handler.handler = tcpip_event_handler;
    params.handler.arg = nullptr;

    if (pcap_filename) {
        dbglog(g_test_log, "PCAP output enabled: {}", pcap_filename);
    }

    g_tcpip = tcpip_open(&params);
    if (!g_tcpip) {
        errlog(g_test_log, "Failed to initialize TcpIp stack");
        vpn_event_loop_destroy(g_event_loop);
        close(tun_fd);
        return 1;
    }

    dbglog(g_test_log, "TcpIp stack initialized successfully");
    infolog(g_test_log, "TUN Echo Test Server Started");
    infolog(g_test_log, "The server is now listening on 1.2.3.4");

    // Step 5: Run event loop in separate thread
    dbglog(g_test_log, "Starting event loop...");
    std::thread event_loop_thread([] {
        vpn_event_loop_run(g_event_loop);
    });

    while (g_keep_running.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    // Stop event loop
    dbglog(g_test_log, "Stopping event loop...");
    vpn_event_loop_stop(g_event_loop);
    event_loop_thread.join();
    
    dbglog(g_test_log, "Event loop stopped gracefully");

    // Cleanup
    dbglog(g_test_log, "Cleaning up...");
    tcpip_close(g_tcpip);
    vpn_event_loop_destroy(g_event_loop);
    close(tun_fd);

    infolog(g_test_log, "Test completed");
    return 0;
}
