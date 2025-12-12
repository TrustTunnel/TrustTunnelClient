#import "VpnClient.h"
#import "vpn/trusttunnel/client.h"
#import "vpn/trusttunnel/connection_info.h"
#import "net/network_manager.h"
#import "common/socket_address.h"

#import <common/network_monitor.h>
#import <common/cidr_range.h>

#import "toml++/toml.h"

#import <net/if.h>
#import <netinet/in.h>
#import <ifaddrs.h>
#import <os/log.h>

static ag::Logger g_logger("VPN_CLIENT");

NS_ASSUME_NONNULL_BEGIN

static void update_interface(const std::string &if_name) {
    uint32_t if_index = if_nametoindex(if_name.c_str());
    if (if_index != 0) {
        ag::vpn_network_manager_set_outbound_interface(if_index);
    }
}

#if TARGET_OS_IPHONE
static ag::SocketAddress get_interface_address(const char *if_name, int family) {
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == 0) {
        for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
            if (0 != strcmp(ifa->ifa_name, if_name)) {
                continue;
            }
            if (ifa->ifa_addr->sa_family == family) {
                ag::SocketAddress sa{ifa->ifa_addr};
                if (family == AF_INET6) {
                    if (sa.addr()[0] == 0xfe && sa.addr()[1] == 0x80) {
                        continue;
                    }
                }
                freeifaddrs(ifaddr);
                return sa;
            }
        }
        freeifaddrs(ifaddr);
    }
    return {};
}
#endif

static bool protectSocket(ag::SocketProtectEvent *event) {
    char if_name[IF_NAMESIZE] = "not set";
    uint32_t idx = ag::vpn_network_manager_get_outbound_interface();
    if_indextoname(idx, if_name);
    dbglog(g_logger, "Setting outbound interface for connection to {} to {} ({})", ag::SocketAddress{event->peer}, idx,
           ag::safe_to_string_view(if_name));
    if (idx == 0) {
        return false;
    }
    if (event->peer->sa_family == AF_INET) {
        if (setsockopt(event->fd, IPPROTO_IP, IP_BOUND_IF, &idx, sizeof(idx)) != 0) {
            dbglog(g_logger, "Setsockopt BOUND_IF failed: {}", strerror(errno));
            return false;
        }
#if TARGET_OS_IPHONE
        if (auto sa = get_interface_address(if_name, AF_INET); sa.valid()) {
            if (bind(event->fd, sa.c_sockaddr(), sa.c_socklen()) != 0) {
                dbglog(g_logger, "Bind to {} failed: {}", sa, strerror(errno));
                return false;
            }
        } else {
            dbglog(g_logger, "No address to bind");
            return false;
        }
#endif
    } else if (event->peer->sa_family == AF_INET6) {
        if (setsockopt(event->fd, IPPROTO_IPV6, IPV6_BOUND_IF, &idx, sizeof(idx)) != 0) {
            dbglog(g_logger, "Setsockopt BOUND_IF failed: {}", strerror(errno));
            return false;
        }
#if TARGET_OS_IPHONE
        if (auto sa = get_interface_address(if_name, AF_INET6); sa.valid()) {
            if (bind(event->fd, sa.c_sockaddr(), sa.c_socklen()) != 0) {
                dbglog(g_logger, "Bind to {} failed: {}", sa, strerror(errno));
                return false;
            }
        } else {
            dbglog(g_logger, "No address to bind");
            return false;
        }
#endif
    }
    return true;
}

static _Nullable SecCertificateRef convertCertificate(X509 *cert) {
    unsigned char *buffer = NULL;
    int len = i2d_X509(cert, &buffer);
    if (len < 0) {
        return NULL;
    }
    NSData *data = [[NSData alloc] initWithBytesNoCopy:(void *)buffer
                                                length:len
                                        deallocator:^void(void *bytes, NSUInteger length) {
                                            OPENSSL_free(bytes);
                                        }];
    return SecCertificateCreateWithData(NULL, (__bridge CFDataRef)data);
}

static bool verify_certificate(const ag::VpnVerifyCertificateEvent *event) {
    SecCertificateRef cert = convertCertificate(event->cert);
    if (!cert) {
        errlog(g_logger, "Failed to create certificate object");
        return false;
    }
    STACK_OF(X509) *chain = event->chain;
    size_t chainLength = sk_X509_num(chain);
    if (chainLength < 0) {
        CFRelease(cert);
        errlog(g_logger, "Untrusted certificate chain is null");
        return false;
    }
    NSMutableArray *trustArray = [[NSMutableArray alloc] initWithCapacity:chainLength + 1];
    [trustArray addObject:(__bridge_transfer id) cert];
    for (size_t i = 0; i < chainLength; ++i) {
        SecCertificateRef chainedCert = convertCertificate(sk_X509_value(chain, i));
        if (!chainedCert) {
            errlog(g_logger, "Failed to create chained certificate object");
            return false;
        }
        [trustArray addObject:(__bridge_transfer id) chainedCert];
    }
    SecPolicyRef policy = SecPolicyCreateBasicX509();
    SecTrustRef trust = NULL;
    OSStatus status = SecTrustCreateWithCertificates((__bridge CFTypeRef)trustArray, policy, &trust);
    if (policy) {
        CFRelease(policy);
    }
    if (status != errSecSuccess) {
        CFRelease(trust);
        /* return getTrustCreationErrorStr(status); */
        return false;
    }
    SecTrustSetAnchorCertificatesOnly(trust, false);
    bool res = SecTrustEvaluateWithError(trust, NULL);
    CFRelease(trust);
    return res;
}

static void NSData_VpnPacket_destructor(void *arg, uint8_t *) {
    @autoreleasepool {
        NSData *data = (__bridge_transfer NSData *) arg;
        (void) data;
    }
}

@interface VpnClient () {
    std::unique_ptr<ag::TrustTunnelClient> _native_client;
    std::unique_ptr<ag::utils::NetworkMonitor> _network_monitor;
    NEPacketTunnelFlow *_tunnelFlow;
    id _readPacketsHandler;
}
@end

@implementation VpnClient

- (BOOL)processClientPackets:(NSArray<NSData *> *)packets {
    ag::VpnPackets nativePackets = {};
    nativePackets.size = [packets count];
    std::vector<ag::VpnPacket> buf(nativePackets.size);
    nativePackets.data = buf.data();
    for (size_t i = 0; i < nativePackets.size; ++i) {
        nativePackets.data[i] = ag::VpnPacket{
            .data = (uint8_t *) packets[i].bytes,
            .size = (size_t) packets[i].length,
            .destructor = NSData_VpnPacket_destructor,
            .destructor_arg = (__bridge_retained void *) packets[i],
        };
    }

    return _native_client->process_client_packets(nativePackets);
}

- (instancetype)initWithConfig:(NSString *)config
            connectionInfoHandler:(ConnectionInfoHandler)connectionInfoHandler
            stateChangeHandler:(StateChangeHandler)stateChangeHandler {
    self = [super init];
    if (self) {

        ag::Logger::set_callback([](ag::LogLevel level, std::string_view message) {
            static const char *const levels[] = {
                [ag::LOG_LEVEL_ERROR] = "ERROR",   [ag::LOG_LEVEL_WARN] = "WARN",   [ag::LOG_LEVEL_INFO] = "INFO",
                [ag::LOG_LEVEL_DEBUG] = "DEBUG", [ag::LOG_LEVEL_TRACE] = "TRACE",
            };
            static os_log_t log_handle = os_log_create("com.adguard.TrustTunnel.VpnClientFramework", "VpnClient");
            os_log(log_handle, "[%{public}s]\t%{public}.*s", levels[level], (int)message.size(), message.data());
        });

        toml::parse_result parse_result = toml::parse(config.UTF8String);
        if (!parse_result) {
            errlog(g_logger, "Failed to parse configuration: {}", parse_result.error().description());
            return nil;
        }
        auto trusttunnel_config = ag::TrustTunnelConfig::build_config(parse_result);
        if (!trusttunnel_config) {
            return nil;
        }
        ag::VpnCallbacks callbacks = {
            .protect_handler = [](ag::SocketProtectEvent *event) {
                event->result = protectSocket(event)
                    ? 0
                    : -1;
            },
            .verify_handler = [](ag::VpnVerifyCertificateEvent *event) {
                event->result = verify_certificate(event)
                    ? 0
                    : -1;
            },
            .client_output_handler = [self](ag::VpnClientOutputEvent *event) {
                @autoreleasepool {
                    size_t length = 0;
                    for (size_t i = 0; i < event->packet.chunks_num; ++i) {
                        length += event->packet.chunks[i].iov_len;
                    }
                    NSMutableData *packet = [[NSMutableData alloc] initWithCapacity:length];
                    for (size_t i = 0; i < event->packet.chunks_num; ++i) {
                        [packet appendBytes:event->packet.chunks[i].iov_base length:event->packet.chunks[i].iov_len];
                    }
                    [self->_tunnelFlow writePackets:@[packet] withProtocols:@[@(event->family)]];
                }
            },
            .state_changed_handler = [stateChangeHandler](ag::VpnStateChangedEvent *event) {
                stateChangeHandler((int)event->state);
            },
            .connection_info_handler = [connectionInfoHandler](ag::VpnConnectionInfoEvent *info) {
                std::string json = ag::ConnectionInfo::to_json(info);
                NSString * str = [NSString stringWithUTF8String: json.c_str()];
                connectionInfoHandler(str);
            }
        };
        self->_native_client = std::make_unique<ag::TrustTunnelClient>(std::move(*trusttunnel_config), std::move(callbacks));
        __weak typeof(self) weakSelf = self;
        self->_network_monitor = ag::utils::create_network_monitor(
            [weakSelf](const std::string &if_name, bool is_connected) {
                update_interface(if_name);
                __strong typeof(self) strongSelf = weakSelf;
                if (strongSelf->_native_client) {
                    strongSelf->_native_client->notify_network_change(is_connected ? ag::VPN_NS_CONNECTED : ag::VPN_NS_NOT_CONNECTED);
                }
            }
        );
        self->_network_monitor->start(nullptr);
        std::string if_name = self->_network_monitor->get_default_interface();
        update_interface(if_name);
    }
    return self;
}

- (void)dealloc {
    _network_monitor->stop(); // shuts down monitor before self is gone
    _network_monitor = nullptr;
}

- (bool)start:(NEPacketTunnelFlow *)tunnelFlow {
    _tunnelFlow = tunnelFlow;
    __weak typeof(self) weakSelf = self;

    auto error = _native_client->connect(ag::TrustTunnelClient::UseProcessPackets{});
    if (error) {
        errlog(g_logger, "Failed to connect: {}", error->pretty_str());
        return  false;
    }
    _readPacketsHandler = ^(NSArray<NSData *> *packets, NSArray<NSNumber *> *protocols) {
        __strong typeof(self) strongSelf = weakSelf;
        if (!strongSelf || ![strongSelf processClientPackets:packets]) {
            infolog(g_logger, "Reading packets stopped");
            return;
        }
        [strongSelf->_tunnelFlow readPacketsWithCompletionHandler:strongSelf->_readPacketsHandler];
    };
    infolog(g_logger, "Reading packets started");
    [_tunnelFlow readPacketsWithCompletionHandler:_readPacketsHandler];
    
    return true;
}

- (bool)stop {
    return _native_client->disconnect();
}

- (void)notify_sleep {
    _native_client->notify_sleep();
}
- (void)notify_wake {
    _native_client->notify_wake();
}

+ (NSArray<NSString *> *)excludeCidr:(NSArray<NSString *> *)includeRoutes
                       excludeRoutes:(NSArray<NSString *> *)excludeRoutes {
    std::vector<ag::CidrRange> includeRanges;
    includeRanges.reserve(includeRoutes.count);
    for(NSString *route in includeRoutes) {
        includeRanges.emplace_back(route.UTF8String);
    }

    std::vector<ag::CidrRange> excludeRanges;
    excludeRanges.reserve(excludeRoutes.count);
    for(NSString *route in excludeRoutes) {
        excludeRanges.emplace_back(route.UTF8String);
    }

    std::vector<ag::CidrRange> result = ag::CidrRange::exclude(includeRanges, excludeRanges);
    NSMutableArray<NSString *> *nsresult = [NSMutableArray arrayWithCapacity:result.size()];
    for (const auto &range : result) {
        auto str = range.to_string();
        NSString *nsstr = [NSString stringWithUTF8String:str.c_str()];
        [nsresult addObject:nsstr];
    }

    return nsresult;
}


@end

NS_ASSUME_NONNULL_END
