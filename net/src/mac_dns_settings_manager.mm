#include "net/mac_dns_settings_manager.h"

#import <TargetConditionals.h>

#import <dispatch/dispatch.h>
#import <Foundation/Foundation.h>
#import <SystemConfiguration/SystemConfiguration.h>

#import "net/utils.h"
#import "common/clock.h"
#import "common/logger.h"

#import "net/network_manager.h"

namespace ag {

#if !TARGET_OS_IPHONE
class VpnMacDnsSettingsManagerImpl {
    dispatch_queue_t m_queue;
    SCDynamicStoreRef m_store = nullptr;
    NSString *m_primary_service;
    SteadyClock::time_point m_last_updated_primary_service{};
    std::string m_dns_server;
    bool m_valid = false;
    Logger m_logger{"VpnMacDnsSettingsManager"};

    struct ConstructorAccess {};

public:
    VpnMacDnsSettingsManagerImpl(ConstructorAccess access, std::string_view dns_server)
            : m_dns_server(dns_server)
    {
        static const int atexit_initialized [[maybe_unused]] = atexit(&VpnMacDnsSettingsManagerImpl::touch_prefs);
        m_queue = dispatch_queue_create("org.adguard.vpnlibs.MacDnsManager", DISPATCH_QUEUE_SERIAL);
        if (!m_queue) {
            return;
        }
        SCDynamicStoreContext context{};
        context.info = this;
        m_store = SCDynamicStoreCreate(nullptr, (__bridge CFStringRef) @"MacDnsManager",
                [](SCDynamicStoreRef store, CFArrayRef changed_keys, void *info) {
                    auto *self = (VpnMacDnsSettingsManagerImpl *) info;
                    self->on_keys_changed((__bridge NSArray *) changed_keys);
                }, &context);
        if (!m_store) {
            return;
        }
        SCDynamicStoreSetNotificationKeys(m_store, nullptr, (__bridge CFArrayRef) @[
            @"^State:/Network/Global/IPv[46]$",
            @"^Setup:/Network/Service/.*/DNS$",
            @"^State:/Network/Service/.*/DNS$",
        ]);
        SCDynamicStoreSetDispatchQueue(m_store, m_queue);
        SCDynamicStoreNotifyValue(m_store, (__bridge CFStringRef) @"State:/Network/Global/IPv4");
        SCDynamicStoreNotifyValue(m_store, (__bridge CFStringRef) @"State:/Network/Global/IPv6");
        m_valid = true;
    }

    static VpnMacDnsSettingsManagerImplPtr create(std::string_view dns_server) {
        auto manager = std::make_unique<VpnMacDnsSettingsManagerImpl>(ConstructorAccess{}, dns_server);
        if (!manager->m_valid) {
            manager.reset();
        }
        return manager;
    }

    ~VpnMacDnsSettingsManagerImpl() {
        touch_prefs();
        if (m_store) {
            SCDynamicStoreSetDispatchQueue(m_store, nullptr);
            CFRelease(m_store);
            m_store = nullptr;
        }
    }

    void on_keys_changed(NSArray *changed_keys) {
        if (m_logger.is_enabled(LOG_LEVEL_DEBUG)) {
            std::vector<std::string> keys;
            for (NSObject *key in changed_keys) {
                NSString *keyStr = [key description];
                keys.push_back(std::string([keyStr UTF8String]));
            }
            dbglog(m_logger, "On keys changed: {}", ag::utils::join(keys.begin(), keys.end(), ", "));
        }

        for (NSString *key in changed_keys) {
            // If DNS setup changed, check if it must be rewritten
            if ([key rangeOfString:@"^Setup:/Network/Service/.*/DNS$" options:NSRegularExpressionSearch].location != NSNotFound) {
                // Avoid loops with other apps
                if (SteadyClock::now() < m_last_updated_primary_service + Secs{5}) {
                    // This will be called several times since prefs is touched.
                    setup_store();
                }
                return;
            }
            // If DNS state changed, pass it to vpn_network_manager.
            if ([key rangeOfString:@"^State:/Network/Service/.*/DNS$" options:NSRegularExpressionSearch].location != NSNotFound) {
                if (m_primary_service && [key containsString:m_primary_service]) {
                    NSDictionary *dns_config = (__bridge_transfer NSDictionary *) SCDynamicStoreCopyValue(m_store, (__bridge CFStringRef) key);
                    NSArray *server_addresses = dns_config[@"ServerAddresses"];
                    SystemDnsServers servers{};
                    for (NSString *serverAddress in server_addresses) {
                        servers.main.push_back(SystemDnsServer{ .address = serverAddress.UTF8String });
                    }
                    vpn_network_manager_update_system_dns(servers);
                }
            }

            NSDictionary *value = (__bridge_transfer NSDictionary *) SCDynamicStoreCopyValue(m_store, (__bridge CFStringRef) key);
            NSString *primary_service = value[@"PrimaryService"];
            if (primary_service && ![primary_service isEqualToString:m_primary_service]) {
                m_primary_service = primary_service;
                m_last_updated_primary_service = SteadyClock::now();
                SCDynamicStoreNotifyValue(m_store, (__bridge CFStringRef) [NSString stringWithFormat:@"State:/Network/Service/%@/DNS", primary_service]);
                touch_prefs();
                setup_store();
            }
        }
    }

    static void touch_prefs() {
        static Logger logger{"S_VpnMacDnsSettingsManager"};
        dbglog(logger, "Touching DNS preferences");
        @autoreleasepool {
            SCPreferencesRef prefs = SCPreferencesCreate(nullptr, (__bridge CFStringRef) @"MacDnsManager", nullptr);
            SCPreferencesLock(prefs, YES);
            CFPropertyListRef properties = SCPreferencesGetValue(prefs, kSCPrefNetworkServices);
            SCPreferencesSetValue(prefs, kSCPrefNetworkServices, properties);
            SCPreferencesApplyChanges(prefs);
            SCPreferencesUnlock(prefs);
            CFRelease(prefs);
        }
    }

    void setup_store() {
        dbglog(m_logger, "Updating DNS servers");
        @autoreleasepool {
            NSDictionary *dns_config = @{@"ServerAddresses": @[@(m_dns_server.c_str())]};
            NSDictionary *existing_config = (__bridge_transfer NSDictionary *) SCDynamicStoreCopyValue(m_store,
                    (__bridge CFStringRef) [NSString stringWithFormat:@"Setup:/Network/Service/%@/DNS", m_primary_service]);
            if (![dns_config isEqualToDictionary:existing_config]) {
                SCDynamicStoreSetValue(m_store,
                        (__bridge CFStringRef) [NSString stringWithFormat:@"Setup:/Network/Service/%@/DNS", m_primary_service],
                        (__bridge CFDictionaryRef) dns_config);
            }
        }
    }

    VpnMacDnsSettingsManagerImpl(const VpnMacDnsSettingsManagerImpl &) = delete;
    VpnMacDnsSettingsManagerImpl(VpnMacDnsSettingsManagerImpl &&) = delete;
    void operator=(const VpnMacDnsSettingsManagerImpl &) = delete;
    void operator=(VpnMacDnsSettingsManagerImpl &&) = delete;
};
#else
class VpnMacDnsSettingsManagerImpl {
public:
    static VpnMacDnsSettingsManagerImplPtr create(std::string_view dns_server) {
        return std::make_unique<VpnMacDnsSettingsManagerImpl>();
    }
};
#endif

VpnMacDnsSettingsManager::VpnMacDnsSettingsManager(VpnMacDnsSettingsManager::ConstructorAccess /*access*/, std::string_view dns_server) {
    m_pimpl = VpnMacDnsSettingsManagerImpl::create(dns_server);
}

VpnMacDnsSettingsManager::~VpnMacDnsSettingsManager() = default;

} // namespace ag
