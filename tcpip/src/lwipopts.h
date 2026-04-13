#ifndef LWIPOPTS_H
#define LWIPOPTS_H

// LWIP is operating in no-system mode
#define NO_SYS 1
#define SYS_LIGHTWEIGHT_PROT 0

// Memory manager settings
#define MEMP_OVERFLOW_CHECK 0
#define MEM_USE_POOLS 0
#define MEMP_MEM_MALLOC 1
#define MEM_LIBC_MALLOC 1

// Disable unneeded LWIP subsystems
#define LWIP_SOCKET 0
#define LWIP_NETCONN 0
#define LWIP_EVENT_API 0

// Use single netif
#define LWIP_SINGLE_NETIF 1

// Use custom timers
#define LWIP_TIMERS_CUSTOM 1

// Disable L2
#define LWIP_ETHERNET 0
#define LWIP_ARP 0

// Enable protocols
#define LWIP_IPV4 1
#define LWIP_IPV6 1
#define IPV6_FRAG_COPYHEADER 1
#define LWIP_IPV6_MLD 0
#define LWIP_IPV6_SCOPES 0

// Enable TCP and UDP
#define LWIP_TCP 1
#define LWIP_UDP 1

// Enable RAW API
#define LWIP_CALLBACK_API 1
#define TCP_LISTEN_BACKLOG 1
#define SO_REUSE 1

// Logging settings
#undef LWIP_DEBUG
#if defined(LWIP_DEBUG)
#define UDP_DEBUG LWIP_DBG_ON
#define TCP_DEBUG LWIP_DBG_ON
#define TCP_OUTPUT_DEBUG LWIP_DBG_ON
#define IP_DEBUG LWIP_DBG_ON
#define IP6_DEBUG LWIP_DBG_ON
#else
#define UDP_DEBUG LWIP_DBG_OFF
#define TCP_DEBUG LWIP_DBG_OFF
#define TCP_OUTPUT_DEBUG LWIP_DBG_OFF
#define IP_DEBUG LWIP_DBG_OFF
#define IP6_DEBUG LWIP_DBG_OFF
#endif

// TCP settings
#define LWIP_WND_SCALE 1
#define LWIP_TCP_TIMESTAMPS 1

#define MAX_SUPPORTED_MTU 9000

#define TCP_WND (256 * 1024)
#define TCP_RCV_SCALE 4
#define TCP_MSS (MAX_SUPPORTED_MTU - IP_HLEN - TCP_HLEN)

#define TCP_SND_BUF (256 * 1024)
#define TCP_SND_QUEUELEN 256
// Explicit SNDLOWAT to avoid LWIP sanity check u16 overflow with large TCP_SND_BUF
#define TCP_SNDLOWAT (2 * TCP_MSS + 1)

#define LWIP_TCP_SACK_OUT 1

// Limit out-of-sequence buffer to prevent unbounded memory growth
#define TCP_OOSEQ_MAX_BYTES TCP_WND
#define TCP_OOSEQ_MAX_PBUFS 64

// IP hooks (implementation in ip_hooks.c)
#define LWIP_HOOK_FILENAME "./ip_hooks.h"

#endif /* LWIPOPTS_H */
