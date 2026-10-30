#ifndef XDPSHIELD_COMMON_H
#define XDPSHIELD_COMMON_H

#include <linux/types.h>
#include <linux/if_ether.h>

#define MAGLEV_M        65537   /* prime, must match internal/maglev */
#define MAX_VIPS        64
#define MAX_BACKENDS    1024
#define CONNTRACK_MAX   524288
#define RATE_STATE_MAX  262144
#define BLOCKLIST_MAX   262144
#define CIDR_MAX        16384
#define AMP_PORTS_MAX   64
#define EVENTS_SIZE     (1 << 20)

#define NSEC_PER_SEC    1000000000ULL

#ifndef IP_MF
#define IP_MF           0x2000
#endif
#ifndef IP_OFFSET
#define IP_OFFSET       0x1FFF
#endif

#define IPPROTO_IPIP_N  4
#define IPPROTO_6IN4    41

enum cfg_flags {
    CFG_DDOS_ENABLED = 1 << 0,
};

enum lb_algo {
    ALGO_MAGLEV = 0,
    ALGO_WRR    = 1,
};

enum block_reason {
    BLOCK_SYN_FLOOD = 1,
    BLOCK_UDP_FLOOD = 2,
    BLOCK_MANUAL    = 3,
};

/* order matters, internal/dataplane/stats.go has a test that checks it */
enum stat_id {
    STAT_RX_PKTS = 0,
    STAT_RX_BYTES,
    STAT_PASS,
    STAT_LB_FWD,
    STAT_LB_FWD_BYTES,
    STAT_CT_HIT,
    STAT_CT_NEW,
    STAT_ALLOWLISTED,
    STAT_BLOCK_ADDED,
    STAT_EVENT_LOST,
    STAT_DROP_MALFORMED,
    STAT_DROP_FRAG,
    STAT_DROP_DENYLIST,
    STAT_DROP_BLOCKED,
    STAT_DROP_BAD_FLAGS,
    STAT_DROP_SYN_FLOOD,
    STAT_DROP_UDP_FLOOD,
    STAT_DROP_NO_BACKEND,
    STAT_DROP_MTU,
    STAT_DROP_ENCAP,
    STAT_ICMP_FRAG_NEEDED,
    STAT_ICMP6_TOO_BIG,
    STAT_DROP_AMPLIFICATION,
    STAT_MAX,
};

struct addr6 {
    __u8 b[16];
};

struct global_cfg {
    __u32 flags;
    __u32 syn_limit_pps;    /* per source, per 1s window */
    __u32 udp_limit_pps;
    __u32 block_ttl_sec;
    __be32 encap_src;       /* outer src for ipip */
    __u32 max_ip_len;       /* largest inner tot_len we encapsulate */
    __u32 hash_seed;        /* same on every lb node or maglev stops being consistent */
    __u32 overhead;         /* bytes the tunnel adds: 20 for ipv4 backends, 40 if any backend is ipv6 */
    struct addr6 encap_src6;/* outer src towards ipv6 backends */
};

struct vip_key {
    __be32 addr;
    __be16 port;
    __u8 proto;
    __u8 pad;
};

struct vip_val {
    __u32 id;
    __u32 algo;
    __u32 table_len;
    __u32 pad;
};

struct backend {
    __be32 addr;            /* family 4 */
    __u8 mac[ETH_ALEN];
    __u8 active;
    __u8 family;            /* 4 or 6, 0 counts as 4 */
    struct addr6 addr6;     /* family 6 */
};

struct flow_key {
    __be32 src;
    __be32 dst;
    __be16 sport;
    __be16 dport;
    __u8 proto;
    __u8 pad[3];
};

struct flow_val {
    __u32 backend_id;
    __u32 pad;
    __u64 last_seen_ns;
};

struct rate_val {
    __u64 syn_tat;      /* gcra theoretical arrival times, ns */
    __u64 udp_tat;
};

struct block_val {
    __u64 expires_ns;
    __u32 reason;
    __u32 pad;
};

struct lpm_key {
    __u32 prefixlen;
    __be32 addr;
};

struct vip_key6 {
    struct addr6 addr;
    __be16 port;
    __u8 proto;
    __u8 pad;
};

struct flow_key6 {
    struct addr6 src;
    struct addr6 dst;
    __be16 sport;
    __be16 dport;
    __u8 proto;
    __u8 pad[3];
};

struct lpm_key6 {
    __u32 prefixlen;
    struct addr6 addr;
};

struct lpm_val {
    __u32 flags;
};

struct traffic_stat {
    __u64 pkts;
    __u64 bytes;
};

struct block_event {
    __u64 ts_ns;
    __be32 src;         /* v4 source, unused when family is 6 */
    __u32 reason;
    __u32 observed_pps;
    __u8 family;        /* 4 or 6 */
    __u8 pad[3];
    struct addr6 src6;
};

#endif
