#ifndef XDPSHIELD_PARSING_H
#define XDPSHIELD_PARSING_H

#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_endian.h>

struct pkt {
    void *data;
    void *end;
    struct ethhdr *eth;
    struct iphdr *ip;
    void *l4;
    __be16 sport;
    __be16 dport;
    __u8 tcp_flags_valid;
    __u8 syn;
    __u8 proto;
    __u8 pad;
};

enum parse_result {
    PARSE_OK = 0,
    PARSE_NOT_IPV4,
    PARSE_BAD,
    PARSE_FRAG,
};

static __always_inline int martian_src(__be32 src)
{
    __u32 a = bpf_ntohl(src);

    if (a == 0 || a == 0xffffffff)
        return 1;
    if ((a >> 24) == 127)       /* loopback */
        return 1;
    if ((a >> 28) == 0xe)       /* multicast 224/4 */
        return 1;
    return 0;
}

/* l2 + l3 only. l4 is parsed separately because we only need it for vip traffic */
static __always_inline int parse_l3(struct pkt *p)
{
    struct ethhdr *eth = p->data;
    struct iphdr *ip;
    __u32 hlen, tot;

    if ((void *)(eth + 1) > p->end)
        return PARSE_BAD;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return PARSE_NOT_IPV4;

    ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > p->end)
        return PARSE_BAD;
    if (ip->version != 4 || ip->ihl < 5)
        return PARSE_BAD;

    hlen = ip->ihl * 4;
    tot = bpf_ntohs(ip->tot_len);
    /* clang drops a plain & 0xffff after the bswap and the verifier then sees an unbounded scalar */
    asm volatile("%0 &= 0xffff" : "+r"(tot));
    if (tot < hlen)
        return PARSE_BAD;
    /* frame may have trailing padding, but never be shorter than tot_len */
    if ((void *)ip + tot > p->end)
        return PARSE_BAD;
    if (martian_src(ip->saddr))
        return PARSE_BAD;

    p->eth = eth;
    p->ip = ip;
    p->proto = ip->protocol;
    p->l4 = (void *)ip + hlen;

    if (ip->frag_off & bpf_htons(IP_MF | IP_OFFSET))
        return PARSE_FRAG;
    return PARSE_OK;
}

/* returns 0 ok, -1 malformed. flags only meaningful for tcp */
static __always_inline int parse_l4(struct pkt *p, int *bad_flags)
{
    *bad_flags = 0;

    if (p->proto == IPPROTO_TCP) {
        struct tcphdr *t = p->l4;

        if ((void *)(t + 1) > p->end)
            return -1;
        if (t->doff < 5)
            return -1;
        if (!t->source || !t->dest)
            return -1;

        p->sport = t->source;
        p->dport = t->dest;
        p->syn = t->syn && !t->ack;

        if (!t->syn && !t->ack && !t->fin && !t->rst)           /* null scan */
            *bad_flags = 1;
        else if (t->fin && t->psh && t->urg)                    /* xmas */
            *bad_flags = 1;
        else if (t->syn && (t->fin || t->rst))
            *bad_flags = 1;
        else if (t->fin && !t->ack)
            *bad_flags = 1;
        return 0;
    }

    if (p->proto == IPPROTO_UDP) {
        struct udphdr *u = p->l4;

        if ((void *)(u + 1) > p->end)
            return -1;
        if (!u->source || !u->dest)
            return -1;

        p->sport = u->source;
        p->dport = u->dest;
        return 0;
    }

    return -1;
}

#endif
