#ifndef XDPSHIELD_MAPS_H
#define XDPSHIELD_MAPS_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "common.h"

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct global_cfg);
} config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_VIPS);
    __type(key, struct vip_key);
    __type(value, struct vip_val);
} vip_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_VIPS);
    __type(key, __be32);
    __type(value, __u8);
} vip_addrs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_BACKENDS);
    __type(key, __u32);
    __type(value, struct backend);
} backend_map SEC(".maps");

/*
 * one inner array per vip. userspace builds a whole new table and swaps the
 * outer slot, so the datapath never sees a half written table.
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, MAX_VIPS);
    __type(key, __u32);
    __array(values, struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __uint(max_entries, MAGLEV_M);
        __type(key, __u32);
        __type(value, __u32);
    });
} lb_tables SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_VIPS);
    __type(key, __u32);
    __type(value, __u32);
} rr_cursor SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, CONNTRACK_MAX);
    __type(key, struct flow_key);
    __type(value, struct flow_val);
} conn_track SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, RATE_STATE_MAX);
    __type(key, __be32);
    __type(value, struct rate_val);
} rate_state SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, BLOCKLIST_MAX);
    __type(key, __be32);
    __type(value, struct block_val);
} dyn_blocklist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, CIDR_MAX);
    __type(key, struct lpm_key);
    __type(value, struct lpm_val);
} deny_cidr SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, CIDR_MAX);
    __type(key, struct lpm_key);
    __type(value, struct lpm_val);
} allow_cidr SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_BACKENDS);
    __type(key, __u32);
    __type(value, struct traffic_stat);
} backend_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_VIPS);
    __type(key, __u32);
    __type(value, struct traffic_stat);
} vip_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, EVENTS_SIZE);
} events SEC(".maps");

#endif
