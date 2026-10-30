// Package statdef mirrors enum stat_id from bpf/include/common.h.
package statdef

import "time"

type Traffic struct {
	Pkts  uint64
	Bytes uint64
}

type BlockEvent struct {
	At     time.Time `json:"at"`
	Src    string    `json:"src"`
	Reason string    `json:"reason"`
	PPS    uint32    `json:"observed_pps"`
}

// order has to match the enum, statdef_test.go parses the header to check
var Names = []string{
	"rx_pkts",
	"rx_bytes",
	"pass",
	"lb_fwd",
	"lb_fwd_bytes",
	"ct_hit",
	"ct_new",
	"allowlisted",
	"block_added",
	"event_lost",
	"drop_malformed",
	"drop_frag",
	"drop_denylist",
	"drop_blocked",
	"drop_bad_flags",
	"drop_syn_flood",
	"drop_udp_flood",
	"drop_no_backend",
	"drop_mtu",
	"drop_encap",
	"icmp_frag_needed",
	"icmp6_too_big",
	"drop_amplification",
}

// block reasons as written by the datapath
const (
	BlockSynFlood = 1
	BlockUDPFlood = 2
	BlockManual   = 3
)

func ReasonName(r uint32) string {
	switch r {
	case BlockSynFlood:
		return "syn_flood"
	case BlockUDPFlood:
		return "udp_flood"
	case BlockManual:
		return "manual"
	}
	return "unknown"
}

const (
	AlgoMaglev = 0
	AlgoWRR    = 1
)

const FlagDDoSEnabled = 1
