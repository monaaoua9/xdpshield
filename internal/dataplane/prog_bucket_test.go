//go:build linux && integration

package dataplane

import (
	"testing"
	"time"
)

// limit is 5/s: burst of 5, then one more token every 200ms. a fixed window
// would refuse everything until the full second is up.
func TestRateLimitRefillsGradually(t *testing.T) {
	p := setup(t)
	src := "45.7.7.7"

	for i := 0; i < 5; i++ {
		if ret, _ := run(t, p, tcpFrame(src, uint16(6000+i), syn)); ret != xdpTX {
			t.Fatalf("burst syn %d: %d", i, ret)
		}
	}
	time.Sleep(450 * time.Millisecond)
	if ret, _ := run(t, p, tcpFrame(src, 6100, syn)); ret != xdpTX {
		t.Fatalf("no token after 450ms: %d", ret)
	}
	if counter(t, p, "drop_syn_flood") != 0 {
		t.Fatal("source was blocked")
	}
}
