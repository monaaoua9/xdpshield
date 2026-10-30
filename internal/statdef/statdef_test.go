package statdef

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestMatchesHeader(t *testing.T) {
	raw, err := os.ReadFile("../../bpf/include/common.h")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	start := strings.Index(src, "enum stat_id {")
	end := strings.Index(src[start:], "};")
	body := src[start : start+end]

	re := regexp.MustCompile(`(?m)^\s*STAT_([A-Z0-9_]+)`)
	var got []string
	for _, m := range re.FindAllStringSubmatch(body, -1) {
		if m[1] == "MAX" {
			continue
		}
		got = append(got, strings.ToLower(m[1]))
	}
	if len(got) != len(Names) {
		t.Fatalf("header has %d stats, go has %d", len(got), len(Names))
	}
	for i := range got {
		if got[i] != Names[i] {
			t.Errorf("stat %d: header %q, go %q", i, got[i], Names[i])
		}
	}
}

func TestReasons(t *testing.T) {
	raw, _ := os.ReadFile("../../bpf/include/common.h")
	for _, want := range []string{"BLOCK_SYN_FLOOD = 1", "BLOCK_UDP_FLOOD = 2", "BLOCK_MANUAL    = 3", "ALGO_WRR    = 1"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("header changed: %q", want)
		}
	}
}
