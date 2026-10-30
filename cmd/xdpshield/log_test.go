//go:build linux

package main

import "testing"

func TestSetupLog(t *testing.T) {
	for _, c := range []struct {
		level, format string
		ok            bool
	}{
		{"info", "text", true},
		{"debug", "json", true},
		{"WARN", "text", true},
		{"loud", "text", false},
		{"info", "yaml", false},
	} {
		if err := setupLog(c.level, c.format); (err == nil) != c.ok {
			t.Errorf("%s/%s: err = %v", c.level, c.format, err)
		}
	}
}
