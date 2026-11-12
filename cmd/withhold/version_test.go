package main

import (
	"runtime/debug"
	"testing"
)

func TestDisplayVersion(t *testing.T) {
	for _, tc := range []struct {
		name, releaseVersion string
		info                 *debug.BuildInfo
		want                 string
	}{
		{"module version", "dev", &debug.BuildInfo{Main: debug.Module{Version: "v1.2.3"}}, "v1.2.3"},
		{"pseudo-version", "dev", &debug.BuildInfo{Main: debug.Module{Version: "v0.0.0-20260101000000-123456789abc"}}, "v0.0.0-20260101000000-123456789abc"},
		{"release takes precedence", "v2.0.0", &debug.BuildInfo{Main: debug.Module{Version: "v1.2.3"}}, "v2.0.0"},
		{"local build", "dev", &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}}, "dev"},
		{"empty metadata", "dev", &debug.BuildInfo{}, "dev"},
		{"missing metadata", "dev", nil, "dev"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := displayVersion(tc.releaseVersion, tc.info); got != tc.want {
				t.Errorf("displayVersion() = %q, want %q", got, tc.want)
			}
		})
	}
}
