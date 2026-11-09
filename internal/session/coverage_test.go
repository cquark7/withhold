package session

import (
	"testing"

	"github.com/cquark7/withhold/internal/control"
)

func TestCoverageReportsEvidenceNotListenerOrScanAttempts(t *testing.T) {
	for _, test := range []struct {
		name string
		live *control.DebugStatus
		want string
	}{
		{"no authenticated session", nil, "unavailable"},
		{"running", &control.DebugStatus{}, "awaiting-traffic"},
		{"CONNECT only", &control.DebugStatus{Connections: 1}, "awaiting-traffic"},
		{"uninspected traffic", &control.DebugStatus{Received: 1, Passthrough: 1}, "traffic-observed"},
		{"failed scans", &control.DebugStatus{Received: 1, Scanned: 1}, "traffic-observed"},
		{"completed inspection", &control.DebugStatus{Received: 1, Scanned: 1, Inspected: 1}, "inspected"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := coverageState(test.live); got != test.want {
				t.Fatalf("coverage %q, want %q", got, test.want)
			}
		})
	}
}
