package session

import "github.com/cquark7/withhold/internal/control"

// Traffic is a value-free snapshot of this proxy process, not per-agent attribution.
type Traffic struct {
	Connections     uint64                  `json:"connections"`
	Received        uint64                  `json:"received"`
	ScanAttempts    uint64                  `json:"scan_attempts"`
	Inspected       uint64                  `json:"inspected"`
	Passthrough     uint64                  `json:"passthrough"`
	Detected        uint64                  `json:"detected"`
	Redacted        uint64                  `json:"redacted"`
	Blocked         uint64                  `json:"blocked"`
	BlockReasons    control.BlockReasons    `json:"block_reasons"`
	Written         uint64                  `json:"written"`
	Responses       uint64                  `json:"responses"`
	UpstreamErrors  uint64                  `json:"upstream_errors"`
	UpstreamReasons control.UpstreamReasons `json:"upstream_reasons"`
}

// These are observations of this process, not a claim that all application
// traffic uses the proxy or that every received body is supported.
func coverageState(live *control.DebugStatus) string {
	if live == nil {
		return "unavailable"
	}
	if live.Inspected > 0 {
		return "inspected"
	}
	if live.Received > 0 {
		return "traffic-observed"
	}
	return "awaiting-traffic"
}

func trafficReport(live *control.DebugStatus) *Traffic {
	if live == nil {
		return nil
	}
	return &Traffic{
		Connections: live.Connections, Received: live.Received,
		ScanAttempts: live.Scanned, Inspected: live.Inspected,
		Passthrough: live.Passthrough, Detected: live.Detected,
		Redacted: live.Redacted, Blocked: live.Blocked, BlockReasons: live.BlockReasons,
		Written: live.Written, Responses: live.Responses,
		UpstreamErrors: live.UpstreamErrors, UpstreamReasons: live.UpstreamReasons,
	}
}
