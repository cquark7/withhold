package session

import "github.com/cquark7/withhold/internal/control"

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

func trafficReport(live *control.DebugStatus) any {
	if live == nil {
		return nil
	}
	return map[string]any{
		"connections": live.Connections, "received": live.Received,
		"scan_attempts": live.Scanned, "inspected": live.Inspected,
		"passthrough": live.Passthrough, "detected": live.Detected,
		"redacted": live.Redacted, "blocked": live.Blocked,
		"written": live.Written, "responses": live.Responses,
		"upstream_errors": live.UpstreamErrors,
	}
}
