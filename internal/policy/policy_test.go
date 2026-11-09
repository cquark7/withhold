package policy

import "testing"

func TestSharedEnforcementUsesCapabilitiesNotSurfaceNames(t *testing.T) {
	for _, test := range []struct {
		name, status, mode, surface, exception string
		unknown, residue, websocket            bool
		want                                   Decision
	}{
		{name: "clean", status: "clean", mode: "redact", want: Decision{"forward", ""}},
		{name: "redact", status: "redacted", mode: "redact", want: Decision{"redact", ""}},
		{name: "block", status: "redacted", mode: "block", want: Decision{"block", "secret-found"}},
		{name: "residue", status: "redacted", mode: "block", residue: true, want: Decision{"block", "unscanned-residue"}},
		{name: "unknown", status: "clean", mode: "redact", unknown: true, want: Decision{"block", "unknown-api-path"}},
		{name: "missing report", mode: "redact", want: Decision{"block", "scanner-error"}},
		{name: "surface name is not an exception", status: "scanner-error", mode: "redact", surface: "embeddings", want: Decision{"block", "scanner-error"}},
		{name: "explicit HTTP exception", status: "scanner-error", mode: "redact", exception: "test-unscanned", want: Decision{"passthrough", "scanner-error"}},
		{name: "HTTP exception does not extend to WS", status: "scanner-error", mode: "redact", exception: "test-unscanned", websocket: true, want: Decision{"block", "scanner-error"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := Route{Mode: test.mode, Surface: test.surface, Unknown: test.unknown, HTTPFailureAction: test.exception}
			if got := Evaluate(r, test.status, test.residue, test.websocket); got != test.want {
				t.Fatalf("decision %+v, want %+v", got, test.want)
			}
		})
	}
}
