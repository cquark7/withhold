package policy

import "testing"

func TestSharedEnforcementUsesCapabilitiesNotSurfaceNames(t *testing.T) {
	for _, test := range []struct {
		name, status, mode, surface string
		unknown, residue            bool
		want                        Decision
	}{
		{name: "clean", status: "clean", mode: "redact", want: Decision{"forward", ""}},
		{name: "redact", status: "redacted", mode: "redact", want: Decision{"redact", ""}},
		{name: "block", status: "redacted", mode: "block", want: Decision{"block", "secret-found"}},
		{name: "residue", status: "redacted", mode: "block", residue: true, want: Decision{"block", "unscanned-residue"}},
		{name: "unknown", status: "clean", mode: "redact", unknown: true, want: Decision{"block", "unknown-api-path"}},
		{name: "missing report", mode: "redact", want: Decision{"block", "scanner-error"}},
		{name: "embeddings scanner error", status: "scanner-error", mode: "redact", surface: "embeddings", want: Decision{"block", "scanner-error"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := Route{Mode: test.mode, Surface: test.surface, Unknown: test.unknown}
			if got := Evaluate(r, test.status, test.residue); got != test.want {
				t.Fatalf("decision %+v, want %+v", got, test.want)
			}
		})
	}
}
