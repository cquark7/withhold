package policy

import "testing"

type fixedProfile struct{ route Route }

func (p *fixedProfile) Classify(string, string) Route { return p.route }
func (*fixedProfile) WantsStream([]byte) bool         { return false }
func (*fixedProfile) Block(string, bool) Response     { return Response{} }

func TestCompositionNeverLetsAnotherAgentWidenPassthrough(t *testing.T) {
	for _, test := range []struct {
		name      string
		a, b      Route
		ambiguous bool
	}{
		{"distinct scope", Route{Scoped: true}, Route{}, false},
		{"overlap", Route{Scoped: true}, Route{Scoped: true}, true},
		{"unknown cannot become known", Route{Scoped: true, Unknown: true}, Route{Scoped: true}, true},
		{"passthrough cannot override scope", Route{Scoped: true}, Route{Passthrough: true}, true},
		{"passthrough cannot override suspicion", Route{Looking: true}, Route{Passthrough: true}, true},
		{"exception cannot override suspicion", Route{Looking: true}, Route{Scoped: true, HTTPFailureAction: "unscanned"}, true},
		{"inspection can cover suspicion", Route{Looking: true}, Route{Scoped: true}, false},
		{"own reviewed exception", Route{Scoped: true, Looking: true, HTTPFailureAction: "unscanned"}, Route{}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			a, b := &fixedProfile{test.a}, &fixedProfile{test.b}
			for _, profiles := range [][]Profile{{a, b}, {b, a}} {
				r := Compose(profiles...).Classify("agent.test", "/request")
				if r.Ambiguous != test.ambiguous || test.ambiguous && (!r.Scoped || !r.Unknown || r.Passthrough || r.HTTPFailureAction != "" || r.Codec != nil) {
					t.Fatalf("unsafe composite route: %+v", r)
				}
				if !test.ambiguous && r.Scoped && r.Profile == nil {
					t.Fatal("selected route lost its error protocol")
				}
			}
		})
	}
}
