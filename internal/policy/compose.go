package policy

import "net/http"

type composed struct{ profiles []Profile }

// Compose keeps each adapter's classification and error protocol. Overlapping
// claims are rejected, not resolved by registration order or passthrough.
func Compose(profiles ...Profile) Profile {
	if len(profiles) == 1 {
		return profiles[0]
	}
	return composed{profiles: profiles}
}

func (c composed) Classify(authority, path string) Route {
	result := Route{Host: Host(authority), Surface: "out-of-scope", API: "unscoped", Mode: "block", Provisional: true}
	claims := 0
	looking := false
	lookingCount := 0
	var suspicious Route
	for _, p := range c.profiles {
		r := p.Classify(authority, path)
		looking = looking || r.Looking
		if r.Looking {
			lookingCount++
			suspicious = r
			suspicious.Profile = p
		}
		if r.Scoped || r.Passthrough {
			claims++
			result = r
			result.Profile = p
		}
	}
	// A different adapter's suspicion must not become a passthrough exception.
	ownSuspicion := 0
	if result.Looking {
		ownSuspicion = 1
	}
	if claims > 1 || claims == 1 && lookingCount > ownSuspicion && result.Passthrough {
		return Route{Host: Host(authority), Surface: "ambiguous-route", API: "ambiguous", Mode: "block", Scoped: true, Unknown: true, Ambiguous: true}
	}
	if claims == 0 && lookingCount == 1 {
		result = suspicious
	}
	result.Looking = looking
	return result
}

func (composed) WantsStream([]byte) bool { return false }
func (composed) Block(string, bool) Response {
	return Response{Status: http.StatusForbidden, Header: http.Header{"Content-Type": {"application/json"}, "X-Withhold-Block": {"1"}}, Body: []byte(`{"error":"Request blocked by withhold: ambiguous or unsupported route."}`)}
}
