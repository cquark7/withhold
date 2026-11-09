// Package policy defines traffic contracts and provider-independent enforcement.
// It never discovers application settings or selects a built-in integration.
package policy

import (
	"net"
	"net/http"
	"strings"
)

type ScopeOptions struct {
	ExtraHosts, ExtraHostRegex, AllowHosts []string
	SuspicionPattern, ChatMode, InlineMode string
}

// Route describes capabilities, not provider names. HTTPFailureAction is an
// explicit inspection-policy exception; it never disables transport admission limits.
type Route struct {
	Host, Surface, API, Mode              string
	Scoped, Passthrough, Looking, Unknown bool
	Provisional                           bool
	AllowNonJSON                          bool
	HTTPFailureAction, NonPostRule        string
}

type Response struct {
	Status int
	Header http.Header
	Body   []byte
}

type Profile interface {
	Classify(authority, path string) Route
	WantsStream(body []byte) bool
	Block(reason string, stream bool) Response
}

func Host(authority string) string {
	if h, _, err := net.SplitHostPort(authority); err == nil {
		return strings.ToLower(h)
	}
	return strings.ToLower(strings.Trim(authority, "[]"))
}

func ValidMode(mode string) bool { return mode == "redact" || mode == "block" }

type Decision struct{ Action, Reason string }

// Evaluate decides findings/failures without handling HTTP or application state.
// Observe is applied by the caller so transport failures remain unconditional.
func Evaluate(route Route, status string, residue bool, websocket bool) Decision {
	if !ValidMode(route.Mode) {
		panic("invalid integration mode")
	}
	if route.Unknown {
		return Decision{"block", "unknown-api-path"}
	}
	if status == "clean" {
		return Decision{"forward", ""}
	}
	if status == "redacted" {
		if route.Mode == "block" {
			if residue {
				return Decision{"block", "unscanned-residue"}
			}
			return Decision{"block", "secret-found"}
		}
		return Decision{"redact", ""}
	}
	if !websocket && route.HTTPFailureAction != "" {
		return Decision{"passthrough", status}
	}
	if status == "" {
		status = "scanner-error"
	}
	return Decision{"block", status}
}
