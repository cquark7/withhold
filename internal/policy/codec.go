package policy

import (
	"context"
	"net/http"
)

// Message is an owned, bounded logical request, projected into the shared JSON
// scanner without putting protocol-specific semantics in the detector.
type Message interface {
	ScanInput() []byte
	Rewrite(scanned []byte) ([]byte, error)
	// HasContent distinguishes inspected model/context text from scanned
	// control identifiers. A handshake alone is not coverage evidence.
	HasContent() bool
}

// RPCCodec opts a route into Connect's unary or enveloped protobuf transport.
// Each decode is independent: references to previous uninspected messages must
// be rejected by the adapter, not resolved by transport.
type RPCCodec struct {
	Streaming bool
	Duplex    bool
	Decode    func(body []byte, limits DecodeLimits) (Message, error)
}

// DecodeLimits reserves retained decoded input before allocation. The callback
// returns a transport-capacity error unchanged; it is not an inspection failure.
// Limits bound input representations, not total process RSS or parser metadata.
type DecodeLimits struct {
	MaxBytes int64
	Reserve  func(int) error
	Context  context.Context
}

// RequestBlocker can select error framing from the actual request, including
// failures before a body can be decoded. It cannot override transport admission.
type RequestBlocker interface {
	BlockRequest(r *http.Request, route Route, reason string) Response
}
