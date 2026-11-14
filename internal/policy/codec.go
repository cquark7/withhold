package policy

import (
	"context"
	"net/http"
)

// Message is an owned, bounded logical request, projected into the shared JSON
// scanner without putting protocol-specific semantics in the detector.
type Message interface {
	ScanInput() []byte
	// Rewrite also receives unchanged scanner input for clean messages, so an
	// adapter can negotiate supported protocol capabilities before forwarding.
	// Other clean bytes must be preserved. Observe mode never calls Rewrite.
	Rewrite(scanned []byte) ([]byte, error)
	// HasContent distinguishes inspected model/context text from scanned
	// control identifiers. A handshake alone is not coverage evidence.
	HasContent() bool
}

// RPCCodec opts a route into Connect's unary or enveloped protobuf transport.
// Decode is stateless. Streaming routes may opt into request-local state with
// OpenStream; transport never resolves application references itself.
type RPCCodec struct {
	Streaming bool
	Duplex    bool
	Decode    func(body []byte, limits DecodeLimits) (Message, error)
	// OpenStream is called once per supported streaming upload. Its Reserve
	// callback admits state retained across messages, without holding an intake
	// job between envelopes. Close runs after decoding stops, on every exit.
	OpenStream func(limits DecodeLimits) (RPCStream, error)
}

// RPCStream owns adapter state for one upload. Decode calls are serial; Close
// runs only after any active Decode returns. Reservations must not outlive it.
type RPCStream interface {
	Decode(body []byte, limits DecodeLimits) (Message, error)
	Close()
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
