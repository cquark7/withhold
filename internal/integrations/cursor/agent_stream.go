package cursor

import (
	"bytes"
	"crypto/sha256"

	"github.com/cquark7/withhold/internal/policy"
)

// Only original, fully resolved uploads are retained, for this HTTP upload's
// lifetime. This stores bytes, never a "clean" decision: every later reference
// is decoded in its expected type and included in that message's scanner input.
type agentStream struct {
	blobs    map[[sha256.Size]byte][]byte
	maxBytes int64
	used     int64
	reserve  func(int) error
}

func openAgentStream(limits policy.DecodeLimits) (policy.RPCStream, error) {
	if limits.MaxBytes <= 0 || limits.MaxBytes > 128*1024*1024 {
		return nil, ErrLimit
	}
	if limits.Context != nil {
		if err := limits.Context.Err(); err != nil {
			return nil, err
		}
	}
	return &agentStream{
		blobs: make(map[[sha256.Size]byte][]byte), maxBytes: limits.MaxBytes, reserve: limits.Reserve,
	}, nil
}

func (s *agentStream) Decode(body []byte, limits policy.DecodeLimits) (policy.Message, error) {
	if s.blobs == nil {
		return nil, ErrUnsupported
	}
	message, err := decodeWithAgentBlobs(agentClientMessage, body, limits, s)
	if err != nil {
		return nil, err
	}
	return message, nil
}

func (s *agentStream) retain(uploads map[[sha256.Size]byte][]byte) error {
	if s == nil {
		return nil
	}
	count, size := len(s.blobs), int64(0)
	for id, data := range uploads {
		if previous, ok := s.blobs[id]; ok {
			if !bytes.Equal(previous, data) {
				return ErrUnsupported
			}
			continue
		}
		count++
		size += int64(len(data)) + sha256.Size
	}
	if count > maxAgentBlobs || size > s.maxBytes-s.used {
		return ErrLimit
	}
	// Reserve the whole batch before making independent copies. Keeping slices
	// of an envelope would retain unrelated input outside this accounting.
	if size != 0 && s.reserve != nil {
		if err := s.reserve(int(size)); err != nil {
			return err
		}
	}
	for id, data := range uploads {
		if _, ok := s.blobs[id]; !ok {
			s.blobs[id] = bytes.Clone(data)
		}
	}
	s.used += size
	return nil
}

func (s *agentStream) Close() {
	s.blobs = nil
	s.used = 0
}
