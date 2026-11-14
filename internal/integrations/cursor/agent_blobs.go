package cursor

import (
	"bytes"
	"crypto/sha256"

	"google.golang.org/protobuf/encoding/protowire"
)

const maxAgentBlobs = 4096

// These references are typed by their owning field, not by guessing at the
// blob's bytes. serde.ts and blob-reference-rewriter.ts establish the protobuf
// encodings for turns, messages, steps, todos, summaries, and shell history.
// ConversationPlan's encoder uses toBinary before hashing the uploaded blob.
var agentBlobTypes = map[string]map[protowire.Number]string{
	"agent.v1.ConversationStateStructure": {
		3: "agent.v1.TodoItem",
		6: "agent.v1.ConversationSummary",
		7: "agent.v1.ConversationPlan",
		8: "agent.v1.ConversationTurnStructure",
	},
	"agent.v1.AgentConversationTurnStructure": {
		1: "agent.v1.UserMessage",
		2: "agent.v1.ConversationStep",
	},
	"agent.v1.ShellConversationTurnStructure": {
		1: "agent.v1.ShellCommand",
		2: "agent.v1.ShellOutput",
	},
	"agent.v1.UserMessage": {
		10: "agent.v1.ConversationStateStructure",
	},
}

func agentByteField(message string, field protowire.Number) bool {
	return agentBlobTypes[message][field] != "" ||
		message == "agent.v1.PreFetchedBlob" && (field == 1 || field == 2)
}

type agentBlobKey struct {
	id   [sha256.Size]byte
	kind string
}

type agentBlobGraph struct {
	decoder *decoder
	blobs   map[[sha256.Size]byte][]byte
	used    map[[sha256.Size]byte]bool
	active  map[agentBlobKey]bool
	done    map[agentBlobKey]bool
	roots   []*wireMessage
}

// A graph is local to one envelope. It never treats a prior request, retry,
// upstream cache hit, or uninspected response as proof that content is clean.
// All uploaded blobs must be reachable through reviewed, locally resolved
// references; even an otherwise-unused blob could disclose confidential data.
func (d *decoder) agentBlobs(root *wireMessage) ([]*wireMessage, error) {
	g := agentBlobGraph{
		decoder: d, blobs: make(map[[sha256.Size]byte][]byte),
		used: make(map[[sha256.Size]byte]bool), active: make(map[agentBlobKey]bool),
		done: make(map[agentBlobKey]bool),
	}
	envelope := root.fields[0].child
	if envelope.name == "agent.v1.AgentRunRequest" || envelope.name == "agent.v1.PrewarmRequest" {
		count := 0
		for _, field := range envelope.fields {
			if field.def.Number != 17 {
				continue
			}
			count++
			if count > maxAgentBlobs {
				return nil, ErrLimit
			}
			if err := d.ctx.Err(); err != nil {
				return nil, err
			}
			id, value := field.child.field(1), field.child.field(2)
			if id == nil || value == nil || len(id.payload) != sha256.Size {
				return nil, ErrUnsupported
			}
			digest := sha256.Sum256(value.payload)
			if !bytes.Equal(id.payload, digest[:]) {
				return nil, ErrUnsupported
			}
			if previous, ok := g.blobs[digest]; ok && !bytes.Equal(previous, value.payload) {
				return nil, ErrUnsupported
			}
			g.blobs[digest] = value.payload
		}
	}
	if err := g.walk(root, 0); err != nil {
		return nil, err
	}
	if len(g.used) != len(g.blobs) {
		return nil, ErrUnsupported
	}
	return g.roots, nil
}

func (g *agentBlobGraph) walk(message *wireMessage, depth int) error {
	if err := g.decoder.ctx.Err(); err != nil {
		return err
	}
	if depth > maxDepth {
		return ErrLimit
	}
	for _, field := range message.fields {
		if kind := agentBlobTypes[message.name][field.def.Number]; kind != "" {
			if len(field.payload) != sha256.Size {
				return ErrUnsupported
			}
			key := agentBlobKey{id: [sha256.Size]byte(field.payload), kind: kind}
			if g.active[key] {
				return ErrUnsupported
			}
			if g.done[key] {
				continue
			}
			data, ok := g.blobs[key.id]
			if !ok {
				return ErrUnsupported
			}
			if len(g.done)+len(g.active) >= maxAgentBlobs || int64(len(data)) > g.decoder.maxBytes-g.decoder.decoded {
				return ErrLimit
			}
			g.decoder.decoded += int64(len(data))
			g.active[key] = true
			child, err := g.decoder.message(kind, data, depth+1)
			if err != nil {
				return err
			}
			if err := g.walk(child, depth+1); err != nil {
				return err
			}
			delete(g.active, key)
			g.done[key], g.used[key.id] = true, true
			g.roots = append(g.roots, child)
		} else if field.child != nil {
			if err := g.walk(field.child, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}
