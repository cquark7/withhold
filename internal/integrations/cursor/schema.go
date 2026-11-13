// Package cursor implements an unregistered Cursor protocol codec.
// It does not configure an editor or establish request-routing coverage.
// Schema provenance identifies the reviewed source, not a runtime version gate.
package cursor

import (
	_ "embed"
	"encoding/json"
	"slices"

	"google.golang.org/protobuf/encoding/protowire"
)

//go:embed schema.json
var schemaData []byte

//go:embed auxiliary-schema.json
var auxiliarySchemaData []byte

type fieldDef struct {
	Number   protowire.Number `json:"number"`
	Name     string           `json:"name"`
	Type     string           `json:"type"`
	Repeated bool             `json:"repeated"`
	Oneof    string           `json:"oneof"`
	MapKey   string           `json:"map_key"`
	Optional bool             `json:"opt"`
}

type schema struct {
	CursorVersion  string                `json:"cursor_version"`
	Bundle         string                `json:"bundle"`
	BundleSHA256   string                `json:"bundle_sha256"`
	Root           string                `json:"root"`
	Enums          map[string][]uint64   `json:"enums"`
	Messages       map[string][]fieldDef `json:"messages"`
	fields         map[string]map[protowire.Number]fieldDef
	inferenceTypes map[string]bool
}

var pinned = loadSchema()

func loadSchema() schema {
	var s schema
	if err := json.Unmarshal(schemaData, &s); err != nil {
		panic("invalid embedded Cursor schema")
	}
	s.inferenceTypes = make(map[string]bool)
	for name := range s.Messages {
		s.inferenceTypes[name] = true
	}
	var auxiliary schema
	if err := json.Unmarshal(auxiliarySchemaData, &auxiliary); err != nil {
		panic("invalid embedded Cursor auxiliary schema")
	}
	for name, fields := range auxiliary.Messages {
		if existing, ok := s.Messages[name]; ok && !slices.Equal(existing, fields) {
			panic("conflicting embedded Cursor message schemas")
		}
		s.Messages[name] = fields
	}
	for name, values := range auxiliary.Enums {
		if existing, ok := s.Enums[name]; ok && !slices.Equal(existing, values) {
			panic("conflicting embedded Cursor enum schemas")
		}
		s.Enums[name] = values
	}
	s.fields = make(map[string]map[protowire.Number]fieldDef)
	for name, fields := range s.Messages {
		index := make(map[protowire.Number]fieldDef)
		for _, field := range fields {
			if field.MapKey != "" {
				entry := name + "." + field.Name + "Entry"
				s.inferenceTypes[entry] = true
				s.fields[entry] = map[protowire.Number]fieldDef{
					1: {Number: 1, Name: "key", Type: field.MapKey},
					2: {Number: 2, Name: "value", Type: field.Type},
				}
				field.Type, field.Repeated = entry, true
			}
			index[field.Number] = field
		}
		s.fields[name] = index
	}
	return s
}

const (
	clientMessage     = "aiserver.v1.RunInferenceClientMessage"
	invokeModel       = "aiserver.v1.RunInferenceInvokeModel"
	inferenceRequest  = "aiserver.v1.InferenceStreamRequest"
	compressedRequest = "aiserver.v1.RunInferenceCompressedRequest"
)

// Present fields with unresolved content, reference, or integrity semantics are
// rejected even when their wire definitions are known.
func supportedField(message string, field fieldDef) bool {
	if !pinned.inferenceTypes[message] {
		// Extraction records provenance, not permission. Only these separately
		// reviewed auxiliary fields enter the runtime, even if their transitive
		// descriptors are also present in the development snapshot.
		fields := auxiliaryFields[message]
		return slices.Contains(fields, int(field.Number))
	}
	switch message {
	case clientMessage:
		return field.Number != 7 && field.Number != 11
	case invokeModel:
		return field.Number != 5 && field.Number != 6
	case inferenceRequest:
		return field.Number != 26 // Length of a static prefix that rewriting can change.
	case "aiserver.v1.InferenceCoreMessage":
		switch field.Number {
		case 7, 17, 18, 19:
			return false // Reasoning, alternate assistant parts, native content, or lineage.
		}
	case "aiserver.v1.InferenceContentPart":
		return field.Number == 1
	case "aiserver.v1.InferenceCursorOptions":
		return field.Number != 3 // Content digest.
	}
	return field.Type != "bytes" || message == compressedRequest && field.Number == 3
}

var auxiliaryFields = map[string][]int{
	"aiserver.v1.NameTabRequest":                      {1, 2, 6, 7},
	"aiserver.v1.ConversationMessage":                 {1, 2, 13, 32, 47, 57, 74, 77, 78, 79, 98},
	"aiserver.v1.ModelInfo":                           {1},
	"agent.v1.UpdateConversationMetadataRequest":      {1, 2, 3, 4},
	"aiserver.v1.ClassifyAgentAutoReviewRequest":      {1, 2, 3, 4, 5},
	"agent.v1.SmartModeClassifierArgs":                {1, 2, 3, 4},
	"agent.v1.SmartModeClassifierConversationMessage": {1, 2, 3, 4},
	"agent.v1.SmartModeClassifierInvokedFile":         {1, 2},
	"agent.v1.SmartModeRiskTarget":                    {1, 2},
	"aiserver.v1.StreamCppRequest":                    {1, 2, 3, 5, 6, 10, 11, 12, 17, 18, 20, 21, 23, 24, 25, 27, 28},
	"aiserver.v1.CurrentFileInfo":                     {1, 2, 3, 5, 6, 8, 9, 18, 19, 20},
	"aiserver.v1.CursorPosition":                      {1, 2},
	"aiserver.v1.CursorRange":                         {1, 2, 3, 4},
}

// Structural identifiers are inspected, but changing them is not a supported
// redaction: names and references must continue to agree with the client.
func writableText(message, name string) bool {
	switch message {
	case "aiserver.v1.InferenceCoreMessage", "aiserver.v1.InferenceTextPart":
		return name == "text"
	case "aiserver.v1.InferenceToolCall":
		return name == "raw_tool_call_args"
	case "aiserver.v1.InferenceAgentTool":
		return name == "description"
	case "aiserver.v1.InferenceCustomToolFormat":
		return name == "definition"
	case "aiserver.v1.InferenceModelConfig":
		return name == "stop_sequences"
	case "aiserver.v1.InferenceCursorOptions":
		return name == "image_description"
	case "google.protobuf.Value":
		return name == "string_value"
	case "aiserver.v1.RunInferenceRoutingMessage":
		return name == "text"
	case "aiserver.v1.RunInferenceExecutePlan":
		return name == "plan_file_content"
	case "aiserver.v1.ConversationMessage":
		return name == "text" || name == "rich_text"
	case "agent.v1.UpdateConversationMetadataRequest":
		return name == "name" || name == "workspace_paths"
	case "aiserver.v1.ClassifyAgentAutoReviewRequest":
		return name == "workspace_paths"
	case "agent.v1.SmartModeClassifierConversationMessage", "agent.v1.SmartModeClassifierInvokedFile":
		return name == "content"
	}
	// Map entries carry user keys/values rather than protocol identifiers.
	return len(message) >= 5 && message[len(message)-5:] == "Entry"
}
