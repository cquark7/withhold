package jsonmeta

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestExactTopLevelBooleanWithoutPayloadCopies(t *testing.T) {
	for _, body := range []string{
		`{"stream":true}`, `{"Stream":true}`, `{"stream":"true"}`, `{"stream":null}`,
		`{"nested":{"stream":true}}`, `{"stream":true,"stream":false}`,
		`{"stream":false,"stream":true}`, `{"str\\eam":true}`, `{"\u0073tream":true}`,
		`{"before":[{"value":"} , \\\""}], "stream" : true , "after":[false,{},[]]}`,
		`{"text":"` + strings.Repeat("ordinary attachment content", 10000) + `","stream":true}`,
		`{"stream":true`, `[]`, `null`, `true`, ` {"stream": true} `,
	} {
		var fields map[string]json.RawMessage
		want := json.Unmarshal([]byte(body), &fields) == nil && string(fields["stream"]) == "true"
		if got := Bool([]byte(body), "stream"); got != want {
			t.Fatalf("metadata differs from JSON object semantics, length=%d", len(body))
		}
	}
}

func FuzzBoolMatchesJSON(f *testing.F) {
	f.Add([]byte(`{"stream":true,"other":[{},"text"]}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		var fields map[string]json.RawMessage
		want := json.Unmarshal(body, &fields) == nil && string(fields["stream"]) == "true"
		if Bool(body, "stream") != want {
			t.Fatal("metadata differs from JSON object semantics")
		}
	})
}
