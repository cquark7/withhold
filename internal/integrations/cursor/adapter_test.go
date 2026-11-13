package cursor

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/cquark7/withhold/internal/connectrpc"
	"github.com/cquark7/withhold/internal/editorsettings"
	"github.com/cquark7/withhold/internal/integration"
	"github.com/cquark7/withhold/internal/policy"
	"google.golang.org/protobuf/encoding/protowire"
)

func TestConfigDefaultsStrictnessAndFrozenSelection(t *testing.T) {
	data, err := Configure(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `{"binary":"cursor","settings_dir":"Cursor"}` {
		t.Fatal("wrong defaults")
	}
	for _, raw := range []string{
		`{"unknown":"private"}`, `{"Binary":"private"}`, `{"binary":null}`,
		`{"binary":1}`, `{"binary":"a","binary":"b"}`, `{"settings_dir":"../private"}`, `[]`,
	} {
		if _, err := Configure(json.RawMessage(raw), nil); err == nil {
			t.Fatal("invalid application config accepted")
		}
	}
	frozen, err := Configure(nil, func(key string) string {
		if key == "WITHHOLD_EDITOR_BIN" {
			return "/custom path/cursor"
		}
		if key == "WITHHOLD_EDITOR_SETTINGS_DIR" {
			return "Cursor - Preview"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	again, err := Configure(frozen, nil)
	if err != nil || !bytes.Equal(again, frozen) {
		t.Fatal("child settings changed")
	}
}

func TestApplicationUsesSeparateStoreAndRestoresRecordedAnchor(t *testing.T) {
	home := t.TempDir()
	for _, test := range []struct{ platform, root string }{
		{"darwin", filepath.Join(home, "Library", "Application Support")},
		{"linux", filepath.Join(home, "xdg")},
		{"windows", filepath.Join(home, "roaming")},
	} {
		t.Run(test.platform, func(t *testing.T) {
			a := Application{Options: integration.ApplicationOptions{Home: home, Platform: test.platform,
				ConfigRoot: filepath.Join(home, "xdg"), AppData: filepath.Join(home, "roaming")}}
			target, err := a.Resolve()
			if err != nil || target.Resource != filepath.Join(test.root, "Cursor", "User", "settings.json") || target.Binary != "cursor" {
				t.Fatalf("wrong target: %+v, %v", target, err)
			}
			if err := os.MkdirAll(filepath.Dir(target.Resource), 0700); err != nil {
				t.Fatal(err)
			}
			const before = `{// original
				"http.proxy":"http://old", "cursor.general.disableHttp2":true,
				"settingsSync.ignoredSettings":["custom"], "keep":9007199254740993,
			}`
			if err := os.WriteFile(target.Resource, []byte(before), 0600); err != nil {
				t.Fatal(err)
			}
			for range 2 {
				if err := a.Apply(target, integration.SetupOptions{Port: 12345}); err != nil {
					t.Fatal(err)
				}
			}
			state, err := a.Read(target)
			if err != nil || !state.BackupPresent || state.Proxy != "http://127.0.0.1:12345" {
				t.Fatal("backup/routing not recorded")
			}
			raw, err := os.ReadFile(target.Resource)
			if err != nil {
				t.Fatal(err)
			}
			current, err := editorsettings.ParseSettings(raw)
			if err != nil {
				t.Fatal(err)
			}
			if string(current["cursor.general.disableHttp2"]) != "false" || string(current["http.proxyStrictSSL"]) != "true" {
				t.Fatal("HTTP/2 or TLS validation disabled")
			}
			var ignored []string
			if json.Unmarshal(current["settingsSync.ignoredSettings"], &ignored) != nil || !slices.Contains(ignored, "cursor.general.disableHttp2") {
				t.Fatal("managed HTTP/2 key could sync")
			}
			current["during-session"] = json.RawMessage(`"preserve"`)
			raw, _ = json.Marshal(current)
			if err := os.WriteFile(target.Resource, raw, 0600); err != nil {
				t.Fatal(err)
			}
			broken := Application{Options: integration.ApplicationOptions{Settings: json.RawMessage(`{"unknown":true}`)}}
			if err := broken.Restore(target); err != nil {
				t.Fatal(err)
			}
			raw, _ = os.ReadFile(target.Resource)
			restored, err := editorsettings.ParseSettings(raw)
			if err != nil {
				t.Fatal(err)
			}
			if string(restored["cursor.general.disableHttp2"]) != "true" || string(restored["during-session"]) != `"preserve"` || string(restored["keep"]) != "9007199254740993" {
				t.Fatal("restore lost original or unrelated edits")
			}
			if _, err := os.Stat(state.BackupPath); !os.IsNotExist(err) {
				t.Fatal("recovery backup not consumed")
			}
		})
	}
}

func TestLaunchPreservesArgumentsAndVerifiedProxyEnvironment(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "editor path")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	a := Application{Options: integration.ApplicationOptions{Platform: "darwin"}}
	command, err := a.Command(integration.Target{Binary: binary}, integration.LaunchOptions{
		Port: 12345, CADir: dir, Args: []string{"--wait", "literal ; $HOME", "--new-window"},
		Environment: []string{"https_proxy=http://wrong", "NODE_EXTRA_CA_CERTS=wrong", "KEEP=value"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(command.Args, []string{binary, "--wait", "literal ; $HOME", "--new-window"}) {
		t.Fatal("argument boundaries changed")
	}
	for _, value := range []string{"HTTPS_PROXY=http://127.0.0.1:12345", "NODE_EXTRA_CA_CERTS=" + filepath.Join(dir, "ca.crt"), "KEEP=value"} {
		if !slices.Contains(command.Env, value) {
			t.Fatal("proxy environment missing")
		}
	}
	for _, value := range command.Env {
		if strings.Contains(value, "wrong") {
			t.Fatal("stale proxy/CA environment retained")
		}
	}
}

func TestTrafficRoutesAndConnectBlocks(t *testing.T) {
	scope, err := NewTraffic(policy.ScopeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for path, rpc := range rpcRoutes {
		for _, host := range []string{"api2.cursor.sh", "agentn.global.api5.cursor.sh", "future.eu.api3.cursor.sh", "api.cursor.com"} {
			route := scope.Classify(host+":443", path)
			if !route.Scoped || route.Unknown || route.Codec == nil || route.Codec.Streaming != rpc.stream || route.Codec.Duplex != rpc.duplex {
				t.Fatal("reviewed route not classified")
			}
			if rpc.inline && route.Mode != "block" {
				t.Fatal("inline default changed")
			}
		}
	}
	for _, path := range []string{"/new.Service/Method", "/agent.v1.AgentService/Run", "/aiserver.v1.FileSyncService/FSUploadFile", "/aiserver.v1.AiService/CppAppend", "/aiserver.v1.AiService/%4eameTab"} {
		route := scope.Classify("api2.cursor.sh", path)
		if !route.Unknown || route.Codec == nil {
			t.Fatal("unknown/cache/blob path could bypass inspection")
		}
	}
	if scope.Classify("api2.cursor.sh.evil.invalid", "/any").Scoped {
		t.Fatal("host suffix matched unrelated host")
	}
	for _, options := range []policy.ScopeOptions{
		{ChatMode: "allow"}, {ExtraHosts: []string{"https://private.invalid"}}, {ExtraHostRegex: []string{"["}}, {SuspicionPattern: "["},
	} {
		if _, err := NewTraffic(options); err == nil {
			t.Fatal("invalid traffic config accepted")
		}
	}
	path := "/aiserver.v1.InferenceService/RunInference"
	r := httptest.NewRequest("POST", "https://api2.cursor.sh"+path, nil)
	r.Header.Set("Content-Type", "application/connect+proto")
	response := scope.BlockRequest(r, scope.Classify("api2.cursor.sh", path), "secret-found")
	frame, err := connectrpc.ReadFrame(bytes.NewReader(response.Body), 4096, nil)
	if err == nil || frame.Flags != 0 {
		t.Fatal("response EndStream flag accepted as a request")
	}
	if response.Status != 200 || response.Body[0] != 2 || !bytes.Contains(response.Body, []byte("permission_denied")) {
		t.Fatal("invalid Connect end-stream error")
	}
}

func TestAuxiliaryContentAndControlMessagesUseSharedScanner(t *testing.T) {
	const sentinel = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
	cases := []struct {
		name string
		body []byte
	}{
		{"aiserver.v1.NameTabRequest", byteField(1, byteField(1, []byte(`token = "`+sentinel+`"`)))},
		{"agent.v1.UpdateConversationMetadataRequest", concat(byteField(1, []byte("conversation")), byteField(2, []byte(`token = "`+sentinel+`"`)))},
		{"aiserver.v1.ClassifyAgentAutoReviewRequest", byteField(1, byteField(4, byteField(2, []byte(`token = "`+sentinel+`"`))))},
		{clientMessage, byteField(1, byteField(4, byteField(2, []byte(`token = "`+sentinel+`"`))))},
	}
	scan := newScanner(t, "")
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			message, err := decodeMessage(test.name, test.body, policy.DecodeLimits{MaxBytes: testCap})
			if err != nil {
				t.Fatal(err)
			}
			if !message.HasContent() {
				t.Fatal("model content was misclassified as control")
			}
			report := scan.Scan(message.ScanInput(), testCap)
			if report["status"] != "redacted" {
				t.Fatal("auxiliary prompt was not detected")
			}
			projection, err := base64.StdEncoding.DecodeString(report["body_base64"].(string))
			if err != nil {
				t.Fatal(err)
			}
			body, err := message.Rewrite(projection)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(body, []byte(sentinel)) || !bytes.Contains(body, []byte("<WITHHELD_")) {
				t.Fatal("auxiliary wire content not redacted")
			}
		})
	}
	for _, wire := range [][]byte{
		byteField(1, byteField(1, []byte("conversation"))), byteField(3, byteField(1, []byte("invocation"))),
		byteField(4, uintField(1, 0)), byteField(5, nil),
	} {
		message, err := DecodeRunInference(wire, testCap)
		if err != nil || message.HasContent() {
			t.Fatalf("control message established model coverage: %v", err)
		}
		if _, err := message.Rewrite(message.ScanInput()); err != nil {
			t.Fatal(err)
		}
	}
}

func TestNameTabObservedConversationFieldsAreScannedSafely(t *testing.T) {
	const secret = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
	conversation := concat(
		byteField(1, []byte("synthetic prompt")),
		uintField(47, 2), // unified_mode
		byteField(57, []byte(`rich text includes "`+secret+`"`)),
		byteField(74, []byte("synthetic-request-id")),
		uintField(77, 1), // is_plan_execution
		byteField(78, []byte("2026-11-13T12:00:00Z")),
		byteField(79, byteField(1, []byte("synthetic-model"))),
		uintField(98, 1), // agent_mode
	)
	wire := byteField(1, conversation)
	message, err := decodeMessage("aiserver.v1.NameTabRequest", wire, policy.DecodeLimits{MaxBytes: testCap})
	if err != nil {
		t.Fatal(err)
	}
	if !message.HasContent() {
		t.Fatal("rich_text was misclassified as metadata")
	}
	for _, value := range []string{
		"rich_text", "request_id", "created_at", "model_name", secret,
	} {
		if !bytes.Contains(message.ScanInput(), []byte(value)) {
			t.Fatalf("observed NameTab field %q was not projected", value)
		}
	}
	scan := newScanner(t, "")
	report := scan.Scan(message.ScanInput(), testCap)
	if report["status"] != "redacted" {
		t.Fatalf("rich_text secret was not detected: %v", report["status"])
	}
	projection, err := base64.StdEncoding.DecodeString(report["body_base64"].(string))
	if err != nil {
		t.Fatal(err)
	}
	rewritten, err := message.Rewrite(projection)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(rewritten, []byte(secret)) || !bytes.Contains(rewritten, []byte("<WITHHELD_")) {
		t.Fatal("NameTab rich_text was not rewritten")
	}
	rewrittenConversation := byteFields(t, rewritten, 1)[0]
	if !bytes.Contains(byteFields(t, rewrittenConversation, 57)[0], []byte("<WITHHELD_")) {
		t.Fatal("rewritten rich_text field is missing its placeholder")
	}
	for _, number := range []protowire.Number{47, 74, 77, 78, 79, 98} {
		before := rawWireField(t, conversation, number)
		after := rawWireField(t, rewrittenConversation, number)
		if !bytes.Equal(before, after) {
			t.Fatalf("metadata field %d changed during redaction", number)
		}
	}
}

func TestNameTabImmutableObservedFieldsBlockFindings(t *testing.T) {
	const secret = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
	wire := byteField(1, concat(
		byteField(74, []byte(secret)),
		byteField(57, []byte("ordinary rich text")),
	))
	message, err := decodeMessage("aiserver.v1.NameTabRequest", wire, policy.DecodeLimits{MaxBytes: testCap})
	if err != nil {
		t.Fatal(err)
	}
	report := newScanner(t, "").Scan(message.ScanInput(), testCap)
	if report["status"] != "redacted" {
		t.Fatal("secret in request_id was not inspected")
	}
	projection, err := base64.StdEncoding.DecodeString(report["body_base64"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if rewritten, err := message.Rewrite(projection); rewritten != nil || !errors.Is(err, ErrUnsupported) {
		t.Fatal("immutable request_id was rewritten instead of failing closed")
	}
}

func TestTabAndAuxiliaryUnreviewedStateFailsClosed(t *testing.T) {
	for _, test := range []struct {
		name string
		body []byte
	}{
		{"aiserver.v1.StreamCppRequest", byteField(1, uintField(18, 1))},
		{"aiserver.v1.StreamCppRequest", byteField(1, byteField(17, []byte("digest")))},
		{"aiserver.v1.StreamCppRequest", byteField(22, nil)},
		{"aiserver.v1.NameTabRequest", byteField(1, byteField(89, []byte("blob-reference")))},
		{"aiserver.v1.NameTabRequest", byteField(1, byteField(18, nil))},
	} {
		if _, err := decodeMessage(test.name, test.body, policy.DecodeLimits{MaxBytes: testCap}); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("unreviewed context accepted: %v", err)
		}
	}
	tab, err := decodeMessage("aiserver.v1.StreamCppRequest", byteField(1, byteField(2, []byte("Explain this function."))), policy.DecodeLimits{MaxBytes: testCap})
	if err != nil || !tab.HasContent() {
		t.Fatalf("inline full content did not decode: %v", err)
	}
	if output, err := tab.Rewrite(bytes.ReplaceAll(tab.ScanInput(), []byte("Explain"), []byte("Redact"))); output != nil || !errors.Is(err, ErrUnsupported) {
		t.Fatal("Tab offsets could be silently corrupted by redaction")
	}
}

func rawWireField(t *testing.T, body []byte, want protowire.Number) []byte {
	t.Helper()
	for len(body) != 0 {
		number, wire, tagSize := protowire.ConsumeTag(body)
		if tagSize < 0 {
			t.Fatal("invalid protobuf tag")
		}
		valueSize := protowire.ConsumeFieldValue(number, wire, body[tagSize:])
		if valueSize < 0 {
			t.Fatal("invalid protobuf value")
		}
		if number == want {
			return bytes.Clone(body[:tagSize+valueSize])
		}
		body = body[tagSize+valueSize:]
	}
	return nil
}

func TestDecodeAdmissionAndCancellation(t *testing.T) {
	capacity := errors.New("test capacity")
	if _, err := decodeMessage(clientMessage, fullRequest(textRequest("safe text")), policy.DecodeLimits{
		MaxBytes: testCap, Reserve: func(int) error { return capacity },
	}); !errors.Is(err, capacity) {
		t.Fatal("codec lost transport admission failure")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := decodeMessage(clientMessage, fullRequest(textRequest("safe text")), policy.DecodeLimits{
		MaxBytes: testCap, Context: ctx,
	}); !errors.Is(err, context.Canceled) {
		t.Fatal("codec ignored cancellation")
	}
	// Reader boundary EOF is not a supported empty client message.
	if _, err := DecodeRunInference(nil, testCap); err == nil || errors.Is(err, io.EOF) {
		t.Fatal("empty protobuf counted as a model request")
	}
}
