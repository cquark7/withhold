package main

import (
	"bytes"
	"flag"
	"reflect"
	"strings"
	"testing"
)

func TestParseOptionsPreservesValuesAndEditorArguments(t *testing.T) {
	for _, test := range []struct {
		name, command string
		args          []string
		wantHelp      bool
		wantError     string
		port          int
		dir           string
		editorArgs    []string
	}{
		{name: "port among flags", command: "on", args: []string{"8090", "--chat-mode", "block", "--port=8091", "8092"}, port: 8092},
		{name: "numeric flag value", command: "on", args: []string{"--max-bytes", "1024", "--port", "8093"}, port: 8093},
		{name: "on rejects end-of-options", command: "on", args: []string{"--", "--port", "8094"}, wantError: "unexpected argument"},
		{name: "help", command: "on", args: []string{"--help"}, wantHelp: true},
		{name: "help is a value", command: "init-ca", args: []string{"--dir", "--help"}, dir: "--help", port: 8080},
		{name: "literal editor args", command: "launch", args: []string{"--", "project with spaces", "--help", "x&echo unsafe"}, editorArgs: []string{"project with spaces", "--help", "x&echo unsafe"}, port: 8080},
		{name: "missing value", command: "on", args: []string{"--port"}, wantError: "needs an argument"},
		{name: "unexpected argument", command: "status", args: []string{"something"}, wantError: "unexpected argument"},
		{name: "unknown flag", command: "on", args: []string{"--porrt", "8090"}, wantError: "not defined"},
		{name: "irrelevant bool", command: "status", args: []string{"--observe=false"}, wantError: "not supported"},
		{name: "irrelevant trust", command: "doctor", args: []string{"--trust", "manual"}, wantError: "not supported"},
		{name: "irrelevant install dir", command: "serve", args: []string{"--bin-dir", "tmp"}, wantError: "not supported"},
		{name: "init only accepts state", command: "init-ca", args: []string{"--port", "8090"}, wantError: "not supported"},
		{name: "init does not read config", command: "init-ca", args: []string{"--config", "config.toml"}, wantError: "not supported"},
		{name: "removed directory alias", command: "on", args: []string{"--ca-dir", "tmp"}, wantError: "not defined"},
		{name: "delimiter stops help", command: "status", args: []string{"--", "--help"}, wantError: "unexpected argument"},
	} {
		t.Run(test.name, func(t *testing.T) {
			o := defaultOptions("~")
			got, showHelp, err := parseOptions(o.flags(test.command), test.command, test.args)
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("error = %v, want %q", err, test.wantError)
				}
				return
			}
			if err != nil || showHelp != test.wantHelp {
				t.Fatalf("help=%v error=%v", showHelp, err)
			}
			if showHelp {
				return
			}
			if o.port != test.port || test.dir != "" && o.dir != test.dir || !reflect.DeepEqual(got, test.editorArgs) {
				t.Fatalf("options=%+v editor=%q", o, got)
			}
		})
	}
}

func TestDebugFlagIsRestrictedToProxyCommands(t *testing.T) {
	for command, want := range map[string]bool{"on": true, "serve": true, "doctor": false, "install": false} {
		if got := allowedFlag(command, "debug"); got != want {
			t.Errorf("--debug allowed for %s = %v, want %v", command, got, want)
		}
	}
	var out bytes.Buffer
	if help(&out, "on") != 0 || !strings.Contains(out.String(), "--debug") || !strings.Contains(out.String(), "debug-findings.log") || !strings.Contains(out.String(), "first 3 Unicode characters") || !strings.Contains(out.String(), "Clean traffic and routine connection events") {
		t.Fatalf("on help does not explain sensitive debug log: %s", out.String())
	}
}

func TestGettingStartedUsesIntegrationDiscoveryNotHarnessAssumptions(t *testing.T) {
	var out bytes.Buffer
	if help(&out, "") != 0 {
		t.Fatal("help failed")
	}
	_, start, ok := strings.Cut(out.String(), "Get started:")
	if !ok || strings.Contains(start, "withhold launch") || strings.Contains(start, "VS Code") || !strings.Contains(start, "withhold integrations") || !strings.Contains(start, "--integration NAME") {
		t.Fatal(out.String())
	}
	out.Reset()
	if help(&out, "launch") != 0 || !strings.Contains(out.String(), "Launch is optional and integration-specific") {
		t.Fatal(out.String())
	}
}

func TestHelpIncludesEverySupportedOptionAndExamples(t *testing.T) {
	t.Setenv("WITHHOLD_MAX_BYTES", "invalid")
	t.Setenv("WITHHOLD_INTEGRATION", "invalid")
	for _, command := range commandOrder {
		t.Run(command, func(t *testing.T) {
			var out bytes.Buffer
			if help(&out, command) != 0 {
				t.Fatal("help failed")
			}
			text := out.String()
			if !strings.Contains(text, "Examples:") || !strings.Contains(text, "Exit codes:") {
				t.Fatal(text)
			}
			o := defaultOptions("~")
			o.flags(command).VisitAll(func(option *flag.Flag) {
				// Match the entire flag token, including the separating space/newline.
				present := strings.Contains(text, "\n  --"+option.Name+" ") || strings.Contains(text, "\n  --"+option.Name+"\n")
				if present != allowedFlag(command, option.Name) {
					t.Errorf("help for --%s: present=%v", option.Name, present)
				}
			})
		})
	}
}

func TestHelpReferencesCurrentDocumentationAndConfigurationScope(t *testing.T) {
	for _, command := range commandOrder {
		var out bytes.Buffer
		if help(&out, command) != 0 {
			t.Fatal("help failed")
		}
		text := out.String()
		if strings.Contains(text, "native-runtime.md") {
			t.Errorf("%s help references a missing guide", command)
		}
		if strings.Contains(text, "Configuration:") != allowedFlag(command, "config") {
			t.Errorf("%s help describes configuration it does not support", command)
		}
	}
}

func TestCompletionUsesCommandOptionsAndRespectsValues(t *testing.T) {
	for _, test := range []struct {
		args []string
		want []string
	}{
		{[]string{"sta"}, []string{"status"}},
		{[]string{"on", "--chat-mode", "b"}, []string{"block"}},
		{[]string{"on", "--chat-mode=b"}, []string{"--chat-mode=block"}},
		{[]string{"status", "--o"}, nil},
		{[]string{"on", "--bi"}, nil},
		{[]string{"doctor", "--max"}, []string{"--max-bytes"}},
		{[]string{"on", "--dir", "--h"}, nil},
		{[]string{"launch", "--", "--h"}, nil},
		{[]string{"completion", "z"}, []string{"zsh"}},
		{[]string{"help", "ser"}, []string{"serve"}},
	} {
		if got := candidates(test.args); !reflect.DeepEqual(got, test.want) {
			t.Errorf("candidates(%q)=%q, want %q", test.args, got, test.want)
		}
	}
	for _, shell := range shells {
		var out bytes.Buffer
		if completion(&out, []string{shell}) != 0 || !strings.Contains(out.String(), "withhold _complete") {
			t.Errorf("invalid script for %s: %s", shell, out.String())
		}
	}
}
