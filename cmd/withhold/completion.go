package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/cquark7/withhold/internal/integrations"
)

var shells = []string{"bash", "zsh", "fish", "powershell"}

// The completion protocol never resolves runtime configuration or local state.
// Its output is data; shell functions pass it to completion APIs without eval.
func candidates(args []string) []string {
	current := ""
	if len(args) > 0 {
		current = args[len(args)-1]
	}
	choices := append(append([]string{}, commandOrder...), "help")
	if len(args) > 1 {
		command := args[0]
		switch command {
		case "help":
			if len(args) > 2 {
				return nil
			}
		case "completion":
			if len(args) > 2 {
				return nil
			}
			choices = shells
		default:
			if _, ok := commands[command]; !ok {
				return nil
			}
			o := defaultOptions("~")
			f := o.flags(command)
			for i := 1; i < len(args)-1; i++ {
				arg := args[i]
				if arg == "--" {
					return nil
				}
				option := f.Lookup(strings.TrimLeft(arg, "-"))
				if option != nil && !boolFlag(option) && !strings.Contains(arg, "=") {
					if i == len(args)-2 {
						return valueCandidates(option.Name, current)
					}
					i++
				}
			}
			if name, value, ok := strings.Cut(current, "="); ok {
				values := valueCandidates(strings.TrimLeft(name, "-"), value)
				for i := range values {
					values[i] = name + "=" + values[i]
				}
				return values
			}
			if command == "scan" && !strings.HasPrefix(current, "-") {
				return nil // Let the shell complete input paths.
			}
			choices = []string{"--help"}
			f.VisitAll(func(option *flag.Flag) {
				if allowedFlag(command, option.Name) {
					choices = append(choices, "--"+option.Name)
				}
			})
		}
	}
	return matching(choices, current)
}

func valueCandidates(name, prefix string) []string {
	switch name {
	case "trust":
		return matching([]string{"system", "manual"}, prefix)
	case "chat-mode", "inline-mode":
		return matching([]string{"redact", "block"}, prefix)
	case "integration":
		var ids []string
		for _, entry := range integrations.List() {
			ids = append(ids, entry.ID)
		}
		return matching(ids, prefix)
	case "pii":
		return matching([]string{"off", "all", "aadhaar", "credit-card", "email", "ip-address", "phone", "us-ssn"}, prefix)
	case "secrets", "no-default-excludes":
		return matching([]string{"true", "false"}, prefix)
	case "confidence":
		return matching([]string{"low", "medium", "high"}, prefix)
	}
	return nil
}
func matching(choices []string, prefix string) []string {
	var result []string
	for _, choice := range choices {
		if strings.HasPrefix(choice, prefix) {
			result = append(result, choice)
		}
	}
	return result
}

func completion(w io.Writer, args []string) int {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		return help(w, "completion")
	}
	if len(args) != 1 {
		return commandUsageError("completion", "choose a shell: bash, zsh, fish, or powershell")
	}
	var script string
	switch args[0] {
	case "bash":
		script = `_withhold_complete() {
    local candidate
    COMPREPLY=()
    while IFS= read -r candidate; do
        COMPREPLY+=("$candidate")
    done < <(withhold _complete "${COMP_WORDS[@]:1:COMP_CWORD}")
}
complete -o default -F _withhold_complete withhold
`
	case "zsh":
		script = `#compdef withhold
_withhold_complete() {
    local -a candidates
    candidates=("${(@f)$(withhold _complete "${words[@]:1:$((CURRENT-1))}")}")
    if [[ -n "${candidates[1]}" ]]; then
        compadd -- "${candidates[@]}"
    else
        _files
    fi
}
compdef _withhold_complete withhold
`
	case "fish":
		script = `complete -c withhold -a '(withhold _complete (commandline -opc)[2..-1] (commandline -ct))'
`
	case "powershell":
		script = `Register-ArgumentCompleter -Native -CommandName withhold -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)
    $elements = @($commandAst.CommandElements | Select-Object -Skip 1 | Where-Object { $_.Extent.StartOffset -lt $cursorPosition })
    $words = @($elements | ForEach-Object { $_.ToString() })
    if ($wordToComplete -eq '' -or $words.Count -eq 0) { $words += '' }
    withhold _complete @words | ForEach-Object {
        [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
    }
}
`
	default:
		return commandUsageError("completion", "unsupported shell; choose bash, zsh, fish, or powershell")
	}
	_, err := io.WriteString(w, script)
	if err != nil {
		fmt.Fprintln(os.Stderr, "withhold: cannot write completion script")
		return 1
	}
	return 0
}
