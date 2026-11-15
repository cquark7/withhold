// Package doclink builds links to this module's published documentation.
package doclink

import (
	"runtime/debug"
	"strings"
)

// URL returns a link to a documentation file in the repository's main branch.
// The repository path comes from the Go module metadata, avoiding a second
// hardcoded copy of the module's GitHub location.
func URL(path string) string {
	info, ok := debug.ReadBuildInfo()
	if !ok || !strings.HasPrefix(info.Main.Path, "github.com/") {
		return ""
	}
	return "https://" + info.Main.Path + "/blob/main/docs/" + strings.TrimLeft(path, "/")
}
