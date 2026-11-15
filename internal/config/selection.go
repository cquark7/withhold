package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"

	"github.com/pelletier/go-toml/v2"
	"github.com/pelletier/go-toml/v2/unstable"

	"github.com/cquark7/withhold/internal/localstate"
)

// SaveAgents changes only the root selection, preserving unrelated settings and
// comments. Callers validate adapter IDs before saving a successful setup.
func SaveAgents(path string, agents []string) error {
	if len(agents) == 0 {
		return errors.New("select agents with 'withhold setup AGENT...'")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	unlock, err := localstate.Lock(path + ".lock")
	if err != nil {
		return err
	}
	defer unlock()
	if err := localstate.Regular(path); err != nil {
		return err
	}
	f, err := os.Open(path)
	var data []byte
	if os.IsNotExist(err) {
		data = []byte("schema = 1\n")
	} else if err != nil {
		return err
	} else {
		data, err = io.ReadAll(io.LimitReader(f, (1<<20)+1))
		closeErr := f.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	}
	if len(data) > 1<<20 {
		return errors.New("config exceeds read limit")
	}
	// Revalidate under the lock rather than replacing an externally edited file.
	encoded, err := tomlJSON(data)
	if err != nil {
		return err
	}
	c := Defaults("linux")
	var version struct{ Schema int }
	if json.Unmarshal(encoded, &version) != nil || version.Schema != 1 {
		return errors.New("config requires schema 1")
	}
	if err = DecodeObject(encoded, &c); err != nil {
		return err
	}
	if err = c.Validate(); err != nil {
		return err
	}
	ids := slices.Clone(agents)
	slices.Sort(ids)
	ids = slices.Compact(ids)
	line, err := toml.Marshal(map[string]any{"agents": ids})
	if err != nil {
		return err
	}
	line = bytes.TrimSuffix(line, []byte("\n"))
	out := append(append(bytes.Clone(line), '\n'), data...)
	p := unstable.Parser{}
	p.Reset(data)
	for p.NextExpression() {
		n := p.Expression()
		if n.Kind == unstable.Table || n.Kind == unstable.ArrayTable {
			break // Only root keys select agents.
		}
		if n.Kind != unstable.KeyValue {
			continue
		}
		key := n.Key()
		if key.Next() && string(key.Node().Data) == "agents" && key.IsLast() {
			start, end := int(n.Raw.Offset), int(n.Raw.Offset+n.Raw.Length)
			out = append(bytes.Clone(data[:start]), line...)
			out = append(out, data[end:]...)
			break
		}
	}
	if len(out) > 1<<20 {
		return errors.New("config exceeds read limit")
	}
	// Windows cannot replace the destination while its read handle is open.
	return localstate.Write(path, out, false)
}
