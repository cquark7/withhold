package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/cquark7/withhold/internal/config"
	"github.com/cquark7/withhold/internal/integration"
	"github.com/cquark7/withhold/internal/integrations"
)

// Parse flags before reading config so help and usage errors remain read-only
// and independent of malformed files. Apply only explicitly supplied flags.
func (o *cliOptions) resolve(f *flag.FlagSet) (config.Config, error) {
	c := config.Defaults(integrations.Default, runtime.GOOS)
	if flagSet(f, "config") && o.configPath == "" {
		return c, errors.New("--config requires a file path")
	}
	path := o.configPath
	if path == "" {
		path = filepath.Join(o.dir, "config.toml")
	}
	loaded, err := config.Load(path, o.configPath != "", c)
	if err == nil {
		c = loaded
	}
	c.Environment(os.Getenv)
	f.Visit(func(option *flag.Flag) {
		switch option.Name {
		case "port":
			c.Proxy.Port = o.port
		case "chat-mode":
			c.Protection.Chat = o.chat
		case "inline-mode":
			c.Protection.Inline = o.inline
		case "observe":
			c.Protection.Observe = o.observe
		case "max-bytes":
			c.Proxy.MaxBytes = o.max
		case "scan-timeout":
			c.Proxy.ScanTimeout = o.timeout.String()
		case "audit":
			c.Audit = o.audit
		case "hint":
			c.Hint = o.hint
		case "upstream-ca":
			c.Proxy.UpstreamCA = o.upstreamCA
		case "trust":
			c.Trust = o.trust
		case "integration":
			c.Integration = o.integration
		case "pii":
			c.Protection.PII = strings.Split(o.pii, ",")
		}
	})
	// Host/regex additions merge across file, environment, and flags.
	c.Proxy.ExtraHosts = append(c.Proxy.ExtraHosts, o.hosts...)
	c.Proxy.ExtraHostRegex = append(c.Proxy.ExtraHostRegex, o.patterns...)
	if c.Audit == "" {
		c.Audit = filepath.Join(o.dir, "audit.jsonl")
	}
	if c.Hint == "" {
		c.Hint = filepath.Join(o.dir, "hints.log")
	}
	for _, target := range []*string{&c.Audit, &c.Hint, &c.Proxy.UpstreamCA} {
		if *target != "" {
			absolute, e := filepath.Abs(*target)
			if e != nil && err == nil {
				err = e
			}
			*target = absolute
		}
	}
	return c, err
}

func (o *cliOptions) use(c config.Config) {
	o.port, o.chat, o.inline, o.observe = c.Proxy.Port, c.Protection.Chat, c.Protection.Inline, c.Protection.Observe
	o.max, o.audit, o.hint, o.upstreamCA = c.Proxy.MaxBytes, c.Audit, c.Hint, c.Proxy.UpstreamCA
	o.timeout, _ = time.ParseDuration(c.Proxy.ScanTimeout)
	o.trust, o.integration = c.Trust, c.Integration
	o.confidence = c.Scan.Confidence
	o.hosts, o.patterns = c.Proxy.ExtraHosts, c.Proxy.ExtraHostRegex
}

func applicationOptions(home string, c config.Config) integration.ApplicationOptions {
	return integration.ApplicationOptions{Home: home, Platform: runtime.GOOS, ConfigRoot: os.Getenv("XDG_CONFIG_HOME"), AppData: os.Getenv("APPDATA"), Settings: c.Application}
}

func configurationID(c config.Config) string {
	data, _ := json.Marshal(c)
	// Hash, never persist or print, private placeholder material. Test-only scope
	// also participates in reuse even though it is not public configuration.
	data = append(data, []byte("\x00"+os.Getenv("WITHHOLD_PLACEHOLDER_KEY")+"\x00"+strings.Join(c.AllowHosts, ","))...)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
