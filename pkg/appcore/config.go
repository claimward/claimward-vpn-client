package appcore

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/claimward/claimward-vpn-client/pkg/protocol"
	"github.com/claimward/claimward-vpn-client/pkg/secureurl"
	"github.com/claimward/claimward-vpn-client/pkg/tokenstore"
)

// configVersion is the file's format. Version 1 (no "version" key) held one
// server and its sign-in parameters; LoadConfig reads it once, writes the
// current one and never reads it again.
const configVersion = 2

// ServerEntry is a server the person added: its URL, and the identity
// provider they chose when the server offers several. Everything else about
// the server (its name, providers, logo, whether it is exclusive) is read
// from the server's own discovery document when it is needed.
type ServerEntry struct {
	// URL is the server's canonical URL (secureurl.Canonical).
	URL string `json:"url"`
	// Provider is the id of the chosen identity provider (protocol.Provider.ID).
	// Empty: the server's only provider, or none chosen yet.
	Provider string `json:"provider,omitempty"`
}

// Config is the app's runtime configuration: a JSON file under the user's
// configuration directory (os.UserConfigDir()/Claimward/config.json: on
// macOS ~/Library/Application Support, on Linux ~/.config, on Windows
// %AppData%). The only environment override is CLAIMWARD_HELPER_SOCKET.
type Config struct {
	// Servers are the servers the person added, in the order they added them.
	Servers []ServerEntry `json:"servers"`
	// SocketPath is the helper's socket (empty = default).
	SocketPath string `json:"socket_path,omitempty"`
}

// file is Config as written.
type file struct {
	Version int `json:"version"`
	Config
}

// legacyConfig is the version-1 file.
type legacyConfig struct {
	ServerURL string `json:"server_url"`
	Provider  string `json:"provider"`
}

// LoadConfig reads config.json (if present) then applies the environment
// override. A version-1 file is migrated: its server becomes the one entry,
// its signed-in session (if any) is kept under that server, and the new
// file is written.
func LoadConfig() (*Config, error) {
	c := &Config{}
	if p, err := configPath(); err == nil {
		if data, rerr := os.ReadFile(p); rerr == nil {
			var probe struct {
				Version int `json:"version"`
			}
			if jerr := json.Unmarshal(data, &probe); jerr != nil {
				return nil, jerr
			}
			switch probe.Version {
			case 0:
				c = migrate(data)
			case configVersion:
				var f file
				if jerr := json.Unmarshal(data, &f); jerr != nil {
					return nil, jerr
				}
				c = &f.Config
			default:
				return nil, fmt.Errorf("%s: configuration version %d is not supported", p, probe.Version)
			}
		} else if !errors.Is(rerr, fs.ErrNotExist) {
			// Unreadable (e.g. permission) — start unconfigured rather than fail;
			// the user can add a server in the app.
			c = &Config{}
		}
	}
	override(&c.SocketPath, "CLAIMWARD_HELPER_SOCKET")
	return c, nil
}

// migrate reads a version-1 file. It is best effort: what cannot be carried
// over (a server that is not an acceptable URL, a session the secret store
// will not hand over) is dropped, and the person adds the server again.
func migrate(data []byte) *Config {
	c := &Config{}
	var old legacyConfig
	if json.Unmarshal(data, &old) != nil {
		return c
	}
	var socket struct {
		SocketPath string `json:"socket_path"`
	}
	_ = json.Unmarshal(data, &socket)
	c.SocketPath = socket.SocketPath
	canon, err := secureurl.Canonical(old.ServerURL)
	if err != nil {
		_ = tokenstore.DiscardLegacy()
		return c
	}
	if old.Provider == "" {
		old.Provider = protocol.KindGitHub
	}
	// The old file named the kind of provider, the server names its providers
	// by id: the kind is the best guess, and Core settles it against the
	// server's document (reconcile) the first time it reads it.
	c.Servers = []ServerEntry{{URL: canon, Provider: old.Provider}}
	if _, err := tokenstore.AdoptLegacy(tokenstore.Key(canon, old.Provider)); err != nil {
		return c // retried at the next start: the old file is still there
	}
	_ = SaveConfig(c)
	return c
}

// Validate reports whether the configuration is usable: every server's URL
// is a canonical, acceptable one, and none is listed twice.
func (c *Config) Validate() error {
	seen := map[string]bool{}
	for _, s := range c.Servers {
		canon, err := secureurl.Canonical(s.URL)
		if err != nil {
			return errors.New("server " + s.URL + ": " + err.Error())
		}
		if canon != s.URL {
			return errors.New("server " + s.URL + ": not canonical, want " + canon)
		}
		if seen[canon] {
			return errors.New("server " + canon + " is listed twice")
		}
		seen[canon] = true
		if s.Provider != "" && !protocol.ValidProviderID(s.Provider) {
			return errors.New("server " + canon + ": invalid provider id")
		}
	}
	return nil
}

func configPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "Claimward", "config.json"), nil
}

// ConfigPath returns the on-disk config location for display (best-effort).
func ConfigPath() string {
	p, _ := configPath()
	return p
}

// SaveConfig writes the config to disk atomically with 0600 permissions.
func SaveConfig(c *Config) error {
	p, err := configPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(file{Version: configVersion, Config: *c}, "", "  ")
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

func override(field *string, env string) {
	if v := os.Getenv(env); v != "" {
		*field = v
	}
}
