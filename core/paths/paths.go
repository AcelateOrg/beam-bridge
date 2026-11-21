package paths

import (
	"fmt"
	"os"
	"path/filepath"
)

type Paths struct {
	Data string
	Profiles string
	Temp string
}

func New(data string) Paths {
	return Paths{
		Data:     data,
		Profiles: filepath.Join(data, "profiles"),
		Temp:     filepath.Join(data, "temp"),
	}
}

// Config is the application config (sectioned format, see
// persistence/settings/file_format.go).
func (p Paths) Config() string { return filepath.Join(p.Data, "config.json") }

// LegacySettings is the old flat settings file, read once for migration and
// then removed.
func (p Paths) LegacySettings() string { return filepath.Join(p.Data, "settings.json") }

func (p Paths) State() string { return filepath.Join(p.Data, "state.json") }

// ProfileExt is the extension of the encrypted at-rest profile container. It
// is deliberately not ".beam" so the store does not look like a set of BEAM
// files to a scanner. ".beam" stays the portable export/import format.
const ProfileExt = ".bpx"

// LegacyProfileExt is the old plaintext on-disk extension, still read once so
// existing installs migrate transparently.
const LegacyProfileExt = ".beam"

func (p Paths) Profile(id string) string { return filepath.Join(p.Profiles, id+ProfileExt) }

func (p Paths) LegacyProfile(id string) string {
	return filepath.Join(p.Profiles, id+LegacyProfileExt)
}

func (p Paths) Core() string { return filepath.Join(p.Data, "core") }

func (p Paths) Valid() bool { return p.Data != "" && p.Profiles != "" && p.Temp != "" }

func (p Paths) EnsureDirs() error {
	for _, dir := range []string{p.Data, p.Profiles, p.Temp, p.Core()} {
		if dir == "" {
			continue
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create directory %s: %w", dir, err)
		}
	}
	return nil
}
