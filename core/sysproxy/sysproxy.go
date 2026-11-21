// Package sysproxy points the operating system proxy settings at Beam's local
// mixed (SOCKS5 + HTTP) inbound and restores the user's own settings after.
//
// The previous settings are written to disk before anything is changed, so a
// crash with the proxy enabled is undone on the next start (Recover) instead
// of leaving the machine pointed at a port nobody listens on.
package sysproxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// wildcardBypass lists the destinations that never go through the proxy, in
// the wildcard syntax of WinINet (CIDR-aware platforms use cidrBypass).
func wildcardBypass() []string {
	list := []string{"localhost", "127.*", "10.*", "192.168.*", "169.254.*"}
	for i := 16; i <= 31; i++ {
		list = append(list, fmt.Sprintf("172.%d.*", i))
	}
	return append(list, "*.local", "[::1]")
}

var cidrBypass = []string{
	"localhost", "127.0.0.0/8", "::1", "*.local", "10.0.0.0/8", "172.16.0.0/12",
	"192.168.0.0/16", "169.254.0.0/16", "fe80::/10", "fc00::/7",
}

const backupName = "sysproxy-backup.json"

// Manager owns the system proxy for one process.
type Manager struct {
	mu         sync.Mutex
	backupPath string
	active     bool
	recovered  bool
	host       string
	port       int
}

// New returns a manager keeping its crash-recovery backup in dataDir.
func New(dataDir string) *Manager {
	path := ""
	if strings.TrimSpace(dataDir) != "" {
		path = filepath.Join(dataDir, backupName)
	}
	return &Manager{backupPath: path}
}

// Supported reports whether this platform can set a system proxy at all.
func Supported() bool { return supported() }

// Active reports whether the system proxy currently points at Beam.
func (m *Manager) Active() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.active
}

// Enable points the system proxy at host:port. The user's settings are
// captured once, on the first Enable; later calls (a port change on a hot
// restart) only re-apply.
func (m *Manager) Enable(host string, port int) error {
	if port <= 0 || port > 65535 {
		return fmt.Errorf("sysproxy: invalid port %d", port)
	}
	if host == "" {
		host = "127.0.0.1"
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.recoverLocked()

	if m.active && m.host == host && m.port == port {
		return nil
	}
	if !m.active {
		saved, err := capture()
		if err != nil {
			return fmt.Errorf("sysproxy: read current settings: %w", err)
		}
		if err := m.writeBackup(saved); err != nil {
			return fmt.Errorf("sysproxy: save current settings: %w", err)
		}
	}
	if err := apply(host, port); err != nil {
		// Half-applied settings are worse than none.
		if !m.active {
			if saved, readErr := m.readBackup(); readErr == nil {
				_ = restore(saved)
			}
			m.removeBackup()
		}
		return fmt.Errorf("sysproxy: %w", err)
	}
	m.active, m.host, m.port = true, host, port
	return nil
}

// Disable gives the user's own proxy settings back. Idempotent.
func (m *Manager) Disable() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.recoverLocked()
	if !m.active {
		return nil
	}
	m.active = false
	saved, err := m.readBackup()
	if err != nil {
		// Without a backup the safest state is "no proxy".
		err = clearProxy()
	} else {
		err = restore(saved)
	}
	m.removeBackup()
	if err != nil {
		return fmt.Errorf("sysproxy: restore settings: %w", err)
	}
	return nil
}

// Recover undoes a system proxy left behind by a crashed session.
func (m *Manager) Recover() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.recoverLocked()
}

func (m *Manager) recoverLocked() {
	if m.recovered {
		return
	}
	m.recovered = true
	if m.active {
		return
	}
	saved, err := m.readBackup()
	if err != nil {
		return
	}
	_ = restore(saved)
	m.removeBackup()
}

type backupFile struct {
	OS    string          `json:"os"`
	Saved json.RawMessage `json:"saved"`
}

func (m *Manager) writeBackup(saved json.RawMessage) error {
	if m.backupPath == "" {
		return nil
	}
	data, err := json.Marshal(backupFile{OS: goos, Saved: saved})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.backupPath), 0o755); err != nil {
		return err
	}
	tmp := m.backupPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, m.backupPath)
}

func (m *Manager) readBackup() (json.RawMessage, error) {
	if m.backupPath == "" {
		return nil, os.ErrNotExist
	}
	data, err := os.ReadFile(m.backupPath)
	if err != nil {
		return nil, err
	}
	var file backupFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, err
	}
	if file.OS != goos {
		return nil, errors.New("sysproxy: backup from another platform")
	}
	return file.Saved, nil
}

func (m *Manager) removeBackup() {
	if m.backupPath != "" {
		_ = os.Remove(m.backupPath)
	}
}

const commandTimeout = 10 * time.Second

// run executes a helper tool and returns its trimmed stdout.
func run(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	prepareCommand(cmd)
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && len(exitErr.Stderr) > 0 {
			return "", fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(exitErr.Stderr)))
		}
		return "", fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return strings.TrimSpace(string(out)), nil
}

func available(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}
