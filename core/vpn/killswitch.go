package vpn

import (
	"errors"

	"beam-bridge/core/platform"
	"beam-bridge/core/types"
)

// Kill switch policy:
//
//   - the VPN dropped on its own (core died, a node switch failed): the
//     internet is paused before anything is torn down, so not a single packet
//     leaves outside the tunnel;
//   - a successful connect gives the internet back (in TUN mode only after
//     the tunnel and its leak protection are up);
//   - a manual disconnect, the "give the internet back" button and turning
//     the setting off release it at once.
//
// The firewall itself belongs to the core (runner.Service); the manager only
// decides when.

// killSwitcher is implemented by cores with a kill switch (runner.Service).
type killSwitcher interface {
	KillSwitchSupported() bool
	EngageKillSwitch() error
	AllowKillSwitchDNS(allow bool) error
	ReleaseKillSwitch() error
	SetLeakProtection(enabled bool) error
}

const killSwitchEvent = "vpn:killswitch"

func (m *Manager) killSwitch() (killSwitcher, bool) {
	ks, ok := m.core.(killSwitcher)
	if !ok || !ks.KillSwitchSupported() {
		return nil, false
	}
	return ks, true
}

func (m *Manager) killSwitchEnabled() bool {
	s := m.settingsRepo.Get()
	return s != nil && s.Connection.KillSwitch
}

// KillSwitchState reports the kill switch to the UI.
func (m *Manager) KillSwitchState() types.KillSwitchState {
	_, supported := m.killSwitch()
	m.mu.RLock()
	defer m.mu.RUnlock()
	return types.KillSwitchState{
		Supported: supported,
		Enabled:   supported && m.killSwitchEnabled(),
		Engaged:   m.killEngaged,
		Reason:    m.killReason,
		Error:     m.killError,
	}
}

// engageKillSwitch pauses the internet after an unexpected drop. Called
// before the session is torn down.
func (m *Manager) engageKillSwitch(cause error) {
	ks, ok := m.killSwitch()
	if !ok || !m.killSwitchEnabled() {
		return
	}
	err := ks.EngageKillSwitch()

	m.mu.Lock()
	m.killEngaged = err == nil
	m.killReason = ""
	if cause != nil {
		m.killReason = cause.Error()
	}
	m.killError = ""
	if err != nil {
		m.killError = err.Error()
	}
	m.mu.Unlock()

	if err != nil {
		platform.LogCrashEvent("vpn: kill switch did not engage: %v", err)
	}
	m.emitKillSwitch()
}

// openKillSwitchDNS lets the system resolver through an engaged kill switch
// for a reconnect attempt. The returned func closes it again.
func (m *Manager) openKillSwitchDNS() func() {
	m.mu.RLock()
	engaged := m.killEngaged
	m.mu.RUnlock()
	ks, ok := m.killSwitch()
	if !engaged || !ok {
		return func() {}
	}
	if err := ks.AllowKillSwitchDNS(true); err != nil {
		platform.LogCrashEvent("vpn: kill switch: %v", err)
	}
	return func() { _ = ks.AllowKillSwitchDNS(false) }
}

// releaseKillSwitch gives the internet back. Idempotent.
func (m *Manager) releaseKillSwitch() error {
	ks, ok := m.killSwitch()
	if !ok {
		return nil
	}
	err := ks.ReleaseKillSwitch()

	m.mu.Lock()
	changed := m.killEngaged || m.killError != ""
	m.killEngaged = false
	m.killReason = ""
	m.killError = ""
	m.mu.Unlock()

	if changed {
		m.emitKillSwitch()
	}
	return err
}

// EngageKillSwitchAfterCrash pauses the internet at launch when the previous
// run died with the VPN up. Its firewall rules died with that process, so
// until the tunnel is back traffic would leave in the clear; the reconnect
// that follows gives the internet back. Reports whether it engaged.
func (m *Manager) EngageKillSwitchAfterCrash() bool {
	m.engageKillSwitch(errors.New("Beam restarted after a crash"))
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.killEngaged
}

// ReleaseKillSwitch is the "give the internet back" button.
func (m *Manager) ReleaseKillSwitch() error {
	return m.releaseKillSwitch()
}

// ApplyKillSwitch applies a just saved setting to the live state: turning it
// off releases everything, turning it on protects a live tunnel at once.
func (m *Manager) ApplyKillSwitch(enabled bool) error {
	ks, ok := m.killSwitch()
	if !ok {
		return nil
	}
	var err error
	if enabled {
		m.mu.RLock()
		up := m.up
		m.mu.RUnlock()
		if up {
			err = ks.SetLeakProtection(true)
		}
	} else {
		err = m.releaseKillSwitch()
		if perr := ks.SetLeakProtection(false); err == nil {
			err = perr
		}
	}
	m.emitKillSwitch()
	return err
}

func (m *Manager) emitKillSwitch() {
	m.emit(killSwitchEvent, m.KillSwitchState())
}
