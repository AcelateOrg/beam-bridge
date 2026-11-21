package types

// KillSwitchState is what the UI shows about the kill switch.
type KillSwitchState struct {
	// Supported: the platform has a kill switch (Windows for now).
	Supported bool `json:"supported"`
	// Enabled: the user turned it on.
	Enabled bool `json:"enabled"`
	// Engaged: the VPN dropped on its own and the internet is paused.
	Engaged bool `json:"engaged"`
	// Reason is why the VPN dropped.
	Reason string `json:"reason,omitempty"`
	// Error: the kill switch should have engaged but could not.
	Error string `json:"error,omitempty"`
}
