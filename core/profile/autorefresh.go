package profile

import (
	"context"
	"time"

	"beam-bridge/core/platform"
)

const DefaultUpdateIntervalHours = 6

const autoRefreshTickInterval = 15 * time.Minute

func (m *Manager) SetAutoRefresh(profileID string, disabled bool) error {
	return m.storage.SetAutoRefresh(profileID, disabled)
}

const MaxUpdateIntervalOverrideHours = 720

func (m *Manager) SetUpdateIntervalOverride(profileID string, hours int) error {
	if hours < 0 {
		hours = 0
	}
	if hours > MaxUpdateIntervalOverrideHours {
		hours = MaxUpdateIntervalOverrideHours
	}
	return m.storage.SetUpdateIntervalOverride(profileID, hours)
}

func (m *Manager) RunAutoRefreshLoop(ctx context.Context) {
	defer platform.RecoverAndLog("auto-refresh-subscriptions")

	select {
	case <-ctx.Done():
		return
	case <-time.After(5 * time.Second):
	}

	m.refreshDueProfiles()

	ticker := time.NewTicker(autoRefreshTickInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.refreshDueProfiles()
		}
	}
}

func (m *Manager) refreshDueProfiles() {
	if m.settingsRepo.Get().Application.DisableSubscriptionAutoRefresh {
		return
	}

	profiles, err := m.storage.GetAll()
	if err != nil {
		return
	}

	now := time.Now()
	for _, p := range profiles {
		if p.URL == "" {
			continue
		}
		if p.AutoRefreshDisabled {
			continue
		}

		interval := p.UpdateIntervalOverrideHours
		if interval <= 0 {
			interval = p.UpdateIntervalHours
		}
		if interval <= 0 {
			interval = DefaultUpdateIntervalHours
		}

		dueAt := p.UpdatedAt.Add(time.Duration(interval) * time.Hour)
		if now.Before(dueAt) {
			continue
		}

		go func(id string) {
			defer platform.RecoverAndLog("auto-refresh-subscription")
			_ = m.RefreshProfile(id)
		}(p.ID)
	}
}
