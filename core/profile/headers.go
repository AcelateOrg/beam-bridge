package profile

import (
	"os"

	"beam-bridge/core/platform"
)

func (m *Manager) buildFetchHeaders() map[string]string {
	hwid := m.settingsRepo.Get().Hwid

	headers := map[string]string{
		// Всегда представляемся как BEAM — никакой маскировки под сторонние
		// клиенты. Панелям достаточно заголовков X-Hwid и Device-Name.
		"User-Agent":      "BEAM/" + platform.GetAppVersion(),
		"X-Device-Os":     platform.DeviceOSLabel(),
		"X-Device-Locale": platform.GetSystemLocale(),
	}
	if osVersion := platform.GetOSVersion(); osVersion != "" {
		headers["X-Ver-Os"] = osVersion
	}

	if hwid.Enabled && hwid.Value != "" {
		headers["X-Hwid"] = hwid.Value
		if hostname, err := os.Hostname(); err == nil && hostname != "" {
			headers["Device-Name"] = hostname
		}
	}

	return headers
}
