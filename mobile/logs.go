//go:build linux

package mobile

import (
	"beam-bridge/core/coreapi"
	"beam-bridge/core/types"
)

// The core's log journal for the app's "Логи" screen: the same buffer and
// levels as desktop's tab. It lives in the core instance, so it outlasts a
// disconnect and is cleared only on request.

// Logs returns up to limit entries newer than afterID as JSON
// ([]types.LogEntry: id, timestamp (ms), level, message, source). afterID 0
// starts from the oldest kept entry.
func Logs(afterID int64, limit int) (string, error) {
	svc, err := runnerService()
	if err != nil {
		return "", err
	}
	entries := svc.Logs().GetSince(afterID, limit)
	if entries == nil {
		entries = []types.LogEntry{}
	}
	return toJSON(entries)
}

// ClearLogs empties the journal.
func ClearLogs() error {
	svc, err := runnerService()
	if err != nil {
		return err
	}
	svc.Logs().Clear()
	return nil
}

// LogLevel is the stored journal level: "off", "error", "info" or "debug".
func LogLevel() string {
	mu.Lock()
	s := settings
	mu.Unlock()
	if s == nil {
		return "info"
	}
	cur := s.Get()
	switch {
	case cur.LogLevel != "":
		return cur.LogLevel
	case cur.DisableCoreLogging:
		return "off"
	}
	return "info"
}

// SetLogLevel stores the journal level and applies it to the core at once.
func SetLogLevel(level string) error {
	mu.Lock()
	s := settings
	mu.Unlock()
	if s == nil {
		return errNotInitialized
	}
	if err := s.SetLogLevel(level); err != nil {
		return err
	}
	svc, err := runnerService()
	if err != nil {
		return err
	}
	applyLogLevel(svc.SetLogOptions, LogLevel())
	return nil
}

func applyLogLevel(set func(coreapi.LogOptions), level string) {
	set(coreapi.LogOptions{CoreLogging: level != "off", MinLevel: level})
}
