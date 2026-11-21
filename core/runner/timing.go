package runner

import (
	"fmt"
	"strings"
	"time"

	"beam-bridge/core/types"
)

// stageTimer measures the stages of a connect, so a slow one shows up in the
// log as a single line instead of a guess.
type stageTimer struct {
	start time.Time
	last  time.Time
	parts []string
}

func newStageTimer() *stageTimer {
	now := time.Now()
	return &stageTimer{start: now, last: now}
}

// mark closes the stage that ran since the previous mark.
func (t *stageTimer) mark(name string) {
	if t == nil {
		return
	}
	now := time.Now()
	t.note(name, now.Sub(t.last))
	t.last = now
}

// note records a duration measured elsewhere (e.g. in parallel).
func (t *stageTimer) note(name string, d time.Duration) {
	if t == nil {
		return
	}
	t.parts = append(t.parts, fmt.Sprintf("%s %dms", name, d.Milliseconds()))
}

func (t *stageTimer) String() string {
	return fmt.Sprintf("%dms (%s)", time.Since(t.start).Milliseconds(), strings.Join(t.parts, ", "))
}

// logTiming writes the connect timing at info level: visible in the regular
// log view, not only in developer mode.
func (s *Service) logTiming(prefix string, t *stageTimer) {
	s.instance.Logs().Add(types.LogEntry{
		Timestamp: time.Now().UnixMilli(),
		Level:     types.LogLevelInfo,
		Source:    "tunnel",
		Message:   prefix + " " + t.String(),
	})
}
