package xray

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"beam-bridge/core/types"

	"github.com/xtls/xray-core/common/crash"
)

// panicLogLimit caps logs/panics.log: past it the file starts over.
const panicLogLimit = 1 << 20

var panicLogMu sync.Mutex

// installCrashHook reports panics the core contained (common/crash): one line
// in the Logs tab and the full stack in logs/panics.log, so a bug in a
// protocol handler is visible and fixable instead of silently costing
// connections.
func (i *Instance) installCrashHook() {
	crash.SetHook(func(where string, value any, stack []byte) {
		if i.logs != nil {
			i.logs.Add(types.LogEntry{
				Level:   types.LogLevelError,
				Message: fmt.Sprintf("core: panic in %s contained, connection closed: %v", where, value),
			})
		}
		if i.paths.Data == "" {
			return
		}
		// The hook runs on the panicking goroutine and must not block it for
		// long: the write is small and happens off it.
		go writePanicLog(filepath.Join(i.paths.Data, "logs"), where, value, stack)
	})
}

func writePanicLog(dir, where string, value any, stack []byte) {
	panicLogMu.Lock()
	defer panicLogMu.Unlock()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	path := filepath.Join(dir, "panics.log")
	flags := os.O_CREATE | os.O_WRONLY | os.O_APPEND
	if st, err := os.Stat(path); err == nil && st.Size() > panicLogLimit {
		flags = os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	}
	f, err := os.OpenFile(path, flags, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = fmt.Fprintf(f, "=== %s panic in %s: %v\n%s\n", time.Now().Format(time.RFC3339), where, value, stack)
}
