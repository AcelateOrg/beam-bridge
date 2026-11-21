package xray

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"beam-bridge/core/types"
)

const defaultLogBufferSize = 1000

const logFileFlushInterval = time.Second

const logFileBufferSize = 32 << 10

const coreLogKeep = 5

type LogBuffer struct {
	mu sync.RWMutex

	entries []types.LogEntry
	start   int
	count   int
	maxSize int

	nextID int64
	sink   func(types.LogEntry)

	file      *os.File
	fileBuf   *bufio.Writer
	lastFlush time.Time
	dir       string

	coreEnabled atomic.Bool
	// minRank — минимальный ранг уровня (logLevelRank), попадающий в буфер.
	// Управляется пользовательской настройкой «Уровень логов».
	minRank atomic.Int32
}

func NewLogBuffer(maxSize int) *LogBuffer {
	if maxSize <= 0 {
		maxSize = defaultLogBufferSize
	}
	lb := &LogBuffer{maxSize: maxSize}
	lb.coreEnabled.Store(true)
	// По умолчанию — info: ошибки, предупреждения и содержательные события
	// видны, отладочный шум — нет.
	lb.minRank.Store(int32(logLevelRank[types.LogLevelInfo]))
	return lb
}

func (lb *LogBuffer) SetCoreLogging(enabled bool) {
	if lb.coreEnabled.Swap(enabled) == enabled {
		return
	}
	if !enabled {
		lb.Clear()
	}
}

func (lb *LogBuffer) CoreLoggingEnabled() bool {
	return lb.coreEnabled.Load()
}

// SetMinLevel задаёт минимальный уровень записей буфера: "error" | "info" |
// "debug" (пустое = "info"). "off" сюда не приходит — он выражается через
// SetCoreLogging(false).
func (lb *LogBuffer) SetMinLevel(level string) {
	switch level {
	case "debug", "trace":
		lb.minRank.Store(int32(logLevelRank[types.LogLevelDebug]))
	case "error":
		lb.minRank.Store(int32(logLevelRank[types.LogLevelError]))
	default:
		lb.minRank.Store(int32(logLevelRank[types.LogLevelInfo]))
	}
}

// MinRank — текущий минимальный ранг уровня записей буфера.
func (lb *LogBuffer) MinRank() int {
	return int(lb.minRank.Load())
}

func (lb *LogBuffer) SetSink(sink func(types.LogEntry)) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	lb.sink = sink
}

func (lb *LogBuffer) Add(entry types.LogEntry) {
	// Фильтр уровня до любой работы: ниже порога строка не стоит ничего.
	if logLevelRank[entry.Level] < int(lb.minRank.Load()) {
		return
	}
	entry.Source = parseSource(entry.Message)

	lb.mu.Lock()
	lb.nextID++
	entry.ID = lb.nextID
	entry.Timestamp = time.Now().UnixMilli()

	if lb.entries == nil {
		lb.entries = make([]types.LogEntry, lb.maxSize)
	}

	pos := (lb.start + lb.count) % lb.maxSize
	if lb.count == lb.maxSize {
		lb.start = (lb.start + 1) % lb.maxSize
	} else {
		lb.count++
	}
	lb.entries[pos] = entry

	if lb.fileBuf != nil {
		fmt.Fprintf(lb.fileBuf, "%s [%s] %s: %s\r\n",
			time.Now().Format("15:04:05.000"), entry.Level, entry.Source, entry.Message)
		now := time.Now()
		if now.Sub(lb.lastFlush) >= logFileFlushInterval ||
			logLevelRank[entry.Level] >= logLevelRank[types.LogLevelWarn] {
			_ = lb.fileBuf.Flush()
			lb.lastFlush = now
		}
	}
	sink := lb.sink
	lb.mu.Unlock()

	if sink != nil {
		sink(entry)
	}
}

func (lb *LogBuffer) entryAt(i int) types.LogEntry {
	return lb.entries[(lb.start+i)%lb.maxSize]
}

func (lb *LogBuffer) GetAll() []types.LogEntry {
	lb.mu.RLock()
	defer lb.mu.RUnlock()
	result := make([]types.LogEntry, lb.count)
	for i := 0; i < lb.count; i++ {
		result[i] = lb.entryAt(i)
	}
	return result
}

func (lb *LogBuffer) GetSince(afterID int64, limit int) []types.LogEntry {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	var result []types.LogEntry
	for i := 0; i < lb.count; i++ {
		entry := lb.entryAt(i)
		if entry.ID > afterID {
			result = append(result, entry)
		}
	}
	if limit > 0 && len(result) > limit {
		result = result[len(result)-limit:]
	}
	return result
}

func (lb *LogBuffer) GetFiltered(level types.LogLevel, source string, limit int) []types.LogEntry {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	if limit <= 0 {
		limit = 100
	}

	var result []types.LogEntry
	for i := lb.count - 1; i >= 0 && len(result) < limit; i-- {
		entry := lb.entryAt(i)
		if level != "" && !isLevelMatch(entry.Level, level) {
			continue
		}
		if source != "" && entry.Source != source {
			continue
		}
		result = append(result, entry)
	}

	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}
	return result
}

func (lb *LogBuffer) Clear() {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	lb.entries = nil
	lb.start = 0
	lb.count = 0

	if lb.file != nil {
		if lb.fileBuf != nil {
			lb.fileBuf.Reset(lb.file)
		}
		_ = lb.file.Truncate(0)
		_, _ = lb.file.Seek(0, 0)
		lb.lastFlush = time.Now()
	}
}

func (lb *LogBuffer) EnableFileLog(dataDir string) {
	if dataDir == "" {
		return
	}
	dir := filepath.Join(dataDir, "logs")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	f, err := os.OpenFile(
		filepath.Join(dir, fmt.Sprintf("core-%s.log", time.Now().Format("20060102-150405"))),
		os.O_CREATE|os.O_WRONLY|os.O_TRUNC,
		0o600,
	)
	if err != nil {
		return
	}

	pruneCoreLogs(dir, coreLogKeep)

	lb.mu.Lock()
	old := lb.file
	oldBuf := lb.fileBuf
	lb.file = f
	lb.fileBuf = bufio.NewWriterSize(f, logFileBufferSize)
	lb.lastFlush = time.Now()
	lb.dir = dir
	lb.mu.Unlock()

	if oldBuf != nil {
		_ = oldBuf.Flush()
	}
	if old != nil {
		_ = old.Close()
	}
}

func pruneCoreLogs(dir string, keep int) {
	if keep <= 0 {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasPrefix(name, "core-") && strings.HasSuffix(name, ".log") {
			names = append(names, name)
		}
	}
	if len(names) <= keep {
		return
	}
	sort.Strings(names)
	for _, name := range names[:len(names)-keep] {
		_ = os.Remove(filepath.Join(dir, name))
	}
}

func (lb *LogBuffer) DisableFileLog() {
	lb.mu.Lock()
	old := lb.file
	oldBuf := lb.fileBuf
	lb.file = nil
	lb.fileBuf = nil
	lb.mu.Unlock()

	if oldBuf != nil {
		_ = oldBuf.Flush()
	}
	if old != nil {
		_ = old.Close()
	}
}

func (lb *LogBuffer) FlushFileLog() {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	if lb.fileBuf != nil {
		_ = lb.fileBuf.Flush()
		lb.lastFlush = time.Now()
	}
}

func (lb *LogBuffer) WriteSidecar(name string, data []byte) {
	lb.mu.RLock()
	dir := lb.dir
	lb.mu.RUnlock()
	if dir == "" {
		return
	}
	_ = os.WriteFile(filepath.Join(dir, name), data, 0o600)
}

var (
	ansiRegex   = regexp.MustCompile(`\x1b\[[0-9;]*m`)
	sourceRegex = regexp.MustCompile(`(?i)^(\w+)[:/]`)

	xrayPrefixRegex = regexp.MustCompile(`^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(\.\d+)? ?(\[[A-Za-z]+\])? ?`)
)

var logLevelRank = map[types.LogLevel]int{
	types.LogLevelTrace: 0,
	types.LogLevelDebug: 1,
	types.LogLevelInfo:  2,
	types.LogLevelWarn:  3,
	types.LogLevelError: 4,
	types.LogLevelFatal: 5,
}

func stripANSI(s string) string {
	if !strings.ContainsRune(s, 0x1b) {
		return s
	}
	return ansiRegex.ReplaceAllString(s, "")
}

func sanitizeCoreMessage(message string) string {
	clean := strings.TrimSpace(stripANSI(message))
	if match := xrayPrefixRegex.FindString(clean); match != "" {
		clean = strings.TrimSpace(clean[len(match):])
	}
	return clean
}

func coreLevelOf(message string) types.LogLevel {
	lower := strings.ToLower(message)
	switch {
	case strings.Contains(lower, "[error]"):
		return types.LogLevelError
	case strings.Contains(lower, "[warning]"), strings.Contains(lower, "[warn]"):
		return types.LogLevelWarn
	case strings.Contains(lower, "[debug]"):
		return types.LogLevelDebug
	default:
		return types.LogLevelInfo
	}
}

func parseSource(msg string) string {
	clean := stripANSI(msg)
	matches := sourceRegex.FindStringSubmatch(clean)
	if matches != nil && len(matches) > 1 {
		return strings.ToLower(matches[1])
	}
	return ""
}

func isLevelMatch(entryLevel, filterLevel types.LogLevel) bool {
	return logLevelRank[entryLevel] >= logLevelRank[filterLevel]
}
