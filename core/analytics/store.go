// Package analytics keeps the local usage statistics of the VPN: traffic and
// connection time per day, hour, profile, config and application. Nothing
// leaves the device; the data lives in one JSON file next to the settings.
package analytics

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	fileName      = "analytics.json"
	fileVersion   = 1
	retentionDays = 90
	saveInterval  = time.Minute
	dateLayout    = "2006-01-02"
)

// Route classes, as reported by the tunnel accounting.
const (
	RouteProxy  = "proxy"
	RouteDirect = "direct"
	RouteBlock  = "block"
)

// ProxyAppKey collects traffic that cannot be attributed to apps (system
// proxy mode: there is no tunnel that sees processes).
const ProxyAppKey = "@proxy"

// Source is what the traffic of a sample belongs to.
type Source struct {
	ProfileID   string
	ProfileName string
	NodeName    string
}

// AppTraffic is per-app traffic of a sample.
type AppTraffic struct {
	Name string
	// Path is the full executable path (for the app icon).
	Path    string
	Route   string
	Up      int64
	Down    int64
	Blocked int64
}

// Sample is one accounting step of a live session.
type Sample struct {
	At       time.Time
	Source   Source
	Up       int64
	Down     int64
	Duration time.Duration
	Apps     []AppTraffic
}

type usage struct {
	Up   int64 `json:"up,omitempty"`
	Down int64 `json:"down,omitempty"`
	Ms   int64 `json:"ms,omitempty"`
}

type namedUsage struct {
	Name string `json:"name"`
	Sub  string `json:"sub,omitempty"`
	Path string `json:"path,omitempty"`
	usage
}

type hourUsage struct {
	Up   int64 `json:"up,omitempty"`
	Down int64 `json:"down,omitempty"`
}

type routeUsage struct {
	Proxy   int64 `json:"proxy,omitempty"`
	Direct  int64 `json:"direct,omitempty"`
	Blocked int64 `json:"blocked,omitempty"`
}

type day struct {
	Date     string                 `json:"date"`
	Total    usage                  `json:"total"`
	Sessions int64                  `json:"sessions,omitempty"`
	Hours    [24]hourUsage          `json:"hours"`
	Profiles map[string]*namedUsage `json:"profiles,omitempty"`
	Nodes    map[string]*namedUsage `json:"nodes,omitempty"`
	Apps     map[string]*namedUsage `json:"apps,omitempty"`
	Routes   routeUsage             `json:"routes"`
}

type fileData struct {
	Version int    `json:"version"`
	Days    []*day `json:"days"`
}

// Store is the statistics database. Safe for concurrent use.
type Store struct {
	mu      sync.Mutex
	path    string
	days    map[string]*day
	dirty   bool
	savedAt time.Time
	now     func() time.Time
}

// Open loads the statistics from dir. A missing or damaged file starts an
// empty database instead of failing.
func Open(dir string) *Store {
	s := &Store{
		path: filepath.Join(dir, fileName),
		days: make(map[string]*day),
		now:  time.Now,
	}
	s.load()
	return s
}

func (s *Store) load() {
	raw, err := os.ReadFile(s.path)
	if err != nil {
		return
	}
	var data fileData
	if err := json.Unmarshal(raw, &data); err != nil {
		return
	}
	for _, d := range data.Days {
		if d == nil {
			continue
		}
		if _, err := time.ParseInLocation(dateLayout, d.Date, time.Local); err != nil {
			continue
		}
		s.days[d.Date] = d
	}
	s.pruneLocked()
}

func (s *Store) dayLocked(at time.Time) *day {
	key := at.Format(dateLayout)
	d := s.days[key]
	if d == nil {
		d = &day{Date: key}
		s.days[key] = d
	}
	return d
}

func named(m *map[string]*namedUsage, key, name, sub string) *namedUsage {
	if *m == nil {
		*m = make(map[string]*namedUsage)
	}
	entry := (*m)[key]
	if entry == nil {
		entry = &namedUsage{}
		(*m)[key] = entry
	}
	// The latest name wins: profiles and configs can be renamed.
	if name != "" {
		entry.Name = name
	}
	if sub != "" {
		entry.Sub = sub
	}
	return entry
}

// AddSession counts a new connection.
func (s *Store) AddSession(at time.Time) {
	s.mu.Lock()
	s.dayLocked(at).Sessions++
	s.dirty = true
	s.mu.Unlock()
}

// Record adds one accounting step and saves the database now and then.
func (s *Store) Record(sample Sample) {
	if sample.Up < 0 {
		sample.Up = 0
	}
	if sample.Down < 0 {
		sample.Down = 0
	}
	ms := sample.Duration.Milliseconds()
	if ms < 0 {
		ms = 0
	}
	if sample.Up == 0 && sample.Down == 0 && ms == 0 && len(sample.Apps) == 0 {
		return
	}

	s.mu.Lock()
	d := s.dayLocked(sample.At)
	d.Total.Up += sample.Up
	d.Total.Down += sample.Down
	d.Total.Ms += ms
	hour := sample.At.Hour()
	d.Hours[hour].Up += sample.Up
	d.Hours[hour].Down += sample.Down

	src := sample.Source
	if src.ProfileID != "" {
		p := named(&d.Profiles, src.ProfileID, src.ProfileName, "")
		p.Up += sample.Up
		p.Down += sample.Down
		p.Ms += ms
		if src.NodeName != "" {
			n := named(&d.Nodes, src.ProfileID+"\x00"+src.NodeName, src.NodeName, src.ProfileName)
			n.Up += sample.Up
			n.Down += sample.Down
			n.Ms += ms
		}
	}

	for _, app := range sample.Apps {
		switch app.Route {
		case RouteDirect:
			d.Routes.Direct += app.Up + app.Down
		case RouteBlock:
			d.Routes.Blocked += app.Blocked
		default:
			d.Routes.Proxy += app.Up + app.Down
		}
		if app.Up == 0 && app.Down == 0 {
			continue
		}
		key := strings.ToLower(app.Name)
		a := named(&d.Apps, key, app.Name, "")
		if app.Path != "" {
			a.Path = app.Path
		}
		a.Up += app.Up
		a.Down += app.Down
	}

	s.dirty = true
	due := s.now().Sub(s.savedAt) >= saveInterval
	s.mu.Unlock()

	if due {
		_ = s.Flush()
	}
}

// Flush writes pending changes to disk.
func (s *Store) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.dirty {
		return nil
	}
	s.pruneLocked()
	if err := s.writeLocked(); err != nil {
		return err
	}
	s.dirty = false
	s.savedAt = s.now()
	return nil
}

// Reset deletes all statistics.
func (s *Store) Reset() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.days = make(map[string]*day)
	s.dirty = false
	s.savedAt = s.now()
	if err := os.Remove(s.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (s *Store) pruneLocked() {
	cutoff := startOfDay(s.now()).AddDate(0, 0, -(retentionDays - 1)).Format(dateLayout)
	for key := range s.days {
		if key < cutoff {
			delete(s.days, key)
		}
	}
}

func (s *Store) writeLocked() error {
	data := fileData{Version: fileVersion, Days: make([]*day, 0, len(s.days))}
	for _, d := range s.days {
		data.Days = append(data.Days, d)
	}
	sort.Slice(data.Days, func(i, j int) bool { return data.Days[i].Date < data.Days[j].Date })

	raw, err := json.Marshal(data)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func startOfDay(t time.Time) time.Time {
	y, m, d := t.Date()
	return time.Date(y, m, d, 0, 0, 0, 0, t.Location())
}
