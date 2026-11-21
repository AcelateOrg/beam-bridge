package analytics

import (
	"sort"
	"strconv"
	"time"
)

// Periods of a report.
const (
	PeriodToday = "today"
	PeriodWeek  = "week"
	PeriodMonth = "month"
	PeriodAll   = "all"
)

const maxReportItems = 50

// Report is the statistics of one period, ready for the UI.
type Report struct {
	Period string `json:"period"`
	// Hourly is true when Series holds the 24 hours of today, otherwise one
	// bucket per day (Key = YYYY-MM-DD).
	Hourly   bool         `json:"hourly"`
	Totals   ReportTotals `json:"totals"`
	Series   []Bucket     `json:"series"`
	Profiles []Item       `json:"profiles"`
	Nodes    []Item       `json:"nodes"`
	Apps     []Item       `json:"apps"`
	Routes   Routes       `json:"routes"`
	// Since is the first day with any data at all (YYYY-MM-DD), "" when
	// the statistics are empty.
	Since string `json:"since"`
}

type ReportTotals struct {
	Up       int64 `json:"up"`
	Down     int64 `json:"down"`
	Seconds  int64 `json:"seconds"`
	Sessions int64 `json:"sessions"`
	// ActiveDays is the number of days with a connection in the period.
	ActiveDays int `json:"activeDays"`
}

type Bucket struct {
	Key  string `json:"key"`
	Up   int64  `json:"up"`
	Down int64  `json:"down"`
}

type Item struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Sub     string `json:"sub"`
	// Path is the executable of an app (for its icon), "" otherwise.
	Path    string `json:"path"`
	Up      int64  `json:"up"`
	Down    int64  `json:"down"`
	Seconds int64  `json:"seconds"`
}

type Routes struct {
	Proxy   int64 `json:"proxy"`
	Direct  int64 `json:"direct"`
	Blocked int64 `json:"blocked"`
}

// Query builds the report of a period.
func (s *Store) Query(period string) Report {
	s.mu.Lock()
	defer s.mu.Unlock()

	today := startOfDay(s.now())
	var first time.Time
	switch period {
	case PeriodToday:
		first = today
	case PeriodWeek:
		first = today.AddDate(0, 0, -6)
	case PeriodMonth:
		first = today.AddDate(0, 0, -29)
	default:
		period = PeriodAll
		first = today.AddDate(0, 0, -6)
		for key := range s.days {
			if t, err := time.ParseInLocation(dateLayout, key, time.Local); err == nil && t.Before(first) {
				first = t
			}
		}
	}

	report := Report{Period: period, Hourly: period == PeriodToday}
	for key := range s.days {
		if report.Since == "" || key < report.Since {
			report.Since = key
		}
	}
	profiles := map[string]*Item{}
	nodes := map[string]*Item{}
	apps := map[string]*Item{}

	if report.Hourly {
		report.Series = make([]Bucket, 24)
		for h := range report.Series {
			report.Series[h].Key = strconv.Itoa(h)
		}
	}

	for t := first; !t.After(today); t = t.AddDate(0, 0, 1) {
		key := t.Format(dateLayout)
		d := s.days[key]
		if !report.Hourly {
			bucket := Bucket{Key: key}
			if d != nil {
				bucket.Up, bucket.Down = d.Total.Up, d.Total.Down
			}
			report.Series = append(report.Series, bucket)
		}
		if d == nil {
			continue
		}
		if report.Hourly {
			for h, usage := range d.Hours {
				report.Series[h].Up += usage.Up
				report.Series[h].Down += usage.Down
			}
		}

		report.Totals.Up += d.Total.Up
		report.Totals.Down += d.Total.Down
		report.Totals.Seconds += d.Total.Ms / 1000
		report.Totals.Sessions += d.Sessions
		if d.Total.Ms > 0 || d.Sessions > 0 {
			report.Totals.ActiveDays++
		}
		report.Routes.Proxy += d.Routes.Proxy
		report.Routes.Direct += d.Routes.Direct
		report.Routes.Blocked += d.Routes.Blocked

		merge(profiles, d.Profiles)
		merge(nodes, d.Nodes)
		merge(apps, d.Apps)
	}

	report.Profiles = sorted(profiles)
	report.Nodes = sorted(nodes)
	report.Apps = sorted(apps)
	return report
}

func merge(into map[string]*Item, from map[string]*namedUsage) {
	for key, entry := range from {
		item := into[key]
		if item == nil {
			item = &Item{ID: key}
			into[key] = item
		}
		// Days are walked oldest first, so the newest name wins.
		if entry.Name != "" {
			item.Name = entry.Name
		}
		if entry.Sub != "" {
			item.Sub = entry.Sub
		}
		if entry.Path != "" {
			item.Path = entry.Path
		}
		item.Up += entry.Up
		item.Down += entry.Down
		item.Seconds += entry.Ms / 1000
	}
}

func sorted(items map[string]*Item) []Item {
	result := make([]Item, 0, len(items))
	for _, item := range items {
		if item.Up+item.Down == 0 && item.Seconds == 0 {
			continue
		}
		result = append(result, *item)
	}
	sort.Slice(result, func(i, j int) bool {
		a, b := result[i].Up+result[i].Down, result[j].Up+result[j].Down
		if a != b {
			return a > b
		}
		if result[i].Seconds != result[j].Seconds {
			return result[i].Seconds > result[j].Seconds
		}
		return result[i].Name < result[j].Name
	})
	if len(result) > maxReportItems {
		result = result[:maxReportItems]
	}
	return result
}
