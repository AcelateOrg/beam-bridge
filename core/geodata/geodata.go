// Package geodata keeps the geoip.dat / geosite.dat databases the core reads
// for geoip: and geosite: routing rules. They are not shipped with the app:
// the first rule that needs them downloads them, later runs refresh them in
// the background.
package geodata

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	FileIP   = "geoip.dat"
	FileSite = "geosite.dat"

	// assetEnv is where the core looks for its data files.
	assetEnv = "xray.location.asset"

	maxAge  = 7 * 24 * time.Hour
	maxSize = 256 << 20

	downloadTimeout = 90 * time.Second
)

// sources lists the mirrors of each file, tried in order. The Russian rules
// build carries every country plus lists such as ru-blocked.
var sources = map[string][]string{
	FileIP: {
		"https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geoip.dat",
		"https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/geoip.dat",
	},
	FileSite: {
		"https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geosite.dat",
		"https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/geosite.dat",
	},
}

type codeIndex struct {
	modTime time.Time
	size    int64
	codes   map[string]bool
}

type Store struct {
	dir    string
	client *http.Client

	// download serialises fetches, so concurrent callers wait for one
	// download instead of starting their own.
	download sync.Mutex

	mu         sync.Mutex
	index      map[string]codeIndex
	attrs      *attrIndex
	refreshing map[string]bool
}

// attrIndex — атрибуты категорий geosite.dat (google@cn, category-ads-all@ads).
type attrIndex struct {
	modTime time.Time
	size    int64
	attrs   map[string][]string
}

// New points the core at dir for its data files.
func New(dir string) *Store {
	_ = os.Setenv(assetEnv, dir)
	return &Store{
		dir:        dir,
		client:     &http.Client{Timeout: downloadTimeout},
		index:      map[string]codeIndex{},
		refreshing: map[string]bool{},
	}
}

func (s *Store) path(file string) string {
	return filepath.Join(s.dir, file)
}

// Codes returns the lower-case codes present in file, downloading the file
// first when it is missing.
func (s *Store) Codes(ctx context.Context, file string) ([]string, error) {
	known, err := s.Known(ctx, file)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(known))
	for code := range known {
		out = append(out, code)
	}
	sort.Strings(out)
	return out, nil
}

// Present reports whether file is already on disk.
func (s *Store) Present(file string) bool {
	_, err := os.Stat(s.path(file))
	return err == nil
}

// Known returns the set of codes in file. A missing file is downloaded
// (blocking); a stale one is used as is and refreshed in the background.
func (s *Store) Known(ctx context.Context, file string) (map[string]bool, error) {
	if _, ok := sources[file]; !ok {
		return nil, fmt.Errorf("unknown geodata file %q", file)
	}
	info, err := os.Stat(s.path(file))
	if err != nil {
		if err := s.fetch(ctx, file); err != nil {
			return nil, err
		}
		if info, err = os.Stat(s.path(file)); err != nil {
			return nil, err
		}
	} else if time.Since(info.ModTime()) > maxAge {
		s.refreshInBackground(file)
	}
	return s.codes(file, info)
}

func (s *Store) codes(file string, info os.FileInfo) (map[string]bool, error) {
	s.mu.Lock()
	cached, ok := s.index[file]
	s.mu.Unlock()
	if ok && cached.modTime.Equal(info.ModTime()) && cached.size == info.Size() {
		return cached.codes, nil
	}

	data, err := os.ReadFile(s.path(file))
	if err != nil {
		return nil, err
	}
	codes, err := parseCodes(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	s.mu.Lock()
	s.index[file] = codeIndex{modTime: info.ModTime(), size: info.Size(), codes: codes}
	s.mu.Unlock()
	return codes, nil
}

func (s *Store) refreshInBackground(file string) {
	s.mu.Lock()
	if s.refreshing[file] {
		s.mu.Unlock()
		return
	}
	s.refreshing[file] = true
	s.mu.Unlock()

	go func() {
		defer func() {
			s.mu.Lock()
			s.refreshing[file] = false
			s.mu.Unlock()
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 2*downloadTimeout)
		defer cancel()
		if err := s.fetch(ctx, file); err != nil {
			log.Printf("geodata: refresh %s: %v", file, err)
		}
	}()
}

// fetch downloads file from the first mirror that returns a valid database
// and swaps it in atomically, so the core never reads a partial file.
func (s *Store) fetch(ctx context.Context, file string) error {
	s.download.Lock()
	defer s.download.Unlock()

	// Another caller may have fetched it while this one waited.
	if info, err := os.Stat(s.path(file)); err == nil && time.Since(info.ModTime()) <= maxAge {
		return nil
	}
	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		return err
	}

	var errs []error
	for _, url := range sources[file] {
		if err := s.fetchFrom(ctx, url, file); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", url, err))
			continue
		}
		return nil
	}
	return fmt.Errorf("download %s: %w", file, errors.Join(errs...))
}

func (s *Store) fetchFrom(ctx context.Context, url, file string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %s", resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxSize+1))
	if err != nil {
		return err
	}
	if len(data) > maxSize {
		return errors.New("file too large")
	}
	// A database that does not parse (an HTML error page, a cut-off
	// transfer) must not replace a working one.
	if _, err := parseCodes(data); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(s.dir, file+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, s.path(file))
}

// SiteAttributes returns the attributes used by the domains of a geosite
// category ("cn", "ads", ...), for rules such as geosite:google@cn.
func (s *Store) SiteAttributes(ctx context.Context, code string) ([]string, error) {
	index, err := s.siteAttrs(ctx)
	if err != nil {
		return nil, err
	}
	attrs := index[strings.ToLower(strings.TrimSpace(code))]
	out := make([]string, len(attrs))
	copy(out, attrs)
	return out, nil
}

// KnownSiteAttribute reports whether code@attr selects at least one domain.
func (s *Store) KnownSiteAttribute(ctx context.Context, code, attr string) (bool, error) {
	index, err := s.siteAttrs(ctx)
	if err != nil {
		return false, err
	}
	attr = strings.ToLower(strings.TrimSpace(attr))
	for _, a := range index[strings.ToLower(strings.TrimSpace(code))] {
		if a == attr {
			return true, nil
		}
	}
	return false, nil
}

func (s *Store) siteAttrs(ctx context.Context) (map[string][]string, error) {
	if _, err := s.Known(ctx, FileSite); err != nil {
		return nil, err
	}
	info, err := os.Stat(s.path(FileSite))
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	cached := s.attrs
	s.mu.Unlock()
	if cached != nil && cached.modTime.Equal(info.ModTime()) && cached.size == info.Size() {
		return cached.attrs, nil
	}
	data, err := os.ReadFile(s.path(FileSite))
	if err != nil {
		return nil, err
	}
	attrs, err := parseSiteAttributes(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", FileSite, err)
	}
	s.mu.Lock()
	s.attrs = &attrIndex{modTime: info.ModTime(), size: info.Size(), attrs: attrs}
	s.mu.Unlock()
	return attrs, nil
}

// parseSiteAttributes walks GeoSiteList -> GeoSite{code=1, domain=2} ->
// Domain{attribute=3} -> Attribute{key=1} and collects the keys per code.
func parseSiteAttributes(data []byte) (map[string][]string, error) {
	out := map[string][]string{}
	err := walkFields(data, func(field uint64, entry []byte) bool {
		if field != 1 {
			return true
		}
		var code string
		set := map[string]bool{}
		ok := walkFields(entry, func(f uint64, value []byte) bool {
			switch f {
			case 1:
				code = strings.ToLower(string(value))
			case 2:
				return walkFields(value, func(df uint64, attr []byte) bool {
					if df != 3 {
						return true
					}
					return walkFields(attr, func(af uint64, key []byte) bool {
						if af == 1 && len(key) > 0 {
							set[strings.ToLower(string(key))] = true
						}
						return true
					}) == nil
				}) == nil
			}
			return true
		}) == nil
		if !ok {
			return false
		}
		if code != "" && len(set) > 0 {
			attrs := make([]string, 0, len(set))
			for a := range set {
				attrs = append(attrs, a)
			}
			sort.Strings(attrs)
			out[code] = attrs
		}
		return true
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// walkFields calls fn for every length-delimited field of a protobuf
// message, skipping varint and fixed-size ones. fn returning false aborts
// with a corruption error.
func walkFields(msg []byte, fn func(field uint64, value []byte) bool) error {
	for pos := 0; pos < len(msg); {
		tag, n := uvarint(msg[pos:])
		if n <= 0 {
			return errors.New("corrupt database")
		}
		pos += n
		switch tag & 7 {
		case 0:
			_, n = uvarint(msg[pos:])
			if n <= 0 {
				return errors.New("corrupt database")
			}
			pos += n
		case 1:
			pos += 8
		case 5:
			pos += 4
		case 2:
			size, n := uvarint(msg[pos:])
			if n <= 0 || size > uint64(len(msg)-pos-n) {
				return errors.New("corrupt database")
			}
			pos += n
			if !fn(tag>>3, msg[pos:pos+int(size)]) {
				return errors.New("corrupt database")
			}
			pos += int(size)
		default:
			return errors.New("corrupt database")
		}
		if pos > len(msg) {
			return errors.New("corrupt database")
		}
	}
	return nil
}

// parseCodes reads the country_code of every entry of a GeoIPList or
// GeoSiteList. Both are `repeated Entry entry = 1` with the code as field 1
// of the entry, so the protobuf wire format is walked directly instead of
// decoding the (large) rule lists.
func parseCodes(data []byte) (map[string]bool, error) {
	codes := map[string]bool{}
	for pos := 0; pos < len(data); {
		tag, n := uvarint(data[pos:])
		if n <= 0 {
			return nil, errors.New("corrupt database")
		}
		pos += n
		if tag != 1<<3|2 {
			return nil, errors.New("corrupt database")
		}
		size, n := uvarint(data[pos:])
		if n <= 0 || size > uint64(len(data)-pos-n) {
			return nil, errors.New("corrupt database")
		}
		pos += n
		if code := entryCode(data[pos : pos+int(size)]); code != "" {
			codes[strings.ToLower(code)] = true
		}
		pos += int(size)
	}
	if len(codes) == 0 {
		return nil, errors.New("empty database")
	}
	return codes, nil
}

// entryCode finds field 1 (a string) among the entry's fields.
func entryCode(entry []byte) string {
	for pos := 0; pos < len(entry); {
		tag, n := uvarint(entry[pos:])
		if n <= 0 {
			return ""
		}
		pos += n
		switch tag & 7 {
		case 0: // varint
			_, n = uvarint(entry[pos:])
			if n <= 0 {
				return ""
			}
			pos += n
		case 2: // length-delimited
			size, n := uvarint(entry[pos:])
			if n <= 0 || size > uint64(len(entry)-pos-n) {
				return ""
			}
			pos += n
			if tag>>3 == 1 {
				return string(entry[pos : pos+int(size)])
			}
			pos += int(size)
		default:
			return ""
		}
	}
	return ""
}

func uvarint(b []byte) (uint64, int) {
	var x uint64
	for i := 0; i < len(b) && i < 10; i++ {
		x |= uint64(b[i]&0x7f) << (7 * i)
		if b[i] < 0x80 {
			return x, i + 1
		}
	}
	return 0, 0
}
