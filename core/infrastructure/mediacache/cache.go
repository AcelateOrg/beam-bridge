// Package mediacache keeps provider images (profile icon, banner) on disk.
//
// They are downloaded when a profile is imported or its subscription is
// refreshed, and the UI loads the local copy. Without it every screen that
// shows the profile pulled the images from the internet again.
package mediacache

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// Prefix is the asset-server path the UI loads cached files from.
const Prefix = "/beam-media/"

// MaxSize bounds one image.
const MaxSize = 4 << 20

var (
	exts        = []string{".png", ".jpg", ".gif", ".webp", ".svg", ".avif"}
	namePattern = regexp.MustCompile(`^[0-9a-f]{32}\.(png|jpg|gif|webp|svg|avif)$`)

	errNotRemote = errors.New("not an https image")
	errTooLarge  = errors.New("image is too large")
	errNotImage  = errors.New("not an image")
)

type Cache struct {
	dir    string
	client *http.Client
	mu     sync.Mutex
}

func New(dir string, client *http.Client) *Cache {
	if client == nil {
		client = http.DefaultClient
	}
	return &Cache{dir: dir, client: client}
}

// Cacheable reports whether u is a remote image the cache handles.
func Cacheable(u string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(u)), "https://")
}

func key(u string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(u)))
	return hex.EncodeToString(sum[:16])
}

func (c *Cache) find(k string) (string, os.FileInfo) {
	for _, ext := range exts {
		path := filepath.Join(c.dir, k+ext)
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
			return path, info
		}
	}
	return "", nil
}

// Has reports whether u is already on disk.
func (c *Cache) Has(u string) bool {
	path, _ := c.find(key(u))
	return path != ""
}

// LocalURL returns the asset-server URL of the cached copy of u, or u itself
// when it is not cached (yet).
func (c *Cache) LocalURL(u string) string {
	if c == nil || !Cacheable(u) {
		return u
	}
	path, info := c.find(key(u))
	if path == "" {
		return u
	}
	// ?v= changes when the file does, so the webview drops its own copy.
	return Prefix + filepath.Base(path) + "?v=" + strconv.FormatInt(info.ModTime().UnixNano(), 36)
}

// Open resolves a file name from the asset-server URL to its path.
func (c *Cache) Open(name string) (string, bool) {
	if c == nil || !namePattern.MatchString(name) {
		return "", false
	}
	path := filepath.Join(c.dir, name)
	if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() {
		return "", false
	}
	return path, true
}

// Fetch downloads u and replaces the cached copy. On any error the old copy
// stays, so a provider CDN hiccup does not blank the banner.
func (c *Cache) Fetch(ctx context.Context, u string) error {
	if !Cacheable(u) {
		return errNotRemote
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSpace(u), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "image/*")
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxSize+1))
	if err != nil {
		return err
	}
	if len(data) > MaxSize {
		return errTooLarge
	}
	ext := imageExt(resp.Header.Get("Content-Type"), data)
	if ext == "" {
		return errNotImage
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	k := key(u)
	final := filepath.Join(c.dir, k+ext)
	if old, err := os.ReadFile(final); err == nil && bytes.Equal(old, data) {
		return nil
	}
	if err := os.MkdirAll(c.dir, 0o755); err != nil {
		return err
	}
	tmp := final + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, final); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	for _, other := range exts {
		if other != ext {
			_ = os.Remove(filepath.Join(c.dir, k+other))
		}
	}
	return nil
}

// Prune removes cached files of images no profile uses any more.
func (c *Cache) Prune(used []string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	keep := make(map[string]bool, len(used))
	for _, u := range used {
		if Cacheable(u) {
			keep[key(u)] = true
		}
	}
	entries, err := os.ReadDir(c.dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		k, _, _ := strings.Cut(name, ".")
		if !keep[k] {
			_ = os.Remove(filepath.Join(c.dir, name))
		}
	}
}

func imageExt(contentType string, data []byte) string {
	switch http.DetectContentType(data) {
	case "image/png":
		return ".png"
	case "image/jpeg":
		return ".jpg"
	case "image/gif":
		return ".gif"
	case "image/webp":
		return ".webp"
	}
	mediaType, _, _ := mime.ParseMediaType(contentType)
	switch mediaType {
	case "image/svg+xml":
		return ".svg"
	case "image/avif":
		return ".avif"
	}
	// SVG served as text/plain or application/octet-stream by a bare CDN.
	head := bytes.ToLower(data[:min(len(data), 1024)])
	if bytes.Contains(head, []byte("<svg")) {
		return ".svg"
	}
	return ""
}
