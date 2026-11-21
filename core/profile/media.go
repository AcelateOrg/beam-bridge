package profile

import (
	"context"
	"log"
	"time"

	"beam-bridge/core/infrastructure/mediacache"
	"beam-bridge/core/types"
)

// Provider images are fetched when a profile is imported or refreshed and
// served from disk afterwards (see mediacache).

const mediaFetchTimeout = 15 * time.Second

func profileImages(p *types.Profile) []string {
	if p == nil {
		return nil
	}
	urls := []string{p.IconURL}
	if p.Branding != nil {
		urls = append(urls, p.Branding.IconURL, p.Branding.BannerImage)
	}
	out := urls[:0]
	seen := make(map[string]bool, len(urls))
	for _, u := range urls {
		if mediacache.Cacheable(u) && !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
	}
	return out
}

// syncProfileMedia downloads the images of one profile. force re-downloads
// files already on disk (subscription refresh: the art may have changed
// under the same URL).
func (m *Manager) syncProfileMedia(id string, force bool) {
	p, err := m.storage.GetByID(id)
	if err != nil {
		return
	}
	for _, u := range profileImages(p) {
		if !force && m.media.Has(u) {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), mediaFetchTimeout)
		if err := m.media.Fetch(ctx, u); err != nil {
			log.Printf("profile media: %s: %v", u, err)
		}
		cancel()
	}
	m.pruneMedia()
}

// syncAllMedia fills the cache for profiles imported before it existed.
func (m *Manager) syncAllMedia() {
	profiles, _ := m.storage.GetAll()
	for _, p := range profiles {
		m.syncProfileMedia(p.ID, false)
	}
	m.pruneMedia()
}

func (m *Manager) pruneMedia() {
	profiles, err := m.storage.GetAll()
	if err != nil {
		return
	}
	var used []string
	for _, p := range profiles {
		used = append(used, profileImages(p)...)
	}
	m.media.Prune(used)
}

// MediaFile resolves a /beam-media/<name> request to the cached file.
func (m *Manager) MediaFile(name string) (string, bool) {
	return m.media.Open(name)
}

// localSummaryMedia points the summary at the cached copies. Branding is
// shared with the stored profile, so it is copied first.
func (m *Manager) localSummaryMedia(s *types.ProfileSummary) {
	s.IconURL = m.media.LocalURL(s.IconURL)
	if s.Branding != nil {
		b := *s.Branding
		b.IconURL = m.media.LocalURL(b.IconURL)
		b.BannerImage = m.media.LocalURL(b.BannerImage)
		s.Branding = &b
	}
}
