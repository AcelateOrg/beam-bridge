package profile

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	infraBeam "beam-bridge/core/infrastructure/beam"
	corePaths "beam-bridge/core/paths"
	"beam-bridge/core/types"
)

const (
	readBeamFileRetries = 3
	readBeamFileBackoff = 40 * time.Millisecond
)

func readBeamFileWithRetry(path string) (*infraBeam.BeamFile, error) {
	var lastErr error
	for attempt := 1; attempt <= readBeamFileRetries; attempt++ {
		beamFile, err := infraBeam.ReadFromFile(path)
		if err == nil {
			return beamFile, nil
		}
		lastErr = err
		if attempt < readBeamFileRetries {
			time.Sleep(readBeamFileBackoff)
		}
	}
	return nil, lastErr
}

var (
	ErrProfileNotFound = errProfileNotFound("profile not found")
	ErrNodeNotFound    = errNodeNotFound("node not found")
)

type errProfileNotFound string

func (e errProfileNotFound) Error() string { return string(e) }

type errNodeNotFound string

func (e errNodeNotFound) Error() string { return string(e) }

type FileRepository struct {
	mu       sync.RWMutex
	paths    corePaths.Paths
	profiles map[string]*types.Profile
	beams    map[string]*infraBeam.BeamFile
	activeID string
}

func NewFileRepository(paths corePaths.Paths) *FileRepository {
	return &FileRepository{
		paths:    paths,
		profiles: make(map[string]*types.Profile),
		beams:    make(map[string]*infraBeam.BeamFile),
	}
}

func (r *FileRepository) Load() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	dir := r.paths.Profiles
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	// An id present as both .bpx and legacy .beam means a half-finished
	// migration; the encrypted .bpx wins and the stray .beam is removed.
	seen := make(map[string]bool)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, corePaths.ProfileExt) {
			continue
		}
		id := strings.TrimSuffix(name, corePaths.ProfileExt)
		path := filepath.Join(dir, name)
		beamFile, err := readBeamFileWithRetry(path)
		if err != nil {
			log.Printf("profile: failed to read %s after %d attempts: %v", path, readBeamFileRetries, err)
			continue
		}
		applyModTime(beamFile, entry)
		r.profiles[id] = beamToProfile(id, beamFile)
		r.beams[id] = beamFile
		seen[id] = true
		// A .bpx written while the keystore was unavailable is plaintext;
		// seal it now that the key is back.
		if infraBeam.KeystoreReady() && !infraBeam.IsEncryptedFile(path) {
			if err := infraBeam.WriteToFile(path, beamFile); err != nil {
				log.Printf("profile: failed to encrypt %s: %v", path, err)
			}
		}
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, corePaths.LegacyProfileExt) {
			continue
		}
		id := strings.TrimSuffix(name, corePaths.LegacyProfileExt)
		legacyPath := filepath.Join(dir, name)
		if seen[id] {
			_ = os.Remove(legacyPath)
			continue
		}
		beamFile, err := readBeamFileWithRetry(legacyPath)
		if err != nil {
			log.Printf("profile: failed to read %s after %d attempts: %v", legacyPath, readBeamFileRetries, err)
			continue
		}
		applyModTime(beamFile, entry)
		r.profiles[id] = beamToProfile(id, beamFile)
		r.beams[id] = beamFile
		seen[id] = true
		// Re-encrypt into the new container, then drop the plaintext file.
		// If writing fails the legacy file stays and we retry next start.
		if err := infraBeam.WriteToFile(r.paths.Profile(id), beamFile); err != nil {
			log.Printf("profile: failed to migrate %s: %v", legacyPath, err)
			continue
		}
		_ = os.Remove(legacyPath)
	}

	r.loadState()
	return nil
}

func applyModTime(beamFile *infraBeam.BeamFile, entry os.DirEntry) {
	info, err := entry.Info()
	if err != nil {
		return
	}
	modTime := info.ModTime().Unix()
	if beamFile.Data.CreatedAt == 0 {
		beamFile.Data.CreatedAt = modTime
	}
	if beamFile.Data.UpdatedAt == 0 {
		beamFile.Data.UpdatedAt = modTime
	}
}

func beamToProfile(id string, beamFile *infraBeam.BeamFile) *types.Profile {
	var expiresAt time.Time
	if beamFile.Data.ExpiresAt > 0 {
		expiresAt = time.Unix(beamFile.Data.ExpiresAt, 0)
	}

	createdAt := time.Now()
	if beamFile.Data.CreatedAt > 0 {
		createdAt = time.Unix(beamFile.Data.CreatedAt, 0)
	}

	updatedAt := time.Now()
	if beamFile.Data.UpdatedAt > 0 {
		updatedAt = time.Unix(beamFile.Data.UpdatedAt, 0)
	}

	profile := &types.Profile{
		ID:                  id,
		Name:                beamFile.Data.Name,
		Provider:            beamFile.Data.Provider,
		URL:                 beamFile.Data.URL,
		Announce:            beamFile.Data.Announce,
		SupportURL:          beamFile.Data.SupportURL,
		IconURL:             beamFile.Data.IconURL,
		CommunityURL:        beamFile.Data.CommunityURL,
		Branding:            beamFile.Data.EffectiveBranding(),
		ProTunLocked:        beamFile.Data.ProTunLocked && beamFile.Data.ProTunPreset != nil,
		HasProTunPreset:     beamFile.Data.ProTunPreset != nil,
		HideProvider:        beamFile.Data.HideProvider,
		ProviderSettings:    beamFile.Data.ProviderSettings,
		DataLimit:           beamFile.Data.DataLimit,
		DataUsed:            beamFile.Data.DataUsed,
		ExpiresAt:           expiresAt,
		CreatedAt:           createdAt,
		UpdatedAt:           updatedAt,
		UpdateIntervalHours: beamFile.Data.UpdateIntervalHours,
		AutoRefreshDisabled: beamFile.Data.AutoRefreshDisabled,

		UpdateIntervalOverrideHours: beamFile.Data.UpdateIntervalOverrideHours,
	}
	// Плоские legacy-поля зеркалируют branding, чтобы старые участки UI
	// (списки профилей) работали и с файлами, где заполнен только блок
	// branding.
	if profile.Branding != nil {
		if profile.IconURL == "" {
			profile.IconURL = profile.Branding.IconURL
		}
		if profile.Announce == "" {
			profile.Announce = profile.Branding.BannerText
		}
		if profile.SupportURL == "" {
			profile.SupportURL = profile.Branding.SupportURL
		}
		if profile.CommunityURL == "" {
			profile.CommunityURL = profile.Branding.CommunityURL
		}
	}
	// Branding is provider data shown as images and links: only safe values
	// reach the UI, whatever the file or the subscription carried.
	profile.Branding.Sanitize()
	profile.IconURL = types.SafeImageURL(profile.IconURL)
	profile.SupportURL = types.SafeLinkURL(profile.SupportURL)
	profile.CommunityURL = types.SafeLinkURL(profile.CommunityURL)
	return profile
}

func (r *FileRepository) GetAll() ([]*types.Profile, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]*types.Profile, 0, len(r.profiles))
	for _, p := range r.profiles {
		profile := *p
		profile.IsActive = p.ID == r.activeID
		result = append(result, &profile)
	}

	sort.Slice(result, func(i, j int) bool {
		if result[i].CreatedAt.Equal(result[j].CreatedAt) {
			return result[i].Name < result[j].Name
		}
		return result[i].CreatedAt.Before(result[j].CreatedAt)
	})

	return result, nil
}

func (r *FileRepository) GetByID(id string) (*types.Profile, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	p, ok := r.profiles[id]
	if !ok {
		return nil, ErrProfileNotFound
	}

	profile := *p
	profile.IsActive = p.ID == r.activeID
	return &profile, nil
}

func (r *FileRepository) GetActive() (*types.Profile, *infraBeam.BeamFile, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.activeID == "" {
		return nil, nil, nil
	}

	profile, ok := r.profiles[r.activeID]
	if !ok {
		return nil, nil, nil
	}

	beamFile, ok := r.beams[r.activeID]
	if !ok {
		return nil, nil, nil
	}

	profileCopy := *profile
	profileCopy.IsActive = true
	beamCopy := *beamFile
	return &profileCopy, &beamCopy, nil
}

func (r *FileRepository) GetBeam(id string) (*infraBeam.BeamFile, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	beam, ok := r.beams[id]
	return beam, ok
}

func (r *FileRepository) Add(beamFile *infraBeam.BeamFile) (*types.Profile, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	id := generateID()
	profile := beamToProfile(id, beamFile)

	path := r.paths.Profile(id)
	if err := infraBeam.WriteToFile(path, beamFile); err != nil {
		return nil, err
	}

	r.profiles[id] = profile
	r.beams[id] = beamFile

	if r.activeID == "" {
		r.activeID = id
		r.saveState()
	}

	return profile, nil
}

func (r *FileRepository) Delete(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.profiles[id]; !ok {
		return nil
	}

	path := r.paths.Profile(id)
	os.Remove(path)

	delete(r.profiles, id)
	delete(r.beams, id)

	if r.activeID == id {
		r.activeID = ""
		var best *types.Profile
		for _, p := range r.profiles {
			if best == nil || best.CreatedAt.Before(p.CreatedAt) {
				best = p
			}
		}
		if best != nil {
			r.activeID = best.ID
		}
		r.saveState()
	}

	return nil
}

func (r *FileRepository) SetActive(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.profiles[id]; !ok {
		return nil
	}

	r.activeID = id
	return r.saveState()
}

func (r *FileRepository) SelectNode(profileID, nodeID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	beamFile, ok := r.beams[profileID]
	if !ok {
		return ErrProfileNotFound
	}

	if !beamFile.SetSelected(nodeID) {
		return ErrNodeNotFound
	}

	path := r.paths.Profile(profileID)
	return infraBeam.WriteToFile(path, beamFile)
}

func (r *FileRepository) SetAutoRefresh(id string, disabled bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	beamFile, ok := r.beams[id]
	if !ok {
		return ErrProfileNotFound
	}
	beamFile.Data.AutoRefreshDisabled = disabled
	if p, ok := r.profiles[id]; ok {
		p.AutoRefreshDisabled = disabled
	}

	path := r.paths.Profile(id)
	return infraBeam.WriteToFile(path, beamFile)
}

func (r *FileRepository) SetUpdateIntervalOverride(id string, hours int) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	beamFile, ok := r.beams[id]
	if !ok {
		return ErrProfileNotFound
	}
	beamFile.Data.UpdateIntervalOverrideHours = hours
	if p, ok := r.profiles[id]; ok {
		p.UpdateIntervalOverrideHours = hours
	}

	path := r.paths.Profile(id)
	return infraBeam.WriteToFile(path, beamFile)
}

func (r *FileRepository) AddDataUsed(id string, delta int64) error {
	if delta <= 0 {
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	beamFile, ok := r.beams[id]
	if !ok {
		return ErrProfileNotFound
	}
	beamFile.Data.DataUsed += delta
	if p, ok := r.profiles[id]; ok {
		p.DataUsed = beamFile.Data.DataUsed
	}

	path := r.paths.Profile(id)
	return infraBeam.WriteToFile(path, beamFile)
}

func (r *FileRepository) UpdateNodeConfig(profileID, nodeID string, update types.NodeConfigUpdate) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	beamFile, ok := r.beams[profileID]
	if !ok {
		return ErrProfileNotFound
	}

	for i := range beamFile.Data.Nodes {
		node := &beamFile.Data.Nodes[i]
		if node.ID != nodeID {
			continue
		}

		if node.BaseName == "" {
			node.BaseName = node.Name
		}

		if update.Name == "" || update.Name == node.Name {
			node.NameOverride = ""
		} else {
			node.NameOverride = update.Name
		}

		if update.Pinned {
			node.PinnedOutbound = types.ApplyOverrides(node.BaseOutbound(), update.Overrides)
			node.Overrides = nil
		} else {
			node.PinnedOutbound = nil
			if len(update.Overrides) == 0 {
				node.Overrides = nil
			} else {
				node.Overrides = update.Overrides
			}
		}

		path := r.paths.Profile(profileID)
		return infraBeam.WriteToFile(path, beamFile)
	}

	return ErrNodeNotFound
}

func (r *FileRepository) UpdateBeam(id string, beamFile *infraBeam.BeamFile) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.profiles[id]; !ok {
		return ErrProfileNotFound
	}

	beamFile.Data.UpdatedAt = time.Now().Unix()
	r.beams[id] = beamFile
	r.profiles[id] = beamToProfile(id, beamFile)

	path := r.paths.Profile(id)
	return infraBeam.WriteToFile(path, beamFile)
}

// RefreshTransports re-derives the transport of every node that still has
// its original share link. Nodes imported before their transport was
// supported (XHTTP, HTTPUpgrade) were stored as plain TCP and never
// connected; this repairs them without waiting for a subscription refresh.
// Only "transport" is replaced, so user overrides keep applying on top.
// Pinned nodes are frozen by the user on purpose and are left alone.
func (r *FileRepository) RefreshTransports(parse func(link string) (map[string]interface{}, error)) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for id, beamFile := range r.beams {
		repaired := 0
		for i := range beamFile.Data.Nodes {
			node := &beamFile.Data.Nodes[i]
			if node.RawLink == "" || node.PinnedOutbound != nil || node.Outbound == nil {
				continue
			}
			fresh, err := parse(node.RawLink)
			if err != nil || fresh == nil || sameJSON(node.Outbound["transport"], fresh["transport"]) {
				continue
			}
			if transport, ok := fresh["transport"]; ok {
				node.Outbound["transport"] = transport
			} else {
				delete(node.Outbound, "transport")
			}
			repaired++
		}
		if repaired == 0 {
			continue
		}
		if err := infraBeam.WriteToFile(r.paths.Profile(id), beamFile); err != nil {
			log.Printf("profile: failed to save repaired transports of %s: %v", id, err)
			continue
		}
		log.Printf("profile: re-parsed transport of %d node(s) in %s", repaired, id)
	}
}

func sameJSON(a, b interface{}) bool {
	left, errLeft := json.Marshal(a)
	right, errRight := json.Marshal(b)
	return errLeft == nil && errRight == nil && bytes.Equal(left, right)
}

func (r *FileRepository) ExportBeam(id string) ([]byte, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	beamFile, ok := r.beams[id]
	if !ok {
		return nil, ErrProfileNotFound
	}

	return beamFile.Export()
}

func (r *FileRepository) Reset() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	dir := r.paths.Profiles
	entries, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	for _, entry := range entries {
		name := entry.Name()
		if strings.HasSuffix(name, corePaths.ProfileExt) || strings.HasSuffix(name, corePaths.LegacyProfileExt) {
			_ = os.Remove(filepath.Join(dir, name))
		}
	}

	_ = os.Remove(r.stateFile())

	r.profiles = make(map[string]*types.Profile)
	r.beams = make(map[string]*infraBeam.BeamFile)
	r.activeID = ""

	return nil
}

func (r *FileRepository) stateFile() string {
	return r.paths.State()
}

func (r *FileRepository) loadState() {
	data, err := os.ReadFile(r.stateFile())
	if err != nil {
		return
	}

	var st struct {
		ActiveID string `json:"activeId"`
	}
	if json.Unmarshal(data, &st) == nil {
		if _, ok := r.profiles[st.ActiveID]; ok {
			r.activeID = st.ActiveID
		}
	}
}

func (r *FileRepository) saveState() error {
	data, _ := json.Marshal(struct {
		ActiveID string `json:"activeId"`
	}{ActiveID: r.activeID})
	return os.WriteFile(r.stateFile(), data, 0600)
}

func generateID() string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		t := time.Now().UnixNano()
		for i := range random {
			random[i] = byte(t >> (i * 8))
		}
	}
	b := make([]byte, 8)
	for i := range b {
		b[i] = letters[int(random[i])%len(letters)]
	}
	return string(b)
}
