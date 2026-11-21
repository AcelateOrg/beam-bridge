package beam

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"

	"beam-bridge/core/types"
)

// storageAAD ties a stored container to its own file. Moving a file to another
// id, or swapping two files, breaks authentication.
func storageAAD(id string) []byte {
	aad := make([]byte, 0, storageHeaderSize+len(id))
	aad = append(aad, StorageMagic...)
	aad = append(aad, StorageVersion)
	return append(aad, id...)
}

// idFromPath is the file name without its extension; it is what the container
// is bound to.
func idFromPath(path string) string {
	base := filepath.Base(path)
	return base[:len(base)-len(filepath.Ext(base))]
}

// ReadFromFile reads a profile from the on-disk store. It accepts both the new
// encrypted container and the older plaintext BEAM files so existing installs
// keep loading; callers re-save through WriteToFile, which upgrades them.
func ReadFromFile(path string) (*BeamFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseStored(data, idFromPath(path))
}

// IsEncryptedFile reports whether path already holds the encrypted container.
// The repository uses it to upgrade plaintext files written while the
// keystore was unavailable.
func IsEncryptedFile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	head := make([]byte, storageMagicSize)
	if _, err := io.ReadFull(f, head); err != nil {
		return false
	}
	return bytes.Equal(head, StorageMagic)
}

func parseStored(data []byte, id string) (*BeamFile, error) {
	if len(data) >= storageMagicSize && bytes.Equal(data[:storageMagicSize], StorageMagic) {
		return decodeStorage(data, id)
	}
	// Legacy plaintext BEAM container (magic "BEAM", version, gzip JSON).
	return ParseData(data)
}

func decodeStorage(data []byte, id string) (*BeamFile, error) {
	if len(data) < storageHeaderSize {
		return nil, ErrInvalidBeam
	}
	version := data[storageMagicSize]
	if version != StorageVersion {
		return nil, ErrVersion
	}
	k := currentKeystore()
	if k == nil {
		return nil, ErrNoKeystore
	}
	plain, err := k.open("profile", data[storageHeaderSize:], storageAAD(id))
	if err != nil {
		return nil, err
	}
	content, err := gunzip(plain)
	if err != nil {
		return nil, err
	}
	return parseBeamJSON(StorageVersion, content)
}

// ParseData decodes the portable interchange format used by Export and by
// files the user imports: magic "BEAM", one version byte, gzipped JSON. A bare
// JSON document is also accepted.
func ParseData(data []byte) (*BeamFile, error) {
	payload := data
	version := byte(CurrentVersion)
	if len(data) >= beamMagicSize && bytes.Equal(data[:beamMagicSize], BeamMagic) {
		if len(data) < beamHeaderSize {
			return nil, ErrInvalidBeam
		}
		version = data[beamMagicSize]
		if version > CurrentVersion {
			return nil, ErrVersion
		}
		payload = data[beamHeaderSize:]
	}

	switch {
	case len(payload) >= 2 && payload[0] == 0x1f && payload[1] == 0x8b:
		content, err := gunzip(payload)
		if err != nil {
			return nil, err
		}
		return parseBeamJSON(version, content)
	case len(bytes.TrimSpace(payload)) > 0 && bytes.TrimSpace(payload)[0] == '{':
		return parseBeamJSON(version, payload)
	default:
		return nil, ErrInvalidBeam
	}
}

func gunzip(compressed []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	content, err := io.ReadAll(io.LimitReader(reader, maxProfileSize+1))
	if err != nil {
		return nil, err
	}
	if len(content) > maxProfileSize {
		return nil, ErrInvalidBeam
	}
	return content, nil
}

func parseBeamJSON(version byte, content []byte) (*BeamFile, error) {
	var beam BeamFile
	if err := json.Unmarshal(content, &beam.Data); err != nil {
		return nil, err
	}
	// A generator's document with only links (see BeamFileData.Links) is
	// current-format even without a name: v1 files never had links.
	if version != LegacyVersion && beam.Data.Name == "" && len(beam.Data.Links) > 0 {
		beam.Data.Name = beam.Data.Provider
		if beam.Data.Name == "" {
			beam.Data.Name = "Beam"
		}
	}
	if version == LegacyVersion || beam.Data.Name == "" {
		return migrateFromV1(content)
	}
	if beam.Data.Categories == nil {
		beam.Data.Categories = []types.Category{}
	}
	if beam.Data.Nodes == nil {
		beam.Data.Nodes = []types.BeamNode{}
	}
	return &beam, nil
}
