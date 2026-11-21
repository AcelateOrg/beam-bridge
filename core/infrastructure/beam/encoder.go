package beam

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// WriteToFile stores a profile in the encrypted at-rest container, bound to
// the file's id, and writes it atomically. When the keystore is not ready
// (tools, tests) it falls back to the portable plaintext format so behaviour
// is unchanged there.
func WriteToFile(path string, beam *BeamFile) error {
	beam.Data.Version = CurrentVersion
	beam.Data.UpdatedAt = time.Now().Unix()

	content, err := json.Marshal(beam.Data)
	if err != nil {
		return err
	}

	var out []byte
	if k := currentKeystore(); k != nil {
		out, err = encodeStorage(content, idFromPath(path), k)
	} else {
		out, err = encodeBeam(content)
	}
	if err != nil {
		return err
	}
	return writeFileAtomic(path, out)
}

// Export produces the portable interchange file the user shares or backs up:
// magic "BEAM", version, gzipped JSON. No device key, no password, so it
// opens on any machine and in older builds.
func (bf *BeamFile) Export() ([]byte, error) {
	data := bf.Data
	data.Version = CurrentVersion
	data.UpdatedAt = time.Now().Unix()

	content, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	return encodeBeam(content)
}

func encodeBeam(content []byte) ([]byte, error) {
	var buf bytes.Buffer
	buf.Write(BeamMagic)
	buf.WriteByte(CurrentVersion)
	if err := gzipInto(&buf, content); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func encodeStorage(content []byte, id string, k *keystore) ([]byte, error) {
	var compressed bytes.Buffer
	if err := gzipInto(&compressed, content); err != nil {
		return nil, err
	}
	sealed, err := k.seal("profile", compressed.Bytes(), storageAAD(id))
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, storageHeaderSize+len(sealed))
	out = append(out, StorageMagic...)
	out = append(out, StorageVersion)
	return append(out, sealed...), nil
}

func gzipInto(buf *bytes.Buffer, content []byte) error {
	writer := gzip.NewWriter(buf)
	if _, err := writer.Write(content); err != nil {
		return err
	}
	return writer.Close()
}

// writeFileAtomic writes through a temp file in the same directory and renames
// it into place, so a crash mid-write never leaves a half-written profile.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".beam-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
