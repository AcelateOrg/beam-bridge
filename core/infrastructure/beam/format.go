package beam

import "errors"

const (
	// LegacyVersion / CurrentVersion describe the portable interchange format
	// (magic "BEAM", one version byte, gzipped JSON). It stays readable by
	// other tools and older builds, so it is what Export produces and what
	// Import accepts.
	LegacyVersion  uint8 = 1
	CurrentVersion uint8 = 2

	// StorageVersion is the at-rest container used for profiles on this
	// machine. It is encrypted with a device-bound key and carries its own
	// magic so the files no longer look like BEAM archives to a scanner.
	StorageVersion uint8 = 4
)

const (
	beamMagicSize  = 4
	beamHeaderSize = 5

	storageMagicSize  = 4
	storageHeaderSize = 5

	// maxProfileSize bounds decompression so a corrupt or hostile payload
	// cannot inflate without end. A real profile is a few kilobytes.
	maxProfileSize = 16 << 20
)

var (
	// BeamMagic opens the portable interchange format.
	BeamMagic = []byte{0x42, 0x45, 0x41, 0x4D} // "BEAM"

	// StorageMagic opens the encrypted at-rest container. Deliberately not
	// ASCII, so a stealer grepping for "BEAM" finds nothing in the profile
	// store.
	StorageMagic = []byte{0xBE, 0x11, 0x5F, 0x01}

	ErrInvalidBeam  = errors.New("invalid .beam file")
	ErrVersion      = errors.New("unsupported .beam version")
	ErrEmptyPayload = errors.New("empty payload")
)
