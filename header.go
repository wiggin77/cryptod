package cryptod

import (
	"bytes"
	"fmt"
	"io"
)

const (
	magicSize  = 2
	schemeSize = 9
	verMajSize = 1
	verMinSize = 1
	headerSize = magicSize + schemeSize + verMajSize + verMinSize

	magic  = "sc"
	scheme = "aes256gcm"
	verMaj = byte(1)
	verMin = byte(0)
)

// header for encrypted files
// (allows for versioning and changing the encryption scheme later)
type header struct {
	size   [1]byte // size in bytes of the other fields
	magic  [magicSize]byte
	scheme [schemeSize]byte
	verMaj [verMajSize]byte
	verMin [verMinSize]byte
}

// initializes the header with valid values
func (h *header) init() {
	h.size[0] = headerSize
	copy(h.magic[:], magic)
	copy(h.scheme[:], scheme)
	h.verMaj[0] = verMaj
	h.verMin[0] = verMin
}

// validates the contents of header
func (h *header) validate() error {
	if !bytes.Equal(h.size[:], []byte{headerSize}) {
		return fmt.Errorf("expected header size %d, got %v", headerSize, h.size)
	}

	if !bytes.Equal(h.magic[:], []byte(magic)) {
		return fmt.Errorf("expected magic %s, got %v", magic, h.magic)
	}

	if !bytes.Equal(h.scheme[:], []byte(scheme)) {
		return fmt.Errorf("expected scheme %s, got %v", scheme, h.scheme)
	}

	if !bytes.Equal(h.verMaj[:], []byte{verMaj}) {
		return fmt.Errorf("expected verMaj %d, got %v", verMaj, h.verMaj)
	}

	if !bytes.Equal(h.verMin[:], []byte{verMin}) {
		return fmt.Errorf("expected verMin %d, got %v", verMin, h.verMin)
	}
	return nil
}

// writes the header to `w`
func (h *header) write(w io.Writer) error {
	var err error
	fields := [][]byte{h.size[:], h.magic[:], h.scheme[:], h.verMaj[:], h.verMin[:]}
	for _, f := range fields {
		if _, err = w.Write(f); err != nil {
			return err
		}
	}
	return nil
}

// reads a header from `r`
func (h *header) read(r io.Reader) error {
	fields := [][]byte{h.size[:], h.magic[:], h.scheme[:], h.verMaj[:], h.verMin[:]}
	for _, f := range fields {
		n, err := r.Read(f)
		if n != len(f) {
			return fmt.Errorf("wrong number of byte read, expected %d, got %d", len(f), n)
		}
		if err != nil && err != io.EOF {
			return err
		}
	}
	return h.validate()
}
