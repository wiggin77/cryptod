package crypto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	chunkTag      = "ct"
	chunkTypeData = "d"
	chunkTypeTomb = "t"
)

type chunkHeader struct {
	nonce []byte
	size  uint32
	tomb  bool
}

// writes a chunk header, containing the tag id, nonce and chunk size
func writeChunkHeader(ch chunkHeader, w io.Writer) error {
	// write the tag (open)
	tag := []byte(chunkTag)
	if _, err := w.Write(tag); err != nil {
		return err
	}

	// write the chunk type
	var t []byte
	if ch.tomb {
		t = []byte(chunkTypeTomb)
	} else {
		t = []byte(chunkTypeData)
	}
	if _, err := w.Write(t); err != nil {
		return err
	}

	// write the nonce size, followed by nonce
	sizeNonce := make([]byte, binary.MaxVarintLen16)
	binary.PutUvarint(sizeNonce, uint64(len(ch.nonce)))
	if _, err := w.Write(sizeNonce); err != nil {
		return err
	}
	if _, err := w.Write(ch.nonce); err != nil {
		return err
	}

	// write the chunk size
	sizeChunk := make([]byte, binary.MaxVarintLen32)
	binary.PutUvarint(sizeChunk, uint64(ch.size))
	if _, err := w.Write(sizeChunk); err != nil {
		return err
	}

	// write the tag (close)
	if _, err := w.Write(tag); err != nil {
		return err
	}
	return nil
}

// reads a chunk header
func readChunkHeader(r io.Reader, maxChunkSize int) (chunkHeader, error) {
	h := chunkHeader{}

	// read the tag (open)
	taglen := len(chunkTag)
	tag := make([]byte, taglen)
	if _, err := r.Read(tag); err != nil {
		return h, err
	}
	if bytes.Compare(tag, []byte(chunkTag)) != 0 {
		return h, errors.New("invalid chunk header tag (open)")
	}

	// read the chunk type
	t := []byte(chunkTypeData)
	if _, err := r.Read(t); err != nil {
		return h, err
	}
	if bytes.Compare(t, []byte(chunkTypeTomb)) == 0 {
		h.tomb = true
	}

	// read nonce size
	sizeNonce := make([]byte, binary.MaxVarintLen16)
	if _, err := r.Read(sizeNonce); err != nil {
		return h, err
	}
	val, err := binary.ReadUvarint(bytes.NewReader(sizeNonce))
	if err != nil {
		return h, err
	}
	size := uint32(val)
	if size > 128 { // sanity check
		return h, fmt.Errorf("invalid nonce size: %d", size)
	}

	// read nonce
	h.nonce = make([]byte, size)
	if _, err := r.Read(h.nonce); err != nil {
		return h, err
	}

	// read chunk size
	sizeChunk := make([]byte, binary.MaxVarintLen32)
	if _, err := r.Read(sizeChunk); err != nil {
		return h, err
	}
	val, err = binary.ReadUvarint(bytes.NewReader(sizeChunk))
	if err != nil {
		return h, err
	}
	h.size = uint32(val)
	if h.size > uint32(maxChunkSize) {
		return h, fmt.Errorf("invalid chunk size: %d, max=%d", h.size, maxChunkSize)
	}

	// read the tag (close)
	tag = make([]byte, taglen)
	if _, err := r.Read(tag); err != nil {
		return h, err
	}
	if bytes.Compare(tag, []byte(chunkTag)) != 0 {
		return h, errors.New("invalid chunk header tag (close)")
	}
	// header ok
	return h, nil
}
