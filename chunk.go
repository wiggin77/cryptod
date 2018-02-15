package cryptod

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

type chunkType byte
type schemeType byte

var (
	chunkTag = []byte{'c', 't'}
)

const (
	chunkTypeData  chunkType = 0x01
	chunkTypeExtra chunkType = 0xF0
	chunkTypeTomb  chunkType = 0xF1

	schemeAES256GCM schemeType = 0x01
)

// Chunk is comprised of a chunk header followed by 0 or more
// bytes of encrypted data.

// chunkHeader describes the layout of a chunk.
type chunkHeader struct {
	ct       chunkType  // the chunk type
	st       schemeType // scheme type (cipher plus envelope)
	nonce    []byte     // nonce
	dataSize uint32     // size of encrypted data in bytes
}

// checkChunkType determines if the chunk type `ct` is valid.
func checkChunkType(ct chunkType) error {
	var err error
	switch ct {
	case chunkTypeData:
	case chunkTypeExtra:
	case chunkTypeTomb:
	default:
		err = fmt.Errorf("invalid chunk type: %d", ct)
	}
	return err
}

// checkScheme determines if the scheme is valid.
func checkSchemeType(st schemeType) error {
	var err error
	switch st {
	case schemeAES256GCM:
	default:
		err = fmt.Errorf("invalid scheme: %d", st)
	}
	return err
}

// writeChunkHeader writes a chunk header
func writeChunkHeader(ch chunkHeader, w *bufio.Writer) error {
	if err := checkChunkType(ch.ct); err != nil {
		return err
	}
	if err := checkSchemeType(ch.st); err != nil {
		return err
	}

	// write the tag
	if _, err := w.Write(chunkTag); err != nil {
		return err
	}

	// write the chunk type
	if err := w.WriteByte(byte(ch.ct)); err != nil {
		return err
	}

	// write the scheme type
	if err := w.WriteByte(byte(ch.st)); err != nil {
		return err
	}

	// write the nonce size, followed by nonce
	if err := w.WriteByte(byte(len(ch.nonce))); err != nil {
		return err
	}
	if _, err := w.Write(ch.nonce); err != nil {
		return err
	}

	// write the chunk size
	sizeChunk := make([]byte, binary.MaxVarintLen32)
	binary.PutUvarint(sizeChunk, uint64(ch.dataSize))
	if _, err := w.Write(sizeChunk); err != nil {
		return err
	}
	return w.Flush()
}

// reads a chunk header
func readChunkHeader(r *bufio.Reader, maxChunkSize int) (chunkHeader, error) {
	h := chunkHeader{}
	var err error

	// read the tag
	taglen := len(chunkTag)
	tag := make([]byte, taglen)
	if _, err = io.ReadFull(r, tag); err != nil {
		return h, err
	}
	if bytes.Compare(tag, chunkTag) != 0 {
		return h, errors.New("invalid chunk tag")
	}

	// read the chunk type
	var ct byte
	if ct, err = r.ReadByte(); err != nil {
		return h, err
	}
	h.ct = chunkType(ct)
	if err := checkChunkType(h.ct); err != nil {
		return h, err
	}

	// read the scheme type
	var st byte
	if st, err = r.ReadByte(); err != nil {
		return h, err
	}
	h.st = schemeType(st)
	if err := checkSchemeType(h.st); err != nil {
		return h, err
	}

	// read nonce size
	var nsize byte
	if nsize, err = r.ReadByte(); err != nil {
		return h, err
	}

	// read nonce
	h.nonce = make([]byte, nsize)
	if _, err := io.ReadFull(r, h.nonce); err != nil {
		return h, err
	}

	// read chunk size
	sizeChunk := make([]byte, binary.MaxVarintLen32)
	if _, err = io.ReadFull(r, sizeChunk); err != nil {
		return h, err
	}
	val, err := binary.ReadUvarint(bytes.NewReader(sizeChunk))
	if err != nil {
		return h, err
	}
	h.dataSize = uint32(val)
	if h.dataSize > uint32(maxChunkSize) {
		return h, fmt.Errorf("invalid chunk size: %d, max=%d", h.dataSize, maxChunkSize)
	}
	// header ok
	return h, nil
}
