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
		err = fmt.Errorf("invalid scheme type: %d", st)
	}
	return err
}

// writeChunkHeader writes a chunk header
func writeChunkHeader(ch chunkHeader, w io.Writer) error {
	if err := checkChunkType(ch.ct); err != nil {
		return err
	}
	if err := checkSchemeType(ch.st); err != nil {
		return err
	}
	buf := bytes.Buffer{}

	// write the tag
	buf.Write(chunkTag)
	// write the chunk type
	buf.WriteByte(byte(ch.ct))
	// write the scheme type
	buf.WriteByte(byte(ch.st))
	// write the nonce size, followed by nonce
	buf.WriteByte(byte(len(ch.nonce)))
	buf.Write(ch.nonce)
	// write the chunk size
	sizeChunk := make([]byte, binary.MaxVarintLen32)
	binary.PutUvarint(sizeChunk, uint64(ch.dataSize))
	buf.Write(sizeChunk)

	// output the result
	_, err := w.Write(buf.Bytes())
	return err
}

// reads a chunk header
func readChunkHeader(r io.Reader, maxChunkSize int) (chunkHeader, error) {
	h := chunkHeader{}
	var err error
	br := bufio.NewReader(r) // noop if `r` is already a bufio.Reader

	// read the tag
	taglen := len(chunkTag)
	tag := make([]byte, taglen)
	if _, err = io.ReadFull(br, tag); err != nil {
		return h, err
	}
	if bytes.Compare(tag, chunkTag) != 0 {
		return h, errors.New("invalid chunk tag")
	}

	// read the chunk type
	var ct byte
	if ct, err = br.ReadByte(); err != nil {
		return h, err
	}
	h.ct = chunkType(ct)
	if err := checkChunkType(h.ct); err != nil {
		return h, err
	}

	// read the scheme type
	var st byte
	if st, err = br.ReadByte(); err != nil {
		return h, err
	}
	h.st = schemeType(st)
	if err := checkSchemeType(h.st); err != nil {
		return h, err
	}

	// read nonce size
	var nsize byte
	if nsize, err = br.ReadByte(); err != nil {
		return h, err
	}

	// read nonce
	h.nonce = make([]byte, nsize)
	if _, err := io.ReadFull(br, h.nonce); err != nil {
		return h, err
	}

	// read chunk size
	sizeChunk := make([]byte, binary.MaxVarintLen32)
	if _, err = io.ReadFull(br, sizeChunk); err != nil {
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
