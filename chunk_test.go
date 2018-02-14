package cryptod

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"testing"
)

func TestReadWriteChunkHeader(t *testing.T) {
	h := chunkHeader{}
	h.nonce = []byte("123456789012")
	h.dataSize = ChunkSize
	h.ct = chunkTypeData
	h.st = schemeAES256GCM

	// write header to buffer
	buf := &bytes.Buffer{}
	if err := writeChunkHeader(h, bufio.NewWriter(buf)); err != nil {
		t.Error("error on write: ", err)
	}

	// read header back from buffer
	var h2 chunkHeader
	var err error
	if h2, err = readChunkHeader(bufio.NewReader(buf), ChunkSize); err != nil {
		t.Error("error on read: ", err)
	}

	if err := compareChunkHeader(h, h2); err != nil {
		t.Error("error on compare: ", err)
	}
}

func TestReadChunkHeaderGibberish(t *testing.T) {
	// create random input data
	buf := make([]byte, ChunkSize*2)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		t.Error("rand.Reader failed?!", err)
		return
	}
	r := bufio.NewReader(bytes.NewReader(buf))

	if _, err := readChunkHeader(r, ChunkSize); err == nil {
		t.Error("expected error")
	}
}

func compareChunkHeader(h1 chunkHeader, h2 chunkHeader) error {
	if h1.ct != h2.ct {
		return fmt.Errorf("mismatched chunk type: got %v, expected %v", h2.ct, h1.ct)
	}
	if h1.st != h2.st {
		return fmt.Errorf("mismatched scheme type: got %v, expected %v", h2.st, h1.st)
	}
	if bytes.Compare(h1.nonce, h2.nonce) != 0 {
		return fmt.Errorf("mismatched nonce: got %v, expected %v", h2.nonce, h1.nonce)
	}
	if h1.dataSize != h2.dataSize {
		return fmt.Errorf("mismatched size: got %v, expected %v", h2.dataSize, h1.dataSize)
	}
	return nil
}
