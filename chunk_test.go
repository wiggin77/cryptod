package crypto

import (
	"bytes"
	"fmt"
	"testing"
)

func TestReadWriteChunkHeader(t *testing.T) {
	h := chunkHeader{}
	h.nonce = []byte("123456789012")
	h.size = chunkSize

	// write header to buffer
	buf := &bytes.Buffer{}
	if err := writeChunkHeader(h, buf); err != nil {
		t.Error("error on write: ", err)
	}

	// read header back from buffer
	var h2 chunkHeader
	var err error
	if h2, err = readChunkHeader(buf, chunkSize); err != nil {
		t.Error("error on read: ", err)
	}

	if err := compareChunkHeader(h, h2); err != nil {
		t.Error("error on compare: ", err)
	}
}

func compareChunkHeader(h1 chunkHeader, h2 chunkHeader) error {
	if bytes.Compare(h1.nonce, h2.nonce) != 0 {
		return fmt.Errorf("mismatched nonce: got %v, expected %v", h2.nonce, h1.nonce)
	}
	if h1.size != h2.size {
		return fmt.Errorf("mismatched size: got %v, expected %v", h2.size, h1.size)
	}
	return nil
}
