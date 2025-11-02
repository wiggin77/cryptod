package cryptod

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
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

func TestReadChunkHeaderGibberish(t *testing.T) {
	// create random input data
	buf := make([]byte, chunkSize*2)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		t.Error("rand.Reader failed?!", err)
		return
	}
	r := bytes.NewReader(buf)

	if _, err := readChunkHeader(r, chunkSize); err == nil {
		t.Error("expected error")
	}
}

// TestTombChunkHeader tests that tomb chunks are correctly written and read
func TestTombChunkHeader(t *testing.T) {
	h := chunkHeader{
		nonce: []byte("123456789012"),
		size:  0,
		tomb:  true,
	}

	// write tomb chunk header to buffer
	buf := &bytes.Buffer{}
	if err := writeChunkHeader(h, buf); err != nil {
		t.Error("error on write: ", err)
	}

	// read tomb chunk header back from buffer
	var h2 chunkHeader
	var err error
	if h2, err = readChunkHeader(buf, chunkSize); err != nil && !h2.tomb {
		t.Error("error on read: ", err)
	}

	if !h2.tomb {
		t.Error("expected tomb chunk, got data chunk")
	}

	if h2.size != 0 {
		t.Errorf("tomb chunk should have size 0, got %d", h2.size)
	}

	if bytes.Compare(h.nonce, h2.nonce) != 0 {
		t.Error("nonce mismatch in tomb chunk")
	}
}

// TestChunkHeaderWithLargeNonce tests chunk headers with maximum nonce size
func TestChunkHeaderWithLargeNonce(t *testing.T) {
	// Create a chunk header with a large nonce (up to 128 bytes is allowed)
	nonce := make([]byte, 128)
	for i := range nonce {
		nonce[i] = byte(i % 256)
	}

	h := chunkHeader{
		nonce: nonce,
		size:  1000,
		tomb:  false,
	}

	buf := &bytes.Buffer{}
	if err := writeChunkHeader(h, buf); err != nil {
		t.Error("error on write: ", err)
	}

	var h2 chunkHeader
	var err error
	if h2, err = readChunkHeader(buf, chunkSize*2); err != nil {
		t.Error("error on read: ", err)
	}

	if err := compareChunkHeader(h, h2); err != nil {
		t.Error("error on compare: ", err)
	}
}

// TestChunkHeaderInvalidNonceSize tests that oversized nonces are rejected
func TestChunkHeaderInvalidNonceSize(t *testing.T) {
	// Manually create a buffer with an invalid nonce size > 128
	buf := &bytes.Buffer{}

	// Write opening tag
	buf.WriteString("ct")

	// Write chunk type (data)
	buf.WriteString("d")

	// Write invalid nonce size (200 bytes)
	sizeNonce := make([]byte, 3)
	binary.PutUvarint(sizeNonce, 200)
	buf.Write(sizeNonce)

	// Try to read it - should fail with nonce size validation
	_, err := readChunkHeader(buf, chunkSize)
	if err == nil {
		t.Error("expected error for oversized nonce, got none")
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
