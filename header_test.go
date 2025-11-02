package cryptod

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
)

func TestHeaderInit(t *testing.T) {
	h := header{}
	if err := h.validate(); err == nil {
		t.Error("empty header should not validate")
	}

	h.init()

	if err := h.validate(); err != nil {
		t.Error("error on validate: ", err)
	}
}

func TestHeaderReadWrite(t *testing.T) {
	h := &header{}
	h.init()

	// write header to buffer
	buf := &bytes.Buffer{}
	if err := h.write(buf); err != nil {
		t.Error("error on write: ", err)
	}

	h2 := header{}
	if err := h2.read(buf); err != nil {
		t.Error("error on read: ", err)
	}

	if err := h2.validate(); err != nil {
		t.Error("error on validate: ", err)
	}
}

func TestHeaderReadGibberish(t *testing.T) {
	// create random input data
	buf := make([]byte, headerSize)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		t.Error("rand.Reader failed?!", err)
		return
	}
	r := bytes.NewReader(buf)

	h := header{}
	if err := h.read(r); err == nil {
		t.Error("expected error")
	}
}

// errorWriter is a test writer that always returns an error
type errorWriter struct{}

func (e *errorWriter) Write(p []byte) (n int, err error) {
	return 0, io.ErrShortWrite
}

// TestHeaderWriteError tests that write errors are properly propagated
// This test demonstrates bug in header.go:71 where errors are returned as nil
func TestHeaderWriteError(t *testing.T) {
	h := header{}
	h.init()

	ew := &errorWriter{}
	err := h.write(ew)

	// BUG: Currently this returns nil instead of the write error
	// After fix, this test should pass
	if err == nil {
		t.Error("BUG: expected write error to be returned, got nil (bug in header.go:71)")
	}
}
