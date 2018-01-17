package crypto

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
