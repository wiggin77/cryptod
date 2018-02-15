package cryptod

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strings"
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

func TestCheckChunkType(t *testing.T) {
	inputs := []chunkType{chunkTypeData, chunkTypeExtra, chunkTypeTomb}
	for _, ct := range inputs {
		if err := checkChunkType(ct); err != nil {
			t.Errorf("unexpected error for ct=%d: %v", ct, err)
		}
	}

	ct := chunkType(0xDE)
	if err := checkChunkType(ct); err == nil {
		t.Errorf("expected error for ct=%d", ct)
	}
}

func TestCheckSchemeType(t *testing.T) {
	inputs := []schemeType{schemeAES256GCM}
	for _, st := range inputs {
		if err := checkSchemeType(st); err != nil {
			t.Errorf("unexpected error for st=%d: %v", st, err)
		}
	}

	st := schemeType(0xDE)
	if err := checkSchemeType(st); err == nil {
		t.Errorf("expected error for st=%d", st)
	}
}

func makeChunkHeader() chunkHeader {
	ch := chunkHeader{}
	ch.ct = chunkTypeData
	ch.st = schemeAES256GCM
	ch.dataSize = 1024
	ch.nonce = []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	return ch
}

func TestWriteChunkHeaderNeg(t *testing.T) {
	bw := bufio.NewWriter(bytes.NewBuffer(make([]byte, 100)))
	ch := makeChunkHeader()
	ch.ct = chunkType(0xDE)
	if err := writeChunkHeader(ch, bw); !strings.Contains(err.Error(), "invalid chunk type") {
		t.Error("expected invalid chunk type error")
	}
	ch = makeChunkHeader()
	ch.st = schemeType(0xDE)
	if err := writeChunkHeader(ch, bw); !strings.Contains(err.Error(), "invalid scheme type") {
		t.Error("expected invalid scheme type error")
	}
	// generate io errors by passing size limited writer
	ch = makeChunkHeader()
	limits := []int{1, 2}
	for _, lim := range limits {
		lw := NewLimitedWriter(&bytes.Buffer{}, lim)
		bw = bufio.NewWriter(lw)
		if err := writeChunkHeader(ch, bw); err == nil {
			t.Errorf("expected error for limit %d", lim)
		}
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

// ErrWriterFull is returned by LimitedWriter when trying to writer beyond the limit.
var ErrWriterFull = errors.New("writer full")

// LimitedWriter provides an io.Writer that can
type LimitedWriter struct {
	limit   int
	written int
	w       io.Writer
}

// NewLimitedWriter returns a new NewLimitedWriter with the specified limit.
func NewLimitedWriter(w io.Writer, limit int) *LimitedWriter {
	return &LimitedWriter{limit: limit, w: w}
}

// Write writes the bytes, returning `ErrWriterFull` if the limit is exceeded.
func (lw *LimitedWriter) Write(p []byte) (int, error) {
	if lw.written >= lw.limit {
		return 0, ErrWriterFull
	}
	avail := lw.limit - lw.written
	if avail > len(p) {
		var err error
		var n int
		if n, err = lw.w.Write(p[:avail]); err == nil {
			err = ErrWriterFull
		}
		return n, err
	}
	return lw.w.Write(p)
}
