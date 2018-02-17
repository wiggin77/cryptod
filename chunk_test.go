package cryptod

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/wiggin77/cryptod/test"
)

func TestReadWriteChunkHeader(t *testing.T) {
	h := chunkHeader{}
	h.nonce = []byte("123456789012")
	h.dataSize = ChunkSize
	h.ct = chunkTypeData
	h.st = schemeAES256GCM

	// write header to buffer
	buf := &bytes.Buffer{}
	if err := writeChunkHeader(h, buf); err != nil {
		t.Error("error on write: ", err)
	}

	// read header back from buffer
	var h2 chunkHeader
	var err error
	if h2, err = readChunkHeader(buf, ChunkSize); err != nil {
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
	w := &bytes.Buffer{}
	ch := makeChunkHeader()
	ch.ct = chunkType(0xDE)
	if err := writeChunkHeader(ch, w); !strings.Contains(err.Error(), "invalid chunk type") {
		t.Error("expected invalid chunk type error")
	}
	ch = makeChunkHeader()
	ch.st = schemeType(0xDE)
	if err := writeChunkHeader(ch, w); !strings.Contains(err.Error(), "invalid scheme type") {
		t.Error("expected invalid scheme type error")
	}

	// generate io error by passing size limited writer
	const limit = 10
	ch = makeChunkHeader()
	lw := test.NewLimitedWriter(&bytes.Buffer{}, limit)
	if err := writeChunkHeader(ch, lw); err == nil {
		t.Errorf("expected error for limit %d", limit)
	}
}

func TestReadChunkHeaderNeg(t *testing.T) {
	// read various amounts of the chunk header to trigger all the
	// error cases.
	limits := []int{1, 2, 3}
	for _, lim := range limits {
		// stuff a chunk header into a buffer
		buf := &bytes.Buffer{}
		ch := makeChunkHeader()
		if err := writeChunkHeader(ch, buf); err != nil {
			t.Error("unexpected error: ", err)
		}
		// read it back
		lr := io.LimitReader(buf, int64(lim))
		if _, err := readChunkHeader(lr, ChunkSize); err == nil {
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
