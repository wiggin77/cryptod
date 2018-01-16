package crypto

import (
	"bytes"
	"io"
	"testing"
)

func TestEncrypt(t *testing.T) {
	r := generatePlain(1000 * 1024 * 100)
	w := &bytes.Buffer{}

	if err := Encrypt(r, w, "secret_key"); err != nil {
		t.Error("encrypt error: ", err)
		return
	}

	t.Logf("cipher len: %d/n", w.Len())
}

func generatePlain(size int) io.Reader {
	section := []byte("0123456789")
	count := (size / len(section)) + 1
	buf := make([]byte, len(section)*count)

	idx := 0
	for i := 0; i < count; i++ {
		copy(buf[idx:], section)
		idx += len(section)
	}
	return bytes.NewReader(buf)
}
