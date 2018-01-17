package crypto

import (
	"bytes"
	"io"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	sizes := []int{1, 10, 100, 1000, 1000 * 1024 * 100}
	const key = "secret key"

	// encrypt then decrypt anf check results
	for _, size := range sizes {
		plaintext := generatePlainText(size)

		r := bytes.NewReader(plaintext)
		buf := &bytes.Buffer{}

		if err := Encrypt(r, buf, key); err != nil {
			t.Errorf("encrypt error for size %d: %v", size, err)
			break
		}

		pbuf := &bytes.Buffer{}
		if err := Decrypt(buf, pbuf, key); err != nil {
			t.Errorf("decrypt error for size %d: %v", size, err)
			break
		}

		if bytes.Compare(plaintext, pbuf.Bytes()) != 0 {
			t.Errorf("compare failed for size %d, bytes differ", size)
			break
		}
	}
}

func TestError(t *testing.T) {
	sizes := []int{2, 10, 100, 1000, 1000 * 1024 * 100}
	const key = "secret key"

	for _, size := range sizes {
		plaintext := generatePlainText(size)

		r := bytes.NewReader(plaintext)
		buf := &bytes.Buffer{}

		if err := Encrypt(r, buf, key); err != nil {
			t.Error("encrypt error: ", err)
		}

		// try decrypting a truncated stream
		pbuf := &bytes.Buffer{}
		half := int64(buf.Len() / 2)
		lr := io.LimitReader(buf, half)

		if err := Decrypt(lr, pbuf, key); err == nil {
			t.Error("expected error decrypting truncated buffer for size ", size)
		}
	}
}

// helper to generate predicable plaintext of any size
func generatePlainText(size int) []byte {
	const s = "0123456789"
	src := []byte(s)
	section := make([]byte, size)

	for i := range section {
		section[i] = src[i%len(s)]
	}
	return section
}
