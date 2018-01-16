package crypto

import (
	"bytes"
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
