package cryptod

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"github.com/wiggin77/cryptod/test"
)

func TestEncryptDecrypt(t *testing.T) {
	sizes := []int{0, 1, 10, 100, 1000, 1000 * 1024 * 4, 1000 * 1024 * 100}
	const key = "secret key"
	const extra = "Wake up, Neo..."

	// encrypt then decrypt and check results
	for _, size := range sizes {
		plaintext := test.GeneratePlainText(size)

		r := bytes.NewReader(plaintext)
		buf := &bytes.Buffer{}

		if err := Encrypt(r, buf, key, []byte(extra)); err != nil {
			t.Errorf("encrypt error for size %d: %v", size, err)
			break
		}

		pbuf := &bytes.Buffer{}
		if ext, err := Decrypt(buf, pbuf, key); err != nil {
			t.Errorf("decrypt error for size %d: %v", size, err)
			break
		} else if bytes.Compare([]byte(extra), ext) != 0 {
			t.Errorf("extra data mismatch for size %d: %v", size, ext)
			break
		}

		if bytes.Compare(plaintext, pbuf.Bytes()) != 0 {
			t.Errorf("compare failed for size %d, bytes differ", size)
			break
		}
	}
}

func TestTruncated(t *testing.T) {
	sizes := []int{2, 10, 100, 1000, 1000 * 1024 * 100}
	const key = "secret key"

	for _, size := range sizes {
		plaintext := test.GeneratePlainText(size)

		r := bytes.NewReader(plaintext)
		buf := &bytes.Buffer{}

		if err := Encrypt(r, buf, key, nil); err != nil {
			t.Error("encrypt error: ", err)
		}

		// try decrypting a truncated stream
		pbuf := &bytes.Buffer{}
		half := int64(buf.Len() / 2)
		lr := io.LimitReader(buf, half)

		if _, err := Decrypt(lr, pbuf, key); err == nil {
			t.Error("expected error decrypting truncated buffer for size ", size)
		}
	}
}

func TestGibberish(t *testing.T) {
	const key = "secret key"
	const size = 1000 * 1024 * 10

	// create random input data
	cbuf := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, cbuf); err != nil {
		t.Error("rand.Reader failed?!", err)
		return
	}
	r := bytes.NewReader(cbuf)

	pbuf := &bytes.Buffer{}
	if _, err := Decrypt(r, pbuf, key); err == nil {
		t.Error("expected error decrypting gibberish")
	}
}

func TestBadKey(t *testing.T) {
	const key = "this is a secret"
	const keybad = "this is a "
	plaintext := test.GeneratePlainText(1000 * 1024 * 10)

	r := bytes.NewReader(plaintext)
	buf := &bytes.Buffer{}

	if err := Encrypt(r, buf, key, nil); err != nil {
		t.Error("encrypt error: ", err)
		return
	}

	pbuf := &bytes.Buffer{}
	_, err := Decrypt(buf, pbuf, keybad)
	if err == nil {
		t.Error("expected a decrypt error with bad key")
	}
}

func TestTamper(t *testing.T) {
	const key = "this is a secret"
	plaintext := test.GeneratePlainText(1000 * 1024 * 10)

	r := bytes.NewReader(plaintext)
	buf := &bytes.Buffer{}

	if err := Encrypt(r, buf, key, nil); err != nil {
		t.Error("encrypt error: ", err)
		return
	}

	// tamper with one byte of the encrypted buffer
	b := buf.Bytes()
	b[2048] = b[2048] + 1

	pbuf := &bytes.Buffer{}
	_, err := Decrypt(buf, pbuf, key)
	if err == nil {
		t.Error("expected a decrypt error with tampered byte")
	}
}
