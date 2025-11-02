package cryptod

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	sizes := []int{0, 1, 10, 100, 1000, 1000 * 1024 * 100}
	const key = "secret key"

	// encrypt then decrypt and check results
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

		if !bytes.Equal(plaintext, pbuf.Bytes()) {
			t.Errorf("compare failed for size %d, bytes differ", size)
			break
		}
	}
}

func TestTruncated(t *testing.T) {
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
	if err := Decrypt(r, pbuf, key); err == nil {
		t.Error("expected error decrypting gibberish")
	}
}

func TestBadKey(t *testing.T) {
	const key = "this is a secret"
	const keybad = "this is a "
	plaintext := generatePlainText(1000 * 1024 * 10)

	r := bytes.NewReader(plaintext)
	buf := &bytes.Buffer{}

	if err := Encrypt(r, buf, key); err != nil {
		t.Error("encrypt error: ", err)
		return
	}

	pbuf := &bytes.Buffer{}
	err := Decrypt(buf, pbuf, keybad)
	if err == nil {
		t.Error("expected a decrypt error with bad key")
	}
}

func TestTamper(t *testing.T) {
	const key = "this is a secret"
	plaintext := generatePlainText(1000 * 1024 * 10)

	r := bytes.NewReader(plaintext)
	buf := &bytes.Buffer{}

	if err := Encrypt(r, buf, key); err != nil {
		t.Error("encrypt error: ", err)
		return
	}

	// tamper with one byte of the encrypted buffer
	b := buf.Bytes()
	b[2048] = b[2048] + 1

	pbuf := &bytes.Buffer{}
	err := Decrypt(buf, pbuf, key)
	if err == nil {
		t.Error("expected a decrypt error with tampered byte")
	}
}

// TestChunkBoundaries tests encryption/decryption at exact chunk size boundaries
func TestChunkBoundaries(t *testing.T) {
	// Test data sizes that align exactly with chunk boundaries
	sizes := []int{
		chunkSize,     // Exactly 1 chunk
		chunkSize * 2, // Exactly 2 chunks
		chunkSize * 3, // Exactly 3 chunks
		chunkSize - 1, // Just under 1 chunk
		chunkSize + 1, // Just over 1 chunk
	}
	const key = "secret key"

	for _, size := range sizes {
		plaintext := generatePlainText(size)

		r := bytes.NewReader(plaintext)
		buf := &bytes.Buffer{}

		if err := Encrypt(r, buf, key); err != nil {
			t.Errorf("encrypt error for size %d: %v", size, err)
			continue
		}

		pbuf := &bytes.Buffer{}
		if err := Decrypt(buf, pbuf, key); err != nil {
			t.Errorf("decrypt error for size %d: %v", size, err)
			continue
		}

		if !bytes.Equal(plaintext, pbuf.Bytes()) {
			t.Errorf("compare failed for size %d, bytes differ", size)
		}
	}
}

// TestMultipleChunks verifies that data spanning multiple chunks is handled correctly
func TestMultipleChunks(t *testing.T) {
	const key = "secret key"
	// Create data that will definitely span multiple chunks (5MB)
	size := chunkSize * 5
	plaintext := generatePlainText(size)

	r := bytes.NewReader(plaintext)
	buf := &bytes.Buffer{}

	if err := Encrypt(r, buf, key); err != nil {
		t.Errorf("encrypt error: %v", err)
		return
	}

	// Verify encrypted size is larger due to overhead
	if buf.Len() <= size {
		t.Error("encrypted data should be larger than plaintext")
	}

	pbuf := &bytes.Buffer{}
	if err := Decrypt(buf, pbuf, key); err != nil {
		t.Errorf("decrypt error: %v", err)
		return
	}

	if !bytes.Equal(plaintext, pbuf.Bytes()) {
		t.Error("decrypted data does not match original")
	}

	t.Logf("Successfully encrypted/decrypted %d bytes across ~%d chunks", size, (size/chunkSize)+1)
}

// TestEmptyFile tests encryption and decryption of an empty file
func TestEmptyFile(t *testing.T) {
	const key = "secret key"
	plaintext := []byte{}

	r := bytes.NewReader(plaintext)
	buf := &bytes.Buffer{}

	if err := Encrypt(r, buf, key); err != nil {
		t.Errorf("encrypt error for empty file: %v", err)
		return
	}

	// Empty file should still have header and tomb chunk
	if buf.Len() == 0 {
		t.Error("encrypted empty file should have header and tomb chunk")
	}

	pbuf := &bytes.Buffer{}
	if err := Decrypt(buf, pbuf, key); err != nil {
		t.Errorf("decrypt error for empty file: %v", err)
		return
	}

	if pbuf.Len() != 0 {
		t.Errorf("decrypted empty file should be empty, got %d bytes", pbuf.Len())
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
