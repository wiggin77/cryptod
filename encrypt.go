package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"io"
)

const (
	chunkSize = 1024 * 1000
)

// Encrypt reads from `r` until EOF and writes the encrypted contents to `w`
// based on the specified key. Ideally the key should be unique for each Writer
// instance.
// Uses AES256 encryption and GCM authentication on chunks of size up to 1MB.
func Encrypt(r io.Reader, w io.Writer, skey string) error {
	// key must be hashed to 32 bytes for AES256
	//h := sha512.New512_256()
	//key := h.Sum([]byte(skey))
	key := sha512.Sum512_256([]byte(skey))

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	// reuse buffers to reduce GC
	plainbuf := make([]byte, chunkSize)
	cipherbuf := make([]byte, len(plainbuf)+gcm.Overhead())
	nonce := make([]byte, gcm.NonceSize())

	for {
		n, err := r.Read(plainbuf)
		if n > 0 {
			p := plainbuf[:n]
			// randomize the nonce
			if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
				return err
			}
			// encrypt and authenticate
			c := gcm.Seal(cipherbuf, nonce, p, nil)
			// write encrypted data to output steam
			n, err = w.Write(c)
			if err != nil {
				return err
			}
		}

		if err == io.EOF {
			break
		}
	}
	return nil
}
