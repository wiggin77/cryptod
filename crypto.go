package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
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
	gcm, err := getGCM(skey)
	if err != nil {
		return err
	}

	// reuse buffers to reduce GC
	pbuf := make([]byte, chunkSize)
	nonce := make([]byte, gcm.NonceSize())
	cbuf := make([]byte, len(pbuf)+gcm.Overhead())
	var ctr uint32 = 1
	var bHeaderWritten bool

	for {
		n, readErr := r.Read(pbuf)
		if n > 0 {
			p := pbuf[:n]
			// randomize the nonce
			if _, err := io.ReadFull(rand.Reader, nonce[binary.MaxVarintLen32:]); err != nil {
				return err
			}
			binary.PutUvarint(nonce, uint64(ctr))
			ctr++
			// encrypt and authenticate
			c := gcm.Seal(cbuf[:0], nonce, p, nil)
			var clen = uint32(len(c))
			if clen > 0 {
				// write file header once but only if there will be more data
				if !bHeaderWritten {
					if bHeaderWritten, err = writeHeader(w); err != nil {
						return err
					}
				}
				// write a chunk tag containing actual encrypted block size
				if err := writeChunkHeader(chunkHeader{nonce: nonce, size: clen}, w); err != nil {
					return err
				}
				// write encrypted data to output steam
				if _, err := w.Write(c); err != nil {
					return err
				}
			}
		}

		if readErr == io.EOF {
			break
		}
	}
	// write the tomb chunk header
	io.ReadFull(rand.Reader, nonce)
	return writeChunkHeader(chunkHeader{nonce: nonce, size: 0, tomb: true}, w)
}

// Decrypt reads from `r` until EOF and writes the decrypted contents to `w`
// based using the specified key.
func Decrypt(r io.Reader, w io.Writer, skey string) error {
	gcm, err := getGCM(skey)
	if err != nil {
		return err
	}

	maxChunkSize := chunkSize + gcm.Overhead()
	maxChunkSizeSanity := maxChunkSize * 2

	// reuse buffers to reduce GC
	buf := make([]byte, maxChunkSize)

	// read and validate the header
	h := header{}
	if err := h.read(r); err != nil {
		return err
	}

	for {
		// read next chunk header
		var ch chunkHeader
		ch, err = readChunkHeader(r, maxChunkSizeSanity)
		if err != nil && !ch.tomb {
			return err
		}
		if ch.tomb {
			break // tomb chunk header means we're done
		}
		// ensure cbuf is big enough
		if cap(buf) < int(ch.size) {
			buf = make([]byte, ch.size)
		}
		// read the encrypted chunk
		cbuf := buf[:ch.size]
		n, readErr := r.Read(cbuf)
		if readErr != nil && readErr != io.EOF {
			return readErr
		}
		if n != int(ch.size) {
			return fmt.Errorf("wrong chunk size read, expected %d, got %d", ch.size, n)
		}
		// decrypt the chunk
		var pbuf []byte
		if pbuf, err = gcm.Open(cbuf[:0], ch.nonce, cbuf, nil); err != nil {
			return err
		}
		// write plaintext to w
		if _, err := w.Write(pbuf); err != nil {
			return err
		}
	}
	return nil
}

// getGCM returns a AES256 block cipher wrapped in GCM.
func getGCM(skey string) (cipher.AEAD, error) {
	// key must be hashed to 32 bytes for AES256
	key := sha512.Sum512_256([]byte(skey))

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm, nil
}

// writes a file header
func writeHeader(w io.Writer) (bool, error) {
	h := header{}
	h.init()
	if err := h.write(w); err != nil {
		return false, err
	}
	return true, nil
}
