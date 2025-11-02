package cryptod

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

// Encrypt reads chunks of data from `r` writes the encrypted contents to `w`
// based on the specified key. Reading continues until io.EOF.
//
// The key should be unique for each io.Reader instance.
// For example, when encrypting files `skey` can be a secret plus the filespec
// to ensure the key is unique for each file.
//
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

	// write the stream header
	if err = writeHeader(w); err != nil {
		return err
	}

	for {
		n, readErr := r.Read(pbuf)
		if n > 0 {
			p := pbuf[:n]
			// randomize the nonce
			if _, err := io.ReadFull(rand.Reader, nonce[binary.MaxVarintLen32:]); err != nil {
				return err
			}
			binary.PutUvarint(nonce, uint64(ctr))
			// create AAD with chunk counter to authenticate chunk sequence
			aad := make([]byte, 4)
			binary.LittleEndian.PutUint32(aad, ctr)
			ctr++
			// encrypt and authenticate with AAD binding chunk counter
			c := gcm.Seal(cbuf[:0], nonce, p, aad)
			var clen = uint32(len(c))
			if clen > 0 {
				// write a chunk header containing actual encrypted block size
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
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	return writeChunkHeader(chunkHeader{nonce: nonce, size: 0, tomb: true}, w)
}

// Decrypt reads chunks of data from `r` and writes the decrypted
// chunks to `w` using the specified key. Reading continues until io.EOF.
func Decrypt(r io.Reader, w io.Writer, skey string) error {
	gcm, err := getGCM(skey)
	if err != nil {
		return err
	}

	maxChunkSize := chunkSize + gcm.Overhead()
	maxChunkSizeSanity := maxChunkSize * 2

	// reuse buffers to reduce GC
	buf := make([]byte, maxChunkSize)
	var ctr uint32 = 1 // track expected chunk counter

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
		// decrypt the chunk with AAD verification
		aad := make([]byte, 4)
		binary.LittleEndian.PutUint32(aad, ctr)
		ctr++
		var pbuf []byte
		if pbuf, err = gcm.Open(cbuf[:0], ch.nonce, cbuf, aad); err != nil {
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
func writeHeader(w io.Writer) error {
	h := header{}
	h.init()
	return h.write(w)
}
