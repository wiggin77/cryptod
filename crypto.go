package cryptod

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	// ChunkSize is the maximum size of an individual chunk in the encrypted stream.
	ChunkSize = 1024 * 1000
)

// Encrypt reads chunks of data from `r` writes the encrypted contents to `w`
// based on the specified key. Reading continues until io.EOF.
//
// The key should be unique for each io.Reader instance.
// For example, when encrypting files `skey` can be a secret plus the filespec
// to ensure the key is unique for each file.
//
// Extra data, up to `ChunkSize` (1MB), can be encrypted with the stream, and will
// be returned when decrypted.
//
// Uses AES256 encryption and GCM authentication on chunks of size up to 1MB.
func Encrypt(reader io.Reader, writer io.Writer, skey string, extra []byte) error {
	if len(extra) > ChunkSize {
		return fmt.Errorf("extra data too big (len=%d), must be less than %d bytes",
			len(extra), ChunkSize)
	}
	br := bufio.NewReader(reader)
	bw := bufio.NewWriter(writer)
	defer bw.Flush()

	// TODO: allow additonal ciphers... which ones?
	gcm, err := getGCM(skey, schemeAES256GCM)
	if err != nil {
		return err
	}

	// reuse buffers to reduce GC
	pbuf := make([]byte, ChunkSize)
	nonce := make([]byte, gcm.NonceSize())
	cbuf := make([]byte, len(pbuf)+gcm.Overhead())
	var ctr uint32 = 1

	for {
		var n int
		var readErr error
		var ct chunkType
		if len(extra) > 0 {
			// write the extra data first, but only once
			n = copy(pbuf, extra)
			ct = chunkTypeExtra
			readErr = nil
			extra = nil
		} else {
			n, readErr = br.Read(pbuf)
			ct = chunkTypeData
		}
		if n > 0 {
			// randomize the nonce
			if _, err := io.ReadFull(rand.Reader, nonce[binary.MaxVarintLen32:]); err != nil {
				return err
			}
			binary.PutUvarint(nonce, uint64(ctr))
			ctr++
			// encrypt and authenticate
			p := pbuf[:n]
			c := gcm.Seal(cbuf[:0], nonce, p, nil)
			var clen = uint32(len(c))
			if clen > 0 {
				// write a chunk header containing actual encrypted block size
				if err := writeChunkHeader(chunkHeader{ct: ct, st: schemeAES256GCM, nonce: nonce, dataSize: clen}, bw); err != nil {
					return err
				}
				// write encrypted data to output steam
				if _, err := bw.Write(c); err != nil {
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
	return writeChunkHeader(chunkHeader{ct: chunkTypeTomb, st: schemeAES256GCM, nonce: nonce, dataSize: 0}, bw)
}

type readCtx struct {
	gcm cipher.AEAD
	st  schemeType
	br  *bufio.Reader
	buf []byte
}

// Decrypt reads chunks of data from `r` and writes the decrypted
// chunks to `w` using the specified key. Reading continues until io.EOF.
// Returns any extra data included in the steam, or error.
func Decrypt(reader io.Reader, writer io.Writer, skey string) ([]byte, error) {
	var err error
	var extra []byte
	rctx := readCtx{}
	if rctx.gcm, err = getGCM(skey, schemeAES256GCM); err != nil {
		return extra, err
	}
	rctx.st = schemeAES256GCM
	rctx.br = bufio.NewReader(reader)
	bw := bufio.NewWriter(writer)
	defer bw.Flush()

	maxChunkSize := ChunkSize + rctx.gcm.Overhead()
	maxChunkSizeSanity := maxChunkSize * 2

	// reuse buffer to reduce GC
	rctx.buf = make([]byte, maxChunkSize)

	for {
		// read next chunk header
		var ch chunkHeader
		ch, err = readChunkHeader(rctx.br, maxChunkSizeSanity)
		if err != nil && ch.ct != chunkTypeTomb {
			return extra, err
		}
		// tomb chunk header means we're done
		if ch.ct == chunkTypeTomb {
			break
		}
		// check if scheme changed and is supported.
		if ch.st != rctx.st {
			if rctx.gcm, err = getGCM(skey, ch.st); err != nil {
				return extra, err
			}
			rctx.st = ch.st
		}
		// read and decrypt
		var pbuf []byte
		if pbuf, err = readEncryptedChunk(rctx, ch); err != nil {
			return extra, err
		}
		rctx.buf = pbuf // re-use the possibly resized buffer

		// handle chunk type
		switch ch.ct {
		case chunkTypeExtra:
			extra = append(extra, pbuf...)
		case chunkTypeData:
			// write plaintext to w
			if _, err := bw.Write(pbuf); err != nil {
				return extra, err
			}
		default:
			return extra, fmt.Errorf("invalid chunk type: %d", ch.ct)
		}
	}
	return extra, nil
}

// readEncryptedChunk reads and decrypts a chunk of data.
func readEncryptedChunk(rctx readCtx, ch chunkHeader) ([]byte, error) {
	// ensure buf is big enough; ch.dataSize already sanity checked in readChunkHeader
	buf := rctx.buf
	size := int(ch.dataSize)
	if cap(buf) < size {
		buf = make([]byte, size)
	}

	var pbuf []byte
	if size > 0 {
		// read the encrypted chunk
		var err error
		cbuf := buf[:size]
		n, err := rctx.br.Read(cbuf)
		if err != nil && err != io.EOF {
			return nil, err
		}
		if n != size {
			return buf, fmt.Errorf("wrong chunk size read, expected %d, got %d", size, n)
		}
		// decrypt the chunk
		if pbuf, err = rctx.gcm.Open(cbuf[:0], ch.nonce, cbuf, nil); err != nil {
			return nil, err
		}
	} else {
		pbuf = buf[0:0]
	}
	return pbuf, nil
}

// getGCM returns a block cipher wrapped in GCM.
func getGCM(skey string, st schemeType) (cipher.AEAD, error) {
	switch st {
	case schemeAES256GCM:
		return getAES256GCM(skey)
		// TODO: support more ciphers?
	}
	return nil, fmt.Errorf("unsupported scheme: %d", st)
}

// getAES256GCM returns a AES256 block cipher wrapped in GCM.
func getAES256GCM(skey string) (cipher.AEAD, error) {
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
