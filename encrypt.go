package aes

import (
	"crypto/sha512"
	"crypto/aes"
	"io"
)

func Encrypt(r io.Reader, w io.Writer, skey string) error {
	plainbuf := make([]byte, aes.BlockSize)
	
	// key must be hashed to 32 bytes for AES256
	h := sha512.New512_256()
	key := h.Sum([]byte(skey))	

	// create sha512 of the plaintext file contents 
	h = sha512.New()
	//  -- use h.Write([]byte) to add bytes to the hash. Use h.Sum(nil) to fetch the 64 byte hash.

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	cipherbuf := make([]byte, aes.BlockSize+len(plainbuf))
}
