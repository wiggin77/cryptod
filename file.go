package cryptod

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// EncryptFile encrypts a file and writes the encrypted contents to another file.
// The input file's mode is preserved in the output file.
//
// The key should be unique for each input file, otherwise potential repetition
// of the block key + nonce could weaken the cipher.  A simple way of ensuring
// this is to use a key comprised of concatenated secret and filespec.
//
// The file name of the input file is encrypted and stored in the output file,
// and is returned when decrypting.
//
// Uses AES256 encryption and GCM authentication on chunks of size up to 1MB.
func EncryptFile(fileIn string, fileOut string, skey string) error {
	var err error
	// make paths absolute
	if fileIn, fileOut, err = absPath(fileIn, fileOut); err != nil {
		return err
	}

	var fin *os.File
	if fin, err = os.Open(fileIn); err != nil {
		return err
	}
	defer fin.Close()

	// get the mode so it can be applied to the output file.
	fi, err := fin.Stat()
	if err != nil {
		return err
	}
	fmode := fi.Mode()

	var fout *os.File
	flags := os.O_RDWR | os.O_CREATE | os.O_TRUNC
	if fout, err = os.OpenFile(fileOut, flags, fmode); err != nil {
		return err
	}
	defer fout.Close()

	// need input filename to store in encrypted file
	_, name := filepath.Split(fileIn)
	if err = Encrypt(fin, fout, skey, []byte(name)); err != nil {
		fout.Close()
		os.Remove(fileOut)
		return err
	}
	return fout.Sync()
}

// DecryptFile decrypts a file and writes the plaintext contents to another file.
// If `fileOut` is the empty string then the new plaintext file will use the original
// filename stored in the encrypted input file.
// The original filename is returned or any error that was encountered.
func DecryptFile(fileIn string, fileOut string, skey string) (string, error) {
	var err error

	// make paths absolute
	if fileIn, fileOut, err = absPath(fileIn, fileOut); err != nil {
		return "", err
	}

	var fin *os.File
	if fin, err = os.Open(fileIn); err != nil {
		return "", err
	}
	defer fin.Close()

	// use temp file name if `fileOut` is empty.
	var bTempUsed bool
	if len(fileOut) == 0 {
		bTempUsed = true
		fileOut = tempFilename(filepath.Dir(fileIn))
	}

	var fout *os.File
	if fout, err = os.Create(fileOut); err != nil {
		return "", err
	}
	defer fout.Close()

	var name []byte
	if name, err = Decrypt(fin, fout, skey); err != nil {
		fout.Close()
		os.Remove(fileOut)
		return "", err
	}
	if err = syncClose(fout); err != nil {
		return "", err
	}

	if bTempUsed {
		// rename output file to original
		fname := string(name)
		fname = filepath.Join(filepath.Dir(fileIn), fname)
		fout.Close()
		return fname, os.Remove(fileOut)
	}
	return string(name), nil
}

// absPath combines two calls to `filepath.Abs` into one.
func absPath(a string, b string) (string, string, error) {
	var err error
	if a, err = filepath.Abs(a); err != nil {
		return a, b, err
	}
	if b, err = filepath.Abs(b); err != nil {
		return a, b, err
	}
	return a, b, nil
}

// syncClose does an fsync and close on a file.
func syncClose(f *os.File) error {
	var s string
	if err := f.Sync(); err != nil {
		s += err.Error() + "; "
	}
	if err := f.Close(); err != nil {
		s += err.Error()
	}
	if len(s) > 0 {
		return errors.New(s)
	}
	return nil
}

// tempFilename returns a filename that is unique
// and unused in the `dir` directory at the time
// this method is called.
func tempFilename(dir string) string {
	b := make([]byte, 8)
	var fname string
	var count int

	for {
		io.ReadFull(rand.Reader, b)
		fname = "dal" + hex.EncodeToString(b)
		fspec := filepath.Join(dir, fname)
		if _, err := os.Stat(fspec); err == nil {
			break
		}
		count++
		if count > 1000 {
			panic(fmt.Errorf("cannot create tmp filename in dir `%s`", dir))
		}
	}
	return fname
}
