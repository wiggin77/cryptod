package cryptod

import (
	"errors"
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
// Extra data can be included, such as original filename or any other info, and
// will be encrypted with the output file. The extra data will be returned when
// decrypting.
//
// Uses AES256 encryption and GCM authentication on chunks of size up to 1MB.
func EncryptFile(fileIn string, fileOut string, skey string, extra []byte) error {
	var err error
	// make paths absolute
	if fileIn, fileOut, err = AbsPath(fileIn, fileOut); err != nil {
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

	if err = Encrypt(fin, fout, skey, extra); err != nil {
		fout.Close()
		os.Remove(fileOut)
		return err
	}
	return fout.Sync()
}

// DecryptFile decrypts a file and writes the plaintext contents to another file.
// Any extra data encrypted with the file it returned.
func DecryptFile(fileIn string, fileOut string, skey string) ([]byte, error) {
	var err error
	var extra []byte

	// make paths absolute
	if fileIn, fileOut, err = AbsPath(fileIn, fileOut); err != nil {
		return extra, err
	}

	var fin *os.File
	if fin, err = os.Open(fileIn); err != nil {
		return extra, err
	}
	defer fin.Close()

	var fout *os.File
	if fout, err = os.Create(fileOut); err != nil {
		return extra, err
	}
	defer fout.Close()

	if extra, err = Decrypt(fin, fout, skey); err != nil {
		fout.Close()
		os.Remove(fileOut)
		return extra, err
	}
	return extra, SyncClose(fout)
}

// AbsPath combines two calls to `filepath.Abs` into one.
func AbsPath(a string, b string) (string, string, error) {
	var err error
	if a, err = filepath.Abs(a); err != nil {
		return a, b, err
	}
	if b, err = filepath.Abs(b); err != nil {
		return a, b, err
	}
	return a, b, nil
}

// SyncClose does an fsync and close on a file.
func SyncClose(f *os.File) error {
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
