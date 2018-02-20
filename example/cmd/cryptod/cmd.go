package main

import (
	"os"
	"path/filepath"

	"github.com/wiggin77/cryptod"
)

// cmd encrypts or decrypts a file
func cmd(encrypt bool, fileIn string, fileOut string, skey string) error {

	if encrypt {
		_, name := filepath.Split(fileIn)
		return cryptod.EncryptFile(fileIn, fileOut, skey, []byte(name))
	}

	var bTempUsed bool
	if len(fileOut) == 0 {
		bTempUsed = true
		fileOut = tempFilename(filepath.Dir(fileIn), "dal-")
	}

	var err error
	var extra []byte
	if extra, err = cryptod.DecryptFile(fileIn, fileOut, skey); err != nil {
		return err
	}

	if bTempUsed {
		fspec := filepath.Join(filepath.Dir(fileOut), string(extra))
		return os.Rename(fileOut, fspec)
	}
	return nil
}
