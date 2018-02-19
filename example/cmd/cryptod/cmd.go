package main

import (
	"github.com/wiggin77/cryptod"
)

// cmd encrypts or decrypts a file
func cmd(encrypt bool, fileIn string, fileOut string, skey string) error {

	if encrypt {
		return cryptod.EncryptFile(fileIn, fileOut, skey)
	}

	var err error
	_, err = cryptod.DecryptFile(fileIn, fileOut, skey)
	return err
}
