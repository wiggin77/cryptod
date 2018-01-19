package main

import (
	"os"

	"github.com/wiggin77/cryptod"
)

// cmd encrypts or decrypts a file
func cmd(encrypt bool, fileIn string, fileOut string, skey string) error {

	r, err := os.Open(fileIn)
	if err != nil {
		return err
	}
	defer r.Close()

	// get the mode so it can be applied to the output file.
	fi, err := r.Stat()
	if err != nil {
		return err
	}
	fmode := fi.Mode()

	// create output file, overwriting if it exists
	w, err := os.Create(fileOut)
	if err != nil {
		return err
	}
	defer w.Close()

	// copy fileIn mode to output file
	if err := w.Chmod(fmode); err != nil {
		return err
	}

	if encrypt {
		err = cryptod.Encrypt(r, w, skey)
	} else {
		err = cryptod.Decrypt(r, w, skey)
	}

	if err != nil {
		w.Close()
		os.Remove(fileOut)
	}
	return err
}
