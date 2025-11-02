package main

import (
	"fmt"
	"os"

	"github.com/wiggin77/cryptod"
)

// cmd encrypts or decrypts a file
func cmd(encrypt bool, fileIn string, fileOut string, skey string) error {

	r, err := os.Open(fileIn)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := r.Close(); closeErr != nil {
			fmt.Fprintf(os.Stderr, "warning: error closing input file: %v\n", closeErr)
		}
	}()

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
	defer func() {
		if closeErr := w.Close(); closeErr != nil {
			fmt.Fprintf(os.Stderr, "warning: error closing output file: %v\n", closeErr)
		}
	}()

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
		if closeErr := w.Close(); closeErr != nil {
			fmt.Fprintf(os.Stderr, "warning: error closing output file during cleanup: %v\n", closeErr)
		}
		if removeErr := os.Remove(fileOut); removeErr != nil {
			fmt.Fprintf(os.Stderr, "warning: error removing output file during cleanup: %v\n", removeErr)
		}
	}
	return err
}
