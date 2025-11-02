// Package main_test provides a simple test of the cryptod sample app.
//go:build linux
// +build linux

package main_test

import (
	"fmt"
	"os"
	"os/exec"
	"testing"
)

const (
	fPlain     = "testdata.txt"
	fEncrypted = "testdata.txt.aes"
	fDecrypted = "testdata.txt.txt"
	key        = "my little secret"
)

func TestEncryptDecrypt(t *testing.T) {
	// create plaintext file.
	pbuf := generatePlainText(1024 * 1000 * 2)
	w, err := os.Create(fPlain)
	if err != nil {
		t.Error("cannot create plaintext file: ", err)
		return
	}
	defer func() { w.Close(); os.Remove(fPlain) }()
	_, err = w.Write(pbuf)
	if err != nil {
		t.Error("cannot write to plaintext file: ", err)
		return
	}
	w.Close()

	wdir, err := os.Getwd()
	fmt.Println("working dir: ", wdir)

	// encrypt it
	defer os.Remove(fEncrypted)
	cmd := exec.Command("/bin/sh", "crypt", "-e", "-f", "-in="+fPlain, "-out="+fEncrypted, "-key="+key)
	err = cmd.Run()
	if err != nil {
		t.Error("error encrypting: ", err)
		return
	}

	// decrypt it
	defer os.Remove(fDecrypted)
	cmd = exec.Command("/bin/sh", "crypt", "-d", "-f", "-in="+fEncrypted, "-out="+fDecrypted, "-key="+key)
	err = cmd.Run()
	if err != nil {
		t.Error("error decrypting: ", err)
		return
	}

	// compare results
	cmd = exec.Command("cmp", "-s", fPlain, fDecrypted)
	err = cmd.Run()
	if err != nil {
		t.Error("error comparing: ", err)
	}
}

// helper to generate predicable plaintext of requested size
func generatePlainText(size int) []byte {
	const s = "0123456789"
	src := []byte(s)
	section := make([]byte, size)

	for i := range section {
		section[i] = src[i%len(s)]
	}
	return section
}
