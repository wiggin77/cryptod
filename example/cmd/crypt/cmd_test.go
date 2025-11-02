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
	wdir, err := os.Getwd()
	if err != nil {
		t.Error("cannot get working directory: ", err)
		return
	}
	fmt.Println("working dir: ", wdir)

	// Build the crypt binary first
	buildCmd := exec.Command("go", "build", "-o", "crypt", ".")
	buildCmd.Dir = wdir
	if output, err := buildCmd.CombinedOutput(); err != nil {
		t.Errorf("cannot build crypt binary: %v\nOutput: %s", err, output)
		return
	}
	defer os.Remove("crypt") // Clean up the binary after the test

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

	// encrypt it
	defer os.Remove(fEncrypted)
	cmd := exec.Command("./crypt", "-e", "-f", "-in="+fPlain, "-out="+fEncrypted)
	cmd.Env = append(os.Environ(), "CRYPTOD_KEY="+key)
	err = cmd.Run()
	if err != nil {
		t.Error("error encrypting: ", err)
		return
	}

	// decrypt it
	defer os.Remove(fDecrypted)
	cmd = exec.Command("./crypt", "-d", "-f", "-in="+fEncrypted, "-out="+fDecrypted)
	cmd.Env = append(os.Environ(), "CRYPTOD_KEY="+key)
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
