package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// tempFilename returns a filename that is unique
// and unused in the `dir` directory at the time
// this method is called.
func tempFilename(dir string, prefix string) string {
	b := make([]byte, 8)
	var fname string
	var count int

	for {
		io.ReadFull(rand.Reader, b)
		fname = prefix + hex.EncodeToString(b)
		fspec := filepath.Join(dir, fname)
		if _, err := os.Stat(fspec); err != nil {
			break
		}
		count++
		if count > 1000 {
			panic(fmt.Errorf("cannot create tmp filename in dir `%s`", dir))
		}
	}
	return fname
}
