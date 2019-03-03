package main

import (
	"flag"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
)

const usageMessage = "\n" +
	`Usage of 'crypt'
 - encrypt a file:
	crypt -e -in=plaintext.txt -out=crypttext.txt.aes -key=this_is_a_secret
 - decrypt a file:
	crypt -d -in=crypttext.txt.aes -out=plaintext.txt -key=this_is_a_secret
 note: spaces must be escaped
`

var (
	modeEncrypt    bool
	modeDecrypt    bool
	fileIn         string
	fileOut        string
	skey           string
	forceOverwrite bool
)

func init() {
	flag.BoolVar(&modeEncrypt, "e", false, "encryption mode")
	flag.BoolVar(&modeDecrypt, "d", false, "decryption mode")
	flag.StringVar(&fileIn, "in", "", "input file")
	flag.StringVar(&fileOut, "out", "", "output file")
	flag.StringVar(&skey, "key", "", "secret key")
	flag.BoolVar(&forceOverwrite, "f", false, "force overwrite of output file")
}

func main() {
	flag.Usage = help
	flag.Parse()

	// need exactly one of `e` or `d`
	if (modeEncrypt && modeDecrypt) || (!modeEncrypt && !modeDecrypt) {
		printError("invalid mode")
		flag.Usage()
	}

	fileIn = expandTilde(fileIn)
	fileOut = expandTilde(fileOut)

	// need an input file and it must exist
	if _, err := os.Stat(fileIn); os.IsNotExist(err) {
		printError("input file does not exist: ", fileIn)
		flag.Usage()
	}

	// need a key
	if skey == "" {
		printError("missing secret key")
		flag.Usage()
	}

	// output file can be infered
	if fileOut == "" {
		fileOut = inferOutputFile(modeEncrypt, fileIn)
	}

	// output file should not exist (unless force overwrite flag is present)
	if _, err := os.Stat(fileOut); err == nil && !forceOverwrite {
		printError("output file exists without force overwrite: ", fileOut)
		flag.Usage()
	}

	err := cmd(modeEncrypt, fileIn, fileOut, skey)
	if err != nil {
		printError(err)
		os.Exit(1)
	}
}

func help() {
	fmt.Fprintln(os.Stderr, usageMessage)
	fmt.Fprintln(os.Stderr, "Flags:")
	flag.PrintDefaults()
	os.Exit(2)
}

func printError(a ...interface{}) {
	fmt.Fprint(os.Stderr, "error -- ")
	fmt.Fprintln(os.Stderr, a...)
}

// infers best fileOut name based on mode and fileIn
func inferOutputFile(encrypt bool, fileIn string) string {
	if encrypt {
		return fileIn + ".aes"
	}

	// for decrypting, if file ends in aes then just strip the extension.
	if strings.HasSuffix(fileIn, ".aes") {
		return strings.TrimSuffix(fileIn, ".aes")
	}

	// just add plaintext extension
	return fileIn + ".plain"
}

// expands a path beginning with "~/" to include user's home dir.
func expandTilde(file string) string {
	if !strings.HasPrefix(file, "~/") {
		return file
	}

	usr, err := user.Current()
	if err != nil {
		return file
	}
	return filepath.Join(usr.HomeDir, file[2:])
}
