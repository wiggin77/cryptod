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
	CRYPTOD_KEY=this_is_a_secret crypt -e -in=plaintext.txt -out=crypttext.txt.aes
 - decrypt a file:
	CRYPTOD_KEY=this_is_a_secret crypt -d -in=crypttext.txt.aes -out=plaintext.txt

 The encryption key must be provided via the CRYPTOD_KEY environment variable.
 WARNING: Never pass keys as command-line arguments - they will be visible in
 process lists and shell history!
`

var (
	modeEncrypt    bool
	modeDecrypt    bool
	fileIn         string
	fileOut        string
	forceOverwrite bool
)

func init() {
	flag.BoolVar(&modeEncrypt, "e", false, "encryption mode")
	flag.BoolVar(&modeDecrypt, "d", false, "decryption mode")
	flag.StringVar(&fileIn, "in", "", "input file")
	flag.StringVar(&fileOut, "out", "", "output file")
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

	// get key from environment variable
	skey := os.Getenv("CRYPTOD_KEY")
	if skey == "" {
		printError("missing secret key - set CRYPTOD_KEY environment variable")
		flag.Usage()
	}

	// output file can be inferred
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
	fmt.Fprint(os.Stderr, usageMessage)
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
