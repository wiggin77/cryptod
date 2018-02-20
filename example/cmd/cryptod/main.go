package main

import (
	"flag"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/wiggin77/cryptod"
)

const usageMessage = "\n" +
	`Usage of 'cryptod'
 - encrypt a file:
	cryptod -e -in=plaintext.txt -out=crypttext.txt.aes -key=this_is_a_secret
 - decrypt a file:
	cryptod -d -in=crypttext.txt.aes -out=plaintext.txt -key=this_is_a_secret
	cryptod -d -in=crypttext.txt.aes -key=this_is_a_secret

Notes:
  - when decrypting, 'out' may be omitted and the original 
    filename will be used
  - spaces must be escaped
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
	flag.StringVar(&fileOut, "out", "", "output file (optional when decrypting)")
	flag.StringVar(&skey, "key", "", "secret key")
	flag.BoolVar(&forceOverwrite, "f", false, "force overwrite of output file")
}

func main() {
	flag.Usage = help
	flag.Parse()

	// need exactly one of `e` or `d`
	if (modeEncrypt && modeDecrypt) || (!modeEncrypt && !modeDecrypt) {
		printError("invalid mode")
		handleError(nil, true)
	}

	// expand tilde to user's home dir, and make both paths absolute.
	fileIn = expandTilde(fileIn)
	fileOut = expandTilde(fileOut)
	var err error
	if fileIn, fileOut, err = cryptod.AbsPath(fileIn, fileOut); err != nil {
		handleError(err, false)
	}

	// need an input file and it must exist
	if _, err := os.Stat(fileIn); os.IsNotExist(err) {
		printError("input file does not exist: ", fileIn)
		handleError(nil, false)
	}

	// need a key
	if skey == "" {
		printError("missing secret key")
		handleError(nil, false)
	}

	// output file can be infered when encrypting
	if len(fileOut) == 0 && modeEncrypt {
		fileOut = fileIn + ".aes"
	}

	// output file should not exist (unless force overwrite flag is present)
	if len(fileOut) > 0 {
		if _, err := os.Stat(fileOut); err == nil && !forceOverwrite {
			printError("output file exists without force overwrite: ", fileOut)
			handleError(nil, false)
		}
	}

	err = cmd(modeEncrypt, fileIn, fileOut, skey)
	if err != nil {
		printError(err)
		os.Exit(1)
	}
}

func handleError(err error, showUsage bool) {
	if err != nil {
		printError(err)
	}
	if showUsage {
		help()
	}
	os.Exit(2)
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
