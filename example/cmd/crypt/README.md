# crypt example

Simple command line utility using [cryptod](https://github.com/wiggin77/cryptod) to encrypt and decrypt files using AES256-GCM.

## Usage

Run script [cmd](https://github.com/wiggin77/cryptod/blob/master/example/cmd/crypt/crypt).

```Bash
Usage of 'crypt'
 - encrypt a file:
  crypt -e -in=plaintext.txt -out=crypttext.txt.aes -key=this_is_a_secret
 - decrypt a file:
  crypt -d -in=crypttext.txt.aes -out=plaintext.txt -key=this_is_a_secret
 note: spaces must be escaped

Flags:
  -d  decryption mode
  -e  encryption mode
  -f  force overwrite of output file
  -in string
      input file
  -key string
      secret key
  -out string
      output file
```
