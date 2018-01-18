// Package cryptod provides AES256-GCM encryption and decryption of arbitrarily large
// sets of data. For example this package can be used to encrypt/decrypt files.
//
// Data is read/written in chunks when encrypting and decrypting therefore the whole data set
// does not need to reside in memory.
//
// To encrypt data, provide an io.Reader interface to the plaintext data and call crypto.Encrypt:
//  plaintext := bytes.NewReader([]byte("my secret data"))
//  cryptbuf := bytes.Buffer{}
//  err := Encrypt(plaintext, cryptbuf, "secret_key")
//
// To decrypt the data, provide an io.Reader interface to the encrypted data and call crypto.Decrypt:
//  plainbuf := bytes.Buffer{}
//  err := Decrypt(cryptbuf, plainbuf, "secret_key")
package cryptod
