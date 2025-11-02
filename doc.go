// Package cryptod provides AES256-GCM encryption and decryption of arbitrarily large
// sets of data. For example this package can be used to encrypt/decrypt files.
//
// Data is read/written in chunks when encrypting and decrypting therefore the whole data set
// will not reside in memory at once.
//
// To encrypt data, provide an io.Reader interface to the plaintext data and an io.Writer which
// will receive the encrypted data:
//
//	plaintext := bytes.NewReader([]byte("my secret data"))
//	cryptbuf := bytes.Buffer{}
//	err := Encrypt(plaintext, cryptbuf, "secret_key")
//
// To decrypt the data, provide an io.Reader interface to the encrypted data and an io.Writer which
// will receive the plaintext:
//
//	plainbuf := bytes.Buffer{}
//	err := Decrypt(cryptbuf, plainbuf, "secret_key")
package cryptod
