# cryptod

[![CI](https://github.com/wiggin77/cryptod/actions/workflows/ci.yml/badge.svg)](https://github.com/wiggin77/cryptod/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/wiggin77/cryptod)](https://goreportcard.com/report/github.com/wiggin77/cryptod)
[![GoDoc](https://godoc.org/github.com/wiggin77/cryptod?status.svg)](https://godoc.org/github.com/wiggin77/cryptod)

A Go library for **AES-256-GCM authenticated encryption** of arbitrarily large data streams. Designed for encrypting files, database backups, logs, or any large dataset without loading everything into memory.

## Features

✅ **Memory Efficient** - Processes data in 1MB chunks, handles files of any size

✅ **Authenticated Encryption** - AES-256-GCM with chunk sequence integrity protection

✅ **Secure by Design** - Protection against chunk reordering, deletion, and duplication attacks

✅ **Streaming API** - Works with any `io.Reader` and `io.Writer`

✅ **Simple API** - Two functions: `Encrypt()` and `Decrypt()`

✅ **Well Tested** - Comprehensive unit tests and security tests

✅ **Production Ready** - Battle-tested cryptographic primitives from Go's standard library

## Installation

```bash
go get github.com/wiggin77/cryptod
```

## Quick Start

### Encrypting Data

```go
package main

import (
    "os"
    "github.com/wiggin77/cryptod"
)

func main() {
    // Open input file
    input, _ := os.Open("document.pdf")
    defer input.Close()

    // Create output file
    output, _ := os.Create("document.pdf.encrypted")
    defer output.Close()

    // Encrypt with a secret key
    key := "your-secret-key-here"
    err := cryptod.Encrypt(input, output, key)
    if err != nil {
        panic(err)
    }
}
```

### Decrypting Data

```go
package main

import (
    "os"
    "github.com/wiggin77/cryptod"
)

func main() {
    // Open encrypted file
    input, _ := os.Open("document.pdf.encrypted")
    defer input.Close()

    // Create output file
    output, _ := os.Create("document.pdf")
    defer output.Close()

    // Decrypt with the same key
    key := "your-secret-key-here"
    err := cryptod.Decrypt(input, output, key)
    if err != nil {
        panic(err)
    }
}
```

## API Documentation

### `Encrypt(r io.Reader, w io.Writer, skey string) error`

Reads data from `r`, encrypts it using AES-256-GCM with the provided key, and writes the encrypted data to `w`.

**Key Recommendations:**
- Use unique keys per file/stream for maximum security
- Consider combining a master secret with a file identifier: `key = secret + filepath`
- Keys are hashed with SHA-512/256 to produce the 32-byte AES key

**Example with unique keys:**
```go
masterSecret := "my-master-secret"
filePath := "/path/to/file.dat"
key := masterSecret + filePath  // Unique key per file

cryptod.Encrypt(input, output, key)
```

### `Decrypt(r io.Reader, w io.Writer, skey string) error`

Reads encrypted data from `r`, decrypts it, and writes the plaintext to `w`. Returns an error if:
- The key is incorrect
- The data has been tampered with
- Chunks have been reordered, deleted, or duplicated

## How It Works

### Architecture

1. **Header**: Contains magic bytes, scheme identifier (`aes256gcm`), and version
2. **Chunked Encryption**: Data is split into 1MB chunks, each encrypted independently
3. **Chunk Headers**: Each chunk has metadata (nonce, encrypted size)
4. **AAD Protection**: Additional Authenticated Data binds chunk sequence numbers, preventing reordering attacks
5. **Tomb Marker**: Special marker indicates end of stream

### Security Features

- **AES-256-GCM**: Industry-standard authenticated encryption
- **Unique Nonces**: 12-byte nonces (5-byte counter + 7-byte random) ensure uniqueness
- **Chunk Integrity**: AAD with sequence numbers prevents chunk manipulation
- **Authentication**: GCM tag verifies both confidentiality and integrity
- **Memory Safe**: No buffer overflows, constant-time operations

### File Format

```
[Header][Chunk1 Header][Chunk1 Data][Chunk2 Header][Chunk2 Data]...[Tomb]
```

## Example CLI Tool

A command-line tool demonstrating library usage is included at [`example/cmd/crypt`](example/cmd/crypt).

**Usage:**
```bash
# Encrypt a file
CRYPTOD_KEY="my-secret" ./example/cmd/crypt/crypt -e -in=file.txt -out=file.txt.aes

# Decrypt a file
CRYPTOD_KEY="my-secret" ./example/cmd/crypt/crypt -d -in=file.txt.aes -out=file.txt
```

**Note**: The CLI requires the key via the `CRYPTOD_KEY` environment variable for security (keys in command-line arguments are visible in process lists).

For build instructions, see the [Development](#development) section below.

## Use Cases

- **File Encryption**: Encrypt sensitive files before storing or transmitting
- **Backup Encryption**: Encrypt database dumps and backups
- **Log Encryption**: Encrypt log files for compliance
- **Stream Processing**: Encrypt data streams in real-time
- **Cloud Storage**: Encrypt data before uploading to cloud storage
- **Data Export**: Encrypt exported data for secure transfer

## Performance

- **Throughput**: Handles gigabyte-sized files efficiently
- **Memory Usage**: Fixed ~2MB overhead (1MB plaintext buffer + 1MB ciphertext buffer)
- **Chunk Size**: 1MB default (configurable in source)

## Security Considerations

### Key Management

- **Never hardcode keys** in source code
- Use environment variables, key management services (KMS), or secure vaults
- Rotate keys periodically
- Consider using unique keys per file/dataset

### Key Derivation

The library uses SHA-512/256 for key derivation. For password-based encryption:
- Use strong, unique passwords
- Consider implementing additional key derivation (PBKDF2, Argon2) for user passwords
- The current implementation is optimized for cryptographic keys, not user passwords

## Development

### Running Tests

The library includes comprehensive unit tests and security tests.

```bash
# Run all tests
go test ./...

# Or use make
make test

# Run tests with race detector
make test-race

# Run security tests
make test-security

# Generate coverage report
make test-cover
```

See [crypto_test.go](crypto_test.go), [security_test.go](security_test.go), and [example/cmd/crypt/cli_security_test.go](example/cmd/crypt/cli_security_test.go) for test examples.

### Code Quality

```bash
# Format code
make fmt

# Check formatting
make check-fmt

# Run go vet
make vet

# Run linter
make lint

# Run all checks (format, vet, lint, test)
make check
```

### Building the CLI

```bash
# Build the crypt CLI tool
make build-cli

# Install to $GOBIN
make install-cli
```
