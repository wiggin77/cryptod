package cryptod

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// TestChunkReordering demonstrates the chunk sequence integrity vulnerability.
// This test shows that encrypted chunks can be reordered without detection,
// violating the integrity guarantees expected from authenticated encryption.
func TestChunkReordering(t *testing.T) {
	// Create test data with distinct chunks
	plaintext := []byte("AAAA" + string(make([]byte, 1024*1000-4)) + "BBBB" + string(make([]byte, 1024*1000-4)))
	key := "test_secret_key"

	// Encrypt the data
	var encrypted bytes.Buffer
	err := Encrypt(bytes.NewReader(plaintext), &encrypted, key)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	encryptedData := encrypted.Bytes()

	// Parse the encrypted stream to find chunk boundaries
	chunks, header, tomb := parseEncryptedStream(t, encryptedData)

	if len(chunks) < 2 {
		t.Skip("Test requires at least 2 chunks, data too small")
	}

	// Reorder chunks: swap chunk 0 and chunk 1
	reordered := bytes.Buffer{}
	reordered.Write(header)
	reordered.Write(chunks[1]) // Write second chunk first
	reordered.Write(chunks[0]) // Write first chunk second
	reordered.Write(tomb)

	// Attempt to decrypt the reordered data
	var decrypted bytes.Buffer
	err = Decrypt(&reordered, &decrypted, key)

	// VULNERABILITY: Decryption should fail but succeeds
	if err != nil {
		t.Logf("Good: Decryption rejected reordered chunks (vulnerability fixed)")
	} else {
		decryptedData := decrypted.Bytes()
		if !bytes.Equal(plaintext, decryptedData) {
			t.Logf("VULNERABILITY CONFIRMED: Chunk reordering was not detected!")
			t.Logf("Decryption succeeded with corrupted output")
			t.Logf("Original length: %d, Decrypted length: %d", len(plaintext), len(decryptedData))
		} else {
			t.Logf("Unexpected: Decryption produced correct output despite reordering")
		}
	}
}

// TestChunkDeletion demonstrates that encrypted chunks can be deleted without detection.
func TestChunkDeletion(t *testing.T) {
	// Create test data with 3 distinct chunks
	chunkSize := 1024 * 1000
	plaintext := make([]byte, chunkSize*3)
	for i := 0; i < chunkSize; i++ {
		plaintext[i] = 'A'
		plaintext[chunkSize+i] = 'B'
		plaintext[2*chunkSize+i] = 'C'
	}
	key := "test_secret_key"

	// Encrypt the data
	var encrypted bytes.Buffer
	err := Encrypt(bytes.NewReader(plaintext), &encrypted, key)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	encryptedData := encrypted.Bytes()

	// Parse the encrypted stream
	chunks, header, tomb := parseEncryptedStream(t, encryptedData)

	if len(chunks) < 3 {
		t.Skip("Test requires at least 3 chunks")
	}

	// Delete the middle chunk
	modified := bytes.Buffer{}
	modified.Write(header)
	modified.Write(chunks[0]) // First chunk
	// Skip chunks[1] - DELETE MIDDLE CHUNK
	modified.Write(chunks[2]) // Third chunk
	modified.Write(tomb)

	// Attempt to decrypt
	var decrypted bytes.Buffer
	err = Decrypt(&modified, &decrypted, key)

	// VULNERABILITY: Should detect missing chunk but doesn't
	if err != nil {
		t.Logf("Good: Decryption rejected modified data (vulnerability fixed)")
	} else {
		t.Logf("VULNERABILITY CONFIRMED: Chunk deletion was not detected!")
		t.Logf("Expected length: %d, Got: %d", len(plaintext), decrypted.Len())
		t.Logf("Data loss: %d bytes", len(plaintext)-decrypted.Len())
	}
}

// TestChunkDuplication demonstrates that chunks can be duplicated without detection.
func TestChunkDuplication(t *testing.T) {
	// Create test data
	chunkSize := 1024 * 1000
	plaintext := make([]byte, chunkSize*2)
	for i := 0; i < chunkSize; i++ {
		plaintext[i] = 'A'
		plaintext[chunkSize+i] = 'B'
	}
	key := "test_secret_key"

	// Encrypt the data
	var encrypted bytes.Buffer
	err := Encrypt(bytes.NewReader(plaintext), &encrypted, key)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	encryptedData := encrypted.Bytes()

	// Parse the encrypted stream
	chunks, header, tomb := parseEncryptedStream(t, encryptedData)

	if len(chunks) < 2 {
		t.Skip("Test requires at least 2 chunks")
	}

	// Duplicate the first chunk
	modified := bytes.Buffer{}
	modified.Write(header)
	modified.Write(chunks[0]) // First chunk
	modified.Write(chunks[0]) // DUPLICATE first chunk
	modified.Write(chunks[1]) // Second chunk
	modified.Write(tomb)

	// Attempt to decrypt
	var decrypted bytes.Buffer
	err = Decrypt(&modified, &decrypted, key)

	// VULNERABILITY: Should detect duplication but doesn't
	if err != nil {
		t.Logf("Good: Decryption rejected duplicated chunks (vulnerability fixed)")
	} else {
		t.Logf("VULNERABILITY CONFIRMED: Chunk duplication was not detected!")
		t.Logf("Expected length: %d, Got: %d", len(plaintext), decrypted.Len())
		t.Logf("Extra data: %d bytes", decrypted.Len()-len(plaintext))
	}
}

// TestWeakKeyDerivation demonstrates vulnerability to dictionary attacks.
func TestWeakKeyDerivation(t *testing.T) {
	plaintext := []byte("sensitive data")
	weakPassword := "password" // Common weak password

	// Encrypt with weak password
	var encrypted bytes.Buffer
	err := Encrypt(bytes.NewReader(plaintext), &encrypted, weakPassword)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Simulate attacker with encrypted file trying common passwords
	commonPasswords := []string{
		"123456",
		"password",
		"12345678",
		"qwerty",
		"abc123",
	}

	// Dictionary attack
	for _, guess := range commonPasswords {
		var decrypted bytes.Buffer
		err := Decrypt(bytes.NewReader(encrypted.Bytes()), &decrypted, guess)
		if err == nil && bytes.Equal(plaintext, decrypted.Bytes()) {
			t.Logf("VULNERABILITY CONFIRMED: Weak password '%s' cracked via dictionary attack!", guess)
			t.Logf("Attack succeeded in %d attempts", indexOf(commonPasswords, guess)+1)
			return
		}
	}

	t.Logf("Dictionary attack failed (password not in common list)")
}

// TestNonceUniqueness verifies that nonces are unique across chunks.
// This test verifies the SECURE implementation of nonce generation.
func TestNonceUniqueness(t *testing.T) {
	plaintext := make([]byte, 1024*1000*5) // 5 chunks worth
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}
	key := "test_key"

	var encrypted bytes.Buffer
	err := Encrypt(bytes.NewReader(plaintext), &encrypted, key)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Extract nonces from all chunks
	chunks, _, _ := parseEncryptedStream(t, encrypted.Bytes())
	nonces := make(map[string]bool)

	for i, chunk := range chunks {
		nonce := extractNonceFromChunk(t, chunk)
		nonceStr := string(nonce)
		if nonces[nonceStr] {
			t.Errorf("NONCE REUSE DETECTED: Chunk %d reuses a nonce!", i)
		}
		nonces[nonceStr] = true
	}

	t.Logf("SUCCESS: All %d chunks have unique nonces", len(chunks))
}

// Helper function to parse encrypted stream into components
func parseEncryptedStream(t *testing.T, data []byte) (chunks [][]byte, header []byte, tomb []byte) {
	// Header is 14 bytes (1 size + 2 magic + 9 scheme + 1 verMaj + 1 verMin)
	if len(data) < 14 {
		t.Fatal("Data too short to contain header")
	}
	header = data[:14]
	pos := 14

	// Parse chunks
	for pos < len(data) {
		if pos+2 > len(data) {
			break
		}

		// Check for chunk tag "ct"
		if data[pos] != 'c' || data[pos+1] != 't' {
			t.Fatalf("Invalid chunk tag at position %d: got %c%c", pos, data[pos], data[pos+1])
		}

		chunkStart := pos
		pos += 2 // Skip "ct"

		// Read chunk type
		if pos >= len(data) {
			break
		}
		chunkType := data[pos]
		pos++

		// Read nonce size (written as MaxVarintLen16 = 3 bytes)
		if pos+3 > len(data) {
			t.Fatalf("Not enough data for nonce size at position %d", pos)
		}
		nonceSize, _ := binary.Uvarint(data[pos : pos+3])
		pos += 3

		// Read nonce
		if pos+int(nonceSize) > len(data) {
			t.Fatalf("Nonce extends beyond buffer at position %d", pos)
		}
		pos += int(nonceSize)

		// Read chunk size (written as MaxVarintLen32 = 5 bytes)
		if pos+5 > len(data) {
			t.Fatalf("Not enough data for chunk size at position %d", pos)
		}
		chunkSize, _ := binary.Uvarint(data[pos : pos+5])
		pos += 5

		// Skip closing "ct"
		if pos+2 > len(data) {
			t.Fatalf("Missing closing tag at position %d", pos)
		}
		if data[pos] != 'c' || data[pos+1] != 't' {
			t.Fatalf("Invalid closing chunk tag at position %d: got %c%c", pos, data[pos], data[pos+1])
		}
		pos += 2

		// If this is a tomb chunk, save it and break
		if chunkType == 't' {
			tomb = data[chunkStart:pos]
			break
		}

		// Read encrypted data
		dataEnd := pos + int(chunkSize)
		if dataEnd > len(data) {
			t.Fatalf("Chunk data extends beyond buffer at position %d: need %d bytes but only %d available",
				pos, chunkSize, len(data)-pos)
		}

		// Save entire chunk (header + data)
		chunks = append(chunks, data[chunkStart:dataEnd])
		pos = dataEnd
	}

	return chunks, header, tomb
}

// Helper to extract nonce from chunk data
func extractNonceFromChunk(t *testing.T, chunk []byte) []byte {
	pos := 0

	// Skip "ct"
	pos += 2

	// Skip chunk type
	pos++

	// Read nonce size (3 bytes)
	nonceSize, _ := binary.Uvarint(chunk[pos : pos+3])
	pos += 3

	// Extract nonce
	nonce := make([]byte, nonceSize)
	copy(nonce, chunk[pos:pos+int(nonceSize)])

	return nonce
}

// Helper function
func indexOf(slice []string, item string) int {
	for i, v := range slice {
		if v == item {
			return i
		}
	}
	return -1
}
