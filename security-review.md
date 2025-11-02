# COMPREHENSIVE SECURITY AUDIT REPORT
## cryptod Go Library - Full Codebase Analysis

**Audit Date:** 2025-11-02
**Repository:** /Users/dlauder/Development/wiggin77/cryptod
**Auditor:** Senior Security Engineer
**Methodology:** White-box source code analysis with exploitation verification

---

## EXECUTIVE SUMMARY

This security audit identified **3 high-confidence security vulnerabilities** in the cryptod library that could lead to data compromise or unauthorized access. The most critical finding is a **chunk sequence integrity vulnerability** that allows attackers to silently corrupt encrypted data through reordering, deletion, or duplication of chunks. Additionally, the CLI tool exposes encryption keys through process arguments, creating a significant information disclosure risk.

The cryptographic primitives (AES-256-GCM, nonce generation, random number generation) are correctly implemented. However, the lack of authenticated binding between chunks undermines the integrity guarantees expected from authenticated encryption.

---

## VULNERABILITY FINDINGS

### 1. CHUNK SEQUENCE INTEGRITY VULNERABILITY ⚠️

**Severity:** HIGH
**Confidence:** 0.95
**Category:** Cryptographic Implementation Flaw / Authentication Bypass
**Files:** crypto.go:53, crypto.go:121

#### Description
The encryption implementation fails to authenticate the sequence and ordering of encrypted chunks. While GCM provides authenticated encryption for individual chunks, there is no cryptographic binding between chunks or validation of their order. This allows an attacker with write access to encrypted files to perform chunk manipulation attacks without detection.

#### Root Cause
At **crypto.go:53** and **crypto.go:121**, GCM encryption/decryption is performed with `nil` for the Additional Authenticated Data (AAD) parameter:

```go
// Line 53 - Encryption
c := gcm.Seal(cbuf[:0], nonce, p, nil)  // AAD is nil

// Line 121 - Decryption
pbuf, err = gcm.Open(cbuf[:0], ch.nonce, cbuf, nil)  // AAD is nil
```

Without AAD binding chunk metadata (sequence number, position), each chunk is authenticated independently but not as part of a sequence.

#### Exploitation Scenarios

**Attack 1: Chunk Reordering**
```
Original:  [Header][Chunk1: "AAAA"][Chunk2: "BBBB"][Tomb]
Attacker:  [Header][Chunk2: "BBBB"][Chunk1: "AAAA"][Tomb]
Result:    Decrypts successfully to "BBBBAAAA" instead of "AAAABBBB"
Detection: NONE - decryption succeeds silently
```

**Attack 2: Chunk Deletion**
```
Original:  [Header][Chunk1][Chunk2][Chunk3][Tomb]
Attacker:  [Header][Chunk1][Chunk3][Tomb]
Result:    Chunk2 data silently lost
Detection: NONE - decryption succeeds
```

**Attack 3: Chunk Duplication**
```
Original:  [Header][Chunk1][Chunk2][Tomb]
Attacker:  [Header][Chunk1][Chunk1][Chunk2][Tomb]
Result:    Chunk1 data appears twice
Detection: NONE - decryption succeeds
```

**Verified with Proof-of-Concept:** Testing confirmed that chunks encrypted with different nonces can be reordered without triggering GCM authentication failures.

#### Impact
- **Silent data corruption:** Decryption completes successfully with corrupted output
- **Data loss:** Chunks can be removed without detection
- **Data manipulation:** Chunk order can be changed to corrupt file structure
- **Integrity violation:** Violates fundamental authenticated encryption guarantees

#### Exploitation Requirements
- Attacker needs write access to encrypted files
- Understanding of file format structure
- No privileged access required

#### Fix Recommendation
Include chunk sequence number in GCM's Additional Authenticated Data:

```go
// During encryption (line 53)
aad := make([]byte, 4)
binary.LittleEndian.PutUint32(aad, ctr)
c := gcm.Seal(cbuf[:0], nonce, p, aad)

// During decryption (line 121)
// Extract counter from chunk header and verify against expected sequence
pbuf, err = gcm.Open(cbuf[:0], ch.nonce, cbuf, expectedAAD)
```

Alternatively, implement an HMAC over the entire file structure or maintain a running hash in each chunk header.

---

### 2. CLI KEY EXPOSURE VIA PROCESS ARGUMENTS ⚠️

**Severity:** HIGH
**Confidence:** 1.00
**Category:** Information Disclosure / Sensitive Data Exposure
**Files:** example/cmd/crypt/main.go:35

#### Description
The CLI tool accepts encryption keys via the `-key` command-line flag, which exposes the secret key through multiple channels accessible to local attackers.

#### Root Cause
At **main.go:35**, the key is defined as a string flag:

```go
flag.StringVar(&skey, "key", "", "secret key")
```

Users invoke the tool as:
```bash
crypt -e -in=file.txt -out=file.txt.aes -key=my_secret_password
```

#### Exposure Vectors

**1. Process List Exposure**
```bash
$ ps aux | grep crypt
user  1234  ... crypt -e -in=file.txt -key=my_secret_password
```
Any user on the system can view `/proc/<pid>/cmdline` to see the key.

**2. Shell History**
```bash
$ history
1234 crypt -e -in=secret.txt -key=my_secret_password
```
Keys are stored in `~/.bash_history`, `~/.zsh_history`, etc.

**3. Process Monitoring/Logging**
System monitoring tools (auditd, process monitors, logging daemons) may capture and log command-line arguments containing the key.

#### Impact
- **Key compromise:** Encryption keys exposed to all local users
- **Persistent exposure:** Keys stored in shell history files
- **Audit trail leakage:** Keys captured in system logs
- **Multi-user systems:** Particularly dangerous on shared systems

#### Exploitation Requirements
- Local access to the system
- Ability to read process information (standard user privilege)
- Or access to shell history files

#### Concrete Exploit Scenario
1. User encrypts sensitive document: `crypt -e -in=confidential.doc -key=Secret123`
2. Attacker with local access runs: `ps aux | grep crypt`
3. Attacker obtains key `Secret123`
4. Attacker decrypts file: `crypt -d -in=confidential.doc.aes -key=Secret123`

#### Fix Recommendation
**Option 1: Environment Variable (Preferred)**
```go
skey := os.Getenv("CRYPT_KEY")
if skey == "" {
    return errors.New("CRYPT_KEY environment variable not set")
}
```

Usage: `CRYPT_KEY=secret crypt -e -in=file.txt -out=file.txt.aes`

**Option 2: Read from File**
```go
flag.StringVar(&keyFile, "keyfile", "", "path to key file")
// Read key from keyFile
```

**Option 3: Interactive Prompt (Best for user-facing tools)**
```go
fmt.Print("Enter encryption key: ")
key, err := terminal.ReadPassword(int(os.Stdin.Fd()))
```

**CRITICAL:** Never accept secrets via command-line flags.

---

### 3. WEAK PASSWORD-BASED KEY DERIVATION ⚠️

**Severity:** MEDIUM
**Confidence:** 0.90
**Category:** Weak Cryptography / Key Management
**Files:** crypto.go:135

#### Description
The library derives AES keys from user-provided strings using a simple SHA-512/256 hash without salt or key stretching, making it vulnerable to brute-force and rainbow table attacks when used with weak passwords.

#### Root Cause
At **crypto.go:135**, key derivation uses direct hashing:

```go
func getGCM(skey string) (cipher.AEAD, error) {
    // key must be hashed to 32 bytes for AES256
    key := sha512.Sum512_256([]byte(skey))
    // ...
}
```

#### Vulnerabilities

**1. No Salt**
- Same password always produces same key
- Enables rainbow table attacks
- Identical passwords across files use identical keys

**2. No Key Stretching**
- Single hash operation (microseconds)
- GPU can test millions of passwords per second
- No computational cost for attackers

**3. Password Weakness**
```
Password: "password"
Key (SHA-512/256): f3f22d82ccf54a92... (deterministic)
```

#### Impact
- **Brute force vulnerability:** Weak passwords easily cracked
- **Rainbow tables:** Pre-computed hash tables effective
- **Dictionary attacks:** Common passwords quickly tested
- **No protection:** Unlike PBKDF2/Argon2/scrypt which slow down attacks

#### Exploitation Scenario
1. Attacker obtains encrypted file
2. Attacker runs dictionary attack with GPU:
   - Tests 10 billion passwords per second
   - Common password cracked in seconds/minutes
3. Attacker decrypts file with discovered password

#### Library Design Consideration
The documentation (lines 20-22) suggests keys should be programmatically generated:
> "The key should be unique for each io.Reader instance. For example, when encrypting files `skey` can be a secret plus the filespec"

This implies keys are meant to be strong secrets, not user passwords. However:
- The CLI tool accepts arbitrary user input as keys
- No validation or warning about weak passwords
- Users naturally treat it as a password field

#### Fix Recommendation

**Option 1: Use Proper Password-Based Key Derivation**
```go
import "golang.org/x/crypto/argon2"

func deriveKey(password string, salt []byte) []byte {
    return argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
}
```

Store salt with encrypted file header.

**Option 2: Enforce Strong Key Requirements**
```go
if len(skey) < 32 {
    return nil, errors.New("key must be at least 32 bytes of high entropy")
}
```

Add documentation warning against using passwords.

**Option 3: Separate Password-Based API**
```go
// For passwords
EncryptWithPassword(r io.Reader, w io.Writer, password string) error

// For cryptographic keys
EncryptWithKey(r io.Reader, w io.Writer, key [32]byte) error
```

**Recommended:** Implement Argon2id with salt stored in file header. Set reasonable parameters (time=1, memory=64MB, parallelism=4).

---

## NON-SECURITY BUGS IDENTIFIED

While not directly exploitable, these bugs indicate code quality issues:

### Bug 1: Error Handling in header.write()
**File:** header.go:71

```go
func (h *header) write(w io.Writer) error {
    var err error
    fields := [][]byte{h.size[:], h.magic[:], h.scheme[:], h.verMaj[:], h.verMin[:]}
    for _, f := range fields {
        if _, err = w.Write(f); err != nil {
            return nil  // BUG: Should return err, not nil
        }
    }
    return nil
}
```

**Impact:** Write errors are silently ignored, could lead to truncated/corrupted output files.

### Bug 2: Ignored Random Error in Tomb Chunk
**File:** crypto.go:72

```go
io.ReadFull(rand.Reader, nonce)  // Error ignored
return writeChunkHeader(chunkHeader{nonce: nonce, size: 0, tomb: true}, w)
```

**Impact:** Minimal - tomb chunks don't encrypt data, so nonce quality doesn't affect security. However, indicates inconsistent error handling.

---

## SECURITY ANALYSIS: NOT VULNERABLE

The following areas were thoroughly examined and found to be secure:

### ✓ Nonce Generation and Uniqueness
- **Structure:** 12-byte GCM nonce = 5 bytes counter + 7 bytes random
- **Counter:** Starts at 1, incremented per chunk within stream
- **Random:** 7 bytes from `crypto/rand.Reader` per stream (56 bits entropy)
- **Analysis:** Counter prevents intra-stream collisions; random part prevents inter-stream collisions
- **Collision probability:** ~1 in 2^56 ≈ 72 quadrillion per chunk pair
- **Verdict:** Properly implemented, no nonce reuse vulnerability

### ✓ GCM Usage
- **Algorithm:** AES-256-GCM (industry standard)
- **Nonce size:** 12 bytes (standard GCM nonce size)
- **Authentication tag:** 16 bytes (GCM overhead)
- **Implementation:** Uses Go's `crypto/cipher` package (well-vetted)
- **Verdict:** Correct usage of authenticated encryption

### ✓ Random Number Generation
- **Source:** `crypto/rand.Reader` (cryptographically secure PRNG)
- **Platform:** Uses `/dev/urandom` on Unix, CryptGenRandom on Windows
- **Verdict:** Industry-standard secure randomness

### ✓ Key Derivation Algorithm
- **Hash:** SHA-512/256 (FIPS 180-4 approved)
- **Output:** 256 bits (matches AES-256 requirements)
- **Note:** Algorithm itself is secure; weakness is lack of salt/stretching for passwords (see Vulnerability #3)

### ✓ Timing Attack Resistance
- **Key derivation:** SHA-512 constant-time ✓
- **GCM operations:** Constant-time MAC verification ✓
- **Comparisons:** No secret-dependent timing in critical paths ✓

### ✓ Memory Safety
- **Language:** Go (memory-safe, no buffer overflows from array access)
- **Bounds checking:** Automatic runtime checks
- **Integer overflow:** Checked at chunk.go:119 (maxChunkSize validation)

### ✓ Input Validation
- **Header validation:** Proper checks for magic, version, size (header.go:42-62)
- **Chunk size limits:** Sanity check at chunk.go:119 (2x expected max)
- **Nonce size:** Validated at chunk.go:99 (max 128 bytes)

---

## EXCLUDED FROM REPORT

The following issues were identified but excluded per the audit scope:

### Denial of Service (DOS)
- Integer overflow in chunk size (uint64→uint32 truncation) causes read failures but not memory corruption
- Large chunk size allocations could exhaust memory
- Malformed headers cause early termination

### Rate Limiting
- No rate limiting on decryption attempts (offline brute force only)

### TOCTOU Race Conditions
- File existence check (main.go:53) to file creation (cmd.go:26) has race window
- Limited exploitability: requires precise timing, encrypted output not controlled

---

## RECOMMENDATIONS SUMMARY

### Immediate (High Priority)
1. **Fix Chunk Integrity:** Implement AAD binding for chunk sequence numbers
2. **Fix CLI Key Exposure:** Remove `-key` flag, use environment variable or key file
3. **Implement PBKDF:** Add Argon2id/PBKDF2 for password-based encryption

### Code Quality
4. Fix error handling in `header.write()` (return `err` not `nil`)
5. Check error from `io.ReadFull` at crypto.go:72
6. Add comprehensive integration tests for chunk manipulation attacks

### Documentation
7. Clarify that library is designed for cryptographic keys, not user passwords
8. Document threat model and assumptions
9. Add security considerations section to README

---

## TESTING METHODOLOGY

This audit employed the following techniques:

1. **Static Code Analysis:** Line-by-line review of all cryptographic operations
2. **Data Flow Analysis:** Traced sensitive data (keys, nonces, plaintexts) through the codebase
3. **Threat Modeling:** Identified trust boundaries and attack surfaces
4. **Proof-of-Concept Development:** Created working exploits for chunk reordering
5. **Cryptographic Review:** Analyzed nonce construction, key derivation, and GCM usage
6. **Error Path Analysis:** Examined error handling for information leakage
7. **Test Coverage Review:** Analyzed existing tests for security-relevant scenarios

---

## CONCLUSION

The cryptod library demonstrates competent use of modern cryptographic primitives (AES-256-GCM, crypto/rand) but suffers from critical weaknesses in authenticated encryption implementation and key management. The **chunk sequence integrity vulnerability** (Vulnerability #1) is the most severe finding, allowing silent data corruption in a library specifically designed to protect data integrity. The **CLI key exposure** (Vulnerability #2) represents a dangerous usability flaw that compromises the security guarantees regardless of the underlying cryptographic strength.

These vulnerabilities are high-confidence findings with clear exploitation paths and significant security impact. Immediate remediation is recommended before production use of this library.

**Overall Risk Assessment:** HIGH
**Recommended Action:** Address all HIGH severity findings before deploying to production

---

**Audit Completed:** 2025-11-02
**Confidence Level:** High (>80% for all reported vulnerabilities)
**False Positive Rate:** Minimal (all findings verified with PoC or theoretical analysis)
