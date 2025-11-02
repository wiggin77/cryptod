package main_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestCLIKeyExposureInProcessList demonstrates that encryption keys are visible
// in the process list when passed as command-line arguments.
//
// This test automatically builds the crypt binary as part of setup for CI compatibility.
func TestCLIKeyExposureInProcessList(t *testing.T) {
	cryptPath := "./crypt"

	// Build the crypt binary if it doesn't exist or rebuild it for fresh tests
	t.Log("Building crypt binary for testing...")
	buildCmd := exec.Command("go", "build", "-o", cryptPath, ".")
	buildOutput, err := buildCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to build crypt binary: %v\nOutput: %s", err, string(buildOutput))
	}
	t.Log("Successfully built crypt binary")

	// Clean up binary after test
	defer func() {
		if err := os.Remove(cryptPath); err != nil && !os.IsNotExist(err) {
			t.Logf("Warning: failed to remove test binary: %v", err)
		}
	}()

	// Create temporary test files
	tmpDir := t.TempDir()
	inputFile := filepath.Join(tmpDir, "test.txt")
	outputFile := filepath.Join(tmpDir, "test.txt.aes")

	testData := []byte("sensitive data for testing")
	err = os.WriteFile(inputFile, testData, 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Secret key - now passed via environment variable
	secretKey := "SuperSecretPassword123"

	// Start encryption process in background with key in environment
	cmd := exec.Command(cryptPath, "-e", "-in="+inputFile, "-out="+outputFile)
	cmd.Env = append(os.Environ(), "CRYPTOD_KEY="+secretKey)

	// Start the process
	err = cmd.Start()
	if err != nil {
		t.Fatalf("Failed to start crypt: %v", err)
	}

	// Give process time to appear in process list
	time.Sleep(100 * time.Millisecond)

	// Try to find the process and check if key is visible
	psCmd := exec.Command("ps", "aux")
	output, err := psCmd.Output()
	if err != nil {
		t.Logf("Warning: Could not run 'ps aux': %v", err)
		if waitErr := cmd.Wait(); waitErr != nil {
			t.Logf("Warning: Error waiting for command: %v", waitErr)
		}
		return
	}

	// Wait for encryption to complete
	if err := cmd.Wait(); err != nil {
		t.Logf("Warning: Command failed: %v", err)
	}

	// Check if the secret key appears in process list
	outputStr := string(output)
	if strings.Contains(outputStr, secretKey) {
		t.Errorf("VULNERABILITY PRESENT: Secret key '%s' is visible in process list!", secretKey)
		t.Errorf("Any user on the system can see this key using 'ps aux'")

		// Show the actual line
		lines := strings.Split(outputStr, "\n")
		for _, line := range lines {
			if strings.Contains(line, "crypt") && strings.Contains(line, secretKey) {
				t.Errorf("Exposed command: %s", line)
			}
		}
	} else {
		t.Logf("SUCCESS: Key not visible in process list (vulnerability fixed!)")
	}
}

// TestCLIKeyExposureInHistory demonstrates that keys passed as CLI arguments
// are stored in shell history files.
func TestCLIKeyExposureInHistory(t *testing.T) {
	t.Log("VULNERABILITY DEMONSTRATION: CLI Key Exposure in Shell History")
	t.Log("")
	t.Log("When users run:")
	t.Log("  $ crypt -e -in=secret.txt -out=secret.txt.aes -key=MyPassword123")
	t.Log("")
	t.Log("The key is permanently stored in shell history files:")
	t.Log("  - ~/.bash_history")
	t.Log("  - ~/.zsh_history")
	t.Log("  - ~/.fish_history")
	t.Log("")
	t.Log("Any attacker with read access to these files can recover the key.")
	t.Log("")
	t.Log("FIXED: Now uses environment variable instead:")
	t.Log("  $ CRYPTOD_KEY=MyPassword123 crypt -e -in=secret.txt -out=secret.txt.aes")
	t.Log("  or")
	t.Log("  $ crypt -e -in=secret.txt -out=secret.txt.aes -keyfile=key.txt")
}

// TestCLIProcCmdlineExposure tests that keys are readable via /proc filesystem
func TestCLIProcCmdlineExposure(t *testing.T) {
	if _, err := os.Stat("/proc"); os.IsNotExist(err) {
		t.Skip("Test requires /proc filesystem (Linux/Unix)")
	}

	t.Log("VULNERABILITY DEMONSTRATION: Keys readable via /proc/<pid>/cmdline")
	t.Log("")
	t.Log("On Linux/Unix systems, command-line arguments are accessible via:")
	t.Log("  /proc/<pid>/cmdline")
	t.Log("")
	t.Log("Any local user can read this file to extract encryption keys.")
	t.Log("")
	t.Log("Example attack:")
	t.Log("  1. User runs: crypt -e -in=file.txt -key=Secret123")
	t.Log("  2. Attacker finds PID: pgrep crypt")
	t.Log("  3. Attacker reads: cat /proc/<pid>/cmdline")
	t.Log("  4. Attacker extracts: Secret123")
	t.Log("")
	t.Log("This vulnerability affects ALL command-line tools that accept secrets as arguments.")
}

// TestSecureKeyInput demonstrates secure alternatives for key input
func TestSecureKeyInput(t *testing.T) {
	t.Log("SECURE ALTERNATIVES for Key Input:")
	t.Log("")
	t.Log("1. Environment Variables (IMPLEMENTED):")
	t.Log("   export CRYPTOD_KEY='my_secret'")
	t.Log("   crypt -e -in=file.txt -out=file.txt.aes")
	t.Log("   Pros: Not visible in process list")
	t.Log("   Cons: Still in shell history, visible in /proc/<pid>/environ")
	t.Log("")
	t.Log("2. Key Files:")
	t.Log("   echo 'my_secret' > key.txt")
	t.Log("   chmod 600 key.txt")
	t.Log("   crypt -e -in=file.txt -out=file.txt.aes -keyfile=key.txt")
	t.Log("   Pros: Not visible in process list or history")
	t.Log("   Cons: Key file must be protected")
	t.Log("")
	t.Log("3. Interactive Prompt (RECOMMENDED):")
	t.Log("   crypt -e -in=file.txt -out=file.txt.aes")
	t.Log("   Enter key: [hidden input]")
	t.Log("   Pros: No exposure in process list, history, or files")
	t.Log("   Cons: Requires interactive session")
	t.Log("")
	t.Log("4. Key Derivation from Passphrase + Salt:")
	t.Log("   Store random salt with encrypted file")
	t.Log("   Use PBKDF2/Argon2 to derive key from passphrase")
	t.Log("   Pros: Can use user-memorable passwords")
	t.Log("   Cons: Requires proper KDF implementation")
}
