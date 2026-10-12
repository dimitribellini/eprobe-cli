package security

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// DefaultPublicKeyHex is the default hex-encoded Ed25519 public key used for module verification
const DefaultPublicKeyHex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"

// GetDefaultPublicKey returns the default Ed25519 public key bytes
func GetDefaultPublicKey() ed25519.PublicKey {
	keyBytes, _ := hex.DecodeString(DefaultPublicKeyHex)
	return keyBytes
}

// VerifyManifest verifies that the manifest bytes match the provided signature using the public key.
func VerifyManifest(manifestBytes []byte, signature []byte, pubKey ed25519.PublicKey) error {
	if len(pubKey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key size: got %d, expected %d", len(pubKey), ed25519.PublicKeySize)
	}
	if len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature size: got %d, expected %d", len(signature), ed25519.SignatureSize)
	}

	// Try 1: Try verifying the raw bytes exactly as received (covers hybrid, LF-only or CRLF-only matches)
	if ed25519.Verify(pubKey, manifestBytes, signature) {
		return nil
	}

	// Try 2: Try normalizing CRLF to LF (covers manifest signed as LF but served as CRLF)
	lfNormalized := bytes.ReplaceAll(manifestBytes, []byte("\r\n"), []byte("\n"))
	if ed25519.Verify(pubKey, lfNormalized, signature) {
		return nil
	}

	// Try 3: Try normalizing LF to CRLF (covers manifest signed as CRLF but served as LF)
	if !bytes.Contains(manifestBytes, []byte("\r\n")) {
		crlfNormalized := bytes.ReplaceAll(manifestBytes, []byte("\n"), []byte("\r\n"))
		if ed25519.Verify(pubKey, crlfNormalized, signature) {
			return nil
		}
	}

	// Try 4: Try reconstructing hybrid line endings (covers manifest signed with hybrid newlines but served/saved as LF)
	hybridBytes := reconstructHybrid(manifestBytes)
	if ed25519.Verify(pubKey, hybridBytes, signature) {
		return nil
	}

	return fmt.Errorf("cryptographic signature verification failed")
}

// reconstructHybrid reconstructs the hybrid carriage-return signature layout
// where every line ends with \r\n except the sha256: line which ends with \n.
func reconstructHybrid(manifestBytes []byte) []byte {
	lines := strings.Split(string(manifestBytes), "\n")
	for i, line := range lines {
		// Do not add \r to empty lines, lines already ending with \r, or the sha256 line
		if line == "" || strings.HasSuffix(line, "\r") {
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(line), "sha256:") {
			continue
		}
		lines[i] = line + "\r"
	}
	return []byte(strings.Join(lines, "\n"))
}

// VerifyProgramHash calculates the SHA256 checksum of the program data and verifies it matches the expected hex hash.
func VerifyProgramHash(programBytes []byte, expectedHexHash string) error {
	hashBytes := sha256.Sum256(programBytes)
	actualHexHash := hex.EncodeToString(hashBytes[:])

	if actualHexHash != expectedHexHash {
		return fmt.Errorf("program file checksum mismatch: got %s, expected %s", actualHexHash, expectedHexHash)
	}

	return nil
}
