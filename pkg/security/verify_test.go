package security

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestVerifyManifestAndHash(t *testing.T) {
	// 1. Generate Ed25519 key pair
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// 2. Mock manifest bytes and signature
	manifestBytes := []byte("name: app/http-tracer\nversion: 1.0.0\nauthor: eprobe-team\n")
	signature := ed25519.Sign(privKey, manifestBytes)

	// 3. Verify valid manifest signature
	err = VerifyManifest(manifestBytes, signature, pubKey)
	if err != nil {
		t.Errorf("expected verification to pass, got: %v", err)
	}

	// 4. Verify invalid manifest signature (tempered data)
	temperedManifest := []byte("name: app/http-tracer\nversion: 2.0.0\nauthor: eprobe-team\n")
	err = VerifyManifest(temperedManifest, signature, pubKey)
	if err == nil {
		t.Error("expected verification to fail for tempered manifest, but it passed")
	}

	// 5. Verify invalid manifest signature (wrong signature bytes)
	badSignature := make([]byte, ed25519.SignatureSize)
	err = VerifyManifest(manifestBytes, badSignature, pubKey)
	if err == nil {
		t.Error("expected verification to fail for wrong signature bytes, but it passed")
	}

	// 6. Test program checksum verification
	programBytes := []byte("mock-ebpf-elf-bytecode-instructions")
	hashBytes := sha256.Sum256(programBytes)
	validHash := hex.EncodeToString(hashBytes[:])

	err = VerifyProgramHash(programBytes, validHash)
	if err != nil {
		t.Errorf("expected checksum verification to pass, got: %v", err)
	}

	// 7. Test program checksum verification (corrupted payload)
	corruptedBytes := []byte("mock-ebpf-elf-bytecode-instructions-corrupted")
	err = VerifyProgramHash(corruptedBytes, validHash)
	if err == nil {
		t.Error("expected checksum verification to fail for corrupted program payload, but it passed")
	}
}

func TestVerifyManifestHybrid(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Create a hybrid manifest: all lines CRLF except the sha256 line which is LF
	hybridManifest := []byte("name: log/stderr-capture\r\nversion: 1.0.0\r\nsha256: 123456\nauthor: eprobe-team\r\n")
	signature := ed25519.Sign(privKey, hybridManifest)

	// Test 1: Verify hybrid raw manifest
	err = VerifyManifest(hybridManifest, signature, pubKey)
	if err != nil {
		t.Errorf("expected hybrid raw manifest to verify: %v", err)
	}

	// Test 2: Verify same manifest after normalization to LF
	lfNormalized := []byte("name: log/stderr-capture\nversion: 1.0.0\nsha256: 123456\nauthor: eprobe-team\n")
	err = VerifyManifest(lfNormalized, signature, pubKey)
	if err != nil {
		t.Errorf("expected LF normalized manifest to verify against hybrid signature: %v", err)
	}
}
