package registry

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

// Helper to create a tar.gz payload from a map of files
func createMockTarGz(t *testing.T, files map[string]string) []byte {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	for name, content := range files {
		body := []byte(content)
		hdr := &tar.Header{
			Name: name,
			Mode: 0644,
			Size: int64(len(body)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("failed to write header: %v", err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatalf("failed to write body: %v", err)
		}
	}

	if err := tw.Close(); err != nil {
		t.Fatalf("failed to close tar: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("failed to close gzip: %v", err)
	}

	return buf.Bytes()
}

func TestUnpackPackageAndCache(t *testing.T) {
	// Setup temporary target directory
	tmpDir, err := os.MkdirTemp("", "eprobe-cache-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Mock valid module assets
	files := map[string]string{
		"manifest.yaml": "name: test-module\nversion: 1.0.0\n",
		"program.o":     "elf-object-bytes",
	}

	packageBytes := createMockTarGz(t, files)

	// Test extraction
	err = UnpackPackage(packageBytes, tmpDir)
	if err != nil {
		t.Fatalf("expected unpack to pass, got: %v", err)
	}

	// Verify files extracted
	manifestBytes, err := os.ReadFile(filepath.Join(tmpDir, "manifest.yaml"))
	if err != nil {
		t.Errorf("failed to read extracted manifest: %v", err)
	}
	if string(manifestBytes) != files["manifest.yaml"] {
		t.Errorf("manifest content mismatch: got %q, expected %q", string(manifestBytes), files["manifest.yaml"])
	}

	programBytes, err := os.ReadFile(filepath.Join(tmpDir, "program.o"))
	if err != nil {
		t.Errorf("failed to read extracted program: %v", err)
	}
	if string(programBytes) != files["program.o"] {
		t.Errorf("program content mismatch: got %q, expected %q", string(programBytes), files["program.o"])
	}
}

func TestUnpackPackageDirectoryTraversalMitigation(t *testing.T) {
	// Setup temporary target directory
	tmpDir, err := os.MkdirTemp("", "eprobe-cache-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Mock malicious module containing relative path traversal (Zip/Tar Slip)
	files := map[string]string{
		"../exploit.txt": "compromised",
	}

	maliciousBytes := createMockTarGz(t, files)

	// Verify extraction fails
	err = UnpackPackage(maliciousBytes, tmpDir)
	if err == nil {
		t.Error("expected unpack to fail due to path traversal check, but it passed")
	}
}

func TestValidateModuleName(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{"sec/exec-audit", false},
		{"app/http-tracer", false},
		{"net/tcp-monitor", false},
		{"test/mock-module", false},
		{"a1/b2", false},
		// Invalid cases
		{"", true},                          // empty
		{"../../etc/passwd", true},           // path traversal
		{"/absolute/path", true},            // absolute path
		{"sec", true},                       // missing domain separator
		{"sec/exec audit", true},            // space in name
		{"SEC/EXEC-AUDIT", true},            // uppercase
		{"sec/../exec-audit", true},         // traversal within name
		{"sec/exec-audit/extra/deep", true}, // too many segments
		{"sec/exec.audit", true},            // dot in name
	}

	for _, tc := range tests {
		err := ValidateModuleName(tc.name)
		if (err != nil) != tc.wantErr {
			t.Errorf("ValidateModuleName(%q): got error=%v, wantErr=%v", tc.name, err, tc.wantErr)
		}
	}
}

func TestGetModulePathContainment(t *testing.T) {
	// Set a known cache directory
	tmpDir, err := os.MkdirTemp("", "eprobe-cache-containment-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	oldCache := CustomCacheDir
	CustomCacheDir = tmpDir
	defer func() { CustomCacheDir = oldCache }()

	// A normal module path should be within the cache root
	normalPath := GetModulePath("sec/exec-audit")
	expected := filepath.Join(tmpDir, "sec", "exec-audit")
	if normalPath != expected {
		t.Errorf("expected path %q, got %q", expected, normalPath)
	}

	// A traversal attempt should be contained to the cache root
	traversalPath := GetModulePath("../../etc/passwd")
	absTraversal, _ := filepath.Abs(traversalPath)
	absRoot, _ := filepath.Abs(tmpDir)

	if absTraversal != absRoot {
		t.Errorf("expected traversal path to be contained to %q, got %q", absRoot, absTraversal)
	}
}
