package registry

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestCLICommandsWorkflow(t *testing.T) {
	// 1. Generate Ed25519 keys
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// 2. Prepare test mock program
	programData := []byte("test-ebpf-object-code")
	hashBytes := sha256.Sum256(programData)
	expectedHash := hex.EncodeToString(hashBytes[:])

	// 3. Prepare test manifest and sign it
	manifest := "name: test/mock-module\nversion: 1.0.0\nauthor: test-author\nsha256: " + expectedHash + "\n"
	signature := ed25519.Sign(privKey, []byte(manifest))
	signatureB64 := base64.StdEncoding.EncodeToString(signature)

	// 4. Create compressed package archive (.epm) in memory
	var archiveBuf bytes.Buffer
	gw := gzip.NewWriter(&archiveBuf)
	tw := tar.NewWriter(gw)

	files := map[string][]byte{
		"manifest.yaml": []byte(manifest),
		"manifest.sig":  signature,
		"program.o":     programData,
	}
	for name, data := range files {
		hdr := &tar.Header{
			Name: name,
			Mode: 0644,
			Size: int64(len(data)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("failed to write header: %v", err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatalf("failed to write body: %v", err)
		}
	}
	_ = tw.Close()
	_ = gw.Close()

	// 5. Spin up test registry server mock
	registryInfo := ModuleInfo{
		Name:        "test/mock-module",
		Version:     "1.0.0",
		Author:      "test-author",
		Manifest:    manifest,
		Signature:   signatureB64,
		DownloadURL: "/v1/modules/test/mock-module/download",
	}

	catalogResponse := CatalogResponse{
		Modules: []ModuleInfo{
			{
				Name:        "test/mock-module",
				Version:     "1.0.0",
				Author:      "test-author",
				Description: "A test mock module",
				DownloadURL: "/v1/modules/test/mock-module/download",
			},
		},
		Total: 1,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/modules/test/mock-module":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(registryInfo)
		case "/v1/modules/test/mock-module/download":
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(archiveBuf.Bytes())
		case "/v1/modules":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(catalogResponse)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// 6. Set temporary local cache folder for testing to keep system directories untouched
	tmpCacheDir, err := os.MkdirTemp("", "eprobe-commands-test-*")
	if err != nil {
		t.Fatalf("failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpCacheDir)

	// Inject the custom cache directory
	CustomCacheDir = tmpCacheDir
	defer func() { CustomCacheDir = "" }()

	// 7. Verify list is empty initially
	if IsModuleCached("test/mock-module") {
		t.Error("expected test module not to be cached initially")
	}

	// 8. Pull module from mock registry server
	err = PullModule(context.Background(), "test/mock-module", server.URL, pubKey)
	if err != nil {
		t.Fatalf("expected PullModule to succeed, got: %v", err)
	}

	// 9. Verify cached assets exist
	if !IsModuleCached("test/mock-module") {
		t.Error("expected test module to be cached after PullModule")
	}

	// 10. Run ListModules (should print list to stdout)
	err = ListModules()
	if err != nil {
		t.Errorf("ListModules failed: %v", err)
	}

	// 11. Run DescribeModule (should print manifest to stdout)
	err = DescribeModule("test/mock-module")
	if err != nil {
		t.Errorf("DescribeModule failed: %v", err)
	}

	// 12. Run UpdateModule (should output already up-to-date)
	err = UpdateModule(context.Background(), "test/mock-module", server.URL, pubKey)
	if err != nil {
		t.Errorf("UpdateModule failed: %v", err)
	}

	// 13. Run SearchRemoteModules (should print catalog from registry)
	err = SearchRemoteModules(context.Background(), server.URL)
	if err != nil {
		t.Errorf("SearchRemoteModules failed: %v", err)
	}

	// 14. Run RemoveModule and verify files cleaned up
	err = RemoveModule("test/mock-module")
	if err != nil {
		t.Fatalf("expected RemoveModule to succeed, got: %v", err)
	}

	if IsModuleCached("test/mock-module") {
		t.Error("expected test module to be removed after RemoveModule")
	}
}

func TestCommandsModuleNameValidation(t *testing.T) {
	// Verify that commands reject invalid module names
	err := DescribeModule("../../etc/passwd")
	if err == nil {
		t.Error("expected DescribeModule to reject path traversal name")
	}

	err = RemoveModule("../../etc/passwd")
	if err == nil {
		t.Error("expected RemoveModule to reject path traversal name")
	}
}
