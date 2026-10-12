package registry

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRegistryClient(t *testing.T) {
	// 1. Setup mock remote server
	mockInfo := ModuleInfo{
		Name:        "app/http-tracer",
		Version:     "1.0.0",
		Author:      "eprobe-team",
		Manifest:    "name: app/http-tracer\nversion: 1.0.0\n",
		Signature:   "bW9jay1zaWduYXR1cmUtYnl0ZXM=", // base64 encoded
		DownloadURL: "/v1/modules/app/http-tracer/download",
	}

	mockCatalog := CatalogResponse{
		Modules: []ModuleInfo{mockInfo},
		Total:   1,
	}

	mockTarball := []byte("gzip-tarball-bytes")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/modules/app/http-tracer":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(mockInfo)
		case "/v1/modules/app/http-tracer/download":
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(mockTarball)
		case "/v1/modules":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(mockCatalog)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// 2. Initialize registry client pointing to mock server
	client := NewClient(server.URL)

	// 3. Test FetchModuleInfo
	info, err := client.FetchModuleInfo(context.Background(), "app/http-tracer")
	if err != nil {
		t.Fatalf("expected FetchModuleInfo to pass, got: %v", err)
	}
	if info.Name != mockInfo.Name {
		t.Errorf("module name mismatch: got %q, expected %q", info.Name, mockInfo.Name)
	}
	if info.Version != mockInfo.Version {
		t.Errorf("module version mismatch: got %q, expected %q", info.Version, mockInfo.Version)
	}
	if info.Signature != mockInfo.Signature {
		t.Errorf("module signature mismatch: got %q, expected %q", info.Signature, mockInfo.Signature)
	}

	// 4. Test DownloadPackage with relative URL (should resolve via ValidateDownloadURL)
	pkgBytes, err := client.DownloadPackage(context.Background(), info.DownloadURL)
	if err != nil {
		t.Fatalf("expected DownloadPackage to pass, got: %v", err)
	}
	if string(pkgBytes) != string(mockTarball) {
		t.Errorf("downloaded package content mismatch: got %q, expected %q", string(pkgBytes), string(mockTarball))
	}

	// 5. Test FetchModuleCatalog
	catalog, err := client.FetchModuleCatalog(context.Background())
	if err != nil {
		t.Fatalf("expected FetchModuleCatalog to pass, got: %v", err)
	}
	if catalog.Total != 1 {
		t.Errorf("expected catalog total 1, got %d", catalog.Total)
	}
	if len(catalog.Modules) != 1 {
		t.Errorf("expected 1 module in catalog, got %d", len(catalog.Modules))
	}
	if catalog.Modules[0].Name != "app/http-tracer" {
		t.Errorf("expected catalog module name 'app/http-tracer', got %q", catalog.Modules[0].Name)
	}
}

func TestValidateDownloadURL_SSRF(t *testing.T) {
	client := NewClient("http://registry.eprobe.io:8080")

	// 1. Relative path should be accepted and resolved
	resolved, err := client.ValidateDownloadURL("/v1/modules/sec/exec-audit/download")
	if err != nil {
		t.Errorf("expected relative URL to be accepted, got: %v", err)
	}
	if resolved != "http://registry.eprobe.io:8080/v1/modules/sec/exec-audit/download" {
		t.Errorf("unexpected resolved URL: %q", resolved)
	}

	// 2. Same-origin absolute URL should be accepted
	_, err = client.ValidateDownloadURL("http://registry.eprobe.io:8080/v1/modules/sec/exec-audit/download")
	if err != nil {
		t.Errorf("expected same-origin URL to be accepted, got: %v", err)
	}

	// 3. Cross-origin URL should be rejected (SSRF prevention)
	_, err = client.ValidateDownloadURL("http://internal-corp-server:9090/steal-data")
	if err == nil {
		t.Error("expected cross-origin URL to be rejected for SSRF prevention, but it passed")
	}

	// 4. Different scheme should be rejected (downgrade attempt or unsupported scheme)
	_, err = client.ValidateDownloadURL("https://registry.eprobe.io:8080/v1/modules/sec/exec-audit/download")
	if err == nil {
		t.Error("expected different-scheme URL to be rejected, but it passed")
	}

	// 5. Test HTTPS Auto-Upgrade
	clientHTTPS := NewClient("https://registry.eprobe.io:8080")
	upgraded, err := clientHTTPS.ValidateDownloadURL("http://registry.eprobe.io:8080/v1/modules/sec/exec-audit/download")
	if err != nil {
		t.Errorf("expected http URL to be upgraded to https, got error: %v", err)
	}
	if upgraded != "https://registry.eprobe.io:8080/v1/modules/sec/exec-audit/download" {
		t.Errorf("expected upgraded URL to be https, got: %q", upgraded)
	}
}
