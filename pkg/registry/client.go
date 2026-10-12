package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const (
	// MaxPackageSize is the maximum download size for a module package (256 MB).
	MaxPackageSize int64 = 256 * 1024 * 1024

	// maxErrorBodySize is the maximum response body size read on error responses (1 MB).
	maxErrorBodySize int64 = 1 * 1024 * 1024
)

// ModuleInfo represents the metadata returned by the Remote Registry API
type ModuleInfo struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Author      string `json:"author"`
	Description string `json:"description,omitempty"`
	UpdatedAt   string `json:"updated_at,omitempty"`
	Manifest    string `json:"manifest"`     // Raw YAML manifest string
	Signature   string `json:"signature"`    // Base64-encoded Ed25519 signature
	DownloadURL string `json:"download_url"` // URL to download the gzip tarball
}

// CatalogResponse represents the response from the GET /v1/modules catalog endpoint.
type CatalogResponse struct {
	Modules []ModuleInfo `json:"modules"`
	Total   int          `json:"total"`
}

// Client represents the eprobe Remote Registry client
type Client struct {
	BaseURL    string
	HTTPClient *http.Client
}

// NewClient creates a new Registry client
func NewClient(baseURL string) *Client {
	return &Client{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// ValidateDownloadURL checks that a download URL shares the same scheme and host as the registry base URL,
// or is a relative path. This prevents SSRF attacks via registry-controlled download URLs.
func (c *Client) ValidateDownloadURL(downloadURL string) (string, error) {
	// If it's a relative path, prepend the base URL
	if len(downloadURL) > 0 && downloadURL[0] == '/' {
		return c.BaseURL + downloadURL, nil
	}

	parsed, err := url.Parse(downloadURL)
	if err != nil {
		return "", fmt.Errorf("invalid download URL: %w", err)
	}

	baseParsed, err := url.Parse(c.BaseURL)
	if err != nil {
		return "", fmt.Errorf("invalid base URL: %w", err)
	}

	if parsed.Host != baseParsed.Host {
		return "", fmt.Errorf("download URL origin %q does not match registry origin %q (possible SSRF)", parsed.Host, baseParsed.Host)
	}

	if parsed.Scheme != baseParsed.Scheme {
		// Auto-upgrade to https if the base URL is https and the host matches
		if baseParsed.Scheme == "https" && parsed.Scheme == "http" {
			parsed.Scheme = "https"
			return parsed.String(), nil
		}
		return "", fmt.Errorf("download URL scheme %q does not match registry scheme %q", parsed.Scheme, baseParsed.Scheme)
	}

	return downloadURL, nil
}

// FetchModuleInfo queries the registry API for the specified module metadata
func (c *Client) FetchModuleInfo(ctx context.Context, name string) (*ModuleInfo, error) {
	reqURL := fmt.Sprintf("%s/v1/modules/%s", c.BaseURL, name)
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to perform HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("module %q not found in registry", name)
	}
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodySize))
		return nil, fmt.Errorf("registry returned error status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var info ModuleInfo
	err = json.NewDecoder(resp.Body).Decode(&info)
	if err != nil {
		return nil, fmt.Errorf("failed to decode module metadata JSON: %w", err)
	}

	return &info, nil
}

// FetchModuleCatalog queries the registry catalog API for all available modules.
// Used by the `eprobe search` subcommand.
func (c *Client) FetchModuleCatalog(ctx context.Context) (*CatalogResponse, error) {
	reqURL := fmt.Sprintf("%s/v1/modules?sort=name&order=asc", c.BaseURL)
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to perform HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodySize))
		return nil, fmt.Errorf("registry returned error status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var catalog CatalogResponse
	err = json.NewDecoder(resp.Body).Decode(&catalog)
	if err != nil {
		return nil, fmt.Errorf("failed to decode module catalog JSON: %w", err)
	}

	return &catalog, nil
}

// DownloadPackage downloads the gzip-compressed module tarball bytes from the given URL.
// Enforces a maximum download size of MaxPackageSize to prevent OOM.
func (c *Client) DownloadPackage(ctx context.Context, downloadURL string) ([]byte, error) {
	// Validate download URL origin to prevent SSRF
	validatedURL, err := c.ValidateDownloadURL(downloadURL)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "GET", validatedURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to perform HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodySize))
		return nil, fmt.Errorf("failed to download package, status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	packageBytes, err := io.ReadAll(io.LimitReader(resp.Body, MaxPackageSize))
	if err != nil {
		return nil, fmt.Errorf("failed to read package stream: %w", err)
	}

	if int64(len(packageBytes)) >= MaxPackageSize {
		return nil, fmt.Errorf("package download exceeds maximum allowed size of %d bytes", MaxPackageSize)
	}

	return packageBytes, nil
}
