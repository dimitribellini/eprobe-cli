package registry

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	SystemCacheDir = "/var/lib/eprobe/modules"

	// MaxExtractedBytes is the maximum total uncompressed size allowed during package extraction (256 MB).
	// Prevents decompression bomb attacks from filling disk.
	MaxExtractedBytes int64 = 256 * 1024 * 1024
)

var CustomCacheDir = ""

// validModuleNamePattern restricts module names to safe characters: lowercase alphanumeric, hyphens, underscores, and a single forward slash for domain separation.
var validModuleNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*/[a-z0-9][a-z0-9_-]*$`)

// ValidateModuleName checks that a module name is safe for use in filesystem paths and HTTP URLs.
// Valid names follow the pattern "domain/module-name" using lowercase alphanumeric characters, hyphens, and underscores.
func ValidateModuleName(name string) error {
	if name == "" {
		return fmt.Errorf("module name cannot be empty")
	}
	if strings.Contains(name, "..") {
		return fmt.Errorf("module name %q contains illegal path traversal sequence", name)
	}
	if filepath.IsAbs(name) {
		return fmt.Errorf("module name %q must be a relative path", name)
	}
	if !validModuleNamePattern.MatchString(name) {
		return fmt.Errorf("module name %q is invalid: must match pattern 'domain/module-name' using lowercase letters, digits, hyphens, and underscores", name)
	}
	return nil
}

// GetCacheDir returns the local cache root directory based on user privileges.
func GetCacheDir() string {
	if CustomCacheDir != "" {
		return CustomCacheDir
	}

	if os.Geteuid() == 0 {
		return SystemCacheDir
	}

	userCache, err := os.UserCacheDir()
	if err != nil {
		// Fallback to local subdirectory
		return "./.cache/eprobe/modules"
	}
	return filepath.Join(userCache, "eprobe", "modules")
}

// GetModulePath returns the absolute local path to a cached module folder.
// It includes a containment check to ensure the resolved path stays within the cache root.
func GetModulePath(name string) string {
	cacheRoot := GetCacheDir()
	candidate := filepath.Join(cacheRoot, filepath.FromSlash(name))

	// Resolve both to absolute paths for containment verification
	resolvedRoot, err := filepath.Abs(cacheRoot)
	if err != nil {
		return candidate
	}
	resolvedCandidate, err := filepath.Abs(candidate)
	if err != nil {
		return candidate
	}

	// Verify the candidate path is strictly within the cache root
	if !strings.HasPrefix(resolvedCandidate, resolvedRoot+string(filepath.Separator)) && resolvedCandidate != resolvedRoot {
		// Return the cache root itself to prevent escape; callers will get a safe but incorrect path
		// that will fail naturally on subsequent file operations
		return resolvedRoot
	}

	return candidate
}

// IsModuleCached checks if a module has been downloaded and contains the required assets.
func IsModuleCached(name string) bool {
	dir := GetModulePath(name)
	if _, err := os.Stat(filepath.Join(dir, "manifest.yaml")); err != nil {
		return false
	}
	if _, err := os.Stat(filepath.Join(dir, "program.o")); err != nil {
		return false
	}
	return true
}

// UnpackPackage decompresses and extracts a gzipped tarball into the target module directory.
// Includes Zip/Tar Slip protection checks to prevent path traversal vulnerabilities.
// Enforces a maximum total extracted size of MaxExtractedBytes to prevent decompression bombs.
func UnpackPackage(packageBytes []byte, targetDir string) error {
	err := os.MkdirAll(targetDir, 0755)
	if err != nil {
		return fmt.Errorf("failed to create target cache directory: %w", err)
	}

	gzipReader, err := gzip.NewReader(bytes.NewReader(packageBytes))
	if err != nil {
		return fmt.Errorf("failed to initialize gzip reader: %w", err)
	}
	defer gzipReader.Close()

	tarReader := tar.NewReader(gzipReader)

	var totalExtracted int64

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to parse tar archive: %w", err)
		}

		// Clean and secure path extraction to avoid Tar/Zip Slip directory traversal vulnerability
		cleanedPath := filepath.Clean(header.Name)
		if strings.HasPrefix(cleanedPath, "..") || filepath.IsAbs(cleanedPath) {
			return fmt.Errorf("illegal directory traversal path detected in archive: %s", header.Name)
		}

		destPath := filepath.Join(targetDir, cleanedPath)
		// Double check resolved destination path is strictly within targetDir
		resolvedTarget, _ := filepath.Abs(targetDir)
		resolvedDest, _ := filepath.Abs(destPath)
		if !strings.HasPrefix(resolvedDest, resolvedTarget+string(filepath.Separator)) && resolvedDest != resolvedTarget {
			return fmt.Errorf("archive path escapes target directory: %s", header.Name)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(destPath, 0755); err != nil {
				return fmt.Errorf("failed to create directory in archive: %w", err)
			}
		case tar.TypeReg:
			// Ensure parent directory exists
			if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
				return fmt.Errorf("failed to create parent dir: %w", err)
			}

			// Check declared file size against remaining extraction budget
			totalExtracted += header.Size
			if totalExtracted > MaxExtractedBytes {
				return fmt.Errorf("archive exceeds maximum allowed extraction size of %d bytes (possible decompression bomb)", MaxExtractedBytes)
			}

			outFile, err := os.OpenFile(destPath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, header.FileInfo().Mode())
			if err != nil {
				return fmt.Errorf("failed to open extraction file: %w", err)
			}

			// Use LimitReader to enforce per-file size limit matching the declared header size
			written, err := io.Copy(outFile, io.LimitReader(tarReader, header.Size+1))
			outFile.Close()
			if err != nil {
				return fmt.Errorf("failed to write file content: %w", err)
			}
			if written > header.Size {
				return fmt.Errorf("file %s exceeds declared size in archive header", header.Name)
			}
		}
	}

	return nil
}

// ReadCachedFile reads the contents of a specific cached module file.
func ReadCachedFile(moduleName, filename string) ([]byte, error) {
	path := filepath.Join(GetModulePath(moduleName), filename)
	return os.ReadFile(path)
}
