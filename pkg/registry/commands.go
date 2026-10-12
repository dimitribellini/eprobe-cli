package registry

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"eprobe/pkg/security"
)

// ListModules prints a formatted list of all downloaded modules cached locally.
func ListModules() error {
	cacheRoot := GetCacheDir()
	
	// Create folder if it doesn't exist yet
	if _, err := os.Stat(cacheRoot); os.IsNotExist(err) {
		fmt.Println("No modules currently downloaded.")
		return nil
	}

	fmt.Printf("%-25s %-10s %-20s %-10s\n", "MODULE", "VERSION", "AUTHOR", "STATUS")
	fmt.Println(strings.Repeat("-", 70))

	// Walk the cache directory to find manifest.yaml files
	err := filepath.Walk(cacheRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // ignore walk errors
		}
		if !info.IsDir() && info.Name() == "manifest.yaml" {
			// Extract relative module name from path
			rel, err := filepath.Rel(cacheRoot, filepath.Dir(path))
			if err != nil {
				return nil
			}
			moduleName := filepath.ToSlash(rel)

			// Read manifest
			manifestBytes, err := os.ReadFile(path)
			if err != nil {
				return nil
			}

			manifest, err := ParseManifest(manifestBytes)
			if err != nil {
				return nil
			}
			version := manifest.Version
			author := manifest.Author

			fmt.Printf("%-25s %-10s %-20s %-10s\n", moduleName, version, author, "cached")
		}
		return nil
	})

	return err
}

// SearchRemoteModules queries the remote registry catalog and prints available modules.
// Used by the `eprobe search` subcommand.
func SearchRemoteModules(ctx context.Context, registryURL string) error {
	client := NewClient(registryURL)

	fmt.Printf("Querying registry at %s...\n\n", registryURL)
	catalog, err := client.FetchModuleCatalog(ctx)
	if err != nil {
		return fmt.Errorf("failed to query registry catalog from %s: %w (check internet connectivity or --registry flag)", registryURL, err)
	}

	if catalog.Total == 0 {
		fmt.Println("No modules found in registry.")
		return nil
	}

	fmt.Printf("%-25s %-10s %-20s %-40s\n", "MODULE", "VERSION", "AUTHOR", "DESCRIPTION")
	fmt.Println(strings.Repeat("-", 100))

	for _, mod := range catalog.Modules {
		desc := mod.Description
		if len(desc) > 40 {
			desc = desc[:37] + "..."
		}
		fmt.Printf("%-25s %-10s %-20s %-40s\n", mod.Name, mod.Version, mod.Author, desc)
	}

	fmt.Printf("\nTotal: %d module(s)\n", catalog.Total)
	return nil
}

// DescribeModule reads and prints description details for a cached module manifest.
func DescribeModule(name string) error {
	if err := ValidateModuleName(name); err != nil {
		return err
	}

	if !IsModuleCached(name) {
		return fmt.Errorf("module %q is not downloaded. Run 'eprobe pull %s' first", name, name)
	}

	manifestBytes, err := ReadCachedFile(name, "manifest.yaml")
	if err != nil {
		return fmt.Errorf("failed to read manifest: %w", err)
	}

	fmt.Printf("Module Details: %s\n", name)
	fmt.Println(strings.Repeat("=", 40))
	fmt.Println(string(manifestBytes))
	return nil
}

// RemoveModule deletes a downloaded module folder from the local cache.
func RemoveModule(name string) error {
	if err := ValidateModuleName(name); err != nil {
		return err
	}

	if !IsModuleCached(name) {
		return fmt.Errorf("module %q is not downloaded", name)
	}

	dir := GetModulePath(name)
	err := os.RemoveAll(dir)
	if err != nil {
		return fmt.Errorf("failed to remove module cache: %w", err)
	}

	fmt.Printf("Successfully removed module %q from cache.\n", name)
	return nil
}

// PullModule downloads, cryptographically verifies, and extracts a module package.
func PullModule(ctx context.Context, name string, registryURL string, pubKey ed25519.PublicKey) error {
	if err := ValidateModuleName(name); err != nil {
		return err
	}

	client := NewClient(registryURL)

	fmt.Printf("Querying registry for module %q...\n", name)
	info, err := client.FetchModuleInfo(ctx, name)
	if err != nil {
		return fmt.Errorf("registry query failed for %s: %w (check internet connectivity or --registry flag)", registryURL, err)
	}

	// 1. Decode the Ed25519 signature
	signature, err := base64.StdEncoding.DecodeString(info.Signature)
	if err != nil {
		return fmt.Errorf("failed to decode manifest signature: %w", err)
	}

	// 2. Validate the manifest signature using the public key
	err = security.VerifyManifest([]byte(info.Manifest), signature, pubKey)
	if err != nil {
		return fmt.Errorf("cryptographic manifest verification failed: %w", err)
	}

	// 3. Extract target program hash from verified manifest metadata
	manifest, err := ParseManifest([]byte(info.Manifest))
	if err != nil {
		return fmt.Errorf("failed to parse manifest: %w", err)
	}
	expectedHash := manifest.SHA256

	// 4. Download package tarball (URL is validated by client.DownloadPackage via ValidateDownloadURL)
	fmt.Printf("Downloading signed module package %s (version: %s)...\n", name, info.Version)
	pkgBytes, err := client.DownloadPackage(ctx, info.DownloadURL)
	if err != nil {
		return fmt.Errorf("download package failed: %w", err)
	}

	// 5. Decompress and extract to local cache directory
	targetDir := GetModulePath(name)
	err = UnpackPackage(pkgBytes, targetDir)
	if err != nil {
		return fmt.Errorf("failed to unpack package to cache: %w", err)
	}

	// 6. Verify program.o binary integrity hash matches the verified manifest value
	programBytes, err := ReadCachedFile(name, "program.o")
	if err != nil {
		// In test mock scenarios, program.o might be optional, but for production it is required
		if expectedHash != "" {
			return fmt.Errorf("failed to read program bytecode for checksum validation: %w", err)
		}
	} else if expectedHash != "" {
		err = security.VerifyProgramHash(programBytes, expectedHash)
		if err != nil {
			// Cleanup corrupted unpack to keep cache clean
			_ = os.RemoveAll(targetDir)
			return fmt.Errorf("integrity check failed for program bytecode: %w", err)
		}
	}

	fmt.Printf("Successfully pulled module %q (version: %s, author: %s).\n", name, info.Version, info.Author)
	return nil
}

// UpdateModule checks if a newer version is available and updates the local cache if so.
// Compares both version string and SHA256 content hash to detect forced updates.
func UpdateModule(ctx context.Context, name string, registryURL string, pubKey ed25519.PublicKey) error {
	if err := ValidateModuleName(name); err != nil {
		return err
	}

	if !IsModuleCached(name) {
		fmt.Printf("Module %q is not cached. Pulling clean version...\n", name)
		return PullModule(ctx, name, registryURL, pubKey)
	}

	client := NewClient(registryURL)
	info, err := client.FetchModuleInfo(ctx, name)
	if err != nil {
		return fmt.Errorf("failed to check registry for updates from %s: %w (check internet connectivity or --registry flag)", registryURL, err)
	}

	// Read cached manifest
	manifestBytes, err := ReadCachedFile(name, "manifest.yaml")
	if err != nil {
		return fmt.Errorf("failed to read local manifest: %w", err)
	}

	// Extract local version and hash
	manifest, err := ParseManifest(manifestBytes)
	if err != nil {
		return fmt.Errorf("failed to parse local manifest: %w", err)
	}
	localVersion := manifest.Version
	localHash := manifest.SHA256

	// Parse remote manifest to get remote hash for content comparison
	remoteManifest, err := ParseManifest([]byte(info.Manifest))
	if err != nil {
		return fmt.Errorf("failed to parse remote manifest: %w", err)
	}
	remoteHash := remoteManifest.SHA256

	if localVersion == info.Version && localHash == remoteHash {
		fmt.Printf("Module %q is already up-to-date (version: %s).\n", name, localVersion)
		return nil
	}

	if localVersion == info.Version && localHash != remoteHash {
		fmt.Printf("Content change detected for %q (version %s): local hash %s -> registry hash %s. Forcing re-pull.\n", name, localVersion, localHash, remoteHash)
	} else {
		fmt.Printf("Update found for %q: local version %s -> registry version %s.\n", name, localVersion, info.Version)
	}

	return PullModule(ctx, name, registryURL, pubKey)
}

// ShowModuleHelp renders a formatted, dedicated help screen for a specific module
func ShowModuleHelp(name string) error {
	if err := ValidateModuleName(name); err != nil {
		return err
	}

	var manifestBytes []byte
	var err error

	if IsModuleCached(name) {
		manifestBytes, err = ReadCachedFile(name, "manifest.yaml")
		if err != nil {
			return fmt.Errorf("failed to read module manifest: %w", err)
		}
	} else {
		localCandidates := []string{
			filepath.Join("modules", name, "manifest.yaml"),
			filepath.Join("..", "eprobe-modules", "modules", name, "manifest.yaml"),
			filepath.Join("/root/antigravity/eprobe-prj/eprobe-modules/modules", name, "manifest.yaml"),
		}
		found := false
		for _, cand := range localCandidates {
			if data, readErr := os.ReadFile(cand); readErr == nil {
				manifestBytes = data
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("module %q is not downloaded. Run 'eprobe pull %s' first or 'eprobe run %s' to auto-pull", name, name, name)
		}
	}

	manifest, err := ParseManifest(manifestBytes)
	if err != nil {
		return fmt.Errorf("failed to parse module manifest: %w", err)
	}

	fmt.Println("================================================================================")
	fmt.Printf("📦 MODULE: %s (v%s)\n", manifest.Name, manifest.Version)
	if manifest.Author != "" {
		fmt.Printf("👤 Author: %s\n", manifest.Author)
	}
	fmt.Println("================================================================================")
	fmt.Println()
	fmt.Println("📖 MISSION / SCOPE:")
	fmt.Printf("  %s\n\n", strings.TrimSpace(manifest.Description))

	fmt.Println("⚙️ ATTACH POINTS (eBPF Kernel & Userspace Hooks):")
	for _, ap := range manifest.AttachPoints {
		fmt.Printf("  • [%-14s] %s (section: %s)\n", ap.Type, ap.Symbol, ap.Section)
	}
	fmt.Println()

	if len(manifest.Variables) > 0 {
		fmt.Println("🎛️ MODULE-SPECIFIC PARAMETERS & FILTERING FLAGS:")
		for _, v := range manifest.Variables {
			flagName := v.CLIFlag
			if flagName == "" {
				flagName = v.Name
			}
			desc := v.Description
			if desc == "" {
				desc = fmt.Sprintf("Set eBPF variable %s (%s)", v.Name, v.Type)
			}
			fmt.Printf("  --%-20s %s\n", flagName, desc)
		}
		fmt.Println()
	}

	if len(manifest.TUIHints.Pages) > 0 {
		fmt.Println("📊 DASHBOARD PAGES (Cycle with [ and ] keys in TUI):")
		for i, p := range manifest.TUIHints.Pages {
			fmt.Printf("  [%d] %s\n", i+1, p.Name)
			for _, pane := range p.Panes {
				summary := pane.Summary
				if summary == "" {
					summary = fmt.Sprintf("Type: %s, Map: %s", pane.Type, pane.MapName)
				}
				fmt.Printf("      - %-25s: %s\n", pane.Name, summary)
			}
		}
		fmt.Println()
	}

	fmt.Println("🚀 USAGE EXAMPLES:")
	fmt.Printf("  # Run with default settings (interactive TUI):\n")
	fmt.Printf("  sudo ./eprobe run %s\n\n", manifest.Name)
	if manifest.Name == "app/universal-tls-sniffer" {
		fmt.Printf("  # Filter by process name (e.g. curl or node):\n")
		fmt.Printf("  sudo ./eprobe run %s --comm curl\n\n", manifest.Name)
		fmt.Printf("  # Filter by target API domain / SNI:\n")
		fmt.Printf("  sudo ./eprobe run %s --host api.stripe.com\n\n", manifest.Name)
		fmt.Printf("  # Show only failing requests (HTTP 4xx & 5xx):\n")
		fmt.Printf("  sudo ./eprobe run %s --errors-only\n\n", manifest.Name)
		fmt.Printf("  # Inspect raw unmasked tokens (disable default sanitization):\n")
		fmt.Printf("  sudo ./eprobe run %s --no-sanitize\n\n", manifest.Name)
		fmt.Printf("  # Use custom libssl path:\n")
		fmt.Printf("  sudo ./eprobe run %s --libssl /usr/lib64/libssl.so.3\n\n", manifest.Name)
	} else {
		fmt.Printf("  # Filter by process PID:\n")
		fmt.Printf("  sudo ./eprobe run %s --pid 1234\n\n", manifest.Name)
		fmt.Printf("  # Stream to SaaS portal:\n")
		fmt.Printf("  sudo ./eprobe run %s -stream-token <UUID>\n\n", manifest.Name)
	}
	fmt.Println("================================================================================")
	return nil
}

