package system

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// ResolveContainers scans for active local container runtime descriptors (Docker, containerd, Podman)
// and builds an ephemeral ID -> metadata lookup table without requiring external CLI tools.
func ResolveContainers() map[string]ContainerMeta {
	containers := make(map[string]ContainerMeta)

	// 1. Resolve via Docker container configs (/var/lib/docker/containers/<id>/config.v2.json)
	resolveDockerConfigs(containers)

	// 2. Resolve via containerd runtime state (/run/containerd/io.containerd.runtime.v2.task/...)
	resolveContainerdState(containers)

	return containers
}

type dockerConfigJSON struct {
	Name   string `json:"Name"`
	Config struct {
		Image string `json:"Image"`
	} `json:"Config"`
}

func resolveDockerConfigs(out map[string]ContainerMeta) {
	dockerDir := "/var/lib/docker/containers"
	entries, err := os.ReadDir(dockerDir)
	if err != nil {
		return
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		id := entry.Name()
		if len(id) < 12 {
			continue
		}

		configPath := filepath.Join(dockerDir, id, "config.v2.json")
		data, err := os.ReadFile(configPath)
		if err != nil {
			continue
		}

		var cfg dockerConfigJSON
		if err := json.Unmarshal(data, &cfg); err == nil {
			name := strings.TrimPrefix(cfg.Name, "/")
			meta := ContainerMeta{
				Name:  name,
				Image: cfg.Config.Image,
			}
			// Index by full ID, 12-char prefix, and 64-char hex
			out[id] = meta
			out[id[:12]] = meta
		}
	}
}

func resolveContainerdState(out map[string]ContainerMeta) {
	containerdDirs := []string{
		"/run/containerd/io.containerd.runtime.v2.task/moby",
		"/run/containerd/io.containerd.runtime.v2.task/k8s.io",
	}

	for _, dir := range containerdDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			id := entry.Name()
			shortID := id
			if len(shortID) > 12 {
				shortID = shortID[:12]
			}
			if _, exists := out[shortID]; !exists {
				out[shortID] = ContainerMeta{
					Name: shortID,
				}
			}
		}
	}
}
