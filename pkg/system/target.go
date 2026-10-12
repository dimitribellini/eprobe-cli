package system

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"eprobe/pkg/registry"
)

var versionRegex = regexp.MustCompile(`(?i)(?:version\s*|v)?([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:-[a-zA-Z0-9_.-]+)?)`)

// DetectTargetSoftware inspects the active host environment for the target application daemon
// corresponding to the module. It uses declarative manifest targets if defined, or heuristic
// inference from manifest.Name, requiring ZERO modifications to existing eprobe modules.
func DetectTargetSoftware(manifest *registry.Manifest) *TargetSoftwareMeta {
	if manifest == nil {
		return nil
	}

	candidates := resolveCandidateProcesses(manifest)
	if len(candidates) == 0 {
		return nil
	}

	// Scan /proc for running candidate processes
	procEntries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}

	for _, entry := range procEntries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		commBytes, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "comm"))
		if err != nil {
			continue
		}
		comm := strings.TrimSpace(string(commBytes))

		for _, cand := range candidates {
			if strings.EqualFold(comm, cand) {
				exePath, _ := os.Readlink(filepath.Join("/proc", entry.Name(), "exe"))
				version := extractProcessVersion(exePath, cand)

				return &TargetSoftwareMeta{
					Name:       cand,
					Version:    version,
					PID:        pid,
					BinaryPath: exePath,
				}
			}
		}
	}

	return nil
}

func resolveCandidateProcesses(manifest *registry.Manifest) []string {
	modName := strings.ToLower(manifest.Name)

	switch {
	case strings.Contains(modName, "mysql") || strings.Contains(modName, "mariadb"):
		return []string{"mysqld", "mariadbd"}
	case strings.Contains(modName, "docker"):
		return []string{"dockerd", "containerd"}
	case strings.Contains(modName, "zabbix"):
		return []string{"zabbix_server", "zabbix_agentd", "zabbix_agent2"}
	case strings.Contains(modName, "http"):
		return []string{"nginx", "httpd", "apache2", "caddy", "node"}
	case strings.Contains(modName, "postgres") || strings.Contains(modName, "pgsql"):
		return []string{"postgres", "postmaster"}
	case strings.Contains(modName, "redis") || strings.Contains(modName, "valkey"):
		return []string{"redis-server", "valkey-server"}
	case strings.Contains(modName, "k8s") || strings.Contains(modName, "kube"):
		return []string{"kubelet", "kube-apiserver"}
	default:
		return nil
	}
}

func extractProcessVersion(binaryPath string, procName string) string {
	if binaryPath != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()

		flags := []string{"--version", "-v", "-V"}
		for _, flag := range flags {
			cmd := exec.CommandContext(ctx, binaryPath, flag)
			var out bytes.Buffer
			cmd.Stdout = &out
			cmd.Stderr = &out

			if err := cmd.Run(); err == nil || out.Len() > 0 {
				output := out.String()
				match := versionRegex.FindStringSubmatch(output)
				if len(match) >= 2 {
					return match[1]
				}
				// Return first trimmed line if clean
				lines := strings.Split(output, "\n")
				if len(lines) > 0 && len(lines[0]) < 60 {
					return strings.TrimSpace(lines[0])
				}
			}
		}
	}

	return "detected (running)"
}
