package system

import (
	"bufio"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"eprobe/pkg/registry"
)

type CPUInfo struct {
	Cores   int    `json:"cores"`
	Model   string `json:"model"`
	Sockets int    `json:"sockets,omitempty"`
}

type MemoryInfo struct {
	TotalBytes     uint64 `json:"total_bytes"`
	SwapTotalBytes uint64 `json:"swap_total_bytes,omitempty"`
}

type RuntimeInfo struct {
	Virtualization string `json:"virtualization,omitempty"`
	CloudProvider  string `json:"cloud_provider,omitempty"`
	InContainer    bool   `json:"in_container"`
	CgroupVersion  int    `json:"cgroup_version"`
}

type ContainerMeta struct {
	Name  string `json:"name"`
	Image string `json:"image,omitempty"`
}

type TargetSoftwareMeta struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	PID        int    `json:"pid,omitempty"`
	BinaryPath string `json:"binary_path,omitempty"`
}

type HostInfo struct {
	Hostname       string                   `json:"hostname"`
	OS             string                   `json:"os"`
	Kernel         string                   `json:"kernel"`
	Arch           string                   `json:"arch"`
	CPU            CPUInfo                  `json:"cpu"`
	Memory         MemoryInfo               `json:"memory"`
	Runtime        RuntimeInfo              `json:"runtime"`
	Containers     map[string]ContainerMeta `json:"containers,omitempty"`
	TargetSoftware *TargetSoftwareMeta      `json:"target_software,omitempty"`
	BootTime       int64                    `json:"boot_time,omitempty"`
	CollectedAt    int64                    `json:"collected_at"`
}

// CollectHostInfo gathers host system metadata across enterprise Linux distros.
func CollectHostInfo(manifest *registry.Manifest) *HostInfo {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown-host"
	}

	info := &HostInfo{
		Hostname:    hostname,
		Arch:        runtime.GOARCH,
		Kernel:      detectKernelRelease(),
		OS:          detectOSDistribution(),
		CPU:         detectCPUInfo(),
		Memory:      detectMemoryInfo(),
		Runtime:     detectRuntimeInfo(),
		Containers:  ResolveContainers(),
		BootTime:    detectBootTime(),
		CollectedAt: time.Now().UnixMilli(),
	}

	// Detect target software using zero-migration heuristic/declarative inspection
	if manifest != nil {
		info.TargetSoftware = DetectTargetSoftware(manifest)
	}

	return info
}

func detectKernelRelease() string {
	if data, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		k := strings.TrimSpace(string(data))
		if k != "" {
			return k
		}
	}
	return runtime.GOOS + "-" + runtime.GOARCH
}

func detectOSDistribution() string {
	// Fallback chain: /etc/os-release -> /usr/lib/os-release -> /etc/redhat-release -> /etc/debian_version
	paths := []string{"/etc/os-release", "/usr/lib/os-release"}
	for _, p := range paths {
		if file, err := os.Open(p); err == nil {
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if strings.HasPrefix(line, "PRETTY_NAME=") {
					file.Close()
					val := strings.TrimPrefix(line, "PRETTY_NAME=")
					val = strings.Trim(val, `"`)
					if val != "" {
						return val
					}
				}
			}
			file.Close()
		}
	}

	if data, err := os.ReadFile("/etc/redhat-release"); err == nil {
		val := strings.TrimSpace(string(data))
		if val != "" {
			return val
		}
	}

	if data, err := os.ReadFile("/etc/debian_version"); err == nil {
		val := strings.TrimSpace(string(data))
		if val != "" {
			return "Debian " + val
		}
	}

	return "Linux " + detectKernelRelease()
}

func detectCPUInfo() CPUInfo {
	cpu := CPUInfo{
		Cores: runtime.NumCPU(),
		Model: "Unknown CPU",
	}

	if file, err := os.Open("/proc/cpuinfo"); err == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "model name") || strings.HasPrefix(line, "Model") || strings.HasPrefix(line, "Hardware") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					cpu.Model = strings.TrimSpace(parts[1])
					break
				}
			}
		}
	}

	return cpu
}

func detectMemoryInfo() MemoryInfo {
	mem := MemoryInfo{}
	if file, err := os.Open("/proc/meminfo"); err == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				key := strings.TrimSuffix(fields[0], ":")
				valKB, _ := strconv.ParseUint(fields[1], 10, 64)
				bytes := valKB * 1024

				if key == "MemTotal" {
					mem.TotalBytes = bytes
				} else if key == "SwapTotal" {
					mem.SwapTotalBytes = bytes
				}
			}
		}
	}
	return mem
}

func detectRuntimeInfo() RuntimeInfo {
	rt := RuntimeInfo{
		Virtualization: "bare-metal",
		CgroupVersion:  1,
	}

	// 1. Cgroup version check
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err == nil {
		rt.CgroupVersion = 2
	}

	// 2. Container check
	if _, err := os.Stat("/.dockerenv"); err == nil {
		rt.InContainer = true
	} else if _, err := os.Stat("/run/.containerenv"); err == nil {
		rt.InContainer = true
	} else if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		content := string(data)
		if strings.Contains(content, "docker") || strings.Contains(content, "kubepods") || strings.Contains(content, "containerd") {
			rt.InContainer = true
		}
	}

	// 3. Virtualization & Cloud check (DMI)
	dmiProduct := ""
	dmiVendor := ""
	if data, err := os.ReadFile("/sys/class/dmi/id/product_name"); err == nil {
		dmiProduct = strings.TrimSpace(string(data))
	}
	if data, err := os.ReadFile("/sys/class/dmi/id/sys_vendor"); err == nil {
		dmiVendor = strings.TrimSpace(string(data))
	}

	combined := strings.ToLower(dmiProduct + " " + dmiVendor)
	switch {
	case strings.Contains(combined, "amazon") || strings.Contains(combined, "ec2"):
		rt.Virtualization = "kvm"
		rt.CloudProvider = "aws"
	case strings.Contains(combined, "google"):
		rt.Virtualization = "kvm"
		rt.CloudProvider = "gcp"
	case strings.Contains(combined, "microsoft") || strings.Contains(combined, "azure"):
		rt.Virtualization = "hyper-v"
		rt.CloudProvider = "azure"
	case strings.Contains(combined, "vmware"):
		rt.Virtualization = "vmware"
	case strings.Contains(combined, "kvm") || strings.Contains(combined, "qemu"):
		rt.Virtualization = "kvm"
	case strings.Contains(combined, "virtualbox"):
		rt.Virtualization = "virtualbox"
	case dmiProduct != "":
		rt.Virtualization = dmiProduct
	}

	// Device-tree fallback for ARM boards (Raspberry Pi, etc.)
	if rt.Virtualization == "bare-metal" {
		if data, err := os.ReadFile("/proc/device-tree/model"); err == nil {
			model := strings.TrimRight(string(data), "\x00")
			if model != "" {
				rt.Virtualization = model
			}
		}
	}

	return rt
}

func detectBootTime() int64 {
	if file, err := os.Open("/proc/stat"); err == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "btime ") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					btime, _ := strconv.ParseInt(fields[1], 10, 64)
					return btime
				}
			}
		}
	}
	return 0
}
