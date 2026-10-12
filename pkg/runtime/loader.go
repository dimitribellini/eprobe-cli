package runtime

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"eprobe/pkg/registry"
)

// ModuleOptions contains optional parameters for loading eBPF modules
type ModuleOptions struct {
	FilterPort      uint16
	FilterPID       uint32
	SlowThresholdUS uint64
	CustomLibSSL    string
	FilterErrors    bool
}

// resolveLibSSLPath locates an active libssl.so on the system or validates the custom path.
func resolveLibSSLPath(customPath string) (string, error) {
	if customPath != "" {
		if _, err := os.Stat(customPath); err == nil {
			return customPath, nil
		}
		return "", fmt.Errorf("specified libssl path %q not found", customPath)
	}

	candidates := []string{
		"/usr/lib64/libssl.so.3",
		"/usr/lib/x86_64-linux-gnu/libssl.so.3",
		"/usr/lib64/libssl.so.1.1",
		"/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
		"/lib64/libssl.so.3",
		"/lib/x86_64-linux-gnu/libssl.so.3",
		"/lib/libssl.so.3",
		"/usr/lib/libssl.so.3",
		"/usr/lib64/libssl.so",
		"/usr/lib/x86_64-linux-gnu/libssl.so",
	}

	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	return "", fmt.Errorf("unable to auto-discover libssl.so on host (please specify via --libssl <path>)")
}

// LoadedModule holds the references to the active eBPF collection and its hooks
type LoadedModule struct {
	Collection *ebpf.Collection
	Links      []link.Link
	Manifest   *registry.Manifest
}

// Close detaches all hooks and releases the eBPF collection
func (lm *LoadedModule) Close() {
	for _, l := range lm.Links {
		l.Close()
	}
	if lm.Collection != nil {
		lm.Collection.Close()
	}
}

// LoadModule loads the eBPF ELF binary, performs relocations, and attaches to hooks dynamically using cache manifests
func LoadModule(name string, opts ModuleOptions) (*LoadedModule, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		fmt.Printf("Warning: failed to remove memlock: %v\n", err)
	}

	modDir := registry.GetModulePath(name)

	// 1. Read manifest.yaml dynamically
	manifestPath := filepath.Join(modDir, "manifest.yaml")
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read module manifest: %w", err)
	}

	// 2. Parse manifest
	manifest, err := registry.ParseManifest(manifestBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse manifest: %w", err)
	}
	if len(manifest.AttachPoints) == 0 {
		return nil, fmt.Errorf("no attach points defined in module manifest")
	}

	// 3. Read program.o dynamically
	programPath := filepath.Join(modDir, "program.o")
	elfBytes, err := os.ReadFile(programPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read module program.o: %w", err)
	}

	// 4. Load the collection spec from ELF bytes
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(elfBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to load collection spec: %w", err)
	}

	// 5. Rewrite variables dynamically if options are supplied
	for _, vInfo := range manifest.Variables {
		if vInfo.CLIFlag == "port" && opts.FilterPort != 0 {
			if v, ok := spec.Variables[vInfo.Name]; ok {
				if err := v.Set(opts.FilterPort); err != nil {
					return nil, fmt.Errorf("failed to set variable %s: %w", vInfo.Name, err)
				}
			}
		} else if vInfo.CLIFlag == "pid" && opts.FilterPID != 0 {
			if v, ok := spec.Variables[vInfo.Name]; ok {
				if err := v.Set(opts.FilterPID); err != nil {
					return nil, fmt.Errorf("failed to set variable %s: %w", vInfo.Name, err)
				}
			}
		} else if (vInfo.CLIFlag == "slow-us" || vInfo.CLIFlag == "slow_us" || vInfo.CLIFlag == "slow") && opts.SlowThresholdUS != 0 {
			if v, ok := spec.Variables[vInfo.Name]; ok {
				if err := v.Set(opts.SlowThresholdUS); err != nil {
					return nil, fmt.Errorf("failed to set variable %s: %w", vInfo.Name, err)
				}
			}
		} else if (vInfo.CLIFlag == "errors-only" || vInfo.CLIFlag == "errors_only") && opts.FilterErrors {
			if v, ok := spec.Variables[vInfo.Name]; ok {
				if err := v.Set(uint8(1)); err != nil {
					return nil, fmt.Errorf("failed to set variable %s: %w", vInfo.Name, err)
				}
			}
		}
	}

	// 6. Load collection into kernel (performs automatic CO-RE relocations against host BTF)
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to load ebpf collection into kernel: %w", err)
	}

	lm := &LoadedModule{
		Collection: coll,
		Links:      make([]link.Link, 0),
		Manifest:   manifest,
	}

	// Cache executable handles for uprobes
	execMap := make(map[string]*link.Executable)

	// 7. Attach hooks dynamically matching manifest specifications
	for _, ap := range manifest.AttachPoints {
		prog, ok := coll.Programs[ap.Section]
		if !ok {
			lm.Close()
			return nil, fmt.Errorf("program section %s not found in ELF", ap.Section)
		}

		if ap.Type == "tracepoint" {
			sys := "syscalls"
			hook := ap.Symbol
			if parts := strings.Split(ap.Symbol, "/"); len(parts) == 2 {
				sys = parts[0]
				hook = parts[1]
			} else if parts := strings.Split(ap.Symbol, ":"); len(parts) == 2 {
				sys = parts[0]
				hook = parts[1]
			}
			tp, err := link.Tracepoint(sys, hook, prog, nil)
			if err != nil {
				lm.Close()
				return nil, fmt.Errorf("failed to attach tracepoint %s/%s: %w", sys, hook, err)
			}
			lm.Links = append(lm.Links, tp)
		} else if ap.Type == "kprobe" {
			kp, err := link.Kprobe(ap.Symbol, prog, nil)
			if err != nil {
				lm.Close()
				return nil, fmt.Errorf("failed to attach kprobe %s: %w", ap.Symbol, err)
			}
			lm.Links = append(lm.Links, kp)
		} else if ap.Type == "raw_tracepoint" {
			rtp, err := link.AttachRawTracepoint(link.RawTracepointOptions{
				Name:    ap.Symbol,
				Program: prog,
			})
			if err != nil {
				lm.Close()
				return nil, fmt.Errorf("failed to attach raw_tracepoint %s: %w", ap.Symbol, err)
			}
			lm.Links = append(lm.Links, rtp)
		} else if ap.Type == "uprobe" || ap.Type == "uretprobe" {
			targetLib, err := resolveLibSSLPath(opts.CustomLibSSL)
			if err != nil {
				lm.Close()
				return nil, fmt.Errorf("failed to resolve target library for %s (%s): %w", ap.Type, ap.Symbol, err)
			}

			ex, ok := execMap[targetLib]
			if !ok {
				var openErr error
				ex, openErr = link.OpenExecutable(targetLib)
				if openErr != nil {
					lm.Close()
					return nil, fmt.Errorf("failed to open executable %s: %w", targetLib, openErr)
				}
				execMap[targetLib] = ex
			}

			if ap.Type == "uprobe" {
				up, err := ex.Uprobe(ap.Symbol, prog, nil)
				if err != nil {
					// Gracefully skip optional extended symbols like SSL_write_ex on older libssl
					if strings.HasSuffix(ap.Symbol, "_ex") {
						fmt.Printf("Notice: optional uprobe symbol %s not found in %s, skipping\n", ap.Symbol, targetLib)
						continue
					}
					lm.Close()
					return nil, fmt.Errorf("failed to attach uprobe %s in %s: %w", ap.Symbol, targetLib, err)
				}
				lm.Links = append(lm.Links, up)
			} else {
				urp, err := ex.Uretprobe(ap.Symbol, prog, nil)
				if err != nil {
					if strings.HasSuffix(ap.Symbol, "_ex") {
						fmt.Printf("Notice: optional uretprobe symbol %s not found in %s, skipping\n", ap.Symbol, targetLib)
						continue
					}
					lm.Close()
					return nil, fmt.Errorf("failed to attach uretprobe %s in %s: %w", ap.Symbol, targetLib, err)
				}
				lm.Links = append(lm.Links, urp)
			}
		} else {
			lm.Close()
			return nil, fmt.Errorf("unsupported attach point type: %s", ap.Type)
		}
	}

	return lm, nil
}

