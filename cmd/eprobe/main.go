package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"eprobe/pkg/registry"
	"eprobe/pkg/runtime"
	"eprobe/pkg/security"
	"eprobe/pkg/telemetry"
)

var version = "dev"

func printUsage() {
	fmt.Printf(`eprobe: The On-Demand, Zero-Dependency eBPF Diagnostics Platform (version: %s)

Commands:
  run <module>          Execute an eBPF diagnostic module (auto-pulls if missing)
  pull <module>         Download and verify a module from the remote registry
  list                  List locally cached diagnostic modules
  search                Search the remote registry catalog for available modules
  describe <module>     Display detailed configuration layout of a cached module
  remove <module>       Delete a cached module from local storage (aliases: delete, rm)
  update <module>       Check remote registry and update local cached module
  version               Display software version information
  help [module]         Show general help or detailed documentation for a specific module

Global Flags:
  -output, --output             Output format: 'tui' (default), 'text', 'json', 'ndjson', or 'stream'
  -port, --port                 Port filter for network trace (default: 0, matches all ports)
  -pid, --pid                   Filter events by process PID (default: 0, matches all processes)
  -slow-us, --slow-us           Slow request/query threshold in microseconds (e.g. 50000)
  -slow-ms, --slow-ms           Slow request/query threshold in milliseconds (e.g. 50)
  -registry, --registry         Registry API base URL (default: https://api.eprobe.io)
  -stream-token, --stream-token Stream token UUID for real-time SaaS portal streaming
  -stream-url, --stream-url     SaaS streaming portal URL (default: https://stream.eprobe.io)
  -h, --help                    Show usage help message
  -v, --version                 Show software version information

Environment Variables:
  REGISTRY_URL                  Override default registry API base URL (default: https://api.eprobe.io)
  EPROBE_STREAM_TOKEN           Default stream token UUID for SaaS portal export
  EPROBE_STREAM_URL             Override default stream portal URL (default: https://stream.eprobe.io)

Examples:
  # Pull a module from the Remote Registry without running it
  eprobe pull sec/exec-audit

  # List locally downloaded and cached diagnostic modules
  eprobe list

  # Display dedicated parameters, filters, and dashboard pages for a module
  eprobe help app/universal-tls-sniffer

  # Run process execution monitor (automatically pulls if missing)
  sudo ./eprobe run sec/exec-audit

  # Stream live eBPF metrics to the SaaS web portal while displaying local TUI
  sudo ./eprobe run app/http-tracer -stream-token 3a4b9c1d-8e7f-4a5b-9c8d-7e6f5a4b3c2d

  # Stream live eBPF metrics headlessly to a local/on-premise portal
  sudo ./eprobe run app/http-tracer -stream-token <UUID> -stream-url https://192.168.1.50 -output stream

  # Stream TCP traffic events on port 80 in JSON format
  sudo ./eprobe run app/http-tracer -port 80 -output json

  # Display the configuration layout of a cached module
  eprobe describe app/http-tracer

  # Delete a cached module
  eprobe remove app/http-tracer

Requirements:
  - Root privileges (sudo) to load and link eBPF bytecode programs.
  - Linux kernel supporting BPF Type Format (BTF) at /sys/kernel/btf/vmlinux.
`, version)
}

type ParsedOptions struct {
	Cmd             string
	Module          string
	OutputFormat    string
	FilterPort      uint16
	FilterPID       uint32
	SlowThresholdUS uint64
	CustomLibSSL    string
	FilterComm      string
	FilterHost      string
	FilterErrors    bool
	Sanitize        bool
	RegistryURL     string
	StreamToken     string
	StreamURL       string
}

func parseArgs() (opts ParsedOptions, err error) {
	opts.OutputFormat = "tui"
	opts.FilterPort = 0
	opts.FilterPID = 0
	opts.SlowThresholdUS = 0
	opts.Sanitize = true // Enabled by default to protect secrets/Bearer tokens
	opts.RegistryURL = "https://api.eprobe.io"
	if envReg := os.Getenv("REGISTRY_URL"); envReg != "" {
		opts.RegistryURL = envReg
	}

	opts.StreamURL = telemetry.DefaultStreamURL
	if envStreamURL := os.Getenv("EPROBE_STREAM_URL"); envStreamURL != "" {
		opts.StreamURL = envStreamURL
	} else if envStreamURL := os.Getenv("STREAM_URL"); envStreamURL != "" {
		opts.StreamURL = envStreamURL
	}

	if envStreamTok := os.Getenv("EPROBE_STREAM_TOKEN"); envStreamTok != "" {
		opts.StreamToken = envStreamTok
	} else if envStreamTok := os.Getenv("STREAM_TOKEN"); envStreamTok != "" {
		opts.StreamToken = envStreamTok
	}

	if len(os.Args) < 2 {
		return opts, fmt.Errorf("no arguments provided")
	}

	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]

		switch arg {
		case "help":
			opts.Cmd = "help"
			if i+1 < len(os.Args) && !strings.HasPrefix(os.Args[i+1], "-") {
				opts.Module = os.Args[i+1]
				i++
			}
			return opts, nil
		case "-h", "--help":
			opts.Cmd = "help"
			return opts, nil
		case "-version", "--version", "version", "-v":
			opts.Cmd = "version"
			return opts, nil
		case "-output", "--output":
			if i+1 >= len(os.Args) {
				return opts, fmt.Errorf("missing value for flag %s", arg)
			}
			opts.OutputFormat = os.Args[i+1]
			i++ // skip value
		case "-port", "--port":
			if i+1 >= len(os.Args) {
				return opts, fmt.Errorf("missing value for flag %s", arg)
			}
			portVal, err := strconv.Atoi(os.Args[i+1])
			if err != nil || portVal < 1 || portVal > 65535 {
				return opts, fmt.Errorf("invalid port value %q (must be 1-65535)", os.Args[i+1])
			}
			opts.FilterPort = uint16(portVal)
			i++ // skip value
		case "-pid", "--pid":
			if i+1 >= len(os.Args) {
				return opts, fmt.Errorf("missing value for flag %s", arg)
			}
			pidVal, err := strconv.Atoi(os.Args[i+1])
			if err != nil || pidVal < 1 {
				return opts, fmt.Errorf("invalid pid value %q", os.Args[i+1])
			}
			opts.FilterPID = uint32(pidVal)
			i++ // skip value
		case "-slow-us", "--slow-us":
			if i+1 >= len(os.Args) {
				return opts, fmt.Errorf("missing value for flag %s", arg)
			}
			slowVal, err := strconv.ParseUint(os.Args[i+1], 10, 64)
			if err != nil || slowVal == 0 {
				return opts, fmt.Errorf("invalid slow-us value %q", os.Args[i+1])
			}
			opts.SlowThresholdUS = slowVal
			i++ // skip value
		case "-slow-ms", "--slow-ms":
			if i+1 >= len(os.Args) {
				return opts, fmt.Errorf("missing value for flag %s", arg)
			}
			slowVal, err := strconv.ParseUint(os.Args[i+1], 10, 64)
			if err != nil || slowVal == 0 {
				return opts, fmt.Errorf("invalid slow-ms value %q", os.Args[i+1])
			}
			opts.SlowThresholdUS = slowVal * 1000
			i++ // skip value
		case "-libssl", "--libssl":
			if i+1 >= len(os.Args) {
				return opts, fmt.Errorf("missing value for flag %s", arg)
			}
			opts.CustomLibSSL = os.Args[i+1]
			i++
		case "-comm", "--comm":
			if i+1 >= len(os.Args) {
				return opts, fmt.Errorf("missing value for flag %s", arg)
			}
			opts.FilterComm = os.Args[i+1]
			i++
		case "-host", "--host":
			if i+1 >= len(os.Args) {
				return opts, fmt.Errorf("missing value for flag %s", arg)
			}
			opts.FilterHost = os.Args[i+1]
			i++
		case "-errors-only", "--errors-only":
			opts.FilterErrors = true
		case "-sanitize", "--sanitize":
			opts.Sanitize = true
		case "-no-sanitize", "--no-sanitize":
			opts.Sanitize = false
		case "-registry", "--registry":
			if i+1 >= len(os.Args) {
				return opts, fmt.Errorf("missing value for flag %s", arg)
			}
			opts.RegistryURL = os.Args[i+1]
			i++ // skip value
		case "-stream-token", "--stream-token":
			if i+1 >= len(os.Args) {
				return opts, fmt.Errorf("missing value for flag %s", arg)
			}
			opts.StreamToken = os.Args[i+1]
			i++ // skip value
		case "-stream-url", "--stream-url":
			if i+1 >= len(os.Args) {
				return opts, fmt.Errorf("missing value for flag %s", arg)
			}
			opts.StreamURL = os.Args[i+1]
			i++ // skip value
		default:
			// Check if it's a key-value style flag like -output=json
			if (len(arg) > 8 && arg[:8] == "-output=") || (len(arg) > 9 && arg[:9] == "--output=") {
				parts := strings.SplitN(arg, "=", 2)
				opts.OutputFormat = parts[1]
			} else if (len(arg) > 6 && arg[:6] == "-port=") || (len(arg) > 7 && arg[:7] == "--port=") {
				parts := strings.SplitN(arg, "=", 2)
				portVal, err := strconv.Atoi(parts[1])
				if err != nil || portVal < 1 || portVal > 65535 {
					return opts, fmt.Errorf("invalid port value %q (must be 1-65535)", parts[1])
				}
				opts.FilterPort = uint16(portVal)
			} else if (len(arg) > 5 && arg[:5] == "-pid=") || (len(arg) > 6 && arg[:6] == "--pid=") {
				parts := strings.SplitN(arg, "=", 2)
				pidVal, err := strconv.Atoi(parts[1])
				if err != nil || pidVal < 1 {
					return opts, fmt.Errorf("invalid pid value %q", parts[1])
				}
				opts.FilterPID = uint32(pidVal)
			} else if (len(arg) > 9 && arg[:9] == "-slow-us=") || (len(arg) > 10 && arg[:10] == "--slow-us=") {
				parts := strings.SplitN(arg, "=", 2)
				slowVal, err := strconv.ParseUint(parts[1], 10, 64)
				if err != nil || slowVal == 0 {
					return opts, fmt.Errorf("invalid slow-us value %q", parts[1])
				}
				opts.SlowThresholdUS = slowVal
			} else if (len(arg) > 9 && arg[:9] == "-slow-ms=") || (len(arg) > 10 && arg[:10] == "--slow-ms=") {
				parts := strings.SplitN(arg, "=", 2)
				slowVal, err := strconv.ParseUint(parts[1], 10, 64)
				if err != nil || slowVal == 0 {
					return opts, fmt.Errorf("invalid slow-ms value %q", parts[1])
				}
				opts.SlowThresholdUS = slowVal * 1000
			} else if (len(arg) > 8 && arg[:8] == "-libssl=") || (len(arg) > 9 && arg[:9] == "--libssl=") {
				parts := strings.SplitN(arg, "=", 2)
				opts.CustomLibSSL = parts[1]
			} else if (len(arg) > 6 && arg[:6] == "-comm=") || (len(arg) > 7 && arg[:7] == "--comm=") {
				parts := strings.SplitN(arg, "=", 2)
				opts.FilterComm = parts[1]
			} else if (len(arg) > 6 && arg[:6] == "-host=") || (len(arg) > 7 && arg[:7] == "--host=") {
				parts := strings.SplitN(arg, "=", 2)
				opts.FilterHost = parts[1]
			} else if (len(arg) > 10 && arg[:10] == "-registry=") || (len(arg) > 11 && arg[:11] == "--registry=") {
				parts := strings.SplitN(arg, "=", 2)
				opts.RegistryURL = parts[1]
			} else if (len(arg) > 14 && arg[:14] == "-stream-token=") || (len(arg) > 15 && arg[:15] == "--stream-token=") {
				parts := strings.SplitN(arg, "=", 2)
				opts.StreamToken = parts[1]
			} else if (len(arg) > 12 && arg[:12] == "-stream-url=") || (len(arg) > 13 && arg[:13] == "--stream-url=") {
				parts := strings.SplitN(arg, "=", 2)
				opts.StreamURL = parts[1]
			} else if arg == "run" || arg == "pull" || arg == "describe" || arg == "remove" || arg == "delete" || arg == "rm" || arg == "update" {
				opts.Cmd = arg
				if arg == "remove" || arg == "delete" || arg == "rm" {
					opts.Cmd = "remove"
				}
				if i+1 < len(os.Args) && !strings.HasPrefix(os.Args[i+1], "-") {
					opts.Module = os.Args[i+1]
					i++
				}
			} else if arg == "list" {
				opts.Cmd = "list"
			} else if arg == "search" {
				opts.Cmd = "search"
			} else if opts.Cmd != "" && opts.Module == "" && !strings.HasPrefix(arg, "-") {
				opts.Module = arg
			} else if (arg == "-h" || arg == "--help") && opts.Cmd == "run" && opts.Module != "" {
				opts.Cmd = "help"
				return opts, nil
			} else {
				// Unknown argument starting with -
				if len(arg) > 0 && arg[0] == '-' {
					return opts, fmt.Errorf("unknown flag: %s", arg)
				}
			}
		}
	}

	if opts.OutputFormat == "stream" && opts.StreamToken == "" {
		return opts, fmt.Errorf("-output stream requires -stream-token or EPROBE_STREAM_TOKEN to be specified")
	}

	return opts, nil
}

func main() {
	opts, err := parseArgs()
	if err != nil {
		printUsage()
		fmt.Printf("\nError: %v\n", err)
		os.Exit(1)
	}

	if opts.Cmd == "help" || opts.Cmd == "" {
		if opts.Module != "" {
			if err := registry.ShowModuleHelp(opts.Module); err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}
			os.Exit(0)
		}
		printUsage()
		os.Exit(0)
	}

	if opts.Cmd == "version" {
		fmt.Printf("eprobe version %s\n", version)
		os.Exit(0)
	}

	// 1. Handle command subcommands that do not require root permissions
	switch opts.Cmd {
	case "list":
		err = registry.ListModules()
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)

	case "search":
		err = registry.SearchRemoteModules(context.Background(), opts.RegistryURL)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)

	case "describe":
		if opts.Module == "" {
			fmt.Println("Error: missing module name. Usage: eprobe describe <module>")
			os.Exit(1)
		}
		err = registry.DescribeModule(opts.Module)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)

	case "remove":
		if opts.Module == "" {
			fmt.Println("Error: missing module name. Usage: eprobe remove <module>")
			os.Exit(1)
		}
		err = registry.RemoveModule(opts.Module)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)

	case "pull":
		if opts.Module == "" {
			fmt.Println("Error: missing module name. Usage: eprobe pull <module>")
			os.Exit(1)
		}
		if valErr := registry.ValidateModuleName(opts.Module); valErr != nil {
			fmt.Printf("Error: %v\n", valErr)
			os.Exit(1)
		}
		pubKey := security.GetDefaultPublicKey()
		err = registry.PullModule(context.Background(), opts.Module, opts.RegistryURL, pubKey)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)

	case "update":
		if opts.Module == "" {
			fmt.Println("Error: missing module name. Usage: eprobe update <module>")
			os.Exit(1)
		}
		if valErr := registry.ValidateModuleName(opts.Module); valErr != nil {
			fmt.Printf("Error: %v\n", valErr)
			os.Exit(1)
		}
		pubKey := security.GetDefaultPublicKey()
		err = registry.UpdateModule(context.Background(), opts.Module, opts.RegistryURL, pubKey)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// 2. Handle the "run" command execution (requires root privileges)
	if opts.Cmd != "run" {
		printUsage()
		os.Exit(1)
	}

	if opts.Module == "" {
		fmt.Println("Error: missing module name. Usage: eprobe run <module>")
		os.Exit(1)
	}

	// Validate module name before any further operations
	if valErr := registry.ValidateModuleName(opts.Module); valErr != nil {
		fmt.Printf("Error: %v\n", valErr)
		os.Exit(1)
	}

	// Root check BEFORE auto-pull to avoid downloading as non-root into wrong cache dir
	if os.Geteuid() != 0 {
		fmt.Println("Error: eprobe must be run as root (sudo) to load eBPF programs.")
		os.Exit(1)
	}

	// Dynamic auto-pull logic if not locally cached
	if !registry.IsModuleCached(opts.Module) {
		fmt.Printf("Module %q is not cached locally. Pulling from registry...\n", opts.Module)
		pubKey := security.GetDefaultPublicKey()
		err = registry.PullModule(context.Background(), opts.Module, opts.RegistryURL, pubKey)
		if err != nil {
			fmt.Printf("Error: failed to pull module: %v\n", err)
			os.Exit(1)
		}
	}

	fmt.Printf("Starting eprobe module %s...\n", opts.Module)

	// Set up cancellation context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Intercept terminate signals
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		fmt.Println("\nStopping eprobe...")
		cancel()
	}()

	// Load eBPF module dynamically from the local cache folder
	lm, err := runtime.LoadModule(opts.Module, runtime.ModuleOptions{
		FilterPort:      opts.FilterPort,
		FilterPID:       opts.FilterPID,
		SlowThresholdUS: opts.SlowThresholdUS,
		CustomLibSSL:    opts.CustomLibSSL,
		FilterErrors:    opts.FilterErrors,
	})
	if err != nil {
		fmt.Printf("Failed to load module: %v\n", err)
		os.Exit(1)
	}
	defer lm.Close()

	fmt.Println("Listening for kernel events... Press Ctrl+C to exit.")

	filterCfg := telemetry.FilterConfig{
		FilterPort:   opts.FilterPort,
		FilterComm:   opts.FilterComm,
		FilterHost:   opts.FilterHost,
		FilterErrors: opts.FilterErrors,
		Sanitize:     opts.Sanitize,
	}

	// Listen and stream raw Ring Buffer events
	err = telemetry.ListenAndStream(ctx, lm.Collection.Maps, lm.Manifest, os.Stdout, opts.OutputFormat, version, filterCfg, opts.StreamToken, opts.StreamURL)
	if err != nil {
		fmt.Printf("Telemetry pipeline error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Exited successfully.")
}
