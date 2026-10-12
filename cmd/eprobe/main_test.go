package main

import (
	"os"
	"testing"
)

func TestParseArgsDefaults(t *testing.T) {
	os.Args = []string{"eprobe", "search"}
	opts, err := parseArgs()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if opts.Cmd != "search" {
		t.Errorf("expected cmd 'search', got %q", opts.Cmd)
	}
	if opts.Module != "" {
		t.Errorf("expected empty module, got %q", opts.Module)
	}
	if opts.OutputFormat != "tui" {
		t.Errorf("expected default output 'tui', got %q", opts.OutputFormat)
	}
	if opts.FilterPort != 0 {
		t.Errorf("expected default port 0, got %d", opts.FilterPort)
	}
	if opts.FilterPID != 0 {
		t.Errorf("expected default pid 0, got %d", opts.FilterPID)
	}
	if opts.SlowThresholdUS != 0 {
		t.Errorf("expected default slow threshold 0, got %d", opts.SlowThresholdUS)
	}
	if opts.RegistryURL != "https://api.eprobe.io" {
		t.Errorf("expected default registry 'https://api.eprobe.io', got %q", opts.RegistryURL)
	}
	if opts.StreamToken != "" {
		t.Errorf("expected empty streamToken, got %q", opts.StreamToken)
	}
	if opts.StreamURL != "https://stream.eprobe.io" {
		t.Errorf("expected default streamURL 'https://stream.eprobe.io', got %q", opts.StreamURL)
	}
}

func TestParseArgsEnvOverride(t *testing.T) {
	t.Setenv("REGISTRY_URL", "https://custom-registry.eprobe.io")
	t.Setenv("EPROBE_STREAM_TOKEN", "env-token-123")
	t.Setenv("EPROBE_STREAM_URL", "https://custom-stream.eprobe.io")

	os.Args = []string{"eprobe", "list"}
	opts, err := parseArgs()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if opts.RegistryURL != "https://custom-registry.eprobe.io" {
		t.Errorf("expected env override 'https://custom-registry.eprobe.io', got %q", opts.RegistryURL)
	}
	if opts.StreamToken != "env-token-123" {
		t.Errorf("expected env override 'env-token-123', got %q", opts.StreamToken)
	}
	if opts.StreamURL != "https://custom-stream.eprobe.io" {
		t.Errorf("expected env override 'https://custom-stream.eprobe.io', got %q", opts.StreamURL)
	}
}

func TestParseArgsOrderIndependence(t *testing.T) {
	os.Args = []string{
		"eprobe", "run",
		"-output", "json",
		"-port", "8080",
		"-pid", "12345",
		"-slow-us", "25000",
		"-registry", "http://localhost:8080",
		"-stream-token", "tok-xyz",
		"-stream-url", "https://stream.local",
		"app/http-tracer",
	}
	opts, err := parseArgs()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if opts.Cmd != "run" {
		t.Errorf("expected cmd 'run', got %q", opts.Cmd)
	}
	if opts.Module != "app/http-tracer" {
		t.Errorf("expected module 'app/http-tracer', got %q", opts.Module)
	}
	if opts.OutputFormat != "json" {
		t.Errorf("expected output 'json', got %q", opts.OutputFormat)
	}
	if opts.FilterPort != 8080 {
		t.Errorf("expected port 8080, got %d", opts.FilterPort)
	}
	if opts.FilterPID != 12345 {
		t.Errorf("expected pid 12345, got %d", opts.FilterPID)
	}
	if opts.SlowThresholdUS != 25000 {
		t.Errorf("expected slow-us 25000, got %d", opts.SlowThresholdUS)
	}
	if opts.RegistryURL != "http://localhost:8080" {
		t.Errorf("expected registry 'http://localhost:8080', got %q", opts.RegistryURL)
	}
	if opts.StreamToken != "tok-xyz" {
		t.Errorf("expected streamToken 'tok-xyz', got %q", opts.StreamToken)
	}
	if opts.StreamURL != "https://stream.local" {
		t.Errorf("expected streamURL 'https://stream.local', got %q", opts.StreamURL)
	}
}

func TestParseArgsSlowMS(t *testing.T) {
	os.Args = []string{"eprobe", "run", "app/http-tracer", "-slow-ms", "50"}
	opts, err := parseArgs()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.SlowThresholdUS != 50000 {
		t.Errorf("expected slow-ms 50 to convert to 50000 us, got %d", opts.SlowThresholdUS)
	}
}

func TestParseArgsStreamOutputValidation(t *testing.T) {
	// -output stream without token should fail
	os.Args = []string{"eprobe", "run", "app/http-tracer", "-output", "stream"}
	_, err := parseArgs()
	if err == nil {
		t.Errorf("expected error when -output stream is used without -stream-token")
	}

	// -output stream with token should succeed
	os.Args = []string{"eprobe", "run", "app/http-tracer", "-output", "stream", "-stream-token", "valid-uuid"}
	opts, err := parseArgs()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.Cmd != "run" || opts.Module != "app/http-tracer" || opts.OutputFormat != "stream" || opts.StreamToken != "valid-uuid" {
		t.Errorf("unexpected parse result: cmd=%s, module=%s, output=%s, token=%s", opts.Cmd, opts.Module, opts.OutputFormat, opts.StreamToken)
	}
}

func TestParseArgsCommandAliases(t *testing.T) {
	os.Args = []string{"eprobe", "rm", "sec/exec-audit"}
	opts, err := parseArgs()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if opts.Cmd != "remove" {
		t.Errorf("expected aliased cmd 'remove', got %q", opts.Cmd)
	}
	if opts.Module != "sec/exec-audit" {
		t.Errorf("expected module 'sec/exec-audit', got %q", opts.Module)
	}
}
