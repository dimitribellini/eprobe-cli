package system

import (
	"testing"

	"eprobe/pkg/registry"
)

func TestCollectHostInfo(t *testing.T) {
	manifest := &registry.Manifest{
		Name:        "app/http-tracer",
		Version:     "2.0.12",
		Description: "Real-time HTTP stream latency",
	}

	info := CollectHostInfo(manifest)
	if info == nil {
		t.Fatalf("CollectHostInfo returned nil")
	}

	if info.Hostname == "" {
		t.Errorf("expected non-empty hostname")
	}
	if info.Arch == "" {
		t.Errorf("expected non-empty arch")
	}
	if info.OS == "" {
		t.Errorf("expected non-empty OS")
	}
	if info.CPU.Cores <= 0 {
		t.Errorf("expected CPU cores > 0, got %d", info.CPU.Cores)
	}
	if info.Memory.TotalBytes <= 0 {
		t.Errorf("expected TotalBytes > 0, got %d", info.Memory.TotalBytes)
	}
}
