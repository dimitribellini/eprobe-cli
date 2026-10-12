package telemetry

import (
	"strings"
	"testing"
)

func TestHistogramEngine(t *testing.T) {
	h := NewHistogram("latency_us", "us", []float64{0, 10, 50, 100})

	events := []map[string]interface{}{
		{"latency_us": 5},
		{"latency_us": 25},
		{"latency_us": 30},
		{"latency_us": 75},
		{"latency_us": 150},
	}

	for _, e := range events {
		h.Update(e)
	}

	if h.total != 5 {
		t.Fatalf("expected total 5, got %d", h.total)
	}

	rendered := h.Render(80, 20)
	if !strings.Contains(rendered, "Total Samples: 5") {
		t.Errorf("rendered histogram missing header: %s", rendered)
	}
	if !strings.Contains(rendered, "latency_us") {
		t.Errorf("rendered histogram missing field name: %s", rendered)
	}
}
