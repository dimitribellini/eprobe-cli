package telemetry

import (
	"strings"
	"testing"

	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

func TestFormatColumnTitle(t *testing.T) {
	tests := []struct {
		field    string
		label    string
		expected string
	}{
		{"duration_us", "", "DURATION"},
		{"latency_us", "", "LATENCY"},
		{"runq_latency_us", "", "RUNQ LATENCY"},
		{"client_ip", "", "CLIENT IP"},
		{"total_stall_ns", "", "TOTAL STALL"},
		{"query_count", "", "QUERY COUNT"},
		{"rx_bytes", "", "RX"},
		{"custom_field", "Custom Label", "CUSTOM LABEL"},
	}

	for _, tt := range tests {
		got := FormatColumnTitle(tt.field, tt.label)
		if got != tt.expected {
			t.Errorf("FormatColumnTitle(%q, %q) = %q, expected %q", tt.field, tt.label, got, tt.expected)
		}
	}
}

func TestIsLatencyField(t *testing.T) {
	if !IsLatencyField("duration_us", "") {
		t.Error("expected duration_us to be a latency field")
	}
	if !IsLatencyField("latency_ms", "") {
		t.Error("expected latency_ms to be a latency field")
	}
	if !IsLatencyField("runq_latency_us", "") {
		t.Error("expected runq_latency_us to be a latency field")
	}
	if !IsLatencyField("anything", "latency") {
		t.Error("expected format:latency to be a latency field")
	}
	if IsLatencyField("comm", "") {
		t.Error("comm should not be a latency field")
	}
}

func TestFormatLatency(t *testing.T) {
	lipgloss.SetColorProfile(termenv.TrueColor)

	// Microseconds scaling
	txt, _ := FormatLatency(500, "duration_us")
	if txt != "500 µs" {
		t.Errorf("expected '500 µs', got %q", txt)
	}

	txt, _ = FormatLatency(5500, "duration_us")
	if txt != "5.50 ms" {
		t.Errorf("expected '5.50 ms', got %q", txt)
	}

	txt, _ = FormatLatency(2500000, "duration_us")
	if txt != "2.50 s" {
		t.Errorf("expected '2.50 s', got %q", txt)
	}

	// Nanoseconds scaling
	txt, _ = FormatLatency(800, "stall_ns")
	if txt != "800 ns" {
		t.Errorf("expected '800 ns', got %q", txt)
	}

	txt, _ = FormatLatency(800000, "stall_ns")
	if txt != "800 µs" {
		t.Errorf("expected '800 µs', got %q", txt)
	}
}

func TestFormatSeverity(t *testing.T) {
	tokens := []string{"CRITICAL", "WARN", "INFO", "DEBUG", "OK"}
	for _, tok := range tokens {
		str, style := FormatSeverity(tok)
		if str != tok {
			t.Errorf("FormatSeverity(%q) returned string %q", tok, str)
		}
		rendered := style.Render(str)
		if !strings.Contains(rendered, tok) {
			t.Errorf("rendered severity should contain %q, got %q", tok, rendered)
		}
	}
}

func TestFormatRateMetric(t *testing.T) {
	// Duration rate in s/s (eliminates 167.6G/s)
	r1 := FormatRateMetric(167.4, "total_stall_ns", "s/s")
	if r1 != "167.4 s/s" {
		t.Errorf("expected '167.4 s/s', got %q", r1)
	}

	// CPU percentage
	r2 := FormatRateMetric(42.5, "cpu_time_ns", "%")
	if r2 != "42.5%" {
		t.Errorf("expected '42.5%%', got %q", r2)
	}

	// Network bytes rate
	r3 := FormatRateMetric(15000000, "tx_bytes", "bytes")
	if r3 != "15.0 MB/s" {
		t.Errorf("expected '15.0 MB/s', got %q", r3)
	}

	r4 := FormatRateMetric(2500, "queries", "qps")
	if r4 != "2.5K/s" {
		t.Errorf("expected '2.5K/s', got %q", r4)
	}
}

func TestFormatHistogramRange(t *testing.T) {
	r1 := FormatHistogramRange(0, 1000, "us")
	if r1 != "0µs-1ms" {
		t.Errorf("expected '0µs-1ms', got %q", r1)
	}

	r2 := FormatHistogramRange(20000, 50000, "us")
	if r2 != "20ms-50ms" {
		t.Errorf("expected '20ms-50ms', got %q", r2)
	}

	r3 := FormatHistogramRange(2000000, 0, "us")
	if r3 != ">= 2s" {
		t.Errorf("expected '>= 2s', got %q", r3)
	}
}

func TestRenderTableWithAnsi(t *testing.T) {
	lipgloss.SetColorProfile(termenv.TrueColor)
	str, style := FormatSeverity("CRITICAL")
	rendered := style.Render(str)

	tbl := table.New(
		table.WithColumns([]table.Column{
			{Title: "LEVEL", Width: 10},
			{Title: "COMM", Width: 12},
		}),
		table.WithRows([]table.Row{
			{rendered, "mariadbd"},
		}),
	)
	tbl.SetWidth(30)
	tbl.SetHeight(5)

	pm := &PaneModel{
		Table: tbl,
	}

	ansiView := renderPaneTable(pm, true)
	if !strings.Contains(ansiView, "LEVEL") || !strings.Contains(ansiView, "mariadbd") {
		t.Errorf("renderPaneTable output missing expected headers or content: %s", ansiView)
	}
}
