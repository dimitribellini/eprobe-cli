package telemetry

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"

	"github.com/charmbracelet/lipgloss"
)

// Bucket represents a histogram value range and count
type Bucket struct {
	Min   float64
	Max   float64
	Count int
}

// Histogram tracks numerical value distribution for a specific telemetry field
type Histogram struct {
	field   string
	unit    string
	buckets []Bucket
	total   int
	mu      sync.RWMutex
}

// NewHistogram creates a new Histogram with specified custom or default logarithmic bounds
func NewHistogram(field, unit string, customBounds []float64) *Histogram {
	h := &Histogram{
		field: field,
		unit:  unit,
	}
	if len(customBounds) > 1 {
		sort.Float64s(customBounds)
		for i := 0; i < len(customBounds)-1; i++ {
			h.buckets = append(h.buckets, Bucket{Min: customBounds[i], Max: customBounds[i+1]})
		}
		h.buckets = append(h.buckets, Bucket{Min: customBounds[len(customBounds)-1], Max: math.Inf(1)})
	} else {
		// Default logarithmic buckets (0..10, 10..50, 50..200, 200..1000, 1000..5000, 5000..+)
		bounds := []float64{0, 10, 50, 200, 1000, 5000}
		for i := 0; i < len(bounds)-1; i++ {
			h.buckets = append(h.buckets, Bucket{Min: bounds[i], Max: bounds[i+1]})
		}
		h.buckets = append(h.buckets, Bucket{Min: 5000, Max: math.Inf(1)})
	}
	return h
}

// Update increments the histogram bucket for the value extracted from event
func (h *Histogram) Update(event map[string]interface{}) {
	if event == nil {
		return
	}
	val, ok := event[h.field]
	if !ok {
		return
	}

	num := toFloat64(val)

	h.mu.Lock()
	defer h.mu.Unlock()

	h.total++
	for i := range h.buckets {
		if num >= h.buckets[i].Min && (num < h.buckets[i].Max || math.IsInf(h.buckets[i].Max, 1)) {
			h.buckets[i].Count++
			break
		}
	}
}

// Render formats the histogram as a text bar chart for the given viewport width
func (h *Histogram) Render(width, height int) string {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if h.total == 0 {
		return " No telemetry data collected for histogram."
	}

	maxCount := 0
	for _, b := range h.buckets {
		if b.Count > maxCount {
			maxCount = b.Count
		}
	}

	barWidth := width - 38
	if barWidth < 5 {
		barWidth = 5
	}

	var lines []string
	unitStr := ""
	if h.unit != "" {
		unitStr = " (" + h.unit + ")"
	}
	header := fmt.Sprintf("Total Samples: %d │ Field: %s%s", h.total, h.field, unitStr)
	lines = append(lines, header)

	for _, b := range h.buckets {
		rangeLabel := FormatHistogramRange(b.Min, b.Max, h.unit)
		pct := float64(b.Count) / float64(h.total) * 100.0

		var bar string
		if maxCount > 0 && b.Count > 0 {
			fullBlocks := int(float64(b.Count) / float64(maxCount) * float64(barWidth))
			if fullBlocks < 1 && b.Count > 0 {
				bar = "▏"
			} else {
				bar = strings.Repeat("█", fullBlocks)
			}
		}

		style := GetHistogramBarStyle(b.Min, h.unit)
		styledBar := style.Render(bar)
		barVisibleWidth := lipgloss.Width(bar)
		padCount := barWidth - barVisibleWidth
		if padCount < 0 {
			padCount = 0
		}
		padding := strings.Repeat(" ", padCount)

		line := fmt.Sprintf("%-13s │ %s%s │ %4d (%5.1f%%)", rangeLabel, styledBar, padding, b.Count, pct)
		lines = append(lines, line)
	}

	return strings.Join(lines, "\n")
}

func toFloat64(val interface{}) float64 {
	switch v := val.(type) {
	case int:
		return float64(v)
	case int32:
		return float64(v)
	case int64:
		return float64(v)
	case uint16:
		return float64(v)
	case uint32:
		return float64(v)
	case uint64:
		return float64(v)
	case float32:
		return float64(v)
	case float64:
		return v
	default:
		var f float64
		fmt.Sscanf(fmt.Sprint(val), "%f", &f)
		return f
	}
}
