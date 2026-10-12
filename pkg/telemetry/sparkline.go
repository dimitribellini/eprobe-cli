package telemetry

import (
	"fmt"
	"math"
	"strings"
	"sync"
	"time"
)

// SparklineBuffer maintains rolling time-series values for telemetry metric trends
type SparklineBuffer struct {
	field       string
	windowSec   int
	aggregation string // rate|avg|max|sum
	history     []float64
	currentSec  int64
	currentVal  float64
	currentCount float64
	mu          sync.Mutex
}

// NewSparklineBuffer creates a new SparklineBuffer for time-series metric tracking
func NewSparklineBuffer(field string, windowSec int, agg string) *SparklineBuffer {
	if windowSec <= 0 {
		windowSec = 60
	}
	if agg == "" {
		agg = "rate"
	}
	return &SparklineBuffer{
		field:       field,
		windowSec:   windowSec,
		aggregation: agg,
		history:     make([]float64, 0, windowSec),
		currentSec:  time.Now().Unix(),
	}
}

// Update records an incoming telemetry event into the current second tick bucket
func (s *SparklineBuffer) Update(event map[string]interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().Unix()
	s.flushSecIfNeeded(now)

	var val float64 = 1
	if s.field != "" && s.field != "count" && event != nil {
		if v, ok := event[s.field]; ok {
			val = toFloat64(v)
		}
	}

	switch s.aggregation {
	case "sum", "rate":
		s.currentVal += val
	case "max":
		if val > s.currentVal || s.currentCount == 0 {
			s.currentVal = val
		}
	case "avg":
		s.currentVal += val
		s.currentCount++
	}
}

// Tick explicitly advances the time tick (called once per second)
func (s *SparklineBuffer) Tick(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flushSecIfNeeded(now.Unix())
}

func (s *SparklineBuffer) flushSecIfNeeded(now int64) {
	if now > s.currentSec {
		elapsed := now - s.currentSec
		// Flush current bucket
		finalVal := s.currentVal
		if s.aggregation == "avg" && s.currentCount > 0 {
			finalVal = s.currentVal / s.currentCount
		}

		s.history = append(s.history, finalVal)

		// Fill missing seconds with 0 if elapsed > 1
		for i := int64(1); i < elapsed; i++ {
			s.history = append(s.history, 0)
		}

		if len(s.history) > s.windowSec {
			s.history = s.history[len(s.history)-s.windowSec:]
		}

		s.currentSec = now
		s.currentVal = 0
		s.currentCount = 0
	}
}

// Render formats the sparkline chart and stats line
func (s *SparklineBuffer) Render(width int) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.history) == 0 {
		return " Waiting for metric data..."
	}

	sparkChars := []rune{' ', '▂', '▃', '▄', '▅', '▆', '▇', '█'}

	minVal := math.MaxFloat64
	maxVal := -math.MaxFloat64
	var sumVal float64

	for _, v := range s.history {
		if v < minVal {
			minVal = v
		}
		if v > maxVal {
			maxVal = v
		}
		sumVal += v
	}

	avgVal := sumVal / float64(len(s.history))
	currentVal := s.history[len(s.history)-1]

	if minVal > maxVal {
		minVal = 0
		maxVal = 0
	}

	// Build sparkline string scaled to width
	chartWidth := width - 4
	if chartWidth < 10 {
		chartWidth = 10
	}

	// Slice or sample history to chartWidth
	var sample []float64
	if len(s.history) <= chartWidth {
		sample = s.history
	} else {
		sample = s.history[len(s.history)-chartWidth:]
	}

	var builder strings.Builder
	for _, v := range sample {
		if maxVal == minVal {
			builder.WriteRune(' ')
		} else {
			idx := int((v - minVal) / (maxVal - minVal) * float64(len(sparkChars)-1))
			if idx < 0 {
				idx = 0
			}
			if idx >= len(sparkChars) {
				idx = len(sparkChars) - 1
			}
			builder.WriteRune(sparkChars[idx])
		}
	}

	fieldLabel := s.field
	if fieldLabel == "" {
		fieldLabel = "event_rate"
	}

	stats := fmt.Sprintf("Metric: %s (%s) │ Cur: %.1f │ Min: %.1f │ Max: %.1f │ Avg: %.1f",
		fieldLabel, s.aggregation, currentVal, minVal, maxVal, avgVal)

	return fmt.Sprintf("%s\n%s", stats, builder.String())
}
