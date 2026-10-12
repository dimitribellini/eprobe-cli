package telemetry

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

var (
	// Styling palettes conforming to protocols.md Section 1.1 Rule 5
	StyleSeverityCritical = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	StyleSeverityWarning  = lipgloss.NewStyle().Foreground(lipgloss.Color("208")).Bold(true)
	StyleSeverityInfo     = lipgloss.NewStyle().Foreground(lipgloss.Color("39"))
	StyleSeverityDebug    = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	StyleSeveritySuccess  = lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true)
	StyleSeverityNormal   = lipgloss.NewStyle().Foreground(lipgloss.Color("252"))

	StyleLatencyHigh = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	StyleLatencyMid  = lipgloss.NewStyle().Foreground(lipgloss.Color("208"))
	StyleLatencyLow  = lipgloss.NewStyle().Foreground(lipgloss.Color("250"))

	StyleBarHigh = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	StyleBarMid  = lipgloss.NewStyle().Foreground(lipgloss.Color("208"))
	StyleBarLow  = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))

	reUnitSuffix = regexp.MustCompile(`_(us|ms|ns|bytes|kb|mb|gb)$`)
)

// FormatColumnTitle formats field keys into human-readable headers without technical suffixes.
func FormatColumnTitle(field, label string) string {
	if label != "" {
		return strings.ToUpper(label)
	}
	if field == "duration_us" {
		return "DURATION"
	}
	if field == "latency_us" {
		return "LATENCY"
	}
	if field == "runq_latency_us" {
		return "RUNQ LATENCY"
	}
	if reUnitSuffix.MatchString(field) {
		clean := reUnitSuffix.ReplaceAllString(field, "")
		return strings.ToUpper(strings.ReplaceAll(clean, "_", " "))
	}
	return strings.ToUpper(strings.ReplaceAll(field, "_", " "))
}

// IsLatencyField returns true if the column field represents a duration or latency metric.
func IsLatencyField(field, format string) bool {
	if format == "latency" {
		return true
	}
	f := strings.ToLower(field)
	return f == "duration_us" ||
		f == "latency_us" ||
		f == "latency_ms" ||
		f == "duration_ms" ||
		strings.Contains(f, "latency") ||
		strings.Contains(f, "duration") ||
		strings.HasSuffix(f, "_us") ||
		strings.HasSuffix(f, "_ms")
}

// FormatLatency formats a numeric latency value with adaptive unit scaling (µs, ms, s).
func FormatLatency(val interface{}, field string) (string, lipgloss.Style) {
	num := ParseFloatSafe(val)
	if math.IsNaN(num) {
		return fmt.Sprint(val), StyleLatencyLow
	}

	f := strings.ToLower(field)
	isMicroseconds := strings.HasSuffix(f, "_us") || f == "duration_us" || f == "latency_us"
	isNanoseconds := strings.HasSuffix(f, "_ns")

	var msVal float64
	var displayStr string

	if isNanoseconds {
		msVal = num / 1e6
		if num < 1000 {
			displayStr = fmt.Sprintf("%d ns", int64(num))
		} else if num < 1e6 {
			displayStr = fmt.Sprintf("%d µs", int64(num/1000))
		} else if msVal < 1000 {
			displayStr = fmt.Sprintf("%.2f ms", msVal)
		} else {
			displayStr = fmt.Sprintf("%.2f s", msVal/1000.0)
		}
	} else if isMicroseconds {
		if num < 1000 {
			displayStr = fmt.Sprintf("%d µs", int64(math.Round(num)))
			return displayStr, StyleLatencyLow
		}
		msVal = num / 1000.0
		if msVal < 1000 {
			displayStr = fmt.Sprintf("%.2f ms", msVal)
		} else {
			displayStr = fmt.Sprintf("%.2f s", msVal/1000.0)
		}
	} else {
		// Default assumes milliseconds if not specified
		msVal = num
		if msVal < 1.0 && msVal > 0 {
			displayStr = fmt.Sprintf("%d µs", int64(msVal*1000))
		} else if msVal < 1000 {
			displayStr = fmt.Sprintf("%.2f ms", msVal)
		} else {
			displayStr = fmt.Sprintf("%.2f s", msVal/1000.0)
		}
	}

	// Apply latency threshold styling
	if msVal >= 20.0 {
		return displayStr, StyleLatencyHigh
	}
	if msVal >= 5.0 {
		return displayStr, StyleLatencyMid
	}
	return displayStr, StyleLatencyLow
}

// FormatSeverity formats severity / log level strings into standard styled tokens.
func FormatSeverity(val interface{}) (string, lipgloss.Style) {
	str := strings.ToUpper(strings.TrimSpace(fmt.Sprint(val)))

	switch str {
	case "CRITICAL", "CRIT", "FATAL", "ERROR", "ERR", "EMERGENCY", "EMERG", "ALERT", "SEVERE", "PANIC":
		return str, StyleSeverityCritical
	case "WARN", "WARNING", "STDERR":
		return str, StyleSeverityWarning
	case "INFO", "NOTICE", "LOG":
		return str, StyleSeverityInfo
	case "DEBUG", "TRACE", "VERBOSE":
		return str, StyleSeverityDebug
	case "OK", "SUCCESS", "PASS":
		return str, StyleSeveritySuccess
	default:
		if strings.Contains(str, "FAIL") {
			return str, StyleSeverityCritical
		}
		return str, StyleSeverityNormal
	}
}

// FormatRateMetric scales continuous delta rate metrics to appropriate units.
func FormatRateMetric(val float64, field, unit string) string {
	f := strings.ToLower(field)
	u := strings.ToLower(unit)

	if u == "%" || f == "cpu_time_ns" {
		return fmt.Sprintf("%.1f%%", val)
	}
	if u == "s/s" || strings.HasSuffix(f, "_ns") {
		return fmt.Sprintf("%.1f s/s", val)
	}
	if u == "bytes" || strings.HasSuffix(f, "_bytes") {
		if val >= 1e9 {
			return fmt.Sprintf("%.1f GB/s", val/1e9)
		}
		if val >= 1e6 {
			return fmt.Sprintf("%.1f MB/s", val/1e6)
		}
		if val >= 1e3 {
			return fmt.Sprintf("%.1f KB/s", val/1e3)
		}
		return fmt.Sprintf("%.0f B/s", val)
	}

	// General metric rate formatting
	return FormatValue(val) + "/s"
}

// FormatValue formats a large numeric value with standard SI metric prefixes (K, M, G, T).
func FormatValue(v float64) string {
	if v >= 1e12 {
		return fmt.Sprintf("%.1fT", v/1e12)
	}
	if v >= 1e9 {
		return fmt.Sprintf("%.1fG", v/1e9)
	}
	if v >= 1e6 {
		return fmt.Sprintf("%.1fM", v/1e6)
	}
	if v >= 1e3 {
		return fmt.Sprintf("%.1fK", v/1e3)
	}
	return fmt.Sprintf("%.0f", v)
}

// ScaleDurationLabel converts microsecond and millisecond values into human-readable range bounds.
func ScaleDurationLabel(val float64, unit string) string {
	u := strings.ToLower(unit)
	if u == "us" || u == "µs" {
		if val >= 1e6 {
			return fmt.Sprintf("%.0fs", val/1e6)
		}
		if val >= 1e3 {
			if math.Mod(val, 1000) == 0 {
				return fmt.Sprintf("%.0fms", val/1e3)
			}
			return fmt.Sprintf("%.1fms", val/1e3)
		}
		return fmt.Sprintf("%.0fµs", val)
	}
	if u == "ms" {
		if val >= 1e3 {
			return fmt.Sprintf("%.0fs", val/1e3)
		}
		return fmt.Sprintf("%.0fms", val)
	}
	return fmt.Sprintf("%.0f%s", val, unit)
}

// FormatHistogramRange formats a bucket interval cleanly (e.g. 20ms-50ms, >= 2s).
func FormatHistogramRange(min, max float64, unit string) string {
	u := strings.ToLower(unit)
	if u == "us" || u == "µs" || u == "ms" {
		if math.IsInf(max, 1) || max <= 0 || max <= min {
			return fmt.Sprintf(">= %s", ScaleDurationLabel(min, unit))
		}
		return fmt.Sprintf("%s-%s", ScaleDurationLabel(min, unit), ScaleDurationLabel(max, unit))
	}

	if math.IsInf(max, 1) || max <= 0 || max <= min {
		return fmt.Sprintf(">= %7.1f%s", min, unit)
	}
	return fmt.Sprintf("%7.1f-%7.1f%s", min, max, unit)
}

// GetHistogramBarStyle returns the Lipgloss style for a bucket based on latency threshold.
func GetHistogramBarStyle(min float64, unit string) lipgloss.Style {
	u := strings.ToLower(unit)
	ms := min
	if u == "us" || u == "µs" {
		ms = min / 1000.0
	} else if u == "ns" {
		ms = min / 1e6
	}

	if ms >= 1000.0 {
		return StyleBarHigh // >= 1s: Red
	}
	if ms >= 250.0 {
		return StyleBarMid // 250ms-1s: Amber
	}
	return StyleBarLow // < 250ms: Green
}

// ParseFloatSafe safely parses any interface to float64.
func ParseFloatSafe(val interface{}) float64 {
	switch v := val.(type) {
	case float64:
		return v
	case float32:
		return float64(v)
	case int:
		return float64(v)
	case int64:
		return float64(v)
	case int32:
		return float64(v)
	case uint64:
		return float64(v)
	case uint32:
		return float64(v)
	case string:
		f, _ := strconv.ParseFloat(v, 64)
		return f
	default:
		return 0
	}
}
