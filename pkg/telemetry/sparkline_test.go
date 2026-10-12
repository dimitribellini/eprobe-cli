package telemetry

import (
	"strings"
	"testing"
	"time"
)

func TestSparklineEngine(t *testing.T) {
	s := NewSparklineBuffer("bytes", 60, "sum")

	s.Update(map[string]interface{}{"bytes": 100})
	s.Update(map[string]interface{}{"bytes": 200})

	s.Tick(time.Now().Add(time.Second))

	rendered := s.Render(60)
	if !strings.Contains(rendered, "Metric: bytes") {
		t.Errorf("rendered sparkline missing metric header: %s", rendered)
	}
}
