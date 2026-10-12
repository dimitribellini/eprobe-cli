package telemetry

import (
	"strings"
	"testing"
)

func TestTraceTreeEngine(t *testing.T) {
	tree := NewTraceTree("pid", "ppid", []string{"comm", "filename"}, "duration_ms", "comm", "", "status_code")

	events := []map[string]interface{}{
		{"pid": 1, "ppid": 0, "comm": "systemd", "filename": "/sbin/init"},
		{"pid": 100, "ppid": 1, "comm": "bash", "filename": "/bin/bash"},
		{"pid": 200, "ppid": 100, "comm": "curl", "filename": "/usr/bin/curl", "duration_ms": 45, "status_code": 200},
	}

	for _, e := range events {
		tree.Update(e)
	}

	rendered := tree.Render(100, 20)
	if !strings.Contains(rendered, "systemd /sbin/init") {
		t.Errorf("expected root process systemd in rendered tree: %s", rendered)
	}
	if !strings.Contains(rendered, "bash /bin/bash") {
		t.Errorf("expected child process bash in rendered tree: %s", rendered)
	}
	if !strings.Contains(rendered, "curl /usr/bin/curl") {
		t.Errorf("expected leaf process curl in rendered tree: %s", rendered)
	}
	if !strings.Contains(rendered, "45µs") && !strings.Contains(rendered, "45ms") {
		t.Errorf("expected duration in rendered tree: %s", rendered)
	}

	// Test ToggleAll
	tree.ToggleAll()
	renderedCollapsed := tree.Render(100, 20)
	if strings.Contains(renderedCollapsed, "curl /usr/bin/curl") {
		t.Errorf("expected leaf curl to be collapsed after ToggleAll: %s", renderedCollapsed)
	}

	tree.ToggleAll()
	renderedExpanded := tree.Render(100, 20)
	if !strings.Contains(renderedExpanded, "curl /usr/bin/curl") {
		t.Errorf("expected leaf curl to be expanded after second ToggleAll: %s", renderedExpanded)
	}
}
