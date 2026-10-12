package registry

import (
	"testing"
)

func TestParseManifest(t *testing.T) {
	yamlData := `
name: sec/exec-audit
version: 1.0.0
author: eprobe-core
sha256: "some-sha256-hash-value"
description: 'Help text for CLI output'
attach_points:
  - type: tracepoint
    symbol: syscalls/sys_enter_execve
    section: trace_sys_execve
  - type: kprobe
    symbol: tcp_sendmsg
    section: kprobe_tcp_sendmsg
maps:
  - name: events
    type: ringbuf
    event_struct: event_t
    event_schema:
      - name: pid
        type: uint32
      - name: comm
        type: string
        length: 16
variables:
  - name: filter_port
    type: uint16
    cli_flag: port
    description: Port filter
tui_hints:
  default_view: stream
  supported_views:
    - stream
    - top
  summary: 'Module testing summary'
  inspect_payload: 'raw_data'
  columns:
    - field: time
      width: 10
    - field: pid
      width: 8
      bold: true
      color: "#FFA500"
  aggregate_by:
    - field: comm
      label: Executions
      type: count
`

	manifest, err := ParseManifest([]byte(yamlData))
	if err != nil {
		t.Fatalf("failed to parse manifest: %v", err)
	}

	if manifest.Name != "sec/exec-audit" {
		t.Errorf("expected Name 'sec/exec-audit', got %q", manifest.Name)
	}
	if manifest.Version != "1.0.0" {
		t.Errorf("expected Version '1.0.0', got %q", manifest.Version)
	}
	if manifest.Author != "eprobe-core" {
		t.Errorf("expected Author 'eprobe-core', got %q", manifest.Author)
	}
	if manifest.SHA256 != "some-sha256-hash-value" {
		t.Errorf("expected SHA256 'some-sha256-hash-value', got %q", manifest.SHA256)
	}
	if manifest.Description != "Help text for CLI output" {
		t.Errorf("expected Description 'Help text for CLI output', got %q", manifest.Description)
	}

	if len(manifest.AttachPoints) != 2 {
		t.Errorf("expected 2 attach points, got %d", len(manifest.AttachPoints))
	} else {
		ap1 := manifest.AttachPoints[0]
		if ap1.Type != "tracepoint" || ap1.Symbol != "syscalls/sys_enter_execve" || ap1.Section != "trace_sys_execve" {
			t.Errorf("unexpected first attach point: %+v", ap1)
		}
		ap2 := manifest.AttachPoints[1]
		if ap2.Type != "kprobe" || ap2.Symbol != "tcp_sendmsg" || ap2.Section != "kprobe_tcp_sendmsg" {
			t.Errorf("unexpected second attach point: %+v", ap2)
		}
	}

	if len(manifest.Maps) != 1 {
		t.Errorf("expected 1 map spec, got %d", len(manifest.Maps))
	} else {
		m1 := manifest.Maps[0]
		if m1.Name != "events" || m1.Type != "ringbuf" || m1.EventStruct != "event_t" {
			t.Errorf("unexpected map spec: %+v", m1)
		}
		if len(m1.EventSchema) != 2 {
			t.Errorf("expected 2 schema fields, got %d", len(m1.EventSchema))
		} else {
			f1 := m1.EventSchema[0]
			if f1.Name != "pid" || f1.Type != "uint32" {
				t.Errorf("unexpected first field: %+v", f1)
			}
			f2 := m1.EventSchema[1]
			if f2.Name != "comm" || f2.Type != "string" || f2.Length != 16 {
				t.Errorf("unexpected second field: %+v", f2)
			}
		}
	}

	if len(manifest.Variables) != 1 {
		t.Errorf("expected 1 variable, got %d", len(manifest.Variables))
	} else {
		v1 := manifest.Variables[0]
		if v1.Name != "filter_port" || v1.Type != "uint16" || v1.CLIFlag != "port" || v1.Description != "Port filter" {
			t.Errorf("unexpected variable: %+v", v1)
		}
	}

	if manifest.TUIHints.DefaultView != "stream" {
		t.Errorf("expected TUIHints.DefaultView 'stream', got %q", manifest.TUIHints.DefaultView)
	}

	if len(manifest.TUIHints.SupportedViews) != 2 || manifest.TUIHints.SupportedViews[0] != "stream" || manifest.TUIHints.SupportedViews[1] != "top" {
		t.Errorf("expected 2 SupportedViews ('stream', 'top'), got %v", manifest.TUIHints.SupportedViews)
	}

	if manifest.TUIHints.Summary != "Module testing summary" {
		t.Errorf("expected TUIHints.Summary 'Module testing summary', got %q", manifest.TUIHints.Summary)
	}

	if manifest.TUIHints.InspectPayload != "raw_data" {
		t.Errorf("expected TUIHints.InspectPayload 'raw_data', got %q", manifest.TUIHints.InspectPayload)
	}

	if len(manifest.TUIHints.Columns) != 2 {
		t.Errorf("expected 2 TUI columns, got %d", len(manifest.TUIHints.Columns))
	} else {
		col1 := manifest.TUIHints.Columns[0]
		if col1.Field != "time" || col1.Width != 10 || col1.Bold || col1.Color != "" {
			t.Errorf("unexpected first column hint: %+v", col1)
		}
		col2 := manifest.TUIHints.Columns[1]
		if col2.Field != "pid" || col2.Width != 8 || !col2.Bold || col2.Color != "#FFA500" {
			t.Errorf("unexpected second column hint: %+v", col2)
		}
	}

	if len(manifest.TUIHints.AggregateBy) != 1 {
		t.Errorf("expected 1 TUI aggregation rule, got %d", len(manifest.TUIHints.AggregateBy))
	} else {
		agg1 := manifest.TUIHints.AggregateBy[0]
		if agg1.Field != "comm" || agg1.Label != "Executions" || agg1.Type != "count" {
			t.Errorf("unexpected aggregation hint: %+v", agg1)
		}
	}

	// Verify backward compatibility normalization
	if manifest.TUIHints.Layout != "grid" {
		t.Errorf("expected layout 'grid' from fallback, got %q", manifest.TUIHints.Layout)
	}
	if len(manifest.TUIHints.Panes) != 1 {
		t.Errorf("expected 1 pane from fallback, got %d", len(manifest.TUIHints.Panes))
	} else {
		pane := manifest.TUIHints.Panes[0]
		if pane.Name != "main" || pane.Type != "stream" || pane.MapName != "events" {
			t.Errorf("unexpected pane fallback: %+v", pane)
		}
		if pane.Position.Width != "100%" || pane.Position.Height != "100%" {
			t.Errorf("expected 100%% width/height for fallback pane, got %+v", pane.Position)
		}
	}
}

func TestParseManifestV3(t *testing.T) {
	yamlData := `
name: app/multi-pane
version: 2.0.0
tui_hints:
  layout: flex
  panes:
    - name: logs
      type: stream
      map_name: log_events
      position:
        row: 0
        col: 1
        width: 50%
        height: 100%
      columns:
        - field: payload
          width: 0
`
	manifest, err := ParseManifest([]byte(yamlData))
	if err != nil {
		t.Fatalf("failed to parse v3 manifest: %v", err)
	}
	if manifest.TUIHints.Layout != "flex" {
		t.Errorf("expected layout flex, got %q", manifest.TUIHints.Layout)
	}
	if len(manifest.TUIHints.Panes) != 1 {
		t.Fatalf("expected 1 pane, got %d", len(manifest.TUIHints.Panes))
	}
	pane := manifest.TUIHints.Panes[0]
	if pane.Name != "logs" || pane.MapName != "log_events" || pane.Position.Width != "50%" || pane.Position.Height != "100%" {
		t.Errorf("unexpected pane details: %+v", pane)
	}
	if len(pane.Columns) != 1 || pane.Columns[0].Field != "payload" {
		t.Errorf("unexpected pane columns: %+v", pane.Columns)
	}
}

func TestParseManifestColonInValues(t *testing.T) {
	yamlData := `
name: app/http-tracer
version: 1.0.0
author: eprobe-core
description: Connect to host:port on tcp:443
sha256: abc123
`

	manifest, err := ParseManifest([]byte(yamlData))
	if err != nil {
		t.Fatalf("failed to parse manifest with colon in value: %v", err)
	}

	if manifest.Description != "Connect to host:port on tcp:443" {
		t.Errorf("expected description with colons preserved, got %q", manifest.Description)
	}
	if manifest.SHA256 != "abc123" {
		t.Errorf("expected SHA256 'abc123', got %q", manifest.SHA256)
	}
}

func TestGetRingBufMap(t *testing.T) {
	// Test with a manifest that has a ringbuf map
	m := &Manifest{
		Maps: []MapSpec{
			{Name: "other_map", Type: "hash"},
			{Name: "events", Type: "ringbuf", EventSchema: []FieldSchema{{Name: "pid", Type: "uint32"}}},
		},
	}
	rbMap := m.GetRingBufMap()
	if rbMap == nil {
		t.Fatal("expected GetRingBufMap to return a map, got nil")
	}
	if rbMap.Name != "events" {
		t.Errorf("expected ringbuf map 'events', got %q", rbMap.Name)
	}

	// Test fallback to first map when no ringbuf type
	m2 := &Manifest{
		Maps: []MapSpec{
			{Name: "fallback_map", Type: "hash"},
		},
	}
	rbMap2 := m2.GetRingBufMap()
	if rbMap2 == nil {
		t.Fatal("expected GetRingBufMap to fallback to first map, got nil")
	}
	if rbMap2.Name != "fallback_map" {
		t.Errorf("expected fallback map 'fallback_map', got %q", rbMap2.Name)
	}

	// Test with no maps
	m3 := &Manifest{}
	rbMap3 := m3.GetRingBufMap()
	if rbMap3 != nil {
		t.Errorf("expected GetRingBufMap to return nil for empty maps, got %+v", rbMap3)
	}
}

func TestParseManifestNewPaneTypes(t *testing.T) {
	yamlData := `
name: app/advanced-observability
version: 1.0.0
tui_hints:
  pages:
    - name: "Multi-View Dashboard"
      panes:
        - name: "Latency Distribution"
          type: histogram
          map_name: events
          histogram_field: latency_us
          unit: us
        - name: "RPS Trend"
          type: sparkline
          map_name: events
          metric_field: count
          aggregation: rate
          time_window_sec: 60
        - name: "Execution Tree"
          type: tree
          map_name: events
          node_id: pid
          parent_id: ppid
          label_fields: [comm, filename]
`

	manifest, err := ParseManifest([]byte(yamlData))
	if err != nil {
		t.Fatalf("failed to parse manifest with new pane types: %v", err)
	}

	if len(manifest.TUIHints.Pages) != 1 {
		t.Fatalf("expected 1 page, got %d", len(manifest.TUIHints.Pages))
	}

	panes := manifest.TUIHints.Pages[0].Panes
	if len(panes) != 3 {
		t.Fatalf("expected 3 panes, got %d", len(panes))
	}

	hPane := panes[0]
	if hPane.Type != "histogram" || hPane.HistogramField != "latency_us" || hPane.Unit != "us" {
		t.Errorf("unexpected histogram pane: %+v", hPane)
	}

	sPane := panes[1]
	if sPane.Type != "sparkline" || sPane.MetricField != "count" || sPane.Aggregation != "rate" || sPane.TimeWindowSec != 60 {
		t.Errorf("unexpected sparkline pane: %+v", sPane)
	}

	tPane := panes[2]
	if tPane.Type != "tree" || tPane.NodeID != "pid" || tPane.ParentID != "ppid" || len(tPane.LabelFields) != 2 {
		t.Errorf("unexpected tree pane: %+v", tPane)
	}
}
