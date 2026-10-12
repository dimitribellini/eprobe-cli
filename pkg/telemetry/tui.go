package telemetry

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"

	"eprobe/pkg/registry"
	"eprobe/pkg/system"
)

// sanitizeString removes ANSI escape codes and all control characters
// that can break terminal rendering (like null bytes, vertical tabs, etc.)
// while explicitly escaping newlines to visual \n characters.
func sanitizeString(s string) string {
	clean := ansi.Strip(s)
	var b strings.Builder
	for _, r := range clean {
		// Keep printable characters. Replace newline, carriage return, and tab explicitly.
		if r == '\n' {
			b.WriteString("\\n")
		} else if r == '\r' {
			// strip CR
		} else if r == '\t' {
			b.WriteRune(' ')
		} else if r >= 32 && r != 127 { // 127 is DEL control character
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Styling & Color Palette
var (
	primaryColor   = lipgloss.Color("#7D56F4") // Purple/Violet
	secondaryColor = lipgloss.Color("#00F0FF") // Neon Cyan
	accentColor    = lipgloss.Color("#FF007F") // Magenta
	warningColor   = lipgloss.Color("#FFA500") // Orange/Amber
	successColor   = lipgloss.Color("#00FF66") // Neon Green
	darkBg         = lipgloss.Color("#1A1A24") // Deep Blue/Black
	grayBg         = lipgloss.Color("#2D2D3D") // Slate Grey
	lightText      = lipgloss.Color("#E2E2E2")
	mutedText      = lipgloss.Color("#888899")

	headerStyle = lipgloss.NewStyle().
			Background(darkBg).
			Foreground(lightText).
			Border(lipgloss.RoundedBorder()).
			BorderForeground(primaryColor).
			Padding(0, 1)

	footerStyle = lipgloss.NewStyle().
			Background(grayBg).
			Foreground(lightText).
			Border(lipgloss.RoundedBorder()).
			BorderForeground(primaryColor).
			Padding(0, 1)

	paneNormalStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(mutedText)

	paneActiveStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(accentColor)

	metricLabelStyle = lipgloss.NewStyle().
				Foreground(mutedText).
				Bold(true)

	metricValueStyle = lipgloss.NewStyle().
				Foreground(secondaryColor).
				Bold(true)

	filterStyle = lipgloss.NewStyle().
			Foreground(warningColor).
			Bold(true)

	errorColor = lipgloss.Color("#FF4444") // Red for warnings
)

type paneEventMsg struct {
	PageIdx int
	PaneIdx int
	Event   map[string]interface{}
}

type tickMsg struct {
	Time time.Time
}

type StateSample struct {
	Value     float64
	Timestamp time.Time
}

type PaneModel struct {
	Def           registry.TUIPane
	Buffer        *EventBuffer
	Aggregator    *Aggregator
	Table         table.Model
	ActiveCols    []registry.ColumnHint
	Viewport      viewport.Model
	EventChan     chan map[string]interface{}
	IsInspectMode bool
	InspectEvent  map[string]interface{}
	InspectKey    string
	FilterQuery   string

	Histogram *Histogram
	Sparkline *SparklineBuffer
	TraceTree *TraceTree

	HashMapRef *ebpf.Map
	HashSchema *registry.MapSpec
	StateCache map[string]StateSample
}

type Model struct {
	width         int
	height        int
	version       string
	manifest      *registry.Manifest
	filterPort    uint16
	totalEvents   int
	rate          int
	rateCounter   int
	activeFilter  string
	droppedEvents *int64

	pages           [][]PaneModel
	activePageIndex int
	activePaneIndex int
	isMaximized     bool
	helpMode        bool
	isPaused        bool
	termWidth       int
	termHeight      int

	keys keyMap
	help help.Model
	
	searchInput textinput.Model
	isSearching bool

	showBriefModal bool
	streamer       *Streamer
	containers     map[string]system.ContainerMeta
}

func (m Model) resolveContainer(cid string) string {
	if m.containers == nil {
		return cid
	}
	cleanCid := strings.TrimSpace(cid)
	if meta, ok := m.containers[cleanCid]; ok && meta.Name != "" {
		return meta.Name
	}
	if len(cleanCid) >= 12 {
		if meta, ok := m.containers[cleanCid[:12]]; ok && meta.Name != "" {
			return meta.Name
		}
	}
	return cid
}

func (m Model) Init() tea.Cmd {
	var cmds []tea.Cmd
	for pIdx := range m.pages {
		for i := range m.pages[pIdx] {
			cmds = append(cmds, listenToPaneEvents(pIdx, i, m.pages[pIdx][i].EventChan))
		}
	}
	cmds = append(cmds, tickRate())
	return tea.Batch(cmds...)
}

func listenToPaneEvents(pageIdx, paneIdx int, ch chan map[string]interface{}) tea.Cmd {
	return func() tea.Msg {
		e := <-ch
		return paneEventMsg{PageIdx: pageIdx, PaneIdx: paneIdx, Event: e}
	}
}

func tickRate() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return tickMsg{Time: t}
	})
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		if m.isSearching {
			if msg.Type == tea.KeyEnter {
				m.isSearching = false
				active := &m.pages[m.activePageIndex][m.activePaneIndex]
				active.FilterQuery = m.searchInput.Value()
				
				if active.IsInspectMode {
					m.rebuildInspectViewport(active)
				}
				
				// Trigger a re-render of stream panes by sending a dummy event
				if len(m.pages[m.activePageIndex]) > m.activePaneIndex {
					pane := &m.pages[m.activePageIndex][m.activePaneIndex]
					if pane.Def.Type == "stream" {
						go func() {
							pane.EventChan <- nil
						}()
					}
				}
				return m, nil
			}
			if msg.Type == tea.KeyEsc {
				m.isSearching = false
				m.searchInput.SetValue(m.pages[m.activePageIndex][m.activePaneIndex].FilterQuery)
				return m, nil
			}
			var tiCmd tea.Cmd
			m.searchInput, tiCmd = m.searchInput.Update(msg)
			return m, tiCmd
		}

		if m.showBriefModal {
			if key.Matches(msg, m.keys.Quit) {
				return m, tea.Quit
			}
			if msg.Type == tea.KeyEsc || msg.Type == tea.KeyEnter || msg.String() == " " || key.Matches(msg, m.keys.Help) {
				m.showBriefModal = false
				return m, nil
			}
			if key.Matches(msg, m.keys.NextPage) || key.Matches(msg, m.keys.PrevPage) {
				m.showBriefModal = false
				// continue below for page navigation
			} else {
				return m, nil
			}
		}

		if key.Matches(msg, m.keys.Quit) {
			return m, tea.Quit
		}
		if key.Matches(msg, m.keys.Help) {
			m.helpMode = !m.helpMode
			m.help.ShowAll = m.helpMode
			return m, nil
		}
		if key.Matches(msg, m.keys.Pause) {
			m.isPaused = !m.isPaused
			return m, nil
		}

		if m.helpMode {
			return m, nil
		}

		switch msg.String() {
		case "1", "2", "3", "4", "5", "6", "7", "8", "9":
			targetIdx := int(msg.String()[0] - '1')
			if targetIdx < len(m.pages) && targetIdx != m.activePageIndex {
				m.activePageIndex = targetIdx
				m.activePaneIndex = 0
				for i := range m.pages[m.activePageIndex] {
					m.pages[m.activePageIndex][i].Table.Blur()
				}
				if len(m.pages[m.activePageIndex]) > 0 {
					m.pages[m.activePageIndex][0].Table.Focus()
				}
				return m, func() tea.Msg { return tea.WindowSizeMsg{Width: m.termWidth, Height: m.termHeight} }
			}
			return m, nil
		}

		if key.Matches(msg, m.keys.NextPage) {
			if len(m.pages) > 1 {
				m.activePageIndex = (m.activePageIndex + 1) % len(m.pages)
				m.activePaneIndex = 0
				for i := range m.pages[m.activePageIndex] {
					m.pages[m.activePageIndex][i].Table.Blur()
				}
				if len(m.pages[m.activePageIndex]) > 0 {
					m.pages[m.activePageIndex][0].Table.Focus()
				}
				return m, func() tea.Msg { return tea.WindowSizeMsg{Width: m.termWidth, Height: m.termHeight} }
			}
			return m, nil
		}

		if key.Matches(msg, m.keys.PrevPage) {
			if len(m.pages) > 1 {
				m.activePageIndex = (m.activePageIndex - 1 + len(m.pages)) % len(m.pages)
				m.activePaneIndex = 0
				for i := range m.pages[m.activePageIndex] {
					m.pages[m.activePageIndex][i].Table.Blur()
				}
				if len(m.pages[m.activePageIndex]) > 0 {
					m.pages[m.activePageIndex][0].Table.Focus()
				}
				return m, func() tea.Msg { return tea.WindowSizeMsg{Width: m.termWidth, Height: m.termHeight} }
			}
			return m, nil
		}

		if key.Matches(msg, m.keys.Tab) {
			if len(m.pages) > 0 && len(m.pages[m.activePageIndex]) > 0 {
				m.activePaneIndex = (m.activePaneIndex + 1) % len(m.pages[m.activePageIndex])
				for i := range m.pages[m.activePageIndex] {
					m.pages[m.activePageIndex][i].Table.Blur()
				}
				m.pages[m.activePageIndex][m.activePaneIndex].Table.Focus()
			}
			return m, nil
		}

		if len(m.pages) == 0 || len(m.pages[m.activePageIndex]) == 0 {
			return m, nil
		}

		activePane := &m.pages[m.activePageIndex][m.activePaneIndex]

		if activePane.Def.Type == "tree" && activePane.TraceTree != nil && !activePane.IsInspectMode {
			if key.Matches(msg, m.keys.Up) {
				activePane.TraceTree.MoveUp()
				return m, nil
			}
			if key.Matches(msg, m.keys.Down) {
				activePane.TraceTree.MoveDown()
				return m, nil
			}
			if key.Matches(msg, m.keys.Left) || key.Matches(msg, m.keys.Right) {
				activePane.TraceTree.ToggleExpand()
				return m, nil
			}
			if msg.String() == "e" || msg.String() == "E" || key.Matches(msg, m.keys.ToggleTree) {
				activePane.TraceTree.ToggleAll()
				return m, nil
			}
			if key.Matches(msg, m.keys.Enter) {
				selected := activePane.TraceTree.GetSelected()
				if selected != nil && selected.RawEvent != nil {
					activePane.IsInspectMode = true
					content := formatEventInspectContent(selected.RawEvent, activePane.Def)
					wrappedContent := lipgloss.NewStyle().Width(m.width - 4).Render(content)
					activePane.Viewport.SetContent(wrappedContent)
					return m, func() tea.Msg { return tea.WindowSizeMsg{Width: m.termWidth, Height: m.termHeight} }
				}
			}
		}

		if msg.String() == "m" || msg.String() == "M" || key.Matches(msg, m.keys.Maximize) {
			m.isMaximized = !m.isMaximized
			return m, func() tea.Msg { return tea.WindowSizeMsg{Width: m.termWidth, Height: m.termHeight} }
		}

		if key.Matches(msg, m.keys.Esc) {
			if activePane.IsInspectMode {
				activePane.IsInspectMode = false
				return m, func() tea.Msg { return tea.WindowSizeMsg{Width: m.termWidth, Height: m.termHeight} }
			} else if m.isMaximized {
				m.isMaximized = false
				return m, func() tea.Msg { return tea.WindowSizeMsg{Width: m.termWidth, Height: m.termHeight} }
			} else if m.activePageIndex != 0 {
				m.activePageIndex = 0
				m.activePaneIndex = 0
				for i := range m.pages[m.activePageIndex] {
					m.pages[m.activePageIndex][i].Table.Blur()
				}
				if len(m.pages[m.activePageIndex]) > 0 {
					m.pages[m.activePageIndex][0].Table.Focus()
				}
				return m, func() tea.Msg { return tea.WindowSizeMsg{Width: m.termWidth, Height: m.termHeight} }
			}
			return m, nil
		}

		if key.Matches(msg, m.keys.Search) {
			m.isSearching = true
			m.searchInput.SetValue(activePane.FilterQuery)
			m.searchInput.Focus()
			return m, textinput.Blink
		}

		if key.Matches(msg, m.keys.Enter) && !activePane.IsInspectMode {
			if activePane.Def.Type != "stream" && activePane.Def.Type != "top" {
				return m, nil
			}
			// Hash map backed panels do not have a historical event buffer to inspect
			if activePane.Def.Type == "top" && activePane.HashMapRef != nil && activePane.Def.InspectPayload != "" {
				return m, nil
			}
			if activePane.Def.InspectPayload != "" {
				if activePane.Def.Type == "stream" {
					rowIdx := activePane.Table.Cursor()
					if rowIdx >= 0 && rowIdx < activePane.Buffer.Len() {
						allEvents := activePane.Buffer.GetAll()
						if rowIdx < len(allEvents) {
							event := allEvents[rowIdx]
							content := formatEventInspectContent(event, activePane.Def)
							wrappedContent := lipgloss.NewStyle().Width(m.width - 4).Render(content)
							activePane.Viewport.SetContent(wrappedContent)
						}
					}
				} else if activePane.Def.Type == "top" {
					row := activePane.Table.SelectedRow()
					if row != nil && len(row) >= 2 {
						activePane.InspectKey = fmt.Sprint(row[0])
						activePane.IsInspectMode = true
						m.rebuildInspectViewport(activePane)
					}
				}
			}
			// Always enter inspect mode for valid inspectable types (stream/top).
			// When InspectPayload is empty, this maximizes the pane as a full-screen table.
			activePane.IsInspectMode = true
			return m, func() tea.Msg { return tea.WindowSizeMsg{Width: m.termWidth, Height: m.termHeight} }
		}

	case tea.WindowSizeMsg:
		m.termWidth = msg.Width
		m.termHeight = msg.Height
		m.width = msg.Width - 2 // Prevent bottom-right character wrap scrolling
		m.height = msg.Height
		headerHeight := 3
		footerHeight := 3
		viewportHeight := m.height - headerHeight - footerHeight
		if viewportHeight < 0 {
			viewportHeight = 0
		}

		for pIdx := range m.pages {
			for i := range m.pages[pIdx] {
				wPct, _ := parsePct(m.pages[pIdx][i].Def.Position.Width)
				hPct, _ := parsePct(m.pages[pIdx][i].Def.Position.Height)
				if wPct == 0 { wPct = 1.0 }
				if hPct == 0 { hPct = 1.0 }

				pWidth := int(float64(m.width) * wPct) - 2 // -2 for borders
				pHeight := int(float64(viewportHeight) * hPct) - 3 // -3 for borders and title

				isMaximizedPane := m.isMaximized && pIdx == m.activePageIndex && i == m.activePaneIndex
				if m.pages[pIdx][i].IsInspectMode || isMaximizedPane {
					pWidth = m.width - 2
					pHeight = viewportHeight - 3
				}

				if pWidth < 10 { pWidth = 10 }
				if pHeight < 5 { pHeight = 5 }

				m.pages[pIdx][i].Table.SetWidth(pWidth)
				m.pages[pIdx][i].Table.SetHeight(pHeight)
				m.pages[pIdx][i].Viewport.Width = pWidth
				m.pages[pIdx][i].Viewport.Height = pHeight

				// Resize columns intelligently
				if len(m.pages[pIdx][i].Def.Columns) > 0 {
					cols, activeCols := budgetColumns(m.pages[pIdx][i].Def.Columns, pWidth, isMaximizedPane)
					m.pages[pIdx][i].Table.SetColumns(cols)
					m.pages[pIdx][i].ActiveCols = activeCols
				} else if m.pages[pIdx][i].Def.Type == "top" {
					var cols []table.Column
					keyTitle := "KEY"
					valTitle := "COUNT"
					if len(m.pages[pIdx][i].Def.AggregateBy) > 0 {
						agg := m.pages[pIdx][i].Def.AggregateBy[0]
						keyTitle = FormatColumnTitle(agg.Field, "")
						if agg.Label != "" {
							valTitle = strings.ToUpper(agg.Label)
						}
					}
					
					valWidth := 13
					overhead := 4 // 2 columns * 2 chars overhead
					keyWidth := pWidth - valWidth - overhead
					if keyWidth < 12 { keyWidth = 12 }
					
					cols = []table.Column{
						{Title: keyTitle, Width: keyWidth},
						{Title: valTitle, Width: valWidth},
					}
					m.pages[pIdx][i].Table.SetColumns(cols)
				}
			}
		}
		
		m.help.Width = m.width
		return m, nil

	case tickMsg:
		m.rate = m.rateCounter
		m.rateCounter = 0
		
		for pIdx := range m.pages {
			for i := range m.pages[pIdx] {
				pane := &m.pages[pIdx][i]
				if pane.Sparkline != nil {
					pane.Sparkline.Tick(msg.Time)
				}
				if pane.Def.Type == "top" && len(pane.Def.AggregateBy) > 0 {
					if pane.HashMapRef != nil {
						pollHashMap(pane, m.containers)
					} else {
						topResults := pane.Aggregator.Top(100)
						var rows []table.Row
						filter := strings.ToLower(pane.FilterQuery)
						for _, res := range topResults {
							if filter != "" {
								if !strings.Contains(strings.ToLower(fmt.Sprint(res.Key)), filter) {
									continue
								}
							}
							keyDisplay := m.resolveContainer(res.Key)
							rows = append(rows, table.Row{keyDisplay, fmt.Sprintf("%.0f", res.Value)})
						}
						pane.Table.SetRows(rows)
					}
				}
			}
		}

		return m, tickRate()

	case paneEventMsg:
		if m.isPaused {
			// Drain the channel but discard event from UI buffers
			return m, listenToPaneEvents(msg.PageIdx, msg.PaneIdx, m.pages[msg.PageIdx][msg.PaneIdx].EventChan)
		}

		if msg.PageIdx == m.activePageIndex {
			m.totalEvents++
			m.rateCounter++
		}

		pane := &m.pages[msg.PageIdx][msg.PaneIdx]
		if msg.Event != nil {
			pane.Buffer.Push(msg.Event)
			pane.Aggregator.Update(msg.Event, pane.Def.AggregateBy)
			if pane.Histogram != nil {
				pane.Histogram.Update(msg.Event)
			}
			if pane.Sparkline != nil {
				pane.Sparkline.Update(msg.Event)
			}
			if pane.TraceTree != nil {
				pane.TraceTree.Update(msg.Event)
			}
		}

		if pane.Def.Type == "stream" {
			columns := pane.Def.Columns
			if len(pane.ActiveCols) > 0 {
				columns = pane.ActiveCols
			}
			allEvents := pane.Buffer.GetAll()
			var rows []table.Row
			filter := strings.ToLower(pane.FilterQuery)
			searchFields := pane.Def.SearchableFields
			
			for _, e := range allEvents {
				if filter != "" && len(searchFields) > 0 {
					matched := false
					for _, field := range searchFields {
						if val, ok := e[field]; ok {
							if strings.Contains(strings.ToLower(fmt.Sprint(val)), filter) {
								matched = true
								break
							}
						}
					}
					if !matched {
						continue
					}
				}
				
				var row table.Row
				for _, col := range columns {
					var valStr string
					if col.Field == "time" || col.Field == "timestamp" {
						if tVal, ok := e[col.Field]; ok && tVal != nil && fmt.Sprint(tVal) != "" {
							valStr = sanitizeString(fmt.Sprint(tVal))
						} else {
							valStr = time.Now().Format("15:04:05")
						}
					} else if val, ok := e[col.Field]; ok {
						if col.Field == "level" || col.Field == "severity" || col.Format == "level" {
							str, style := FormatSeverity(val)
							valStr = style.Render(str)
						} else if IsLatencyField(col.Field, col.Format) {
							str, style := FormatLatency(val, col.Field)
							valStr = style.Render(str)
						} else {
							var strVal string
							if s, isStr := val.(string); isStr {
								strVal = s
							} else {
								strVal = fmt.Sprint(val)
							}
							if col.Field == "container_id" || col.Format == "container_id" {
								strVal = m.resolveContainer(strVal)
							}
							valStr = sanitizeString(strVal)
						}
					}
					row = append(row, valStr)
				}
				rows = append(rows, row)
			}
			pane.Table.SetRows(rows)
			pane.Table.GotoBottom()
		}

		return m, listenToPaneEvents(msg.PageIdx, msg.PaneIdx, pane.EventChan)
	}

	if len(m.pages) > 0 && len(m.pages[m.activePageIndex]) > 0 {
		activePane := &m.pages[m.activePageIndex][m.activePaneIndex]
		if activePane.IsInspectMode {
			if activePane.Def.InspectPayload != "" {
				activePane.Viewport, cmd = activePane.Viewport.Update(msg)
			} else {
				activePane.Table, cmd = activePane.Table.Update(msg)
			}
		} else {
			activePane.Table, cmd = activePane.Table.Update(msg)
		}
		cmds = append(cmds, cmd)
	}

	return m, tea.Batch(cmds...)
}

func parsePct(val string) (float64, error) {
	if strings.HasSuffix(val, "%") {
		var n float64
		_, err := fmt.Sscanf(val, "%f%%", &n)
		return n / 100.0, err
	}
	return 0, fmt.Errorf("invalid percentage")
}

func stripChunkHeader(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\x00", ""))
	if idx := strings.Index(s, "\n"); idx > 0 && idx <= 10 {
		line := strings.TrimRight(s[:idx], "\r")
		allHex := true
		for _, r := range line {
			if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
				allHex = false
				break
			}
		}
		if allHex && len(line) > 0 {
			return strings.TrimSpace(s[idx+1:])
		}
	}
	return s
}

func formatEventInspectContent(event map[string]interface{}, paneDef registry.TUIPane) string {
	if event == nil {
		return "No event data available."
	}

	inspectField := paneDef.InspectPayload

	// 1. Resolve Product/Server Version
	versionVal := ""
	if paneDef.VersionField != "" && event[paneDef.VersionField] != nil {
		versionVal = fmt.Sprint(event[paneDef.VersionField])
	} else {
		for _, k := range []string{"server_version", "version", "product_version", "engine_version"} {
			if event[k] != nil && fmt.Sprint(event[k]) != "" {
				versionVal = fmt.Sprint(event[k])
				break
			}
		}
	}

	// 2. Resolve Protocol
	protoVal := ""
	if paneDef.ProtoField != "" && event[paneDef.ProtoField] != nil {
		protoVal = fmt.Sprint(event[paneDef.ProtoField])
	} else {
		for _, k := range []string{"proto", "protocol", "dialect"} {
			if event[k] != nil && fmt.Sprint(event[k]) != "" {
				protoVal = fmt.Sprint(event[k])
				break
			}
		}
	}

	// 3. Resolve Request / Input Body
	reqPayloadVal := ""
	if paneDef.RequestPayloadField != "" && event[paneDef.RequestPayloadField] != nil {
		reqPayloadVal = fmt.Sprint(event[paneDef.RequestPayloadField])
	} else {
		for _, k := range []string{"req_payload", "query", "command", "args", "payload"} {
			if event[k] != nil && fmt.Sprint(event[k]) != "" {
				reqPayloadVal = fmt.Sprint(event[k])
				break
			}
		}
	}

	// 4. Resolve Response / Output Body
	respPayloadVal := ""
	if paneDef.ResponsePayloadField != "" && event[paneDef.ResponsePayloadField] != nil {
		respPayloadVal = fmt.Sprint(event[paneDef.ResponsePayloadField])
	} else {
		for _, k := range []string{"resp_payload", "response", "result", "error_msg"} {
			if event[k] != nil && fmt.Sprint(event[k]) != "" {
				respPayloadVal = fmt.Sprint(event[k])
				break
			}
		}
	}

	// If neither dual payload nor version exists, and inspectField is specific, fallback to original single field
	if reqPayloadVal == "" && respPayloadVal == "" && versionVal == "" && protoVal == "" && inspectField != "raw" && inspectField != "raw_data" && inspectField != "*" && inspectField != "" {
		if val, ok := event[inspectField]; ok {
			if str, isStr := val.(string); isStr {
				cleanStr := strings.ReplaceAll(str, "\x00", "")
				return ansi.Strip(cleanStr)
			}
			b, _ := json.MarshalIndent(val, "", "  ")
			return string(b)
		}
	}

	var b strings.Builder

	// Header Banner
	b.WriteString("═══ 📦 EVENT INSPECTION ═══════════════════════════════════════════════════════\n")

	// Metadata Summary Line
	var metaItems []string
	if protoVal != "" {
		metaItems = append(metaItems, fmt.Sprintf("Protocol: %s", protoVal))
	}
	if versionVal != "" {
		metaItems = append(metaItems, fmt.Sprintf("Version: %s", versionVal))
	}
	if event["status_code"] != nil && fmt.Sprint(event["status_code"]) != "0" {
		metaItems = append(metaItems, fmt.Sprintf("Status: %v", event["status_code"]))
	}
	if event["duration_us"] != nil {
		dUs, _ := strconv.ParseFloat(fmt.Sprint(event["duration_us"]), 64)
		if dUs >= 1000.0 {
			metaItems = append(metaItems, fmt.Sprintf("Latency: %.2fms", dUs/1000.0))
		} else if dUs > 0 {
			metaItems = append(metaItems, fmt.Sprintf("Latency: %.0fµs", dUs))
		}
	}
	if event["comm"] != nil || event["pid"] != nil {
		metaItems = append(metaItems, fmt.Sprintf("Process: %v [PID: %v]", event["comm"], event["pid"]))
	}
	if len(metaItems) > 0 {
		b.WriteString(strings.Join(metaItems, "  │  ") + "\n")
	}
	if event["method"] != nil && event["path"] != nil {
		hostPrefix := ""
		if event["host"] != nil && fmt.Sprint(event["host"]) != "" {
			hostPrefix = fmt.Sprintf(" http://%v", event["host"])
		}
		b.WriteString(fmt.Sprintf("Endpoint: %v%s%v\n", event["method"], hostPrefix, event["path"]))
	}

	// Request Payload Section
	if reqPayloadVal != "" {
		b.WriteString("\n─── ▶ REQUEST / INPUT PAYLOAD ────────────────────────────────────────────────\n")
		cleanReq := stripChunkHeader(reqPayloadVal)
		var js interface{}
		if json.Unmarshal([]byte(cleanReq), &js) == nil {
			prettyJSON, err := json.MarshalIndent(js, "", "  ")
			if err == nil {
				cleanReq = string(prettyJSON)
			}
		}
		b.WriteString(cleanReq + "\n")
	}

	// Response Payload Section
	if respPayloadVal != "" {
		b.WriteString("\n─── ◀ RESPONSE / OUTPUT BODY ─────────────────────────────────────────────────\n")
		cleanResp := stripChunkHeader(respPayloadVal)
		var js interface{}
		if json.Unmarshal([]byte(cleanResp), &js) == nil {
			prettyJSON, err := json.MarshalIndent(js, "", "  ")
			if err == nil {
				cleanResp = string(prettyJSON)
			}
		}
		b.WriteString(cleanResp + "\n")
	}

	// All Raw Fields Section
	b.WriteString("\n─── 📋 ALL EVENT FIELDS ──────────────────────────────────────────────────────\n")
	var fieldLines []string
	for k, v := range event {
		if k == "req_payload" || k == "resp_payload" {
			continue // Already shown prominently above
		}
		fieldLines = append(fieldLines, fmt.Sprintf("%-16s: %v", k, v))
	}
	sort.Strings(fieldLines)
	b.WriteString(strings.Join(fieldLines, "\n"))

	return b.String()
}

func (m Model) rebuildInspectViewport(pane *PaneModel) {
	if !pane.IsInspectMode || pane.Def.Type != "top" {
		return
	}

	aggField := "unknown_field"
	if len(pane.Def.AggregateBy) > 0 {
		aggField = pane.Def.AggregateBy[0].Field
	}
	aggKey := pane.InspectKey
	if aggKey == "" {
		row := pane.Table.SelectedRow()
		if row != nil && len(row) >= 2 {
			aggKey = fmt.Sprint(row[0])
		}
	}
	if aggKey == "" {
		return
	}

	inspectField := pane.Def.InspectPayload
	allEvents := pane.Buffer.GetAll()
	var lines []string

	headerStr := fmt.Sprintf("=== Recent raw events for %s: %s ===", strings.ToUpper(aggField), aggKey)
	lines = append(lines, headerStr)

	filter := strings.ToLower(pane.FilterQuery)
	count := 0

	for _, event := range allEvents {
		if fmt.Sprint(event[aggField]) == aggKey {
			var payloadStr string
			if inspectField == "raw" || inspectField == "raw_data" || inspectField == "*" {
				payloadStr = formatEventInspectContent(event, pane.Def)
			} else {
				if val, ok := event[inspectField]; ok {
					if strVal, isStr := val.(string); isStr {
						cleanStr := ansi.Strip(strVal)
						cleanStr = strings.ReplaceAll(cleanStr, "\x00", "")
						payloadStr = cleanStr
					} else {
						b, _ := json.Marshal(val)
						payloadStr = string(b)
					}
				}
			}

			if payloadStr != "" {
				if filter != "" {
					if !strings.Contains(strings.ToLower(payloadStr), filter) {
						continue
					}
				}
				count++
				lines = append(lines, payloadStr)
			}
		}
	}

	if count == 0 {
		if filter != "" {
			lines = append(lines, fmt.Sprintf("No recent raw events found matching filter %q.", pane.FilterQuery))
		} else {
			lines = append(lines, "No recent raw events found in buffer.")
		}
	}

	content := strings.Join(lines, "\n")
	wrappedContent := lipgloss.NewStyle().Width(m.width - 4).Render(content)
	pane.Viewport.SetContent(wrappedContent)
}

func (m Model) renderBriefContent() string {
	var b strings.Builder

	desc := "No module description available."
	author := "eprobe-core-team"
	ver := "v1.0.0"
	modName := "unknown"
	if m.manifest != nil {
		if m.manifest.Name != "" {
			modName = m.manifest.Name
		}
		if m.manifest.Description != "" {
			desc = m.manifest.Description
		}
		if m.manifest.Author != "" {
			author = m.manifest.Author
		}
		if m.manifest.Version != "" {
			ver = m.manifest.Version
		}
	}

	headerTitle := fmt.Sprintf("📦 Module Overview: %s (v%s by %s)", modName, ver, author)
	b.WriteString(lipgloss.NewStyle().Foreground(secondaryColor).Bold(true).Render(headerTitle) + "\n")
	b.WriteString(fmt.Sprintf("   %s\n\n", desc))

	b.WriteString(lipgloss.NewStyle().Foreground(primaryColor).Bold(true).Render("📊 Dashboards & Available Pages:") + "\n")
	if m.manifest != nil && len(m.manifest.TUIHints.Pages) > 0 {
		for pIdx, p := range m.manifest.TUIHints.Pages {
			activeIndicator := "  "
			if pIdx == m.activePageIndex {
				activeIndicator = "● "
			}
			pageTitle := fmt.Sprintf("   %s[%d/%d] %s", activeIndicator, pIdx+1, len(m.manifest.TUIHints.Pages), strings.ToUpper(p.Name))
			b.WriteString(lipgloss.NewStyle().Foreground(accentColor).Bold(true).Render(pageTitle) + "\n")
			for _, pane := range p.Panes {
				searchHint := ""
				if len(pane.SearchableFields) > 0 {
					searchHint = " (Filterable: /)"
				}
				paneSummary := pane.Summary
				if paneSummary == "" {
					paneSummary = "Telemetry data pane"
				}
				b.WriteString(fmt.Sprintf("       - [%s] %s: %s%s\n", strings.ToUpper(pane.Type), pane.Name, paneSummary, searchHint))
			}
		}
	} else {
		b.WriteString("   - Default Page Layout\n")
	}

	b.WriteString("\n" + lipgloss.NewStyle().Foreground(warningColor).Bold(true).Render("⌨️  Essential Shortcuts & Keybindings:") + "\n")
	b.WriteString("   1-9 / [ / ]  Switch Dashboard Pages        m        Maximize / Restore Active Pane\n")
	b.WriteString("   Tab          Cycle Active Panes            /        Dynamic Filter / Search\n")
	b.WriteString("   Enter        Inspect Event / Maximize      Esc      Close Modal / Reset View\n")
	b.WriteString("   p / Space    Pause / Resume Stream         q        Quit eprobe\n")
	b.WriteString("   ↑/↓/j/k      Navigate Rows / Tree Nodes    ←/→/h/l  Collapse / Expand Tree Branch\n")
	b.WriteString("   e            Expand / Collapse All Nodes   ?        Toggle Help & Overview\n\n")

	b.WriteString(lipgloss.NewStyle().Foreground(mutedText).Italic(true).Render("Press [Esc], [Enter], or [Space] to dismiss this overview and open dashboard..."))

	return b.String()
}

func (m Model) View() string {
	if m.width == 0 || m.height == 0 {
		return "Initializing eprobe TUI..."
	}

	headerHeight := 3
	footerHeight := 3
	viewportHeight := m.height - headerHeight - footerHeight
	if viewportHeight < 0 { viewportHeight = 0 }

	statusIndicator := lipgloss.NewStyle().Foreground(successColor).Render("● RUNNING")
	if m.isPaused {
		statusIndicator = lipgloss.NewStyle().Foreground(warningColor).Render("⏸ PAUSED")
	}
	modName := "unknown"
	pageName := "Unknown Page"
	if m.manifest != nil { 
		if m.manifest.Version != "" {
			modName = fmt.Sprintf("%s v%s", m.manifest.Name, m.manifest.Version)
		} else {
			modName = m.manifest.Name
		}
		if len(m.manifest.TUIHints.Pages) > m.activePageIndex {
			pageName = m.manifest.TUIHints.Pages[m.activePageIndex].Name
		}
	}
	
	pageIndicator := pageName
	if m.manifest != nil && len(m.manifest.TUIHints.Pages) > 1 {
		pageIndicator = fmt.Sprintf("[%d/%d] %s", m.activePageIndex+1, len(m.manifest.TUIHints.Pages), pageName)
	}

	streamIndicator := ""
	if m.streamer != nil {
		streamIndicator = fmt.Sprintf("   │   Stream: %s", lipgloss.NewStyle().Foreground(secondaryColor).Bold(true).Render("Active"))
	}

	cliVer := m.version
	if cliVer != "" && !strings.HasPrefix(cliVer, "v") && cliVer != "dev" {
		cliVer = "v" + cliVer
	}

	headerContent := fmt.Sprintf("eprobe %s   │   Module: %s   │   Page: %s%s   │   Status: %s",
		cliVer,
		lipgloss.NewStyle().Foreground(secondaryColor).Bold(true).Render(modName),
		lipgloss.NewStyle().Foreground(primaryColor).Bold(true).Render(pageIndicator),
		streamIndicator,
		statusIndicator,
	)
	
	headerContentTruncated := ansi.Truncate(headerContent, m.width - 8, "...")
	headerView := headerStyle.Width(m.width - 4).Render(headerContentTruncated)

	var contentView string

	if m.showBriefModal || m.helpMode {
		briefText := m.renderBriefContent()
		boxStyle := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(primaryColor).
			Padding(1, 2).
			Width(m.width - 4)
		contentView = boxStyle.Render(briefText)
	} else if len(m.pages) > m.activePageIndex {
		// Layout the panes for the active page
		
		var inspectPane *PaneModel
		for i := range m.pages[m.activePageIndex] {
			if m.pages[m.activePageIndex][i].IsInspectMode {
				inspectPane = &m.pages[m.activePageIndex][i]
				break
			}
		}

		if inspectPane != nil {
			title := fmt.Sprintf(" %s (INSPECT) ", strings.ToUpper(inspectPane.Def.Name))
			var inspectContent string
			if inspectPane.Def.InspectPayload != "" {
				inspectContent = inspectPane.Viewport.View()
			} else {
				inspectContent = renderPaneTable(inspectPane, true)
			}
			contentView = paneActiveStyle.Width(m.width - 2).Height(viewportHeight).Render(lipgloss.JoinVertical(lipgloss.Left, 
				lipgloss.NewStyle().Foreground(accentColor).Bold(true).Render(title),
				inspectContent,
			))
		} else if m.isMaximized && len(m.pages[m.activePageIndex]) > m.activePaneIndex {
			pane := m.pages[m.activePageIndex][m.activePaneIndex]
			title := fmt.Sprintf(" %s [MAXIMIZED - Press 'm' or 'Esc' to Restore] ", strings.ToUpper(pane.Def.Name))
			var pContent string
			pWidth := m.width - 6
			switch pane.Def.Type {
			case "histogram":
				if pane.Histogram != nil {
					pContent = pane.Histogram.Render(pWidth, viewportHeight-2)
				} else {
					pContent = "Histogram pane not initialized"
				}
			case "sparkline":
				if pane.Sparkline != nil {
					pContent = pane.Sparkline.Render(pWidth)
				} else {
					pContent = "Sparkline pane not initialized"
				}
			case "tree":
				if pane.TraceTree != nil {
					pContent = pane.TraceTree.Render(pWidth, viewportHeight-2)
				} else {
					pContent = "TraceTree pane not initialized"
				}
			case "top", "stream":
				pContent = renderPaneTable(&pane, true)
			default:
				pContent = "Unsupported pane type"
			}
			contentView = paneActiveStyle.Width(m.width - 2).Height(viewportHeight).Render(lipgloss.JoinVertical(lipgloss.Left,
				lipgloss.NewStyle().Foreground(accentColor).Bold(true).Render(title),
				pContent,
			))
		} else {
			rowsMap := make(map[int][]int)
			for i, p := range m.pages[m.activePageIndex] {
				rowsMap[p.Def.Position.Row] = append(rowsMap[p.Def.Position.Row], i)
			}
			
			var rows []int
			for r := range rowsMap {
				rows = append(rows, r)
			}
			sort.Ints(rows)

			var rowViews []string
			for _, rowIdx := range rows {
				var colViews []string
				for _, pIdx := range rowsMap[rowIdx] {
					pane := m.pages[m.activePageIndex][pIdx]
					
					wPct, _ := parsePct(pane.Def.Position.Width)
					if wPct == 0 { wPct = 1.0 }
					pWidth := int(float64(m.width) * wPct) - 2

					style := paneNormalStyle.Width(pWidth + 2)
					if pIdx == m.activePaneIndex {
						style = paneActiveStyle.Width(pWidth + 2)
					}

					var pContent string
					switch pane.Def.Type {
					case "histogram":
						if pane.Histogram != nil {
							pContent = pane.Histogram.Render(pWidth, viewportHeight)
						} else {
							pContent = "Histogram pane not initialized"
						}
					case "sparkline":
						if pane.Sparkline != nil {
							pContent = pane.Sparkline.Render(pWidth)
						} else {
							pContent = "Sparkline pane not initialized"
						}
					case "tree":
						if pane.TraceTree != nil {
							pContent = pane.TraceTree.Render(pWidth, viewportHeight)
						} else {
							pContent = "Tree pane not initialized"
						}
					default:
						pContent = renderPaneTable(&pane, pIdx == m.activePaneIndex)
					}
					
					title := fmt.Sprintf(" %s ", strings.ToUpper(pane.Def.Name))
					if pIdx == m.activePaneIndex {
						badge := " [ACTIVE • 'm' Maximize] "
						if len(title)+len(badge) > pWidth-2 {
							badge = " [ACTIVE • 'm'] "
							if len(title)+len(badge) > pWidth-2 {
								badge = " [ACTIVE] "
							}
						}
						title = fmt.Sprintf(" %s%s", strings.ToUpper(pane.Def.Name), badge)
					}
					title = ansi.Truncate(title, pWidth-2, "…")
					rendered := style.Render(lipgloss.JoinVertical(lipgloss.Left, 
						lipgloss.NewStyle().Foreground(secondaryColor).Bold(true).Render(title),
						pContent,
					))
					colViews = append(colViews, rendered)
				}
				rowViews = append(rowViews, lipgloss.JoinHorizontal(lipgloss.Top, colViews...))
			}
			contentView = lipgloss.JoinVertical(lipgloss.Left, rowViews...)
		}
	}

	contentLines := strings.Split(contentView, "\n")
	for len(contentLines) < viewportHeight {
		contentLines = append(contentLines, "")
	}
	contentView = strings.Join(contentLines[:viewportHeight], "\n")

	rateStr := fmt.Sprintf("%d Hz/sec", m.rate)
	if m.rate == 0 && m.totalEvents > 0 { rateStr = "<1 Hz/sec" }

	var activeFilters []string
	if m.activeFilter != "None" && m.activeFilter != "" {
		activeFilters = append(activeFilters, m.activeFilter)
	}

	if len(m.pages) > m.activePageIndex && len(m.pages[m.activePageIndex]) > m.activePaneIndex {
		q := m.pages[m.activePageIndex][m.activePaneIndex].FilterQuery
		if q != "" {
			activeFilters = append(activeFilters, fmt.Sprintf("Pane:%q", q))
		}
	}

	finalFilterStr := "None"
	if len(activeFilters) > 0 {
		finalFilterStr = strings.Join(activeFilters, " + ")
	}

	footerContent := fmt.Sprintf("%s %s   │   %s %s   │   %s %s",
		metricLabelStyle.Render("Total Events:"),
		metricValueStyle.Render(fmt.Sprintf("%d", m.totalEvents)),
		metricLabelStyle.Render("Event Rate:"),
		metricValueStyle.Render(rateStr),
		metricLabelStyle.Render("Filters:"),
		filterStyle.Render(finalFilterStr),
	)

	dropped := atomic.LoadInt64(m.droppedEvents)
	if dropped > 0 {
		footerContent += fmt.Sprintf("   │   %s %s",
			metricLabelStyle.Render("Dropped:"),
			lipgloss.NewStyle().Foreground(errorColor).Bold(true).Render(fmt.Sprintf("%d", dropped)),
		)
	}

	if m.isSearching && len(m.pages) > m.activePageIndex && len(m.pages[m.activePageIndex]) > m.activePaneIndex {
			paneName := m.pages[m.activePageIndex][m.activePaneIndex].Def.Name
			footerContent = fmt.Sprintf(" %s %s", 
				lipgloss.NewStyle().Foreground(primaryColor).Bold(true).Render(fmt.Sprintf("🔍 Filter %s:", strings.ToUpper(paneName))),
				m.searchInput.View(),
			)
	}

	footerContentTruncated := ansi.Truncate(footerContent, m.width - 8, "...")
	footerView := footerStyle.Width(m.width - 4).Render(footerContentTruncated)

	return lipgloss.JoinVertical(lipgloss.Left, headerView, contentView, footerView)
}

// renderPaneTable renders table contents with ANSI-aware cell truncation and scrolling.
func renderPaneTable(pane *PaneModel, isFocused bool) string {
	tbl := pane.Table
	cols := tbl.Columns()
	rows := tbl.Rows()
	cursor := tbl.Cursor()
	height := tbl.Height()
	if height < 1 {
		height = 1
	}

	var headerCells []string
	for _, col := range cols {
		if col.Width <= 0 {
			continue
		}
		cell := ansi.Truncate(col.Title, col.Width, "…")
		headerCells = append(headerCells, lipgloss.NewStyle().Width(col.Width).MaxWidth(col.Width).Bold(false).Render(cell))
	}
	headerLine := lipgloss.NewStyle().
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("240")).
		BorderBottom(true).
		Render(strings.Join(headerCells, "  "))

	// Sliding window for visible rows
	start := 0
	if cursor >= height {
		start = cursor - height + 1
	}
	end := start + height
	if end > len(rows) {
		end = len(rows)
	}

	var renderedRows []string
	for r := start; r < end; r++ {
		row := rows[r]
		var rowCells []string
		for i, val := range row {
			if i >= len(cols) || cols[i].Width <= 0 {
				continue
			}
			w := cols[i].Width
			cell := ansi.Truncate(val, w, "…")
			cellPadded := lipgloss.NewStyle().Width(w).MaxWidth(w).Inline(true).Render(cell)
			rowCells = append(rowCells, cellPadded)
		}
		rowLine := strings.Join(rowCells, "  ")
		if r == cursor && isFocused {
			rowLine = lipgloss.NewStyle().Foreground(lipgloss.Color("229")).Background(lipgloss.Color("57")).Render(rowLine)
		}
		renderedRows = append(renderedRows, rowLine)
	}

	for len(renderedRows) < height {
		renderedRows = append(renderedRows, "")
	}

	return headerLine + "\n" + lipgloss.JoinVertical(lipgloss.Left, renderedRows...)
}

// budgetColumns calculates column widths and fits columns within availWidth to guarantee no line wrapping.
func budgetColumns(rawCols []registry.ColumnHint, availWidth int, isMaximized bool) ([]table.Column, []registry.ColumnHint) {
	if len(rawCols) == 0 {
		return nil, nil
	}

	type colMeta struct {
		hint        registry.ColumnHint
		title       string
		minWidth    int
		isFlex      bool
		isSecondary bool
	}

	var metas []colMeta
	for _, col := range rawCols {
		field := strings.ToLower(col.Field)
		title := FormatColumnTitle(col.Field, col.Label)
		w := col.Width

		isFlex := field == "message" || field == "payload" || field == "query" || field == "filename" || field == "path" || w <= 0
		isSecondary := field == "tid" || field == "runq_latency_us" || field == "stall_type" || field == "op_type" || field == "daddr" || field == "saddr" || field == "client_ip"

		minW := w
		switch {
		case field == "time" || field == "timestamp":
			minW = 10
		case field == "level" || field == "severity" || col.Format == "level":
			if minW < 10 {
				minW = 10
			}
		case field == "container_id":
			if minW < 16 {
				minW = 16
			}
		case field == "comm":
			if minW < 15 {
				minW = 15
			}
		case field == "pid":
			if minW < 7 {
				minW = 7
			}
		case field == "tid":
			if minW < 8 {
				minW = 8
			}
		case field == "duration_us" || field == "duration" || field == "latency_us" || col.Format == "latency":
			if minW < 12 {
				minW = 12
			}
		case field == "runq_latency_us":
			if minW < 13 {
				minW = 13
			}
		case isFlex:
			minW = 0
		default:
			if minW < 8 {
				minW = 8
			}
		}

		metas = append(metas, colMeta{
			hint:        col,
			title:       title,
			minWidth:    minW,
			isFlex:      isFlex,
			isSecondary: isSecondary,
		})
	}

	active := metas
	if !isMaximized && availWidth < 140 {
		fixedSum := 0
		for _, m := range active {
			fixedSum += m.minWidth
		}
		overhead := len(active) * 2
		// If total exceeds available width minus flex allowance, drop secondary columns
		if fixedSum+overhead+15 > availWidth {
			var filtered []colMeta
			for _, m := range active {
				if m.isSecondary && fixedSum+overhead+15 > availWidth {
					fixedSum -= m.minWidth
					overhead -= 2
					continue
				}
				filtered = append(filtered, m)
			}
			active = filtered
		}
	}

	fixedSum := 0
	flexCount := 0
	for _, m := range active {
		if m.isFlex {
			flexCount++
		} else {
			fixedSum += m.minWidth
		}
	}
	overhead := len(active) * 2
	remaining := availWidth - fixedSum - overhead
	if remaining < 12 {
		remaining = 12
	}

	flexWidth := 15
	if flexCount > 0 {
		flexWidth = remaining / flexCount
		if flexWidth < 12 {
			flexWidth = 12
		}
	}

	var cols []table.Column
	var activeHints []registry.ColumnHint
	for _, m := range active {
		w := m.minWidth
		if m.isFlex {
			w = flexWidth
		}
		cols = append(cols, table.Column{Title: m.title, Width: w})
		activeHints = append(activeHints, m.hint)
	}

	return cols, activeHints
}

func initTable(def registry.TUIPane) (table.Model, []registry.ColumnHint) {
	var cols []table.Column
	var activeCols []registry.ColumnHint
	
	if len(def.Columns) > 0 {
		cols, activeCols = budgetColumns(def.Columns, 120, false)
	} else {
		cols = []table.Column{
			{Title: "TIME", Width: 10},
			{Title: "PID", Width: 8},
			{Title: "COMM", Width: 15},
			{Title: "MESSAGE", Width: 40},
		}
		activeCols = []registry.ColumnHint{
			{Field: "time", Width: 10},
			{Field: "pid", Width: 8},
			{Field: "comm", Width: 15},
			{Field: "message", Width: 40},
		}
	}
	
	t := table.New(
		table.WithColumns(cols),
		table.WithFocused(false),
	)
	
	s := table.DefaultStyles()
	s.Header = s.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("240")).
		BorderBottom(true).
		Bold(false)
	s.Selected = s.Selected.
		Foreground(lipgloss.Color("229")).
		Background(lipgloss.Color("57")).
		Bold(false)
	t.SetStyles(s)
	
	return t, activeCols
}

func initTopTable(def registry.TUIPane) table.Model {
	var cols []table.Column
	
	keyTitle := "KEY"
	valTitle := "COUNT"
	if len(def.AggregateBy) > 0 {
		agg := def.AggregateBy[0]
		keyTitle = FormatColumnTitle(agg.Field, "")
		if agg.Label != "" {
			valTitle = strings.ToUpper(agg.Label)
		}
	}
	cols = []table.Column{
		{Title: keyTitle, Width: 25},
		{Title: valTitle, Width: 13},
	}
	
	t := table.New(
		table.WithColumns(cols),
		table.WithFocused(false),
	)
	
	s := table.DefaultStyles()
	s.Header = s.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("240")).
		BorderBottom(true).
		Bold(false)
	s.Selected = s.Selected.
		Foreground(lipgloss.Color("229")).
		Background(lipgloss.Color("57")).
		Bold(false)
	t.SetStyles(s)
	
	return t
}

func StartTUI(ctx context.Context, bpfMaps map[string]*ebpf.Map, manifest *registry.Manifest, version string, filterCfg FilterConfig, streamer *Streamer) error {
	var droppedCounter int64

	ti := textinput.New()
	ti.Placeholder = "Type filter and press Enter..."
	ti.CharLimit = 64
	ti.Width = 40

	m := Model{
		version:        version,
		manifest:       manifest,
		filterPort:     filterCfg.FilterPort,
		droppedEvents:  &droppedCounter,
		keys:           keys,
		help:           help.New(),
		searchInput:    ti,
		showBriefModal: true,
		streamer:       streamer,
		containers:     system.ResolveContainers(),
	}

	var activeFilters []string
	if filterCfg.FilterPort > 0 {
		activeFilters = append(activeFilters, fmt.Sprintf("Port=%d", filterCfg.FilterPort))
	}
	if filterCfg.FilterComm != "" {
		activeFilters = append(activeFilters, fmt.Sprintf("Comm=%s", filterCfg.FilterComm))
	}
	if filterCfg.FilterHost != "" {
		activeFilters = append(activeFilters, fmt.Sprintf("Host=%s", filterCfg.FilterHost))
	}
	if filterCfg.FilterErrors {
		activeFilters = append(activeFilters, "ErrorsOnly")
	}
	if len(activeFilters) > 0 {
		m.activeFilter = strings.Join(activeFilters, ", ")
	} else {
		m.activeFilter = "None"
	}

	mapChans := make(map[string][]chan map[string]interface{})

	if manifest != nil {
		for _, pageDef := range manifest.TUIHints.Pages {
			var pagePanes []PaneModel
			for i, paneDef := range pageDef.Panes {
				pm := PaneModel{
					Def:        paneDef,
					Buffer:     NewEventBuffer(10000),
					Aggregator: NewAggregator(),
					EventChan:  make(chan map[string]interface{}, 10000),
					Viewport:   viewport.New(0, 0),
				}
				
				if paneDef.Type == "top" {
					pm.Table = initTopTable(paneDef)
				} else {
					pm.Table, pm.ActiveCols = initTable(paneDef)
				}

				if paneDef.Type == "histogram" {
					pm.Histogram = NewHistogram(paneDef.HistogramField, paneDef.Unit, paneDef.Buckets)
				} else if paneDef.Type == "sparkline" {
					pm.Sparkline = NewSparklineBuffer(paneDef.MetricField, paneDef.TimeWindowSec, paneDef.Aggregation)
				} else if paneDef.Type == "tree" {
					pm.TraceTree = NewTraceTree(paneDef.NodeID, paneDef.ParentID, paneDef.LabelFields, paneDef.DurationField, paneDef.BadgeField, paneDef.TokenField, paneDef.StatusField)
				}

				if i == 0 {
					pm.Table.Focus()
				}
				
				pagePanes = append(pagePanes, pm)

				if paneDef.MapName != "" {
					mapSpec := manifest.GetMapByName(paneDef.MapName)
					if mapSpec != nil && mapSpec.Type == "hash" {
						if bpfMap, ok := bpfMaps[paneDef.MapName]; ok {
							pagePanes[len(pagePanes)-1].HashMapRef = bpfMap
							pagePanes[len(pagePanes)-1].HashSchema = mapSpec
						}
					} else {
						mapChans[paneDef.MapName] = append(mapChans[paneDef.MapName], pm.EventChan)
					}
				}
			}
			m.pages = append(m.pages, pagePanes)
		}
	}

	for mapName, chans := range mapChans {
		if bpfMap, ok := bpfMaps[mapName]; ok {
			go runMapReader(ctx, bpfMap, manifest.GetMapByName(mapName), chans, &droppedCounter, filterCfg, streamer)
		}
	}

	if len(m.pages) > 0 && len(m.pages[0]) > 0 && (manifest == nil || manifest.TUIHints.Pages[0].Panes[0].InspectPayload == "") {
		// Just a visual hint override
		m.keys.Enter.SetEnabled(true) // we upgraded Enter to always work in v3.1+
	}

	p := tea.NewProgram(
		&m,
		tea.WithAltScreen(),
		tea.WithMouseCellMotion(),
	)

	// Handle graceful closure when context is cancelled externally
	go func() {
		<-ctx.Done()
		p.Send(tea.Quit())
	}()

	_, err := p.Run()
	return err
}

func runMapReader(ctx context.Context, bpfMap *ebpf.Map, mapSpec *registry.MapSpec, eventChans []chan map[string]interface{}, dropped *int64, filterCfg FilterConfig, streamer *Streamer) {
	rd, err := ringbuf.NewReader(bpfMap)
	if err != nil {
		return
	}
	defer rd.Close()

	go func() {
		<-ctx.Done()
		rd.Close()
	}()

	var schema []registry.FieldSchema
	if mapSpec != nil {
		schema = mapSpec.EventSchema
	}

	for {
		record, err := rd.Read()
		if err != nil {
			return
		}

		e, err := DecodeDynamicEvent(record.RawSample, schema)
		if err == nil {
			if !MatchesFilters(e, schema, filterCfg) {
				continue
			}
			if filterCfg.Sanitize {
				SanitizeEvent(e)
			}

			if streamer != nil && mapSpec != nil {
				streamer.EnqueueEvent(mapSpec.Name, e)
			}

			for _, ch := range eventChans {
				select {
				case ch <- e:
				default:
					atomic.AddInt64(dropped, 1)
				}
			}
		}
	}
}

// pollHashMap iterates a BPF_MAP_TYPE_HASH, decodes key/value pairs via schema,
// and populates the pane's table rows with sorted results.
func pollHashMap(pane *PaneModel, containers map[string]system.ContainerMeta) {
	if pane.HashMapRef == nil || pane.HashSchema == nil {
		return
	}

	if pane.StateCache == nil {
		pane.StateCache = make(map[string]StateSample)
	}

	keySize := calcSchemaSize(pane.HashSchema.KeySchema)
	valSize := calcSchemaSize(pane.HashSchema.ValueSchema)
	if keySize == 0 || valSize == 0 {
		return
	}

	key := make([]byte, keySize)
	val := make([]byte, valSize)
	now := time.Now()

	var results []AggregationResult
	iter := pane.HashMapRef.Iterate()
	for iter.Next(&key, &val) {
		dk, err := DecodeDynamicEvent(key, pane.HashSchema.KeySchema)
		if err != nil {
			continue
		}
		dv, err := DecodeDynamicEvent(val, pane.HashSchema.ValueSchema)
		if err != nil {
			continue
		}

		// Use first key field as the grouping key
		keyStr := ""
		if len(pane.HashSchema.KeySchema) > 0 {
			if v, ok := dk[pane.HashSchema.KeySchema[0].Name]; ok {
				var rawKey string
				if s, isStr := v.(string); isStr {
					rawKey = s
				} else {
					rawKey = fmt.Sprint(v)
				}
				keyStr = sanitizeString(rawKey)
			}
		}

		if len(pane.Def.AggregateBy) > 0 {
			aggType := pane.Def.AggregateBy[0].Type
			vf := pane.Def.AggregateBy[0].ValueField

			if aggType == "value" {
				if numVal, ok := dv[vf]; ok {
					results = append(results, AggregationResult{Key: keyStr, Value: toFloat64(numVal)})
				}
			} else if aggType == "delta_rate" {
				if numVal, ok := dv[vf]; ok {
					currentVal := toFloat64(numVal)
					if prev, ok := pane.StateCache[keyStr]; ok {
						deltaVal := currentVal - prev.Value
						deltaTimeSec := now.Sub(prev.Timestamp).Seconds()
						if deltaTimeSec > 0 && deltaVal >= 0 {
							var rate float64
							if vf == "cpu_time_ns" {
								rate = (deltaVal / (deltaTimeSec * 1e9)) * 100.0
							} else if strings.HasSuffix(vf, "_ns") || pane.Def.Unit == "s/s" {
								rate = deltaVal / (deltaTimeSec * 1e9)
							} else {
								rate = deltaVal / deltaTimeSec
							}
							results = append(results, AggregationResult{Key: keyStr, Value: rate})
						}
					}
					pane.StateCache[keyStr] = StateSample{Value: currentVal, Timestamp: now}
				}
			}
		}
	}

	sort.Slice(results, func(i, j int) bool { return results[i].Value > results[j].Value })

	filter := strings.ToLower(pane.FilterQuery)
	var rows []table.Row
	for _, r := range results {
		if filter != "" && !strings.Contains(strings.ToLower(r.Key), filter) {
			continue
		}
		formattedVal := ""
		if len(pane.Def.AggregateBy) > 0 && pane.Def.AggregateBy[0].Type == "delta_rate" {
			vf := pane.Def.AggregateBy[0].ValueField
			formattedVal = FormatRateMetric(r.Value, vf, pane.Def.Unit)
		} else {
			formattedVal = FormatValue(r.Value)
		}
		displayKey := r.Key
		if containers != nil {
			if meta, ok := containers[r.Key]; ok && meta.Name != "" {
				displayKey = meta.Name
			} else if len(r.Key) >= 12 {
				if meta, ok := containers[r.Key[:12]]; ok && meta.Name != "" {
					displayKey = meta.Name
				}
			}
		}
		rows = append(rows, table.Row{displayKey, formattedVal})
	}
	pane.Table.SetRows(rows)
}

// calcSchemaSize returns the total byte size of a field schema.
func calcSchemaSize(schema []registry.FieldSchema) int {
	size := 0
	for _, f := range schema {
		switch f.Type {
		case "uint8":
			size += 1
		case "uint16":
			size += 2
		case "uint32", "ipv4":
			size += 4
		case "uint64":
			size += 8
		case "string":
			size += f.Length
		case "ipv6":
			size += 16
		default:
			size += 4
		}
	}
	return size
}


// formatValue formats a large numeric value with appropriate unit suffixes.
func formatValue(v float64) string {
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
