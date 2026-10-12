package telemetry

import (
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

var (
	badgeAgentStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(lipgloss.Color("#059669")).
			Padding(0, 1)

	badgeLLMStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(lipgloss.Color("#DB2777")).
			Padding(0, 1)

	badgeToolStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(lipgloss.Color("#D97706")).
			Padding(0, 1)

	badgeHTTPStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(lipgloss.Color("#0D9488")).
			Padding(0, 1)

	badgeDBStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(lipgloss.Color("#2563EB")).
			Padding(0, 1)

	badgeOtherStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(lipgloss.Color("#64748B")).
			Padding(0, 1)

	warningStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#EF4444"))

	tokenChipStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#94A3B8")).
			Background(lipgloss.Color("#1E293B")).
			Padding(0, 1)

	barFastStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#10B981"))

	barMedStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F59E0B"))

	barSlowStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#EF4444"))

	dimBarStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#334155"))
)

// TreeNode represents a single process or HTTP span node in the execution tree
type TreeNode struct {
	ID            string
	ParentID      string
	Label         string
	Badge         string
	BadgeCategory string
	Duration      string
	DurationUs    float64
	Tokens        string
	HasWarning    bool
	StatusCode    int
	Proto         string
	ServerVersion string
	ReqPayload    string
	RespPayload   string
	Children      []*TreeNode
	Expanded      bool
	RawEvent      map[string]interface{}
	Depth         int
	IsLast        bool
}

// TraceTree maintains dynamic hierarchical parent-child execution graphs
type TraceTree struct {
	nodeIDKey     string
	parentIDKey   string
	labelFields   []string
	durationKey   string
	badgeKey      string
	tokenKey      string
	statusKey     string
	nodes         map[string]*TreeNode
	roots         []*TreeNode
	cursorIdx     int
	flattenedList []*TreeNode
	maxDurationUs float64
	allCollapsed  bool
	mu            sync.RWMutex
}

// NewTraceTree initializes a new TraceTree instance with optional badge, token, and status keys
func NewTraceTree(nodeIDKey, parentIDKey string, labelFields []string, durationKey string, optionalKeys ...string) *TraceTree {
	if nodeIDKey == "" {
		nodeIDKey = "pid"
	}
	if parentIDKey == "" {
		parentIDKey = "ppid"
	}

	badgeKey := ""
	tokenKey := ""
	statusKey := "status_code"

	if len(optionalKeys) > 0 {
		badgeKey = optionalKeys[0]
	}
	if len(optionalKeys) > 1 {
		tokenKey = optionalKeys[1]
	}
	if len(optionalKeys) > 2 && optionalKeys[2] != "" {
		statusKey = optionalKeys[2]
	}

	return &TraceTree{
		nodeIDKey:     nodeIDKey,
		parentIDKey:   parentIDKey,
		labelFields:   labelFields,
		durationKey:   durationKey,
		badgeKey:      badgeKey,
		tokenKey:      tokenKey,
		statusKey:     statusKey,
		nodes:         make(map[string]*TreeNode),
		maxDurationUs: 1000.0,
	}
}

func getBadgeCategory(badge, label string, event map[string]interface{}) string {
	b := strings.ToLower(badge)
	l := strings.ToLower(label)
	comm := ""
	if v, ok := event["comm"]; ok && v != nil {
		comm = strings.ToLower(fmt.Sprint(v))
	}
	method := ""
	if v, ok := event["method"]; ok && v != nil {
		method = strings.ToLower(fmt.Sprint(v))
	}

	if strings.Contains(b, "agent") || strings.Contains(l, "invoke_agent") || strings.Contains(comm, "agent") {
		return "agent"
	}
	if strings.Contains(b, "llm") || strings.Contains(l, "chat") || strings.Contains(comm, "openai") || strings.Contains(comm, "claude") {
		return "llm"
	}
	if strings.Contains(b, "tool") || strings.Contains(l, "tool") || strings.Contains(l, "fetch_") {
		return "tool"
	}
	if strings.Contains(method, "get") || strings.Contains(method, "post") || strings.Contains(b, "http") || strings.Contains(comm, "http") || strings.Contains(comm, "nginx") || strings.Contains(comm, "php") {
		return "http"
	}
	if strings.Contains(b, "sql") || strings.Contains(comm, "mysql") || strings.Contains(comm, "postgres") || strings.Contains(comm, "redis") {
		return "db"
	}
	return "other"
}

// Update inserts or connects an event into the trace tree structure
func (t *TraceTree) Update(event map[string]interface{}) {
	if event == nil {
		return
	}

	rawID, hasID := event[t.nodeIDKey]
	if !hasID {
		rawID = event["req_id"]
		if rawID == nil {
			rawID = event["pid"]
		}
	}
	idStr := fmt.Sprint(rawID)
	if idStr == "" || idStr == "<nil>" {
		return
	}

	parentIDStr := ""
	if rawParent, hasParent := event[t.parentIDKey]; hasParent {
		parentIDStr = fmt.Sprint(rawParent)
		if parentIDStr == "<nil>" {
			parentIDStr = ""
		}
	} else if rawParent := event["parent_req_id"]; rawParent != nil {
		parentIDStr = fmt.Sprint(rawParent)
	} else if rawParent := event["ppid"]; rawParent != nil {
		parentIDStr = fmt.Sprint(rawParent)
	}

	// Build node label
	var labelParts []string
	if len(t.labelFields) > 0 {
		for _, f := range t.labelFields {
			if v, ok := event[f]; ok && v != nil {
				part := fmt.Sprint(v)
				cleanPart := sanitizeString(part)
				labelParts = append(labelParts, cleanPart)
			}
		}
	}
	labelStr := strings.Join(labelParts, " ")
	if labelStr == "" {
		if path, ok := event["path"]; ok && path != nil {
			labelStr = sanitizeString(fmt.Sprint(path))
		} else if query, ok := event["query"]; ok && query != nil {
			labelStr = sanitizeString(fmt.Sprint(query))
		} else if comm, ok := event["comm"]; ok && comm != nil {
			labelStr = sanitizeString(fmt.Sprint(comm))
		} else {
			labelStr = fmt.Sprintf("Node-%s", idStr)
		}
	}

	// Determine Badge
	badgeStr := "Other"
	if t.badgeKey != "" && event[t.badgeKey] != nil {
		badgeStr = sanitizeString(fmt.Sprint(event[t.badgeKey]))
	} else if event["method"] != nil {
		badgeStr = sanitizeString(fmt.Sprint(event["method"]))
	} else if event["comm"] != nil {
		badgeStr = sanitizeString(fmt.Sprint(event["comm"]))
	} else if event["container_id"] != nil {
		badgeStr = "Docker"
	}
	badgeCat := getBadgeCategory(badgeStr, labelStr, event)

	// Determine Duration & Latency
	durationStr := ""
	var durUs float64
	if t.durationKey != "" && event[t.durationKey] != nil {
		durUs, _ = strconv.ParseFloat(fmt.Sprint(event[t.durationKey]), 64)
	} else if event["duration_us"] != nil {
		durUs, _ = strconv.ParseFloat(fmt.Sprint(event["duration_us"]), 64)
	} else if event["latency_ms"] != nil {
		ms, _ := strconv.ParseFloat(fmt.Sprint(event["latency_ms"]), 64)
		durUs = ms * 1000.0
	}

	if durUs > 0 {
		if durUs >= 1000.0 {
			durationStr = fmt.Sprintf("%.2fms", durUs/1000.0)
		} else {
			durationStr = fmt.Sprintf("%.0fµs", durUs)
		}
	}

	// Determine Tokens / Byte counts
	tokenStr := ""
	if t.tokenKey != "" && event[t.tokenKey] != nil {
		tokenStr = fmt.Sprint(event[t.tokenKey])
	} else if event["tokens"] != nil {
		tokenStr = fmt.Sprint(event["tokens"])
	} else if rx := event["rx_bytes"]; rx != nil {
		if rxN, err := strconv.Atoi(fmt.Sprint(rx)); err == nil && rxN > 0 {
			tokenStr = fmt.Sprintf("%d B", rxN)
		}
	}

	// Determine Status & Warning
	statusCode := 0
	if event[t.statusKey] != nil {
		statusCode, _ = strconv.Atoi(fmt.Sprint(event[t.statusKey]))
	} else if event["status_code"] != nil {
		statusCode, _ = strconv.Atoi(fmt.Sprint(event["status_code"]))
	}
	hasWarning := durUs > 50000.0 || (statusCode >= 400)

	// Extract Host / Domain / IP if available
	hostStr := ""
	if h, ok := event["host"]; ok && h != nil && fmt.Sprint(h) != "" {
		hostStr = sanitizeString(fmt.Sprint(h))
	} else if dIP, ok := event["d_ip"]; ok && dIP != nil && fmt.Sprint(dIP) != "" {
		hostStr = sanitizeString(fmt.Sprint(dIP))
	} else if sIP, ok := event["s_ip"]; ok && sIP != nil && fmt.Sprint(sIP) != "" {
		hostStr = sanitizeString(fmt.Sprint(sIP))
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if durUs > t.maxDurationUs {
		t.maxDurationUs = durUs
	}

	node, exists := t.nodes[idStr]
	if !exists {
		node = &TreeNode{
			ID:       idStr,
			Expanded: true,
		}
		t.nodes[idStr] = node
	}

	node.ParentID = parentIDStr
	node.Label = labelStr
	node.Badge = badgeStr
	node.BadgeCategory = badgeCat
	node.Duration = durationStr
	node.DurationUs = durUs
	node.Tokens = tokenStr
	node.StatusCode = statusCode
	node.HasWarning = hasWarning
	node.RawEvent = event

	// Extract Proto & Server Version & Payloads
	protoStr := ""
	if p, ok := event["proto"]; ok && p != nil && fmt.Sprint(p) != "" {
		protoStr = fmt.Sprint(p)
	} else if p, ok := event["protocol"]; ok && p != nil && fmt.Sprint(p) != "" {
		protoStr = fmt.Sprint(p)
	}
	serverVerStr := ""
	if s, ok := event["server_version"]; ok && s != nil && fmt.Sprint(s) != "" {
		serverVerStr = fmt.Sprint(s)
	} else if s, ok := event["version"]; ok && s != nil && fmt.Sprint(s) != "" {
		serverVerStr = fmt.Sprint(s)
	}
	reqPayloadStr := ""
	if rp, ok := event["req_payload"]; ok && rp != nil && fmt.Sprint(rp) != "" {
		reqPayloadStr = fmt.Sprint(rp)
	} else if rp, ok := event["query"]; ok && rp != nil && fmt.Sprint(rp) != "" {
		reqPayloadStr = fmt.Sprint(rp)
	} else if rp, ok := event["command"]; ok && rp != nil && fmt.Sprint(rp) != "" {
		reqPayloadStr = fmt.Sprint(rp)
	} else if rp, ok := event["args"]; ok && rp != nil && fmt.Sprint(rp) != "" {
		reqPayloadStr = fmt.Sprint(rp)
	}
	respPayloadStr := ""
	if rp, ok := event["resp_payload"]; ok && rp != nil && fmt.Sprint(rp) != "" {
		respPayloadStr = fmt.Sprint(rp)
	} else if rp, ok := event["response"]; ok && rp != nil && fmt.Sprint(rp) != "" {
		respPayloadStr = fmt.Sprint(rp)
	} else if rp, ok := event["result"]; ok && rp != nil && fmt.Sprint(rp) != "" {
		respPayloadStr = fmt.Sprint(rp)
	} else if rp, ok := event["error_msg"]; ok && rp != nil && fmt.Sprint(rp) != "" {
		respPayloadStr = fmt.Sprint(rp)
	}

	node.Proto = protoStr
	node.ServerVersion = serverVerStr
	node.ReqPayload = reqPayloadStr
	node.RespPayload = respPayloadStr

	// Resolve Parent Node
	var parent *TreeNode
	if parentIDStr != "" && parentIDStr != idStr && parentIDStr != "0" {
		if p, ok := t.nodes[parentIDStr]; ok {
			parent = p
		}
	}

	// If no parent span was found, but we have a Host / IP, group under that Virtual Host
	if parent == nil && hostStr != "" {
		hostKey := fmt.Sprintf("host:%s", hostStr)
		hNode, hExists := t.nodes[hostKey]
		if !hExists {
			hNode = &TreeNode{
				ID:            hostKey,
				Label:         fmt.Sprintf("%s (1 request)", hostStr),
				Badge:         "Host",
				BadgeCategory: "http",
				Expanded:      true,
			}
			t.nodes[hostKey] = hNode
		}
		parent = hNode
		node.ParentID = hostKey
	} else if parent == nil && parentIDStr != "" && parentIDStr != idStr && parentIDStr != "0" {
		// Pure process hierarchy (e.g. sec/exec-audit, perf/stall-tracer): create enriched process placeholder
		parentLabel := fmt.Sprintf("PID %s", parentIDStr)
		parentBadge := "Process"
		parentBadgeCat := "other"

		var commStr, cidStr string
		if c, ok := event["comm"]; ok && c != nil && fmt.Sprint(c) != "" {
			commStr = fmt.Sprint(c)
		}
		if cid, ok := event["container_id"]; ok && cid != nil && fmt.Sprint(cid) != "" {
			cidStr = fmt.Sprint(cid)
		}

		if commStr != "" {
			parentLabel = fmt.Sprintf("%s (PID %s)", commStr, parentIDStr)
		}
		if cidStr != "" {
			parentBadge = cidStr
			parentBadgeCat = "docker"
		}

		placeholder := &TreeNode{
			ID:            parentIDStr,
			Label:         parentLabel,
			Badge:         parentBadge,
			BadgeCategory: parentBadgeCat,
			Expanded:      true,
		}
		t.nodes[parentIDStr] = placeholder
		parent = placeholder
	}

	// If parent already exists as a bare placeholder, enrich it with child metadata if available
	if parent != nil && strings.HasPrefix(parent.Label, "PID ") {
		if c, ok := event["comm"]; ok && c != nil && fmt.Sprint(c) != "" {
			parent.Label = fmt.Sprintf("%s (%s)", fmt.Sprint(c), parent.Label)
		}
		if cid, ok := event["container_id"]; ok && cid != nil && fmt.Sprint(cid) != "" {
			parent.Badge = fmt.Sprint(cid)
			parent.BadgeCategory = "docker"
		}
	}

	// Attach node to parent
	if parent != nil && parent.ID != idStr {
		alreadyChild := false
		for _, child := range parent.Children {
			if child.ID == idStr {
				alreadyChild = true
				break
			}
		}
		if !alreadyChild {
			parent.Children = append(parent.Children, node)
			// If parent is a Host, dynamically update its request count and average duration
			if strings.HasPrefix(parent.ID, "host:") {
				hostName := strings.TrimPrefix(parent.ID, "host:")
				totalDur := 0.0
				for _, c := range parent.Children {
					totalDur += c.DurationUs
				}
				avgDurMs := 0.0
				if len(parent.Children) > 0 {
					avgDurMs = (totalDur / float64(len(parent.Children))) / 1000.0
				}
				parent.Label = fmt.Sprintf("%s (%d requests)", hostName, len(parent.Children))
				if avgDurMs >= 1.0 {
					parent.Duration = fmt.Sprintf("%.1fms avg", avgDurMs)
				} else if avgDurMs > 0 {
					parent.Duration = fmt.Sprintf("%.0fµs avg", avgDurMs*1000.0)
				}
			}
		}
	}

	t.rebuildRoots()
}

func (t *TraceTree) rebuildRoots() {
	var newRoots []*TreeNode
	for _, n := range t.nodes {
		if n.ParentID == "" || n.ParentID == "0" || n.ParentID == n.ID {
			newRoots = append(newRoots, n)
		} else {
			if _, pExists := t.nodes[n.ParentID]; !pExists {
				newRoots = append(newRoots, n)
			}
		}
	}
	t.roots = newRoots
	t.rebuildFlattened()
}

func (t *TraceTree) rebuildFlattened() {
	var list []*TreeNode
	for i, root := range t.roots {
		isLast := i == len(t.roots)-1
		t.flattenNode(root, 0, isLast, &list)
	}
	t.flattenedList = list
	if t.cursorIdx >= len(t.flattenedList) {
		t.cursorIdx = len(t.flattenedList) - 1
	}
	if t.cursorIdx < 0 && len(t.flattenedList) > 0 {
		t.cursorIdx = 0
	}
}

func (t *TraceTree) flattenNode(n *TreeNode, depth int, isLast bool, list *[]*TreeNode) {
	n.Depth = depth
	n.IsLast = isLast
	*list = append(*list, n)

	if n.Expanded {
		for i, child := range n.Children {
			cIsLast := i == len(n.Children)-1
			t.flattenNode(child, depth+1, cIsLast, list)
		}
	}
}

// MoveUp navigates the cursor selection up
func (t *TraceTree) MoveUp() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.cursorIdx > 0 {
		t.cursorIdx--
	}
}

// MoveDown navigates the cursor selection down
func (t *TraceTree) MoveDown() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.cursorIdx < len(t.flattenedList)-1 {
		t.cursorIdx++
	}
}

// ToggleExpand expands or collapses the currently selected tree node
func (t *TraceTree) ToggleExpand() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.cursorIdx >= 0 && t.cursorIdx < len(t.flattenedList) {
		node := t.flattenedList[t.cursorIdx]
		node.Expanded = !node.Expanded
		t.rebuildFlattened()
	}
}

// ToggleAll toggles between expanding all nodes and collapsing all nodes (Option A)
func (t *TraceTree) ToggleAll() {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.allCollapsed = !t.allCollapsed
	targetState := !t.allCollapsed

	for _, n := range t.nodes {
		n.Expanded = targetState
	}
	t.rebuildFlattened()
}

// GetSelected returns the currently selected node
func (t *TraceTree) GetSelected() *TreeNode {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.cursorIdx >= 0 && t.cursorIdx < len(t.flattenedList) {
		return t.flattenedList[t.cursorIdx]
	}
	return nil
}

func renderBadge(badge, cat string) string {
	b := fmt.Sprintf("[%s]", badge)
	switch cat {
	case "agent":
		return badgeAgentStyle.Render(b)
	case "llm":
		return badgeLLMStyle.Render(b)
	case "tool":
		return badgeToolStyle.Render(b)
	case "http":
		return badgeHTTPStyle.Render(b)
	case "db":
		return badgeDBStyle.Render(b)
	default:
		return badgeOtherStyle.Render(b)
	}
}

func renderMiniWaterfall(durUs, maxUs float64, hasWarning bool, durStr string) string {
	const barWidth = 8
	if maxUs <= 0 {
		maxUs = 1.0
	}
	fill := int((durUs / maxUs) * float64(barWidth))
	if fill < 1 && durUs > 0 {
		fill = 1
	}
	if fill > barWidth {
		fill = barWidth
	}
	empty := barWidth - fill

	fillChars := strings.Repeat("█", fill)
	emptyChars := strings.Repeat("░", empty)

	var coloredFill string
	if hasWarning || durUs > 200000.0 {
		coloredFill = barSlowStyle.Render(fillChars)
	} else if durUs > 50000.0 {
		coloredFill = barMedStyle.Render(fillChars)
	} else {
		coloredFill = barFastStyle.Render(fillChars)
	}
	coloredEmpty := dimBarStyle.Render(emptyChars)

	warnIcon := "  "
	if hasWarning {
		warnIcon = warningStyle.Render("⚠️")
	}

	return fmt.Sprintf("[%s%s] %s %-7s", coloredFill, coloredEmpty, warnIcon, durStr)
}

// Render formats the hierarchical tree with connectors, category badges, and Unicode mini-waterfall
func (t *TraceTree) Render(width, height int) string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if len(t.flattenedList) == 0 {
		return " No process or span execution tree nodes detected."
	}

	if width <= 0 {
		width = 80
	}
	if height <= 0 {
		height = 20
	}

	// Calculate Visible Scrolling Window to prevent viewport overflow
	totalItems := len(t.flattenedList)
	windowSize := height
	if windowSize > totalItems {
		windowSize = totalItems
	}

	startIdx := 0
	if t.cursorIdx >= windowSize {
		startIdx = t.cursorIdx - windowSize + 1
	}
	endIdx := startIdx + windowSize
	if endIdx > totalItems {
		endIdx = totalItems
		startIdx = endIdx - windowSize
		if startIdx < 0 {
			startIdx = 0
		}
	}

	var lines []string

	for i := startIdx; i < endIdx; i++ {
		n := t.flattenedList[i]

		prefix := ""
		if n.Depth > 0 {
			indent := strings.Repeat("│   ", n.Depth-1)
			connector := "├── "
			if n.IsLast {
				connector = "└── "
			}
			prefix = indent + connector
		}

		expandIcon := "  "
		if len(n.Children) > 0 {
			if n.Expanded {
				expandIcon = "▼ "
			} else {
				expandIcon = "▶ "
			}
		}

		cursor := " "
		if i == t.cursorIdx {
			cursor = "❯"
		}

		badgeFormatted := ""
		if n.Badge != "" {
			badgeFormatted = renderBadge(n.Badge, n.BadgeCategory) + " "
		}

		tokenFormatted := ""
		if n.Tokens != "" {
			tokenFormatted = " " + tokenChipStyle.Render("⚯ "+n.Tokens)
		}

		leftPart := fmt.Sprintf("%s %s%s%s%s%s", cursor, prefix, expandIcon, badgeFormatted, n.Label, tokenFormatted)

		// If width is generous (>= 50 chars), render the synchronized right-aligned mini-waterfall
		if width >= 50 && n.Duration != "" {
			waterfallFormatted := renderMiniWaterfall(n.DurationUs, t.maxDurationUs, n.HasWarning, n.Duration)
			wfWidth := lipgloss.Width(waterfallFormatted)
			
			availLeft := width - wfWidth - 2
			if availLeft < 10 {
				availLeft = 10
			}
			leftPartTrunc := ansi.Truncate(leftPart, availLeft, "...")
			leftW := lipgloss.Width(leftPartTrunc)

			pad := width - leftW - wfWidth
			if pad < 1 {
				pad = 1
			}
			line := leftPartTrunc + strings.Repeat(" ", pad) + waterfallFormatted
			line = ansi.Truncate(line, width, "")
			lines = append(lines, line)
		} else {
			durSuffix := ""
			if n.Duration != "" {
				durSuffix = " [" + n.Duration + "]"
			}
			line := leftPart + durSuffix
			line = ansi.Truncate(line, width, "...")
			lines = append(lines, line)
		}
	}

	return strings.Join(lines, "\n")
}
