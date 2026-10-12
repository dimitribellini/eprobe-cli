package registry

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Manifest represents the structure of manifest.yaml
type Manifest struct {
	Name         string        `json:"name"`
	Version      string        `json:"version"`
	Author       string        `json:"author"`
	SHA256       string        `json:"sha256"`
	Description  string        `json:"description"`
	AttachPoints []AttachPoint `json:"attach_points"`
	Maps         []MapSpec     `json:"maps"`
	Variables    []Variable    `json:"variables"`
	TUIHints     TUIHints      `json:"tui_hints"`
	RawContent   string        `json:"-"`
}

type AttachPoint struct {
	Type    string `json:"type"`
	Symbol  string `json:"symbol"`
	Section string `json:"section"`
}

type MapSpec struct {
	Name        string        `json:"name"`
	Type        string        `json:"type"`
	EventStruct string        `json:"event_struct"`
	EventSchema []FieldSchema `json:"event_schema"`
	KeyStruct   string        `json:"key_struct,omitempty"`
	KeySchema   []FieldSchema `json:"key_schema,omitempty"`
	ValueStruct string        `json:"value_struct,omitempty"`
	ValueSchema []FieldSchema `json:"value_schema,omitempty"`
}

type FieldSchema struct {
	Name   string `json:"name"`
	Type   string `json:"type"` // uint8|uint16|uint32|uint64|string|ipv4|ipv6
	Length int    `json:"length,omitempty"`
	Format string `json:"format,omitempty"` // port|ip|hex
}

type Variable struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	CLIFlag     string `json:"cli_flag"`
	Description string `json:"description"`
}

type TUIPosition struct {
	Row    int    `json:"row"`
	Col    int    `json:"col"`
	Width  string `json:"width"`
	Height string `json:"height"`
}

type TUIPane struct {
	Name             string          `json:"name"`
	Type             string          `json:"type"`
	MapName          string          `json:"map_name"`
	Position         TUIPosition     `json:"position"`
	Summary          string          `json:"summary,omitempty"`
	InspectPayload   string          `json:"inspect_payload,omitempty"`
	SearchableFields []string        `json:"searchable_fields,omitempty"`
	Columns          []ColumnHint    `json:"columns,omitempty"`
	AggregateBy      []AggregateHint `json:"aggregate_by,omitempty"`

	// Histogram configuration
	HistogramField string    `json:"histogram_field,omitempty"`
	Buckets        []float64 `json:"buckets,omitempty"`
	Unit           string    `json:"unit,omitempty"`

	// Sparkline configuration
	MetricField   string `json:"metric_field,omitempty"`
	TimeWindowSec int    `json:"time_window_sec,omitempty"`
	Aggregation   string `json:"aggregation,omitempty"` // rate|avg|max|sum

	// Trace Tree configuration
	NodeID        string   `json:"node_id,omitempty"`
	ParentID      string   `json:"parent_id,omitempty"`
	LabelFields   []string `json:"label_fields,omitempty"`
	BadgeField    string   `json:"badge_field,omitempty"`
	TokenField    string   `json:"token_field,omitempty"`
	StatusField   string   `json:"status_field,omitempty"`
	Views         []string `json:"views,omitempty"`
	DurationField string   `json:"duration_field,omitempty"`

	// Universal Metadata & Payload configuration
	VersionField        string `json:"version_field,omitempty"`
	ProtoField          string `json:"proto_field,omitempty"`
	RequestPayloadField string `json:"request_payload_field,omitempty"`
	ResponsePayloadField string `json:"response_payload_field,omitempty"`
}

type TUIPage struct {
	Name   string    `json:"name"`
	Layout string    `json:"layout,omitempty"`
	Panes  []TUIPane `json:"panes"`
}

type TUIHints struct {
	// v4.0 Multi-Page layout
	Pages []TUIPage `json:"pages,omitempty"`

	// Legacy v3.0 Multi-Sector layout
	Layout string    `json:"layout,omitempty"`
	Panes  []TUIPane `json:"panes,omitempty"`

	// Legacy v2.0 support
	DefaultView    string          `json:"default_view,omitempty"`
	SupportedViews []string        `json:"supported_views,omitempty"` // e.g., ["stream", "top"]
	Summary        string          `json:"summary,omitempty"`         // Module-specific help text
	InspectPayload string          `json:"inspect_payload,omitempty"` // Field name for detail view
	SearchableFields []string      `json:"searchable_fields,omitempty"`
	Columns        []ColumnHint    `json:"columns,omitempty"`
	AggregateBy    []AggregateHint `json:"aggregate_by,omitempty"`
}

type ColumnHint struct {
	Field  string `json:"field"`
	Label  string `json:"label,omitempty"`
	Width  int    `json:"width"`
	Format string `json:"format,omitempty"`
	Bold   bool   `json:"bold"`
	Color  string `json:"color,omitempty"`
}

type AggregateHint struct {
	Field      string `json:"field"`
	Label      string `json:"label"`
	Type       string `json:"type"`
	ValueField string `json:"value_field,omitempty"`
}

// yamlNode is an internal node representation for indent-based YAML parsing
type yamlNode struct {
	key      string
	value    string
	isList   bool
	children []*yamlNode
}

func parseScalar(val string) interface{} {
	val = strings.TrimSpace(val)

	// Handle inline YAML arrays like [a, b, c]
	if strings.HasPrefix(val, "[") && strings.HasSuffix(val, "]") {
		inner := val[1 : len(val)-1]
		var list []interface{}
		if strings.TrimSpace(inner) == "" {
			return list
		}
		parts := strings.Split(inner, ",")
		for _, p := range parts {
			cleanP := strings.TrimSpace(p)
			// Strip quotes if present on inline array items
			if len(cleanP) >= 2 && ((cleanP[0] == '"' && cleanP[len(cleanP)-1] == '"') || (cleanP[0] == '\'' && cleanP[len(cleanP)-1] == '\'')) {
				cleanP = cleanP[1 : len(cleanP)-1]
			}
			list = append(list, parseScalar(cleanP))
		}
		return list
	}

	if val == "true" {
		return true
	}
	if val == "false" {
		return false
	}
	if num, err := strconv.Atoi(val); err == nil {
		return num
	}
	return val
}

func (n *yamlNode) toValue() interface{} {
	if len(n.children) == 0 {
		return parseScalar(n.value)
	}

	if n.children[0].isList {
		var list []interface{}
		for _, c := range n.children {
			if c.key != "" {
				// List of maps: the children of c are sibling keys of the map
				m := make(map[string]interface{})
				m[c.key] = parseScalar(c.value)
				for _, gc := range c.children {
					m[gc.key] = gc.toValue()
				}
				list = append(list, m)
			} else {
				// List of scalars: items like "- simple_value" with no key.
				// NOTE: This only handles simple scalar values. Nested structures
				// under keyless list items are not supported by this parser.
				list = append(list, c.toValue())
			}
		}
		return list
	}

	m := make(map[string]interface{})
	for _, c := range n.children {
		m[c.key] = c.toValue()
	}
	return m
}

// UnmarshalYAML parses YAML bytes using an indent-based strategy and unmarshals it into v.
func UnmarshalYAML(data []byte, v interface{}) error {
	lines := strings.Split(string(data), "\n")
	root := &yamlNode{key: "root"}
	stack := []*yamlNode{root}
	indents := []int{-1}

	for _, line := range lines {
		// Truncate comments
		inQuote := false
		quoteChar := rune(0)
		commentIdx := -1
		for i, r := range line {
			if (r == '"' || r == '\'') && (i == 0 || line[i-1] != '\\') {
				if !inQuote {
					inQuote = true
					quoteChar = r
				} else if r == quoteChar {
					inQuote = false
				}
			}
			if r == '#' && !inQuote {
				commentIdx = i
				break
			}
		}
		if commentIdx >= 0 {
			line = line[:commentIdx]
		}

		trimmed := strings.TrimRight(line, " \t\r")
		if trimmed == "" {
			continue
		}

		indent := 0
		for _, r := range trimmed {
			if r == ' ' {
				indent++
			} else if r == '\t' {
				indent += 4
			} else {
				break
			}
		}

		content := strings.TrimSpace(trimmed)
		if content == "" {
			continue
		}

		isList := false
		if strings.HasPrefix(content, "-") {
			isList = true
			content = strings.TrimSpace(strings.TrimPrefix(content, "-"))
		}

		var key, val string
		// Find the first ": " (colon-space) or ":" at end-of-line to correctly handle
		// values containing colons (e.g., URLs like http://host:port/path).
		colonSpaceIdx := strings.Index(content, ": ")
		colonTabIdx := strings.Index(content, ":\t")
		colonEOL := len(content) > 0 && content[len(content)-1] == ':'

		colonIdx := -1
		if colonSpaceIdx >= 0 {
			colonIdx = colonSpaceIdx
		}
		if colonTabIdx >= 0 && (colonIdx < 0 || colonTabIdx < colonIdx) {
			colonIdx = colonTabIdx
		}
		if colonIdx < 0 && colonEOL {
			colonIdx = len(content) - 1
		}

		if colonIdx >= 0 {
			key = strings.TrimSpace(content[:colonIdx])
			val = strings.TrimSpace(content[colonIdx+1:])
		} else {
			val = content
		}

		if len(key) >= 2 && ((key[0] == '"' && key[len(key)-1] == '"') || (key[0] == '\'' && key[len(key)-1] == '\'')) {
			key = key[1 : len(key)-1]
		}
		if len(val) >= 2 && ((val[0] == '"' && val[len(val)-1] == '"') || (val[0] == '\'' && val[len(val)-1] == '\'')) {
			val = val[1 : len(val)-1]
		}

		node := &yamlNode{
			key:    key,
			value:  val,
			isList: isList,
		}

		for len(stack) > 1 && indents[len(indents)-1] >= indent {
			stack = stack[:len(stack)-1]
			indents = indents[:len(indents)-1]
		}

		parent := stack[len(stack)-1]
		parent.children = append(parent.children, node)

		stack = append(stack, node)
		indents = append(indents, indent)
	}

	rootMap := make(map[string]interface{})
	for _, c := range root.children {
		rootMap[c.key] = c.toValue()
	}

	jsonBytes, err := json.Marshal(rootMap)
	if err != nil {
		return fmt.Errorf("failed to marshal parsed YAML tree to JSON: %w", err)
	}

	return json.Unmarshal(jsonBytes, v)
}

// ParseManifest reads manifest bytes and populates a Manifest struct
func ParseManifest(data []byte) (*Manifest, error) {
	var m Manifest
	err := UnmarshalYAML(data, &m)
	if err != nil {
		return nil, err
	}
	m.RawContent = string(data)
	m.NormalizeLegacyManifest()
	return &m, nil
}

// NormalizeLegacyManifest converts a v2.0 manifest into a v3.0 single-pane layout.
func (m *Manifest) NormalizeLegacyManifest() {
	if len(m.TUIHints.Panes) == 0 && len(m.TUIHints.Columns) > 0 {
		paneType := m.TUIHints.DefaultView
		if paneType == "" {
			paneType = "stream"
		}
		pane := TUIPane{
			Name:           "main",
			Type:           paneType,
			Position:       TUIPosition{Row: 0, Col: 0, Width: "100%", Height: "100%"},
			Summary:        m.TUIHints.Summary,
			InspectPayload: m.TUIHints.InspectPayload,
			SearchableFields: m.TUIHints.SearchableFields,
			Columns:        m.TUIHints.Columns,
			AggregateBy:    m.TUIHints.AggregateBy,
		}
		if mapSpec := m.GetRingBufMap(); mapSpec != nil {
			pane.MapName = mapSpec.Name
		}
		m.TUIHints.Panes = []TUIPane{pane}
		m.TUIHints.Layout = "grid"
	}

	// Normalize v3.0 -> v4.0
	if len(m.TUIHints.Pages) == 0 && len(m.TUIHints.Panes) > 0 {
		pageName := "Overview"
		if m.Name != "" {
			parts := strings.Split(m.Name, "/")
			pageName = strings.ToUpper(parts[len(parts)-1])
		}
		m.TUIHints.Pages = []TUIPage{
			{
				Name:   pageName,
				Layout: m.TUIHints.Layout,
				Panes:  m.TUIHints.Panes,
			},
		}
	}
}

// GetRingBufMap returns the first ring buffer map specification from the manifest,
// falling back to the first map if no explicit ringbuf type is found.
// Returns nil if no maps are defined.
func (m *Manifest) GetRingBufMap() *MapSpec {
	for i, mSpec := range m.Maps {
		if mSpec.Type == "ringbuf" {
			return &m.Maps[i]
		}
	}
	if len(m.Maps) > 0 {
		return &m.Maps[0]
	}
	return nil
}

// GetMapByName returns the map specification with the given name.
func (m *Manifest) GetMapByName(name string) *MapSpec {
	for i, mSpec := range m.Maps {
		if mSpec.Name == name {
			return &m.Maps[i]
		}
	}
	return nil
}
