package telemetry

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"

	"eprobe/pkg/registry"
)

func TestGoString(t *testing.T) {
	tests := []struct {
		input    []byte
		expected string
	}{
		{[]byte("hello\x00world"), "hello"},
		{[]byte("test\x00\x00\x00"), "test"},
		{[]byte{0}, ""},
		{[]byte("no-null"), "no-null"},
	}

	for _, tc := range tests {
		got := GoString(tc.input)
		if got != tc.expected {
			t.Errorf("GoString(%q) = %q; expected %q", tc.input, got, tc.expected)
		}
	}
}

func TestDecodeDynamicEvent(t *testing.T) {
	// Let's mock a FieldSchema
	schema := []registry.FieldSchema{
		{Name: "val_u8", Type: "uint8"},
		{Name: "val_u16", Type: "uint16"},
		{Name: "val_u32", Type: "uint32"},
		{Name: "val_u64", Type: "uint64"},
		{Name: "val_str", Type: "string", Length: 12},
		{Name: "val_ipv4", Type: "ipv4"},
	}

	// Calculate size: 1 + 2 + 4 + 8 + 12 + 4 = 31 bytes
	raw := make([]byte, 31)
	raw[0] = 42                                           // uint8
	binary.LittleEndian.PutUint16(raw[1:3], 12345)        // uint16
	binary.LittleEndian.PutUint32(raw[3:7], 987654321)    // uint32
	binary.LittleEndian.PutUint64(raw[7:15], 98765432100) // uint64
	copy(raw[15:27], []byte("hello-world\x00"))           // string (12 bytes)
	copy(raw[27:31], []byte{10, 0, 0, 1})                 // ipv4 (10.0.0.1)

	event, err := DecodeDynamicEvent(raw, schema)
	if err != nil {
		t.Fatalf("failed to decode dynamic event: %v", err)
	}

	if event["val_u8"] != uint8(42) {
		t.Errorf("expected val_u8 42, got %v", event["val_u8"])
	}
	if event["val_u16"] != uint16(12345) {
		t.Errorf("expected val_u16 12345, got %v", event["val_u16"])
	}
	if event["val_u32"] != uint32(987654321) {
		t.Errorf("expected val_u32 987654321, got %v", event["val_u32"])
	}
	if event["val_u64"] != uint64(98765432100) {
		t.Errorf("expected val_u64 98765432100, got %v", event["val_u64"])
	}
	if event["val_str"] != "hello-world" {
		t.Errorf("expected val_str 'hello-world', got %v", event["val_str"])
	}
	if event["val_ipv4"] != "10.0.0.1" {
		t.Errorf("expected val_ipv4 '10.0.0.1', got %v", event["val_ipv4"])
	}
}

func TestDecodeDynamicEventIPv4NetworkByteOrder(t *testing.T) {
	// Test that IPv4 addresses use raw byte order (network byte order) via net.IP
	schema := []registry.FieldSchema{
		{Name: "addr", Type: "ipv4"},
	}
	raw := net.ParseIP("192.168.1.1").To4()
	event, err := DecodeDynamicEvent(raw, schema)
	if err != nil {
		t.Fatalf("failed to decode: %v", err)
	}
	if event["addr"] != "192.168.1.1" {
		t.Errorf("expected '192.168.1.1', got %v", event["addr"])
	}
}

func TestMatchesPortFilter(t *testing.T) {
	schema := []registry.FieldSchema{
		{Name: "pid", Type: "uint32"},
		{Name: "sport", Type: "uint16", Format: "port"},
		{Name: "dport", Type: "uint16", Format: "port"},
		{Name: "comm", Type: "string", Length: 16},
	}

	event := map[string]interface{}{
		"pid":   uint32(1234),
		"sport": uint16(8080),
		"dport": uint16(443),
		"comm":  "curl",
	}

	// Match on source port
	if !MatchesPortFilter(event, schema, 8080) {
		t.Error("expected port filter 8080 to match sport")
	}

	// Match on destination port
	if !MatchesPortFilter(event, schema, 443) {
		t.Error("expected port filter 443 to match dport")
	}

	// No match
	if MatchesPortFilter(event, schema, 9999) {
		t.Error("expected port filter 9999 not to match")
	}

	// Port filter by name heuristic
	schemaByName := []registry.FieldSchema{
		{Name: "src_port", Type: "uint16"},
	}
	eventByName := map[string]interface{}{
		"src_port": uint16(80),
	}
	if !MatchesPortFilter(eventByName, schemaByName, 80) {
		t.Error("expected name-based port filter to match src_port")
	}
}

func TestMatchesFilters(t *testing.T) {
	schema := []registry.FieldSchema{
		{Name: "pid", Type: "uint32"},
		{Name: "dport", Type: "uint16", Format: "port"},
		{Name: "comm", Type: "string", Length: 16},
		{Name: "host", Type: "string", Length: 64},
		{Name: "status_code", Type: "uint16"},
	}

	event := map[string]interface{}{
		"pid":         uint32(100),
		"dport":       uint16(443),
		"comm":        "python3",
		"host":        "api.stripe.com",
		"status_code": uint16(200),
	}

	// 1. Comm filter
	if !MatchesFilters(event, schema, FilterConfig{FilterComm: "python"}) {
		t.Error("expected python filter to match python3")
	}
	if MatchesFilters(event, schema, FilterConfig{FilterComm: "node"}) {
		t.Error("expected node filter not to match python3")
	}

	// 2. Host filter
	if !MatchesFilters(event, schema, FilterConfig{FilterHost: "stripe.com"}) {
		t.Error("expected stripe.com filter to match api.stripe.com")
	}
	if MatchesFilters(event, schema, FilterConfig{FilterHost: "openai.com"}) {
		t.Error("expected openai.com filter not to match api.stripe.com")
	}

	// 3. Errors only filter
	if MatchesFilters(event, schema, FilterConfig{FilterErrors: true}) {
		t.Error("expected status 200 to be filtered out when FilterErrors is true")
	}
	errorEvent := map[string]interface{}{
		"status_code": uint16(500),
	}
	if !MatchesFilters(errorEvent, schema, FilterConfig{FilterErrors: true}) {
		t.Error("expected status 500 to match when FilterErrors is true")
	}
}

func TestSanitizeEvent(t *testing.T) {
	event := map[string]interface{}{
		"req_payload":  "POST /v1/chat HTTP/1.1\r\nAuthorization: Bearer sk-1234567890abcdef\r\n\r\n{\"key\":\"sk_live_987654321\"}",
		"resp_payload": "HTTP/1.1 200 OK\r\n\r\n{\"result\":\"ok\"}",
	}

	SanitizeEvent(event)

	reqPayload := event["req_payload"].(string)
	if strings.Contains(reqPayload, "sk-1234567890abcdef") {
		t.Errorf("expected Bearer token to be masked, got %s", reqPayload)
	}
	if !strings.Contains(reqPayload, "Bearer **********") {
		t.Errorf("expected Bearer ********** in masked payload, got %s", reqPayload)
	}
	if strings.Contains(reqPayload, "sk_live_987654321") {
		t.Errorf("expected sk_live key to be masked, got %s", reqPayload)
	}
}

