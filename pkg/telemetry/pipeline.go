package telemetry

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"

	"eprobe/pkg/registry"
)

// DecodeDynamicEvent decodes a raw byte slice into a generic map according to the FieldSchema.
func DecodeDynamicEvent(raw []byte, schema []registry.FieldSchema) (map[string]interface{}, error) {
	event := make(map[string]interface{})
	offset := 0
	for _, field := range schema {
		size := 0
		switch field.Type {
		case "uint8":
			size = 1
		case "uint16":
			size = 2
		case "uint32":
			size = 4
		case "uint64":
			size = 8
		case "string":
			size = field.Length
			if size <= 0 {
				return nil, fmt.Errorf("string field %s must have a positive length specified in manifest", field.Name)
			}
		case "ipv4":
			size = 4
		case "ipv6":
			size = 16
		default:
			return nil, fmt.Errorf("unsupported schema field type %q for field %s", field.Type, field.Name)
		}

		if offset+size > len(raw) {
			return nil, fmt.Errorf("raw sample too small for field %s (need %d bytes, have %d)", field.Name, size, len(raw)-offset)
		}

		fieldBytes := raw[offset : offset+size]
		offset += size

		var val interface{}
		switch field.Type {
		case "uint8":
			val = fieldBytes[0]
		case "uint16":
			val = binary.LittleEndian.Uint16(fieldBytes)
		case "uint32":
			val = binary.LittleEndian.Uint32(fieldBytes)
		case "uint64":
			val = binary.LittleEndian.Uint64(fieldBytes)
		case "string":
			val = GoString(fieldBytes)
		case "ipv4":
			val = net.IP(fieldBytes).String()
		case "ipv6":
			val = net.IP(fieldBytes).String()
		}

		event[field.Name] = val
	}
	return event, nil
}

// FilterConfig holds runtime event filtering and sanitization options.
type FilterConfig struct {
	FilterPort   uint16
	FilterComm   string
	FilterHost   string
	FilterErrors bool
	Sanitize     bool
}

// MatchesPortFilter checks whether a decoded event matches the specified port filter.
// It scans all schema fields with Format=="port" or whose name contains "port",
// and returns true if ANY matching field equals the filter value.
// This means for modules with both sport/dport, a match on either port passes the filter.
func MatchesPortFilter(event map[string]interface{}, schema []registry.FieldSchema, filterPort uint16) bool {
	for _, field := range schema {
		if field.Format == "port" || strings.Contains(strings.ToLower(field.Name), "port") {
			if val, ok := event[field.Name]; ok {
				var valPort uint16
				switch num := val.(type) {
				case uint8:
					valPort = uint16(num)
				case uint16:
					valPort = num
				case uint32:
					valPort = uint16(num)
				case uint64:
					valPort = uint16(num)
				}
				if valPort == filterPort {
					return true
				}
			}
		}
	}
	return false
}

// MatchesFilters evaluates an event against all configured filters (port, comm, host, errors).
func MatchesFilters(e map[string]interface{}, schema []registry.FieldSchema, cfg FilterConfig) bool {
	if cfg.FilterPort > 0 && !MatchesPortFilter(e, schema, cfg.FilterPort) {
		return false
	}
	if cfg.FilterComm != "" {
		comm, ok := e["comm"].(string)
		if !ok || !strings.Contains(strings.ToLower(comm), strings.ToLower(cfg.FilterComm)) {
			return false
		}
	}
	if cfg.FilterHost != "" {
		host, ok := e["host"].(string)
		if !ok || !strings.Contains(strings.ToLower(host), strings.ToLower(cfg.FilterHost)) {
			return false
		}
	}
	if cfg.FilterErrors {
		hasError := false
		if sc, ok := e["status_code"]; ok {
			var code int
			switch v := sc.(type) {
			case uint8:
				code = int(v)
			case uint16:
				code = int(v)
			case uint32:
				code = int(v)
			case uint64:
				code = int(v)
			case int:
				code = v
			}
			if code >= 400 {
				hasError = true
			}
		}
		if !hasError {
			if lvl, ok := e["level"].(string); ok {
				lvlUpper := strings.ToUpper(lvl)
				if strings.Contains(lvlUpper, "ERR") || strings.Contains(lvlUpper, "FAIL") || strings.Contains(lvlUpper, "CRIT") {
					hasError = true
				}
			}
		}
		if !hasError {
			return false
		}
	}
	return true
}

var (
	bearerRegex = regexp.MustCompile(`(?i)(bearer\s+)[A-Za-z0-9_\-\.]+`)
	apiKeyRegex = regexp.MustCompile(`(?i)(sk_live_|key-|api[_-]?key[=:\s]+)[A-Za-z0-9_\-]+`)
)

// SanitizeEvent masks sensitive tokens (Bearer tokens, API keys) in payload fields.
func SanitizeEvent(e map[string]interface{}) {
	payloadFields := []string{"req_payload", "resp_payload", "query", "message", "payload"}
	for _, k := range payloadFields {
		if raw, ok := e[k].(string); ok && raw != "" {
			cleaned := bearerRegex.ReplaceAllString(raw, "${1}**********")
			cleaned = apiKeyRegex.ReplaceAllString(cleaned, "${1}**********")
			e[k] = cleaned
		}
	}
}

// ListenAndStream opens the ring buffer reader and streams telemetry events to output writer or starts TUI
func ListenAndStream(ctx context.Context, bpfMaps map[string]*ebpf.Map, manifest *registry.Manifest, output io.Writer, outputFormat string, version string, filterCfg FilterConfig, streamToken string, streamURL string) error {
	var streamer *Streamer
	if streamToken != "" {
		rawYAML := ""
		if manifest != nil {
			rawYAML = manifest.RawContent
		}
		var err error
		streamer, err = NewStreamer(ctx, streamURL, streamToken, rawYAML)
		if err != nil {
			return fmt.Errorf("failed to initialize telemetry streamer: %w", err)
		}
		defer streamer.Close()
	}

	// Mode 1: When stream token is provided and output is default or "stream", launch dedicated Streaming Monitor
	if streamer != nil && (outputFormat == "tui" || outputFormat == "stream" || outputFormat == "") {
		var activeReaders []*ringbuf.Reader

		if manifest != nil && len(manifest.Maps) > 0 {
			for _, mSpec := range manifest.Maps {
				if mSpec.Type == "ringbuf" {
					bpfMap := bpfMaps[mSpec.Name]
					if bpfMap == nil {
						continue
					}

					rd, err := ringbuf.NewReader(bpfMap)
					if err != nil {
						continue
					}
					activeReaders = append(activeReaders, rd)

					mapName := mSpec.Name
					schema := mSpec.EventSchema

					go func(rd *ringbuf.Reader, mapName string, schema []registry.FieldSchema) {
						for {
							record, err := rd.Read()
							if err != nil {
								return
							}
							event, err := DecodeDynamicEvent(record.RawSample, schema)
							if err != nil {
								continue
							}
							if !MatchesFilters(event, schema, filterCfg) {
								continue
							}
							if filterCfg.Sanitize {
								SanitizeEvent(event)
							}
							streamer.EnqueueEvent(mapName, event)
						}
					}(rd, mapName, schema)
				}
			}
		}

		// Launch background 1-second ticker for BPF Hash Maps polling (e.g. cpu_stats, net_stats)
		if manifest != nil && len(manifest.Maps) > 0 {
			stateCache := make(map[string]map[string]StateSample)

			go func() {
				ticker := time.NewTicker(1 * time.Second)
				defer ticker.Stop()

				for {
					select {
					case <-ctx.Done():
						return
					case <-ticker.C:
						now := time.Now()
						for _, mSpec := range manifest.Maps {
							if mSpec.Type != "hash" {
								continue
							}
							bpfMap, ok := bpfMaps[mSpec.Name]
							if !ok || bpfMap == nil {
								continue
							}

							keySize := calcSchemaSize(mSpec.KeySchema)
							valSize := calcSchemaSize(mSpec.ValueSchema)
							if keySize == 0 || valSize == 0 {
								continue
							}

							key := make([]byte, keySize)
							val := make([]byte, valSize)

							if _, ok := stateCache[mSpec.Name]; !ok {
								stateCache[mSpec.Name] = make(map[string]StateSample)
							}
							mapCache := stateCache[mSpec.Name]

							var aggHints []registry.AggregateHint
							for _, page := range manifest.TUIHints.Pages {
								for _, pane := range page.Panes {
									if pane.MapName == mSpec.Name && len(pane.AggregateBy) > 0 {
										aggHints = pane.AggregateBy
										break
									}
								}
								if len(aggHints) > 0 {
									break
								}
							}

							iter := bpfMap.Iterate()
							for iter.Next(&key, &val) {
								dk, err := DecodeDynamicEvent(key, mSpec.KeySchema)
								if err != nil {
									continue
								}
								dv, err := DecodeDynamicEvent(val, mSpec.ValueSchema)
								if err != nil {
									continue
								}

								keyStr := ""
								if len(mSpec.KeySchema) > 0 {
									if v, ok := dk[mSpec.KeySchema[0].Name]; ok {
										keyStr = sanitizeString(fmt.Sprint(v))
									}
								}
								if keyStr == "" {
									keyStr = "unknown"
								}

								eventData := make(map[string]interface{})
								for k, v := range dk {
									eventData[k] = v
								}
								for k, v := range dv {
									eventData[k] = v
								}
								eventData["title"] = keyStr

								if len(aggHints) > 0 {
									aggType := aggHints[0].Type
									vf := aggHints[0].ValueField

									if aggType == "value" {
										if numVal, ok := dv[vf]; ok {
											fVal := toFloat64(numVal)
											eventData["value"] = fVal
											eventData["formatted_val"] = formatValue(fVal)
										}
									} else if aggType == "delta_rate" {
										if numVal, ok := dv[vf]; ok {
											currentVal := toFloat64(numVal)
											if prev, ok := mapCache[keyStr]; ok {
												deltaVal := currentVal - prev.Value
												deltaTimeSec := now.Sub(prev.Timestamp).Seconds()
												if deltaTimeSec > 0 && deltaVal >= 0 {
													var rate float64
													if vf == "cpu_time_ns" {
														rate = (deltaVal / (deltaTimeSec * 1e9)) * 100.0
														eventData["cpu_pct"] = fmt.Sprintf("%.1f%%", rate)
														eventData["value"] = rate
														eventData["formatted_val"] = fmt.Sprintf("%.1f%%", rate)
													} else if strings.HasSuffix(vf, "_ns") {
														stallSec := deltaVal / (deltaTimeSec * 1e9)
														eventData["value"] = stallSec
														eventData["formatted_val"] = fmt.Sprintf("%.1f s/s", stallSec)
													} else {
														rate = deltaVal / deltaTimeSec
														eventData["throughput"] = rate
														eventData["value"] = rate
														eventData["formatted_val"] = formatValue(rate) + "/s"
													}
												}
											} else {
												// Baseline initial sample: default to 0.0% / 0.0 s/s / 0 B/s rate
												if vf == "cpu_time_ns" {
													eventData["cpu_pct"] = "0.0%"
													eventData["value"] = 0.0
													eventData["formatted_val"] = "0.0%"
												} else if strings.HasSuffix(vf, "_ns") {
													eventData["value"] = 0.0
													eventData["formatted_val"] = "0.0 s/s"
												} else {
													eventData["throughput"] = 0.0
													eventData["value"] = 0.0
													eventData["formatted_val"] = "0 B/s"
												}
											}
											mapCache[keyStr] = StateSample{Value: currentVal, Timestamp: now}
										}
									}
								}

								streamer.EnqueueEvent(mSpec.Name, eventData)
							}
						}
					}
				}
			}()
		}

		defer func() {
			for _, rd := range activeReaders {
				rd.Close()
			}
		}()

		if len(activeReaders) == 0 {
			rbMap := manifest.GetRingBufMap()
			if rbMap == nil {
				return fmt.Errorf("no ringbuf map defined in manifest")
			}
			
			bpfMap := bpfMaps[rbMap.Name]
			if bpfMap == nil {
				return fmt.Errorf("map %q not found in loaded BPF objects", rbMap.Name)
			}

			rd, err := ringbuf.NewReader(bpfMap)
			if err != nil {
				return fmt.Errorf("failed to open ring buffer reader: %w", err)
			}
			defer rd.Close()

			schema := rbMap.EventSchema

			go func() {
				for {
					record, err := rd.Read()
					if err != nil {
						return
					}
					event, err := DecodeDynamicEvent(record.RawSample, schema)
					if err != nil {
						continue
					}
					if !MatchesFilters(event, schema, filterCfg) {
						continue
					}
					if filterCfg.Sanitize {
						SanitizeEvent(event)
					}
					streamer.EnqueueEvent(rbMap.Name, event)
				}
			}()
		}

		modName := "unknown"
		if manifest != nil {
			modName = manifest.Name
		}
		return RunStreamMonitor(ctx, streamer, modName, version)
	}

	// Mode 2: Local interactive TUI mode (when not streaming)
	if outputFormat == "tui" {
		return StartTUI(ctx, bpfMaps, manifest, version, filterCfg, streamer)
	}

	// Mode 3: Raw console / JSON output streaming
	outputJSON := outputFormat == "json" || outputFormat == "ndjson"

	rbMap := manifest.GetRingBufMap()
	if rbMap == nil {
		return fmt.Errorf("no ringbuf map defined in manifest")
	}
	
	bpfMap := bpfMaps[rbMap.Name]
	if bpfMap == nil {
		return fmt.Errorf("map %q not found in loaded BPF objects", rbMap.Name)
	}

	rd, err := ringbuf.NewReader(bpfMap)
	if err != nil {
		return fmt.Errorf("failed to open ring buffer reader: %w", err)
	}
	defer rd.Close()

	// Handle graceful closure when context finishes
	go func() {
		<-ctx.Done()
		rd.Close()
	}()

	schema := rbMap.EventSchema

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			return fmt.Errorf("error reading from ring buffer: %w", err)
		}

		event, err := DecodeDynamicEvent(record.RawSample, schema)
		if err != nil {
			continue
		}

		if !MatchesFilters(event, schema, filterCfg) {
			continue
		}
		if filterCfg.Sanitize {
			SanitizeEvent(event)
		}

		if streamer != nil {
			streamer.EnqueueEvent(rbMap.Name, event)
		}

		if outputJSON {
			data, _ := json.Marshal(event)
			output.Write(append(data, '\n'))
		} else {
			var fields []string
			for _, fSchema := range schema {
				if val, ok := event[fSchema.Name]; ok {
					fields = append(fields, fmt.Sprintf("%s=%v", strings.ToUpper(fSchema.Name), val))
				}
			}
			fmt.Fprintf(output, "[EVENT] %s\n", strings.Join(fields, "  "))
		}
	}
}

// GoString converts null-terminated byte slice to string
func GoString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
