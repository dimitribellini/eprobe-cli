package telemetry

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"eprobe/pkg/registry"
	"eprobe/pkg/system"
)

const (
	DefaultStreamURL = "https://stream.eprobe.io"
	DefaultBatchSize = 250
	BatchFlushPeriod = 50 * time.Millisecond
	MaxQueueSize     = 10000
)

// ManifestFrame is the initial handshake payload sent to the broker.
type ManifestFrame struct {
	Type    string           `json:"type"`
	Token   string           `json:"token"`
	Format  string           `json:"format"`
	Content string           `json:"content"`
	Host    *system.HostInfo `json:"host,omitempty"`
}

// StreamEvent represents an individual telemetry event.
type StreamEvent struct {
	Map       string                 `json:"map"`
	Timestamp int64                  `json:"timestamp"`
	Data      map[string]interface{} `json:"data"`
}

// BatchFrame represents a micro-batch of telemetry events.
type BatchFrame struct {
	Type       string        `json:"type"`
	Token      string        `json:"token"`
	Count      int           `json:"count"`
	Compressed bool          `json:"compressed"`
	Events     []StreamEvent `json:"events"`
}

// CloseFrame is sent upon graceful shutdown.
type CloseFrame struct {
	Type  string `json:"type"`
	Token string `json:"token"`
}

// StreamerStats holds real-time transfer and network statistics.
type StreamerStats struct {
	Connected       bool
	TargetURL       string
	StreamToken     string
	StartTime       time.Time
	TotalEvents     int64
	TotalBatches    int64
	RawBytes        int64
	CompressedBytes int64
	DroppedEvents   int64
	HandshakeOK     bool
}

// Streamer handles live telemetry streaming to the eProbe SaaS portal.
type Streamer struct {
	token           string
	targetURL       string
	wsURL           string
	rawYAML         string
	manifest        *registry.Manifest
	conn            *websocket.Conn
	eventCh         chan StreamEvent
	ctx             context.Context
	cancel          context.CancelFunc
	wg              sync.WaitGroup
	isClosed        int32
	sendMu          sync.Mutex
	startTime       time.Time
	totalEvents     int64
	totalBatches    int64
	rawBytes        int64
	compressedBytes int64
	droppedEvents   int64
	handshakeOK     bool
}

// NormalizeStreamURL converts standard HTTP/HTTPS URLs to WebSocket URLs
// and appends necessary query parameters for the broker handshake.
func NormalizeStreamURL(rawURL, token string) (string, error) {
	if strings.TrimSpace(rawURL) == "" {
		rawURL = DefaultStreamURL
	}

	// Default to https scheme if none provided
	if !strings.HasPrefix(rawURL, "http://") &&
		!strings.HasPrefix(rawURL, "https://") &&
		!strings.HasPrefix(rawURL, "ws://") &&
		!strings.HasPrefix(rawURL, "wss://") {
		rawURL = "https://" + rawURL
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid stream broker URL: %w", err)
	}

	// Normalize scheme: http -> ws, https -> wss
	switch u.Scheme {
	case "http":
		u.Scheme = "ws"
	case "https":
		u.Scheme = "wss"
	}

	// Default path to /ws if not specified
	if u.Path == "" || u.Path == "/" {
		u.Path = "/ws"
	}

	// Set query parameters
	q := u.Query()
	q.Set("token", token)
	q.Set("role", "agent")
	u.RawQuery = q.Encode()

	return u.String(), nil
}

// NewStreamer creates and connects a new telemetry streamer.
func NewStreamer(parentCtx context.Context, streamURL, token, rawYAML string) (*Streamer, error) {
	if token == "" {
		return nil, fmt.Errorf("stream token must not be empty")
	}

	if streamURL == "" {
		streamURL = DefaultStreamURL
	}

	wsURL, err := NormalizeStreamURL(streamURL, token)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(parentCtx)

	dialer := websocket.DefaultDialer
	dialer.HandshakeTimeout = 10 * time.Second

	conn, resp, err := dialer.DialContext(ctx, wsURL, nil)
	if err != nil {
		cancel()
		if resp != nil {
			return nil, fmt.Errorf("failed to connect to stream broker at %s (HTTP %s): %w", streamURL, resp.Status, err)
		}
		return nil, fmt.Errorf("failed to connect to stream broker at %s: %w", streamURL, err)
	}

	var parsedManifest *registry.Manifest
	if len(rawYAML) > 0 {
		if m, err := registry.ParseManifest([]byte(rawYAML)); err == nil {
			parsedManifest = m
		}
	}

	s := &Streamer{
		token:       token,
		targetURL:   streamURL,
		wsURL:       wsURL,
		rawYAML:     rawYAML,
		manifest:    parsedManifest,
		conn:        conn,
		eventCh:     make(chan StreamEvent, MaxQueueSize),
		ctx:         ctx,
		cancel:      cancel,
		startTime:   time.Now(),
		handshakeOK: false,
	}

	// Step 1: Send Manifest Handshake
	if err := s.sendManifestHandshake(); err != nil {
		s.conn.Close()
		s.cancel()
		return nil, fmt.Errorf("manifest handshake failed: %w", err)
	}
	s.handshakeOK = true

	// Step 2: Start background batch worker
	s.wg.Add(1)
	go s.batchWorker()

	return s, nil
}

// sendManifestHandshake sends the initial manifest frame to the broker.
func (s *Streamer) sendManifestHandshake() error {
	frame := ManifestFrame{
		Type:    "manifest",
		Token:   s.token,
		Format:  "yaml",
		Content: s.rawYAML,
		Host:    system.CollectHostInfo(s.manifest),
	}

	data, err := json.Marshal(frame)
	if err != nil {
		return fmt.Errorf("failed to marshal manifest frame: %w", err)
	}

	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	return s.conn.WriteMessage(websocket.TextMessage, data)
}

// EnqueueEvent enqueues a telemetry event for batched streaming without blocking the caller.
func (s *Streamer) EnqueueEvent(mapName string, data map[string]interface{}) {
	if atomic.LoadInt32(&s.isClosed) != 0 {
		return
	}

	atomic.AddInt64(&s.totalEvents, 1)

	evt := StreamEvent{
		Map:       mapName,
		Timestamp: time.Now().UnixMilli(),
		Data:      data,
	}

	select {
	case s.eventCh <- evt:
	default:
		atomic.AddInt64(&s.droppedEvents, 1)
	}
}

// batchWorker flushes event batches every 50ms or when reaching DefaultBatchSize.
func (s *Streamer) batchWorker() {
	defer s.wg.Done()

	ticker := time.NewTicker(BatchFlushPeriod)
	defer ticker.Stop()

	batch := make([]StreamEvent, 0, DefaultBatchSize)

	flush := func() {
		if len(batch) == 0 {
			return
		}
		s.sendBatch(batch)
		batch = make([]StreamEvent, 0, DefaultBatchSize)
	}

	for {
		select {
		case <-s.ctx.Done():
			// Drain remaining events in channel before exit
			for {
				select {
				case evt := <-s.eventCh:
					batch = append(batch, evt)
					if len(batch) >= DefaultBatchSize {
						flush()
					}
				default:
					flush()
					return
				}
			}

		case evt := <-s.eventCh:
			batch = append(batch, evt)
			if len(batch) >= DefaultBatchSize {
				flush()
			}

		case <-ticker.C:
			flush()
		}
	}
}

// sendBatch marshals, compresses, and sends an event batch frame.
func (s *Streamer) sendBatch(events []StreamEvent) {
	batch := BatchFrame{
		Type:       "batch",
		Token:      s.token,
		Count:      len(events),
		Compressed: true,
		Events:     events,
	}

	jsonBytes, err := json.Marshal(batch)
	if err != nil {
		return
	}

	// Compress payload with Gzip
	var buf bytes.Buffer
	gzWriter := gzip.NewWriter(&buf)
	if _, err := gzWriter.Write(jsonBytes); err != nil {
		return
	}
	if err := gzWriter.Close(); err != nil {
		return
	}

	atomic.AddInt64(&s.totalBatches, 1)
	atomic.AddInt64(&s.rawBytes, int64(len(jsonBytes)))
	atomic.AddInt64(&s.compressedBytes, int64(buf.Len()))

	s.sendMu.Lock()
	defer s.sendMu.Unlock()

	if atomic.LoadInt32(&s.isClosed) == 0 {
		_ = s.conn.WriteMessage(websocket.BinaryMessage, buf.Bytes())
	}
}

// GetStats returns a snapshot of current streaming statistics.
func (s *Streamer) GetStats() StreamerStats {
	isClosed := atomic.LoadInt32(&s.isClosed) != 0
	return StreamerStats{
		Connected:       !isClosed,
		TargetURL:       s.targetURL,
		StreamToken:     s.token,
		StartTime:       s.startTime,
		TotalEvents:     atomic.LoadInt64(&s.totalEvents),
		TotalBatches:    atomic.LoadInt64(&s.totalBatches),
		RawBytes:        atomic.LoadInt64(&s.rawBytes),
		CompressedBytes: atomic.LoadInt64(&s.compressedBytes),
		DroppedEvents:   atomic.LoadInt64(&s.droppedEvents),
		HandshakeOK:     s.handshakeOK,
	}
}

// Close gracefully terminates the streaming connection.
func (s *Streamer) Close() {
	if !atomic.CompareAndSwapInt32(&s.isClosed, 0, 1) {
		return
	}

	// Signal worker and drain
	s.cancel()
	s.wg.Wait()

	s.sendMu.Lock()
	defer s.sendMu.Unlock()

	// Send close frame
	closeMsg, _ := json.Marshal(CloseFrame{
		Type:  "close",
		Token: s.token,
	})
	_ = s.conn.WriteMessage(websocket.TextMessage, closeMsg)
	_ = s.conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "agent terminating"))
	_ = s.conn.Close()
}
