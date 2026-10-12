package telemetry

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

var testUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

func TestNormalizeStreamURL(t *testing.T) {
	tests := []struct {
		name        string
		rawURL      string
		token       string
		wantScheme  string
		wantHost    string
		wantPath    string
		wantToken   string
		wantRole    string
		wantErr     bool
	}{
		{
			name:       "default URL when empty",
			rawURL:     "",
			token:      "abc-123",
			wantScheme: "wss",
			wantHost:   "stream.eprobe.io",
			wantPath:   "/ws",
			wantToken:  "abc-123",
			wantRole:   "agent",
		},
		{
			name:       "https main domain",
			rawURL:     "https://stream.eprobe.io",
			token:      "token-xyz",
			wantScheme: "wss",
			wantHost:   "stream.eprobe.io",
			wantPath:   "/ws",
			wantToken:  "token-xyz",
			wantRole:   "agent",
		},
		{
			name:       "http local dev server with port",
			rawURL:     "http://localhost:8080",
			token:      "dev-token",
			wantScheme: "ws",
			wantHost:   "localhost:8080",
			wantPath:   "/ws",
			wantToken:  "dev-token",
			wantRole:   "agent",
		},
		{
			name:       "bare IP and port without scheme",
			rawURL:     "192.168.1.50:8080",
			token:      "ip-token",
			wantScheme: "wss",
			wantHost:   "192.168.1.50:8080",
			wantPath:   "/ws",
			wantToken:  "ip-token",
			wantRole:   "agent",
		},
		{
			name:       "custom path preserved",
			rawURL:     "https://stream.eprobe.io/custom-ws",
			token:      "custom-token",
			wantScheme: "wss",
			wantHost:   "stream.eprobe.io",
			wantPath:   "/custom-ws",
			wantToken:  "custom-token",
			wantRole:   "agent",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeStreamURL(tc.rawURL, tc.token)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantErr {
				return
			}

			u, err := url.Parse(got)
			if err != nil {
				t.Fatalf("failed to parse output URL %q: %v", got, err)
			}

			if u.Scheme != tc.wantScheme {
				t.Errorf("scheme: got %q, want %q", u.Scheme, tc.wantScheme)
			}
			if u.Host != tc.wantHost {
				t.Errorf("host: got %q, want %q", u.Host, tc.wantHost)
			}
			if u.Path != tc.wantPath {
				t.Errorf("path: got %q, want %q", u.Path, tc.wantPath)
			}
			if u.Query().Get("token") != tc.wantToken {
				t.Errorf("token: got %q, want %q", u.Query().Get("token"), tc.wantToken)
			}
			if u.Query().Get("role") != tc.wantRole {
				t.Errorf("role: got %q, want %q", u.Query().Get("role"), tc.wantRole)
			}
		})
	}
}

func TestStreamerEndToEnd(t *testing.T) {
	var mu sync.Mutex
	var receivedManifest ManifestFrame
	var receivedBatches []BatchFrame

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		role := r.URL.Query().Get("role")
		if token != "test-token-42" || role != "agent" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		conn, err := testUpgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade error: %v", err)
			return
		}
		defer conn.Close()

		for {
			msgType, data, err := conn.ReadMessage()
			if err != nil {
				break
			}

			mu.Lock()
			if msgType == websocket.TextMessage {
				var mf ManifestFrame
				if err := json.Unmarshal(data, &mf); err == nil && mf.Type == "manifest" {
					receivedManifest = mf
				}
			} else if msgType == websocket.BinaryMessage {
				gzReader, err := gzip.NewReader(bytes.NewReader(data))
				if err == nil {
					var batch BatchFrame
					if err := json.NewDecoder(gzReader).Decode(&batch); err == nil {
						receivedBatches = append(receivedBatches, batch)
					}
					gzReader.Close()
				}
			}
			mu.Unlock()
		}
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rawYAML := "name: test/module\nversion: 1.0.0"
	streamer, err := NewStreamer(ctx, server.URL, "test-token-42", rawYAML)
	if err != nil {
		t.Fatalf("failed to create streamer: %v", err)
	}

	// Enqueue test events
	for i := 0; i < 5; i++ {
		streamer.EnqueueEvent("test_events", map[string]interface{}{
			"pid":  1000 + i,
			"comm": "test-proc",
		})
	}

	// Wait for 50ms batch flush
	time.Sleep(150 * time.Millisecond)

	streamer.Close()

	mu.Lock()
	defer mu.Unlock()

	// Verify handshake
	if receivedManifest.Type != "manifest" || receivedManifest.Token != "test-token-42" {
		t.Errorf("manifest handshake not received properly: %+v", receivedManifest)
	}
	if !strings.Contains(receivedManifest.Content, "name: test/module") {
		t.Errorf("manifest content mismatch: %q", receivedManifest.Content)
	}
	if receivedManifest.Host == nil {
		t.Errorf("expected host metadata in manifest frame, got nil")
	} else if receivedManifest.Host.Hostname == "" {
		t.Errorf("expected non-empty hostname in host metadata")
	}

	// Verify batches
	if len(receivedBatches) == 0 {
		t.Fatalf("no batches received by broker")
	}

	totalEvents := 0
	for _, b := range receivedBatches {
		totalEvents += len(b.Events)
	}
	if totalEvents != 5 {
		t.Errorf("expected 5 total events across batches, got %d", totalEvents)
	}
}
