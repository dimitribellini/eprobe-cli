package telemetry

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type streamTickMsg time.Time

type streamModel struct {
	streamer    *Streamer
	moduleName  string
	version     string
	dashboardURL string
	width       int
	height      int
	lastEvents  int64
	lastBytes   int64
	lastTime    time.Time
	eventRate   float64
	byteRate    float64
}

func newStreamModel(streamer *Streamer, moduleName, version string) streamModel {
	slug := strings.ReplaceAll(moduleName, "/", "-")
	dashURL := fmt.Sprintf("https://eprobe.io/dashboard/%s/%s", slug, streamer.token)
	
	// If custom target host used, adapt dashboard URL host
	if streamer.targetURL != DefaultStreamURL && streamer.targetURL != "" {
		host := streamer.targetURL
		host = strings.TrimPrefix(host, "http://")
		host = strings.TrimPrefix(host, "https://")
		host = strings.TrimPrefix(host, "ws://")
		host = strings.TrimPrefix(host, "wss://")
		host = strings.Split(host, "/")[0]
		dashURL = fmt.Sprintf("https://%s/dashboard/%s/%s", host, slug, streamer.token)
	}

	return streamModel{
		streamer:     streamer,
		moduleName:   moduleName,
		version:      version,
		dashboardURL: dashURL,
		lastTime:     time.Now(),
	}
}

func (m streamModel) Init() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return streamTickMsg(t)
	})
}

func (m streamModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c", "esc":
			return m, tea.Quit
		}
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	case streamTickMsg:
		stats := m.streamer.GetStats()
		now := time.Now()
		elapsed := now.Sub(m.lastTime).Seconds()
		if elapsed > 0 {
			m.eventRate = float64(stats.TotalEvents-m.lastEvents) / elapsed
			m.byteRate = float64(stats.CompressedBytes-m.lastBytes) / elapsed
			m.lastEvents = stats.TotalEvents
			m.lastBytes = stats.CompressedBytes
			m.lastTime = now
		}
		return m, tea.Tick(time.Second, func(t time.Time) tea.Msg {
			return streamTickMsg(t)
		})
	}
	return m, nil
}

func (m streamModel) View() string {
	stats := m.streamer.GetStats()
	uptime := time.Since(stats.StartTime).Truncate(time.Second)

	cardWidth := 74
	if m.width > 20 && m.width < 78 {
		cardWidth = m.width - 4
	}

	boxStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(primaryColor).
		Padding(1, 2).
		Width(cardWidth)

	titleStyle := lipgloss.NewStyle().
		Foreground(secondaryColor).
		Bold(true)

	labelStyle := lipgloss.NewStyle().
		Foreground(mutedText).
		Width(18)

	valStyle := lipgloss.NewStyle().
		Foreground(lightText).
		Bold(true)

	connStatus := lipgloss.NewStyle().Foreground(successColor).Bold(true).Render("● CONNECTED (Port 443 / TLS)")
	if !stats.Connected {
		connStatus = lipgloss.NewStyle().Foreground(errorColor).Bold(true).Render("✕ DISCONNECTED")
	}

	handshakeStatus := lipgloss.NewStyle().Foreground(successColor).Render("✔ Manifest Synchronized")
	if !stats.HandshakeOK {
		handshakeStatus = lipgloss.NewStyle().Foreground(warningColor).Render("⏳ Handshake Pending")
	}

	// Calculate compression savings
	compressionRatio := 0.0
	if stats.RawBytes > 0 {
		compressionRatio = (1.0 - (float64(stats.CompressedBytes) / float64(stats.RawBytes))) * 100.0
		if compressionRatio < 0 {
			compressionRatio = 0
		}
	}

	var b strings.Builder

	b.WriteString(titleStyle.Render("⚡ eProbe SaaS Real-Time Telemetry Stream") + "\n")
	b.WriteString(lipgloss.NewStyle().Foreground(mutedText).Render("Streaming kernel eBPF diagnostic metrics to cloud visualizer") + "\n\n")

	b.WriteString(fmt.Sprintf("%s %s\n", labelStyle.Render("Connection:"), connStatus))
	b.WriteString(fmt.Sprintf("%s %s\n", labelStyle.Render("Target Broker:"), valStyle.Render(stats.TargetURL)))
	b.WriteString(fmt.Sprintf("%s %s\n", labelStyle.Render("Stream Token:"), lipgloss.NewStyle().Foreground(secondaryColor).Render(stats.StreamToken)))
	b.WriteString(fmt.Sprintf("%s %s\n", labelStyle.Render("Module:"), valStyle.Render(fmt.Sprintf("%s (%s)", m.moduleName, m.version))))
	b.WriteString(fmt.Sprintf("%s %s\n", labelStyle.Render("Handshake:"), handshakeStatus))
	b.WriteString(fmt.Sprintf("%s %s\n", labelStyle.Render("Session Time:"), valStyle.Render(uptime.String())))

	b.WriteString("\n" + lipgloss.NewStyle().Foreground(mutedText).Render("── Data Transfer & Network Statistics ──────────────────────────────") + "\n")

	b.WriteString(fmt.Sprintf("%s %s  %s\n",
		labelStyle.Render("Events Streamed:"),
		valStyle.Render(fmt.Sprintf("%d events", stats.TotalEvents)),
		lipgloss.NewStyle().Foreground(secondaryColor).Render(fmt.Sprintf("(Rate: %.0f evt/s)", m.eventRate)),
	))

	b.WriteString(fmt.Sprintf("%s %s\n",
		labelStyle.Render("Micro-Batches:"),
		valStyle.Render(fmt.Sprintf("%d batches (50ms interval)", stats.TotalBatches)),
	))

	b.WriteString(fmt.Sprintf("%s %s  %s\n",
		labelStyle.Render("Data Transferred:"),
		valStyle.Render(formatBytes(stats.CompressedBytes)),
		lipgloss.NewStyle().Foreground(successColor).Render(fmt.Sprintf("(Raw: %s, -%.1f%% Gzip savings)", formatBytes(stats.RawBytes), compressionRatio)),
	))

	b.WriteString(fmt.Sprintf("%s %s\n",
		labelStyle.Render("Bandwidth:"),
		valStyle.Render(fmt.Sprintf("%.1f KB/s", m.byteRate/1024.0)),
	))

	if stats.DroppedEvents > 0 {
		b.WriteString(fmt.Sprintf("%s %s\n",
			labelStyle.Render("Dropped Events:"),
			lipgloss.NewStyle().Foreground(warningColor).Bold(true).Render(fmt.Sprintf("%d", stats.DroppedEvents)),
		))
	} else {
		b.WriteString(fmt.Sprintf("%s %s\n",
			labelStyle.Render("Dropped Events:"),
			valStyle.Render("0 (clean buffer)"),
		))
	}

	b.WriteString("\n" + lipgloss.NewStyle().Foreground(secondaryColor).Bold(true).Render("👉 Live Web Dashboard:") + "\n")
	b.WriteString(lipgloss.NewStyle().Foreground(primaryColor).Underline(true).Render(m.dashboardURL) + "\n\n")

	b.WriteString(lipgloss.NewStyle().Foreground(mutedText).Italic(true).Render("Press [Ctrl+C] or [q] to stop streaming and detach probe."))

	rendered := boxStyle.Render(b.String())

	if m.height > 24 {
		paddingTop := (m.height - lipgloss.Height(rendered)) / 3
		if paddingTop > 0 {
			rendered = strings.Repeat("\n", paddingTop) + rendered
		}
	}

	return rendered
}

// formatBytes formats byte sizes into human readable units.
func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// RunStreamMonitor launches the dedicated Bubbletea streaming monitor.
func RunStreamMonitor(ctx context.Context, streamer *Streamer, moduleName, version string) error {
	m := newStreamModel(streamer, moduleName, version)
	p := tea.NewProgram(m, tea.WithAltScreen())

	go func() {
		<-ctx.Done()
		p.Send(tea.Quit())
	}()

	_, err := p.Run()
	return err
}
