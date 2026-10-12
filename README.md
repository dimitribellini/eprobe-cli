# eprobe: Tactical Ephemeral eBPF Incident Response Toolkit

`eprobe` is a high-performance, single-binary tactical incident response utility that abstracts the complexity of kernel-level tracing. Built specifically for **Site Reliability Engineers (SREs), L3 Escalation Engineers, and Platform DevOps**, it serves as the modern, unified replacement for the classic UNIX diagnostic stack (`top`, `strace`, `tcpdump`).

When standard APM platforms (Datadog, Grafana) alert that a system is failing, they lack the kernel-level resolution to explain *why*. Legacy diagnostic tools like `strace` attach via `ptrace` and impose a catastrophic 100x performance penalty that risks freezing production databases and application worker pools. `eprobe` bridges this critical diagnostic gap using read-only CO-RE eBPF probes with `<1%` CPU overhead.

---

## 🏛️ The Three Messaging Pillars

1. **Ephemeral & Zero-Instrumentation**: Single statically compiled binary (under 25MB) with no dependencies on `clang`, `llvm`, or local kernel headers. Injects read-only eBPF bytecode on demand; leaves zero background daemons or sidecars on the host. Clean detach with `Ctrl+C` terminates probes instantly.
2. **High-Resolution Kernel Correlation**: Direct in-kernel correlation of off-CPU stalls, futex lockups, D-state disk sleep, cgroup CPU bandwidth throttling, and network sockets to PIDs/TIDs with `<1%` CPU overhead.
3. **Air-Gapped, BYO-LLM Root Cause Analysis**: Zero cloud egress. Generates client-side sanitized `.zip` archives containing `00_PROMPT_COPY_PASTE.md` and statistical health profiles (`01_EXECUTIVE_SUMMARY.md`) for private Claude, ChatGPT, or local Ollama instances with zero token costs and zero data leaks.

---

## 🚀 Key Features

*   **Frictionless Installation:** Statically compiled Go binary (under 25MB) requiring no local compiler toolchain (`clang`, `llvm`) or kernel headers on the target host.
*   **Dynamic eBPF Module Registry:** Fetches, verifies, caches, and runs cryptographically signed eBPF diagnostic modules on demand (e.g. `perf/stall-tracer`, `app/docker-monitor`, `sec/exec-audit`).
*   **Kernel & User-Space Dynamic Interception (Kprobes & Uprobes):** Seamlessly attaches to kernel tracepoints/raw tracepoints as well as user-space shared libraries (e.g. dynamic OpenSSL `libssl.so` uprobes/uretprobes for zero-proxy, zero-certificate plaintext HTTPS/HTTP2 inspection with multi-distro discovery).
*   **Built-in Credential Sanitizer:** Automatically redacts Authorization Bearer tokens, API keys, and passwords by default for safe terminal triage, live audits, and demonstrations, with instant opt-out (`--no-sanitize`).
*   **Unbloated CLI with Dedicated Per-Module Help:** Keeps root CLI commands clean (`eprobe --help`), while rendering dedicated rich documentation, parameter descriptions, and multi-page diagnostic layouts on demand via `eprobe help <module>`.
*   **Dynamic Parsing & Diagnostic Layout Engine:** Decodes kernel-space binary ring buffer events and polls stateful BPF hash maps dynamically based on the module's manifest schemas, rendering customizable Bubbletea TUI log columns and aggregation leaderboards dynamically from layout hints.
*   **Compile Once – Run Everywhere (CO-RE):** Adapts bytecode offsets dynamically using local BPF Type Format (BTF) definitions to run on different kernel versions on-the-fly.
*   **Secure by Design:** Strict Ed25519 cryptographic signature verification, path traversal mitigation, automatic HTTP-to-HTTPS payload upgrading, and built-in SSRF and decompression bomb protections.
*   **Real-Time SaaS Collaborative Ingestion:** Extracts live telemetry to the `eprobe-saas` Web Inspector over Secure WebSockets (Port 443 TLS) using Gzip micro-batches and raw manifest handshakes via `-stream-token` and `-stream-url`. Concurrently captures from all ring buffer maps and periodically polls BPF hash maps (`type: hash`) with delta-rate calculations (`CPU %`, `TX/RX Bytes/s`), mirroring the full local TUI dataset to the Web Diagnostic View.
*   **Host Information & Universal Entity Resolution Protocol:** Non-invasively collects host hardware topology, OS distribution, container names (`container_id` ➔ container name via runtime-agnostic discovery), and target application versions in user-space. Transmits them in the handshake frame to enrich Web UI diagnostic views and Air-Gapped AI Bundles with zero eBPF probe changes, while dynamically resolving container hashes directly in TUI Top leaderboards and stream tables.

---

## 📋 Dynamic Module Manifest Schema

Diagnostic packages (`.epm` bundles) specify how they load, link, parse, and render dynamically using a `manifest.yaml` configuration file structured as follows:

```yaml
name: perf/stall-tracer
version: 1.0.0
author: eprobe-core
sha256: <bytecode-sha256-hex>
description: "High-resolution off-CPU and scheduler stall diagnostics: microsecond D-state storage sleep, futex mutex contention, and runnable queue starvation"
attach_points:
  - type: raw_tracepoint
    symbol: sched_switch
    section: raw_trace_sched_switch
maps:
  - name: stall_events
    type: ringbuf
    event_struct: stall_event_t
    event_schema:
      - name: pid
        type: uint32
      - name: tid
        type: uint32
      - name: comm
        type: string
        length: 16
      - name: container_id
        type: string
        length: 16
        format: container_id
      - name: duration_us
        type: uint64
variables:
  - name: threshold_ms
    type: uint64
    cli_flag: threshold-ms
    description: "Minimum stall duration threshold in milliseconds (default 20ms)"
tui_hints:
  pages:
    - name: "System Off-CPU & Scheduler Overview"
      layout: grid
      panes:
        - name: stall_events_stream
          type: stream
          map_name: stall_events
          position:
            row: 0
            col: 0
            width: 100%
            height: 100%
          summary: "Live stream of threshold-exceeding scheduler stalls"
          inspect_payload: "message"
          columns:
            - field: time
              width: 10
            - field: pid
              width: 8
              bold: true
              color: "#FFA500"
            - field: comm
              width: 16
            - field: duration_us
              width: 12
```

---

## 🎨 TUI Components & Module Developer Reference Guide

`eprobe` provides 5 core TUI pane types in `tui_hints.pages[].panes[]` to visualize any eBPF telemetry dataset declaratively:

1. **`stream`**: Live event table widget with searchable columns, inspect payload modal (`Enter`), dynamic filtering (`/`), and automatic container name resolution for `container_id` columns.
2. **`top`**: Real-time leaderboards with event accumulation (`aggregate_by: type: count`) or literal value/gauge aggregation from in-kernel hash maps (`aggregate_by: type: value` / `delta_rate`), sorting top N keys dynamically with automatic container name resolution.
3. **`histogram`**: Distribution bar charts for numerical fields (e.g. latency distributions, packet sizes, execution durations) using Unicode blocks (`█`, `▆`, `▄`, `▂`).
4. **`sparkline`**: Time-series trend graphs with scrolling Unicode levels (` ▂▃▄▅▆▇█`) and summary metrics (`Cur`, `Min`, `Max`, `Avg`).
5. **`tree`**: Interactive process execution (`pid`/`ppid`) or distributed trace span execution trees (`req_id`/`parent_req_id`) with tree connectors (`├── `, `└── `), branch expand/collapse (`←`/`→` or `h`/`l`), and inspect modal.

### ⌨️ Interactive TUI Navigation & Keybindings

When running any diagnostic module in default interactive TUI mode (`sudo ./eprobe run <module>`), the terminal inspector supports rich navigation:

| Keybinding | Action | Description |
| :--- | :--- | :--- |
| **`1` – `9`** | **Direct Chapter Jump** | Instantly jumps to the corresponding diagnostic view page. |
| **`[` / `]`** | **Previous / Next Page** | Cycles sequentially through multi-page diagnostic views. |
| **`Tab`** | **Cycle Active Pane** | Moves focus between layout panes, highlighting the active pane with a colored border and `[ACTIVE]` indicator. |
| **`m`** | **Maximize / Restore Pane** | Expands the focused pane to 100% full-screen terminal height and width; press again or `Esc` to restore the grid. |
| **`Enter`** | **Inspect Event / Drill-down**| Opens deep inspection modal on the selected stream row or trace tree node; reveals dual HTTP/SQL payloads, headers, and protocol metadata. |
| **`/`** | **Dynamic Filter / Search** | Activates real-time substring filtering on the focused stream or top pane. |
| **`Space` / `p`** | **Pause / Resume Stream** | Freezes the live eBPF stream to inspect high-frequency events without terminal jitter. |
| **`↑` / `↓` (`k` / `j`)** | **Row & Tree Navigation** | Moves selection cursor through table events or trace tree nodes. |
| **`←` / `→` (`h` / `l`)** | **Collapse / Expand Branch**| Collapses or expands the selected trace tree branch. |
| **`e`** | **Toggle All Branches** | Expands or collapses all branches across the entire trace tree simultaneously. |
| **`?`** | **Overview & Help Modal** | Displays module metadata, mission statement, page catalog, and keybindings reference. |
| **`Esc`** | **Back / Dismiss Modal** | Closes active inspect modal, search bar, or restores maximized pane. |
| **`q` / `Ctrl+C`** | **Graceful Detach** | Safely detaches eBPF probes from the kernel and cleans up BPF maps. |

---

## 🏗️ Architecture

```
 +--------------------------------------------------------------------------+
 |                              LOCAL CLIENT                                |
 |                                                                          |
 |  +---------------+      (1) CLI Command       +-----------------------+  |
 |  |  Operator CLI | -------------------------> |     Runtime Engine    |  |
 |  +---------------+                            +-----------------------+  |
 |                                                           |              |
 |  +---------------+      (4) Load Bytecode                 |              |
 |  | Linux Kernel  | <--------------------------------------+              |
 |  +---------------+                                        |              |
 |         |                                                 | (3) Mount    |
 |         | (5a) Emit Events          (5b) Hash Maps        |     & Listen |
 |         v                                v                v              |
 |  +---------------+             +---------------+                         |
 |  |  Ring Buffer  |             |  BPF Hash     |                         |
 |  +---------------+             |  Maps (Tick)  |                         |
 |         |                      +---------------+                         |
 |         |       (6) Process Telemetry   |        +-----------------------+|
 |         +----------------------------->|------->|  Telemetry Pipeline   ||
 |                                                  +-----------------------+|
 |                                                           |              |
 +-----------------------------------------------------------|--------------+
                                                             |
                 +-------------------------------------------+
                 | (2) Get Module                            | (7) WSS Ingestion (443)
                 v                                           v
   +---------------------------+               +---------------------------+
   |   REMOTE REGISTRY         |               |   WEB INSPECTOR           |
   |   (Signed Packages)       |               |   (Diagnostic Views & RCA)|
   +---------------------------+               +---------------------------+
```

---

## 📁 Diagnostic Modules Catalog

Diagnostic tools are organized into specialized namespaces:

*   **`perf/` (Kernel Stalls & Latency):** High-resolution off-CPU tracing, D-state uninterruptible sleep, scheduler preemption delays, and futex mutex contention (e.g. `perf/stall-tracer`).
*   **`app/` (Application Subsystems & Protocols):** Plaintext HTTPS/HTTP2 decryption, microsecond latency tracing, database query auditing, container throttling, and Zabbix server diagnostics (e.g. `app/docker-monitor`, `app/mysql-monitor`, `app/http-tracer`, `app/zabbix-monitor`, `app/universal-tls-sniffer`).
*   **`sec/` (Process Forensics & Auditing):** Detecting anomalous command execution, obfuscated CLI arguments, parent-child lineages, and privilege escalations (e.g. `sec/exec-audit`).
*   **`log/` (Crash & Error Sinks):** Kernel-level capturing of standard error writes (`fd == 2`) and unhandled panic traces across hosts and containers (e.g. `log/stderr-capture`).

---

## 🛠️ Getting Started

### Prerequisites
*   Linux OS
*   BPF-enabled kernel supporting CO-RE (typically Kernel 5.8+)
*   `/sys/kernel/btf/vmlinux` must be present on the host

### Development Setup
1.  **Clone the Repository:**
    ```bash
    git clone https://git.quadrata.dev/dimi/eprobe-cli.git
    cd eprobe-cli
    ```
2.  **Run Unit Tests:**
    Verify the zero-copy telemetry decoding pipelines:
    ```bash
    go test -v ./...
    ```
3.  **Build the Static CLI:**
    Build the standalone `eprobe` static binary:
    ```bash
    make build
    ```

---

## 📖 Usage & Invocation

Loading and executing eBPF tracepoints and kprobes requires root privileges (`sudo`).

### 1. General Command Syntax
```bash
# Run a diagnostic module (automatically pulls from registry if cached copy is missing)
sudo ./eprobe run <module-name> [flags]

# Pull a module manifest and bytecode from registry without executing it
./eprobe pull <module-name> [flags]

# List all locally downloaded and cached diagnostic modules
./eprobe list

# Search the remote registry for available modules
./eprobe search [flags]

# Display metadata and layout of a cached module manifest
./eprobe describe <module-name>

# Check for updates and sync a module cache with the Remote Registry
./eprobe update <module-name> [flags]

# Delete a downloaded module cache
./eprobe remove <module-name>

# Display dedicated parameters, filters, and multi-page diagnostic layout for a module
./eprobe help <module-name>

# Check eprobe CLI version
./eprobe version
```

> [!TIP]
> The eprobe CLI features an order-independent flag parser. Flags like `-output json`, `-port 80`, `-pid 1234`, `-slow-us 50000`, or `-registry http://localhost:8080` can be passed anywhere in the command.

### 2. Tactical Incident Triage Examples

#### ⏱️ Kernel Off-CPU Stall & Mutex Diagnostics (`perf/stall-tracer`)
Triages unexplained freezes, D-state storage sleep, and futex rwlock contention:
```bash
# Launch interactive terminal TUI with default 20ms stall threshold
sudo ./eprobe run perf/stall-tracer

# Isolate stalls for a specific process PID during an active incident
sudo ./eprobe run perf/stall-tracer --pid 4092

# Filter exclusively for D-state (disk / block I/O) stalls
sudo ./eprobe run perf/stall-tracer --stall-type 1
```

#### 🐳 Container Runtime & Cgroup Throttling (`app/docker-monitor`)
Triages container crashes, OOM kills, and CFS quota throttling:
```bash
# Launch container diagnostics in interactive terminal TUI
sudo ./eprobe run app/docker-monitor

# Isolate diagnostics to a specific container PID
sudo ./eprobe run app/docker-monitor --pid 14208
```

#### 🛡️ Process Execution Forensics (`sec/exec-audit`)
Captures process execution, full 256-byte arguments, and login UIDs across `sudo`:
```bash
# Launch real-time process execution forensics
sudo ./eprobe run sec/exec-audit

# Stream structured NDJSON to SIEM or log pipelines
sudo ./eprobe run sec/exec-audit -output json
```

#### 🌐 HTTP Ingress & TTFB Latency Triage (`app/http-tracer`)
Captures HTTP status codes, microsecond TTFB, W3C distributed trace trees, and 5xx cascades:
```bash
# Launch HTTP diagnostics on port 8080 with 20ms slow request alert
sudo ./eprobe run app/http-tracer -port 8080 -slow-ms 20
```

#### 🔐 Universal TLS Plaintext Sniffer (`app/universal-tls-sniffer`)
Captures plaintext HTTPS/HTTP2 via OpenSSL uprobes without certificates or proxy setup:
```bash
# Launch TLS decryption with automatic credential sanitization
sudo ./eprobe run app/universal-tls-sniffer

# Filter by target host and display only HTTP errors (4xx & 5xx)
sudo ./eprobe run app/universal-tls-sniffer --host api.stripe.com --errors-only
```

---

## ☁️ Collaborative Web Diagnostic Views & Telemetry Ingestion

Extract kernel eBPF diagnostic telemetry to the browser-based Web Inspector in real time:

```bash
# Extract telemetry to browser-based collaborative diagnostic view
sudo ./eprobe run app/zabbix-monitor --stream-token 0486cf95-eb6a-4cf6-aa4e-d6ec1ffeaf03
```

Renders a live network & telemetry statistics dashboard in the terminal:
```text
┌─ eprobe Incident Telemetry Ingestion ──────────────────────────────────┐
│                                                                        │
│  Connection:       ● CONNECTED (Port 443 / TLS)                        │
│  Target Broker:    https://stream.eprobe.io                            │
│  Stream Token:     0486cf95-eb6a-4cf6-aa4e-d6ec1ffeaf03               │
│  Module:           app/zabbix-monitor (1.0.0)                          │
│  Handshake:        ✔ Manifest Synchronized                             │
│  Session Time:     00:03:42                                            │
│                                                                        │
│  ── Data Transfer & Network Statistics ──────────────────────────────  │
│  Events Streamed:  14,820 events  (Rate: 260 evt/s)                    │
│  Micro-Batches:    296 batches (50ms interval)                         │
│  Data Transferred: 138.4 KB  (Raw: 1.12 MB, -87.6% Gzip savings)       │
│  Bandwidth:        16.2 KB/s                                           │
│  Dropped Events:   0 (clean buffer)                                    │
│                                                                        │
│  👉 Live Diagnostic View:                                              │
│  https://eprobe.io/dashboard/app-zabbix-monitor/0486cf95-eb6a-4cf6...  │
│                                                                        │
│  Press [Ctrl+C] or [q] to stop extraction and clean detach probe.      │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 🔒 Graceful Clean Detach
Press `Ctrl+C` or `q` to terminate the CLI. The runtime engine intercepts `SIGINT` / `SIGTERM` to safely detach all probes from the kernel, send a graceful session close frame to the web broker, and clean up allocated eBPF Ring Buffers and Hash Maps. It leaves zero background agents on the host.

---

## 📄 License
This project is licensed under the MIT License - see the LICENSE file for details.
