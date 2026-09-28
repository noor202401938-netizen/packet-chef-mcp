# @noorfatima123456/packet-chef-mcp

> **Zero-dependency, pure-JavaScript PCAP & PCAPng network forensics engine for AI agents.**  
> Built for Claude Code, Cursor, Strix, and Windsurf, with dual-transport support (Local `stdio` & Cloud `HTTP/SSE`).

[![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)](package.json)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Node](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen.svg)](package.json)
[![MCP](https://img.shields.io/badge/MCP-v1.30.1-orange.svg)](https://modelcontextprotocol.io/)
[![Zero-Dependency](https://img.shields.io/badge/dependencies-0-success.svg)](package.json)

---

## ⚡ Why packet-chef-mcp v2.0?

Traditional network analysis utilities (`tshark`, `libpcap`, Python `scapy`) were designed for human network engineers, not autonomous AI agents:
1. They require **heavy native toolchains and C bindings** that frequently fail to compile or install on minimal Docker containers, serverless environments, or restricted cloud runners.
2. They dump **hundreds of megabytes of raw hex and verbose protocol trees** into agent context windows, causing massive context bloat and catastrophic token exhaustion.

**`packet-chef-mcp` v2.0 is built from first principles as an AI-First Network Triage Sensor:**
- **Zero Native Dependencies:** 100% pure Node.js `Buffer` arithmetic. Runs anywhere Node.js runs without root permissions.
- **Strict Context Economy:** Converts raw binary captures into compact, bounded (&lt;2KB) JSON summaries and paginated views (default limit `20`, maximum `100`), preserving agent reasoning budget.
- **High-Signal Threat Decoders:** Focuses on the top 90% of cloud/web attack indicators: DNS exfiltration, HTTP verbs, TLS SNI, JA3/JA4 fingerprints, C2 beacon periodicity, WebSockets, and QUIC handshakes.
- **Dual Transport Security:** Local `stdio` mode permits local file analysis (`filePath`), while remote `HTTP/SSE` mode strictly blocks filesystem access, accepting only isolated Base64 streams (up to 10MB).

### 📋 Capabilities, Scope & Limitations Matrix

| Category | Supported in packet-chef-mcp v2.0 | Architectural Boundaries & Out of Scope | Recommended Deep Tool |
|:---|:---|:---|:---|
| **Container Formats** | Classic libpcap (`.pcap`), native PCAPng (`.pcapng` with SHB, IDB, EPB, SPB) | Multi-gigabyte continuous packet rings | `mergecap` / `editcap` |
| **Link Layers** | Ethernet II, Linux Cooked SLL (`LinkType 113`), BSD/Linux Loopback (`LinkType 0`), Raw IP (`LinkType 12`) | 802.11 Radiotap, ZigBee, CAN bus, Cellular radio frames | `tshark` / `aircrack-ng` |
| **Layer 3 / 4** | IPv4, IPv4 Defragmentation (RFC 791), IPv6 (RFC 5952 `::`), IPv6 Ext Header 44 Fragment Guard, TCP flags & stream reassembly, UDP datagrams | SCTP, IPsec ESP decryption | `tshark` / `snort` |
| **Layer 7 Protocols** | DNS (RFC 1035), HTTP/1.x, HTTP/2 Preface Detection (RFC 7540 fail-fast), TLS 1.0–1.3 ClientHello (SNI/JA3/JA4), RFC 6455 WebSocket (with RFC 7692 `permessage-deflate` flagging), QUIC v1 Initial (RFC 9001 AEAD) | Active Directory (SMB, Kerberos, DCE/RPC) — auto-tagged with handoff hints, HTTP/2 binary multiplexing (HPACK), SSH, RDP | `wireshark` / `zeek` |
| **Memory Capacity** | Max 10MB Base64, max 500MB local file buffer, max 10MB per TCP stream, **32MB global stream buffer ceiling** | Multi-gigabyte captures (&gt;500MB) exceeding V8 memory limits | `zeek` / `tshark -Y` |

---

## 🚀 Quick Start

### 1. Run with npx (stdio mode)

Add to your AI agent harness configuration (e.g. Claude Code, Cursor, Windsurf, or Strix):

```json
{
  "mcpServers": {
    "packet-chef": {
      "command": "npx",
      "args": ["-y", "@noorfatima123456/packet-chef-mcp@latest"]
    }
  }
}
```

### 2. Local Installation

```bash
git clone https://github.com/noorfatima123456/packet-chef-mcp.git
cd packet-chef-mcp
npm install
npm test
```

### 3. Running as Remote HTTP / SSE Server (Azure / Docker / Cloud)

```bash
# Launch on port 8080 (or specify PORT environment variable)
node server.js --http --port 8080
```

Accessible endpoints:
- `GET /` — Cyber-Dark status dashboard & interactive forensic sandbox
- `GET /health` — Health and liveness probe (`{"status":"ok","tools":15}`)
- `GET /.well-known/mcp/server-card.json` — Model Context Protocol discovery metadata
- `GET /sse` — Server-Sent Events MCP endpoint
- `POST /messages` — JSON-RPC message gateway

---

## 🛠️ MCP Tools (15 Production Forensics Operations)

| Tool | Parameters | Description |
|:---|:---|:---|
| `packet_summary` | `input?: string` (base64)<br>`filePath?: string` (stdio only) | High-density forensic summary (<2KB JSON): total packets, duration, wire bytes, average packet size, protocol distribution (TCP/UDP/ICMP), unique source/dest IPs, and top 10 talkers. |
| `packet_list` | `input?: string`<br>`filePath?: string`<br>`offset?: number` (default 0)<br>`limit?: number` (default 20, max 100)<br>`protocol?: string` | Bounded, paginated list of packet metadata. Protects LLM context with clean summaries (index, timestamp, length, 5-tuple, protocol, flags) without raw byte dumping. |
| `packet_extract_conversations` | `input?: string`<br>`filePath?: string`<br>`limit?: number` (default 50, max 200) | Bidirectional 5-tuple conversation tracker. Ranks network flows by total bytes transferred and tracks full TCP flag lifecycles (`hasSYN`, `hasACK`, `hasFIN`, `hasRST`). |
| `packet_extract_dns` | `input?: string`<br>`filePath?: string`<br>`queryType?: string`<br>`limit?: number` (default 50, max 200) | Parses DNS queries and responses (RFC 1035) with label pointer loop protection. Ranks queried domains and decodes A, AAAA, CNAME, TXT, MX, and PTR records. |
| `packet_extract_http` | `input?: string`<br>`filePath?: string`<br>`method?: string`<br>`limit?: number` (default 20, max 100) | Reassembles TCP streams and extracts HTTP/1.x requests and responses. Parses methods, URIs, headers, status codes, chunked transfers, body previews (4KB cap), and cognitive guidance hints. |
| `packet_extract_tls_sni` | `input?: string`<br>`filePath?: string`<br>`limit?: number` (default 50, max 200) | Extracts Server Name Indication (SNI) hostnames and client metadata from TLS ClientHello handshakes. Ranks accessed domains by frequency without decrypting payload data. |
| `packet_detect_beacons` | `input?: string`<br>`filePath?: string`<br>`minConnections?: number` (default 8)<br>`includeBenign?: boolean` (default true) | Detects periodic C2 beacon communications using statistical time-delta variance (Coefficient of Variation, jitter %, median interval). Filters benign infrastructure (NTP, cloud IMDS, public resolvers) with confidence ratings (HIGH/MEDIUM/LOW). |
| `packet_detect_dns_tunneling` | `input?: string`<br>`filePath?: string`<br>`minSubdomains?: number` (default 15) | Identifies DNS data exfiltration and tunneling channels (dnscat2, iodine, Cobalt Strike DNS beacons). Analyzes Shannon character entropy, subdomain label lengths, character set encodings (hex/base32/base64), and CDN heuristics. |
| `packet_extract_credentials` | `input?: string`<br>`filePath?: string` | Hunts for cleartext and recoverable credentials in HTTP Basic / Digest headers, URL query parameters, form/JSON POST bodies, FTP USER/PASS commands, and SMTP authentication. |
| `packet_entropy` | `input?: string`<br>`filePath?: string`<br>`packetIndex?: number` | Calculates Shannon entropy (0.0 to 8.0 bits/byte) to evaluate payload randomness and distinguish between plaintext, structured data (JSON/HTML/code), and encrypted / compressed malware or C2 traffic. |
| `packet_ja3_fingerprints` | `input?: string`<br>`filePath?: string`<br>`limit?: number` (default 50, max 200) | Extracts and aggregates JA3, JA3S, and JA4 TLS client fingerprints with RFC 8701 GREASE filtering. Cross-references known malware and C2 signatures (Cobalt Strike, Metasploit, Sliver, Emotet). |
| `packet_extract_websocket` | `input?: string`<br>`filePath?: string`<br>`limit?: number` (default 50, max 200) | Reassembles TCP streams and parses RFC 6455 WebSocket frames. Automatically unmasks client-to-server payloads using 4-byte XOR keys and decodes UTF-8 / JSON messages. |
| `packet_extract_quic_sni` | `input?: string`<br>`filePath?: string`<br>`limit?: number` (default 50, max 200) | Inspects UDP 443 datagrams for QUIC (RFC 9000) Initial Handshake packets. Decodes variable-length integers and extracts TLS 1.3 ClientHello SNI hostnames, ALPN, and Connection IDs via RFC 9001 Initial Secret AEAD decryption. |
| `packet_filter_export` | `input?: string`<br>`filePath?: string`<br>`filterIp?: string`<br>`filterPort?: number`<br>`filterProtocol?: string`<br>`limit?: number` (default 1000) | Filters PCAP/PCAPng packet records by IP, port, protocol, or direction and serializes the matching slice into a standardized classic PCAP binary (base64-encoded). |
| `packet_to_zeek_logs` | `input?: string`<br>`filePath?: string`<br>`logTypes?: string[]` (default `["conn","dns","http"]`) | Exports connection, DNS, and HTTP events formatted in Zeek-compatible TSV schema (`conn.log`, `dns.log`, `http.log`) for structured SIEM ingestion. |

---

## 🛡️ Forensic Guardrails & Security
 
 - **Truth-in-Triage Coverage Envelope:** Automatically reports `inspectionCoverageRatio`, `uninspectedVolumeRatio`, `analyzedProtocols`, and `uninspectedCategories` to eliminate silent false negatives for autonomous AI agents.
 - **HTTP/2 Fail-Fast Detection:** Detects RFC 7540 client connection preface (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`) and provides surgical native `tshark` command line strings.
 - **RFC 7692 WebSocket Compression Flagging:** Identifies `permessage-deflate` and RSV1 bits, flagging compressed binary frames with explicit handoff recommendations to `cyberchef_gunzip`.
 - **IPv6 Extension Header 44 Fragment Guard:** Parses fragment offset and flags continuation slices to suppress corrupt L4 payload parsing.
 - **Global Stream Memory Ceiling:** Enforces a strict 32MB global ceiling across all concurrent reassembled TCP streams with proactive LRU eviction to prevent memory exhaustion under attack.
 - **PCAPng Auto-Detection:** Seamlessly parses Section Header Blocks (`0x0A0D0D0A`), Interface Description Blocks (`0x00000001`), Enhanced Packet Blocks (`0x00000006`), and Simple Packet Blocks (`0x00000003`) with microsecond/nanosecond timestamps.
 - **Linux Cooked SLL (LinkType 113) Support:** Captures created via `tcpdump -i any` are natively parsed without requiring `tcprewrite` normalization.
 - **Crash Hardening:** Isolated try-catch boundaries per packet frame and verified with 100-round random fuzzing payloads to safeguard agent execution against corrupted captures.
 - **Dual Transport Guardrails:** Council-certified security prevents Local File Inclusion (LFI). When running over remote `HTTP/SSE`, filesystem access via `filePath` is strictly blocked.
 - **Council Benign Infrastructure Tagging:** Automatic recognition and down-ranking of legitimate cloud pulses (169.254.169.254 IMDS, NTP port 123, public resolvers) to prevent false alerts.

---

## 🧪 Testing

Run the comprehensive unit, integration, and fuzz test suite:

```bash
npm test
```

Test coverage includes **94 automated tests** across 34 categories:
- Little-endian and Big-endian PCAP headers (microsecond & nanosecond)
- Native PCAPng block reader (SHB, IDB, EPB, SPB)
- Multi-Link Layer decoders (Ethernet II, Linux Cooked SLL 113, Loopback 0, Raw IP 12)
- 802.1Q single and 802.1ad QinQ double VLAN encapsulation
- Fragmented IPv4 packet detection & IPv6 RFC 5952 `::` address zero-compression
- TCP flag decoding & UDP datagram validation
- Transport security (LFI prevention in HTTP mode)
- Full TCP stream reassembly (in-order, out-of-order, deduplication, overlapping segment trimming, state lifecycle tracking)
- RFC 1035 DNS parsing (A, AAAA, TXT records, label compression pointer resolution, loop protection)
- HTTP/1.x parsing (GET/POST, Content-Length, Chunked encoding, response statuses, body previews, automated forensic hints)
- TLS ClientHello SNI extraction and metadata parsing
- JA3, JA3S & JA4 TLS fingerprinting with RFC 8701 GREASE filtering and signature attribution
- RFC 6455 WebSocket frame unmasking and JSON payload decoding
- QUIC & HTTP/3 Initial Packet SNI extraction on UDP 443
- C2 beacon detection (Coefficient of Variation, jitter %, median interval, benign service tagging)
- DNS tunneling detection (Shannon character entropy, label lengths, hex/base32/base64 profiling, CDN filtering)
- Cleartext credential hunting (HTTP Basic, Digest, query params, POST bodies, FTP USER/PASS, SMTP AUTH)
- Shannon entropy payload randomness classification (0.0 to 8.0 bits/byte)
- Filtered PCAP binary generator (`packet_filter_export`)
- Standardized Zeek TSV log generator (`packet_to_zeek_logs`)
- Enterprise protocol triage banners (SMB, Kerberos handoff hints)
- RFC 791 IPv4 defragmentation engine
- Capture safety guardrails & truncation limits
- HTTP/2 connection preface detection & fail-fast triage
- RFC 7692 WebSocket compression flagging (`permessage-deflate`)
- IPv6 Extension Header 44 fragment guard
- Truth-in-Triage coverage envelope (`inspectionCoverageRatio`)
- Global 32MB stream buffer memory ceiling
- DNS-over-TCP 2-byte prefix handling (RFC 1035 §4.2.2 & RFC 7766)
- Mid-stream inverted capture orientation recovery (auto-detect request/response swap)
- Duplicate / retransmitted SYN stream sequence immunity
- Chained IPv6 extension header traversal (Hop-by-Hop, Routing, Destination Options)
- URLSearchParams & JSON multi-word credential extraction
- 100-round pseudo-random byte fuzzing (zero crashes)

---

## 📄 License

Apache-2.0 © 2026 Noor Fatima
