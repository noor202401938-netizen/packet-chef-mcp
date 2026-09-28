export const SERVER_CARD = {
  "serverInfo": {
    "name": "packet-chef-mcp",
    "version": "2.0.1"
  },
  "authentication": {
    "required": false
  },
  "tools": [
    {
      "name": "packet_summary",
      "description": "High-density L3–L7 triage summary (<2KB JSON). Fast reconnaissance of packet totals, talkers, DNS/HTTP/TLS volumes, and warnings for unparsed enterprise protocols (SMB, Kerberos, SSH).",
      "inputSchema": {
        "type": "object",
        "properties": {
          "input": {
            "type": "string",
            "description": "Base64-encoded PCAP file bytes (max 10MB). Supported across both local and remote deployments."
          },
          "filePath": {
            "type": "string",
            "description": "Absolute filesystem path to a PCAP file (up to 500MB). Allowed ONLY on local stdio connections; rejected in remote HTTP/SSE mode."
          }
        }
      }
    },
    {
      "name": "packet_list",
      "description": "Returns a paginated list of packet summary records from a PCAP capture. Enforces strict LLM context limits with default limit 20 and max 100.",
      "inputSchema": {
        "type": "object",
        "properties": {
          "input": {
            "type": "string",
            "description": "Base64-encoded PCAP file bytes (max 10MB)."
          },
          "filePath": {
            "type": "string",
            "description": "Absolute path to a PCAP file on disk (local stdio only)."
          },
          "offset": {
            "type": "number",
            "description": "Zero-based packet index offset for pagination (default: 0)."
          },
          "limit": {
            "type": "number",
            "description": "Maximum number of packets to return (default: 20, max: 100)."
          },
          "protocol": {
            "type": "string",
            "description": "Optional protocol filter ('TCP', 'UDP', 'ICMP', 'DNS', 'HTTP', 'TLS')."
          }
        }
      }
    },
    {
      "name": "packet_extract_conversations",
      "description": "Aggregates and tracks bidirectional 5-tuple conversations (src/dst IP, ports, protocol). Computes sent/received packet and byte counts, duration, and TCP flag lifecycles (SYN/ACK/FIN/RST). Ranked by total bytes transferred.",
      "inputSchema": {
        "type": "object",
        "properties": {
          "input": {
            "type": "string",
            "description": "Base64-encoded PCAP file bytes (max 10MB)."
          },
          "filePath": {
            "type": "string",
            "description": "Absolute path to a PCAP file on disk (local stdio only)."
          },
          "limit": {
            "type": "number",
            "description": "Maximum number of conversations to return (default: 50, max: 200)."
          }
        }
      }
    },
    {
      "name": "packet_extract_dns",
      "description": "Extracts and parses DNS queries and responses (RFC 1035) with label pointer loop protection. Aggregates query counts, unique domain rankings, and transaction details (A, AAAA, CNAME, TXT, MX, PTR).",
      "inputSchema": {
        "type": "object",
        "properties": {
          "input": {
            "type": "string",
            "description": "Base64-encoded PCAP file bytes (max 10MB)."
          },
          "filePath": {
            "type": "string",
            "description": "Absolute path to a PCAP file on disk (local stdio only)."
          },
          "queryType": {
            "type": "string",
            "description": "Optional query type filter (e.g. 'A', 'AAAA', 'TXT', 'CNAME')."
          },
          "limit": {
            "type": "number",
            "description": "Maximum number of DNS transactions to return (default: 50, max: 200)."
          }
        }
      }
    },
    {
      "name": "packet_extract_http",
      "description": "Reassembles TCP streams and extracts HTTP/1.x requests and responses. Parses method, URI, headers, status codes, chunked transfers, body previews (4KB cap), and cognitive guidance hints.",
      "inputSchema": {
        "type": "object",
        "properties": {
          "input": {
            "type": "string",
            "description": "Base64-encoded PCAP file bytes (max 10MB)."
          },
          "filePath": {
            "type": "string",
            "description": "Absolute path to a PCAP file on disk (local stdio only)."
          },
          "method": {
            "type": "string",
            "description": "Optional HTTP method filter (e.g. 'GET', 'POST')."
          },
          "limit": {
            "type": "number",
            "description": "Maximum number of HTTP transactions to return (default: 20, max: 100)."
          }
        }
      }
    },
    {
      "name": "packet_extract_tls_sni",
      "description": "Extracts Server Name Indication (SNI) hostnames and client metadata from TLS ClientHello handshakes. Ranks accessed domains by frequency without decrypting payload data.",
      "inputSchema": {
        "type": "object",
        "properties": {
          "input": {
            "type": "string",
            "description": "Base64-encoded PCAP file bytes (max 10MB)."
          },
          "filePath": {
            "type": "string",
            "description": "Absolute path to a PCAP file on disk (local stdio only)."
          },
          "limit": {
            "type": "number",
            "description": "Maximum number of TLS handshakes to return (default: 50, max: 200)."
          }
        }
      }
    },
    {
      "name": "packet_detect_beacons",
      "description": "Detects periodic C2 beacon communications using statistical time-delta variance (Coefficient of Variation, jitter %, median interval). Filters benign infrastructure (NTP, cloud IMDS, public resolvers) with confidence ratings (HIGH/MEDIUM/LOW).",
      "inputSchema": {
        "type": "object",
        "properties": {
          "input": {
            "type": "string",
            "description": "Base64-encoded PCAP file bytes (max 10MB)."
          },
          "filePath": {
            "type": "string",
            "description": "Absolute path to a PCAP file on disk (local stdio only)."
          },
          "minConnections": {
            "type": "number",
            "description": "Minimum recurring connection attempts to evaluate (default: 8)."
          },
          "includeBenign": {
            "type": "boolean",
            "description": "Whether to include tagged benign services in the output (default: true)."
          }
        }
      }
    },
    {
      "name": "packet_detect_dns_tunneling",
      "description": "Identifies DNS data exfiltration and tunneling channels (e.g. dnscat2, iodine, Cobalt Strike DNS beacons). Analyzes Shannon character entropy, subdomain label lengths, character set encodings (hex/base32/base64), and CDN heuristics.",
      "inputSchema": {
        "type": "object",
        "properties": {
          "input": {
            "type": "string",
            "description": "Base64-encoded PCAP file bytes (max 10MB)."
          },
          "filePath": {
            "type": "string",
            "description": "Absolute path to a PCAP file on disk (local stdio only)."
          },
          "minSubdomains": {
            "type": "number",
            "description": "Minimum unique subdomains under a parent domain to trigger analysis (default: 15)."
          }
        }
      }
    },
    {
      "name": "packet_extract_credentials",
      "description": "Hunts for cleartext and recoverable credentials in HTTP Basic / Digest headers, URL query parameters, form/JSON POST bodies, FTP USER/PASS commands, and SMTP authentication.",
      "inputSchema": {
        "type": "object",
        "properties": {
          "input": {
            "type": "string",
            "description": "Base64-encoded PCAP file bytes (max 10MB)."
          },
          "filePath": {
            "type": "string",
            "description": "Absolute path to a PCAP file on disk (local stdio only)."
          }
        }
      }
    },
    {
      "name": "packet_entropy",
      "description": "Calculates Shannon entropy (0.0 to 8.0 bits/byte) to evaluate payload randomness and distinguish between plaintext, structured data (JSON/HTML/code), and encrypted / compressed malware or C2 traffic.",
      "inputSchema": {
        "type": "object",
        "properties": {
          "input": {
            "type": "string",
            "description": "Base64-encoded PCAP file bytes (max 10MB)."
          },
          "filePath": {
            "type": "string",
            "description": "Absolute path to a PCAP file on disk (local stdio only)."
          },
          "packetIndex": {
            "type": "number",
            "description": "Optional zero-based packet index to calculate entropy for a single packet payload."
          }
        }
      }
    },
    {
      "name": "packet_ja3_fingerprints",
      "description": "Extracts and aggregates JA3, JA3S, and JA4 TLS client fingerprints across the capture. Correlates hashes against known C2 frameworks (Cobalt Strike, Metasploit, Sliver) and automation tools.",
      "inputSchema": {
        "type": "object",
        "properties": {
          "input": {
            "type": "string",
            "description": "Base64-encoded PCAP/PCAPng file bytes (max 10MB)."
          },
          "filePath": {
            "type": "string",
            "description": "Absolute path to a PCAP/PCAPng file on disk (local stdio only)."
          },
          "limit": {
            "type": "number",
            "description": "Maximum unique fingerprints to return (default 50)."
          }
        }
      }
    },
    {
      "name": "packet_extract_websocket",
      "description": "Reassembles TCP streams and parses RFC 6455 WebSocket frames, unmasking client payloads and decoding text/JSON messages for persistent C2 or chat triage.",
      "inputSchema": {
        "type": "object",
        "properties": {
          "input": {
            "type": "string",
            "description": "Base64-encoded PCAP/PCAPng file bytes (max 10MB)."
          },
          "filePath": {
            "type": "string",
            "description": "Absolute path to a PCAP/PCAPng file on disk (local stdio only)."
          },
          "limit": {
            "type": "number",
            "description": "Maximum WebSocket frames to return (default 50)."
          }
        }
      }
    },
    {
      "name": "packet_extract_quic_sni",
      "description": "Extracts SNI hostnames, ALPN tags, and Connection IDs (DCID/SCID) from QUIC v1 / HTTP/3 Initial packets over UDP (port 443) via RFC 9001 Section 5.2 Initial Secret AEAD decryption.",
      "inputSchema": {
        "type": "object",
        "properties": {
          "input": {
            "type": "string",
            "description": "Base64-encoded PCAP/PCAPng file bytes (max 10MB)."
          },
          "filePath": {
            "type": "string",
            "description": "Absolute path to a PCAP/PCAPng file on disk (local stdio only)."
          },
          "limit": {
            "type": "number",
            "description": "Maximum QUIC handshakes to return (default 50)."
          }
        }
      }
    },
    {
      "name": "packet_filter_export",
      "description": "Filters PCAP/PCAPng traffic by IP address, port, protocol, or time window and exports a clean, RFC-compliant classic PCAP binary (base64 or saved to disk).",
      "inputSchema": {
        "type": "object",
        "properties": {
          "input": {
            "type": "string",
            "description": "Base64-encoded PCAP/PCAPng file bytes (max 10MB)."
          },
          "filePath": {
            "type": "string",
            "description": "Absolute path to a PCAP/PCAPng file on disk (local stdio only)."
          },
          "ip": {
            "type": "string",
            "description": "Filter by IP address (matches either source or destination)."
          },
          "port": {
            "type": "number",
            "description": "Filter by port number (matches source or destination)."
          },
          "protocol": {
            "type": "string",
            "description": "Filter by transport/app protocol (TCP, UDP, ICMP, DNS, HTTP, TLS, ALL)."
          },
          "limit": {
            "type": "number",
            "description": "Maximum matched packets to export (default 1000)."
          }
        }
      }
    },
    {
      "name": "packet_to_zeek_logs",
      "description": "Exports connection, DNS, and HTTP events formatted in Zeek-compatible TSV schema (conn.log, dns.log, http.log) for SIEM ingestion into Splunk, ELK, or Wazuh. (Note: Generates TSV schemas, does not execute Zeek scripting engine).",
      "inputSchema": {
        "type": "object",
        "properties": {
          "input": {
            "type": "string",
            "description": "Base64-encoded PCAP/PCAPng file bytes (max 10MB)."
          },
          "filePath": {
            "type": "string",
            "description": "Absolute path to a PCAP/PCAPng file on disk (local stdio only)."
          }
        }
      }
    }
  ]
};
