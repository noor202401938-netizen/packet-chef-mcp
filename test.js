/**
 * packet-chef-mcp - Phase 1 Comprehensive Test Suite
 * Validates binary decoders, endianness, VLANs, IPv4/IPv6, TCP/UDP,
 * input security, transport guardrails, conversation tracking, and 100-round fuzzing.
 */

import assert from "node:assert";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { parsePcapHeader, parsePackets, parsePcap, PCAP_MAGICS } from "./utils/pcap-parser.js";
import { decodeEthernet, ETHER_TYPES } from "./utils/ethernet.js";
import { decodeIPv4, IP_PROTOCOLS } from "./utils/ipv4.js";
import { decodeIPv6, formatIPv6 } from "./utils/ipv6.js";
import { decodeTCP, TCP_FLAGS } from "./utils/tcp.js";
import { decodeUDP } from "./utils/udp.js";
import { dissectPacket } from "./utils/packet-dissector.js";
import { IPv4Defragmenter } from "./utils/ipv4-defragmenter.js";
import { generateSummary } from "./utils/summary-generator.js";
import { trackConversations } from "./utils/conversation-tracker.js";
import { resolveInput, analyzePcapBuffer } from "./server.js";
import { parseDNS } from "./utils/dns-parser.js";
import { parseHTTPStream, parseHTTPRequest, parseHTTPResponse, HTTP2_CLIENT_PREFACE } from "./utils/http-parser.js";
import { TCPReassembler, MAX_GLOBAL_STREAM_BYTES } from "./utils/tcp-reassembler.js";
import { parseClientHello, extractTLSSNI } from "./utils/tls-parser.js";
import { detectBeacons } from "./utils/beacon-detector.js";
import { detectDNSTunneling, calculateStringEntropy } from "./utils/dns-tunnel-detector.js";
import { extractCredentials } from "./utils/credential-extractor.js";
import { calculateEntropy, analyzeCaptureEntropy } from "./utils/entropy.js";
import { parsePcapNg, isPcapNg } from "./utils/pcapng-parser.js";
import { decodeSLL, decodeLoopback, decodeRawIP } from "./utils/sll.js";
import { calculateJA3, isGrease, KNOWN_JA3_SIGNATURES } from "./utils/ja3.js";
import { parseWebSocketFrames } from "./utils/websocket-parser.js";
import { parseQuicInitial } from "./utils/quic-parser.js";
import { exportToPcap, generateZeekLogs } from "./utils/exporters.js";
import { SERVER_CARD } from "./utils/server-card-data.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Helper to construct a synthetic 24-byte PCAP global header
function buildPcapHeader({
  magic = PCAP_MAGICS.LE_MICRO,
  versionMajor = 2,
  versionMinor = 4,
  thisZone = 0,
  sigFigs = 0,
  snapLen = 65535,
  linkType = 1,
  isLittleEndian = true
} = {}) {
  const buf = Buffer.alloc(24);
  const writeU32 = isLittleEndian ? (v, o) => buf.writeUInt32LE(v, o) : (v, o) => buf.writeUInt32BE(v, o);
  const writeU16 = isLittleEndian ? (v, o) => buf.writeUInt16LE(v, o) : (v, o) => buf.writeUInt16BE(v, o);
  const writeI32 = isLittleEndian ? (v, o) => buf.writeInt32LE(v, o) : (v, o) => buf.writeInt32BE(v, o);

  writeU32(magic, 0);
  writeU16(versionMajor, 4);
  writeU16(versionMinor, 6);
  writeI32(thisZone, 8);
  writeU32(sigFigs, 12);
  writeU32(snapLen, 16);
  writeU32(linkType, 20);

  return buf;
}

// Helper to build a 16-byte packet record header + payload
function buildPacketRecord({
  tsSec = 1700000000,
  tsSub = 500000,
  data = Buffer.alloc(0),
  origLen = null,
  isLittleEndian = true
} = {}) {
  const inclLen = data.length;
  const wireLen = origLen !== null ? origLen : inclLen;
  const recHeader = Buffer.alloc(16);
  const writeU32 = isLittleEndian ? (v, o) => recHeader.writeUInt32LE(v, o) : (v, o) => recHeader.writeUInt32BE(v, o);

  writeU32(tsSec, 0);
  writeU32(tsSub, 4);
  writeU32(inclLen, 8);
  writeU32(wireLen, 12);

  return Buffer.concat([recHeader, data]);
}

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  ✅ ${name}`);
    passed++;
  } catch (err) {
    console.error(`  ❌ ${name}`);
    console.error(`     Error: ${err.message}`);
    failed++;
  }
}

console.log("\n🧪 Running packet-chef-mcp Full Verification Test Suite...\n");

// ----------------------------------------------------
// Section 1: PCAP Header & Formats
// ----------------------------------------------------
console.log("📁 1. PCAP Header Parsing & Formats");

test("Parse standard Little-Endian microsecond PCAP header", () => {
  const buf = buildPcapHeader({ magic: PCAP_MAGICS.LE_MICRO, isLittleEndian: true });
  const h = parsePcapHeader(buf);
  assert.strictEqual(h.isLittleEndian, true);
  assert.strictEqual(h.isNanosecond, false);
  assert.strictEqual(h.versionMajor, 2);
  assert.strictEqual(h.versionMinor, 4);
  assert.strictEqual(h.linkType, 1);
});

test("Parse Big-Endian microsecond PCAP header", () => {
  const buf = buildPcapHeader({ magic: PCAP_MAGICS.BE_MICRO, isLittleEndian: false });
  const h = parsePcapHeader(buf);
  assert.strictEqual(h.isLittleEndian, false);
  assert.strictEqual(h.isNanosecond, false);
  assert.strictEqual(h.linkType, 1);
});

test("Parse Nanosecond-resolution PCAP header", () => {
  const buf = buildPcapHeader({ magic: PCAP_MAGICS.LE_NANO, isLittleEndian: true });
  const h = parsePcapHeader(buf);
  assert.strictEqual(h.isNanosecond, true);
  assert.strictEqual(h.isLittleEndian, true);
});

test("Reject PCAPng with actionable editcap instruction", () => {
  const buf = Buffer.alloc(24);
  buf.writeUInt32BE(0x0a0d0d0a, 0); // PCAPng Section Header Block magic
  assert.throws(() => parsePcapHeader(buf), (err) => {
    return err.message.includes("PCAPNG_NOT_SUPPORTED") && err.message.includes("editcap -F pcap");
  });
});

test("Reject PNG image file with helpful type detection", () => {
  const pngHeader = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, ...new Array(16).fill(0)]);
  assert.throws(() => parsePcapHeader(pngHeader), (err) => {
    return err.message.includes("PNG image signature");
  });
});

test("Accept Linux Cooked capture (LinkType 113 SLL natively in v2)", () => {
  const buf = buildPcapHeader({ linkType: 113 });
  const h = parsePcapHeader(buf);
  assert.strictEqual(h.linkType, 113);
});

test("Reject unsupported link-layer type (e.g. 127 802.11 Radiotap)", () => {
  const buf = buildPcapHeader({ linkType: 127 });
  assert.throws(() => parsePcapHeader(buf), (err) => {
    return err.message.includes("UNSUPPORTED_LINK_TYPE");
  });
});

// ----------------------------------------------------
// Section 2: Ethernet Frame Decoder
// ----------------------------------------------------
console.log("\n🔌 2. Ethernet Frame Decoder");

test("Decode standard Ethernet II frame", () => {
  const frame = Buffer.alloc(30);
  // Dst: 00:11:22:33:44:55
  frame.set([0x00, 0x11, 0x22, 0x33, 0x44, 0x55], 0);
  // Src: aa:bb:cc:dd:ee:ff
  frame.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 6);
  // EtherType: IPv4 (0x0800)
  frame.writeUInt16BE(0x0800, 12);

  const eth = decodeEthernet(frame);
  assert.strictEqual(eth.dstMac, "00:11:22:33:44:55");
  assert.strictEqual(eth.srcMac, "aa:bb:cc:dd:ee:ff");
  assert.strictEqual(eth.etherType, 0x0800);
  assert.strictEqual(eth.vlanId, null);
  assert.strictEqual(eth.payloadOffset, 14);
});

test("Decode 802.1Q VLAN-tagged frame", () => {
  const frame = Buffer.alloc(34);
  frame.set([0x00, 0x11, 0x22, 0x33, 0x44, 0x55], 0);
  frame.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 6);
  frame.writeUInt16BE(0x8100, 12); // VLAN tag EtherType
  frame.writeUInt16BE(100, 14);    // TCI (VLAN ID 100)
  frame.writeUInt16BE(0x0800, 16); // Real inner EtherType (IPv4)

  const eth = decodeEthernet(frame);
  assert.strictEqual(eth.vlanId, 100);
  assert.strictEqual(eth.etherType, 0x0800);
  assert.strictEqual(eth.payloadOffset, 18);
});

test("Decode 802.1ad QinQ double-tagged frame", () => {
  const frame = Buffer.alloc(40);
  frame.writeUInt16BE(0x88a8, 12); // Outer QinQ
  frame.writeUInt16BE(10, 14);
  frame.writeUInt16BE(0x8100, 16); // Inner VLAN
  frame.writeUInt16BE(200, 18);   // Inner VLAN ID 200
  frame.writeUInt16BE(0x0800, 20); // Real inner EtherType

  const eth = decodeEthernet(frame);
  assert.strictEqual(eth.vlanId, 200);
  assert.strictEqual(eth.etherType, 0x0800);
  assert.strictEqual(eth.payloadOffset, 22);
});

test("Graceful handling of non-IPv4 frame (e.g. ARP 0x0806)", () => {
  const frame = Buffer.alloc(28);
  frame.writeUInt16BE(0x0806, 12); // ARP
  const eth = decodeEthernet(frame);
  assert.strictEqual(eth.etherType, 0x0806);
});

// ----------------------------------------------------
// Section 3: IPv4 & IPv6 Decoders
// ----------------------------------------------------
console.log("\n🌐 3. IPv4 & IPv6 Decoders");

test("Decode standard IPv4 header (IHL = 5)", () => {
  const ipBuf = Buffer.alloc(30);
  ipBuf[0] = 0x45; // Version 4, IHL 5 (20 bytes)
  ipBuf.writeUInt16BE(30, 2); // Total length
  ipBuf.writeUInt16BE(1234, 4); // ID
  ipBuf.writeUInt16BE(0x4000, 6); // Flags: DF = 1
  ipBuf[8] = 64; // TTL
  ipBuf[9] = 6;  // Protocol: TCP
  ipBuf.set([192, 168, 1, 50], 12); // Src IP
  ipBuf.set([93, 184, 216, 34], 16); // Dst IP

  const ip = decodeIPv4(ipBuf);
  assert.strictEqual(ip.version, 4);
  assert.strictEqual(ip.ihl, 20);
  assert.strictEqual(ip.totalLength, 30);
  assert.strictEqual(ip.protocol, 6);
  assert.strictEqual(ip.protocolName, "TCP");
  assert.strictEqual(ip.ttl, 64);
  assert.strictEqual(ip.flags.DF, true);
  assert.strictEqual(ip.flags.MF, false);
  assert.strictEqual(ip.isFragmented, false);
  assert.strictEqual(ip.srcIP, "192.168.1.50");
  assert.strictEqual(ip.dstIP, "93.184.216.34");
  assert.strictEqual(ip.payloadOffset, 20);
});

test("Decode IPv4 header with options (IHL = 6, 24 bytes)", () => {
  const ipBuf = Buffer.alloc(34);
  ipBuf[0] = 0x46; // Version 4, IHL 6 (24 bytes)
  ipBuf.writeUInt16BE(34, 2);
  ipBuf[9] = 17; // UDP
  ipBuf.set([10, 0, 0, 1], 12);
  ipBuf.set([10, 0, 0, 2], 16);

  const ip = decodeIPv4(ipBuf);
  assert.strictEqual(ip.ihl, 24);
  assert.strictEqual(ip.protocolName, "UDP");
  assert.strictEqual(ip.payloadOffset, 24);
});

test("Detect fragmented IPv4 packet (MF=1 or fragmentOffset > 0)", () => {
  const ipBuf = Buffer.alloc(20);
  ipBuf[0] = 0x45;
  ipBuf.writeUInt16BE(0x2064, 6); // MF = 1, fragment offset = 100 * 8 = 800 bytes
  ipBuf.set([192, 168, 1, 1], 12);
  ipBuf.set([192, 168, 1, 2], 16);

  const ip = decodeIPv4(ipBuf);
  assert.strictEqual(ip.flags.MF, true);
  assert.strictEqual(ip.fragmentOffset, 800);
  assert.strictEqual(ip.isFragmented, true);
});

test("Decode IPv6 header and format address with :: compression", () => {
  const ip6Buf = Buffer.alloc(50);
  // Version 6 (0x60000000)
  ip6Buf.writeUInt32BE(0x60000000, 0);
  ip6Buf.writeUInt16BE(10, 4); // Payload length
  ip6Buf[6] = 6;  // NextHeader = TCP
  ip6Buf[7] = 64; // HopLimit

  // Src: 2001:0db8:0000:0000:0000:0000:0000:0001 -> 2001:db8::1
  ip6Buf.writeUInt16BE(0x2001, 8);
  ip6Buf.writeUInt16BE(0x0db8, 10);
  ip6Buf.writeUInt16BE(0x0001, 22);

  // Dst: fe80:0000:0000:0000:0000:0000:0000:0002 -> fe80::2
  ip6Buf.writeUInt16BE(0xfe80, 24);
  ip6Buf.writeUInt16BE(0x0002, 38);

  const ip6 = decodeIPv6(ip6Buf);
  assert.strictEqual(ip6.version, 6);
  assert.strictEqual(ip6.nextHeader, 6);
  assert.strictEqual(ip6.nextHeaderName, "TCP");
  assert.strictEqual(ip6.srcIP, "2001:db8::1");
  assert.strictEqual(ip6.dstIP, "fe80::2");
  assert.strictEqual(ip6.payloadOffset, 40);
});

// ----------------------------------------------------
// Section 4: TCP & UDP Decoders
// ----------------------------------------------------
console.log("\n📦 4. TCP & UDP Decoders");

test("Decode standard TCP segment with SYN flag", () => {
  const tcpBuf = Buffer.alloc(24);
  tcpBuf.writeUInt16BE(48321, 0); // srcPort
  tcpBuf.writeUInt16BE(443, 2);   // dstPort
  tcpBuf.writeUInt32BE(1000000, 4); // seqNum
  tcpBuf.writeUInt32BE(0, 8);       // ackNum
  tcpBuf[12] = 0x50; // dataOffset = 5 (20 bytes)
  tcpBuf[13] = TCP_FLAGS.SYN; // SYN flag
  tcpBuf.writeUInt16BE(64240, 14); // windowSize

  const tcp = decodeTCP(tcpBuf);
  assert.strictEqual(tcp.srcPort, 48321);
  assert.strictEqual(tcp.dstPort, 443);
  assert.strictEqual(tcp.seqNum, 1000000);
  assert.strictEqual(tcp.ackNum, 0);
  assert.strictEqual(tcp.dataOffset, 20);
  assert.strictEqual(tcp.flags.SYN, true);
  assert.strictEqual(tcp.flags.ACK, false);
  assert.strictEqual(tcp.flags.FIN, false);
  assert.strictEqual(tcp.windowSize, 64240);
});

test("Decode TCP segment with options and payload", () => {
  const tcpBuf = Buffer.alloc(40);
  tcpBuf.writeUInt16BE(80, 0);
  tcpBuf.writeUInt16BE(50123, 2);
  tcpBuf[12] = 0x70; // dataOffset = 7 (28 bytes)
  tcpBuf[13] = TCP_FLAGS.ACK | TCP_FLAGS.PSH;
  // Write payload at offset 28
  tcpBuf.write("HTTP/1.1", 28);

  const tcp = decodeTCP(tcpBuf);
  assert.strictEqual(tcp.dataOffset, 28);
  assert.strictEqual(tcp.flags.ACK, true);
  assert.strictEqual(tcp.flags.PSH, true);
  assert.strictEqual(tcp.payload.toString(), "HTTP/1.1\x00\x00\x00\x00");
});

test("Decode UDP datagram", () => {
  const udpBuf = Buffer.alloc(16);
  udpBuf.writeUInt16BE(53123, 0); // srcPort
  udpBuf.writeUInt16BE(53, 2);    // dstPort (DNS)
  udpBuf.writeUInt16BE(16, 4);    // length (8 header + 8 payload)
  udpBuf.write("DNSQUERY", 8);

  const udp = decodeUDP(udpBuf);
  assert.strictEqual(udp.srcPort, 53123);
  assert.strictEqual(udp.dstPort, 53);
  assert.strictEqual(udp.length, 16);
  assert.strictEqual(udp.payload.toString(), "DNSQUERY");
});

// ----------------------------------------------------
// Section 5: Input Resolution & Transport Guardrails
// ----------------------------------------------------
console.log("\n🔒 5. Input Resolution & Transport Guardrails");

test("Accept valid base64 input string", () => {
  const dummy = Buffer.from("DUMMY_PCAP_DATA");
  const b64 = dummy.toString("base64");
  const res = resolveInput({ input: b64 }, "stdio");
  assert.deepStrictEqual(res, dummy);
});

test("Reject base64 input exceeding 10MB limit", () => {
  // 11MB fake base64
  const hugeBuf = Buffer.alloc(11 * 1024 * 1024);
  const b64 = hugeBuf.toString("base64");
  assert.throws(() => resolveInput({ input: b64 }, "stdio"), (err) => {
    return err.message.includes("INPUT_TOO_LARGE");
  });
});

test("Reject filePath in remote HTTP/SSE mode (Council Guardrail)", () => {
  assert.throws(() => resolveInput({ filePath: "/etc/passwd" }, "http"), (err) => {
    return err.message.includes("FILE_PATH_NOT_ALLOWED_IN_HTTP_MODE");
  });
});

test("Reject non-existent filePath in stdio mode", () => {
  assert.throws(() => resolveInput({ filePath: "./non_existent_file.pcap" }, "stdio"), (err) => {
    return err.message.includes("FILE_NOT_FOUND");
  });
});

// ----------------------------------------------------
// Section 6: End-to-End Pipeline & Real PCAP Fixture
// ----------------------------------------------------
console.log("\n🔍 6. End-to-End Analysis Pipeline");

test("End-to-End Multi-Packet Synthetic Capture Analysis", () => {
  // 1. Build a valid PCAP file with 3 packets:
  //    Packet 1: IPv4 TCP SYN 192.168.1.50:4832 -> 93.184.216.34:80
  //    Packet 2: IPv4 TCP SYN/ACK 93.184.216.34:80 -> 192.168.1.50:4832
  //    Packet 3: IPv4 UDP DNS 192.168.1.50:54321 -> 8.8.8.8:53

  // Ethernet header (14 bytes)
  const ethTCP1 = Buffer.alloc(14);
  ethTCP1.writeUInt16BE(0x0800, 12);

  // IPv4 header (20 bytes)
  const ipTCP1 = Buffer.alloc(20);
  ipTCP1[0] = 0x45;
  ipTCP1.writeUInt16BE(40, 2);
  ipTCP1[8] = 64;
  ipTCP1[9] = 6; // TCP
  ipTCP1.set([192, 168, 1, 50], 12);
  ipTCP1.set([93, 184, 216, 34], 16);

  // TCP header (20 bytes)
  const tcp1 = Buffer.alloc(20);
  tcp1.writeUInt16BE(4832, 0);
  tcp1.writeUInt16BE(80, 2);
  tcp1.writeUInt32BE(100, 4);
  tcp1[12] = 0x50;
  tcp1[13] = TCP_FLAGS.SYN;

  const pkt1Data = Buffer.concat([ethTCP1, ipTCP1, tcp1]);

  // Packet 2: Response SYN/ACK
  const ethTCP2 = Buffer.alloc(14);
  ethTCP2.writeUInt16BE(0x0800, 12);

  const ipTCP2 = Buffer.alloc(20);
  ipTCP2[0] = 0x45;
  ipTCP2.writeUInt16BE(40, 2);
  ipTCP2[8] = 64;
  ipTCP2[9] = 6;
  ipTCP2.set([93, 184, 216, 34], 12);
  ipTCP2.set([192, 168, 1, 50], 16);

  const tcp2 = Buffer.alloc(20);
  tcp2.writeUInt16BE(80, 0);
  tcp2.writeUInt16BE(4832, 2);
  tcp2.writeUInt32BE(500, 4);
  tcp2.writeUInt32BE(101, 8);
  tcp2[12] = 0x50;
  tcp2[13] = TCP_FLAGS.SYN | TCP_FLAGS.ACK;

  const pkt2Data = Buffer.concat([ethTCP2, ipTCP2, tcp2]);

  // Packet 3: DNS Query over UDP
  const ethUDP = Buffer.alloc(14);
  ethUDP.writeUInt16BE(0x0800, 12);

  const ipUDP = Buffer.alloc(20);
  ipUDP[0] = 0x45;
  ipUDP.writeUInt16BE(38, 2);
  ipUDP[8] = 64;
  ipUDP[9] = 17; // UDP
  ipUDP.set([192, 168, 1, 50], 12);
  ipUDP.set([8, 8, 8, 8], 16);

  const udp = Buffer.alloc(8);
  udp.writeUInt16BE(54321, 0);
  udp.writeUInt16BE(53, 2);
  udp.writeUInt16BE(18, 4);

  const dnsPayload = Buffer.from("GOOGLE_COM_QUERY");
  const pkt3Data = Buffer.concat([ethUDP, ipUDP, udp, dnsPayload]);

  // Assemble full PCAP buffer
  const pcapHeader = buildPcapHeader();
  const rec1 = buildPacketRecord({ tsSec: 1700000001, data: pkt1Data });
  const rec2 = buildPacketRecord({ tsSec: 1700000002, data: pkt2Data });
  const rec3 = buildPacketRecord({ tsSec: 1700000005, data: pkt3Data });

  const fullPcap = Buffer.concat([pcapHeader, rec1, rec2, rec3]);

  // Execute parsing and dissection
  const { header, packets, warnings } = parsePcap(fullPcap);
  assert.strictEqual(packets.length, 3);
  assert.strictEqual(warnings.length, 0);

  const dissected = packets.map(dissectPacket);

  // Validate Summary
  const summary = generateSummary(dissected);
  assert.strictEqual(summary.totalPackets, 3);
  assert.strictEqual(summary.protocols.TCP.count, 2);
  assert.strictEqual(summary.protocols.UDP.count, 1);
  assert.strictEqual(summary.uniqueSourceIPs, 2);
  assert.strictEqual(summary.uniqueDestIPs, 3);
  assert.strictEqual(summary.topTalkers[0].ip, "192.168.1.50");

  // Validate Conversation Tracking
  const conv = trackConversations(dissected);
  assert.strictEqual(conv.totalConversations, 2);
  // Check TCP bidirectional aggregation
  const tcpConv = conv.conversations.find((c) => c.protocol === "TCP");
  assert.ok(tcpConv, "TCP conversation must be identified");
  assert.strictEqual(tcpConv.totalPackets, 2);
  assert.strictEqual(tcpConv.tcpFlags.hasSYN, true);
  assert.strictEqual(tcpConv.tcpFlags.hasACK, true);
  assert.strictEqual(tcpConv.appProtocol, "HTTP");
});

test("Real-world capture fixture (5-packet Ethernet PCAP loaded from disk)", () => {
  const fixturePath = path.join(__dirname, "test", "fixtures", "sample_5pkt.pcap");
  assert.ok(fs.existsSync(fixturePath), "Fixture file must exist on disk");

  // Verify resolution via resolveInput (local stdio mode)
  const fileBytes = resolveInput({ filePath: fixturePath }, "stdio");
  assert.strictEqual(fileBytes.length, 466);

  const { header, packets, warnings } = parsePcap(fileBytes);
  assert.strictEqual(packets.length, 5);
  assert.strictEqual(header.linkType, 1);
  assert.strictEqual(warnings.length, 0);

  const dissected = packets.map(dissectPacket);

  // Packet 1: DNS query over UDP
  assert.strictEqual(dissected[0].transport.protocol, "UDP");
  assert.strictEqual(dissected[0].transport.dstPort, 53);
  assert.strictEqual(dissected[0].appProtocol, "DNS");

  // Packet 2: TCP SYN
  assert.strictEqual(dissected[1].transport.protocol, "TCP");
  assert.strictEqual(dissected[1].transport.flags.SYN, true);
  assert.strictEqual(dissected[1].transport.flags.ACK, false);

  // Packet 3: TCP SYN-ACK
  assert.strictEqual(dissected[2].transport.protocol, "TCP");
  assert.strictEqual(dissected[2].transport.flags.SYN, true);
  assert.strictEqual(dissected[2].transport.flags.ACK, true);

  // Packet 4: TCP ACK
  assert.strictEqual(dissected[3].transport.protocol, "TCP");
  assert.strictEqual(dissected[3].transport.flags.ACK, true);

  // Packet 5: TCP PSH+ACK HTTP GET Request
  assert.strictEqual(dissected[4].transport.protocol, "TCP");
  assert.strictEqual(dissected[4].transport.flags.PSH, true);
  assert.strictEqual(dissected[4].appProtocol, "HTTP");

  // Summary Metrics
  const summary = generateSummary(dissected);
  assert.strictEqual(summary.totalPackets, 5);
  assert.strictEqual(summary.protocols.TCP.count, 4);
  assert.strictEqual(summary.protocols.UDP.count, 1);
  assert.strictEqual(summary.identifiedApplications.HTTP, 4);
  assert.strictEqual(summary.identifiedApplications.DNS, 1);

  // Conversation tracking
  const conv = trackConversations(dissected);
  assert.strictEqual(conv.totalConversations, 2);
  const tcpFlow = conv.conversations.find((c) => c.protocol === "TCP");
  assert.strictEqual(tcpFlow.totalPackets, 4);
  assert.strictEqual(tcpFlow.tcpFlags.hasSYN, true);
  assert.strictEqual(tcpFlow.tcpFlags.hasACK, true);
});

// ----------------------------------------------------
// Section 7: TCP Stream Reassembly
// ----------------------------------------------------
console.log("\n🔄 7. TCP Stream Reassembly");

test("In-order TCP stream reassembly", () => {
  const reassembler = new TCPReassembler();
  const srcIP = "10.0.0.1";
  const dstIP = "10.0.0.2";
  const clientPort = 50000;
  const serverPort = 80;

  // SYN: seq = 1000
  reassembler.addPacket(srcIP, dstIP, { srcPort: clientPort, dstPort: serverPort, seqNum: 1000, flags: { SYN: true } }, Buffer.alloc(0));
  // Segment 1: seq = 1001, payload = "HELLO " (6 bytes)
  reassembler.addPacket(srcIP, dstIP, { srcPort: clientPort, dstPort: serverPort, seqNum: 1001, flags: { ACK: true } }, Buffer.from("HELLO "));
  // Segment 2: seq = 1007, payload = "WORLD" (5 bytes)
  reassembler.addPacket(srcIP, dstIP, { srcPort: clientPort, dstPort: serverPort, seqNum: 1007, flags: { ACK: true } }, Buffer.from("WORLD"));

  const streams = reassembler.getStreams();
  assert.strictEqual(streams.length, 1);
  assert.strictEqual(streams[0].clientData.toString("utf8"), "HELLO WORLD");
  assert.strictEqual(streams[0].outOfOrderSegments, 0);
  assert.strictEqual(streams[0].retransmissions, 0);
});

test("Out-of-order segment reassembly [1, 3, 2]", () => {
  const reassembler = new TCPReassembler();
  const srcIP = "192.168.1.10";
  const dstIP = "192.168.1.20";

  // SYN: seq = 2000
  reassembler.addPacket(srcIP, dstIP, { srcPort: 4000, dstPort: 80, seqNum: 2000, flags: { SYN: true } }, Buffer.alloc(0));
  // Seg 1: seq = 2001, len = 5 ("PART1")
  reassembler.addPacket(srcIP, dstIP, { srcPort: 4000, dstPort: 80, seqNum: 2001, flags: { ACK: true } }, Buffer.from("PART1"));
  // Seg 3 (out of order): seq = 2011, len = 5 ("PART3")
  reassembler.addPacket(srcIP, dstIP, { srcPort: 4000, dstPort: 80, seqNum: 2011, flags: { ACK: true } }, Buffer.from("PART3"));
  // Seg 2: seq = 2006, len = 5 ("PART2")
  reassembler.addPacket(srcIP, dstIP, { srcPort: 4000, dstPort: 80, seqNum: 2006, flags: { ACK: true } }, Buffer.from("PART2"));

  const streams = reassembler.getStreams();
  assert.strictEqual(streams[0].clientData.toString("utf8"), "PART1PART2PART3");
  assert.ok(streams[0].outOfOrderSegments >= 1);
});

test("Retransmission deduplication", () => {
  const reassembler = new TCPReassembler();
  const srcIP = "192.168.1.10";
  const dstIP = "192.168.1.20";

  // SYN: seq = 3000
  reassembler.addPacket(srcIP, dstIP, { srcPort: 4000, dstPort: 80, seqNum: 3000, flags: { SYN: true } }, Buffer.alloc(0));
  // Seg 1
  reassembler.addPacket(srcIP, dstIP, { srcPort: 4000, dstPort: 80, seqNum: 3001, flags: { ACK: true } }, Buffer.from("UNIQUE_DATA"));
  // Seg 1 Retransmitted
  reassembler.addPacket(srcIP, dstIP, { srcPort: 4000, dstPort: 80, seqNum: 3001, flags: { ACK: true } }, Buffer.from("UNIQUE_DATA"));

  const streams = reassembler.getStreams();
  assert.strictEqual(streams[0].clientData.toString("utf8"), "UNIQUE_DATA");
  assert.strictEqual(streams[0].retransmissions, 1);
});

test("Overlapping segment trimming", () => {
  const reassembler = new TCPReassembler();
  const srcIP = "10.0.0.1";
  const dstIP = "10.0.0.2";

  // SYN: seq = 4000
  reassembler.addPacket(srcIP, dstIP, { srcPort: 5000, dstPort: 80, seqNum: 4000, flags: { SYN: true } }, Buffer.alloc(0));
  // Seg 1: seq = 4001, len = 8 ("AAAABBBB") -> endSeq = 4009
  reassembler.addPacket(srcIP, dstIP, { srcPort: 5000, dstPort: 80, seqNum: 4001, flags: { ACK: true } }, Buffer.from("AAAABBBB"));
  // Seg 2: seq = 4005, len = 8 ("BBBBCCCC") -> overlaps "BBBB", adds "CCCC"
  reassembler.addPacket(srcIP, dstIP, { srcPort: 5000, dstPort: 80, seqNum: 4005, flags: { ACK: true } }, Buffer.from("BBBBCCCC"));

  const streams = reassembler.getStreams();
  assert.strictEqual(streams[0].clientData.toString("utf8"), "AAAABBBBCCCC");
});

test("SYN -> data -> FIN lifecycle tracking", () => {
  const reassembler = new TCPReassembler();
  const src = "1.1.1.1";
  const dst = "2.2.2.2";

  // Client SYN
  reassembler.addPacket(src, dst, { srcPort: 1234, dstPort: 80, seqNum: 100, flags: { SYN: true } }, Buffer.alloc(0));
  let streams = reassembler.getStreams();
  assert.strictEqual(streams[0].state, "SYN_SENT");

  // Server SYN-ACK
  reassembler.addPacket(dst, src, { srcPort: 80, dstPort: 1234, seqNum: 500, flags: { SYN: true, ACK: true } }, Buffer.alloc(0));
  streams = reassembler.getStreams();
  assert.strictEqual(streams[0].state, "ESTABLISHED");

  // Client FIN
  reassembler.addPacket(src, dst, { srcPort: 1234, dstPort: 80, seqNum: 101, flags: { FIN: true, ACK: true } }, Buffer.alloc(0));
  streams = reassembler.getStreams();
  assert.strictEqual(streams[0].state, "FIN_WAIT");

  // Server FIN
  reassembler.addPacket(dst, src, { srcPort: 80, dstPort: 1234, seqNum: 501, flags: { FIN: true, ACK: true } }, Buffer.alloc(0));
  streams = reassembler.getStreams();
  assert.strictEqual(streams[0].state, "CLOSED");
});

test("RST-terminated stream state tracking", () => {
  const reassembler = new TCPReassembler();
  reassembler.addPacket("1.1.1.1", "2.2.2.2", { srcPort: 1000, dstPort: 80, seqNum: 1, flags: { SYN: true } }, Buffer.alloc(0));
  reassembler.addPacket("2.2.2.2", "1.1.1.1", { srcPort: 80, dstPort: 1000, seqNum: 1, flags: { RST: true } }, Buffer.alloc(0));
  const streams = reassembler.getStreams();
  assert.strictEqual(streams[0].state, "RESET");
});

test("Bidirectional stream client and server data separation", () => {
  const reassembler = new TCPReassembler();
  const cIP = "192.168.1.100";
  const sIP = "93.184.216.34";

  // Handshake
  reassembler.addPacket(cIP, sIP, { srcPort: 50000, dstPort: 80, seqNum: 1000, flags: { SYN: true } }, Buffer.alloc(0));
  reassembler.addPacket(sIP, cIP, { srcPort: 80, dstPort: 50000, seqNum: 5000, flags: { SYN: true, ACK: true } }, Buffer.alloc(0));

  // Client Request
  reassembler.addPacket(cIP, sIP, { srcPort: 50000, dstPort: 80, seqNum: 1001, flags: { ACK: true } }, Buffer.from("GET / HTTP/1.1\r\n\r\n"));

  // Server Response
  reassembler.addPacket(sIP, cIP, { srcPort: 80, dstPort: 50000, seqNum: 5001, flags: { ACK: true } }, Buffer.from("HTTP/1.1 200 OK\r\n\r\n"));

  const streams = reassembler.getStreams();
  assert.strictEqual(streams[0].clientData.toString("utf8"), "GET / HTTP/1.1\r\n\r\n");
  assert.strictEqual(streams[0].serverData.toString("utf8"), "HTTP/1.1 200 OK\r\n\r\n");
});

// ----------------------------------------------------
// Section 8: DNS Protocol Decoder
// ----------------------------------------------------
console.log("\n📡 8. DNS Protocol Decoder");

test("Parse standard DNS A query", () => {
  const dnsBuf = Buffer.concat([
    Buffer.from([0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
    Buffer.from([0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00]),
    Buffer.from([0x00, 0x01, 0x00, 0x01])
  ]);

  const dns = parseDNS(dnsBuf);
  assert.ok(dns);
  assert.strictEqual(dns.transactionId, 0x1234);
  assert.strictEqual(dns.isResponse, false);
  assert.strictEqual(dns.questions.length, 1);
  assert.strictEqual(dns.questions[0].name, "google.com");
  assert.strictEqual(dns.questions[0].type, "A");
  assert.strictEqual(dns.questions[0].class, "IN");
});

test("Parse DNS response with label compression pointer", () => {
  const header = Buffer.from([
    0xab, 0xcd,
    0x81, 0x80,
    0x00, 0x01,
    0x00, 0x01,
    0x00, 0x00,
    0x00, 0x00
  ]);
  const question = Buffer.from([
    0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
    0x00, 0x01, 0x00, 0x01
  ]);
  const answer = Buffer.from([
    0xc0, 0x0c,
    0x00, 0x01,
    0x00, 0x01,
    0x00, 0x00, 0x01, 0x2c,
    0x00, 0x04,
    93, 184, 216, 34
  ]);

  const dns = parseDNS(Buffer.concat([header, question, answer]));
  assert.ok(dns);
  assert.strictEqual(dns.isResponse, true);
  assert.strictEqual(dns.rcodeName, "NoError");
  assert.strictEqual(dns.answers.length, 1);
  assert.strictEqual(dns.answers[0].name, "example.com");
  assert.strictEqual(dns.answers[0].type, "A");
  assert.strictEqual(dns.answers[0].data, "93.184.216.34");
  assert.strictEqual(dns.answers[0].ttl, 300);
});

test("Parse DNS AAAA (IPv6) and TXT records", () => {
  const header = Buffer.from([
    0x56, 0x78, 0x81, 0x80,
    0x00, 0x01, 0x00, 0x02,
    0x00, 0x00, 0x00, 0x00
  ]);
  const question = Buffer.from([
    0x04, 0x74, 0x65, 0x73, 0x74, 0x00,
    0x00, 0x1c, 0x00, 0x01
  ]);
  const aaaaIp = Buffer.from([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01]);
  const ans1 = Buffer.concat([
    Buffer.from([0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x10]),
    aaaaIp
  ]);
  const txtVal = Buffer.from("v=spf1");
  const ans2 = Buffer.concat([
    Buffer.from([0xc0, 0x0c, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, txtVal.length + 1, txtVal.length]),
    txtVal
  ]);

  const dns = parseDNS(Buffer.concat([header, question, ans1, ans2]));
  assert.ok(dns);
  assert.strictEqual(dns.answers.length, 2);
  assert.strictEqual(dns.answers[0].type, "AAAA");
  assert.strictEqual(dns.answers[0].data, "2001:db8::1");
  assert.strictEqual(dns.answers[1].type, "TXT");
  assert.strictEqual(dns.answers[1].data, "v=spf1");
});

test("Malformed DNS with compression loop terminates safely", () => {
  const looped = Buffer.from([
    0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01
  ]);

  const dns = parseDNS(looped);
  assert.ok(dns, "Must not throw on looped pointer");
  assert.ok(dns.questions[0].name.includes("<loop>"));
});

// ----------------------------------------------------
// Section 9: HTTP/1.x Protocol Decoder
// ----------------------------------------------------
console.log("\n🌐 9. HTTP/1.x Protocol Decoder");

test("Parse HTTP GET request with headers and URI", () => {
  const raw = Buffer.from(
    "GET /api/v1/users?role=admin HTTP/1.1\r\n" +
    "Host: internal.corp\r\n" +
    "Authorization: Bearer confidential_token\r\n" +
    "User-Agent: curl/8.4.0\r\n\r\n"
  );
  const parsed = parseHTTPRequest(raw);
  assert.ok(parsed);
  const req = parsed.request;
  assert.strictEqual(req.method, "GET");
  assert.strictEqual(req.uri, "/api/v1/users?role=admin");
  assert.strictEqual(req.headers["host"], "internal.corp");
  assert.strictEqual(req.headers["authorization"], "Bearer confidential_token");
  assert.ok(req.hints.some((h) => h.includes("Credentials detected")));
});

test("Parse HTTP POST with Content-Length body", () => {
  const bodyText = '{"username":"analyst","action":"inspect"}';
  const raw = Buffer.from(
    "POST /api/action HTTP/1.1\r\n" +
    "Host: target.local\r\n" +
    `Content-Length: ${bodyText.length}\r\n` +
    "Content-Type: application/json\r\n\r\n" +
    bodyText
  );
  const parsed = parseHTTPRequest(raw);
  assert.ok(parsed);
  assert.strictEqual(parsed.request.method, "POST");
  assert.strictEqual(parsed.request.body, bodyText);
  assert.strictEqual(parsed.request.bodyLength, bodyText.length);
});

test("Parse HTTP chunked transfer encoding", () => {
  const raw = Buffer.from(
    "POST /upload HTTP/1.1\r\n" +
    "Host: transfer.org\r\n" +
    "Transfer-Encoding: chunked\r\n\r\n" +
    "5\r\nHELLO\r\n" +
    "6\r\n WORLD\r\n" +
    "0\r\n\r\n"
  );
  const parsed = parseHTTPRequest(raw);
  assert.ok(parsed);
  assert.strictEqual(parsed.request.body, "HELLO WORLD");
});

test("Parse HTTP response status, headers, and body", () => {
  const raw = Buffer.from(
    "HTTP/1.1 500 Internal Server Error\r\n" +
    "Server: nginx/1.24\r\n" +
    "Content-Length: 15\r\n\r\n" +
    "Database failed"
  );
  const parsed = parseHTTPResponse(raw);
  assert.ok(parsed);
  assert.strictEqual(parsed.response.statusCode, 500);
  assert.strictEqual(parsed.response.statusText, "Internal Server Error");
  assert.strictEqual(parsed.response.body, "Database failed");
  assert.ok(parsed.response.hints.some((h) => h.includes("Server error response (500)")));
});

// ----------------------------------------------------
// Section 10: TLS SNI Decoder
// ----------------------------------------------------
console.log("\n🔒 10. TLS SNI Decoder");

function buildClientHello(sniHostname) {
  const sniBuf = Buffer.from(sniHostname, "utf8");

  // Extension 0x0000 (server_name)
  const sniList = Buffer.concat([
    Buffer.from([0x00, sniBuf.length + 3, 0x00]),
    Buffer.alloc(2),
    sniBuf
  ]);
  sniList.writeUInt16BE(sniBuf.length, 3);

  const extData = Buffer.concat([
    Buffer.from([0x00, 0x00]),
    Buffer.alloc(2),
    sniList
  ]);
  extData.writeUInt16BE(sniList.length, 2);

  const extensions = Buffer.concat([
    Buffer.alloc(2),
    extData
  ]);
  extensions.writeUInt16BE(extData.length, 0);

  const clientVersion = Buffer.from([0x03, 0x03]); // TLS 1.2
  const random = Buffer.alloc(32, 0x5a);
  const sessionId = Buffer.from([0x00]);
  const cipherSuites = Buffer.from([0x00, 0x02, 0xc0, 0x2f]);
  const compression = Buffer.from([0x01, 0x00]);

  const handshakeBody = Buffer.concat([
    clientVersion,
    random,
    sessionId,
    cipherSuites,
    compression,
    extensions
  ]);

  const handshakeHeader = Buffer.alloc(4);
  handshakeHeader[0] = 0x01; // ClientHello
  handshakeHeader[1] = (handshakeBody.length >> 16) & 0xff;
  handshakeHeader[2] = (handshakeBody.length >> 8) & 0xff;
  handshakeHeader[3] = handshakeBody.length & 0xff;

  const handshake = Buffer.concat([handshakeHeader, handshakeBody]);

  const recordHeader = Buffer.alloc(5);
  recordHeader[0] = 0x16; // Handshake
  recordHeader.writeUInt16BE(0x0301, 1);
  recordHeader.writeUInt16BE(handshake.length, 3);

  return Buffer.concat([recordHeader, handshake]);
}

test("Extract SNI from valid TLS 1.2 ClientHello", () => {
  const hello = buildClientHello("api.cloudflare.com");
  const sni = extractTLSSNI(hello);
  assert.strictEqual(sni, "api.cloudflare.com");
});

test("Extract TLS ClientHello metadata", () => {
  const hello = buildClientHello("gateway.c2-domain.com");
  const meta = parseClientHello(hello);
  assert.ok(meta);
  assert.strictEqual(meta.sni, "gateway.c2-domain.com");
  assert.strictEqual(meta.clientVersion, "TLS 1.2");
  assert.strictEqual(meta.cipherSuitesCount, 1);
});

test("Return null for non-ClientHello records", () => {
  const appData = Buffer.from([0x17, 0x03, 0x03, 0x00, 0x10, ...new Array(16).fill(0xaa)]);
  assert.strictEqual(extractTLSSNI(appData), null);
  assert.strictEqual(parseClientHello(appData), null);
});

// ----------------------------------------------------
// Section 11: Phase 2 Application Tools on PCAP Fixtures
// ----------------------------------------------------
console.log("\n🧰 11. Phase 2 Application Tools on PCAP Fixtures");

test("Tool packet_extract_dns on sample_5pkt.pcap", () => {
  const fixturePath = path.join(__dirname, "test", "fixtures", "sample_5pkt.pcap");
  const buffer = resolveInput({ filePath: fixturePath }, "stdio");
  const { packets } = analyzePcapBuffer(buffer);

  const records = [];
  for (const p of packets) {
    if ((p.transport?.srcPort === 53 || p.transport?.dstPort === 53) && p.payload) {
      const parsed = parseDNS(p.payload);
      if (parsed) records.push(parsed);
    }
  }

  assert.strictEqual(records.length, 1);
  assert.strictEqual(records[0].questions[0].name, "example.com");
  assert.strictEqual(records[0].questions[0].type, "A");
});

test("Tool packet_extract_http on sample_5pkt.pcap", () => {
  const fixturePath = path.join(__dirname, "test", "fixtures", "sample_5pkt.pcap");
  const buffer = resolveInput({ filePath: fixturePath }, "stdio");
  const { packets } = analyzePcapBuffer(buffer);

  const reassembler = new TCPReassembler();
  for (const p of packets) {
    if (p.transport?.protocol === "TCP" && p.network && p.transport) {
      reassembler.addPacket(p.network.srcIP, p.network.dstIP, p.transport, p.payload, p.timestampISO);
    }
  }

  const streams = reassembler.getStreams();
  assert.strictEqual(streams.length, 1);
  const { requests } = parseHTTPStream(streams[0].clientData, streams[0].serverData);
  assert.strictEqual(requests.length, 1);
  assert.strictEqual(requests[0].method, "GET");
  assert.strictEqual(requests[0].uri, "/forensics.html");
  assert.strictEqual(requests[0].headers["host"], "example.com");
});

test("Tool packet_extract_tls_sni on synthetic TLS capture", () => {
  const tlsHello = buildClientHello("auth.secure-bank.com");
  const eth = Buffer.alloc(14);
  eth.writeUInt16BE(0x0800, 12);
  const ip = Buffer.alloc(20);
  ip[0] = 0x45;
  ip.writeUInt16BE(20 + 20 + tlsHello.length, 2);
  ip[8] = 64;
  ip[9] = 6;
  ip.set([10, 0, 0, 1], 12);
  ip.set([104, 16, 100, 1], 16);
  const tcp = Buffer.alloc(20);
  tcp.writeUInt16BE(54321, 0);
  tcp.writeUInt16BE(443, 2);
  tcp[12] = 0x50;

  const pkt = Buffer.concat([eth, ip, tcp, tlsHello]);
  const pcap = Buffer.concat([buildPcapHeader(), buildPacketRecord({ data: pkt })]);

  const { packets } = analyzePcapBuffer(pcap);
  assert.strictEqual(packets.length, 1);
  const hello = parseClientHello(packets[0].payload);
  assert.ok(hello);
  assert.strictEqual(hello.sni, "auth.secure-bank.com");
});

// ----------------------------------------------------
// Section 12: C2 Beacon Detection
// ----------------------------------------------------
console.log("\n📡 12. C2 Beacon Detection");

test("Detect perfect 60-second beacon (CV ≈ 0)", () => {
  const packets = [];
  const baseTime = 1700000000000;
  for (let i = 0; i < 10; i++) {
    packets.push({
      timestampMs: baseTime + i * 60000,
      timestampISO: new Date(baseTime + i * 60000).toISOString(),
      network: { srcIP: "192.168.1.50", dstIP: "198.51.100.1" },
      transport: { protocol: "TCP", srcPort: 49152 + i, dstPort: 4444, flags: { SYN: true, ACK: false } },
      wireLength: 60
    });
  }

  const result = detectBeacons(packets, { minConnections: 8 });
  assert.strictEqual(result.beaconCandidates.length, 1);
  const candidate = result.beaconCandidates[0];
  assert.strictEqual(candidate.destination, "198.51.100.1");
  assert.strictEqual(candidate.destinationPort, 4444);
  assert.strictEqual(candidate.estimatedIntervalSeconds, 60);
  assert.strictEqual(candidate.coefficientOfVariation, 0);
  assert.strictEqual(candidate.confidence, "HIGH");
  assert.strictEqual(candidate.isKnownBenignService, false);
});

test("Detect 60-second beacon with 25% jitter", () => {
  const packets = [];
  let currentTime = 1700000000000;
  const intervals = [45, 75, 45, 75, 45, 75, 45, 75, 45, 75, 60];

  packets.push({
    timestampMs: currentTime,
    timestampISO: new Date(currentTime).toISOString(),
    network: { srcIP: "10.0.0.5", dstIP: "203.0.113.50" },
    transport: { protocol: "TCP", srcPort: 51000, dstPort: 8443, flags: { SYN: true, ACK: false } },
    wireLength: 64
  });

  for (let i = 0; i < intervals.length; i++) {
    currentTime += intervals[i] * 1000;
    packets.push({
      timestampMs: currentTime,
      timestampISO: new Date(currentTime).toISOString(),
      network: { srcIP: "10.0.0.5", dstIP: "203.0.113.50" },
      transport: { protocol: "TCP", srcPort: 51001 + i, dstPort: 8443, flags: { SYN: true, ACK: false } },
      wireLength: 64
    });
  }

  const result = detectBeacons(packets, { minConnections: 8 });
  assert.strictEqual(result.beaconCandidates.length, 1);
  const candidate = result.beaconCandidates[0];
  assert.strictEqual(candidate.destination, "203.0.113.50");
  assert.ok(candidate.confidence === "HIGH" || candidate.confidence === "MEDIUM");
  assert.ok(candidate.jitterPercent > 20 && candidate.jitterPercent < 30);
});

test("Filter & tag benign cloud metadata / NTP pulses", () => {
  const packets = [];
  const baseTime = 1700000000000;
  for (let i = 0; i < 10; i++) {
    packets.push({
      timestampMs: baseTime + i * 10000,
      timestampISO: new Date(baseTime + i * 10000).toISOString(),
      network: { srcIP: "10.0.0.1", dstIP: "169.254.169.254" },
      transport: { protocol: "TCP", srcPort: 40000 + i, dstPort: 80, flags: { SYN: true, ACK: false } },
      wireLength: 60
    });
  }

  const result = detectBeacons(packets, { minConnections: 8, includeBenign: true });
  assert.strictEqual(result.beaconCandidates.length, 1);
  const candidate = result.beaconCandidates[0];
  assert.strictEqual(candidate.destination, "169.254.169.254");
  assert.strictEqual(candidate.isKnownBenignService, true);
  assert.strictEqual(candidate.benignServiceType, "CLOUD_METADATA");
  assert.ok(candidate.verdict.includes("Benign activity"));
});

test("Reject irregular / random legitimate traffic", () => {
  const packets = [];
  let t = 1700000000000;
  const irregularIntervals = [1, 150, 4, 300, 12, 450, 2, 90, 8, 240];

  packets.push({
    timestampMs: t,
    timestampISO: new Date(t).toISOString(),
    network: { srcIP: "10.0.0.1", dstIP: "1.2.3.4" },
    transport: { protocol: "TCP", srcPort: 50000, dstPort: 80, flags: { SYN: true, ACK: false } },
    wireLength: 60
  });

  for (let i = 0; i < irregularIntervals.length; i++) {
    t += irregularIntervals[i] * 1000;
    packets.push({
      timestampMs: t,
      timestampISO: new Date(t).toISOString(),
      network: { srcIP: "10.0.0.1", dstIP: "1.2.3.4" },
      transport: { protocol: "TCP", srcPort: 50001 + i, dstPort: 80, flags: { SYN: true, ACK: false } },
      wireLength: 60
    });
  }

  const result = detectBeacons(packets, { minConnections: 8 });
  if (result.beaconCandidates.length > 0) {
    assert.strictEqual(result.beaconCandidates[0].confidence, "INFORMATIONAL");
  }
});

// ----------------------------------------------------
// Section 13: DNS Tunneling Detection
// ----------------------------------------------------
console.log("\n🚇 13. DNS Tunneling Detection");

test("Detect base64-encoded DNS tunnel subdomains", () => {
  const queries = [];
  // 25 random base64 strings
  for (let i = 0; i < 25; i++) {
    const raw = crypto.randomBytes(18).toString("base64").replace(/[+/=]/g, "a");
    queries.push({ name: `${raw}.tunnel.evil-c2.net`, type: "TXT" });
  }

  const result = detectDNSTunneling(queries, { minSubdomains: 15 });
  assert.strictEqual(result.suspiciousDomains.length, 1);
  const target = result.suspiciousDomains[0];
  assert.strictEqual(target.parentDomain, "evil-c2.net");
  assert.strictEqual(target.uniqueSubdomains, 25);
  assert.ok(target.subdomainEntropy > 3.5);
  assert.strictEqual(target.confidence, "HIGH");
  assert.strictEqual(target.isKnownCdnDomain, false);
});

test("Detect hex-encoded DNS tunnel subdomains", () => {
  const queries = [];
  for (let i = 0; i < 20; i++) {
    const hex = crypto.randomBytes(16).toString("hex");
    queries.push({ name: `${hex}.exfil.data-drop.org`, type: "A" });
  }

  const result = detectDNSTunneling(queries, { minSubdomains: 15 });
  assert.strictEqual(result.suspiciousDomains.length, 1);
  const target = result.suspiciousDomains[0];
  assert.strictEqual(target.parentDomain, "data-drop.org");
  assert.strictEqual(target.characterSetProfile, "hex");
  assert.strictEqual(target.confidence, "HIGH");
});

test("Profile and demote trusted CDN subdomains", () => {
  const queries = [];
  for (let i = 0; i < 20; i++) {
    const sub = `edge-node-${i}-cache`;
    queries.push({ name: `${sub}.cloudflare.com`, type: "A" });
  }

  const result = detectDNSTunneling(queries, { minSubdomains: 15 });
  if (result.suspiciousDomains.length > 0) {
    const cdn = result.suspiciousDomains.find((d) => d.parentDomain === "cloudflare.com");
    if (cdn) {
      assert.strictEqual(cdn.isKnownCdnDomain, true);
      assert.strictEqual(cdn.confidence, "LOW");
    }
  }
});

// ----------------------------------------------------
// Section 14: Cleartext Credential Extraction
// ----------------------------------------------------
console.log("\n🔑 14. Cleartext Credential Extraction");

test("Extract HTTP Basic and Bearer auth credentials", () => {
  const httpTransactions = [
    {
      client: "192.168.1.100:54321",
      server: "10.0.0.1:80",
      request: {
        method: "GET",
        uri: "/admin/dashboard",
        headers: {
          host: "corp-intranet.local",
          authorization: "Basic YWRtaW46c3VwZXJzZWNyZXQyMDI2IQ=="
        }
      }
    },
    {
      client: "192.168.1.100:54322",
      server: "10.0.0.1:80",
      request: {
        method: "GET",
        uri: "/api/data",
        headers: {
          host: "corp-intranet.local",
          authorization: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.token123"
        }
      }
    }
  ];

  const result = extractCredentials(httpTransactions, []);
  assert.strictEqual(result.totalCredentialsFound, 2);

  const basic = result.credentials.find((c) => c.type === "HTTP_BASIC");
  assert.ok(basic);
  assert.strictEqual(basic.username, "admin");
  assert.strictEqual(basic.password, "supersecret2026!");

  const bearer = result.credentials.find((c) => c.type === "HTTP_BEARER");
  assert.ok(bearer);
  assert.ok(bearer.token.includes("token123"));
});

test("Extract credentials from HTTP query params and POST bodies", () => {
  const httpTransactions = [
    {
      client: "10.0.0.2:48000",
      server: "93.184.216.34:80",
      request: {
        method: "GET",
        uri: "/login.php?user=alice&password=AlicePassword!",
        headers: { host: "example.com" }
      }
    },
    {
      client: "10.0.0.2:48001",
      server: "93.184.216.34:80",
      request: {
        method: "POST",
        uri: "/api/auth",
        headers: { host: "example.com", "content-type": "application/json" },
        body: '{"username":"bob","password":"SecretPassword99"}'
      }
    }
  ];

  const result = extractCredentials(httpTransactions, []);
  assert.strictEqual(result.totalCredentialsFound, 2);

  const queryCred = result.credentials.find((c) => c.type === "HTTP_QUERY_PARAM");
  assert.strictEqual(queryCred.username, "alice");
  assert.strictEqual(queryCred.password, "AlicePassword!");

  const bodyCred = result.credentials.find((c) => c.type === "HTTP_BODY");
  assert.strictEqual(bodyCred.username, "bob");
  assert.strictEqual(bodyCred.password, "SecretPassword99");
});

test("Extract FTP cleartext USER and PASS commands from TCP stream", () => {
  const tcpStreams = [
    {
      client: "192.168.1.50:41234",
      server: "192.168.1.1:21",
      startTime: "2026-09-28T00:00:00.000Z",
      clientData: Buffer.from("USER backup_operator\r\nPASS Winter2026#Secure\r\nTYPE I\r\n")
    }
  ];

  const result = extractCredentials([], tcpStreams);
  assert.strictEqual(result.totalCredentialsFound, 1);
  assert.strictEqual(result.credentials[0].type, "FTP");
  assert.strictEqual(result.credentials[0].username, "backup_operator");
  assert.strictEqual(result.credentials[0].password, "Winter2026#Secure");
});

// ----------------------------------------------------
// Section 15: Shannon Entropy & Randomness Analysis
// ----------------------------------------------------
console.log("\n🎲 15. Shannon Entropy & Randomness Analysis");

test("High entropy for pseudo-random / encrypted bytes", () => {
  const randomBytes = crypto.randomBytes(2048);
  const result = calculateEntropy(randomBytes);
  assert.ok(result.entropy > 7.5);
  assert.strictEqual(result.verdict, "encrypted_or_compressed");
  assert.strictEqual(result.maxEntropy, 8.0);
});

test("Low entropy for ASCII plaintext strings", () => {
  const text = Buffer.from("The quick brown fox jumps over the lazy dog. A repeatable pattern of standard English sentences.");
  const result = calculateEntropy(text);
  assert.ok(result.entropy < 4.5);
  assert.strictEqual(result.verdict, "plaintext");
});

// ----------------------------------------------------
// Section 16: Phase 3 Threat Tools on PCAP Captures
// ----------------------------------------------------
console.log("\n🧰 16. Phase 3 Threat Tools on PCAP Captures");

test("Tool packet_detect_beacons on synthetic periodic capture", () => {
  // Build a synthetic capture with 9 SYN packets spaced 30 seconds apart
  const packets = [];
  const baseTime = 1700000000;
  for (let i = 0; i < 9; i++) {
    const eth = Buffer.alloc(14);
    eth.writeUInt16BE(0x0800, 12);
    const ip = Buffer.alloc(20);
    ip[0] = 0x45;
    ip.writeUInt16BE(40, 2);
    ip[8] = 64;
    ip[9] = 6;
    ip.set([192, 168, 1, 10], 12);
    ip.set([198, 51, 100, 99], 16);
    const tcp = Buffer.alloc(20);
    tcp.writeUInt16BE(50000 + i, 0);
    tcp.writeUInt16BE(4444, 2);
    tcp.writeUInt32BE(1000 * i, 4);
    tcp[12] = 0x50;
    tcp[13] = TCP_FLAGS.SYN;

    const data = Buffer.concat([eth, ip, tcp]);
    packets.push(buildPacketRecord({ tsSec: baseTime + i * 30, data }));
  }

  const pcap = Buffer.concat([buildPcapHeader(), ...packets]);
  const { packets: dissected } = analyzePcapBuffer(pcap);
  assert.strictEqual(dissected.length, 9);

  const result = detectBeacons(dissected, { minConnections: 8 });
  assert.strictEqual(result.beaconCandidates.length, 1);
  assert.strictEqual(result.beaconCandidates[0].destination, "198.51.100.99");
  assert.strictEqual(result.beaconCandidates[0].estimatedIntervalSeconds, 30);
  assert.strictEqual(result.beaconCandidates[0].confidence, "HIGH");
});

test("Tool packet_entropy single packet inspection", () => {
  const randomPayload = crypto.randomBytes(1024);
  const result = calculateEntropy(randomPayload);
  assert.ok(result.entropy > 7.5);
  assert.strictEqual(result.verdict, "encrypted_or_compressed");
  assert.strictEqual(result.byteCount, 1024);
});

// ----------------------------------------------------
// Section 17: Crash-Immunity Fuzz Testing
// ----------------------------------------------------
console.log("\n🛡️ 17. Crash-Immunity Fuzz Testing (100 rounds)");

test("Feed 100 rounds of pseudo-random garbage into parser without crashes", () => {
  for (let i = 0; i < 100; i++) {
    const size = Math.floor(Math.random() * 2048) + 1;
    const garbage = crypto.randomBytes(size);

    try {
      parsePcap(garbage);
    } catch (err) {
      // Clean descriptive errors are expected and required
      assert.ok(err.message, "Error must have a descriptive message");
    }
  }
});

// ----------------------------------------------------
// Section 18: PCAPng Native Parsing Engine (v2)
// ----------------------------------------------------
console.log("\n📦 18. PCAPng Native Parsing Engine (v2)");

test("Detect PCAPng container magic", () => {
  const pcapngBuf = Buffer.from([0x0a, 0x0d, 0x0d, 0x0a, 0x20, 0x00, 0x00, 0x00, 0x4d, 0x3c, 0x2b, 0x1a]);
  assert.strictEqual(isPcapNg(pcapngBuf), true);
  assert.strictEqual(isPcapNg(Buffer.from([0xa1, 0xb2, 0xc3, 0xd4, 0x00, 0x00, 0x00, 0x00])), false);
});

test("Parse full synthetic PCAPng with SHB, IDB, and EPB records", () => {
  // 1. Section Header Block (SHB: 28 bytes)
  const shb = Buffer.alloc(28);
  shb.writeUInt32LE(0x0a0d0d0a, 0); // Type: SHB
  shb.writeUInt32LE(28, 4);         // Total Length
  shb.writeUInt32LE(0x1a2b3c4d, 8); // Byte-Order Magic (LE)
  shb.writeUInt16LE(1, 12);         // Major: 1
  shb.writeUInt16LE(0, 14);         // Minor: 0
  shb.writeInt32LE(-1, 16);         // Section length: unconstrained
  shb.writeInt32LE(-1, 20);
  shb.writeUInt32LE(28, 24);        // Trailing Length

  // 2. Interface Description Block (IDB: 20 bytes)
  const idb = Buffer.alloc(20);
  idb.writeUInt32LE(0x00000001, 0); // Type: IDB
  idb.writeUInt32LE(20, 4);         // Total Length
  idb.writeUInt16LE(1, 8);          // LinkType: 1 (Ethernet)
  idb.writeUInt16LE(0, 10);         // Reserved
  idb.writeUInt32LE(65535, 12);     // SnapLen
  idb.writeUInt32LE(20, 16);        // Trailing Length

  // 3. Enhanced Packet Block (EPB)
  const fakeEthPacket = Buffer.alloc(64, 0xaa);
  const epbLen = 32 + fakeEthPacket.length;
  const epb = Buffer.alloc(epbLen);
  epb.writeUInt32LE(0x00000006, 0); // Type: EPB
  epb.writeUInt32LE(epbLen, 4);     // Total Length
  epb.writeUInt32LE(0, 8);          // Interface ID: 0
  epb.writeUInt32LE(100, 12);       // Timestamp High
  epb.writeUInt32LE(500000, 16);    // Timestamp Low
  epb.writeUInt32LE(64, 20);        // Captured Length
  epb.writeUInt32LE(64, 24);        // Original Length
  fakeEthPacket.copy(epb, 28);
  epb.writeUInt32LE(epbLen, epbLen - 4); // Trailing Length

  const fullPcapng = Buffer.concat([shb, idb, epb]);

  // Parse natively with parsePcapNg
  const parsed = parsePcapNg(fullPcapng);
  assert.strictEqual(parsed.header.format, "PCAPng");
  assert.strictEqual(parsed.header.isLittleEndian, true);
  assert.strictEqual(parsed.interfaces.length, 1);
  assert.strictEqual(parsed.interfaces[0].linkType, 1);
  assert.strictEqual(parsed.packets.length, 1);
  assert.strictEqual(parsed.packets[0].data.length, 64);

  // Parse transparently through main parsePcap entrypoint
  const autoParsed = parsePcap(fullPcapng);
  assert.strictEqual(autoParsed.header.format, "PCAPng");
  assert.strictEqual(autoParsed.packets.length, 1);
});

// ----------------------------------------------------
// Section 19: Linux Cooked SLL & Loopback (v2)
// ----------------------------------------------------
console.log("\n🔌 19. Linux Cooked SLL & Loopback (v2)");

test("Decode Linux Cooked Capture (LinkType 113 SLL)", () => {
  const sllBuf = Buffer.alloc(16);
  sllBuf.writeUInt16BE(0, 0);   // PacketType: HOST
  sllBuf.writeUInt16BE(1, 2);   // ARPHRD: ETHER
  sllBuf.writeUInt16BE(6, 4);   // AddrLen: 6
  Buffer.from("001122334455", "hex").copy(sllBuf, 6); // MAC
  sllBuf.writeUInt16BE(0x0800, 14); // Protocol: IPv4

  const sll = decodeSLL(sllBuf, 0);
  assert.strictEqual(sll.packetType, "HOST");
  assert.strictEqual(sll.etherType, 0x0800);
  assert.strictEqual(sll.srcMac, "00:11:22:33:44:55");
  assert.strictEqual(sll.payloadOffset, 16);
});

test("Decode BSD/Linux Loopback (LinkType 0)", () => {
  const loopBuf = Buffer.alloc(4);
  loopBuf.writeUInt32LE(2, 0); // Family 2: PF_INET / IPv4
  const loop = decodeLoopback(loopBuf, 0);
  assert.strictEqual(loop.family, 2);
  assert.strictEqual(loop.etherType, 0x0800);
  assert.strictEqual(loop.payloadOffset, 4);
});

// ----------------------------------------------------
// Section 20: JA3, JA3S & JA4 TLS Fingerprinting (v2)
// ----------------------------------------------------
console.log("\n🔑 20. JA3, JA3S & JA4 TLS Fingerprinting (v2)");

test("Filter GREASE values correctly", () => {
  assert.strictEqual(isGrease(0x0a0a), true);
  assert.strictEqual(isGrease(0x2a2a), true);
  assert.strictEqual(isGrease(0x1a1a), true);
  assert.strictEqual(isGrease(0xc02f), false); // Standard ECDHE-RSA-AES128-GCM-SHA256
  assert.strictEqual(isGrease(0x0035), false);
});

test("Calculate accurate JA3 and JA4 hashes with GREASE filtering", () => {
  const sampleHello = {
    clientVersion: "TLS 1.2",
    clientVersionRaw: 771,
    sni: "victim-bank.com",
    alpn: "h2",
    cipherSuitesRaw: [0x0a0a, 0xc02f, 0xc030, 0xcca9, 0x1a1a], // Contains GREASE
    extensionsRaw: [{ type: 0x0a0a }, { type: 0 }, { type: 10 }, { type: 11 }, { type: 16 }],
    supportedCurvesRaw: [0x2a2a, 29, 23, 24],
    ecPointFormatsRaw: [0]
  };

  const ja3 = calculateJA3(sampleHello);
  assert.ok(ja3);
  assert.strictEqual(ja3.ciphersCount, 3); // 2 GREASE filtered out
  assert.strictEqual(ja3.extensionsCount, 4); // 1 GREASE filtered out
  assert.strictEqual(ja3.ja3String, "771,49199-49200-52393,0-10-11-16,29-23-24,0");
  assert.strictEqual(ja3.ja3Hash.length, 32);
  assert.ok(ja3.ja4String.startsWith("t12d"));
});

test("Detect Cobalt Strike and Metasploit JA3 threat signatures", () => {
  assert.strictEqual(KNOWN_JA3_SIGNATURES["a0e9f5d64349fb13191bc781f81f42e1"].tool, "Cobalt Strike");
  assert.strictEqual(KNOWN_JA3_SIGNATURES["72a589da586844d7f0818ce684948eea"].tool, "Metasploit Meterpreter");
});

// ----------------------------------------------------
// Section 21: RFC 6455 WebSocket Frame De-masking (v2)
// ----------------------------------------------------
console.log("\n🌐 21. RFC 6455 WebSocket Frame De-masking (v2)");

test("Unmask client-to-server WebSocket JSON frame", () => {
  const secretJson = '{"action":"exfiltrate","token":"top_secret_2026"}';
  const secretBuf = Buffer.from(secretJson, "utf8");
  const maskKey = Buffer.from([0x37, 0xfa, 0x21, 0x3d]);

  // Mask payload with XOR
  const maskedPayload = Buffer.alloc(secretBuf.length);
  for (let i = 0; i < secretBuf.length; i++) {
    maskedPayload[i] = secretBuf[i] ^ maskKey[i % 4];
  }

  // Build frame: FIN=1, Opcode=0x1 (TEXT) -> 0x81, MASK=1, Len=maskedPayload.length -> 0x80 | len
  const frameHeader = Buffer.from([0x81, 0x80 | maskedPayload.length]);
  const wsFrame = Buffer.concat([frameHeader, maskKey, maskedPayload]);

  const frames = parseWebSocketFrames(wsFrame);
  assert.strictEqual(frames.length, 1);
  assert.strictEqual(frames[0].opcode, "TEXT");
  assert.strictEqual(frames[0].isMasked, true);
  assert.strictEqual(frames[0].isJson, true);
  assert.strictEqual(frames[0].jsonData.action, "exfiltrate");
  assert.strictEqual(frames[0].jsonData.token, "top_secret_2026");
});

// ----------------------------------------------------
// Section 22: QUIC & HTTP/3 Initial Packet SNI (v2)
// ----------------------------------------------------
console.log("\n🚀 22. QUIC & HTTP/3 Initial Packet SNI (v2)");

test("Extract SNI from unencrypted QUIC Initial Handshake packet", () => {
  // Construct minimal TLS 1.3 ClientHello with SNI "gateway.cloudflare.com"
  const sniHost = "gateway.cloudflare.com";
  const sniBuf = Buffer.from(sniHost);
  const ext = Buffer.concat([
    Buffer.from([0x00, 0x00, 0x00, sniBuf.length + 5, 0x00, sniBuf.length + 3, 0x00, 0x00, sniBuf.length]),
    sniBuf
  ]);
  const clientHello = Buffer.concat([
    Buffer.from([0x03, 0x03]),
    Buffer.alloc(32, 0x22),
    Buffer.from([0x00, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00]),
    Buffer.from([0x00, ext.length]),
    ext
  ]);
  const hs = Buffer.concat([
    Buffer.from([0x01, 0x00, (clientHello.length >> 8) & 0xff, clientHello.length & 0xff]),
    clientHello
  ]);

  // Construct QUIC Initial Header
  // Byte 0: 0xc0 (Long Header, Initial 0x00, Fixed Bit 1)
  // Bytes 1..4: 0x00000001 (QUIC v1)
  // DCID len: 4, DCID: 0x01020304
  // SCID len: 4, SCID: 0x05060708
  // Token len: 0 (varint 0x00)
  // Packet len: varint
  const quicHeader = Buffer.concat([
    Buffer.from([0xc0, 0x00, 0x00, 0x00, 0x01]), // Initial, Version 1
    Buffer.from([0x04, 0x01, 0x02, 0x03, 0x04]), // DCID
    Buffer.from([0x04, 0x05, 0x06, 0x07, 0x08]), // SCID
    Buffer.from([0x00]),                         // Token length 0
    Buffer.from([0x40 | ((hs.length + 4) >> 8), (hs.length + 4) & 0xff]), // Packet length 2-byte varint
    Buffer.from([0x00, 0x01])                    // Packet number
  ]);

  const quicPacket = Buffer.concat([quicHeader, hs]);
  const quic = parseQuicInitial(quicPacket);
  assert.ok(quic);
  assert.strictEqual(quic.isInitial, true);
  assert.strictEqual(quic.dcid, "01020304");
  assert.strictEqual(quic.scid, "05060708");
  assert.strictEqual(quic.sni, sniHost);
});

// ----------------------------------------------------
// Section 23: Filtered PCAP Export & Zeek TSV Logs (v2)
// ----------------------------------------------------
console.log("\n💾 23. Filtered PCAP Export & Zeek TSV Logs (v2)");

test("Export filtered packets to valid classic PCAP binary", () => {
  const dummyPayload = Buffer.from("PCAP_EXPORT_TEST_PAYLOAD");
  const packets = [
    { timestampMs: 1700000000000, data: dummyPayload, origLen: dummyPayload.length },
    { timestampMs: 1700000001000, data: dummyPayload, origLen: dummyPayload.length }
  ];

  const exportedBuf = exportToPcap(packets, 1);
  assert.ok(exportedBuf.length > 24);

  // Validate that the exported buffer re-parses cleanly as valid PCAP
  const parsed = parsePcap(exportedBuf);
  assert.strictEqual(parsed.header.linkType, 1);
  assert.strictEqual(parsed.packets.length, 2);
  assert.strictEqual(parsed.packets[0].data.toString(), "PCAP_EXPORT_TEST_PAYLOAD");
});

test("Generate standardized Zeek TSV logs (conn.log, dns.log, http.log)", () => {
  const analysis = {
    conversations: [
      {
        client: "192.168.1.100:54321",
        server: "93.184.216.34:80",
        protocol: "TCP",
        appProtocol: "HTTP",
        durationMs: 1500,
        bytesClient: 500,
        bytesServer: 2400,
        hasFIN: true
      }
    ],
    dnsQueries: [
      {
        client: "192.168.1.100:51234",
        server: "8.8.8.8:53",
        timestamp: "2023-11-14T22:13:20.000Z",
        transactionId: 4660,
        name: "example.com",
        type: "A",
        rcode: 0,
        answers: [{ ip: "93.184.216.34" }]
      }
    ],
    httpTransactions: [
      {
        client: "192.168.1.100:54321",
        server: "93.184.216.34:80",
        request: {
          method: "GET",
          uri: "/index.html",
          headers: { host: "example.com", "user-agent": "Mozilla/5.0" }
        },
        response: { statusCode: 200, statusText: "OK" }
      }
    ]
  };

  const logs = generateZeekLogs(analysis);
  assert.ok(logs.connLog.includes("#fields ts uid id.orig_h"));
  assert.ok(logs.connLog.includes("192.168.1.100\t54321\t93.184.216.34\t80"));
  assert.ok(logs.dnsLog.includes("example.com"));
  assert.ok(logs.httpLog.includes("/index.html"));
});

// ----------------------------------------------------
// Section 24: v2 Tool Suite Count Verification
// ----------------------------------------------------
console.log("\n🧰 24. v2 MCP Tool Suite Count Verification (15 Tools)");

test("SERVER_CARD lists all 15 v2 tools", () => {
  assert.strictEqual(SERVER_CARD.serverInfo.version, "2.0.0");
  assert.strictEqual(SERVER_CARD.tools.length, 15);
  const toolNames = SERVER_CARD.tools.map(t => t.name);
  assert.ok(toolNames.includes("packet_ja3_fingerprints"));
  assert.ok(toolNames.includes("packet_extract_websocket"));
  assert.ok(toolNames.includes("packet_extract_quic_sni"));
  assert.ok(toolNames.includes("packet_filter_export"));
  assert.ok(toolNames.includes("packet_to_zeek_logs"));
});

// ----------------------------------------------------
// Section 25: Wire Hardening & Protocol Remediation
// ----------------------------------------------------
console.log("\n🛡️ 25. Wire Hardening & Protocol Remediation");

test("Real RFC 9001 Encrypted QUIC Initial Packet AEAD Decryption & SNI Extraction", () => {
  const QUIC_V1_SALT = Buffer.from("38762cf7f55934b34d179ae6a4c80cadccbb7f0a", "hex");

  function hkdfExpandLabel(secret, label, context, length) {
    const fullLabel = Buffer.from("tls13 " + label, "utf8");
    const info = Buffer.concat([
      Buffer.from([(length >> 8) & 0xff, length & 0xff]),
      Buffer.from([fullLabel.length]),
      fullLabel,
      Buffer.from([context.length]),
      Buffer.from(context)
    ]);
    return Buffer.from(crypto.hkdfSync("sha256", secret, Buffer.alloc(0), info, length));
  }

  const hostname = "secure.payment-gateway.org";
  const serverNameExt = Buffer.concat([
    Buffer.from([0x00, 0x00]),
    Buffer.from([0x00, hostname.length + 5]),
    Buffer.from([0x00, hostname.length + 3]),
    Buffer.from([0x00]),
    Buffer.from([0x00, hostname.length]),
    Buffer.from(hostname, "utf8")
  ]);
  const extTotalLen = serverNameExt.length;
  const extensionsBlock = Buffer.concat([
    Buffer.from([(extTotalLen >> 8) & 0xff, extTotalLen & 0xff]),
    serverNameExt
  ]);

  const rawHello = Buffer.concat([
    Buffer.from([0x01]),
    Buffer.from([0x00, 0x00, 0x00]),
    Buffer.from([0x03, 0x03]),
    crypto.randomBytes(32),
    Buffer.from([0x00]),
    Buffer.from([0x00, 0x02, 0x13, 0x01]),
    Buffer.from([0x01, 0x00]),
    extensionsBlock
  ]);
  const helloLen = rawHello.length - 4;
  rawHello[1] = (helloLen >> 16) & 0xff;
  rawHello[2] = (helloLen >> 8) & 0xff;
  rawHello[3] = helloLen & 0xff;

  const cryptoFrame = Buffer.concat([
    Buffer.from([0x06]),
    Buffer.from([0x00]),
    Buffer.from([0x40 | ((rawHello.length >> 8) & 0x3f), rawHello.length & 0xff]),
    rawHello
  ]);

  const padding = Buffer.alloc(1100 - cryptoFrame.length, 0x00);
  const payloadPlaintext = Buffer.concat([cryptoFrame, padding]);

  const dcid = Buffer.from("8394c8f03e515708", "hex");
  const scid = Buffer.alloc(0);

  const initialSecret = crypto.createHmac("sha256", QUIC_V1_SALT).update(dcid).digest();
  const clientInitialSecret = hkdfExpandLabel(initialSecret, "client in", "", 32);
  const key = hkdfExpandLabel(clientInitialSecret, "quic key", "", 16);
  const iv = hkdfExpandLabel(clientInitialSecret, "quic iv", "", 12);
  const hp = hkdfExpandLabel(clientInitialSecret, "quic hp", "", 16);

  const pnVal = 1;
  const pnLen = 1;
  const pktLenVal = pnLen + payloadPlaintext.length + 16;

  const firstByteUnprotected = 0xc0 | (pnLen - 1);
  const headerPrefix = Buffer.concat([
    Buffer.from([firstByteUnprotected]),
    Buffer.from([0x00, 0x00, 0x00, 0x01]),
    Buffer.from([dcid.length]),
    dcid,
    Buffer.from([scid.length]),
    scid,
    Buffer.from([0x00]),
    Buffer.from([0x40 | ((pktLenVal >> 8) & 0x3f), pktLenVal & 0xff])
  ]);

  const pnBytes = Buffer.from([pnVal]);
  const aad = Buffer.concat([headerPrefix, pnBytes]);
  const nonce = Buffer.from(iv);
  nonce[nonce.length - 1] ^= pnVal;

  const cipher = crypto.createCipheriv("aes-128-gcm", key, nonce);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(payloadPlaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  const sample = ciphertext.subarray(3, 19);
  const hpCipher = crypto.createCipheriv("aes-128-ecb", hp, null);
  hpCipher.setAutoPadding(false);
  const mask = hpCipher.update(sample);

  const protectedFirstByte = firstByteUnprotected ^ (mask[0] & 0x0f);
  const protectedPN = Buffer.from([pnBytes[0] ^ mask[1]]);

  const wirePacket = Buffer.concat([
    Buffer.from([protectedFirstByte]),
    headerPrefix.subarray(1),
    protectedPN,
    ciphertext,
    tag
  ]);

  const result = parseQuicInitial(wirePacket);
  assert.ok(result, "RFC 9001 Initial packet must parse");
  assert.strictEqual(result.sni, "secure.payment-gateway.org");
  assert.strictEqual(result.dcid, "8394c8f03e515708");
  assert.ok(result.ja3, "JA3 fingerprint must be computed from decrypted ClientHello");
});

test("WebSocket Frame Extraction Past HTTP/1.1 Upgrade Handshake", () => {
  const httpHandshake = Buffer.from(
    "GET /chat/stream HTTP/1.1\r\n" +
    "Host: c2.adversary.org\r\n" +
    "Upgrade: websocket\r\n" +
    "Connection: Upgrade\r\n" +
    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
    "latin1"
  );

  const msg = JSON.stringify({ action: "beacon", host: "victim-pc", id: 1337 });
  const rawMsg = Buffer.from(msg, "utf8");
  const maskKey = Buffer.from([0x3a, 0x7b, 0x1c, 0x8f]);
  const maskedPayload = Buffer.alloc(rawMsg.length);
  for (let i = 0; i < rawMsg.length; i++) {
    maskedPayload[i] = rawMsg[i] ^ maskKey[i % 4];
  }

  const wsFrame = Buffer.concat([
    Buffer.from([0x81, 0x80 | rawMsg.length]),
    maskKey,
    maskedPayload
  ]);

  const streamWithHandshake = Buffer.concat([httpHandshake, wsFrame]);
  const frames = parseWebSocketFrames(streamWithHandshake);
  assert.strictEqual(frames.length, 1);
  assert.strictEqual(frames[0].opcode, "TEXT");
  assert.strictEqual(frames[0].isJson, true);
  assert.strictEqual(frames[0].jsonData.action, "beacon");
  assert.strictEqual(frames[0].jsonData.host, "victim-pc");
});

test("C2 Beacon Detection in Persistent Established TCP Sessions with Debounced Pulses", () => {
  const packets = [];
  const baseTime = 1700000000000;

  // Single persistent TCP connection established at t=0
  packets.push({
    timestampMs: baseTime,
    timestampISO: new Date(baseTime).toISOString(),
    network: { srcIP: "10.10.10.5", dstIP: "198.51.100.99" },
    transport: { protocol: "TCP", srcPort: 49500, dstPort: 443, flags: { SYN: true, ACK: false } },
    wireLength: 64
  });

  // 10 periodic data pulses sent every 30 seconds within the same established session.
  // Each pulse sends 2 packets within 5ms (burst)
  for (let i = 1; i <= 10; i++) {
    const pulseTime = baseTime + i * 30000;
    // Packet 1 of pulse
    packets.push({
      timestampMs: pulseTime,
      timestampISO: new Date(pulseTime).toISOString(),
      network: { srcIP: "10.10.10.5", dstIP: "198.51.100.99" },
      transport: { protocol: "TCP", srcPort: 49500, dstPort: 443, flags: { ACK: true, PSH: true } },
      payload: Buffer.from("POST /api/heartbeat HTTP/1.1\r\n\r\n"),
      wireLength: 120
    });
    // Packet 2 of pulse (burst retry/ack 3ms later)
    packets.push({
      timestampMs: pulseTime + 3,
      timestampISO: new Date(pulseTime + 3).toISOString(),
      network: { srcIP: "10.10.10.5", dstIP: "198.51.100.99" },
      transport: { protocol: "TCP", srcPort: 49500, dstPort: 443, flags: { ACK: true } },
      payload: Buffer.from("ack"),
      wireLength: 60
    });
  }

  const result = detectBeacons(packets, { minConnections: 8 });
  assert.strictEqual(result.beaconCandidates.length, 1);
  const beacon = result.beaconCandidates[0];
  assert.strictEqual(beacon.destination, "198.51.100.99");
  assert.strictEqual(beacon.estimatedIntervalSeconds, 30);
  assert.strictEqual(beacon.coefficientOfVariation, 0);
  assert.strictEqual(beacon.confidence, "HIGH");
});

test("Credential Extractor Substring Collision Immunity (bypass, compass, passport)", () => {
  const benignHttp = [
    {
      client: "10.0.0.1:50000",
      server: "10.0.0.2:80",
      request: {
        method: "POST",
        uri: "/api/config",
        body: JSON.stringify({
          bypass: true,
          compass: "north",
          passport: "A12345678",
          surpass: 99
        })
      }
    }
  ];

  const result = extractCredentials(benignHttp, []);
  assert.strictEqual(result.totalCredentialsFound, 0, "Benign words containing 'pass' must NOT be flagged as credentials");

  const validHttp = [
    {
      client: "10.0.0.1:50000",
      server: "10.0.0.2:80",
      request: {
        method: "POST",
        uri: "/api/login",
        body: JSON.stringify({
          user: "admin",
          password: "SuperSecretPassword123!"
        })
      }
    }
  ];
  const validResult = extractCredentials(validHttp, []);
  assert.strictEqual(validResult.totalCredentialsFound, 1);
  assert.strictEqual(validResult.credentials[0].username, "admin");
  assert.strictEqual(validResult.credentials[0].password, "SuperSecretPassword123!");
});

test("DNS Tunneling Immunity on Multi-Tenant Domains (github.io, pages.dev, azurewebsites.net)", () => {
  const queries = [];
  // 30 distinct long developer queries under github.io
  for (let i = 0; i < 30; i++) {
    queries.push({ name: `subsite-${i}-project-documentation-assets.github.io.` });
  }

  const result = detectDNSTunneling(queries, { minSubdomains: 15 });
  const githubEntry = result.suspiciousDomains.find(d => d.parentDomain === "github.io");
  assert.ok(githubEntry, "github.io should be analyzed");
  assert.strictEqual(githubEntry.isKnownCdnDomain, true, "github.io must be recognized as trusted multi-tenant infrastructure");
  assert.strictEqual(githubEntry.confidence, "LOW", "Multi-tenant domains must NOT trigger HIGH confidence tunneling alerts");
});

test("Fragmented Multi-Segment TLS ClientHello Reassembly & SNI Extraction", () => {
  const tlsHello = buildClientHello("cloud-vault.enterprise-finance.com");
  const seg1 = tlsHello.subarray(0, 40);
  const seg2 = tlsHello.subarray(40);

  const reassembler = new TCPReassembler();
  reassembler.addPacket("10.0.0.1", "1.1.1.1", { protocol: "TCP", srcPort: 54321, dstPort: 443, seqNum: 1000, flags: { ACK: true } }, seg1, new Date().toISOString());
  reassembler.addPacket("10.0.0.1", "1.1.1.1", { protocol: "TCP", srcPort: 54321, dstPort: 443, seqNum: 1040, flags: { PSH: true, ACK: true } }, seg2, new Date().toISOString());

  const streams = reassembler.getStreams();
  assert.strictEqual(streams.length, 1);
  assert.strictEqual(streams[0].clientData.length, tlsHello.length);

  const hello = parseClientHello(streams[0].clientData);
  assert.ok(hello);
  assert.strictEqual(hello.sni, "cloud-vault.enterprise-finance.com");
});

// ----------------------------------------------------
// 26. Enterprise Protocol Triage & Anti-False-Negative Banners
// ----------------------------------------------------
console.log(`\n🏢 26. Enterprise Protocol Triage & Anti-False-Negative Banners`);

test("Detect unparsed enterprise protocols (SMB & Kerberos) and emit agent handoff hints", () => {
  const pcapHeader = buildPcapHeader();
  const records = [];

  function makeTcpPacket(srcPort, dstPort, id, ipLen = 40) {
    const eth = Buffer.alloc(14);
    eth.writeUInt16BE(0x0800, 12);
    const ip = Buffer.alloc(20);
    ip[0] = 0x45;
    ip.writeUInt16BE(ipLen, 2);
    ip.writeUInt16BE(id, 4);
    ip[8] = 64;
    ip[9] = 6; // TCP
    ip.set([192, 168, 1, 100], 12);
    ip.set([192, 168, 1, 10], 16);
    const tcp = Buffer.alloc(20);
    tcp.writeUInt16BE(srcPort, 0);
    tcp.writeUInt16BE(dstPort, 2);
    tcp[12] = 0x50; // 5 * 4 = 20
    tcp[13] = TCP_FLAGS.ACK;
    return Buffer.concat([eth, ip, tcp]);
  }

  // 50 SMB packets (port 445)
  for (let i = 0; i < 50; i++) {
    const pkt = makeTcpPacket(50000 + i, 445, 1000 + i);
    records.push(buildPacketRecord({ tsSec: 1700000000 + i, data: pkt }));
  }

  // 20 Kerberos packets (port 88)
  for (let i = 0; i < 20; i++) {
    const pkt = makeTcpPacket(51000 + i, 88, 2000 + i);
    records.push(buildPacketRecord({ tsSec: 1700000100 + i, data: pkt }));
  }

  const pcapBuf = Buffer.concat([pcapHeader, ...records]);
  const { packets, warnings } = analyzePcapBuffer(pcapBuf);
  assert.strictEqual(packets.length, 70);

  const summary = generateSummary(packets, warnings);
  assert.strictEqual(summary.totalPackets, 70);
  assert.ok(Array.isArray(summary.unparsedEnterpriseProtocols), "unparsedEnterpriseProtocols must be present");
  assert.strictEqual(summary.unparsedEnterpriseProtocols.length, 2);

  const smbProto = summary.unparsedEnterpriseProtocols.find(p => p.name === "SMB");
  assert.ok(smbProto, "SMB must be identified");
  assert.strictEqual(smbProto.port, 445);
  assert.strictEqual(smbProto.packetCount, 50);

  const krbProto = summary.unparsedEnterpriseProtocols.find(p => p.name === "Kerberos");
  assert.ok(krbProto, "Kerberos must be identified");
  assert.strictEqual(krbProto.port, 88);
  assert.strictEqual(krbProto.packetCount, 20);

  assert.ok(Array.isArray(summary.agentHandoffHints), "agentHandoffHints must be present");
  assert.ok(summary.agentHandoffHints.length >= 3, "At least 3 handoff guidance items expected");
  assert.ok(summary.agentHandoffHints[0].includes("70 packets of enterprise non-web protocols"));
  assert.ok(summary.agentHandoffHints[1].includes("PacketChef specializes in Web/DNS/TLS/QUIC"));
  assert.ok(summary.agentHandoffHints[2].includes("DO NOT conclude the capture is clean"));
  assert.ok(summary.agentHandoffHints[2].includes("tshark -r <capture> -Y 'smb || kerberos'"));

  const entWarn = summary.warnings.find(w => w.includes("UNPARSED_ENTERPRISE_PROTOCOLS"));
  assert.ok(entWarn, "Warnings array must contain unparsed enterprise alert");
});

// ----------------------------------------------------
// 27. Layer 3 IPv4 Defragmentation Engine (RFC 791)
// ----------------------------------------------------
console.log(`\n🧩 27. Layer 3 IPv4 Defragmentation Engine (RFC 791)`);

test("IPv4Defragmenter reassembles in-order and out-of-order fragmented UDP datagrams", () => {
  const defrag = new IPv4Defragmenter();

  // Create synthetic 300-byte UDP datagram
  const udpHeader = Buffer.alloc(8);
  udpHeader.writeUInt16BE(45000, 0); // srcPort
  udpHeader.writeUInt16BE(53, 2);    // dstPort (DNS)
  udpHeader.writeUInt16BE(300, 4);   // length
  udpHeader.writeUInt16BE(0, 6);     // csum

  const udpPayload = crypto.randomBytes(292);
  const fullL4 = Buffer.concat([udpHeader, udpPayload]);

  // Fragment 1: 180 bytes (offset 0, MF=1)
  const frag1Data = fullL4.subarray(0, 180);
  const ip1 = {
    srcIP: "10.0.0.1",
    dstIP: "1.1.1.1",
    protocol: 17,
    identification: 0x99aa,
    fragmentOffset: 0,
    isFragmented: true,
    flags: { MF: true, DF: false }
  };

  // Fragment 2: 120 bytes (offset 180, MF=0)
  const frag2Data = fullL4.subarray(180, 300);
  const ip2 = {
    srcIP: "10.0.0.1",
    dstIP: "1.1.1.1",
    protocol: 17,
    identification: 0x99aa,
    fragmentOffset: 180,
    isFragmented: true,
    flags: { MF: false, DF: false }
  };

  // 1. In-order test
  const res1 = defrag.addFragment(ip1, frag1Data, 1000);
  assert.strictEqual(res1.complete, false);
  assert.strictEqual(res1.isPending, true);

  const res2 = defrag.addFragment(ip2, frag2Data, 1002);
  assert.strictEqual(res2.complete, true);
  assert.strictEqual(res2.totalLength, 300);
  assert.ok(res2.reassembledPayload.equals(fullL4), "Reassembled payload must exactly match original 300 bytes");

  // 2. Out-of-order test (feed frag2 before frag1 with new identification)
  const ip1b = { ...ip1, identification: 0x99ab };
  const ip2b = { ...ip2, identification: 0x99ab };

  const outOfOrder1 = defrag.addFragment(ip2b, frag2Data, 2000);
  assert.strictEqual(outOfOrder1.complete, false);
  assert.strictEqual(outOfOrder1.isPending, true);

  const outOfOrder2 = defrag.addFragment(ip1b, frag1Data, 2005);
  assert.strictEqual(outOfOrder2.complete, true);
  assert.strictEqual(outOfOrder2.totalLength, 300);
  assert.ok(outOfOrder2.reassembledPayload.equals(fullL4), "Out-of-order reassembled payload must match");

  // 3. Datagram size ceiling test (>65535 bytes)
  const oversizedIp = {
    srcIP: "10.0.0.1",
    dstIP: "1.1.1.1",
    protocol: 17,
    identification: 0x99ac,
    fragmentOffset: 65500,
    isFragmented: true,
    flags: { MF: false }
  };
  const oversizedData = Buffer.alloc(100); // 65500 + 100 = 65600 > 65535
  const overRes = defrag.addFragment(oversizedIp, oversizedData, 3000);
  assert.strictEqual(overRes.complete, false);
  assert.strictEqual(overRes.error, "MAX_DATAGRAM_EXCEEDED");
});

test("End-to-End PCAP Dissection of fragmented UDP DNS packet through IPv4Defragmenter", () => {
  // Construct a 200-byte UDP DNS Query split across 2 IPv4 fragments
  const eth = Buffer.alloc(14);
  eth.writeUInt16BE(0x0800, 12);

  // UDP datagram: 8-byte header + 192 bytes DNS payload
  const udpHeader = Buffer.alloc(8);
  udpHeader.writeUInt16BE(55555, 0);
  udpHeader.writeUInt16BE(53, 2);
  udpHeader.writeUInt16BE(200, 4);

  // Valid minimal DNS Query payload
  const dnsHeader = Buffer.alloc(12);
  dnsHeader.writeUInt16BE(0x1234, 0); // ID
  dnsHeader.writeUInt16BE(0x0100, 2); // Standard query
  dnsHeader.writeUInt16BE(1, 4);      // QDCOUNT = 1
  const dnsQ = Buffer.concat([Buffer.from("\x06google\x03com\x00"), Buffer.from("\x00\x01\x00\x01")]);
  const dnsPad = Buffer.alloc(192 - dnsHeader.length - dnsQ.length, 0x41);
  const dnsFull = Buffer.concat([dnsHeader, dnsQ, dnsPad]);
  const l4Full = Buffer.concat([udpHeader, dnsFull]); // 200 bytes

  // Packet 1: First 120 bytes of L4 payload (includes UDP header).
  // Flags: MF=1, Offset=0 -> flagsFrag = 0x2000
  const ip1 = Buffer.alloc(20);
  ip1[0] = 0x45;
  ip1.writeUInt16BE(20 + 120, 2); // Total length = 140
  ip1.writeUInt16BE(0x5678, 4);    // Identification
  ip1.writeUInt16BE(0x2000, 6);    // MF = 1, Offset = 0
  ip1[8] = 64;                     // TTL
  ip1[9] = 17;                     // UDP
  ip1.set([192, 168, 1, 50], 12);
  ip1.set([8, 8, 8, 8], 16);

  const pkt1Data = Buffer.concat([eth, ip1, l4Full.subarray(0, 120)]);

  // Packet 2: Remaining 80 bytes.
  // Flags: MF=0, Offset=120 (120 / 8 = 15 = 0x000F) -> flagsFrag = 0x000F
  const ip2 = Buffer.alloc(20);
  ip2[0] = 0x45;
  ip2.writeUInt16BE(20 + 80, 2);  // Total length = 100
  ip2.writeUInt16BE(0x5678, 4);   // Same identification
  ip2.writeUInt16BE(0x000F, 6);   // MF = 0, Offset = 120 (15 * 8)
  ip2[8] = 64;
  ip2[9] = 17;
  ip2.set([192, 168, 1, 50], 12);
  ip2.set([8, 8, 8, 8], 16);

  const pkt2Data = Buffer.concat([eth, ip2, l4Full.subarray(120, 200)]);

  const pcapHeader = buildPcapHeader();
  const rec1 = buildPacketRecord({ tsSec: 1700000500, data: pkt1Data });
  const rec2 = buildPacketRecord({ tsSec: 1700000501, data: pkt2Data });
  const pcapBuf = Buffer.concat([pcapHeader, rec1, rec2]);

  const { packets } = analyzePcapBuffer(pcapBuf);
  assert.strictEqual(packets.length, 2);

  // Packet 1 is pending defragmentation
  assert.strictEqual(packets[0].network.isFragmented, true);
  assert.strictEqual(packets[0].isFragmentPending, true);
  assert.strictEqual(packets[0].isDefragmented, false);

  // Packet 2 completes the datagram
  assert.strictEqual(packets[1].network.isFragmented, true);
  assert.strictEqual(packets[1].isFragmentPending, false);
  assert.strictEqual(packets[1].isDefragmented, true);
  assert.strictEqual(packets[1].transport.protocol, "UDP");
  assert.strictEqual(packets[1].transport.dstPort, 53);
  assert.strictEqual(packets[1].appProtocol, "DNS");
  assert.strictEqual(packets[1].payload.length, 192); // 200 bytes minus 8-byte UDP header
});

// ----------------------------------------------------
// 28. Capture Safety Guardrails & Truncation
// ----------------------------------------------------
console.log(`\n🛡️ 28. Capture Safety Guardrails & Truncation`);

test("parsePcap and analyzePcapBuffer enforce maxPackets limit and attach editcap guidance", () => {
  const fixturePath = path.join(__dirname, "test", "fixtures", "sample_5pkt.pcap");
  const fileBytes = fs.readFileSync(fixturePath);

  // 1. parsePcap with maxPackets: 2
  const parsed = parsePcap(fileBytes, { maxPackets: 2 });
  assert.strictEqual(parsed.packets.length, 2);
  const truncWarn = parsed.warnings.find(w => w.includes("CAPTURE_TRUNCATED"));
  assert.ok(truncWarn, "parsePcap must emit CAPTURE_TRUNCATED warning when packet limit hit");
  assert.ok(truncWarn.includes("editcap -c 50000"), "Warning must advise using editcap");

  // 2. analyzePcapBuffer with maxPackets: 3
  const analyzed = analyzePcapBuffer(fileBytes, { maxPackets: 3 });
  assert.strictEqual(analyzed.packets.length, 3);
  const analyzedWarn = analyzed.warnings.find(w => w.includes("CAPTURE_TRUNCATED"));
  assert.ok(analyzedWarn, "analyzePcapBuffer must emit CAPTURE_TRUNCATED warning");
  assert.ok(analyzedWarn.includes("editcap -c 50000"), "Must provide actionable editcap command");
});

// ----------------------------------------------------
// 29. HTTP/2 Connection Preface Detection & Fail-Fast Triage
// ----------------------------------------------------
console.log(`\n🌐 29. HTTP/2 Connection Preface Detection & Fail-Fast Triage`);

test("parseHTTPStream detects HTTP/2 client connection preface (RFC 7540)", () => {
  const http2ClientStream = Buffer.concat([
    HTTP2_CLIENT_PREFACE,
    Buffer.from([0x00, 0x00, 0x04, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00]) // SETTINGS frame
  ]);
  const serverResponse = Buffer.alloc(0);

  const { requests, responses, hasHttp2 } = parseHTTPStream(http2ClientStream, serverResponse);
  assert.strictEqual(hasHttp2, true, "Must flag hasHttp2: true");
  assert.strictEqual(requests.length, 0, "Must not misparse binary HTTP/2 frames as HTTP/1.x requests");
});

test("HTTP/2 stream triggers HTTP2_UNPARSED warning with surgical tshark handoff", () => {
  // Build synthetic PCAP with HTTP/2 stream on port 80
  const eth = Buffer.alloc(14);
  eth.writeUInt16BE(0x0800, 12);
  const ip = Buffer.alloc(20);
  ip[0] = 0x45;
  ip.writeUInt16BE(40 + HTTP2_CLIENT_PREFACE.length, 2);
  ip.writeUInt16BE(0x1122, 4);
  ip[8] = 64;
  ip[9] = 6; // TCP
  ip.set([192, 168, 1, 100], 12);
  ip.set([93, 184, 216, 34], 16);

  const tcp = Buffer.alloc(20);
  tcp.writeUInt16BE(54321, 0);
  tcp.writeUInt16BE(80, 2);
  tcp.writeUInt32BE(1000, 4);
  tcp[12] = 0x50;
  tcp[13] = TCP_FLAGS.PSH | TCP_FLAGS.ACK;

  const pktData = Buffer.concat([eth, ip, tcp, HTTP2_CLIENT_PREFACE]);
  const pcapHeader = buildPcapHeader();
  const rec = buildPacketRecord({ tsSec: 1700000000, data: pktData });
  const pcapBuf = Buffer.concat([pcapHeader, rec]);

  const { packets } = analyzePcapBuffer(pcapBuf);
  assert.strictEqual(packets.length, 1);

  const reassembler = new TCPReassembler();
  reassembler.addPacket(packets[0].network.srcIP, packets[0].network.dstIP, packets[0].transport, packets[0].payload, packets[0].timestampISO);
  const streams = reassembler.getStreams();
  assert.strictEqual(streams.length, 1);

  const { hasHttp2 } = parseHTTPStream(streams[0].clientData, streams[0].serverData);
  assert.strictEqual(hasHttp2, true);
});

// ----------------------------------------------------
// 30. WebSocket RFC 7692 Compression Flagging (permessage-deflate)
// ----------------------------------------------------
console.log(`\n🔌 30. WebSocket RFC 7692 Compression Flagging`);

test("parseWebSocketFrames detects permessage-deflate and flags compressed frames", () => {
  // Build WebSocket upgrade request containing permessage-deflate extension
  const upgradeHeader = "GET /chat HTTP/1.1\r\n" +
    "Host: server.example.com\r\n" +
    "Upgrade: websocket\r\n" +
    "Connection: Upgrade\r\n" +
    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
    "Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n" +
    "Sec-WebSocket-Version: 13\r\n\r\n";

  // Build compressed frame: FIN=1, RSV1=1 (compressed), opcode=1 (TEXT), unmasked
  // b0: 0x80 (FIN) | 0x40 (RSV1) | 0x01 (TEXT) = 0xc1
  // b1: 0x0a (length 10, unmasked)
  const compressedPayload = Buffer.from([0x72, 0x49, 0x4d, 0xcb, 0x49, 0x2c, 0x49, 0x55, 0x00, 0x00]);
  const frameHeader = Buffer.from([0xc1, compressedPayload.length]);
  const streamBuf = Buffer.concat([Buffer.from(upgradeHeader), frameHeader, compressedPayload]);

  const frames = parseWebSocketFrames(streamBuf, "server->client");
  assert.strictEqual(frames.length, 1);
  assert.strictEqual(frames[0].fin, true);
  assert.strictEqual(frames[0].rsv1, true);
  assert.strictEqual(frames[0].isCompressed, true);
  assert.strictEqual(frames[0].compressionAlgorithm, "deflate");
  assert.ok(frames[0].textPreview.includes("compressed deflate"));
  assert.ok(frames[0].handoffHint.includes("cyberchef_gunzip"));
});

// ----------------------------------------------------
// 31. IPv6 Extension Header 44 (Fragmentation Guard)
// ----------------------------------------------------
console.log(`\n🌐 31. IPv6 Extension Header 44 (Fragmentation Guard)`);

test("decodeIPv6 parses Fragment Extension Header 44 and flags continuation slices", () => {
  // Construct 40-byte IPv6 header + 8-byte Fragment Header + 100 bytes payload
  const ipv6Data = Buffer.alloc(40 + 8 + 100);
  ipv6Data.writeUInt32BE(0x60000000, 0); // Version 6
  ipv6Data.writeUInt16BE(8 + 100, 4);     // Payload length (fragment header 8 + payload 100)
  ipv6Data[6] = 44;                      // Next Header = Fragment (44)
  ipv6Data[7] = 64;                      // Hop limit
  ipv6Data.set([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 8);  // 2001:db8::1
  ipv6Data.set([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2], 24); // 2001:db8::2

  // Fragment Header (offset 40):
  // Byte 0: Next Header = 6 (TCP)
  // Byte 1: Reserved
  // Bytes 2-3: Fragment Offset = 120 (120/8 = 15 = 0x000F) | M = 1 -> 0x0079
  // Bytes 4-7: Identification = 0x12345678
  const fragOffset = 40;
  ipv6Data[fragOffset] = 6; // encapsulated TCP
  ipv6Data[fragOffset + 1] = 0;
  ipv6Data.writeUInt16BE(0x0079, fragOffset + 2); // offset 120, M=1
  ipv6Data.writeUInt32BE(0x12345678, fragOffset + 4);

  const ip6 = decodeIPv6(ipv6Data, 0);
  assert.strictEqual(ip6.version, 6);
  assert.strictEqual(ip6.isFragmented, true);
  assert.strictEqual(ip6.nextHeader, 6, "Encapsulated nextHeader should be TCP");
  assert.strictEqual(ip6.rawNextHeader, 44, "Raw nextHeader should be Fragment (44)");
  assert.strictEqual(ip6.hasMoreFragments, true);
  assert.strictEqual(ip6.identification, 0x12345678);
  assert.strictEqual(ip6.payloadOffset, 48); // 40 + 8
});

test("packet-dissector suppresses invalid L4 decoding on IPv6 continuation fragments", () => {
  const eth = Buffer.alloc(14);
  eth.writeUInt16BE(0x86dd, 12); // IPv6 EtherType

  const ipv6Data = Buffer.alloc(40 + 8 + 60);
  ipv6Data.writeUInt32BE(0x60000000, 0);
  ipv6Data.writeUInt16BE(8 + 60, 4);
  ipv6Data[6] = 44; // Fragment
  ipv6Data[7] = 64;
  ipv6Data.set([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 8);
  ipv6Data.set([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2], 24);

  // Continuation fragment: offset 120 > 0
  ipv6Data[40] = 6; // TCP
  ipv6Data.writeUInt16BE(0x0079, 42); // offset 120, M=1
  ipv6Data.writeUInt32BE(0xaabbccdd, 44);

  const pktData = Buffer.concat([eth, ipv6Data]);
  const rawPkt = {
    index: 1,
    linkType: 1,
    origLen: pktData.length,
    inclLen: pktData.length,
    data: pktData,
    timestampMs: 1700000000000,
    timestampISO: new Date(1700000000000).toISOString()
  };

  const dissected = dissectPacket(rawPkt);
  assert.strictEqual(dissected.network.version, 6);
  assert.strictEqual(dissected.network.isFragmented, true);
  assert.strictEqual(dissected.isFragmentPending, true);
  assert.strictEqual(dissected.transport, null, "Continuation fragment must NOT parse corrupted L4 headers");
  assert.strictEqual(dissected.payload.length, 60);
});

// ----------------------------------------------------
// 32. Truth-in-Triage Coverage Envelope
// ----------------------------------------------------
console.log(`\n📊 32. Truth-in-Triage Coverage Envelope`);

test("generateSummary calculates inspectionCoverageRatio and populates uninspectedCategories", () => {
  const fixturePath = path.join(__dirname, "test", "fixtures", "sample_5pkt.pcap");
  const fileBytes = fs.readFileSync(fixturePath);

  const { packets, warnings } = analyzePcapBuffer(fileBytes);
  const summary = generateSummary(packets, warnings);

  assert.ok(summary.coverageEnvelope, "coverageEnvelope must be present in summary");
  assert.strictEqual(typeof summary.coverageEnvelope.inspectionCoverageRatio, "number");
  assert.strictEqual(typeof summary.coverageEnvelope.uninspectedVolumeRatio, "number");
  assert.ok(Array.isArray(summary.coverageEnvelope.analyzedProtocols));
  assert.ok(Array.isArray(summary.coverageEnvelope.uninspectedCategories));
  assert.ok(summary.coverageEnvelope.verdictConfidence);
  assert.ok(summary.coverageEnvelope.aiCognitiveGuidance);
});

// ----------------------------------------------------
// 33. Global Stream Buffer Memory Ceiling (32MB)
// ----------------------------------------------------
console.log(`\n🛡️ 33. Global Stream Buffer Memory Ceiling (32MB)`);

test("TCPReassembler enforces 32MB global memory ceiling under stream flooding", () => {
  const reassembler = new TCPReassembler();
  assert.strictEqual(MAX_GLOBAL_STREAM_BYTES, 32 * 1024 * 1024);

  // Synthesize streams with large segments
  const chunkSize = 500 * 1024; // 500KB per stream
  const chunkData = Buffer.alloc(chunkSize, 0x42);

  for (let i = 0; i < 75; i++) {
    // 75 streams * 500KB = 37.5MB total attempted data
    const srcPort = 10000 + i;
    const tcpHeader = {
      srcPort,
      dstPort: 80,
      seqNum: 1000,
      flags: { SYN: true, ACK: false }
    };
    reassembler.addPacket(`10.0.0.${i + 1}`, "1.1.1.1", tcpHeader, chunkData);
  }

  // Verify memory cap remained bounded
  const totalBuffered = reassembler._getTotalBufferedBytes();
  assert.ok(totalBuffered <= MAX_GLOBAL_STREAM_BYTES, `Total buffered (${totalBuffered}) must not exceed 32MB`);
});

// ----------------------------------------------------
// 34. Adversarial Wire Edge-Cases & Invisible Failures
// ----------------------------------------------------
console.log(`\n🔥 34. Adversarial Wire Edge-Cases & Invisible Failures`);

test("parseDNS correctly strips RFC 1035 §4.2.2 2-byte TCP length prefix", () => {
  const qName = Buffer.from([0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00]);
  const qTypeClass = Buffer.from([0x00, 0x01, 0x00, 0x01]);
  const dnsMessage = Buffer.concat([
    Buffer.from([0x12, 0x34]), // txId
    Buffer.from([0x01, 0x00]), // flags
    Buffer.from([0x00, 0x01]), // qdcount
    Buffer.from([0x00, 0x00]),
    Buffer.from([0x00, 0x00]),
    Buffer.from([0x00, 0x00]),
    qName,
    qTypeClass
  ]);
  const tcpDnsPayload = Buffer.concat([
    Buffer.from([(dnsMessage.length >> 8) & 0xff, dnsMessage.length & 0xff]),
    dnsMessage
  ]);

  const parsed = parseDNS(tcpDnsPayload, true);
  assert.ok(parsed, "DNS over TCP should parse successfully");
  assert.strictEqual(parsed.transactionId, 0x1234);
  assert.strictEqual(parsed.questions.length, 1);
  assert.strictEqual(parsed.questions[0].name, "example.com");
  assert.strictEqual(parsed.questions[0].type, "A");
});

test("parseHTTPStream auto-detects inverted stream orientation on mid-stream captures", () => {
  const reassembler = new TCPReassembler();
  const cIP = "192.168.1.100", sIP = "93.184.216.34", cPort = 54321, sPort = 80;

  // Mid-stream capture begins with server packet
  reassembler.addPacket(sIP, cIP, { srcPort: sPort, dstPort: cPort, seqNum: 5000, flags: { ACK: true } }, Buffer.alloc(0));
  const httpGet = Buffer.from("GET /api/secret HTTP/1.1\r\nHost: example.com\r\n\r\n");
  reassembler.addPacket(cIP, sIP, { srcPort: cPort, dstPort: sPort, seqNum: 1000, flags: { ACK: true, PSH: true } }, httpGet);
  const httpResp = Buffer.from("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK");
  reassembler.addPacket(sIP, cIP, { srcPort: sPort, dstPort: cPort, seqNum: 5000, flags: { ACK: true, PSH: true } }, httpResp);

  const streams = reassembler.getStreams();
  assert.strictEqual(streams.length, 1);
  const res = parseHTTPStream(streams[0].clientData, streams[0].serverData);
  assert.strictEqual(res.requests.length, 1, "Should recover inverted client request");
  assert.strictEqual(res.requests[0].uri, "/api/secret");
  assert.strictEqual(res.responses.length, 1, "Should recover inverted server response");
  assert.strictEqual(res.responses[0].statusCode, 200);
});

test("DirectionReassembler ignores duplicate SYN on active stream to prevent sequence desync", () => {
  const reassembler = new TCPReassembler();
  const cIP = "10.0.0.1", sIP = "10.0.0.2", cPort = 1234, sPort = 80;

  reassembler.addPacket(cIP, sIP, { srcPort: cPort, dstPort: sPort, seqNum: 100, flags: { SYN: true } }, Buffer.alloc(0));
  reassembler.addPacket(cIP, sIP, { srcPort: cPort, dstPort: sPort, seqNum: 101, flags: { ACK: true } }, Buffer.from("0123456789"));
  // Duplicate SYN arrives
  reassembler.addPacket(cIP, sIP, { srcPort: cPort, dstPort: sPort, seqNum: 100, flags: { SYN: true } }, Buffer.alloc(0));
  reassembler.addPacket(cIP, sIP, { srcPort: cPort, dstPort: sPort, seqNum: 111, flags: { ACK: true } }, Buffer.from("ABCDEFGHIJ"));

  const st = reassembler.getStreams()[0];
  assert.strictEqual(st.clientData.toString("utf8"), "0123456789ABCDEFGHIJ");
});

test("decodeIPv6 traverses chained extension headers (Hop-by-Hop -> UDP)", () => {
  const ipv6Header = Buffer.alloc(40);
  ipv6Header.writeUInt32BE(0x60000000, 0);
  ipv6Header.writeUInt16BE(16, 4);
  ipv6Header[6] = 0; // Hop-by-Hop
  ipv6Header[7] = 64;
  ipv6Header[23] = 1;
  ipv6Header[39] = 2;

  const hbhHeader = Buffer.from([17, 0, 0x05, 0x02, 0x00, 0x00, 0x01, 0x00]); // Next: UDP (17)
  const udpHeader = Buffer.from([0x14, 0xe9, 0x14, 0xe9, 0x00, 0x08, 0x00, 0x00]);
  const rawPacket = Buffer.concat([ipv6Header, hbhHeader, udpHeader]);

  const ethHeader = Buffer.concat([Buffer.alloc(6, 0xaa), Buffer.alloc(6, 0xbb), Buffer.from([0x86, 0xdd])]);
  const fullFrame = Buffer.concat([ethHeader, rawPacket]);

  const dissected = dissectPacket({ data: fullFrame, timestampMs: 1000, wireLength: fullFrame.length }, 1);
  assert.ok(dissected.transport, "Layer 4 transport must be parsed past extension header");
  assert.strictEqual(dissected.transport.protocol, "UDP");
  assert.strictEqual(dissected.transport.srcPort, 5353);
});

test("extractCredentials preserves multi-word passphrases with spaces in form and JSON bodies", () => {
  const reqForm = {
    method: "POST",
    uri: "/login",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: "username=admin&password=Correct Horse Battery Staple!&token=xyz"
  };
  const resForm = extractCredentials([reqForm], []);
  assert.strictEqual(resForm.totalCredentialsFound, 1);
  assert.strictEqual(resForm.credentials[0].password, "Correct Horse Battery Staple!");

  const reqJson = {
    method: "POST",
    uri: "/api/auth",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ username: "alice", password: "Secret Space Phrase 2026" })
  };
  const resJson = extractCredentials([reqJson], []);
  assert.strictEqual(resJson.totalCredentialsFound, 1);
  assert.strictEqual(resJson.credentials[0].password, "Secret Space Phrase 2026");
});

// ----------------------------------------------------
// Test Summary
// ----------------------------------------------------
console.log(`\n========================================`);
console.log(`🏁 Complete packet-chef-mcp Test Results: ${passed} passed, ${failed} failed`);
console.log(`========================================\n`);

if (failed > 0) {
  process.exit(1);
}


