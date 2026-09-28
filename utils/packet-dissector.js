/**
 * packet-chef-mcp - Layer 2-4 Packet Dissector Pipeline (v2)
 * Decodes raw packet records into structured forensic objects with per-packet isolation.
 * Supports Ethernet, Linux SLL (113), Loopback (0), Raw IP (12), IPv4/IPv6,
 * TCP, UDP, ICMP, Layer 3 IPv4 Defragmentation, TLS ClientHello (with JA3/JA4),
 * QUIC Initial SNI, and WebSocket hints.
 */

import { decodeEthernet, ETHER_TYPES } from "./ethernet.js";
import { decodeSLL, decodeLoopback, decodeRawIP } from "./sll.js";
import { decodeIPv4, IP_PROTOCOLS } from "./ipv4.js";
import { decodeIPv6 } from "./ipv6.js";
import { decodeTCP } from "./tcp.js";
import { decodeUDP } from "./udp.js";
import { parseClientHello } from "./tls-parser.js";
import { parseQuicInitial } from "./quic-parser.js";
import { IPv4Defragmenter } from "./ipv4-defragmenter.js";

/**
 * Dissects a single packet through Layer 2 -> Layer 3 -> Layer 4 -> Layer 7 hints.
 * Never throws uncaught exceptions; errors are caught and returned in error fields.
 * @param {object} pkt Packet record from pcap-parser or pcapng-parser
 * @param {number} [defaultLinkType=1]
 * @param {IPv4Defragmenter} [defragmenter=null] Optional L3 defragmenter instance
 * @returns {object} Dissected packet representation
 */
export function dissectPacket(pkt, defaultLinkType = 1, defragmenter = null) {
  const linkType = pkt.linkType || defaultLinkType || 1;

  const result = {
    index: pkt.index,
    timestampISO: pkt.timestampISO,
    timestampMs: pkt.timestampMs,
    wireLength: pkt.origLen,
    capturedLength: pkt.inclLen,
    isTruncated: pkt.isTruncated || false,
    linkType,
    ethernet: null,
    network: null,
    transport: null,
    appProtocol: "UNKNOWN",
    payload: Buffer.alloc(0),
    isFragmentPending: false,
    isDefragmented: false,
    defragmentedLength: null,
    ja3: null,
    quic: null,
    parseError: null
  };

  try {
    let etherType = null;
    let nextOffset = 0;

    // 1. Layer 2: Link Layer Dispatch (Ethernet, Linux SLL, Loopback, Raw IP)
    if (linkType === 113) {
      // Linux Cooked Capture (SLL)
      const sll = decodeSLL(pkt.data, 0);
      result.ethernet = {
        srcMac: sll.srcMac,
        dstMac: null,
        etherType: sll.etherType,
        packetType: sll.packetType
      };
      etherType = sll.etherType;
      nextOffset = sll.payloadOffset;
    } else if (linkType === 0) {
      // Loopback / Null
      const loop = decodeLoopback(pkt.data, 0);
      result.ethernet = {
        srcMac: null,
        dstMac: null,
        etherType: loop.etherType,
        family: loop.family
      };
      etherType = loop.etherType;
      nextOffset = loop.payloadOffset;
    } else if (linkType === 12) {
      // Raw IP
      const raw = decodeRawIP(pkt.data, 0);
      etherType = raw.etherType;
      nextOffset = raw.payloadOffset;
    } else {
      // Default: Ethernet II (LinkType 1)
      const eth = decodeEthernet(pkt.data, 0);
      result.ethernet = {
        srcMac: eth.srcMac,
        dstMac: eth.dstMac,
        etherType: eth.etherType,
        vlanId: eth.vlanId
      };
      etherType = eth.etherType;
      nextOffset = eth.payloadOffset;
    }

    // 2. Layer 3: Network Layer (IPv4 / IPv6 / ARP)
    if (etherType === ETHER_TYPES.IPV4) {
      const ip = decodeIPv4(pkt.data, nextOffset);
      result.network = {
        version: 4,
        srcIP: ip.srcIP,
        dstIP: ip.dstIP,
        protocol: ip.protocol,
        protocolName: ip.protocolName,
        ttl: ip.ttl,
        isFragmented: ip.isFragmented,
        fragmentOffset: ip.fragmentOffset,
        identification: ip.identification
      };

      let l4Buffer = pkt.data;
      let l4Offset = ip.payloadOffset;
      let shouldDecodeL4 = true;

      // Handle Layer 3 IPv4 Fragmentation
      if (ip.isFragmented) {
        const fragData = pkt.data.subarray(ip.payloadOffset, ip.payloadOffset + ip.payloadLength);
        if (defragmenter) {
          const defragResult = defragmenter.addFragment(ip, fragData, pkt.timestampMs);
          if (defragResult && defragResult.complete) {
            result.isDefragmented = true;
            result.defragmentedLength = defragResult.reassembledPayload.length;
            l4Buffer = defragResult.reassembledPayload;
            l4Offset = 0;
            shouldDecodeL4 = true;
          } else {
            result.isFragmentPending = true;
            result.payload = fragData;
            shouldDecodeL4 = false;
          }
        } else {
          // No defragmenter provided: only fragment offset 0 has L4 header
          if (ip.fragmentOffset === 0) {
            result.isFragmentPending = true;
            shouldDecodeL4 = true;
          } else {
            result.isFragmentPending = true;
            result.payload = fragData;
            shouldDecodeL4 = false;
          }
        }
      }

      // 3. Layer 4: Transport (TCP / UDP / ICMP)
      if (shouldDecodeL4) {
        if (ip.protocol === IP_PROTOCOLS.TCP) {
          const tcp = decodeTCP(l4Buffer, l4Offset);
          result.transport = {
            protocol: "TCP",
            srcPort: tcp.srcPort,
            dstPort: tcp.dstPort,
            seqNum: tcp.seqNum,
            ackNum: tcp.ackNum,
            flags: tcp.flags,
            windowSize: tcp.windowSize
          };
          result.payload = tcp.payload;

          // Fast Layer 7 heuristic tags & JA3
          if (tcp.srcPort === 80 || tcp.dstPort === 80 || tcp.srcPort === 8080 || tcp.dstPort === 8080) {
            result.appProtocol = "HTTP";
          } else if (tcp.srcPort === 443 || tcp.dstPort === 443) {
            result.appProtocol = "TLS";
            // Attempt TLS ClientHello extraction + JA3
            if (tcp.payload && tcp.payload.length >= 44) {
              const tls = parseClientHello(tcp.payload);
              if (tls && tls.ja3) {
                result.ja3 = tls.ja3;
              }
            }
          } else if (tcp.srcPort === 53 || tcp.dstPort === 53) {
            result.appProtocol = "DNS";
          }
        } else if (ip.protocol === IP_PROTOCOLS.UDP) {
          const udp = decodeUDP(l4Buffer, l4Offset);
          result.transport = {
            protocol: "UDP",
            srcPort: udp.srcPort,
            dstPort: udp.dstPort,
            length: udp.length
          };
          result.payload = udp.payload;

          // Fast Layer 7 heuristic tags & QUIC Initial
          if (udp.srcPort === 53 || udp.dstPort === 53) {
            result.appProtocol = "DNS";
          } else if (udp.srcPort === 123 || udp.dstPort === 123) {
            result.appProtocol = "NTP";
          } else if (udp.srcPort === 443 || udp.dstPort === 443) {
            result.appProtocol = "QUIC";
            if (udp.payload && udp.payload.length >= 32) {
              const q = parseQuicInitial(udp.payload);
              if (q) {
                result.quic = q;
                if (q.ja3) result.ja3 = q.ja3;
              }
            }
          }
        } else if (ip.protocol === IP_PROTOCOLS.ICMP) {
          result.transport = {
            protocol: "ICMP",
            type: l4Buffer.length > l4Offset ? l4Buffer[l4Offset] : null,
            code: l4Buffer.length > l4Offset + 1 ? l4Buffer[l4Offset + 1] : null
          };
          result.payload = l4Buffer.subarray(l4Offset + 2);
          result.appProtocol = "ICMP";
        }
      }
    } else if (etherType === ETHER_TYPES.IPV6) {
      const ip6 = decodeIPv6(pkt.data, nextOffset);
      result.network = {
        version: 6,
        srcIP: ip6.srcIP,
        dstIP: ip6.dstIP,
        protocol: ip6.nextHeader,
        protocolName: ip6.nextHeaderName,
        ttl: ip6.hopLimit,
        isFragmented: ip6.isFragmented,
        fragmentOffset: ip6.fragmentOffset,
        identification: ip6.identification
      };

      nextOffset = ip6.payloadOffset;
      let shouldDecodeL4 = true;

      if (ip6.isFragmented) {
        result.isFragmentPending = true;
        if (ip6.fragmentOffset > 0) {
          shouldDecodeL4 = false;
          result.payload = pkt.data.subarray(nextOffset, nextOffset + ip6.capturedPayloadLength);
        }
      }

      if (shouldDecodeL4) {
        if (ip6.nextHeader === IP_PROTOCOLS.TCP) {
          const tcp = decodeTCP(pkt.data, nextOffset);
          result.transport = {
            protocol: "TCP",
            srcPort: tcp.srcPort,
            dstPort: tcp.dstPort,
            seqNum: tcp.seqNum,
            ackNum: tcp.ackNum,
            flags: tcp.flags,
            windowSize: tcp.windowSize
          };
          result.payload = tcp.payload;
          if (tcp.srcPort === 80 || tcp.dstPort === 80) result.appProtocol = "HTTP";
          else if (tcp.srcPort === 443 || tcp.dstPort === 443) result.appProtocol = "TLS";
          else if (tcp.srcPort === 53 || tcp.dstPort === 53) result.appProtocol = "DNS";
        } else if (ip6.nextHeader === IP_PROTOCOLS.UDP) {
          const udp = decodeUDP(pkt.data, nextOffset);
          result.transport = {
            protocol: "UDP",
            srcPort: udp.srcPort,
            dstPort: udp.dstPort,
            length: udp.length
          };
          result.payload = udp.payload;
          if (udp.srcPort === 53 || udp.dstPort === 53) result.appProtocol = "DNS";
          else if (udp.srcPort === 443 || udp.dstPort === 443) result.appProtocol = "QUIC";
        }
      }
    } else if (etherType === ETHER_TYPES.ARP) {
      result.appProtocol = "ARP";
      result.payload = pkt.data.subarray(nextOffset);
    }
  } catch (err) {
    result.parseError = err.message;
  }

  return result;
}

/**
 * Dissects an array of raw packet records using an isolated IPv4Defragmenter context.
 * @param {Array<object>} packets
 * @param {number} [defaultLinkType=1]
 * @returns {Array<object>} Dissected packets
 */
export function dissectPackets(packets, defaultLinkType = 1) {
  const defragmenter = new IPv4Defragmenter();
  return packets.map(pkt => dissectPacket(pkt, pkt.linkType || defaultLinkType, defragmenter));
}
