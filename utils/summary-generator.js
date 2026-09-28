/**
 * packet-chef-mcp - Capture Summary Generator
 * Computes high-density forensic overview: protocol distribution, bandwidth,
 * duration, unique IPs, top talkers, and enterprise non-web protocol triage warnings.
 */

export const ENTERPRISE_NON_WEB_PORTS = {
  445:  { name: "SMB", risk: "Lateral movement / PsExec / Ransomware file sharing" },
  139:  { name: "NetBIOS-SSN", risk: "Legacy SMB / NetBIOS session service" },
  88:   { name: "Kerberos", risk: "Ticket-granting / Kerberoasting / AS-REP Roasting" },
  389:  { name: "LDAP", risk: "Domain enumeration / BloodHound Active Directory queries" },
  636:  { name: "LDAPS", risk: "Secure LDAP directory queries" },
  135:  { name: "MS-RPC", risk: "Endpoint mapper / WMI execution / DCOM lateral movement" },
  3389: { name: "RDP", risk: "Remote Desktop Protocol graphical sessions" },
  22:   { name: "SSH", risk: "Secure Shell tunnels / terminal sessions" }
};

/**
 * Generates an executive capture summary from dissected packets.
 * @param {Array<object>} dissectedPackets
 * @param {Array<string>} [initialWarnings=[]]
 * @returns {object} Summary metadata object (<2KB JSON)
 */
export function generateSummary(dissectedPackets, initialWarnings = []) {
  const totalPackets = dissectedPackets.length;
  if (totalPackets === 0) {
    return {
      totalPackets: 0,
      durationSeconds: 0,
      totalBytes: 0,
      averagePacketSize: 0,
      protocols: {},
      identifiedApplications: {},
      uniqueSourceIPs: 0,
      uniqueDestIPs: 0,
      topTalkers: [],
      unparsedEnterpriseProtocols: [],
      agentHandoffHints: [],
      coverageEnvelope: {
        inspectionCoverageRatio: 0,
        uninspectedVolumeRatio: 0,
        analyzedProtocols: [],
        uninspectedCategories: [],
        verdictConfidence: "NO_TRAFFIC",
        aiCognitiveGuidance: "Empty capture."
      },
      warnings: Array.isArray(initialWarnings) ? initialWarnings : []
    };
  }

  let totalBytes = 0;
  let minMs = Infinity;
  let maxMs = -Infinity;

  const protocolCounts = {
    TCP: { count: 0, bytes: 0 },
    UDP: { count: 0, bytes: 0 },
    ICMP: { count: 0, bytes: 0 },
    other: { count: 0, bytes: 0 }
  };

  const appProtocolCounts = {};
  const srcIpSet = new Set();
  const dstIpSet = new Set();
  const talkerMap = new Map(); // ip -> { sentBytes, receivedBytes, totalBytes }
  const enterpriseMap = new Map(); // name -> { name, port, packetCount, byteVolume, risk }

  for (const pkt of dissectedPackets) {
    totalBytes += pkt.wireLength;
    if (pkt.timestampMs < minMs) minMs = pkt.timestampMs;
    if (pkt.timestampMs > maxMs) maxMs = pkt.timestampMs;

    // Protocol distribution
    const proto = pkt.transport ? pkt.transport.protocol : (pkt.network ? pkt.network.protocolName : "other");
    if (proto === "TCP") {
      protocolCounts.TCP.count++;
      protocolCounts.TCP.bytes += pkt.wireLength;
    } else if (proto === "UDP") {
      protocolCounts.UDP.count++;
      protocolCounts.UDP.bytes += pkt.wireLength;
    } else if (proto === "ICMP") {
      protocolCounts.ICMP.count++;
      protocolCounts.ICMP.bytes += pkt.wireLength;
    } else {
      protocolCounts.other.count++;
      protocolCounts.other.bytes += pkt.wireLength;
    }

    if (pkt.appProtocol && pkt.appProtocol !== "UNKNOWN") {
      appProtocolCounts[pkt.appProtocol] = (appProtocolCounts[pkt.appProtocol] || 0) + 1;
    }

    // Enterprise non-web detection
    if (pkt.transport) {
      const port = ENTERPRISE_NON_WEB_PORTS[pkt.transport.dstPort]
        ? pkt.transport.dstPort
        : (ENTERPRISE_NON_WEB_PORTS[pkt.transport.srcPort] ? pkt.transport.srcPort : null);
      if (port) {
        const meta = ENTERPRISE_NON_WEB_PORTS[port];
        if (!enterpriseMap.has(meta.name)) {
          enterpriseMap.set(meta.name, {
            name: meta.name,
            port: Number(port),
            packetCount: 0,
            byteVolume: 0,
            risk: meta.risk
          });
        }
        const ent = enterpriseMap.get(meta.name);
        ent.packetCount++;
        ent.byteVolume += pkt.wireLength;
      }
    }

    // IP tracking
    if (pkt.network && pkt.network.srcIP) {
      srcIpSet.add(pkt.network.srcIP);
      let s = talkerMap.get(pkt.network.srcIP);
      if (!s) {
        s = { ip: pkt.network.srcIP, sentBytes: 0, receivedBytes: 0, totalBytes: 0 };
        talkerMap.set(pkt.network.srcIP, s);
      }
      s.sentBytes += pkt.wireLength;
      s.totalBytes += pkt.wireLength;
    }

    if (pkt.network && pkt.network.dstIP) {
      dstIpSet.add(pkt.network.dstIP);
      let d = talkerMap.get(pkt.network.dstIP);
      if (!d) {
        d = { ip: pkt.network.dstIP, sentBytes: 0, receivedBytes: 0, totalBytes: 0 };
        talkerMap.set(pkt.network.dstIP, d);
      }
      d.receivedBytes += pkt.wireLength;
      d.totalBytes += pkt.wireLength;
    }
  }

  // Calculate percentages
  const protocolsFormatted = {};
  for (const [key, val] of Object.entries(protocolCounts)) {
    if (val.count > 0 || key !== "other") {
      protocolsFormatted[key] = {
        count: val.count,
        percent: +( (val.count / totalPackets) * 100 ).toFixed(1),
        bytes: val.bytes
      };
    }
  }

  // Top 10 talkers by totalBytes
  const topTalkers = Array.from(talkerMap.values())
    .sort((a, b) => b.totalBytes - a.totalBytes)
    .slice(0, 10);

  const durationSeconds = minMs !== Infinity && maxMs !== -Infinity
    ? +((maxMs - minMs) / 1000).toFixed(3)
    : 0;

  // Process enterprise protocol findings and handoff guidance
  const unparsedEnterpriseProtocols = Array.from(enterpriseMap.values())
    .sort((a, b) => b.packetCount - a.packetCount);
  const totalEnterprisePackets = unparsedEnterpriseProtocols.reduce((sum, p) => sum + p.packetCount, 0);

  const warnings = Array.isArray(initialWarnings) ? [...initialWarnings] : [];
  const agentHandoffHints = [];

  if (unparsedEnterpriseProtocols.length > 0) {
    const protoNames = unparsedEnterpriseProtocols.map(p => `${p.name} (port ${p.port})`).join(", ");
    const filterDisplay = unparsedEnterpriseProtocols
      .map(p => p.name.toLowerCase() === "netbios-ssn" ? "nbss" : (p.name.toLowerCase() === "ms-rpc" ? "dcerpc" : p.name.toLowerCase()))
      .join(" || ");
    agentHandoffHints.push(
      `CRITICAL: ${totalEnterprisePackets} packets of enterprise non-web protocols (${protoNames}) detected.`,
      `PacketChef specializes in Web/DNS/TLS/QUIC L3-L7 triage and does not parse ${unparsedEnterpriseProtocols.map(p => p.name).join("/")} application payloads.`,
      `DO NOT conclude the capture is clean based solely on zero HTTP/DNS/TLS findings. Recommend dispatching host tool: \`tshark -r <capture> -Y '${filterDisplay}'\` for deep Active Directory/endpoint inspection.`
    );
    warnings.push(`UNPARSED_ENTERPRISE_PROTOCOLS: Detected ${totalEnterprisePackets} packets of unparsed enterprise services (${protoNames}). Dispatch tshark for deep Active Directory/endpoint inspection.`);
  }

  // Calculate Truth-in-Triage Coverage Envelope
  let parsedL7Bytes = 0;
  for (const pkt of dissectedPackets) {
    if (pkt.appProtocol && pkt.appProtocol !== "UNKNOWN") {
      parsedL7Bytes += pkt.wireLength;
    }
  }

  const enterpriseBytes = unparsedEnterpriseProtocols.reduce((sum, p) => sum + p.byteVolume, 0);
  const uninspectedBytes = totalBytes - parsedL7Bytes;
  const inspectionCoverageRatio = totalBytes > 0 ? +(parsedL7Bytes / totalBytes).toFixed(3) : 0;
  const uninspectedVolumeRatio = totalBytes > 0 ? +(uninspectedBytes / totalBytes).toFixed(3) : 0;

  const uninspectedCategories = [];
  if (enterpriseBytes > 0) uninspectedCategories.push("Enterprise-Active-Directory (SMB/Kerberos/LDAP/RPC/RDP)");
  if (uninspectedBytes > enterpriseBytes) uninspectedCategories.push("Encrypted-TLS-Payloads-or-Binary-Streams (HTTP/2 / QUIC 1-RTT / Raw)");

  const coverageEnvelope = {
    inspectionCoverageRatio,
    uninspectedVolumeRatio,
    analyzedProtocols: ["IPv4", "IPv6", "TCP", "UDP", "ICMP", ...Object.keys(appProtocolCounts)],
    uninspectedCategories,
    verdictConfidence: inspectionCoverageRatio >= 0.7 ? "HIGH_L7_COVERAGE" : (inspectionCoverageRatio >= 0.3 ? "PARTIAL_TRIAGE_SURFACE" : "LOW_L7_VISIBILITY"),
    aiCognitiveGuidance: uninspectedVolumeRatio > 0.3
      ? "CRITICAL: Significant uninspected traffic volume detected. Do NOT declare capture clean based solely on zero HTTP/DNS alerts. Review unparsedEnterpriseProtocols and dispatch surgical tshark commands."
      : "High L7 protocol coverage achieved. Triage summary reflects analyzed traffic."
  };

  return {
    totalPackets,
    captureStart: minMs !== Infinity ? new Date(minMs).toISOString() : null,
    captureEnd: maxMs !== -Infinity ? new Date(maxMs).toISOString() : null,
    durationSeconds: Math.max(0, durationSeconds),
    totalBytes,
    averagePacketSize: Math.round(totalBytes / totalPackets),
    protocols: protocolsFormatted,
    identifiedApplications: appProtocolCounts,
    uniqueSourceIPs: srcIpSet.size,
    uniqueDestIPs: dstIpSet.size,
    topTalkers,
    unparsedEnterpriseProtocols,
    agentHandoffHints,
    coverageEnvelope,
    warnings
  };
}
