/**
 * packet-chef-mcp - 5-Tuple Network Conversation Tracker
 * Aggregates bidirectional flows between endpoints, tracks byte distributions,
 * timing metrics, and TCP flag lifecycles.
 */

/**
 * Creates a canonical bidirectional conversation key.
 */
function getCanonicalKey(ip1, port1, ip2, port2, protocol) {
  const ep1 = `${ip1}:${port1 || 0}`;
  const ep2 = `${ip2}:${port2 || 0}`;
  if (ep1 < ep2) {
    return { key: `${ep1} <-> ${ep2} (${protocol})`, forward: true, ep1, ep2 };
  }
  return { key: `${ep2} <-> ${ep1} (${protocol})`, forward: false, ep1: ep2, ep2: ep1 };
}

/**
 * Aggregates dissected packets into sorted conversation streams.
 * @param {Array<object>} dissectedPackets
 * @param {object} [options]
 * @returns {object} { totalConversations, returnedCount, hasMore, conversations }
 */
export function trackConversations(dissectedPackets, options = {}) {
  const limit = Math.min(Math.max(1, options.limit || 50), 200);
  const conversationMap = new Map();

  for (const pkt of dissectedPackets) {
    if (!pkt.network || !pkt.network.srcIP || !pkt.network.dstIP) continue;

    const protocol = pkt.transport ? pkt.transport.protocol : pkt.network.protocolName;
    const srcPort = pkt.transport ? pkt.transport.srcPort : 0;
    const dstPort = pkt.transport ? pkt.transport.dstPort : 0;

    const { key, forward, ep1, ep2 } = getCanonicalKey(
      pkt.network.srcIP,
      srcPort,
      pkt.network.dstIP,
      dstPort,
      protocol
    );

    let conv = conversationMap.get(key);
    if (!conv) {
      conv = {
        id: key,
        endpointA: ep1,
        endpointB: ep2,
        protocol,
        appProtocol: pkt.appProtocol !== "UNKNOWN" ? pkt.appProtocol : null,
        packetsAtoB: 0,
        packetsBtoA: 0,
        bytesAtoB: 0,
        bytesBtoA: 0,
        totalPackets: 0,
        totalBytes: 0,
        startTime: pkt.timestampISO,
        endTime: pkt.timestampISO,
        startMs: pkt.timestampMs,
        endMs: pkt.timestampMs,
        tcpFlags: {
          hasSYN: false,
          hasACK: false,
          hasFIN: false,
          hasRST: false,
          hasPSH: false
        }
      };
      conversationMap.set(key, conv);
    }

    conv.totalPackets++;
    conv.totalBytes += pkt.wireLength;
    conv.endTime = pkt.timestampISO;
    conv.endMs = Math.max(conv.endMs, pkt.timestampMs);

    if (forward) {
      conv.packetsAtoB++;
      conv.bytesAtoB += pkt.wireLength;
    } else {
      conv.packetsBtoA++;
      conv.bytesBtoA += pkt.wireLength;
    }

    if (pkt.appProtocol !== "UNKNOWN" && !conv.appProtocol) {
      conv.appProtocol = pkt.appProtocol;
    }

    if (pkt.transport && pkt.transport.flags) {
      if (pkt.transport.flags.SYN) conv.tcpFlags.hasSYN = true;
      if (pkt.transport.flags.ACK) conv.tcpFlags.hasACK = true;
      if (pkt.transport.flags.FIN) conv.tcpFlags.hasFIN = true;
      if (pkt.transport.flags.RST) conv.tcpFlags.hasRST = true;
      if (pkt.transport.flags.PSH) conv.tcpFlags.hasPSH = true;
    }
  }

  // Calculate durations and format results
  const allConversations = Array.from(conversationMap.values()).map((c) => {
    const durationSeconds = +((c.endMs - c.startMs) / 1000).toFixed(3);
    const { startMs, endMs, ...rest } = c;
    return {
      ...rest,
      durationSeconds: Math.max(0, durationSeconds)
    };
  });

  // Sort by totalBytes descending
  allConversations.sort((a, b) => b.totalBytes - a.totalBytes);

  const totalConversations = allConversations.length;
  const conversations = allConversations.slice(0, limit);

  return {
    totalConversations,
    returnedCount: conversations.length,
    hasMore: totalConversations > limit,
    conversations
  };
}
