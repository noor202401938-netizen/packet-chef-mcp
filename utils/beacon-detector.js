/**
 * packet-chef-mcp - C2 Beacon Detector
 * Detects periodic Command & Control (C2) communication pulses in network captures.
 * Employs time-delta statistical variance (Coefficient of Variation) analysis,
 * median interval estimation, jitter percentage calculations, and Council benign
 * infrastructure filtering (NTP, Cloud Metadata, Public Resolvers).
 */

const KNOWN_RESOLVER_IPS = new Set([
  "8.8.8.8", "8.8.4.4",
  "1.1.1.1", "1.0.0.1",
  "9.9.9.9", "149.112.112.112",
  "208.67.222.222", "208.67.220.220"
]);

/**
 * Calculates the median of a sorted numerical array.
 */
function calculateMedian(sortedArr) {
  if (sortedArr.length === 0) return 0;
  const mid = Math.floor(sortedArr.length / 2);
  return sortedArr.length % 2 !== 0
    ? sortedArr[mid]
    : +((sortedArr[mid - 1] + sortedArr[mid]) / 2).toFixed(3);
}

/**
 * Detects if the connection target matches known benign cloud/network infrastructure.
 */
function identifyBenignService(dstIP, dstPort) {
  if (dstPort === 123) {
    return { isBenign: true, type: "NTP", label: "Network Time Protocol (NTP) synchronization pulse" };
  }
  if (dstIP === "169.254.169.254") {
    return { isBenign: true, type: "CLOUD_METADATA", label: "Cloud Instance Metadata Service (IMDS) heartbeat" };
  }
  if ((dstPort === 53 || dstPort === 853) && KNOWN_RESOLVER_IPS.has(dstIP)) {
    return { isBenign: true, type: "DNS_RESOLVER", label: "Public DNS resolver health check / keepalive" };
  }
  return { isBenign: false, type: null, label: null };
}

/**
 * Analyzes packet streams to identify C2 beacon candidates.
 * @param {Array<object>} packets Dissected packet records
 * @param {object} [options={}]
 * @param {number} [options.minConnections=8] Minimum connections to evaluate periodicity
 * @param {boolean} [options.includeBenign=true] Whether to include tagged benign services
 * @returns {object} Beacon candidates and analysis metadata
 */
export function detectBeacons(packets, options = {}) {
  const minConnections = options.minConnections || 8;
  const includeBenign = options.includeBenign !== false;

  // Group connections by 3-tuple (srcIP, dstIP, dstPort)
  const groupMap = new Map();

  for (const p of packets) {
    if (!p.network || !p.transport) continue;

    // Support connection initiations (TCP SYN, UDP requests) and periodic data pulses in established TCP sessions
    const isTcpSyn = p.transport.protocol === "TCP" && p.transport.flags && p.transport.flags.SYN && !p.transport.flags.ACK;
    const isUdpFlow = p.transport.protocol === "UDP";
    const isTcpDataPulse = p.transport.protocol === "TCP" && ((p.payload && p.payload.length > 0) || (p.transport.flags && p.transport.flags.PSH));

    if (!isTcpSyn && !isUdpFlow && !isTcpDataPulse) continue;

    const srcIP = p.network.srcIP;
    const dstIP = p.network.dstIP;
    const dstPort = p.transport.dstPort;
    const key = `${srcIP}->${dstIP}:${dstPort}`;

    let group = groupMap.get(key);
    if (!group) {
      group = {
        source: srcIP,
        destination: dstIP,
        destinationPort: dstPort,
        protocol: p.transport.protocol,
        rawTimestamps: [],
        timestamps: [],
        totalBytesSent: 0,
        totalBytesReceived: 0,
        firstSeen: p.timestampISO,
        lastSeen: p.timestampISO
      };
      groupMap.set(key, group);
    }

    group.rawTimestamps.push(p.timestampMs);
    group.totalBytesSent += p.wireLength || 0;
    group.lastSeen = p.timestampISO;
  }

  const candidates = [];
  let benignServicesFiltered = 0;

  for (const group of groupMap.values()) {
    // Sort raw timestamps ascending
    group.rawTimestamps.sort((a, b) => a - b);

    // Debounce pulses within 500ms into a single communication event
    const debounced = [];
    for (const t of group.rawTimestamps) {
      if (debounced.length === 0 || (t - debounced[debounced.length - 1]) >= 500) {
        debounced.push(t);
      }
    }
    group.timestamps = debounced;

    if (group.timestamps.length < minConnections) continue;

    // Compute intervals (in seconds) between consecutive connections
    const deltas = [];
    for (let i = 1; i < group.timestamps.length; i++) {
      const deltaSec = (group.timestamps[i] - group.timestamps[i - 1]) / 1000;
      if (deltaSec > 0) {
        deltas.push(deltaSec);
      }
    }

    if (deltas.length < minConnections - 1) continue;

    // Statistical calculations
    const sum = deltas.reduce((acc, v) => acc + v, 0);
    const mean = sum / deltas.length;

    // Ignore ultra-rapid bursts (< 0.05s mean) as they are likely streaming/bulk transfers, not beacons
    if (mean < 0.05) continue;

    const variance = deltas.reduce((acc, v) => acc + Math.pow(v - mean, 2), 0) / deltas.length;
    const stdDev = Math.sqrt(variance);

    // Coefficient of Variation: CV = StdDev / Mean
    const cv = +(stdDev / mean).toFixed(4);
    const sortedDeltas = [...deltas].sort((a, b) => a - b);
    const medianInterval = calculateMedian(sortedDeltas);
    const jitterPercent = +(cv * 100).toFixed(1);

    // Confidence determination
    let confidence = "INFORMATIONAL";
    if (cv < 0.25) confidence = "HIGH";
    else if (cv < 0.40) confidence = "MEDIUM";
    else if (cv < 0.60) confidence = "LOW";

    // Benign service identification
    const benign = identifyBenignService(group.destination, group.destinationPort);
    if (benign.isBenign) {
      benignServicesFiltered++;
      if (!includeBenign) continue;
    }

    // Scoring formula: (1 - CV) * log2(count) * benignMultiplier
    const benignMultiplier = benign.isBenign ? 0.1 : 1.0;
    const rawScore = (1 - Math.min(cv, 1.0)) * Math.log2(group.timestamps.length) * benignMultiplier;
    const score = +Math.max(0, rawScore).toFixed(3);

    let verdict = "";
    if (benign.isBenign) {
      verdict = `Benign activity: ${benign.label} with estimated interval of ${medianInterval}s (jitter: ${jitterPercent}%).`;
    } else if (confidence === "HIGH") {
      verdict = `Strong C2 beacon candidate: ${group.timestamps.length} periodic connections every ~${medianInterval}s with low jitter (${jitterPercent}%).`;
    } else if (confidence === "MEDIUM") {
      verdict = `Probable beacon: ${group.timestamps.length} connections every ~${medianInterval}s with moderate jitter (${jitterPercent}%).`;
    } else if (confidence === "LOW") {
      verdict = `Weak periodicity: ${group.timestamps.length} connections every ~${medianInterval}s with high jitter (${jitterPercent}%).`;
    } else {
      verdict = `Irregular / non-periodic connection pattern (CV: ${cv}).`;
    }

    candidates.push({
      source: group.source,
      destination: group.destination,
      destinationPort: group.destinationPort,
      protocol: group.protocol,
      connectionCount: group.timestamps.length,
      estimatedIntervalSeconds: +medianInterval.toFixed(2),
      meanIntervalSeconds: +mean.toFixed(2),
      jitterPercent,
      coefficientOfVariation: cv,
      confidence,
      score,
      isKnownBenignService: benign.isBenign,
      benignServiceType: benign.type,
      totalBytesSent: group.totalBytesSent,
      firstSeen: group.firstSeen,
      lastSeen: group.lastSeen,
      verdict
    });
  }

  // Sort candidates by score descending
  candidates.sort((a, b) => b.score - a.score);

  return {
    beaconCandidates: candidates.slice(0, 20),
    totalGroupsAnalyzed: groupMap.size,
    benignServicesFiltered
  };
}
