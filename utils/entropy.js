/**
 * packet-chef-mcp - Shannon Entropy Calculator
 * Computes payload randomness to distinguish between plaintext, structured data
 * (code, JSON, HTML, PE binaries), and encrypted / compressed data (C2 payloads, TLS, packed malware).
 */

/**
 * Calculates Shannon entropy (in bits per byte, 0.0 to 8.0) for a buffer or string.
 * @param {Buffer|string} input 
 * @returns {object} { entropy, maxEntropy, ratio, verdict, byteCount }
 */
export function calculateEntropy(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(String(input || ""));
  const len = buf.length;

  if (len === 0) {
    return {
      entropy: 0,
      maxEntropy: 8.0,
      ratio: 0,
      verdict: "empty",
      byteCount: 0
    };
  }

  // Count byte frequency (0 - 255)
  const counts = new Uint32Array(256);
  for (let i = 0; i < len; i++) {
    counts[buf[i]]++;
  }

  let entropy = 0;
  for (let i = 0; i < 256; i++) {
    const c = counts[i];
    if (c > 0) {
      const p = c / len;
      entropy -= p * Math.log2(p);
    }
  }

  const roundedEntropy = +entropy.toFixed(3);
  const ratio = +(roundedEntropy / 8.0).toFixed(3);

  let verdict = "plaintext";
  if (roundedEntropy >= 7.2) {
    verdict = "encrypted_or_compressed";
  } else if (roundedEntropy >= 4.5) {
    verdict = "structured";
  }

  return {
    entropy: roundedEntropy,
    maxEntropy: 8.0,
    ratio,
    verdict,
    byteCount: len
  };
}

/**
 * Analyzes entropy across a list of packets or flows.
 * @param {Array<object>} packets Dissected packet records
 * @returns {object} High-entropy packet flows and anomalies
 */
export function analyzeCaptureEntropy(packets) {
  const highEntropyPayloads = [];
  let totalAnalyzed = 0;

  for (const p of packets) {
    if (!p.payload || p.payload.length < 32) continue;
    totalAnalyzed++;

    const ent = calculateEntropy(p.payload);
    if (ent.verdict === "encrypted_or_compressed") {
      highEntropyPayloads.push({
        packetIndex: p.index,
        timestamp: p.timestampISO,
        source: p.network ? `${p.network.srcIP}:${p.transport?.srcPort || 0}` : "unknown",
        destination: p.network ? `${p.network.dstIP}:${p.transport?.dstPort || 0}` : "unknown",
        protocol: p.transport?.protocol || "TCP",
        appProtocol: p.appProtocol,
        payloadBytes: p.payload.length,
        entropy: ent.entropy,
        verdict: ent.verdict
      });
    }
  }

  return {
    totalPayloadsAnalyzed: totalAnalyzed,
    highEntropyCount: highEntropyPayloads.length,
    highEntropyPayloads: highEntropyPayloads.slice(0, 50)
  };
}
