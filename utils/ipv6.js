/**
 * packet-chef-mcp - IPv6 Header Decoder
 * RFC 8200 compliant: 40-byte fixed header decoding, RFC 5952 zero-compression
 * address formatting, and nextHeader protocol mapping.
 */

const NEXT_HEADER_NAMES = {
  0:  "Hop-by-Hop",
  6:  "TCP",
  17: "UDP",
  41: "IPv6-Encapsulation",
  43: "Routing",
  44: "Fragment",
  50: "ESP",
  51: "AH",
  58: "ICMPv6",
  60: "Destination-Options"
};

/**
 * Formats a 16-byte buffer as an RFC 5952 compliant IPv6 address string
 * with proper :: compression for the longest zero run.
 * @param {Buffer} buffer
 * @param {number} offset
 * @returns {string} Formatted IPv6 address (e.g. "2001:db8::1")
 */
export function formatIPv6(buffer, offset) {
  const words = [];
  for (let i = 0; i < 16; i += 2) {
    words.push(buffer.readUInt16BE(offset + i));
  }

  // Find the longest run of zeros for :: compression
  let bestStart = -1;
  let bestLen = 0;
  let currentStart = -1;
  let currentLen = 0;

  for (let i = 0; i < words.length; i++) {
    if (words[i] === 0) {
      if (currentStart === -1) {
        currentStart = i;
        currentLen = 1;
      } else {
        currentLen++;
      }
      if (currentLen > bestLen) {
        bestStart = currentStart;
        bestLen = currentLen;
      }
    } else {
      currentStart = -1;
      currentLen = 0;
    }
  }

  // Only compress if the zero run is at least 2 words long
  if (bestLen < 2) {
    return words.map((w) => w.toString(16)).join(":");
  }

  const left = words.slice(0, bestStart).map((w) => w.toString(16)).join(":");
  const right = words.slice(bestStart + bestLen).map((w) => w.toString(16)).join(":");

  return `${left}::${right}`;
}

/**
 * Decodes an IPv6 packet header.
 * @param {Buffer} data
 * @param {number} [offset=0]
 * @returns {object} Decoded IPv6 metadata
 */
export function decodeIPv6(data, offset = 0) {
  if (!Buffer.isBuffer(data)) {
    throw new TypeError("decodeIPv6: data must be a Buffer");
  }

  const remaining = data.length - offset;
  if (remaining < 40) {
    throw new Error(`TRUNCATED_IPV6: Available bytes (${remaining}) shorter than fixed 40-byte IPv6 header.`);
  }

  const vtcFl = data.readUInt32BE(offset);
  const version = vtcFl >>> 28;
  if (version !== 6) {
    throw new Error(`INVALID_IPV6_VERSION: Expected version 6, encountered ${version}.`);
  }

  const trafficClass = (vtcFl >>> 20) & 0xff;
  const flowLabel = vtcFl & 0xfffff;

  const payloadLengthWire = data.readUInt16BE(offset + 4);
  const nextHeader = data[offset + 6];
  const nextHeaderName = NEXT_HEADER_NAMES[nextHeader] || `IPv6-NextHeader-${nextHeader}`;
  const hopLimit = data[offset + 7];

  const srcIP = formatIPv6(data, offset + 8);
  const dstIP = formatIPv6(data, offset + 24);

  let effectiveNextHeader = nextHeader;
  let effectiveNextHeaderName = nextHeaderName;
  let isFragmented = false;
  let fragmentOffset = 0;
  let hasMoreFragments = false;
  let identification = null;
  let payloadOffset = offset + 40;

  // RFC 8200: Walk chained IPv6 extension headers to resolve upper-layer protocol (TCP/UDP/ICMP)
  const EXTENSION_HEADERS = new Set([0, 43, 44, 51, 60, 135]);
  let currentHeader = nextHeader;
  let extensionHeadersLength = 0;

  while (EXTENSION_HEADERS.has(currentHeader) && payloadOffset < data.length) {
    if (currentHeader === 44) {
      // RFC 8200 Section 4.5: Fragment Header (fixed 8 bytes)
      if (payloadOffset + 8 > data.length) break;
      isFragmented = true;
      const fragNext = data[payloadOffset];
      const fragField = data.readUInt16BE(payloadOffset + 2);
      fragmentOffset = (fragField & 0xfff8); // in 8-byte units
      hasMoreFragments = (fragField & 0x0001) !== 0;
      identification = data.readUInt32BE(payloadOffset + 4);
      payloadOffset += 8;
      extensionHeadersLength += 8;
      currentHeader = fragNext;
    } else if (currentHeader === 51) {
      // RFC 4302: Authentication Header (AH) length in 4-octet units minus 2
      if (payloadOffset + 2 > data.length) break;
      const ahNext = data[payloadOffset];
      const ahLen = (data[payloadOffset + 1] + 2) * 4;
      if (payloadOffset + ahLen > data.length) break;
      payloadOffset += ahLen;
      extensionHeadersLength += ahLen;
      currentHeader = ahNext;
    } else {
      // RFC 8200: Standard Extension Headers (0: Hop-by-Hop, 43: Routing, 60: Dest Options, 135: Mobility)
      // Header Extension Length is in 8-octet units, not including the first 8 octets
      if (payloadOffset + 2 > data.length) break;
      const extNext = data[payloadOffset];
      const extLen = (data[payloadOffset + 1] + 1) * 8;
      if (payloadOffset + extLen > data.length) break;
      payloadOffset += extLen;
      extensionHeadersLength += extLen;
      currentHeader = extNext;
    }
  }

  effectiveNextHeader = currentHeader;
  effectiveNextHeaderName = NEXT_HEADER_NAMES[effectiveNextHeader] || `IPv6-NextHeader-${effectiveNextHeader}`;

  const capturedPayloadLength = Math.max(0, data.length - payloadOffset);
  const wirePayloadLength = Math.max(0, payloadLengthWire - extensionHeadersLength);
  const payloadLength = Math.min(wirePayloadLength, capturedPayloadLength);

  return {
    version: 6,
    trafficClass,
    flowLabel,
    payloadLength: payloadLengthWire,
    nextHeader: effectiveNextHeader,
    nextHeaderName: effectiveNextHeaderName,
    rawNextHeader: nextHeader,
    isFragmented,
    fragmentOffset,
    hasMoreFragments,
    identification,
    hopLimit,
    srcIP,
    dstIP,
    payloadOffset,
    capturedPayloadLength: payloadLength
  };
}
