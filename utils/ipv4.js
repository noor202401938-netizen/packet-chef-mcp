/**
 * packet-chef-mcp - IPv4 Header Decoder
 * RFC 791 compliant: handles variable IHL (options), flags, fragmentation detection,
 * TTL, protocol mapping, and source/dest IP formatting.
 */

export const IP_PROTOCOLS = {
  ICMP: 1,
  TCP:  6,
  UDP:  17,
  GRE:  47,
  ESP:  50,
  AH:   51,
  ICMPV6: 58
};

const PROTOCOL_NAMES = {
  1: "ICMP",
  2: "IGMP",
  6: "TCP",
  17: "UDP",
  41: "IPv6-Encapsulation",
  47: "GRE",
  50: "ESP",
  51: "AH",
  58: "ICMPv6"
};

export function formatIPv4(buffer, offset) {
  return `${buffer[offset]}.${buffer[offset + 1]}.${buffer[offset + 2]}.${buffer[offset + 3]}`;
}

/**
 * Decodes an IPv4 packet header.
 * @param {Buffer} data
 * @param {number} [offset=0]
 * @returns {object} Decoded IPv4 header metadata
 */
export function decodeIPv4(data, offset = 0) {
  if (!Buffer.isBuffer(data)) {
    throw new TypeError("decodeIPv4: data must be a Buffer");
  }

  const remaining = data.length - offset;
  if (remaining < 20) {
    throw new Error(`TRUNCATED_IPV4: Available bytes (${remaining}) shorter than minimum IPv4 header (20).`);
  }

  const verIhl = data[offset];
  const version = verIhl >> 4;
  if (version !== 4) {
    throw new Error(`INVALID_IPV4_VERSION: Expected version 4, encountered ${version}.`);
  }

  const ihlWords = verIhl & 0x0f;
  const ihlBytes = ihlWords * 4;

  if (ihlBytes < 20) {
    throw new Error(`INVALID_IPV4_IHL: Header length (${ihlBytes} bytes) less than minimum 20.`);
  }

  if (remaining < ihlBytes) {
    throw new Error(`TRUNCATED_IPV4_HEADER: Header requires ${ihlBytes} bytes but only ${remaining} available.`);
  }

  const totalLength = data.readUInt16BE(offset + 2);
  const identification = data.readUInt16BE(offset + 4);

  const flagsFrag = data.readUInt16BE(offset + 6);
  const df = (flagsFrag & 0x4000) !== 0;
  const mf = (flagsFrag & 0x2000) !== 0;
  const fragmentOffset = (flagsFrag & 0x1fff) * 8;
  const isFragmented = mf || fragmentOffset > 0;

  const ttl = data[offset + 8];
  const protocol = data[offset + 9];
  const protocolName = PROTOCOL_NAMES[protocol] || `IP-Proto-${protocol}`;
  const checksum = data.readUInt16BE(offset + 10);

  const srcIP = formatIPv4(data, offset + 12);
  const dstIP = formatIPv4(data, offset + 16);

  const payloadOffset = offset + ihlBytes;
  // Account for capture snapping: payload length is bounded by available captured bytes and totalLength
  const wirePayloadLength = Math.max(0, totalLength - ihlBytes);
  const capturedPayloadLength = Math.max(0, data.length - payloadOffset);
  const payloadLength = Math.min(wirePayloadLength, capturedPayloadLength);

  return {
    version: 4,
    ihl: ihlBytes,
    totalLength,
    identification,
    flags: {
      DF: df,
      MF: mf
    },
    fragmentOffset,
    isFragmented,
    ttl,
    protocol,
    protocolName,
    checksum,
    srcIP,
    dstIP,
    payloadOffset,
    payloadLength
  };
}
