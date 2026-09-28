/**
 * packet-chef-mcp - UDP Header Decoder
 * RFC 768 compliant: decodes source/dest ports, datagram length, checksum,
 * and safely extracts bounded UDP payload.
 */

/**
 * Decodes a UDP datagram header.
 * @param {Buffer} data
 * @param {number} [offset=0]
 * @returns {object} Decoded UDP metadata
 */
export function decodeUDP(data, offset = 0) {
  if (!Buffer.isBuffer(data)) {
    throw new TypeError("decodeUDP: data must be a Buffer");
  }

  const remaining = data.length - offset;
  if (remaining < 8) {
    throw new Error(`TRUNCATED_UDP: Available bytes (${remaining}) shorter than fixed 8-byte UDP header.`);
  }

  const srcPort = data.readUInt16BE(offset);
  const dstPort = data.readUInt16BE(offset + 2);
  const length = data.readUInt16BE(offset + 4);
  const checksum = data.readUInt16BE(offset + 6);

  const payloadOffset = offset + 8;
  const wirePayloadLength = Math.max(0, length - 8);
  const capturedPayloadLength = Math.max(0, data.length - payloadOffset);
  const payloadLength = Math.min(wirePayloadLength, capturedPayloadLength);
  const payload = data.subarray(payloadOffset, payloadOffset + payloadLength);

  return {
    srcPort,
    dstPort,
    length,
    checksum,
    payloadOffset,
    payloadLength,
    payload
  };
}
