/**
 * packet-chef-mcp - TCP Header Decoder
 * RFC 793 compliant: decodes source/dest ports, sequence/acknowledgment numbers,
 * variable data offset (options), individual TCP flags, window size, and bounds payload.
 */

export const TCP_FLAGS = {
  FIN: 0x01,
  SYN: 0x02,
  RST: 0x04,
  PSH: 0x08,
  ACK: 0x10,
  URG: 0x20,
  ECE: 0x40,
  CWR: 0x80
};

/**
 * Decodes a TCP segment header.
 * @param {Buffer} data
 * @param {number} [offset=0]
 * @returns {object} Decoded TCP header metadata
 */
export function decodeTCP(data, offset = 0) {
  if (!Buffer.isBuffer(data)) {
    throw new TypeError("decodeTCP: data must be a Buffer");
  }

  const remaining = data.length - offset;
  if (remaining < 20) {
    throw new Error(`TRUNCATED_TCP: Available bytes (${remaining}) shorter than minimum 20-byte TCP header.`);
  }

  const srcPort = data.readUInt16BE(offset);
  const dstPort = data.readUInt16BE(offset + 2);
  const seqNum = data.readUInt32BE(offset + 4);
  const ackNum = data.readUInt32BE(offset + 8);

  const dataOffsetByte = data[offset + 12];
  const dataOffsetWords = dataOffsetByte >> 4;
  const dataOffset = dataOffsetWords * 4;

  if (dataOffset < 20) {
    throw new Error(`INVALID_TCP_DATA_OFFSET: Data offset (${dataOffset} bytes) less than minimum 20.`);
  }

  if (remaining < dataOffset) {
    throw new Error(`TRUNCATED_TCP_HEADER: Header requires ${dataOffset} bytes but only ${remaining} available.`);
  }

  const flagsByte = data[offset + 13];
  const flags = {
    FIN: (flagsByte & TCP_FLAGS.FIN) !== 0,
    SYN: (flagsByte & TCP_FLAGS.SYN) !== 0,
    RST: (flagsByte & TCP_FLAGS.RST) !== 0,
    PSH: (flagsByte & TCP_FLAGS.PSH) !== 0,
    ACK: (flagsByte & TCP_FLAGS.ACK) !== 0,
    URG: (flagsByte & TCP_FLAGS.URG) !== 0,
    ECE: (flagsByte & TCP_FLAGS.ECE) !== 0,
    CWR: (flagsByte & TCP_FLAGS.CWR) !== 0,
    raw: flagsByte
  };

  const windowSize = data.readUInt16BE(offset + 14);
  const checksum = data.readUInt16BE(offset + 16);
  const urgentPointer = data.readUInt16BE(offset + 18);

  const payloadOffset = offset + dataOffset;
  const payloadLength = Math.max(0, data.length - payloadOffset);
  const payload = data.subarray(payloadOffset);

  return {
    srcPort,
    dstPort,
    seqNum,
    ackNum,
    dataOffset,
    flags,
    windowSize,
    checksum,
    urgentPointer,
    payloadOffset,
    payloadLength,
    payload
  };
}
