/**
 * packet-chef-mcp - Linux Cooked Capture (SLL) & Loopback Decoders
 * Handles LinkType 113 (Linux SLL / tcpdump -i any), LinkType 0 (BSD/Linux Loopback),
 * and LinkType 12 (Raw IP).
 */

import { ETHER_TYPES } from "./ethernet.js";

export const SLL_PACKET_TYPES = {
  0: "HOST",      // Specifically addressed to us
  1: "BROADCAST", // Sent to broadcast address
  2: "MULTICAST", // Sent to multicast address
  3: "OTHERHOST", // Addressed to someone else (promiscuous mode)
  4: "OUTGOING"   // Sent by this machine
};

/**
 * Decodes a 16-byte Linux Cooked Capture (SLL v1) header.
 * @param {Buffer} buffer
 * @param {number} [offset=0]
 * @returns {object}
 */
export function decodeSLL(buffer, offset = 0) {
  if (buffer.length < offset + 16) {
    throw new Error(`TRUNCATED_SLL: Buffer length (${buffer.length - offset}) is less than SLL header size (16).`);
  }

  const packetTypeCode = buffer.readUInt16BE(offset);
  const arphrdType = buffer.readUInt16BE(offset + 2);
  const addrLen = buffer.readUInt16BE(offset + 4);
  const rawAddr = buffer.subarray(offset + 6, offset + 6 + Math.min(addrLen, 8));
  const protocol = buffer.readUInt16BE(offset + 14);

  let srcMac = "";
  if (addrLen === 6) {
    srcMac = Array.from(rawAddr).map(b => b.toString(16).padStart(2, "0")).join(":");
  }

  return {
    packetType: SLL_PACKET_TYPES[packetTypeCode] || `TYPE_${packetTypeCode}`,
    packetTypeCode,
    arphrdType,
    addrLen,
    srcMac,
    etherType: protocol,
    payloadOffset: offset + 16
  };
}

/**
 * Decodes a 4-byte Loopback / Null header (LinkType 0).
 * @param {Buffer} buffer
 * @param {number} [offset=0]
 * @returns {object}
 */
export function decodeLoopback(buffer, offset = 0) {
  if (buffer.length < offset + 4) {
    throw new Error(`TRUNCATED_LOOPBACK: Buffer length (${buffer.length - offset}) is less than Loopback header size (4).`);
  }

  // Loopback family can be Little or Big Endian depending on capturing OS
  let family = buffer.readUInt32LE(offset);
  if (family > 255) {
    family = buffer.readUInt32BE(offset);
  }

  let etherType = ETHER_TYPES.IPV4;
  if (family === 2) {
    etherType = ETHER_TYPES.IPV4; // PF_INET
  } else if (family === 24 || family === 28 || family === 30) {
    etherType = ETHER_TYPES.IPV6; // PF_INET6
  }

  return {
    family,
    etherType,
    payloadOffset: offset + 4
  };
}

/**
 * Decodes a Raw IP header (LinkType 12).
 * @param {Buffer} buffer
 * @param {number} [offset=0]
 * @returns {object}
 */
export function decodeRawIP(buffer, offset = 0) {
  if (buffer.length <= offset) {
    throw new Error("TRUNCATED_RAW_IP: Empty payload.");
  }
  const version = (buffer[offset] >> 4) & 0x0f;
  const etherType = version === 6 ? ETHER_TYPES.IPV6 : ETHER_TYPES.IPV4;
  return {
    etherType,
    payloadOffset: offset
  };
}
