/**
 * packet-chef-mcp - Ethernet Frame Decoder
 * Decodes Layer 2 Ethernet II frames, 802.1Q single and double (QinQ) VLAN tags.
 */

export const ETHER_TYPES = {
  IPV4: 0x0800,
  ARP:  0x0806,
  VLAN: 0x8100,
  QINQ: 0x88a8,
  IPV6: 0x86dd
};

function formatMac(buffer, offset) {
  const bytes = [];
  for (let i = 0; i < 6; i++) {
    bytes.push(buffer[offset + i].toString(16).padStart(2, "0"));
  }
  return bytes.join(":");
}

/**
 * Decodes an Ethernet frame.
 * @param {Buffer} data Raw packet buffer
 * @param {number} [offset=0]
 * @returns {object} Decoded Ethernet frame metadata
 */
export function decodeEthernet(data, offset = 0) {
  if (!Buffer.isBuffer(data)) {
    throw new TypeError("decodeEthernet: data must be a Buffer");
  }

  if (data.length - offset < 14) {
    throw new Error(`TRUNCATED_ETHERNET: Frame too short (${data.length - offset} bytes, min 14).`);
  }

  const dstMac = formatMac(data, offset);
  const srcMac = formatMac(data, offset + 6);
  let etherType = data.readUInt16BE(offset + 12);
  let currentOffset = offset + 14;
  let vlanId = null;
  let vlanPriority = null;

  // Handle 802.1Q Single VLAN Tag
  if (etherType === ETHER_TYPES.VLAN) {
    if (data.length - currentOffset < 4) {
      throw new Error("TRUNCATED_VLAN: Frame truncated in 802.1Q VLAN header.");
    }
    const tci = data.readUInt16BE(currentOffset);
    vlanPriority = (tci >> 13) & 0x07;
    vlanId = tci & 0x0FFF;
    etherType = data.readUInt16BE(currentOffset + 2);
    currentOffset += 4;
  }
  // Handle 802.1ad QinQ Double VLAN Tag
  else if (etherType === ETHER_TYPES.QINQ) {
    if (data.length - currentOffset < 8) {
      throw new Error("TRUNCATED_QINQ: Frame truncated in QinQ header.");
    }
    // Skip outer tag, inspect inner tag
    const innerType = data.readUInt16BE(currentOffset + 2);
    if (innerType === ETHER_TYPES.VLAN) {
      const innerTci = data.readUInt16BE(currentOffset + 4);
      vlanId = innerTci & 0x0FFF;
      etherType = data.readUInt16BE(currentOffset + 6);
      currentOffset += 8;
    } else {
      etherType = innerType;
      currentOffset += 4;
    }
  }

  return {
    srcMac,
    dstMac,
    etherType,
    vlanId,
    vlanPriority,
    payloadOffset: currentOffset,
    payloadLength: Math.max(0, data.length - currentOffset)
  };
}
