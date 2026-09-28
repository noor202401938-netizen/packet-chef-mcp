/**
 * packet-chef-mcp - Native PCAPng (PCAP Next Generation) Parser
 * Pure JavaScript, zero-dependency parser for PCAPng container files.
 * Handles Section Header Blocks (SHB), Interface Description Blocks (IDB),
 * Enhanced Packet Blocks (EPB), Simple Packet Blocks (SPB), and Name Resolution Blocks (NRB).
 * Supports Little-Endian and Big-Endian captures with microsecond and nanosecond timestamps.
 */

export const PCAPNG_BLOCKS = {
  SHB: 0x0a0d0d0a, // Section Header Block
  IDB: 0x00000001, // Interface Description Block
  PB:  0x00000002, // Packet Block (obsolete, but handled)
  SPB: 0x00000003, // Simple Packet Block
  NRB: 0x00000004, // Name Resolution Block
  ISB: 0x00000005, // Interface Statistics Block
  EPB: 0x00000006  // Enhanced Packet Block
};

export const PCAPNG_BOM = {
  LE: 0x1a2b3c4d,
  BE: 0x4d3c2b1a
};

/**
 * Checks if a buffer begins with the PCAPng Section Header Block magic.
 * @param {Buffer} buffer
 * @returns {boolean}
 */
export function isPcapNg(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 12) return false;
  // Block Type must be 0x0A0D0D0A in either endianness (symmetrical in bytes: 0a 0d 0d 0a)
  return buffer[0] === 0x0a && buffer[1] === 0x0d && buffer[2] === 0x0d && buffer[3] === 0x0a;
}

/**
 * Parses a PCAPng buffer and returns an array of normalized packet records
 * compatible with the classic PCAP packet structure.
 * @param {Buffer} buffer
 * @param {object} [options]
 * @param {number} [options.maxPackets=500000]
 * @returns {{ header: object, packets: Array<object>, interfaces: Array<object> }}
 */
export function parsePcapNg(buffer, { maxPackets = 100000 } = {}) {
  if (!Buffer.isBuffer(buffer)) {
    throw new TypeError("NOT_PCAPNG: Input must be a valid Buffer.");
  }

  if (buffer.length < 32) {
    throw new Error(`NOT_PCAPNG: Buffer is too small (${buffer.length} bytes) for a valid PCAPng file.`);
  }

  let offset = 0;
  let isLittleEndian = true;
  const interfaces = [];
  const packets = [];
  const warnings = [];
  let sectionHeader = null;

  while (offset + 8 <= buffer.length && packets.length < maxPackets) {
    // Read Block Type (always byte-order detected from SHB)
    const blockType = isLittleEndian ? buffer.readUInt32LE(offset) : buffer.readUInt32BE(offset);
    const blockTotalLength = isLittleEndian ? buffer.readUInt32LE(offset + 4) : buffer.readUInt32BE(offset + 4);

    if (blockTotalLength < 12 || offset + blockTotalLength > buffer.length) {
      // Malformed block or truncated tail
      break;
    }

    switch (blockType) {
      case PCAPNG_BLOCKS.SHB: {
        // Section Header Block: Byte-Order Magic is at offset + 8
        const bom = buffer.readUInt32LE(offset + 8);
        if (bom === PCAPNG_BOM.LE) {
          isLittleEndian = true;
        } else if (bom === PCAPNG_BOM.BE || buffer.readUInt32BE(offset + 8) === PCAPNG_BOM.BE) {
          isLittleEndian = false;
        }

        const readU16 = isLittleEndian ? (o) => buffer.readUInt16LE(o) : (o) => buffer.readUInt16BE(o);
        const versionMajor = readU16(offset + 12);
        const versionMinor = readU16(offset + 14);

        sectionHeader = {
          format: "PCAPng",
          versionMajor,
          versionMinor,
          isLittleEndian,
          linkType: 1 // default, will be overridden by IDB
        };
        break;
      }

      case PCAPNG_BLOCKS.IDB: {
        // Interface Description Block
        const readU16 = isLittleEndian ? (o) => buffer.readUInt16LE(o) : (o) => buffer.readUInt16BE(o);
        const readU32 = isLittleEndian ? (o) => buffer.readUInt32LE(o) : (o) => buffer.readUInt32BE(o);

        const linkType = readU16(offset + 8);
        const snapLen = readU32(offset + 12);

        let tsResol = 6; // default 10^-6 (microseconds)
        let isPowerOf2 = false;

        // Parse optional options at offset + 16 up to offset + blockTotalLength - 4
        let optOffset = offset + 16;
        const optEnd = offset + blockTotalLength - 4;
        let ifName = `Interface #${interfaces.length}`;

        while (optOffset + 4 <= optEnd) {
          const optCode = readU16(optOffset);
          const optLen = readU16(optOffset + 2);
          const optValOffset = optOffset + 4;
          if (optCode === 0) break; // End of options

          if (optCode === 2 && optValOffset + optLen <= optEnd) {
            // if_name
            ifName = buffer.toString("utf8", optValOffset, optValOffset + optLen);
          } else if (optCode === 9 && optLen === 1 && optValOffset < optEnd) {
            // if_tsresol
            const rawResol = buffer[optValOffset];
            isPowerOf2 = (rawResol & 0x80) !== 0;
            tsResol = rawResol & 0x7f;
          }

          // Options are padded to 32-bit boundaries
          const paddedLen = (optLen + 3) & ~3;
          optOffset = optValOffset + paddedLen;
        }

        interfaces.push({
          id: interfaces.length,
          linkType,
          snapLen,
          name: ifName,
          tsResol,
          isPowerOf2
        });

        // Set global linkType to first interface's linkType
        if (sectionHeader && interfaces.length === 1) {
          sectionHeader.linkType = linkType;
        }
        break;
      }

      case PCAPNG_BLOCKS.EPB: {
        // Enhanced Packet Block
        const readU32 = isLittleEndian ? (o) => buffer.readUInt32LE(o) : (o) => buffer.readUInt32BE(o);
        const ifId = readU32(offset + 8);
        const tsHigh = readU32(offset + 12);
        const tsLow = readU32(offset + 16);
        const capturedLen = readU32(offset + 20);
        const originalLen = readU32(offset + 24);

        const dataOffset = offset + 28;
        if (dataOffset + capturedLen <= offset + blockTotalLength) {
          const iface = interfaces[ifId] || interfaces[0] || { tsResol: 6, isPowerOf2: false, linkType: 1 };
          
          // Timestamp computation based on tsresol
          let timestampMs = 0;
          const rawUnits = BigInt(tsHigh) * 4294967296n + BigInt(tsLow);
          if (iface.isPowerOf2) {
            // Units are 2^-tsResol seconds
            const divisor = 2n ** BigInt(iface.tsResol);
            timestampMs = Number((rawUnits * 1000n) / divisor);
          } else {
            // Units are 10^-tsResol seconds (6 = microsecond, 9 = nanosecond)
            if (iface.tsResol === 6) {
              timestampMs = Number(rawUnits / 1000n);
            } else if (iface.tsResol === 9) {
              timestampMs = Number(rawUnits / 1000000n);
            } else {
              const divisor = 10n ** BigInt(Math.max(0, iface.tsResol - 3));
              timestampMs = Number(rawUnits / divisor);
            }
          }

          const packetData = buffer.subarray(dataOffset, dataOffset + capturedLen);

          packets.push({
            index: packets.length + 1,
            interfaceId: ifId,
            linkType: iface.linkType,
            timestampMs,
            timestampISO: new Date(timestampMs).toISOString(),
            inclLen: capturedLen,
            origLen: originalLen,
            isTruncated: capturedLen < originalLen,
            data: packetData
          });
        }
        break;
      }

      case PCAPNG_BLOCKS.SPB: {
        // Simple Packet Block (assumes interface 0)
        const readU32 = isLittleEndian ? (o) => buffer.readUInt32LE(o) : (o) => buffer.readUInt32BE(o);
        const originalLen = readU32(offset + 8);
        const capturedLen = blockTotalLength - 16;
        const dataOffset = offset + 12;

        if (dataOffset + capturedLen <= offset + blockTotalLength) {
          const packetData = buffer.subarray(dataOffset, dataOffset + capturedLen);
          packets.push({
            index: packets.length + 1,
            interfaceId: 0,
            linkType: interfaces[0]?.linkType || 1,
            timestampMs: 0,
            timestampISO: new Date(0).toISOString(),
            inclLen: capturedLen,
            origLen: originalLen,
            isTruncated: capturedLen < originalLen,
            data: packetData
          });
        }
        break;
      }

      default:
        // Ignore other blocks (NRB, ISB, Custom) safely
        break;
    }

    offset += blockTotalLength;
  }

  if (!sectionHeader) {
    throw new Error("CORRUPTED_PCAPNG: No valid Section Header Block found in capture.");
  }

  if (packets.length >= maxPackets) {
    warnings.push(`CAPTURE_TRUNCATED: Capture contains >=${maxPackets.toLocaleString()} packets, reaching the memory safety ceiling. Parsed the first ${maxPackets.toLocaleString()} packets for triage safety. To process full captures in slices, use: editcap -c 50000 <capture.pcap> <chunk.pcap> or packet_filter_export.`);
  }

  return {
    header: sectionHeader,
    interfaces,
    packets,
    warnings
  };
}
