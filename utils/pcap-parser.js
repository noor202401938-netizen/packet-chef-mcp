/**
 * packet-chef-mcp - Core PCAP & PCAPng Binary Parser (v2)
 * Zero-dependency pure-Buffer parser for classic libpcap and PCAPng files.
 * Handles LE, BE, nanosecond timestamps, truncation, Linux SLL, Loopback, Raw IP,
 * and native PCAPng container streams.
 */

import { parsePcapNg, isPcapNg } from "./pcapng-parser.js";

export const PCAP_MAGICS = {
  MICRO:    0xa1b2c3d4,
  NANO:     0xa1b23c4d,
  LE_MICRO: 0xa1b2c3d4,
  BE_MICRO: 0xa1b2c3d4,
  LE_NANO:  0xa1b23c4d,
  BE_NANO:  0xa1b23c4d,
  PCAPNG:   0x0a0d0d0a
};

export const LINK_TYPES = {
  NULL: 0,             // BSD/Linux Loopback
  ETHERNET: 1,         // Standard Ethernet II
  RAW_IP: 12,          // Raw IPv4/IPv6
  LINUX_SLL: 113,      // Linux Cooked Capture (e.g. tcpdump -i any)
  IEEE802_11: 105,
  IEEE802_11_RADIO: 127
};

export const MAX_PACKETS_LIMIT = 100000;

/**
 * Validates and parses the 24-byte PCAP global header or PCAPng section header.
 * @param {Buffer} buffer 
 * @returns {object} Parsed header metadata and reader functions
 */
export function parsePcapHeader(buffer) {
  if (!Buffer.isBuffer(buffer)) {
    throw new TypeError("NOT_PCAP: Input must be a valid Buffer.");
  }

  if (buffer.length < 24) {
    throw new Error(`NOT_PCAP: File is too small (${buffer.length} bytes). Minimum PCAP header requires 24 bytes.`);
  }

  // Check magic number in big-endian representation for format identification
  const magicBE = buffer.readUInt32BE(0);

  // Native PCAPng support in v2
  if (isPcapNg(buffer)) {
    if (buffer.length < 32) {
      throw new Error(
        "PCAPNG_NOT_SUPPORTED: Detected PCAPng format (magic 0x0A0D0D0A). " +
        "Convert to classic PCAP first using editcap: editcap -F pcap input.pcapng output.pcap"
      );
    }
    return {
      format: "PCAPng",
      magic: PCAP_MAGICS.PCAPNG,
      isLittleEndian: buffer.readUInt32LE(8) === 0x1a2b3c4d,
      isNanosecond: false,
      versionMajor: 1,
      versionMinor: 0,
      linkType: 1
    };
  }

  // Check for common non-PCAP file signatures
  if (magicBE === 0x89504e47) {
    throw new Error("NOT_PCAP: File has a PNG image signature (0x89504e47), not a valid PCAP capture.");
  }
  if ((magicBE >>> 8) === 0xffd8ff) {
    throw new Error("NOT_PCAP: File has a JPEG image signature, not a valid PCAP capture.");
  }
  if (magicBE === 0x504b0304) {
    throw new Error("NOT_PCAP: File has a ZIP/archive signature (0x504B0304), not a valid PCAP capture.");
  }
  if (magicBE === 0x7f454c46) {
    throw new Error("NOT_PCAP: File has an ELF executable binary signature (0x7F454C46), not a valid PCAP capture.");
  }
  if (magicBE === 0x25504446) {
    throw new Error("NOT_PCAP: File has a PDF document signature (%PDF), not a valid PCAP capture.");
  }

  // Identify endianness and timestamp resolution
  let isLittleEndian = false;
  let isNanosecond = false;
  let magic = magicBE;

  if (magicBE === 0xd4c3b2a1) {
    // Disk bytes: 0xd4 0xc3 0xb2 0xa1 -> Little-Endian microsecond
    isLittleEndian = true;
    isNanosecond = false;
  } else if (magicBE === 0xa1b2c3d4) {
    // Disk bytes: 0xa1 0xb2 0xc3 0xd4 -> Big-Endian microsecond
    isLittleEndian = false;
    isNanosecond = false;
  } else if (magicBE === 0x4d3cb2a1) {
    // Disk bytes: 0x4d 0x3c 0xb2 0xa1 -> Little-Endian nanosecond
    isLittleEndian = true;
    isNanosecond = true;
  } else if (magicBE === 0xa1b23c4d) {
    // Disk bytes: 0xa1 0xb2 0x3c 0x4d -> Big-Endian nanosecond
    isLittleEndian = false;
    isNanosecond = true;
  } else {
    throw new Error(
      `NOT_PCAP: Invalid PCAP magic number (0x${magicBE.toString(16).padStart(8, "0")}). ` +
      `Expected 0xa1b2c3d4 (microsecond) or 0xa1b23c4d (nanosecond).`
    );
  }

  // Read header fields with proper endianness
  const readU16 = isLittleEndian 
    ? (offset) => buffer.readUInt16LE(offset) 
    : (offset) => buffer.readUInt16BE(offset);
  const readU32 = isLittleEndian 
    ? (offset) => buffer.readUInt32LE(offset) 
    : (offset) => buffer.readUInt32BE(offset);
  const readI32 = isLittleEndian 
    ? (offset) => buffer.readInt32LE(offset) 
    : (offset) => buffer.readInt32BE(offset);

  const versionMajor = readU16(4);
  const versionMinor = readU16(6);
  const thisZone = readI32(8);
  const sigFigs = readU32(12);
  const snapLen = readU32(16);
  const linkType = readU32(20);

  // LinkType validation (v2 expands to Ethernet 1, Linux SLL 113, Loopback 0, Raw IP 12)
  const isSupportedLinkType = (
    linkType === LINK_TYPES.ETHERNET ||
    linkType === LINK_TYPES.LINUX_SLL ||
    linkType === LINK_TYPES.NULL ||
    linkType === LINK_TYPES.RAW_IP
  );

  if (!isSupportedLinkType) {
    throw new Error(
      `UNSUPPORTED_LINK_TYPE: Capture uses unsupported link-layer type ${linkType}. ` +
      `Supported types in v2: Ethernet (1), Linux SLL (113), Loopback (0), Raw IP (12). ` +
      `Convert with: tcprewrite --dlt=enet --infile=in.pcap --outfile=out.pcap`
    );
  }

  return {
    magic,
    versionMajor,
    versionMinor,
    thisZone,
    sigFigs,
    snapLen,
    linkType,
    isLittleEndian,
    isNanosecond,
    readU16,
    readU32,
    readI32
  };
}

/**
 * Generator function that streams packet records sequentially from a PCAP buffer.
 * @param {Buffer} buffer 
 * @param {object} [options]
 * @param {number} [options.maxPackets=500000]
 * @yields {object} Individual parsed packet record
 */
export function* parsePackets(buffer, { maxPackets = MAX_PACKETS_LIMIT } = {}) {
  const header = parsePcapHeader(buffer);
  let offset = 24;
  let packetIndex = 0;

  const readU32 = header.isLittleEndian 
    ? (o) => buffer.readUInt32LE(o) 
    : (o) => buffer.readUInt32BE(o);

  while (offset + 16 <= buffer.length && packetIndex < maxPackets) {
    const tsSec = readU32(offset);
    const tsSub = readU32(offset + 4);
    const inclLen = readU32(offset + 8);
    const origLen = readU32(offset + 12);
    offset += 16;

    let isTruncated = false;
    let packetData;

    if (offset + inclLen > buffer.length) {
      isTruncated = true;
      packetData = buffer.subarray(offset);
      offset = buffer.length;
    } else {
      packetData = buffer.subarray(offset, offset + inclLen);
      offset += inclLen;
    }

    // Convert timestamp to ISO date string and epoch milliseconds
    const subSecondsMs = header.isNanosecond ? tsSub / 1000000 : tsSub / 1000;
    const timestampMs = tsSec * 1000 + Math.floor(subSecondsMs);
    const timestampISO = new Date(timestampMs).toISOString();

    packetIndex++;

    yield {
      index: packetIndex,
      linkType: header.linkType,
      tsSec,
      tsSub,
      isNanosecond: header.isNanosecond,
      timestampMs,
      timestampISO,
      inclLen,
      origLen,
      isTruncated,
      data: packetData
    };

    if (isTruncated) {
      break; // Stop at file boundary
    }
  }
}

/**
 * Complete PCAP & PCAPng parser returning global header and array of all packet records.
 * @param {Buffer} buffer 
 * @param {object} [options]
 * @returns {object} { header, packets, warnings, interfaces? }
 */
export function parsePcap(buffer, options = {}) {
  // Seamless PCAPng detection and parsing
  if (isPcapNg(buffer)) {
    return parsePcapNg(buffer, options);
  }

  const header = parsePcapHeader(buffer);
  const packets = [];
  const warnings = [];
  const maxPackets = options.maxPackets || MAX_PACKETS_LIMIT;

  for (const pkt of parsePackets(buffer, { maxPackets, ...options })) {
    if (pkt.isTruncated) {
      warnings.push(`File truncated at packet #${pkt.index}: Expected ${pkt.inclLen} bytes, parsed available ${pkt.data.length} bytes.`);
    }
    packets.push(pkt);
  }

  if (packets.length >= maxPackets) {
    warnings.push(`CAPTURE_TRUNCATED: Capture contains >=${maxPackets.toLocaleString()} packets, reaching the memory safety ceiling. Parsed the first ${maxPackets.toLocaleString()} packets for triage safety. To process full captures in slices, use: editcap -c 50000 <capture.pcap> <chunk.pcap> or packet_filter_export.`);
  }

  return {
    header,
    packets,
    warnings
  };
}
