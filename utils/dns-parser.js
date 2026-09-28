/**
 * packet-chef-mcp - DNS Protocol Parser
 * Pure Node.js Buffer decoder for DNS queries and responses (RFC 1035).
 * Features recursive label pointer decompression with cycle detection,
 * type resolution (A, AAAA, CNAME, TXT, MX, PTR, NS, SOA), and crash immunity.
 */

export const DNS_TYPES = {
  1: "A",
  2: "NS",
  5: "CNAME",
  6: "SOA",
  12: "PTR",
  15: "MX",
  16: "TXT",
  28: "AAAA",
  33: "SRV",
  41: "OPT",
  255: "ANY"
};

export const DNS_RCODES = {
  0: "NoError",
  1: "FormatError",
  2: "ServerFailure",
  3: "NXDomain",
  4: "NotImplemented",
  5: "Refused"
};

const MAX_COMPRESSION_POINTERS = 10;

/**
 * Reads a domain name from DNS payload, resolving RFC 1035 compression pointers.
 * @param {Buffer} buffer 
 * @param {number} offset 
 * @returns {{ name: string, nextOffset: number }}
 */
export function readDNSName(buffer, offset) {
  let current = offset;
  let jumps = 0;
  let jumped = false;
  let nextOffset = -1;
  const labels = [];
  const visitedPointers = new Set();

  while (current < buffer.length) {
    const len = buffer[current];

    if (len === 0) {
      if (!jumped) {
        nextOffset = current + 1;
      }
      break;
    }

    // Check top 2 bits for compression pointer (0b11xxxxxx = 0xC0)
    if ((len & 0xc0) === 0xc0) {
      if (current + 1 >= buffer.length) break;
      const pointer = ((len & 0x3f) << 8) | buffer[current + 1];

      if (!jumped) {
        nextOffset = current + 2;
        jumped = true;
      }

      jumps++;
      if (jumps > MAX_COMPRESSION_POINTERS || visitedPointers.has(pointer)) {
        // Pointer loop or excessive recursion detected; break safely
        labels.push("<loop>");
        break;
      }
      visitedPointers.add(pointer);
      current = pointer;
      continue;
    }

    // Standard length-prefixed label
    current++;
    if (current + len > buffer.length) {
      labels.push("<truncated>");
      if (!jumped) nextOffset = buffer.length;
      break;
    }

    const label = buffer.toString("utf8", current, current + len);
    labels.push(label);
    current += len;
  }

  if (!jumped && nextOffset === -1) {
    nextOffset = Math.min(current, buffer.length);
  }

  return {
    name: labels.join(".") || ".",
    nextOffset: nextOffset !== -1 ? nextOffset : current
  };
}

/**
 * Formats an IPv6 Buffer into RFC 5952 zero-compressed colon-hex representation.
 */
function formatIPv6(buf, offset) {
  const words = [];
  for (let i = 0; i < 8; i++) {
    words.push(buf.readUInt16BE(offset + i * 2).toString(16));
  }
  const full = words.join(":");
  return full.replace(/(?:^|:)0(?::0)+(?::|$)/, "::");
}

/**
 * Parses a DNS packet payload (RFC 1035 UDP or RFC 7766 TCP).
 * @param {Buffer} payload 
 * @param {boolean} [isTcp=false]
 * @returns {object|null}
 */
export function parseDNS(payload, isTcp = false) {
  if (!Buffer.isBuffer(payload) || payload.length < 12) {
    return null;
  }

  // RFC 1035 Section 4.2.2 / RFC 7766: DNS over TCP messages are prefixed with a 2-byte length field.
  // Auto-detect length match or respect isTcp flag
  if (isTcp || (payload.length >= 14 && payload.readUInt16BE(0) === payload.length - 2)) {
    payload = payload.subarray(2);
  }

  if (payload.length < 12) {
    return null;
  }

  try {
    const transactionId = payload.readUInt16BE(0);
    const flags = payload.readUInt16BE(2);

    const isResponse = Boolean((flags >>> 15) & 0x01);
    const opcode = (flags >>> 11) & 0x0f;
    const authoritative = Boolean((flags >>> 10) & 0x01);
    const truncated = Boolean((flags >>> 9) & 0x01);
    const recursionDesired = Boolean((flags >>> 8) & 0x01);
    const recursionAvailable = Boolean((flags >>> 7) & 0x01);
    const rcode = flags & 0x0f;
    const rcodeName = DNS_RCODES[rcode] || `RCODE_${rcode}`;

    const qdCount = payload.readUInt16BE(4);
    const anCount = payload.readUInt16BE(6);
    const nsCount = payload.readUInt16BE(8);
    const arCount = payload.readUInt16BE(10);

    let offset = 12;

    // 1. Parse Questions
    const questions = [];
    for (let i = 0; i < qdCount && offset < payload.length; i++) {
      const { name, nextOffset } = readDNSName(payload, offset);
      offset = nextOffset;

      if (offset + 4 <= payload.length) {
        const qtype = payload.readUInt16BE(offset);
        const qclass = payload.readUInt16BE(offset + 2);
        offset += 4;

        questions.push({
          name,
          type: DNS_TYPES[qtype] || `TYPE_${qtype}`,
          class: qclass === 1 ? "IN" : `CLASS_${qclass}`
        });
      }
    }

    // Helper to parse resource records (Answers, Authorities, Additionals)
    function parseRRs(count) {
      const records = [];
      for (let i = 0; i < count && offset < payload.length; i++) {
        const { name, nextOffset } = readDNSName(payload, offset);
        offset = nextOffset;

        if (offset + 10 > payload.length) break;

        const typeNum = payload.readUInt16BE(offset);
        const classNum = payload.readUInt16BE(offset + 2);
        const ttl = payload.readUInt32BE(offset + 4);
        const rdLength = payload.readUInt16BE(offset + 8);
        offset += 10;

        if (offset + rdLength > payload.length) break;

        const typeStr = DNS_TYPES[typeNum] || `TYPE_${typeNum}`;
        let data = null;

        if (typeNum === 1 && rdLength === 4) {
          // A record: IPv4
          data = `${payload[offset]}.${payload[offset + 1]}.${payload[offset + 2]}.${payload[offset + 3]}`;
        } else if (typeNum === 28 && rdLength === 16) {
          // AAAA record: IPv6
          data = formatIPv6(payload, offset);
        } else if (typeNum === 5 || typeNum === 2 || typeNum === 12) {
          // CNAME, NS, PTR
          const { name: cname } = readDNSName(payload, offset);
          data = cname;
        } else if (typeNum === 15 && rdLength >= 2) {
          // MX record: preference + domain
          const preference = payload.readUInt16BE(offset);
          const { name: mxHost } = readDNSName(payload, offset + 2);
          data = { preference, host: mxHost };
        } else if (typeNum === 16) {
          // TXT record: sequence of length-prefixed strings
          let txtOffset = offset;
          const strings = [];
          while (txtOffset < offset + rdLength) {
            const txtLen = payload[txtOffset];
            txtOffset++;
            if (txtOffset + txtLen <= offset + rdLength) {
              strings.push(payload.toString("utf8", txtOffset, txtOffset + txtLen));
              txtOffset += txtLen;
            } else {
              break;
            }
          }
          data = strings.join(" ");
        } else {
          // Raw hex representation for unsupported or complex types
          data = payload.subarray(offset, offset + rdLength).toString("hex");
        }

        offset += rdLength;

        records.push({
          name,
          type: typeStr,
          class: classNum === 1 ? "IN" : `CLASS_${classNum}`,
          ttl,
          data
        });
      }
      return records;
    }

    const answers = parseRRs(anCount);
    const authorities = parseRRs(nsCount);
    const additionals = parseRRs(arCount);

    return {
      transactionId,
      isResponse,
      opcode,
      rcode,
      rcodeName,
      flags: {
        authoritative,
        truncated,
        recursionDesired,
        recursionAvailable
      },
      questions,
      answers,
      authorities,
      additionals
    };
  } catch (err) {
    return null;
  }
}
