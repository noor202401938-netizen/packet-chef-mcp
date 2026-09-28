/**
 * packet-chef-mcp - TLS Parser
 * Extracts Server Name Indication (SNI), handshake metadata, and raw parameters
 * from TLS ClientHello packets for JA3/JA4 fingerprinting.
 * RFC 5246 / RFC 8446 compliant sequential parser with robust bounds checking.
 */

import { calculateJA3 } from "./ja3.js";

export const TLS_RECORD_TYPES = {
  CHANGE_CIPHER_SPEC: 0x14,
  ALERT: 0x15,
  HANDSHAKE: 0x16,
  APPLICATION_DATA: 0x17
};

export const TLS_HANDSHAKE_TYPES = {
  HELLO_REQUEST: 0x00,
  CLIENT_HELLO: 0x01,
  SERVER_HELLO: 0x02,
  CERTIFICATE: 0x0b,
  SERVER_KEY_EXCHANGE: 0x0c,
  SERVER_HELLO_DONE: 0x0e
};

export const TLS_VERSIONS = {
  0x0300: "SSL 3.0",
  0x0301: "TLS 1.0",
  0x0302: "TLS 1.1",
  0x0303: "TLS 1.2",
  0x0304: "TLS 1.3"
};

/**
 * Parses a TLS ClientHello record and extracts SNI, JA3/JA4 fields, and metadata.
 * @param {Buffer} payload 
 * @returns {object|null}
 */
export function parseClientHello(payload) {
  if (!Buffer.isBuffer(payload) || payload.length < 44) {
    return null;
  }

  try {
    // 1. Validate TLS Record Header
    const contentType = payload[0];
    if (contentType !== TLS_RECORD_TYPES.HANDSHAKE) {
      return null;
    }

    const recordVersion = payload.readUInt16BE(1);
    const recordLength = payload.readUInt16BE(3);

    // 2. Validate Handshake Header
    let offset = 5;
    if (offset >= payload.length) return null;

    const handshakeType = payload[offset];
    if (handshakeType !== TLS_HANDSHAKE_TYPES.CLIENT_HELLO) {
      return null;
    }

    // Handshake length (24-bit uint)
    if (offset + 4 > payload.length) return null;
    offset += 4;

    // 3. Client Version (2 bytes)
    if (offset + 2 > payload.length) return null;
    const clientVersionNum = payload.readUInt16BE(offset);
    const clientVersion = TLS_VERSIONS[clientVersionNum] || `0x${clientVersionNum.toString(16)}`;
    offset += 2;

    // 4. Random (32 bytes)
    offset += 32;
    if (offset > payload.length) return null;

    // 5. Session ID
    if (offset >= payload.length) return null;
    const sessionIdLen = payload[offset];
    offset += 1 + sessionIdLen;
    if (offset > payload.length) return null;

    // 6. Cipher Suites
    if (offset + 2 > payload.length) return null;
    const cipherSuitesLen = payload.readUInt16BE(offset);
    offset += 2;

    const cipherSuitesRaw = [];
    const cipherEnd = offset + cipherSuitesLen;
    if (cipherEnd > payload.length) return null;
    for (let cOff = offset; cOff + 2 <= cipherEnd; cOff += 2) {
      cipherSuitesRaw.push(payload.readUInt16BE(cOff));
    }
    offset = cipherEnd;

    // 7. Compression Methods
    if (offset >= payload.length) return null;
    const compLen = payload[offset];
    offset += 1 + compLen;
    if (offset > payload.length) return null;

    // 8. Extensions
    let sni = null;
    let alpn = null;
    const extensionsRaw = [];
    const supportedCurvesRaw = [];
    const ecPointFormatsRaw = [];
    let extensionCount = 0;

    if (offset + 2 <= payload.length) {
      const extensionsLen = payload.readUInt16BE(offset);
      offset += 2;
      const extEnd = Math.min(offset + extensionsLen, payload.length);

      while (offset + 4 <= extEnd) {
        const extType = payload.readUInt16BE(offset);
        const extLen = payload.readUInt16BE(offset + 2);
        offset += 4;
        extensionCount++;
        extensionsRaw.push({ type: extType, len: extLen });

        if (offset + extLen > extEnd) break;

        // Extension 0x0000 = server_name (SNI)
        if (extType === 0x0000) {
          let sniOffset = offset;
          if (sniOffset + 2 <= offset + extLen) {
            const sniListLen = payload.readUInt16BE(sniOffset);
            sniOffset += 2;
            const listEnd = Math.min(sniOffset + sniListLen, offset + extLen);
            while (sniOffset + 3 <= listEnd) {
              const nameType = payload[sniOffset];
              const nameLen = payload.readUInt16BE(sniOffset + 1);
              sniOffset += 3;
              if (sniOffset + nameLen <= listEnd) {
                if (nameType === 0x00) {
                  sni = payload.toString("utf8", sniOffset, sniOffset + nameLen);
                  break;
                }
                sniOffset += nameLen;
              } else {
                break;
              }
            }
          }
        } else if (extType === 0x000a) {
          // supported_groups / elliptic_curves (extension 10)
          if (offset + 2 <= offset + extLen) {
            const groupsLen = payload.readUInt16BE(offset);
            for (let g = offset + 2; g + 2 <= offset + 2 + groupsLen && g + 2 <= offset + extLen; g += 2) {
              supportedCurvesRaw.push(payload.readUInt16BE(g));
            }
          }
        } else if (extType === 0x000b) {
          // ec_point_formats (extension 11)
          if (offset + 1 <= offset + extLen) {
            const formatsLen = payload[offset];
            for (let f = offset + 1; f < offset + 1 + formatsLen && f < offset + extLen; f++) {
              ecPointFormatsRaw.push(payload[f]);
            }
          }
        } else if (extType === 0x0010) {
          // Application-Layer Protocol Negotiation (ALPN, extension 16)
          if (offset + 2 <= offset + extLen) {
            const alpnListLen = payload.readUInt16BE(offset);
            if (offset + 3 <= offset + extLen) {
              const protoLen = payload[offset + 2];
              if (offset + 3 + protoLen <= offset + extLen) {
                alpn = payload.toString("utf8", offset + 3, offset + 3 + protoLen);
              }
            }
          }
        }

        offset += extLen;
      }
    }

    const basicRecord = {
      sni,
      alpn,
      clientVersion,
      clientVersionRaw: clientVersionNum,
      recordVersion: TLS_VERSIONS[recordVersion] || `0x${recordVersion.toString(16)}`,
      cipherSuitesCount: cipherSuitesRaw.length,
      cipherSuitesRaw,
      extensionsCount: extensionCount,
      extensionsRaw,
      supportedCurvesRaw,
      ecPointFormatsRaw
    };

    const ja3Data = calculateJA3(basicRecord);

    return {
      ...basicRecord,
      ja3: ja3Data
    };
  } catch (err) {
    return null;
  }
}

/**
 * Convenience extractor returning the SNI hostname string or null.
 * @param {Buffer} payload 
 * @returns {string|null}
 */
export function extractTLSSNI(payload) {
  const result = parseClientHello(payload);
  return result ? result.sni : null;
}
