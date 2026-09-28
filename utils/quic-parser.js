/**
 * packet-chef-mcp - QUIC & HTTP/3 Initial Packet SNI Parser (RFC 9000 / RFC 9001 / RFC 9114)
 * Parses QUIC Initial Handshake packets over UDP (port 443) using RFC 9001 Section 5.2
 * Initial Secret derivation, AES-128-ECB header unprotection, and AES-128-GCM payload decryption
 * to extract real-world TLS 1.3 ClientHello SNI hostnames, ALPN, and Connection IDs without private keys.
 */

import crypto from "node:crypto";
import { parseClientHello } from "./tls-parser.js";

// RFC 9001 Section 5.2 Initial Salt for QUIC version 1
const QUIC_V1_SALT = Buffer.from("38762cf7f55934b34d179ae6a4c80cadccbb7f0a", "hex");

/**
 * HKDF-Expand-Label (RFC 8446 Section 7.1 / RFC 9001 Section 5.1)
 */
function hkdfExpandLabel(secret, label, context, length) {
  const fullLabel = Buffer.from("tls13 " + label, "utf8");
  const info = Buffer.concat([
    Buffer.from([(length >> 8) & 0xff, length & 0xff]),
    Buffer.from([fullLabel.length]),
    fullLabel,
    Buffer.from([context.length]),
    Buffer.from(context)
  ]);
  return Buffer.from(crypto.hkdfSync("sha256", secret, Buffer.alloc(0), info, length));
}

/**
 * Reads a QUIC variable-length integer (RFC 9000 Section 16).
 * 2MSB determines length: 00=1B, 01=2B, 10=4B, 11=8B
 * @param {Buffer} buffer
 * @param {number} offset
 * @returns {{ value: number, len: number }|null}
 */
export function readQuicVarInt(buffer, offset) {
  if (offset >= buffer.length) return null;
  const first = buffer[offset];
  const prefix = (first >> 6) & 0x03;

  if (prefix === 0) {
    return { value: first & 0x3f, len: 1 };
  } else if (prefix === 1) {
    if (offset + 2 > buffer.length) return null;
    return { value: ((first & 0x3f) << 8) | buffer[offset + 1], len: 2 };
  } else if (prefix === 2) {
    if (offset + 4 > buffer.length) return null;
    return {
      value: ((first & 0x3f) << 24) | (buffer[offset + 1] << 16) | (buffer[offset + 2] << 8) | buffer[offset + 3],
      len: 4
    };
  } else {
    // 8-byte varint
    if (offset + 8 > buffer.length) return null;
    const high = ((first & 0x3f) << 24) | (buffer[offset + 1] << 16) | (buffer[offset + 2] << 8) | buffer[offset + 3];
    const low = buffer.readUInt32BE(offset + 4);
    return { value: high * 4294967296 + low, len: 8 };
  }
}

/**
 * Attempts RFC 9001 Section 5.2 Initial Secret AEAD Decryption for QUIC v1.
 * @param {Buffer} udpPayload
 * @param {Buffer} dcidBuf
 * @param {number} pnOffset
 * @param {number} pktLenVal
 * @returns {Buffer|null} Decrypted payload frames
 */
function decryptQuicV1Initial(udpPayload, dcidBuf, pnOffset, pktLenVal) {
  try {
    const pktEnd = Math.min(udpPayload.length, pnOffset + pktLenVal);
    if (pktEnd <= pnOffset + 20) return null; // Needs at least 4 bytes PN + 16 bytes tag

    // 1. Initial Secret Derivation
    const initialSecret = crypto.createHmac("sha256", QUIC_V1_SALT).update(dcidBuf).digest();
    const clientInitialSecret = hkdfExpandLabel(initialSecret, "client in", "", 32);
    const key = hkdfExpandLabel(clientInitialSecret, "quic key", "", 16);
    const iv = hkdfExpandLabel(clientInitialSecret, "quic iv", "", 12);
    const hp = hkdfExpandLabel(clientInitialSecret, "quic hp", "", 16);

    // 2. Header Protection Removal
    const sampleOffset = pnOffset + 4;
    if (sampleOffset + 16 > udpPayload.length || sampleOffset + 16 > pktEnd) return null;
    const sample = udpPayload.subarray(sampleOffset, sampleOffset + 16);

    const hpCipher = crypto.createCipheriv("aes-128-ecb", hp, null);
    hpCipher.setAutoPadding(false);
    const mask = hpCipher.update(sample);

    const firstByte = udpPayload[0] ^ (mask[0] & 0x0f);
    const pnLen = (firstByte & 0x03) + 1;

    const pnBytes = Buffer.alloc(pnLen);
    let pnVal = 0;
    for (let i = 0; i < pnLen; i++) {
      pnBytes[i] = udpPayload[pnOffset + i] ^ mask[1 + i];
      pnVal = (pnVal << 8) | pnBytes[i];
    }

    // 3. Reconstruct Nonce
    const nonce = Buffer.from(iv);
    for (let i = 0; i < pnLen; i++) {
      nonce[nonce.length - 1 - i] ^= pnBytes[pnLen - 1 - i];
    }

    // 4. Construct Authenticated Additional Data (AAD)
    const aad = Buffer.concat([
      Buffer.from([firstByte]),
      udpPayload.subarray(1, pnOffset),
      pnBytes
    ]);

    // 5. AEAD Decrypt Payload
    const ciphertextStart = pnOffset + pnLen;
    const ciphertextEnd = pktEnd - 16;
    if (ciphertextStart >= ciphertextEnd) return null;

    const ciphertext = udpPayload.subarray(ciphertextStart, ciphertextEnd);
    const authTag = udpPayload.subarray(ciphertextEnd, pktEnd);

    const decipher = crypto.createDecipheriv("aes-128-gcm", key, nonce);
    decipher.setAAD(aad);
    decipher.setAuthTag(authTag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch (err) {
    // Decryption failed or not an encrypted packet
    return null;
  }
}

/**
 * Parses a UDP datagram to inspect if it is a QUIC Initial packet.
 * Supports both real-world RFC 9001 AEAD-encrypted payloads and cleartext fallbacks.
 * @param {Buffer} udpPayload
 * @returns {object|null}
 */
export function parseQuicInitial(udpPayload) {
  if (!Buffer.isBuffer(udpPayload) || udpPayload.length < 32) return null;

  const firstByte = udpPayload[0];
  const isLongHeader = (firstByte & 0x80) !== 0;
  if (!isLongHeader) return null; // Not a long header

  const packetType = (firstByte >> 4) & 0x03;
  if (packetType !== 0x00) {
    // Not an Initial Packet (0x00 = Initial)
    return null;
  }

  const version = udpPayload.readUInt32BE(1);
  if (version === 0) {
    // Version negotiation packet, not Initial
    return null;
  }

  let offset = 5;

  // Destination Connection ID
  if (offset >= udpPayload.length) return null;
  const dcidLen = udpPayload[offset];
  offset += 1;
  if (offset + dcidLen > udpPayload.length) return null;
  const dcidRaw = udpPayload.subarray(offset, offset + dcidLen);
  const dcid = dcidRaw.toString("hex");
  offset += dcidLen;

  // Source Connection ID
  if (offset >= udpPayload.length) return null;
  const scidLen = udpPayload[offset];
  offset += 1;
  if (offset + scidLen > udpPayload.length) return null;
  const scid = udpPayload.subarray(offset, offset + scidLen).toString("hex");
  offset += scidLen;

  // Token Length (varint)
  const tokenLen = readQuicVarInt(udpPayload, offset);
  if (!tokenLen) return null;
  offset += tokenLen.len + tokenLen.value;
  if (offset >= udpPayload.length) return null;

  // Packet Length (varint)
  const pktLen = readQuicVarInt(udpPayload, offset);
  if (!pktLen) return null;
  offset += pktLen.len;

  let sni = null;
  let clientHello = null;

  // Attempt Path 1: RFC 9001 Section 5.2 AEAD Decryption (for real wire traffic)
  if (version === 1 && dcidRaw.length > 0) {
    const decryptedPayload = decryptQuicV1Initial(udpPayload, dcidRaw, offset, pktLen.value);
    if (decryptedPayload && decryptedPayload.length > 0) {
      // Parse decrypted QUIC frames (CRYPTO frame is type 0x06)
      let fOff = 0;
      while (fOff < decryptedPayload.length) {
        const frameType = decryptedPayload[fOff];
        if (frameType === 0x00) {
          // PADDING frame
          fOff++;
          continue;
        } else if (frameType === 0x06) {
          // CRYPTO frame: offset (varint), length (varint), data
          fOff++;
          const cOffset = readQuicVarInt(decryptedPayload, fOff);
          if (!cOffset) break;
          fOff += cOffset.len;
          const cLen = readQuicVarInt(decryptedPayload, fOff);
          if (!cLen) break;
          fOff += cLen.len;

          if (fOff + cLen.value <= decryptedPayload.length) {
            const cryptoData = decryptedPayload.subarray(fOff, fOff + cLen.value);
            // If cryptoData starts with TLS Handshake type 0x01 (ClientHello)
            if (cryptoData[0] === 0x01) {
              const rec = Buffer.concat([
                Buffer.from([0x16, 0x03, 0x01, (cryptoData.length >> 8) & 0xff, cryptoData.length & 0xff]),
                cryptoData
              ]);
              clientHello = parseClientHello(rec);
              if (clientHello && clientHello.sni) {
                sni = clientHello.sni;
                break;
              }
            }
          }
          fOff += cLen.value;
        } else {
          // Skip other frames or stop
          break;
        }
      }
    }
  }

  // Attempt Path 2: Cleartext heuristic fallback (for synthetic / unencrypted test vectors)
  if (!sni) {
    const searchSlice = udpPayload.subarray(offset);
    for (let i = 0; i < searchSlice.length - 10; i++) {
      if (searchSlice[i] === 0x01 && searchSlice[i + 4] === 0x03 && searchSlice[i + 5] === 0x03) {
        const hsLen = (searchSlice[i + 1] << 16) | (searchSlice[i + 2] << 8) | searchSlice[i + 3];
        if (i + 4 + hsLen <= searchSlice.length) {
          const hsBytes = searchSlice.subarray(i, i + 4 + hsLen);
          const record = Buffer.concat([
            Buffer.from([0x16, 0x03, 0x01, (hsBytes.length >> 8) & 0xff, hsBytes.length & 0xff]),
            hsBytes
          ]);
          clientHello = parseClientHello(record);
          if (clientHello && clientHello.sni) {
            sni = clientHello.sni;
            break;
          }
        }
      }
    }
  }

  const quicVersionStr = version === 1 ? "QUIC v1 (0x00000001)" : `QUIC (0x${version.toString(16)})`;
  return {
    protocol: "QUIC",
    version: `0x${version.toString(16)}`,
    quicVersion: quicVersionStr,
    isInitial: true,
    dcid,
    scid,
    sni,
    alpn: clientHello?.alpn || "h3",
    ja3: clientHello?.ja3 || null
  };
}
