/**
 * packet-chef-mcp - WebSocket Protocol Decoder (RFC 6455)
 * Extracts WebSocket frames from TCP stream buffers, de-masks client frames,
 * and reconstructs text, JSON, and binary messages for agent forensic triage.
 */

export const WS_OPCODES = {
  0x0: "CONTINUATION",
  0x1: "TEXT",
  0x2: "BINARY",
  0x8: "CLOSE",
  0x9: "PING",
  0xa: "PONG"
};

/**
 * Parses all WebSocket frames from a TCP stream buffer.
 * @param {Buffer} buffer Raw TCP payload bytes
 * @param {string} [direction="client->server"]
 * @returns {Array<object>} Array of parsed and unmasked WebSocket messages
 */
export function parseWebSocketFrames(buffer, direction = "client->server") {
  if (!Buffer.isBuffer(buffer) || buffer.length < 2) return [];

  const frames = [];
  let offset = 0;
  let hasPermessageDeflate = false;

  // RFC 6455 Section 4: Advance past HTTP Upgrade handshake if present in reassembled stream
  const headerEnd = buffer.indexOf("\r\n\r\n");
  if (headerEnd !== -1) {
    const headStr = buffer.subarray(0, headerEnd).toString("latin1").toLowerCase();
    if (headStr.includes("upgrade:") && headStr.includes("websocket")) {
      offset = headerEnd + 4;
      if (headStr.includes("permessage-deflate")) {
        hasPermessageDeflate = true;
      }
    }
  } else {
    const headerEndLf = buffer.indexOf("\n\n");
    if (headerEndLf !== -1) {
      const headStr = buffer.subarray(0, headerEndLf).toString("latin1").toLowerCase();
      if (headStr.includes("upgrade:") && headStr.includes("websocket")) {
        offset = headerEndLf + 2;
        if (headStr.includes("permessage-deflate")) {
          hasPermessageDeflate = true;
        }
      }
    }
  }

  while (offset + 2 <= buffer.length) {
    const b0 = buffer[offset];
    const b1 = buffer[offset + 1];

    const fin = (b0 & 0x80) !== 0;
    const rsv1 = (b0 & 0x40) !== 0;
    const opcodeNum = b0 & 0x0f;
    const opcode = WS_OPCODES[opcodeNum] || `UNKNOWN_0x${opcodeNum.toString(16)}`;

    const isMasked = (b1 & 0x80) !== 0;
    let payloadLen = b1 & 0x7f;
    let headerLen = 2;

    if (payloadLen === 126) {
      if (offset + 4 > buffer.length) break;
      payloadLen = buffer.readUInt16BE(offset + 2);
      headerLen = 4;
    } else if (payloadLen === 127) {
      if (offset + 10 > buffer.length) break;
      // High 32-bit + low 32-bit (cap at reasonable 10MB)
      const high = buffer.readUInt32BE(offset + 2);
      const low = buffer.readUInt32BE(offset + 6);
      if (high > 0 || low > 10 * 1024 * 1024) {
        // Discard absurd frame sizes
        break;
      }
      payloadLen = low;
      headerLen = 10;
    }

    let maskKey = null;
    if (isMasked) {
      if (offset + headerLen + 4 > buffer.length) break;
      maskKey = buffer.subarray(offset + headerLen, offset + headerLen + 4);
      headerLen += 4;
    }

    if (offset + headerLen + payloadLen > buffer.length) {
      // Incomplete frame at stream boundary
      break;
    }

    const rawPayload = buffer.subarray(offset + headerLen, offset + headerLen + payloadLen);
    let payload = rawPayload;

    // Unmask if masked
    if (isMasked && maskKey) {
      payload = Buffer.alloc(rawPayload.length);
      for (let i = 0; i < rawPayload.length; i++) {
        payload[i] = rawPayload[i] ^ maskKey[i % 4];
      }
    }

    // RFC 7692: If RSV1 is set or permessage-deflate was negotiated, payload is compressed with DEFLATE
    const isCompressed = rsv1 || (hasPermessageDeflate && (opcode === "TEXT" || opcode === "BINARY" || opcode === "CONTINUATION"));
    let textPreview = null;
    let isJson = false;
    let jsonParsed = null;

    if (isCompressed) {
      textPreview = `<compressed deflate: ${payload.length} bytes>`;
    } else if (opcode === "TEXT" || opcode === "CONTINUATION") {
      try {
        textPreview = payload.toString("utf8");
        if (textPreview.trim().startsWith("{") || textPreview.trim().startsWith("[")) {
          jsonParsed = JSON.parse(textPreview);
          isJson = true;
        }
      } catch {
        textPreview = payload.toString("latin1");
      }
    }

    frames.push({
      index: frames.length + 1,
      direction,
      fin,
      rsv1,
      opcode,
      opcodeName: opcode,
      isMasked,
      maskingKey: maskKey ? maskKey.toString("hex") : null,
      payloadLength: payloadLen,
      isCompressed,
      compressionAlgorithm: isCompressed ? "deflate" : null,
      textPreview: textPreview ? (textPreview.length > 512 ? `${textPreview.slice(0, 512)}...[TRUNCATED]` : textPreview) : null,
      payloadText: textPreview,
      isJson,
      jsonData: jsonParsed,
      rawPayloadBase64: payload.toString("base64"),
      payloadHex: payload.length <= 64 ? payload.toString("hex") : `${payload.subarray(0, 64).toString("hex")}...`,
      handoffHint: isCompressed ? "Payload is raw deflate compressed (RFC 7692). Decompress rawPayloadBase64 using cyberchef_bake with 'Raw Inflate' (or cyberchef_gunzip / BuiltinChef.rawInflate)." : null
    });

    offset += headerLen + payloadLen;
  }

  return frames;
}
