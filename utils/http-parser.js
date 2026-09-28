/**
 * packet-chef-mcp - HTTP/1.x Stream Parser
 * Extracts HTTP requests and responses from reassembled TCP stream buffers.
 * Features chunked transfer decoding, header parsing, body extraction with
 * bounded previews (4KB cap), and cognitive guidance hints for forensic triage.
 */

const HTTP_METHODS = new Set([
  "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"
]);

export const HTTP2_CLIENT_PREFACE = Buffer.from("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");

const MAX_BODY_PREVIEW = 4096; // 4KB preview limit to prevent LLM context exhaustion

/**
 * Checks if a buffer contains printable UTF-8 text.
 */
function isPrintableText(buf) {
  if (!buf || buf.length === 0) return true;
  const checkLen = Math.min(buf.length, 256);
  let nonPrintable = 0;
  for (let i = 0; i < checkLen; i++) {
    const b = buf[i];
    // Allow ASCII printable (32-126), tab (9), newline (10), carriage return (13)
    if (b < 32 && b !== 9 && b !== 10 && b !== 13) {
      nonPrintable++;
    }
  }
  return (nonPrintable / checkLen) < 0.1;
}

/**
 * Generates automated cognitive triage hints for security analysts.
 */
function generateHTTPHints(item, isResponse = false) {
  const hints = [];

  if (!isResponse) {
    if (item.headers && item.headers["authorization"]) {
      hints.push("Credentials detected in Authorization header.");
    }
    if (item.headers && item.headers["x-forwarded-for"]) {
      hints.push(`Proxy trail observed in X-Forwarded-For: ${item.headers["x-forwarded-for"]}`);
    }
    const uri = item.uri || "";
    if (uri.includes("../") || uri.includes("..\\") || uri.includes("%2e%2e")) {
      hints.push("Potential path traversal pattern (../) detected in URI.");
    }
    if (uri.toLowerCase().includes("cmd.exe") || uri.toLowerCase().includes("/bin/sh") || uri.toLowerCase().includes("/bin/bash")) {
      hints.push("Potential remote shell execution pattern detected in URI.");
    }
    if (uri.includes("<script") || uri.includes("%3cscript") || uri.toLowerCase().includes("union select")) {
      hints.push("Potential web attack payload (XSS/SQLi) detected in request URI.");
    }
  } else {
    if (item.statusCode >= 500) {
      hints.push(`Server error response (${item.statusCode}) may indicate crash, unhandled exception, or denial of service.`);
    } else if (item.statusCode === 401 || item.statusCode === 403) {
      hints.push(`Access denied status (${item.statusCode}) indicates unauthorized access attempt or restrictive ACL.`);
    }
    if (item.headers && item.headers["set-cookie"]) {
      hints.push("Session cookie set by server; potential authentication state change.");
    }
  }

  return hints;
}

/**
 * Parses HTTP chunked transfer encoding bytes.
 */
function decodeChunkedBody(bodyBuf) {
  const chunks = [];
  let offset = 0;

  while (offset < bodyBuf.length) {
    // Find next CRLF ending the hex chunk size line
    const crlfIdx = bodyBuf.indexOf("\r\n", offset);
    if (crlfIdx === -1) break;

    const sizeStr = bodyBuf.toString("ascii", offset, crlfIdx).trim().split(";")[0];
    const chunkSize = parseInt(sizeStr, 16);

    if (isNaN(chunkSize)) break;
    offset = crlfIdx + 2;

    if (chunkSize === 0) {
      // Final zero-length chunk
      break;
    }

    if (offset + chunkSize <= bodyBuf.length) {
      chunks.push(bodyBuf.subarray(offset, offset + chunkSize));
      offset += chunkSize;
      if (offset + 2 <= bodyBuf.length && bodyBuf[offset] === 0x0d && bodyBuf[offset + 1] === 0x0a) {
        offset += 2;
      }
    } else {
      // Incomplete chunk at end of stream
      chunks.push(bodyBuf.subarray(offset));
      break;
    }
  }

  return Buffer.concat(chunks);
}

/**
 * Parses a single HTTP request from a stream buffer starting at offset.
 */
export function parseHTTPRequest(buffer, startOffset = 0) {
  if (!Buffer.isBuffer(buffer) || startOffset >= buffer.length) return null;

  // Search for end of headers delimiter (\r\n\r\n or \n\n)
  let headerEnd = buffer.indexOf("\r\n\r\n", startOffset);
  let delimiterLen = 4;
  if (headerEnd === -1) {
    headerEnd = buffer.indexOf("\n\n", startOffset);
    delimiterLen = 2;
  }
  if (headerEnd === -1) return null;

  const headerText = buffer.toString("latin1", startOffset, headerEnd);
  const lines = headerText.split(/\r?\n/);
  if (lines.length === 0) return null;

  const reqLineParts = lines[0].trim().split(" ");
  if (reqLineParts.length < 2) return null;

  const method = reqLineParts[0].toUpperCase();
  if (!HTTP_METHODS.has(method)) return null;

  const uri = reqLineParts[1];
  const httpVersion = reqLineParts[2] ? reqLineParts[2].replace(/^HTTP\//i, "") : "1.1";

  const headers = {};
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    const colonIdx = line.indexOf(":");
    if (colonIdx !== -1) {
      const key = line.slice(0, colonIdx).trim().toLowerCase();
      const val = line.slice(colonIdx + 1).trim();
      headers[key] = val;
    }
  }

  let bodyOffset = headerEnd + delimiterLen;
  let bodyBytes = Buffer.alloc(0);
  let nextOffset = bodyOffset;

  const contentLengthHeader = headers["content-length"];
  const transferEncoding = (headers["transfer-encoding"] || "").toLowerCase();

  if (transferEncoding.includes("chunked")) {
    const rawBody = buffer.subarray(bodyOffset);
    bodyBytes = decodeChunkedBody(rawBody);
    // Approximate advancement for chunked streams
    const finalChunkIdx = buffer.indexOf("0\r\n\r\n", bodyOffset);
    nextOffset = finalChunkIdx !== -1 ? finalChunkIdx + 5 : buffer.length;
  } else if (contentLengthHeader !== undefined) {
    const cl = parseInt(contentLengthHeader, 10);
    if (!isNaN(cl) && cl >= 0) {
      const available = Math.min(cl, buffer.length - bodyOffset);
      bodyBytes = buffer.subarray(bodyOffset, bodyOffset + available);
      nextOffset = bodyOffset + available;
    }
  }

  const isText = isPrintableText(bodyBytes);
  const bodyPreview = isText
    ? bodyBytes.subarray(0, MAX_BODY_PREVIEW).toString("utf8")
    : `<binary data: ${bodyBytes.length} bytes; base64: ${bodyBytes.subarray(0, 128).toString("base64")}...>`;

  const req = {
    method,
    uri,
    httpVersion,
    headers,
    body: bodyPreview,
    bodyLength: bodyBytes.length,
    isBodyTruncated: bodyBytes.length > MAX_BODY_PREVIEW,
    hints: []
  };

  req.hints = generateHTTPHints(req, false);

  return { request: req, nextOffset };
}

/**
 * Parses a single HTTP response from a stream buffer starting at offset.
 */
export function parseHTTPResponse(buffer, startOffset = 0) {
  if (!Buffer.isBuffer(buffer) || startOffset >= buffer.length) return null;

  let headerEnd = buffer.indexOf("\r\n\r\n", startOffset);
  let delimiterLen = 4;
  if (headerEnd === -1) {
    headerEnd = buffer.indexOf("\n\n", startOffset);
    delimiterLen = 2;
  }
  if (headerEnd === -1) return null;

  const headerText = buffer.toString("latin1", startOffset, headerEnd);
  const lines = headerText.split(/\r?\n/);
  if (lines.length === 0) return null;

  const statusMatch = lines[0].match(/^HTTP\/([0-9.]+)\s+(\d{3})(?:\s+(.*))?$/i);
  if (!statusMatch) return null;

  const httpVersion = statusMatch[1];
  const statusCode = parseInt(statusMatch[2], 10);
  const statusText = statusMatch[3] ? statusMatch[3].trim() : "";

  const headers = {};
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    const colonIdx = line.indexOf(":");
    if (colonIdx !== -1) {
      const key = line.slice(0, colonIdx).trim().toLowerCase();
      const val = line.slice(colonIdx + 1).trim();
      headers[key] = val;
    }
  }

  let bodyOffset = headerEnd + delimiterLen;
  let bodyBytes = Buffer.alloc(0);
  let nextOffset = bodyOffset;

  const contentLengthHeader = headers["content-length"];
  const transferEncoding = (headers["transfer-encoding"] || "").toLowerCase();

  if (transferEncoding.includes("chunked")) {
    const rawBody = buffer.subarray(bodyOffset);
    bodyBytes = decodeChunkedBody(rawBody);
    const finalChunkIdx = buffer.indexOf("0\r\n\r\n", bodyOffset);
    nextOffset = finalChunkIdx !== -1 ? finalChunkIdx + 5 : buffer.length;
  } else if (contentLengthHeader !== undefined) {
    const cl = parseInt(contentLengthHeader, 10);
    if (!isNaN(cl) && cl >= 0) {
      const available = Math.min(cl, buffer.length - bodyOffset);
      bodyBytes = buffer.subarray(bodyOffset, bodyOffset + available);
      nextOffset = bodyOffset + available;
    }
  } else {
    // If no content length or chunking, response body consumes remaining buffer
    bodyBytes = buffer.subarray(bodyOffset);
    nextOffset = buffer.length;
  }

  const isText = isPrintableText(bodyBytes);
  const bodyPreview = isText
    ? bodyBytes.subarray(0, MAX_BODY_PREVIEW).toString("utf8")
    : `<binary data: ${bodyBytes.length} bytes; base64: ${bodyBytes.subarray(0, 128).toString("base64")}...>`;

  const resp = {
    httpVersion,
    statusCode,
    statusText,
    headers,
    body: bodyPreview,
    bodyLength: bodyBytes.length,
    isBodyTruncated: bodyBytes.length > MAX_BODY_PREVIEW,
    hints: []
  };

  resp.hints = generateHTTPHints(resp, true);

  return { response: resp, nextOffset };
}

/**
 * Parses all requests and responses from reassembled client and server buffers.
 * @param {Buffer} clientData
 * @param {Buffer} serverData
 * @returns {{ requests: Array<object>, responses: Array<object> }}
 */
export function parseHTTPStream(clientData, serverData) {
  const requests = [];
  const responses = [];
  let hasHttp2 = false;

  let cData = clientData;
  let sData = serverData;

  // Auto-detect inverted TCP stream orientation (mid-stream capture starting on server packet)
  const clientLooksLikeResponse = Buffer.isBuffer(cData) && cData.length >= 8 && cData.subarray(0, 8).toString("latin1").toUpperCase().startsWith("HTTP/1.");
  let serverLooksLikeRequest = false;
  if (Buffer.isBuffer(sData) && sData.length >= 4) {
    const sPrefix = sData.subarray(0, 10).toString("latin1").toUpperCase();
    for (const m of HTTP_METHODS) {
      if (sPrefix.startsWith(`${m} `)) {
        serverLooksLikeRequest = true;
        break;
      }
    }
  }

  if (serverLooksLikeRequest || clientLooksLikeResponse) {
    cData = serverData;
    sData = clientData;
  }

  // Check for HTTP/2 Client Connection Preface (RFC 7540 Section 3.5)
  if (Buffer.isBuffer(cData) && cData.length >= 24) {
    if (cData.indexOf(HTTP2_CLIENT_PREFACE) !== -1) {
      hasHttp2 = true;
    }
  }

  // Parse client requests
  if (Buffer.isBuffer(cData) && cData.length > 0 && !hasHttp2) {
    let offset = 0;
    while (offset < cData.length) {
      const res = parseHTTPRequest(cData, offset);
      if (!res || res.nextOffset <= offset) {
        break;
      }
      requests.push(res.request);
      offset = res.nextOffset;
    }
  }

  // Parse server responses
  if (Buffer.isBuffer(sData) && sData.length > 0 && !hasHttp2) {
    let offset = 0;
    while (offset < sData.length) {
      const res = parseHTTPResponse(sData, offset);
      if (!res || res.nextOffset <= offset) {
        break;
      }
      responses.push(res.response);
      offset = res.nextOffset;
    }
  }

  return { requests, responses, hasHttp2 };
}
