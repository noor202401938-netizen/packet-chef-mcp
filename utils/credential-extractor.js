/**
 * packet-chef-mcp - Credential Extractor
 * Hunts for cleartext and recoverable credentials in HTTP headers, URL params,
 * form/JSON payloads, FTP commands, SMTP authentication, and Telnet sessions.
 */

/**
 * Extracts credentials from HTTP headers, URIs, and bodies.
 */
function extractFromHTTP(req, client, server, timestamp) {
  const creds = [];
  const headers = req.headers || {};
  const host = headers["host"] || "unknown";

  // 1. Authorization: Basic <base64>
  const authHeader = headers["authorization"];
  if (authHeader) {
    if (authHeader.toLowerCase().startsWith("basic ")) {
      const b64 = authHeader.slice(6).trim();
      try {
        const decoded = Buffer.from(b64, "base64").toString("utf8");
        const colonIdx = decoded.indexOf(":");
        if (colonIdx !== -1) {
          creds.push({
            type: "HTTP_BASIC",
            timestamp,
            source: client,
            destination: server,
            host,
            uri: req.uri,
            username: decoded.slice(0, colonIdx),
            password: decoded.slice(colonIdx + 1),
            context: `Decoded from HTTP Authorization header on ${req.method} ${req.uri}`
          });
        }
      } catch (err) {
        // Ignore base64 decoding error
      }
    } else if (authHeader.toLowerCase().startsWith("bearer ")) {
      const token = authHeader.slice(7).trim();
      creds.push({
        type: "HTTP_BEARER",
        timestamp,
        source: client,
        destination: server,
        host,
        uri: req.uri,
        username: null,
        password: null,
        token: token.length > 64 ? `${token.slice(0, 32)}...${token.slice(-16)}` : token,
        context: `Bearer token observed on ${req.method} ${req.uri}`
      });
    } else if (authHeader.toLowerCase().startsWith("digest ")) {
      const userMatch = authHeader.match(/username="?([^",]+)"?/i);
      if (userMatch) {
        creds.push({
          type: "HTTP_DIGEST",
          timestamp,
          source: client,
          destination: server,
          host,
          uri: req.uri,
          username: userMatch[1],
          password: "<hashed>",
          context: `Digest authentication username on ${req.method} ${req.uri}`
        });
      }
    }
  }

  // 2. Query parameter credentials
  if (req.uri && req.uri.includes("?")) {
    const query = req.uri.slice(req.uri.indexOf("?") + 1);
    const passMatch = query.match(/(?:^|[&;])(?:pass|password|passwd|pwd|secret)=([^&;]+)/i);
    const userMatch = query.match(/(?:^|[&;])(?:user|username|login|email)=([^&;]+)/i);
    if (passMatch) {
      creds.push({
        type: "HTTP_QUERY_PARAM",
        timestamp,
        source: client,
        destination: server,
        host,
        uri: req.uri,
        username: userMatch ? decodeURIComponent(userMatch[1]) : null,
        password: decodeURIComponent(passMatch[1]),
        context: "Exposed cleartext credential parameters in HTTP request URI"
      });
    }
  }

  // 3. Request body parameters (form urlencoded, JSON, or regex fallback)
  if (req.body && typeof req.body === "string" && !req.body.startsWith("<binary")) {
    const body = req.body;
    let foundBodyCred = false;

    // A. Form URL-Encoded parameter extraction (e.g. username=admin&password=My+Pass)
    if (body.includes("=")) {
      try {
        const params = new URLSearchParams(body);
        let user = null;
        let pass = null;
        for (const [key, val] of params.entries()) {
          const k = key.toLowerCase();
          if (["username", "user", "login", "email"].includes(k) && !user) {
            user = val;
          }
          if (["password", "passwd", "pwd", "pass", "secret"].includes(k) && !pass) {
            pass = val;
          }
        }
        if (pass) {
          foundBodyCred = true;
          creds.push({
            type: "HTTP_BODY",
            timestamp,
            source: client,
            destination: server,
            host,
            uri: req.uri,
            username: user,
            password: pass,
            context: `Form URL-encoded login credentials in HTTP ${req.method} body`
          });
        }
      } catch (_) {}
    }

    // B. JSON body extraction
    if (!foundBodyCred && body.trim().startsWith("{")) {
      try {
        const obj = JSON.parse(body);
        let user = null;
        let pass = null;
        for (const [k, v] of Object.entries(obj)) {
          const keyLow = k.toLowerCase();
          if (["username", "user", "login", "email"].includes(keyLow) && typeof v === "string") {
            user = v;
          }
          if (["password", "passwd", "pwd", "pass", "secret"].includes(keyLow) && typeof v === "string") {
            pass = v;
          }
        }
        if (pass) {
          foundBodyCred = true;
          creds.push({
            type: "HTTP_BODY",
            timestamp,
            source: client,
            destination: server,
            host,
            uri: req.uri,
            username: user,
            password: pass,
            context: `JSON login credentials in HTTP ${req.method} body`
          });
        }
      } catch (_) {}
    }

    // C. Regex fallback for unquoted or non-standard payloads
    if (!foundBodyCred) {
      const passMatch = body.match(/\b(?:password|passwd|pwd|pass)\b\s*[:=]\s*(?:"([^"]+)"|'([^']+)'|([^&,\r\n]+))/i);
      const userMatch = body.match(/\b(?:username|user|login|email)\b\s*[:=]\s*(?:"([^"]+)"|'([^']+)'|([^&,\r\n]+))/i);
      if (passMatch) {
        const passVal = passMatch[1] || passMatch[2] || passMatch[3];
        const userVal = userMatch ? (userMatch[1] || userMatch[2] || userMatch[3]) : null;
        creds.push({
          type: "HTTP_BODY",
          timestamp,
          source: client,
          destination: server,
          host,
          uri: req.uri,
          username: userVal ? userVal.trim() : null,
          password: passVal.trim(),
          context: `Login credentials extracted from HTTP ${req.method} body`
        });
      }
    }
  }

  return creds;
}

/**
 * Extracts cleartext FTP and SMTP credentials from raw TCP streams.
 */
function extractFromTCPStream(stream) {
  const creds = [];
  let clientText = stream.clientData.toString("latin1");
  const serverText = stream.serverData ? stream.serverData.toString("latin1") : "";

  // Check if orientation is flipped (mid-stream capture)
  let src = stream.client;
  let dst = stream.server;
  if (!clientText.match(/USER\s+/i) && serverText.match(/USER\s+/i)) {
    clientText = serverText;
    src = stream.server;
    dst = stream.client;
  } else if (!clientText.match(/AUTH\s+PLAIN/i) && serverText.match(/AUTH\s+PLAIN/i)) {
    clientText = serverText;
    src = stream.server;
    dst = stream.client;
  }

  // FTP: USER <user> and PASS <password>
  const ftpUser = clientText.match(/USER\s+([^\r\n]+)/i);
  const ftpPass = clientText.match(/PASS\s+([^\r\n]+)/i);

  if (ftpUser && ftpPass) {
    creds.push({
      type: "FTP",
      timestamp: stream.startTime,
      source: src,
      destination: dst,
      host: dst,
      username: ftpUser[1].trim(),
      password: ftpPass[1].trim(),
      context: "Cleartext FTP USER and PASS commands extracted from stream"
    });
  }

  // SMTP: AUTH PLAIN <base64>
  const smtpAuthPlain = clientText.match(/AUTH\s+PLAIN\s+([A-Za-z0-9+/=]+)/i);
  if (smtpAuthPlain) {
    try {
      const decodedBuf = Buffer.from(smtpAuthPlain[1], "base64");
      // Format: \0username\0password or authzid\0authcid\0passwd
      const parts = [];
      let start = 0;
      for (let i = 0; i < decodedBuf.length; i++) {
        if (decodedBuf[i] === 0) {
          if (i > start) parts.push(decodedBuf.subarray(start, i).toString("utf8"));
          start = i + 1;
        }
      }
      if (start < decodedBuf.length) {
        parts.push(decodedBuf.subarray(start).toString("utf8"));
      }

      if (parts.length >= 2) {
        creds.push({
          type: "SMTP",
          timestamp: stream.startTime,
          source: src,
          destination: dst,
          host: dst,
          username: parts[0],
          password: parts[1],
          context: "Decoded cleartext credentials from SMTP AUTH PLAIN"
        });
      }
    } catch (e) {
      // Ignore decode error
    }
  }

  return creds;
}

/**
 * Hunts for credentials across HTTP transactions and TCP streams.
 * @param {Array<object>} httpTransactions Extracted HTTP request/response objects
 * @param {Array<object>} tcpStreams Reassembled TCP streams
 * @returns {object} Extracted credentials and summary
 */
export function extractCredentials(httpTransactions = [], tcpStreams = []) {
  const credentials = [];

  // 1. Audit HTTP transactions
  for (const t of httpTransactions) {
    const req = t.request || (t.method ? t : null);
    if (req) {
      const list = extractFromHTTP(req, t.client || "unknown", t.server || "unknown", req.timestamp || "unknown");
      credentials.push(...list);
    }
  }

  // 2. Audit raw TCP streams (FTP, SMTP, Telnet)
  for (const s of tcpStreams) {
    if (s.clientData && s.clientData.length > 0) {
      const list = extractFromTCPStream(s);
      credentials.push(...list);
    }
  }

  return {
    totalCredentialsFound: credentials.length,
    credentials
  };
}
