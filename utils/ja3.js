/**
 * packet-chef-mcp - JA3, JA3S & JA4 TLS Fingerprinting Engine
 * Implements pure-JS JA3/JA3S (Salesforce) and JA4 TLS fingerprinting with
 * GREASE filtering and signature detection for malware/C2 attribution.
 */

import crypto from "node:crypto";

// RFC 8701 GREASE values filter
export function isGrease(val) {
  return (val & 0x0f0f) === 0x0a0a && ((val >> 8) & 0xff) === (val & 0xff);
}

// Known malicious and tool JA3 fingerprint database
export const KNOWN_JA3_SIGNATURES = {
  "a0e9f5d64349fb13191bc781f81f42e1": { tool: "Cobalt Strike", type: "MALWARE_C2", confidence: "HIGH" },
  "0474d5952a8ae5d2afdcbd13daed7c38": { tool: "Cobalt Strike", type: "MALWARE_C2", confidence: "HIGH" },
  "72a589da586844d7f0818ce684948eea": { tool: "Metasploit Meterpreter", type: "MALWARE_C2", confidence: "HIGH" },
  "4d7a28d6f22da2e8ee70388601660f5c": { tool: "Emotet Banking Trojan", type: "MALWARE", confidence: "HIGH" },
  "b32309a26951912be7dba376398abc3b": { tool: "Sliver C2 Framework", type: "MALWARE_C2", confidence: "HIGH" },
  "e3579b2931eb677f3a8b417e8139589d": { tool: "Python Requests library", type: "SCRIPT_TOOL", confidence: "MEDIUM" },
  "8390e19b52a912a7d04eb589b2db6c9e": { tool: "Go-http-client / Go malware", type: "TOOL_OR_MALWARE", confidence: "MEDIUM" },
  "8d89fedb8f5223c6d7a46237c1d763ad": { tool: "cURL CLI", type: "CLI_TOOL", confidence: "MEDIUM" }
};

/**
 * Computes JA3 and JA4 fingerprints from a parsed TLS ClientHello.
 * @param {object} hello ClientHello parsed by tls-parser
 * @returns {object} { ja3String, ja3Hash, ja4String, matchedSignature }
 */
export function calculateJA3(hello) {
  if (!hello) return null;

  // 1. SSL/TLS Version (decimal)
  const version = hello.clientVersionRaw || (hello.clientVersion === "TLS 1.3" ? 772 : (hello.clientVersion === "TLS 1.2" ? 771 : 769));

  // 2. Ciphers (excluding GREASE)
  const ciphers = (hello.cipherSuitesRaw || [])
    .filter(c => !isGrease(c));

  // 3. Extensions (excluding GREASE)
  const extensions = (hello.extensionsRaw || [])
    .filter(e => !isGrease(e.type))
    .map(e => e.type);

  // 4. Supported Groups / Elliptic Curves (extension 10)
  const curves = (hello.supportedCurvesRaw || [])
    .filter(c => !isGrease(c));

  // 5. EC Point Formats (extension 11)
  const pointFormats = hello.ecPointFormatsRaw || [];

  // Assemble JA3 String: SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat
  const ja3Parts = [
    version,
    ciphers.join("-"),
    extensions.join("-"),
    curves.join("-"),
    pointFormats.join("-")
  ];
  const ja3String = ja3Parts.join(",");
  const ja3Hash = crypto.createHash("md5").update(ja3String).digest("hex");

  // Modern JA4 calculation: a_b_c
  // Part a: Protocol (t) + version (12/13) + SNI (d/i) + cipherCount + extCount + ALPN
  const proto = "t";
  const verStr = version === 772 ? "13" : (version === 771 ? "12" : (version === 770 ? "11" : "10"));
  const sniFlag = hello.sni ? "d" : "i";
  const cCount = String(Math.min(99, ciphers.length)).padStart(2, "0");
  const eCount = String(Math.min(99, extensions.length)).padStart(2, "0");
  const alpn = hello.alpn ? hello.alpn.slice(0, 2).padEnd(2, "0") : "00";
  const ja4PartA = `${proto}${verStr}${sniFlag}${cCount}${eCount}${alpn}`;

  // Part b: Truncated SHA-256 (12 chars) of sorted ciphers
  const sortedCiphersHex = [...ciphers].sort((a, b) => a - b).map(c => c.toString(16).padStart(4, "0")).join(",");
  const ja4PartB = crypto.createHash("sha256").update(sortedCiphersHex).digest("hex").slice(0, 12);

  // Part c: Truncated SHA-256 (12 chars) of sorted extensions
  const sortedExtsHex = [...extensions].sort((a, b) => a - b).map(e => e.toString(16).padStart(4, "0")).join(",");
  const ja4PartC = crypto.createHash("sha256").update(sortedExtsHex).digest("hex").slice(0, 12);

  const ja4String = `${ja4PartA}_${ja4PartB}_${ja4PartC}`;

  const matched = KNOWN_JA3_SIGNATURES[ja3Hash] || null;

  return {
    ja3String,
    ja3Hash,
    ja3: ja3Hash,
    ja4String,
    ja4: ja4String,
    matchedThreat: matched,
    matchedSignature: matched,
    ciphersCount: ciphers.length,
    extensionsCount: extensions.length
  };
}
