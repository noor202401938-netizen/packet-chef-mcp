/**
 * packet-chef-mcp - DNS Tunnel Detector
 * Identifies DNS data exfiltration, covert C2 channels, and tunneling utilities
 * (e.g. dnscat2, iodine, Cobalt Strike DNS beacons).
 * Computes Shannon character entropy, subdomain label lengths, character set profiles,
 * and CDN heuristic filtering.
 */

const KNOWN_CDN_DOMAINS = new Set([
  "akamaiedge.net", "akamai.net", "cloudflare.com", "cloudfront.net",
  "azureedge.net", "trafficmanager.net", "1e100.net", "google.com",
  "googleapis.com", "apple-dns.net", "fastly.net", "awsdns.com",
  "github.io", "pages.dev", "azurewebsites.net", "s3.amazonaws.com",
  "amazonaws.com", "herokuapp.com", "netlify.app", "vercel.app",
  "workers.dev", "firebaseapp.com", "cloudapp.net"
]);

/**
 * Calculates the Shannon entropy (in bits per character) of a string.
 * @param {string} str 
 * @returns {number}
 */
export function calculateStringEntropy(str) {
  if (!str || str.length === 0) return 0;

  const freqs = new Map();
  for (let i = 0; i < str.length; i++) {
    const ch = str[i];
    freqs.set(ch, (freqs.get(ch) || 0) + 1);
  }

  let entropy = 0;
  const len = str.length;
  for (const count of freqs.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }

  return +entropy.toFixed(3);
}

/**
 * Extracts the base parent domain (e.g. "evil.com" from "data.sub.evil.com").
 */
export function extractParentDomain(domain) {
  if (!domain || typeof domain !== "string") return "unknown";
  const clean = domain.toLowerCase().replace(/\.+$/, "");
  const parts = clean.split(".");

  if (parts.length <= 2) return clean;

  // Handle common two-part TLDs (e.g. .co.uk, .com.au)
  const secondLast = parts[parts.length - 2];
  if (["co", "com", "org", "net", "edu", "gov"].includes(secondLast) && parts.length >= 3) {
    return parts.slice(-3).join(".");
  }

  return parts.slice(-2).join(".");
}

/**
 * Profiles the encoding / character set of subdomain strings.
 */
function profileCharacterSet(str) {
  if (!str || str.length === 0) return "empty";

  // Clean label separators (dots, hyphens) to analyze payload characters
  const clean = str.replace(/[\.\-_]/g, "");
  if (clean.length === 0) return "empty";

  let hexChars = 0;
  let base32Chars = 0;
  let base64Chars = 0;

  for (let i = 0; i < clean.length; i++) {
    const ch = clean[i];
    if (/[0-9a-fA-F]/.test(ch)) hexChars++;
    if (/[a-z2-7]/i.test(ch)) base32Chars++;
    if (/[a-zA-Z0-9+\/=_]/.test(ch)) base64Chars++;
  }

  const len = clean.length;
  if (hexChars / len >= 0.85) return "hex";
  if (base32Chars / len >= 0.85 && hexChars / len < 0.75) return "base32";
  if (base64Chars / len >= 0.85) return "base64";
  return "mixed";
}

/**
 * Detects DNS tunneling activity from an array of DNS queries.
 * @param {Array<{ name: string }>} dnsQueries 
 * @param {object} [options={}]
 * @param {number} [options.minSubdomains=15]
 * @returns {object} Suspicious tunneling domains and metrics
 */
export function detectDNSTunneling(dnsQueries, options = {}) {
  const minSubdomains = options.minSubdomains || 15;
  const domainGroups = new Map();

  for (const q of dnsQueries) {
    if (!q || !q.name || q.name === ".") continue;

    const fullDomain = q.name.toLowerCase().replace(/\.+$/, "");
    const parent = extractParentDomain(fullDomain);

    if (fullDomain === parent) continue; // No subdomain present

    // Extract prefix subdomains
    const sub = fullDomain.slice(0, fullDomain.length - parent.length - 1);
    if (!sub) continue;

    let group = domainGroups.get(parent);
    if (!group) {
      group = {
        parentDomain: parent,
        subdomainSet: new Set(),
        totalQueries: 0,
        queryTypes: new Set()
      };
      domainGroups.set(parent, group);
    }

    group.subdomainSet.add(sub);
    group.totalQueries++;
    if (q.type) group.queryTypes.add(q.type);
  }

  const suspiciousDomains = [];

  for (const group of domainGroups.values()) {
    const uniqueCount = group.subdomainSet.size;
    if (uniqueCount < minSubdomains) continue;

    const subdomains = Array.from(group.subdomainSet);
    const totalSubdomainLen = subdomains.reduce((acc, s) => acc + s.length, 0);
    const avgSubdomainLength = +(totalSubdomainLen / uniqueCount).toFixed(1);

    // Compute aggregate entropy across sample subdomains
    const sampleJoined = subdomains.slice(0, 50).join("");
    const subdomainEntropy = calculateStringEntropy(sampleJoined);
    const charSet = profileCharacterSet(sampleJoined);

    const isCdn = KNOWN_CDN_DOMAINS.has(group.parentDomain);

    let confidence = null;
    let verdict = "";

    if (!isCdn && subdomainEntropy > 3.5 && avgSubdomainLength > 15) {
      confidence = "HIGH";
      verdict = `Critical DNS tunneling indicator: ${uniqueCount} high-entropy (${subdomainEntropy} bits/char) long subdomains (avg ${avgSubdomainLength} chars, ${charSet} encoded).`;
    } else if (!isCdn && (subdomainEntropy > 3.0 && uniqueCount >= 20)) {
      confidence = "MEDIUM";
      verdict = `Probable DNS tunneling / exfiltration: ${uniqueCount} unique subdomains with elevated entropy (${subdomainEntropy} bits/char).`;
    } else if (isCdn) {
      confidence = "LOW";
      verdict = `Benign / CDN pattern: ${uniqueCount} machine-generated subdomains under trusted infrastructure (${group.parentDomain}).`;
    } else if (subdomainEntropy > 2.8 && uniqueCount >= 30) {
      confidence = "LOW";
      verdict = `Unusual DNS query volume: ${uniqueCount} subdomains under ${group.parentDomain}.`;
    }

    if (confidence) {
      suspiciousDomains.push({
        parentDomain: group.parentDomain,
        uniqueSubdomains: uniqueCount,
        sampleSubdomains: subdomains.slice(0, 5),
        avgSubdomainLength,
        subdomainEntropy,
        characterSetProfile: charSet,
        totalQueries: group.totalQueries,
        queryTypes: Array.from(group.queryTypes),
        isKnownCdnDomain: isCdn,
        confidence,
        verdict
      });
    }
  }

  // Sort by confidence: HIGH > MEDIUM > LOW, then by unique subdomains
  const confOrder = { HIGH: 3, MEDIUM: 2, LOW: 1 };
  suspiciousDomains.sort((a, b) => {
    const diff = (confOrder[b.confidence] || 0) - (confOrder[a.confidence] || 0);
    return diff !== 0 ? diff : b.uniqueSubdomains - a.uniqueSubdomains;
  });

  return {
    suspiciousDomains,
    totalParentDomainsAnalyzed: domainGroups.size
  };
}
