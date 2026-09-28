/**
 * packet-chef-mcp - PCAP Filtered Binary Exporter & Zeek Log Generator
 * Serializes forensic subsets into standard classic PCAP binaries and formats
 * standard Zeek TSV logs (conn.log, dns.log, http.log) for SIEM ingestion.
 */

import crypto from "node:crypto";

/**
 * Builds a standard 24-byte classic PCAP global header.
 * @param {object} [options]
 * @returns {Buffer}
 */
export function buildClassicPcapHeader({ magic = 0xa1b2c3d4, linkType = 1, snapLen = 65535 } = {}) {
  const buf = Buffer.alloc(24);
  buf.writeUInt32LE(magic, 0);     // Magic: 0xa1b2c3d4 (LE microsecond)
  buf.writeUInt16LE(2, 4);          // Major version 2
  buf.writeUInt16LE(4, 6);          // Minor version 4
  buf.writeInt32LE(0, 8);           // ThisZone GMT offset 0
  buf.writeUInt32LE(0, 12);         // SigFigs 0
  buf.writeUInt32LE(snapLen, 16);   // SnapLen
  buf.writeUInt32LE(linkType, 20);  // LinkType (1 = Ethernet)
  return buf;
}

/**
 * Builds a 16-byte PCAP packet record header prepended to data.
 * @param {number} timestampMs
 * @param {Buffer} data
 * @param {number} [origLen]
 * @returns {Buffer}
 */
export function buildPacketRecord(timestampMs, data, origLen = null) {
  const sec = Math.floor(timestampMs / 1000);
  const usec = Math.floor((timestampMs % 1000) * 1000);
  const len = data.length;
  const wireLen = origLen || len;

  const rec = Buffer.alloc(16);
  rec.writeUInt32LE(sec, 0);
  rec.writeUInt32LE(usec, 4);
  rec.writeUInt32LE(len, 8);
  rec.writeUInt32LE(wireLen, 12);

  return Buffer.concat([rec, data]);
}

/**
 * Exports filtered packets into an RFC-compliant PCAP buffer.
 * @param {Array<object>} packets List of dissected or raw packet objects
 * @param {number} [linkType=1]
 * @returns {Buffer}
 */
export function exportToPcap(packets, linkType = 1) {
  const chunks = [buildClassicPcapHeader({ linkType })];

  for (const pkt of packets) {
    if (pkt.data && Buffer.isBuffer(pkt.data)) {
      chunks.push(buildPacketRecord(pkt.timestampMs || Date.now(), pkt.data, pkt.origLen || pkt.data.length));
    }
  }

  return Buffer.concat(chunks);
}

/**
 * Generates Zeek-compatible TSV logs (conn.log, dns.log, http.log).
 * @param {object} analysis
 * @returns {object} { connLog: string, dnsLog: string, httpLog: string }
 */
export function generateZeekLogs(analysis = {}) {
  const safeAnalysis = (analysis && !Array.isArray(analysis)) ? analysis : {};
  const { conversations = [], dnsQueries = [], httpTransactions = [] } = safeAnalysis;

  // 1. conn.log
  const connHeader = [
    "#separator \\x09",
    "#set_separator ,",
    "#empty_field (empty)",
    "#unset_field -",
    "#fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service duration orig_bytes resp_bytes conn_state",
    "#types time string addr port addr port string string interval count count string"
  ].join("\n");

  const connLines = conversations.map((c, i) => {
    const ts = (new Date(c.startTime || 0).getTime() / 1000).toFixed(6);
    const uid = `C${crypto.randomBytes(6).toString("hex")}`;
    const clientStr = c.client || c.endpointA || "0.0.0.0:0";
    const serverStr = c.server || c.endpointB || "0.0.0.0:0";
    const [origH, origP] = clientStr.split(":");
    const [respH, respP] = serverStr.split(":");
    const proto = (c.protocol || "tcp").toLowerCase();
    const service = c.appProtocol || "-";
    const duration = c.durationMs !== undefined
      ? (c.durationMs / 1000).toFixed(3)
      : (((c.endMs || 0) - (c.startMs || 0)) / 1000).toFixed(3);
    const origBytes = c.bytesClient !== undefined ? c.bytesClient : (c.bytesAtoB || 0);
    const respBytes = c.bytesServer !== undefined ? c.bytesServer : (c.bytesBtoA || 0);
    const connState = (c.hasFIN || c.tcpFlags?.hasFIN) ? "SF" : ((c.hasRST || c.tcpFlags?.hasRST) ? "RSTO" : "OTH");
    return `${ts}\t${uid}\t${origH}\t${origP}\t${respH}\t${respP}\t${proto}\t${service}\t${duration}\t${origBytes}\t${respBytes}\t${connState}`;
  });

  const connLog = `${connHeader}\n${connLines.join("\n")}\n#close ${new Date().toISOString()}`;

  // 2. dns.log
  const dnsHeader = [
    "#separator \\x09",
    "#set_separator ,",
    "#empty_field (empty)",
    "#unset_field -",
    "#fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto trans_id query qclass qclass_name qtype qtype_name rcode rcode_name answers",
    "#types time string addr port addr port string count string count string count string count string vector[string]"
  ].join("\n");

  const dnsLines = dnsQueries.map((q, i) => {
    const ts = (new Date(q.timestamp || 0).getTime() / 1000).toFixed(6);
    const uid = `D${crypto.randomBytes(6).toString("hex")}`;
    const [origH, origP] = (q.client || "0.0.0.0:0").split(":");
    const [respH, respP] = (q.server || "0.0.0.0:53").split(":");
    const transId = q.transactionId || 0;
    const query = q.name || "-";
    const qtype = q.type || "A";
    const rcode = q.rcode || 0;
    const rcodeName = rcode === 0 ? "NOERROR" : `RCODE_${rcode}`;
    const answers = (q.answers || []).map(a => a.data || a.ip).filter(Boolean).join(",") || "-";
    return `${ts}\t${uid}\t${origH}\t${origP}\t${respH}\t${respP}\tudp\t${transId}\t${query}\t1\tC_INTERNET\t1\t${qtype}\t${rcode}\t${rcodeName}\t${answers}`;
  });

  const dnsLog = `${dnsHeader}\n${dnsLines.join("\n")}\n#close ${new Date().toISOString()}`;

  // 3. http.log
  const httpHeader = [
    "#separator \\x09",
    "#set_separator ,",
    "#empty_field (empty)",
    "#unset_field -",
    "#fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p method host uri version user_agent status_code status_msg",
    "#types time string addr port addr port string string string string string count string"
  ].join("\n");

  const httpLines = httpTransactions.map((tx, i) => {
    const ts = (new Date(tx.request?.timestamp || 0).getTime() / 1000).toFixed(6);
    const uid = `H${crypto.randomBytes(6).toString("hex")}`;
    const [origH, origP] = (tx.client || "0.0.0.0:0").split(":");
    const [respH, respP] = (tx.server || "0.0.0.0:80").split(":");
    const req = tx.request || {};
    const resp = tx.response || {};
    const method = req.method || "GET";
    const host = req.headers?.host || "-";
    const uri = req.uri || "/";
    const ua = req.headers?.["user-agent"] || "-";
    const status = resp.statusCode || 200;
    const msg = resp.statusText || "OK";
    return `${ts}\t${uid}\t${origH}\t${origP}\t${respH}\t${respP}\t${method}\t${host}\t${uri}\t1.1\t${ua}\t${status}\t${msg}`;
  });

  const httpLog = `${httpHeader}\n${httpLines.join("\n")}\n#close ${new Date().toISOString()}`;

  return {
    connLog,
    dnsLog,
    httpLog,
    "conn.log": connLog,
    "dns.log": dnsLog,
    "http.log": httpLog
  };
}
