/**
 * packet-chef-mcp - TCP Stream Reassembler
 * Robust, zero-native-dependency TCP stream reconstruction engine.
 * Handles out-of-order segments, sequence gaps, retransmission deduplication,
 * overlapping segment trimming, and strict memory safety bounds.
 */

const MAX_PENDING_SEGMENTS = 256;
const MAX_STREAM_BYTES = 10 * 1024 * 1024; // 10MB per stream direction
const MAX_STREAMS = 1000;
const MAX_SEEN_CACHE = 2048;
export const MAX_GLOBAL_STREAM_BYTES = 32 * 1024 * 1024; // 32MB global ceiling for entire stream pool

/**
 * RFC 1982 32-bit sequence number signed comparison.
 * Returns negative if a < b, positive if a > b, 0 if equal.
 */
function seqDiff(a, b) {
  return (a - b) | 0;
}

/**
 * Unidirectional TCP stream segment processor.
 */
class DirectionReassembler {
  constructor() {
    this.segments = [];          // Pending out-of-order segments: [{ seqNum, payload, endSeq }]
    this.nextExpectedSeq = null;  // Next expected byte sequence number
    this.reassembled = Buffer.alloc(0);
    this.seen = new Set();        // Set of "seq:len" for fast retransmission dedup
    this.packetCount = 0;
    this.byteCount = 0;
    this.retransmissions = 0;
    this.outOfOrderSegments = 0;
    this.hasSYN = false;
    this.hasFIN = false;
    this.isTruncated = false;
  }

  addSegment(seqNum, payload, flags = {}) {
    this.packetCount++;
    const payloadLen = payload ? payload.length : 0;
    this.byteCount += payloadLen;

    if (flags.SYN) {
      if (!this.hasSYN) {
        this.hasSYN = true;
        // In TCP, SYN consumes 1 sequence number
        this.nextExpectedSeq = ((seqNum + 1) >>> 0);
        if (payloadLen === 0) return;
        seqNum = this.nextExpectedSeq;
      } else {
        // Duplicate or retransmitted SYN on active stream: ignore to prevent sequence desync
        this.retransmissions++;
        return;
      }
    }

    if (flags.FIN) {
      this.hasFIN = true;
    }

    if (!payload || payloadLen === 0) {
      return;
    }

    // Mid-stream capture: first packet seen without SYN
    if (this.nextExpectedSeq === null) {
      this.nextExpectedSeq = seqNum >>> 0;
    }

    const endSeq = ((seqNum + payloadLen) >>> 0);
    const seenKey = `${seqNum}:${payloadLen}`;

    // 1. Exact retransmission deduplication
    if (this.seen.has(seenKey)) {
      this.retransmissions++;
      return;
    }
    if (this.seen.size < MAX_SEEN_CACHE) {
      this.seen.add(seenKey);
    }

    // 2. Fully acknowledged / past data
    if (seqDiff(endSeq, this.nextExpectedSeq) <= 0) {
      this.retransmissions++;
      return;
    }

    // 3. In-order arrival: seqNum <= nextExpectedSeq and endSeq > nextExpectedSeq
    if (seqDiff(seqNum, this.nextExpectedSeq) <= 0) {
      let dataToAppend = payload;
      if (seqDiff(seqNum, this.nextExpectedSeq) < 0) {
        // Trim overlapping prefix already assembled
        const overlap = (this.nextExpectedSeq - seqNum) >>> 0;
        dataToAppend = payload.subarray(overlap);
      }

      this._appendReassembled(dataToAppend);
      this.nextExpectedSeq = endSeq;

      // Drain any contiguous segments now unlocked in the out-of-order buffer
      this._drainBuffered();
      return;
    }

    // 4. Out-of-order segment: seqNum > nextExpectedSeq
    this.outOfOrderSegments++;
    this._insertBuffered({ seqNum, payload, endSeq });

    // 5. Gap safety: prevent stalled buffers if dropped packets never arrive
    if (this.segments.length > MAX_PENDING_SEGMENTS) {
      // Force-flush: skip the unreceived gap and advance to the earliest buffered segment
      const earliest = this.segments.shift();
      this._appendReassembled(earliest.payload);
      this.nextExpectedSeq = earliest.endSeq;
      this._drainBuffered();
    }
  }

  _appendReassembled(chunk) {
    if (!chunk || chunk.length === 0) return;

    if (this.reassembled.length + chunk.length > MAX_STREAM_BYTES) {
      const allowed = MAX_STREAM_BYTES - this.reassembled.length;
      if (allowed > 0) {
        this.reassembled = Buffer.concat([this.reassembled, chunk.subarray(0, allowed)]);
      }
      this.isTruncated = true;
      return;
    }

    this.reassembled = Buffer.concat([this.reassembled, chunk]);
  }

  _insertBuffered(segment) {
    // Insert sorted by seqNum
    let idx = 0;
    while (idx < this.segments.length && seqDiff(this.segments[idx].seqNum, segment.seqNum) < 0) {
      idx++;
    }
    this.segments.splice(idx, 0, segment);
  }

  _drainBuffered() {
    while (this.segments.length > 0) {
      const seg = this.segments[0];
      const diff = seqDiff(seg.seqNum, this.nextExpectedSeq);

      if (diff > 0) {
        // Next expected sequence not yet reached (still a hole)
        break;
      }

      this.segments.shift();

      if (seqDiff(seg.endSeq, this.nextExpectedSeq) <= 0) {
        // Completely covered by current reassembled data
        continue;
      }

      let chunk = seg.payload;
      if (diff < 0) {
        // Partially overlapping segment; trim prefix
        const overlap = (this.nextExpectedSeq - seg.seqNum) >>> 0;
        chunk = seg.payload.subarray(overlap);
      }

      this._appendReassembled(chunk);
      this.nextExpectedSeq = seg.endSeq;
    }
  }
}

/**
 * Bidirectional TCP Conversation Stream
 */
export class TCPConversationStream {
  constructor(id, clientIP, clientPort, serverIP, serverPort, startTime) {
    this.id = id;
    this.clientIP = clientIP;
    this.clientPort = clientPort;
    this.serverIP = serverIP;
    this.serverPort = serverPort;
    this.startTime = startTime;
    this.endTime = startTime;
    this.state = "INIT"; // INIT, SYN_SENT, ESTABLISHED, FIN_WAIT, CLOSED, RESET

    this.client = new DirectionReassembler();
    this.server = new DirectionReassembler();
    this.lastActiveTime = startTime;
  }

  addPacket(srcIP, srcPort, tcpHeader, payload, timestampISO) {
    this.endTime = timestampISO;
    this.lastActiveTime = Date.now();

    const isClient = (srcIP === this.clientIP && srcPort === this.clientPort);
    const dir = isClient ? this.client : this.server;
    const flags = tcpHeader.flags || {};

    if (flags.RST) {
      this.state = "RESET";
    }

    dir.addSegment(tcpHeader.seqNum, payload, flags);

    // State machine transitions
    if (this.state !== "RESET") {
      if (this.client.hasSYN && !this.server.hasSYN) {
        this.state = "SYN_SENT";
      } else if (this.client.hasSYN && this.server.hasSYN) {
        this.state = "ESTABLISHED";
      }

      if (this.client.hasFIN || this.server.hasFIN) {
        if (this.client.hasFIN && this.server.hasFIN) {
          this.state = "CLOSED";
        } else {
          this.state = "FIN_WAIT";
        }
      }
    }
  }

  getSummary() {
    return {
      id: this.id,
      client: `${this.clientIP}:${this.clientPort}`,
      server: `${this.serverIP}:${this.serverPort}`,
      srcIP: this.clientIP,
      srcPort: this.clientPort,
      dstIP: this.serverIP,
      dstPort: this.serverPort,
      state: this.state,
      startTime: this.startTime,
      endTime: this.endTime,
      clientData: this.client.reassembled,
      serverData: this.server.reassembled,
      clientBytes: this.client.byteCount,
      serverBytes: this.server.byteCount,
      totalBytes: this.client.byteCount + this.server.byteCount,
      clientPackets: this.client.packetCount,
      serverPackets: this.server.packetCount,
      totalPackets: this.client.packetCount + this.server.packetCount,
      retransmissions: this.client.retransmissions + this.server.retransmissions,
      outOfOrderSegments: this.client.outOfOrderSegments + this.server.outOfOrderSegments,
      isTruncated: this.client.isTruncated || this.server.isTruncated
    };
  }
}

/**
 * Main TCP Reassembly Manager
 */
export class TCPReassembler {
  constructor() {
    this.streams = new Map(); // id -> TCPConversationStream
  }

  /**
   * Generates a canonical bidirectional stream key.
   */
  static getStreamKey(ipA, portA, ipB, portB) {
    const endA = `${ipA}:${portA}`;
    const endB = `${ipB}:${portB}`;
    return endA < endB ? `${endA}<->${endB}` : `${endB}<->${endA}`;
  }

  /**
   * Feed a parsed TCP packet into the reassembler.
   * @param {string} srcIP 
   * @param {string} dstIP 
   * @param {object} tcpHeader Decoded TCP header from decodeTCP
   * @param {Buffer} payload TCP payload buffer
   * @param {string} timestampISO ISO timestamp string
   */
  addPacket(srcIP, dstIP, tcpHeader, payload, timestampISO = new Date().toISOString()) {
    if (!tcpHeader || typeof tcpHeader.srcPort !== "number" || typeof tcpHeader.dstPort !== "number") {
      return;
    }

    const key = TCPReassembler.getStreamKey(srcIP, tcpHeader.srcPort, dstIP, tcpHeader.dstPort);
    let stream = this.streams.get(key);

    if (!stream) {
      // LRU eviction if stream table exceeds capacity
      if (this.streams.size >= MAX_STREAMS) {
        this._evictOldestStream();
      }

      // First packet seen determines client vs server orientation (or SYN packet)
      stream = new TCPConversationStream(
        key,
        srcIP,
        tcpHeader.srcPort,
        dstIP,
        tcpHeader.dstPort,
        timestampISO
      );
      this.streams.set(key, stream);
    }

    stream.addPacket(srcIP, tcpHeader.srcPort, tcpHeader, payload, timestampISO);

    // Enforce global buffer memory ceiling (32MB) across all active streams
    this._enforceGlobalMemoryCeiling();
  }

  _getTotalBufferedBytes() {
    let total = 0;
    for (const s of this.streams.values()) {
      total += (s.client.reassembled.length + s.server.reassembled.length);
    }
    return total;
  }

  _enforceGlobalMemoryCeiling() {
    let total = this._getTotalBufferedBytes();
    if (total <= MAX_GLOBAL_STREAM_BYTES) return;

    // Evict oldest or closed streams until total memory is below 24MB (75% threshold)
    const target = (MAX_GLOBAL_STREAM_BYTES * 0.75) | 0;
    while (this.streams.size > 0 && total > target) {
      this._evictOldestStream();
      total = this._getTotalBufferedBytes();
    }
  }

  _evictOldestStream() {
    let oldestKey = null;
    let oldestTime = Infinity;

    // Prioritize evicting CLOSED or RESET streams
    for (const [k, s] of this.streams.entries()) {
      if (s.state === "CLOSED" || s.state === "RESET") {
        this.streams.delete(k);
        return;
      }
      if (s.lastActiveTime < oldestTime) {
        oldestTime = s.lastActiveTime;
        oldestKey = k;
      }
    }

    if (oldestKey) {
      this.streams.delete(oldestKey);
    }
  }

  /**
   * Returns all reassembled stream summaries.
   * @returns {Array<object>}
   */
  getStreams() {
    return Array.from(this.streams.values()).map((s) => s.getSummary());
  }

  /**
   * Returns a specific stream by endpoints.
   */
  getStream(ipA, portA, ipB, portB) {
    const key = TCPReassembler.getStreamKey(ipA, portA, ipB, portB);
    const stream = this.streams.get(key);
    return stream ? stream.getSummary() : null;
  }
}
