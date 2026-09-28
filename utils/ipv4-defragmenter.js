/**
 * packet-chef-mcp - Layer 3 IPv4 Defragmentation Engine (RFC 791)
 * Pure Node.js Buffer reassembly for fragmented IPv4 datagrams.
 * Handles out-of-order slices, overlapping fragments, 64KB size enforcement,
 * LRU eviction, and session expiration.
 */

export class IPv4Defragmenter {
  /**
   * @param {object} [options]
   * @param {number} [options.timeoutMs=30000] - Sliding session expiration in ms (RFC 791 standard: 30s)
   * @param {number} [options.maxDatagramSize=65535] - Maximum allowable reassembled IPv4 payload
   * @param {number} [options.maxActiveReassemblies=1000] - Hard ceiling on concurrent fragment contexts
   */
  constructor(options = {}) {
    this.timeoutMs = options.timeoutMs || 30000;
    this.maxDatagramSize = options.maxDatagramSize || 65535;
    this.maxActiveReassemblies = options.maxActiveReassemblies || 1000;
    this.sessions = new Map(); // key -> Session
  }

  /**
   * Generates unique 4-tuple key for IPv4 fragment tracking.
   * @param {object} ip - Decoded IPv4 header object
   * @returns {string}
   */
  _getKey(ip) {
    return `${ip.srcIP}:${ip.dstIP}:${ip.protocol}:${ip.identification}`;
  }

  /**
   * Prunes expired fragment reassembly sessions.
   * @param {number} currentTimestampMs
   */
  _cleanupExpired(currentTimestampMs) {
    if (!currentTimestampMs) return;
    for (const [key, session] of this.sessions.entries()) {
      if (currentTimestampMs - session.lastSeenAt > this.timeoutMs) {
        this.sessions.delete(key);
      }
    }
  }

  /**
   * Processes an incoming IPv4 packet fragment.
   * @param {object} ip - Decoded IPv4 header object from decodeIPv4
   * @param {Buffer} fragmentData - Payload bytes contained in this IP fragment
   * @param {number} [timestampMs=0] - Packet arrival timestamp in epoch ms
   * @returns {object|null} { complete: boolean, reassembledPayload?: Buffer, firstFragmentIp?: object, isPending?: boolean, error?: string }
   */
  addFragment(ip, fragmentData, timestampMs = 0) {
    if (!ip || !ip.isFragmented) {
      return null;
    }

    if (timestampMs) {
      this._cleanupExpired(timestampMs);
    }

    const key = this._getKey(ip);
    let session = this.sessions.get(key);

    if (!session) {
      // LRU eviction if capacity ceiling reached
      if (this.sessions.size >= this.maxActiveReassemblies) {
        const oldestKey = this.sessions.keys().next().value;
        this.sessions.delete(oldestKey);
      }

      session = {
        key,
        srcIP: ip.srcIP,
        dstIP: ip.dstIP,
        protocol: ip.protocol,
        identification: ip.identification,
        createdAt: timestampMs || Date.now(),
        lastSeenAt: timestampMs || Date.now(),
        slices: [], // Array of { offset, data, end }
        totalExpectedLength: null,
        firstFragmentIp: null
      };
      this.sessions.set(key, session);
    }

    session.lastSeenAt = timestampMs || Date.now();

    // Preserve the first fragment's IPv4 header (contains the original L4 header context)
    if (ip.fragmentOffset === 0) {
      session.firstFragmentIp = ip;
    }

    const offset = ip.fragmentOffset;
    const len = fragmentData ? fragmentData.length : 0;
    const end = offset + len;

    // Defense-in-depth: Enforce RFC 791 maximum IPv4 datagram size (65535 bytes)
    if (end > this.maxDatagramSize) {
      this.sessions.delete(key);
      return { complete: false, isPending: false, error: "MAX_DATAGRAM_EXCEEDED" };
    }

    // MF (More Fragments) flag: if false, this fragment marks the end of the datagram
    const isLast = !ip.flags?.MF;
    if (isLast) {
      session.totalExpectedLength = end;
    }

    // Insert slice and keep slices sorted by offset
    session.slices.push({ offset, data: fragmentData || Buffer.alloc(0), end });
    session.slices.sort((a, b) => a.offset - b.offset);

    // Evaluate whether all bytes from offset 0 to totalExpectedLength are contiguous
    if (session.totalExpectedLength !== null) {
      let currentOffset = 0;
      for (const slice of session.slices) {
        if (slice.offset > currentOffset) {
          // Gap detected: awaiting missing intermediate fragment
          return { complete: false, isPending: true };
        }
        if (slice.end > currentOffset) {
          currentOffset = slice.end;
        }
      }

      if (currentOffset >= session.totalExpectedLength) {
        // Complete datagram reassembled!
        const reassembled = Buffer.alloc(session.totalExpectedLength);
        for (const slice of session.slices) {
          slice.data.copy(reassembled, slice.offset);
        }

        const firstIp = session.firstFragmentIp || ip;
        this.sessions.delete(key);

        return {
          complete: true,
          reassembledPayload: reassembled,
          firstFragmentIp: firstIp,
          totalLength: reassembled.length
        };
      }
    }

    return { complete: false, isPending: true };
  }

  /**
   * Returns current active reassembly sessions count.
   * @returns {number}
   */
  get activeSessionsCount() {
    return this.sessions.size;
  }

  /**
   * Resets all internal reassembly states.
   */
  reset() {
    this.sessions.clear();
  }
}
