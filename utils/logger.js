/**
 * Production-grade structured JSON logger for packet-chef-mcp.
 * Emits strictly to stderr to preserve stdout exclusively for MCP JSON-RPC framing.
 */
export const Logger = {
  log(level, event, metadata = {}) {
    const entry = {
      timestamp: new Date().toISOString(),
      level: level.toUpperCase(),
      event,
      pid: process.pid,
      ...metadata
    };
    process.stderr.write(JSON.stringify(entry) + "\n");
  },

  info(event, metadata) {
    this.log("info", event, metadata);
  },

  warn(event, metadata) {
    this.log("warn", event, metadata);
  },

  error(event, metadata) {
    this.log("error", event, metadata);
  }
};
