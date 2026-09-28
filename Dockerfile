# Multi-stage minimal & hardened production Dockerfile
FROM node:20-alpine AS builder

WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev

FROM node:20-alpine AS runner

WORKDIR /app
ENV NODE_ENV=production
ENV PORT=8080

# Run container as unprivileged non-root user (node:node, UID 1000)
USER node

# Copy dependencies and application source with appropriate ownership
COPY --chown=node:node --from=builder /app/node_modules ./node_modules
COPY --chown=node:node package*.json ./
COPY --chown=node:node server.js ./
COPY --chown=node:node bin ./bin
COPY --chown=node:node utils ./utils
COPY --chown=node:node .well-known ./.well-known
COPY --chown=node:node README.md LICENSE ./

EXPOSE 8080

# Built-in Docker healthcheck against local endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD node -e "import('http').then(http => http.get('http://localhost:' + (process.env.PORT || 8080) + '/health', res => process.exit(res.statusCode === 200 ? 0 : 1)).on('error', () => process.exit(1)));"

CMD ["node", "server.js", "--http"]
