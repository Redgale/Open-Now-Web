# ─── Stage 1: Build the React frontend ───────────────────────────────────────
FROM node:20-alpine AS builder

WORKDIR /app

# Install deps first for better layer caching
COPY package.json package-lock.json ./
RUN npm ci

# Copy everything and build
COPY . .
RUN npm run build

# Verify the index.html is at the expected location
RUN test -f dist/index.html || (echo "ERROR: dist/index.html not found. Build output:" && find dist -name "*.html" && exit 1)

# ─── Stage 2: Production Node.js server ──────────────────────────────────────
FROM node:20-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production

# Copy package files and install production dependencies only
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

# Copy the built frontend
COPY --from=builder /app/dist ./dist

# Copy the BFF server
COPY server.js ./

EXPOSE 8080

# Health check — Koyeb uses this to decide when the container is ready
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:8080/ | grep -q "OpenNOW" || exit 1

CMD ["node", "server.js"]
