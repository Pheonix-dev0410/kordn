# kordn Contain-mode sandbox image.
# Build from the repo root:  docker build -f sandbox/Dockerfile -t kordn-sandbox .
# The build context is filtered by sandbox/Dockerfile.dockerignore (allowlist).

# ---- build: compile TypeScript ----
FROM node:24-slim@sha256:55fb5f5a527ea2c5c4a95f963e48ef90aa38c7b346054fdc8ee9957a2b55d205 AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY src ./src
RUN npm run build

# ---- deps: production dependencies only ----
FROM node:24-slim@sha256:55fb5f5a527ea2c5c4a95f963e48ef90aa38c7b346054fdc8ee9957a2b55d205 AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund

# ---- runtime: no shell, no npm, non-root ----
# gcr.io/distroless/nodejs24-debian13:nonroot, pinned. ENTRYPOINT is /nodejs/bin/node.
FROM gcr.io/distroless/nodejs24-debian13:nonroot@sha256:cb606325b7ec4af55462cb0b424a53b452a5b4a894ffe841fcf1048d216fb9f8
WORKDIR /app
# Everything is root-owned and read-only to the agent, even if the rootfs were writable.
COPY --from=deps /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./
COPY sandbox/agent.mjs ./sandbox/agent.mjs
ENV NODE_ENV=production
USER 65532:65532
# The agent is the MCP client and starts `kordn --guardian /run/kordn.sock` over stdio.
# Replace it by passing another script as the command.
CMD ["/app/sandbox/agent.mjs"]
