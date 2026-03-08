# ==========================================================================
# Dockerfile — DYNAN: Unified WASM Dynamic Analysis
#
# Single container with:
#   • Node.js + Playwright (Chromium)    — WASM hooking, tracing, CDP
#   • Wasabi (doehyunbaek/wasabi)        — binary instrumentation
#   • tshark / dumpcap / editcap         — PCAP capture + TLS decryption
#
# Build:  docker build -t dynan .
# Run:    docker run --rm -e TARGET_URL=https://example.com -v ./output:/output dynan
# ==========================================================================

# Stage 1: Main dynan (Node.js + Playwright + Wasabi)
FROM node:20-bookworm

# ── System dependencies ──────────────────────────────────────────────────
# Chromium libs + Rust toolchain (for Wasabi) + Wireshark (tshark/dumpcap/editcap)
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        # Chromium headless dependencies
        libnss3 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 \
        libxkbcommon0 libxcomposite1 libxdamage1 libxrandr2 libgbm1 \
        libpango-1.0-0 libcairo2 libasound2 libxshmfence1 \
        # Wasabi build/runtime dependencies
        git curl ca-certificates build-essential pkg-config clang cmake \
        rustc cargo \
        # Network capture + TLS decryption
        tshark \
    && rm -rf /var/lib/apt/lists/*

# Install Wasabi CLI from doehyunbaek/wasabi (candidate branch)
RUN git clone --depth=1 --single-branch --branch candidate https://github.com/doehyunbaek/wasabi.git /tmp/wasabi && \
    cargo install --path /tmp/wasabi/crates/wasabi --locked --root /usr/local && \
    rm -rf /tmp/wasabi

# Allow dumpcap to capture without root (needed in some Docker setups)
RUN setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap || true

WORKDIR /app

# ── Node.js dependencies ────────────────────────────────────────────────
COPY package.json ./
RUN npm install --production

# ── Install Playwright Chromium + system deps ───────────────────────────
RUN npx playwright install chromium --with-deps

# ── Copy application code ───────────────────────────────────────────────
COPY run_analysis.js ./
COPY instrument.js   ./
COPY entrypoint.sh   ./
RUN chmod +x entrypoint.sh


# ── Output volume ───────────────────────────────────────────────────────
# The orchestrator bind-mounts a host directory here.
VOLUME ["/output"]

ENTRYPOINT ["./entrypoint.sh"]
