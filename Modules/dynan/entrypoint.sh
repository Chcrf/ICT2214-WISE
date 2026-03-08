#!/bin/bash
# ============================================================================
# entrypoint.sh
#
# Container entry point for DYNAN.
# 1. Starts PCAP capture (dumpcap) in the background
# 2. Runs the Playwright analysis script
# 3. Stops capture and merges TLS keys into the PCAP
# ============================================================================

set -euo pipefail

OUTPUT_DIR="/output"
mkdir -p "$OUTPUT_DIR"

# ── TLS decryption: Chromium will write pre-master secrets here ─────────
export SSLKEYLOGFILE="/tmp/sslkeys.log"

# ── Start packet capture ──────────────────────────────────────────────────
# dumpcap (lightweight Wireshark capture tool) captures all interfaces.
# We capture in the background and save PID for clean shutdown.
dumpcap -i any -w "$OUTPUT_DIR/capture.pcap" -q &
DUMPCAP_PID=$!

# Give dumpcap a moment to bind
sleep 1

# ── Run the Playwright analysis ──────────────────────────────────────────
node run_analysis.js || true  # don't fail the container if analysis errors

# ── Stop packet capture ──────────────────────────────────────────────────
kill "$DUMPCAP_PID" 2>/dev/null || true
wait "$DUMPCAP_PID" 2>/dev/null || true

# ── Merge TLS keys into PCAP for decryption ──────────────────────────────
# editcap --inject-secrets creates a pcapng with embedded TLS session keys,
# allowing Wireshark to decrypt TLS traffic without the keylog file.
if [ -f "$SSLKEYLOGFILE" ] && [ -s "$SSLKEYLOGFILE" ]; then
  if command -v editcap &>/dev/null; then
    editcap --inject-secrets "tls,$SSLKEYLOGFILE" \
      "$OUTPUT_DIR/capture.pcap" \
      "$OUTPUT_DIR/capture_decrypted.pcapng" 2>/dev/null || true
  fi
  # Also copy the raw keylog file for manual use
  cp "$SSLKEYLOGFILE" "$OUTPUT_DIR/sslkeys.log"
fi

echo "[entrypoint] Analysis finished. Output: $OUTPUT_DIR"
