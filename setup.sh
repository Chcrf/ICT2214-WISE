#!/usr/bin/env bash
# Installs dependencies and builds WISE artifacts.
# Usage: ./setup.sh

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

info() { printf '%s\n' "[WISE] $*"; }
warn() { printf '%s\n' "[WISE] $*" >&2; }
need_cmd() { command -v "$1" >/dev/null 2>&1; }

info "Starting setup from ${ROOT}"
cd "${ROOT}"

if ! need_cmd python3; then
    warn "python3 not found. Install Python 3.12+ and retry."
    exit 1
fi

if [ ! -d "${ROOT}/virtualenv" ]; then
    info "Creating python virtualenv..."
    python3 -m venv "${ROOT}/virtualenv"
fi

# shellcheck disable=SC1091
source "${ROOT}/virtualenv/bin/activate"

info "Installing python requirements..."
python3 -m pip install -r "${ROOT}/requirements.txt"

info "Initializing database..."
python3 -c "from backend.database import init_database; init_database()"

if need_cmd docker; then
    DYNAN_IMAGE_TAG="${DYNAN_IMAGE_TAG:-dynan}"
    YARAGEN_IMAGE_TAG="${YARAGEN_IMAGE:-yaragen:latest}"

    info "Building dynan image..."
    (cd "${ROOT}/Modules/dynan" && docker build -t "${DYNAN_IMAGE_TAG}" .)

    if [ -d "${ROOT}/Modules/yaragen" ]; then
        info "Building yaragen image..."
        (cd "${ROOT}/Modules/yaragen" && docker build -t "${YARAGEN_IMAGE_TAG}" .)
    fi
else
    warn "docker not found; skipping docker image builds."
fi

if need_cmd npm; then
    info "Installing frontend dependencies..."
    (cd "${ROOT}/frontend" && npm install)

    info "Building frontend..."
    (cd "${ROOT}/frontend" && npm run build)
else
    warn "npm not found; skipping frontend install/build."
fi

info "Setup complete. Keys/providers are not configured by this script."
