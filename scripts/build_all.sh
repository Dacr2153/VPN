#!/usr/bin/env bash
# scripts/build_all.sh — Full build: Rust workspace + Python proto stubs + GUI deps
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

log() { echo -e "\033[1;36m==> $*\033[0m"; }

# ── 1. Rust workspace ──────────────────────────────────────────────────────────
log "Building Rust workspace..."
cd "$REPO_ROOT"
cargo build --release --workspace
log "Rust build complete."

# ── 2. Proto stubs ────────────────────────────────────────────────────────────
log "Generating Python proto stubs..."
bash "$SCRIPT_DIR/gen_proto.sh"

# ── 3. Python GUI dependencies ────────────────────────────────────────────────
log "Installing Python dependencies..."
pip3 install --quiet PySide6 grpcio grpcio-tools protobuf
log "Python deps installed."

# ── 4. Smoke test ────────────────────────────────────────────────────────────
log "Running Rust tests..."
cargo test --workspace 2>&1 | tail -20

log "Build complete!  Binaries:"
echo "  $REPO_ROOT/target/release/vpnd"
echo "  $REPO_ROOT/target/release/vpnctl"
echo ""
echo "Run daemon: sudo $REPO_ROOT/target/release/vpnd --socket /tmp/vpnd.sock"
echo "Run CLI:    $REPO_ROOT/target/release/vpnctl status"
echo "Run GUI:    python3 $REPO_ROOT/client-gui/vpnforge_client.py"
echo "Run admin:  python3 $REPO_ROOT/admin-gui/vpnforge_admin.py"
