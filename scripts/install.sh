#!/usr/bin/env bash
# scripts/install.sh
# Install VPNForge binaries, configs, systemd unit, and set capabilities.
# Must be run as root.
set -euo pipefail

PREFIX="${PREFIX:-/usr/local}"
SYSCONFDIR="${SYSCONFDIR:-/etc}"
SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

BOLD='\033[1m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
RESET='\033[0m'

info()    { echo -e "  \033[0;36m→\033[0m $*"; }
success() { echo -e "  \033[0;32m✓\033[0m $*"; }

[[ $EUID -eq 0 ]] || { echo "Run as root: sudo $0"; exit 1; }

cd "$ROOT_DIR"

echo -e "\n${BOLD}VPNForge Installer${RESET}\n"

# Build release binaries if not already present
if [[ ! -f target/release/vpnd || ! -f target/release/vpnctl ]]; then
    info "Building release binaries…"
    cargo build --workspace --release
fi

# ── Binaries ─────────────────────────────────────────────────────────────────
info "Installing binaries…"
install -Dm755 target/release/vpnd   "$PREFIX/sbin/vpnd"
install -Dm755 target/release/vpnctl "$PREFIX/bin/vpnctl"

# Drop root privileges for vpnd using capabilities
if command -v setcap &>/dev/null; then
    setcap 'cap_net_admin,cap_net_bind_service,cap_net_raw+eip' "$PREFIX/sbin/vpnd"
    success "Capabilities set on vpnd"
fi

success "vpnd   → $PREFIX/sbin/vpnd"
success "vpnctl → $PREFIX/bin/vpnctl"

# ── Configuration ─────────────────────────────────────────────────────────────
info "Creating config directories…"
install -dm750 "$SYSCONFDIR/vpnforge/profiles"
install -dm755 "/var/log/vpnforge"

if [[ ! -f "$SYSCONFDIR/vpnforge/server.toml" ]]; then
    install -Dm640 configs/server.example.toml "$SYSCONFDIR/vpnforge/server.toml"
    success "Created $SYSCONFDIR/vpnforge/server.toml (edit before starting)"
fi

if [[ ! -f "$SYSCONFDIR/vpnforge/client.toml" ]]; then
    install -Dm640 configs/client.example.toml "$SYSCONFDIR/vpnforge/client.toml"
    success "Created $SYSCONFDIR/vpnforge/client.toml"
fi

# ── System user ───────────────────────────────────────────────────────────────
if ! id vpnd &>/dev/null; then
    info "Creating system user 'vpnd'…"
    useradd --system --no-create-home --shell /sbin/nologin vpnd
    success "User 'vpnd' created"
fi
chown vpnd:vpnd /var/log/vpnforge
chown root:vpnd "$SYSCONFDIR/vpnforge"
chmod 750 "$SYSCONFDIR/vpnforge"

# ── systemd ───────────────────────────────────────────────────────────────────
if command -v systemctl &>/dev/null; then
    info "Installing systemd service…"
    install -Dm644 scripts/vpnd.service "$SYSTEMD_DIR/vpnd.service"
    systemctl daemon-reload
    success "systemd unit installed: vpnd.service"
fi

# ── Shell completions (system-wide) ───────────────────────────────────────────
if [[ -d /usr/share/bash-completion/completions ]]; then
    "$PREFIX/bin/vpnctl" completion bash > /usr/share/bash-completion/completions/vpnctl
    success "Bash completion installed"
fi
if [[ -d /usr/share/fish/vendor_completions.d ]]; then
    "$PREFIX/bin/vpnctl" completion fish > /usr/share/fish/vendor_completions.d/vpnctl.fish
    success "Fish completion installed"
fi

echo -e "\n${GREEN}${BOLD}Installation complete!${RESET}\n"
echo -e "  1. Edit config:  ${CYAN}$SYSCONFDIR/vpnforge/server.toml${RESET}"
echo -e "  2. Start daemon: ${CYAN}systemctl enable --now vpnd${RESET}"
echo -e "  3. Add profile:  ${CYAN}vpnctl profile add${RESET}"
echo -e "  4. Connect:      ${CYAN}vpnctl connect <profile>${RESET}"
echo ""
