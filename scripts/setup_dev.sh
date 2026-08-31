#!/usr/bin/env bash
# scripts/setup_dev.sh
# Install development dependencies on Arch Linux / Ubuntu
set -euo pipefail

BOLD='\033[1m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
RED='\033[0;31m'
RESET='\033[0m'

info()    { echo -e "  ${CYAN}→${RESET} $*"; }
success() { echo -e "  ${GREEN}✓${RESET} $*"; }
error()   { echo -e "  ${RED}✗${RESET} $*"; exit 1; }

echo -e "\n${BOLD}VPNForge — Dev Environment Setup${RESET}\n"

# ── Detect distro ────────────────────────────────────────────────────────────
if command -v pacman &>/dev/null; then
    DISTRO="arch"
elif command -v apt-get &>/dev/null; then
    DISTRO="debian"
else
    error "Unsupported distro. Install manually: protobuf, wireguard-tools, openssl, nftables"
fi

# ── System packages ──────────────────────────────────────────────────────────
info "Installing system packages…"

if [[ $DISTRO == "arch" ]]; then
    sudo pacman -Sy --needed --noconfirm \
        protobuf \
        wireguard-tools \
        openssl \
        nftables \
        iproute2 \
        iputils \
        2>/dev/null && success "System packages installed"
elif [[ $DISTRO == "debian" ]]; then
    sudo apt-get update -qq
    sudo apt-get install -y --no-install-recommends \
        protobuf-compiler \
        wireguard-tools \
        openssl \
        nftables \
        iproute2 \
        iputils-ping \
        2>/dev/null && success "System packages installed"
fi

# ── Rust toolchain ───────────────────────────────────────────────────────────
if ! command -v rustup &>/dev/null; then
    info "Installing Rust toolchain…"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path
    source "$HOME/.cargo/env"
    success "Rust installed"
fi

info "Updating Rust to stable…"
rustup update stable 2>/dev/null
success "Rust $(rustc --version)"

# ── Cargo tools ─────────────────────────────────────────────────────────────
for tool in cargo-audit cargo-watch; do
    if ! command -v ${tool/-/_} &>/dev/null 2>&1; then
        info "Installing $tool…"
        cargo install "$tool" --quiet
        success "$tool installed"
    fi
done

# ── /dev/net/tun ─────────────────────────────────────────────────────────────
if [[ ! -e /dev/net/tun ]]; then
    info "Creating /dev/net/tun…"
    sudo mkdir -p /dev/net
    sudo mknod /dev/net/tun c 10 200
    sudo chmod 666 /dev/net/tun
    success "/dev/net/tun created"
else
    success "/dev/net/tun present"
fi

# ── Directory structure ──────────────────────────────────────────────────────
info "Creating config directories…"
sudo mkdir -p /etc/vpnforge/profiles /var/log/vpnforge /run/vpnd
sudo chmod 750 /etc/vpnforge /run/vpnd

echo -e "\n${GREEN}${BOLD}Dev environment ready!${RESET}\n"
echo -e "  Build:  ${CYAN}make build${RESET}"
echo -e "  Run:    ${CYAN}make dev-run${RESET}  (in another terminal)"
echo -e "  Status: ${CYAN}make dev-status${RESET}"
echo ""
