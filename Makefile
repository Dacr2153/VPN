.PHONY: all build release test clean install uninstall fmt lint proto certs help

# ─────────────────────────────────────────────
#  Variables
# ─────────────────────────────────────────────
PREFIX       ?= /usr/local
SYSCONFDIR   ?= /etc
SYSTEMD_DIR  ?= /etc/systemd/system
CARGO        := cargo
PROTOC       := protoc

BOLD  := \033[1m
RESET := \033[0m
GREEN := \033[0;32m
CYAN  := \033[0;36m
RED   := \033[0;31m

# ─────────────────────────────────────────────
#  Default target
# ─────────────────────────────────────────────
all: build

help: ## Show this help message
	@echo ""
	@echo "  $(BOLD)VPNForge Build System$(RESET)"
	@echo ""
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*##/ { printf "  $(CYAN)%-18s$(RESET) %s\n", $$1, $$2 }' $(MAKEFILE_LIST)
	@echo ""

# ─────────────────────────────────────────────
#  Build
# ─────────────────────────────────────────────
build: ## Build debug binaries (vpnd + vpnctl)
	@echo "$(BOLD)Building…$(RESET)"
	$(CARGO) build --workspace

release: ## Build optimized release binaries
	@echo "$(BOLD)Building release…$(RESET)"
	$(CARGO) build --workspace --release
	@echo ""
	@echo "  $(GREEN)✓$(RESET) vpnd   → target/release/vpnd"
	@echo "  $(GREEN)✓$(RESET) vpnctl → target/release/vpnctl"

proto: ## Regenerate gRPC stubs from proto/vpnd.proto
	@command -v $(PROTOC) >/dev/null 2>&1 || { echo "$(RED)protoc not found. Install: pacman -S protobuf$(RESET)"; exit 1; }
	@echo "$(BOLD)Regenerating protobuf stubs…$(RESET)"
	$(CARGO) build --workspace  # build.rs triggers tonic-build
	@echo "$(GREEN)✓ Done$(RESET)"

# ─────────────────────────────────────────────
#  Tests
# ─────────────────────────────────────────────
test: ## Run all unit + integration tests
	$(CARGO) test --workspace

test-unit: ## Run unit tests only
	$(CARGO) test --workspace --lib

test-integration: ## Run integration tests (requires root for TUN/TAP)
	$(CARGO) test --workspace --test '*' -- --nocapture

# ─────────────────────────────────────────────
#  Code quality
# ─────────────────────────────────────────────
fmt: ## Format all code with rustfmt
	$(CARGO) fmt --all

lint: ## Run clippy lints
	$(CARGO) clippy --workspace --all-targets -- -D warnings

audit: ## Security audit of dependencies
	@command -v cargo-audit >/dev/null 2>&1 || cargo install cargo-audit
	cargo audit

# ─────────────────────────────────────────────
#  Installation
# ─────────────────────────────────────────────
install: release ## Install vpnd + vpnctl to PREFIX (default /usr/local)
	@echo "$(BOLD)Installing to $(PREFIX)…$(RESET)"

	# Binaries
	install -Dm755 target/release/vpnd   $(DESTDIR)$(PREFIX)/sbin/vpnd
	install -Dm755 target/release/vpnctl $(DESTDIR)$(PREFIX)/bin/vpnctl

	# Config directories
	install -dm755 $(DESTDIR)$(SYSCONFDIR)/vpnforge/profiles
	install -dm755 $(DESTDIR)/var/log/vpnforge
	install -dm755 $(DESTDIR)/run/vpnd

	# Example configs (don't overwrite existing)
	[ -f $(DESTDIR)$(SYSCONFDIR)/vpnforge/server.toml ] || \
		install -Dm644 configs/server.example.toml $(DESTDIR)$(SYSCONFDIR)/vpnforge/server.toml
	[ -f $(DESTDIR)$(SYSCONFDIR)/vpnforge/client.toml ] || \
		install -Dm644 configs/client.example.toml $(DESTDIR)$(SYSCONFDIR)/vpnforge/client.toml

	# systemd service
	install -Dm644 scripts/vpnd.service $(DESTDIR)$(SYSTEMD_DIR)/vpnd.service

	# Man pages (if generated)
	# install -Dm644 docs/vpnctl.1 $(PREFIX)/share/man/man1/vpnctl.1

	@echo "$(GREEN)✓ Installed$(RESET)"
	@echo ""
	@echo "  Next steps:"
	@echo "  1. Edit $(SYSCONFDIR)/vpnforge/server.toml"
	@echo "  2. Run: $(CYAN)sudo systemctl enable --now vpnd$(RESET)"
	@echo "  3. Add a profile: $(CYAN)vpnctl profile add$(RESET)"
	@echo "  4. Connect: $(CYAN)vpnctl connect <profile>$(RESET)"

uninstall: ## Remove installed files
	rm -f $(PREFIX)/sbin/vpnd $(PREFIX)/bin/vpnctl
	rm -f $(SYSTEMD_DIR)/vpnd.service
	@echo "$(GREEN)✓ Uninstalled$(RESET)"

# ─────────────────────────────────────────────
#  Development helpers
# ─────────────────────────────────────────────
certs: ## Generate development TLS certificates
	@bash scripts/create_test_certs.sh

setup: ## Install development dependencies (Arch Linux)
	@bash scripts/setup_dev.sh

completions: release ## Install shell completions for current user
	@mkdir -p ~/.local/share/bash-completion/completions
	@mkdir -p ~/.config/fish/completions
	@mkdir -p ~/.zfunc
	./target/release/vpnctl completion bash > ~/.local/share/bash-completion/completions/vpnctl
	./target/release/vpnctl completion fish > ~/.config/fish/completions/vpnctl.fish
	./target/release/vpnctl completion zsh  > ~/.zfunc/_vpnctl
	@echo "$(GREEN)✓ Shell completions installed$(RESET)"
	@echo "  Restart your shell or run: source ~/.bashrc"

dev-run: build ## Start daemon in dev mode (writes socket to /tmp/vpnd.sock)
	@echo "$(BOLD)Starting vpnd in dev mode…$(RESET)"
	sudo ./target/debug/vpnd --socket /tmp/vpnd.sock --verbose

dev-status: ## Quick status check (dev socket)
	VPND_SOCKET=/tmp/vpnd.sock ./target/debug/vpnctl status

# ─────────────────────────────────────────────
#  Clean
# ─────────────────────────────────────────────
clean: ## Remove build artifacts
	$(CARGO) clean
