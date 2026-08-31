# VPNForge

Production-grade, multi-protocol VPN daemon and client suite built in Rust with Python GUIs.

| Component | Status |
|-----------|--------|
| WireGuard | Full (boringtun userspace — Cloudflare) |
| OpenVPN | Partial (TLS 1.3 control + data channel) |
| IPsec IKEv2 | Partial (strongSwan VICI integration) |

**Stack:** Rust (daemon + CLI) · Python/PySide6 (GUI clients) · gRPC over Unix socket
**Security:** ChaCha20-Poly1305 · AES-256-GCM · Kill switch · DNS leak prevention · Ed25519 profile signing · Argon2id at-rest encryption

---

## Table of Contents

- [Architecture](#architecture)
- [Features](#features)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [CLI Reference](#cli-reference)
- [gRPC API](#grpc-api)
- [Security](#security)
- [Testing](#testing)
- [Makefile Targets](#makefile-targets)
- [Systemd Service](#systemd-service)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                         User Space                               │
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────────────┐  │
│  │ vpnforge-    │  │ vpnforge-    │  │      vpnctl CLI       │  │
│  │ client.py    │  │ admin.py     │  │     (Rust / Clap)     │  │
│  │ (PySide6)    │  │ (PySide6)    │  │                       │  │
│  └──────┬───────┘  └──────┬───────┘  └───────────┬───────────┘  │
│         └─────────────────┴──────────────────────┘              │
│                           │  gRPC over Unix socket               │
│                    /run/vpnd/control.sock                         │
│                           │                                      │
│  ┌────────────────────────▼───────────────────────────────────┐  │
│  │                      vpnd daemon                           │  │
│  │                                                            │  │
│  │  ┌────────────┐  ┌────────────┐  ┌──────────────────────┐  │  │
│  │  │   gRPC     │  │  Session   │  │    Kill Switch       │  │  │
│  │  │  Server    │  │  Manager   │  │  (nftables/iptables) │  │  │
│  │  └────────────┘  └────────────┘  └──────────────────────┘  │  │
│  │                                                            │  │
│  │  ┌────────────┐  ┌────────────┐  ┌──────────────────────┐  │  │
│  │  │ WireGuard  │  │  OpenVPN   │  │      IPsec IKEv2     │  │  │
│  │  │ (boringtun)│  │  (rustls)  │  │   (strongSwan VICI)  │  │  │
│  │  └────────────┘  └────────────┘  └──────────────────────┘  │  │
│  │                                                            │  │
│  │  ┌────────────┐  ┌────────────┐  ┌──────────────────────┐  │  │
│  │  │   Crypto   │  │  Routing   │  │     DNS Guard        │  │  │
│  │  │   (ring)   │  │ (netlink)  │  │  + DoT/DoH Proxy     │  │  │
│  │  └────────────┘  └────────────┘  └──────────────────────┘  │  │
│  └────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
                            │
                  ┌─────────▼──────────┐
                  │    Linux Kernel     │
                  │  TUN/TAP device     │
                  │  Netfilter/nftables │
                  │  Network stack      │
                  └────────────────────┘
```

All control communication uses gRPC over a Unix domain socket (`/run/vpnd/control.sock`). The socket is owned by `root:root` with mode `0600`, providing OS-level access control without network exposure.

---

## Features

- **Multi-protocol support** — WireGuard (full), OpenVPN (TLS 1.3), IPsec IKEv2
- **WireGuard key management** — Generate, rotate PSK + static keypairs, Argon2id+AES-GCM sealed private keys
- **Kill switch** — Default-deny firewall policy via nftables (preferred) or iptables
- **DNS leak prevention** — VPN-only resolver enforcement via resolv.conf management
- **Encrypted DNS** — Built-in DoT/DoH proxy (Cloudflare, Quad9) with DNSSEC validation
- **Split tunneling** — Route only specific CIDRs through the VPN
- **Profile signing** — Ed25519 signatures prevent unauthorized profile substitution
- **Process hardening** — `prctl(PR_SET_DUMPABLE, 0)`, `mlockall`, `PR_SET_NO_NEW_PRIVS`
- **Auto-reconnect** — Exponential backoff with jitter
- **Idle session timeout** — Automatic disconnect after configurable inactivity period
- **IP leak test** — STUN-based public IP verification
- **Live monitoring** — Streaming bandwidth, latency, and packet loss metrics
- **Admin panel** — Real-time session management, system health gauges, topology view, alerts
- **Shell completions** — Bash, Fish, Zsh via `vpnctl completion`

---

## Project Structure

```
vpn_v/
├── Cargo.toml                  # Workspace manifest
├── Makefile                    # Build, test, install targets
├── proto/
│   └── vpnd.proto              # gRPC service definition (427 lines)
├── vpnd/                       # Daemon crate
│   ├── Cargo.toml
│   ├── build.rs                # tonic-build proto compilation
│   ├── src/
│   │   ├── main.rs             # Entry point, process hardening, tunnel orchestration
│   │   ├── lib.rs              # Module re-exports
│   │   ├── config/
│   │   │   ├── mod.rs          # TOML config load/save
│   │   │   └── schema.rs       # Strongly-typed config structs (VpndConfig, Profile, etc.)
│   │   ├── ipc/
│   │   │   ├── grpc_server.rs  # gRPC VpndService implementation (~1600 lines)
│   │   │   └── peer_cred.rs    # SO_PEERCRED IPC authentication
│   │   ├── tunnel/
│   │   │   ├── tuntap.rs       # TUN interface creation (ioctl TUNSETIFF)
│   │   │   ├── wireguard.rs    # WireGuard tunnel (boringtun Noise session)
│   │   │   ├── openvpn.rs      # OpenVPN TLS 1.3 framing
│   │   │   └── ipsec.rs        # IPsec IKEv2 (strongSwan VICI)
│   │   ├── crypto/
│   │   │   ├── aes_gcm.rs      # AES-256-GCM AEAD (ring)
│   │   │   ├── chacha20.rs     # ChaCha20-Poly1305 (ring)
│   │   │   ├── key_exchange.rs # Curve25519 DH + WireGuard keypair generation
│   │   │   ├── profile_seal.rs # Argon2id+AES-256-GCM at-rest encryption
│   │   │   └── profile_signing.rs # Ed25519 sign/verify profiles
│   │   ├── session/
│   │   │   ├── manager.rs      # Session lifecycle (DashMap<Uuid, Session>)
│   │   │   └── reconnect.rs    # Exponential backoff + jitter
│   │   ├── routing/
│   │   │   ├── netlink.rs      # Route management (rtnetlink)
│   │   │   └── split_tunnel.rs # Split-tunnel CIDR policy
│   │   ├── network/
│   │   │   ├── dns_guard.rs    # /etc/resolv.conf management
│   │   │   ├── dns_resolver.rs # DoT/DoH encrypted DNS proxy
│   │   │   └── nat_traversal.rs# STUN NAT discovery (RFC 5389)
│   │   ├── kill_switch/
│   │   │   └── firewall.rs     # nftables/iptables default-deny rules
│   │   ├── metrics/
│   │   │   ├── collector.rs    # Metrics aggregation + streaming
│   │   │   └── system.rs       # /proc-based CPU, memory, load, uptime
│   │   └── utils/
│   │       └── redact.rs       # Log redaction for sensitive data
│   └── tests/
│       ├── crypto.rs           # AES-GCM, ChaCha20, key exchange tests
│       ├── sessions.rs         # Session manager lifecycle tests
│       └── reconnect.rs        # Reconnect policy delay/cap tests
├── vpnctl/                     # CLI crate
│   ├── Cargo.toml
│   ├── build.rs
│   └── src/
│       └── main.rs             # 14-subcommand CLI (~1350 lines)
├── client-gui/                 # Python desktop client
│   ├── pyproject.toml
│   └── vpnforge_client.py      # PySide6 GUI (~880 lines)
├── admin-gui/                  # Python admin panel
│   ├── pyproject.toml
│   └── vpnforge_admin.py       # PySide6 admin GUI (~830 lines)
├── configs/
│   ├── server.example.toml     # Server configuration template
│   ├── client.example.toml     # Client configuration template
│   └── profile.example.toml    # WireGuard profile template
├── scripts/
│   ├── build_all.sh            # Full build (Rust + Python stubs + deps)
│   ├── install.sh              # System installer (binaries, systemd, user)
│   ├── setup_dev.sh            # Dev environment setup (Arch/Ubuntu)
│   ├── gen_proto.sh            # Python gRPC stub generation
│   ├── create_test_certs.sh    # OpenVPN test PKI generator
│   └── vpnd.service            # systemd unit file
├── tests/
│   └── wireshark/
│       ├── validate_encryption.py  # tshark-based encryption verification
│       └── check_dns_leak.py       # DNS leak detection script
└── docs/
    ├── ARCHITECTURE.md         # Component diagram + protocol details
    ├── SECURITY.md             # Threat model + crypto design
    └── API.md                  # gRPC API reference
```

---

## Prerequisites

### Rust

```bash
# Install Rust (if not present)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

- Minimum Rust version: **1.75** (edition 2021)
- Required system packages: `protobuf-compiler` (protoc), `wireguard-tools`, `openssl`, `nftables`, `iproute2`, `iputils`

### Python (GUI clients)

- Python >= 3.11
- PySide6 >= 6.6.0
- grpcio >= 1.60.0
- grpcio-tools >= 1.60.0
- protobuf >= 4.25.0
- PySide6-Charts >= 6.6.0 (client GUI)
- networkx >= 3.2 (admin GUI, optional for topology layout)

### System

- Linux (required for TUN/TAP, netlink routing, nftables)
- `/dev/net/tun` device (created by `setup_dev.sh` if missing)
- Root or `CAP_NET_ADMIN` capability for daemon operation

---

## Installation

### Quick build

```bash
bash scripts/build_all.sh
```

This compiles the Rust workspace, generates Python proto stubs, and installs Python dependencies.

### Manual build

```bash
# Build release binaries
make release
# → target/release/vpnd
# → target/release/vpnctl
```

### System install (via Makefile)

```bash
sudo make install
# Installs to /usr/local/sbin/vpnd and /usr/local/bin/vpnctl
# Creates /etc/vpnforge/, /var/log/vpnforge/, systemd service
```

### System install (via script)

```bash
sudo bash scripts/install.sh
```

The installer also:
- Creates a `vpnd` system user
- Sets `CAP_NET_ADMIN`, `CAP_NET_BIND_SERVICE`, `CAP_NET_RAW` capabilities on `vpnd`
- Installs systemd service and shell completions

### Development setup

```bash
bash scripts/setup_dev.sh    # Installs deps on Arch/Ubuntu
make build                    # Debug build
make dev-run                  # Start daemon on /tmp/vpnd.sock
make dev-status               # Check status (separate terminal)
```

---

## Configuration

### Server configuration

Copy and edit:

```bash
sudo cp configs/server.example.toml /etc/vpnforge/server.toml
sudo vim /etc/vpnforge/server.toml
```

Key sections:

| Section | Purpose |
|---------|---------|
| `[daemon]` | Socket path, daemonize, PID file, privilege drop |
| `[server.wireguard]` | Listen port, private key, subnet, MTU |
| `[server.openvpn]` | Listen port, TLS certs, cipher |
| `[server.ipsec]` | IKE port, NAT-T, auth method, certs |
| `[logging]` | Level (`trace`/`debug`/`info`/`warn`/`error`), JSON mode, log file |
| `[security]` | Profile signing key, `require_signed_profiles`, session timeout |
| `[network]` | STUN servers, privacy warning suppression |
| `[ipc]` | Allowed UIDs/GIDs, audit logging |

### Client configuration

Copy and edit:

```bash
mkdir -p ~/.config/vpnforge
cp configs/client.example.toml ~/.config/vpnforge/config.toml
```

Key sections:

| Section | Purpose |
|---------|---------|
| `[daemon]` | Socket path |
| `[client]` | Profiles directory, auto-connect |
| `[client.reconnect]` | Enabled, max attempts, delay range |
| `[client.dns]` | Encrypted DoT/DoH, DNSSEC validation, upstream servers |
| `[logging]` | Level, format, file |

### Profile configuration

Individual profiles are stored as TOML files in the profiles directory (default: `/etc/vpnforge/profiles/`). See `configs/profile.example.toml` for a WireGuard profile template.

Profiles support:
- WireGuard keys (plaintext or Argon2id+AES-GCM sealed)
- OpenVPN certificates (CA, client cert, client key)
- Kill switch, split tunneling, DNS server, IPv6 toggle
- MTU override (0 = auto-detect)

---

## Usage

### 1. Start the daemon

```bash
# Production (requires root)
sudo vpnd

# Development (no root needed for socket, but still needs CAP_NET_ADMIN for TUN)
sudo vpnd --socket /tmp/vpnd.sock --verbose
```

### 2. Generate a WireGuard keypair

```bash
vpnctl keygen
# Private key: <base64>
# Public key:  <base64>
```

### 3. Add a profile

```bash
# Interactive wizard
vpnctl profile add

# Or import from WireGuard .conf file
vpnctl profile import ~/my-vpn.conf
```

### 4. Connect

```bash
vpnctl connect my-profile
```

If the profile uses a sealed private key, you will be prompted for the unlock passphrase. For unattended setups:

```bash
echo "my-passphrase" | vpnctl connect my-profile --passphrase-stdin
```

### 5. Monitor the connection

```bash
vpnctl status         # One-shot status
vpnctl monitor        # Live streaming dashboard (Ctrl+C to exit)
```

### 6. Test for leaks

```bash
vpnctl test dns       # DNS leak test
vpnctl test ip        # IP leak test (STUN-based)
vpnctl test all       # Both
```

### 7. Rotate keys

```bash
vpnctl rotate-keys my-profile                     # Rotate PSK only
vpnctl rotate-keys my-profile --rotate-keypair    # Rotate PSK + static keypair
```

### 8. Disconnect

```bash
vpnctl disconnect
```

---

## CLI Reference

Global flags:

| Flag | Description |
|------|-------------|
| `--socket <PATH>` | Override daemon socket path (env: `VPND_SOCKET`) |
| `-j, --json` | Machine-readable JSON output |
| `-q, --quiet` | Suppress non-essential output |

Commands:

| Command | Description |
|---------|-------------|
| `connect <profile>` | Connect to a VPN profile (`-f` to force disconnect first) |
| `disconnect [profile]` | Disconnect (empty = all) |
| `status` | Show connection status |
| `monitor` | Live metrics dashboard |
| `profile list` | List saved profiles |
| `profile show <name>` | Show profile details |
| `profile add` | Interactive profile creation wizard |
| `profile import <file>` | Import `.conf` (WireGuard) or `.ovpn` (OpenVPN) |
| `profile delete <name>` | Delete a profile |
| `test dns` | DNS leak test |
| `test ip` | IP leak test |
| `test all` | Run all leak tests |
| `ping <target>` | ICMP ping through VPN tunnel |
| `routes` | Show current routing table |
| `kill-switch on` | Enable kill switch |
| `kill-switch off` | Disable kill switch |
| `kill-switch status` | Show kill switch status |
| `health` | Daemon health (CPU, memory, uptime, sessions) |
| `keygen` | Generate WireGuard keypair (offline) |
| `rotate-keys <profile>` | Rotate WireGuard keys |
| `completion <shell>` | Generate shell completions (bash/fish/zsh) |

Shell completions:

```bash
# Install for current user
make completions

# Or manually
vpnctl completion bash >> ~/.bashrc
vpnctl completion zsh  > ~/.zfunc/_vpnctl
vpnctl completion fish > ~/.config/fish/completions/vpnctl.fish
```

---

## gRPC API

All RPCs are defined in `proto/vpnd.proto` and served over a Unix domain socket.

**Transport:** gRPC over Unix socket (`/run/vpnd/control.sock`)
**TLS:** None (Unix socket provides OS-level access control)
**Authentication:** `SO_PEERCRED` (kernel-reported UID/GID/PID) + filesystem permissions

### Connection Management

| RPC | Request | Response | Description |
|-----|---------|----------|-------------|
| `ConnectVpn` | `ConnectRequest { profile_id, force, passphrase }` | `ConnectResponse { success, error, virtual_ip, server_ip, protocol }` | Start VPN connection |
| `Disconnect` | `DisconnectRequest { profile_id }` | `DisconnectResponse { success, error }` | Disconnect session |
| `GetStatus` | `Empty` | `StatusResponse { state, profile_id, virtual_ip, server_ip, protocol, ... }` | Current connection status |

### Profile Management

| RPC | Request | Response | Description |
|-----|---------|----------|-------------|
| `ListProfiles` | `Empty` | `ProfileList { profiles }` | List all profiles |
| `GetProfile` | `ProfileIdRequest { id }` | `Profile` | Get profile details |
| `SaveProfile` | `Profile` | `SaveProfileResponse { success, id, error }` | Create/update profile |
| `DeleteProfile` | `ProfileIdRequest { id }` | `DeleteProfileResponse` | Delete profile |
| `ImportProfile` | `ImportRequest { data, format, name, passphrase }` | `SaveProfileResponse` | Import .ovpn/.conf |
| `RotateProfileKeys` | `RotateKeysRequest { profile_id, rotate_static_keypair, passphrase }` | `RotateKeysResponse { new_public_key, new_preshared_key }` | Rotate WireGuard keys |

### Metrics & Diagnostics

| RPC | Request | Response | Description |
|-----|---------|----------|-------------|
| `StreamMetrics` | `Empty` | `stream MetricsUpdate` | Live bandwidth/latency metrics |
| `RunPingTest` | `PingRequest { host, count, timeout }` | `stream PingResult` | ICMP ping test |
| `RunDnsLeakTest` | `Empty` | `DnsLeakResult` | DNS leak detection |
| `RunIpLeakTest` | `Empty` | `IpLeakResult` | IP leak detection (STUN) |
| `GetRouteTable` | `Empty` | `RouteTableResponse` | Routing table |

### Security Controls

| RPC | Request | Response | Description |
|-----|---------|----------|-------------|
| `SetKillSwitch` | `KillSwitchRequest { enabled, server_ip, server_port, protocol }` | `KillSwitchResponse` | Enable/disable kill switch |
| `GetKillSwitchStatus` | `Empty` | `KillSwitchResponse` | Kill switch state |

### Admin RPCs

| RPC | Request | Response | Description |
|-----|---------|----------|-------------|
| `GetSessions` | `Empty` | `SessionList` | List active sessions |
| `KickSession` | `SessionIdRequest { id }` | `KickSessionResponse` | Terminate session |
| `GetSystemHealth` | `Empty` | `SystemHealth` | CPU, memory, uptime |
| `StreamSystemHealth` | `Empty` | `stream SystemHealth` | Real-time health metrics |
| `StreamTopology` | `Empty` | `stream TopologyUpdate` | Network topology graph |
| `GetAlerts` | `AlertFilter` | `AlertList` | System alerts |
| `AcknowledgeAlert` | `AlertIdRequest` | `AckAlertResponse` | Acknowledge alert |
| `SetServerConfig` | `ServerConfig` | `SetConfigResponse` | Update server config |
| `GetServerConfig` | `Empty` | `ServerConfig` | Read server config |

### gRPC CLI examples

```bash
# Get status
grpcurl -plaintext -unix /run/vpnd/control.sock VpndService/GetStatus

# Connect
grpcurl -plaintext -unix /run/vpnd/control.sock \
  -d '{"profile_id": "my-wg-server"}' \
  VpndService/ConnectVpn

# Enable kill switch
grpcurl -plaintext -unix /run/vpnd/control.sock \
  -d '{"enabled": true, "server_ip": "1.2.3.4", "server_port": 51820, "protocol": "udp"}' \
  VpndService/SetKillSwitch
```

### Python client example

```python
import grpc
from vpnd_pb2_grpc import VpndServiceStub
import vpnd_pb2

channel = grpc.insecure_channel("unix:///run/vpnd/control.sock")
stub = VpndServiceStub(channel)

status = stub.GetStatus(vpnd_pb2.Empty())
print(f"Connected: {status.state == 2}, IP: {status.virtual_ip}")
```

---

## Security

### Threat Model

| Threat | Mitigation |
|--------|-----------|
| Traffic interception | ChaCha20-Poly1305 / AES-256-GCM AEAD encryption |
| DNS leaks | DnsGuard + DoT/DoH proxy + kill switch |
| VPN dropout leaks | nftables/iptables default-deny firewall rules |
| Key extraction via coredump | `prctl(PR_SET_DUMPABLE, 0)` |
| Key extraction via swap | `mlockall(MCL_CURRENT \| MCL_FUTURE)` |
| Privilege escalation | `prctl(PR_SET_NO_NEW_PRIVS, 1)` |
| Replay attacks | WireGuard anti-replay counter window |
| Handshake downgrade | Noise_IKpsk2 — no cipher negotiation |
| Profile tampering | Ed25519 signatures on all profile files |
| At-rest key exposure | Argon2id + AES-256-GCM sealed private keys |
| Memory key leaks | `Zeroizing<[u8; 32]>` — zeroed on drop |

### Process hardening (applied at daemon startup)

```rust
prctl::set_dumpable(false);     // No core dumps
prctl::set_no_new_privs();      // No privilege escalation
libc::mlockall(MCL_CURRENT | MCL_FUTURE);  // Keys never swapped to disk
```

### Kill switch

When activated, applies a default-deny firewall policy:

- **nftables** (preferred): `table inet vpnforge_ks` with DROP policy + ALLOW for loopback + VPN server
- **iptables** (fallback): `iptables -P OUTPUT DROP` + allow rules

Rules persist if the VPN connection drops, preventing traffic leaks.

### Encrypted DNS

When `[client.dns].encrypted = true`, the daemon spawns a local DoT proxy (`127.0.0.53:53`) that forwards all queries through TLS-encrypted upstreams (Cloudflare, Quad9 by default). DNSSEC validation is enabled.

### IPC authentication

The Unix socket uses `SO_PEERCRED` to verify peer UID/GID at accept time. Configurable via `[ipc] allowed_uids` and `[ipc] allowed_gids`.

### Known limitations

| Issue | Severity | Status |
|-------|----------|--------|
| No seccomp filter | Medium | Planned |
| No systemd-resolved integration | Low | Planned (`resolvectl` API) |
| No user namespace isolation | Medium | Planned (`unshare(CLONE_NEWUSER)`) |
| No AppArmor/SELinux profile | Medium | Planned |
| `import_profile` for .ovpn unimplemented | Low | Partial (daemon-side parsing) |

---

## Testing

### Unit and integration tests

```bash
# All tests
make test

# Unit tests only
make test-unit

# Integration tests (requires root for TUN/TAP)
make test-integration

# With output
cargo test --package vpnd -- --nocapture
```

Test coverage:
- `vpnd/tests/crypto.rs` — AES-256-GCM round-trip, tamper detection, ChaCha20-Poly1305, key exchange, key zeroization
- `vpnd/tests/sessions.rs` — Session creation, state transitions, removal, unique IDs
- `vpnd/tests/reconnect.rs` — Delay calculation, max cap, jitter variation, exponential backoff

### Wireshark validation scripts

```bash
# Validate encryption (requires tshark + root)
sudo python3 tests/wireshark/validate_encryption.py --interface tun0 --duration 10

# DNS leak detection
sudo python3 tests/wireshark/check_dns_leak.py --vpn-resolver 10.0.0.1
```

### Code quality

```bash
make fmt     # Format with rustfmt
make lint    # Clippy lints (-D warnings)
make audit   # cargo-audit dependency scan
```

### Security audit

```bash
cargo audit
```

---

## Makefile Targets

| Target | Description |
|--------|-------------|
| `make build` | Debug build (vpnd + vpnctl) |
| `make release` | Optimized release build |
| `make test` | All unit + integration tests |
| `make test-unit` | Unit tests only |
| `make test-integration` | Integration tests (needs root) |
| `make fmt` | Format all Rust code |
| `make lint` | Clippy lints |
| `make audit` | Dependency security audit |
| `make install` | Install to `/usr/local` |
| `make uninstall` | Remove installed files |
| `make certs` | Generate test PKI (OpenVPN) |
| `make setup` | Install dev dependencies (Arch/Ubuntu) |
| `make completions` | Install shell completions |
| `make dev-run` | Start daemon in dev mode |
| `make dev-status` | Quick status check (dev socket) |
| `make proto` | Regenerate gRPC stubs |
| `make clean` | Remove build artifacts |
| `make help` | Show available targets |

---

## Systemd Service

The included `vpnd.service` unit provides:

- **Security hardening:** `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`
- **Capability bounding:** `CAP_NET_ADMIN`, `CAP_NET_BIND_SERVICE`, `CAP_NET_RAW`
- **Restart policy:** `on-failure` with 5s delay
- **Logging:** journald integration

```bash
sudo systemctl enable --now vpnd
sudo systemctl status vpnd
sudo journalctl -u vpnd -f
```

---

## Dependencies

### Rust (key crates)

| Crate | Version | Purpose |
|-------|---------|---------|
| `boringtun` | 0.6 | WireGuard userspace (Cloudflare) |
| `tonic` | 0.12 | gRPC server/client |
| `ring` | 0.17 | AES-256-GCM, ChaCha20-Poly1305, Ed25519 |
| `x25519-dalek` | 2.0.0-rc.3 | Curve25519 DH |
| `chacha20poly1305` | 0.10 | ChaCha20-Poly1305 AEAD |
| `aes-gcm` | 0.10 | AES-256-GCM AEAD |
| `argon2` | 0.5 | Argon2id KDF (RFC 9106) |
| `zeroize` | 1 | Memory zeroization |
| `hickory-resolver` | 0.24 | DoT/DoH DNS resolver |
| `rustls` | 0.23 | TLS 1.3 |
| `tun` | 0.6 | Async TUN interface |
| `rtnetlink` | 0.14 | Linux netlink routing |
| `nix` | 0.29 | Unix APIs, process hardening |
| `tokio` | 1 | Async runtime |
| `clap` | 4 | CLI argument parsing |
| `serde` / `toml` | 1 / 0.8 | Configuration serialization |

### Python

```
PySide6>=6.6.0
PySide6-Charts>=6.6.0
grpcio>=1.60.0
grpcio-tools>=1.60.0
protobuf>=4.25.0
networkx>=3.2         # admin-gui only
```

---

## Troubleshooting

### "Cannot reach daemon" error

Ensure the daemon is running:

```bash
# Production
sudo systemctl status vpnd

# Development
sudo vpnd --socket /tmp/vpnd.sock --verbose
```

### TUN device not available

```bash
sudo mkdir -p /dev/net && sudo mknod /dev/net/tun c 10 200
# Or run setup_dev.sh
```

### DNS leak detected after disconnect

The original `/etc/resolv.conf` is backed up at `/run/vpnd/resolv.conf.bak` and restored on clean disconnect. If the daemon was killed abruptly:

```bash
sudo cp /run/vpnd/resolv.conf.bak /etc/resolv.conf
```

### Kill switch stuck after disconnect

```bash
# Remove nftables rules
sudo nft delete table inet vpnforge_ks

# Or reset iptables
sudo iptables -P OUTPUT ACCEPT
sudo iptables -F OUTPUT
```

### Permission denied on socket

The daemon socket requires root or membership in the `vpnd` group:

```bash
sudo usermod -aG vpnd $USER
# Then log out and back in
```

### Memory locked (mlockall) failed

Ensure the service has `LimitMEMLOCK=infinity` or the `CAP_IPC_LOCK` capability:

```ini
# In vpnd.service [Service]
LimitMEMLOCK=infinity
```

---

## License

MIT
