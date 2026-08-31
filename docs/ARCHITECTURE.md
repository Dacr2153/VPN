# VPNForge Architecture

## Overview

VPNForge is a production-grade, multi-protocol VPN daemon and client suite built in Rust with Python GUIs. It supports WireGuard, OpenVPN, and IPsec protocols through a unified gRPC control API.

```
┌──────────────────────────────────────────────────────────────┐
│                        User Space                            │
│                                                              │
│  ┌─────────────┐   ┌───────────────┐   ┌─────────────────┐  │
│  │ vpnforge-   │   │  vpnforge-    │   │    vpnctl CLI   │  │
│  │ client.py   │   │  admin.py     │   │   (Rust/Clap)   │  │
│  │ (PySide6)   │   │  (PySide6)    │   │                 │  │
│  └──────┬──────┘   └───────┬───────┘   └────────┬────────┘  │
│         │                  │                    │           │
│         └──────────────────┴────────────────────┘           │
│                            │  gRPC over Unix socket          │
│                     /run/vpnd/control.sock                   │
│                            │                                 │
│  ┌─────────────────────────▼──────────────────────────────┐  │
│  │                     vpnd daemon                        │  │
│  │                                                        │  │
│  │  ┌───────────┐  ┌───────────┐  ┌────────────────────┐  │  │
│  │  │  gRPC     │  │  Session  │  │    Kill Switch     │  │  │
│  │  │  Server   │  │  Manager  │  │  (nftables/iptables)│  │  │
│  │  └───────────┘  └───────────┘  └────────────────────┘  │  │
│  │                                                        │  │
│  │  ┌───────────┐  ┌───────────┐  ┌────────────────────┐  │  │
│  │  │ WireGuard │  │  OpenVPN  │  │      IPsec         │  │  │
│  │  │(boringtun)│  │  (rustls) │  │   (strongSwan)     │  │  │
│  │  └───────────┘  └───────────┘  └────────────────────┘  │  │
│  │                                                        │  │
│  │  ┌───────────┐  ┌───────────┐  ┌────────────────────┐  │  │
│  │  │   Crypto  │  │  Routing  │  │   DNS Guard        │  │  │
│  │  │  (ring)   │  │ (netlink) │  │  (DNS leak prev.)  │  │  │
│  │  └───────────┘  └───────────┘  └────────────────────┘  │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
                            │
                  ┌─────────▼──────────┐
                  │    Linux Kernel     │
                  │                    │
                  │  TUN/TAP device    │
                  │  Netfilter/nftables │
                  │  Network stack     │
                  └────────────────────┘
```

## Components

### `vpnd` — Daemon

The main daemon process. Runs as root (or with `CAP_NET_ADMIN`).

| Module | Purpose | Implementation |
|--------|---------|---------------|
| `ipc/grpc_server.rs` | Control API | tonic 0.12 over Unix socket |
| `tunnel/wireguard.rs` | WireGuard protocol | boringtun 0.6 (Cloudflare) |
| `tunnel/openvpn.rs` | OpenVPN TLS mode | rustls 0.23 + custom framing |
| `tunnel/ipsec.rs` | IPsec IKEv2 | strongSwan VICI protocol |
| `tunnel/tuntap.rs` | TUN interface | ioctl(TUNSETIFF) via nix |
| `routing/netlink.rs` | Route management | rtnetlink 0.14 |
| `session/manager.rs` | Session lifecycle | DashMap<Uuid, Session> |
| `session/reconnect.rs` | Auto-reconnect | Exponential backoff + jitter |
| `crypto/aes_gcm.rs` | AES-256-GCM AEAD | ring 0.17 |
| `crypto/chacha20.rs` | ChaCha20-Poly1305 | ring 0.17 |
| `crypto/key_exchange.rs` | Curve25519 DH | x25519-dalek |
| `network/dns_guard.rs` | DNS leak prevention | resolv.conf management |
| `network/nat_traversal.rs` | STUN NAT traversal | RFC 5389 client |
| `kill_switch/firewall.rs` | Kill switch | nftables (nft) or iptables |
| `metrics/system.rs` | System metrics | /proc/stat, /proc/meminfo |

### `vpnctl` — CLI

14-subcommand CLI tool for daemon interaction:

```
vpnctl connect <profile>     # Connect using a saved profile
vpnctl disconnect            # Disconnect current session
vpnctl status                # Show connection status
vpnctl profiles list         # List saved profiles
vpnctl profiles add          # Add a new profile
vpnctl profiles remove <id>  # Remove a profile
vpnctl kill-switch enable    # Enable kill switch
vpnctl kill-switch disable   # Disable kill switch
vpnctl ping-test             # Test connection quality
vpnctl dns-leak-test         # Check for DNS leaks
vpnctl sessions list         # List all sessions
vpnctl sessions kick <id>    # Kick a session
vpnctl logs                  # Stream daemon logs
vpnctl import <file>         # Import .ovpn or .conf profile
```

### Python GUIs

**`client-gui/vpnforge_client.py`** — End-user desktop client

- PySide6 with dark theme
- System tray integration with colored status icon
- Tab-based UI: Connect, Metrics, Logs
- Live bandwidth and latency display
- Kill switch toggle

**`admin-gui/vpnforge_admin.py`** — Server administration panel

- Session management table with kick capability
- Real-time CPU/memory/load gauges (streamed from daemon)
- Alert feed with severity color coding
- Audit log viewer with filtering

## Data Flow

### Connection establishment (WireGuard)

```
1. User selects profile → gRPC ConnectVpn(profile_name)
2. vpnd loads profile config (server IP, port, keys)
3. WireGuardTunnel::connect() called
4. boringtun creates WireGuard interface (via TUN fd)
5. Noise_IKpsk2 handshake → session keys established
6. RouteManager adds default route via tun0
7. DnsGuard writes /etc/resolv.conf → VPN DNS only
8. SessionManager stores session state
9. StreamSystemHealth begins emitting metrics
```

### Kill switch activation

```
1. Client calls SetKillSwitch(enabled=true, server_ip, port, protocol)
2. vpnd validates server_ip (parse::<IpAddr>())
3. KillSwitch::enable() called:
   a. Detects nftables or iptables
   b. Applies ALLOW rules for: loopback + server_ip:port
   c. Applies DROP rule for all other outbound traffic
4. If VPN disconnects, rules remain → no traffic leaks
5. SetKillSwitch(enabled=false) → KillSwitch::disable() removes all rules
```

## Protocol Details

### WireGuard (default)

- **Crypto**: Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s
- **Keys**: X25519 keypairs (32 bytes), stored in `Zeroizing<[u8;32]>`
- **Transport**: UDP, default port 51820
- **MTU**: 1420 (accounts for WireGuard + IP headers)

### OpenVPN (TLS mode)

- **Control channel**: TLS 1.3 via rustls
- **Cipher**: AES-256-GCM or ChaCha20-Poly1305
- **Auth**: Certificate-based (CA + client cert) or username/password
- **Ports**: TCP/UDP 1194 (configurable)

### IPsec (IKEv2)

- **Key exchange**: strongSwan charon daemon via VICI protocol
- **Auth**: PSK or certificate-based
- **ESP**: AES-256-GCM
- **PFS**: DH group 20 (NIST P-384)

## gRPC API Transport

All control communication uses:
- **Transport**: Unix domain socket `/run/vpnd/control.sock`
- **Protocol**: gRPC / HTTP/2
- **TLS**: None (Unix socket provides OS-level access control)
- **Auth**: File permissions on socket (owner = root, mode 0600)

The socket is accessible only to processes running as root or with the `vpnd` group.
