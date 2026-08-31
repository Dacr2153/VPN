# VPNForge gRPC API Reference

All RPCs are defined in `proto/vpnd.proto` and served over a Unix domain socket at `/run/vpnd/control.sock`.

The service is `VpndService`. Use `grpcurl` or any gRPC client to interact.

---

## Connection Management

### `ConnectVpn`

Start a VPN connection using a saved profile.

**Request** `ConnectRequest`
| Field | Type | Description |
|-------|------|-------------|
| `profile_name` | `string` | Name of the profile to connect |

**Response** `ConnectResponse`
| Field | Type | Description |
|-------|------|-------------|
| `session_id` | `string` | UUID of the new session |
| `virtual_ip` | `string` | Assigned virtual IP (e.g. `10.0.0.2`) |
| `error` | `string` | Error message (empty on success) |

---

### `Disconnect`

Disconnect the active VPN session.

**Request** `DisconnectRequest` (empty)

**Response** `DisconnectResponse`
| Field | Type | Description |
|-------|------|-------------|
| `success` | `bool` | True if disconnected |
| `error` | `string` | Error message |

---

### `GetStatus`

Get current connection status.

**Request** `Empty`

**Response** `StatusResponse`
| Field | Type | Description |
|-------|------|-------------|
| `connected` | `bool` | Whether a session is active |
| `profile_name` | `string` | Active profile name |
| `virtual_ip` | `string` | VPN virtual IP |
| `server_ip` | `string` | VPN server IP |
| `protocol` | `string` | `wireguard`, `openvpn`, or `ipsec` |
| `uptime_seconds` | `int64` | Seconds connected |

---

## Session Management

### `GetSessions`

List all active sessions (server mode).

**Request** `Empty`

**Response** `SessionsResponse`
| Field | Type | Description |
|-------|------|-------------|
| `sessions` | `repeated Session` | List of active sessions |

**`Session` message**
| Field | Type | Description |
|-------|------|-------------|
| `id` | `string` | Session UUID |
| `peer_id` | `string` | Peer public key (WireGuard) or cert CN |
| `virtual_ip` | `string` | Peer's virtual IP |
| `real_ip` | `string` | Peer's real source IP |
| `protocol` | `string` | Protocol in use |
| `connected_since` | `int64` | Unix timestamp of connection |
| `rx_bytes` | `int64` | Bytes received from peer |
| `tx_bytes` | `int64` | Bytes sent to peer |
| `latency_ms` | `double` | Estimated latency in ms |
| `username` | `string` | Authenticated username |
| `geo_country` | `string` | Peer's country code (GeoIP lookup) |

---

### `KickSession`

Forcefully terminate a session.

**Request** `SessionIdRequest`
| Field | Type | Description |
|-------|------|-------------|
| `id` | `string` | Session UUID to kick |

**Response** `KickResponse`
| Field | Type | Description |
|-------|------|-------------|
| `success` | `bool` | True if session was terminated |
| `error` | `string` | Error message |

---

## Security Controls

### `SetKillSwitch`

Enable or disable the network kill switch.

**Request** `KillSwitchRequest`
| Field | Type | Description |
|-------|------|-------------|
| `enabled` | `bool` | True to enable, false to disable |
| `server_ip` | `string` | VPN server IP (required when enabling) |
| `server_port` | `uint32` | VPN server port (required when enabling) |
| `protocol` | `string` | `tcp` or `udp` |

**Response** `KillSwitchResponse`
| Field | Type | Description |
|-------|------|-------------|
| `success` | `bool` | Whether the operation succeeded |
| `backend` | `string` | Firewall backend used (`nftables` or `iptables`) |
| `error` | `string` | Error message |

---

## Profile Management

### `ListProfiles`

**Request** `Empty`

**Response** `ProfilesResponse`
| Field | Type | Description |
|-------|------|-------------|
| `profiles` | `repeated ProfileInfo` | List of saved profiles |

**`ProfileInfo` message**
| Field | Type | Description |
|-------|------|-------------|
| `name` | `string` | Profile name |
| `server` | `string` | Server hostname/IP |
| `protocol` | `string` | VPN protocol |
| `created_at` | `int64` | Creation timestamp |

---

### `ImportProfile`

Import a profile from .ovpn or WireGuard .conf bytes.

**Request** `ImportRequest`
| Field | Type | Description |
|-------|------|-------------|
| `name` | `string` | Name for the new profile |
| `data` | `bytes` | Raw file contents |
| `format` | `string` | `ovpn` or `wireguard` |

**Response** `ImportResponse`
| Field | Type | Description |
|-------|------|-------------|
| `success` | `bool` | True if import succeeded |
| `profile_id` | `string` | Assigned profile ID |
| `error` | `string` | Error message |

---

## Metrics & Health

### `GetSystemHealth`

**Request** `Empty`

**Response** `SystemHealthResponse`
| Field | Type | Description |
|-------|------|-------------|
| `cpu_percent` | `float` | CPU utilization 0-100 |
| `memory_used_bytes` | `int64` | RAM in use |
| `memory_total_bytes` | `int64` | Total RAM |
| `rx_bytes_per_sec` | `int64` | Current download rate |
| `tx_bytes_per_sec` | `int64` | Current upload rate |
| `active_sessions` | `int32` | Number of active sessions |
| `uptime_seconds` | `int64` | Daemon uptime in seconds |
| `load_avg_1m` | `float` | 1-minute load average |
| `version` | `string` | Daemon version string |

---

### `StreamSystemHealth`

Server-streaming RPC — emits health updates at regular intervals.

**Request** `Empty`

**Response** `stream SystemHealthResponse`

---

## Quality Testing

### `RunPingTest`

**Request** `PingTestRequest`
| Field | Type | Description |
|-------|------|-------------|
| `target` | `string` | Hostname or IP to ping |
| `count` | `uint32` | Number of ping packets |

**Response** `PingTestResponse`
| Field | Type | Description |
|-------|------|-------------|
| `rtt_ms` | `double` | Round-trip time in ms |
| `jitter_ms` | `double` | Jitter in ms |
| `loss_percent` | `double` | Packet loss percentage |

---

### `RunDnsLeakTest`

**Request** `Empty`

**Response** `DnsLeakTestResponse`
| Field | Type | Description |
|-------|------|-------------|
| `leaked` | `bool` | True if DNS queries are leaking outside VPN |
| `resolvers` | `repeated string` | DNS servers that responded |
| `vpn_resolver` | `string` | Expected VPN resolver |

---

## Alert Management

### `GetAlerts`

**Request** `AlertFilter`
| Field | Type | Description |
|-------|------|-------------|
| `min_severity` | `string` | Minimum severity: `low`, `medium`, `high`, `critical` |
| `limit` | `uint32` | Max alerts to return (default 100) |

**Response** `AlertsResponse`
| Field | Type | Description |
|-------|------|-------------|
| `alerts` | `repeated Alert` | List of alerts |

**`Alert` message**
| Field | Type | Description |
|-------|------|-------------|
| `id` | `string` | Alert UUID |
| `severity` | `string` | `low`, `medium`, `high`, `critical` |
| `message` | `string` | Human-readable alert text |
| `timestamp_ms` | `int64` | Alert timestamp (Unix ms) |

---

## Example Usage

### grpcurl (command line)

```bash
# Get status
grpcurl -plaintext -unix /run/vpnd/control.sock VpndService/GetStatus

# Connect to a profile
grpcurl -plaintext -unix /run/vpnd/control.sock \
  -d '{"profile_name": "my-wg-server"}' \
  VpndService/ConnectVpn

# Enable kill switch
grpcurl -plaintext -unix /run/vpnd/control.sock \
  -d '{"enabled": true, "server_ip": "1.2.3.4", "server_port": 51820, "protocol": "udp"}' \
  VpndService/SetKillSwitch
```

### Python (grpcio)

```python
import grpc
from vpnd_pb2_grpc import VpndServiceStub
import vpnd_pb2

channel = grpc.insecure_channel("unix:///run/vpnd/control.sock")
stub = VpndServiceStub(channel)

status = stub.GetStatus(vpnd_pb2.Empty())
print(f"Connected: {status.connected}, IP: {status.virtual_ip}")
```
