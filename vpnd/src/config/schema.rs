// vpnd/src/config/schema.rs
// Strongly-typed configuration structs — never raw Strings for IPs

use anyhow::{bail, Result};
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

// ─────────────────────────────────────────────
//  Top-level config
// ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VpndConfig {
    #[serde(default)]
    pub daemon: DaemonConfig,

    #[serde(default)]
    pub server: Option<ServerConfig>,

    #[serde(default)]
    pub client: Option<ClientConfig>,

    #[serde(default)]
    pub logging: LoggingConfig,

    #[serde(default)]
    pub ipc: IpcConfig,

    #[serde(default)]
    pub security: SecurityConfig,

    #[serde(default)]
    pub network: NetworkConfig,
}

impl VpndConfig {
    /// Validate the configuration for logical consistency
    pub fn validate(&self) -> Result<()> {
        if self.server.is_none() && self.client.is_none() {
            bail!("Config must have either [server] or [client] section");
        }
        if let Some(ref s) = self.server {
            s.validate()?;
        }
        if let Some(ref c) = self.client {
            c.validate()?;
        }
        Ok(())
    }

    pub fn is_server_mode(&self) -> bool {
        self.server.is_some()
    }
}

// ─────────────────────────────────────────────
//  Daemon settings
// ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    /// Path to the Unix domain socket for IPC
    pub socket_path: PathBuf,

    /// Run as daemon (fork and detach)
    #[serde(default)]
    pub daemonize: bool,

    /// PID file path
    pub pid_file: Option<PathBuf>,

    /// Drop privileges to this user after startup
    pub run_as_user: Option<String>,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            socket_path: PathBuf::from(crate::IPC_SOCKET_PATH),
            daemonize: false,
            pid_file: Some(PathBuf::from("/run/vpnd/vpnd.pid")),
            run_as_user: Some("vpnd".into()),
        }
    }
}

// ─────────────────────────────────────────────
//  IPC authentication settings
// ─────────────────────────────────────────────

/// Configuration for the gRPC-over-Unix-socket IPC layer.
///
/// Authentication is performed via `SO_PEERCRED`: the kernel itself reports
/// the peer's UID/GID/PID at socket-accept time, so this is a defense-in-depth
/// mechanism on top of the socket file's filesystem permissions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcConfig {
    /// UIDs allowed to connect to the daemon's control socket.
    /// An empty list means "allow only root and the daemon's own UID".
    /// `0` (root) is always implicitly allowed.
    #[serde(default)]
    pub allowed_uids: Vec<u32>,

    /// GIDs allowed to connect (e.g. a `vpn` group). Empty = no GID-based access.
    #[serde(default)]
    pub allowed_gids: Vec<u32>,

    /// When true, every accepted IPC connection is logged with the peer's
    /// UID/GID/PID. Useful for audit trails. Defaults to true.
    #[serde(default = "default_true")]
    pub audit_connections: bool,
}

impl Default for IpcConfig {
    fn default() -> Self {
        Self {
            allowed_uids: Vec::new(),
            allowed_gids: Vec::new(),
            audit_connections: true,
        }
    }
}

fn default_true() -> bool { true }

// ─────────────────────────────────────────────
//  Security settings (signing, profile policy)
// ─────────────────────────────────────────────

/// Daemon-wide security policies for at-rest data.
///
/// `require_signed_profiles` is the most important field: when true (the
/// default) the daemon refuses to load a profile whose Ed25519 signature
/// does not verify against the persistent signing key.  This is what
/// prevents an attacker who gains *write* access to `/etc/vpnforge/profiles/`
/// from silently substituting a peer endpoint pointing to their own server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// PKCS#8 file holding the daemon's Ed25519 profile-signing keypair.
    /// Mode `0600`, owned by the daemon user.  Generated on first run.
    #[serde(default = "default_signing_key_path")]
    pub signing_key_path: PathBuf,

    /// Reject any profile that is unsigned or whose signature does not verify.
    #[serde(default = "default_true")]
    pub require_signed_profiles: bool,

    /// When true (default), every saved profile is automatically signed
    /// before being written to disk.
    #[serde(default = "default_true")]
    pub auto_sign_on_save: bool,

    /// Idle session timeout in seconds. Sessions with no traffic for this
    /// long are torn down to prevent forgotten always-on connections from
    /// silently leaking metadata. Set to `0` to disable.
    /// Default: 8 hours (28800 s).
    #[serde(default = "default_session_timeout")]
    pub session_timeout_secs: u64,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            signing_key_path: default_signing_key_path(),
            require_signed_profiles: true,
            auto_sign_on_save: true,
            session_timeout_secs: default_session_timeout(),
        }
    }
}

fn default_session_timeout() -> u64 { 28_800 }

fn default_signing_key_path() -> PathBuf {
    PathBuf::from("/var/lib/vpnforge/signing.key")
}

// ─────────────────────────────────────────────
//  Network: STUN, MTU and other low-level knobs
// ─────────────────────────────────────────────

/// Knobs that affect outbound metadata exposure.
///
/// **Privacy note**: The default STUN servers (Google, Cloudflare) are run
/// by major US-based providers and will see your IP every time NAT
/// discovery runs. For higher anonymity requirements, point `stun_servers`
/// at servers operated by an organization you trust (or your own).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Ordered list of STUN servers (host:port) used for NAT discovery.
    /// When empty, the daemon's compiled-in defaults are used and a
    /// privacy warning is emitted at startup.
    #[serde(default)]
    pub stun_servers: Vec<String>,

    /// Suppress the warning that fires when default STUN servers are used.
    /// Only set this to true after you have *consciously* accepted the
    /// metadata exposure described above.
    #[serde(default)]
    pub suppress_stun_privacy_warning: bool,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            stun_servers: Vec::new(),
            suppress_stun_privacy_warning: false,
        }
    }
}

impl NetworkConfig {
    /// Returns the configured STUN server list, falling back to the
    /// compiled-in defaults. The boolean is true when defaults were used.
    pub fn effective_stun_servers(&self) -> (Vec<String>, bool) {
        if self.stun_servers.is_empty() {
            (
                crate::network::nat_traversal::DEFAULT_STUN_SERVERS
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
                true,
            )
        } else {
            (self.stun_servers.clone(), false)
        }
    }
}

// ─────────────────────────────────────────────
//  Server config
// ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Bind address for the VPN server
    pub listen_addr: IpAddr,

    /// Virtual IP subnet assigned to clients
    pub subnet: IpNetwork,

    /// Server-side virtual IP (e.g. 10.8.0.1)
    pub server_ip: Ipv4Addr,

    /// DNS server pushed to clients
    pub dns: IpAddr,

    /// Maximum concurrent clients
    #[serde(default = "default_max_clients")]
    pub max_clients: usize,

    /// NAT the VPN traffic through this interface (e.g. eth0)
    pub nat_interface: Option<String>,

    /// WireGuard server config
    pub wireguard: Option<WireGuardServerConfig>,

    /// OpenVPN server config
    pub openvpn: Option<OpenVpnServerConfig>,

    /// IPsec server config
    pub ipsec: Option<IpsecServerConfig>,
}

impl ServerConfig {
    pub fn validate(&self) -> Result<()> {
        if !self.subnet.contains(IpAddr::V4(self.server_ip)) {
            bail!(
                "server_ip {} is not within subnet {}",
                self.server_ip,
                self.subnet
            );
        }
        if self.wireguard.is_none() && self.openvpn.is_none() && self.ipsec.is_none() {
            bail!("Server config must enable at least one protocol");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireGuardServerConfig {
    pub port: u16,
    /// Base64-encoded private key
    pub private_key: String,
    /// Optional pre-shared key
    pub preshared_key: Option<String>,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    /// Allowed peers (public_key → allowed IPs)
    #[serde(default)]
    pub peers: Vec<WireGuardPeerConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireGuardPeerConfig {
    pub public_key: String,
    pub preshared_key: Option<String>,
    pub allowed_ips: Vec<IpNetwork>,
    pub endpoint: Option<SocketAddr>,
    pub persistent_keepalive: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenVpnServerConfig {
    pub port: u16,
    pub protocol: TransportProtocol,
    pub ca_cert_path: PathBuf,
    pub server_cert_path: PathBuf,
    pub server_key_path: PathBuf,
    pub dh_params_path: Option<PathBuf>,
    /// TLS auth key for tls-crypt
    pub tls_crypt_key_path: Option<PathBuf>,
    /// Cipher for data channel
    #[serde(default = "default_cipher")]
    pub cipher: String,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpsecServerConfig {
    pub ike_port: u16,
    pub natt_port: u16,
    pub ca_cert_path: PathBuf,
    pub server_cert_path: PathBuf,
    pub server_key_path: PathBuf,
    /// IKEv2 EAP identity
    pub identity: String,
    pub ike_proposals: Vec<String>,
    pub esp_proposals: Vec<String>,
}

// ─────────────────────────────────────────────
//  Client config
// ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// Directory where profiles are stored
    #[serde(default = "default_profiles_dir")]
    pub profiles_dir: PathBuf,

    /// Auto-connect profile ID on startup
    pub auto_connect: Option<String>,

    /// Kill switch: block all traffic when not connected
    #[serde(default)]
    pub kill_switch: bool,

    /// Reconnection settings
    #[serde(default)]
    pub reconnect: ReconnectConfig,

    /// Encrypted DNS (DoT/DoH) settings
    #[serde(default)]
    pub dns: DnsConfig,
}

impl ClientConfig {
    pub fn validate(&self) -> Result<()> {
        Ok(())
    }
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            profiles_dir: default_profiles_dir(),
            auto_connect: None,
            kill_switch: false,
            reconnect: ReconnectConfig::default(),
            dns: DnsConfig::default(),
        }
    }
}

// ─────────────────────────────────────────────
//  Encrypted DNS (DoT / DoH)
// ─────────────────────────────────────────────

/// Configuration for the encrypted-DNS proxy.
///
/// When enabled, the daemon spawns a local UDP listener (default
/// `127.0.0.53:53`) that forwards every query to one or more DoT/DoH
/// upstreams, with TLS certificate verification.  The listener address is
/// the one written into `/etc/resolv.conf`, so all stub-resolvers on the
/// machine route through encrypted DNS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    /// Master switch.  When false, the daemon falls back to using the
    /// VPN-pushed DNS server in plaintext (legacy behaviour).
    #[serde(default)]
    pub encrypted: bool,

    /// Local UDP/TCP listen address.  Defaults to `127.0.0.53:53` to match
    /// systemd-resolved's well-known address.
    #[serde(default = "default_dns_listen")]
    pub listen: SocketAddr,

    /// DoT upstreams.  Each entry is `IP:PORT@SNI` (eg. `1.1.1.1:853@cloudflare-dns.com`).
    /// Defaults to Cloudflare + Quad9.
    #[serde(default = "default_dot_upstreams")]
    pub dot_upstreams: Vec<String>,

    /// When true, DNSSEC validation is enabled on the resolver.
    #[serde(default = "default_true")]
    pub validate_dnssec: bool,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            encrypted: false,
            listen: default_dns_listen(),
            dot_upstreams: default_dot_upstreams(),
            validate_dnssec: true,
        }
    }
}

fn default_dns_listen() -> SocketAddr {
    "127.0.0.53:53".parse().expect("static address parses")
}

fn default_dot_upstreams() -> Vec<String> {
    vec![
        "1.1.1.1:853@cloudflare-dns.com".into(),
        "1.0.0.1:853@cloudflare-dns.com".into(),
        "9.9.9.9:853@dns.quad9.net".into(),
    ]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconnectConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_reconnect_max_attempts")]
    pub max_attempts: u32,
    #[serde(default = "default_reconnect_initial_delay_ms")]
    pub initial_delay_ms: u64,
    #[serde(default = "default_reconnect_max_delay_ms")]
    pub max_delay_ms: u64,
}

impl Default for ReconnectConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_attempts: 0, // 0 = unlimited
            initial_delay_ms: 1000,
            max_delay_ms: 60_000,
        }
    }
}

// ─────────────────────────────────────────────
//  Logging config
// ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default)]
    pub json: bool,
    pub log_file: Option<PathBuf>,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".into(),
            json: false,
            log_file: None,
        }
    }
}

// ─────────────────────────────────────────────
//  Shared enums
// ─────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportProtocol {
    Udp,
    Tcp,
}

impl Default for TransportProtocol {
    fn default() -> Self {
        Self::Udp
    }
}

// ─────────────────────────────────────────────
//  Defaults
// ─────────────────────────────────────────────

fn default_max_clients() -> usize {
    1024
}

fn default_mtu() -> u16 {
    1420
}

fn default_cipher() -> String {
    "AES-256-GCM".into()
}

fn default_profiles_dir() -> PathBuf {
    let mut p = dirs_next::config_dir().unwrap_or_else(|| PathBuf::from("~/.config"));
    p.push("vpnforge/profiles");
    p
}

fn default_log_level() -> String {
    "info".into()
}

fn default_reconnect_max_attempts() -> u32 {
    0
}

fn default_reconnect_initial_delay_ms() -> u64 {
    1000
}

fn default_reconnect_max_delay_ms() -> u64 {
    60_000
}

// ─────────────────────────────────────────────
//  Profile (per-connection settings)
// ─────────────────────────────────────────────

/// A VPN connection profile serialized to TOML in profiles_dir
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub name: String,
    /// "wireguard" | "openvpn" | "ipsec"
    pub protocol: String,
    pub server_host: String,
    pub server_port: u16,
    /// Assigned virtual IP (optional, some servers auto-assign)
    pub virtual_ip: Option<String>,

    // WireGuard fields
    /// Plaintext base64 private key (legacy / unsealed profiles).
    /// New profiles should prefer `wg_private_key_sealed`.
    pub wg_private_key: Option<String>,
    /// Argon2id+AES-256-GCM sealed envelope: "vpf1$<base64(salt|nonce|ct+tag)>".
    /// When present, `wg_private_key` is ignored.
    pub wg_private_key_sealed: Option<String>,
    pub wg_peer_pubkey: Option<String>,
    pub wg_preshared_key: Option<String>,

    // OpenVPN / IPsec credentials
    pub username: Option<String>,
    #[serde(skip_serializing)] // never persist password to disk
    pub password: Option<String>,
    pub ca_cert_path: Option<String>,
    pub client_cert_path: Option<String>,
    pub client_key_path: Option<String>,

    /// Enable kill switch for this profile
    #[serde(default)]
    pub kill_switch: bool,

    /// Use split tunneling (only vpn_routes go through VPN)
    #[serde(default)]
    pub split_tunnel: bool,

    /// CIDRs routed through the VPN when split_tunnel is true
    #[serde(default)]
    pub vpn_routes: Vec<String>,

    /// DNS server to use (default: VPN server's DNS)
    pub dns_server: Option<String>,

    /// Disable IPv6 to prevent IPv6 leaks
    #[serde(default = "default_true")]
    pub disable_ipv6: bool,

    /// RFC 3339 timestamp when the WireGuard private key was generated/imported.
    /// Used to warn the user when keys are old (recommended rotation: 90 days).
    #[serde(default)]
    pub wg_private_key_created_at: Option<String>,

    /// RFC 3339 timestamp when the WireGuard preshared key was generated.
    /// PSKs add post-quantum-style protection on top of the X25519 handshake;
    /// they should be rotated regularly.
    #[serde(default)]
    pub wg_preshared_key_created_at: Option<String>,
}

impl Profile {
    /// Returns true if this profile stores its WireGuard private key
    /// as an Argon2id+AES-GCM sealed envelope (and therefore requires a
    /// passphrase to unlock at connect time).
    pub fn has_sealed_private_key(&self) -> bool {
        self.wg_private_key_sealed
            .as_deref()
            .map(crate::crypto::profile_seal::is_sealed)
            .unwrap_or(false)
    }

    /// Resolve the WireGuard private key, decrypting the sealed envelope
    /// when present. The returned string is held in `Zeroizing` and wiped
    /// from memory on drop.
    ///
    /// `passphrase_provider` is invoked only when a sealed key is detected;
    /// it MUST return the user-supplied passphrase as bytes.
    ///
    /// The AAD bound into the AEAD tag is the literal string
    /// `"vpnforge:profile:<name>"` so that an attacker cannot move a
    /// sealed blob to a different profile and have it still authenticate.
    pub fn resolve_wg_private_key<F>(
        &self,
        passphrase_provider: F,
    ) -> anyhow::Result<zeroize::Zeroizing<String>>
    where
        F: FnOnce() -> anyhow::Result<zeroize::Zeroizing<Vec<u8>>>,
    {
        use anyhow::{anyhow, Context};

        if let Some(sealed) = self.wg_private_key_sealed.as_deref() {
            if !crate::crypto::profile_seal::is_sealed(sealed) {
                return Err(anyhow!(
                    "wg_private_key_sealed is present but has unknown format"
                ));
            }
            let pass = passphrase_provider().context("failed to obtain passphrase")?;
            let aad = format!("vpnforge:profile:{}", self.name);
            let plain = crate::crypto::profile_seal::unseal(sealed, &pass, aad.as_bytes())
                .context("failed to decrypt WireGuard private key")?;
            // The plaintext is base64 ASCII; validate UTF-8 without leaking it.
            let s = std::str::from_utf8(&plain)
                .map_err(|_| anyhow!("decrypted private key is not valid UTF-8"))?
                .to_string();
            return Ok(zeroize::Zeroizing::new(s));
        }

        if let Some(plain) = self.wg_private_key.as_deref() {
            return Ok(zeroize::Zeroizing::new(plain.to_string()));
        }

        Err(anyhow!(
            "profile '{}' has no WireGuard private key (neither plaintext nor sealed)",
            self.name
        ))
    }

    /// Age (in days) of the WireGuard private key, or `None` if the timestamp
    /// is missing or unparseable.
    pub fn private_key_age_days(&self) -> Option<i64> {
        timestamp_age_days(self.wg_private_key_created_at.as_deref())
    }

    /// Age (in days) of the WireGuard preshared key.
    pub fn preshared_key_age_days(&self) -> Option<i64> {
        timestamp_age_days(self.wg_preshared_key_created_at.as_deref())
    }

    /// True if this profile carries a non-empty preshared key.
    pub fn has_preshared_key(&self) -> bool {
        self.wg_preshared_key
            .as_deref()
            .map(|s| !s.is_empty())
            .unwrap_or(false)
    }
}

/// Parse an RFC 3339 timestamp and return its age in days relative to now.
fn timestamp_age_days(stamp: Option<&str>) -> Option<i64> {
    let s = stamp?;
    let dt = chrono::DateTime::parse_from_rfc3339(s).ok()?;
    let age = chrono::Utc::now().signed_duration_since(dt.with_timezone(&chrono::Utc));
    Some(age.num_days())
}

#[cfg(test)]
mod key_age_tests {
    use super::*;

    fn base() -> Profile {
        Profile {
            name: "t".into(), protocol: "wireguard".into(),
            server_host: "1.1.1.1".into(), server_port: 51820,
            virtual_ip: None,
            wg_private_key: None, wg_private_key_sealed: None,
            wg_peer_pubkey: None, wg_preshared_key: None,
            username: None, password: None,
            ca_cert_path: None, client_cert_path: None, client_key_path: None,
            kill_switch: false, split_tunnel: false, vpn_routes: vec![],
            dns_server: None, disable_ipv6: false,
            wg_private_key_created_at: None, wg_preshared_key_created_at: None,
        }
    }

    #[test]
    fn missing_timestamps_yield_none() {
        let p = base();
        assert!(p.private_key_age_days().is_none());
        assert!(p.preshared_key_age_days().is_none());
    }

    #[test]
    fn old_timestamp_reports_positive_age() {
        let mut p = base();
        let then = chrono::Utc::now() - chrono::Duration::days(100);
        p.wg_private_key_created_at = Some(then.to_rfc3339());
        let age = p.private_key_age_days().unwrap();
        assert!(age >= 99 && age <= 101, "age was {}", age);
    }

    #[test]
    fn malformed_timestamp_yields_none() {
        let mut p = base();
        p.wg_private_key_created_at = Some("not-a-date".into());
        assert!(p.private_key_age_days().is_none());
    }

    #[test]
    fn has_preshared_key_detects_empty_and_present() {
        let mut p = base();
        assert!(!p.has_preshared_key());
        p.wg_preshared_key = Some(String::new());
        assert!(!p.has_preshared_key());
        p.wg_preshared_key = Some("abc".into());
        assert!(p.has_preshared_key());
    }
}
