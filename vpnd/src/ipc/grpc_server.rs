// vpnd/src/ipc/grpc_server.rs
// gRPC service implementation aligned with proto/vpnd.proto
//
// All RPCs are served over a Unix domain socket.
// Socket path: /run/vpnd/control.sock (prod) or /tmp/vpnd.sock (dev)

use crate::config::VpndConfig;
use crate::kill_switch::firewall::KillSwitch;
use crate::metrics::collector::MetricsSnapshot;
use crate::metrics::system::{CpuSampler, read_memory, read_load_avg, read_uptime_seconds};
use crate::session::manager::{SessionManager, SessionState};
use parking_lot::Mutex;
use std::path::Path;
use std::sync::Arc;
use tokio::net::UnixListener;
use tokio::sync::{watch, RwLock};
use tonic::{transport::Server, Request, Response, Status};
use tracing::{info, warn};

// Include generated protobuf code
pub mod proto {
    tonic::include_proto!("vpnd");
}

use proto::vpnd_service_server::{VpndService as VpndServiceTrait, VpndServiceServer};
use proto::*;

/// Signal sent through the connect-channel: profile id + optional passphrase
/// for at-rest decryption of the WireGuard private key.
///
/// `passphrase` is held in `Zeroizing` so the bytes are wiped from memory
/// after the receiver has consumed them.
#[derive(Clone, Default)]
pub struct ConnectSignal {
    pub profile_id: Option<String>,
    pub passphrase: Option<std::sync::Arc<zeroize::Zeroizing<Vec<u8>>>>,
}

/// Shared daemon state accessible from gRPC handlers
pub struct DaemonState {
    pub config: Arc<RwLock<VpndConfig>>,
    pub session_manager: Arc<SessionManager>,
    /// Signal daemon to connect to profile (profile id + optional passphrase)
    pub connect_tx: watch::Sender<ConnectSignal>,
    /// Signal daemon to disconnect
    pub disconnect_tx: watch::Sender<bool>,
    /// Stream of live metrics
    pub metrics_rx: watch::Receiver<MetricsSnapshot>,
    /// Kill switch active flag (fast path for status queries)
    pub kill_switch_active: Arc<std::sync::atomic::AtomicBool>,
    /// Actual kill switch manager (applies/removes firewall rules)
    pub kill_switch: Arc<tokio::sync::Mutex<Option<KillSwitch>>>,
    /// CPU sampler for health RPC (needs mutable state for delta)
    pub cpu_sampler: Arc<Mutex<CpuSampler>>,
    /// Persistent Ed25519 keypair used to sign and verify profile files.
    /// `None` if signing is disabled at startup or key load failed.
    pub signing_key: Option<Arc<ring::signature::Ed25519KeyPair>>,
}

/// The gRPC service implementation
pub struct VpndService {
    state: Arc<DaemonState>,
}

impl VpndService {
    pub fn new(state: Arc<DaemonState>) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl VpndServiceTrait for VpndService {
    async fn connect_vpn(
        &self,
        request: Request<ConnectRequest>,
    ) -> Result<Response<ConnectResponse>, Status> {
        let req = request.into_inner();
        info!(profile_id = %req.profile_id, "Connect request received");

        let passphrase = if req.passphrase.is_empty() {
            None
        } else {
            Some(std::sync::Arc::new(zeroize::Zeroizing::new(
                req.passphrase.clone().into_bytes(),
            )))
        };

        self.state
            .connect_tx
            .send(ConnectSignal {
                profile_id: Some(req.profile_id.clone()),
                passphrase,
            })
            .map_err(|_| Status::internal("Failed to signal connect"))?;

        Ok(Response::new(ConnectResponse {
            success: true,
            error: String::new(),
            virtual_ip: String::new(),
            server_ip: String::new(),
            protocol: String::new(),
        }))
    }

    async fn disconnect(
        &self,
        _request: Request<DisconnectRequest>,
    ) -> Result<Response<DisconnectResponse>, Status> {
        info!("Disconnect request received");

        self.state
            .disconnect_tx
            .send(true)
            .map_err(|_| Status::internal("Failed to signal disconnect"))?;

        Ok(Response::new(DisconnectResponse {
            success: true,
            error: String::new(),
        }))
    }

    async fn get_status(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<StatusResponse>, Status> {
        let sessions = self.state.session_manager.list_sessions();

        let (state, profile_id, virtual_ip, server_ip, protocol) =
            if let Some(session) = sessions.first() {
                let state = match &session.state {
                    SessionState::Connecting => ConnectionState::Connecting,
                    SessionState::Connected => ConnectionState::Connected,
                    SessionState::Reconnecting => ConnectionState::Reconnecting,
                    SessionState::Disconnected => ConnectionState::Disconnected,
                    SessionState::Failed(_) => ConnectionState::Error,
                };
                (
                    state as i32,
                    session.id.clone(),
                    session.virtual_ip.map(|ip| ip.to_string()).unwrap_or_default(),
                    session.server_ip.to_string(),
                    session.protocol.clone(),
                )
            } else {
                (ConnectionState::Disconnected as i32, String::new(), String::new(), String::new(), String::new())
            };

        let ks_active = self.state.kill_switch_active.load(std::sync::atomic::Ordering::Relaxed);

        Ok(Response::new(StatusResponse {
            state,
            profile_id,
            profile_name: String::new(),
            virtual_ip,
            server_ip,
            protocol,
            connected_since: 0,
            server_country: String::new(),
            handshake_ms: 0.0,
            kill_switch_active: ks_active,
        }))
    }

    type StreamMetricsStream = futures::stream::BoxStream<'static, Result<MetricsUpdate, Status>>;

    async fn stream_metrics(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<Self::StreamMetricsStream>, Status> {
        use futures::StreamExt;
        Ok(Response::new(Box::pin(
            tokio_stream::wrappers::WatchStream::new(
                self.state.metrics_rx.clone()
            ).map(|snap| Ok(MetricsUpdate {
                rx_bytes_per_sec: snap.rx_rate_bps as i64,
                tx_bytes_per_sec: snap.tx_rate_bps as i64,
                rx_bytes_total: snap.bytes_received as i64,
                tx_bytes_total: snap.bytes_sent as i64,
                latency_ms: snap.rtt_ms as f32,
                packet_loss_pct: snap.loss_percent as f32,
                timestamp_ms: snap.timestamp as i64 * 1000,
                active_sessions: 1,
            }))
        ) as Self::StreamMetricsStream))
    }

    async fn list_profiles(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<ProfileList>, Status> {
        let config = self.state.config.read().await;
        let default_client = crate::config::ClientConfig::default();
        let client_cfg = config.client.as_ref().unwrap_or(&default_client);
        let profiles_dir = client_cfg.profiles_dir.to_string_lossy().to_string();

        let mut profiles = Vec::new();

        if let Ok(mut dir) = tokio::fs::read_dir(&profiles_dir).await {
            while let Ok(Some(entry)) = dir.next_entry().await {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("toml") {
                    if let Ok(content) = tokio::fs::read_to_string(&path).await {
                        if let Ok(p) = toml::from_str::<crate::config::Profile>(&content) {
                            profiles.push(profile_to_proto(p));
                        }
                    }
                }
            }
        }

        Ok(Response::new(ProfileList { profiles }))
    }

    async fn get_profile(
        &self,
        request: Request<ProfileIdRequest>,
    ) -> Result<Response<Profile>, Status> {
        let id = request.into_inner().id;
        let safe_id = sanitize_profile_name(&id)?;

        let config = self.state.config.read().await;
        let default_client = crate::config::ClientConfig::default();
        let client_cfg = config.client.as_ref().unwrap_or(&default_client);
        let path = format!("{}/{}.toml", client_cfg.profiles_dir.to_string_lossy(), safe_id);

        let content = tokio::fs::read_to_string(&path)
            .await
            .map_err(|_| Status::not_found(format!("Profile '{}' not found", id)))?;

        let p: crate::config::Profile = toml::from_str(&content)
            .map_err(|e| Status::internal(format!("Failed to parse profile: {}", e)))?;

        Ok(Response::new(profile_to_proto(p)))
    }

    async fn save_profile(
        &self,
        request: Request<Profile>,
    ) -> Result<Response<SaveProfileResponse>, Status> {
        let proto_profile = request.into_inner();
        let safe_name = sanitize_profile_name(&proto_profile.name)?;

        let config = self.state.config.read().await;
        let default_client = crate::config::ClientConfig::default();
        let client_cfg = config.client.as_ref().unwrap_or(&default_client);
        let profiles_dir = client_cfg.profiles_dir.to_string_lossy().to_string();
        let path = format!("{}/{}.toml", profiles_dir, safe_name);

        // ── At-rest encryption ────────────────────────────────────────────────
        // If the client supplied a passphrase AND a plaintext WG private key,
        // we encrypt it with Argon2id+AES-256-GCM and persist *only* the sealed
        // envelope. The plaintext field is cleared so it never reaches disk.
        let (wg_priv_plain, wg_priv_sealed): (Option<String>, Option<String>) = {
            use crate::crypto::profile_seal;
            let pass_b = proto_profile.passphrase.as_bytes();
            let plaintext = if proto_profile.wg_private_key.is_empty() {
                None
            } else {
                Some(String::from_utf8_lossy(&proto_profile.wg_private_key).to_string())
            };
            let already_sealed = if proto_profile.wg_private_key_sealed.is_empty() {
                None
            } else {
                Some(proto_profile.wg_private_key_sealed.clone())
            };

            if !pass_b.is_empty() {
                let plain = plaintext.as_deref().ok_or_else(|| {
                    Status::invalid_argument(
                        "passphrase supplied but no plaintext WG private key to seal",
                    )
                })?;
                let aad = format!("vpnforge:profile:{}", proto_profile.name);
                let sealed = profile_seal::seal(plain.as_bytes(), pass_b, aad.as_bytes())
                    .map_err(|e| Status::internal(format!("seal failed: {}", e)))?;
                (None, Some(sealed))
            } else {
                (plaintext, already_sealed)
            }
        };

        let profile = crate::config::Profile {
            name: proto_profile.name.clone(),
            protocol: format!("{:?}", proto_profile.protocol).to_lowercase(),
            server_host: proto_profile.server_host.clone(),
            server_port: proto_profile.server_port as u16,
            virtual_ip: None,
            wg_private_key: wg_priv_plain,
            wg_private_key_sealed: wg_priv_sealed,
            wg_peer_pubkey: if proto_profile.wg_peer_pubkey.is_empty() { None } else {
                Some(String::from_utf8_lossy(&proto_profile.wg_peer_pubkey).to_string())
            },
            wg_preshared_key: if proto_profile.wg_preshared_key.is_empty() { None } else {
                Some(proto_profile.wg_preshared_key.clone())
            },
            username: if proto_profile.username.is_empty() { None } else { Some(proto_profile.username.clone()) },
            password: None,
            ca_cert_path: None,
            client_cert_path: None,
            client_key_path: None,
            kill_switch: proto_profile.kill_switch,
            split_tunnel: proto_profile.split_tunnel,
            vpn_routes: proto_profile.vpn_routes.clone(),
            dns_server: if proto_profile.dns_server.is_empty() { None } else { Some(proto_profile.dns_server.clone()) },
            disable_ipv6: proto_profile.ipv6_disabled,
            wg_private_key_created_at: None,
            wg_preshared_key_created_at: None,
        };

        // Ensure profiles directory exists with restricted permissions (0700)
        // so that private key material in profile files is not exposed to
        // other users on the system even if file permissions are loose.
        std::fs::create_dir_all(&profiles_dir)
            .map_err(|e| Status::internal(format!("Cannot create profiles dir: {}", e)))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(
                &profiles_dir,
                std::fs::Permissions::from_mode(0o700),
            );
        }

        let toml_str = toml::to_string_pretty(&profile)
            .map_err(|e| Status::internal(format!("Failed to serialize profile: {}", e)))?;

        // ── Sign the profile body before writing it ──────────────────────────
        // When auto_sign_on_save is true (default) we append a trailing
        // `# vpnforge-signature: …` line so the daemon (and only the daemon)
        // can prove the file has not been tampered with on disk.
        let body_to_write: String = {
            let auto_sign = config.security.auto_sign_on_save;
            if auto_sign {
                if let Some(kp) = self.state.signing_key.as_ref() {
                    crate::crypto::profile_signing::sign_profile(&toml_str, kp.as_ref())
                } else {
                    toml_str
                }
            } else {
                toml_str
            }
        };

        // Write profile with 0600 permissions — private keys must never be world-readable.
        {
            use std::os::unix::fs::OpenOptionsExt;
            let file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&path)
                .map_err(|e| Status::internal(format!("Cannot create profile file: {}", e)))?;
            use std::io::Write;
            let mut writer = std::io::BufWriter::new(file);
            writer.write_all(body_to_write.as_bytes())
                .map_err(|e| Status::internal(format!("Cannot write profile: {}", e)))?;
        }

        info!(profile = %proto_profile.name, "Profile saved");
        Ok(Response::new(SaveProfileResponse {
            success: true,
            id: safe_name,
            error: String::new(),
        }))
    }

    async fn delete_profile(
        &self,
        request: Request<ProfileIdRequest>,
    ) -> Result<Response<DeleteProfileResponse>, Status> {
        let id = request.into_inner().id;
        let safe_id = sanitize_profile_name(&id)?;

        let config = self.state.config.read().await;
        let default_client = crate::config::ClientConfig::default();
        let client_cfg = config.client.as_ref().unwrap_or(&default_client);
        let path = format!("{}/{}.toml", client_cfg.profiles_dir.to_string_lossy(), safe_id);

        tokio::fs::remove_file(&path)
            .await
            .map_err(|_| Status::not_found(format!("Profile '{}' not found", id)))?;

        info!(profile = %id, "Profile deleted");
        Ok(Response::new(DeleteProfileResponse { success: true, error: String::new() }))
    }

    /// Rotate the WireGuard preshared key (and optionally the static keypair)
    /// of an existing profile.
    ///
    /// **Important**: when `rotate_static_keypair = true`, the *server's* peer
    /// configuration must be updated with the returned `new_public_key`
    /// before the next connect attempt or the handshake will fail.  This RPC
    /// handles only the client-side change.
    async fn rotate_profile_keys(
        &self,
        request: Request<RotateKeysRequest>,
    ) -> Result<Response<RotateKeysResponse>, Status> {
        use crate::crypto::{profile_seal, profile_signing, WireGuardKeyPair};
        let req = request.into_inner();
        let safe_id = sanitize_profile_name(&req.profile_id)?;

        let config = self.state.config.read().await;
        let default_client = crate::config::ClientConfig::default();
        let client_cfg = config.client.as_ref().unwrap_or(&default_client);
        let path = format!("{}/{}.toml", client_cfg.profiles_dir.to_string_lossy(), safe_id);

        let auto_sign = config.security.auto_sign_on_save;
        let require_signed = config.security.require_signed_profiles;
        drop(config);

        let content = tokio::fs::read_to_string(&path)
            .await
            .map_err(|_| Status::not_found(format!("Profile '{}' not found", req.profile_id)))?;

        // Verify existing signature first — never modify a tampered file.
        if require_signed {
            let pk = self
                .state
                .signing_key
                .as_ref()
                .map(|kp| profile_signing::public_key_bytes(kp.as_ref()))
                .ok_or_else(|| Status::failed_precondition("signing key unavailable"))?;
            if let Err(e) = profile_signing::verify_profile(&content, &pk) {
                return Err(Status::failed_precondition(format!(
                    "refusing to rotate keys on a profile with invalid signature: {}",
                    e
                )));
            }
        }

        let mut profile: crate::config::Profile = toml::from_str(&content)
            .map_err(|e| Status::internal(format!("Failed to parse profile: {}", e)))?;

        let now = chrono::Utc::now().to_rfc3339();

        // ── New PSK ─────────────────────────────────────────────────────────
        // 32 random bytes from the OS RNG, base64-encoded — same format as
        // `wg genpsk`.
        let new_psk = {
            use rand_core::{OsRng, RngCore};
            let mut buf = [0u8; 32];
            OsRng.fill_bytes(&mut buf);
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD.encode(buf)
        };
        profile.wg_preshared_key = Some(new_psk.clone());
        profile.wg_preshared_key_created_at = Some(now.clone());

        // ── Optionally rotate static keypair ────────────────────────────────
        let new_pub_b64 = if req.rotate_static_keypair {
            let kp = WireGuardKeyPair::generate();
            let new_priv = kp.private_key_base64();
            let new_pub = kp.public_key_base64();

            // Decide how to persist the new private key:
            //   - if a passphrase is provided → seal it
            //   - else if the existing profile was sealed → reseal with the
            //     passphrase the caller MUST have re-supplied
            //   - else → store as plaintext (legacy mode)
            if !req.passphrase.is_empty() {
                let aad = format!("vpnforge:profile:{}", profile.name);
                let sealed = profile_seal::seal(
                    new_priv.as_bytes(),
                    req.passphrase.as_bytes(),
                    aad.as_bytes(),
                )
                .map_err(|e| Status::internal(format!("seal failed: {}", e)))?;
                profile.wg_private_key = None;
                profile.wg_private_key_sealed = Some(sealed);
            } else if profile.wg_private_key_sealed.is_some() {
                return Err(Status::invalid_argument(
                    "this profile is sealed; passphrase is required to re-seal the new key",
                ));
            } else {
                profile.wg_private_key = Some(new_priv);
                profile.wg_private_key_sealed = None;
            }
            profile.wg_private_key_created_at = Some(now.clone());
            new_pub
        } else {
            String::new()
        };

        // ── Serialize, sign, write atomically ───────────────────────────────
        let toml_str = toml::to_string_pretty(&profile)
            .map_err(|e| Status::internal(format!("Serialization error: {}", e)))?;
        let body = if auto_sign {
            if let Some(kp) = self.state.signing_key.as_ref() {
                profile_signing::sign_profile(&toml_str, kp.as_ref())
            } else {
                toml_str
            }
        } else {
            toml_str
        };

        // Write to a temp file in the same directory then rename — this is
        // crash-safe and never leaves a half-written profile on disk.
        let tmp_path = format!("{}.rotate.tmp", path);
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp_path)
                .map_err(|e| Status::internal(format!("Cannot create tmp profile: {}", e)))?;
            f.write_all(body.as_bytes())
                .map_err(|e| Status::internal(format!("Write failed: {}", e)))?;
            f.sync_all().ok();
        }
        std::fs::rename(&tmp_path, &path)
            .map_err(|e| Status::internal(format!("Rename failed: {}", e)))?;

        info!(
            profile = %profile.name,
            rotated_keypair = req.rotate_static_keypair,
            "Profile keys rotated"
        );

        Ok(Response::new(RotateKeysResponse {
            success: true,
            error: String::new(),
            new_public_key: new_pub_b64,
            new_preshared_key: new_psk,
        }))
    }

    async fn import_profile(
        &self,
        request: Request<ImportRequest>,
    ) -> Result<Response<SaveProfileResponse>, Status> {
        let req = request.into_inner();
        let text = String::from_utf8(req.data.clone())
            .map_err(|_| Status::invalid_argument("File is not valid UTF-8"))?;

        let mut profile = match req.format.to_lowercase().as_str() {
            "wg" | "wireguard" | "conf" => parse_wireguard_conf(&text, &req.name)?,
            "ovpn" | "openvpn" | "" => parse_ovpn(&text, &req.name)?,
            other => return Err(Status::invalid_argument(format!("Unknown format '{}'", other))),
        };

        // ── At-rest encryption ────────────────────────────────────────────────
        // If the importer provided a passphrase and the profile carries a WG
        // private key (e.g. parsed from a .conf file), seal it now so the
        // plaintext is never persisted to disk.
        if !req.passphrase.is_empty() {
            if let Some(plain) = profile.wg_private_key.take() {
                use crate::crypto::profile_seal;
                let aad = format!("vpnforge:profile:{}", profile.name);
                let sealed = profile_seal::seal(
                    plain.as_bytes(),
                    req.passphrase.as_bytes(),
                    aad.as_bytes(),
                )
                .map_err(|e| Status::internal(format!("seal failed: {}", e)))?;
                profile.wg_private_key_sealed = Some(sealed);
            }
        }

        let safe_name = sanitize_profile_name(&profile.name)?;

        let config = self.state.config.read().await;
        let default_client = crate::config::ClientConfig::default();
        let client_cfg = config.client.as_ref().unwrap_or(&default_client);
        let profiles_dir = client_cfg.profiles_dir.to_string_lossy().to_string();

        tokio::fs::create_dir_all(&profiles_dir)
            .await
            .map_err(|e| Status::internal(format!("Cannot create profiles dir: {}", e)))?;

        let path = format!("{}/{}.toml", profiles_dir, safe_name);
        let toml_str = toml::to_string_pretty(&profile)
            .map_err(|e| Status::internal(format!("Serialization error: {}", e)))?;

        // Sign the body unless explicitly disabled (mirrors save_profile).
        let body_to_write: String = {
            let auto_sign = config.security.auto_sign_on_save;
            if auto_sign {
                if let Some(kp) = self.state.signing_key.as_ref() {
                    crate::crypto::profile_signing::sign_profile(&toml_str, kp.as_ref())
                } else {
                    toml_str
                }
            } else {
                toml_str
            }
        };

        // Write with O_EXCL-equivalent semantics and restrict to 0600.
        // Profile files may contain WireGuard private keys — they must never
        // be readable by other users on the system.
        {
            use std::os::unix::fs::OpenOptionsExt;
            let file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&path)
                .map_err(|e| Status::internal(format!("Cannot create profile file: {}", e)))?;
            use std::io::Write;
            let mut writer = std::io::BufWriter::new(file);
            writer.write_all(body_to_write.as_bytes())
                .map_err(|e| Status::internal(format!("Cannot write profile: {}", e)))?;
        }

        info!(name = %safe_name, format = %req.format, "Profile imported");
        Ok(Response::new(SaveProfileResponse {
            success: true,
            id: safe_name,
            error: String::new(),
        }))
    }

    type RunPingTestStream = futures::stream::BoxStream<'static, Result<PingResult, Status>>;

    async fn run_ping_test(
        &self,
        request: Request<PingRequest>,
    ) -> Result<Response<Self::RunPingTestStream>, Status> {
        let req = request.into_inner();

        // Validate host to prevent command injection and argument injection.
        // Even though Command::new avoids a shell, we must also block leading '-'
        // which could be interpreted as flags by the ping binary itself.
        let host = req.host.trim().to_string();
        let is_valid_host = !host.is_empty()
            && !host.starts_with('-')          // block flag injection (e.g. -i eth0)
            && host.chars().all(|c| c.is_ascii_alphanumeric()
                || matches!(c, '.' | '-' | ':' | '[' | ']'));  // IPv4, IPv6, hostnames
        if !is_valid_host {
            return Err(Status::invalid_argument(
                "Invalid host: must be a valid hostname or IP address",
            ));
        }

        let count = req.count.max(1).min(20).to_string();
        let output = tokio::process::Command::new("ping")
            .args(["-c", &count, "-W", "2", &host])
            .output()
            .await
            .map_err(|e| Status::internal(format!("ping failed: {}", e)))?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let success = output.status.success();
        let avg_ms = parse_ping_avg_rtt(&stdout).unwrap_or(0.0);

        let results = vec![Ok(PingResult {
            rtt_ms: avg_ms,
            success,
            seq: 0,
            error: if success { String::new() } else { String::from_utf8_lossy(&output.stderr).to_string() },
            avg_ms,
            loss_pct: if success { 0.0 } else { 100.0 },
        })];

        use futures::StreamExt;
        Ok(Response::new(Box::pin(futures::stream::iter(results)) as Self::RunPingTestStream))
    }

    async fn run_dns_leak_test(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<DnsLeakResult>, Status> {
        // Use the system stub resolver to check which DNS servers respond.
        // We query `whoami.akamai.net` — a real hostname whose TXT/A records
        // contain the IP of the resolver that answered, letting us detect
        // leaks without shelling out to nslookup.
        use hickory_resolver::{
            config::{ResolverConfig, ResolverOpts},
            TokioAsyncResolver,
        };

        let resolver = TokioAsyncResolver::tokio(
            ResolverConfig::default(),
            ResolverOpts::default(),
        );

        let dns_servers: Vec<String>;
        let leaked: bool;
        let error: String;

        match resolver.lookup_ip("whoami.akamai.net.").await {
            Ok(response) => {
                // Collect the answering server IPs as a proxy for resolver identity.
                dns_servers = response
                    .iter()
                    .map(|ip| ip.to_string())
                    .collect();
                leaked = false;
                error = String::new();
            }
            Err(e) => {
                dns_servers = vec![];
                leaked = true;
                error = format!("DNS resolution failed: {}", e);
            }
        }

        // Also check /etc/resolv.conf to report the configured stub resolver.
        let resolv_servers = read_resolv_conf_servers();
        let all_servers: Vec<String> = resolv_servers
            .into_iter()
            .chain(dns_servers.into_iter())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();

        Ok(Response::new(DnsLeakResult {
            leaked,
            dns_servers: all_servers,
            expected_servers: vec![],
            error,
        }))
    }

    async fn run_ip_leak_test(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<IpLeakResult>, Status> {
        match crate::network::nat_traversal::StunClient::discover_with_fallback().await {
            Ok(discovery) => Ok(Response::new(IpLeakResult {
                leaked: false,
                detected_ip: discovery.mapped_address.ip().to_string(),
                expected_ip: String::new(),
                country: String::new(),
                ipv6_leaked: false,
                detected_ipv6: String::new(),
                error: String::new(),
            })),
            Err(e) => Ok(Response::new(IpLeakResult {
                leaked: true,
                detected_ip: String::new(),
                expected_ip: String::new(),
                country: String::new(),
                ipv6_leaked: false,
                detected_ipv6: String::new(),
                error: format!("STUN discovery failed: {}", e),
            })),
        }
    }

    async fn get_route_table(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<RouteTableResponse>, Status> {
        let output = tokio::process::Command::new("ip")
            .args(["route", "show"])
            .output()
            .await
            .map_err(|e| Status::internal(format!("ip route failed: {}", e)))?;

        let routes = String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.is_empty() { return None; }
                let destination = parts[0].to_string();
                let gateway = parts.iter().position(|&s| s == "via")
                    .and_then(|i| parts.get(i + 1))
                    .unwrap_or(&"direct")
                    .to_string();
                let interface = parts.iter().position(|&s| s == "dev")
                    .and_then(|i| parts.get(i + 1))
                    .unwrap_or(&"")
                    .to_string();
                Some(RouteEntry { destination, gateway, interface, metric: 0 })
            })
            .collect();

        Ok(Response::new(RouteTableResponse { routes }))
    }

    async fn set_kill_switch(
        &self,
        request: Request<KillSwitchRequest>,
    ) -> Result<Response<KillSwitchResponse>, Status> {
        let req = request.into_inner();

        let mut ks_guard = self.state.kill_switch.lock().await;

        if req.enabled {
            // Parse and validate the server IP — no string injection possible via typed parsing
            let server_ip: std::net::IpAddr = req.server_ip.parse().map_err(|_| {
                Status::invalid_argument("Invalid server IP address for kill switch")
            })?;
            let port = req.server_port as u16;
            let transport = match req.protocol.to_lowercase().as_str() {
                "tcp" | "openvpn-tcp" => "tcp",
                _ => "udp",
            };

            let ks = ks_guard.get_or_insert_with(|| {
                // KillSwitch::new is async but we're in a sync closure;
                // initialise with a placeholder that will be hydrated below
                KillSwitch::uninitialised()
            });

            ks.enable(server_ip, port, "tun0", transport)
                .await
                .map_err(|e| Status::internal(format!("Failed to enable kill switch: {}", e)))?;

            self.state
                .kill_switch_active
                .store(true, std::sync::atomic::Ordering::SeqCst);

            info!(server = %server_ip, port = port, "Kill switch ENABLED");
        } else {
            if let Some(ks) = ks_guard.as_mut() {
                ks.disable().await.map_err(|e| {
                    Status::internal(format!("Failed to disable kill switch: {}", e))
                })?;
            }
            self.state
                .kill_switch_active
                .store(false, std::sync::atomic::Ordering::SeqCst);
            info!("Kill switch DISABLED");
        }

        let active = self.state.kill_switch_active.load(std::sync::atomic::Ordering::Relaxed);
        Ok(Response::new(KillSwitchResponse {
            active,
            error: String::new(),
        }))
    }

    async fn get_kill_switch_status(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<KillSwitchResponse>, Status> {
        let active = self.state.kill_switch_active.load(std::sync::atomic::Ordering::Relaxed);
        Ok(Response::new(KillSwitchResponse { active, error: String::new() }))
    }

    async fn get_sessions(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<SessionList>, Status> {
        let sessions = self.state.session_manager.list_sessions()
            .into_iter()
            .map(|s| SessionInfo {
                id: s.id,
                peer_id: String::new(),
                virtual_ip: s.virtual_ip.map(|ip| ip.to_string()).unwrap_or_default(),
                real_ip: s.server_ip.to_string(),
                protocol: s.protocol,
                connected_since: 0,
                rx_bytes: s.bytes_received as i64,
                tx_bytes: s.bytes_sent as i64,
                latency_ms: 0.0,
                geo_country: String::new(),
                geo_city: String::new(),
                username: String::new(),
            })
            .collect::<Vec<_>>();

        let total = sessions.len() as u32;
        Ok(Response::new(SessionList { sessions, total }))
    }

    async fn kick_session(
        &self,
        request: Request<SessionIdRequest>,
    ) -> Result<Response<KickSessionResponse>, Status> {
        let id = request.into_inner().id;
        self.state.session_manager.disconnect(&id);
        Ok(Response::new(KickSessionResponse { success: true, error: String::new() }))
    }

    async fn get_system_health(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<SystemHealth>, Status> {
        // Real CPU sample from /proc/stat
        let cpu_percent = {
            let mut sampler = self.state.cpu_sampler.lock();
            sampler.sample().unwrap_or(None).unwrap_or(0.0)
        };
        // Real memory from /proc/meminfo
        let (memory_used_bytes, memory_total_bytes) = read_memory().unwrap_or((0, 0));
        // Load averages from /proc/loadavg
        let (load_avg_1m, load_avg_5m) = read_load_avg().unwrap_or((0.0, 0.0));
        // System uptime from /proc/uptime
        let uptime_seconds = read_uptime_seconds().unwrap_or(0);

        let metrics = self.state.metrics_rx.borrow().clone();
        let timestamp_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        Ok(Response::new(SystemHealth {
            cpu_percent,
            memory_used_bytes,
            memory_total_bytes,
            rx_bytes_per_sec: metrics.rx_rate_bps as i64,
            tx_bytes_per_sec: metrics.tx_rate_bps as i64,
            active_sessions: self.state.session_manager.session_count() as u32,
            uptime_seconds,
            version: env!("CARGO_PKG_VERSION").to_string(),
            load_avg_1m,
            load_avg_5m,
            timestamp_ms,
        }))
    }

    type StreamSystemHealthStream = futures::stream::BoxStream<'static, Result<SystemHealth, Status>>;

    async fn stream_system_health(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<Self::StreamSystemHealthStream>, Status> {
        use futures::StreamExt;
        let rx = self.state.metrics_rx.clone();
        let session_count = self.state.session_manager.session_count() as u32;
        let cpu_sampler = self.state.cpu_sampler.clone();
        let stream = tokio_stream::wrappers::WatchStream::new(rx)
            .map(move |snap| {
                let cpu_percent = {
                    let mut s = cpu_sampler.lock();
                    s.sample().unwrap_or(None).unwrap_or(0.0)
                };
                let (memory_used_bytes, memory_total_bytes) = read_memory().unwrap_or((0, 0));
                let (load_avg_1m, load_avg_5m) = read_load_avg().unwrap_or((0.0, 0.0));
                let uptime_seconds = read_uptime_seconds().unwrap_or(0);
                let timestamp_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as i64;
                Ok(SystemHealth {
                    cpu_percent,
                    memory_used_bytes,
                    memory_total_bytes,
                    rx_bytes_per_sec: snap.rx_rate_bps as i64,
                    tx_bytes_per_sec: snap.tx_rate_bps as i64,
                    active_sessions: session_count,
                    uptime_seconds,
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    load_avg_1m,
                    load_avg_5m,
                    timestamp_ms,
                })
            });
        Ok(Response::new(Box::pin(stream) as Self::StreamSystemHealthStream))
    }

    type StreamTopologyStream = futures::stream::BoxStream<'static, Result<TopologyUpdate, Status>>;

    async fn stream_topology(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<Self::StreamTopologyStream>, Status> {
        use futures::StreamExt;
        let session_manager = self.state.session_manager.clone();
        let metrics_rx = self.state.metrics_rx.clone();

        // Emit a topology snapshot every time metrics update
        let stream = tokio_stream::wrappers::WatchStream::new(metrics_rx)
            .map(move |_snap| {
                let sessions = session_manager.list_sessions();
                let timestamp_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as i64;

                // Build topology: one "server" node + one node per active session
                let mut nodes = vec![TopologyNode {
                    id: "vpnforge-daemon".to_string(),
                    label: "VPNForge Server".to_string(),
                    ip: "127.0.0.1".to_string(),
                    node_type: "server".to_string(),
                    protocol: String::new(),
                    country: String::new(),
                    latency_ms: 0.0,
                    active: true,
                }];

                let mut edges = Vec::new();

                for session in &sessions {
                    let node_id = session.id.clone();
                    let virtual_ip = session.virtual_ip
                        .map(|ip| ip.to_string())
                        .unwrap_or_default();
                    let is_connected = matches!(
                        session.state,
                        crate::session::manager::SessionState::Connected
                    );

                    nodes.push(TopologyNode {
                        id: node_id.clone(),
                        label: format!("Client {}", &node_id[..8.min(node_id.len())]),
                        ip: virtual_ip,
                        node_type: "client".to_string(),
                        protocol: session.protocol.clone(),
                        country: String::new(),
                        latency_ms: 0.0,
                        active: is_connected,
                    });

                    edges.push(TopologyEdge {
                        source: "vpnforge-daemon".to_string(),
                        target: node_id,
                        bandwidth: (session.bytes_sent + session.bytes_received) as f32,
                        latency_ms: 0.0,
                        healthy: is_connected,
                    });
                }

                Ok(TopologyUpdate { nodes, edges, timestamp_ms })
            });

        Ok(Response::new(Box::pin(stream) as Self::StreamTopologyStream))
    }

    async fn get_alerts(
        &self,
        _request: Request<AlertFilter>,
    ) -> Result<Response<AlertList>, Status> {
        Ok(Response::new(AlertList { alerts: vec![] }))
    }

    async fn acknowledge_alert(
        &self,
        _request: Request<AlertIdRequest>,
    ) -> Result<Response<AckAlertResponse>, Status> {
        Ok(Response::new(AckAlertResponse { success: true, error: String::new() }))
    }

    async fn set_server_config(
        &self,
        request: Request<ServerConfig>,
    ) -> Result<Response<SetConfigResponse>, Status> {
        let req = request.into_inner();
        let mut config = self.state.config.write().await;

        // Parse and validate the listen address
        let listen_addr: std::net::IpAddr = if req.listen_address.is_empty() {
            "0.0.0.0".parse().unwrap()
        } else {
            req.listen_address.parse().map_err(|_| {
                Status::invalid_argument("Invalid listen_address")
            })?
        };

        let server_subnet: ipnetwork::IpNetwork = if req.server_subnet.is_empty() {
            "10.8.0.0/24".parse().unwrap()
        } else {
            req.server_subnet.parse().map_err(|_| {
                Status::invalid_argument("Invalid server_subnet CIDR")
            })?
        };

        let dns_addr: std::net::IpAddr = if req.dns_server.is_empty() {
            "8.8.8.8".parse().unwrap()
        } else {
            req.dns_server.parse().map_err(|_| {
                Status::invalid_argument("Invalid dns_server")
            })?
        };

        let server_cfg = crate::config::ServerConfig {
            listen_addr,
            subnet: server_subnet,
            server_ip: "10.8.0.1".parse().unwrap(),
            dns: dns_addr,
            max_clients: req.max_clients as usize,
            nat_interface: if req.nat_interface.is_empty() { None } else { Some(req.nat_interface.clone()) },
            wireguard: if req.enable_wireguard {
                Some(crate::config::WireGuardServerConfig {
                    port: req.wireguard_port as u16,
                    private_key: String::new(), // generated separately
                    preshared_key: None,
                    mtu: if req.mtu == 0 { 1420 } else { req.mtu as u16 },
                    peers: vec![],
                })
            } else { None },
            openvpn: None,
            ipsec: None,
        };

        config.server = Some(server_cfg);
        info!("Server config updated via RPC");
        Ok(Response::new(SetConfigResponse { success: true, error: String::new() }))
    }

    async fn get_server_config(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<ServerConfig>, Status> {
        let config = self.state.config.read().await;

        let sc = config.server.as_ref().ok_or_else(|| {
            Status::not_found("Daemon is not running in server mode")
        })?;

        let wg_port = sc.wireguard.as_ref().map(|w| w.port as u32).unwrap_or(51820);
        let ovpn_port = sc.openvpn.as_ref().map(|o| o.port as u32).unwrap_or(1194);

        Ok(Response::new(ServerConfig {
            listen_address: sc.listen_addr.to_string(),
            wireguard_port: wg_port,
            openvpn_port: ovpn_port,
            ipsec_port: 500,
            server_subnet: sc.subnet.to_string(),
            dns_server: sc.dns.to_string(),
            max_clients: sc.max_clients as u32,
            enable_wireguard: sc.wireguard.is_some(),
            enable_openvpn: sc.openvpn.is_some(),
            enable_ipsec: sc.ipsec.is_some(),
            mtu: sc.wireguard.as_ref().map(|w| w.mtu as u32).unwrap_or(1420),
            nat_enabled: sc.nat_interface.is_some(),
            nat_interface: sc.nat_interface.clone().unwrap_or_default(),
        }))
    }
}

// ──────────────────────────────────────────────
// gRPC server startup
// ──────────────────────────────────────────────

/// Start the gRPC server on a Unix domain socket
pub async fn start_grpc_server(
    socket_path: &str,
    service: VpndService,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    use crate::ipc::peer_cred::{is_authorized, AuthDecision, AuthenticatedListener, PeerCred};

    if Path::new(socket_path).exists() {
        // Only remove if it is actually a socket, not a regular file or symlink
        // that may have been placed by an attacker to intercept the daemon.
        let meta = std::fs::symlink_metadata(socket_path)?;
        if meta.file_type().is_symlink() {
            return Err(anyhow::anyhow!(
                "Socket path '{}' is a symlink — refusing to remove it to prevent symlink attacks",
                socket_path
            ));
        }
        std::fs::remove_file(socket_path)?;
    }

    if let Some(parent) = Path::new(socket_path).parent() {
        std::fs::create_dir_all(parent)?;
        // Restrict the socket parent directory so only root can traverse it.
        // This hardens the brief window between bind() and set_permissions().
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(
                parent,
                std::fs::Permissions::from_mode(0o755),
            );
        }
    }

    // Set umask to 0o177 so the socket is created with permissions 0o600.
    // set_permissions() is called immediately after, but the umask prevents
    // a race window where the socket is temporarily world-accessible.
    #[cfg(unix)]
    let _prev_umask = {
        // SAFETY: umask() is always safe to call.
        unsafe { libc::umask(0o177) }
    };

    let listener = UnixListener::bind(socket_path)?;

    // Restore previous umask
    #[cfg(unix)]
    unsafe { libc::umask(_prev_umask) };

    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o660))?;

    // ── Snapshot the IPC policy under the read lock; releasing the guard
    //    before serve so requests don't fight for the config lock. ──────────
    let (allowed_uids, allowed_gids, audit_connections) = {
        let cfg = service.state.config.read().await;
        (
            cfg.ipc.allowed_uids.clone(),
            cfg.ipc.allowed_gids.clone(),
            cfg.ipc.audit_connections,
        )
    };
    let daemon_uid = unsafe { libc::geteuid() };

    info!(
        socket = %socket_path,
        daemon_uid,
        allowed_uids = ?allowed_uids,
        allowed_gids = ?allowed_gids,
        "gRPC server listening on Unix socket (SO_PEERCRED enforced)"
    );

    let incoming = AuthenticatedListener::new(listener, audit_connections);

    // ── Tonic interceptor: enforce SO_PEERCRED-based allow-list ────────────
    let interceptor = move |req: tonic::Request<()>| -> Result<tonic::Request<()>, Status> {
        let cred = req.extensions().get::<PeerCred>().copied().ok_or_else(|| {
            // This should never happen: AuthenticatedListener always injects PeerCred.
            // If it ever does, fail closed.
            warn!("IPC request with no peer credentials in extensions — rejecting");
            Status::permission_denied("missing peer credentials")
        })?;
        match is_authorized(&cred, daemon_uid, &allowed_uids, &allowed_gids) {
            AuthDecision::Allowed => Ok(req),
            AuthDecision::Denied(reason) => {
                warn!(
                    uid = cred.uid,
                    gid = cred.gid,
                    pid = cred.pid,
                    reason = %reason,
                    "IPC request denied by SO_PEERCRED policy"
                );
                Err(Status::permission_denied(format!(
                    "IPC access denied: {}",
                    reason
                )))
            }
        }
    };

    Server::builder()
        .add_service(VpndServiceServer::with_interceptor(service, interceptor))
        .serve_with_incoming_shutdown(incoming, async move {
            let _ = shutdown.changed().await;
            info!("gRPC server shutting down");
        })
        .await?;

    Ok(())
}

// ──────────────────────────────────────────────
// Helper functions
// ──────────────────────────────────────────────

fn sanitize_profile_name(name: &str) -> Result<String, Status> {
    if name.is_empty() {
        return Err(Status::invalid_argument("Profile name cannot be empty"));
    }
    if !name.chars().all(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | '.')) {
        return Err(Status::invalid_argument(
            "Profile name may only contain alphanumeric characters, hyphens, underscores, and dots",
        ));
    }
    if name.contains("..") || name.starts_with('.') {
        return Err(Status::invalid_argument("Invalid profile name"));
    }
    Ok(name.to_string())
}

fn profile_to_proto(p: crate::config::Profile) -> Profile {
    Profile {
        id: p.name.clone(),
        name: p.name,
        server_host: p.server_host,
        server_port: p.server_port as u32,
        protocol: 0, // WIREGUARD default
        username: p.username.unwrap_or_default(),
        password: String::new(),
        ca_cert: vec![],
        client_cert: vec![],
        client_key: vec![],
        wg_private_key: p.wg_private_key.map(|k| k.into_bytes()).unwrap_or_default(),
        wg_peer_pubkey: p.wg_peer_pubkey.map(|k| k.into_bytes()).unwrap_or_default(),
        wg_preshared_key: p.wg_preshared_key.unwrap_or_default(),
        wg_keepalive: 25,
        kill_switch: p.kill_switch,
        split_tunnel: p.split_tunnel,
        vpn_routes: p.vpn_routes,
        exclude_routes: vec![],
        dns_server: p.dns_server.unwrap_or_default(),
        ipv6_disabled: p.disable_ipv6,
        created_at: String::new(),
        updated_at: String::new(),
        auto_connect: false,
        mtu: 1420,
        wg_private_key_sealed: p.wg_private_key_sealed.unwrap_or_default(),
        // Never echo a passphrase back to clients — server is write-only for this field.
        passphrase: String::new(),
    }
}

fn parse_ping_avg_rtt(output: &str) -> Option<f32> {
    for line in output.lines() {
        if line.contains("rtt min/avg/max") {
            if let Some(stats) = line.split('=').nth(1) {
                let parts: Vec<&str> = stats.trim().split('/').collect();
                if parts.len() >= 2 {
                    return parts[1].trim().split(' ').next()?.parse().ok();
                }
            }
        }
    }
    None
}

fn extract_dns_servers(_nslookup_output: &str) -> Vec<String> {
    // Kept for compatibility; the DNS leak test no longer uses nslookup.
    vec![]
}

/// Read nameserver entries from /etc/resolv.conf.
fn read_resolv_conf_servers() -> Vec<String> {
    std::fs::read_to_string("/etc/resolv.conf")
        .unwrap_or_default()
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.starts_with("nameserver") {
                line.split_whitespace().nth(1).map(|s| s.to_string())
            } else {
                None
            }
        })
        .collect()
}

// ──────────────────────────────────────────────
// Profile parsers
// ──────────────────────────────────────────────

/// Parse a WireGuard .conf file into a Profile struct.
///
/// Example .conf:
/// ```text
/// [Interface]
/// PrivateKey = <base64>
/// Address    = 10.0.0.2/32
/// DNS        = 1.1.1.1
///
/// [Peer]
/// PublicKey  = <base64>
/// Endpoint   = vpn.example.com:51820
/// AllowedIPs = 0.0.0.0/0
/// PresharedKey = <base64>          # optional
/// ```
fn parse_wireguard_conf(
    text: &str,
    name_hint: &str,
) -> Result<crate::config::Profile, Status> {
    let mut private_key = None::<String>;
    let mut peer_pubkey = None::<String>;
    let mut preshared_key = None::<String>;
    let mut endpoint_host = String::new();
    let mut endpoint_port: u16 = 51820;
    let mut dns_server = None::<String>;
    let mut allowed_ips: Vec<String> = Vec::new();
    let mut address = None::<String>;

    let mut section = "";
    for raw_line in text.lines() {
        let line = match raw_line.find('#') {
            Some(p) => raw_line[..p].trim(),
            None => raw_line.trim(),
        };
        if line.is_empty() { continue; }

        if line.eq_ignore_ascii_case("[Interface]") { section = "interface"; continue; }
        if line.eq_ignore_ascii_case("[Peer]")      { section = "peer";      continue; }

        if let Some((k, v)) = line.split_once('=') {
            let key = k.trim().to_lowercase();
            let val = v.trim().to_string();
            match (section, key.as_str()) {
                ("interface", "privatekey") => private_key = Some(val),
                ("interface", "address")    => address = Some(val.split(',').next().unwrap_or("").trim().to_string()),
                ("interface", "dns")        => dns_server = Some(val.split(',').next().unwrap_or("").trim().to_string()),
                ("peer", "publickey")       => peer_pubkey = Some(val),
                ("peer", "presharedkey")    => preshared_key = Some(val),
                ("peer", "allowedips")      => {
                    for cidr in val.split(',') {
                        let c = cidr.trim().to_string();
                        if !c.is_empty() { allowed_ips.push(c); }
                    }
                }
                ("peer", "endpoint") => {
                    // endpoint may be host:port or [IPv6]:port
                    if let Some(pos) = val.rfind(':') {
                        endpoint_host = val[..pos].trim_matches('[').trim_matches(']').to_string();
                        endpoint_port = val[pos+1..].parse().unwrap_or(51820);
                    } else {
                        endpoint_host = val;
                    }
                }
                _ => {}
            }
        }
    }

    if endpoint_host.is_empty() {
        return Err(Status::invalid_argument(
            "WireGuard config missing [Peer] Endpoint",
        ));
    }

    // Derive a profile name: prefer name_hint, fallback to endpoint host
    let name = if name_hint.is_empty() {
        endpoint_host.replace('.', "-").replace(':', "-")
    } else {
        name_hint.to_string()
    };

    let vpn_routes: Vec<String> = if allowed_ips.iter().any(|r| r == "0.0.0.0/0") {
        vec![] // full tunnel — no split tunnel routes stored, RouteManager handles default route
    } else {
        allowed_ips
    };

    Ok(crate::config::Profile {
        name,
        protocol: "wireguard".into(),
        server_host: endpoint_host,
        server_port: endpoint_port,
        virtual_ip: address.and_then(|a| {
            let ip = a.split('/').next()?.to_string();
            Some(ip)
        }),
        wg_private_key: private_key,
        wg_private_key_sealed: None,
        wg_peer_pubkey: peer_pubkey,
        wg_preshared_key: preshared_key,
        username: None,
        password: None,
        ca_cert_path: None,
        client_cert_path: None,
        client_key_path: None,
        kill_switch: false,
        split_tunnel: !vpn_routes.is_empty(),
        vpn_routes,
        dns_server,
        disable_ipv6: false,
        wg_private_key_created_at: None,
        wg_preshared_key_created_at: None,
    })
}

/// Parse an OpenVPN .ovpn file into a Profile struct.
///
/// Handles the most common directives: remote, proto, verb, auth-user-pass,
/// inline certs (<ca>, <cert>, <key>), and tls-auth / tls-crypt.
fn parse_ovpn(text: &str, name_hint: &str) -> Result<crate::config::Profile, Status> {
    let mut server_host = String::new();
    let mut server_port: u16 = 1194;
    let mut username = None::<String>;
    let mut dns_server = None::<String>;

    // Collect inline embedded certs but we only store paths; for import we skip saving cert bytes
    // (they are embedded and don't map 1:1 to files without extraction).
    let mut has_inline_ca   = false;
    let mut has_inline_cert = false;
    let mut has_inline_key  = false;
    let mut in_block = "";

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') { continue; }

        // Inline block markers
        if trimmed.starts_with("<ca>")          { in_block = "ca";   has_inline_ca   = true; continue; }
        if trimmed.starts_with("</ca>")         { in_block = "";     continue; }
        if trimmed.starts_with("<cert>")        { in_block = "cert"; has_inline_cert = true; continue; }
        if trimmed.starts_with("</cert>")       { in_block = "";     continue; }
        if trimmed.starts_with("<key>")         { in_block = "key";  has_inline_key  = true; continue; }
        if trimmed.starts_with("</key>")        { in_block = "";     continue; }
        if trimmed.starts_with("<tls-auth>") || trimmed.starts_with("<tls-crypt>") { in_block = "tls"; continue; }
        if trimmed.starts_with("</tls-auth>") || trimmed.starts_with("</tls-crypt>") { in_block = ""; continue; }
        if !in_block.is_empty() { continue; } // skip inline cert data lines

        let parts: Vec<&str> = trimmed.splitn(4, char::is_whitespace).collect();
        let directive = parts[0].to_lowercase();

        match directive.as_str() {
            "remote" => {
                if let Some(host) = parts.get(1) {
                    server_host = host.to_string();
                }
                if let Some(port_str) = parts.get(2) {
                    server_port = port_str.parse().unwrap_or(1194);
                }
            }
            "dhcp-option" if parts.get(1).map(|s| s.eq_ignore_ascii_case("DNS")).unwrap_or(false) => {
                dns_server = parts.get(2).map(|s| s.to_string());
            }
            "auth-user-pass" => {
                // indicates username/password auth is needed
                username = Some(String::new()); // placeholder — user must fill in GUI
            }
            _ => {}
        }
    }

    let _ = (has_inline_ca, has_inline_cert, has_inline_key); // suppress unused warnings

    if server_host.is_empty() {
        return Err(Status::invalid_argument(
            "OpenVPN config missing 'remote' directive",
        ));
    }

    let name = if name_hint.is_empty() {
        server_host.replace('.', "-")
    } else {
        name_hint.to_string()
    };

    Ok(crate::config::Profile {
        name,
        protocol: "openvpn".into(),
        server_host,
        server_port,
        virtual_ip: None,
        wg_private_key: None,
        wg_private_key_sealed: None,
        wg_peer_pubkey: None,
        wg_preshared_key: None,
        username,
        password: None,
        ca_cert_path: None,    // inline certs not extracted to files
        client_cert_path: None,
        client_key_path: None,
        kill_switch: false,
        split_tunnel: false,
        vpn_routes: vec![],
        dns_server,
        disable_ipv6: false,
        wg_private_key_created_at: None,
        wg_preshared_key_created_at: None,
    })
}

#[cfg(test)]
mod parser_tests {
    use super::*;

    const WG_CONF: &str = r#"
[Interface]
PrivateKey = abcdef1234567890abcdef1234567890abcdef1234567890abcdef123456789A=
Address = 10.0.0.2/32
DNS = 10.0.0.1

[Peer]
PublicKey = XYZ1234567890abcdefXYZ1234567890abcdefXYZ1234567890abcdefXYZ12345=
AllowedIPs = 0.0.0.0/0
Endpoint = vpn.example.com:51820
PresharedKey = PSK1234567890abcdef1234567890abcdef1234567890abcdef1234567890abc=
    "#;

    const OVPN_CONF: &str = r#"
client
dev tun
proto udp
remote vpn.example.com 1194
resolv-retry infinite
nobind
auth-user-pass
dhcp-option DNS 10.8.0.1
<ca>
-----BEGIN CERTIFICATE-----
MIIBfake
-----END CERTIFICATE-----
</ca>
    "#;

    #[test]
    fn parse_wg_conf_basic() {
        let p = parse_wireguard_conf(WG_CONF, "test-wg").unwrap();
        assert_eq!(p.name, "test-wg");
        assert_eq!(p.server_host, "vpn.example.com");
        assert_eq!(p.server_port, 51820);
        assert_eq!(p.protocol, "wireguard");
        assert!(p.wg_private_key.is_some());
        assert!(p.wg_peer_pubkey.is_some());
        assert!(p.wg_preshared_key.is_some());
        assert_eq!(p.dns_server.as_deref(), Some("10.0.0.1"));
    }

    #[test]
    fn parse_wg_conf_infers_name_from_endpoint() {
        let p = parse_wireguard_conf(WG_CONF, "").unwrap();
        assert!(!p.name.is_empty());
        assert!(p.name.contains("vpn") || p.name.contains("example") || p.name.contains("com"));
    }

    #[test]
    fn parse_wg_missing_endpoint_errors() {
        let result = parse_wireguard_conf("[Interface]\nPrivateKey = abc=\n[Peer]\nPublicKey = xyz=\n", "");
        assert!(result.is_err());
    }

    #[test]
    fn parse_ovpn_basic() {
        let p = parse_ovpn(OVPN_CONF, "test-ovpn").unwrap();
        assert_eq!(p.name, "test-ovpn");
        assert_eq!(p.server_host, "vpn.example.com");
        assert_eq!(p.server_port, 1194);
        assert_eq!(p.protocol, "openvpn");
        assert!(p.username.is_some()); // auth-user-pass present
        assert_eq!(p.dns_server.as_deref(), Some("10.8.0.1"));
    }

    #[test]
    fn parse_ovpn_missing_remote_errors() {
        let result = parse_ovpn("client\ndev tun\n", "");
        assert!(result.is_err());
    }
}
