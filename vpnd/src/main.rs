// vpnd/src/main.rs
// VPNForge daemon entry point
//
// Usage:
//   vpnd --config /etc/vpnforge/server.toml --mode server
//   vpnd --config ~/.config/vpnforge/client.toml --mode client
//   vpnd --socket /tmp/vpnd.sock  (dev mode)

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{watch, RwLock};
use tracing::{error, info, warn};
use tracing_subscriber::{fmt, EnvFilter};

use vpnd::{
    config::{load_config, VpndConfig},
    ipc::grpc_server::{start_grpc_server, ConnectSignal, DaemonState, VpndService},
    metrics::collector::{MetricsCollector, MetricsCounters},
    metrics::system::CpuSampler,
    routing::{netlink::RouteManager, SplitTunnelPolicy},
    session::manager::SessionManager,
    IPC_SOCKET_PATH,
};

#[derive(Debug, Clone, Copy, ValueEnum)]
enum DaemonMode {
    Server,
    Client,
    Auto,
}

#[derive(Parser, Debug)]
#[command(
    name = "vpnd",
    version = env!("CARGO_PKG_VERSION"),
    about = "VPNForge Daemon — WireGuard/OpenVPN/IPsec VPN daemon",
    long_about = None,
)]
struct Args {
    /// Config file path (TOML format)
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Override IPC socket path (overrides config file value)
    #[arg(long)]
    socket: Option<String>,

    /// Operation mode
    #[arg(short, long, value_enum, default_value = "auto")]
    mode: DaemonMode,

    /// Enable verbose logging (sets RUST_LOG=debug)
    #[arg(short, long)]
    verbose: bool,

    /// Write structured JSON logs
    #[arg(long)]
    json_log: bool,

    /// Log file path (defaults to stdout)
    #[arg(long)]
    log_file: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    setup_logging(&args);

    // Resolve socket path: CLI flag > config > compile-time default.
    // (Config is loaded below; we display a placeholder until then.)
    info!(
        version = env!("CARGO_PKG_VERSION"),
        "VPNForge daemon starting"
    );

    // Load configuration
    let config_path = args.config.unwrap_or_else(|| {
        PathBuf::from("/etc/vpnforge/vpnd.toml")
    });

    let config = if config_path.exists() {
        load_config(&config_path)
            .with_context(|| format!("Failed to load config: {}", config_path.display()))?
    } else {
        info!(path = %config_path.display(), "Config file not found, using defaults");
        VpndConfig::default()
    };

    config.validate().context("Configuration validation failed")?;

    // Resolve effective socket path: CLI > config file > compile-time default.
    let socket_path = args.socket.unwrap_or_else(|| {
        config
            .daemon
            .socket_path
            .to_string_lossy()
            .into_owned()
    });
    info!(socket = %socket_path, version = env!("CARGO_PKG_VERSION"), "VPNForge daemon starting");

    let config = Arc::new(RwLock::new(config));

    // ──────────────────────────────────────────────
    // Process hardening (security)
    // ──────────────────────────────────────────────

    #[cfg(target_os = "linux")]
    harden_process();

    // Set up shared channels for IPC ↔ daemon communication
    let (connect_tx, connect_rx) = watch::channel::<ConnectSignal>(ConnectSignal::default());
    let (disconnect_tx, disconnect_rx) = watch::channel::<bool>(false);
    let (shutdown_tx, shutdown_rx) = watch::channel::<bool>(false);

    // Metrics
    let counters = MetricsCounters::new();
    let mut metrics_collector = MetricsCollector::new(
        counters.clone(),
        "none".into(),
        "none".into(),
    );
    let metrics_rx = metrics_collector.subscribe();

    // Session manager
    let session_manager = Arc::new(SessionManager::new());

    // Kill switch flag (cross-thread)
    let kill_switch_active = Arc::new(std::sync::atomic::AtomicBool::new(false));

    // Kill switch firewall manager (lazily initialised on first enable)
    let kill_switch = Arc::new(tokio::sync::Mutex::new(None::<vpnd::kill_switch::firewall::KillSwitch>));

    // CPU sampler for system health RPCs
    let cpu_sampler = Arc::new(parking_lot::Mutex::new(CpuSampler::new()));

    // ── Profile signing keypair ──────────────────────────────────────────────
    // Generate-and-persist on first run; load on subsequent runs.  Signing is
    // a *strong* default — a misconfigured filesystem ACL on the profiles
    // directory becomes a much smaller problem because the daemon will refuse
    // to honour any tampered-with profile.
    let signing_key: Option<Arc<ring::signature::Ed25519KeyPair>> = {
        let cfg_guard = config.read().await;
        let sec = cfg_guard.security.clone();
        drop(cfg_guard);
        match vpnd::crypto::profile_signing::load_or_generate_keypair(&sec.signing_key_path) {
            Ok(kp) => Some(Arc::new(kp)),
            Err(e) => {
                if sec.require_signed_profiles {
                    return Err(e.context(
                        "could not load or generate profile-signing key (set [security] require_signed_profiles = false to bypass)"
                    ));
                } else {
                    tracing::warn!(error = %e, "profile signing disabled (key unavailable)");
                    None
                }
            }
        }
    };

    // ── STUN privacy audit (Phase 2.7) ───────────────────────────────────
    // Default STUN servers (Google/Cloudflare) see your public IP every
    // time NAT discovery runs. Warn loudly so an operator who cares about
    // metadata exposure can override [network] stun_servers.
    {
        let cfg_guard = config.read().await;
        let (servers, used_defaults) = cfg_guard.network.effective_stun_servers();
        let suppress = cfg_guard.network.suppress_stun_privacy_warning;
        drop(cfg_guard);
        info!(servers = ?servers, used_defaults, "STUN servers configured");
        if used_defaults && !suppress {
            warn!(
                "STUN privacy notice: using built-in default STUN servers (Google, Cloudflare, Ekiga). \
                 Each NAT-discovery query reveals your public IP to those operators. \
                 To self-host or pick a privacy-respecting alternative, set [network] stun_servers in vpnd.toml. \
                 To silence this warning, set [network] suppress_stun_privacy_warning = true."
            );
        }
    }

    // Build gRPC service state
    let state = Arc::new(DaemonState {
        config: config.clone(),
        session_manager: session_manager.clone(),
        connect_tx,
        disconnect_tx: disconnect_tx.clone(),
        metrics_rx: metrics_rx.clone(),
        kill_switch_active: kill_switch_active.clone(),
        kill_switch,
        cpu_sampler,
        signing_key,
    });

    let service = VpndService::new(state.clone());

    // ── Start the encrypted-DNS proxy when `[client.dns] encrypted = true`
    //    so every plain-DNS query from the OS stub resolver flows through
    //    DoT and never leaks in cleartext.  This is fail-loud: if the proxy
    //    cannot bind, we abort startup rather than fall back to plaintext.
    let _dot_proxy: Option<vpnd::network::DotProxy> = {
        let cfg_guard = config.read().await;
        let enabled = cfg_guard
            .client
            .as_ref()
            .map(|c| c.dns.encrypted)
            .unwrap_or(false);
        if enabled {
            let dns_cfg = cfg_guard.client.as_ref().unwrap().dns.clone();
            drop(cfg_guard);
            let upstreams: Vec<vpnd::network::DotUpstream> = dns_cfg
                .dot_upstreams
                .iter()
                .map(|s| vpnd::network::DotUpstream::parse(s))
                .collect::<Result<_, _>>()
                .context("invalid DoT upstream in [client.dns]")?;
            let proxy = vpnd::network::start_dot_proxy(
                dns_cfg.listen,
                upstreams,
                dns_cfg.validate_dnssec,
            )
            .await
            .context("failed to start encrypted-DNS proxy")?;
            Some(proxy)
        } else {
            None
        }
    };

    // Set up signal handlers
    let shutdown_tx_ctrlc = shutdown_tx.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.expect("Failed to listen for Ctrl+C");
        info!("Shutdown signal received (SIGINT)");
        let _ = shutdown_tx_ctrlc.send(true);
    });

    #[cfg(unix)]
    {
        let shutdown_tx_sigterm = shutdown_tx.clone();
        tokio::spawn(async move {
            let mut sigterm = tokio::signal::unix::signal(
                tokio::signal::unix::SignalKind::terminate()
            ).expect("Failed to register SIGTERM handler");
            sigterm.recv().await;
            info!("Shutdown signal received (SIGTERM)");
            let _ = shutdown_tx_sigterm.send(true);
        });
    }

    // Metrics sampling loop
    let mut metrics_shutdown = shutdown_rx.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    metrics_collector.sample();
                }
                _ = metrics_shutdown.changed() => {
                    if *metrics_shutdown.borrow() {
                        break;
                    }
                }
            }
        }
    });

    // ──────────────────────────────────────────────
    // Idle-session reaper (Phase 2.9)
    // Periodically inspects every session and asks the daemon to disconnect
    // any that has had no traffic for `[security] session_timeout_secs`.
    // ──────────────────────────────────────────────
    {
        let cfg = config.clone();
        let sm = session_manager.clone();
        let disc = disconnect_tx.clone();
        let mut shutdown = shutdown_rx.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                tokio::select! {
                    _ = tick.tick() => {
                        let timeout_secs = cfg.read().await.security.session_timeout_secs;
                        if timeout_secs == 0 { continue; }
                        let timeout = std::time::Duration::from_secs(timeout_secs);
                        let expired = sm.expired_session_ids(timeout);
                        if !expired.is_empty() {
                            warn!(
                                count = expired.len(),
                                timeout_secs,
                                "Idle session(s) exceeded timeout — initiating disconnect"
                            );
                            for id in expired {
                                sm.disconnect(&id);
                            }
                            // Single disconnect pulse — handler tears the
                            // tunnel down for the active session.
                            let _ = disc.send(true);
                        }
                    }
                    _ = shutdown.changed() => { if *shutdown.borrow() { break; } }
                }
            }
        });
    }

    // ──────────────────────────────────────────────
    // VPN connection handler loop
    // Watches for profile-connect/disconnect signals from gRPC and runs the tunnel.
    // ──────────────────────────────────────────────
    {
        let config_arc = config.clone();
        let session_mgr = session_manager.clone();
        let mut connect_rx2 = connect_rx.clone();
        let mut disconnect_rx2 = disconnect_rx.clone();
        let mut shutdown_vpn = shutdown_rx.clone();
        // Pass a clone of the signing keypair into the connect loop so it can
        // verify profile signatures before they are loaded.
        let signing_key_for_verify = state.signing_key.clone();

        tokio::spawn(async move {
            // Active tunnel handle; dropped = tunnel stops
            let mut tunnel_handle: Option<tokio::task::JoinHandle<()>> = None;

            loop {
                tokio::select! {
                    _ = connect_rx2.changed() => {
                        let signal = connect_rx2.borrow().clone();
                        let profile_id = match signal.profile_id {
                            Some(id) => id,
                            None => continue,
                        };
                        let passphrase = signal.passphrase;

                        // Cancel any existing tunnel
                        if let Some(h) = tunnel_handle.take() {
                            h.abort();
                        }

                        let cfg = config_arc.read().await;
                        let default_client = vpnd::config::ClientConfig::default();
                        let client_cfg = cfg.client.as_ref().unwrap_or(&default_client);
                        let profiles_dir = client_cfg.profiles_dir.clone();
                        let require_signed = cfg.security.require_signed_profiles;
                        drop(cfg);

                        let profile_path = profiles_dir.join(format!("{profile_id}.toml"));
                        let content = match tokio::fs::read_to_string(&profile_path).await {
                            Ok(c) => c,
                            Err(e) => {
                                error!(profile_id = %profile_id, error = %e, "Profile file not found");
                                continue;
                            }
                        };

                        // ── Verify the profile's Ed25519 signature ──────────
                        // A profile that does not verify is treated as if it
                        // did not exist. This is what prevents an attacker who
                        // wrote into /etc/vpnforge/profiles/ from redirecting
                        // the user's traffic to a malicious endpoint.
                        if require_signed {
                            let pk = signing_key_for_verify
                                .as_ref()
                                .map(|kp| vpnd::crypto::profile_signing::public_key_bytes(kp.as_ref()));
                            match pk {
                                Some(pk_bytes) => {
                                    if let Err(e) = vpnd::crypto::profile_signing::verify_profile(&content, &pk_bytes) {
                                        error!(
                                            profile_id = %profile_id,
                                            error = %e,
                                            "REFUSING to connect — profile signature did not verify. \
                                             Either re-sign the profile or set [security] require_signed_profiles = false."
                                        );
                                        continue;
                                    }
                                }
                                None => {
                                    error!(
                                        "require_signed_profiles=true but no signing key is loaded — refusing to connect"
                                    );
                                    continue;
                                }
                            }
                        }

                        let profile: vpnd::config::Profile = match toml::from_str(&content) {
                            Ok(p) => p,
                            Err(e) => {
                                error!(profile_id = %profile_id, error = %e, "Failed to parse profile");
                                continue;
                            }
                        };

                        // ── Cryptographic hygiene warnings (Phase 2.5) ──────
                        //
                        // We never refuse to connect just because a key is
                        // old — that would lock the user out of their own
                        // VPN — but we do log loudly so the next time they
                        // glance at the journal they know to rotate.
                        const KEY_ROTATION_DAYS: i64 = 90;
                        if !profile.has_preshared_key() {
                            warn!(
                                profile = %profile.name,
                                "WireGuard preshared key (PSK) is MISSING. PSKs harden the handshake \
                                 against a future quantum-capable adversary; generate one with \
                                 `vpnctl rotate-keys {}` before relying on this tunnel for sensitive traffic.",
                                profile.name
                            );
                        } else if let Some(age) = profile.preshared_key_age_days() {
                            if age > KEY_ROTATION_DAYS {
                                warn!(
                                    profile = %profile.name,
                                    age_days = age,
                                    "WireGuard preshared key is older than {} days — consider rotating with `vpnctl rotate-keys {}`",
                                    KEY_ROTATION_DAYS, profile.name
                                );
                            }
                        }
                        if let Some(age) = profile.private_key_age_days() {
                            if age > KEY_ROTATION_DAYS {
                                warn!(
                                    profile = %profile.name,
                                    age_days = age,
                                    "WireGuard static private key is older than {} days — consider rotating",
                                    KEY_ROTATION_DAYS
                                );
                            }
                        }

                        info!(
                            profile = %profile.name,
                            protocol = %profile.protocol,
                            host = %profile.server_host,
                            "Starting VPN connection",
                        );

                        let sm = session_mgr.clone();

                        tunnel_handle = Some(tokio::spawn(async move {
                            if let Err(e) = run_tunnel(profile, sm, passphrase).await {
                                error!("Tunnel error: {}", e);
                            }
                        }));
                    }

                    _ = disconnect_rx2.changed() => {
                        if *disconnect_rx2.borrow() {
                            info!("Disconnect requested — stopping active tunnel");
                            if let Some(h) = tunnel_handle.take() {
                                h.abort();
                            }
                        }
                    }

                    _ = shutdown_vpn.changed() => {
                        if *shutdown_vpn.borrow() {
                            if let Some(h) = tunnel_handle.take() {
                                h.abort();
                            }
                            break;
                        }
                    }
                }
            }
        });
    }

    // Start gRPC server (blocks until shutdown)
    info!(socket = %socket_path, "Starting gRPC server");
    start_grpc_server(&socket_path, service, shutdown_rx)
        .await
        .context("gRPC server failed")?;

    info!("VPNForge daemon stopped");
    Ok(())
}

fn setup_logging(args: &Args) {
    let filter = if args.verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::from_default_env()
            .add_directive("vpnd=info".parse().unwrap())
    };

    if args.json_log {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(true)
            .with_file(true)
            .with_line_number(true)
            .init();
    }
}

/// Apply OS-level process hardening for security.
///
/// Must be called early in main(), before any connection handling:
/// - Disable core dumps to prevent key material from being written to disk.
/// - Lock current+future memory pages (mlock) so keys are never swapped out.
/// - Set PR_SET_NO_NEW_PRIVS so no child process can gain elevated privileges.
#[cfg(target_os = "linux")]
fn harden_process() {
    use nix::sys::prctl;

    // Prevent core dumps — a core file would expose in-memory keys
    if let Err(e) = prctl::set_dumpable(false) {
        tracing::warn!(error = %e, "Failed to disable core dumps (prctl PR_SET_DUMPABLE)");
    } else {
        tracing::debug!("Core dumps disabled");
    }

    // PR_SET_NO_NEW_PRIVS: this process and its children can never gain new privileges
    // (e.g. via setuid binary execution)
    if let Err(e) = prctl::set_no_new_privs() {
        tracing::warn!(error = %e, "Failed to set PR_SET_NO_NEW_PRIVS");
    } else {
        tracing::debug!("PR_SET_NO_NEW_PRIVS set");
    }

    // Lock all current and future memory pages — prevents keys from being swapped to disk.
    // Requires CAP_IPC_LOCK (granted via systemd's LimitMEMLOCK=infinity or AmbientCapabilities).
    #[cfg(target_os = "linux")]
    unsafe {
        // MCL_CURRENT | MCL_FUTURE = 3
        if libc::mlockall(3) != 0 {
            tracing::warn!("mlockall failed — memory may be swapped (need CAP_IPC_LOCK or LimitMEMLOCK)");
        } else {
            tracing::debug!("Memory pages locked (mlockall MCL_CURRENT|MCL_FUTURE)");
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// run_tunnel — establishes a VPN connection for the given profile
//
// For WireGuard profiles:
//   1. Creates a TUN interface
//   2. Creates the WireGuard tunnel (boringtun Noise session)
//   3. If split_tunnel=true, applies SplitTunnelPolicy routes
//   4. Runs the packet-processing loop until the task is aborted
// ──────────────────────────────────────────────────────────────────────────────
async fn run_tunnel(
    profile: vpnd::config::Profile,
    _session_mgr: Arc<SessionManager>,
    passphrase: Option<std::sync::Arc<zeroize::Zeroizing<Vec<u8>>>>,
) -> Result<()> {
    use vpnd::tunnel::tuntap::{TunDevice, netmask_from_prefix};

    match profile.protocol.as_str() {
        "wireguard" => {
            use vpnd::tunnel::wireguard::WireGuardTunnel;
            use vpnd::crypto::WireGuardKeyPair;
            use std::net::SocketAddr;

            // Resolve the WireGuard private key, decrypting the sealed envelope
            // when the profile uses at-rest encryption.
            let private_key = profile
                .resolve_wg_private_key(|| {
                    let pass = passphrase.as_ref().ok_or_else(|| {
                        anyhow::anyhow!(
                            "profile '{}' has a sealed private key but no passphrase was provided",
                            profile.name
                        )
                    })?;
                    // Clone the bytes into a fresh Zeroizing buffer.
                    Ok(zeroize::Zeroizing::new(pass.as_slice().to_vec()))
                })
                .context("Failed to resolve WireGuard private key")?;
            let private_key_b64: &str = private_key.as_str();

            let peer_pubkey_b64 = profile
                .wg_peer_pubkey
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("WireGuard profile missing peer PublicKey"))?;

            let endpoint: SocketAddr = format!("{}:{}", profile.server_host, profile.server_port)
                .parse()
                .context("Invalid server endpoint")?;

            let virtual_ip: std::net::Ipv4Addr = profile
                .virtual_ip
                .as_deref()
                .unwrap_or("10.0.0.2")
                .parse()
                .context("Invalid virtual IP")?;

            let tun_name = format!("wg-vpnf{}", profile.server_port % 1000);

            let key_pair = WireGuardKeyPair::from_private_key_base64(private_key_b64)
                .context("Failed to load WireGuard private key")?;

            // Create TUN interface (10.x.x.x/32 → full peer model)
            let tun = TunDevice::create(
                &tun_name,
                virtual_ip,
                netmask_from_prefix(32),
                1420, // WireGuard MTU
            )
            .context("Failed to create TUN device")?;

            // Obtain the interface index for routing
            let tun_if_index: u32 = {
                let name_cstr = std::ffi::CString::new(tun_name.as_bytes())
                    .context("Invalid TUN interface name")?;
                let idx = unsafe { libc::if_nametoindex(name_cstr.as_ptr()) };
                if idx == 0 {
                    return Err(anyhow::anyhow!("Could not resolve interface index for {tun_name}"));
                }
                idx
            };

            info!(
                tun   = %tun_name,
                if_id = tun_if_index,
                vip   = %virtual_ip,
                peer  = %endpoint,
                "TUN interface created",
            );

            // Apply split-tunnel routing if requested
            if profile.split_tunnel && !profile.vpn_routes.is_empty() {
                let policy = SplitTunnelPolicy::from_strings(&profile.vpn_routes, &[])
                    .context("Failed to build split-tunnel policy")?;
                let mut route_mgr = RouteManager::new().await
                    .context("Failed to create RouteManager")?;
                policy.apply(&mut route_mgr, tun_if_index).await
                    .context("Failed to apply split-tunnel routes")?;
                info!(
                    routes = %profile.vpn_routes.join(", "),
                    "Split-tunnel routes applied",
                );
            }

            // Build and run the WireGuard tunnel
            let tunnel = WireGuardTunnel::new(
                &key_pair,
                peer_pubkey_b64,
                profile.wg_preshared_key.as_deref(),
                endpoint,
                virtual_ip,
                Some(25), // keepalive 25 s
                &tun_name,
            )
            .await
            .context("Failed to initialize WireGuard tunnel")?;

            let (metrics_tx, _metrics_rx) = tokio::sync::mpsc::channel(64);
            tunnel.run(tun, metrics_tx).await
                .context("WireGuard tunnel exited with error")?;
        }

        proto => {
            warn!(protocol = %proto, "Protocol not yet supported in run_tunnel; connection stub only");
        }
    }

    Ok(())
}
