// vpnctl/src/main.rs
//
// VPNForge CLI — professional terminal interface for the vpnd daemon.
//
// Usage examples:
//   vpnctl connect home-server
//   vpnctl status
//   vpnctl monitor
//   vpnctl profile add
//   vpnctl profile import ~/vpn.conf
//   vpnctl test dns
//   vpnctl completion bash >> ~/.bashrc

use anyhow::{bail, Context, Result};
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::{generate, Shell};
use colored::Colorize;
use crossterm::{
    cursor, execute,
    terminal::{Clear, ClearType},
};
use dialoguer::{theme::ColorfulTheme, Confirm, Input, Password, Select};
use indicatif::{ProgressBar, ProgressStyle};
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::Duration;
use tokio::net::UnixStream;
use tokio_stream::StreamExt;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

pub mod proto {
    tonic::include_proto!("vpnd");
}

use proto::vpnd_service_client::VpndServiceClient;
use proto::*;

// ─────────────────────────────────────────────────────────────────────────────
//  Constants
// ─────────────────────────────────────────────────────────────────────────────

const DEFAULT_SOCKET: &str = "/run/vpnd/control.sock";
const DEV_SOCKET: &str = "/tmp/vpnd.sock";

// ─────────────────────────────────────────────────────────────────────────────
//  CLI definition
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "vpnctl",
    version,
    about = "VPNForge — control your VPN daemon from the terminal",
    long_about = concat!(
        "VPNForge Control Tool\n\n",
        "Communicates with the vpnd daemon over a Unix socket.\n",
        "Run `sudo vpnd` first to start the daemon.\n\n",
        "Socket path: /run/vpnd/control.sock (or set VPND_SOCKET)"
    ),
    after_help = "TIP: Run `vpnctl completion bash >> ~/.bashrc` for tab-completion."
)]
struct Cli {
    /// IPC socket path (daemon must be running)
    #[arg(long, default_value = DEFAULT_SOCKET, env = "VPND_SOCKET", global = true)]
    socket: String,

    /// Output as JSON (machine-readable)
    #[arg(long, short = 'j', global = true)]
    json: bool,

    /// Suppress all non-essential output
    #[arg(long, short = 'q', global = true)]
    quiet: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Connect to a VPN profile
    #[command(visible_alias = "c")]
    Connect {
        /// Profile name to connect with
        profile: String,
        /// Disconnect any existing connection first
        #[arg(long)]
        force: bool,
        /// Read the unlock passphrase from stdin (one line) instead of prompting on the TTY.
        /// Useful for unattended setups (e.g. systemd LoadCredentialEncrypted).
        #[arg(long)]
        passphrase_stdin: bool,
    },

    /// Disconnect from VPN
    #[command(visible_alias = "d")]
    Disconnect {
        /// Profile ID to disconnect (empty = all)
        #[arg(default_value = "")]
        profile: String,
    },

    /// Show current connection status
    #[command(visible_alias = "s")]
    Status,

    /// Live connection monitor — streaming metrics dashboard
    #[command(visible_alias = "m")]
    Monitor,

    /// Profile management
    #[command(visible_alias = "p")]
    Profile {
        #[command(subcommand)]
        action: ProfileAction,
    },

    /// Run diagnostics
    Test {
        #[command(subcommand)]
        test: TestKind,
    },

    /// ICMP ping through the VPN tunnel
    Ping {
        /// Destination host or IP
        target: String,
        /// Number of pings to send
        #[arg(short = 'n', long, default_value = "5")]
        count: u32,
    },

    /// Show current routing table
    Routes,

    /// Kill switch management
    KillSwitch {
        #[command(subcommand)]
        action: KillSwitchAction,
    },

    /// Check daemon health
    Health,

    /// Generate a WireGuard keypair (no daemon needed)
    Keygen,

    /// Rotate the WireGuard preshared key (and optionally the static keypair) of a profile.
    ///
    /// Always rotates the PSK. Pass --rotate-keypair to also generate a fresh
    /// static keypair (the new public key will be printed and MUST be added to
    /// the server before the next connect attempt).
    RotateKeys {
        /// Profile name
        profile: String,
        /// Also generate a new static WireGuard keypair (requires server-side update)
        #[arg(long)]
        rotate_keypair: bool,
        /// Read the seal passphrase from stdin (one line) instead of prompting
        #[arg(long)]
        passphrase_stdin: bool,
    },

    /// Generate shell completion script
    Completion {
        /// Target shell
        #[arg(value_enum)]
        shell: Shell,
    },
}

#[derive(Subcommand)]
enum ProfileAction {
    /// List all saved profiles
    #[command(visible_alias = "ls")]
    List,
    /// Show profile details
    Show { name: String },
    /// Add a new profile interactively
    Add,
    /// Import a WireGuard .conf or OpenVPN .ovpn file
    Import {
        /// Path to the .conf/.ovpn file
        file: PathBuf,
        /// Override profile name
        #[arg(long)]
        name: Option<String>,
    },
    /// Delete a profile
    #[command(visible_alias = "rm")]
    Delete { name: String },
}

#[derive(Subcommand)]
enum TestKind {
    /// DNS leak test — checks if DNS queries leave the VPN tunnel
    Dns,
    /// IP leak test — verifies your public IP routes through VPN (STUN)
    Ip,
    /// Run all tests at once
    All,
}

#[derive(Subcommand)]
enum KillSwitchAction {
    /// Enable kill switch — block all traffic if VPN drops
    On,
    /// Disable kill switch
    Off,
    /// Show kill switch status
    Status,
}

// ─────────────────────────────────────────────────────────────────────────────
//  Entry point
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Shell completion is offline — no daemon needed
    if let Commands::Completion { shell } = &cli.command {
        generate(*shell, &mut Cli::command(), "vpnctl", &mut io::stdout());
        return Ok(());
    }

    // Keygen is also offline
    if let Commands::Keygen = &cli.command {
        cmd_keygen();
        return Ok(());
    }

    // Profile add / import can give better error messages before connecting
    let channel = connect_to_daemon(&cli.socket).await?;
    let mut client = VpndServiceClient::new(channel);

    match cli.command {
        Commands::Connect { profile, force, passphrase_stdin } => {
            cmd_connect(&mut client, &profile, force, passphrase_stdin, cli.quiet).await?
        }
        Commands::Disconnect { profile } => {
            cmd_disconnect(&mut client, &profile, cli.quiet).await?
        }
        Commands::Status => cmd_status(&mut client, cli.json).await?,
        Commands::Monitor => cmd_monitor(&mut client).await?,
        Commands::Profile { action } => {
            cmd_profile(&mut client, action, cli.quiet).await?
        }
        Commands::Test { test } => cmd_test(&mut client, test, cli.json).await?,
        Commands::Ping { target, count } => {
            cmd_ping(&mut client, &target, count).await?
        }
        Commands::Routes => cmd_routes(&mut client, cli.json).await?,
        Commands::KillSwitch { action } => {
            cmd_kill_switch(&mut client, action, cli.quiet).await?
        }
        Commands::Health => cmd_health(&mut client, cli.json).await?,
        Commands::RotateKeys { profile, rotate_keypair, passphrase_stdin } => {
            cmd_rotate_keys(&mut client, &profile, rotate_keypair, passphrase_stdin, cli.quiet).await?
        }
        Commands::Keygen | Commands::Completion { .. } => unreachable!(),
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
//  Commands
// ─────────────────────────────────────────────────────────────────────────────

async fn cmd_connect(
    client: &mut VpndServiceClient<Channel>,
    profile: &str,
    force: bool,
    passphrase_stdin: bool,
    quiet: bool,
) -> Result<()> {
    // ── Fetch profile metadata so we know whether a passphrase is required ──
    // We only prompt the user when the profile actually carries a sealed key.
    let profile_meta = client
        .get_profile(ProfileIdRequest { id: profile.to_string() })
        .await
        .map(|r| r.into_inner())
        .ok();

    let needs_passphrase = profile_meta
        .as_ref()
        .map(|p| !p.wg_private_key_sealed.is_empty())
        .unwrap_or(false);

    let passphrase = if needs_passphrase {
        if passphrase_stdin {
            // Read a single line from stdin without echo control.
            let mut buf = String::new();
            std::io::stdin().read_line(&mut buf)
                .context("failed to read passphrase from stdin")?;
            buf.trim_end_matches(['\n', '\r']).to_string()
        } else {
            Password::with_theme(&ColorfulTheme::default())
                .with_prompt(format!("Passphrase for profile '{}'", profile))
                .interact()
                .context("failed to read passphrase")?
        }
    } else {
        String::new()
    };

    let pb = if !quiet {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"])
                .template("{spinner:.cyan} {msg}")?,
        );
        pb.set_message(format!("Connecting to profile '{}'…", profile.cyan()));
        pb.enable_steady_tick(Duration::from_millis(80));
        Some(pb)
    } else {
        None
    };

    let r = client
        .connect_vpn(ConnectRequest {
            profile_id: profile.to_string(),
            force,
            passphrase: passphrase.clone(),
        })
        .await
        .context("ConnectVpn RPC failed")?
        .into_inner();

    // Best-effort wipe of the local copy of the passphrase
    {
        use zeroize::Zeroize;
        let mut buf = passphrase.into_bytes();
        buf.zeroize();
    }

    if let Some(pb) = pb {
        pb.finish_and_clear();
    }

    if r.success {
        println!(
            "{} Connected  {}  {}  {}",
            "●".green(),
            format!("ip={}", r.virtual_ip).bold(),
            format!("server={}", r.server_ip).dimmed(),
            r.protocol.yellow()
        );
    } else {
        eprintln!("{} {}", "✗".red().bold(), r.error.red());
        std::process::exit(1);
    }
    Ok(())
}

async fn cmd_disconnect(
    client: &mut VpndServiceClient<Channel>,
    profile: &str,
    quiet: bool,
) -> Result<()> {
    let pb = if !quiet {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"])
                .template("{spinner:.yellow} {msg}")?,
        );
        pb.set_message("Disconnecting…".to_string());
        pb.enable_steady_tick(Duration::from_millis(80));
        Some(pb)
    } else {
        None
    };

    let r = client
        .disconnect(DisconnectRequest {
            profile_id: profile.to_string(),
        })
        .await
        .context("Disconnect RPC failed")?
        .into_inner();

    if let Some(pb) = pb {
        pb.finish_and_clear();
    }

    if r.success {
        println!("{} Disconnected", "●".dimmed());
    } else {
        eprintln!("{} {}", "✗".red().bold(), r.error.red());
        std::process::exit(1);
    }
    Ok(())
}

async fn cmd_status(
    client: &mut VpndServiceClient<Channel>,
    json_out: bool,
) -> Result<()> {
    let s = client
        .get_status(Empty {})
        .await
        .context("GetStatus failed")?
        .into_inner();

    if json_out {
        // Emit raw protobuf fields as JSON
        println!("{}", serde_json::json!({
            "state": s.state,
            "profile_id": s.profile_id,
            "profile_name": s.profile_name,
            "virtual_ip": s.virtual_ip,
            "server_ip": s.server_ip,
            "protocol": s.protocol,
            "kill_switch_active": s.kill_switch_active,
            "connected_since": s.connected_since,
            "handshake_ms": s.handshake_ms,
        }));
        return Ok(());
    }

    let (bullet, state_label) = match s.state {
        1 => ("◕".yellow().to_string(), "Connecting".yellow().to_string()),
        2 => ("●".green().to_string(), "Connected".green().bold().to_string()),
        3 => ("◑".yellow().to_string(), "Reconnecting".yellow().to_string()),
        4 => ("◔".yellow().to_string(), "Disconnecting".yellow().to_string()),
        5 => ("●".red().to_string(), "Error".red().bold().to_string()),
        _ => ("○".dimmed().to_string(), "Disconnected".dimmed().to_string()),
    };

    println!("{} {}", bullet, state_label);

    if s.state >= 1 && s.state <= 3 {
        println!("  {:<16} {}", "Profile:".dimmed(), s.profile_name.bold());
        println!("  {:<16} {}", "Protocol:".dimmed(), s.protocol.cyan());
        println!("  {:<16} {}", "Server:".dimmed(), s.server_ip);
        println!("  {:<16} {}", "Virtual IP:".dimmed(), s.virtual_ip.yellow());
        if s.connected_since > 0 {
            let elapsed = (chrono::Utc::now().timestamp_millis() - s.connected_since).max(0);
            println!("  {:<16} {}", "Uptime:".dimmed(), format_duration(elapsed as u64 / 1000));
        }
        if s.handshake_ms > 0.0 {
            println!("  {:<16} {:.0} ms", "Last handshake:".dimmed(), s.handshake_ms);
        }
        println!(
            "  {:<16} {}",
            "Kill switch:".dimmed(),
            if s.kill_switch_active {
                "ACTIVE".green().bold().to_string()
            } else {
                "off".dimmed().to_string()
            }
        );
    }
    Ok(())
}

async fn cmd_monitor(client: &mut VpndServiceClient<Channel>) -> Result<()> {
    use std::io::Write;

    // Get initial status
    let s = client.get_status(Empty {}).await?.into_inner();
    if s.state != 2 {
        bail!(
            "VPN is not connected (state={}). Connect first with: {}",
            s.state,
            "vpnctl connect <profile>".cyan()
        );
    }

    // Subscribe to metrics stream
    let mut stream = client.stream_metrics(Empty {}).await?.into_inner();

    // Hide cursor for clean display
    let mut stdout = io::stdout();
    execute!(stdout, cursor::Hide)?;

    // Catch Ctrl-C to restore cursor
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    ctrlc::set_handler(move || {
        let _ = shutdown_tx.send(true);
    })
    .ok();

    println!(
        "\n  {} {} — Live Monitor  {}",
        "●".green(),
        s.profile_name.bold(),
        "(Ctrl+C to exit)".dimmed()
    );
    println!(
        "  {} on {} via {}",
        s.virtual_ip.yellow(),
        s.server_ip.dimmed(),
        s.protocol.cyan()
    );
    println!("{}", "─".repeat(60).dimmed());

    let header_pos = crossterm::cursor::position().unwrap_or((0, 5));
    let base_row = header_pos.1 + 1;
    let mut last_rx_total: i64 = 0;
    let mut last_tx_total: i64 = 0;

    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => break,
            item = stream.next() => {
                match item {
                    None => break,
                    Some(Err(e)) => {
                        execute!(stdout, cursor::Show)?;
                        bail!("Metrics stream error: {}", e);
                    }
                    Some(Ok(m)) => {
                        execute!(stdout, cursor::MoveTo(0, base_row))?;
                        execute!(stdout, Clear(ClearType::FromCursorDown))?;

                        let rx_bar = sparkline(m.rx_bytes_per_sec, 20_000_000);
                        let tx_bar = sparkline(m.tx_bytes_per_sec, 20_000_000);

                        println!(
                            "  {} {:>12}/s  {}",
                            "▼ RX:".green(),
                            format_bytes_rate(m.rx_bytes_per_sec),
                            rx_bar.green()
                        );
                        println!(
                            "  {} {:>12}/s  {}",
                            "▲ TX:".cyan(),
                            format_bytes_rate(m.tx_bytes_per_sec),
                            tx_bar.cyan()
                        );
                        println!(
                            "  {} {:>8.1} ms   {} {:.1}%",
                            "⏱ Latency:".dimmed(),
                            m.latency_ms,
                            "Loss:".dimmed(),
                            m.packet_loss_pct
                        );

                        if last_rx_total > 0 {
                            println!(
                                "  {} {}  {} {}",
                                "Total RX:".dimmed(),
                                format_bytes(m.rx_bytes_total).yellow(),
                                "Total TX:".dimmed(),
                                format_bytes(m.tx_bytes_total).cyan()
                            );
                        }
                        last_rx_total = m.rx_bytes_total;
                        last_tx_total = m.tx_bytes_total;

                        stdout.flush()?;
                    }
                }
            }
        }
    }

    execute!(stdout, cursor::Show)?;
    println!("\n{}", "Monitor stopped.".dimmed());
    Ok(())
}

async fn cmd_profile(
    client: &mut VpndServiceClient<Channel>,
    action: ProfileAction,
    quiet: bool,
) -> Result<()> {
    match action {
        ProfileAction::List => {
            let profiles = client
                .list_profiles(Empty {})
                .await
                .context("ListProfiles failed")?
                .into_inner()
                .profiles;

            if profiles.is_empty() {
                println!("{}", "No profiles saved. Add one with: vpnctl profile add".dimmed());
                return Ok(());
            }

            // Table header
            let w_name = profiles.iter().map(|p| p.name.len()).max().unwrap_or(8).max(8) + 2;
            let divider = format!(
                "  {}  {}  {}",
                "─".repeat(w_name),
                "─".repeat(12),
                "─".repeat(28)
            );

            println!("{}", divider.dimmed());
            println!(
                "  {:<w$}  {:<12}  {}",
                "NAME".bold(),
                "PROTOCOL".bold(),
                "SERVER".bold(),
                w = w_name
            );
            println!("{}", divider.dimmed());

            for p in &profiles {
                let proto_str = match p.protocol {
                    1 => "OpenVPN".cyan().to_string(),
                    2 => "IPsec/IKEv2".cyan().to_string(),
                    _ => "WireGuard".green().to_string(),
                };
                println!(
                    "  {:<w$}  {:<21}  {}:{}",
                    p.name,
                    proto_str,
                    p.server_host,
                    p.server_port,
                    w = w_name
                );
            }
            println!("{}", divider.dimmed());
            println!("  {} profile(s)", profiles.len().to_string().bold());
        }

        ProfileAction::Show { name } => {
            let p = client
                .get_profile(ProfileIdRequest { id: name.clone() })
                .await
                .with_context(|| format!("Profile '{}' not found", name))?
                .into_inner();

            let proto_str = match p.protocol {
                1 => "OpenVPN",
                2 => "IPsec/IKEv2",
                _ => "WireGuard",
            };

            println!("{}", format!("  Profile: {}", p.name).bold());
            println!("  {:<20} {}", "Protocol:".dimmed(), proto_str.cyan());
            println!("  {:<20} {}:{}", "Server:".dimmed(), p.server_host, p.server_port);
            println!("  {:<20} {}", "MTU:".dimmed(), if p.mtu == 0 { "auto".to_string() } else { p.mtu.to_string() });
            println!("  {:<20} {}", "Kill switch:".dimmed(), bool_indicator(p.kill_switch));
            println!("  {:<20} {}", "Split tunnel:".dimmed(), bool_indicator(p.split_tunnel));
            println!("  {:<20} {}", "IPv6 disabled:".dimmed(), bool_indicator(p.ipv6_disabled));
            if !p.dns_server.is_empty() {
                println!("  {:<20} {}", "DNS server:".dimmed(), p.dns_server);
            }
            if !p.vpn_routes.is_empty() {
                println!("  {:<20} {}", "VPN routes:".dimmed(), p.vpn_routes.join(", "));
            }
            if p.protocol == 0 {
                // WireGuard
                if !p.wg_peer_pubkey.is_empty() {
                    let pk = base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &p.wg_peer_pubkey,
                    );
                    println!("  {:<20} {}", "Peer pubkey:".dimmed(), pk);
                }
                println!("  {:<20} {}", "Keepalive:".dimmed(), format!("{}s", p.wg_keepalive));
            }
        }

        ProfileAction::Add => {
            cmd_profile_add(client, quiet).await?;
        }

        ProfileAction::Import { file, name } => {
            cmd_profile_import(client, &file, name.as_deref(), quiet).await?;
        }

        ProfileAction::Delete { name } => {
            if !quiet {
                let confirm = Confirm::with_theme(&ColorfulTheme::default())
                    .with_prompt(format!("Delete profile '{}'?", name.red()))
                    .default(false)
                    .interact()?;
                if !confirm {
                    println!("{}", "Cancelled.".dimmed());
                    return Ok(());
                }
            }

            let r = client
                .delete_profile(ProfileIdRequest { id: name.clone() })
                .await
                .context("DeleteProfile failed")?
                .into_inner();

            if r.success {
                println!("{} Profile '{}' deleted.", "✓".green(), name.bold());
            } else {
                bail!("{}", r.error);
            }
        }
    }
    Ok(())
}

/// Interactive wizard to create a new VPN profile
async fn cmd_profile_add(
    client: &mut VpndServiceClient<Channel>,
    _quiet: bool,
) -> Result<()> {
    let theme = ColorfulTheme::default();
    println!("\n  {} New VPN Profile\n", "✦".cyan().bold());

    let name: String = Input::with_theme(&theme)
        .with_prompt("Profile name")
        .validate_with(|s: &String| {
            if s.chars().all(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | '.')) && !s.is_empty() {
                Ok(())
            } else {
                Err("Only letters, numbers, -, _, . allowed")
            }
        })
        .interact_text()?;

    let proto_choices = &["WireGuard", "OpenVPN", "IPsec/IKEv2"];
    let proto_idx = Select::with_theme(&theme)
        .with_prompt("Protocol")
        .items(proto_choices)
        .default(0)
        .interact()?;

    let server_host: String = Input::with_theme(&theme)
        .with_prompt("Server hostname or IP")
        .interact_text()?;

    let default_port = match proto_idx { 1 => 1194u16, 2 => 500, _ => 51820 };
    let server_port_str: String = Input::with_theme(&theme)
        .with_prompt("Server port")
        .default(default_port.to_string())
        .interact_text()?;
    let server_port: u32 = server_port_str.parse().context("Invalid port number")?;

    let kill_switch = Confirm::with_theme(&theme)
        .with_prompt("Enable kill switch?")
        .default(true)
        .interact()?;

    // WireGuard-specific fields
    let (wg_private_key, wg_peer_pubkey) = if proto_idx == 0 {
        let priv_key: String = Password::with_theme(&theme)
            .with_prompt("WireGuard private key (base64)")
            .allow_empty_password(true)
            .interact()?;
        let peer_key: String = Input::with_theme(&theme)
            .with_prompt("WireGuard peer public key (base64)")
            .allow_empty(true)
            .interact_text()?;
        (priv_key.into_bytes(), peer_key.into_bytes())
    } else {
        (vec![], vec![])
    };

    let dns: String = Input::with_theme(&theme)
        .with_prompt("DNS server (empty = keep default)")
        .allow_empty(true)
        .interact_text()?;

    let profile = Profile {
        id: name.clone(),
        name: name.clone(),
        server_host,
        server_port,
        protocol: proto_idx as i32,
        username: String::new(),
        password: String::new(),
        ca_cert: vec![],
        client_cert: vec![],
        client_key: vec![],
        wg_private_key,
        wg_private_key_sealed: String::new(),
        wg_peer_pubkey,
        wg_preshared_key: String::new(),
        wg_keepalive: 25,
        kill_switch,
        split_tunnel: false,
        vpn_routes: vec![],
        exclude_routes: vec![],
        dns_server: dns,
        ipv6_disabled: false,
        created_at: String::new(),
        updated_at: String::new(),
        auto_connect: false,
        mtu: 0,
        passphrase: String::new(),
    };

    let r = client
        .save_profile(profile)
        .await
        .context("SaveProfile failed")?
        .into_inner();

    if r.success {
        println!("\n{} Profile '{}' saved.", "✓".green(), name.bold());
        println!("  Connect with: {}", format!("vpnctl connect {}", name).cyan());
    } else {
        bail!("{}", r.error);
    }
    Ok(())
}

/// Import a WireGuard .conf or OpenVPN .ovpn file
async fn cmd_profile_import(
    client: &mut VpndServiceClient<Channel>,
    file: &PathBuf,
    name_override: Option<&str>,
    _quiet: bool,
) -> Result<()> {
    let content = std::fs::read(file)
        .with_context(|| format!("Cannot read file '{}'", file.display()))?;

    let ext = file
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    let format = match ext.as_str() {
        "conf" => "wg",
        "ovpn" => "ovpn",
        _ => bail!("Unknown file format '{}'. Expected .conf (WireGuard) or .ovpn (OpenVPN)", ext),
    };

    let name = name_override.map(|s| s.to_string()).unwrap_or_else(|| {
        file.file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("imported")
            .to_string()
    });

    // If WireGuard .conf, parse locally for a richer profile
    if format == "wg" {
        let profile = parse_wg_conf(&content, &name)?;
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"])
                .template("{spinner:.cyan} {msg}")
                .unwrap(),
        );
        pb.set_message(format!("Importing '{}'…", name.cyan()));
        pb.enable_steady_tick(Duration::from_millis(80));

        let r = client.save_profile(profile).await?.into_inner();
        pb.finish_and_clear();
        if r.success {
            println!("{} Profile '{}' imported from {}", "✓".green(), name.bold(), file.display());
            println!("  Connect with: {}", format!("vpnctl connect {}", name).cyan());
        } else {
            bail!("{}", r.error);
        }
        return Ok(());
    }

    // OpenVPN/generic — send raw bytes to daemon
    let r = client
        .import_profile(ImportRequest {
            data: content,
            format: format.to_string(),
            name: name.clone(),
            passphrase: String::new(),
        })
        .await
        .context("ImportProfile failed")?
        .into_inner();

    if r.success {
        println!("{} Profile '{}' imported.", "✓".green(), name.bold());
    } else {
        bail!("{}", r.error);
    }
    Ok(())
}

/// Parse a WireGuard .conf file into a Profile proto message
fn parse_wg_conf(data: &[u8], name: &str) -> Result<Profile> {
    let text = std::str::from_utf8(data).context("WireGuard conf is not valid UTF-8")?;

    let mut private_key = String::new();
    let mut address = String::new();
    let mut dns = String::new();
    let mut mtu = 0u32;

    let mut endpoint_host = String::new();
    let mut endpoint_port = 51820u32;
    let mut peer_pubkey = String::new();
    let mut preshared_key = String::new();
    let mut allowed_ips: Vec<String> = vec![];
    let mut keepalive = 25u32;

    let mut section = "";
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.starts_with('[') {
            if line.eq_ignore_ascii_case("[Interface]") { section = "iface"; }
            else if line.eq_ignore_ascii_case("[Peer]") { section = "peer"; }
            continue;
        }
        if line.is_empty() || line.starts_with('#') { continue; }

        let Some((key, val)) = line.split_once('=') else { continue };
        let (k, v) = (key.trim(), val.trim());

        match (section, k.to_lowercase().as_str()) {
            ("iface", "privatekey")   => private_key = v.to_string(),
            ("iface", "address")      => address = v.to_string(),
            ("iface", "dns")          => dns = v.split(',').next().unwrap_or("").trim().to_string(),
            ("iface", "mtu")          => mtu = v.parse().unwrap_or(0),
            ("peer", "publickey")     => peer_pubkey = v.to_string(),
            ("peer", "presharedkey")  => preshared_key = v.to_string(),
            ("peer", "allowedips")    => {
                allowed_ips = v.split(',').map(|s| s.trim().to_string()).collect();
            }
            ("peer", "endpoint") => {
                // host:port or [ipv6]:port
                if let Some(last_colon) = v.rfind(':') {
                    endpoint_host = v[..last_colon].trim_matches('[').trim_matches(']').to_string();
                    endpoint_port = v[last_colon + 1..].parse().unwrap_or(51820);
                }
            }
            ("peer", "persistentkeepalive") => keepalive = v.parse().unwrap_or(25),
            _ => {}
        }
    }

    if endpoint_host.is_empty() {
        bail!("WireGuard .conf has no [Peer] Endpoint — cannot determine server address");
    }

    // Determine if it's a split tunnel or full tunnel
    let is_split = !allowed_ips.iter().any(|r| r == "0.0.0.0/0" || r == "::/0");

    Ok(Profile {
        id: name.to_string(),
        name: name.to_string(),
        server_host: endpoint_host,
        server_port: endpoint_port,
        protocol: 0, // WIREGUARD
        username: String::new(),
        password: String::new(),
        ca_cert: vec![],
        client_cert: vec![],
        client_key: vec![],
        wg_private_key: private_key.into_bytes(),
        wg_private_key_sealed: String::new(),
        wg_peer_pubkey: peer_pubkey.into_bytes(),
        wg_preshared_key: preshared_key,
        wg_keepalive: keepalive,
        kill_switch: !is_split,
        split_tunnel: is_split,
        vpn_routes: if is_split { allowed_ips } else { vec![] },
        exclude_routes: vec![],
        dns_server: dns,
        ipv6_disabled: false,
        created_at: String::new(),
        updated_at: String::new(),
        auto_connect: false,
        mtu,
        passphrase: String::new(),
    })
}

async fn cmd_ping(
    client: &mut VpndServiceClient<Channel>,
    target: &str,
    count: u32,
) -> Result<()> {
    println!("PING {} ({} packets)…", target.bold(), count);

    let mut stream = client
        .run_ping_test(PingRequest {
            host: target.to_string(),
            count,
            timeout: 2000,
        })
        .await
        .context("RunPingTest failed")?
        .into_inner();

    let mut total = 0u32;
    let mut success = 0u32;
    let mut sum_rtt = 0.0f64;

    while let Some(item) = stream.next().await {
        let r = item?;
        total += 1;
        if r.success {
            success += 1;
            sum_rtt += r.rtt_ms as f64;
            println!(
                "  {} seq={:<3} rtt={:.2}ms",
                "●".green(),
                r.seq,
                r.rtt_ms
            );
        } else {
            println!("  {} seq={:<3} {}", "●".red(), r.seq, r.error.red());
        }
    }

    let loss = if total > 0 { 100.0 * (total - success) as f64 / total as f64 } else { 100.0 };
    let avg = if success > 0 { sum_rtt / success as f64 } else { 0.0 };

    println!(
        "\n  {} sent, {} received, {:.0}% loss — avg {:.2}ms",
        total.to_string().bold(),
        success.to_string().bold(),
        loss,
        avg
    );
    Ok(())
}

async fn cmd_test(
    client: &mut VpndServiceClient<Channel>,
    test: TestKind,
    json_out: bool,
) -> Result<()> {
    let run_dns = matches!(test, TestKind::Dns | TestKind::All);
    let run_ip = matches!(test, TestKind::Ip | TestKind::All);

    if run_dns {
        let pb = spinner_start("Running DNS leak test…");
        let r = client.run_dns_leak_test(Empty {}).await?.into_inner();
        pb.finish_and_clear();

        if json_out {
            println!("{}", serde_json::json!({ "dns": {"leaked": r.leaked, "servers": r.dns_servers, "error": r.error} }));
        } else if r.leaked {
            println!("{} DNS LEAK DETECTED", "⚠".red().bold());
            println!("  DNS servers observed: {:?}", r.dns_servers);
            if !r.error.is_empty() { println!("  Detail: {}", r.error.dimmed()); }
        } else {
            println!("{} No DNS leak detected", "✓".green().bold());
            println!("  Servers: {}", r.dns_servers.join(", ").dimmed());
        }
    }

    if run_ip {
        let pb = spinner_start("Running IP leak test (STUN)…");
        let r = client.run_ip_leak_test(Empty {}).await?.into_inner();
        pb.finish_and_clear();

        if json_out {
            println!("{}", serde_json::json!({ "ip": {"leaked": r.leaked, "detected_ip": r.detected_ip, "error": r.error} }));
        } else if r.leaked {
            println!("{} IP LEAK — detected {}", "⚠".red().bold(), r.detected_ip.red());
        } else {
            println!("{} No IP leak — public IP: {}", "✓".green().bold(), r.detected_ip.yellow());
        }
    }
    Ok(())
}

async fn cmd_routes(
    client: &mut VpndServiceClient<Channel>,
    json_out: bool,
) -> Result<()> {
    let rt = client.get_route_table(Empty {}).await?.into_inner();

    if json_out {
        let entries: Vec<_> = rt.routes.iter().map(|r| {
            serde_json::json!({
                "destination": r.destination,
                "gateway": r.gateway,
                "interface": r.interface,
                "metric": r.metric
            })
        }).collect();
        println!("{}", serde_json::to_string_pretty(&entries)?);
        return Ok(());
    }

    println!("  {:<24} {:<18} {:<12} {}", "DESTINATION".bold(), "GATEWAY".bold(), "IFACE".bold(), "METRIC".bold());
    println!("  {}", "─".repeat(64).dimmed());
    for r in &rt.routes {
        println!("  {:<24} {:<18} {:<12} {}", r.destination, r.gateway, r.interface, r.metric);
    }
    Ok(())
}

async fn cmd_kill_switch(
    client: &mut VpndServiceClient<Channel>,
    action: KillSwitchAction,
    _quiet: bool,
) -> Result<()> {
    match action {
        KillSwitchAction::Status => {
            let r = client.get_kill_switch_status(Empty {}).await?.into_inner();
            println!(
                "Kill switch: {}",
                if r.active { "ACTIVE".green().bold().to_string() } else { "off".dimmed().to_string() }
            );
        }
        KillSwitchAction::On => {
            let r = client
                .set_kill_switch(KillSwitchRequest {
                    enabled: true,
                    server_ip: String::new(),
                    server_port: 0,
                    protocol: String::new(),
                })
                .await?
                .into_inner();
            if r.error.is_empty() {
                println!("{} Kill switch {}", "✓".green(), "ENABLED".green().bold());
            } else {
                bail!("{}", r.error);
            }
        }
        KillSwitchAction::Off => {
            let r = client
                .set_kill_switch(KillSwitchRequest {
                    enabled: false,
                    server_ip: String::new(),
                    server_port: 0,
                    protocol: String::new(),
                })
                .await?
                .into_inner();
            if r.error.is_empty() {
                println!("{} Kill switch {}", "✓".green(), "disabled".dimmed());
            } else {
                bail!("{}", r.error);
            }
        }
    }
    Ok(())
}

async fn cmd_health(
    client: &mut VpndServiceClient<Channel>,
    json_out: bool,
) -> Result<()> {
    let h = client.get_system_health(Empty {}).await?.into_inner();

    if json_out {
        println!("{}", serde_json::json!({
            "cpu_percent": h.cpu_percent,
            "memory_used_bytes": h.memory_used_bytes,
            "memory_total_bytes": h.memory_total_bytes,
            "rx_bytes_per_sec": h.rx_bytes_per_sec,
            "tx_bytes_per_sec": h.tx_bytes_per_sec,
            "active_sessions": h.active_sessions,
            "uptime_seconds": h.uptime_seconds,
            "version": h.version
        }));
        return Ok(());
    }

    println!("{} vpnd {} — daemon healthy", "●".green(), h.version.bold());
    println!("  {:<18} {} / {}", "Memory:".dimmed(), format_bytes(h.memory_used_bytes), format_bytes(h.memory_total_bytes));
    println!("  {:<18} {:.1}%", "CPU:".dimmed(), h.cpu_percent);
    println!("  {:<18} {}", "Uptime:".dimmed(), format_duration(h.uptime_seconds as u64));
    println!("  {:<18} {}", "Active sessions:".dimmed(), h.active_sessions.to_string().yellow());
    println!("  {:<18} {}/s ▼  {}/s ▲", "Throughput:".dimmed(),
        format_bytes_rate(h.rx_bytes_per_sec),
        format_bytes_rate(h.tx_bytes_per_sec)
    );
    Ok(())
}

fn cmd_keygen() {
    use vpnd::crypto::key_exchange::WireGuardKeyPair;
    let kp = WireGuardKeyPair::generate();
    println!("{}", "Generated WireGuard keypair:".bold());
    println!("  {:<14} {}", "Private key:".dimmed(), kp.private_key_base64().yellow());
    println!("  {:<14} {}", "Public key:".dimmed(), kp.public_key_base64().green());
    println!("\n  {}", "⚠  Keep the private key secret — never share it.".red().dimmed());
}

// ─────────────────────────────────────────────────────────────────────────────
//  Key rotation (Phase 2.5/2.6)
// ─────────────────────────────────────────────────────────────────────────────

async fn cmd_rotate_keys(
    client: &mut VpndServiceClient<Channel>,
    profile: &str,
    rotate_keypair: bool,
    passphrase_stdin: bool,
    quiet: bool,
) -> Result<()> {
    use zeroize::Zeroize;

    // Sealed-key + keypair rotation requires the passphrase to re-seal the
    // new private key. Probe the existing profile first so we know whether
    // to ask for one.
    let mut needs_passphrase = false;
    if rotate_keypair {
        let existing = client
            .get_profile(ProfileIdRequest { id: profile.to_string() })
            .await?
            .into_inner();
        if !existing.wg_private_key_sealed.is_empty() {
            needs_passphrase = true;
        }
    }

    let mut passphrase = String::new();
    if needs_passphrase {
        if passphrase_stdin {
            use std::io::BufRead;
            let stdin = std::io::stdin();
            let mut line = String::new();
            stdin.lock().read_line(&mut line)?;
            passphrase = line.trim_end_matches(['\n', '\r']).to_string();
        } else {
            use dialoguer::{theme::ColorfulTheme, Password};
            passphrase = Password::with_theme(&ColorfulTheme::default())
                .with_prompt("Profile unlock passphrase (to re-seal the new private key)")
                .interact()?;
        }
        if passphrase.is_empty() {
            anyhow::bail!("passphrase cannot be empty for a sealed profile");
        }
    }

    let resp = client
        .rotate_profile_keys(RotateKeysRequest {
            profile_id: profile.to_string(),
            rotate_static_keypair: rotate_keypair,
            passphrase: passphrase.clone(),
        })
        .await?
        .into_inner();

    // Wipe the passphrase from memory immediately after the RPC.
    passphrase.zeroize();

    if !resp.success {
        anyhow::bail!("rotation failed: {}", resp.error);
    }

    if !quiet {
        println!("{} Keys rotated for profile {}", "✔".green(), profile.bold());
        println!("  {:<22} {}", "New preshared key:".dimmed(), resp.new_preshared_key.yellow());
        if !resp.new_public_key.is_empty() {
            println!("  {:<22} {}", "New public key:".dimmed(), resp.new_public_key.green());
            println!();
            println!("  {}", "⚠  The server's [Peer] section MUST be updated with the new".red());
            println!("  {}", "    public key AND the new preshared key before reconnecting.".red());
        } else {
            println!();
            println!("  {}", "⚠  Update the server's [Peer] section with the new preshared key.".yellow());
        }
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
//  Transport
// ─────────────────────────────────────────────────────────────────────────────

async fn connect_to_daemon(socket_path: &str) -> Result<Channel> {
    // Try provided path; if it doesn't exist and we're in dev mode, try /tmp/vpnd.sock
    let path = if std::path::Path::new(socket_path).exists() {
        socket_path.to_string()
    } else if socket_path == DEFAULT_SOCKET && std::path::Path::new(DEV_SOCKET).exists() {
        eprintln!("{} using dev socket {}", "⚠".yellow(), DEV_SOCKET.dimmed());
        DEV_SOCKET.to_string()
    } else {
        bail!(
            "Cannot reach daemon at '{}'\n  Is vpnd running?  Try: {}\n  Or set: {}",
            socket_path.yellow(),
            "sudo vpnd".cyan(),
            "VPND_SOCKET=/tmp/vpnd.sock".dimmed()
        );
    };

    let p = path.clone();
    let channel = Endpoint::try_from("http://[::]:50051")?
        .connect_timeout(Duration::from_secs(3))
        .connect_with_connector(service_fn(move |_: Uri| {
            let p = p.clone();
            async move {
                let stream = UnixStream::connect(&p).await?;
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
            }
        }))
        .await
        .with_context(|| format!("Could not connect to vpnd socket '{}'", path))?;

    Ok(channel)
}

// ─────────────────────────────────────────────────────────────────────────────
//  Formatting helpers
// ─────────────────────────────────────────────────────────────────────────────

fn format_bytes(b: i64) -> String {
    if b < 0 { return "?".to_string(); }
    let b = b as f64;
    if b < 1_024.0 { format!("{:.0} B", b) }
    else if b < 1_048_576.0 { format!("{:.1} KiB", b / 1_024.0) }
    else if b < 1_073_741_824.0 { format!("{:.1} MiB", b / 1_048_576.0) }
    else { format!("{:.2} GiB", b / 1_073_741_824.0) }
}

fn format_bytes_rate(bps: i64) -> String {
    if bps < 0 { return "?".to_string(); }
    let bps = bps as f64;
    if bps < 1_024.0 { format!("{:.0} B", bps) }
    else if bps < 1_048_576.0 { format!("{:.1} KiB", bps / 1_024.0) }
    else { format!("{:.2} MiB", bps / 1_048_576.0) }
}

fn format_duration(secs: u64) -> String {
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    if h > 0 { format!("{}h {}m", h, m) }
    else if m > 0 { format!("{}m {}s", m, s) }
    else { format!("{}s", s) }
}

/// ASCII sparkline bar (width chars wide)
fn sparkline(value: i64, max: i64) -> String {
    let blocks = ["░", "▒", "▓", "█"];
    let width = 16usize;
    let ratio = (value as f64 / max as f64).clamp(0.0, 1.0);
    let filled = (ratio * width as f64).round() as usize;
    let mut s = String::with_capacity(width * 4);
    for i in 0..width {
        s.push_str(if i < filled { blocks[3] } else { blocks[0] });
    }
    s
}

fn bool_indicator(v: bool) -> colored::ColoredString {
    if v { "yes".green() } else { "no".dimmed() }
}

fn spinner_start(msg: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"])
            .template("{spinner:.cyan} {msg}")
            .unwrap(),
    );
    pb.set_message(msg.to_string());
    pb.enable_steady_tick(Duration::from_millis(80));
    pb
}

// Bring base64 Engine trait into scope
use base64::Engine as _;

// serde_json for --json output
use serde_json;

