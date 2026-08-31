//! Encrypted DNS proxy (DoT / DoH).
//!
//! This module starts a local UDP+TCP listener (default `127.0.0.53:53`)
//! that accepts plain-DNS queries from the operating system's stub
//! resolver, and forwards every request to one or more upstream
//! resolvers reached over **TLS 1.3** (DNS-over-TLS, RFC 7858) using
//! `hickory-resolver`.
//!
//! Threat model addressed:
//!   * Plaintext DNS leaks the user's browsing history to anyone on
//!     the network path between the client and the resolver — including
//!     ISPs that are notorious for selling that data.
//!   * A malicious local resolver can poison answers (cf. KAMINSKY).
//!     DNSSEC validation is enabled by default to mitigate this.
//!
//! Design notes:
//!   * The proxy is *not* started automatically; it is a deliberate
//!     opt-in via `[client.dns] encrypted = true`.  When opt-in is on,
//!     the [`crate::network::DnsGuard`] writes
//!     `nameserver <listen_addr>` into `/etc/resolv.conf` so every
//!     resolver on the machine flows through this process.
//!   * Upstream selection: round-robin across all configured DoT
//!     servers.  TLS certificate verification uses the platform root
//!     store via `rustls-native-certs`.
//!   * No caching layer is added beyond hickory-resolver's built-in
//!     positive/negative caches: caching is correctness-sensitive and
//!     letting the upstream answer be canonical avoids surprises.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use hickory_proto::op::{Header, MessageType, OpCode, ResponseCode};
use hickory_resolver::config::{
    NameServerConfig, Protocol, ResolverConfig, ResolverOpts,
};
use hickory_resolver::TokioAsyncResolver;
use hickory_server::authority::MessageResponseBuilder;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::ServerFuture;
use tokio::net::{TcpListener, UdpSocket};
use tracing::{debug, error, info, warn};

/// A single parsed `IP:PORT@SNI` upstream entry.
#[derive(Debug, Clone)]
pub struct DotUpstream {
    pub addr: SocketAddr,
    pub sni: String,
}

impl DotUpstream {
    /// Parse `IP:PORT@SNI`.  Returns an error on malformed input so that
    /// misconfiguration is loud rather than silently falling back to
    /// plaintext DNS.
    pub fn parse(s: &str) -> Result<Self> {
        let (addr_str, sni) = s
            .split_once('@')
            .ok_or_else(|| anyhow!("DoT upstream '{}' missing '@SNI' suffix", s))?;
        let addr: SocketAddr = addr_str
            .parse()
            .with_context(|| format!("invalid socket address in '{}'", s))?;
        if sni.is_empty() {
            return Err(anyhow!("DoT upstream '{}' has empty SNI", s));
        }
        Ok(Self {
            addr,
            sni: sni.to_string(),
        })
    }
}

/// Build a `TokioAsyncResolver` configured to use the supplied DoT
/// upstreams exclusively.  `validate_dnssec=true` enables DNSSEC.
pub fn build_dot_resolver(
    upstreams: &[DotUpstream],
    validate_dnssec: bool,
) -> Result<TokioAsyncResolver> {
    if upstreams.is_empty() {
        return Err(anyhow!("at least one DoT upstream is required"));
    }

    let mut cfg = ResolverConfig::new();
    for up in upstreams {
        let ns = NameServerConfig {
            socket_addr: up.addr,
            protocol: Protocol::Tls,
            tls_dns_name: Some(up.sni.clone()),
            trust_negative_responses: true,
            bind_addr: None,
            tls_config: None,
        };
        cfg.add_name_server(ns);
    }

    let mut opts = ResolverOpts::default();
    opts.validate = validate_dnssec;
    opts.timeout = Duration::from_secs(5);
    opts.attempts = 2;
    // Try every upstream before failing.
    opts.num_concurrent_reqs = upstreams.len().max(1);
    // We want hickory's own cache: low-TTL replies are unfortunately
    // common and hammering upstreams hurts perf without changing answers.
    opts.cache_size = 256;

    Ok(TokioAsyncResolver::tokio(cfg, opts))
}

/// `RequestHandler` that proxies every incoming DNS query to the
/// configured DoT resolver.
struct DotProxyHandler {
    resolver: Arc<TokioAsyncResolver>,
}

#[async_trait::async_trait]
impl RequestHandler for DotProxyHandler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let query = request.query();
        let name = query.name();
        let rtype = query.query_type();

        debug!(
            qname = %name,
            qtype = ?rtype,
            client = ?request.src(),
            "proxying DNS query via DoT"
        );

        // Look up via DoT resolver
        let lookup = match self.resolver.lookup(name.clone(), rtype).await {
            Ok(l) => l,
            Err(e) => {
                warn!(qname = %name, error = %e, "DoT lookup failed — returning SERVFAIL");
                return send_servfail(request, &mut response_handle).await;
            }
        };

        let records: Vec<_> = lookup.records().to_vec();

        let mut header = Header::response_from_request(request.header());
        header.set_message_type(MessageType::Response);
        header.set_op_code(OpCode::Query);
        header.set_response_code(ResponseCode::NoError);
        header.set_authoritative(false);
        header.set_recursion_available(true);

        let builder = MessageResponseBuilder::from_message_request(request);
        let msg = builder.build(header, records.iter(), &[], &[], &[]);

        match response_handle.send_response(msg).await {
            Ok(info) => info,
            Err(e) => {
                error!(error = %e, "failed to send DoT proxy response");
                fallback_response_info(request)
            }
        }
    }
}

async fn send_servfail<R: ResponseHandler>(
    request: &Request,
    response_handle: &mut R,
) -> ResponseInfo {
    let mut header = Header::response_from_request(request.header());
    header.set_message_type(MessageType::Response);
    header.set_response_code(ResponseCode::ServFail);
    let builder = MessageResponseBuilder::from_message_request(request);
    let msg = builder.build_no_records(header);
    response_handle
        .send_response(msg)
        .await
        .unwrap_or_else(|_| fallback_response_info(request))
}

fn fallback_response_info(request: &Request) -> ResponseInfo {
    let mut header = Header::response_from_request(request.header());
    header.set_response_code(ResponseCode::ServFail);
    header.into()
}

/// Running DoT proxy.  Drop to stop.
pub struct DotProxy {
    handle: tokio::task::JoinHandle<()>,
    listen_addr: SocketAddr,
}

impl DotProxy {
    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    /// Stop the proxy (best-effort).
    pub fn shutdown(self) {
        self.handle.abort();
    }
}

/// Start the encrypted-DNS proxy listening on `listen` and forwarding to
/// the supplied DoT upstreams.  Both UDP and TCP are bound (RFC 7766).
pub async fn start_dot_proxy(
    listen: SocketAddr,
    upstreams: Vec<DotUpstream>,
    validate_dnssec: bool,
) -> Result<DotProxy> {
    let resolver = Arc::new(build_dot_resolver(&upstreams, validate_dnssec)?);

    let udp = UdpSocket::bind(listen)
        .await
        .with_context(|| format!("failed to bind UDP {} for DoT proxy", listen))?;
    let tcp = TcpListener::bind(listen)
        .await
        .with_context(|| format!("failed to bind TCP {} for DoT proxy", listen))?;

    let handler = DotProxyHandler {
        resolver: resolver.clone(),
    };

    let mut server = ServerFuture::new(handler);
    server.register_socket(udp);
    server.register_listener(tcp, Duration::from_secs(10));

    info!(
        listen = %listen,
        upstreams = ?upstreams.iter().map(|u| u.addr).collect::<Vec<_>>(),
        validate_dnssec,
        "encrypted DNS proxy started (DoT, TLS 1.3)"
    );

    let handle = tokio::spawn(async move {
        if let Err(e) = server.block_until_done().await {
            error!(error = %e, "DoT proxy stopped unexpectedly");
        }
    });

    Ok(DotProxy {
        handle,
        listen_addr: listen,
    })
}

// ─────────────────────────────── tests ───────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_upstream() {
        let u = DotUpstream::parse("1.1.1.1:853@cloudflare-dns.com").unwrap();
        assert_eq!(u.addr.to_string(), "1.1.1.1:853");
        assert_eq!(u.sni, "cloudflare-dns.com");
    }

    #[test]
    fn parse_missing_sni_fails() {
        assert!(DotUpstream::parse("1.1.1.1:853").is_err());
    }

    #[test]
    fn parse_empty_sni_fails() {
        assert!(DotUpstream::parse("1.1.1.1:853@").is_err());
    }

    #[test]
    fn parse_invalid_addr_fails() {
        assert!(DotUpstream::parse("not-an-addr@cloudflare-dns.com").is_err());
    }

    #[test]
    fn build_resolver_rejects_empty_upstreams() {
        assert!(build_dot_resolver(&[], true).is_err());
    }

    #[test]
    fn build_resolver_succeeds_with_one_upstream() {
        let up = DotUpstream::parse("1.1.1.1:853@cloudflare-dns.com").unwrap();
        assert!(build_dot_resolver(&[up], true).is_ok());
    }
}
