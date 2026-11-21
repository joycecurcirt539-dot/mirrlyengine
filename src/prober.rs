use serde::Serialize;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAX_PROBE_HTTP_BYTES: usize = 4096;

/// Unified outcome emitted by [`probe_transport_health`] and `ProbeTransportHealth` C-FFI.
#[derive(Serialize, Clone, Debug)]
pub struct TransportProbeResult {
    pub alive: bool,
    pub rtt_ms: i64,
    pub domain: String,
    pub ip: String,
    pub colo: String,
    pub stage: String,
    pub failure: String,
}

fn is_cf_or_flowseal_host(host: &str) -> bool {
    let lower = host.trim().to_ascii_lowercase();
    if lower.is_empty() {
        return false;
    }
    if crate::config::is_cloudflare_domain(&lower) {
        return true;
    }
    let user_domain = crate::config::CFPROXY.read().user_domain.trim().to_ascii_lowercase();
    if !user_domain.is_empty() && lower == user_domain {
        return true;
    }
    let last_worker = crate::config::LAST_SOCKS5_WORKER
        .read()
        .trim()
        .to_ascii_lowercase();
    if !last_worker.is_empty() && lower == last_worker {
        return true;
    }
    crate::cfproxy::FLOWSEAL_OPEN_BASES
        .iter()
        .any(|base| lower == format!("{base}.co.uk") || lower.ends_with(&format!(".{base}.co.uk")))
}

async fn resolve_probe_addrs(host: &str, port: u16) -> Vec<SocketAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return vec![SocketAddr::new(ip, port)];
    }

    let ips = if is_cf_or_flowseal_host(host) {
        crate::cfproxy::resolve_dual_stack_ips(host).await
    } else {
        let mut resolved: Vec<IpAddr> = match tokio::net::lookup_host((host, port)).await {
            Ok(iter) => iter.map(|sa| sa.ip()).collect(),
            Err(_) => Vec::new(),
        };
        resolved.sort_unstable();
        resolved.dedup();
        let (v4, v6): (Vec<IpAddr>, Vec<IpAddr>) = resolved.into_iter().partition(|ip| ip.is_ipv4());
        crate::network_profile::filter_ip_family(crate::cfproxy::interleave_dual_stack_ips(v6, v4))
    };

    ips.into_iter().map(|ip| SocketAddr::new(ip, port)).collect()
}

fn sanitize_host_and_port(raw: &str, default_port: u16) -> Option<(String, u16)> {
    let mut s = raw.trim();
    for prefix in ["https://", "http://", "wss://", "ws://"] {
        if let Some(rest) = s.strip_prefix(prefix) {
            s = rest;
            break;
        }
    }
    let s = s.trim_end_matches('/');
    if s.is_empty() || s.contains('/') || s.contains('?') || s.contains('#') || s.contains('@') {
        return None;
    }

    if let Some(after_open) = s.strip_prefix('[') {
        let close_idx = after_open.find(']')?;
        let host = &after_open[..close_idx];
        let rest = &after_open[close_idx + 1..];
        if rest.is_empty() {
            return Some((host.to_string(), default_port));
        }
        let port = rest.strip_prefix(':')?.parse::<u16>().ok()?;
        return Some((host.to_string(), port));
    }

    if let Some((host, port_str)) = s.rsplit_once(':') {
        if !host.is_empty() && !host.contains(':') {
            if let Ok(port) = port_str.parse::<u16>() {
                return Some((host.to_string(), port));
            }
        }
    }

    Some((s.to_string(), default_port))
}

fn parse_http_status_code(raw: &[u8]) -> Option<u16> {
    let text = std::str::from_utf8(raw).ok()?;
    let first_line = text.lines().next()?.trim();
    let mut parts = first_line.split_whitespace();
    let version = parts.next()?;
    if !version.starts_with("HTTP/") {
        return None;
    }
    parts.next()?.parse::<u16>().ok()
}

async fn send_http_probe<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    host_header: &str,
) -> Option<u16> {
    let req = format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: mirrlyengine/1.0\r\nConnection: close\r\n\r\n",
        host_header
    );
    if stream.write_all(req.as_bytes()).await.is_err() {
        return None;
    }
    if stream.flush().await.is_err() {
        return None;
    }

    let mut buf = [0u8; MAX_PROBE_HTTP_BYTES];
    let mut total = 0usize;
    while total < buf.len() {
        match stream.read(&mut buf[total..]).await {
            Ok(0) => break,
            Ok(n) => {
                total += n;
                if buf[..total].windows(2).any(|w| w == b"\r\n") || buf[..total].contains(&b'\n') {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    parse_http_status_code(&buf[..total])
}

/// Measures TCP connect reachability and RTT across dual-stack candidates.
pub async fn ping_tcp_host(host: &str, port: u16, timeout_ms: u64) -> (bool, i64, String) {
    let clean_host = host
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']');
    if clean_host.is_empty() {
        return (false, -1, "Empty host".to_string());
    }

    let addrs = resolve_probe_addrs(clean_host, port).await;
    if addrs.is_empty() {
        return (false, -1, "Host resolution failed".to_string());
    }

    let budget = Duration::from_millis(timeout_ms.clamp(250, 10_000));
    let mut last_err = "No address tried".to_string();

    for target_addr in addrs {
        let t0 = Instant::now();
        match tokio::time::timeout(budget, tokio::net::TcpStream::connect(target_addr)).await {
            Ok(Ok(stream)) => {
                crate::platform::configure_socket_platform(&socket2::SockRef::from(&stream));
                let rtt = t0.elapsed().as_millis().max(1) as i64;
                return (true, rtt, target_addr.ip().to_string());
            }
            Ok(Err(err)) => {
                last_err = err.to_string();
            }
            Err(_) => {
                last_err = "Connection timeout".to_string();
            }
        }
    }

    (false, -1, last_err)
}

/// Probes a Cloudflare Worker / WS endpoint over HTTP or HTTPS depending on active TLS mode.
///
/// Returns status `"ONLINE"`, `"RATE_LIMITED_429"`, or `"ERROR_UNREACHABLE"` plus RTT in ms.
pub async fn ping_worker_endpoint(domain: &str, timeout_ms: u64) -> (String, Option<i64>) {
    let use_tls = crate::ws::is_tls_enabled();
    let default_port = if use_tls { 443 } else { 80 };
    let Some((clean_host, port)) = sanitize_host_and_port(domain, default_port) else {
        return ("ERROR_UNREACHABLE".to_string(), None);
    };

    let addrs = resolve_probe_addrs(&clean_host, port).await;
    if addrs.is_empty() {
        return ("ERROR_UNREACHABLE".to_string(), None);
    }

    let total_budget = Duration::from_millis(timeout_ms.clamp(400, 15_000));
    let t0 = Instant::now();
    let probe_res = tokio::time::timeout(total_budget, async {
        for addr in addrs.into_iter().take(4) {
            let connect_res = tokio::time::timeout(
                Duration::from_millis(2500),
                tokio::net::TcpStream::connect(addr),
            )
            .await;
            let Ok(Ok(tcp)) = connect_res else {
                continue;
            };
            crate::platform::configure_socket_platform(&socket2::SockRef::from(&tcp));

            let status = if use_tls {
                let connector = tokio_rustls::TlsConnector::from(crate::ws::TLS_CONFIG_CHROME.clone());
                let Ok(tls) = connector.connect(crate::ws::server_name(&clean_host), tcp).await
                else {
                    continue;
                };
                send_http_probe(tls, &clean_host).await
            } else {
                send_http_probe(tcp, &clean_host).await
            };

            if let Some(code) = status {
                return Some(code);
            }
        }
        None
    })
    .await;

    let rtt = t0.elapsed().as_millis().max(1) as i64;
    match probe_res {
        Ok(Some(200 | 101)) => ("ONLINE".to_string(), Some(rtt)),
        Ok(Some(429 | 1015 | 1027)) => ("RATE_LIMITED_429".to_string(), Some(rtt)),
        _ => ("ERROR_UNREACHABLE".to_string(), None),
    }
}

fn classify_ws_probe_failure(err: &crate::ws::WsError) -> &'static str {
    match err {
        crate::ws::WsError::Timeout | crate::ws::WsError::Canceled => "CONNECT_TIMEOUT",
        crate::ws::WsError::Handshake(h) => {
            if h.status_code == 429 || h.status_code == 1015 || h.status_code == 1027 {
                "RATE_LIMITED_429"
            } else {
                "HOST_UNREACHABLE"
            }
        }
        crate::ws::WsError::Io(e) => match e.kind() {
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => "CONNECT_TIMEOUT",
            std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::BrokenPipe => "DPI_BLOCKED",
            _ => "HOST_UNREACHABLE",
        },
        crate::ws::WsError::Other(msg) => {
            let low = msg.to_ascii_lowercase();
            if crate::ws::is_tls_enabled()
                && (low.contains("tls") || low.contains("cert") || low.contains("handshake"))
            {
                "TLS_HANDSHAKE_FAILED"
            } else if low.contains("dns") || low.contains("resolve") {
                "HOST_RESOLUTION_FAILED"
            } else if low.contains("reset") || low.contains("dpi") {
                "DPI_BLOCKED"
            } else {
                "HOST_UNREACHABLE"
            }
        }
    }
}

fn failed_probe(domain: String, stage: &str, failure: &str) -> TransportProbeResult {
    TransportProbeResult {
        alive: false,
        rtt_ms: -1,
        domain,
        ip: String::new(),
        colo: String::new(),
        stage: stage.to_string(),
        failure: failure.to_string(),
    }
}

/// Probes active proxy transport health (modes: 0=MTProto Anycast, 1=SOCKS5 Anycast,
/// 2=SOCKS5 Worker, 3=MTProto Worker).
pub async fn probe_transport_health(
    mode: i32,
    domain_override: &str,
    timeout_ms: u64,
) -> TransportProbeResult {
    let to_ms = timeout_ms.clamp(400, 8000);
    let tls_on = crate::ws::is_tls_enabled();
    let default_stage = if tls_on { "WSS_TLS" } else { "WS_PLAIN_80" };

    if mode == 4 {
        return failed_probe(
            domain_override.trim().to_string(),
            "UNSUPPORTED",
            "WARP_NOT_SUPPORTED",
        );
    }

    if mode == 2 || mode == 3 {
        let user_domain = {
            let trimmed = domain_override.trim();
            if !trimmed.is_empty() {
                crate::cfproxy::normalize_cf_domain(trimmed)
            } else {
                let configured = crate::config::CFPROXY.read().user_domain.clone();
                crate::cfproxy::normalize_cf_domain(&configured)
            }
        };
        if user_domain.is_empty() {
            return failed_probe(String::new(), default_stage, "HOST_RESOLUTION_FAILED");
        }
        let scope = if mode == 2 {
            crate::cfproxy::ProtoScope::Socks5
        } else {
            crate::cfproxy::ProtoScope::Mtproto
        };
        if crate::cfproxy::cfproxy_429_cooldown_remaining_scoped(&user_domain, scope)
            > Duration::ZERO
        {
            return failed_probe(user_domain, default_stage, "RATE_LIMITED_429");
        }

        let (status, rtt_opt) = ping_worker_endpoint(&user_domain, to_ms).await;
        if status == "ONLINE" {
            return TransportProbeResult {
                alive: true,
                rtt_ms: rtt_opt.unwrap_or(1),
                domain: user_domain,
                ip: String::new(),
                colo: String::new(),
                stage: if tls_on { "WORKER_WSS" } else { "WORKER_WS_80" }.to_string(),
                failure: "NONE".to_string(),
            };
        }
        if status == "RATE_LIMITED_429" {
            return TransportProbeResult {
                alive: false,
                rtt_ms: rtt_opt.unwrap_or(-1),
                domain: user_domain,
                ip: String::new(),
                colo: String::new(),
                stage: default_stage.to_string(),
                failure: "RATE_LIMITED_429".to_string(),
            };
        }

        let ips = crate::cfproxy::resolve_dual_stack_ips(&user_domain).await;
        if let Some(ip) = ips.first() {
            let port = crate::ws::default_ws_port();
            let addrs = vec![SocketAddr::new(*ip, port)];
            let path = if mode == 2 { "/tcp-v2" } else { "/apiws" };
            let t0 = Instant::now();
            match crate::ws::ws_connect_happy_eyeballs(
                &user_domain,
                path,
                &addrs,
                Duration::from_millis(to_ms),
            )
            .await
            {
                Ok((ws, winner)) => {
                    let rtt = t0.elapsed().as_millis().max(1) as i64;
                    let colo = ws.colo().to_string();
                    tokio::spawn(async move {
                        let _ = ws.close().await;
                    });
                    return TransportProbeResult {
                        alive: true,
                        rtt_ms: rtt,
                        domain: user_domain,
                        ip: winner.ip().to_string(),
                        colo,
                        stage: if tls_on { "WORKER_WSS" } else { "WORKER_WS_80" }.to_string(),
                        failure: "NONE".to_string(),
                    };
                }
                Err(err) => {
                    let mut res = failed_probe(
                        user_domain,
                        default_stage,
                        classify_ws_probe_failure(&err),
                    );
                    res.ip = ip.to_string();
                    return res;
                }
            }
        }

        return failed_probe(user_domain, default_stage, "CONNECT_TIMEOUT");
    }

    let mut candidates: Vec<String> = Vec::new();
    let trimmed_ov = crate::balancer::normalize_domain(domain_override);
    if !trimmed_ov.is_empty() {
        candidates.push(trimmed_ov);
    }
    if let Some(fastest) = crate::balancer::BALANCER
        .read()
        .get_fastest_domain_for_dc(2, false)
    {
        if !candidates.contains(&fastest) {
            candidates.push(fastest);
        }
    }
    {
        let cfg_domains = crate::config::CFPROXY.read().domains.clone();
        for raw in cfg_domains.into_iter().take(6) {
            let dec = crate::cfproxy::decode_cf_domain(&raw);
            let norm = crate::balancer::normalize_domain(&dec);
            if !norm.is_empty() && !candidates.contains(&norm) {
                candidates.push(norm);
            }
            if candidates.len() >= 3 {
                break;
            }
        }
    }
    for &open_base in crate::cfproxy::FLOWSEAL_OPEN_BASES.iter().take(3) {
        let dom = format!("{open_base}.co.uk");
        if !candidates.contains(&dom) {
            candidates.push(dom);
        }
        if candidates.len() >= 3 {
            break;
        }
    }

    let port = crate::ws::default_ws_port();
    let per_domain_timeout = Duration::from_millis((to_ms / 2).clamp(600, 1800));
    let mut last_failure = "HOST_UNREACHABLE";
    let mut last_domain = candidates.first().cloned().unwrap_or_default();

    for base in candidates.into_iter().take(3) {
        let target_host = format!("kws2.{base}");
        last_domain = base.clone();
        let candidate_ips = crate::cfproxy::resolve_dual_stack_ips(&target_host).await;
        if candidate_ips.is_empty() {
            last_failure = "HOST_RESOLUTION_FAILED";
            continue;
        }
        let addrs: Vec<SocketAddr> = candidate_ips
            .into_iter()
            .take(4)
            .map(|ip| SocketAddr::new(ip, port))
            .collect();
        let t0 = Instant::now();
        match crate::ws::ws_connect_happy_eyeballs(&target_host, "/apiws", &addrs, per_domain_timeout)
            .await
        {
            Ok((ws, winner)) => {
                let rtt = t0.elapsed().as_millis().max(1) as i64;
                let colo = ws.colo().to_string();
                tokio::spawn(async move {
                    let _ = ws.close().await;
                });
                return TransportProbeResult {
                    alive: true,
                    rtt_ms: rtt,
                    domain: base,
                    ip: winner.ip().to_string(),
                    colo,
                    stage: if tls_on {
                        "FLOWSEAL_WSS"
                    } else {
                        "FLOWSEAL_WS_80"
                    }
                    .to_string(),
                    failure: "NONE".to_string(),
                };
            }
            Err(err) => {
                last_failure = classify_ws_probe_failure(&err);
            }
        }
    }

    failed_probe(last_domain, default_stage, last_failure)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_http_status_code_handles_standard_and_malformed_lines() {
        assert_eq!(parse_http_status_code(b"HTTP/1.1 200 OK\r\n"), Some(200));
        assert_eq!(
            parse_http_status_code(b"HTTP/1.1 429 Too Many Requests\r\n"),
            Some(429)
        );
        assert_eq!(parse_http_status_code(b"GARBAGE\r\n"), None);
    }

    #[test]
    fn sanitize_host_and_port_strips_scheme_and_rejects_paths() {
        assert_eq!(
            sanitize_host_and_port("https://worker.example.dev/", 443),
            Some(("worker.example.dev".to_string(), 443))
        );
        assert_eq!(
            sanitize_host_and_port("127.0.0.1:8080", 80),
            Some(("127.0.0.1".to_string(), 8080))
        );
        assert_eq!(
            sanitize_host_and_port("worker.example.dev/bad?x=1", 443),
            None
        );
    }
}
