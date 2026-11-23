use crate::config::*;
use crate::ws::{is_http_status_error, server_name, RawWebSocket, WsError, TLS_CONFIG_CHROME};
use once_cell::sync::Lazy;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

// ---------------------------------------------------------------------------
// Domain decoding
// ---------------------------------------------------------------------------

pub static FLOWSEAL_OPEN_BASES: &[&str] = &[
    "pclead",
    "offshor",
    "cakeisalie",
    "noskomnadzor",
    "lovetrue",
    "sorokdva",
    "pyatdesyatdva",
    "kartoshka",
    "sorokodin",
    "pyatdesyatodin",
    "notelega",
    "ebally",
    "nebally",
    "havegreatday",
    "pomogite",
    "fixtelega",
    "sadnews",
    "onedaychamp",
    "stopblocking",
    "nothingthere",
];

pub fn decode_cf_domain(s: &str) -> String {
    let mut s_trim = s.trim();
    while s_trim.ends_with('.') {
        s_trim = &s_trim[..s_trim.len() - 1];
    }
    if s_trim.is_empty() {
        return String::new();
    }

    // Strip optional kws{dc}. or kws{dc}-{idx}. prefix if present
    let stripped = if let Some((prefix, rest)) = s_trim.split_once('.') {
        if prefix.starts_with("kws")
            && prefix.len() > 3
            && prefix[3..].chars().all(|c| c.is_ascii_digit() || c == '-')
        {
            rest
        } else {
            s_trim
        }
    } else {
        s_trim
    };

    let lower = stripped.to_ascii_lowercase();

    // Check if domain already matches an open Flowseal base (.co.uk, .com, or plain base)
    let open_base = if let Some(base) = lower.strip_suffix(".co.uk") {
        Some(base)
    } else if let Some(base) = lower.strip_suffix(".com") {
        Some(base)
    } else {
        Some(lower.as_str())
    };

    if let Some(base) = open_base {
        if FLOWSEAL_OPEN_BASES.contains(&base) {
            return format!("{}.co.uk", base);
        }
    }

    if lower.ends_with(".com") {
        let suffix = ".co.uk";
        let p = &stripped[..stripped.len() - 4];
        let mut n = 0i32;
        for c in p.chars() {
            if c.is_ascii_alphabetic() {
                n += 1;
            }
        }
        let mut result: Vec<u8> = Vec::new();
        for &c in p.as_bytes() {
            if c.is_ascii_lowercase() {
                let v = (((c - b'a') as i32 - n % 26 + 26) % 26) as u8 + b'a';
                result.push(v);
            } else if c.is_ascii_uppercase() {
                let v = (((c - b'A') as i32 - n % 26 + 26) % 26) as u8 + b'A';
                result.push(v);
            } else {
                result.push(c);
            }
        }
        let mut out = String::from_utf8_lossy(&result).to_string();
        out.push_str(suffix);
        return out;
    }

    stripped.to_string()
}

pub fn normalize_cf_domain(s: &str) -> String {
    let mut s_trim = s.trim();
    if s_trim.is_empty() {
        return String::new();
    }
    while s_trim.ends_with('.') {
        s_trim = &s_trim[..s_trim.len() - 1];
    }
    s_trim.to_lowercase()
}

pub fn parse_cfproxy_domains(body: &str) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut domains = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let decoded = decode_cf_domain(line);
        let d = normalize_cf_domain(&decoded);
        if !d.is_empty() && seen.insert(d.clone()) {
            domains.push(d);
        }
    }
    domains
}

pub fn default_cfproxy_domains() -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut domains = Vec::with_capacity(CFPROXY_ENC.len());
    for enc in CFPROXY_ENC {
        let decoded = decode_cf_domain(enc);
        let d = normalize_cf_domain(&decoded);
        if !d.is_empty() && seen.insert(d.clone()) {
            domains.push(d);
        }
    }
    domains
}

pub fn merge_cfproxy_domains(lists: &[Vec<String>]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut merged = Vec::new();
    for list in lists {
        for raw in list {
            let decoded = decode_cf_domain(raw);
            let d = normalize_cf_domain(&decoded);
            if d.is_empty() || seen.contains(&d) {
                continue;
            }
            seen.insert(d.clone());
            merged.push(d);
        }
    }
    merged
}

// ---------------------------------------------------------------------------
// 429 cooldown logic
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct CfproxyRecoveryCircuitEntry {
    pub until: Instant,
    pub network_generation: u64,
    pub stage: crate::recovery::EstablishmentStage,
    pub reason: String,
    pub in_flight_trial: bool,
}

static CFPROXY_RECOVERY_CIRCUIT: Lazy<
    parking_lot::RwLock<std::collections::HashMap<String, CfproxyRecoveryCircuitEntry>>,
> = Lazy::new(|| parking_lot::RwLock::new(std::collections::HashMap::new()));

pub fn canonical_cfproxy_cooldown_key(domain: &str) -> String {
    let mut s = domain.trim();
    if let Some(stripped) = s.strip_prefix("mtproto:") {
        s = stripped.trim();
    } else if let Some(stripped) = s.strip_prefix("socks5:") {
        s = stripped.trim();
    }
    let normalized = normalize_cf_domain(s);
    if normalized.is_empty() {
        return String::new();
    }
    if let Some((prefix, base)) = normalized.split_once('.') {
        if prefix.starts_with("kws")
            && prefix.len() > 3
            && prefix[3..].chars().all(|character| character.is_ascii_digit() || character == '-')
        {
            return base.to_string();
        }
    }
    normalized
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtoScope {
    Mtproto,
    Socks5,
    Global,
}

impl ProtoScope {
    pub const fn prefix(self) -> &'static str {
        match self {
            ProtoScope::Mtproto => "mtproto:",
            ProtoScope::Socks5 => "socks5:",
            ProtoScope::Global => "",
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            ProtoScope::Mtproto => "mtproto",
            ProtoScope::Socks5 => "socks5",
            ProtoScope::Global => "global",
        }
    }
}

impl std::fmt::Display for ProtoScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

pub fn scoped_cfproxy_cooldown_key(domain: &str, scope: ProtoScope) -> String {
    let canonical = canonical_cfproxy_cooldown_key(domain);
    if canonical.is_empty() {
        return String::new();
    }
    match scope {
        ProtoScope::Global => canonical,
        ProtoScope::Mtproto | ProtoScope::Socks5 => format!("{}{}", scope.prefix(), canonical),
    }
}

// ---------------------------------------------------------------------------
// Isolated statistics tracking per protocol
// ---------------------------------------------------------------------------

static MTPROTO_429_HITS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static SOCKS5_429_HITS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static GLOBAL_429_HITS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub fn cfproxy_429_hits(scope: ProtoScope) -> u64 {
    match scope {
        ProtoScope::Mtproto => MTPROTO_429_HITS.load(std::sync::atomic::Ordering::Relaxed),
        ProtoScope::Socks5 => SOCKS5_429_HITS.load(std::sync::atomic::Ordering::Relaxed),
        ProtoScope::Global => GLOBAL_429_HITS.load(std::sync::atomic::Ordering::Relaxed),
    }
}

pub fn reset_cfproxy_429_hits(scope: ProtoScope) {
    match scope {
        ProtoScope::Mtproto => MTPROTO_429_HITS.store(0, std::sync::atomic::Ordering::Relaxed),
        ProtoScope::Socks5 => SOCKS5_429_HITS.store(0, std::sync::atomic::Ordering::Relaxed),
        ProtoScope::Global => GLOBAL_429_HITS.store(0, std::sync::atomic::Ordering::Relaxed),
    }
}

pub fn cfproxy_429_strikes_scoped(domain: &str, scope: ProtoScope) -> i32 {
    let key = scoped_cfproxy_cooldown_key(domain, scope);
    if key.is_empty() {
        return 0;
    }
    let map = CFPROXY_429.read();
    map.get(&key)
        .filter(|state| state.until.map(|u| u > Instant::now()).unwrap_or(false))
        .map(|state| state.strikes)
        .unwrap_or(0)
}

pub fn clear_cfproxy_429_cooldowns() {
    CFPROXY_429.write().clear();
    CFPROXY_RECOVERY_CIRCUIT.write().clear();
}

pub fn clear_cfproxy_429_cooldown_scoped(domain: &str, scope: ProtoScope) {
    let key = scoped_cfproxy_cooldown_key(domain, scope);
    if key.is_empty() {
        return;
    }
    CFPROXY_429.write().remove(&key);
}

pub fn clear_cfproxy_429_cooldown(domain: &str) {
    let d = canonical_cfproxy_cooldown_key(domain);
    if d.is_empty() {
        return;
    }
    let mut map = CFPROXY_429.write();
    map.remove(&d);
    map.remove(&format!("{}{}", ProtoScope::Mtproto.prefix(), d));
    map.remove(&format!("{}{}", ProtoScope::Socks5.prefix(), d));
    drop(map);
    CFPROXY_RECOVERY_CIRCUIT.write().remove(&d);
}

pub fn retry_after_delay(err: &WsError) -> Duration {
    let h = match err.handshake() {
        Some(h) => h,
        None => return Duration::ZERO,
    };
    let retry_after = h.headers.get("retry-after").map(|s| s.trim()).unwrap_or("");
    if retry_after.is_empty() {
        return Duration::ZERO;
    }
    if let Ok(seconds) = retry_after.parse::<i64>() {
        if seconds > 0 {
            return Duration::from_secs(seconds as u64);
        }
    }
    Duration::ZERO
}

pub fn next_cfproxy_429_cooldown_delay(prev: &Cfproxy429State, retry_after: Duration) -> Duration {
    if retry_after > Duration::ZERO {
        if retry_after > CFPROXY_429_MAX_COOLDOWN {
            return CFPROXY_429_MAX_COOLDOWN;
        }
        return retry_after;
    }
    let mut strikes = prev.strikes;
    let expired = prev
        .until
        .map(|until| until <= Instant::now())
        .unwrap_or(true);
    if expired {
        strikes = 0;
    }
    let mut delay = CFPROXY_429_COOLDOWN;
    for _ in 0..strikes {
        delay *= 2;
        if delay >= CFPROXY_429_MAX_COOLDOWN {
            return CFPROXY_429_MAX_COOLDOWN;
        }
    }
    if delay > CFPROXY_429_MAX_COOLDOWN {
        return CFPROXY_429_MAX_COOLDOWN;
    }
    delay
}

pub fn mark_cfproxy_429_cooldown_scoped(domain: &str, scope: ProtoScope, err: &WsError) {
    let key = scoped_cfproxy_cooldown_key(domain, scope);
    if key.is_empty() {
        return;
    }
    let d = canonical_cfproxy_cooldown_key(domain);
    let retry_after = retry_after_delay(err);
    let mut map = CFPROXY_429.write();
    let prev = map.get(&key).cloned().unwrap_or_default();
    let delay = next_cfproxy_429_cooldown_delay(&prev, retry_after);
    let mut strikes = prev.strikes + 1;
    let expired = prev
        .until
        .map(|until| until <= Instant::now())
        .unwrap_or(true);
    if expired {
        strikes = 1;
    }
    let new_until = Instant::now() + delay;
    let until = if expired {
        new_until
    } else {
        prev.until
            .map(|existing| existing.max(new_until))
            .unwrap_or(new_until)
    };
    map.insert(
        key.clone(),
        Cfproxy429State {
            until: Some(until),
            strikes,
        },
    );
    drop(map);

    match scope {
        ProtoScope::Mtproto => {
            MTPROTO_429_HITS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            STATS.mtproto_429_cooldown_hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        ProtoScope::Socks5 => {
            SOCKS5_429_HITS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            STATS.socks5_429_cooldown_hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        ProtoScope::Global => {
            GLOBAL_429_HITS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    ldebug!(
        " CF cooldown [{}] {}: {:.0}s after 429 (strike {})",
        scope,
        d,
        delay.as_secs_f64().ceil(),
        strikes
    );
}

pub fn mark_cfproxy_429_cooldown(domain: &str, err: &WsError) {
    mark_cfproxy_429_cooldown_scoped(domain, ProtoScope::Global, err);
}

pub fn cfproxy_429_cooldown_remaining_scoped(domain: &str, scope: ProtoScope) -> Duration {
    let d = canonical_cfproxy_cooldown_key(domain);
    if d.is_empty() {
        return Duration::ZERO;
    }
    let now = Instant::now();
    let current_net = crate::generation_guard::current_network();

    // Check if domain is the user's primary custom worker.
    // User custom worker must NEVER be suppressed by path-level / recovery circuit breaks
    // caused by mobile network jitter, resets or timeouts. Only strict HTTP 429 applies to it.
    let is_custom_user_worker = {
        let user_d = CFPROXY.read().user_domain.trim().to_string();
        !user_d.is_empty() && canonical_cfproxy_cooldown_key(&user_d) == d
    };

    let recovery_remaining = if is_custom_user_worker {
        Duration::ZERO
    } else {
        CFPROXY_RECOVERY_CIRCUIT
            .read()
            .get(&d)
            .and_then(|entry| {
                // Path-specific TCP/TLS/Relay failures are scoped to network generation.
                // If the network generation has changed, the path failure does NOT block the new network!
                if current_net > 0 && entry.network_generation > 0 && current_net != entry.network_generation {
                    None
                } else {
                    Some(entry.until.saturating_duration_since(now))
                }
            })
            .unwrap_or(Duration::ZERO)
    };

    let key = scoped_cfproxy_cooldown_key(domain, scope);
    let mut map = CFPROXY_429.write();
    let until = match map.get(&key).and_then(|state| state.until) {
        Some(until) => until,
        None => return recovery_remaining,
    };
    if until <= now {
        map.remove(&key);
        return recovery_remaining;
    }
    // 429 is endpoint rate-limit: if until > now, it applies to this protocol scope
    (until - now).max(recovery_remaining)
}

pub fn cfproxy_429_cooldown_remaining(domain: &str) -> Duration {
    let g = cfproxy_429_cooldown_remaining_scoped(domain, ProtoScope::Global);
    let m = cfproxy_429_cooldown_remaining_scoped(domain, ProtoScope::Mtproto);
    let s = cfproxy_429_cooldown_remaining_scoped(domain, ProtoScope::Socks5);
    g.max(m).max(s)
}

pub fn try_acquire_cfproxy_half_open_trial(domain: &str, current_net: u64) -> bool {
    let d = canonical_cfproxy_cooldown_key(domain);
    if d.is_empty() {
        return true;
    }
    // 429 is global: if under 429 cooldown, trial is not permitted
    if cfproxy_429_cooldown_remaining(&d) > Duration::ZERO {
        return false;
    }
    let mut map = CFPROXY_RECOVERY_CIRCUIT.write();
    if let Some(entry) = map.get_mut(&d) {
        let now = Instant::now();
        let net_changed = current_net > 0 && entry.network_generation > 0 && current_net != entry.network_generation;
        let expired = now >= entry.until;

        if net_changed || expired {
            if entry.in_flight_trial {
                // "half-open допускает одну попытку, не толпу"
                return false;
            }
            entry.in_flight_trial = true;
            return true;
        }
        // Still open on current network
        return false;
    }
    true
}

pub fn release_cfproxy_half_open_trial(domain: &str) {
    let d = canonical_cfproxy_cooldown_key(domain);
    if !d.is_empty() {
        let mut map = CFPROXY_RECOVERY_CIRCUIT.write();
        if let Some(entry) = map.get_mut(&d) {
            entry.in_flight_trial = false;
        }
    }
}

// ---------------------------------------------------------------------------
// Cache files
// ---------------------------------------------------------------------------

fn cfproxy_cache_path() -> Option<PathBuf> {
    let dir = CFPROXY.read().cache_dir.trim().to_string();
    if dir.is_empty() {
        return None;
    }
    Some(PathBuf::from(dir).join(CFPROXY_CACHE_FILE_NAME))
}

fn load_cfproxy_domains_from_cache() -> Vec<String> {
    let path = match cfproxy_cache_path() {
        Some(p) => p,
        None => return Vec::new(),
    };
    let data = match std::fs::read_to_string(&path) {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };
    let list: Vec<String> = data.split('\n').map(|s| s.to_string()).collect();
    merge_cfproxy_domains(&[list])
}

fn save_cfproxy_domains_to_cache(domains: &[String]) {
    let path = match cfproxy_cache_path() {
        Some(p) => p,
        None => return,
    };
    if domains.is_empty() {
        return;
    }
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            ldebug!(" CF: кеш создать не удалось: {}", e);
            return;
        }
    }
    let data = domains.join("\n");
    if let Err(e) = std::fs::write(&path, data) {
        ldebug!(" CF: кеш сохранить не удалось: {}", e);
    }
}

fn should_refresh_cfproxy_domains() -> bool {
    let path = match cfproxy_cache_path() {
        Some(p) => p,
        None => return true,
    };
    let meta = match std::fs::metadata(&path) {
        Ok(m) => m,
        Err(_) => return true,
    };
    let modified = match meta.modified() {
        Ok(t) => t,
        Err(_) => return true,
    };
    match modified.elapsed() {
        Ok(elapsed) => elapsed >= CFPROXY_REFRESH_INTERVAL,
        Err(_) => true,
    }
}

pub fn init_cfproxy_domains() {
    let defaults = default_cfproxy_domains();
    let cached = load_cfproxy_domains_from_cache();

    crate::generation_guard::change_config(|| {
        let mut cfg = CFPROXY.write();
        if !cached.is_empty() {
            let n = cached.len();
            cfg.domains = merge_cfproxy_domains(&[cached, defaults]);
            crate::balancer::BALANCER
                .write()
                .update_domains_list(&cfg.domains);
            linfo!(" CF: кеш доменов загружен ({} шт.)", n);
        } else {
            cfg.domains = defaults;
            crate::balancer::BALANCER
                .write()
                .update_domains_list(&cfg.domains);
        }
    });
}

pub fn start_cfproxy_refresh() {
    if !crate::ws::is_tls_enabled() {
        ldebug!(" CF: TLS выключен, пропускаю HTTPS-обновление списка доменов");
        return;
    }
    if !should_refresh_cfproxy_domains() {
        ldebug!(" CF: кеш свежий, пропускаю обновление списка");
        return;
    }
    tokio::spawn(async move {
        for _ in 0..3 {
            if try_refresh_cfproxy_domains().await {
                return;
            }
            tokio::time::sleep(Duration::from_secs(10)).await;
        }
        ldebug!(" CF: обновить список доменов не удалось, остаюсь на кеше/встроенном списке");
    });
}

fn decode_chunked_body(data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        let line_end = data[pos..].windows(2).position(|w| w == b"\r\n")?;
        let size_line = std::str::from_utf8(&data[pos..pos + line_end]).ok()?;
        let hex_len = size_line.split(';').next()?.trim();
        let chunk_len = usize::from_str_radix(hex_len, 16).ok()?;
        pos += line_end + 2;
        if chunk_len == 0 {
            return Some(out);
        }
        if pos + chunk_len > data.len() {
            return None;
        }
        out.extend_from_slice(&data[pos..pos + chunk_len]);
        pos += chunk_len;
        if data.get(pos..pos + 2) == Some(b"\r\n") {
            pos += 2;
        } else {
            return None;
        }
    }
    None
}

const MAX_HTTP_FETCH_BYTES: usize = 256 * 1024;

fn parse_http_text_response(raw: &[u8]) -> Result<String, String> {
    let hdr_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "invalid HTTP response headers".to_string())?;
    let hdr_str = std::str::from_utf8(&raw[..hdr_end]).map_err(|e| e.to_string())?;
    let mut lines = hdr_str.lines();
    let status_line = lines.next().ok_or_else(|| "empty HTTP status".to_string())?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    if status != 200 {
        return Err(format!("HTTP {}", status));
    }

    let mut is_chunked = false;
    let mut content_len: Option<usize> = None;
    for line in lines {
        if let Some((name, val)) = line.split_once(':') {
            let k = name.trim().to_ascii_lowercase();
            let v = val.trim().to_ascii_lowercase();
            if k == "transfer-encoding" && v.contains("chunked") {
                is_chunked = true;
            } else if k == "content-length" {
                content_len = v.parse().ok();
            }
        }
    }

    let body_raw = &raw[hdr_end + 4..];
    let body = if is_chunked {
        decode_chunked_body(body_raw).ok_or_else(|| "truncated chunked body".to_string())?
    } else if let Some(len) = content_len {
        if body_raw.len() < len {
            return Err("truncated Content-Length body".to_string());
        }
        body_raw[..len].to_vec()
    } else if raw.len() >= MAX_HTTP_FETCH_BYTES {
        return Err("HTTP response exceeded max size".to_string());
    } else {
        body_raw.to_vec()
    };

    Ok(String::from_utf8_lossy(&body).into_owned())
}

async fn fetch_https_text(url_str: &str, timeout: Duration) -> Result<String, String> {
    let parsed = url::Url::parse(url_str).map_err(|e| e.to_string())?;
    if parsed.scheme() != "https" {
        return Err("only https URLs are supported".to_string());
    }
    let host = parsed.host_str().ok_or("missing URL host")?.to_string();
    let port = parsed.port_or_known_default().unwrap_or(443);
    let mut target = parsed.path().to_string();
    if target.is_empty() {
        target.push('/');
    }
    if let Some(q) = parsed.query() {
        target.push('?');
        target.push_str(q);
    }

    tokio::time::timeout(timeout, async move {
        let resolved_ips: Vec<IpAddr> = tokio::net::lookup_host((host.as_str(), port))
            .await
            .map_err(|e| e.to_string())?
            .map(|sa| sa.ip())
            .collect();
        let (v4, v6): (Vec<IpAddr>, Vec<IpAddr>) =
            resolved_ips.into_iter().partition(|ip| ip.is_ipv4());
        let ordered_ips = crate::network_profile::filter_ip_family(interleave_dual_stack_ips(v6, v4));
        if ordered_ips.is_empty() {
            return Err("DNS returned no usable addresses".to_string());
        }

        let mut connected = None;
        let mut last_err = None;
        for ip in ordered_ips {
            let addr = SocketAddr::new(ip, port);
            match tokio::time::timeout(Duration::from_secs(3), tokio::net::TcpStream::connect(addr)).await {
                Ok(Ok(s)) => {
                    connected = Some(s);
                    break;
                }
                Ok(Err(e)) => last_err = Some(e.to_string()),
                Err(_) => last_err = Some("TCP connect timeout".to_string()),
            }
        }
        let tcp = connected.ok_or_else(|| last_err.unwrap_or_else(|| "TCP connect failed".to_string()))?;
        crate::platform::configure_socket_platform(&socket2::SockRef::from(&tcp));

        let connector = tokio_rustls::TlsConnector::from(TLS_CONFIG_CHROME.clone());
        let mut tls = connector
            .connect(server_name(&host), tcp)
            .await
            .map_err(|e| e.to_string())?;

        let req = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0 tg-ws-proxy-android\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
            target, host
        );
        tls.write_all(req.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        tls.flush().await.map_err(|e| e.to_string())?;

        let mut raw = Vec::new();
        let mut limited = (&mut tls).take(MAX_HTTP_FETCH_BYTES as u64);
        limited
            .read_to_end(&mut raw)
            .await
            .map_err(|e| e.to_string())?;

        parse_http_text_response(&raw)
    })
    .await
    .map_err(|_| "HTTP request timeout".to_string())?
}

pub async fn try_refresh_cfproxy_domains() -> bool {
    if !crate::ws::is_tls_enabled() {
        return false;
    }
    let expected = crate::generation_guard::snapshot();
    let body = match fetch_https_text(CFPROXY_DOMAINS_URL, Duration::from_secs(8)).await {
        Ok(b) => b,
        Err(e) => {
            ldebug!(" CF: GitHub недоступен: {}", e);
            return false;
        }
    };

    let new_domains = parse_cfproxy_domains(&body);

    if !new_domains.is_empty() {
        let merged = merge_cfproxy_domains(&[new_domains.clone(), default_cfproxy_domains()]);
        return crate::generation_guard::change_config_if_current(expected, || {
            CFPROXY.write().domains = merged.clone();
            crate::balancer::BALANCER
                .write()
                .update_domains_list(&merged);
            save_cfproxy_domains_to_cache(&merged);
            linfo!(" CF: список доменов обновлен ({} шт.)", new_domains.len());
            true
        })
        .unwrap_or(false);
    }
    false
}

// ---------------------------------------------------------------------------
// Dual-Stack DNS Resolver (Cloudflare Anycast & System DNS)
// ---------------------------------------------------------------------------

pub const CF_ANYCAST_IPS_V4: &[&str] = &[
    "162.159.192.1",
    "104.16.249.249",
    "172.67.74.152",
    "188.114.97.1",
    "104.21.234.180",
    "188.114.96.1",
];

pub const CF_ANYCAST_IPS_V6: &[&str] = &[
    "2606:4700:4700::1111",
    "2606:4700:4700::1001",
    "2a06:98c1:3121::1",
    "2a06:98c1:3120::1",
    "2606:4700:3033::ac43:999f",
    "2606:4700:3037::6815:eab4",
];

pub fn default_cf_anycast_dual_stack() -> Vec<IpAddr> {
    let mut v6 = Vec::new();
    for s in CF_ANYCAST_IPS_V6 {
        if let Ok(ip) = s.parse::<IpAddr>() {
            v6.push(ip);
        }
    }
    let mut v4 = Vec::new();
    for s in CF_ANYCAST_IPS_V4 {
        if let Ok(ip) = s.parse::<IpAddr>() {
            v4.push(ip);
        }
    }
    interleave_dual_stack_ips(v6, v4)
}

pub fn interleave_dual_stack_ips(v6: Vec<IpAddr>, v4: Vec<IpAddr>) -> Vec<IpAddr> {
    let mut interleaved = Vec::with_capacity(v6.len() + v4.len());
    let ipv6_only = crate::recovery::is_ipv6_only_network();
    if ipv6_only {
        // In pure IPv6-only network without CLAT, all IPv6 addresses come first
        interleaved.extend(v6);
        interleaved.extend(v4);
    } else {
        // Cellular networks and Russian ISPs running TSPU heavily blackhole or throttle
        // Cloudflare Anycast IPv6 (2606:4700::/32). Placing all clean IPv4 addresses first
        // avoids the 3-5s IPv6 SYN timeout completely across mobile and Wi-Fi tethering.
        interleaved.extend(v4);
        interleaved.extend(v6);
    }
    interleaved
}

#[derive(Clone, Debug)]
pub struct CfDohCacheEntry {
    pub ips: Vec<IpAddr>,
    pub expires_at: Instant,
    pub network_generation: u64,
}

static DOH_CACHE: Lazy<
    parking_lot::RwLock<std::collections::HashMap<String, CfDohCacheEntry>>,
> = Lazy::new(|| parking_lot::RwLock::new(std::collections::HashMap::new()));

#[derive(Clone, Debug)]
pub struct CfWinnerCacheEntry {
    pub addr: SocketAddr,
    pub expires_at: Instant,
    pub network_generation: u64,
}

static WINNER_CACHE: Lazy<
    parking_lot::RwLock<std::collections::HashMap<String, CfWinnerCacheEntry>>,
> = Lazy::new(|| parking_lot::RwLock::new(std::collections::HashMap::new()));

pub fn clear_winner_cache() {
    WINNER_CACHE.write().clear();
}

pub fn invalidate_winner_host(domain: &str) {
    let domain = normalize_cf_domain(domain);
    if !domain.is_empty() {
        WINNER_CACHE.write().remove(&domain);
    }
}

pub fn get_cached_winner(domain: &str) -> Option<SocketAddr> {
    let domain = normalize_cf_domain(domain);
    let cur_gen = crate::network_profile::current_generation();
    let entry = WINNER_CACHE.read().get(&domain)?.clone();
    if Instant::now() < entry.expires_at && entry.network_generation == cur_gen {
        Some(entry.addr)
    } else {
        None
    }
}

pub fn set_cached_winner(expected: crate::generation_guard::GenerationStamp, domain: &str, addr: SocketAddr) {
    let domain = normalize_cf_domain(domain);
    if !domain.is_empty() {
        crate::generation_guard::apply_if_current(expected, || {
            WINNER_CACHE.write().insert(
                domain,
                CfWinnerCacheEntry {
                    addr,
                    expires_at: Instant::now() + Duration::from_secs(900),
                    network_generation: expected.network,
                },
            );
        });
    }
}

pub fn clear_doh_cache() {
    DOH_CACHE.write().clear();
    WINNER_CACHE.write().clear();
}

pub fn invalidate_doh_host(domain: &str) {
    let domain = normalize_cf_domain(domain);
    if !domain.is_empty() {
        DOH_CACHE.write().remove(&domain);
        WINNER_CACHE.write().remove(&domain);
    }
}

pub fn cache_resolved_ips_if_current(
    expected: crate::generation_guard::GenerationStamp,
    domain: &str,
    ips: Vec<IpAddr>,
) -> bool {
    crate::generation_guard::apply_if_current(expected, || {
        DOH_CACHE.write().insert(
            domain.to_string(),
            CfDohCacheEntry {
                ips,
                expires_at: Instant::now() + Duration::from_secs(300),
                network_generation: expected.network,
            },
        );
    })
    .is_some()
}

pub fn cached_resolved_ips(domain: &str) -> Option<Vec<IpAddr>> {
    let cur_gen = crate::network_profile::current_generation();
    let entry = DOH_CACHE.read().get(domain)?.clone();
    if Instant::now() < entry.expires_at && entry.network_generation == cur_gen && !entry.ips.is_empty() {
        Some(entry.ips)
    } else {
        None
    }
}

pub fn mark_cfproxy_recovery_cooldown(domain: &str, delay: Duration, reason: &str) {
    mark_cfproxy_recovery_circuit_at_stage(
        domain,
        delay,
        reason,
        crate::recovery::EstablishmentStage::Wss,
        crate::generation_guard::current_network(),
    );
}

pub fn mark_cfproxy_recovery_circuit_at_stage(
    domain: &str,
    delay: Duration,
    reason: &str,
    stage: crate::recovery::EstablishmentStage,
    network_gen: u64,
) {
    let key = canonical_cfproxy_cooldown_key(domain);
    if key.is_empty() {
        return;
    }
    let user_d = CFPROXY.read().user_domain.trim().to_string();
    if !user_d.is_empty() && canonical_cfproxy_cooldown_key(&user_d) == key {
        ldebug!(
            " Suppressing recovery circuit cooldown for primary custom worker {}",
            key
        );
        return;
    }
    let until = Instant::now() + delay;
    let mut map = CFPROXY_RECOVERY_CIRCUIT.write();
    let effective_until = map
        .get(&key)
        .map(|old| old.until.max(until))
        .unwrap_or(until);
    map.insert(
        key.clone(),
        CfproxyRecoveryCircuitEntry {
            until: effective_until,
            network_generation: network_gen,
            stage,
            reason: reason.to_string(),
            in_flight_trial: false,
        },
    );
    drop(map);
    ldebug!(
        " CF recovery circuit {}: {}s (stage={:?}, net={}, {})",
        key,
        delay.as_secs(),
        stage,
        network_gen,
        reason
    );
}

pub fn clear_cfproxy_recovery_cooldown(domain: &str) {
    let key = canonical_cfproxy_cooldown_key(domain);
    if !key.is_empty() {
        CFPROXY_RECOVERY_CIRCUIT.write().remove(&key);
    }
}

pub fn clear_all_recovery_cooldowns() {
    CFPROXY_RECOVERY_CIRCUIT.write().clear();
}

pub async fn resolve_dual_stack_ips(domain: &str) -> Vec<IpAddr> {
    let domain = domain.trim();
    if domain.is_empty() {
        return Vec::new();
    }

    // 1. Direct IP check
    if let Ok(ip) = domain.parse::<IpAddr>() {
        return crate::network_profile::filter_ip_family(vec![ip]);
    }

    // 2. Cache hit (0 ms)
    let cur_gen = crate::network_profile::current_generation();
    if let Some(entry) = DOH_CACHE.read().get(domain).cloned() {
        if Instant::now() < entry.expires_at && entry.network_generation == cur_gen && !entry.ips.is_empty() {
            return crate::network_profile::filter_ip_family(entry.ips);
        }
    }

    // 3. Per-host singleflight resolution via system getaddrinfo
    let expected = crate::generation_guard::snapshot();
    let domain_key = format!("{}:{}:{}:{}", expected.network, expected.profile, expected.config, domain);
    let domain_task = domain.to_string();
    let resolved = crate::budget::DNS_SINGLEFLIGHT
        .execute(domain_key, || async move {
            resolve_dual_stack_ips_uncached(&domain_task, expected).await
        })
        .await;
    crate::network_profile::filter_ip_family(resolved)
}

async fn resolve_dual_stack_ips_uncached(
    domain: &str,
    expected: crate::generation_guard::GenerationStamp,
) -> Vec<IpAddr> {
    // 1. First, try fast system DNS lookup (network-bound, dual-stack via getaddrinfo)
    let host = format!("{}:{}", domain, crate::ws::default_ws_port());
    let mut addrs_list = Vec::new();
    if let Ok(Ok(addrs)) = tokio::time::timeout(Duration::from_millis(1500), tokio::net::lookup_host(&host)).await {
        for a in addrs {
            if !addrs_list.contains(&a.ip()) {
                addrs_list.push(a.ip());
            }
        }
    }

    if !addrs_list.is_empty() {
        if crate::config::is_cloudflare_domain(domain)
            || CFPROXY.read().user_domain.eq_ignore_ascii_case(domain)
            || crate::config::LAST_SOCKS5_WORKER.read().eq_ignore_ascii_case(domain)
        {
            let anycast = default_cf_anycast_dual_stack();
            for ip in anycast {
                if !addrs_list.contains(&ip) {
                    addrs_list.push(ip);
                }
            }
        }
        cache_resolved_ips_if_current(expected, domain, addrs_list.clone());
        return addrs_list;
    }

    // 2. System DNS failed or timed out: fallback to clean Anycast dual-stack
    let anycast = default_cf_anycast_dual_stack();
    cache_resolved_ips_if_current(expected, domain, anycast.clone());
    anycast
}

// ---------------------------------------------------------------------------
// cfConnectDomain (RFC 8305 Happy Eyeballs Dual-Stack Connection)
// ---------------------------------------------------------------------------

pub async fn cf_connect_domain_with_category(
    domain: &str,
    path: &str,
    early_data: Option<&[u8]>,
    timeout: f64,
    category: crate::budget::FlowCategory,
    cancel_token: Option<&CancellationToken>,
) -> (Option<RawWebSocket>, String, Option<WsError>) {
    // One process-wide admission point prevents simultaneous local clients,
    // pool refills and endpoint races from multiplying dial attempts.
    let expected = crate::generation_guard::snapshot();
    let attempt_permit = match crate::budget::DIAL_BUDGET
        .acquire(category, cancel_token)
        .await
    {
        Ok(permit) => permit,
        Err(e) => {
            return (
                None,
                String::new(),
                Some(WsError::Other(format!("Cloudflare dial budget closed: {}", e))),
            )
        }
    };

    if !crate::generation_guard::is_current(expected) {
        return (
            None,
            String::new(),
            Some(WsError::Canceled),
        );
    }

    let dial_generation = attempt_permit.generation;
    let dial_attempt = async {
        let path = if path.is_empty() { "/apiws" } else { path };

        let is_mobile = MOBILE_NETWORK.load(std::sync::atomic::Ordering::Relaxed);
        let dial_timeout = crate::config::adaptive_dial_timeout(is_mobile);
        let attempt_timeout = crate::ws::ws_connect_timeout(timeout);
        let phase_timeout = if path.starts_with("/tcp") {
            attempt_timeout
        } else {
            attempt_timeout.max(dial_timeout)
        };

        let candidate_ips = resolve_dual_stack_ips(domain).await;
        let is_anycast_fallback = if crate::config::is_cloudflare_domain(domain) {
            let anycast = default_cf_anycast_dual_stack();
            !candidate_ips.is_empty() && candidate_ips.iter().all(|ip| anycast.contains(ip))
        } else {
            false
        };
        let default_port = crate::ws::default_ws_port();
        let candidate_addrs: Vec<SocketAddr> = candidate_ips
            .into_iter()
            .map(|ip| SocketAddr::new(ip, default_port))
            .collect();

        if candidate_addrs.is_empty() {
            crate::recovery::record_if_current(
                expected,
                domain,
                crate::recovery::RecoveryCause::DnsFailure,
            );
            return (
                None,
                String::new(),
                Some(WsError::Other(
                    "dns_failed: no candidate addresses resolved".to_string(),
                )),
            );
        }

        // RFC 8305 Section 6: Stateful Address Selection
        // Prioritize the sticky winning address at the head of candidate_addrs (position 0).
        // Happy Eyeballs dials this address immediately at T=0.
        // If it succeeds, only this address connects. If it stalls, the next candidate starts at T=250ms,
        // preventing connection dropouts without any sequential blocking delays!
        let mut addrs_to_dial = candidate_addrs;
        if let Some(sticky_addr) = get_cached_winner(domain) {
            if let Some(pos) = addrs_to_dial.iter().position(|&a| a == sticky_addr) {
                if pos > 0 {
                    addrs_to_dial.swap(0, pos);
                }
                ldebug!(
                    "CF Stateful address selection: prioritized sticky winner {} -> {} (pos 0)",
                    domain,
                    sticky_addr.ip()
                );
            }
        } else {
            ldebug!(
                " CF Happy Eyeballs dial {} with {} dual-stack IPs (fallback_ip={})",
                domain,
                addrs_to_dial.len(),
                is_anycast_fallback
            );
        }

        match crate::ws::ws_connect_happy_eyeballs_ext(
            domain,
            path,
            early_data,
            &addrs_to_dial,
            phase_timeout,
        )
        .await
        {
            Ok((ws, winner_addr)) => {
                let winner_ip = winner_addr.ip().to_string();
                ldebug!(" CF Happy Eyeballs connected {} -> {}", domain, winner_ip);
                set_cached_winner(expected, domain, winner_addr);
                (Some(ws), winner_ip, None)
            }
            Err(e) => {
                invalidate_winner_host(domain);
                if is_anycast_fallback {
                    crate::recovery::record_if_current(
                        expected,
                        domain,
                        crate::recovery::RecoveryCause::FallbackIpFailed,
                    );
                    (
                        None,
                        String::new(),
                        Some(WsError::Other(format!("fallback_ip_failed: {}", e.compact()))),
                    )
                } else {
                    (None, String::new(), Some(e))
                }
            }
        }
    };

    let result = tokio::select! {
        result = dial_attempt => result,
        _ = crate::budget::DIAL_BUDGET.wait_for_generation_change(dial_generation) => {
            (
                None,
                String::new(),
                Some(WsError::Other(format!(
                    "network generation changed during dial ({})",
                    dial_generation
                ))),
            )
        }
    };
    if !crate::generation_guard::is_current(expected) {
        if let Some(ws) = result.0 {
            let _ = ws.close().await;
        }
        return (None, String::new(), Some(WsError::Canceled));
    }
    result
}

pub fn log_cf_conn_error(msg: &str, err: &WsError) {
    if let WsError::Io(e) = err {
        if e.kind() == std::io::ErrorKind::ConnectionReset {
            return;
        }
    }
    if is_http_status_error(err, 429) {
        lwarn!("{}", msg);
    } else {
        lerror!("{}", msg);
    }
}

/// Unified Flowseal Anycast CDN candidate selector shared by MTProto (`WsPool` + Happy Eyeballs)
/// and SOCKS5 (warm pool + Happy Eyeballs).
///
/// When `FLOWSEAL_PER_DC_ENABLED` is `true`, guarantees strict per-DC/per-slot exclusivity:
/// 1. Uses only this slot's disjoint `exclusive_primary` bucket (explicit pin, active domain,
///    or shard `idx % 10 == slot_idx`) while any non-429 domain in it is available.
/// 2. Only borrows from `unoccupied_overflow` (never occupied by another slot) if `exclusive_primary`
///    has no eligible non-429 domains, atomically claiming the borrowed domain(s) under `BALANCER.write()`
///    so concurrent DCs cannot select the same CDN.
/// 3. Falls back to `shared_fallback` ONLY when zero unoccupied non-429 domains exist anywhere.
///
/// Returns normalized base domains (without `kws{dc}.`) that are not currently in 429 cooldown.
pub fn select_flowseal_candidates_for_dc(
    dc: i32,
    is_media: bool,
    scope: ProtoScope,
    max_race_candidates: Option<usize>,
) -> Vec<String> {
    let effective_dc = DC_OVERRIDES.get(&dc).copied().unwrap_or(dc);
    let mut domains = CFPROXY.read().domains.clone();
    if domains.is_empty() {
        domains = default_cfproxy_domains();
    }

    if crate::config::is_flowseal_per_dc_enabled() {
        if max_race_candidates == Some(0) {
            return Vec::new();
        }
        let pinned = crate::config::get_flowseal_pinned_domain(effective_dc, is_media);
        let reserved =
            crate::config::flowseal_pinned_domains_for_other_slots(effective_dc, is_media);

        // Hold BALANCER.write() across bucket computation + atomic in-flight claim so concurrent
        // Tokio tasks for different DCs can never pick the same unoccupied domain.
        let mut bal = crate::balancer::BALANCER.write();
        let buckets = bal.get_domains_for_dc_isolated_buckets(
            effective_dc,
            is_media,
            &domains,
            pinned.as_deref(),
            &reserved,
        );

        let filter_eligible = |list: Vec<String>| -> Vec<String> {
            list.into_iter()
                .filter(|d| {
                    !d.is_empty()
                        && cfproxy_429_cooldown_remaining_scoped(d, scope) == Duration::ZERO
                })
                .collect()
        };

        let excl_ok = filter_eligible(buckets.exclusive_primary);
        if !excl_ok.is_empty() {
            let chosen = match max_race_candidates {
                Some(max_total) => excl_ok.into_iter().take(max_total).collect::<Vec<_>>(),
                None => excl_ok,
            };
            // Warm pools dial `chosen[0]`; races dial all of `chosen`.
            let claim_slice = if max_race_candidates.is_some() {
                &chosen[..]
            } else {
                &chosen[..1]
            };
            bal.claim_in_flight_domains(effective_dc, is_media, claim_slice);
            return chosen;
        }

        let overflow_ok = filter_eligible(buckets.unoccupied_overflow);
        if !overflow_ok.is_empty() {
            let borrow_cap = match max_race_candidates {
                Some(max_total) => {
                    let cap = if overflow_ok.len() > 3 { 2 } else { 1 };
                    cap.min(max_total)
                }
                None => 1,
            };
            let chosen: Vec<String> = overflow_ok.into_iter().take(borrow_cap).collect();
            bal.claim_in_flight_domains(effective_dc, is_media, &chosen);
            return chosen;
        }

        // Last resort: zero unoccupied non-429 domains remain anywhere (e.g. tiny domain list).
        // Do not overwrite another slot's ownership claims; just return shared fallback.
        let shared_ok = filter_eligible(buckets.shared_fallback);
        return match max_race_candidates {
            Some(max_total) => shared_ok.into_iter().take(max_total).collect(),
            None => shared_ok,
        };
    }

    let mut ordered = crate::balancer::BALANCER
        .read()
        .get_domains_for_dc(effective_dc, is_media);
    let mut seen: std::collections::HashSet<String> = ordered.iter().cloned().collect();
    for d in &domains {
        let norm = crate::balancer::normalize_domain(d);
        if !norm.is_empty() && seen.insert(norm.clone()) {
            ordered.push(norm);
        }
    }

    let eligible: Vec<String> = ordered
        .into_iter()
        .filter(|d| {
            !d.is_empty() && cfproxy_429_cooldown_remaining_scoped(d, scope) == Duration::ZERO
        })
        .collect();

    let Some(max_total) = max_race_candidates else {
        return eligible;
    };
    if eligible.is_empty() || max_total == 0 {
        return Vec::new();
    }

    let mut selected = Vec::with_capacity(max_total.min(eligible.len()));
    let mut selected_seen = std::collections::HashSet::new();
    let diverse_ordered = crate::node_independence::NODE_INDEPENDENCE_TRACKER
        .read()
        .select_diverse_race_candidates(&eligible, 4);
    for d in diverse_ordered {
        if selected.len() >= max_total {
            break;
        }
        if selected_seen.insert(d.clone()) {
            selected.push(d);
        }
    }
    for d in &eligible {
        if selected.len() >= max_total {
            break;
        }
        if selected_seen.insert(d.clone()) {
            selected.push(d.clone());
        }
    }

    selected
}

/// Builds a JSON snapshot of the Flowseal per-DC routing configuration, active DC assignments,
/// and available base domains for host apps and diagnostics.
pub fn build_flowseal_dc_config_json() -> String {
    let enabled = crate::config::is_flowseal_per_dc_enabled();
    let pinned_routes: Vec<serde_json::Value> = crate::config::snapshot_flowseal_dc_domains()
        .into_iter()
        .map(|(dc_id, is_media, domain)| {
            serde_json::json!({
                "dc_id": dc_id,
                "is_media": is_media,
                "domain": domain,
            })
        })
        .collect();
    let active_routes: Vec<serde_json::Value> = crate::balancer::BALANCER
        .read()
        .active_routes_snapshot()
        .into_iter()
        .map(|(dc_id, is_media, domain)| {
            serde_json::json!({
                "dc_id": dc_id,
                "is_media": is_media,
                "domain": domain,
            })
        })
        .collect();
    let mut available_domains = CFPROXY.read().domains.clone();
    if available_domains.is_empty() {
        available_domains = default_cfproxy_domains();
    }
    serde_json::json!({
        "enabled": enabled,
        "pinned_routes": pinned_routes,
        "active_routes": active_routes,
        "available_domains": available_domains,
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_doh_cache_clear() {
        let test_ip = "1.2.3.4".parse::<IpAddr>().unwrap();
        DOH_CACHE.write().insert(
            "test.worker.dev".to_string(),
            CfDohCacheEntry {
                ips: vec![test_ip],
                expires_at: Instant::now() + Duration::from_secs(300),
                network_generation: 1,
            },
        );
        assert!(DOH_CACHE.read().contains_key("test.worker.dev"));

        clear_doh_cache();
        assert!(!DOH_CACHE.read().contains_key("test.worker.dev"));
    }

    #[test]
    fn test_cfproxy_429_cooldown_clear() {
        CFPROXY_429.write().insert(
            "test429.worker.dev".to_string(),
            crate::config::Cfproxy429State {
                until: Some(Instant::now() + Duration::from_secs(60)),
                strikes: 1,
            },
        );
        assert!(cfproxy_429_cooldown_remaining("test429.worker.dev") > Duration::ZERO);

        clear_cfproxy_429_cooldowns();
        assert_eq!(
            cfproxy_429_cooldown_remaining("test429.worker.dev"),
            Duration::ZERO
        );
    }

    #[test]
    fn test_interleave_dual_stack_ips() {
        let v6_1 = "2606:4700::1".parse::<IpAddr>().unwrap();
        let v6_2 = "2606:4700::2".parse::<IpAddr>().unwrap();
        let v4_1 = "1.1.1.1".parse::<IpAddr>().unwrap();
        let v4_2 = "1.0.0.1".parse::<IpAddr>().unwrap();

        // Dual-Stack: IPv4 preferred first on Cloudflare Anycast for TSPU bypass
        crate::recovery::set_ipv6_only_network(false);
        let interleaved = interleave_dual_stack_ips(vec![v6_1, v6_2], vec![v4_1, v4_2]);
        assert_eq!(interleaved, vec![v4_1, v4_2, v6_1, v6_2]);

        // IPv6-only network: IPv6 first without IPv4 interleaved ahead
        crate::recovery::set_ipv6_only_network(true);
        let interleaved_v6_only = interleave_dual_stack_ips(vec![v6_1, v6_2], vec![v4_1, v4_2]);
        assert_eq!(interleaved_v6_only, vec![v6_1, v6_2, v4_1, v4_2]);
        crate::recovery::set_ipv6_only_network(false);
    }

    #[test]
    fn test_decode_cf_domain() {
        assert_eq!(decode_cf_domain("virkgj.com"), "pclead.co.uk");
        assert_eq!(decode_cf_domain("vmmzovy.com"), "offshor.co.uk");
        assert_eq!(decode_cf_domain("mkuosckvso.com"), "cakeisalie.co.uk");
        assert_eq!(decode_cf_domain("cakeisalie.co.uk"), "cakeisalie.co.uk");
        // Open domain ending with .com should map to .co.uk without Caesar shifting
        assert_eq!(decode_cf_domain("cakeisalie.com"), "cakeisalie.co.uk");
        assert_eq!(decode_cf_domain("pclead.com"), "pclead.co.uk");
        assert_eq!(decode_cf_domain("kws2.virkgj.com"), "pclead.co.uk");
        assert_eq!(decode_cf_domain("kws4.cakeisalie.co.uk"), "cakeisalie.co.uk");
        assert_eq!(
            decode_cf_domain("my-worker.workers.dev"),
            "my-worker.workers.dev"
        );
        assert_eq!(decode_cf_domain("custom.domain.org"), "custom.domain.org");
    }

    #[test]
    fn test_deduplicate_cfproxy_domains() {
        // Both encrypted and open formats deduplicate cleanly
        let raw = "virkgj.com\npclead.co.uk\npclead.com\nvmmzovy.com\noffshor.co.uk\n";
        let parsed = parse_cfproxy_domains(raw);
        assert_eq!(parsed, vec!["pclead.co.uk".to_string(), "offshor.co.uk".to_string()]);

        let merged = merge_cfproxy_domains(&[
            vec!["virkgj.com".to_string()],
            vec!["pclead.co.uk".to_string(), "pclead.com".to_string()],
            vec!["vmmzovy.com".to_string()],
        ]);
        assert_eq!(merged, vec!["pclead.co.uk".to_string(), "offshor.co.uk".to_string()]);
    }

    #[test]
    fn test_normalize_cf_domain() {
        assert_eq!(normalize_cf_domain("  example.com.  "), "example.com");
        assert_eq!(normalize_cf_domain("PCLEAD.CO.UK"), "pclead.co.uk");
        assert_eq!(
            normalize_cf_domain("my-worker.workers.dev."),
            "my-worker.workers.dev"
        );
        assert_eq!(normalize_cf_domain(""), "");
    }

    #[test]
    fn test_canonical_cfproxy_cooldown_key() {
        assert_eq!(canonical_cfproxy_cooldown_key("kws2.worker.dev"), "worker.dev");
        assert_eq!(canonical_cfproxy_cooldown_key("kws2-1.worker.dev"), "worker.dev");
        assert_eq!(canonical_cfproxy_cooldown_key("worker.dev"), "worker.dev");
    }

    #[test]
    fn test_parse_cfproxy_domains() {
        let raw_data = "# Remote domains list from GitHub\n\nvirkgj.com\nvmmzovy.com\n# Comment\nmkuosckvso.com\n";
        let parsed = parse_cfproxy_domains(raw_data);
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0], "pclead.co.uk");
        assert_eq!(parsed[1], "offshor.co.uk");
        assert_eq!(parsed[2], "cakeisalie.co.uk");
    }

    #[test]
    fn test_non_cloudflare_domain_forbids_anycast_fallback() {
        assert!(!crate::config::is_cloudflare_domain("api.telegram.org"));
        assert!(!crate::config::is_cloudflare_domain("telegram.org"));
        assert!(!crate::config::is_cloudflare_domain("example.com"));
        assert!(!crate::config::is_cloudflare_domain("evil-cloudflare.com"));
        assert!(!crate::config::is_cloudflare_domain("notcloudflare.com"));

        assert!(crate::config::is_cloudflare_domain("my-worker.workers.dev"));
        assert!(crate::config::is_cloudflare_domain("test.pages.dev"));
        assert!(crate::config::is_cloudflare_domain("cloudflare.com"));
        assert!(crate::config::is_cloudflare_domain("dns.cloudflare.com"));
        assert!(crate::config::is_cloudflare_domain("tunnel.trycloudflare.com"));
    }

    #[test]
    fn test_recovery_cause_fallback_ip_failed_distinct_from_dns_failure() {
        assert_ne!(
            crate::recovery::RecoveryCause::DnsFailure,
            crate::recovery::RecoveryCause::FallbackIpFailed
        );
        assert_eq!(
            crate::recovery::action_for_cause(crate::recovery::RecoveryCause::DnsFailure),
            crate::recovery::RecoveryAction::RotateResolverAddress
        );
        assert_eq!(
            crate::recovery::action_for_cause(crate::recovery::RecoveryCause::FallbackIpFailed),
            crate::recovery::RecoveryAction::TryNextWorker
        );
    }

    #[test]
    fn test_mob030_circuit_breaker_network_scoping_and_single_trial() {
        let domain = "test-worker.workers.dev";
        clear_cfproxy_429_cooldowns();

        // 1. Path-specific failure (e.g. Wss or Ready ACK failure) on Network Gen 1
        let net_gen_1 = 1;
        let net_gen_2 = 2;
        mark_cfproxy_recovery_circuit_at_stage(
            domain,
            Duration::from_secs(60),
            "relay_ack_failed",
            crate::recovery::EstablishmentStage::Ready,
            net_gen_1,
        );

        // On Net Gen 1, cooldown is active
        crate::generation_guard::advance_network(); // let's set current_network
        // Under Net Gen 1, half-open trial is not yet permitted because cooldown hasn't expired
        assert!(!try_acquire_cfproxy_half_open_trial(domain, net_gen_1));

        // When network generation switches to Net Gen 2:
        // Path failure is per-network, so on Net Gen 2 half-open trial IS allowed!
        assert!(try_acquire_cfproxy_half_open_trial(domain, net_gen_2));

        // But half-open allows strictly ONE trial ("не толпу"):
        assert!(!try_acquire_cfproxy_half_open_trial(domain, net_gen_2));

        // Releasing trial allows another single trial:
        release_cfproxy_half_open_trial(domain);
        assert!(try_acquire_cfproxy_half_open_trial(domain, net_gen_2));

        // Successful contract verification clears the circuit completely
        clear_cfproxy_recovery_cooldown(domain);
        assert!(try_acquire_cfproxy_half_open_trial(domain, net_gen_2));

        // 2. 429 rate-limiting is GLOBAL across network switches
        let err_429 = WsError::Handshake(crate::ws::WsHandshakeError {
            status_code: 429,
            status_line: "429 Too Many Requests".to_string(),
            headers: std::collections::HashMap::new(),
            location: String::new(),
        });
        mark_cfproxy_429_cooldown(domain, &err_429);

        // 429 blocks both Net Gen 1 and Net Gen 2
        assert!(cfproxy_429_cooldown_remaining(domain) > Duration::ZERO);
        assert!(!try_acquire_cfproxy_half_open_trial(domain, net_gen_1));
        assert!(!try_acquire_cfproxy_half_open_trial(domain, net_gen_2));

        clear_cfproxy_429_cooldowns();
    }

    #[test]
    fn test_parse_http_text_response_variants() {
        let fixed = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\npclead.comextra";
        assert_eq!(parse_http_text_response(fixed).unwrap(), "pclead.com");

        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n6\r\npclead\r\n4\r\n.com\r\n0\r\n\r\n";
        assert_eq!(parse_http_text_response(chunked).unwrap(), "pclead.com");

        let not_found = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(parse_http_text_response(not_found).unwrap_err(), "HTTP 404");

        let trunc = b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\nshort";
        assert!(parse_http_text_response(trunc).is_err());
    }

    #[test]
    fn test_select_flowseal_candidates_per_dc_pin_and_429_failover() {
        let _guard = crate::config::FlowsealPerDcTestGuard::acquire();
        clear_cfproxy_429_cooldowns();
        crate::balancer::BALANCER.write().reset_ranking();

        let pool_domains = vec![
            "pclead.co.uk".to_string(),
            "offshor.co.uk".to_string(),
            "cakeisalie.co.uk".to_string(),
            "noskomnadzor.co.uk".to_string(),
            "lovetrue.co.uk".to_string(),
        ];
        CFPROXY.write().domains = pool_domains.clone();
        crate::balancer::BALANCER
            .write()
            .update_domains_list(&pool_domains);

        crate::config::set_flowseal_per_dc_enabled(true);
        assert!(crate::config::set_flowseal_dc_domain(
            4,
            Some(true),
            "cakeisalie.co.uk"
        ));

        // DC4 Media gets cakeisalie.co.uk at index 0 for both warm pool and Happy Eyeballs race.
        let dc4_warm = select_flowseal_candidates_for_dc(4, true, ProtoScope::Socks5, None);
        let dc4_race = select_flowseal_candidates_for_dc(4, true, ProtoScope::Socks5, Some(6));
        assert_eq!(dc4_warm.first().map(String::as_str), Some("cakeisalie.co.uk"));
        assert_eq!(dc4_race.first().map(String::as_str), Some("cakeisalie.co.uk"));

        // DC2 Chat avoids DC4's pinned domain as its primary candidate.
        let dc2_warm = select_flowseal_candidates_for_dc(2, false, ProtoScope::Socks5, None);
        assert_ne!(dc2_warm.first().map(String::as_str), Some("cakeisalie.co.uk"));

        // Putting cakeisalie.co.uk in SOCKS5 429 cooldown automatically fails DC4 Media over
        // without affecting MTProto scope or DC2 Chat.
        let err_429 = WsError::Handshake(crate::ws::WsHandshakeError {
            status_code: 429,
            status_line: "429 Too Many Requests".to_string(),
            headers: std::collections::HashMap::new(),
            location: String::new(),
        });
        mark_cfproxy_429_cooldown_scoped("kws4.cakeisalie.co.uk", ProtoScope::Socks5, &err_429);

        let dc4_after_429 = select_flowseal_candidates_for_dc(4, true, ProtoScope::Socks5, Some(6));
        assert!(!dc4_after_429.is_empty());
        assert!(!dc4_after_429.contains(&"cakeisalie.co.uk".to_string()));

        let dc4_mtproto = select_flowseal_candidates_for_dc(4, true, ProtoScope::Mtproto, Some(6));
        assert_eq!(
            dc4_mtproto.first().map(String::as_str),
            Some("cakeisalie.co.uk")
        );

        clear_cfproxy_429_cooldowns();
        crate::balancer::BALANCER.write().reset_ranking();
    }

    #[test]
    fn test_select_flowseal_candidates_strict_disjoint_across_all_dcs_and_small_pools() {
        let _guard = crate::config::FlowsealPerDcTestGuard::acquire();
        clear_cfproxy_429_cooldowns();
        crate::balancer::BALANCER.write().reset_ranking();

        // 1. Default 20-domain Flowseal list: all 10 (dc_id, is_media) Happy Eyeballs race sets
        //    must be 100% pairwise disjoint even on simultaneous cold start.
        let twenty_domains: Vec<String> = (0..20).map(|i| format!("fs{:02}.co.uk", i)).collect();
        CFPROXY.write().domains = twenty_domains.clone();
        crate::balancer::BALANCER
            .write()
            .update_domains_list(&twenty_domains);
        crate::config::set_flowseal_per_dc_enabled(true);

        let mut seen_across_all_slots = std::collections::HashSet::new();
        for dc in 1..=5 {
            for is_media in [false, true] {
                let race_set =
                    select_flowseal_candidates_for_dc(dc, is_media, ProtoScope::Socks5, Some(6));
                assert_eq!(
                    race_set.len(),
                    2,
                    "DC{} media={} should own its 2 disjoint shard domains",
                    dc,
                    is_media
                );
                for dom in race_set {
                    assert!(
                        seen_across_all_slots.insert(dom.clone()),
                        "collision detected: {} assigned to DC{} media={} while already claimed by another slot",
                        dom,
                        dc,
                        is_media
                    );
                }
            }
        }
        assert_eq!(seen_across_all_slots.len(), 20);

        // 2. Tight 5-domain list across 5 active slots: atomic in-flight claims guarantee
        //    5 distinct CDN domains with zero overlap even when slots exceed shard indices.
        crate::balancer::BALANCER.write().reset_ranking();
        let five_domains: Vec<String> = (0..5).map(|i| format!("tiny{}.co.uk", i)).collect();
        CFPROXY.write().domains = five_domains.clone();
        crate::balancer::BALANCER
            .write()
            .update_domains_list(&five_domains);

        let five_slots = [(1, false), (2, false), (2, true), (4, true), (5, false)];
        let mut seen_five = std::collections::HashSet::new();
        for (dc, is_media) in five_slots {
            let race_set =
                select_flowseal_candidates_for_dc(dc, is_media, ProtoScope::Mtproto, Some(6));
            assert_eq!(race_set.len(), 1);
            assert!(
                seen_five.insert(race_set[0].clone()),
                "tight-pool collision on {} for DC{} media={}",
                race_set[0],
                dc,
                is_media
            );
        }
        assert_eq!(seen_five.len(), 5);

        // 3. When a slot's own shard fails (consecutive_failures > 0), it borrows an unoccupied
        //    domain from another unused shard without colliding with active/claimed slots.
        crate::balancer::BALANCER.write().reset_ranking();
        CFPROXY.write().domains = twenty_domains.clone();
        crate::balancer::BALANCER
            .write()
            .update_domains_list(&twenty_domains);

        let dc2_chat = select_flowseal_candidates_for_dc(2, false, ProtoScope::Socks5, Some(6));
        let dc4_media_initial =
            select_flowseal_candidates_for_dc(4, true, ProtoScope::Socks5, Some(6));
        let gen = crate::balancer::BALANCER.read().current_generation();
        for dom in &dc4_media_initial {
            crate::balancer::BALANCER
                .write()
                .record_failure(gen, 4, true, dom);
        }
        let dc4_media_failover =
            select_flowseal_candidates_for_dc(4, true, ProtoScope::Socks5, Some(6));
        assert!(!dc4_media_failover.is_empty());
        for dom in &dc4_media_failover {
            assert!(
                !dc2_chat.contains(dom),
                "DC4 Media failover {} collided with DC2 Chat {:?}",
                dom,
                dc2_chat
            );
            assert!(
                !dc4_media_initial.contains(dom),
                "DC4 Media failover reused failed shard domain {}",
                dom
            );
        }

        // 4. Pool smaller than active slots (2 domains, 3 DCs): first 2 get distinct domains,
        //    3rd safely falls back instead of returning empty.
        crate::balancer::BALANCER.write().reset_ranking();
        let two_domains = vec!["only1.co.uk".to_string(), "only2.co.uk".to_string()];
        CFPROXY.write().domains = two_domains.clone();
        crate::balancer::BALANCER
            .write()
            .update_domains_list(&two_domains);

        let s1 = select_flowseal_candidates_for_dc(1, false, ProtoScope::Socks5, Some(6));
        let s2 = select_flowseal_candidates_for_dc(2, false, ProtoScope::Socks5, Some(6));
        let s3 = select_flowseal_candidates_for_dc(4, true, ProtoScope::Socks5, Some(6));
        assert_eq!(s1.len(), 1);
        assert_eq!(s2.len(), 1);
        assert_ne!(s1[0], s2[0]);
        assert!(!s3.is_empty(), "3rd DC must fall back instead of returning empty");

        clear_cfproxy_429_cooldowns();
        crate::balancer::BALANCER.write().reset_ranking();
    }

    #[test]
    fn test_experimental_per_dc_toggle_off_preserves_legacy_behavior() {
        let _guard = crate::config::FlowsealPerDcTestGuard::acquire();
        clear_cfproxy_429_cooldowns();
        crate::balancer::BALANCER.write().reset_ranking();

        let domains = vec![
            "pclead.co.uk".to_string(),
            "offshor.co.uk".to_string(),
            "cakeisalie.co.uk".to_string(),
        ];
        CFPROXY.write().domains = domains.clone();
        crate::balancer::BALANCER
            .write()
            .update_domains_list(&domains);

        // Experimental toggle is OFF by default.
        assert!(!crate::config::is_flowseal_per_dc_enabled());

        // Even if a pin is saved in config, it MUST NOT take effect while toggle is OFF.
        assert!(crate::config::set_flowseal_dc_domain(
            4,
            Some(true),
            "cakeisalie.co.uk"
        ));

        // Legacy behavior: DC2 and DC4 can both set and share the same active domain ("pclead.co.uk").
        assert!(crate::balancer::BALANCER
            .write()
            .update_domain_for_dc(2, false, "pclead.co.uk"));
        assert!(crate::balancer::BALANCER
            .write()
            .update_domain_for_dc(4, true, "pclead.co.uk"));
        assert_eq!(
            crate::balancer::BALANCER
                .read()
                .get_active_domain_for_dc(4, true)
                .as_deref(),
            Some("pclead.co.uk")
        );

        // Selector with toggle OFF ignores DC4 pin ("cakeisalie.co.uk") and leads with legacy active domain.
        let dc4_off = select_flowseal_candidates_for_dc(4, true, ProtoScope::Socks5, Some(6));
        assert_eq!(dc4_off.first().map(String::as_str), Some("pclead.co.uk"));

        // Turning the experimental toggle ON immediately activates pin & isolation.
        crate::config::set_flowseal_per_dc_enabled(true);
        let dc4_on = select_flowseal_candidates_for_dc(4, true, ProtoScope::Socks5, Some(6));
        assert_eq!(dc4_on.first().map(String::as_str), Some("cakeisalie.co.uk"));
        assert!(!dc4_on.contains(&"pclead.co.uk".to_string()));

        clear_cfproxy_429_cooldowns();
        crate::balancer::BALANCER.write().reset_ranking();
    }
}
