use once_cell::sync::Lazy;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicI64, AtomicU64, Ordering};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Constants & Configuration
// ---------------------------------------------------------------------------

// Controls TCP_NODELAY on proxy and WebSocket sockets (default false = Nagle enabled; toggled via SetTcpNoDelay).
pub static TCP_NODELAY: AtomicBool = AtomicBool::new(false);
pub static SOCKS5_OPTIMISTIC_RESPONSE: AtomicBool = AtomicBool::new(true);

pub const SOCKS5_UPLINK_WORKER: i32 = 0;
pub const SOCKS5_UPLINK_FLOWSEAL: i32 = 1;
pub static SOCKS5_UPLINK_MODE: AtomicI32 = AtomicI32::new(SOCKS5_UPLINK_WORKER);

#[inline]
pub fn get_socks5_uplink_mode() -> i32 {
    SOCKS5_UPLINK_MODE.load(Ordering::Relaxed)
}

#[inline]
pub fn set_socks5_uplink_mode(mode: i32) {
    SOCKS5_UPLINK_MODE.store(mode, Ordering::Relaxed);
}
pub const DEFAULT_RECV_BUF: usize = 0;
pub const DEFAULT_SEND_BUF: usize = 0;
pub const DEFAULT_MTPROTO_STANDBY_PER_ACTIVE_SLOT: i32 = 2;

/// Profile-aware absolute idle timeout for active bridges.
/// Data idle != dead: a flow with active transport health (PONG frames / TCP keepalive)
/// remains open across long idle pauses (10+ minutes). This absolute ceiling retires
/// completely abandoned flows after 15–30 minutes to prevent resource leaks.
pub fn profile_aware_absolute_idle_timeout() -> Duration {
    let profile = crate::network_profile::get_profile();
    match (profile.power_save_mode, profile.screen_on, profile.is_constrained()) {
        (true, _, _) => Duration::from_secs(30 * 60),        // 30 min in power save
        (false, false, _) => Duration::from_secs(30 * 60),    // 30 min screen off
        (false, true, true) => Duration::from_secs(15 * 60),   // 15 min active cellular / metered
        (false, true, false) => Duration::from_secs(30 * 60),  // 30 min active broadband Wi-Fi
    }
}

/// Helper struct representing a bounded range [min .. max] for adaptive network calibration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdaptiveRange<T> {
    pub min: T,
    pub max: T,
}

impl<T: Ord + Copy> AdaptiveRange<T> {
    pub const fn new(min: T, max: T) -> Self {
        Self { min, max }
    }

    pub fn clamp(&self, val: T) -> T {
        val.clamp(self.min, self.max)
    }
}

pub const ESTABLISHMENT_BUDGET_MOBILE_RANGE: AdaptiveRange<usize> = AdaptiveRange::new(4, 16);
pub const ESTABLISHMENT_BUDGET_WIFI_RANGE: AdaptiveRange<usize> = AdaptiveRange::new(6, 24);
pub const BACKGROUND_BUDGET_MOBILE_RANGE: AdaptiveRange<usize> = AdaptiveRange::new(4, 10);
pub const BACKGROUND_BUDGET_WIFI_RANGE: AdaptiveRange<usize> = AdaptiveRange::new(6, 16);

pub const DIAL_TIMEOUT_WIFI_RANGE_MS: AdaptiveRange<u64> = AdaptiveRange::new(1500, 5000);
pub const DIAL_TIMEOUT_MOBILE_RANGE_MS: AdaptiveRange<u64> = AdaptiveRange::new(2500, 9000);
pub const HAPPY_EYEBALLS_RANGE_MS: AdaptiveRange<u64> = AdaptiveRange::new(80, 800);

/// Adaptive establishment and background concurrency budgets.
/// Calibrated against current network profile: RTT, jitter, downlink throughput, and power state.
pub fn adaptive_establishment_budget(is_mobile: bool) -> (usize, usize) {
    let profile = crate::network_profile::get_profile();
    let rtt = profile.transport_sli.smoothed_rtt_ms;
    let jitter = profile.transport_sli.jitter_ms;
    let down_kbps = if profile.transport_sli.downstream_bps > 0 {
        profile.transport_sli.downstream_bps / 1000
    } else {
        profile.estimated_down_kbps as u64
    };
    let is_congested = profile.congested || (rtt > 600) || (jitter > 300);
    let power_save = profile.power_save_mode;

    if is_mobile {
        let est = if power_save || is_congested {
            4
        } else if rtt > 0 && rtt < 100 && down_kbps > 20_000 {
            if down_kbps > 50_000 && rtt < 60 { 16 } else { 12 }
        } else if rtt > 0 && rtt < 250 && down_kbps > 5_000 {
            10
        } else {
            // Cold start default on mobile LTE: allow rapid parallel multi-DC stream pre-warming
            8
        };
        let bg = if power_save || is_congested { 3 } else if est >= 8 { 6 } else { 4 };
        (ESTABLISHMENT_BUDGET_MOBILE_RANGE.clamp(est), BACKGROUND_BUDGET_MOBILE_RANGE.clamp(bg))
    } else {
        let est = if power_save || is_congested {
            6
        } else if (rtt > 0 && rtt < 40 && down_kbps > 50_000) || down_kbps > 100_000 {
            20
        } else if (rtt > 0 && rtt < 80 && down_kbps > 25_000) || down_kbps > 40_000 {
            16
        } else if rtt > 0 && rtt < 150 {
            12
        } else {
            10
        };
        let bg = if power_save || is_congested { 4 } else if est >= 12 { 8 } else if est >= 8 { 6 } else { 4 };
        (ESTABLISHMENT_BUDGET_WIFI_RANGE.clamp(est), BACKGROUND_BUDGET_WIFI_RANGE.clamp(bg))
    }
}

/// Adaptive dial phase timeout calibrated to radio channel characteristics.
pub fn adaptive_dial_timeout(is_mobile: bool) -> Duration {
    let profile = crate::network_profile::get_profile();
    let rtt = profile.transport_sli.smoothed_rtt_ms;
    let jitter = profile.transport_sli.jitter_ms;

    if is_mobile {
        let base_ms = if rtt > 0 {
            (rtt as u64) * 4 + jitter * 3 + 1500
        } else {
            4000
        };
        Duration::from_millis(DIAL_TIMEOUT_MOBILE_RANGE_MS.clamp(base_ms))
    } else {
        let base_ms = if rtt > 0 {
            (rtt as u64) * 3 + jitter * 2 + 1000
        } else {
            2500
        };
        Duration::from_millis(DIAL_TIMEOUT_WIFI_RANGE_MS.clamp(base_ms))
    }
}

/// Adaptive parallel TCP/TLS candidate socket throttle limit.
pub fn adaptive_parallel_socket_limit() -> usize {
    let profile = crate::network_profile::get_profile();
    let rtt = profile.transport_sli.smoothed_rtt_ms;
    let jitter = profile.transport_sli.jitter_ms;
    if profile.is_constrained() {
        if profile.power_save_mode || profile.congested || rtt > 500 || jitter > 250 {
            4
        } else if rtt > 0 && rtt < 100 {
            8
        } else {
            6
        }
    } else {
        if profile.congested {
            6
        } else if rtt > 0 && rtt < 50 {
            12
        } else {
            8
        }
    }
}

/// Adaptive WebSocket pool connect timeout in seconds.
pub fn adaptive_ws_connect_timeout() -> f64 {
    let profile = crate::network_profile::get_profile();
    let rtt = profile.transport_sli.smoothed_rtt_ms;
    let jitter = profile.transport_sli.jitter_ms;
    let secs = if rtt > 0 {
        ((rtt as f64) * 4.0 + (jitter as f64) * 2.0 + 3000.0) / 1000.0
    } else if profile.is_constrained() {
        10.0
    } else {
        8.0
    };
    secs.clamp(4.0, 14.0)
}


pub const BRIDGE_WRITE_TIMEOUT: Duration = Duration::from_secs(45);
pub const WS_HEARTBEAT_CHECK_INTERVAL: Duration = Duration::from_secs(5);
pub const WS_POOL_HOUSEKEEP_INTERVAL: Duration = Duration::from_secs(10);
pub const WS_WRITE_TIMEOUT: Duration = Duration::from_secs(60);
// Control writes tolerate the same network stalls as payload writes.
pub const WS_CONTROL_TIMEOUT: Duration = Duration::from_secs(45);
pub const WS_BRIDGE_CHUNK_SIZE: usize = 64 * 1024;

pub const WS_POOL_REUSE_MAX_AGE: f64 = 120.0;

pub const CFPROXY_CACHE_FILE_NAME: &str = "cfproxy-domains-cache.txt";
pub const CFPROXY_REFRESH_INTERVAL: Duration = Duration::from_secs(12 * 3600);
pub const CFPROXY_429_COOLDOWN: Duration = Duration::from_secs(45);
pub const CFPROXY_429_MAX_COOLDOWN: Duration = Duration::from_secs(300);

pub const MIN_SOCKET_BUFFER: i32 = 32 * 1024;
pub const DEFAULT_MAX_SOCKET_BUFFER: i32 = 2 * 1024 * 1024;
pub const HIGH_THROUGHPUT_MAX_SOCKET_BUFFER: i32 = 8 * 1024 * 1024;

/// Backward-compatible alias for existing code
pub const MAX_SOCKET_BUFFER: i32 = DEFAULT_MAX_SOCKET_BUFFER;

/// Dynamic atomic ceiling for TCP / SOCKS5 sockets (defaults to 2 MiB)
pub static MAX_SOCKET_BUFFER_CEILING: AtomicI32 = AtomicI32::new(DEFAULT_MAX_SOCKET_BUFFER);

#[inline]
pub fn max_socket_buffer() -> i32 {
    MAX_SOCKET_BUFFER_CEILING.load(Ordering::Relaxed)
}

#[inline]
pub fn set_max_socket_buffer_ceiling(ceiling: i32) {
    let clamped = ceiling.clamp(MIN_SOCKET_BUFFER, HIGH_THROUGHPUT_MAX_SOCKET_BUFFER);
    MAX_SOCKET_BUFFER_CEILING.store(clamped, Ordering::Relaxed);
}

pub static REQUESTED_RECV_BUF: AtomicI32 = AtomicI32::new(DEFAULT_RECV_BUF as i32);
pub static REQUESTED_SEND_BUF: AtomicI32 = AtomicI32::new(DEFAULT_SEND_BUF as i32);
pub static RECV_BUF: AtomicI32 = AtomicI32::new(DEFAULT_RECV_BUF as i32);
pub static SEND_BUF: AtomicI32 = AtomicI32::new(DEFAULT_SEND_BUF as i32);
pub static LAST_OS_RECV_BUF: AtomicI32 = AtomicI32::new(0);
pub static LAST_OS_SEND_BUF: AtomicI32 = AtomicI32::new(0);
pub static SOCKETS_CONFIGURED_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static LAST_LOGGED_OS_BUFFER_PAIR: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SocketBufferStatus {
    pub configured_recv_bytes: i32,
    pub configured_send_bytes: i32,
    pub clamped_recv_bytes: i32,
    pub clamped_send_bytes: i32,
    pub last_os_recv_bytes: i32,
    pub last_os_send_bytes: i32,
    pub sockets_configured_total: u64,
    pub autotune_baseline: bool,
}

pub fn get_socket_buffer_status() -> SocketBufferStatus {
    let configured_recv = REQUESTED_RECV_BUF.load(Ordering::Relaxed);
    let configured_send = REQUESTED_SEND_BUF.load(Ordering::Relaxed);
    let clamped_recv = RECV_BUF.load(Ordering::Relaxed);
    let clamped_send = SEND_BUF.load(Ordering::Relaxed);
    let autotune = clamped_recv == 0 && clamped_send == 0;
    SocketBufferStatus {
        configured_recv_bytes: configured_recv,
        configured_send_bytes: configured_send,
        clamped_recv_bytes: clamped_recv,
        clamped_send_bytes: clamped_send,
        last_os_recv_bytes: LAST_OS_RECV_BUF.load(Ordering::Relaxed),
        last_os_send_bytes: LAST_OS_SEND_BUF.load(Ordering::Relaxed),
        sockets_configured_total: SOCKETS_CONFIGURED_TOTAL.load(Ordering::Relaxed),
        autotune_baseline: autotune,
    }
}

pub static MTPROTO_STANDBY_PER_ACTIVE_SLOT_REQUESTED: AtomicI32 =
    AtomicI32::new(DEFAULT_MTPROTO_STANDBY_PER_ACTIVE_SLOT);
pub static LOG_VERBOSE: AtomicBool = AtomicBool::new(false);
/// Set by the Android connectivity observer. Wi-Fi keeps the existing tuning;
/// cellular uses a smaller shared dial budget and a conservative idle pool.
pub static MOBILE_NETWORK: AtomicBool = AtomicBool::new(false);

/// Throttling of concurrent dial attempts (disabled by default, managed via Advanced Settings).
pub static DIAL_THROTTLING_ENABLED: AtomicBool = AtomicBool::new(false);

pub fn is_dial_throttling_enabled() -> bool {
    DIAL_THROTTLING_ENABLED.load(Ordering::Relaxed)
}

pub fn set_dial_throttling_enabled(enabled: bool) {
    DIAL_THROTTLING_ENABLED.store(enabled, Ordering::Relaxed);
}

// ---------------------------------------------------------------------------
// Transport Pool & Concurrency Metrics (MOB-016)
// ---------------------------------------------------------------------------

pub const MTPROTO_MIN_STANDBY: i32 = 1;
pub const MTPROTO_MAX_STANDBY: i32 = 4;

/// Computes the effective MTProto standby socket limit per active DC slot.
/// On mobile: 1 standby socket to keep resource and radio footprint minimal.
/// On Wi-Fi: requested pool size clamped to 1..4 (native upper bound).
pub fn effective_mtproto_standby(requested: i32, is_mobile: bool) -> usize {
    if is_mobile {
        1
    } else {
        requested.clamp(MTPROTO_MIN_STANDBY, MTPROTO_MAX_STANDBY) as usize
    }
}

/// Global establishment (dial) budget.
/// Dynamically scales within [1 .. 5] on mobile and [3 .. 8] on Wi-Fi.
pub fn global_establishment_budget(is_mobile: bool) -> usize {
    adaptive_establishment_budget(is_mobile).0
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TransportPoolStatus {
    pub transport: String,
    pub is_mobile: bool,
    pub mtproto_standby_per_active_slot_requested: i32,
    pub mtproto_standby_per_active_slot_effective: i32,
    pub global_establishment_budget: usize,
    pub socks_concurrent_flows: i64,
}

pub fn get_transport_pool_status(running_transport: &str) -> TransportPoolStatus {
    let is_mobile = MOBILE_NETWORK.load(Ordering::Relaxed);
    let requested = MTPROTO_STANDBY_PER_ACTIVE_SLOT_REQUESTED.load(Ordering::Relaxed);
    let effective = effective_mtproto_standby(requested, is_mobile) as i32;
    let budget = global_establishment_budget(is_mobile);
    let flows = if running_transport == "socks5" {
        STATS.connections_active.load(Ordering::Relaxed)
    } else {
        0
    };

    TransportPoolStatus {
        transport: running_transport.to_string(),
        is_mobile,
        mtproto_standby_per_active_slot_requested: requested,
        mtproto_standby_per_active_slot_effective: effective,
        global_establishment_budget: budget,
        socks_concurrent_flows: flows,
    }
}

#[derive(Clone, Default)]
pub struct Cfproxy429State {
    pub until: Option<Instant>,
    pub strikes: i32,
}

// Cloudflare proxy config
pub static CFPROXY_ENABLED: AtomicBool = AtomicBool::new(true);

pub struct CfproxyConfig {
    pub user_domain: String,
    pub domains: Vec<String>,
    pub active: String,
    pub cache_dir: String,
}

pub static CFPROXY: Lazy<RwLock<CfproxyConfig>> = Lazy::new(|| {
    RwLock::new(CfproxyConfig {
        user_domain: String::new(),
        domains: Vec::new(),
        active: String::new(),
        cache_dir: String::new(),
    })
});

pub static CFPROXY_429: Lazy<RwLock<HashMap<String, Cfproxy429State>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

// Flowseal Anycast CDN per-DC routing configuration (independent of Cloudflare Worker `user_domain`).
pub static FLOWSEAL_PER_DC_ENABLED: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FlowsealDcRouteKey {
    pub dc_id: i32,
    /// `None` applies to both chat and media on `dc_id`; `Some(false)` = chat only; `Some(true)` = media only.
    pub is_media: Option<bool>,
}

pub static FLOWSEAL_DC_DOMAINS: Lazy<RwLock<HashMap<FlowsealDcRouteKey, String>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

#[inline]
pub fn is_flowseal_per_dc_enabled() -> bool {
    FLOWSEAL_PER_DC_ENABLED.load(Ordering::Relaxed)
}

#[inline]
pub fn set_flowseal_per_dc_enabled(enabled: bool) {
    FLOWSEAL_PER_DC_ENABLED.store(enabled, Ordering::Relaxed);
}

pub fn normalize_flowseal_dc_domain(raw: &str) -> String {
    let trimmed = raw.trim().trim_end_matches('.');
    if trimmed.is_empty() || trimmed.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return String::new();
    }
    let stripped = crate::balancer::normalize_domain(trimmed)
        .trim_end_matches('.')
        .to_string();
    if stripped.is_empty() {
        return String::new();
    }
    if crate::cfproxy::FLOWSEAL_OPEN_BASES.contains(&stripped.as_str()) {
        return format!("{}.co.uk", stripped);
    }
    if !stripped.contains('.') {
        return String::new();
    }
    stripped
}

pub fn set_flowseal_dc_domain(dc_id: i32, is_media: Option<bool>, raw_domain: &str) -> bool {
    if !(1..=5).contains(&dc_id) {
        return false;
    }
    let key = FlowsealDcRouteKey { dc_id, is_media };
    if raw_domain.trim().is_empty() {
        FLOWSEAL_DC_DOMAINS.write().remove(&key);
        return true;
    }
    let normalized = normalize_flowseal_dc_domain(raw_domain);
    if normalized.is_empty() {
        return false;
    }
    FLOWSEAL_DC_DOMAINS.write().insert(key, normalized);
    true
}

pub fn clear_flowseal_dc_domains() {
    FLOWSEAL_DC_DOMAINS.write().clear();
}

pub fn get_flowseal_pinned_domain(dc_id: i32, is_media: bool) -> Option<String> {
    let effective_dc = DC_OVERRIDES.get(&dc_id).copied().unwrap_or(dc_id);
    let map = FLOWSEAL_DC_DOMAINS.read();
    map.get(&FlowsealDcRouteKey {
        dc_id: effective_dc,
        is_media: Some(is_media),
    })
    .or_else(|| {
        map.get(&FlowsealDcRouteKey {
            dc_id: effective_dc,
            is_media: None,
        })
    })
    .cloned()
}

pub fn flowseal_pinned_domains_for_other_slots(
    dc_id: i32,
    is_media: bool,
) -> std::collections::HashSet<String> {
    let effective_dc = DC_OVERRIDES.get(&dc_id).copied().unwrap_or(dc_id);
    let map = FLOWSEAL_DC_DOMAINS.read();
    let own = map
        .get(&FlowsealDcRouteKey {
            dc_id: effective_dc,
            is_media: Some(is_media),
        })
        .or_else(|| {
            map.get(&FlowsealDcRouteKey {
                dc_id: effective_dc,
                is_media: None,
            })
        });
    let mut reserved = std::collections::HashSet::new();
    for dom in map.values() {
        if own.map(|o| o.as_str()) != Some(dom.as_str()) {
            reserved.insert(dom.clone());
        }
    }
    reserved
}

pub fn snapshot_flowseal_dc_domains() -> Vec<(i32, Option<bool>, String)> {
    let map = FLOWSEAL_DC_DOMAINS.read();
    let mut entries: Vec<(FlowsealDcRouteKey, String)> =
        map.iter().map(|(k, v)| (*k, v.clone())).collect();
    entries.sort_by_key(|(k, _)| *k);
    entries
        .into_iter()
        .map(|(k, v)| (k.dc_id, k.is_media, v))
        .collect()
}

fn parse_flowseal_dc_map_key(raw_key: &str) -> Option<FlowsealDcRouteKey> {
    let lower = raw_key.trim().to_ascii_lowercase();
    let rest = lower.strip_prefix("dc").unwrap_or(&lower);
    let (dc_part, is_media) = if let Some(prefix) = rest.strip_suffix("_media") {
        (prefix, Some(true))
    } else if let Some(prefix) = rest.strip_suffix("-media") {
        (prefix, Some(true))
    } else if let Some(prefix) = rest.strip_suffix(":media") {
        (prefix, Some(true))
    } else if let Some(prefix) = rest.strip_suffix("_chat") {
        (prefix, Some(false))
    } else if let Some(prefix) = rest.strip_suffix("-chat") {
        (prefix, Some(false))
    } else if let Some(prefix) = rest.strip_suffix(":chat") {
        (prefix, Some(false))
    } else if let Some(prefix) = rest.strip_suffix('m') {
        (prefix, Some(true))
    } else if let Some(prefix) = rest.strip_suffix('c') {
        (prefix, Some(false))
    } else {
        (rest, None)
    };
    let dc_id = dc_part.parse::<i32>().ok()?;
    if !(1..=5).contains(&dc_id) {
        return None;
    }
    Some(FlowsealDcRouteKey { dc_id, is_media })
}

fn parse_flowseal_route_entry(
    val: &serde_json::Value,
    out: &mut HashMap<FlowsealDcRouteKey, String>,
) -> Result<(), String> {
    let obj = val
        .as_object()
        .ok_or_else(|| "route entry must be an object".to_string())?;
    let dc_val = obj
        .get("dc_id")
        .or_else(|| obj.get("dc"))
        .and_then(|v| v.as_i64())
        .ok_or_else(|| "route entry missing integer dc_id".to_string())?;
    let dc_id = dc_val as i32;
    if !(1..=5).contains(&dc_id) {
        return Err(format!("dc_id out of range 1..=5: {}", dc_id));
    }
    let is_media = match obj.get("is_media").or_else(|| obj.get("media")) {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::Bool(b)) => Some(*b),
        Some(serde_json::Value::Number(n)) => match n.as_i64() {
            Some(0) => Some(false),
            Some(1) => Some(true),
            Some(-1) => None,
            _ => return Err("invalid numeric is_media (expected -1, 0, or 1)".to_string()),
        },
        _ => return Err("invalid is_media type".to_string()),
    };
    let domain_raw = obj
        .get("domain")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "route entry missing string domain".to_string())?;
    let key = FlowsealDcRouteKey { dc_id, is_media };
    if domain_raw.trim().is_empty() {
        out.remove(&key);
        return Ok(());
    }
    let normalized = normalize_flowseal_dc_domain(domain_raw);
    if normalized.is_empty() {
        return Err(format!("invalid Flowseal domain: {}", domain_raw));
    }
    out.insert(key, normalized);
    Ok(())
}

fn parse_flowseal_map_object(
    obj: &serde_json::Map<String, serde_json::Value>,
    out: &mut HashMap<FlowsealDcRouteKey, String>,
) -> Result<(), String> {
    for (k, v) in obj {
        let key = parse_flowseal_dc_map_key(k)
            .ok_or_else(|| format!("invalid DC route key: {}", k))?;
        let domain_raw = v
            .as_str()
            .ok_or_else(|| format!("domain for {} must be a string", k))?;
        if domain_raw.trim().is_empty() {
            out.remove(&key);
            continue;
        }
        let normalized = normalize_flowseal_dc_domain(domain_raw);
        if normalized.is_empty() {
            return Err(format!("invalid Flowseal domain for {}: {}", k, domain_raw));
        }
        out.insert(key, normalized);
    }
    Ok(())
}

/// Atomically parses and applies Flowseal per-DC routing configuration from JSON.
/// Supported formats:
/// - `{"enabled": true, "routes": [{"dc_id": 2, "is_media": true, "domain": "offshor.co.uk"}]}`
/// - `{"enabled": true, "domains": {"dc2": "pclead.co.uk", "dc4_media": "cakeisalie.co.uk"}}`
/// - `{"dc2": "pclead.co.uk", "4m": "cakeisalie.co.uk"}`
/// - `[{"dc_id": 4, "is_media": true, "domain": "cakeisalie.co.uk"}]`
pub fn set_flowseal_dc_domains_from_json(raw_json: &str) -> Result<usize, String> {
    let val: serde_json::Value =
        serde_json::from_str(raw_json).map_err(|e| format!("invalid JSON: {}", e))?;
    let mut parsed_routes: HashMap<FlowsealDcRouteKey, String> = HashMap::new();
    let mut parsed_enabled: Option<bool> = None;

    match &val {
        serde_json::Value::Array(arr) => {
            for item in arr {
                parse_flowseal_route_entry(item, &mut parsed_routes)?;
            }
        }
        serde_json::Value::Object(obj) => {
            if let Some(en) = obj.get("enabled") {
                parsed_enabled = Some(
                    en.as_bool()
                        .ok_or_else(|| "`enabled` field must be boolean".to_string())?,
                );
            }
            if let Some(routes_val) = obj.get("routes") {
                let arr = routes_val
                    .as_array()
                    .ok_or_else(|| "`routes` field must be an array".to_string())?;
                for item in arr {
                    parse_flowseal_route_entry(item, &mut parsed_routes)?;
                }
            } else if let Some(domains_val) = obj.get("domains") {
                let map = domains_val
                    .as_object()
                    .ok_or_else(|| "`domains` field must be an object".to_string())?;
                parse_flowseal_map_object(map, &mut parsed_routes)?;
            } else {
                let mut direct_map = serde_json::Map::new();
                for (k, v) in obj {
                    if k == "enabled" {
                        continue;
                    }
                    direct_map.insert(k.clone(), v.clone());
                }
                parse_flowseal_map_object(&direct_map, &mut parsed_routes)?;
            }
        }
        _ => return Err("JSON root must be an object or array".to_string()),
    }

    let count = parsed_routes.len();
    *FLOWSEAL_DC_DOMAINS.write() = parsed_routes;
    if let Some(en) = parsed_enabled {
        set_flowseal_per_dc_enabled(en);
    }
    Ok(count)
}

pub const CFPROXY_DOMAINS_URL: &str =
    "https://raw.githubusercontent.com/Flowseal/tg-ws-proxy/main/.github/cfproxy-domains.txt";

// MTProto proxy secret
pub static PROXY_SECRET: Lazy<RwLock<String>> =
    Lazy::new(|| RwLock::new("00000000000000000000000000000000".to_string()));

pub const DEFAULT_FAKETLS_DOMAIN: &str = "www.google.com";

pub static FAKETLS_DOMAIN: Lazy<RwLock<String>> =
    Lazy::new(|| RwLock::new(DEFAULT_FAKETLS_DOMAIN.to_string()));

pub fn get_faketls_domain() -> String {
    let dom = FAKETLS_DOMAIN.read().trim().to_string();
    if dom.is_empty() {
        DEFAULT_FAKETLS_DOMAIN.to_string()
    } else {
        dom
    }
}

pub fn set_faketls_domain(domain: &str) {
    let trimmed = domain.trim();
    let effective = if trimmed.is_empty() || trimmed.contains('\0') {
        DEFAULT_FAKETLS_DOMAIN
    } else {
        trimmed
    };
    *FAKETLS_DOMAIN.write() = effective.to_string();
}

pub fn apply_proxy_secret_input(raw: &str) -> bool {
    let s = raw.trim();
    if !s.is_ascii() || s.len() < 32 {
        return false;
    }
    if s.len() >= 34 && s[..2].eq_ignore_ascii_case("ee") {
        let sec_hex = &s[2..34];
        if hex::decode(sec_hex).is_err() {
            return false;
        }
        let domain_hex = &s[34..];
        let parsed_domain = if domain_hex.is_empty() {
            None
        } else {
            hex::decode(domain_hex)
                .ok()
                .and_then(|bytes| String::from_utf8(bytes).ok())
                .map(|d| d.trim().to_string())
                .filter(|d| !d.is_empty() && !d.contains('\0'))
        };
        *PROXY_SECRET.write() = sec_hex.to_ascii_lowercase();
        set_faketls_domain(parsed_domain.as_deref().unwrap_or(DEFAULT_FAKETLS_DOMAIN));
        return true;
    }
    if s.len() == 34 && s[..2].eq_ignore_ascii_case("dd") {
        let sec_hex = &s[2..34];
        if hex::decode(sec_hex).is_err() {
            return false;
        }
        *PROXY_SECRET.write() = sec_hex.to_ascii_lowercase();
        set_faketls_domain(DEFAULT_FAKETLS_DOMAIN);
        return true;
    }
    if s.len() == 32 {
        if hex::decode(s).is_err() {
            return false;
        }
        *PROXY_SECRET.write() = s.to_ascii_lowercase();
        set_faketls_domain(DEFAULT_FAKETLS_DOMAIN);
        return true;
    }
    false
}

pub fn format_secret_with_prefix(tls_enabled: bool) -> String {
    let sec = PROXY_SECRET.read().clone();
    if tls_enabled {
        let domain = get_faketls_domain();
        let domain_hex = hex::encode(domain.as_bytes());
        format!("ee{}{}", sec, domain_hex)
    } else {
        format!("dd{}", sec)
    }
}

pub static LAST_SOCKS5_WORKER: Lazy<RwLock<String>> = Lazy::new(|| RwLock::new(String::new()));

// SOCKS5 User/Password Authentication (RFC 1928 / RFC 1929)
#[derive(Clone, Default, Debug)]
pub struct Socks5AuthConfig {
    pub username: String,
    pub password: String,
}

pub static SOCKS5_AUTH: Lazy<RwLock<Socks5AuthConfig>> = Lazy::new(|| {
    RwLock::new(Socks5AuthConfig {
        username: String::new(),
        password: String::new(),
    })
});

pub fn is_cloudflare_domain(domain: &str) -> bool {
    let d = domain.trim().to_lowercase();
    if d.is_empty() {
        return false;
    }
    if d.ends_with(".pages.dev")
        || d.ends_with(".workers.dev")
        || d.ends_with(".cloudflare.com")
        || d.ends_with(".cloudflareclient.com")
        || d.ends_with(".trycloudflare.com")
        || d.ends_with(".cloudflareaccess.com")
        || d == "pages.dev"
        || d == "workers.dev"
        || d == "cloudflare.com"
    {
        return true;
    }
    let base = crate::balancer::normalize_domain(&d);
    let cfg = CFPROXY.read();
    if !cfg.user_domain.is_empty() && crate::balancer::normalize_domain(&cfg.user_domain) == base {
        return true;
    }
    if cfg
        .domains
        .iter()
        .any(|dom| crate::balancer::normalize_domain(dom) == base)
    {
        return true;
    }
    drop(cfg);
    if !is_flowseal_per_dc_enabled() {
        return false;
    }
    FLOWSEAL_DC_DOMAINS
        .read()
        .values()
        .any(|dom| crate::balancer::normalize_domain(dom) == base)
}


pub static CFPROXY_ENC: &[&str] = &[
    "virkgj.com",
    "vmmzovy.com",
    "mkuosckvso.com",
    "zaewayzmplad.com",
    "twdmbzcm.com",
    "awzwsldi.com",
    "clngqrflngqin.com",
    "tjacxbqtj.com",
    "bxaxtxmrw.com",
    "dmohrsgmohcrwb.com",
    "vwbmtmoi.com",
    "khgrre.com",
    "ulihssf.com",
    "tmhqsdqmfpmk.com",
    "xwuwoqbm.com",
    "orgcnunpj.com",
    "zhkuldz.com",
    "zypoljnslxa.com",
    "efabnxaowuzs.com",
    "zaftuzsftqdq.com",
];

pub fn canonical_dc_ipv4(dc: i32) -> &'static str {
    match dc {
        1 => "149.154.175.50",
        2 => "149.154.167.51",
        3 => "149.154.175.100",
        4 => "149.154.167.91",
        5 => "149.154.171.5",
        203 => "91.105.192.100",
        _ => "149.154.167.51",
    }
}

pub fn canonical_ipv4_for_dc(dc: i32) -> &'static str {
    canonical_dc_ipv4(dc)
}

pub fn lookup_telegram_dc_by_ip(ip_str: &str) -> Option<(i32, bool)> {
    let clean = ip_str.trim().trim_matches(['[', ']']);
    if let Ok(ip) = clean.parse::<IpAddr>() {
        return lookup_telegram_dc_ip(ip);
    }
    None
}

pub fn lookup_telegram_dc_ip(ip: IpAddr) -> Option<(i32, bool)> {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            // Specific known media endpoints
            match o {
                [149, 154, 175, 51] | [149, 154, 175, 52] => return Some((1, true)),
                [149, 154, 175, 101] | [149, 154, 175, 102] => return Some((3, true)),
                [149, 154, 167, 52]
                | [149, 154, 167, 53]
                | [149, 154, 167, 151]
                | [149, 154, 167, 222]
                | [149, 154, 167, 223]
                | [149, 154, 162, 123] => return Some((2, true)),
                [149, 154, 167, 93]
                | [149, 154, 164, 250]
                | [149, 154, 166, 120]
                | [149, 154, 166, 121]
                | [149, 154, 167, 118]
                | [149, 154, 165, 111] => return Some((4, true)),
                [91, 108, 56, 102]
                | [91, 108, 56, 128]
                | [91, 108, 56, 131]
                | [91, 108, 56, 151]
                | [91, 108, 56, 166] => return Some((5, true)),
                _ => {}
            }

            // Subnet matching
            if o[0] == 149 && o[1] == 154 {
                if o[2] == 175 {
                    if (100..=102).contains(&o[3]) {
                        return Some((3, false));
                    }
                    return Some((1, false));
                }
                if o[2] == 167 {
                    if (91..=95).contains(&o[3]) {
                        return Some((4, false));
                    }
                    if o[3] == 118 {
                        return Some((4, true));
                    }
                    return Some((2, false));
                }
                if (160..=166).contains(&o[2]) {
                    return Some((4, false));
                }
                if (168..=174).contains(&o[2]) {
                    return Some((5, false));
                }
            }

            if o[0] == 91 && o[1] == 108 {
                if (56..=59).contains(&o[2]) || (4..=7).contains(&o[2]) {
                    return Some((5, false));
                }
                if (8..=11).contains(&o[2]) || (16..=31).contains(&o[2]) {
                    return Some((2, false));
                }
                if (12..=15).contains(&o[2]) {
                    return Some((4, false));
                }
            }

            if o[0] == 91 && o[1] == 105 && (o[2] == 192 || o[2] == 193) {
                return Some((203, false));
            }

            if o[0] == 95 && o[1] == 161 && (64..=79).contains(&o[2]) {
                return Some((2, false));
            }

            if o[0] == 185 && o[1] == 76 && o[2] == 151 {
                return Some((2, false));
            }

            None
        }
        IpAddr::V6(v6) => {
            let seg = v6.segments();

            // 1. 2001:67c:4e8::/48
            if seg[0] == 0x2001 && seg[1] == 0x067c && seg[2] == 0x04e8 {
                match seg[3] {
                    0xf001 => return Some((1, false)),
                    0xf002 => return Some((2, false)),
                    0xf003 => return Some((3, false)),
                    0xf004 => return Some((4, false)),
                    0xf005 => return Some((5, false)),
                    _ => return Some((2, false)),
                }
            }

            // 2. 2001:b28:f23c..f23f::/48
            if seg[0] == 0x2001 && seg[1] == 0x0b28 && (0xf23c..=0xf23f).contains(&seg[2]) {
                match seg[3] {
                    0xf001 => return Some((1, false)),
                    0xf002 => return Some((2, false)),
                    0xf003 => return Some((3, false)),
                    0xf004 => return Some((4, false)),
                    0xf005 => return Some((5, false)),
                    _ => {
                        if seg[2] == 0xf23f {
                            return Some((5, false));
                        }
                        return Some((2, false));
                    }
                }
            }

            // 3. 2a0a:f280..f287::/32
            if seg[0] == 0x2a0a && (0xf280..=0xf287).contains(&seg[1]) {
                match seg[2] {
                    1 => return Some((1, false)),
                    2 => return Some((2, false)),
                    3 => return Some((3, false)),
                    4 => return Some((4, false)),
                    5 => return Some((5, false)),
                    0x0203 | 203 => return Some((203, false)),
                    _ => match seg[3] {
                        0xf001 => return Some((1, false)),
                        0xf002 => return Some((2, false)),
                        0xf003 => return Some((3, false)),
                        0xf004 => return Some((4, false)),
                        0xf005 => return Some((5, false)),
                        _ => return Some((2, false)),
                    },
                }
            }

            None
        }
    }
}

pub fn lookup_telegram_dc(host: &str) -> Option<(i32, bool)> {
    let clean = host.trim().trim_matches(['[', ']']);
    if let Some(res) = lookup_telegram_dc_by_ip(clean) {
        return Some(res);
    }
    let lower = clean.to_ascii_lowercase();
    if lower.contains("pluto") { return Some((1, false)); }
    if lower.contains("venus") { return Some((2, false)); }
    if lower.contains("aurora") { return Some((3, false)); }
    if lower.contains("vesta") { return Some((4, false)); }
    if lower.contains("flora") { return Some((5, false)); }
    if lower.contains("kws1") { return Some((1, lower.contains("-1"))); }
    if lower.contains("kws2") { return Some((2, lower.contains("-1"))); }
    if lower.contains("kws3") { return Some((3, lower.contains("-1"))); }
    if lower.contains("kws4") { return Some((4, lower.contains("-1"))); }
    if lower.contains("kws5") { return Some((5, lower.contains("-1"))); }
    None
}

// Telegram protocols & DC mapping
pub fn valid_proto(p: u32) -> bool {
    matches!(p, 0xEFEFEFEF | 0xEEEEEEEE | 0xDDDDDDDD)
}

pub static DC_OVERRIDES: Lazy<HashMap<i32, i32>> = Lazy::new(|| {
    let mut m = HashMap::new();
    m.insert(203, 2);
    m
});

// Global state
pub static DC_OPT: Lazy<RwLock<HashMap<i32, String>>> = Lazy::new(|| RwLock::new(HashMap::new()));

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct Stats {
    pub connections_total: AtomicI64,
    pub connections_active: AtomicI64,
    pub connections_ws: AtomicI64,
    pub connections_cfproxy: AtomicI64,
    pub socks5_fastpath_hits: AtomicI64,
    pub connections_http_reject: AtomicI64,
    pub connections_bad: AtomicI64,
    pub ws_errors: AtomicI64,
    pub bytes_up: AtomicI64,
    pub bytes_down: AtomicI64,
    pub pool_hits: AtomicI64,
    pub pool_misses: AtomicI64,
    pub mtproto_429_cooldown_hits: AtomicI64,
    pub socks5_429_cooldown_hits: AtomicI64,
}

pub static STATS: Lazy<Stats> = Lazy::new(Stats::default);

impl Stats {
    #[inline]
    pub fn dec_connections_active(&self) {
        let _ = self.connections_active.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |v| Some(if v > 0 { v - 1 } else { 0 }),
        );
    }

    pub fn summary(&self) -> String {
        let ph = self.pool_hits.load(Ordering::Relaxed);
        let pm = self.pool_misses.load(Ordering::Relaxed);
        format!(
            "total={} active={} ws={} cf={} fp={} bad={} err={} pool={}/{} up={} down={}",
            self.connections_total.load(Ordering::Relaxed),
            self.connections_active.load(Ordering::Relaxed),
            self.connections_ws.load(Ordering::Relaxed),
            self.connections_cfproxy.load(Ordering::Relaxed),
            self.socks5_fastpath_hits.load(Ordering::Relaxed),
            self.connections_bad.load(Ordering::Relaxed),
            self.ws_errors.load(Ordering::Relaxed),
            ph,
            ph + pm,
            human_bytes(self.bytes_up.load(Ordering::Relaxed)),
            human_bytes(self.bytes_down.load(Ordering::Relaxed)),
        )
    }

    pub fn summary_ru(&self) -> String {
        let mut parts = vec![format!(
            "акт:{}",
            self.connections_active.load(Ordering::Relaxed)
        )];
        let ws = self.connections_ws.load(Ordering::Relaxed);
        if ws > 0 {
            parts.push(format!("ws:{}", ws));
        }
        let cf = self.connections_cfproxy.load(Ordering::Relaxed);
        if cf > 0 {
            parts.push(format!("cf:{}", cf));
        }
        let fp = self.socks5_fastpath_hits.load(Ordering::Relaxed);
        if fp > 0 {
            parts.push(format!("fp:{}", fp));
        }
        let err = self.ws_errors.load(Ordering::Relaxed);
        if err > 0 {
            parts.push(format!("ош:{}", err));
        }
        let cf429_mt = self.mtproto_429_cooldown_hits.load(Ordering::Relaxed);
        if cf429_mt > 0 {
            parts.push(format!("cf429_mt:{}", cf429_mt));
        }
        let cf429_s5 = self.socks5_429_cooldown_hits.load(Ordering::Relaxed);
        if cf429_s5 > 0 {
            parts.push(format!("cf429_s5:{}", cf429_s5));
        }
        parts.push(format!(
            "↑{} ↓{}",
            human_bytes(self.bytes_up.load(Ordering::Relaxed)),
            human_bytes(self.bytes_down.load(Ordering::Relaxed))
        ));
        parts.join(" | ")
    }

    pub fn reset(&self) {
        self.connections_total.store(0, Ordering::Relaxed);
        self.connections_active.store(0, Ordering::Relaxed);
        self.connections_ws.store(0, Ordering::Relaxed);
        self.connections_cfproxy.store(0, Ordering::Relaxed);
        self.socks5_fastpath_hits.store(0, Ordering::Relaxed);
        self.connections_http_reject.store(0, Ordering::Relaxed);
        self.connections_bad.store(0, Ordering::Relaxed);
        self.ws_errors.store(0, Ordering::Relaxed);
        self.bytes_up.store(0, Ordering::Relaxed);
        self.bytes_down.store(0, Ordering::Relaxed);
        self.pool_hits.store(0, Ordering::Relaxed);
        self.pool_misses.store(0, Ordering::Relaxed);
        self.mtproto_429_cooldown_hits.store(0, Ordering::Relaxed);
        self.socks5_429_cooldown_hits.store(0, Ordering::Relaxed);
    }
}

pub fn human_bytes(n: i64) -> String {
    let units = ["B", "KB", "MB", "GB", "TB"];
    let mut f = n as f64;
    for (i, u) in units.iter().enumerate() {
        if f.abs() < 1024.0 || i == units.len() - 1 {
            return format!("{:.1}{}", f, u);
        }
        f /= 1024.0;
    }
    format!("{:.1}TB", f)
}

// ---------------------------------------------------------------------------
// Logger (platform stderr / Android logcat / C-FFI callback)
// ---------------------------------------------------------------------------

fn emit(level: crate::platform::LogLevel, prefix: &str, msg: &str) {
    let line = format!("{}{}", prefix, msg);
    crate::platform::emit_log(level, &line);
}

pub fn log_info(msg: &str) {
    emit(crate::platform::LogLevel::Info, "", msg);
}
pub fn log_warn(msg: &str) {
    emit(crate::platform::LogLevel::Warn, "[WARN] ", msg);
}
pub fn log_error(msg: &str) {
    emit(crate::platform::LogLevel::Error, "[ERROR] ", msg);
}
pub fn log_debug(msg: &str) {
    if LOG_VERBOSE.load(Ordering::Relaxed) {
        emit(crate::platform::LogLevel::Debug, "[DEBUG] ", msg);
    }
}

#[macro_export]
macro_rules! linfo  { ($($a:tt)*) => { $crate::config::log_info(&format!($($a)*)) }; }
#[macro_export]
macro_rules! lwarn  { ($($a:tt)*) => { $crate::config::log_warn(&format!($($a)*)) }; }
#[macro_export]
macro_rules! lerror { ($($a:tt)*) => { $crate::config::log_error(&format!($($a)*)) }; }
#[macro_export]
macro_rules! ldebug { ($($a:tt)*) => { $crate::config::log_debug(&format!($($a)*)) }; }

pub fn init_logging(verbose: bool) {
    LOG_VERBOSE.store(verbose, Ordering::Relaxed);
}

pub fn now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
pub(crate) struct MobileNetworkTestGuard {
    _lock: parking_lot::MutexGuard<'static, ()>,
    prev: bool,
}

#[cfg(test)]
impl MobileNetworkTestGuard {
    pub(crate) fn set(is_mobile: bool) -> Self {
        static LOCK: Lazy<parking_lot::Mutex<()>> = Lazy::new(|| parking_lot::Mutex::new(()));
        let lock = LOCK.lock();
        let prev = MOBILE_NETWORK.swap(is_mobile, Ordering::SeqCst);
        Self { _lock: lock, prev }
    }
}

#[cfg(test)]
impl Drop for MobileNetworkTestGuard {
    fn drop(&mut self) {
        MOBILE_NETWORK.store(self.prev, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod secret_tests {
    use super::*;

    struct SecretTestGuard {
        _lock: parking_lot::MutexGuard<'static, ()>,
        prev_secret: String,
        prev_domain: String,
    }

    impl SecretTestGuard {
        fn acquire() -> Self {
            static LOCK: Lazy<parking_lot::Mutex<()>> = Lazy::new(|| parking_lot::Mutex::new(()));
            let lock = LOCK.lock();
            let prev_secret = PROXY_SECRET.read().clone();
            let prev_domain = FAKETLS_DOMAIN.read().clone();
            Self {
                _lock: lock,
                prev_secret,
                prev_domain,
            }
        }
    }

    impl Drop for SecretTestGuard {
        fn drop(&mut self) {
            *PROXY_SECRET.write() = self.prev_secret.clone();
            *FAKETLS_DOMAIN.write() = self.prev_domain.clone();
        }
    }

    #[test]
    fn secret_parsing_and_faketls_domain_contract() {
        let _guard = SecretTestGuard::acquire();

        // 1. ee<32_hex><domain_hex> stores normalized 32-hex secret + decoded domain.
        let cf_hex = hex::encode("cloudflare.com".as_bytes());
        assert!(apply_proxy_secret_input(&format!(
            "EE0123456789ABCDEF0123456789ABCDEF{}",
            cf_hex
        )));
        assert_eq!(*PROXY_SECRET.read(), "0123456789abcdef0123456789abcdef");
        assert_eq!(get_faketls_domain(), "cloudflare.com");
        assert_eq!(
            format_secret_with_prefix(true),
            format!("ee0123456789abcdef0123456789abcdef{}", cf_hex)
        );
        assert_eq!(
            format_secret_with_prefix(false),
            "dd0123456789abcdef0123456789abcdef"
        );

        // 2. ee<32_hex> without domain falls back to DEFAULT_FAKETLS_DOMAIN.
        assert!(apply_proxy_secret_input("eeaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        assert_eq!(*PROXY_SECRET.read(), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert_eq!(get_faketls_domain(), DEFAULT_FAKETLS_DOMAIN);

        // 3. ee<32_hex><invalid_hex> falls back to DEFAULT_FAKETLS_DOMAIN.
        assert!(apply_proxy_secret_input("eebbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbzzzz"));
        assert_eq!(*PROXY_SECRET.read(), "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        assert_eq!(get_faketls_domain(), DEFAULT_FAKETLS_DOMAIN);

        // 4. dd<32_hex> and bare <32_hex> reset domain to DEFAULT_FAKETLS_DOMAIN.
        assert!(apply_proxy_secret_input(&format!(
            "eecccccccccccccccccccccccccccccccc{}",
            cf_hex
        )));
        assert_eq!(get_faketls_domain(), "cloudflare.com");
        assert!(apply_proxy_secret_input("DDdddddddddddddddddddddddddddddddd"));
        assert_eq!(*PROXY_SECRET.read(), "dddddddddddddddddddddddddddddddd");
        assert_eq!(get_faketls_domain(), DEFAULT_FAKETLS_DOMAIN);

        assert!(apply_proxy_secret_input(&format!(
            "eecccccccccccccccccccccccccccccccc{}",
            cf_hex
        )));
        assert!(apply_proxy_secret_input("11111111111111111111111111111111"));
        assert_eq!(*PROXY_SECRET.read(), "11111111111111111111111111111111");
        assert_eq!(get_faketls_domain(), DEFAULT_FAKETLS_DOMAIN);

        // 5. Invalid inputs leave secret and domain unchanged.
        assert!(!apply_proxy_secret_input("short"));
        assert!(!apply_proxy_secret_input("not_hex_0123456789abcdef01234567"));
        assert!(!apply_proxy_secret_input("dd1234"));
        assert!(!apply_proxy_secret_input("п1111111111111111111111111111111"));
        assert_eq!(*PROXY_SECRET.read(), "11111111111111111111111111111111");
        assert_eq!(get_faketls_domain(), DEFAULT_FAKETLS_DOMAIN);
    }
}

#[cfg(test)]
pub struct FlowsealPerDcTestGuard {
    _lock: parking_lot::MutexGuard<'static, ()>,
    prev_enabled: bool,
    prev_map: HashMap<FlowsealDcRouteKey, String>,
}

#[cfg(test)]
impl FlowsealPerDcTestGuard {
    pub fn acquire() -> Self {
        static LOCK: Lazy<parking_lot::Mutex<()>> = Lazy::new(|| parking_lot::Mutex::new(()));
        let lock = LOCK.lock();
        let prev_enabled = is_flowseal_per_dc_enabled();
        let prev_map = FLOWSEAL_DC_DOMAINS.read().clone();
        set_flowseal_per_dc_enabled(false);
        clear_flowseal_dc_domains();
        Self {
            _lock: lock,
            prev_enabled,
            prev_map,
        }
    }
}

#[cfg(test)]
impl Drop for FlowsealPerDcTestGuard {
    fn drop(&mut self) {
        set_flowseal_per_dc_enabled(self.prev_enabled);
        *FLOWSEAL_DC_DOMAINS.write() = self.prev_map.clone();
    }
}

#[cfg(test)]
mod flowseal_per_dc_tests {
    use super::*;

    #[test]
    fn normalize_flowseal_dc_domain_handles_open_bases_prefixes_and_custom_domains() {
        assert_eq!(normalize_flowseal_dc_domain("pclead"), "pclead.co.uk");
        assert_eq!(
            normalize_flowseal_dc_domain("kws4.pclead.co.uk:443"),
            "pclead.co.uk"
        );
        assert_eq!(
            normalize_flowseal_dc_domain("https://kws2-1.offshor.co.uk/apiws"),
            "offshor.co.uk"
        );
        // Custom .com domains must NOT be Caesar-mangled.
        assert_eq!(
            normalize_flowseal_dc_domain("custom-cdn.example.com"),
            "custom-cdn.example.com"
        );
        assert_eq!(normalize_flowseal_dc_domain("149.154.167.51"), "");
        assert_eq!(normalize_flowseal_dc_domain("invalidlabel"), "");
        assert_eq!(normalize_flowseal_dc_domain("   "), "");
    }

    #[test]
    fn per_dc_pin_precedence_and_json_formats() {
        let _guard = FlowsealPerDcTestGuard::acquire();

        assert!(set_flowseal_dc_domain(2, None, "pclead"));
        assert!(set_flowseal_dc_domain(2, Some(true), "kws2.offshor.co.uk"));
        assert!(!set_flowseal_dc_domain(0, None, "pclead"));
        assert!(!set_flowseal_dc_domain(6, None, "pclead"));
        assert!(!set_flowseal_dc_domain(4, Some(true), "1.2.3.4"));

        // Exact (dc, is_media) beats general (dc, None); DC 203 resolves via DC_OVERRIDES -> DC 2.
        assert_eq!(
            get_flowseal_pinned_domain(2, false).as_deref(),
            Some("pclead.co.uk")
        );
        assert_eq!(
            get_flowseal_pinned_domain(2, true).as_deref(),
            Some("offshor.co.uk")
        );
        assert_eq!(
            get_flowseal_pinned_domain(203, false).as_deref(),
            Some("pclead.co.uk")
        );
        assert_eq!(get_flowseal_pinned_domain(4, true), None);

        // Reserved domains for DC4 include both DC2 pins.
        let reserved_dc4 = flowseal_pinned_domains_for_other_slots(4, true);
        assert!(reserved_dc4.contains("pclead.co.uk"));
        assert!(reserved_dc4.contains("offshor.co.uk"));

        // Batch JSON: routes array + enabled toggle.
        let count = set_flowseal_dc_domains_from_json(
            r#"{"enabled":true,"routes":[{"dc_id":2,"is_media":false,"domain":"pclead"},{"dc_id":4,"is_media":true,"domain":"cakeisalie.co.uk"}]}"#,
        )
        .expect("valid routes JSON");
        assert_eq!(count, 2);
        assert!(is_flowseal_per_dc_enabled());
        assert_eq!(
            get_flowseal_pinned_domain(2, false).as_deref(),
            Some("pclead.co.uk")
        );
        assert_eq!(
            get_flowseal_pinned_domain(4, true).as_deref(),
            Some("cakeisalie.co.uk")
        );
        assert!(is_cloudflare_domain("kws4.cakeisalie.co.uk"));

        // Batch JSON: direct map shorthand.
        let count2 = set_flowseal_dc_domains_from_json(
            r#"{"enabled":false,"dc1":"lovetrue","2m":"noskomnadzor.co.uk","dc4_media":"custom.cdn.example"}"#,
        )
        .expect("valid map JSON");
        assert_eq!(count2, 3);
        assert!(!is_flowseal_per_dc_enabled());
        assert_eq!(
            get_flowseal_pinned_domain(1, false).as_deref(),
            Some("lovetrue.co.uk")
        );
        assert_eq!(
            get_flowseal_pinned_domain(2, true).as_deref(),
            Some("noskomnadzor.co.uk")
        );
        assert_eq!(
            get_flowseal_pinned_domain(4, true).as_deref(),
            Some("custom.cdn.example")
        );
        // Experimental setting is OFF: pinned custom domain must NOT affect Cloudflare domain checks.
        assert!(!is_cloudflare_domain("kws4.custom.cdn.example"));
        set_flowseal_per_dc_enabled(true);
        assert!(is_cloudflare_domain("kws4.custom.cdn.example"));
        set_flowseal_per_dc_enabled(false);

        // Invalid JSON must NOT overwrite prior state.
        assert!(set_flowseal_dc_domains_from_json(r#"{"dc9":"pclead.co.uk"}"#).is_err());
        assert_eq!(
            get_flowseal_pinned_domain(4, true).as_deref(),
            Some("custom.cdn.example")
        );
    }
}


