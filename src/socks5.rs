use crate::cfproxy::*;
use crate::config::*;
use crate::crypto::{new_aes_ctr, MsgSplitter};
use crate::ws::*;
use crate::{ldebug, linfo, lwarn};
use byteorder::{ByteOrder, LittleEndian};
use once_cell::sync::Lazy;
use sha2::Digest;
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

pub(crate) fn spawn_task<F>(future: F) -> tokio::task::JoinHandle<F::Output>
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(future)
    } else {
        crate::runtime().spawn(future)
    }
}

#[inline]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[inline]
fn constant_time_auth_verify(user_in: &[u8], user_exp: &[u8], pass_in: &[u8], pass_exp: &[u8]) -> bool {
    let u_hash_in = sha2::Sha256::digest(user_in);
    let u_hash_exp = sha2::Sha256::digest(user_exp);
    let p_hash_in = sha2::Sha256::digest(pass_in);
    let p_hash_exp = sha2::Sha256::digest(pass_exp);

    constant_time_eq(&u_hash_in, &u_hash_exp) & constant_time_eq(&p_hash_in, &p_hash_exp)
}

async fn read_exact_bounded(
    client: &mut TcpStream,
    buf: &mut [u8],
    cancel: &CancellationToken,
    timeout: Duration,
) -> bool {
    tokio::select! {
        _ = cancel.cancelled() => false,
        result = tokio::time::timeout(timeout, client.read_exact(buf)) =>
            matches!(result, Ok(Ok(_))),
    }
}

async fn dial_direct_tcp(target: &str, timeout: Duration) -> Option<TcpStream> {
    if let Ok(mut addrs) = tokio::net::lookup_host(target).await {
        if let Some(addr) = addrs.next() {
            if let Ok(stream) = crate::ws::connect_outbound_tcp(&addr, timeout).await {
                return Some(stream);
            }
        }
    }
    tokio::time::timeout(timeout, TcpStream::connect(target))
        .await
        .ok()?
        .ok()
}

pub async fn run_socks5_server(
    host: String,
    port: u16,
    cancel_root: CancellationToken,
    cancel_sessions: Arc<parking_lot::RwLock<CancellationToken>>,
    listener: TcpListener,
) -> std::io::Result<()> {
    linfo!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    linfo!("  SOCKS5 Proxy started");
    linfo!("  Address: {}:{}", host, port);

    // Prime the multi-DC warm socket pool for DC2 chat, DC2 media, and DC4 media
    let initial_user_domain = CFPROXY.read().user_domain.clone();
    trigger_warm_socks5_pool_prime(initial_user_domain, cancel_root.clone());
    ensure_warm_pool_housekeeper(cancel_root.clone());

    let mut sessions = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            _ = cancel_root.cancelled() => break,
            _ = sessions.join_next(), if !sessions.is_empty() => {}
            accept = listener.accept() => {
                match accept {
                    Ok((conn, _)) => {
                        let cancel = cancel_sessions.read().child_token();
                        sessions.spawn(async move {
                            handle_socks5_client(conn, cancel).await;
                        });
                    }
                    Err(_) => continue,
                }
            }
        }
    }

    if tokio::time::timeout(Duration::from_secs(2), async {
        while sessions.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        lwarn!("SOCKS5 shutdown: aborting sessions that did not drain in time");
        sessions.abort_all();
        while sessions.join_next().await.is_some() {}
    }

    Ok(())
}

async fn handle_socks5_client(
    mut client: TcpStream,
    cancel: CancellationToken,
) {
    STATS.connections_total.fetch_add(1, Ordering::Relaxed);
    STATS.connections_active.fetch_add(1, Ordering::Relaxed);
    struct ActiveGuard;
    impl Drop for ActiveGuard {
        fn drop(&mut self) {
            STATS.dec_connections_active();
        }
    }
    let _guard = ActiveGuard;

    set_client_sock_opts(&client);
    if !crate::traffic_guard::is_traffic_authorized() {
        let _ = client.write_all(&[0x05, 0xFF]).await;
        return;
    }

    // 1. Handshake: Auth methods (RFC 1928 / RFC 1929)
    let mut header = [0u8; 2];
    if !read_exact_bounded(&mut client, &mut header, &cancel, Duration::from_secs(5)).await {
        return;
    }
    if header[0] != 0x05 {
        return;
    }
    let num_methods = header[1] as usize;
    if num_methods == 0 || num_methods > 255 {
        return;
    }
    let mut methods = vec![0u8; num_methods];
    if !read_exact_bounded(&mut client, &mut methods, &cancel, Duration::from_secs(5)).await {
        return;
    }

    let (auth_required, expected_user, expected_pass) = {
        let auth = SOCKS5_AUTH.read();
        let has_user = !auth.username.is_empty();
        let has_pass = !auth.password.is_empty();
        (
            has_user || has_pass,
            auth.username.clone(),
            auth.password.clone(),
        )
    };

    if auth_required {
        if !methods.contains(&0x02) {
            lwarn!(
                "SOCKS5 client did not offer Username/Password auth (methods: {:?})",
                methods
            );
            let _ = client.write_all(&[0x05, 0xFF]).await;
            return;
        }

        if client.write_all(&[0x05, 0x02]).await.is_err() {
            return;
        }

        let mut auth_ver_ulen = [0u8; 2];
        if !read_exact_bounded(&mut client, &mut auth_ver_ulen, &cancel, Duration::from_secs(5)).await {
            return;
        }
        if auth_ver_ulen[0] != 0x01 {
            let _ = client.write_all(&[0x01, 0xFF]).await;
            return;
        }
        let ulen = auth_ver_ulen[1] as usize;
        let mut uname_buf = vec![0u8; ulen];
        if !read_exact_bounded(&mut client, &mut uname_buf, &cancel, Duration::from_secs(5)).await {
            return;
        }

        let mut plen_buf = [0u8; 1];
        if !read_exact_bounded(&mut client, &mut plen_buf, &cancel, Duration::from_secs(5)).await {
            return;
        }
        let plen = plen_buf[0] as usize;
        let mut pass_buf = vec![0u8; plen];
        if !read_exact_bounded(&mut client, &mut pass_buf, &cancel, Duration::from_secs(5)).await {
            return;
        }

        if constant_time_auth_verify(&uname_buf, expected_user.as_bytes(), &pass_buf, expected_pass.as_bytes()) {
            if client.write_all(&[0x01, 0x00]).await.is_err() {
                return;
            }
        } else {
            lwarn!(
                "SOCKS5 auth rejected: credentials mismatch (expected user='{}' len={}, got user='{}' len={}; expected pass len={}, got pass len={})",
                expected_user,
                expected_user.len(),
                String::from_utf8_lossy(&uname_buf),
                uname_buf.len(),
                expected_pass.len(),
                pass_buf.len()
            );
            let _ = client.write_all(&[0x01, 0xFF]).await;
            return;
        }
    } else {
        if methods.contains(&0x00) {
            if client.write_all(&[0x05, 0x00]).await.is_err() {
                return;
            }
        } else if methods.contains(&0x02) {
            if client.write_all(&[0x05, 0x02]).await.is_err() {
                return;
            }
            let mut auth_ver_ulen = [0u8; 2];
            if !read_exact_bounded(&mut client, &mut auth_ver_ulen, &cancel, Duration::from_secs(5)).await {
                return;
            }
            let ulen = auth_ver_ulen[1] as usize;
            let mut uname_buf = vec![0u8; ulen];
            if !read_exact_bounded(&mut client, &mut uname_buf, &cancel, Duration::from_secs(5)).await { return; }
            let mut plen_buf = [0u8; 1];
            if !read_exact_bounded(&mut client, &mut plen_buf, &cancel, Duration::from_secs(5)).await { return; }
            let plen = plen_buf[0] as usize;
            let mut pass_buf = vec![0u8; plen];
            if !read_exact_bounded(&mut client, &mut pass_buf, &cancel, Duration::from_secs(5)).await { return; }
            if client.write_all(&[0x01, 0x00]).await.is_err() {
                return;
            }
        } else {
            let _ = client.write_all(&[0x05, 0xFF]).await;
            return;
        }
    }

    // 2. Request details
    let mut req_hdr = [0u8; 4];
    if !read_exact_bounded(&mut client, &mut req_hdr, &cancel, Duration::from_secs(5)).await {
        return;
    }
    if req_hdr[0] != 0x05 {
        return;
    }
    if req_hdr[1] == 0x03 {
        // CMD 0x03 = UDP ASSOCIATE (RFC 1928): not relayed, prompt Telegram VoIP TCP TURN fallback
        let _ = client
            .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await;
        return;
    }
    if req_hdr[1] != 0x01 {
        // CMD 0x01 = CONNECT
        let _ = client
            .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await;
        return;
    }

    let target_host = match req_hdr[3] {
        0x01 => {
            let mut ip = [0u8; 4];
            if !read_exact_bounded(&mut client, &mut ip, &cancel, Duration::from_secs(5)).await {
                return;
            }
            Ipv4Addr::from(ip).to_string()
        }
        0x03 => {
            let mut len = [0u8; 1];
            if !read_exact_bounded(&mut client, &mut len, &cancel, Duration::from_secs(5)).await {
                return;
            }
            let mut domain = vec![0u8; len[0] as usize];
            if !read_exact_bounded(&mut client, &mut domain, &cancel, Duration::from_secs(5)).await {
                return;
            }
            String::from_utf8_lossy(&domain).to_string()
        }
        0x04 => {
            let mut ip = [0u8; 16];
            if !read_exact_bounded(&mut client, &mut ip, &cancel, Duration::from_secs(5)).await {
                return;
            }
            Ipv6Addr::from(ip).to_string()
        }
        _ => {
            let _ = client
                .write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
            return;
        }
    };

    let mut port_buf = [0u8; 2];
    if !read_exact_bounded(&mut client, &mut port_buf, &cancel, Duration::from_secs(5)).await {
        return;
    }
    let target_port = u16::from_be_bytes(port_buf);
    let target_addr = if target_host.contains(':') && !target_host.starts_with('[') {
        format!("[{}]:{}", target_host, target_port)
    } else {
        format!("{}:{}", target_host, target_port)
    };

    let is_tg = is_telegram_host(&target_host);

    // -- Non-Telegram Host: Direct TCP passthrough --
    if !is_tg {
        ldebug!("SOCKS5 passthrough for non-Telegram target {}", target_addr);
        let dial_res = dial_direct_tcp(&target_addr, Duration::from_millis(3000)).await;
        let remote = match dial_res {
            Some(stream) => {
                set_sock_opts(&stream);
                stream
            }
            None => {
                lwarn!("SOCKS5 passthrough connection failed for {}", target_addr);
                let _ = client.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
                return;
            }
        };

        if client.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await.is_err() {
            return;
        }

        bridge_socks5_stream(client, remote, vec![], cancel).await;
        return;
    }

    // Ensure TCP_NODELAY is active for immediate transmission without Nagle delay
    let _ = client.set_nodelay(true);

    // -- Telegram Host: Immediate SOCKS5 0x00 success reply --
    // Per RFC 1928, the client waits for the proxy's CONNECT reply before sending payload.
    // An immediate reply yields 0 ms RTT in Telegram's tgnet latency estimator,
    // which provokes tgnet into opening 4-8 concurrent chunk download streams immediately.
    if client
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .is_err()
    {
        return;
    }

    // Read initial MTProto data with coalescing:
    // Guarantees at least 64 bytes for MTProto handshake, and captures any pipelined RPC payload
    // (such as TL_ping_delay_disconnect) sent in the same burst by Telegram client.
    let mut init_buf = vec![0u8; 4096];
    let mut total_read = 0;
    while total_read < 64 {
        let read_res = tokio::select! {
            _ = cancel.cancelled() => return,
            res = tokio::time::timeout(Duration::from_secs(15), client.read(&mut init_buf[total_read..])) => res,
        };
        match read_res {
            Ok(Ok(0)) | Err(_) | Ok(Err(_)) => {
                ldebug!("SOCKS5 Telegram client disconnected before 64-byte init packet");
                return;
            }
            Ok(Ok(n)) => {
                total_read += n;
            }
        }
    }

    // Opportunistically consume any additional pipelined RPC payload already in kernel buffer
    if total_read < init_buf.len() {
        if let Ok(n) = client.try_read(&mut init_buf[total_read..]) {
            if n > 0 {
                total_read += n;
            }
        }
    }
    // If exactly 64 bytes were read, micro-poll for up to 5 ms for pipelined ping frame
    if total_read == 64 {
        let _ = tokio::select! {
            _ = cancel.cancelled() => Ok(()),
            res = tokio::time::timeout(Duration::from_millis(5), async {
                if let Ok(n) = client.read(&mut init_buf[total_read..]).await {
                    if n > 0 {
                        total_read += n;
                    }
                }
            }) => res,
        };
    }
    init_buf.truncate(total_read);

    // Reject HTTP transport attempts
    if crate::proxy::is_http_transport(&init_buf[..64]) {
        STATS.connections_http_reject.fetch_add(1, Ordering::Relaxed);
        ldebug!("SOCKS5 rejected HTTP transport on port {}", target_port);
        let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
        return;
    }

    // Extract DC, media flag, and protocol tag from destination host and initial 64-byte handshake
    let host_dc = lookup_telegram_dc(&target_host);
    let init_dc = dc_from_init(&init_buf[..64]);
    let (dc, mut is_media, detected_proto) = match (host_dc, init_dc) {
        (Some((hdc, hmedia)), Some((_idc, imedia, proto))) => (hdc, hmedia || imedia, Some(proto)),
        (Some((hdc, hmedia)), None) => (hdc, hmedia, None),
        (None, Some((idc, imedia, proto))) => (idc, imedia, Some(proto)),
        (None, None) => (2, false, None),
    };
    if dc == 4 {
        is_media = true;
    }

    let (worker_dst, effective_port) =
        resolve_socks5_telegram_destination(&target_host, target_port, Some(dc), is_media);

    let worker_enabled = CFPROXY_ENABLED.load(Ordering::Relaxed);
    let uplink_mode = crate::config::get_socks5_uplink_mode();
    let uplink_name = if uplink_mode == crate::config::SOCKS5_UPLINK_FLOWSEAL {
        "Anycast CDN Flowseal"
    } else {
        "Cloudflare Worker"
    };

    let init_head: Option<[u8; 64]> = if init_buf.len() >= 64 {
        let mut h = [0u8; 64];
        h.copy_from_slice(&init_buf[..64]);
        Some(h)
    } else {
        None
    };

    let initial_payload = if init_buf.len() > 64 {
        init_buf[64..].to_vec()
    } else {
        Vec::new()
    };

    if worker_enabled {
        ldebug!(
            "SOCKS5 routing to {} for DC{}{}: {}:{} (coalesced: {} bytes)",
            uplink_name,
            dc,
            if is_media { " (media)" } else { "" },
            worker_dst,
            effective_port,
            total_read
        );

        let ws_opt =
            socks5_acquire_upstream_ws(dc, is_media, &worker_dst, effective_port, &init_buf, &cancel)
                .await;
        if let Some((ws, winner_domain)) = ws_opt {
            STATS.connections_cfproxy.fetch_add(1, Ordering::Relaxed);
            STATS.connections_ws.fetch_add(1, Ordering::Relaxed);
            let is_flowseal = uplink_mode == crate::config::SOCKS5_UPLINK_FLOWSEAL || CFPROXY.read().user_domain.is_empty();
            let pending_payload = if is_flowseal { initial_payload } else { Vec::new() };
            bridge_socks5_ws(
                client,
                Arc::new(ws),
                dc,
                is_media,
                &winner_domain,
                cancel,
                detected_proto,
                pending_payload,
                init_head,
                is_flowseal,
            ).await;
            return;
        }
        lwarn!(
            "SOCKS5 Worker upstream unavailable for DC{}; suppressing direct unproxied TCP fallback to protect connection",
            dc
        );
        return;
    }

    // Direct unproxied TCP fallback to Telegram DC is intentionally disabled:
    // In Russia, direct IP ranges (149.154.x.x, 91.108.x.x) are blocked/throttled by TSPU.
    // Attempting direct TCP fallback results in 10-second connection hangs.
    lwarn!(
        "SOCKS5 Worker disabled; direct TCP connection to Telegram DC{} {}:{} suppressed to prevent stalls",
        dc,
        worker_dst,
        effective_port
    );
}




pub fn is_telegram_host(host: &str) -> bool {
    let trimmed = host.trim().trim_matches(['[', ']']).to_ascii_lowercase();
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        if crate::config::lookup_telegram_dc_ip(ip).is_some() {
            return true;
        }
        return match ip {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                // 149.154.160.0/20: 149.154.(160..=175).*
                if octets[0] == 149 && octets[1] == 154 && (octets[2] >= 160 && octets[2] <= 175) {
                    return true;
                }
                // 91.108.0.0/16: 91.108.*.*
                if octets[0] == 91 && octets[1] == 108 {
                    return true;
                }
                // 91.105.192.0/23: 91.105.(192..=193).*
                if octets[0] == 91 && octets[1] == 105 && (octets[2] == 192 || octets[2] == 193) {
                    return true;
                }
                // 185.76.151.0/24: 185.76.151.*
                if octets[0] == 185 && octets[1] == 76 && octets[2] == 151 {
                    return true;
                }
                // 95.161.64.0/20: 95.161.(64..=79).*
                if octets[0] == 95 && octets[1] == 161 && (octets[2] >= 64 && octets[2] <= 79) {
                    return true;
                }
                // 194.221.248.0/21: 194.221.(248..=255).*
                if octets[0] == 194 && octets[1] == 221 && (octets[2] >= 248 && octets[2] <= 255) {
                    return true;
                }
                false
            }
            IpAddr::V6(v6) => {
                let seg = v6.segments();
                (seg[0] == 0x2001 && seg[1] == 0x067c && seg[2] == 0x04e8)
                    || (seg[0] == 0x2001 && seg[1] == 0x0b28 && (0xf23c..=0xf23f).contains(&seg[2]))
                    || (seg[0] == 0x2a0a && (0xf280..=0xf287).contains(&seg[1]))
            }
        };
    }

    trimmed == "telegram.org"
        || trimmed.ends_with(".telegram.org")
        || trimmed == "t.me"
        || trimmed.ends_with(".t.me")
        || trimmed == "telesco.pe"
        || trimmed.ends_with(".telesco.pe")
        || trimmed == "telegram.dog"
        || trimmed.ends_with(".telegram.dog")
        || trimmed == "telegra.ph"
        || trimmed.ends_with(".telegra.ph")
        || trimmed == "cdn-telegram.org"
        || trimmed.ends_with(".cdn-telegram.org")
        || trimmed == "telegram-cdn.org"
        || trimmed.ends_with(".telegram-cdn.org")
}

pub fn canonical_ipv4_for_dc(dc: i32) -> &'static str {
    crate::config::canonical_ipv4_for_dc(dc)
}

pub fn lookup_telegram_dc(host: &str) -> Option<(i32, bool)> {
    crate::config::lookup_telegram_dc(host)
}

pub fn resolve_socks5_telegram_destination(
    host: &str,
    port: u16,
    dc: Option<i32>,
    is_media: bool,
) -> (String, u16) {
    let host_trimmed = host.trim().trim_matches(['[', ']']);
    let (detected_dc, detected_media) = lookup_telegram_dc(host_trimmed)
        .map(|(d, m)| (Some(d), m))
        .unwrap_or((None, false));
    let effective_dc = dc.or(detected_dc);
    let effective_media = is_media || detected_media;

    if effective_media {
        // If target host is already an explicit media IP, preserve it
        if host_trimmed.parse::<std::net::IpAddr>().is_ok() && detected_media {
            return (host_trimmed.to_string(), port);
        }
        // Canonical media endpoints
        if let Some(d) = effective_dc {
            let media_ip = match d {
                1 => "149.154.175.52",
                2 => "149.154.167.52",
                3 => "149.154.175.101",
                4 => "149.154.167.93",
                5 => "91.108.56.131",
                _ => canonical_ipv4_for_dc(d),
            };
            return (media_ip.to_string(), port);
        }
    } else if let Some(d) = effective_dc {
        return (canonical_ipv4_for_dc(d).to_string(), port);
    }

    (host_trimmed.to_string(), port)
}

pub fn dc_from_init(data: &[u8]) -> Option<(i32, bool, u32)> {
    if data.len() < 64 {
        return None;
    }

    let mut stream = crate::crypto::new_aes_ctr(&data[8..40], &data[40..56]);
    let mut ks = [0u8; 64];
    stream.xor(&mut ks);

    let proto = LittleEndian::read_u32(&[
        data[56] ^ ks[56],
        data[57] ^ ks[57],
        data[58] ^ ks[58],
        data[59] ^ ks[59],
    ]);
    let dc_raw = LittleEndian::read_i16(&[
        data[60] ^ ks[60],
        data[61] ^ ks[61],
    ]);

    if !matches!(proto, 0xEFEFEFEF | 0xEEEEEEEE | 0xDDDDDDDD) {
        return None;
    }

    let dc_abs = (dc_raw as i32).abs();
    let is_media = dc_raw < 0;

    if (1..=5).contains(&dc_abs) || dc_abs == 203 {
        Some((dc_abs, is_media, proto))
    } else {
        None
    }
}

pub fn patch_init_dc(data: &[u8], dc: i32) -> Vec<u8> {
    if data.len() < 64 {
        return data.to_vec();
    }
    let mut new_dc = [0u8; 2];
    LittleEndian::write_i16(&mut new_dc, dc as i16);

    let mut stream = crate::crypto::new_aes_ctr(&data[8..40], &data[40..56]);
    let mut ks = [0u8; 64];
    stream.xor(&mut ks);

    let mut patched = data.to_vec();
    patched[60] = ks[60] ^ new_dc[0];
    patched[61] = ks[61] ^ new_dc[1];
    patched
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Socks5WarmKey {
    pub dc: i32,
    pub is_media: bool,
}

pub struct Socks5WarmEntry {
    pub ws: RawWebSocket,
    pub domain: String,
    pub created: Instant,
}

pub struct Socks5Slot {
    queue: parking_lot::Mutex<VecDeque<Socks5WarmEntry>>,
    in_flight: AtomicUsize,
}

impl Socks5Slot {
    pub fn new() -> Self {
        Self {
            queue: parking_lot::Mutex::new(VecDeque::new()),
            in_flight: AtomicUsize::new(0),
        }
    }

    /// Instant non-blocking pop for Flowseal Anycast nodes where any fresh entry is valid.
    pub fn try_pop_fresh_any(&self, max_age: Duration) -> Option<(RawWebSocket, String)> {
        let mut q = self.queue.lock();
        while let Some(entry) = q.pop_front() {
            if !entry.ws.is_closed() && entry.created.elapsed() < max_age {
                return Some((entry.ws, entry.domain));
            } else {
                spawn_task(async move {
                    let _ = entry.ws.close().await;
                });
            }
        }
        None
    }

    /// Instant non-blocking pop (<1 us). If empty, returns None immediately without waiting.
    pub fn try_pop_fresh(&self, user_domain: &str, max_age: Duration) -> Option<RawWebSocket> {
        let mut q = self.queue.lock();
        while let Some(entry) = q.pop_front() {
            if entry.created.elapsed() < max_age && entry.domain == user_domain {
                return Some(entry.ws);
            } else {
                spawn_task(async move {
                    let _ = entry.ws.close().await;
                });
            }
        }
        None
    }

    pub fn push_if_below(&self, entry: Socks5WarmEntry, target: usize) -> Result<(), Socks5WarmEntry> {
        let mut q = self.queue.lock();
        if q.len() < target {
            q.push_back(entry);
            Ok(())
        } else {
            Err(entry)
        }
    }

    pub fn ready_count(&self) -> usize {
        self.queue.lock().len()
    }

    pub fn in_flight_count(&self) -> usize {
        self.in_flight.load(Ordering::Relaxed)
    }

    pub fn drain_all(&self) -> Vec<Socks5WarmEntry> {
        let mut q = self.queue.lock();
        self.in_flight.store(0, Ordering::Relaxed);
        q.drain(..).collect()
    }
}

static SOCKS5_WARM_SLOTS: Lazy<parking_lot::RwLock<HashMap<Socks5WarmKey, Arc<Socks5Slot>>>> =
    Lazy::new(|| {
        let mut m = HashMap::new();
        m.insert(Socks5WarmKey { dc: 2, is_media: false }, Arc::new(Socks5Slot::new()));
        m.insert(Socks5WarmKey { dc: 2, is_media: true }, Arc::new(Socks5Slot::new()));
        m.insert(Socks5WarmKey { dc: 4, is_media: true }, Arc::new(Socks5Slot::new()));
        m.insert(Socks5WarmKey { dc: 1, is_media: false }, Arc::new(Socks5Slot::new()));
        parking_lot::RwLock::new(m)
    });

pub fn get_warm_slot(key: Socks5WarmKey) -> Arc<Socks5Slot> {
    {
        let r = SOCKS5_WARM_SLOTS.read();
        if let Some(slot) = r.get(&key) {
            return slot.clone();
        }
    }
    let mut w = SOCKS5_WARM_SLOTS.write();
    w.entry(key).or_insert_with(|| Arc::new(Socks5Slot::new())).clone()
}

pub fn target_warm_capacity(key: Socks5WarmKey) -> usize {
    let is_mobile = MOBILE_NETWORK.load(Ordering::Relaxed);
    match (key.dc, key.is_media) {
        // DC2 chat: default MTProto gateway for messages, ping and notifications
        (2, false) => if is_mobile { 2 } else { 3 },
        // DC2 media: personal voice notes, video notes (circles), personal chat media
        (2, true) => if is_mobile { 3 } else { 4 },
        // DC4 media: public channels, large files, videos
        (4, true) => if is_mobile { 3 } else { 4 },
        // DC1 chat: login, bot sessions
        (1, false) => 1,
        // Other DCs (e.g. DC5, DC3) or non-media DC4: keep 1 standby
        _ => 1,
    }
}

pub fn trigger_warm_socks5_refill(user_domain: String, dc: i32, is_media: bool, cancel: CancellationToken) {
    let uplink_mode = crate::config::get_socks5_uplink_mode();
    let is_flowseal = uplink_mode == crate::config::SOCKS5_UPLINK_FLOWSEAL || user_domain.is_empty();
    let key = Socks5WarmKey { dc, is_media };
    let target = target_warm_capacity(key);
    let slot = get_warm_slot(key);

    spawn_task(async move {
        // Atomic batch deficit calculation under slot-level sync lock (<1 us)
        let needed = {
            let current = slot.ready_count();
            let inflight = slot.in_flight.load(Ordering::Relaxed);
            if current + inflight >= target {
                0
            } else {
                let n = target - (current + inflight);
                slot.in_flight.fetch_add(n, Ordering::Relaxed);
                n
            }
        };

        if needed == 0 {
            return;
        }

        // Spawn 'needed' concurrent connection tasks simultaneously (0 sequential delay)
        for _ in 0..needed {
            let user_domain = user_domain.clone();
            let cancel = cancel.clone();
            let slot = slot.clone();
            spawn_task(async move {
                struct SlotInFlightGuard {
                    slot: Arc<Socks5Slot>,
                }
                impl Drop for SlotInFlightGuard {
                    fn drop(&mut self) {
                        self.slot.in_flight.fetch_sub(1, Ordering::Relaxed);
                    }
                }
                let _guard = SlotInFlightGuard { slot: slot.clone() };

                let timeout = crate::config::adaptive_ws_connect_timeout().max(8.0);
                let (ws_opt, domain_tag) = if is_flowseal {
                    let effective_dc = DC_OVERRIDES.get(&dc).copied().unwrap_or(dc);
                    let (enabled, mut domains) = {
                        let cfg = CFPROXY.read();
                        (CFPROXY_ENABLED.load(Ordering::Relaxed), cfg.domains.clone())
                    };
                    if domains.is_empty() {
                        domains = crate::cfproxy::default_cfproxy_domains();
                    }
                    let ordered = crate::balancer::BALANCER
                        .read()
                        .get_domains_for_dc(effective_dc, is_media);
                    let mut candidates = Vec::new();
                    for d in ordered {
                        let norm = crate::balancer::normalize_domain(&d);
                        if !norm.is_empty() && cfproxy_429_cooldown_remaining_scoped(&norm, ProtoScope::Socks5) == Duration::ZERO {
                            candidates.push(norm);
                        }
                    }
                    for d in &domains {
                        let norm = crate::balancer::normalize_domain(d);
                        if !norm.is_empty() && !candidates.contains(&norm) && cfproxy_429_cooldown_remaining_scoped(&norm, ProtoScope::Socks5) == Duration::ZERO {
                            candidates.push(norm);
                        }
                    }
                    if candidates.is_empty() {
                        candidates = crate::cfproxy::default_cfproxy_domains();
                    }

                    let domain_base = candidates[rand::random::<usize>() % candidates.len()].clone();
                    let target_host = format!("kws{}.{}", effective_dc, domain_base);
                    let (ws, _, _) = cf_connect_domain_with_category(
                        &target_host,
                        "/apiws",
                        None,
                        timeout,
                        crate::budget::FlowCategory::Background,
                        Some(&cancel),
                    )
                    .await;
                    (ws, domain_base)
                } else {
                    let worker_dst = canonical_ipv4_for_dc(dc);
                    let sid = format!("{:016x}", rand::random::<u64>());
                    let media_flag = if is_media { "1" } else { "0" };
                    let path = format!(
                        "/apiws?dst={}&dc={}&media={}&sid={}",
                        worker_dst, dc, media_flag, sid
                    );

                    let (ws, _, _) = cf_connect_domain_with_category(
                        &user_domain,
                        &path,
                        None,
                        timeout,
                        crate::budget::FlowCategory::Background,
                        Some(&cancel),
                    )
                    .await;
                    (ws, user_domain)
                };

                if let Some(ws) = ws_opt {
                    if let Err(entry) = slot.push_if_below(
                        Socks5WarmEntry {
                            ws,
                            domain: domain_tag,
                            created: Instant::now(),
                        },
                        target,
                    ) {
                        tokio::spawn(async move {
                            let _ = entry.ws.close().await;
                        });
                    } else {
                        ldebug!(
                            "SOCKS5 warm pool: buffered standby socket for DC{}{} (pool size: {})",
                            dc,
                            if is_media { "m" } else { "" },
                            slot.ready_count()
                        );
                    }
                }
            });
        }
    });
}

pub fn trigger_warm_socks5_pool_prime(user_domain: String, cancel: CancellationToken) {
    let is_mobile = MOBILE_NETWORK.load(Ordering::Relaxed);
    if is_mobile {
        // Mobile / Hotspot Staggered Prime:
        // Do not fire 10-12 concurrent handshakes at once!
        // Stagger to prevent cellular bufferbloat and modem TX queue exhaustion:
        let u = user_domain.clone();
        let c = cancel.clone();
        spawn_task(async move {
            // Stage 1: Critical DC2 chat immediately (2 streams)
            trigger_warm_socks5_refill(u.clone(), 2, false, c.clone());
            // Stage 2: DC2 media after 120ms stagger (2 streams)
            tokio::time::sleep(Duration::from_millis(120)).await;
            if c.is_cancelled() { return; }
            trigger_warm_socks5_refill(u.clone(), 2, true, c.clone());
            // Stage 3: DC4 media after 250ms stagger (2 streams)
            tokio::time::sleep(Duration::from_millis(250)).await;
            if c.is_cancelled() { return; }
            trigger_warm_socks5_refill(u.clone(), 4, true, c.clone());
        });
    } else {
        // Broadband Wi-Fi Parallel Prime:
        trigger_warm_socks5_refill(user_domain.clone(), 2, false, cancel.clone());
        trigger_warm_socks5_refill(user_domain.clone(), 2, true, cancel.clone());
        trigger_warm_socks5_refill(user_domain.clone(), 4, true, cancel.clone());
        trigger_warm_socks5_refill(user_domain.clone(), 1, false, cancel.clone());
    }
}

pub fn clear_socks5_warm_pool() {
    let slots: Vec<Arc<Socks5Slot>> = {
        let r = SOCKS5_WARM_SLOTS.read();
        r.values().cloned().collect()
    };
    for slot in slots {
        let dead = slot.drain_all();
        if !dead.is_empty() {
            spawn_task(async move {
                for entry in dead {
                    let _ = entry.ws.close().await;
                }
            });
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Socks5WarmPoolStatus {
    pub ready_total: usize,
    pub target_total: usize,
    pub in_flight_total: usize,
    pub dc2_chat_ready: usize,
    pub dc2_chat_target: usize,
    pub dc2_media_ready: usize,
    pub dc2_media_target: usize,
    pub dc4_media_ready: usize,
    pub dc4_media_target: usize,
}

pub fn get_socks5_warm_pool_status() -> Socks5WarmPoolStatus {
    let (enabled, _user_domain) = {
        let cfg = CFPROXY.read();
        (CFPROXY_ENABLED.load(Ordering::Relaxed), cfg.user_domain.trim().to_string())
    };
    if !enabled {
        return Socks5WarmPoolStatus {
            ready_total: 0,
            target_total: 0,
            in_flight_total: 0,
            dc2_chat_ready: 0,
            dc2_chat_target: 0,
            dc2_media_ready: 0,
            dc2_media_target: 0,
            dc4_media_ready: 0,
            dc4_media_target: 0,
        };
    }

    let slot_dc2_chat = get_warm_slot(Socks5WarmKey { dc: 2, is_media: false });
    let slot_dc2_media = get_warm_slot(Socks5WarmKey { dc: 2, is_media: true });
    let slot_dc4_media = get_warm_slot(Socks5WarmKey { dc: 4, is_media: true });
    let _slot_dc1_chat = get_warm_slot(Socks5WarmKey { dc: 1, is_media: false });

    let dc2_chat_ready = slot_dc2_chat.ready_count();
    let dc2_media_ready = slot_dc2_media.ready_count();
    let dc4_media_ready = slot_dc4_media.ready_count();

    let all_slots: Vec<Arc<Socks5Slot>> = {
        let r = SOCKS5_WARM_SLOTS.read();
        r.values().cloned().collect()
    };
    let ready_total: usize = all_slots.iter().map(|s| s.ready_count()).sum();
    let in_flight_total: usize = all_slots.iter().map(|s| s.in_flight_count()).sum();

    let dc2_chat_target = target_warm_capacity(Socks5WarmKey { dc: 2, is_media: false });
    let dc2_media_target = target_warm_capacity(Socks5WarmKey { dc: 2, is_media: true });
    let dc4_media_target = target_warm_capacity(Socks5WarmKey { dc: 4, is_media: true });
    let dc1_chat_target = target_warm_capacity(Socks5WarmKey { dc: 1, is_media: false });
    let target_total = dc2_chat_target + dc2_media_target + dc4_media_target + dc1_chat_target;

    Socks5WarmPoolStatus {
        ready_total,
        target_total,
        in_flight_total,
        dc2_chat_ready,
        dc2_chat_target,
        dc2_media_ready,
        dc2_media_target,
        dc4_media_ready,
        dc4_media_target,
    }
}

pub fn ensure_warm_pool_housekeeper(cancel: CancellationToken) {
    spawn_task(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(20));
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = interval.tick() => {
                    let user_domain = CFPROXY.read().user_domain.clone();
                    let is_mobile = MOBILE_NETWORK.load(Ordering::Relaxed);
                    // On cellular networks, CGNAT drops idle TCP after 15-30s.
                    // Keep idle sockets bounded to 22s on mobile to avoid dead sockets.
                    let max_idle = if is_mobile { Duration::from_secs(22) } else { Duration::from_secs(60) };

                    let pairs: Vec<(Socks5WarmKey, Arc<Socks5Slot>)> = {
                        let r = SOCKS5_WARM_SLOTS.read();
                        r.iter().map(|(k, v)| (*k, v.clone())).collect()
                    };

                    for (key, slot) in pairs {
                        let dead_entries = {
                            let mut q = slot.queue.lock();
                            let mut alive = VecDeque::new();
                            let mut dead = Vec::new();
                            while let Some(entry) = q.pop_front() {
                                if entry.ws.is_closed() || entry.created.elapsed() > max_idle {
                                    dead.push(entry);
                                } else {
                                    alive.push_back(entry);
                                }
                            }
                            *q = alive;
                            dead
                        };

                        for dead in dead_entries {
                            spawn_task(async move {
                                let _ = dead.ws.close().await;
                            });
                        }

                        let target = target_warm_capacity(key);
                        if slot.ready_count() + slot.in_flight_count() < target {
                            trigger_warm_socks5_refill(user_domain.clone(), key.dc, key.is_media, cancel.clone());
                        }
                    }
                }
            }
        }
    });
}

pub async fn socks5_acquire_upstream_ws(
    dc: i32,
    is_media: bool,
    worker_dst: &str,
    target_port: u16,
    init: &[u8],
    cancel_token: &CancellationToken,
) -> Option<(RawWebSocket, String)> {
    let expected = crate::generation_guard::snapshot();
    let (enabled, user_domain) = {
        let cfg = CFPROXY.read();
        (
            CFPROXY_ENABLED.load(Ordering::Relaxed),
            cfg.user_domain.clone(),
        )
    };

    if !enabled {
        return None;
    }

    let uplink_mode = crate::config::get_socks5_uplink_mode();
    let is_flowseal = uplink_mode == crate::config::SOCKS5_UPLINK_FLOWSEAL || user_domain.is_empty();

    // ── Anycast CDN Flowseal Uplink ──
    if is_flowseal {
        let effective_dc = DC_OVERRIDES.get(&dc).copied().unwrap_or(dc);
        let key = Socks5WarmKey { dc: effective_dc, is_media };
        let slot = get_warm_slot(key);

        let is_mobile = MOBILE_NETWORK.load(Ordering::Relaxed);
        let max_age = if is_mobile { Duration::from_secs(22) } else { Duration::from_secs(45) };
        let warm_opt = slot.try_pop_fresh_any(max_age);

        let (ws, winner_domain) = if let Some((ws, domain)) = warm_opt {
            ldebug!(
                "SOCKS5 Flowseal warm pool ok {} (DC{}{}) (0 ms)",
                domain,
                effective_dc,
                if is_media { "m" } else { "" }
            );
            (ws, domain)
        } else {
            ldebug!(
                "SOCKS5 Flowseal Anycast race attempt -> DC{}{}",
                effective_dc,
                if is_media { " (media)" } else { "" }
            );
            let race_res = crate::proxy::cfproxy_acquire_raw_ws_race(
                effective_dc,
                is_media,
                ProtoScope::Socks5,
                cancel_token,
            )
            .await;
            match race_res {
                Some(r) => r,
                None => {
                    lwarn!(
                        "SOCKS5 Flowseal upstream unavailable for DC{}{}; suppressing unproxied TCP fallback",
                        effective_dc,
                        if is_media { "m" } else { "" }
                    );
                    return None;
                }
            }
        };

        if !crate::generation_guard::is_current(expected) {
            ldebug!("SOCKS5 Flowseal dial completed but network generation changed; dropping stale socket");
            let _ = ws.close().await;
            return None;
        }

        if !init.is_empty() {
            if init.len() >= 64 {
                // Frame 1: Exactly 64 bytes of Obfuscated2 handshake
                // In Flowseal Anycast CDN, negative DC is strictly required to route to Media servers.
                let target_dc = if is_media { -effective_dc } else { effective_dc };
                let patched_init_head = patch_init_dc(&init[..64], target_dc);
                if let Err(e) = ws.send(&patched_init_head).await {
                    let _ = ws.close().await;
                    lwarn!("SOCKS5 Flowseal first 64-byte handshake write failed: {:?}", e);
                    return None;
                }
            } else {
                if let Err(e) = ws.send(init).await {
                    let _ = ws.close().await;
                    lwarn!("SOCKS5 Flowseal short payload write failed: {:?}", e);
                    return None;
                }
            }
        }

        // Replenish warm pool slot in background for subsequent parallel requests
        trigger_warm_socks5_refill(user_domain.clone(), effective_dc, is_media, cancel_token.clone());

        clear_cfproxy_429_cooldown_scoped(&winner_domain, ProtoScope::Socks5);
        clear_cfproxy_recovery_cooldown(&winner_domain);
        let base_domain = crate::balancer::normalize_domain(&winner_domain);
        if !base_domain.is_empty() {
            crate::balancer::BALANCER.write().record_useful_success(
                crate::network_profile::current_generation(),
                effective_dc,
                is_media,
                &base_domain,
            );
        }
        *LAST_SOCKS5_WORKER.write() = winner_domain.clone();
        STATS.socks5_fastpath_hits.fetch_add(1, Ordering::Relaxed);
        return Some((ws, winner_domain));
    }

    // ── Cloudflare Worker Uplink ──
    if user_domain.is_empty() {
        lwarn!("SOCKS5 requires configured Cloudflare Worker; none configured");
        return None;
    }

    let sid = format!("{:016x}", rand::random::<u64>());
    let media_flag = if is_media { "1" } else { "0" };
    let path = if target_port == 443 {
        format!(
            "/apiws?dst={}&dc={}&media={}&sid={}",
            worker_dst, dc, media_flag, sid
        )
    } else {
        format!(
            "/apiws?dst={}&dc={}&media={}&sid={}&port={}",
            worker_dst, dc, media_flag, sid, target_port
        )
    };

    let remaining = cfproxy_429_cooldown_remaining_scoped(&user_domain, ProtoScope::Socks5);
    if remaining > Duration::ZERO {
        ldebug!(
            "SOCKS5 custom worker {} is cooling down ({:.0}s)",
            user_domain,
            remaining.as_secs_f64()
        );
        return None;
    }

    // Fast-path: Check if we have a warm pre-connected socket for target (DC, media) (0 ms acquisition)
    let warm_key = Socks5WarmKey { dc, is_media };
    let is_mobile = MOBILE_NETWORK.load(Ordering::Relaxed);
    let max_age = if is_mobile { Duration::from_secs(22) } else { Duration::from_secs(45) };
    let slot = get_warm_slot(warm_key);
    let warm_opt = slot.try_pop_fresh(&user_domain, max_age);

    if let Some(ws) = warm_opt {
        if !init.is_empty() {
            if ws.send(init).await.is_ok() {
                ldebug!(
                    "SOCKS5 DC{}{} acquired from warm pre-connect pool (0 ms)",
                    dc,
                    if is_media { "m" } else { "" }
                );
                STATS.socks5_fastpath_hits.fetch_add(1, Ordering::Relaxed);
                trigger_warm_socks5_refill(user_domain.clone(), dc, is_media, cancel_token.clone());
                return Some((ws, user_domain.clone()));
            } else {
                let _ = ws.close().await;
            }
        } else {
            ldebug!(
                "SOCKS5 DC{}{} acquired from warm pre-connect pool (0 ms)",
                dc,
                if is_media { "m" } else { "" }
            );
            STATS.socks5_fastpath_hits.fetch_add(1, Ordering::Relaxed);
            trigger_warm_socks5_refill(user_domain.clone(), dc, is_media, cancel_token.clone());
            return Some((ws, user_domain.clone()));
        }
    }

    ldebug!(
        "SOCKS5 custom worker {} attempt -> DC{}{} (dst={})",
        user_domain,
        dc,
        if is_media { "m" } else { "" },
        worker_dst
    );
    let init_buf = init.to_vec();
    let fp_worker = user_domain.clone();
    let fp_path = path.clone();
    let child_cancel = cancel_token.child_token();

    let is_mobile = MOBILE_NETWORK.load(Ordering::Relaxed);
    let worker_timeout = if is_mobile {
        crate::config::adaptive_ws_connect_timeout().clamp(3.0, 4.0)
    } else {
        crate::config::adaptive_ws_connect_timeout().clamp(3.2, 4.5)
    };
    let dial_res = tokio::select! {
        _ = cancel_token.cancelled() => return None,
        res = cf_connect_domain_with_category(
            &fp_worker,
            &fp_path,
            None,
            worker_timeout,
            crate::budget::FlowCategory::UserFlow,
            Some(&child_cancel),
        ) => res,
    };

    let (mut ws_opt, mut resolved_ip, mut err_opt) = dial_res;

    // Fast local retry on transient connection failure (unless 429 or cancelled)
    if ws_opt.is_none() && !cancel_token.is_cancelled() {
        let is_429 = err_opt.as_ref().map(|e| is_http_status_error(e, 429)).unwrap_or(false);
        if !is_429 {
            ldebug!("SOCKS5 custom worker {} initial dial failed; retrying once...", user_domain);
            tokio::time::sleep(Duration::from_millis(50)).await;
            if !cancel_token.is_cancelled() {
                let retry_res = cf_connect_domain_with_category(
                    &fp_worker,
                    &fp_path,
                    None,
                    2.5,
                    crate::budget::FlowCategory::UserFlow,
                    Some(&child_cancel),
                ).await;
                ws_opt = retry_res.0;
                resolved_ip = retry_res.1;
                err_opt = retry_res.2;
            }
        }
    }

    if let Some(ws) = ws_opt {
        if !crate::generation_guard::is_current(expected) {
            ldebug!("SOCKS5 dial completed but network generation changed; dropping stale socket");
            let _ = ws.close().await;
            return None;
        }

        if !init_buf.is_empty() {
            if let Err(e) = ws.send(&init_buf).await {
                let _ = ws.close().await;
                lwarn!("SOCKS5 custom worker first packet write failed: {:?}", e);
            } else {
                if !resolved_ip.is_empty() {
                    ldebug!("SOCKS5 custom worker ok {} via {}", user_domain, resolved_ip);
                } else {
                    ldebug!("SOCKS5 custom worker ok {}", user_domain);
                }
                clear_cfproxy_429_cooldown_scoped(&user_domain, ProtoScope::Socks5);
                clear_cfproxy_recovery_cooldown(&user_domain);
                *LAST_SOCKS5_WORKER.write() = user_domain.clone();
                STATS.socks5_fastpath_hits.fetch_add(1, Ordering::Relaxed);
                trigger_warm_socks5_refill(user_domain.clone(), dc, is_media, cancel_token.clone());
                return Some((ws, user_domain.clone()));
            }
        } else {
            if !resolved_ip.is_empty() {
                ldebug!("SOCKS5 custom worker ok {} via {}", user_domain, resolved_ip);
            } else {
                ldebug!("SOCKS5 custom worker ok {}", user_domain);
            }
            clear_cfproxy_429_cooldown_scoped(&user_domain, ProtoScope::Socks5);
            clear_cfproxy_recovery_cooldown(&user_domain);
            *LAST_SOCKS5_WORKER.write() = user_domain.clone();
            STATS.socks5_fastpath_hits.fetch_add(1, Ordering::Relaxed);
            trigger_warm_socks5_refill(user_domain.clone(), dc, is_media, cancel_token.clone());
            return Some((ws, user_domain.clone()));
        }
    }

    if let Some(e) = err_opt {
        if is_http_status_error(&e, 429) {
            mark_cfproxy_429_cooldown_scoped(&user_domain, ProtoScope::Socks5, &e);
        }
        lwarn!(
            "SOCKS5 custom worker {} fail: {}",
            user_domain,
            e.compact()
        );
    }
    None
}



/// Bounded async write that strictly honors the cancellation token and applies a write deadline.
pub async fn bounded_write<W: tokio::io::AsyncWriteExt + Unpin>(
    writer: &mut W,
    data: &[u8],
    cancel: &CancellationToken,
    timeout_dur: Duration,
) -> Result<(), std::io::Error> {
    let deadline = tokio::time::Instant::now() + timeout_dur;
    let mut written = 0;
    while written < data.len() {
        let result = tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(std::io::ErrorKind::Interrupted.into()),
            _ = tokio::time::sleep_until(deadline) => Err(std::io::ErrorKind::TimedOut.into()),
            result = writer.write(&data[written..]) => result,
        };
        match result {
            Ok(0) => return Err(std::io::ErrorKind::WriteZero.into()),
            Ok(n) => written += n,
            Err(error) => {
                return Err(std::io::Error::new(
                    error.kind(),
                    format!(
                        "bridge write stopped after {written}/{} bytes: {error}",
                        data.len()
                    ),
                ))
            }
        }
    }
    Ok(())
}

/// Bounded async shutdown that emits a FIN segment to half-close the writer direction.
pub async fn bounded_shutdown<W: tokio::io::AsyncWriteExt + Unpin>(
    writer: &mut W,
    cancel: &CancellationToken,
    timeout_dur: Duration,
) -> Result<(), std::io::Error> {
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Err(std::io::Error::new(
            std::io::ErrorKind::Interrupted,
            "operation cancelled"
        )),
        res = tokio::time::timeout(timeout_dur, writer.shutdown()) => match res {
            Ok(shutdown_res) => shutdown_res,
            Err(_) => Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "shutdown timeout"
            )),
        }
    }
}

pub async fn bridge_socks5_ws(
    client: TcpStream,
    ws: Arc<RawWebSocket>,
    dc: i32,
    is_media: bool,
    winner_domain: &str,
    cancel_token: CancellationToken,
    proto: Option<u32>,
    initial_clt_data: Vec<u8>,
    init_head: Option<[u8; 64]>,
    is_flowseal: bool,
) {
    let session_start = Instant::now();
    let total_up = Arc::new(AtomicU64::new(0));
    let total_down = Arc::new(AtomicU64::new(0));
    let close_reason = Arc::new(parking_lot::Mutex::new("Normal".to_string()));

    let (mut c_read, mut c_write) = client.into_split();
    let bridge_cancel = cancel_token.child_token();
    let _bridge_guard = bridge_cancel.clone().drop_guard();
    let activity = crate::bridge::BridgeActivity::with_ws(ws.clone());

    let ws_ping = ws.clone();
    let cancel_ping = bridge_cancel.clone();
    let reason_ping = close_reason.clone();
    let heartbeat = async move {
        if ws_ping.run_heartbeat(cancel_ping.clone()).await.is_err() {
            *reason_ping.lock() = "HeartbeatTimeout".to_string();
            cancel_ping.cancel();
        }
    };

    let (mut splitter, mut clt_dec, mut tg_enc) = if is_flowseal && init_head.is_some() {
        let head = init_head.unwrap();
        let p = proto.unwrap_or(0xEFEFEFEF);
        let s = MsgSplitter::new(p);
        let mut d = new_aes_ctr(&head[8..40], &head[40..56]);
        let mut dummy = [0u8; 64];
        d.xor(&mut dummy);
        let e = d.clone();
        (Some(s), Some(d), Some(e))
    } else {
        (None, None, None)
    };

    // Up: Client -> WS
    let ws_up = ws.clone();
    let bridge_cancel_up = bridge_cancel.clone();
    let activity_up = activity.clone();
    let total_up_clone = total_up.clone();
    let reason_up = close_reason.clone();
    let up = async move {
        // 1. Process initial coalesced application data (if any) through splitter
        if !initial_clt_data.is_empty() {
            let n = initial_clt_data.len();
            total_up_clone.fetch_add(n as u64, Ordering::Relaxed);
            STATS.bytes_up.fetch_add(n as i64, Ordering::Relaxed);
            if let (Some(ref mut s), Some(ref mut d), Some(ref mut e)) = (&mut splitter, &mut clt_dec, &mut tg_enc) {
                let frames = s.process(&initial_clt_data, d, e);
                if !frames.is_empty() {
                    if let Err(err) = ws_up.send_batch(&frames).await {
                        ldebug!("Bridge WS upstream send_batch initial error: {:?}", err);
                        bridge_cancel_up.cancel();
                        return;
                    }
                }
            } else {
                if let Err(err) = ws_up.send(&initial_clt_data).await {
                    ldebug!("Bridge WS upstream send initial error: {:?}", err);
                    bridge_cancel_up.cancel();
                    return;
                }
            }
        }

        let mut buf = vec![0u8; WS_BRIDGE_CHUNK_SIZE];
        loop {
            let res = tokio::select! {
                _ = bridge_cancel_up.cancelled() => break,
                r = tokio::time::timeout(Duration::from_secs(30), c_read.read(&mut buf)) => r,
            };
            match res {
                Ok(Ok(0)) => {
                    activity_up.upload_eof();
                    if let (Some(ref mut s), _, Some(ref mut e)) = (&mut splitter, &mut clt_dec, &mut tg_enc) {
                        let tail = s.flush(e);
                        if !tail.is_empty() {
                            let _ = ws_up.send_batch(&tail).await;
                        }
                    }
                    let mut r = reason_up.lock();
                    if *r == "Normal" {
                        *r = "ClientEof".to_string();
                    }
                    break;
                }
                Ok(Err(e)) => {
                    ldebug!("Bridge WS client read error: {}", e);
                    let mut r = reason_up.lock();
                    if *r == "Normal" {
                        *r = format!("ClientReadErr({})", e);
                    }
                    bridge_cancel_up.cancel();
                    break;
                }
                Err(_) => {
                    let idle = ws_up.heartbeat_idle_for();
                    if idle >= crate::config::profile_aware_absolute_idle_timeout() {
                        ldebug!("Bridge WS overall idle timeout exceeded ({}s)", idle.as_secs());
                        let mut r = reason_up.lock();
                        if *r == "Normal" {
                            *r = format!("IdleTimeout({}s)", idle.as_secs());
                        }
                        bridge_cancel_up.cancel();
                        break;
                    }
                    continue;
                }
                Ok(Ok(n)) => {
                    activity_up.touch();
                    total_up_clone.fetch_add(n as u64, Ordering::Relaxed);
                    STATS.bytes_up.fetch_add(n as i64, Ordering::Relaxed);

                    if let (Some(ref mut s), Some(ref mut d), Some(ref mut e)) = (&mut splitter, &mut clt_dec, &mut tg_enc) {
                        let frames = s.process(&buf[..n], d, e);
                        if !frames.is_empty() {
                            let send_res = tokio::select! {
                                _ = bridge_cancel_up.cancelled() => Err(WsError::Other("cancelled".to_string())),
                                r = ws_up.send_batch(&frames) => r,
                            };
                            if let Err(e) = send_res {
                                ldebug!("Bridge WS upstream send_batch error: {:?}", e);
                                let mut r = reason_up.lock();
                                if *r == "Normal" {
                                    *r = format!("WsSendBatchErr({:?})", e);
                                }
                                bridge_cancel_up.cancel();
                                break;
                            }
                        }
                    } else {
                        let send_res = tokio::select! {
                            _ = bridge_cancel_up.cancelled() => Err(WsError::Other("cancelled".to_string())),
                            r = ws_up.send(&buf[..n]) => r,
                        };
                        if let Err(e) = send_res {
                            ldebug!("Bridge WS upstream send error: {:?}", e);
                            let mut r = reason_up.lock();
                            if *r == "Normal" {
                                *r = format!("WsSendErr({:?})", e);
                            }
                            bridge_cancel_up.cancel();
                            break;
                        }
                    }
                }
            }
        }

        if let (Some(ref mut s), _, Some(ref mut e)) = (&mut splitter, &mut clt_dec, &mut tg_enc) {
            let tail = s.flush(e);
            if !tail.is_empty() {
                let _ = ws_up.send_batch(&tail).await;
            }
        }
    };

    // Down: WS -> Client
    let ws_down = ws.clone();
    let bridge_cancel_down = bridge_cancel.clone();
    let total_down_clone = total_down.clone();
    let reason_down = close_reason.clone();
    let down_dst = winner_domain.to_string();
    let down = async move {
        let mut bytes_before_stall: u64 = 0;
        let mut last_progress_log = Instant::now();
        let mut last_progress_bytes: u64 = 0;
        let mut first_rx = true;
        let base_domain = crate::balancer::normalize_domain(&down_dst);
        let cur_gen = crate::network_profile::current_generation();

        loop {
            let res = activity
                .wait(ws_down.recv(), &bridge_cancel_down)
                .await
                .unwrap_or_else(|error| Err(WsError::Io(error)));
            match res {
                Ok(data) => {
                    if data.is_empty() {
                        continue;
                    }
                    activity.touch();
                    let n = data.len();
                    bytes_before_stall = bytes_before_stall.saturating_add(n as u64);
                    total_down_clone.fetch_add(n as u64, Ordering::Relaxed);
                    STATS.bytes_down.fetch_add(n as i64, Ordering::Relaxed);

                    if first_rx && n > 0 {
                        first_rx = false;
                        if !base_domain.is_empty() {
                            crate::balancer::BALANCER.write().record_useful_success(
                                cur_gen,
                                dc,
                                is_media,
                                &base_domain,
                            );
                        }
                    }

                    let current_total = total_down_clone.load(Ordering::Relaxed);
                    if current_total >= 64 * 1024 {
                        let now = Instant::now();
                        let elapsed = now.duration_since(last_progress_log);
                        if elapsed >= Duration::from_secs(5) {
                            let delta_b = current_total.saturating_sub(last_progress_bytes);
                            let speed = (delta_b as f64 / 1024.0) / elapsed.as_secs_f64();
                            crate::linfo!(
                                "SOCKS5 DC{}{} transfer: rx={:.1} KB ({:.1} KB/s)",
                                dc,
                                if is_media { " (media)" } else { "" },
                                current_total as f64 / 1024.0,
                                speed
                            );
                            last_progress_log = now;
                            last_progress_bytes = current_total;
                        }
                    }

                    if let Err(e) =
                        bounded_write(&mut c_write, &data, &bridge_cancel_down, BRIDGE_WRITE_TIMEOUT)
                            .await
                    {
                        ldebug!("Bridge WS client write error: {}", e);
                        *reason_down.lock() = format!("ClientWriteErr({})", e);
                        bridge_cancel_down.cancel();
                        break;
                    }
                }
                Err(WsError::Timeout) => {
                    let idle = ws_down.heartbeat_idle_for();
                    if idle >= crate::config::profile_aware_absolute_idle_timeout() {
                        ldebug!("Bridge WS download idle timeout exceeded ({}s)", idle.as_secs());
                        let mut r = reason_down.lock();
                        if *r == "Normal" {
                            *r = format!("DownloadIdleTimeout({}s)", idle.as_secs());
                        }
                        bridge_cancel_down.cancel();
                        break;
                    }
                    continue;
                }
                Err(e) => {
                    ldebug!("Bridge WS downstream recv closed/error: {:?}", e);
                    {
                        let mut r = reason_down.lock();
                        if *r == "Normal" {
                            *r = format!("WsRecvErr({:?})", e);
                        }
                    }
                    let _ =
                        bounded_shutdown(&mut c_write, &bridge_cancel_down, BRIDGE_WRITE_TIMEOUT).await;
                    bridge_cancel_down.cancel();
                    break;
                }
            }
        }

        if first_rx && !base_domain.is_empty() {
            crate::balancer::BALANCER.write().record_failure(
                cur_gen,
                dc,
                is_media,
                &base_domain,
            );
        }

        let domain = ws_down.recovery_scope().to_string();
        let tracker_domain = if !base_domain.is_empty() { &base_domain } else { &domain };
        if bytes_before_stall == 0 && !bridge_cancel_down.is_cancelled() {
            crate::node_independence::NODE_INDEPENDENCE_TRACKER
                .write()
                .record_node_stall(tracker_domain, 0);
        } else if bytes_before_stall > 0 {
            crate::node_independence::NODE_INDEPENDENCE_TRACKER
                .write()
                .record_node_bytes_transferred(tracker_domain, bytes_before_stall);
        }
        let _ =
            bounded_shutdown(&mut c_write, &bridge_cancel_down, Duration::from_secs(2)).await;
    };

    let transfer = async {
        tokio::join!(up, down);
        bridge_cancel.cancel();
    };
    tokio::join!(transfer, heartbeat);
    ws.close().await;

    let duration = session_start.elapsed();
    let dur_sec = duration.as_secs_f64();
    let rx_kb = total_down.load(Ordering::Relaxed) as f64 / 1024.0;
    let tx_kb = total_up.load(Ordering::Relaxed) as f64 / 1024.0;
    let avg_speed_kb = if dur_sec > 0.05 { rx_kb / dur_sec } else { 0.0 };
    let reason = close_reason.lock().clone();
    crate::linfo!(
        "SOCKS5 session ended: DC{}{} (dst={}), dur={:.1}s, rx={:.1} KB, tx={:.1} KB, avg={:.1} KB/s, reason={}",
        dc,
        if is_media { " (media)" } else { "" },
        winner_domain,
        dur_sec,
        rx_kb,
        tx_kb,
        avg_speed_kb,
        reason
    );
}



pub async fn bridge_socks5_stream<S>(
    mut client: TcpStream,
    mut upstream: S,
    initial_downlink: Vec<u8>,
    cancel_token: CancellationToken,
) where
    S: tokio::io::AsyncReadExt + tokio::io::AsyncWriteExt + Send + Unpin + 'static,
{
    if !initial_downlink.is_empty() {
        if bounded_write(&mut client, &initial_downlink, &cancel_token, BRIDGE_WRITE_TIMEOUT)
            .await
            .is_err()
        {
            return;
        }
    }
    let _ = tokio::select! {
        _ = cancel_token.cancelled() => Ok((0, 0)),
        res = tokio::io::copy_bidirectional(&mut client, &mut upstream) => res,
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_bounded_write_success_and_cancellation() {
        let (mut client_reader, mut server_writer) = tokio::io::duplex(1024);
        let cancel = CancellationToken::new();

        let write_res = bounded_write(
            &mut server_writer,
            b"hello-bounded-write",
            &cancel,
            Duration::from_secs(2),
        )
        .await;
        assert!(write_res.is_ok());

        let mut read_buf = [0u8; 19];
        client_reader.read_exact(&mut read_buf).await.unwrap();
        assert_eq!(&read_buf, b"hello-bounded-write");

        cancel.cancel();
        let cancelled_res = bounded_write(
            &mut server_writer,
            b"should-not-be-written",
            &cancel,
            Duration::from_secs(2),
        )
        .await;
        assert!(cancelled_res.is_err());
        assert_eq!(
            cancelled_res.unwrap_err().kind(),
            std::io::ErrorKind::Interrupted
        );
    }

    #[tokio::test]
    async fn test_bounded_write_timeout_on_blocked_reader() {
        let (_client_reader, mut server_writer) = tokio::io::duplex(16);
        let cancel = CancellationToken::new();

        let _ = server_writer.write_all(&[1u8; 16]).await;

        let timeout_res = bounded_write(
            &mut server_writer,
            &[2u8; 32],
            &cancel,
            Duration::from_millis(50),
        )
        .await;

        assert!(timeout_res.is_err());
        assert_eq!(
            timeout_res.unwrap_err().kind(),
            std::io::ErrorKind::TimedOut
        );
    }

    #[test]
    fn test_is_telegram_host_classification() {
        assert!(is_telegram_host("149.154.167.50"));
        assert!(is_telegram_host("91.108.56.100"));
        assert!(is_telegram_host("91.105.192.100"));
        assert!(is_telegram_host("185.76.151.10"));
        assert!(is_telegram_host("95.161.76.100"));
        assert!(is_telegram_host("2001:b28:f23d:f001::a"));
        assert!(is_telegram_host("2001:67c:4e8:f002::a"));
        assert!(is_telegram_host("telegram.org"));
        assert!(is_telegram_host("api.telegram.org"));
        assert!(is_telegram_host("t.me"));

        assert!(!is_telegram_host("google.com"));
        assert!(!is_telegram_host("1.1.1.1"));
        assert!(!is_telegram_host("8.8.8.8"));
        assert!(!is_telegram_host("192.168.1.1"));
    }

    #[test]
    fn test_dc_from_init_and_patch() {
        // Build a mock 64-byte MTProto init for DC2 (chat)
        let mut init = [0u8; 64];
        for i in 0..64 {
            init[i] = (i * 7 + 13) as u8;
        }

        // Apply CTR keystream to inject valid proto (0xEEEEEEEE) and dc (2)
        let mut stream = crate::crypto::new_aes_ctr(&init[8..40], &init[40..56]);
        let mut ks = [0u8; 64];
        stream.xor(&mut ks);

        LittleEndian::write_u32(&mut init[56..60], 0xEEEEEEEE ^ LittleEndian::read_u32(&ks[56..60]));
        LittleEndian::write_i16(&mut init[60..62], 2 ^ LittleEndian::read_i16(&ks[60..62]));

        let res = dc_from_init(&init);
        assert_eq!(res, Some((2, false, 0xEEEEEEEE)));

        // Patch to DC4
        let patched = patch_init_dc(&init, 4);
        let res_patched = dc_from_init(&patched);
        assert_eq!(res_patched, Some((4, false, 0xEEEEEEEE)));

        // Patch to DC4 Media (negative DC)
        let patched_media = patch_init_dc(&init, -4);
        let res_patched_media = dc_from_init(&patched_media);
        assert_eq!(res_patched_media, Some((4, true, 0xEEEEEEEE)));
    }

    #[test]
    fn test_lookup_telegram_dc_ipv6_and_ipv4() {
        // Expanded IPv6 used by Telegram Android client
        assert_eq!(
            lookup_telegram_dc("2001:067c:04e8:f004:0000:0000:0000:0007"),
            Some((4, false))
        );
        // Shortened IPv6
        assert_eq!(lookup_telegram_dc("2001:67c:4e8:f004::7"), Some((4, false)));
        assert_eq!(lookup_telegram_dc("[2001:67c:4e8:f004::7]"), Some((4, false)));
        assert_eq!(lookup_telegram_dc("2001:67c:4e8:f002::a"), Some((2, false)));
        assert_eq!(lookup_telegram_dc("2001:b28:f23d:f001::a"), Some((1, false)));
        assert_eq!(lookup_telegram_dc("2001:b28:f23f:f005::a"), Some((5, false)));

        // IPv4
        assert_eq!(lookup_telegram_dc("149.154.167.91"), Some((4, false)));
        assert_eq!(lookup_telegram_dc("149.154.167.50"), Some((2, false)));
        assert_eq!(lookup_telegram_dc("149.154.167.118"), Some((4, true)));
        assert_eq!(lookup_telegram_dc("91.108.56.100"), Some((5, false)));
        assert_eq!(lookup_telegram_dc("91.105.192.100"), Some((203, false)));
    }

    #[test]
    fn test_resolve_socks5_telegram_destination_canonical() {
        // DC4 IPv6 maps to canonical DC4 IPv4
        let (dst, port) = resolve_socks5_telegram_destination(
            "2001:067c:04e8:f004:0000:0000:0000:0007",
            443,
            Some(4),
            false,
        );
        assert_eq!(dst, "149.154.167.91");
        assert_eq!(port, 443);

        // DC4 media maps to canonical DC4 IPv4
        let (dst, port) =
            resolve_socks5_telegram_destination("149.154.167.118", 443, Some(4), true);
        assert_eq!(dst, "149.154.167.91");
        assert_eq!(port, 443);

        // DC2 maps to canonical DC2 IPv4
        let (dst, port) =
            resolve_socks5_telegram_destination("149.154.167.50", 443, Some(2), false);
        assert_eq!(dst, "149.154.167.51");
        assert_eq!(port, 443);
    }
}
