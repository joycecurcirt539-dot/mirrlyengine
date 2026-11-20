#[macro_use]
pub mod config;
pub mod balancer;
pub mod budget;
pub mod bridge;
pub mod cfproxy;
pub mod crypto;
pub mod faketls;
pub mod generation_guard;
pub mod network_profile;
pub mod node_independence;
pub mod proxy;
pub mod recovery;
pub mod socks5;
pub mod tls_observability;
pub mod ws;
pub mod platform;

pub use cfproxy::ProtoScope;

use config::*;
use once_cell::sync::OnceCell;
use parking_lot::Mutex;
use proxy::{run_proxy, WsPool};
use socks5::run_socks5_server;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::runtime::Runtime;
use tokio_util::sync::CancellationToken;

static RUNTIME: OnceCell<Runtime> = OnceCell::new();
static ENGINE_STARTED_AT: OnceCell<Instant> = OnceCell::new();
static MTPROTO_RUNNING: AtomicBool = AtomicBool::new(false);
static SOCKS5_RUNNING: AtomicBool = AtomicBool::new(false);
static MTPROTO_LISTEN_PORT: AtomicU16 = AtomicU16::new(0);
static SOCKS5_LISTEN_PORT: AtomicU16 = AtomicU16::new(0);
static REQUESTED_RUNTIME_THREADS: AtomicUsize = AtomicUsize::new(0);

fn mark_engine_started() {
    ENGINE_STARTED_AT.get_or_init(Instant::now);
}

fn engine_uptime_secs() -> u64 {
    ENGINE_STARTED_AT
        .get()
        .map(|started| started.elapsed().as_secs())
        .unwrap_or(0)
}

pub fn build_stats_json() -> String {
    serde_json::json!({
        "connections_total": STATS.connections_total.load(Ordering::Relaxed),
        "connections_active": STATS.connections_active.load(Ordering::Relaxed),
        "connections_ws": STATS.connections_ws.load(Ordering::Relaxed),
        "connections_cfproxy": STATS.connections_cfproxy.load(Ordering::Relaxed),
        "connections_bad": STATS.connections_bad.load(Ordering::Relaxed),
        "ws_errors": STATS.ws_errors.load(Ordering::Relaxed),
        "bytes_up": STATS.bytes_up.load(Ordering::Relaxed),
        "bytes_down": STATS.bytes_down.load(Ordering::Relaxed),
        "pool_hits": STATS.pool_hits.load(Ordering::Relaxed),
        "pool_misses": STATS.pool_misses.load(Ordering::Relaxed),
        "uptime_secs": engine_uptime_secs(),
        "tls_enabled": ws::is_tls_enabled(),
        "mtproto_running": MTPROTO_RUNNING.load(Ordering::Acquire),
        "socks5_running": SOCKS5_RUNNING.load(Ordering::Acquire),
        "mtproto_port": MTPROTO_LISTEN_PORT.load(Ordering::Acquire),
        "socks5_port": SOCKS5_LISTEN_PORT.load(Ordering::Acquire),
    })
    .to_string()
}

struct ListenerDoneSignal(Option<std::sync::mpsc::SyncSender<()>>);

impl Drop for ListenerDoneSignal {
    fn drop(&mut self) {
        if let Some(tx) = self.0.take() {
            let _ = tx.try_send(());
        }
    }
}

struct MtprotoState {
    pool: Arc<WsPool>,
    handle: tokio::task::JoinHandle<()>,
    cancel_tasks: CancellationToken,
    cancel_sessions: Arc<parking_lot::RwLock<CancellationToken>>,
    done_rx: std::sync::mpsc::Receiver<()>,
}

struct Socks5State {
    handle: tokio::task::JoinHandle<()>,
    cancel_tasks: CancellationToken,
    cancel_sessions: Arc<parking_lot::RwLock<CancellationToken>>,
    done_rx: std::sync::mpsc::Receiver<()>,
}

static MTPROTO_STATE: OnceCell<Mutex<Option<MtprotoState>>> = OnceCell::new();
static SOCKS5_STATE: OnceCell<Mutex<Option<Socks5State>>> = OnceCell::new();

fn mtproto_state_cell() -> &'static Mutex<Option<MtprotoState>> {
    MTPROTO_STATE.get_or_init(|| Mutex::new(None))
}

fn socks5_state_cell() -> &'static Mutex<Option<Socks5State>> {
    SOCKS5_STATE.get_or_init(|| Mutex::new(None))
}

fn abort_and_wait_listener_drop(
    handle: tokio::task::JoinHandle<()>,
    cancel_tasks: CancellationToken,
    done_rx: std::sync::mpsc::Receiver<()>,
) {
    cancel_tasks.cancel();
    handle.abort();
    // Only wait synchronously when called outside a Tokio runtime worker thread.
    if tokio::runtime::Handle::try_current().is_err() {
        let _ = done_rx.recv_timeout(Duration::from_millis(500));
    }
}

fn map_bind_error(err_kind: std::io::ErrorKind) -> c_int {
    if err_kind == std::io::ErrorKind::AddrInUse {
        -1
    } else {
        -2
    }
}

fn init_crypto_and_panic_hook() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    if !std::thread::panicking() {
        static PANIC_HOOK_SET: OnceCell<()> = OnceCell::new();
        PANIC_HOOK_SET.get_or_init(|| {
            std::panic::set_hook(Box::new(|info| {
                crate::lerror!("RUST ENGINE PANIC: {}", info);
            }));
        });
    }
}

fn effective_runtime_worker_threads() -> usize {
    let requested = REQUESTED_RUNTIME_THREADS.load(Ordering::Acquire);
    if requested > 0 {
        return requested.clamp(1, 16);
    }
    let (min_threads, max_threads) = platform::default_runtime_thread_bounds();
    let detected_cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(min_threads);
    detected_cores.clamp(min_threads, max_threads)
}

pub(crate) fn runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| {
        init_crypto_and_panic_hook();

        let worker_threads = effective_runtime_worker_threads();

        crate::linfo!(
            "Tokio multi-thread runtime initialized: {} worker threads",
            worker_threads
        );

        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(worker_threads)
            .thread_name("mirrly-rt")
            .event_interval(31)
            .max_blocking_threads(32)
            .enable_all()
            .build()
            .expect("failed to build global tokio runtime")
    })
}

fn cstr_to_string(p: *const c_char) -> String {
    if p.is_null() {
        return String::new();
    }
    unsafe { CStr::from_ptr(p).to_string_lossy().into_owned() }
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn StartProxy(
    c_host: *const c_char,
    port: c_int,
    c_dc_ips: *const c_char,
    c_secret: *const c_char,
    verbose: c_int,
) -> c_int {
    if port < 0 || port > u16::MAX as c_int {
        return -2;
    }

    init_crypto_and_panic_hook();

    let cell = mtproto_state_cell();
    let mut guard = cell.lock();

    if let Some(old_state) = guard.take() {
        MTPROTO_RUNNING.store(false, Ordering::Release);
        MTPROTO_LISTEN_PORT.store(0, Ordering::Release);
        crate::linfo!("StartProxy: taking down previous active MTProto state before restart");
        abort_and_wait_listener_drop(old_state.handle, old_state.cancel_tasks, old_state.done_rx);
    }

    generation_guard::change_config(|| {});

    let host = cstr_to_string(c_host);
    let go_port = port as u16;
    let _dc_ips_str = cstr_to_string(c_dc_ips);
    let secret_str = cstr_to_string(c_secret);
    let is_verbose = verbose != 0;

    init_logging(is_verbose);
    cfproxy::init_cfproxy_domains();
    cfproxy::clear_doh_cache();
    recovery::reset();
    balancer::BALANCER.write().reset_ranking();
    node_independence::NODE_INDEPENDENCE_TRACKER.write().reset();
    tls_observability::TLS_TRACKER.write().reset();

    if secret_str.len() >= 32 {
        let clean_sec = if secret_str.starts_with("ee") && secret_str.len() >= 34 {
            &secret_str[2..34]
        } else if secret_str.starts_with("dd") && secret_str.len() == 34 {
            &secret_str[2..34]
        } else {
            &secret_str[..32]
        };
        if hex::decode(clean_sec).is_ok() {
            *PROXY_SECRET.write() = clean_sec.to_string();
        }
    }

    let dc_opt_map: HashMap<i32, String> = HashMap::new();
    *DC_OPT.write() = dc_opt_map.clone();

    let rt = runtime();
    let cancel_tasks = CancellationToken::new();
    let cancel_sessions = Arc::new(parking_lot::RwLock::new(cancel_tasks.child_token()));
    let pool = Arc::new(WsPool::new(cancel_tasks.clone()));

    let (tx, rx) = std::sync::mpsc::channel::<Result<u16, (std::io::ErrorKind, String)>>();
    let (done_tx, done_rx) = std::sync::mpsc::sync_channel::<()>(1);

    let pool_task = pool.clone();
    let host_task = host.clone();
    let map_task = dc_opt_map.clone();
    let cancel_root = cancel_tasks.clone();
    let cancel_sessions_task = cancel_sessions.clone();

    let handle = rt.spawn(async move {
        let _done_signal = ListenerDoneSignal(Some(done_tx));
        let addr = format!("{}:{}", host_task, go_port);
        match platform::bind_local_tcp(&addr) {
            Ok((listener, bound_port)) => {
                let _ = tx.send(Ok(bound_port));
                if let Err(e) = run_proxy(
                    pool_task,
                    host_task,
                    bound_port,
                    map_task,
                    cancel_root,
                    cancel_sessions_task,
                    listener,
                )
                .await
                {
                    crate::lerror!("listen on {}: {}", addr, e);
                }
            }
            Err(e) => {
                let kind = e.kind();
                let _ = tx.send(Err((kind, format!("listen on {}: {}", addr, e))));
            }
        }
    });

    let bound_port = match rx.recv() {
        Ok(Ok(p)) => p,
        Ok(Err((kind, msg))) => {
            abort_and_wait_listener_drop(handle, cancel_tasks, done_rx);
            crate::lwarn!("StartProxy bind error: {}", msg);
            return map_bind_error(kind);
        }
        Err(_) => {
            abort_and_wait_listener_drop(handle, cancel_tasks, done_rx);
            return -3;
        }
    };

    let cancel_balancer = cancel_tasks.clone();
    rt.spawn(async move {
        cfproxy::start_background_balancer_loop(cancel_balancer).await;
    });

    *guard = Some(MtprotoState {
        pool,
        handle,
        cancel_tasks,
        cancel_sessions,
        done_rx,
    });
    mark_engine_started();
    MTPROTO_LISTEN_PORT.store(bound_port, Ordering::Release);
    MTPROTO_RUNNING.store(true, Ordering::Release);

    0
}

#[no_mangle]
pub unsafe extern "C" fn StartSocks5Proxy(
    c_host: *const c_char,
    port: c_int,
    verbose: c_int,
) -> c_int {
    if port < 0 || port > u16::MAX as c_int {
        return -2;
    }

    init_crypto_and_panic_hook();

    let cell = socks5_state_cell();
    let mut guard = cell.lock();

    if let Some(old_state) = guard.take() {
        SOCKS5_RUNNING.store(false, Ordering::Release);
        SOCKS5_LISTEN_PORT.store(0, Ordering::Release);
        crate::linfo!("StartSocks5Proxy: taking down previous active SOCKS5 state before restart");
        abort_and_wait_listener_drop(old_state.handle, old_state.cancel_tasks, old_state.done_rx);
    }

    generation_guard::change_config(|| {});

    let host = cstr_to_string(c_host);
    let go_port = port as u16;
    let is_verbose = verbose != 0;

    init_logging(is_verbose);
    cfproxy::init_cfproxy_domains();
    cfproxy::clear_doh_cache();
    recovery::reset();
    *LAST_SOCKS5_WORKER.write() = String::new();
    node_independence::NODE_INDEPENDENCE_TRACKER.write().reset();
    tls_observability::TLS_TRACKER.write().reset();

    let rt = runtime();
    let cancel_tasks = CancellationToken::new();
    let cancel_sessions = Arc::new(parking_lot::RwLock::new(cancel_tasks.child_token()));

    let (tx, rx) = std::sync::mpsc::channel::<Result<u16, (std::io::ErrorKind, String)>>();
    let (done_tx, done_rx) = std::sync::mpsc::sync_channel::<()>(1);

    let host_task = host.clone();
    let cancel_root = cancel_tasks.clone();
    let cancel_sessions_task = cancel_sessions.clone();

    let handle = rt.spawn(async move {
        let _done_signal = ListenerDoneSignal(Some(done_tx));
        let addr = format!("{}:{}", host_task, go_port);
        match platform::bind_local_tcp(&addr) {
            Ok((listener, bound_port)) => {
                let _ = tx.send(Ok(bound_port));
                if let Err(e) = run_socks5_server(
                    host_task,
                    bound_port,
                    cancel_root,
                    cancel_sessions_task,
                    listener,
                )
                .await
                {
                    crate::lerror!("listen socks5 on {}: {}", addr, e);
                }
            }
            Err(e) => {
                let kind = e.kind();
                let _ = tx.send(Err((kind, format!("listen socks5 on {}: {}", addr, e))));
            }
        }
    });

    let bound_port = match rx.recv() {
        Ok(Ok(p)) => p,
        Ok(Err((kind, msg))) => {
            abort_and_wait_listener_drop(handle, cancel_tasks, done_rx);
            crate::lwarn!("StartSocks5Proxy bind error: {}", msg);
            return map_bind_error(kind);
        }
        Err(_) => {
            abort_and_wait_listener_drop(handle, cancel_tasks, done_rx);
            return -3;
        }
    };

    let cancel_warm = cancel_tasks.clone();
    rt.spawn(async move {
        let user_domain = CFPROXY.read().user_domain.clone();
        socks5::trigger_warm_socks5_pool_prime(user_domain, cancel_warm);
    });

    *guard = Some(Socks5State {
        handle,
        cancel_tasks,
        cancel_sessions,
        done_rx,
    });
    mark_engine_started();
    SOCKS5_LISTEN_PORT.store(bound_port, Ordering::Release);
    SOCKS5_RUNNING.store(true, Ordering::Release);

    0
}

#[no_mangle]
pub extern "C" fn GetMtprotoListenPort() -> c_int {
    if MTPROTO_RUNNING.load(Ordering::Acquire) {
        MTPROTO_LISTEN_PORT.load(Ordering::Acquire) as c_int
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn GetSocks5ListenPort() -> c_int {
    if SOCKS5_RUNNING.load(Ordering::Acquire) {
        SOCKS5_LISTEN_PORT.load(Ordering::Acquire) as c_int
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn SetRuntimeWorkerThreads(threads: c_int) -> c_int {
    if threads <= 0 {
        REQUESTED_RUNTIME_THREADS.store(0, Ordering::Release);
    } else {
        let clamped = (threads as usize).clamp(1, 16);
        REQUESTED_RUNTIME_THREADS.store(clamped, Ordering::Release);
    }
    if RUNTIME.get().is_some() {
        return -1;
    }
    effective_runtime_worker_threads() as c_int
}

#[no_mangle]
pub unsafe extern "C" fn SetLogCallback(
    callback: Option<platform::LogCallbackFn>,
    user_data: *mut c_void,
) {
    platform::set_log_callback(callback, user_data);
}

#[no_mangle]
pub extern "C" fn StopProxy() -> c_int {
    StopMtprotoProxy();
    StopSocks5Proxy();
    0
}

#[no_mangle]
pub extern "C" fn StopMtprotoProxy() -> c_int {
    MTPROTO_RUNNING.store(false, Ordering::Release);
    MTPROTO_LISTEN_PORT.store(0, Ordering::Release);
    let state_opt = mtproto_state_cell().lock().take();
    if let Some(state) = state_opt {
        crate::linfo!("StopMtprotoProxy: cancelling MTProto tasks");
        let pool = state.pool;
        abort_and_wait_listener_drop(state.handle, state.cancel_tasks, state.done_rx);
        runtime().spawn(async move {
            pool.close_all().await;
        });
    }
    0
}

#[no_mangle]
pub extern "C" fn StopSocks5Proxy() -> c_int {
    SOCKS5_RUNNING.store(false, Ordering::Release);
    SOCKS5_LISTEN_PORT.store(0, Ordering::Release);
    let state_opt = socks5_state_cell().lock().take();
    if let Some(state) = state_opt {
        crate::linfo!("StopSocks5Proxy: cancelling SOCKS5 tasks");
        abort_and_wait_listener_drop(state.handle, state.cancel_tasks, state.done_rx);
    }
    0
}

#[no_mangle]
pub extern "C" fn ResetNetworkSockets() {
    reset_network_sockets_for_reason("external/network-generation reset");
}

#[no_mangle]
pub extern "C" fn EmergencyKillAllSockets() {
    reset_network_sockets_for_reason("emergency kill all sockets");
}

pub(crate) fn reset_network_sockets_for_reason(reason: &str) {
    generation_guard::invalidate_profile();
    recovery::reset();

    crate::linfo!(
        "ResetNetworkSockets: last-level reset reason={} (preserving DoH cache, active worker, and 429 backoff)",
        reason
    );

    {
        let guard = mtproto_state_cell().lock();
        if let Some(ref state) = *guard {
            let old_token = {
                let mut lock = state.cancel_sessions.write();
                let old = lock.clone();
                *lock = state.cancel_tasks.child_token();
                old
            };
            old_token.cancel();
            let pool = state.pool.clone();
            runtime().spawn(async move {
                let map = DC_OPT.read().clone();
                pool.reset_and_warmup(&map).await;
            });
        }
    }

    {
        let guard = socks5_state_cell().lock();
        if let Some(ref state) = *guard {
            let old_token = {
                let mut lock = state.cancel_sessions.write();
                let old = lock.clone();
                *lock = state.cancel_tasks.child_token();
                old
            };
            old_token.cancel();
            let user_domain = CFPROXY.read().user_domain.clone();
            socks5::trigger_warm_socks5_pool_prime(user_domain, state.cancel_tasks.clone());
        }
    }

    DC_FAIL_UNTIL.write().clear();
    WS_BLACKLIST.write().clear();
    balancer::BALANCER.write().reset_ranking();
    node_independence::NODE_INDEPENDENCE_TRACKER.write().reset();
    socks5::clear_socks5_warm_pool();
    cfproxy::clear_doh_cache();
}

pub(crate) fn reset_network_routing_for_reason_if_current(
    expected: generation_guard::GenerationStamp,
    reason: &str,
) -> bool {
    generation_guard::invalidate_profile_if_current(expected, || {
        crate::linfo!(
            "ResetNetworkRouting: rotating candidate endpoints and DoH cache reason={} (keeping active data sessions intact)",
            reason
        );
        DC_FAIL_UNTIL.write().clear();
        WS_BLACKLIST.write().clear();
        balancer::BALANCER.write().reset_ranking();
        node_independence::NODE_INDEPENDENCE_TRACKER.write().reset();
    })
    .is_some()
}

/// Enter offline dormancy without launching DNS, CDN races or pool warmup.
/// A later ResetNetworkSockets performs the single recovery cycle.
#[no_mangle]
pub extern "C" fn SuspendNetworkSockets() {
    {
        let guard = mtproto_state_cell().lock();
        if let Some(ref state) = *guard {
            crate::linfo!("SuspendNetworkSockets: cancelling MTProto sessions without reconnect work");
            let old_token = {
                let mut lock = state.cancel_sessions.write();
                let old = lock.clone();
                *lock = state.cancel_tasks.child_token();
                old
            };
            old_token.cancel();
            let pool = state.pool.clone();
            runtime().spawn(async move {
                pool.reset().await;
            });
        }
    }
    {
        let guard = socks5_state_cell().lock();
        if let Some(ref state) = *guard {
            crate::linfo!("SuspendNetworkSockets: cancelling SOCKS5 sessions without reconnect work");
            let old_token = {
                let mut lock = state.cancel_sessions.write();
                let old = lock.clone();
                *lock = state.cancel_tasks.child_token();
                old
            };
            old_token.cancel();
        }
    }
}

/// Add missing idle MTProto sockets without rotating the session token or
/// closing established bridges. Also primes SOCKS5 warm pool if SOCKS5 is active.
#[no_mangle]
pub extern "C" fn WarmupWsPool() {
    {
        let guard = mtproto_state_cell().lock();
        if let Some(ref state) = *guard {
            let pool = state.pool.clone();
            runtime().spawn(async move {
                let map = DC_OPT.read().clone();
                pool.prewarm(&map).await;
            });
        }
    }
    {
        let guard = socks5_state_cell().lock();
        if let Some(ref state) = *guard {
            let user_domain = CFPROXY.read().user_domain.clone();
            socks5::trigger_warm_socks5_pool_prime(user_domain, state.cancel_tasks.clone());
        }
    }
}

/// Predictive screen wakeup hook.
/// Clears transient cooldowns caused by phone sleep, triggers MTProto prewarm and wakes timers.
#[no_mangle]
pub extern "C" fn OnScreenWakeup() {
    crate::linfo!("OnScreenWakeup: triggering predictive wake and preserving endpoint rate-limit quarantine");
    cfproxy::clear_all_recovery_cooldowns();
    WarmupWsPool();
}

#[no_mangle]
pub extern "C" fn SetMtprotoStandbyPerActiveSlot(size: c_int) -> c_int {
    let requested = size.clamp(config::MTPROTO_MIN_STANDBY, config::MTPROTO_MAX_STANDBY);
    MTPROTO_STANDBY_PER_ACTIVE_SLOT_REQUESTED.store(requested, Ordering::Relaxed);
    let effective = config::effective_mtproto_standby(
        requested,
        config::MOBILE_NETWORK.load(Ordering::Relaxed),
    ) as c_int;
    crate::linfo!(
        "SetMtprotoStandbyPerActiveSlot: requested={} effective={} is_mobile={}",
        requested,
        effective,
        config::MOBILE_NETWORK.load(Ordering::Relaxed)
    );
    effective
}

#[no_mangle]
pub extern "C" fn SetPoolSize(size: c_int) -> c_int {
    let standby = if size <= config::MTPROTO_MAX_STANDBY {
        size
    } else {
        (size / 4).clamp(config::MTPROTO_MIN_STANDBY, config::MTPROTO_MAX_STANDBY)
    };
    let effective = SetMtprotoStandbyPerActiveSlot(standby);
    crate::linfo!(
        "SetPoolSize: requested={} mapped_standby={} effective={}",
        size,
        standby,
        effective
    );
    effective
}

#[no_mangle]
pub extern "C" fn set_pool_size(size: c_int) -> c_int {
    SetPoolSize(size)
}

#[no_mangle]
pub extern "C" fn SetIpv6OnlyNetwork(is_ipv6_only: c_int) {
    let flag = is_ipv6_only != 0;
    crate::recovery::set_ipv6_only_network(flag);
    crate::linfo!("SetIpv6OnlyNetwork: ipv6_only={}", flag);
}

#[no_mangle]
pub extern "C" fn GetTransportPoolStatusJson() -> *mut c_char {
    let mtp_active = mtproto_state_cell().lock().is_some();
    let s5_active = socks5_state_cell().lock().is_some();
    let transport = if mtp_active && s5_active {
        "both"
    } else if mtp_active {
        "mtproto"
    } else if s5_active {
        "socks5"
    } else {
        "idle"
    };
    let status = config::get_transport_pool_status(transport);
    let json = serde_json::to_string(&status).unwrap_or_else(|_| "{}".to_string());
    CString::new(json).unwrap_or_default().into_raw()
}

#[no_mangle]
pub extern "C" fn GetWarmPoolStatusJson() -> *mut c_char {
    let status = socks5::get_socks5_warm_pool_status();
    let json = serde_json::to_string(&status).unwrap_or_else(|_| "{}".to_string());
    CString::new(json).unwrap_or_default().into_raw()
}

#[no_mangle]
pub extern "C" fn SetSocketBufferSizes(recv_size: c_int, send_size: c_int) -> c_int {
    let max_ceiling = config::max_socket_buffer();
    let requested_recv = recv_size.max(0);
    let requested_send = send_size.max(0);
    let recv = if requested_recv == 0 {
        0
    } else {
        requested_recv.clamp(config::MIN_SOCKET_BUFFER, max_ceiling)
    };
    let send = if requested_send == 0 {
        0
    } else {
        requested_send.clamp(config::MIN_SOCKET_BUFFER, max_ceiling)
    };
    REQUESTED_RECV_BUF.store(requested_recv, Ordering::Relaxed);
    REQUESTED_SEND_BUF.store(requested_send, Ordering::Relaxed);
    RECV_BUF.store(recv, Ordering::Relaxed);
    SEND_BUF.store(send, Ordering::Relaxed);
    crate::linfo!(
        "SetSocketBufferSizes: requested_recv={} requested_send={} effective_recv={} effective_send={} autotune_baseline={}",
        requested_recv,
        requested_send,
        recv,
        send,
        recv == 0 && send == 0
    );
    0
}

#[no_mangle]
pub extern "C" fn SetMaxSocketBufferCeiling(ceiling: c_int) -> c_int {
    config::set_max_socket_buffer_ceiling(ceiling);
    0
}

#[no_mangle]
pub extern "C" fn GetSocketBufferStatusJson() -> *mut c_char {
    let status = config::get_socket_buffer_status();
    let json = serde_json::to_string(&status).unwrap_or_else(|_| "{}".to_string());
    CString::new(json).unwrap_or_default().into_raw()
}

#[no_mangle]
pub unsafe extern "C" fn GetLastOsSocketBufferSizes(
    recv_out: *mut c_int,
    send_out: *mut c_int,
) -> c_int {
    if recv_out.is_null() || send_out.is_null() {
        return -1;
    }
    unsafe {
        *recv_out = config::LAST_OS_RECV_BUF.load(Ordering::Relaxed);
        *send_out = config::LAST_OS_SEND_BUF.load(Ordering::Relaxed);
    }
    0
}

#[no_mangle]
pub extern "C" fn SetNetworkProfile(is_mobile: c_int) {
    network_profile::update_legacy_transport(is_mobile != 0);
}

#[no_mangle]
pub extern "C" fn SetDialThrottlingEnabled(enabled: c_int) {
    config::set_dial_throttling_enabled(enabled != 0);
}

#[no_mangle]
pub extern "C" fn IsDialThrottlingEnabled() -> c_int {
    if config::is_dial_throttling_enabled() { 1 } else { 0 }
}

#[no_mangle]
pub unsafe extern "C" fn SetNetworkProfileJson(c_json: *const c_char) -> c_int {
    let json = cstr_to_string(c_json);
    match network_profile::set_profile_json(&json) {
        Ok(_) => 0,
        Err(error) => {
            crate::lerror!("SetNetworkProfileJson error: {}", error);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn GetNetworkProfileJson() -> *mut c_char {
    CString::new(network_profile::get_profile_json())
        .unwrap_or_default()
        .into_raw()
}

#[no_mangle]
pub extern "C" fn SetTcpNoDelay(enabled: c_int) {
    let nodelay = enabled != 0;
    TCP_NODELAY.store(nodelay, Ordering::Relaxed);
    crate::linfo!("SetTcpNoDelay: set to {}", nodelay);
}

#[no_mangle]
pub unsafe extern "C" fn SetCfProxyCacheDir(c_cache_dir: *const c_char) {
    let dir = cstr_to_string(c_cache_dir);
    generation_guard::change_config(|| {
        CFPROXY.write().cache_dir = dir.trim().to_string();
    });
}

#[no_mangle]
pub unsafe extern "C" fn SetCfProxyConfig(enabled: c_int, c_user_domain: *const c_char) {
    let user_domain = cstr_to_string(c_user_domain);
    let _is_cdn = user_domain.trim().is_empty() && (enabled != 0);
    generation_guard::change_config(|| {
        CFPROXY_ENABLED.store(enabled != 0, Ordering::Relaxed);
        *LAST_SOCKS5_WORKER.write() = String::new();
        let mut cfg = CFPROXY.write();
        cfg.user_domain = user_domain.clone();
        cfg.active = user_domain;
    });

    let pool_opt = mtproto_state_cell().lock().as_ref().map(|s| s.pool.clone());
    if let Some(pool) = pool_opt {
        let dc_opt = DC_OPT.read().clone();
        let rt = runtime();
        rt.spawn(async move {
            pool.reset().await;
            if enabled != 0 {
                pool.prewarm(&dc_opt).await;
            }
        });
    }
}

#[no_mangle]
pub extern "C" fn SetTlsEnabled(enabled: c_int) {
    let flag = enabled != 0;
    generation_guard::change_config(|| {
        ws::set_tls_enabled(flag);
        tls_observability::TLS_TRACKER.write().reset();
        cfproxy::clear_winner_cache();
        cfproxy::clear_all_recovery_cooldowns();
        recovery::reset();
    });
    reset_network_sockets_for_reason(if flag { "tls_enabled" } else { "tls_disabled" });
}

#[no_mangle]
pub extern "C" fn IsTlsEnabled() -> c_int {
    if ws::is_tls_enabled() {
        1
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn SetTlsRecordPaddingEnabled(enabled: c_int) {
    let flag = enabled != 0;
    ws::set_tls_record_padding_enabled(flag);
    generation_guard::change_config(|| {});
}

#[no_mangle]
pub extern "C" fn IsTlsRecordPaddingEnabled() -> c_int {
    if ws::is_tls_record_padding_enabled() {
        1
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn SetTlsClientHelloSplitEnabled(enabled: c_int) {
    let flag = enabled != 0;
    ws::set_tls_client_hello_split_enabled(flag);
    generation_guard::change_config(|| {});
}

#[no_mangle]
pub extern "C" fn IsTlsClientHelloSplitEnabled() -> c_int {
    if ws::is_tls_client_hello_split_enabled() {
        1
    } else {
        0
    }
}

/// Promotes a preflight-verified Flowseal Anycast domain for one Telegram DC.
/// The balancer normalizes `kws{dc}.domain:443` into its base domain; it keeps
/// the remaining CDN candidates available for the normal Happy Eyeballs race.
#[no_mangle]
pub unsafe extern "C" fn PromoteCfproxyDomainForDc(
    dc_id: c_int,
    is_media: c_int,
    c_domain: *const c_char,
) -> c_int {
    if !(1..=5).contains(&dc_id) {
        return 0;
    }
    let domain = cstr_to_string(c_domain);
    if domain.trim().is_empty() {
        return 0;
    }

    generation_guard::change_config(|| {
        crate::balancer::BALANCER
            .write()
            .update_domain_for_dc(dc_id, is_media != 0, &domain);
    });
    crate::linfo!("MTProto Anycast candidate promoted for DC{}: {}", dc_id, domain);
    1
}

#[no_mangle]
pub unsafe extern "C" fn SetWorkerProtocol(_c_domain: *const c_char, _proto_ver: c_int) {
    // Protocol is unified to modern WSS relay (/apiws); proto_ver subnegotiation is deprecated.
    // Retained for backward FFI binary compatibility with JNA bindings.
}

#[no_mangle]
pub unsafe extern "C" fn SetSecret(c_secret: *const c_char) {
    let s = cstr_to_string(c_secret);
    if s.len() < 32 {
        return;
    }
    let clean_sec = if s.starts_with("ee") && s.len() >= 34 {
        &s[2..34]
    } else if s.starts_with("dd") && s.len() == 34 {
        &s[2..34]
    } else if s.len() == 32 {
        &s[..32]
    } else {
        return;
    };
    if hex::decode(clean_sec).is_err() {
        return;
    }
    *PROXY_SECRET.write() = clean_sec.to_string();
}

#[no_mangle]
pub unsafe extern "C" fn SetSocks5Auth(c_username: *const c_char, c_password: *const c_char) {
    let username = cstr_to_string(c_username);
    let password = cstr_to_string(c_password);
    let mut auth = SOCKS5_AUTH.write();
    auth.username = username;
    auth.password = password;
}

#[no_mangle]
pub extern "C" fn SetSocks5Optimistic(enabled: c_int) {
    let flag = enabled != 0;
    SOCKS5_OPTIMISTIC_RESPONSE.store(flag, Ordering::Relaxed);
    crate::linfo!("SetSocks5Optimistic: enabled={}", flag);
}

#[no_mangle]
pub extern "C" fn IsSocks5Optimistic() -> c_int {
    if SOCKS5_OPTIMISTIC_RESPONSE.load(Ordering::Relaxed) {
        1
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn SetSocks5UplinkMode(mode: c_int) {
    generation_guard::change_config(|| {
        socks5::clear_socks5_warm_pool();
        config::set_socks5_uplink_mode(mode);
        crate::linfo!("SetSocks5UplinkMode: mode={}", mode);
    });
}

#[no_mangle]
pub extern "C" fn GetSocks5UplinkMode() -> c_int {
    config::get_socks5_uplink_mode()
}

#[no_mangle]
pub extern "C" fn GetStats() -> *mut c_char {
    let s = STATS.summary();
    CString::new(s).unwrap_or_default().into_raw()
}

#[no_mangle]
pub extern "C" fn GetStatsJson() -> *mut c_char {
    let json = build_stats_json();
    CString::new(json)
        .unwrap_or_else(|_| CString::new("{}").unwrap())
        .into_raw()
}

#[no_mangle]
pub extern "C" fn GetSecretWithPrefix() -> *mut c_char {
    let sec = PROXY_SECRET.read().clone();
    CString::new(format!("dd{}", sec))
        .unwrap_or_default()
        .into_raw()
}

#[no_mangle]
pub extern "C" fn GetUsefulRxSliJson() -> *mut c_char {
    CString::new("{}").unwrap_or_default().into_raw()
}

#[no_mangle]
pub extern "C" fn SetNetworkGeneration(gen: i64) {
    if gen > 0 {
        network_profile::update_generation(gen as u64);
    }
}

#[no_mangle]
pub extern "C" fn GetDomainBalancerStatusJson() -> *mut c_char {
    let s = balancer::BALANCER.read().get_status_json();
    CString::new(s).unwrap_or_default().into_raw()
}

#[no_mangle]
pub extern "C" fn GetDialBudgetStatsJson() -> *mut c_char {
    let rt = runtime();
    let stats = rt.block_on(async { budget::DIAL_BUDGET.stats().await });
    let s = serde_json::to_string(&stats).unwrap_or_else(|_| "{}".to_string());
    CString::new(s).unwrap_or_default().into_raw()
}

#[no_mangle]
pub extern "C" fn GetNodeIndependenceStatusJson() -> *mut c_char {
    let s = node_independence::NODE_INDEPENDENCE_TRACKER.read().get_all_telemetry_json();
    CString::new(s).unwrap_or_default().into_raw()
}

#[no_mangle]
pub extern "C" fn GetTlsObservabilityStatusJson() -> *mut c_char {
    let s = tls_observability::TLS_TRACKER.read().get_status_json();
    CString::new(s).unwrap_or_default().into_raw()
}

#[no_mangle]
pub unsafe extern "C" fn FreeString(p: *mut c_char) {
    if !p.is_null() {
        let _ = CString::from_raw(p);
    }
}

// ===========================================================================
// JNI Bridge for MirrlyEngineController (Android or explicit `jni` feature)
// ===========================================================================

#[cfg(any(target_os = "android", feature = "jni"))]
mod jni_bridge {
    use super::*;

    type JNIEnv = *mut *const *const std::ffi::c_void;
    type JString = *mut std::ffi::c_void;
    type JClass = *mut std::ffi::c_void;
    type JBoolean = u8;
    type JInt = i32;
    type JLong = i64;

    unsafe fn jni_get_string(env: JNIEnv, jstr: JString) -> String {
        if env.is_null() || jstr.is_null() {
            return String::new();
        }
        let table = *env;
        let get_utf_chars_fn: extern "system" fn(
            JNIEnv,
            JString,
            *mut JBoolean,
        ) -> *const std::os::raw::c_char = std::mem::transmute(*table.add(169));
        let release_utf_chars_fn: extern "system" fn(
            JNIEnv,
            JString,
            *const std::os::raw::c_char,
        ) = std::mem::transmute(*table.add(170));

        let chars = get_utf_chars_fn(env, jstr, std::ptr::null_mut());
        if chars.is_null() {
            return String::new();
        }
        let res = std::ffi::CStr::from_ptr(chars)
            .to_string_lossy()
            .into_owned();
        release_utf_chars_fn(env, jstr, chars);
        res
    }

    unsafe fn jni_new_string(env: JNIEnv, s: &str) -> JString {
        if env.is_null() {
            return std::ptr::null_mut();
        }
        let c_str = match std::ffi::CString::new(s) {
            Ok(cs) => cs,
            Err(_) => return std::ptr::null_mut(),
        };
        let table = *env;
        let new_utf_fn: extern "system" fn(JNIEnv, *const std::os::raw::c_char) -> JString =
            std::mem::transmute(*table.add(167));
        new_utf_fn(env, c_str.as_ptr())
    }

    #[no_mangle]
    pub unsafe extern "system" fn Java_org_telegram_messenger_mirrly_MirrlyEngineController_nativeStartSocks5(
        env: JNIEnv,
        _class: JClass,
        j_ip: JString,
        port: JInt,
    ) -> JString {
        let ip = jni_get_string(env, j_ip);
        let c_ip = match std::ffi::CString::new(ip) {
            Ok(s) => s,
            Err(_) => return jni_new_string(env, "Invalid IP"),
        };
        let code = StartSocks5Proxy(c_ip.as_ptr(), port, 1);
        if code == 0 {
            std::ptr::null_mut()
        } else if code == -1 {
            jni_new_string(env, "PORT_BUSY")
        } else {
            jni_new_string(env, "BIND_FAILED")
        }
    }

    #[no_mangle]
    pub unsafe extern "system" fn Java_org_telegram_messenger_mirrly_MirrlyEngineController_nativeStartMtproto(
        env: JNIEnv,
        _class: JClass,
        j_ip: JString,
        port: JInt,
        j_secret: JString,
        j_upstream: JString,
    ) -> JString {
        let ip = jni_get_string(env, j_ip);
        let secret = jni_get_string(env, j_secret);
        let upstream = jni_get_string(env, j_upstream);

        let c_ip = match std::ffi::CString::new(ip) {
            Ok(s) => s,
            Err(_) => return jni_new_string(env, "Invalid IP"),
        };
        let c_sec = match std::ffi::CString::new(secret) {
            Ok(s) => s,
            Err(_) => return jni_new_string(env, "Invalid Secret"),
        };
        let c_up = match std::ffi::CString::new(upstream) {
            Ok(s) => s,
            Err(_) => return jni_new_string(env, "Invalid Upstream"),
        };

        let code = StartProxy(c_ip.as_ptr(), port, c_up.as_ptr(), c_sec.as_ptr(), 1);
        if code == 0 {
            std::ptr::null_mut()
        } else if code == -1 {
            jni_new_string(env, "PORT_BUSY")
        } else {
            jni_new_string(env, "BIND_FAILED")
        }
    }

    #[no_mangle]
    pub unsafe extern "system" fn Java_org_telegram_messenger_mirrly_MirrlyEngineController_nativeStopProxy(
        _env: JNIEnv,
        _class: JClass,
    ) {
        StopProxy();
    }

    #[no_mangle]
    pub unsafe extern "system" fn Java_org_telegram_messenger_mirrly_MirrlyEngineController_nativeSoftReconnect(
        _env: JNIEnv,
        _class: JClass,
    ) {
        ResetNetworkSockets();
        SuspendNetworkSockets();
        WarmupWsPool();
    }

    #[no_mangle]
    pub unsafe extern "system" fn Java_org_telegram_messenger_mirrly_MirrlyEngineController_nativeGetStatsJson(
        env: JNIEnv,
        _class: JClass,
    ) -> JString {
        let json = build_stats_json();
        jni_new_string(env, &json)
    }

    #[no_mangle]
    pub unsafe extern "system" fn Java_org_telegram_messenger_mirrly_MirrlyEngineController_nativeGenerateSecret(
        env: JNIEnv,
        _class: JClass,
        j_domain: JString,
    ) -> JString {
        let domain = jni_get_string(env, j_domain);
        let target_domain = if domain.trim().is_empty() {
            "www.google.com"
        } else {
            domain.trim()
        };
        use rand::RngCore;
        let mut random_bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut random_bytes);
        let random_hex = hex::encode(random_bytes);
        let domain_hex = hex::encode(target_domain.as_bytes());
        let secret = format!("ee{}{}", random_hex, domain_hex);
        jni_new_string(env, &secret)
    }

    #[no_mangle]
    pub unsafe extern "system" fn Java_org_telegram_messenger_mirrly_MirrlyEngineController_nativeSetSecret(
        env: JNIEnv,
        _class: JClass,
        j_secret: JString,
    ) -> JInt {
        let secret = jni_get_string(env, j_secret);
        let c_sec = match std::ffi::CString::new(secret) {
            Ok(s) => s,
            Err(_) => return -1,
        };
        SetSecret(c_sec.as_ptr());
        0
    }

    #[no_mangle]
    pub unsafe extern "system" fn Java_org_telegram_messenger_mirrly_MirrlyEngineController_nativeOnNetworkStateChanged(
        _env: JNIEnv,
        _class: JClass,
        connected: JBoolean,
        _is_wifi: JBoolean,
        _is_cellular: JBoolean,
    ) -> JLong {
        if connected != 0 {
            WarmupWsPool();
        } else {
            SuspendNetworkSockets();
        }
        0
    }

    #[no_mangle]
    pub unsafe extern "system" fn Java_org_telegram_messenger_mirrly_MirrlyEngineController_nativeOnScreenWake(
        _env: JNIEnv,
        _class: JClass,
    ) {
        OnScreenWakeup();
    }

    #[no_mangle]
    pub unsafe extern "system" fn Java_org_telegram_messenger_mirrly_MirrlyEngineController_nativeSetCfProxyConfig(
        env: JNIEnv,
        _class: JClass,
        j_domain: JString,
        _j_secret: JString,
    ) {
        let domain = jni_get_string(env, j_domain);
        let c_dom = match std::ffi::CString::new(domain) {
            Ok(s) => s,
            Err(_) => return,
        };
        SetCfProxyConfig(1, c_dom.as_ptr());
    }

    #[no_mangle]
    pub unsafe extern "system" fn Java_org_telegram_messenger_mirrly_MirrlyEngineController_nativeSetTlsClientHelloSplit(
        _env: JNIEnv,
        _class: JClass,
        enabled: JBoolean,
    ) {
        SetTlsClientHelloSplitEnabled(if enabled != 0 { 1 } else { 0 });
    }

    #[no_mangle]
    pub unsafe extern "system" fn Java_org_telegram_messenger_mirrly_MirrlyEngineController_nativeSetTlsEnabled(
        _env: JNIEnv,
        _class: JClass,
        enabled: JBoolean,
    ) {
        SetTlsEnabled(if enabled != 0 { 1 } else { 0 });
    }

    #[no_mangle]
    pub unsafe extern "system" fn Java_org_telegram_messenger_mirrly_MirrlyEngineController_nativeIsTlsEnabled(
        _env: JNIEnv,
        _class: JClass,
    ) -> JBoolean {
        if IsTlsEnabled() != 0 {
            1
        } else {
            0
        }
    }

    #[no_mangle]
    pub unsafe extern "system" fn Java_org_telegram_messenger_mirrly_MirrlyEngineController_nativeSetTlsFingerprintProfile(
        _env: JNIEnv,
        _class: JClass,
        _j_profile: JString,
    ) -> JInt {
        0
    }

    #[no_mangle]
    pub unsafe extern "system" fn Java_org_telegram_messenger_mirrly_MirrlyEngineController_nativeResetNetworkSockets(
        _env: JNIEnv,
        _class: JClass,
    ) {
        ResetNetworkSockets();
    }
}

#[cfg(test)]
mod stats_json_tests {
    use super::*;

    #[test]
    fn build_stats_json_serializes_valid_telemetry_schema() {
        STATS.connections_total.store(7, Ordering::Relaxed);
        STATS.connections_active.store(3, Ordering::Relaxed);
        STATS.bytes_up.store(1024, Ordering::Relaxed);
        STATS.bytes_down.store(4096, Ordering::Relaxed);
        STATS.dec_connections_active();
        assert_eq!(STATS.connections_active.load(Ordering::Relaxed), 2);

        let raw = build_stats_json();
        let parsed: serde_json::Value = serde_json::from_str(&raw).expect("valid JSON");
        assert_eq!(parsed["connections_total"], 7);
        assert_eq!(parsed["connections_active"], 2);
        assert_eq!(parsed["bytes_up"], 1024);
        assert_eq!(parsed["bytes_down"], 4096);
        assert!(parsed["uptime_secs"].is_u64());
        assert!(parsed["tls_enabled"].is_boolean());
        assert!(parsed["mtproto_running"].is_boolean());
        assert!(parsed["socks5_running"].is_boolean());

        STATS.connections_active.store(0, Ordering::Relaxed);
        STATS.dec_connections_active();
        assert_eq!(STATS.connections_active.load(Ordering::Relaxed), 0);
    }
}
