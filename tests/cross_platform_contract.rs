use mirrlyengine::config::{
    DEFAULT_MAX_SOCKET_BUFFER, HIGH_THROUGHPUT_MAX_SOCKET_BUFFER, RECV_BUF, REQUESTED_RECV_BUF,
    REQUESTED_SEND_BUF, SEND_BUF,
};
use mirrlyengine::network_profile::NetworkProfile;
use mirrlyengine::ws::set_sock_opts;
use mirrlyengine::{
    FreeString, GetMtprotoListenPort, GetSocks5ListenPort, GetStatsJson, SetLogCallback,
    SetMaxSocketBufferCeiling, SetRuntimeWorkerThreads, SetSocketBufferSizes, StartProxy,
    StartSocks5Proxy, StopMtprotoProxy, StopProxy, StopSocks5Proxy,
};
use parking_lot::Mutex;
use std::ffi::{CStr, CString};
use std::net::TcpListener;
use std::os::raw::{c_char, c_int, c_void};
use std::sync::atomic::Ordering;
use tokio::net::TcpStream;

static FFI_TEST_LOCK: Mutex<()> = Mutex::new(());

struct ProxyCleanupGuard;
impl Drop for ProxyCleanupGuard {
    fn drop(&mut self) {
        StopProxy();
    }
}

#[test]
fn ephemeral_ports_and_restart_and_conflict_work_cross_platform() {
    let _lock = FFI_TEST_LOCK.lock();
    let _cleanup = ProxyCleanupGuard;

    let host = CString::new("127.0.0.1").unwrap();
    let empty = CString::new("").unwrap();
    let secret = CString::new("00000000000000000000000000000000").unwrap();

    // 1. Start SOCKS5 with ephemeral port 0 and verify port discovery.
    let rc_s5 = unsafe { StartSocks5Proxy(host.as_ptr(), 0, 0) };
    assert_eq!(rc_s5, 0);
    let s5_port = GetSocks5ListenPort();
    assert!(s5_port > 0, "expected ephemeral SOCKS5 port > 0, got {s5_port}");

    // 2. Start MTProto with ephemeral port 0 and verify port discovery.
    let rc_mtp = unsafe { StartProxy(host.as_ptr(), 0, empty.as_ptr(), secret.as_ptr(), 0) };
    assert_eq!(rc_mtp, 0);
    let mtp_port = GetMtprotoListenPort();
    assert!(mtp_port > 0, "expected ephemeral MTProto port > 0, got {mtp_port}");

    // 3. Stats JSON must report both active ports.
    let raw_stats = GetStatsJson();
    assert!(!raw_stats.is_null());
    let stats_str = unsafe { CStr::from_ptr(raw_stats) }.to_string_lossy().into_owned();
    unsafe { FreeString(raw_stats) };
    let parsed: serde_json::Value = serde_json::from_str(&stats_str).expect("valid stats JSON");
    assert_eq!(parsed["socks5_running"], true);
    assert_eq!(parsed["mtproto_running"], true);
    assert_eq!(parsed["socks5_port"], s5_port);
    assert_eq!(parsed["mtproto_port"], mtp_port);

    // 4. Stop and immediately restart on the exact same ports without AddrInUse race.
    assert_eq!(StopSocks5Proxy(), 0);
    assert_eq!(GetSocks5ListenPort(), 0);
    assert_eq!(unsafe { StartSocks5Proxy(host.as_ptr(), s5_port, 0) }, 0);
    assert_eq!(GetSocks5ListenPort(), s5_port);

    assert_eq!(StopMtprotoProxy(), 0);
    assert_eq!(GetMtprotoListenPort(), 0);
    assert_eq!(
        unsafe { StartProxy(host.as_ptr(), mtp_port, empty.as_ptr(), secret.as_ptr(), 0) },
        0
    );
    assert_eq!(GetMtprotoListenPort(), mtp_port);

    // 5. Attempting to bind to an already occupied local port must return -1 (PORT_BUSY).
    assert_eq!(StopSocks5Proxy(), 0);
    let occupant = TcpListener::bind("127.0.0.1:0").expect("bind occupant");
    let occupied_port = occupant.local_addr().unwrap().port() as c_int;
    let busy_rc = unsafe { StartSocks5Proxy(host.as_ptr(), occupied_port, 0) };
    assert_eq!(busy_rc, -1, "occupied port must fail with -1 (PORT_BUSY)");
    assert_eq!(GetSocks5ListenPort(), 0);
    drop(occupant);

    // 6. Invalid ports must fail cleanly with -2.
    assert_eq!(unsafe { StartSocks5Proxy(host.as_ptr(), -1, 0) }, -2);
    assert_eq!(unsafe { StartSocks5Proxy(host.as_ptr(), 70_000, 0) }, -2);
}

#[test]
fn log_callback_receives_engine_logs_and_unregisters_cleanly() {
    let _lock = FFI_TEST_LOCK.lock();

    unsafe extern "C" fn capture_log(
        level: c_int,
        message: *const c_char,
        user_data: *mut c_void,
    ) {
        if message.is_null() || user_data.is_null() {
            return;
        }
        let sink = &*(user_data as *const Mutex<Vec<(c_int, String)>>);
        let text = CStr::from_ptr(message).to_string_lossy().into_owned();
        sink.lock().push((level, text));
    }

    let logs: Mutex<Vec<(c_int, String)>> = Mutex::new(Vec::new());
    let ptr = (&logs as *const Mutex<Vec<(c_int, String)>>) as *mut c_void;

    unsafe { SetLogCallback(Some(capture_log), ptr) };
    mirrlyengine::linfo!("cross-platform-test-info");
    mirrlyengine::lwarn!("cross-platform-test-warn");
    unsafe { SetLogCallback(None, std::ptr::null_mut()) };
    mirrlyengine::linfo!("after-unregister-should-not-capture");

    let captured = logs.lock();
    assert!(
        captured
            .iter()
            .any(|(lvl, msg)| *lvl == 0 && msg.contains("cross-platform-test-info")),
        "expected info log in callback, got {:?}",
        *captured
    );
    assert!(
        captured
            .iter()
            .any(|(lvl, msg)| *lvl == 1 && msg.contains("cross-platform-test-warn")),
        "expected warn log in callback, got {:?}",
        *captured
    );
    assert!(
        !captured
            .iter()
            .any(|(_, msg)| msg.contains("after-unregister-should-not-capture")),
        "callback fired after unregistering"
    );
}

#[test]
fn default_network_profile_is_ready_without_android_observer() {
    let profile = NetworkProfile::default();
    assert!(profile.validated);
    assert!(!profile.suspended);
    assert_eq!(profile.power_mode, "ACTIVE");
    #[cfg(not(target_os = "android"))]
    assert_eq!(profile.ip_family_preference, "DUAL_STACK");
    #[cfg(target_os = "android")]
    assert_eq!(profile.ip_family_preference, "IPV4_ONLY");
}

#[test]
fn runtime_worker_threads_respects_bounds() {
    let _lock = FFI_TEST_LOCK.lock();
    // Ensure runtime exists or check return semantics:
    // before runtime init returns clamped value (1..=16), after runtime init returns -1.
    let res = SetRuntimeWorkerThreads(2);
    assert!(res == 2 || res == -1);
    let reset_res = SetRuntimeWorkerThreads(0);
    assert!(reset_res > 0 || reset_res == -1);
}

#[tokio::test(flavor = "current_thread")]
async fn socket_buffer_ceiling_applies_beyond_default_2mb_on_real_socket() {
    let _lock = FFI_TEST_LOCK.lock();
    struct RestoreBuffers {
        req_r: i32,
        req_s: i32,
        r: i32,
        s: i32,
    }
    impl Drop for RestoreBuffers {
        fn drop(&mut self) {
            SetMaxSocketBufferCeiling(DEFAULT_MAX_SOCKET_BUFFER);
            REQUESTED_RECV_BUF.store(self.req_r, Ordering::Relaxed);
            REQUESTED_SEND_BUF.store(self.req_s, Ordering::Relaxed);
            RECV_BUF.store(self.r, Ordering::Relaxed);
            SEND_BUF.store(self.s, Ordering::Relaxed);
        }
    }
    let _restore = RestoreBuffers {
        req_r: REQUESTED_RECV_BUF.load(Ordering::Relaxed),
        req_s: REQUESTED_SEND_BUF.load(Ordering::Relaxed),
        r: RECV_BUF.load(Ordering::Relaxed),
        s: SEND_BUF.load(Ordering::Relaxed),
    };

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Baseline 64 KiB socket buffers
    SetMaxSocketBufferCeiling(DEFAULT_MAX_SOCKET_BUFFER);
    SetSocketBufferSizes(64 * 1024, 64 * 1024);
    let small_stream = TcpStream::connect(addr).await.unwrap();
    let (_p1, _) = listener.accept().await.unwrap();
    set_sock_opts(&small_stream);
    let small_sock = socket2::SockRef::from(&small_stream);
    let small_recv = small_sock.recv_buffer_size().unwrap() as i32;

    // Raised 8 MiB ceiling with 4 MiB requested buffers
    SetMaxSocketBufferCeiling(HIGH_THROUGHPUT_MAX_SOCKET_BUFFER);
    SetSocketBufferSizes(4 * 1024 * 1024, 4 * 1024 * 1024);
    let status = mirrlyengine::config::get_socket_buffer_status();
    assert_eq!(status.clamped_recv_bytes, 4 * 1024 * 1024);
    assert_eq!(status.clamped_send_bytes, 4 * 1024 * 1024);

    let stream = TcpStream::connect(addr).await.unwrap();
    let (_p2, _) = listener.accept().await.unwrap();
    set_sock_opts(&stream);

    let sock_ref = socket2::SockRef::from(&stream);
    let os_recv = sock_ref.recv_buffer_size().unwrap() as i32;
    let os_send = sock_ref.send_buffer_size().unwrap() as i32;
    assert!(
        os_recv > small_recv && os_send > 0,
        "expected OS buffers to grow past 64 KiB baseline: small_recv={small_recv}, os_recv={os_recv}, os_send={os_send}"
    );
    #[cfg(windows)]
    assert!(
        os_recv > DEFAULT_MAX_SOCKET_BUFFER && os_send > DEFAULT_MAX_SOCKET_BUFFER,
        "expected Windows OS buffers to exceed 2 MiB default ceiling: recv={os_recv}, send={os_send}"
    );
}
