use mirrlyengine::config::{
    DEFAULT_MAX_SOCKET_BUFFER, HIGH_THROUGHPUT_MAX_SOCKET_BUFFER, RECV_BUF, REQUESTED_RECV_BUF,
    REQUESTED_SEND_BUF, SEND_BUF, TCP_NODELAY,
};
use mirrlyengine::network_profile::NetworkProfile;
use mirrlyengine::ws::{connect_outbound_tcp, set_client_sock_opts, set_sock_opts};
use mirrlyengine::{
    FreeString, GetLastStartError, GetMtprotoListenPort, GetSecretWithPrefix, GetSocks5ListenPort,
    GetStatsJson, GetUsefulRxSliJson, IsSocks5Optimistic, IsTlsEnabled, IsTlsRecordPaddingEnabled,
    PingHost, PingWorker, SetLogCallback, SetMaxSocketBufferCeiling, SetNetworkProfileJson,
    SetRuntimeWorkerThreads, SetSecret, SetSocketBufferSizes, SetSocks5Optimistic, SetTcpNoDelay,
    SetTlsEnabled, SetTlsRecordPaddingEnabled, StartProxy, StartSocks5Proxy, StopMtprotoProxy,
    StopProxy, StopSocks5Proxy,
};
use parking_lot::Mutex;
use std::ffi::{CStr, CString};
use std::io::{Read, Write};
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

    // 5. Attempting to bind to an already occupied local port must return -3 (START_ERR_ADDR_IN_USE).
    assert_eq!(StopSocks5Proxy(), 0);
    let occupant = TcpListener::bind("127.0.0.1:0").expect("bind occupant");
    let occupied_port = occupant.local_addr().unwrap().port() as c_int;
    let busy_rc = unsafe { StartSocks5Proxy(host.as_ptr(), occupied_port, 0) };
    assert_eq!(
        busy_rc, -3,
        "occupied port must fail with -3 (START_ERR_ADDR_IN_USE)"
    );
    assert_eq!(GetSocks5ListenPort(), 0);

    assert_eq!(StopMtprotoProxy(), 0);
    let busy_mtp_rc =
        unsafe { StartProxy(host.as_ptr(), occupied_port, empty.as_ptr(), secret.as_ptr(), 0) };
    assert_eq!(
        busy_mtp_rc, -3,
        "occupied MTProto port must fail with -3 (START_ERR_ADDR_IN_USE)"
    );
    assert_eq!(GetMtprotoListenPort(), 0);
    drop(occupant);

    // 6. Invalid ports or invalid bind hosts must fail cleanly with -5 (START_ERR_OTHER).
    assert_eq!(unsafe { StartSocks5Proxy(host.as_ptr(), -1, 0) }, -5);
    assert_eq!(unsafe { StartSocks5Proxy(host.as_ptr(), 70_000, 0) }, -5);
    assert_eq!(
        unsafe { StartProxy(host.as_ptr(), -1, empty.as_ptr(), secret.as_ptr(), 0) },
        -5
    );
    assert_eq!(
        unsafe { StartProxy(host.as_ptr(), 70_000, empty.as_ptr(), secret.as_ptr(), 0) },
        -5
    );
    let bad_host = CString::new("256.256.256.256").unwrap();
    assert_eq!(unsafe { StartSocks5Proxy(bad_host.as_ptr(), 0, 0) }, -5);
    assert_eq!(
        unsafe { StartProxy(bad_host.as_ptr(), 0, empty.as_ptr(), secret.as_ptr(), 0) },
        -5
    );
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

#[test]
fn useful_sli_json_and_last_start_error_and_probers_work_cross_platform() {
    let _lock = FFI_TEST_LOCK.lock();
    let _cleanup = ProxyCleanupGuard;

    struct RestoreTls(c_int);
    impl Drop for RestoreTls {
        fn drop(&mut self) {
            SetTlsEnabled(self.0);
        }
    }
    let _tls_guard = RestoreTls(IsTlsEnabled());

    // 1. GetUsefulRxSliJson exposes all expected cross-platform SLI keys.
    let raw_sli = GetUsefulRxSliJson();
    assert!(!raw_sli.is_null());
    let sli_str = unsafe { CStr::from_ptr(raw_sli) }.to_string_lossy().into_owned();
    unsafe { FreeString(raw_sli) };
    let sli: serde_json::Value = serde_json::from_str(&sli_str).expect("valid SLI JSON");
    for key in [
        "transport",
        "tls_enabled",
        "active_conns",
        "connections_total",
        "warm_ready",
        "warm_target",
        "balancer_healthy_domains",
        "balancer_total_domains",
        "rx_bytes",
        "tx_bytes",
    ] {
        assert!(sli.get(key).is_some(), "missing SLI key '{key}'");
    }

    // 2. GetLastStartError reports OS bind details on port conflict and clears on success.
    let occupant = TcpListener::bind("127.0.0.1:0").expect("bind occupant");
    let occupied_port = occupant.local_addr().unwrap().port() as c_int;
    let host = CString::new("127.0.0.1").unwrap();
    let busy_rc = unsafe { StartSocks5Proxy(host.as_ptr(), occupied_port, 0) };
    assert_eq!(busy_rc, -3);

    let err_ptr = GetLastStartError();
    assert!(!err_ptr.is_null());
    let err_msg = unsafe { CStr::from_ptr(err_ptr) }.to_string_lossy().into_owned();
    unsafe { FreeString(err_ptr) };
    assert!(
        err_msg.contains(&occupied_port.to_string()),
        "expected occupied port in GetLastStartError, got '{err_msg}'"
    );
    drop(occupant);

    assert_eq!(unsafe { StartSocks5Proxy(host.as_ptr(), 0, 0) }, 0);
    let cleared_ptr = GetLastStartError();
    let cleared_msg = unsafe { CStr::from_ptr(cleared_ptr) }
        .to_string_lossy()
        .into_owned();
    unsafe { FreeString(cleared_ptr) };
    assert!(
        cleared_msg.is_empty(),
        "expected cleared start error on success, got '{cleared_msg}'"
    );

    // 3. PingHost succeeds against a local listening socket.
    let ping_listener = TcpListener::bind("127.0.0.1:0").expect("bind ping target");
    let ping_port = ping_listener.local_addr().unwrap().port() as c_int;
    let ping_json_ptr = unsafe { PingHost(host.as_ptr(), ping_port, 1000) };
    let ping_json = unsafe { CStr::from_ptr(ping_json_ptr) }
        .to_string_lossy()
        .into_owned();
    unsafe { FreeString(ping_json_ptr) };
    let ping_val: serde_json::Value = serde_json::from_str(&ping_json).expect("valid PingHost JSON");
    assert_eq!(ping_val["success"], true);
    assert!(ping_val["rtt_ms"].as_i64().unwrap_or(-1) >= 1);
    drop(ping_listener);

    // 4. PingWorker accurately parses HTTP 200 and HTTP 429 in plain WS (no-TLS) mode.
    SetTlsEnabled(0);
    for (status_line, expected_status) in [
        ("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", "ONLINE"),
        ("HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\n\r\n", "RATE_LIMITED_429"),
    ] {
        let srv = TcpListener::bind("127.0.0.1:0").expect("bind worker mock");
        let port = srv.local_addr().unwrap().port();
        let response = status_line.to_string();
        let handle = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = srv.accept() {
                let mut req_buf = [0u8; 512];
                let _ = stream.read(&mut req_buf);
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });

        let target = CString::new(format!("127.0.0.1:{port}")).unwrap();
        let worker_ptr = unsafe { PingWorker(target.as_ptr(), 1500) };
        let worker_json = unsafe { CStr::from_ptr(worker_ptr) }
            .to_string_lossy()
            .into_owned();
        unsafe { FreeString(worker_ptr) };
        let _ = handle.join();

        let worker_val: serde_json::Value =
            serde_json::from_str(&worker_json).expect("valid PingWorker JSON");
        assert_eq!(worker_val["status"], expected_status, "got {worker_json}");
        assert!(worker_val["rtt_ms"].as_i64().unwrap_or(-1) >= 1);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn tcp_nodelay_defaults_to_false_and_toggles_across_client_sock_and_outbound_sockets() {
    let _lock = FFI_TEST_LOCK.lock();
    struct RestoreNoDelay(bool);
    impl Drop for RestoreNoDelay {
        fn drop(&mut self) {
            SetTcpNoDelay(if self.0 { 1 } else { 0 });
        }
    }
    let _restore = RestoreNoDelay(TCP_NODELAY.load(Ordering::Relaxed));

    SetTcpNoDelay(0);
    assert!(!TCP_NODELAY.load(Ordering::Relaxed));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let client1 = TcpStream::connect(addr).await.unwrap();
    let (accepted1, _) = listener.accept().await.unwrap();
    set_client_sock_opts(&accepted1);
    set_sock_opts(&client1);
    assert_eq!(accepted1.nodelay().unwrap(), false);
    assert_eq!(client1.nodelay().unwrap(), false);

    let outbound1 = connect_outbound_tcp(&addr, std::time::Duration::from_secs(1))
        .await
        .unwrap();
    let (_acc_out1, _) = listener.accept().await.unwrap();
    assert_eq!(outbound1.nodelay().unwrap(), false);

    SetTcpNoDelay(1);
    assert!(TCP_NODELAY.load(Ordering::Relaxed));

    let client2 = TcpStream::connect(addr).await.unwrap();
    let (accepted2, _) = listener.accept().await.unwrap();
    set_client_sock_opts(&accepted2);
    set_sock_opts(&client2);
    assert_eq!(accepted2.nodelay().unwrap(), true);
    assert_eq!(client2.nodelay().unwrap(), true);

    let outbound2 = connect_outbound_tcp(&addr, std::time::Duration::from_secs(1))
        .await
        .unwrap();
    let (_acc_out2, _) = listener.accept().await.unwrap();
    assert_eq!(outbound2.nodelay().unwrap(), true);
}

#[test]
fn get_secret_with_prefix_respects_tls_and_faketls_domain_and_flags() {
    let _lock = FFI_TEST_LOCK.lock();
    struct RestoreState {
        tls: c_int,
        padding: c_int,
        optimistic: c_int,
    }
    impl Drop for RestoreState {
        fn drop(&mut self) {
            SetTlsEnabled(self.tls);
            SetTlsRecordPaddingEnabled(self.padding);
            SetSocks5Optimistic(self.optimistic);
        }
    }
    let _guard = RestoreState {
        tls: IsTlsEnabled(),
        padding: IsTlsRecordPaddingEnabled(),
        optimistic: IsSocks5Optimistic(),
    };

    let read_secret = || -> String {
        let ptr = GetSecretWithPrefix();
        assert!(!ptr.is_null());
        let s = unsafe { CStr::from_ptr(ptr) }.to_string_lossy().into_owned();
        unsafe { FreeString(ptr) };
        s
    };

    let raw32 = "0123456789abcdef0123456789abcdef";
    let c_raw = CString::new(raw32).unwrap();
    unsafe { SetSecret(c_raw.as_ptr()) };

    // When TLS is disabled -> dd{32_hex}
    SetTlsEnabled(0);
    assert_eq!(read_secret(), format!("dd{raw32}"));

    // When TLS is enabled -> ee{32_hex}{default_google_hex}
    SetTlsEnabled(1);
    assert_eq!(
        read_secret(),
        format!("ee{raw32}7777772e676f6f676c652e636f6d")
    );

    // Passing ee<32><custom_domain_hex> to SetSecret updates stored FakeTLS domain
    let custom_domain_hex = hex::encode("cloudflare.com");
    let c_ee_custom = CString::new(format!("ee{raw32}{custom_domain_hex}")).unwrap();
    unsafe { SetSecret(c_ee_custom.as_ptr()) };
    SetTlsEnabled(1);
    assert_eq!(read_secret(), format!("ee{raw32}{custom_domain_hex}"));
    SetTlsEnabled(0);
    assert_eq!(read_secret(), format!("dd{raw32}"));

    // Restore default domain via bare secret
    unsafe { SetSecret(c_raw.as_ptr()) };

    // Verify SetTlsRecordPaddingEnabled / IsTlsRecordPaddingEnabled
    SetTlsRecordPaddingEnabled(0);
    assert_eq!(IsTlsRecordPaddingEnabled(), 0);
    SetTlsRecordPaddingEnabled(1);
    assert_eq!(IsTlsRecordPaddingEnabled(), 1);

    // Verify SetSocks5Optimistic / IsSocks5Optimistic
    SetSocks5Optimistic(0);
    assert_eq!(IsSocks5Optimistic(), 0);
    SetSocks5Optimistic(1);
    assert_eq!(IsSocks5Optimistic(), 1);

    // Verify SetNetworkProfileJson accepts websocket_keep_alive_seconds = 120
    let profile_json = CString::new(
        r#"{"transport":"WIFI","validated":true,"metered":false,"CaptivePortal":false,"suspended":false,"mtu":1500,"power_mode":"ACTIVE","websocket_keep_alive_seconds":120}"#,
    )
    .unwrap();
    assert_eq!(unsafe { SetNetworkProfileJson(profile_json.as_ptr()) }, 0);
    assert_eq!(
        mirrlyengine::network_profile::get_profile().websocket_keep_alive_seconds,
        120
    );
}
