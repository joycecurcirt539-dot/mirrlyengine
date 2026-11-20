use std::cell::Cell;
use std::ffi::CString;
use std::net::SocketAddr;
use std::os::raw::{c_char, c_int, c_void};
use parking_lot::RwLock;

/// Log severity levels passed to [`SetLogCallback`](crate::SetLogCallback).
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Info = 0,
    Warn = 1,
    Error = 2,
    Debug = 3,
}

pub type LogCallbackFn =
    unsafe extern "C" fn(level: c_int, message: *const c_char, user_data: *mut c_void);

static LOG_CALLBACK: RwLock<Option<(LogCallbackFn, usize)>> = RwLock::new(None);

thread_local! {
    static IN_LOG_CALLBACK: Cell<bool> = const { Cell::new(false) };
}

struct CallbackReentrancyGuard;
impl Drop for CallbackReentrancyGuard {
    fn drop(&mut self) {
        IN_LOG_CALLBACK.with(|flag| flag.set(false));
    }
}

/// Registers or clears the C-FFI log sink callback.
///
/// Passing `None` restores default stderr/OS logging without forwarding to a host callback.
pub fn set_log_callback(callback: Option<LogCallbackFn>, user_data: *mut c_void) {
    let entry = callback.map(|cb| (cb, user_data as usize));
    *LOG_CALLBACK.write() = entry;
}

#[cfg(target_os = "android")]
fn android_log_line(level: LogLevel, line: &str) {
    unsafe extern "C" {
        fn __android_log_print(prio: i32, tag: *const i8, fmt: *const i8, ...) -> i32;
    }
    let prio = match level {
        LogLevel::Debug => 3, // ANDROID_LOG_DEBUG
        LogLevel::Info => 4,  // ANDROID_LOG_INFO
        LogLevel::Warn => 5,  // ANDROID_LOG_WARN
        LogLevel::Error => 6, // ANDROID_LOG_ERROR
    };
    let clean = line.replace('\0', " ");
    if let (Ok(tag), Ok(fmt), Ok(msg)) = (
        CString::new("MirrlyEngine"),
        CString::new("%s"),
        CString::new(clean),
    ) {
        unsafe {
            __android_log_print(
                prio,
                tag.as_ptr() as *const i8,
                fmt.as_ptr() as *const i8,
                msg.as_ptr() as *const i8,
            );
        }
    }
}

#[cfg(not(target_os = "android"))]
#[inline]
fn android_log_line(_level: LogLevel, _line: &str) {}

/// Emits a formatted engine log line to `stderr`, Android logcat (on Android),
/// and any registered C-FFI host callback without holding locks across the call.
pub fn emit_log(level: LogLevel, line: &str) {
    eprintln!("{}", line);
    android_log_line(level, line);

    let registered = *LOG_CALLBACK.read();
    if let Some((cb, user_data_addr)) = registered {
        let already_inside = IN_LOG_CALLBACK.with(|flag| {
            if flag.get() {
                true
            } else {
                flag.set(true);
                false
            }
        });
        if already_inside {
            return;
        }
        let _guard = CallbackReentrancyGuard;
        let sanitized = line.replace('\0', " ");
        if let Ok(c_line) = CString::new(sanitized) {
            unsafe {
                cb(level as c_int, c_line.as_ptr(), user_data_addr as *mut c_void);
            }
        }
    }
}

/// Applies platform-specific socket protections (such as `SO_NOSIGPIPE` on Darwin).
///
/// Embedded `cdylib`/`staticlib` builds on macOS and iOS do not inherit Rust's
/// binary `SIGPIPE` ignore handler, so every TCP socket must opt out of `SIGPIPE`.
#[inline]
pub(crate) fn configure_socket_platform(socket: &socket2::Socket) {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        let _ = socket.set_nosigpipe(true);
    }
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    {
        let _ = socket;
    }
}

/// Clamps TCP MSS to 1240 bytes only on Unix/Android targets when a constrained
/// cellular/metered network profile is active. Desktop broadband links are never clamped.
#[inline]
pub(crate) fn apply_mobile_mss_clamp(socket: &socket2::Socket) {
    #[cfg(all(unix, not(target_os = "redox")))]
    {
        use std::sync::atomic::Ordering;
        if crate::config::MOBILE_NETWORK.load(Ordering::Relaxed) {
            let _ = socket.set_mss(1240);
        }
    }
    #[cfg(not(all(unix, not(target_os = "redox"))))]
    {
        let _ = socket;
    }
}

/// Binds a local proxy TCP listener with platform-correct reuse semantics:
/// - Unix (`Linux`, `macOS`, `iOS`, `Android`): enables `SO_REUSEADDR` for fast restarts
///   across `TIME_WAIT`, without `SO_REUSEPORT` so duplicate listeners fail with `AddrInUse`.
/// - Windows: keeps `SO_REUSEADDR` disabled so Winsock returns `WSAEADDRINUSE` instead of
///   silently binding over another active listener.
pub(crate) fn bind_local_tcp(addr: &str) -> std::io::Result<(tokio::net::TcpListener, u16)> {
    let sock_addr: SocketAddr = addr
        .parse()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let domain = if sock_addr.is_ipv6() {
        socket2::Domain::IPV6
    } else {
        socket2::Domain::IPV4
    };
    let socket =
        socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
    configure_socket_platform(&socket);

    #[cfg(unix)]
    {
        let _ = socket.set_reuse_address(true);
    }
    #[cfg(windows)]
    {
        let _ = socket.set_reuse_address(false);
    }

    socket.set_nonblocking(true)?;
    socket.bind(&sock_addr.into())?;
    socket.listen(1024)?;
    let std_listener: std::net::TcpListener = socket.into();
    let listener = tokio::net::TcpListener::from_std(std_listener)?;
    let bound_port = listener.local_addr()?.port();
    Ok((listener, bound_port))
}

/// Returns the default `NetworkProfile.transport` for the host OS.
pub(crate) fn default_transport() -> &'static str {
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    {
        "ETHERNET"
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        "OTHER"
    }
}

/// Returns the default `NetworkProfile.ip_family_preference` for the host OS.
///
/// Desktop and Apple targets default to `DUAL_STACK` (supporting IPv6-only/NAT64 networks
/// while still prioritizing IPv4 first via `interleave_dual_stack_ips`); Android defaults to
/// `IPV4_ONLY` unless configured via `SetNetworkProfileJson`.
pub(crate) fn default_ip_family_preference() -> &'static str {
    #[cfg(target_os = "android")]
    {
        "IPV4_ONLY"
    }
    #[cfg(not(target_os = "android"))]
    {
        "DUAL_STACK"
    }
}

/// Returns the default `(min_threads, max_threads)` bounds for the Tokio runtime.
///
/// iOS app/network extensions operate under tight memory budgets, so their default
/// thread cap is lower unless overridden with [`SetRuntimeWorkerThreads`](crate::SetRuntimeWorkerThreads).
pub(crate) fn default_runtime_thread_bounds() -> (usize, usize) {
    #[cfg(target_os = "ios")]
    {
        (2, 4)
    }
    #[cfg(not(target_os = "ios"))]
    {
        (4, 8)
    }
}
