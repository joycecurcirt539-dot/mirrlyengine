#ifndef MIRRLYENGINE_H
#define MIRRLYENGINE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Log severity levels passed to mirrly_log_callback_t. */
enum {
    MIRRLY_LOG_INFO = 0,
    MIRRLY_LOG_WARN = 1,
    MIRRLY_LOG_ERROR = 2,
    MIRRLY_LOG_DEBUG = 3
};

/** SOCKS5 uplink modes for SetSocks5UplinkMode / GetSocks5UplinkMode. */
enum {
    MIRRLY_SOCKS5_UPLINK_WORKER = 0,
    MIRRLY_SOCKS5_UPLINK_FLOWSEAL = 1
};

/** Return codes for StartProxy and StartSocks5Proxy. */
enum {
    MIRRLY_START_OK = 0,
    MIRRLY_START_ERR_GENERAL = -1,
    MIRRLY_START_ERR_ADDR_IN_USE = -3,
    MIRRLY_START_ERR_PERMISSION_DENIED = -4,
    MIRRLY_START_ERR_OTHER = -5
};

/**
 * Host log callback signature.
 * The `message` pointer is only valid for the duration of the callback invocation.
 */
typedef void (*mirrly_log_callback_t)(int level, const char* message, void* user_data);

/**
 * Optional host socket-protection callback (e.g. Android VpnService.protect(fd)).
 * Return non-zero on success, 0 on failure.
 */
typedef int (*mirrly_protect_socket_callback_t)(int fd);
void SetProtectSocketCallback(mirrly_protect_socket_callback_t callback);

/* -------------------------------------------------------------------------- */
/* Lifecycle & Ports                                                          */
/* -------------------------------------------------------------------------- */

/**
 * Starts the local MTProto proxy listener on `host:port`.
 * Pass `port = 0` to let the OS assign an ephemeral free port, then query
 * `GetMtprotoListenPort()`.
 * Returns `0` (`MIRRLY_START_OK`) on success, `-3` (`MIRRLY_START_ERR_ADDR_IN_USE`) if the
 * port is already in use, `-4` (`MIRRLY_START_ERR_PERMISSION_DENIED`) on permission denied,
 * `-5` (`MIRRLY_START_ERR_OTHER`) on invalid arguments or other bind errors, or `-1`
 * (`MIRRLY_START_ERR_GENERAL`) on general start failure.
 */
int StartProxy(const char* host, int port, const char* dc_ips, const char* secret, int verbose);

/**
 * Starts the local SOCKS5 proxy listener on `host:port`.
 * Pass `port = 0` to let the OS assign an ephemeral free port, then query
 * `GetSocks5ListenPort()`.
 * Returns `0` (`MIRRLY_START_OK`) on success, `-3` (`MIRRLY_START_ERR_ADDR_IN_USE`) if the
 * port is already in use, `-4` (`MIRRLY_START_ERR_PERMISSION_DENIED`) on permission denied,
 * `-5` (`MIRRLY_START_ERR_OTHER`) on invalid arguments or other bind errors, or `-1`
 * (`MIRRLY_START_ERR_GENERAL`) on general start failure.
 */
int StartSocks5Proxy(const char* host, int port, int verbose);

/** Returns the bound MTProto port when running, or 0 when stopped. */
int GetMtprotoListenPort(void);

/** Returns the bound SOCKS5 port when running, or 0 when stopped. */
int GetSocks5ListenPort(void);

/** Stops both MTProto and SOCKS5 proxies. Returns 0. */
int StopProxy(void);

/** Stops the MTProto proxy and waits briefly for listener release. Returns 0. */
int StopMtprotoProxy(void);

/** Stops the SOCKS5 proxy and waits briefly for listener release. Returns 0. */
int StopSocks5Proxy(void);

/**
 * Configures Tokio worker thread count (clamped 1..16; 0 resets to platform default).
 * Must be called before the first StartProxy/StartSocks5Proxy call.
 * Returns the effective thread count, or -1 if the runtime is already initialized.
 */
int SetRuntimeWorkerThreads(int threads);

/** Registers or clears (pass NULL) the host log callback. */
void SetLogCallback(mirrly_log_callback_t callback, void* user_data);

/* -------------------------------------------------------------------------- */
/* Network Recovery, Pool & Power Hooks                                       */
/* -------------------------------------------------------------------------- */

void ResetNetworkSockets(void);
void EmergencyKillAllSockets(void);
void SuspendNetworkSockets(void);
void WarmupWsPool(void);
void OnScreenWakeup(void);

int SetMtprotoStandbyPerActiveSlot(int size);
int SetPoolSize(int size);

void SetIpv6OnlyNetwork(int is_ipv6_only);
void SetNetworkProfile(int is_mobile);
int SetNetworkProfileJson(const char* json);
/** Caller must free returned string via FreeString(). */
char* GetNetworkProfileJson(void);
void SetNetworkGeneration(int64_t generation);

void SetDialThrottlingEnabled(int enabled);
int IsDialThrottlingEnabled(void);

/* -------------------------------------------------------------------------- */
/* Socket Buffers & TCP Options                                               */
/* -------------------------------------------------------------------------- */

int SetSocketBufferSizes(int recv_size, int send_size);
int SetMaxSocketBufferCeiling(int ceiling);
/** Caller must free returned string via FreeString(). */
char* GetSocketBufferStatusJson(void);
int GetLastOsSocketBufferSizes(int* recv_out, int* send_out);
void SetTcpNoDelay(int enabled);

/* -------------------------------------------------------------------------- */
/* Cloudflare / TLS / Secret / SOCKS5 Configuration                           */
/* -------------------------------------------------------------------------- */

void SetCfProxyCacheDir(const char* cache_dir);
void SetCfProxyConfig(int enabled, const char* user_domain);
int PromoteCfproxyDomainForDc(int dc_id, int is_media, const char* domain);

void SetFlowsealPerDcEnabled(int enabled);
int IsFlowsealPerDcEnabled(void);
/**
 * Pins or clears (empty/NULL domain) a Flowseal Anycast base domain for a Telegram DC.
 * `dc_id`: 1..5. `is_media`: 0 = chat, 1 = media, -1 = all traffic for that DC.
 * Returns 1 on success, 0 on invalid arguments.
 */
int SetFlowsealDcDomain(int dc_id, int is_media, const char* domain);
/**
 * Batch-configures Flowseal per-DC routing from JSON.
 * Returns 1 on success, 0 on parse/validation failure.
 */
int SetFlowsealDcDomainsJson(const char* json);
void ClearFlowsealDcDomains(void);
/** Caller must free returned string via FreeString(). */
char* GetFlowsealDcConfigJson(void);

void SetTlsEnabled(int enabled);
int IsTlsEnabled(void);
void SetTlsRecordPaddingEnabled(int enabled);
int IsTlsRecordPaddingEnabled(void);
void SetTlsClientHelloSplitEnabled(int enabled);
int IsTlsClientHelloSplitEnabled(void);

void SetSecret(const char* secret);
/** Caller must free returned string via FreeString(). */
char* GetSecretWithPrefix(void);

void SetSocks5Auth(const char* username, const char* password);
void SetSocks5Optimistic(int enabled);
int IsSocks5Optimistic(void);
void SetSocks5UplinkMode(int mode);
int GetSocks5UplinkMode(void);

/* -------------------------------------------------------------------------- */
/* Telemetry & Memory Management                                              */
/* -------------------------------------------------------------------------- */

/** Caller must free every string returned by Get* functions via FreeString(). */
char* GetStats(void);
char* GetStatsJson(void);
char* GetUsefulRxSliJson(void);
char* GetLastStartError(void);
char* GetTransportPoolStatusJson(void);
char* GetWarmPoolStatusJson(void);
char* GetDomainBalancerStatusJson(void);
char* GetDialBudgetStatsJson(void);
char* GetNodeIndependenceStatusJson(void);
char* GetTlsObservabilityStatusJson(void);

/* -------------------------------------------------------------------------- */
/* Network Diagnostics & Transport Probing (Free returned strings via FreeString) */
/* -------------------------------------------------------------------------- */

char* PingHost(const char* host, int port, int timeout_ms);
char* PingWorker(const char* domain, int timeout_ms);
char* ProbeTransportHealth(int mode, const char* domain, int timeout_ms);

/** Frees any string allocated and returned by mirrlyengine Get, Ping, or Probe functions. */
void FreeString(char* ptr);

#ifdef __cplusplus
}
#endif

#endif /* MIRRLYENGINE_H */
