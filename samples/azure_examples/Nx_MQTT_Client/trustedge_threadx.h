/**
 * trustedge_threadx.h
 *
 * ThreadX integration for DigiCert TrustEdge native flow on STM32U585AI.
 *
 * ── Flow ────────────────────────────────────────────────────────────────────
 *
 *   1. PROV_UART_Listen()         — factory floor: burn bootstrap.zip over UART
 *   2. DIGICERT_addEntropy32Bits()— seed RNG from STM32 HAL_RNG
 *   3. TRUSTEDGE_init()           — initialise TrustCore library
 *   4. TRUSTEDGE_registerDNSLookupCallback() — wire NetX Duo DNS
 *   5. TRUSTEDGE_setMountPoint("/") — bind RAM VFS to filesystem abstraction
 *   6. Write /est/trustedge.json  — TrustEdge config (paths, agent settings)
 *   7. Write bootstrap.zip        — copy from flash into VFS for extraction
 *   8. TRUSTEDGE_extractBootStrap() — unzip → bootstrap_config.json in conf_dir
 *   9. TRUSTEDGE_launch(LAUNCH_AND_EXIT) — connect DTM, enroll device cert
 *  10. TRUSTEDGE_deinit()
 *
 * ── Integration ─────────────────────────────────────────────────────────────
 *
 *   In app_netxduo.c:
 *
 *     TX_THREAD AppTrustEdgeThread;
 *     #include "trustedge_threadx.h"
 *
 *     // in MX_NetXDuo_Init():
 *     tx_thread_create(&AppTrustEdgeThread, "TrustEdge",
 *                      trustedge_threadx_entry, 0,
 *                      stack, TRUSTEDGE_THREAD_STACK_SIZE,
 *                      TRUSTEDGE_THREAD_PRIORITY, TRUSTEDGE_THREAD_PRIORITY,
 *                      TX_NO_TIME_SLICE, TX_DONT_START);
 *
 *     // in App_SNTP_Thread_Entry(), after time sync:
 *     tx_thread_resume(&AppTrustEdgeThread);
 *
 * ── VFS paths (trustedge.json) ───────────────────────────────────────────────
 *
 *   /est/trustedge.json         TrustEdge global config (written at startup)
 *   /est/conf/                  conf_dir: bootstrap_config.json lands here
 *   /est/keystore/              enrolled device key and certificate
 *   /tmp/                       temp extraction workspace (no real FS needed)
 */

#ifndef TRUSTEDGE_THREADX_H
#define TRUSTEDGE_THREADX_H

#include "tx_api.h"

/* ── VFS path configuration ─────────────────────────────────────────────── */

/* Paths that go into /est/trustedge.json — must be consistent with each other */
#define TE_ROOT_DIR           "/est"
#define TE_CONF_DIR           "/est/conf"
#define TE_KEYSTORE_DIR       "/est/keystore"
#define TE_SERVICE_DIR        "/est/service"
#define TE_WORKSPACE_DIR      "/tmp"

/* Path written by TRUSTEDGE_extractBootStrap() — must match conf_dir */
#define TE_BOOTSTRAP_CONFIG   TE_CONF_DIR "/bootstrap_config.json"

/* VFS name used for the in-memory copy of the flash bootstrap.zip */
#define TE_BOOTSTRAP_ZIP_VFS  "bootstrap.zip"

/* ── Agent tuning ───────────────────────────────────────────────────────── */

#define TE_KEEPALIVE_S         25
#define TE_SLEEP_INTERVAL_S    30
#define TE_RECV_POLL_MS        2000
#define TE_CONN_UPTIME_S       60
#define TE_ACTION_TIMEOUT_S    300
#define TE_MAX_RETRY           3
#define TE_RENEWAL_HOURS       720
#define TE_CERT_RENEWAL_HOURS  360
#define TE_REFRESH_HOURS       24
#define TE_PROTO_BUF_SIZE      16384

/* ── Public API ──────────────────────────────────────────────────────────── */

void trustedge_threadx_entry(ULONG thread_input);

#endif /* TRUSTEDGE_THREADX_H */
