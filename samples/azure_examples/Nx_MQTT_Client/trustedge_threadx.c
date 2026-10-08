/**
 * trustedge_threadx.c
 *
 * DigiCert TrustEdge native integration thread for STM32U585AI + ThreadX.
 *
 * Runs as a ThreadX thread (AppTrustEdgeThread) after SNTP time sync.
 * Implements the full 6-step TrustEdge provisioning flow against DigiCert
 * Device Trust Manager (DTM), using the bootstrap.zip burned to dedicated
 * flash at factory.
 *
 * See trustedge_threadx.h for configuration and integration instructions.
 */

#include "trustedge_threadx.h"
#include "app_netxduo.h"
#include "prov_uart.h"
#include "bootstrap_certs_flash.h"
#include "cert_store_flash.h"
#include "clm_vfs.h"

/* TrustCore / TrustEdge library headers */
#include "moptions.h"
#include "mtypes.h"
#include "merrors.h"
#include "mocana.h"
#include "utils.h"
#include "trustedge_main.h"

/* NetX Duo */
#include "nxd_dns.h"
#include "tx_api.h"

/* HAL */
#include "stm32u5xx_hal.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* Stringify helper — used in TRUSTEDGE_JSON_TEMPLATE */
#define _TOSTR_INNER(x)  #x
#define _TOSTR(x)        _TOSTR_INNER(x)

/* ── Externals provided by app_netxduo.c ────────────────────────────────── */

extern NX_IP           IpInstance;
extern NX_PACKET_POOL  AppPool;
extern NX_DNS          DnsClient;
extern UART_HandleTypeDef huart1;
extern RNG_HandleTypeDef  hrng;

/* Semaphore released once the device certificate is ready (unblocks MQTT) */
extern TX_SEMAPHORE CLMReadySemaphore;

/* ── trustedge.json template ─────────────────────────────────────────────── */
/*
 * Written to /est/trustedge.json in the RAM VFS before calling
 * TRUSTEDGE_launch().  Paths must be consistent with trustedge_threadx.h
 * TE_CONF_DIR, TE_KEYSTORE_DIR, TE_WORKSPACE_DIR, and TE_SERVICE_DIR.
 *
 * bin_dir / lib_dir are not used on embedded targets; set to null.
 * The "api" section is not needed for the embedded library mode.
 */
static const char TRUSTEDGE_JSON_TEMPLATE[] =
    "{\n"
    "  \"directory_paths\": {\n"
    "    \"bin_dir\": null,\n"
    "    \"lib_dir\": null,\n"
    "    \"root_dir\": \"" TE_ROOT_DIR "\",\n"
    "    \"conf_dir\": \"" TE_CONF_DIR "\",\n"
    "    \"keystore_dir\": \"" TE_KEYSTORE_DIR "\"\n"
    "  },\n"
    "  \"proxy\": {\n"
    "    \"url\": null\n"
    "  },\n"
    "  \"agent\": {\n"
    "    \"bootstrap\": \"" TE_BOOTSTRAP_CONFIG "\",\n"
    "    \"workspace_dir\": \"" TE_WORKSPACE_DIR "\",\n"
    "    \"connection_uptime_interval\": " _TOSTR(TE_CONN_UPTIME_S) ",\n"
    "    \"keepalive_interval\": " _TOSTR(TE_KEEPALIVE_S) ",\n"
    "    \"recv_polling_interval\": " _TOSTR(TE_RECV_POLL_MS) ",\n"
    "    \"sleep_interval\": " _TOSTR(TE_SLEEP_INTERVAL_S) ",\n"
    "    \"action_handler_timeout\": " _TOSTR(TE_ACTION_TIMEOUT_S) ",\n"
    "    \"enforce_token\": false,\n"
    "    \"max_retry_count\": " _TOSTR(TE_MAX_RETRY) ",\n"
    "    \"log_payload\": false,\n"
    "    \"protocol_buffer_size\": " _TOSTR(TE_PROTO_BUF_SIZE) ",\n"
    "    \"attributes_refresh_hours\": " _TOSTR(TE_REFRESH_HOURS) ",\n"
    "    \"renewal_hours\": " _TOSTR(TE_RENEWAL_HOURS) ",\n"
    "    \"chunk_supported\": false,\n"
    "    \"chunk_size\": 512,\n"
    "    \"chunk_window_size\": 4\n"
    "  },\n"
    "  \"certificate\": {\n"
    "    \"service_dir\": \"" TE_SERVICE_DIR "\",\n"
    "    \"polling_interval\": 15,\n"
    "    \"renewal_hours\": " _TOSTR(TE_CERT_RENEWAL_HOURS) ",\n"
    "    \"mode\": \"agent\"\n"
    "  },\n"
    "  \"service\": {\n"
    "    \"mode\": \"agent\"\n"
    "  },\n"
    "  \"log\": {\n"
    "    \"loglevel\": \"INFO\"\n"
    "  }\n"
    "}\n";

/* ── DNS lookup callback (called by TrustEdge for hostname resolution) ───── */

static int trustedge_dns_lookup(char *hostname, char *ip_string)
{
    ULONG ip_addr = 0;
    UINT  ret;

    if (!hostname || !ip_string)
        return -1;

    ret = nx_dns_host_by_name_get(&DnsClient,
                                  (UCHAR *)hostname,
                                  &ip_addr,
                                  NX_IP_PERIODIC_RATE * 5);   /* 5-second timeout */
    if (ret != NX_SUCCESS)
        return -1;

    /* Format as dotted-quad ASCII */
    snprintf(ip_string, 16, "%lu.%lu.%lu.%lu",
             (ip_addr >> 24) & 0xFFU,
             (ip_addr >> 16) & 0xFFU,
             (ip_addr >>  8) & 0xFFU,
              ip_addr        & 0xFFU);
    return 0;
}

/* ── Helpers ─────────────────────────────────────────────────────────────── */

static void seed_entropy(void)
{
    uint32_t rnd;
    for (int i = 0; i < 32; i++) {
        if (HAL_RNG_GenerateRandomNumber(&hrng, &rnd) == HAL_OK)
            DIGICERT_addEntropy32Bits(rnd);
    }
}

static int wait_for_ip_ready(uint32_t timeout_ms)
{
    ULONG ip   = 0;
    ULONG mask = 0;
    uint32_t elapsed = 0;

    while (elapsed < timeout_ms) {
        if (nx_ip_address_get(&IpInstance, &ip, &mask) == NX_SUCCESS && ip != 0)
            return 0;
        tx_thread_sleep(TX_TIMER_TICKS_PER_SECOND);    /* 1-second poll */
        elapsed += 1000U;
    }
    return -1;
}

static int write_trustedge_json_to_vfs(void)
{
    MSTATUS st = UTILS_writeFile("/est/trustedge.json",
                                 (const ubyte *)TRUSTEDGE_JSON_TEMPLATE,
                                 (ubyte4)strlen(TRUSTEDGE_JSON_TEMPLATE));
    return (st == 0) ? 0 : -1;
}

static int write_bootstrap_zip_to_vfs(void)
{
    const uint8_t *zip_ptr = NULL;
    uint32_t       zip_len = 0;

    if (BOOTSTRAP_ZIP_GetPtr(&zip_ptr, &zip_len) != HAL_OK)
        return -1;

    MSTATUS st = UTILS_writeFile(TE_BOOTSTRAP_ZIP_VFS, (const ubyte *)zip_ptr, (ubyte4)zip_len);
    return (st == 0) ? 0 : -1;
}

/* ── Thread entry ────────────────────────────────────────────────────────── */

void trustedge_threadx_entry(ULONG thread_input)
{
    (void)thread_input;

    /* Reset the VFS before anything else so stale data from a warm reset
     * cannot affect this enrollment run.                                    */
    CLM_VFS_Reset();

    /* ── Step 1: Factory floor UART provisioning ──────────────────────────
     * If no bootstrap.zip is in flash, block for up to 5 minutes waiting
     * for the floor tool (burn_bootstrap_certs.py).  If already provisioned,
     * listen briefly for a re-provision attempt then continue.              */
    printf("[TE] Waiting for factory provisioning (UART)...\r\n");
    int prov_rc = PROV_UART_Listen(&huart1, PROV_UART_REPROBE_MS);
    if (prov_rc == PROV_ERR_TIMEOUT || prov_rc == PROV_ERR_CRC ||
        prov_rc == PROV_ERR_FLASH) {
        printf("[TE] ERROR: Provisioning failed (%d). Halting.\r\n", prov_rc);
        tx_thread_suspend(tx_thread_identify());
        return;
    }

    if (!BOOTSTRAP_ZIP_IsProvisioned()) {
        printf("[TE] ERROR: No bootstrap.zip in flash. Halting.\r\n");
        tx_thread_suspend(tx_thread_identify());
        return;
    }
    printf("[TE] Bootstrap zip present in flash.\r\n");

    /* ── Step 2: Wait for IP (DHCP) — belt-and-suspenders poll ───────────
     * App_Main_Thread_Entry already waited on Semaphore; by the time SNTP
     * thread resumes us, IP is assigned.  Poll just in case.               */
    if (wait_for_ip_ready(30000U) != 0) {
        printf("[TE] ERROR: No IP address after 30 s. Halting.\r\n");
        tx_thread_suspend(tx_thread_identify());
        return;
    }
    printf("[TE] Network ready.\r\n");

    /* ── Step 3: Seed RNG entropy ──────────────────────────────────────── */
    seed_entropy();
    printf("[TE] Entropy seeded.\r\n");

    /* ── Step 4: Initialise TrustEdge ─────────────────────────────────── */
    int te_rc = TRUSTEDGE_init();
    if (te_rc != 0) {
        printf("[TE] ERROR: TRUSTEDGE_init() failed (%d). Halting.\r\n", te_rc);
        tx_thread_suspend(tx_thread_identify());
        return;
    }
    printf("[TE] TRUSTEDGE_init OK.\r\n");

    /* ── Step 5: Register NetX Duo DNS resolver ────────────────────────── */
    TRUSTEDGE_registerDNSLookupCallback(trustedge_dns_lookup);

    /* ── Step 6: Set VFS mount point ──────────────────────────────────── */
    te_rc = TRUSTEDGE_setMountPoint((unsigned char *)"/");
    if (te_rc != 0) {
        printf("[TE] ERROR: TRUSTEDGE_setMountPoint() failed (%d). Halting.\r\n", te_rc);
        TRUSTEDGE_deinit();
        tx_thread_suspend(tx_thread_identify());
        return;
    }

    /* ── Step 7: Write trustedge.json to VFS ──────────────────────────── */
    if (write_trustedge_json_to_vfs() != 0) {
        printf("[TE] ERROR: Failed to write trustedge.json to VFS.\r\n");
        TRUSTEDGE_deinit();
        tx_thread_suspend(tx_thread_identify());
        return;
    }
    printf("[TE] /est/trustedge.json written to VFS.\r\n");

    /* ── Step 8: Copy bootstrap.zip from flash to VFS ─────────────────── */
    if (write_bootstrap_zip_to_vfs() != 0) {
        printf("[TE] ERROR: Failed to copy bootstrap.zip to VFS.\r\n");
        TRUSTEDGE_deinit();
        tx_thread_suspend(tx_thread_identify());
        return;
    }
    printf("[TE] bootstrap.zip copied to VFS (%s).\r\n", TE_BOOTSTRAP_ZIP_VFS);

    /* ── Step 9: Extract bootstrap bundle ─────────────────────────────── */
    te_rc = TRUSTEDGE_extractBootStrap(TE_BOOTSTRAP_ZIP_VFS);
    if (te_rc != 0) {
        printf("[TE] ERROR: TRUSTEDGE_extractBootStrap() failed (%d). Halting.\r\n", te_rc);
        TRUSTEDGE_deinit();
        tx_thread_suspend(tx_thread_identify());
        return;
    }
    printf("[TE] Bootstrap extracted. Status: %s\r\n",
           (TRUSTEDGE_getStatus() == PROVISIONED) ? "PROVISIONED" : "not PROVISIONED");

    if (TRUSTEDGE_getStatus() != PROVISIONED) {
        printf("[TE] ERROR: Expected PROVISIONED status after extraction.\r\n");
        TRUSTEDGE_deinit();
        tx_thread_suspend(tx_thread_identify());
        return;
    }

    /* ── Step 10: Launch TrustEdge — connect DTM and enroll device cert ── */
    printf("[TE] Launching TrustEdge agent (LAUNCH_AND_EXIT)...\r\n");
    te_rc = TRUSTEDGE_launch(LAUNCH_AND_EXIT);
    if (te_rc != 0) {
        printf("[TE] ERROR: TRUSTEDGE_launch() failed (%d).\r\n", te_rc);
    } else {
        printf("[TE] Device registration complete.\r\n");

        /* Persist enrolled key/cert from RAM VFS to cert_store_flash so they
         * survive power cycles.  CLM_VFS_GetKeyDer / GetCertDer scan the VFS
         * for the enrolled files written by TrustEdge.                       */
        const uint8_t *p_key  = NULL;
        uint32_t       key_len = 0;
        const uint8_t *p_cert  = NULL;
        uint32_t       cert_len = 0;

        if (CLM_VFS_GetKeyDer(&p_key, &key_len) == 0 &&
            CLM_VFS_GetCertDer(&p_cert, &cert_len) == 0) {
            /* Hand the enrolled PEM to the MQTT thread's mTLS buffers. */
            APP_SetDeviceCert(p_cert, cert_len, p_key, key_len);
            if (CERT_STORE_WriteKey(p_key,  key_len)  == HAL_OK &&
                CERT_STORE_WriteCert(p_cert, cert_len) == HAL_OK) {
                printf("[TE] Enrolled key and cert persisted to flash.\r\n");
            } else {
                printf("[TE] WARNING: Failed to persist enrolled cert to flash.\r\n");
            }
        } else {
            printf("[TE] WARNING: Enrolled key/cert not found in VFS.\r\n");
        }
    }

    /* ── Step 11: Clean up TrustEdge ─────────────────────────────────── */
    TRUSTEDGE_deinit();

    /* Signal MQTT thread that the device certificate is ready */
    tx_semaphore_put(&CLMReadySemaphore);

    printf("[TE] Done. MQTT thread unblocked.\r\n");
}
