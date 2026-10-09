/**
 * cert_store_flash.h
 *
 * Flash-backed keystore for DigiCert TrustCore CLM on STM32U585.
 * Reserves the last 24 KB of Bank 2 flash (pages 125-127) so the
 * linker must be told to stop code at 0x081F9FFF or earlier.
 *
 * Flash layout (STM32U585AI, 2 MB dual-bank, 8 KB pages):
 *   0x081FA000 – 0x081FBFFF  Bank 2 Page 125  Private key (DER)
 *   0x081FC000 – 0x081FDFFF  Bank 2 Page 126  Device certificate (DER)
 *   0x081FE000 – 0x081FFFFF  Bank 2 Page 127  Metadata (expiry, state)
 */

#ifndef CERT_STORE_FLASH_H
#define CERT_STORE_FLASH_H

#include "stm32u5xx_hal.h"
#include <stdint.h>

/* ── Flash region addresses ─────────────────────────────────────────────── */
#define CERT_STORE_KEY_ADDR       ((uint32_t)0x081FA000U)
#define CERT_STORE_CERT_ADDR      ((uint32_t)0x081FC000U)
#define CERT_STORE_META_ADDR      ((uint32_t)0x081FE000U)
#define CERT_STORE_PAGE_SIZE      (8192U)

/* Maximum stored sizes (must fit within one 8 KB page each) */
#define CERT_STORE_MAX_KEY_LEN    (512U)    /* PKCS#8 ECC P-256 DER ~121 B */
#define CERT_STORE_MAX_CERT_LEN   (2048U)   /* X.509 DER typically < 1.5 KB */

/* Sentinel written at offset 0 to detect valid data */
#define CERT_STORE_MAGIC          (0xDC190001U)

/* ── On-flash record layouts ─────────────────────────────────────────────── */

/* Header preceding the raw DER blob in the key / cert pages.
 * STM32U585 HAL_FLASH_Program(FLASH_TYPEPROGRAM_QUADWORD) requires the
 * destination address to be 16-byte aligned.  Base addresses (0x081FA000 etc.)
 * are page-aligned (16-byte aligned), so the struct must also be exactly
 * 16 bytes so the DER data that follows starts at base + 16 (still aligned). */
typedef struct __attribute__((packed)) {
    uint32_t magic;        /* CERT_STORE_MAGIC */
    uint32_t len;          /* DER length in bytes */
    uint8_t  reserved[8]; /* padding to 16 bytes (one quadword) */
} CertStoreHdr_t;

/* Metadata page */
typedef struct __attribute__((packed)) {
    uint32_t magic;           /* CERT_STORE_MAGIC                      */
    uint32_t not_before;      /* Unix timestamp (seconds since epoch)   */
    uint32_t not_after;       /* Unix timestamp of certificate expiry   */
    uint32_t enrollment_ts;   /* Unix timestamp of last enrollment      */
    uint32_t renewal_count;   /* How many times the cert has been renewed */
    uint8_t  state;           /* CLM provisioning state at time of save */
    uint8_t  key_type;        /* 0 = EC P-256, 1 = RSA 2048            */
    uint8_t  reserved[6];
} CertStoreMeta_t;

/* ── Public API ──────────────────────────────────────────────────────────── */
HAL_StatusTypeDef CERT_STORE_Init(void);
uint8_t           CERT_STORE_IsProvisioned(void);

HAL_StatusTypeDef CERT_STORE_WriteKey(const uint8_t *key_der, uint32_t len);
HAL_StatusTypeDef CERT_STORE_ReadKey(uint8_t *buf, uint32_t buf_len, uint32_t *out_len);

HAL_StatusTypeDef CERT_STORE_WriteCert(const uint8_t *cert_der, uint32_t len);
HAL_StatusTypeDef CERT_STORE_ReadCert(uint8_t *buf, uint32_t buf_len, uint32_t *out_len);

HAL_StatusTypeDef CERT_STORE_WriteMeta(const CertStoreMeta_t *meta);
HAL_StatusTypeDef CERT_STORE_ReadMeta(CertStoreMeta_t *meta);

/* Erase all three pages — use before re-provisioning */
HAL_StatusTypeDef CERT_STORE_Erase(void);

#endif /* CERT_STORE_FLASH_H */
