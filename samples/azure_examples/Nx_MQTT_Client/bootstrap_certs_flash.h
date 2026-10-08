/**
 * bootstrap_certs_flash.h
 *
 * Flash-backed store for the DigiCert Device Trust Manager (DTM) bootstrap zip.
 *
 * ── What is stored ───────────────────────────────────────────────────────────
 *
 * TrustEdge's native flow expects a "bootstrap.zip" bundle as produced by DTM.
 * That zip is burned at factory via UART and read back at boot to seed the VFS
 * before calling TRUSTEDGE_extractBootStrap().  The raw zip bytes are stored
 * verbatim — no parsing, no cert directory — so TrustEdge can unzip them itself.
 *
 * ── Flash region ─────────────────────────────────────────────────────────────
 *
 * Bank 2 pages 123-124 (2 × 8 KB = 16 KB)
 *   0x081F6000 – 0x081F7FFF  page 123  header + start of zip data
 *   0x081F8000 – 0x081F9FFF  page 124  zip data continuation
 *
 * On-flash layout:
 *   Offset 0x00  BootstrapZipHdr_t  (16 bytes, one quadword)
 *   Offset 0x10  raw zip bytes      (up to BOOTSTRAP_ZIP_MAX_LEN)
 *
 * STM32U585 flash constraints:
 *   – 128-bit (16-byte) quadword programming unit, 16-byte aligned destination
 *   – 8 KB erase unit (one page)
 *   – BOOTSTRAP_ZIP_BASE_ADDR is page-aligned → 16-byte aligned ✓
 *
 * Sizing: DTM bootstrap zips are typically 6–8 KB; 16 KB pool (minus 16-byte
 * header = 16,368 bytes) provides comfortable headroom.
 */

#ifndef BOOTSTRAP_CERTS_FLASH_H
#define BOOTSTRAP_CERTS_FLASH_H

#include "stm32u5xx_hal.h"
#include <stdint.h>

/* ── Flash region constants ─────────────────────────────────────────────── */

#define BOOTSTRAP_ZIP_BASE_ADDR   (0x081F6000U)
#define BOOTSTRAP_ZIP_PAGE_SIZE   (8192U)
#define BOOTSTRAP_ZIP_TOTAL_SIZE  (16384U)          /* 2 pages × 8 KB       */
#define BOOTSTRAP_ZIP_MAGIC       (0xDC190003U)     /* distinct from enrolled-cert store */
#define BOOTSTRAP_ZIP_VERSION     (1U)

/* Header is exactly 16 bytes (one quadword) */
#define BOOTSTRAP_ZIP_HDR_SIZE    (16U)
#define BOOTSTRAP_ZIP_MAX_LEN     (BOOTSTRAP_ZIP_TOTAL_SIZE - BOOTSTRAP_ZIP_HDR_SIZE)  /* 16368 bytes */

#define BOOTSTRAP_ZIP_DATA_ADDR   (BOOTSTRAP_ZIP_BASE_ADDR + BOOTSTRAP_ZIP_HDR_SIZE)

/* ── On-flash header ────────────────────────────────────────────────────── */

typedef struct __attribute__((packed)) {
    uint32_t magic;    /* BOOTSTRAP_ZIP_MAGIC                     */
    uint32_t version;  /* BOOTSTRAP_ZIP_VERSION                   */
    uint32_t zip_len;  /* byte length of the zip data that follows */
    uint32_t reserved; /* 0xFF padding to complete 16-byte quadword */
} BootstrapZipHdr_t;

/* ── Public API ──────────────────────────────────────────────────────────── */

HAL_StatusTypeDef BOOTSTRAP_ZIP_Init(void);

/* Returns 1 if a valid DTM bootstrap zip is stored, 0 otherwise */
uint8_t           BOOTSTRAP_ZIP_IsProvisioned(void);

/*
 * Write the raw DTM bootstrap zip to flash.
 * Erases both pages, writes header + zip_data.
 */
HAL_StatusTypeDef BOOTSTRAP_ZIP_Write(const uint8_t *zip_data, uint32_t zip_len);

/*
 * Read the raw zip bytes into caller-supplied buffer.
 * out_len set to actual zip length on success.
 */
HAL_StatusTypeDef BOOTSTRAP_ZIP_Read(uint8_t *buf, uint32_t buf_len, uint32_t *out_len);

/*
 * Return a direct flash pointer to the zip data and its length.
 * Valid until the next BOOTSTRAP_ZIP_Write or BOOTSTRAP_ZIP_Erase call.
 * The flash address is memory-mapped on Cortex-M33 — no copy needed.
 */
HAL_StatusTypeDef BOOTSTRAP_ZIP_GetPtr(const uint8_t **pp_data, uint32_t *out_len);

/* Erase both pages — call before re-provisioning */
HAL_StatusTypeDef BOOTSTRAP_ZIP_Erase(void);

#endif /* BOOTSTRAP_CERTS_FLASH_H */
