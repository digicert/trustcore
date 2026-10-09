/**
 * prov_uart.c
 *
 * Factory-floor UART provisioning — receives the raw DTM bootstrap.zip and
 * writes it to flash via BOOTSTRAP_ZIP_Write().
 *
 * Protocol (all multi-byte fields little-endian):
 *
 *   Host → MAGIC_START[4]
 *   Board → ACK(0x06)   if not yet provisioned
 *           ALREADY(0xAA) if already provisioned (host may still re-provision)
 *
 *   Host → zip_len[4 LE]
 *   Board → ACK if zip_len ≤ BOOTSTRAP_ZIP_MAX_LEN, else NAK
 *
 *   Host → zip_data[zip_len]
 *   Host → crc32[4 LE]   CRC-32 (ISO 3309 / Ethernet) over zip_data only
 *   Board → ACK if CRC matches, else NAK
 *
 *   Host → MAGIC_COMMIT[4]
 *   Board → ACK after successful flash write, else NAK
 */

#include "prov_uart.h"
#include "bootstrap_certs_flash.h"
#include <string.h>

/* ── Wire-protocol constants ─────────────────────────────────────────────── */

static const uint8_t MAGIC_START[4]  = { 0xDC, 0x19, 0x50, 0x56 };
static const uint8_t MAGIC_COMMIT[4] = { 0xDC, 0x19, 0x43, 0x4D };

#define PROV_ACK     (0x06U)
#define PROV_NAK     (0x15U)
#define PROV_ALREADY (0xAAU)

/* Receive buffer in BSS — avoids stack pressure during provisioning */
static uint8_t s_zip_buf[BOOTSTRAP_ZIP_MAX_LEN];

/* ── CRC-32 (ISO 3309 / Ethernet) ────────────────────────────────────────── */

static uint32_t crc32_compute(const uint8_t *data, uint32_t len)
{
    uint32_t crc = 0xFFFFFFFFU;
    for (uint32_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int b = 0; b < 8; b++)
            crc = (crc & 1U) ? (crc >> 1) ^ 0xEDB88320U : (crc >> 1);
    }
    return ~crc;
}

/* ── Low-level UART helpers ──────────────────────────────────────────────── */

static void uart_send_byte(UART_HandleTypeDef *h, uint8_t b)
{
    HAL_UART_Transmit(h, &b, 1, 100U);
}

static HAL_StatusTypeDef uart_recv(UART_HandleTypeDef *h, uint8_t *buf,
                                   uint16_t len, uint32_t timeout_ms)
{
    return HAL_UART_Receive(h, buf, len, timeout_ms);
}

/* ── Session handler ─────────────────────────────────────────────────────── */

static int run_session(UART_HandleTypeDef *huart, uint32_t first_byte_timeout_ms)
{
    uint8_t buf[4];

    /* 1. Wait for MAGIC_START — byte-by-byte match within the timeout window */
    uint32_t matched = 0;
    uint32_t deadline = HAL_GetTick() + first_byte_timeout_ms;

    while (HAL_GetTick() < deadline) {
        uint32_t remaining = deadline - HAL_GetTick();
        if (remaining == 0U) break;
        if (remaining > 500U) remaining = 500U;

        uint8_t b;
        if (HAL_UART_Receive(huart, &b, 1, remaining) != HAL_OK)
            break;
        if (b == MAGIC_START[matched]) {
            if (++matched == 4U) goto got_magic;
        } else {
            matched = (b == MAGIC_START[0]) ? 1U : 0U;
        }
    }
    return PROV_ERR_TIMEOUT;

got_magic:
    uart_send_byte(huart, BOOTSTRAP_ZIP_IsProvisioned() ? PROV_ALREADY : PROV_ACK);

    /* 2. Read zip_len (4 bytes LE) */
    if (uart_recv(huart, buf, 4, 5000U) != HAL_OK)
        return PROV_ERR_TIMEOUT;

    uint32_t zip_len = (uint32_t)buf[0]
                     | ((uint32_t)buf[1] << 8)
                     | ((uint32_t)buf[2] << 16)
                     | ((uint32_t)buf[3] << 24);

    if (zip_len == 0U || zip_len > BOOTSTRAP_ZIP_MAX_LEN) {
        uart_send_byte(huart, PROV_NAK);
        return PROV_ERR_PARAM;
    }
    uart_send_byte(huart, PROV_ACK);

    /* 3. Read zip_data in 256-byte chunks (avoids hitting HAL UART transfer limits) */
    uint32_t received = 0;
    while (received < zip_len) {
        uint32_t chunk = zip_len - received;
        if (chunk > 256U) chunk = 256U;
        if (uart_recv(huart, s_zip_buf + received, (uint16_t)chunk, 10000U) != HAL_OK) {
            uart_send_byte(huart, PROV_NAK);
            return PROV_ERR_TIMEOUT;
        }
        received += chunk;
    }

    /* 4. Read and verify CRC-32 (4 bytes LE) */
    if (uart_recv(huart, buf, 4, 5000U) != HAL_OK) {
        uart_send_byte(huart, PROV_NAK);
        return PROV_ERR_TIMEOUT;
    }
    uint32_t host_crc = (uint32_t)buf[0]
                      | ((uint32_t)buf[1] << 8)
                      | ((uint32_t)buf[2] << 16)
                      | ((uint32_t)buf[3] << 24);

    if (crc32_compute(s_zip_buf, zip_len) != host_crc) {
        uart_send_byte(huart, PROV_NAK);
        return PROV_ERR_CRC;
    }
    uart_send_byte(huart, PROV_ACK);

    /* 5. Wait for MAGIC_COMMIT */
    if (uart_recv(huart, buf, 4, 5000U) != HAL_OK)
        return PROV_ERR_TIMEOUT;
    if (memcmp(buf, MAGIC_COMMIT, 4) != 0)
        return PROV_ERR_TIMEOUT;

    /* 6. Write zip to flash */
    if (BOOTSTRAP_ZIP_Write(s_zip_buf, zip_len) != HAL_OK) {
        uart_send_byte(huart, PROV_NAK);
        return PROV_ERR_FLASH;
    }

    uart_send_byte(huart, PROV_ACK);
    return PROV_OK;
}

/* ── Public API ──────────────────────────────────────────────────────────── */

int PROV_UART_Listen(UART_HandleTypeDef *huart, uint32_t reprobe_ms)
{
    uint32_t timeout_ms;

    if (BOOTSTRAP_ZIP_IsProvisioned()) {
        if (reprobe_ms == 0U)
            return PROV_SKIPPED;
        timeout_ms = reprobe_ms;
    } else {
        timeout_ms = PROV_UART_MANDATORY_MS;
    }

    int rc = run_session(huart, timeout_ms);

    /* Timeout during re-probe window is expected — not an error */
    if (rc == PROV_ERR_TIMEOUT && BOOTSTRAP_ZIP_IsProvisioned())
        return PROV_SKIPPED;

    return rc;
}
