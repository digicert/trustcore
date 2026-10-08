/**
 * prov_uart.h
 *
 * Factory-floor UART provisioning — burns the DTM bootstrap.zip to flash.
 *
 * ── Purpose ─────────────────────────────────────────────────────────────────
 *
 * At manufacturing time, the floor PC running burn_bootstrap_certs.py sends the
 * raw DTM bootstrap.zip blob over USART1 (ST-LINK VCP, 115200 8N1).
 * The device writes it verbatim to the BOOTSTRAP_ZIP flash region so that
 * trustedge_threadx.c can copy it into the VFS at boot and call
 * TRUSTEDGE_extractBootStrap().
 *
 * ── Wire protocol (binary, little-endian) ───────────────────────────────────
 *
 *   1. Host  → MAGIC_START [4]  {0xDC,0x19,0x50,0x56}
 *      Device → ACK(0x06) | ALREADY(0xAA) | NAK(0x15)
 *      (ALREADY if bootstrap zip is already in flash; host may re-provision)
 *
 *   2. Host  → zip_len [4 LE]   raw byte count of the bootstrap.zip
 *      Device → ACK | NAK       NAK if zip_len > BOOTSTRAP_ZIP_MAX_LEN
 *
 *   3. Host  → zip_data [zip_len]
 *      Host  → crc32    [4 LE]  CRC-32 (ISO 3309) over zip_data
 *      Device → ACK | NAK       NAK on CRC mismatch
 *
 *   4. Host  → MAGIC_COMMIT [4]  {0xDC,0x19,0x43,0x4D}
 *      Device → ACK             flash write succeeded
 *             | NAK             flash write failed
 *
 * ── Integration point ───────────────────────────────────────────────────────
 *
 *   Call PROV_UART_Listen() at the start of trustedge_threadx_entry(), before
 *   TRUSTEDGE_init():
 *
 *     extern UART_HandleTypeDef huart1;
 *     PROV_UART_Listen(&huart1, PROV_UART_REPROBE_MS);
 *     if (!BOOTSTRAP_ZIP_IsProvisioned()) { // halt }
 */

#ifndef PROV_UART_H
#define PROV_UART_H

#include "stm32u5xx_hal.h"

/* Return codes */
#define PROV_OK           (0)
#define PROV_SKIPPED      (1)   /* already provisioned, no session in window  */
#define PROV_ERR_TIMEOUT  (-1)
#define PROV_ERR_CRC      (-2)
#define PROV_ERR_PARAM    (-3)  /* zip_len out of range                       */
#define PROV_ERR_FLASH    (-4)

/* How long to listen for a re-provision session when already provisioned.
 * Un-provisioned boards block for PROV_UART_MANDATORY_MS. */
#define PROV_UART_REPROBE_MS    (8000U)
#define PROV_UART_MANDATORY_MS  (300000U)

int PROV_UART_Listen(UART_HandleTypeDef *huart, uint32_t reprobe_ms);

#endif /* PROV_UART_H */
