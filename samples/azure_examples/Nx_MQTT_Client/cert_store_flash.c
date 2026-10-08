/**
 * cert_store_flash.c
 *
 * Flash-backed keystore for the DigiCert TrustCore CLM layer.
 *
 * STM32U585AI flash facts:
 *   – 2 MB total, dual-bank (Bank 1: 0x08000000, Bank 2: 0x08100000)
 *   – 128 pages per bank, 8 KB per page
 *   – Programming unit: 128-bit (16 bytes) quadword, must be aligned
 *   – Erase unit: one page (8 KB)
 *
 * This module uses Bank 2 pages 125-127 (last 24 KB) which are far enough
 * above any realistic code image.  Ensure the linker script excludes them:
 *   FLASH (rx) : ORIGIN = 0x08000000, LENGTH = 2024K   ← reduced from 2048K
 */

#include "cert_store_flash.h"
#include <string.h>
#include <stdio.h>

/* ── Internal helpers ────────────────────────────────────────────────────── */

/* Convert an absolute flash address to bank + page-within-bank */
static void addr_to_bank_page(uint32_t addr, uint32_t *bank, uint32_t *page)
{
    if (addr >= 0x08100000U) {
        *bank = FLASH_BANK_2;
        *page = (addr - 0x08100000U) / CERT_STORE_PAGE_SIZE;
    } else {
        *bank = FLASH_BANK_1;
        *page = (addr - 0x08000000U) / CERT_STORE_PAGE_SIZE;
    }
}

/* Erase one 8 KB flash page given its absolute start address */
static HAL_StatusTypeDef erase_page(uint32_t page_addr)
{
    FLASH_EraseInitTypeDef erase_init;
    uint32_t page_error = 0;
    uint32_t bank, page;

    addr_to_bank_page(page_addr, &bank, &page);

    erase_init.TypeErase = FLASH_TYPEERASE_PAGES;
    erase_init.Banks     = bank;
    erase_init.Page      = page;
    erase_init.NbPages   = 1;

    HAL_StatusTypeDef ret = HAL_FLASHEx_Erase(&erase_init, &page_error);
    if (ret != HAL_OK || page_error != 0xFFFFFFFFU) {
        ret = HAL_ERROR;
    }
    return ret;
}

/*
 * Write arbitrary data to flash.
 * STM32U585 requires 128-bit (16-byte) aligned quadword writes.
 * We pad the source to a multiple of 16 bytes with 0xFF before writing.
 */
static HAL_StatusTypeDef write_flash(uint32_t dest_addr, const uint8_t *src, uint32_t len)
{
    uint8_t  quad[16];
    uint32_t offset = 0;
    HAL_StatusTypeDef ret = HAL_OK;

    while (offset < len) {
        uint32_t chunk = len - offset;
        if (chunk > 16U) chunk = 16U;

        memset(quad, 0xFF, sizeof(quad));
        memcpy(quad, src + offset, chunk);

        ret = HAL_FLASH_Program(FLASH_TYPEPROGRAM_QUADWORD,
                                dest_addr + offset,
                                (uint32_t)(uintptr_t)quad);
        if (ret != HAL_OK) break;

        offset += 16U;
    }
    return ret;
}

/* ── Public API ──────────────────────────────────────────────────────────── */

HAL_StatusTypeDef CERT_STORE_Init(void)
{
    /* Nothing to initialise at run time; flash is always accessible. */
    return HAL_OK;
}

uint8_t CERT_STORE_IsProvisioned(void)
{
    const CertStoreHdr_t *kh = (const CertStoreHdr_t *)(uintptr_t)CERT_STORE_KEY_ADDR;
    const CertStoreHdr_t *ch = (const CertStoreHdr_t *)(uintptr_t)CERT_STORE_CERT_ADDR;
    const CertStoreMeta_t *m  = (const CertStoreMeta_t *)(uintptr_t)CERT_STORE_META_ADDR;

    return (kh->magic == CERT_STORE_MAGIC &&
            ch->magic == CERT_STORE_MAGIC &&
            m->magic  == CERT_STORE_MAGIC &&
            kh->len > 0 && kh->len <= CERT_STORE_MAX_KEY_LEN &&
            ch->len > 0 && ch->len <= CERT_STORE_MAX_CERT_LEN) ? 1U : 0U;
}

HAL_StatusTypeDef CERT_STORE_WriteKey(const uint8_t *key_der, uint32_t len)
{
    if (!key_der || len == 0 || len > CERT_STORE_MAX_KEY_LEN) return HAL_ERROR;

    CertStoreHdr_t hdr = { .magic = CERT_STORE_MAGIC, .len = len };
    HAL_StatusTypeDef ret;

    HAL_FLASH_Unlock();
    ret = erase_page(CERT_STORE_KEY_ADDR);
    if (ret == HAL_OK) ret = write_flash(CERT_STORE_KEY_ADDR, (const uint8_t *)&hdr, sizeof(hdr));
    if (ret == HAL_OK) ret = write_flash(CERT_STORE_KEY_ADDR + sizeof(hdr), key_der, len);
    HAL_FLASH_Lock();
    return ret;
}

HAL_StatusTypeDef CERT_STORE_ReadKey(uint8_t *buf, uint32_t buf_len, uint32_t *out_len)
{
    if (!buf || !out_len) return HAL_ERROR;
    const CertStoreHdr_t *hdr = (const CertStoreHdr_t *)(uintptr_t)CERT_STORE_KEY_ADDR;
    if (hdr->magic != CERT_STORE_MAGIC || hdr->len > CERT_STORE_MAX_KEY_LEN) return HAL_ERROR;
    if (hdr->len > buf_len) return HAL_ERROR;
    *out_len = hdr->len;
    memcpy(buf, (const uint8_t *)(uintptr_t)(CERT_STORE_KEY_ADDR + sizeof(CertStoreHdr_t)), hdr->len);
    return HAL_OK;
}

HAL_StatusTypeDef CERT_STORE_WriteCert(const uint8_t *cert_der, uint32_t len)
{
    if (!cert_der || len == 0 || len > CERT_STORE_MAX_CERT_LEN) return HAL_ERROR;

    CertStoreHdr_t hdr = { .magic = CERT_STORE_MAGIC, .len = len };
    HAL_StatusTypeDef ret;

    HAL_FLASH_Unlock();
    ret = erase_page(CERT_STORE_CERT_ADDR);
    if (ret == HAL_OK) ret = write_flash(CERT_STORE_CERT_ADDR, (const uint8_t *)&hdr, sizeof(hdr));
    if (ret == HAL_OK) ret = write_flash(CERT_STORE_CERT_ADDR + sizeof(hdr), cert_der, len);
    HAL_FLASH_Lock();
    return ret;
}

HAL_StatusTypeDef CERT_STORE_ReadCert(uint8_t *buf, uint32_t buf_len, uint32_t *out_len)
{
    if (!buf || !out_len) return HAL_ERROR;
    const CertStoreHdr_t *hdr = (const CertStoreHdr_t *)(uintptr_t)CERT_STORE_CERT_ADDR;
    if (hdr->magic != CERT_STORE_MAGIC || hdr->len > CERT_STORE_MAX_CERT_LEN) return HAL_ERROR;
    if (hdr->len > buf_len) return HAL_ERROR;
    *out_len = hdr->len;
    memcpy(buf, (const uint8_t *)(uintptr_t)(CERT_STORE_CERT_ADDR + sizeof(CertStoreHdr_t)), hdr->len);
    return HAL_OK;
}

HAL_StatusTypeDef CERT_STORE_WriteMeta(const CertStoreMeta_t *meta)
{
    if (!meta) return HAL_ERROR;

    CertStoreMeta_t m = *meta;
    m.magic = CERT_STORE_MAGIC;
    HAL_StatusTypeDef ret;

    HAL_FLASH_Unlock();
    ret = erase_page(CERT_STORE_META_ADDR);
    if (ret == HAL_OK) ret = write_flash(CERT_STORE_META_ADDR, (const uint8_t *)&m, sizeof(m));
    HAL_FLASH_Lock();
    return ret;
}

HAL_StatusTypeDef CERT_STORE_ReadMeta(CertStoreMeta_t *meta)
{
    if (!meta) return HAL_ERROR;
    const CertStoreMeta_t *m = (const CertStoreMeta_t *)(uintptr_t)CERT_STORE_META_ADDR;
    if (m->magic != CERT_STORE_MAGIC) return HAL_ERROR;
    *meta = *m;
    return HAL_OK;
}

HAL_StatusTypeDef CERT_STORE_Erase(void)
{
    HAL_StatusTypeDef ret;
    HAL_FLASH_Unlock();
    ret = erase_page(CERT_STORE_KEY_ADDR);
    if (ret == HAL_OK) ret = erase_page(CERT_STORE_CERT_ADDR);
    if (ret == HAL_OK) ret = erase_page(CERT_STORE_META_ADDR);
    HAL_FLASH_Lock();
    return ret;
}
