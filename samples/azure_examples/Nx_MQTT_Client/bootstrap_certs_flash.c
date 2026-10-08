/**
 * bootstrap_certs_flash.c
 *
 * Flash-backed store for the raw DTM bootstrap.zip on STM32U585.
 * See bootstrap_certs_flash.h for region layout and sizing.
 *
 * STM32U585 flash constraints:
 *   – 128-bit (16-byte) quadword programming unit, 16-byte aligned destination
 *   – 8 KB erase unit (one page)
 */

#include "bootstrap_certs_flash.h"
#include <string.h>

/* ── Internal helpers ────────────────────────────────────────────────────── */

static void addr_to_bank_page(uint32_t addr, uint32_t *bank, uint32_t *page)
{
    if (addr >= 0x08100000U) {
        *bank = FLASH_BANK_2;
        *page = (addr - 0x08100000U) / BOOTSTRAP_ZIP_PAGE_SIZE;
    } else {
        *bank = FLASH_BANK_1;
        *page = (addr - 0x08000000U) / BOOTSTRAP_ZIP_PAGE_SIZE;
    }
}

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
    if (ret != HAL_OK || page_error != 0xFFFFFFFFU)
        ret = HAL_ERROR;
    return ret;
}

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

HAL_StatusTypeDef BOOTSTRAP_ZIP_Init(void)
{
    return HAL_OK;
}

uint8_t BOOTSTRAP_ZIP_IsProvisioned(void)
{
    const BootstrapZipHdr_t *hdr =
        (const BootstrapZipHdr_t *)(uintptr_t)BOOTSTRAP_ZIP_BASE_ADDR;

    return (hdr->magic   == BOOTSTRAP_ZIP_MAGIC   &&
            hdr->version == BOOTSTRAP_ZIP_VERSION  &&
            hdr->zip_len  > 0U                     &&
            hdr->zip_len <= BOOTSTRAP_ZIP_MAX_LEN) ? 1U : 0U;
}

HAL_StatusTypeDef BOOTSTRAP_ZIP_Write(const uint8_t *zip_data, uint32_t zip_len)
{
    if (!zip_data || zip_len == 0U || zip_len > BOOTSTRAP_ZIP_MAX_LEN)
        return HAL_ERROR;

    BootstrapZipHdr_t hdr = {
        .magic    = BOOTSTRAP_ZIP_MAGIC,
        .version  = BOOTSTRAP_ZIP_VERSION,
        .zip_len  = zip_len,
        .reserved = 0xFFFFFFFFU,
    };

    HAL_StatusTypeDef ret;
    HAL_FLASH_Unlock();

    ret = erase_page(BOOTSTRAP_ZIP_BASE_ADDR);
    if (ret == HAL_OK)
        ret = erase_page(BOOTSTRAP_ZIP_BASE_ADDR + BOOTSTRAP_ZIP_PAGE_SIZE);

    if (ret == HAL_OK)
        ret = write_flash(BOOTSTRAP_ZIP_BASE_ADDR, (const uint8_t *)&hdr, sizeof(hdr));

    if (ret == HAL_OK)
        ret = write_flash(BOOTSTRAP_ZIP_DATA_ADDR, zip_data, zip_len);

    HAL_FLASH_Lock();
    return ret;
}

HAL_StatusTypeDef BOOTSTRAP_ZIP_Read(uint8_t *buf, uint32_t buf_len, uint32_t *out_len)
{
    if (!buf || !out_len) return HAL_ERROR;

    const BootstrapZipHdr_t *hdr =
        (const BootstrapZipHdr_t *)(uintptr_t)BOOTSTRAP_ZIP_BASE_ADDR;

    if (hdr->magic   != BOOTSTRAP_ZIP_MAGIC  ||
        hdr->version != BOOTSTRAP_ZIP_VERSION ||
        hdr->zip_len == 0U || hdr->zip_len > BOOTSTRAP_ZIP_MAX_LEN)
        return HAL_ERROR;

    if (hdr->zip_len > buf_len) return HAL_ERROR;

    memcpy(buf,
           (const uint8_t *)(uintptr_t)BOOTSTRAP_ZIP_DATA_ADDR,
           hdr->zip_len);

    *out_len = hdr->zip_len;
    return HAL_OK;
}

HAL_StatusTypeDef BOOTSTRAP_ZIP_GetPtr(const uint8_t **pp_data, uint32_t *out_len)
{
    if (!pp_data || !out_len) return HAL_ERROR;

    const BootstrapZipHdr_t *hdr =
        (const BootstrapZipHdr_t *)(uintptr_t)BOOTSTRAP_ZIP_BASE_ADDR;

    if (hdr->magic   != BOOTSTRAP_ZIP_MAGIC  ||
        hdr->version != BOOTSTRAP_ZIP_VERSION ||
        hdr->zip_len == 0U || hdr->zip_len > BOOTSTRAP_ZIP_MAX_LEN)
        return HAL_ERROR;

    *pp_data = (const uint8_t *)(uintptr_t)BOOTSTRAP_ZIP_DATA_ADDR;
    *out_len = hdr->zip_len;
    return HAL_OK;
}

HAL_StatusTypeDef BOOTSTRAP_ZIP_Erase(void)
{
    HAL_StatusTypeDef ret;
    HAL_FLASH_Unlock();
    ret = erase_page(BOOTSTRAP_ZIP_BASE_ADDR);
    if (ret == HAL_OK)
        ret = erase_page(BOOTSTRAP_ZIP_BASE_ADDR + BOOTSTRAP_ZIP_PAGE_SIZE);
    HAL_FLASH_Lock();
    return ret;
}
