/**
 * clm_vfs.c
 *
 * RAM-backed virtual filesystem for DigiCert TrustCore SDK on bare-metal
 * Azure RTOS / ThreadX (no FileX, no POSIX fopen/fread/fwrite).
 *
 * ── Why this exists ─────────────────────────────────────────────────────
 * TRUSTEDGE_EST_main() stores the enrolled private key and device certificate
 * via DIGICERT_writeFile() → UTILS_writeFile().  On platforms without a real
 * filesystem (e.g. STM32 with ThreadX and no FileX), the stock utils.c
 * falls through to C-library FILE* which is unavailable on bare metal.
 *
 * This file provides concrete definitions of ALL UTILS_* and DIGICERT_*
 * file I/O symbols, replacing both utils.c and the file-I/O section of
 * mocana.c.  Neither utils.c nor mocana.c should be added to the build;
 * everything the linker needs is here.
 *
 * ── Build requirements ───────────────────────────────────────────────────
 *   - Do NOT add utils.c or the file-I/O portion of mocana.c to the build.
 *   - Add clm_vfs.c to MX_Application_Src in CMakeLists.txt instead.
 *   - __RTOS_AZURE__ (or __RTOS_THREADX__) must be defined so that the
 *     TrustCore headers select the correct RTOS types.
 *
 * ── Memory layout ────────────────────────────────────────────────────────
 *   Up to CLM_VFS_MAX_SLOTS files, each pointing into a flat pool:
 *
 *   Slot  Path pattern             Typical content / size
 *   ──── ────────────────────────  ──────────────────────────────────────
 *     -  <keystore>/keys/[name].der    ECDSA P-256 private key (~121 B)
 *     -  <keystore>/keys/[name].pem    Same key, PEM-encoded (~230 B)
 *     -  <keystore>/certs/[name].der   Device certificate DER (~1.5 KB)
 *     -  <keystore>/certs/[name].pem   Device certificate PEM (~2 KB)
 *     -  <keystore>/keys/[name]_req.*  CSR (~400 B, temporary)
 *
 *   CLM_VFS_POOL_SIZE must cover the sum of all files written during one
 *   EST enrollment round.  8 KB is conservative headroom.
 */

#include "moptions.h"
#include "mdefs.h"      /* TRUE / FALSE */
#include "mtypes.h"
#include "merrors.h"
#include "mrtos.h"      /* RTOS abstraction */
#include "mstdlib.h"    /* CONVERT_MALLOC / CONVERT_FREE */
#include "utils.h"      /* UTILS_FILE_STREAM_CTX, function declarations  */
#include "mocana.h"     /* DIGICERT_* function declarations               */
#include "clm_vfs.h"
#include <string.h>
#include <stdint.h>
#include <stdio.h>      /* snprintf */

/* ── tuning ──────────────────────────────────────────────────────────────
 * Increase CLM_VFS_POOL_SIZE if TRUSTEDGE_EST_main() returns memory errors.
 * Each write carves from the pool; the pool is reset by CLM_VFS_Reset().
 *
 * TrustEdge native flow requires headroom for:
 *   trustedge.json    (~700 B)
 *   bootstrap.zip     (~8 KB stored in VFS for extraction)
 *   extracted files   (bootstrap_config.json + key + cert ≈ 5 KB)
 *   keystore output   (enrolled key + cert ≈ 4 KB)
 *   temp copies       (~4 KB headroom for append/overwrite churn)
 * Total budget: ~32 KB.  Slots: up to 24 distinct file paths.
 */
#define CLM_VFS_MAX_SLOTS   24U
#define CLM_VFS_PATH_MAX    128U
#define CLM_VFS_POOL_SIZE   32768U

/* ── internal slot store ─────────────────────────────────────────────── */
typedef struct {
    char     path[CLM_VFS_PATH_MAX];
    uint8_t *pData;      /* pointer into g_pool */
    uint32_t len;
    uint8_t  valid;
} VfsSlot_t;

static VfsSlot_t g_vfs[CLM_VFS_MAX_SLOTS];
static uint8_t   g_pool[CLM_VFS_POOL_SIZE];
static uint32_t  g_pool_top;

/* ── private helpers ─────────────────────────────────────────────────── */

static VfsSlot_t *vfs_find(const char *path)
{
    uint32_t i;
    for (i = 0; i < CLM_VFS_MAX_SLOTS; i++)
        if (g_vfs[i].valid &&
            strncmp(g_vfs[i].path, path, CLM_VFS_PATH_MAX - 1U) == 0)
            return &g_vfs[i];
    return NULL;
}

static VfsSlot_t *vfs_alloc_slot(void)
{
    uint32_t i;
    for (i = 0; i < CLM_VFS_MAX_SLOTS; i++)
        if (!g_vfs[i].valid) return &g_vfs[i];
    return NULL;
}

static uint8_t *pool_alloc(uint32_t size)
{
    if ((g_pool_top > CLM_VFS_POOL_SIZE) ||
         (size > CLM_VFS_POOL_SIZE - g_pool_top))
	    return NULL;
    uint8_t *p = &g_pool[g_pool_top];
    g_pool_top += size;
    return p;
}

static int has_suffix(const char *str, const char *sfx)
{
    size_t sl = strlen(str), fl = strlen(sfx);
    return (sl >= fl) && (strcmp(str + sl - fl, sfx) == 0);
}

/* ── Public CLM VFS API ──────────────────────────────────────────────── */

void CLM_VFS_Reset(void)
{
    memset(g_vfs,  0, sizeof(g_vfs));
    memset(g_pool, 0, sizeof(g_pool));
    g_pool_top = 0;
}

int CLM_VFS_GetKeyDer(const uint8_t **ppKey, uint32_t *pLen)
{
    uint32_t i;
    if (!ppKey || !pLen) return -1;
    /* TrustEdge writes TRUSTEDGE_KEYS_FOLDER ("keys") under keystore_dir
     * as PEM-encoded PKCS#8 files (TRUSTEDGE_SUFFIX_PEM = ".pem").       */
    for (i = 0; i < CLM_VFS_MAX_SLOTS; i++) {
        if (!g_vfs[i].valid || !g_vfs[i].pData) continue;
        if (strstr(g_vfs[i].path, "/keys/") && has_suffix(g_vfs[i].path, ".pem")) {
            *ppKey = g_vfs[i].pData;
            *pLen  = g_vfs[i].len;
            return 0;
        }
    }
    return -1;
}

int CLM_VFS_GetCertDer(const uint8_t **ppCert, uint32_t *pLen)
{
    uint32_t i;
    if (!ppCert || !pLen) return -1;
    /* TrustEdge writes TRUSTEDGE_CERTS_FOLDER ("certs") under keystore_dir
     * as PEM-encoded X.509 files (TRUSTEDGE_SUFFIX_PEM = ".pem").        */
    for (i = 0; i < CLM_VFS_MAX_SLOTS; i++) {
        if (!g_vfs[i].valid || !g_vfs[i].pData) continue;
        if (strstr(g_vfs[i].path, "/certs/") && has_suffix(g_vfs[i].path, ".pem")) {
            *ppCert = g_vfs[i].pData;
            *pLen   = g_vfs[i].len;
            return 0;
        }
    }
    return -1;
}

/* ── UTILS_* implementations ─────────────────────────────────────────── */

MSTATUS UTILS_mkdir(const char *directory)
{
    VfsSlot_t *slot;
    if (!directory) return ERR_NULL_POINTER;

    /* Write a zero-length sentinel so FMGMT_pathExists can detect this
     * path as an existing directory.  pData == NULL + len == 0 is the
     * marker; UTILS_readFile refuses to return sentinels as file data.  */
    slot = vfs_find(directory);
    if (!slot) {
        slot = vfs_alloc_slot();
        if (!slot) return ERR_MEM_ALLOC_FAIL;
        strncpy(slot->path, directory, CLM_VFS_PATH_MAX - 1U);
        slot->path[CLM_VFS_PATH_MAX - 1U] = '\0';
        slot->pData = NULL;
        slot->len   = 0U;
        slot->valid = 1U;
    }
    return OK;
}

/* Returns 1 if path is a virtual directory sentinel (written by UTILS_mkdir),
 * 0 if it is a regular file or does not exist.
 * Used by AZURERTOS_pathExists in azurertos_fmgmt.c.                          */
int VFS_isDirectory(const char *path)
{
    VfsSlot_t *slot;
    if (!path) return 0;
    slot = vfs_find(path);
    return (slot && slot->pData == NULL && slot->len == 0U) ? 1 : 0;
}

MSTATUS UTILS_writeFile(const char *pFilename, const ubyte *pBuffer, ubyte4 bufLength)
{
    VfsSlot_t *slot;
    uint8_t   *p;

    if (!pFilename || !pBuffer) return ERR_NULL_POINTER;

    slot = vfs_find(pFilename);
    if (!slot) {
        slot = vfs_alloc_slot();
        if (!slot) return ERR_MEM_ALLOC_FAIL;
        strncpy(slot->path, pFilename, CLM_VFS_PATH_MAX - 1U);
        slot->path[CLM_VFS_PATH_MAX - 1U] = '\0';
        slot->valid = 1U;
    }

    p = pool_alloc(bufLength);
    if (!p) return ERR_MEM_ALLOC_FAIL;

    memcpy(p, pBuffer, bufLength);
    slot->pData = p;
    slot->len   = bufLength;
    return OK;
}

MSTATUS UTILS_appendFile(const char *pFilename, const ubyte *pBuffer, ubyte4 bufLength)
{
    VfsSlot_t *slot;
    uint32_t   newLen;
    uint8_t   *p;

    if (!pFilename || !pBuffer) return ERR_NULL_POINTER;

    slot = vfs_find(pFilename);
    if (!slot) {
        /* file does not exist yet → create */
        return UTILS_writeFile(pFilename, pBuffer, bufLength);
    }

    newLen = slot->len + bufLength;
    p = pool_alloc(newLen);
    if (!p) return ERR_MEM_ALLOC_FAIL;

    memcpy(p, slot->pData, slot->len);
    memcpy(p + slot->len, pBuffer, bufLength);
    slot->pData = p;
    slot->len   = newLen;
    return OK;
}

MSTATUS UTILS_readFile(const char *pFilename, ubyte **ppRetBuffer, ubyte4 *pRetBufLength)
{
    VfsSlot_t *slot;
    ubyte     *p;

    if (!pFilename || !ppRetBuffer || !pRetBufLength) return ERR_NULL_POINTER;

    slot = vfs_find(pFilename);
    if (!slot) return ERR_NOT_FOUND;
    /* Directory sentinels (pData == NULL, len == 0) are not readable files. */
    if (slot->pData == NULL && slot->len == 0U) return ERR_NOT_FOUND;

    /* Allocate a copy; caller must free via UTILS_freeReadFile / DIGICERT_freeReadFile */
    p = (ubyte *)MALLOC(slot->len + 1U);
    if (!p) return ERR_MEM_ALLOC_FAIL;

    memcpy(p, slot->pData, slot->len);
    p[slot->len]   = 0;
    *ppRetBuffer   = p;
    *pRetBufLength = slot->len;
    return OK;
}

MSTATUS UTILS_readFileRaw(const ubyte *pFileObj, ubyte **ppRetBuffer, ubyte4 *pRetBufLength)
{
    /* pFileObj is a raw FILE* cast to ubyte* in the POSIX path.
     * Not applicable on bare metal; callers fall back to UTILS_readFile. */
    (void)pFileObj;
    (void)ppRetBuffer;
    (void)pRetBufLength;
    return ERR_NOT_FOUND;
}

MSTATUS UTILS_freeReadFile(ubyte **ppRetBuffer)
{
    if (!ppRetBuffer || !*ppRetBuffer) return ERR_NULL_POINTER;
    FREE(*ppRetBuffer);
    *ppRetBuffer = NULL;
    return OK;
}

MSTATUS UTILS_deleteFile(const char *pFilename)
{
    VfsSlot_t *slot;
    if (!pFilename) return ERR_NULL_POINTER;
    slot = vfs_find(pFilename);
    if (slot) memset(slot, 0, sizeof(*slot)); /* idempotent */
    return OK;
}

MSTATUS UTILS_checkFile(const char *pFilename, const char *pExt, intBoolean *pFileExist)
{
    char buf[CLM_VFS_PATH_MAX];

    if (!pFilename || !pFileExist) return ERR_NULL_POINTER;

    *pFileExist = (vfs_find(pFilename) != NULL) ? TRUE : FALSE;

    if (!(*pFileExist) && pExt) {
        /* try <pFilename>.<pExt> */
        snprintf(buf, sizeof(buf), "%s.%s", pFilename, pExt);
        *pFileExist = (vfs_find(buf) != NULL) ? TRUE : FALSE;
    }
    return OK;
}

MSTATUS UTILS_copyFile(const char *pSrcFilename, const char *pDestFilename, ubyte4 bufLength)
{
    VfsSlot_t *src;
    (void)bufLength;

    if (!pSrcFilename || !pDestFilename) return ERR_NULL_POINTER;

    src = vfs_find(pSrcFilename);
    if (!src) return ERR_NOT_FOUND;

    return UTILS_writeFile(pDestFilename, src->pData, src->len);
}

/* ── Stream I/O ──────────────────────────────────────────────────────── */

MSTATUS UTILS_initReadFile(UTILS_FILE_STREAM_CTX *pCtx, const char *pFilename)
{
    VfsSlot_t *slot;
    if (!pCtx || !pFilename) return ERR_NULL_POINTER;

    slot = vfs_find(pFilename);
    if (!slot) return ERR_NOT_FOUND;

    pCtx->pFileStream = (void *)slot;
    pCtx->fileSize    = slot->len;
    pCtx->bytesRead   = 0;
    return OK;
}

MSTATUS UTILS_updateReadFile(UTILS_FILE_STREAM_CTX *pCtx, ubyte *pBuffer,
                             ubyte4 bufferLen, ubyte4 *pBytesRead, byteBoolean *pDone)
{
    VfsSlot_t *slot;
    uint32_t   avail, copy;

    if (!pCtx || !pBuffer || !pBytesRead || !pDone) return ERR_NULL_POINTER;

    slot = (VfsSlot_t *)pCtx->pFileStream;
    if (!slot) return ERR_NULL_POINTER;

    avail       = slot->len - pCtx->bytesRead;
    copy        = (avail < (uint32_t)bufferLen) ? avail : (uint32_t)bufferLen;
    memcpy(pBuffer, slot->pData + pCtx->bytesRead, copy);
    pCtx->bytesRead += copy;
    *pBytesRead     = copy;
    *pDone          = (pCtx->bytesRead >= slot->len) ? (byteBoolean)TRUE : (byteBoolean)FALSE;
    return OK;
}

MSTATUS UTILS_initWriteFile(UTILS_FILE_STREAM_CTX *pCtx, const char *pFilename)
{
    /* Stream writes are not used in the EST enrollment path. */
    (void)pFilename;
    if (!pCtx) return ERR_NULL_POINTER;
    pCtx->pFileStream = NULL;
    pCtx->fileSize    = 0;
    pCtx->bytesRead   = 0;
    return OK;
}

MSTATUS UTILS_updateWriteFile(UTILS_FILE_STREAM_CTX *pCtx, ubyte *pBuffer, ubyte4 bufferLen)
{
    (void)pCtx;
    (void)pBuffer;
    (void)bufferLen;
    return OK;
}

MSTATUS UTILS_closeFile(UTILS_FILE_STREAM_CTX *pCtx)
{
    if (!pCtx) return ERR_NULL_POINTER;
    pCtx->pFileStream = NULL;
    return OK;
}

/* ── DIGICERT_* wrappers ─────────────────────────────────────────────────
 * When the full TrustCore SDK is compiled (TRUSTCORE_SDK_AVAILABLE), mocana.c
 * already provides these thin wrappers (they delegate to UTILS_* above).
 * Only compile them here when the SDK is absent so clm_vfs.c stands alone.
 */
#ifndef TRUSTCORE_SDK_AVAILABLE

sbyte4 DIGICERT_readFile(const char *pFilename, ubyte **ppRetBuffer, ubyte4 *pRetBufLength)
{
    return (sbyte4)UTILS_readFile(pFilename, ppRetBuffer, pRetBufLength);
}

sbyte4 DIGICERT_freeReadFile(ubyte **ppRetBuffer)
{
    return (sbyte4)UTILS_freeReadFile(ppRetBuffer);
}

sbyte4 DIGICERT_writeFile(const char *pFilename, const ubyte *pBuffer, ubyte4 bufLength)
{
    return (sbyte4)UTILS_writeFile(pFilename, pBuffer, bufLength);
}

sbyte4 DIGICERT_appendFile(const char *pFilename, const ubyte *pBuffer, ubyte4 bufLength)
{
    return (sbyte4)UTILS_appendFile(pFilename, pBuffer, bufLength);
}

sbyte4 DIGICERT_copyFile(const char *pSrcFilename, const char *pDestFilename)
{
    return (sbyte4)UTILS_copyFile(pSrcFilename, pDestFilename, 0U);
}

sbyte4 DIGICERT_deleteFile(const char *pFilename)
{
    return (sbyte4)UTILS_deleteFile(pFilename);
}

sbyte4 DIGICERT_checkFile(const char *pFilename, const char *pExt, intBoolean *pFileExist)
{
    return (sbyte4)UTILS_checkFile(pFilename, pExt, pFileExist);
}

#endif /* TRUSTCORE_SDK_AVAILABLE */
