/**
 * @file sapi2_hmac.c
 * @brief This file contains SAPI2 HMAC related functions for TPM2.
 *
 * @flags
 *  To enable this file's functions, the following flags must be defined in
 * moptions.h:
 *
 *  + \c \__ENABLE_DIGICERT_TPM2__
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

#include "../../../../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_TPM2__))

#include "../../../../common/mtypes.h"
#include "../../../../common/mdefs.h"
#include "../../../../common/merrors.h"
#include "../../../../common/mrtos.h"
#include "../../../../common/mstdlib.h"
#include "../../../../common/debug_console.h"
#include "../../../../common/base64.h"
#include "../../../../common/vlong.h"
#include "../../../../common/mocana.h"
#include "../../../../crypto/hw_accel.h"
#include "../../../../common/random.h"
#include "../../../../crypto/crypto.h"
#include "../../../../crypto/md5.h"
#include "../../../../crypto/sha1.h"
#include "../../../../crypto/sha256.h"
#include "../../../../crypto/sha512.h"
#include "../../../../crypto/hmac.h"
#include "../tpm_common/tpm_error_utils.h"
#include "../tpm2_types.h"
#include "sapi2_hmac.h"
#include "sapi2_hash.h"
#include "sapi2_utils.h"
/**
 * @brief Function to compute command or response HMAC
 *
 */
MSTATUS
SAPI2_HMAC_computeCmdRspHMAC(MOCTPM2_SESSION *pSession, TPM2B_AUTH *pAuth,
        TPM2B_DIGEST *pCRPHash, TPM2B_DIGEST *pResult)
{ 
    MSTATUS status = OK;
    HASH_ELEMENT hash_element[2];
    ubyte *pAuthInfo = NULL;
    ubyte4 authInfoLen = 0;
    ubyte *pHmacKey = NULL;
    ubyte4 hmacKeyLen = 0;
    ubyte *pHmacBuf = NULL;
    ubyte4 hmacBufLen = 0;
    const BulkHashAlgo *pBulkHashAlgo = NULL;
    ubyte4 offset;
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;

#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    /* just in case build uses both TAP and hwAccel */
    hwAccelDescr hwAccelCtx = 0;
#endif
    
    if ((NULL == pSession) || (NULL == pAuth) ||
            (NULL == pCRPHash) || (NULL == pResult))
    {
        status = ERR_INVALID_ARG;
        DB_PRINT("SAPI2_HMAC_computeCommandResponseHMAC: Invalid input parameter! status = %d\n",
                (int)status);
        goto exit;
    }
    
#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    status = (MSTATUS) HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx);
    if (OK != status)
        goto exit;
#endif

    rc = SAPI2_UTILS_getHashAlg(pSession->hashAlgId, &pBulkHashAlgo);
    if (TSS2_RC_SUCCESS != rc)
    {
        status = ERR_INTERNAL_ERROR;
        DB_PRINT("SAPI2_HMAC_computeCommandResponseHMAC: Failed to get hash algorithm! status = %d\n",
                (int)status);
        goto exit;
    }

    /* Set Session digest size if it is not yet initialized */
    if (!pSession->digestSize)
    {
        pSession->digestSize = pBulkHashAlgo->digestSize;
    }

    if (sizeof(pResult->buffer) < pSession->digestSize)
    {
        status = ERR_INVALID_ARG;
        DB_PRINT("SAPI2_HMAC_computeCommandResponseHMAC: Insufficient space in result buffer! status = %d\n",
                (int)status);

        goto exit;
    }

    pAuthInfo = pAuth->buffer;
    authInfoLen = pAuth->size;

    /* Concatenate session key and authValue */
    hmacKeyLen = pSession->keyLen + authInfoLen;

    if (hmacKeyLen > 0)
    {
        if (OK != (status = DIGI_CALLOC((void **)&pHmacKey, 1, hmacKeyLen)))
        {
            DB_PRINT("SAPI2_HMAC_computeCommandResponseHMAC: Unable to allocate %d bytes for hmac key! status = %d\n",
                    hmacKeyLen, (int)status);
            goto exit;
        }
        if (pSession->keyLen)
        {
            if (OK != (status =
                    DIGI_MEMCPY(&(pHmacKey[0]), pSession->sessionKey, pSession->keyLen)))
            {
                DB_PRINT("SAPI2_HMAC_computeCommandResponseHMAC: Failed to copy session key, status = %d\n"
                        , (int)status);
                goto exit;
            }
        }

        if (authInfoLen)
        {
            if (OK != (status =
                    DIGI_MEMCPY(&(pHmacKey[pSession->keyLen]), pAuthInfo, authInfoLen)))
            {
                DB_PRINT("SAPI2_HMAC_computeCommandResponseHMAC: Failed to copy authInfo, status = %d\n"
                        , (int)status);
                goto exit;
            }
        }
    }

    /* Concatenate cpHash, NonceNewer, NonceOlder and session attributes */
    hmacBufLen = pCRPHash->size + pSession->nonceNewer.size + pSession->nonceOlder.size + sizeof(pSession->attributes);

    if (OK != (status = DIGI_CALLOC((void **)&pHmacBuf, 1, hmacBufLen)))
    {
        DB_PRINT("SAPI2_HMAC_computeCommandResponseHMAC: Unable to allocate %d bytes for hmac buffer! status = %d\n",
                hmacBufLen, (int)status);
        goto exit;
    }
    offset = 0;
    if (OK != (status = DIGI_MEMCPY(&(pHmacBuf[0]), pCRPHash->buffer, pCRPHash->size)))
    {
        DB_PRINT("SAPI2_HMAC_computeCommandResponseHMAC: Failed to copy cp/rpHash, status = %d\n"
                , (int)status);
        goto exit;
    }

    offset += pCRPHash->size;
    if (OK != (status =
            DIGI_MEMCPY(&(pHmacBuf[offset]), pSession->nonceNewer.buffer, pSession->nonceNewer.size)))
    {
        DB_PRINT("SAPI2_HMAC_computeCommandResponseHMAC: Failed to copy nonceNewer, status = %d\n"
                , (int)status);
        goto exit;
    }

    offset += pSession->nonceNewer.size;
    if (OK != (status =
            DIGI_MEMCPY(&(pHmacBuf[offset]), pSession->nonceOlder.buffer, pSession->nonceOlder.size)))
    {
        DB_PRINT("SAPI2_HMAC_computeCommandResponseHMAC: Failed to copy nonceOlder, status = %d\n"
                , (int)status);
        goto exit;
    }

    offset += pSession->nonceOlder.size;
    if (OK != (status =
            DIGI_MEMCPY(&(pHmacBuf[offset]), &pSession->attributes, sizeof(pSession->attributes))))
    {
        DB_PRINT("SAPI2_HMAC_computeCommandResponseHMAC: Failed to copy session attributes, status = %d\n"
                , (int)status);
        goto exit;
    }

    offset += sizeof(pSession->attributes);

    /* run the HMAC function */
    if (OK != (status = HmacQuick(MOC_HASH(hwAccelCtx) pHmacKey, hmacKeyLen,
            (const ubyte*)pHmacBuf, (sbyte4)hmacBufLen, pResult->buffer,
            pBulkHashAlgo)))
    {
        DB_PRINT("SAPI2_HMAC_computeCommandResponseHMAC: Unable to compute HMAC! status = %d\n",
                (int)status);
        goto exit;
    }

    pResult->size = pSession->digestSize;

exit:
    
#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    (void) HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);
#endif
    
    if (pHmacBuf)
    {
        if (OK != (status =
                shredMemory((ubyte **)&pHmacBuf, hmacBufLen, TRUE)))
        {
            DB_PRINT("%s.%d Failed to shredMemory, rc 0x%02x = %s\n",
                    __FUNCTION__, __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
    }

    if (pHmacKey)
    {
        if (OK != (status =
                shredMemory((ubyte **)&pHmacKey, hmacKeyLen, TRUE)))
        {
            DB_PRINT("%s.%d Failed to shredMemory, rc 0x%02x = %s\n",
                    __FUNCTION__, __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
    }

    status = DIGI_MEMSET((ubyte *)hash_element, 0, sizeof(hash_element));

    return status;
}

#endif /* (defined(__ENABLE_DIGICERT_TPM2__) */
