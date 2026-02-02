/**
 * @file sapi2_hash.c
 * @brief This file contains SAPI HASH related functions for TPM2.
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

#if (defined(__ENABLE_DIGICERT_TPM2__) || defined(__ENABLE_DIGICERT_SMP_PKCS11__))

#ifdef __ENABLE_DIGICERT_SMP_PKCS11__
#define __ENABLE_DIGICERT_TPM2__
#endif

#include "../../../../common/mtypes.h"
#include "../../../../common/mdefs.h"
#include "../../../../common/merrors.h"
#include "../../../../common/mrtos.h"
#include "../../../../common/mstdlib.h"
#include "../../../../common/debug_console.h"
#include "../../../../common/base64.h"
#include "../../../../common/mocana.h"
#include "../../../../crypto/hw_accel.h"
#include "../../../../common/random.h"
#include "../../../../common/vlong.h"
#include "../../../../crypto/crypto.h"
#include "../tpm_common/tpm_error_utils.h"
#include "../tpm2_types.h"
#include "sapi2_hmac.h"
#include "sapi2_hash.h"
#include "sapi2_utils.h"

/**
 * @brief Function to compute HASH
 *
 */
MSTATUS
SAPI2_HASH_computeHASH(TPM2_ALG_ID algId, HASH_ELEMENT *pHashElement, ubyte4 maxHashElements,
        ubyte *pHashOutput, ubyte4 hashLen)
{
    MSTATUS status = OK;
    const BulkHashAlgo *pBulkHashAlgo = NULL;
    BulkCtx bulkCtx = NULL;
    ubyte4 numHashElements = 0;
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    
#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    /* just in case build uses both TAP and hwAccel */
    hwAccelDescr hwAccelCtx = 0;
#endif
    
    if ((NULL == pHashElement) || (NULL == pHashOutput))
    {
        status = ERR_INVALID_ARG;
        goto exit;
    }
    
#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    status = (MSTATUS) HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx);
    if (OK != status)
        goto exit;
#endif

    rc = SAPI2_UTILS_getHashAlg(algId, &pBulkHashAlgo);
    if (TSS2_RC_SUCCESS != rc)
    {
        status = ERR_INTERNAL_ERROR;
        DB_PRINT("SAPI2_HASH_computeHASH: Failed to get hash algorithm! status = %d\n",
                (int)status);
        goto exit;
    }

    if (pBulkHashAlgo)
    {
        if (pBulkHashAlgo->digestSize > hashLen)
        {
            status = ERR_INVALID_ARG;
            DB_PRINT("SAPI2_HASH_computeHASH: Insufficient space in output digest buffer! status = %d\n",
                    (int)status);
            goto exit;
        }

        /* Allocate Digest */
        if (OK != (status = pBulkHashAlgo->allocFunc(MOC_HASH(hwAccelCtx) &bulkCtx)))
        {
            DB_PRINT("SAPI2_HASH_computeHASH: failed to allocate digest! status = %d\n", (int)status);
            goto exit;
        }

        /* Initialize Digest */
        if (OK != (status = pBulkHashAlgo->initFunc(MOC_HASH(hwAccelCtx) bulkCtx)))
        {
            DB_PRINT("SAPI2_HASH_computeHASH: failed to initialize digest! status = %d\n", (int)status);
            goto exit;
        }

        /* Compute digest over all the input buffers */
        while((numHashElements < maxHashElements) && (pHashElement->pBuf))
        {
            if (OK != (status = pBulkHashAlgo->updateFunc(MOC_HASH(hwAccelCtx) bulkCtx, pHashElement->pBuf, pHashElement->bufLen)))
            {
                DB_PRINT("SAPI2_HASH_computeHASH: failed to update digest! status = %d\n", (int)status);
                goto exit;
            }

            pHashElement++;
            numHashElements++;
        }

        /* Finalize Digest */
        if (OK != (status = pBulkHashAlgo->finalFunc(MOC_HASH(hwAccelCtx) bulkCtx, pHashOutput)))
        {
            DB_PRINT("SAPI2_HASH_computeHASH: failed to finalize digest! status = %d\n", (int)status);
            goto exit;
        }
    }

exit:
    
#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    (void) HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);
#endif
    
    if (pBulkHashAlgo && bulkCtx)
        pBulkHashAlgo->freeFunc(MOC_HASH(hwAccelCtx) &bulkCtx);

    return status;
}

/**
 * @brief Function to compute command/response parameter cpHash/rpHash
 *
 */
MSTATUS
SAPI2_HASH_computeHashEx(MOCTPM2_SESSION *pSession, TPM2_RC responseCode,
        TPM2_CC commandCode, TPM2B_NAME **ppNames, ubyte4 numNames, 
        HASH_ELEMENT *pParms, ubyte4 maxParms, TPM2B_DIGEST *pResult)
{
    MSTATUS status = OK;
    const BulkHashAlgo *pBulkHashAlgo = NULL;
    BulkCtx bulkCtx = NULL;
    ubyte4 numHashElements = 0;
    ubyte4 htonlval;
    TPM2B_NAME *pNames;
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    
#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    /* just in case build uses both TAP and hwAccel */
    hwAccelDescr hwAccelCtx = 0;
#endif
    
    if ((NULL == pSession) || (NULL == pResult))
    {
        status = ERR_INVALID_ARG;
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
        DB_PRINT("SAPI2_HASH_computeHASH: Failed to get hash algorithm! status = %d\n",
                (int)status);
        goto exit;
    }

    if (pBulkHashAlgo)
    {
        if (pBulkHashAlgo->digestSize > sizeof(pResult->buffer))
        {
            status = ERR_INVALID_ARG;
            DB_PRINT("SAPI2_HASH_computeHashEx: Insufficient space in output digest buffer! status = %d\n",
                    (int)status);
            goto exit;
        }

        /* Allocate Digest */
        if (OK != (status = pBulkHashAlgo->allocFunc(MOC_HASH(hwAccelCtx) &bulkCtx)))
        {
            DB_PRINT("SAPI2_HASH_computeHashEx: failed to allocate digest! status = %d\n", (int)status);
            goto exit;
        }

        /* Initialize Digest */
        if (OK != (status = pBulkHashAlgo->initFunc(MOC_HASH(hwAccelCtx) bulkCtx)))
        {
            DB_PRINT("SAPI2_HASH_computeHashEx: failed to initialize digest! status = %d\n", (int)status);
            goto exit;
        }

        /*
         * Per the spec: rpHashes are only required to be calculated if
         * the return code is TPM2_RC_SUCCESS, which is 0. it is
         * redundant and included only for legacy reasins. For this
         * function, we assume that we are calculating rpHASH if the
         * response code is zero. For non-zero response codes, we assume
         * the caller is attempting to calculate cpHASH
         */
        if (responseCode == 0)
        {
            /* compute digest for response code if enabled */
            htonlval = responseCode;
            if (OK != (status = pBulkHashAlgo->updateFunc(MOC_HASH(hwAccelCtx) bulkCtx, (const ubyte *)&htonlval, sizeof(htonlval))))
            {
                DB_PRINT("SAPI2_HASH_computeHashEx: failed to update digest over command code! status = %d\n", (int)status);
                goto exit;
            }
        }

        /* compute digest for command code */
	DIGI_HTONL((ubyte *)&htonlval, commandCode);
        if (OK != (status = pBulkHashAlgo->updateFunc(MOC_HASH(hwAccelCtx) bulkCtx, (const ubyte *)&htonlval, sizeof(htonlval))))
        {
            DB_PRINT("SAPI2_HASH_computeHashEx: failed to update digest over command code! status = %d\n", (int)status);
            goto exit;
        }

        if (ppNames)
        {
            /* Compute digest over all names */
            while (numNames)
            {
                pNames = *ppNames;
                if (pNames)
                {
                    if (OK != (status = pBulkHashAlgo->updateFunc(MOC_HASH(hwAccelCtx) bulkCtx, pNames->name, pNames->size)))
                    {
                        DB_PRINT("SAPI2_HASH_computeHashEx: failed to update digest over names! status = %d\n", (int)status);
                        goto exit;
                    }
                }

                ppNames++;
                numNames--;
            }
        }

        if (pParms)
        {
            /* Compute digest over all the parameters */
            while((numHashElements < maxParms) && (pParms->pBuf))
            {
                if (OK != (status = pBulkHashAlgo->updateFunc(MOC_HASH(hwAccelCtx) bulkCtx, pParms->pBuf, pParms->bufLen)))
                {
                    DB_PRINT("SAPI2_HASH_computeHashEx: failed to update digest over parameters! status = %d\n", (int)status);
                    goto exit;
                }

                pParms++;
                numHashElements++;
            }
        }

        /* Finalize Digest */
        if (OK != (status = pBulkHashAlgo->finalFunc(MOC_HASH(hwAccelCtx) bulkCtx, pResult->buffer)))
        {
            DB_PRINT("SAPI2_HASH_computeHashEx: failed to finalize digest! status = %d\n", (int)status);
            goto exit;
        }

        pResult->size = pSession->digestSize;
    }

exit:
    
#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    (void) HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);
#endif
    
    if (pBulkHashAlgo && bulkCtx)
        pBulkHashAlgo->freeFunc(MOC_HASH(hwAccelCtx) &bulkCtx);

    return status;
}

/**
 * @brief Function to compute command parameter cpHash
 *
 */
MSTATUS
SAPI2_HASH_computeCmdPHash(MOCTPM2_SESSION *pSession,
        TPM2_CC commandCode, TPM2B_NAME **ppNames, ubyte4 numNames, 
        HASH_ELEMENT *pParms, ubyte4 maxParms, TPM2B_DIGEST *pResult)
{
    return SAPI2_HASH_computeHashEx(pSession, 1, commandCode, ppNames,
            numNames, pParms, maxParms, pResult);
}

/**
 * @brief Function to compute response parameter rpHash
 *
 */
MSTATUS
SAPI2_HASH_computeRspPHash(MOCTPM2_SESSION *pSession,
        TPM2_CC commandCode, TPM2_CC responseCode, HASH_ELEMENT *pParms, 
        ubyte4 maxParms, TPM2B_DIGEST *pResult)
{
    /*
     * Per the spec: rpHashes are only required to be calculated if
     * the return code is TPM2_RC_SUCCESS, which is 0. it is
     * redundant and included only for legacy reasins. For this
     * function, we assume that we are calculating rpHASH if the
     * response code is zero. For non-zero response codes, we assume
     * the caller is attempting to calculate cpHASH
     */

    return SAPI2_HASH_computeHashEx(pSession, responseCode,
            commandCode, NULL, 0, pParms, maxParms, pResult);
}

#endif /* (defined(__ENABLE_DIGICERT_TPM2__)) */
