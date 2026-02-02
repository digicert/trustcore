/**
 * @file fapi2_hmac.c
 * @brief This file contains code and structures required for creating and using the TPM2
 * as a symmetric crypto engine
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
#include "../tpm_common/tpm_error_utils.h"
#include "fapi2.h"
#include "fapi2_internal.h"

/*
 * This API uses a symmetric key in the TPM to perform HMAC on the given data using given 
 * hash algorithm and the input key.
 */
TSS2_RC FAPI2_SYM_Hmac(
        FAPI2_CONTEXT *pCtx,
        SymHmacIn *pIn,
        SymHmacOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TSS2_RC exit_rc = TSS2_RC_SUCCESS;
    TPMI_ALG_HASH hashAlg = TPM2_ALG_NULL;
    TPMT_PUBLIC *pPublic = NULL;
    FAPI2_OBJECT *pKey = NULL;
    MOCTPM2_OBJECT_HANDLE *pKeyHandle = NULL;
    MOCTPM2_OBJECT_HANDLE *pAuthSession = NULL;
    HmacIn hmacIn = { 0 };
    HmacOut hmacOut = { 0 };
    TPM2B_MAX_BUFFER *pMaxBuffer = NULL;
    ubyte *pOutput = NULL;
    ContextFlushObjectIn flushObjectIn = { 0 };
    ubyte4 outSize = 0;

    if (!pCtx || !pIn || !pOut)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    TPM2B_SIZE_CHECK(&pIn->keyName, TPM2B_MAX_SIZE(&pIn->keyName));

    if ((pIn->bufferLen == 0) || (NULL == pIn->pBuffer))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid buffer length or buffer specified, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    rc = FAPI2_CONTEXT_lookupObject(pCtx, &pIn->keyName, &pKey);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Unable to find key object, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /*
     * Make sure authValue is set.
     */
    if ((pKey->authValueRequired) && (!pKey->authValueValid))
    {
        rc = TSS2_FAPI_RC_NOT_PERMITTED;
        DB_PRINT("%s.%d Key does not have authValue set, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pPublic = &pKey->public.objectPublic.publicArea;

    if ((pPublic->type != TPM2_ALG_KEYEDHASH) ||
            (pPublic->objectAttributes & TPMA_OBJECT_RESTRICTED) ||
            (pPublic->parameters.keyedHashDetail.scheme.scheme != TPM2_ALG_HMAC))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid key type provided, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (OK != DIGI_CALLOC((void **)&pMaxBuffer, 1, sizeof(*pMaxBuffer)))
    {
        rc = TSS2_SYS_RC_INSUFFICIENT_BUFFER;
        DB_PRINT("%s.%d Failed to allocate memory"
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (pIn->bufferLen > TPM2_MAX_DIGEST_BUFFER)
    {
        rc = TSS2_SYS_RC_INSUFFICIENT_BUFFER;
        DB_PRINT("%s.%d input buffer too large"
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (OK != DIGI_MEMCPY(pMaxBuffer->buffer, pIn->pBuffer, pIn->bufferLen))
    {
        rc = TSS2_SYS_RC_GENERAL_FAILURE;
        goto exit;
    }
    pMaxBuffer->size = pIn->bufferLen;

    if (pIn->hashAlg == TPM2_ALG_NULL)
    {
        /* Get the hash algorithm from key, specified during creation */
        hashAlg = pPublic->parameters.keyedHashDetail.scheme.details.hmac.hashAlg;
    }
    else
    {
        hashAlg = pIn->hashAlg;
    }

    /* Figure out size of output buffer */
    switch (pIn->hashAlg)
    {
        case TPM2_ALG_SHA1:
            outSize = TPM2_SHA1_DIGEST_SIZE;
            break;

        case TPM2_ALG_SHA256:
            outSize = TPM2_SHA256_DIGEST_SIZE;
            break;

        case TPM2_ALG_SHA384:
            outSize = TPM2_SHA384_DIGEST_SIZE;
            break;

        case TPM2_ALG_SHA512:
            outSize = TPM2_SHA512_DIGEST_SIZE;
            break;

        case TPM2_ALG_SM3_256:
            outSize = TPM2_SM3_256_DIGEST_SIZE;
            break;

        default:
            rc = TSS2_SYS_RC_BAD_VALUE;
            DB_PRINT("%s.%d unsupported hash algorithm for key"
                    ", rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
            break;
    }

    /*
     * Allocate output buffer, must be equal to input buffer length.
     */
    if (OK != DIGI_CALLOC((void **)&pOutput, 1, outSize))
    {
        rc = TSS2_SYS_RC_INSUFFICIENT_BUFFER;
        DB_PRINT("%s.%d Failed to allocate memory"
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /*
     * Create handle for the child key. This will load the key into the TPM.
     */
    rc = FAPI2_UTILS_loadObjectTree(pCtx, pKey, &pKeyHandle);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to create handle for child key."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (!(pPublic->objectAttributes & TPMA_OBJECT_USERWITHAUTH))
    {
        rc = FAPI2_UTILS_getObjectAuthSession(pCtx, pKey, &pAuthSession);
    } 
    else
    {
        rc = FAPI2_UTILS_startSession(pCtx, &pAuthSession);
    }

    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to Start session."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    hmacIn.hashAlg = pIn->hashAlg;
    hmacIn.pInData = pMaxBuffer;
    hmacIn.pAuthSession = pAuthSession;
    hmacIn.pObjectHandle = pKeyHandle;
    hmacIn.pAuthObjectHandle = &pKey->authValue;

    rc = SAPI2_SYM_Hmac(pCtx->pSapiCtx, &hmacIn, &hmacOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to encrypt/decrypt buffer."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (hmacOut.outData.size != outSize)
    {
        rc = TSS2_SYS_RC_MALFORMED_RESPONSE;
        DB_PRINT("%s.%d Output data size not equal to expected HASH size"
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    DIGI_MEMCPY(pOutput, hmacOut.outData.buffer, outSize);
    pOut->pOutBuffer = pOutput;
    pOut->outLen = outSize;
    pOutput = NULL;

    rc = TSS2_RC_SUCCESS;
exit:

    if (pOutput && pIn && outSize)
        shredMemory((ubyte **)(&pOutput), outSize, TRUE);

    if (pMaxBuffer)
        shredMemory((ubyte **)(&pMaxBuffer), sizeof(*pMaxBuffer), TRUE);

    if (pAuthSession)
    {
        exit_rc = FAPI2_UTILS_closeSession(pCtx,
                &pAuthSession);
        if (TSS2_RC_SUCCESS == rc)
            rc = exit_rc;
    }

    if (pKeyHandle)
    {
        exit_rc = FAPI2_UTILS_destroyHandle(pCtx, &pKeyHandle);
        if (TSS2_RC_SUCCESS == rc)
            rc = exit_rc;
    }

    if (pKey)
    {
        flushObjectIn.objName = pKey->objectName;
        exit_rc = FAPI2_CONTEXT_flushObject(pCtx, &flushObjectIn);
    }

    if (TSS2_RC_SUCCESS == rc)
        rc = exit_rc;

    return rc;
}

#endif /* (defined(__ENABLE_DIGICERT_TPM2__)) */

