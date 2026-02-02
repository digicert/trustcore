/**
 * @file sapi2_session.c
 * @brief This file contains SAPI2 session management functions for TPM2.
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
#include "../../../../common/merrors.h"
#include "../../../../common/mocana.h"
#include "../../../../common/mdefs.h"
#include "../../../../common/mstdlib.h"
#include "../../../../common/debug_console.h"
#include "../../../../common/mocana.h"
#include "../../../../crypto/hw_accel.h"
#include "../tpm_common/tpm_error_utils.h"
#include "sapi2_session.h"
#include "sapi2_utils.h"
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../../../../crypto_interface/cryptointerface.h"
#endif

static TSS2_RC SAPI2_SESSION_getSessionSalt(
        MOCTPM2_OBJECT_HANDLE *pSaltKey,
        TPM2B_DIGEST *pSeed,
        TPM2B_ENCRYPTED_SECRET *pEncryptedSeed
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    ubyte oaepHashOid = 0;
    const BulkHashAlgo *pHashAlgOut = NULL;
    RSAKey *pRsaKey = NULL;
#ifdef __ENABLE_DIGICERT_ECC__
    ECCKey *pEccKey = NULL;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    ubyte4 eccCurveId;
#else
    PEllipticCurvePtr pECcurve = NULL;
#endif
#endif
#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    hwAccelDescr hwAccelCtx = 0;
#endif

    if (!pSeed || !pSaltKey || !pEncryptedSeed)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    if (0 != HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("Unable to open hardware acceleration channel.\n",
                 __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }
#endif
    
    /*
     * Get nameAlg digest, that us used for both OAEP RSA encryption
     * and for KDFe for ECDH.
     */
    rc = SAPI2_UTILS_getHashAlgFromAlgId(
            pSaltKey->publicArea.objectPublicArea.nameAlg,
            &pHashAlgOut, &oaepHashOid);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to get hash algorithm Oid, "
                "rc 0x%02x = %s\n", __FUNCTION__, __LINE__, rc,
                tss2_err_string(rc));
        goto exit;
    }

    /*
     * Generate salt and encrypted salt.
     */
    switch (pSaltKey->publicArea.objectPublicArea.type)
    {
    case TPM2_ALG_RSA:
        rc = SAPI2_UTILS_convertTpm2RsaPublicToRSAKey( MOC_RSA(hwAccelCtx)
                &(pSaltKey->publicArea.objectPublicArea.unique.rsa), &pRsaKey,
                pSaltKey->publicArea.objectPublicArea.parameters.rsaDetail.exponent);
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed to covert TPM2 RSA key to mocana RSA key, "
                    "rc 0x%02x = %s\n", __FUNCTION__, __LINE__, rc,
                    tss2_err_string(rc));
            goto exit;
        }

        pSeed->size = pHashAlgOut->digestSize;
        rc = SAPI2_UTILS_generateRsaSeed(MOC_RSA(hwAccelCtx) pRsaKey, oaepHashOid,
                (const ubyte *)"SECRET", sizeof("SECRET"),
                pSeed->buffer, pSeed->size,
                pEncryptedSeed);
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed to get seed for RSA salt key, "
                    "rc 0x%02x = %s\n", __FUNCTION__, __LINE__, rc,
                    tss2_err_string(rc));
            goto exit;
        }
        break;
#ifdef __ENABLE_DIGICERT_ECC__
    case TPM2_ALG_ECC:
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        rc =SAPI2_UTILS_getECCurveFromTpm2EccCurveID(
                pSaltKey->publicArea.objectPublicArea.parameters.eccDetail.curveID,
                &eccCurveId);
#else
        rc =SAPI2_UTILS_getECCurveFromTpm2EccCurveID(
                pSaltKey->publicArea.objectPublicArea.parameters.eccDetail.curveID,
                &pECcurve);
#endif
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed to get EC Curve, "
                    "rc 0x%02x = %s\n", __FUNCTION__, __LINE__, rc,
                    tss2_err_string(rc));
            goto exit;
        }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        rc = SAPI2_UTILS_convertTpm2EccPublicToEccKey( MOC_ECC(hwAccelCtx)
                &(pSaltKey->publicArea.objectPublicArea.unique.ecc),
                eccCurveId,
                &pEccKey
                );
#else
        rc = SAPI2_UTILS_convertTpm2EccPublicToEccKey( MOC_ECC(hwAccelCtx)
                &(pSaltKey->publicArea.objectPublicArea.unique.ecc),
                pECcurve,
                &pEccKey
                );
#endif
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed to get convert ECC salt key, "
                    "rc 0x%02x = %s\n", __FUNCTION__, __LINE__, rc,
                    tss2_err_string(rc));
            goto exit;
        }

        pSeed->size = pHashAlgOut->digestSize;
        rc = SAPI2_UTILS_generateECCSeed( MOC_ECC(hwAccelCtx) pEccKey,
                (const ubyte *)"SECRET", sizeof("SECRET"),
                pSaltKey->publicArea.objectPublicArea.nameAlg,
                pSeed->buffer, pSeed->size,
                pEncryptedSeed);
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed to generate ECC salt,"
                    "rc 0x%02x = %s\n", __FUNCTION__, __LINE__, rc,
                    tss2_err_string(rc));
            goto exit;
        }
        break;
#endif
    default:
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid handle for salting key, "
                "rc 0x%02x = %s\n", __FUNCTION__, __LINE__, rc,
                tss2_err_string(rc));
        goto exit;
        break;
    }

    rc = TSS2_RC_SUCCESS;
exit:
#ifdef __ENABLE_DIGICERT_ECC__
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (pEccKey)
        CRYPTO_INTERFACE_EC_deleteKey((void **) &pEccKey, akt_ecc);
#else
    if (pEccKey)
        EC_deleteKey(&pEccKey);
#endif
#endif
    if (pRsaKey)
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_RSA_freeKey((void **)&pRsaKey, NULL, akt_rsa);
#else
        RSA_freeKey(&pRsaKey, NULL);
#endif
    
#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    (void) HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);
#endif
    
    return rc;
}

TSS2_RC SAPI2_SESSION_StartAuthSession(
        SAPI2_CONTEXT *pSapiContext,
        StartAuthSessionIn *pIn,
        StartAuthSessionOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;

    TPM2_COMMAND_HEADER cmdHeader = { 0 };
    TPM2_START_AUTH_SESSION_CMD_HANDLES cmdHandles = { 0 };
    TPM2_START_AUTH_SESSION_CMD_PARAMS cmdParams = { 0 };

    TPM2_RESPONSE_HEADER rspHeader = { 0 };
    TPM2_START_AUTH_SESSION_RSP_HANDLES rspHandles = { 0 };
    TPM2_START_AUTH_SESSION_RSP_PARAMS rspParams = { 0 };

    /* TPM2_StartAuthSession has 2 handles */
    TPM2B_NAME *pHandleNames[2] = { 0 };

    sapi2_cmd_desc cmdDesc = { 0 };
    sapi2_rsp_desc rspDesc = { 0 };

    MOCTPM2_SESSION *pNewSession = NULL;
    const BulkHashAlgo *pBulkHashAlgo = NULL;

    TPM2B_DIGEST salt = { 0 };

    if ((NULL == pIn) || (NULL == pOut) || (NULL == pSapiContext))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (OK != DIGI_CALLOC((void **)&pNewSession, 1, sizeof(MOCTPM2_SESSION)))
    {
        rc = TSS2_SYS_RC_IO_ERROR;
        DB_PRINT("%s.%d Invalid to allocate memory for session struct,"
                " rc 0x%02x = %s\n", __FUNCTION__, __LINE__,
                rc, tss2_err_string(rc));
        goto exit;
    }

    /* Compile Header Structure */

    /* For now we don't support session during this command */
    cmdHeader.tag = TPM2_ST_NO_SESSIONS;

    /* Fill in 0 initially, the command size must only be filled in
     * after serialization.
     */
    cmdHeader.commandCode = 0;
    cmdHeader.commandCode = TPM2_CC_StartAuthSession;

    /* Compile Handle Structure */
    cmdHandles.tpmKey = TPM2_RH_NULL;

    if (pIn->pTpmKey)
    {
        if (!IS_TPM2_PERSISTENT_HANDLE(pIn->pTpmKey->tpm2Handle) &&
                !IS_TPM2_TRANSIENT_HANDLE(pIn->pTpmKey->tpm2Handle))
        {
            rc = TSS2_SYS_RC_BAD_VALUE;
            DB_PRINT("%s.%d Invalid handle for encryption key, "
                    "rc 0x%02x = %s\n", __FUNCTION__, __LINE__, rc,
                    tss2_err_string(rc));
            goto exit;
        }

        rc = SAPI2_SESSION_getSessionSalt(pIn->pTpmKey, &salt, &cmdParams.encryptedSalt);
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed to generate salt, "
                    "rc 0x%02x = %s\n", __FUNCTION__, __LINE__, rc,
                    tss2_err_string(rc));
            goto exit;
        }

        cmdHandles.tpmKey = pIn->pTpmKey->tpm2Handle;
        pHandleNames[0] = &pIn->pTpmKey->objectName;

    }

    cmdHandles.bind = TPM2_RH_NULL;

    if (pIn->pBind)
    {
        if (!IS_VALID_TPM2_HANDLE(pIn->pBind->tpm2Handle))
        {
            rc = TSS2_SYS_RC_BAD_VALUE;
            DB_PRINT("%s.%d Invalid handle for bind entity,"
                    " rc 0x%02x = %s\n", __FUNCTION__, __LINE__,
                    rc, tss2_err_string(rc));
            goto exit;
        }
        cmdHandles.bind = pIn->pBind->tpm2Handle;
        pHandleNames[1] = &pIn->pBind->objectName;
    }

    /* Compile parameters structure */
    if (pIn->nonceCaller.size > sizeof(cmdParams.nonceCaller.buffer))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid nonce size, rc 0x%02x = %s\n",
                __FUNCTION__, __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (pIn->nonceCaller.size > 0)
    {
        cmdParams.nonceCaller = pIn->nonceCaller;
    }

    cmdParams.sessionType = pIn->sessionType;
    cmdParams.symmetric = pIn->symmetric;
    cmdParams.authHash = pIn->authHash;

    /* Assemble command descriptor */
    cmdDesc.pUnserializedHeader = &cmdHeader;
    cmdDesc.pUnserializedHandles = (ubyte *)&cmdHandles;
    cmdDesc.UnserializedHandlesSize = sizeof(cmdHandles);
    cmdDesc.ppNames = pHandleNames;
    cmdDesc.numHandlesAndNames = 2;
    cmdDesc.handlesType = SAPI2_ST_TPM2_START_AUTH_SESSION_CMD_HANDLES;
    cmdDesc.pUnserializedParameters = (ubyte *)&cmdParams;
    cmdDesc.UnserializedParametersSize = sizeof(cmdParams);
    cmdDesc.parametersType = SAPI2_ST_TPM2_START_AUTH_SESSION_CMD_PARAMS;

    /* Assemble response descriptor */
    rspDesc.commandCode = TPM2_CC_StartAuthSession;
    rspDesc.pUnserializedHeader = &rspHeader;
    rspDesc.pUnserializedHandles = (ubyte *)&rspHandles;
    rspDesc.UnserializedHandlesSize = sizeof(rspHandles);
    rspDesc.handlesType = SAPI2_ST_TPM2_START_AUTH_SESSION_RSP_HANDLES;
    rspDesc.pUnserializedParameters = (ubyte *)&rspParams;
    rspDesc.UnserializedParametersSize = sizeof(rspParams);
    rspDesc.parametersType = SAPI2_ST_TPM2_START_AUTH_SESSION_RSP_PARAMS;

    rc = SAPI2_CONTEXT_executeCommand(pSapiContext, &cmdDesc, &rspDesc);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to execute command, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    rc = SAPI2_UTILS_getHashAlg(cmdParams.authHash, &pBulkHashAlgo);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to get hash algorithm object, "
                "rc 0x%02x = %s\n", __FUNCTION__, __LINE__, rc,
                tss2_err_string(rc));
        goto exit;
    }

    pNewSession->hashAlgId = cmdParams.authHash;
    pNewSession->digestSize = pBulkHashAlgo->digestSize;
    pNewSession->nonceOlder = cmdParams.nonceCaller;
    pNewSession->nonceNewer = rspParams.nonceTPM;
    pNewSession->sessionType = pIn->sessionType;
    pNewSession->sessionHaspolicyAuthValue = FALSE;

    /*
     * Calculate session Key. If tmpKey and bind are NULL
     * the sessionKey is an empty buffer
     */

    /*
     * We only support unbound, unsalted or salted sessions. Bound
     * sessions provide little value, especially when we have salted
     * sessions and the expectation is that bound sessions will be
     * rarely used. Salted sessions themselves have limited use unless
     * the TPM is a remote TPM and we are communicating to the TPM
     * over an insecure channel. We support it here as a defense in depth
     * mechanism.
     * In most use cases, an application will talk to a local TPM
     * and salted sessions provide limited value since operating systems
     * can read the application memory entirely anyway, which means the
     * sessionKey can be compromised. If we trust the OS to not read
     * application memory, we can also trust it to isolate application
     * memory correctly to avoid another application stealing secrets.
     */
    if (pIn->pTpmKey)
    {
        pNewSession->keyLen = pNewSession->digestSize;

        if (TSS2_RC_SUCCESS != (rc = SAPI2_UTILS_TPM2_KDFA(pNewSession->hashAlgId,
                salt.buffer, salt.size,
                (const char *)"ATH",
                pNewSession->nonceNewer.buffer, pNewSession->nonceNewer.size,
                pNewSession->nonceOlder.buffer, pNewSession->nonceOlder.size,
                pNewSession->sessionKey, pNewSession->keyLen
                )))
        {
            DB_PRINT("%s.%d Failed to generate session key, rc 0x%02x = %s\n", __FUNCTION__,
            __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
    }

    /*
     * Session handles dont have a public area, so we pass NULL to
     * SAPI2_HANDLES_CreateObjectHandle.
     */
    pOut->pSessionHandle = NULL;
    rc = SAPI2_HANDLES_createObjectHandle(rspHandles.sessionHandle, NULL,
            &pOut->pSessionHandle);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to create object handle for session, "
                "rc 0x%02x = %s\n", __FUNCTION__, __LINE__, rc,
                tss2_err_string(rc));
        goto exit;
    }

    pOut->pSessionHandle->pMetadata = (void *)pNewSession;
    pOut->pSessionHandle->metaDataSize = sizeof(*pNewSession);
    pOut->pSessionHandle->type = MOCTPM2_OBJ_METADATA_TYPE_SESSION;

    rc = TSS2_RC_SUCCESS;
exit:
    if (TSS2_RC_SUCCESS != rc)
    {
        if (pNewSession)
        {
            if (OK != shredMemory((ubyte **)&pNewSession,
                    sizeof(MOCTPM2_SESSION), TRUE))
            {
                rc = TSS2_SYS_RC_IO_ERROR;
                DB_PRINT("%s.%d Failed to shredMemory, rc 0x%02x = %s\n",
                        __FUNCTION__, __LINE__, rc, tss2_err_string(rc));
            }
        }
        if (pOut && pOut->pSessionHandle)
        {
            SAPI2_HANDLES_destroyHandle(&pOut->pSessionHandle, FALSE);
            pOut->pSessionHandle = NULL;
        }
    }

    return rc;
}

static TSS2_RC SAPI2_SESSION_modifySessionAttributes(
        MOCTPM2_OBJECT_HANDLE *pSessionHandle,
        TPMA_SESSION attributes,
        byteBoolean setBits
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    MOCTPM2_SESSION *pSession = NULL;
    TPMA_SESSION supportedAttrMask = TPMA_SESSION_CONTINUESESSION;

    if (NULL == pSessionHandle)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Bad session handle pointer, rc 0x%02x = %s\n",
                       __FUNCTION__, __LINE__, rc,
                       tss2_err_string(TSS2_SYS_RC_BAD_REFERENCE));
        goto exit;
    }

    if ((pSessionHandle->type != MOCTPM2_OBJ_METADATA_TYPE_SESSION) ||
            (pSessionHandle->metaDataSize != sizeof(MOCTPM2_SESSION)) ||
            ((attributes & ~supportedAttrMask) != 0))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid session handle rc 0x%02x = %s\n",
                       __FUNCTION__, __LINE__, rc,
                       tss2_err_string(TSS2_SYS_RC_BAD_REFERENCE));
        goto exit;
    }

    pSession = (MOCTPM2_SESSION *)pSessionHandle->pMetadata;
    if (setBits)
        pSession->attributes = attributes;
    else
        pSession->attributes &= ~attributes;

    rc = TSS2_RC_SUCCESS;

exit:
    return rc;
}

TSS2_RC SAPI2_SESSION_setSessionAttributes(
        MOCTPM2_OBJECT_HANDLE *pSessionHandle,
        TPMA_SESSION attributes
)
{
    return SAPI2_SESSION_modifySessionAttributes(pSessionHandle,
            attributes, TRUE);
}

TSS2_RC SAPI2_SESSION_clearSessionAttributes(
        MOCTPM2_OBJECT_HANDLE *pSessionHandle,
        TPMA_SESSION attributes
)
{
    return SAPI2_SESSION_modifySessionAttributes(pSessionHandle,
                attributes, FALSE);
}

TSS2_RC SAPI2_SESSION_getNonceNewer(
        MOCTPM2_OBJECT_HANDLE *pSessionHandle,
        TPM2B_NONCE **ppNonceNewer
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    MOCTPM2_SESSION *pSession = NULL;

    if (NULL == pSessionHandle || ( !ppNonceNewer) || (*ppNonceNewer))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Bad session handle pointer, rc 0x%02x = %s\n",
                       __FUNCTION__, __LINE__, rc,
                       tss2_err_string(TSS2_SYS_RC_BAD_REFERENCE));
        goto exit;
    }

    if ((pSessionHandle->type != MOCTPM2_OBJ_METADATA_TYPE_SESSION) ||
            (pSessionHandle->metaDataSize != sizeof(MOCTPM2_SESSION)))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid session handle rc 0x%02x = %s\n",
                       __FUNCTION__, __LINE__, rc,
                       tss2_err_string(TSS2_SYS_RC_BAD_REFERENCE));
        goto exit;
    }

    pSession = (MOCTPM2_SESSION *)pSessionHandle->pMetadata;

    *ppNonceNewer = &pSession->nonceNewer;

    rc = TSS2_RC_SUCCESS;

exit:
    return rc;

}
#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */
