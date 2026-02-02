/**
 * @file sapi2_utils.c
 * @brief This file contains SAPI2 utility functions for TPM2.
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

/* TPM2 needs to be defined for certain definitions in the headers about to be included */
#ifdef __ENABLE_DIGICERT_SMP_PKCS11__
#define __ENABLE_DIGICERT_TPM2__
#endif

#include "../../../../common/mtypes.h"
#include "../../../../common/merrors.h"
#include "../../../../common/mocana.h"
#include "../../../../common/mdefs.h"
#include "../../../../common/mstdlib.h"
#include "../../../../common/mrtos.h"
#include "../../../../common/debug_console.h"
#include "../../../../common/base64.h"
#include "../../../../common/random.h"
#include "../../../../common/vlong.h"
#include "../../../../crypto/crypto.h"
#include "../../../../crypto/md5.h"
#include "../../../../crypto/sha1.h"
#include "../../../../crypto/sha256.h"
#include "../../../../crypto/sha512.h"
#include "../../../../crypto/hmac.h"
#include "../../../../crypto/hw_accel.h"
#include "../tpm_common/tpm_error_utils.h"
#include "../../../../crypto/nist_prf.h"
#include "../../../../crypto/nist_kdf.h"
#include "../../../../crypto/pubcrypto.h"
#include "../../../../crypto/pkcs1.h"
#include "sapi2_session.h"
#include "sapi2_utils.h"
#include "sapi2_handles.h"
#include "sapi2_hash.h"
#include "sapi2_hmac.h"
#include "sapi2_serialize.h"
#include "../tap_serialize_tpm2.h"
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../../../../crypto_interface/cryptointerface.h"
#include "../../../../crypto_interface/crypto_interface_pkcs1.h"
#endif

/* Remove TPM2 definition so we dont get unused code in PKCS11 build */
#ifdef __ENABLE_DIGICERT_SMP_PKCS11__
#undef __ENABLE_DIGICERT_TPM2__
#endif

static TSS2_RC SAPI2_UTILS_getName(void *pPublic, ubyte4 publicSize,
        TPM2B_NAME *pOutName, SAPI2_SERIALIZE_TYPE type,
        TPMI_ALG_HASH nameAlg);

#ifdef __ENABLE_DIGICERT_TPM2__

TSS2_RC SAPI2_UTILS_getNvName(TPM2_HANDLE handle,
        TPMS_NV_PUBLIC *pPublic, TPM2B_NAME *pOutName)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;

    if ((NULL == pPublic) || (NULL == pOutName))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid input pointers, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (!IS_TPM2_NV_HANDLE(handle))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid TPM NV handle, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    rc = SAPI2_UTILS_getName(pPublic, sizeof(TPMS_NV_PUBLIC),
            pOutName, SAPI2_ST_TPMS_NV_PUBLIC, pPublic->nameAlg);

exit:
    return rc;
}

/**
 * @brief Function to update Nonces
 * @details This function should be called after receiving a response from TPM and before computing Response HMAC
 *
 */
TSS2_RC
SAPI2_UTILS_updateNonces(MOCTPM2_SESSION *pSession, TPM2B_NONCE *pNonceNewer)
{
    TSS2_RC status = TSS2_SYS_RC_GENERAL_FAILURE;

    if ((NULL == pSession) || (NULL == pNonceNewer))
    {
        status = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d SAPI2_UTILS_updateNonce: Invalid input parameter!, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, status, tss2_err_string(status));
        goto exit;
    }

    if (pNonceNewer->size !=  pSession->nonceNewer.size)
    {
        status = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("SAPI2_UTILS_updateNonce: Nonce size mismatch Input size of %d != Session size of %d ! status = %d\n", (int)pNonceNewer->size, (int)pSession->nonceNewer.size, (int)status);
        goto exit;
    }

    if (OK !=
            DIGI_MEMCPY(pSession->nonceOlder.buffer, pSession->nonceNewer.buffer,
                    pSession->nonceOlder.size))
    {
        status = TSS2_SYS_RC_IO_ERROR;
        DB_PRINT("SAPI2_UTILS_updateNonce: failed nonceOlder memcpy "
                "nonce size = %d, session nonce size = %d, status = %d\n", (int)pNonceNewer->size, (int)pSession->nonceNewer.size, (int)status);
        goto exit;
    }

    if (OK !=
            DIGI_MEMCPY(pSession->nonceNewer.buffer, pNonceNewer->buffer, pSession->nonceNewer.size))
    {
        status = TSS2_SYS_RC_IO_ERROR;
        DB_PRINT("SAPI2_UTILS_updateNonce: failed nonceNewer memcpy "
                "nonce size = %d, session nonce size = %d, status = %d\n", (int)pNonceNewer->size, (int)pSession->nonceNewer.size, (int)status);
        goto exit;
    }

    status = TSS2_RC_SUCCESS;
exit:
    return status;
}

TSS2_RC SAPI2_UTILS_getCmdStream(
        sapi2_utils_cmd_context *pCmdCtx,
        ubyte4 *pCmdBufferSizeOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    ubyte *pCpBuffer = NULL;
    MSTATUS status = ERR_GENERAL;
    ubyte4 bytesWrittenCmdBuf = 0;
    ubyte4 bytesWrittenSerialized = 0;
    ubyte4 bytesWrittenCpBuffer = 0;
    ubyte i = 0;
    MOCTPM2_SESSION *pSession = NULL;
    HASH_ELEMENT cpHashElement = { 0 };
    TPM2B_DIGEST cpHash =  { 0 };
    TPM2B_NONCE nonceNewer = { 0 };
    TPM2B_AUTH authHmac = { 0 };
    TPMS_AUTH_COMMAND authArea = { 0 };
    ubyte4 authorizationSize = 0;
    ubyte4 authorizationSizeSerialized = 0;
    ubyte4 authorizationSizeOffset = 0;
    TPM2B_AUTH emptyAuth = { 0 };

    /* Make sure have random context */
    if (NULL == g_pRandomContext)
    {
        rc = TSS2_SYS_RC_INSUFFICIENT_CONTEXT;
        DB_PRINT("%s.%d do not have global randomContext, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((NULL == pCmdCtx) || (NULL == pCmdBufferSizeOut) ||
            (NULL == pCmdCtx->pCmdDesc))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid command context, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /* Header cannot be NULL for any command */
    if ((NULL == pCmdCtx->pCmdDesc->pUnserializedHeader) ||
            (NULL == pCmdCtx->pCmdStreamOut) || (0 == pCmdCtx->cmdStreamOutSize))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid header or command buffer pointers, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /*
     * If the number of handles is > 0, both names and handles must
     * be present.
     */
    if (pCmdCtx->pCmdDesc->numHandlesAndNames > 0)
    {
        if ((NULL == pCmdCtx->pCmdDesc->pUnserializedHandles) ||
                (NULL == pCmdCtx->pCmdDesc->ppNames) ||
                (0 == pCmdCtx->pCmdDesc->UnserializedHandlesSize))
        {
            rc = TSS2_SYS_RC_BAD_VALUE;
            DB_PRINT("%s.%d Invalid handles buffer pointers, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
    }

    if ((pCmdCtx->pCmdDesc->handlesType >= SAPI2_ST_END) ||
            (pCmdCtx->pCmdDesc->parametersType >= SAPI2_ST_END))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid handle types, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /*
     * Check if parameters are passed in. Commands such as
     * TPM2_NVUndefineSpace have handles but no parameters.
     */
    if (pCmdCtx->pCmdDesc->UnserializedParametersSize > 0)
    {
        if (NULL == pCmdCtx->pCmdDesc->pUnserializedParameters)
        {
            rc = TSS2_SYS_RC_BAD_VALUE;
            DB_PRINT("%s.%d Invalid parameter buffer pointers, rc 0x%02x = %s\n", __FUNCTION__,
                    __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        /*
         * Allocate UnserializedParametersSize bytes for command parameters
         * serialized buffer. The serialized buffer should be no more than
         * the unserialized buffer. We allocate a separate buffer for command
         * parameters since this buffer must be placed after the authorization
         * area in the command stream. The authorization area cannot be
         * constructed without the serialized command parameters buffer hash
         * pr cpHash. So we allocate a separate buffer temporarily, calculate
         * the cpHash, construct the authorization area and then free it.
         */
        if (OK != DIGI_CALLOC((void **)&pCpBuffer, 1,
                pCmdCtx->pCmdDesc->UnserializedParametersSize))
        {
            rc = TSS2_SYS_RC_IO_ERROR;
            DB_PRINT("%s.%d Failed CALLOC, rc 0x%02x = %s\n", __FUNCTION__,
                    __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
    }

    /* Serialize header, handles and parameters in command stream */
    status = SAPI2_SERIALIZE_serialize(
            SAPI2_ST_TPM2_COMMAND_HEADER,
            TAP_SD_IN,
            (ubyte *)pCmdCtx->pCmdDesc->pUnserializedHeader,
            sizeof(TPM2_COMMAND_HEADER),
            pCmdCtx->pCmdStreamOut,
            pCmdCtx->cmdStreamOutSize,
            &bytesWrittenCmdBuf);
    if (OK != status)
    {
        rc = TSS2_SYS_RC_GENERAL_FAILURE;
        DB_PRINT("%s.%d Failed to serialize command header, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /* Serialize handles, which is always after the header area if present */
    if (pCmdCtx->pCmdDesc->numHandlesAndNames > 0)
    {
        status = SAPI2_SERIALIZE_serialize(
                pCmdCtx->pCmdDesc->handlesType,
                TAP_SD_IN,
                (ubyte *)pCmdCtx->pCmdDesc->pUnserializedHandles,
                pCmdCtx->pCmdDesc->UnserializedHandlesSize,
                pCmdCtx->pCmdStreamOut,
                pCmdCtx->cmdStreamOutSize,
                &bytesWrittenCmdBuf);
        if (OK != status)
        {
            rc = TSS2_SYS_RC_GENERAL_FAILURE;
            DB_PRINT("%s.%d Failed to serialize command handles, rc 0x%02x = %s\n", __FUNCTION__,
                    __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
    }

    /*
     * If there are no sessions, the parameter area is right after
     * the handle area.
     */
    if (pCmdCtx->pCmdDesc->pUnserializedHeader->tag == TPM2_ST_NO_SESSIONS)
    {
        if (pCmdCtx->pCmdDesc->UnserializedParametersSize > 0)
        {
            status = SAPI2_SERIALIZE_serialize(
                    pCmdCtx->pCmdDesc->parametersType,
                    TAP_SD_IN,
                    (ubyte *)pCmdCtx->pCmdDesc->pUnserializedParameters,
                    pCmdCtx->pCmdDesc->UnserializedParametersSize,
                    pCmdCtx->pCmdStreamOut,
                    pCmdCtx->cmdStreamOutSize,
                    &bytesWrittenCmdBuf);
            if (OK != status)
            {
                rc = TSS2_SYS_RC_GENERAL_FAILURE;
                DB_PRINT("%s.%d Failed to serialize command parameters,, rc 0x%02x = %s\n", __FUNCTION__,
                        __LINE__, rc, tss2_err_string(rc));
                goto exit;
            }
        }
    }
    else
    {
        /*
         * AuthorizationSize is the first field after the handles area.
         * Remember the offset and increment the number of bytes written.
         * The authorizationSize will be written once the authorization
         * area has been serialized.
         */
        authorizationSizeOffset = bytesWrittenCmdBuf;
        bytesWrittenCmdBuf = bytesWrittenCmdBuf + sizeof(ubyte4);

        /*
         * Since there area sessions, authorization areas are present
         * in the command stream before the parameters. Serialize the
         * parameters into a separate buffer to be copied over later.
         */
        if (pCmdCtx->pCmdDesc->UnserializedParametersSize > 0)
        {
            status = SAPI2_SERIALIZE_serialize(
                    pCmdCtx->pCmdDesc->parametersType,
                    TAP_SD_IN,
                    (ubyte *)pCmdCtx->pCmdDesc->pUnserializedParameters,
                    pCmdCtx->pCmdDesc->UnserializedParametersSize,
                    pCpBuffer,
                    pCmdCtx->pCmdDesc->UnserializedParametersSize,
                    &bytesWrittenCpBuffer);
            if (OK != status)
            {
                rc = TSS2_SYS_RC_GENERAL_FAILURE;
                DB_PRINT("%s.%d Failed to serialize command parameters, rc 0x%02x = %s\n", __FUNCTION__,
                        __LINE__, rc, tss2_err_string(rc));
                goto exit;
            }
        }
        if ((0 == pCmdCtx->pCmdDesc->numSessionHandlesAndAuthValues) ||
                (pCmdCtx->pCmdDesc->numSessionHandlesAndAuthValues > SAPI2_MAX_SESSIONS)||
                (NULL == pCmdCtx->pCmdDesc->ppSessionHandles) ||
                (NULL == pCmdCtx->pCmdDesc->ppAuthValues))
        {
            rc = TSS2_SYS_RC_INVALID_SESSIONS;
            DB_PRINT("%s.%d Command expects session handles, or"
                    "invalid number of handles specified, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        /*
         * For each session in the command context:
         * 1. Verify integrtiy of pointers and session context structures.
         * 2. Compute cpHash. This must be done on the serialized command buffer.
         * 3. Generate a random nonce, which will be used as nonceCaller/nonceNewer.
         *    Update the nonces in the session data structure(MOCTPM2_SESSION)
         * 4. Calculate command HMAC using the provided authValues.
         * 5. Assemble and serialize the TPMS_AUTH_COMMAND structurre into
         *    the command stream.
         */
        for (i = 0; i < pCmdCtx->pCmdDesc->numSessionHandlesAndAuthValues; i++)
        {
            if (NULL == pCmdCtx->pCmdDesc->ppSessionHandles[i])
            {
                rc = TSS2_SYS_RC_INVALID_SESSIONS;
                DB_PRINT("%s.%d Command expects session handles., rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
                goto exit;
            }

            if ((NULL == pCmdCtx->pCmdDesc->ppSessionHandles[i]->pMetadata) ||
                    (pCmdCtx->pCmdDesc->ppSessionHandles[i]->metaDataSize != sizeof(MOCTPM2_SESSION)) ||
                    (pCmdCtx->pCmdDesc->ppSessionHandles[i]->type != MOCTPM2_OBJ_METADATA_TYPE_SESSION))
            {
                rc = TSS2_SYS_RC_INVALID_SESSIONS;
                DB_PRINT("%s.%d Session handle does not contain required"
                        " metadata, rc 0x%02x = %s\n", __FUNCTION__,
                        __LINE__, rc, tss2_err_string(rc));
                goto exit;
            }

            pSession = (MOCTPM2_SESSION *)
                    pCmdCtx->pCmdDesc->ppSessionHandles[i]->pMetadata;

            if ((pSession->nonceOlder.size >
                sizeof(pSession->nonceOlder.buffer)) ||
                    (pSession->nonceNewer.size >
            sizeof(pSession->nonceNewer.buffer)))
            {
                rc = TSS2_SYS_RC_INVALID_SESSIONS;
                DB_PRINT("%s.%d Unexpected nonce sizes., rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
                goto exit;
            }

            if (pSession->sessionType == TPM2_SE_TRIAL)
            {
                rc = TSS2_SYS_RC_INVALID_SESSIONS;
                DB_PRINT("%s.%d Cannot use trial policy for authorization., rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
                goto exit;
            }

            if (OK != DIGI_MEMSET((ubyte *)&cpHashElement, 0, sizeof(cpHashElement)))
            {
                status = TSS2_SYS_RC_IO_ERROR;
                DB_PRINT("%s.%d Failed memset, rc 0x%02x = %s\n", __FUNCTION__,
                                __LINE__, rc, tss2_err_string(rc));
                goto exit;
            }

            if (OK != DIGI_MEMSET((ubyte *)&cpHash, 0, sizeof(cpHash)))
            {
                status = TSS2_SYS_RC_IO_ERROR;
                DB_PRINT("%s.%d Failed memset, rc 0x%02x = %s\n", __FUNCTION__,
                                __LINE__, rc, tss2_err_string(rc));
                goto exit;
            }

            cpHashElement.bufLen = bytesWrittenCpBuffer;
            cpHashElement.pBuf = pCpBuffer;
            status = SAPI2_HASH_computeCmdPHash(
                    pSession,
                    pCmdCtx->pCmdDesc->pUnserializedHeader->commandCode,
                    pCmdCtx->pCmdDesc->ppNames,
                    pCmdCtx->pCmdDesc->numHandlesAndNames,
                    &cpHashElement,
                    1,
                    &cpHash
            );
            if (OK != status)
            {
                rc = TSS2_SYS_RC_GENERAL_FAILURE;
                DB_PRINT("%s.%d Failed to calculate cpHash, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
                goto exit;
            }

            if (OK != DIGI_MEMSET((ubyte *)&nonceNewer.buffer, 0, sizeof(nonceNewer.buffer)))
            {
                status = TSS2_SYS_RC_IO_ERROR;
                DB_PRINT("%s.%d Failed memset, rc 0x%02x = %s\n", __FUNCTION__,
                                __LINE__, rc, tss2_err_string(rc));
                goto exit;
            }

            nonceNewer.size = pSession->nonceNewer.size;
            status = RANDOM_numberGenerator(g_pRandomContext,
                    (ubyte *)&nonceNewer.buffer,
                    pSession->nonceNewer.size);
            if (OK != status)
            {
                rc = TSS2_SYS_RC_GENERAL_FAILURE;
                DB_PRINT("%s.%d Failed to get command nonce, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
                goto exit;
            }

            rc = SAPI2_UTILS_updateNonces(pSession, &nonceNewer);
            if (TSS2_RC_SUCCESS != rc)
            {
                DB_PRINT("%s.%d Failed to roll nonces, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
                goto exit;
            }

            if (OK != DIGI_MEMSET((ubyte *)&authHmac.buffer, 0, sizeof(authHmac.buffer)))
            {
                status = TSS2_SYS_RC_IO_ERROR;
                DB_PRINT("%s.%d Failed memset, rc 0x%02x = %s\n", __FUNCTION__,
                                __LINE__, rc, tss2_err_string(rc));
                goto exit;
            }

            /*
             * Policy session hmac calculation only uses authValue,
             * if the session included policyAuthValue term.
             */
            if ((pSession->sessionType == TPM2_SE_POLICY) &&
                    (!pSession->sessionHaspolicyAuthValue))
            {
                status = SAPI2_HMAC_computeCmdRspHMAC(
                        pSession,
                        &emptyAuth,
                        &cpHash,
                        &authHmac
                );
            }
            else
            {
                status = SAPI2_HMAC_computeCmdRspHMAC(
                        pSession,
                        pCmdCtx->pCmdDesc->ppAuthValues[i],
                        &cpHash,
                        &authHmac
                );
            }
            if (OK != status)
            {
                rc = TSS2_SYS_RC_GENERAL_FAILURE;
                DB_PRINT("%s.%d Failed to compute command HMAC, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
                goto exit;
            }

            if (OK != DIGI_MEMSET((ubyte *)&authArea, 0, sizeof(authArea)))
            {
                status = TSS2_SYS_RC_IO_ERROR;
                DB_PRINT("%s.%d Failed memset, rc 0x%02x = %s\n", __FUNCTION__,
                                __LINE__, rc, tss2_err_string(rc));
                goto exit;
            }

            authArea.sessionHandle = pCmdCtx->pCmdDesc->ppSessionHandles[i]->tpm2Handle;
            authArea.sessionAttributes = pSession->attributes;
            authArea.nonce = nonceNewer;
            authArea.hmac = authHmac;

            status = SAPI2_SERIALIZE_serialize(
                    SAPI2_ST_TPMS_AUTH_COMMAND,
                    TAP_SD_IN,
                    (ubyte *)&authArea,
                    sizeof(authArea),
                    pCmdCtx->pCmdStreamOut,
                    pCmdCtx->cmdStreamOutSize,
                    &bytesWrittenCmdBuf);
            if (OK != status)
            {
                rc = TSS2_SYS_RC_GENERAL_FAILURE;
                DB_PRINT("%s.%d Failed to serialize command authorization, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
                goto exit;
            }
        }

        /*
         * Copy command parameters buffer cpBuffer into pCmdCtx->pCmdStreamOut.
         * After this step, the command stream(pCmdCtx->pCmdStreamOut)
         * looks as follows(See chapter 18, Part 1, Architecture):
         * **************************
         * Serialized Command Header
         * --------------------------
         * Serialized Handles
         * --------------------------
         * authorizationSize
         * --------------------------
         * Serialized Auth session 1 (If it exists)
         * --------------------------
         * Serialized Auth Session 2 (If it exists)
         * -------------------------- <--- (bytesWrittenCmdBuf)
         * Serialized Command Parameters(cpBuffer)
         * ************************** <-----(New bytesWrittenCmdBuf)
         */
        if ((bytesWrittenCmdBuf + bytesWrittenCpBuffer) > pCmdCtx->cmdStreamOutSize)
        {
            rc = TSS2_SYS_RC_INSUFFICIENT_BUFFER;
            DB_PRINT("%s.%d Insufficient command stream buffer, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        authorizationSize = bytesWrittenCmdBuf
                - authorizationSizeOffset - sizeof(ubyte4);


        if (OK != ubyte4ToArray(authorizationSize,
                (ubyte *)&authorizationSizeSerialized))
        {
            rc = TSS2_SYS_RC_GENERAL_FAILURE;
            DB_PRINT("%s.%d Failed to serialize authorizationSize, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        if (OK != DIGI_MEMCPY((pCmdCtx->pCmdStreamOut + authorizationSizeOffset),
                (ubyte *)&authorizationSizeSerialized, sizeof(ubyte4)))
        {
            status = TSS2_SYS_RC_IO_ERROR;
            DB_PRINT("%s.%d Failed memcpy, rc 0x%02x = %s\n", __FUNCTION__,
                            __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        if (pCmdCtx->pCmdDesc->UnserializedParametersSize > 0)
        {
            if (OK != DIGI_MEMCPY((pCmdCtx->pCmdStreamOut + bytesWrittenCmdBuf),
                    pCpBuffer, bytesWrittenCpBuffer))
            {
                status = TSS2_SYS_RC_IO_ERROR;
                DB_PRINT("%s.%d Failed memcpy, rc 0x%02x = %s\n", __FUNCTION__,
                        __LINE__, rc, tss2_err_string(rc));
                goto exit;
            }

            bytesWrittenCmdBuf = bytesWrittenCmdBuf + bytesWrittenCpBuffer;
        }
    }

    if (OK != ubyte4ToArray(bytesWrittenCmdBuf,
            (ubyte *)&bytesWrittenSerialized))
    {
        rc = TSS2_SYS_RC_GENERAL_FAILURE;
        DB_PRINT("%s.%d Failed to serialize bytesWritten, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (OK != DIGI_MEMCPY((ubyte *)(pCmdCtx->pCmdStreamOut + sizeof(TPMI_ST_COMMAND_TAG)),
            (ubyte *)&bytesWrittenSerialized, sizeof(ubyte4)))
    {
        status = TSS2_SYS_RC_IO_ERROR;
        DB_PRINT("%s.%d Failed memcpy, rc 0x%02x = %s\n", __FUNCTION__,
                        __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    *pCmdBufferSizeOut = bytesWrittenCmdBuf;
    rc = TSS2_RC_SUCCESS;

exit:
    if (pCpBuffer)
    {
        if (OK != shredMemory((ubyte **)&pCpBuffer,
            pCmdCtx->pCmdDesc->UnserializedParametersSize, TRUE))
        {
            rc = TSS2_SYS_RC_IO_ERROR;
            DB_PRINT("%s.%d Failed to shredMemory, rc 0x%02x = %s\n",
                    __FUNCTION__, __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
    }

    return rc;
}

TSS2_RC SAPI2_UTILS_getRspStructures(sapi2_utils_rsp_context *pRspCtx)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    MSTATUS status = ERR_GENERAL;
    ubyte4 bytesDeserialized = 0;
    ubyte4 serializedParameterSize = 0;
    ubyte4 parameterSize = 0;
    ubyte i = 0;
    MOCTPM2_SESSION *pSession = NULL;
    TPMS_AUTH_RESPONSE authResponse = { 0 };
    HASH_ELEMENT rpHashElement = { 0 };
    ubyte4 rpBufferOffset = { 0 };
    TPM2B_DIGEST rpHash =  { 0 };
    TPM2B_AUTH authHmac = { 0 };
    sbyte4 hmacCmpResult = 0;
    TPM2B_AUTH emptyAuth = { 0 };

    if (NULL == pRspCtx || NULL == pRspCtx->pRspDesc)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid response context, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((NULL == pRspCtx->pRspDesc->pUnserializedHeader) || (NULL == pRspCtx->pRspStreamIn)
            || (0 == pRspCtx->rspStreamInSize))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid header pointers or response buffer"
                "pointer , rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((pRspCtx->pRspDesc->UnserializedHandlesSize > 0) &&
            (NULL == pRspCtx->pRspDesc->pUnserializedHandles))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid handles buffer pointer or size, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((0 == pRspCtx->pRspDesc->UnserializedHandlesSize) &&
            (NULL != pRspCtx->pRspDesc->pUnserializedHandles))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid handles buffer pointer or size, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((pRspCtx->pRspDesc->handlesType >= SAPI2_ST_END) ||
            (pRspCtx->pRspDesc->parametersType >= SAPI2_ST_END))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid handles or parameters type, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((pRspCtx->pRspDesc->UnserializedParametersSize > 0) &&
            (NULL == pRspCtx->pRspDesc->pUnserializedParameters))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid parameters pointer or size, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((0 == pRspCtx->pRspDesc->UnserializedParametersSize) &&
            (NULL != pRspCtx->pRspDesc->pUnserializedParameters))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid parameters pointer or size, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    status = SAPI2_SERIALIZE_serialize(
            SAPI2_ST_TPM2_RESPONSE_HEADER,
            TAP_SD_OUT,
            pRspCtx->pRspStreamIn,
            pRspCtx->rspStreamInSize,
            (ubyte *)pRspCtx->pRspDesc->pUnserializedHeader,
            sizeof(TPM2_RESPONSE_HEADER),
            &bytesDeserialized);
    if (OK != status)
    {
        rc = TSS2_SYS_RC_GENERAL_FAILURE;
        DB_PRINT("%s.%d Failed to serialize response header, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (pRspCtx->pRspDesc->pUnserializedHeader->responseCode != TPM2_RC_SUCCESS)
    {
        /* Response de-serialization was successful but the command
         * execution was not. Callers must check response code before
         * using handles and parameters area.
         */
        rc = TSS2_RC_SUCCESS;

        /* Interpretation of this error will be done by caller, skip print */
        goto exit;
    }

    /* De-serialized handles, if expected */
    if ((pRspCtx->pRspDesc->UnserializedHandlesSize > 0) &&
            (pRspCtx->pRspDesc->pUnserializedHandles))
    {
        status = SAPI2_SERIALIZE_serialize(
                pRspCtx->pRspDesc->handlesType,
                TAP_SD_OUT,
                pRspCtx->pRspStreamIn,
                pRspCtx->rspStreamInSize,
                (ubyte *)pRspCtx->pRspDesc->pUnserializedHandles,
                pRspCtx->pRspDesc->UnserializedHandlesSize,
                &bytesDeserialized);
        if (OK != status)
        {
            rc = TSS2_SYS_RC_GENERAL_FAILURE;
            DB_PRINT("%s.%d Failed to serialize response handles, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
    }

    /*
     * If there are no sessions, there is no parameterSize and Authorization
     * area. The parameters are is right after the handles area in this case.
     */
    if (pRspCtx->pRspDesc->pUnserializedHeader->tag == TPM2_ST_NO_SESSIONS)
    {
        if ((pRspCtx->pRspDesc->UnserializedParametersSize > 0) &&
                (pRspCtx->pRspDesc->pUnserializedParameters))
        {
            status = SAPI2_SERIALIZE_serialize(
                    pRspCtx->pRspDesc->parametersType,
                    TAP_SD_OUT,
                    pRspCtx->pRspStreamIn,
                    pRspCtx->rspStreamInSize,
                    (ubyte *)pRspCtx->pRspDesc->pUnserializedParameters,
                    pRspCtx->pRspDesc->UnserializedParametersSize,
                    &bytesDeserialized);
            if (OK != status)
            {
                rc = TSS2_SYS_RC_GENERAL_FAILURE;
                DB_PRINT("%s.%d Failed to serialize response parameters,"
                        "rc 0x%02x = %s\n", __FUNCTION__, __LINE__, rc,
                        tss2_err_string(rc));
                goto exit;
            }
        }
    }
    else
    {
        if (OK != DIGI_MEMCPY(&serializedParameterSize,
                (pRspCtx->pRspStreamIn + bytesDeserialized),
                sizeof(ubyte4)))
        {
            status = TSS2_SYS_RC_IO_ERROR;
            DB_PRINT("%s.%d Failed memcpy, rc 0x%02x = %s\n", __FUNCTION__,
                            __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        bytesDeserialized = bytesDeserialized + sizeof(ubyte4);
        rpBufferOffset = bytesDeserialized;

        if (OK != arrayToUbyte4((ubyte *)&serializedParameterSize,
                &parameterSize))
        {
            rc = TSS2_SYS_RC_GENERAL_FAILURE;
            DB_PRINT("%s.%d Failed to deserialize parameterSize, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        if (((parameterSize == 0) &&
                (NULL != pRspCtx->pRspDesc->pUnserializedParameters)) ||
                ((parameterSize > 0) &&
                        (NULL == pRspCtx->pRspDesc->pUnserializedParameters)) ||
                        (pRspCtx->pRspDesc->UnserializedParametersSize < parameterSize))
        {
            rc = TSS2_SYS_RC_MALFORMED_RESPONSE;
            DB_PRINT("%s.%d Failed to serialize response parameters, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        if (parameterSize > 0)
        {
            status = SAPI2_SERIALIZE_serialize(
                    pRspCtx->pRspDesc->parametersType,
                    TAP_SD_OUT,
                    pRspCtx->pRspStreamIn,
                    pRspCtx->rspStreamInSize,
                    (ubyte *)pRspCtx->pRspDesc->pUnserializedParameters,
                    pRspCtx->pRspDesc->UnserializedParametersSize,
                    &bytesDeserialized);
            if (OK != status)
            {
                rc = TSS2_SYS_RC_GENERAL_FAILURE;
                DB_PRINT("%s.%d Failed to serialize response parameters, rc 0x%02x = %s\n", __FUNCTION__,
                        __LINE__, rc, tss2_err_string(rc));
                goto exit;
            }
        }

        if ((0 == pRspCtx->pRspDesc->numSessionHandlesAndAuthValues) ||
                (pRspCtx->pRspDesc->numSessionHandlesAndAuthValues > SAPI2_MAX_SESSIONS)||
                (NULL == pRspCtx->pRspDesc->ppSessionHandles) ||
                (NULL == pRspCtx->pRspDesc->ppAuthValues))
        {
            rc = TSS2_SYS_RC_INVALID_SESSIONS;
            DB_PRINT("%s.%d Response parsing expects session handles, or"
                    "invalid number of handles specified, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        /*
         * We expect the same number of response authorizations
         * as this command. This is reflected by
         * pRspCtx->pRspDesc->numSessionHandlesAndAuthValues.
         */
        for (i = 0; i < pRspCtx->pRspDesc->numSessionHandlesAndAuthValues; i++)
        {
            if (bytesDeserialized >= pRspCtx->rspStreamInSize)
            {
                if (bytesDeserialized > pRspCtx->rspStreamInSize)
                {
                    DB_PRINT("%s.%d Possible corruption. Deserialized"
                            " more data than available, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
                }
                rc = TSS2_SYS_RC_MALFORMED_RESPONSE;
                DB_PRINT("%s.%d Response buffer parsed fully but expecting"
                        " more authroizaton data, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
                goto exit;
            }

            if (NULL == pRspCtx->pRspDesc->ppSessionHandles[i])
            {
                rc = TSS2_SYS_RC_INVALID_SESSIONS;
                DB_PRINT("%s.%d Response parsing expects session handles., rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
                goto exit;
            }

            if ((NULL == pRspCtx->pRspDesc->ppSessionHandles[i]->pMetadata) ||
                    pRspCtx->pRspDesc->ppSessionHandles[i]->metaDataSize != sizeof(MOCTPM2_SESSION) ||
                    (pRspCtx->pRspDesc->ppSessionHandles[i]->type != MOCTPM2_OBJ_METADATA_TYPE_SESSION))
            {
                rc = TSS2_SYS_RC_INVALID_SESSIONS;
                DB_PRINT("%s.%d Session handle does not contain required"
                        " metadata, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
                goto exit;
            }

            status = SAPI2_SERIALIZE_serialize(
                    SAPI2_ST_TPMS_AUTH_RESPONSE,
                    TAP_SD_OUT,
                    pRspCtx->pRspStreamIn,
                    pRspCtx->rspStreamInSize,
                    (ubyte *)&authResponse,
                    sizeof(TPMS_AUTH_RESPONSE),
                    &bytesDeserialized);
            if (OK != status)
            {
                rc = TSS2_SYS_RC_GENERAL_FAILURE;
                DB_PRINT("%s.%d Failed to serialize response auth area, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
                goto exit;
            }

            pSession = (MOCTPM2_SESSION *)
                                pRspCtx->pRspDesc->ppSessionHandles[i]->pMetadata;

            if (authResponse.sessionAttributes != pSession->attributes)
            {
                rc = TSS2_SYS_RC_MALFORMED_RESPONSE;
                DB_PRINT("%s.%d Response session attributes dont match, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
                goto exit;
            }

            rc = SAPI2_UTILS_updateNonces(pSession, &authResponse.nonce);
            if (TSS2_RC_SUCCESS != rc)
            {
                DB_PRINT("%s.%d Failed to roll nonces, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
                goto exit;
            }

            if (OK != DIGI_MEMSET((ubyte *)&rpHashElement, 0, sizeof(rpHashElement)))
            {
                status = TSS2_SYS_RC_IO_ERROR;
                DB_PRINT("%s.%d Failed memset, rc 0x%02x = %s\n", __FUNCTION__,
                                __LINE__, rc, tss2_err_string(rc));
                goto exit;
            }

            if (OK != DIGI_MEMSET((ubyte *)&rpHash, 0, sizeof(rpHash)))
            {
                status = TSS2_SYS_RC_IO_ERROR;
                DB_PRINT("%s.%d Failed memset, rc 0x%02x = %s\n", __FUNCTION__,
                                __LINE__, rc, tss2_err_string(rc));
                goto exit;
            }

            rpHashElement.bufLen = parameterSize;
            rpHashElement.pBuf = pRspCtx->pRspStreamIn + rpBufferOffset;
            status = SAPI2_HASH_computeRspPHash(
                    pSession,
                    pRspCtx->pRspDesc->commandCode,
                    pRspCtx->pRspDesc->pUnserializedHeader->responseCode,
                    &rpHashElement,
                    1,
                    &rpHash
            );
            if (OK != status)
            {
                rc = TSS2_SYS_RC_GENERAL_FAILURE;
                DB_PRINT("%s.%d Failed to calculate rpHash, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
                goto exit;
            }

            if (OK != DIGI_MEMSET((ubyte *)&authHmac.buffer, 0, sizeof(authHmac.buffer)))
            {
                status = TSS2_SYS_RC_IO_ERROR;
                DB_PRINT("%s.%d Failed memset, rc 0x%02x = %s\n", __FUNCTION__,
                                __LINE__, rc, tss2_err_string(rc));
                goto exit;
            }

            /*
             * Policy session hmac calculation only uses authValue,
             * if the session included policyAuthValue term.
             */
            if ((pSession->sessionType == TPM2_SE_POLICY) &&
                    (!pSession->sessionHaspolicyAuthValue))
            {
                status = SAPI2_HMAC_computeCmdRspHMAC(
                        pSession,
                        &emptyAuth,
                        &rpHash,
                        &authHmac
                );
            }
            else
            {
                status = SAPI2_HMAC_computeCmdRspHMAC(
                        pSession,
                        pRspCtx->pRspDesc->ppAuthValues[i],
                        &rpHash,
                        &authHmac
                );
            }
            if (OK != status)
            {
                rc = TSS2_SYS_RC_GENERAL_FAILURE;
                DB_PRINT("%s.%d Failed to compute response HMAC, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
                goto exit;
            }

            if (authHmac.size != authResponse.hmac.size)
            {
                rc = TSS2_SYS_RC_GENERAL_FAILURE;
                DB_PRINT("%s.%d Response HMAC size mismatch, rc 0x%02x = %s\n", __FUNCTION__,
                        __LINE__, rc, tss2_err_string(rc));
                goto exit;
            }

            if (OK != DIGI_MEMCMP((const ubyte *)authHmac.buffer,
                    (const ubyte *)authResponse.hmac.buffer,
                    authResponse.hmac.size, &hmacCmpResult))
            {
                rc = TSS2_SYS_RC_IO_ERROR;
                DB_PRINT("%s.%d Failed memcmp, rc 0x%02x = %s\n", __FUNCTION__,
                                __LINE__, rc, tss2_err_string(rc));
                goto exit;
            }

            if (hmacCmpResult != 0)
            {
                rc = TSS2_SYS_RC_GENERAL_FAILURE;
                DB_PRINT("%s.%d Response HMAC verification failed, rc 0x%02x = %s\n", __FUNCTION__,
                        __LINE__, rc, tss2_err_string(rc));
                goto exit;
            }


        }
    }

    if (bytesDeserialized != pRspCtx->rspStreamInSize)
    {
        rc = TSS2_SYS_RC_GENERAL_FAILURE;
        DB_PRINT("%s.%d Response has more bytes than expected"
                "bytesSerialized = %d, rspStreamSizeIn = %d\n",
                __FUNCTION__, __LINE__, bytesDeserialized,
                pRspCtx->rspStreamInSize);
        goto exit;
    }

    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}

#endif /* ifdef __ENABLE_DIGICERT_TPM2__ */

/* PKCS11 Currently uses SAPI2_UTILS_TPM2_KDFA for attestation flow */
#if (defined(__ENABLE_DIGICERT_TPM2__) || defined(__ENABLE_DIGICERT_SMP_PKCS11__))

MSTATUS SAPI2_UTILS_getHashAlgFromAlgId(
        TPM2_ALG_ID hashAlgId,
        const BulkHashAlgo **ppHashAlgOut,
        ubyte *hashAlgOid
)
{
    ubyte hashAlg = 0;
    MSTATUS status = ERR_GENERAL;

    if ((NULL == ppHashAlgOut) || (NULL != *ppHashAlgOut) || (NULL == hashAlgOid))
    {
        status = ERR_INVALID_INPUT;
        DB_PRINT("%s.%d Invalid inputs\n", __FUNCTION__,
                        __LINE__);
        goto exit;
    }

    switch (hashAlgId)
    {
    case TPM2_ALG_SHA1:
        hashAlg = sha1withRSAEncryption;
        break;
    case TPM2_ALG_SHA256:
        hashAlg = sha256withRSAEncryption;
        break;
    case TPM2_ALG_SHA384:
        hashAlg = sha384withRSAEncryption;
        break;
    case TPM2_ALG_SHA512:
        hashAlg = sha512withRSAEncryption;
        break;
    default:
        status = ERR_INVALID_INPUT;
        DB_PRINT("%s.%d Invalid hash alg specified\n", __FUNCTION__,
                                __LINE__);
        goto exit;
        break;
    }

    /* Select Hash Algorithm */
    if (OK != (status = CRYPTO_getRSAHashAlgo(hashAlg, ppHashAlgOut)))
    {
        DB_PRINT("%s.%d Unable to get Hash algorithm! status = %d\n,"
                , __FUNCTION__, __LINE__, (int)status);
        goto exit;
    }

    *hashAlgOid = hashAlg;

    status = OK;
exit:
    return status;
}

TSS2_RC SAPI2_UTILS_getHashAlg(
        TPM2_ALG_ID hashAlgId,
        const BulkHashAlgo **ppHashAlgOut
)
{
    ubyte oid = 0;

    if (OK != SAPI2_UTILS_getHashAlgFromAlgId(hashAlgId, ppHashAlgOut, &oid))
    {
        return TSS2_SYS_RC_GENERAL_FAILURE;
    }
    return TSS2_RC_SUCCESS;
}


/*
 * KDFA as specified in the TPM library specification part 1.
 * All lenghts, including output key length must be in bytes. It will be
 * converted to bits internally.
 */
TSS2_RC SAPI2_UTILS_TPM2_KDFA(
        TPM2_ALG_ID hashAlgId,
        ubyte *pSecretKeyMaterial,
        ubyte4 pSecretKeyMaterialLen,
        const char *pLabel,
        ubyte *pContextU,
        ubyte4 contextULen,
        ubyte *pContextV,
        ubyte4 contextVLen,
        ubyte *pKeyOut,
        ubyte4 keyOutLen
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    MSTATUS status = ERR_GENERAL;
    const BulkHashAlgo *pHashAlgOut = NULL;
    HMAC_CTX *pHmacCtx = NULL;
    ubyte4 labelSize = DIGI_STRLEN((const sbyte *)pLabel);
    ubyte *pContext = NULL;
    ubyte4 contextSize = contextULen + contextVLen;
    
#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    hwAccelDescr hwAccelCtx = 0;
#endif
    
    if ((NULL == pSecretKeyMaterial) || (0 == pSecretKeyMaterialLen))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid secret key material pointer or length, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((NULL == pKeyOut) || (0 == keyOutLen))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid output key pointer or length, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((NULL != pContextU) && (0 == contextULen))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid contextU length, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((0 != contextULen) && (NULL == pContextU))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid contextU pointer, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((NULL != pContextV) && (0 == contextVLen))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid contextU length, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((0 != contextVLen) && (NULL == pContextV))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid contextV pointer, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (contextSize > 0)
    {
        if (OK != DIGI_CALLOC((void **)&pContext, 1, contextSize))
        {
            rc = TSS2_SYS_RC_IO_ERROR;
            DB_PRINT("%s.%d Failed CALLOC, rc 0x%02x = %s\n", __FUNCTION__,
                    __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
    }

    if (pContextU)
    {
        if (OK != DIGI_MEMCPY(pContext, pContextU, contextULen))
        {
            status = TSS2_SYS_RC_IO_ERROR;
            DB_PRINT("%s.%d Failed memcpy, rc 0x%02x = %s\n", __FUNCTION__,
                            __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
    }

    if (pContextV)
    {
        if (OK != DIGI_MEMCPY((pContext + contextULen), pContextV, contextVLen))
        {
            status = TSS2_SYS_RC_IO_ERROR;
            DB_PRINT("%s.%d Failed memcpy, rc 0x%02x = %s\n", __FUNCTION__,
                            __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
    }

#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    status = (MSTATUS) HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx);
    if (OK != status)
        goto exit;
#endif
    
    /* Create HMAC context for the NIST KDF */
    rc = SAPI2_UTILS_getHashAlg(hashAlgId, &pHashAlgOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Invalid hash algorithm specified or algorithm"
                " not implemented, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    status = HmacCreate(MOC_HASH(hwAccelCtx) &pHmacCtx, pHashAlgOut);
    if (OK != status)
    {
        rc = TSS2_SYS_RC_GENERAL_FAILURE;
        DB_PRINT("%s.%d Failed to create HMAC context, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    status = HmacKey(MOC_HASH(hwAccelCtx) pHmacCtx,
            pSecretKeyMaterial, pSecretKeyMaterialLen);
    if (OK != status)
    {
        rc = TSS2_SYS_RC_GENERAL_FAILURE;
        DB_PRINT("%s.%d Failed to insert key into HMAC context, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /* Call nist KDF with the following parameters that are fixed per the TPM
     * spec:
     * contextSize = 4 bytes, ie 32 bits(see spec)
     * keyMaterialSize = 4 bytes, ie 32 bits(see spec)
     * littleEndian = FALSE, for contextSize and keyMaterialSize. They must be
     * in bigendian(TPM Canonical) per the spec.
     * Refer to spec 11.4.9.2, Ver 1.38, Part 1 Architecture for details.
     */

    status = KDF_NIST_CounterMode( MOC_SYM(hwAccelCtx) 4,
            pHmacCtx, &NIST_PRF_Hmac, (const ubyte *)pLabel, labelSize, pContext, contextSize,
            4, FALSE, pKeyOut, keyOutLen);
    if (OK != status)
    {
        rc = TSS2_SYS_RC_GENERAL_FAILURE;
        DB_PRINT("%s.%d Failed NIST KDF, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    rc = TSS2_RC_SUCCESS;
exit:
    if (pContext)
    {
        if (OK != shredMemory((ubyte **)&pContext,
            contextSize, TRUE))
        {
            rc = TSS2_SYS_RC_IO_ERROR;
            DB_PRINT("%s.%d Failed to shredMemory, rc 0x%02x = %s\n",
                    __FUNCTION__, __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
    }

    if (pHmacCtx)
        HmacDelete(MOC_HASH(hwAccelCtx)  &pHmacCtx);

#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    (void) HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);
#endif
    return rc;
}

static TSS2_RC SAPI2_UTILS_getName(void *pPublic, ubyte4 publicSize,
        TPM2B_NAME *pOutName, SAPI2_SERIALIZE_TYPE type,
        TPMI_ALG_HASH nameAlg)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    ubyte *pSerialized = NULL;
    ubyte4 bytesWritten = 0;
    ubyte *pDigest = NULL;
    ubyte* nameBuffer = NULL;
    const BulkHashAlgo *pHashAlgOut = NULL;
    ubyte4 digestSize = 0;
    HASH_ELEMENT hashElement = { 0 };


    MSTATUS status = ERR_GENERAL;

    if ((NULL == pPublic) || (NULL == pOutName) || (publicSize == 0))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid input pointers, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((type != SAPI2_ST_TPMS_NV_PUBLIC) && (type != SAPI2_ST_TPMT_PUBLIC))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid serialize type, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (OK != DIGI_CALLOC((void **)&pSerialized, 1, publicSize))
    {
        rc = TSS2_SYS_RC_IO_ERROR;
        DB_PRINT("%s.%d Failed to allocate memory for serialization, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    status = SAPI2_SERIALIZE_serialize(
            type,
            TAP_SD_IN,
            (ubyte *)pPublic,
            publicSize,
            pSerialized,
            publicSize,
            &bytesWritten);

    if ((OK != status) || (bytesWritten > publicSize))
    {
        rc = TSS2_SYS_RC_GENERAL_FAILURE;
        DB_PRINT("%s.%d Failed to serialize public area, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (TSS2_RC_SUCCESS !=
            SAPI2_UTILS_getHashAlg(nameAlg, &pHashAlgOut))
    {
        rc = TSS2_SYS_RC_GENERAL_FAILURE;
        DB_PRINT("%s.%d Unknown/unsupported name alg, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    digestSize = pHashAlgOut->digestSize;

    if (digestSize > sizeof(pOutName->name))
    {
        rc = TSS2_SYS_RC_INSUFFICIENT_BUFFER;
        DB_PRINT("%s.%d nameAlg size too large, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (OK != DIGI_CALLOC((void **)&pDigest, 1, digestSize))
    {
        rc = TSS2_SYS_RC_IO_ERROR;
        DB_PRINT("%s.%d Failed to allocate memory for digest, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /* Name for NV:≔ nameAlg ||HnameAlg(handle→nvPublicArea)
     * Name for object :≔ nameAlg ||HnameAlg(handle→publicArea)
     * TPM2 spec, part1, section 17
     */
    hashElement.bufLen = bytesWritten;
    hashElement.pBuf = pSerialized;

    status = SAPI2_HASH_computeHASH(nameAlg, &hashElement, 1,
            pDigest, digestSize);
    if (OK != status)
    {
        rc = TSS2_SYS_RC_GENERAL_FAILURE;
        DB_PRINT("%s.%d failed to digest public area, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    bytesWritten = 0;

    if (OK != DIGI_MEMSET(pSerialized, 0, sizeof(TPMI_ALG_HASH)))
    {
        rc = TSS2_SYS_RC_IO_ERROR;
        DB_PRINT("%s.%d Failed memset, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    status = SAPI2_SERIALIZE_serialize(
            SAPI2_ST_TPMI_ALG_HASH,
            TAP_SD_IN,
            (ubyte *)&nameAlg,
            sizeof(TPMI_ALG_HASH),
            pSerialized,
            sizeof(TPMI_ALG_HASH),
            &bytesWritten);
    if ((OK != status) || (bytesWritten != sizeof(TPMI_ALG_HASH)))
    {
        rc = TSS2_SYS_RC_GENERAL_FAILURE;
        DB_PRINT("%s.%d Failed to serialize TPMI_ALG_HASH, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pOutName->size = sizeof(TPMI_ALG_HASH) + digestSize;

    nameBuffer = pOutName->name;
    if (OK != DIGI_MEMCPY(nameBuffer, pSerialized, sizeof(TPMI_ALG_HASH)))
    {
        rc = TSS2_SYS_RC_IO_ERROR;
        DB_PRINT("%s.%d Failed memcpy, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    nameBuffer = nameBuffer + sizeof(TPMI_ALG_HASH);

    if (OK != DIGI_MEMCPY(nameBuffer, pDigest, digestSize))
    {
        rc = TSS2_SYS_RC_IO_ERROR;
        DB_PRINT("%s.%d Failed memcpy, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    rc = TSS2_RC_SUCCESS;

exit:
    if (pSerialized)
    {
        if (OK != shredMemory((ubyte **)&pSerialized,
                publicSize, TRUE))
        {
            rc = TSS2_SYS_RC_IO_ERROR;
            DB_PRINT("%s.%d Failed to shredMemory, rc 0x%02x = %s\n",
                    __FUNCTION__, __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
    }

    if (pDigest)
    {
        if (OK != shredMemory((ubyte **)&pDigest,
            digestSize, TRUE))
        {
            rc = TSS2_SYS_RC_IO_ERROR;
            DB_PRINT("%s.%d Failed to shredMemory, rc 0x%02x = %s\n",
                    __FUNCTION__, __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
    }

    return rc;
}

TSS2_RC SAPI2_UTILS_getObjectName(TPM2_HANDLE handle,
        TPMT_PUBLIC *pPublic, TPM2B_NAME *pOutName)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TPM2_HT handleType = 0;
    MSTATUS status = ERR_GENERAL;
    ubyte4 bytesWritten = 0;

    if (NULL == pOutName)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid input pointer, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    handleType = (handle & TPM2_HR_RANGE_MASK) >> TPM2_HR_SHIFT;

    /* See TPM2 spec, part 1, table 3 for equations */
    switch (handleType)
    {
    case TPM2_HT_PCR:
    case TPM2_HT_HMAC_SESSION:
    case TPM2_HT_POLICY_SESSION:
    case TPM2_HT_PERMANENT:
        pOutName->size = sizeof(TPM2_HANDLE);
        status = SAPI2_SERIALIZE_serialize(
                SAPI2_ST_TPM2_HANDLE,
                TAP_SD_IN,
                (ubyte *)&handle,
                sizeof(TPM2_HANDLE),
                pOutName->name,
                sizeof(TPM2_HANDLE),
                &bytesWritten);
        if ((OK != status) || (bytesWritten != sizeof(TPM2_HANDLE)))
        {
            rc = TSS2_SYS_RC_GENERAL_FAILURE;
            DB_PRINT("%s.%d Failed to serialize TPM2_HANDLE, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
        rc = TSS2_RC_SUCCESS;
        break;
    case TPM2_HT_TRANSIENT:
    case TPM2_HT_PERSISTENT:
        if (NULL == pPublic)
        {
            rc = TSS2_RC_SUCCESS;
            goto exit;
        }
        rc = SAPI2_UTILS_getName(pPublic, sizeof(TPMT_PUBLIC),
                pOutName, SAPI2_ST_TPMT_PUBLIC, pPublic->nameAlg);
        break;
    case TPM2_HT_NV_INDEX: /* SAPI2_UTILS_getNvName */
    default:
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid TPM handle\n",
                __FUNCTION__, __LINE__);
        goto exit;
    }

exit:
    return rc;
}

#endif /* if (defined(__ENABLE_DIGICERT_TPM2__) || defined(__ENABLE_DIGICERT_SMP_PKCS11__)) */

#ifdef __ENABLE_DIGICERT_TPM2__
/*
 * KDFE as specified in the TPM library specification part 1.
 * All lengths, including output length must be in bytes. It will be
 * converted to bits internally.
 */

TSS2_RC SAPI2_UTILS_TPM2_KDFE(
        TPM2_ALG_ID hashAlgId,
        ubyte *pZpointX,
        ubyte4 zPointXLen,
        const char *pLabel,
        ubyte *pPartyUInfo,
        ubyte4 partyUInfoLen,
        ubyte *pPartyVInfo,
        ubyte4 partyVInfoLen,
        ubyte *pKeyOut,
        ubyte4 keyOutLen
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    ubyte4 labelSize = 0;
    ubyte *pOtherInfo = NULL;
    ubyte4 otherInfoLen = 0;
    ubyte4 remBytesToProduce = keyOutLen;
    ubyte4 bytesThisRound = 0;
    ubyte *pDigest = NULL;
    ubyte4 counter = 1;
    ubyte4 counterTpmCanonical = 0;
    const BulkHashAlgo *pHashAlg = NULL;
    BulkCtx bulkCtx = NULL;
    ubyte *pOut = pKeyOut;
    
#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    hwAccelDescr hwAccelCtx = 0;
#endif
    
    if ((NULL == pZpointX) || (0 == zPointXLen) || (NULL == pLabel))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid zPoint pointer or length, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    labelSize = DIGI_STRLEN((const sbyte *)pLabel);
    if (0 == labelSize)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Label cannot be a null string, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /*
     * Adjust size to include NULL character in otherInfo buffer
     */
    labelSize += 1;

    if ((NULL == pKeyOut) || (0 == keyOutLen))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid output key pointer or length, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((NULL != pPartyUInfo) && (0 == partyUInfoLen))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid partyUinfo length, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((0 != partyUInfoLen) && (NULL == pPartyUInfo))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid partyUinfo pointer, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((NULL != pPartyVInfo) && (0 == partyVInfoLen))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid partyVinfo length, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((0 != partyVInfoLen) && (NULL == pPartyVInfo))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid partyVinfo pointer, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    rc = SAPI2_UTILS_getHashAlg(hashAlgId, &pHashAlg);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Invalid hash algorithm specified or algorithm"
                " not implemented, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (OK != DIGI_CALLOC((void **)&pDigest, 1, pHashAlg->digestSize))
    {
        rc = TSS2_SYS_RC_IO_ERROR;
        DB_PRINT("%s.%d Failed CALLOC, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    otherInfoLen = labelSize + partyUInfoLen + partyVInfoLen;

    if (otherInfoLen > 0)
    {
        if (OK != DIGI_CALLOC((void **)&pOtherInfo, 1, otherInfoLen))
        {
            rc = TSS2_SYS_RC_IO_ERROR;
            DB_PRINT("%s.%d Failed CALLOC, rc 0x%02x = %s\n", __FUNCTION__,
                    __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
    }

    if (OK != DIGI_MEMCPY(pOtherInfo, pLabel, labelSize))
    {
        rc = TSS2_SYS_RC_IO_ERROR;
        DB_PRINT("%s.%d Failed memcpy, rc 0x%02x = %s\n", __FUNCTION__,
                        __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (pPartyUInfo)
    {
        if (OK != DIGI_MEMCPY(pOtherInfo + labelSize, pPartyUInfo, partyUInfoLen))
        {
            rc = TSS2_SYS_RC_IO_ERROR;
            DB_PRINT("%s.%d Failed memcpy, rc 0x%02x = %s\n", __FUNCTION__,
                            __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
    }

    if (pPartyVInfo)
    {
        if (OK != DIGI_MEMCPY((pOtherInfo + labelSize + partyUInfoLen), pPartyVInfo, partyVInfoLen))
        {
            rc = TSS2_SYS_RC_IO_ERROR;
            DB_PRINT("%s.%d Failed memcpy, rc 0x%02x = %s\n", __FUNCTION__,
                            __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
    }

    /*
     * TODO: RK Replace with nanoCrypto implementation of SP800-56A.
     * counter loop:
     * digest(i) = H(counter || Z || otherInfo)
     */

#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    if( 0 != HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx) )
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("Cannot open hwAccel channel.\n", __FUNCTION__,
             __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }
#endif
    
    while (remBytesToProduce)
    {
        if (OK != pHashAlg->allocFunc(MOC_HASH(hwAccelCtx) &bulkCtx))
        {
            rc = TSS2_SYS_RC_IO_ERROR;
            DB_PRINT("%s.%d Failed to allocate hash context, rc 0x%02x = %s\n", __FUNCTION__,
                            __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        if (OK != pHashAlg->initFunc(MOC_HASH(hwAccelCtx) bulkCtx))
        {
            rc = TSS2_SYS_RC_IO_ERROR;
            DB_PRINT("%s.%d Failed to init hash context, rc 0x%02x = %s\n", __FUNCTION__,
                            __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        if (OK != ubyte4ToArray(counter, (ubyte *)&counterTpmCanonical))
        {
            rc = TSS2_SYS_RC_IO_ERROR;
            DB_PRINT("%s.%d Failed conversion to big endian, rc 0x%02x = %s\n", __FUNCTION__,
                            __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        if (OK != pHashAlg->updateFunc(MOC_HASH(hwAccelCtx) bulkCtx, (ubyte*)&counterTpmCanonical, sizeof(counterTpmCanonical)))
        {
            rc = TSS2_SYS_RC_IO_ERROR;
            DB_PRINT("%s.%d Failed to update hash context with counter, rc 0x%02x = %s\n", __FUNCTION__,
                            __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        if (OK != pHashAlg->updateFunc(MOC_HASH(hwAccelCtx) bulkCtx, pZpointX, zPointXLen))
        {
            rc = TSS2_SYS_RC_IO_ERROR;
            DB_PRINT("%s.%d Failed to update hash context with zPoint, rc 0x%02x = %s\n", __FUNCTION__,
                            __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        if (OK != pHashAlg->updateFunc(MOC_HASH(hwAccelCtx) bulkCtx, pOtherInfo, otherInfoLen))
        {
            rc = TSS2_SYS_RC_IO_ERROR;
            DB_PRINT("%s.%d Failed to update hash context with otherInfo, rc 0x%02x = %s\n", __FUNCTION__,
                            __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        if (OK != pHashAlg->finalFunc(MOC_HASH(hwAccelCtx) bulkCtx, pDigest))
        {
            rc = TSS2_SYS_RC_IO_ERROR;
            DB_PRINT("%s.%d Failed to finalize hash, rc 0x%02x = %s\n", __FUNCTION__,
                            __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        pHashAlg->freeFunc(MOC_HASH(hwAccelCtx) &bulkCtx);
        bulkCtx = NULL;

        bytesThisRound = (remBytesToProduce >= pHashAlg->digestSize) ?
                pHashAlg->digestSize : remBytesToProduce;
        if (OK != DIGI_MEMCPY(pOut, pDigest, bytesThisRound))
        {
            rc = TSS2_SYS_RC_IO_ERROR;
            DB_PRINT("%s.%d Failed Memcpy, rc 0x%02x = %s\n", __FUNCTION__,
                            __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        if (OK != DIGI_MEMSET(pDigest, 0, pHashAlg->digestSize))
        {
            rc = TSS2_SYS_RC_IO_ERROR;
            DB_PRINT("%s.%d Failed memset, rc 0x%02x = %s\n", __FUNCTION__,
                            __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        counter++;
        remBytesToProduce -= bytesThisRound;
        pOut += bytesThisRound;
    }

    rc = TSS2_RC_SUCCESS;
exit:
    if (pHashAlg && bulkCtx)
        pHashAlg->freeFunc(MOC_HASH(hwAccelCtx) &bulkCtx);

    if (pHashAlg && pDigest)
        shredMemory(&pDigest, pHashAlg->digestSize, TRUE);

    if ((otherInfoLen > 0) && pOtherInfo)
        shredMemory(&pOtherInfo, otherInfoLen, TRUE);
    
#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    (void) HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);
#endif
    
    return rc;
}
/*
 * Convert from RSAKey to Mocana public and private keys. This is typically used when
 * we want to load an external key into the TPM.
 */
TSS2_RC SAPI2_UTILS_convertRSAKeyToTpm2Rsa(
        RSAKey *pRsaKey,
        TPM2B_PUBLIC_KEY_RSA *pRsaPublic,
        TPM2B_PRIVATE_KEY_RSA *pRsaPrivate
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    MRsaKeyTemplate template = { 0 };
#else
    sbyte4 priKeySize = 0;
#endif
#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    hwAccelDescr hwAccelCtx = 0;
#endif

    if (!pRsaKey || !pRsaPublic || !pRsaPrivate)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointers, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }
    
#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    if( 0 != HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx) )
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("Cannot open hwAccel channel.\n", __FUNCTION__,
                 __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }
#endif

    rc = SAPI2_UTILS_convertRSAPublicToTpm2RsaPublic(MOC_RSA(hwAccelCtx) pRsaKey, pRsaPublic);
    if (TSS2_RC_SUCCESS != rc)
    {
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (OK != CRYPTO_INTERFACE_RSA_getKeyParametersAlloc( MOC_RSA(hwAccelCtx)
            pRsaKey, &template, MOC_GET_PRIVATE_KEY_DATA, akt_rsa))
    {
        DB_PRINT("%s.%d Failed to extract RSA private key, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (template.pLen > sizeof(pRsaPrivate->buffer))
    {
        rc = TSS2_SYS_RC_GENERAL_FAILURE;
        DB_PRINT("%s.%d RSA Key size too large\n", __FUNCTION__,
        __LINE__);
        goto exit;
    }

    if (OK != DIGI_MEMSET(
            pRsaPrivate->buffer, 0x00,
            sizeof(pRsaPrivate->buffer) - template.pLen))
    {
        DB_PRINT("%s.%d Failed to extract RSA private key, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (OK != DIGI_MEMCPY(
            pRsaPrivate->buffer + (sizeof(pRsaPrivate->buffer) - template.pLen),
            template.pP, template.pLen))
    {
        DB_PRINT("%s.%d Failed to extract RSA private key, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }
#else
    priKeySize = 0;
    if (OK != VLONG_byteStringFromVlong(RSA_P(pRsaKey),
            NULL, &priKeySize))
    {
        DB_PRINT("%s.%d Failed to extract RSA private key, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (priKeySize > sizeof(pRsaPrivate->buffer))
    {
        rc = TSS2_SYS_RC_GENERAL_FAILURE;
        DB_PRINT("%s.%d RSA Key size too large\n", __FUNCTION__,
        __LINE__);
        goto exit;
    }

    if (OK != VLONG_byteStringFromVlong(RSA_P(pRsaKey),
            pRsaPrivate->buffer, &priKeySize))
    {
        DB_PRINT("%s.%d Failed to extract RSA private key, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pRsaPrivate->size = priKeySize;
#endif

    rc = TSS2_RC_SUCCESS;
exit:
    
#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    (void) HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);
#endif
    
    return rc;
}

/*
 * Convert from RSAKey public to TPM2 public key
 */
TSS2_RC SAPI2_UTILS_convertRSAPublicToTpm2RsaPublic(
    MOC_RSA(hwAccelDescr hwAccelCtx)
    RSAKey *pRsaKey,
    TPM2B_PUBLIC_KEY_RSA *pTpm2Rsa
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    sbyte4 keySize = 0;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    MRsaKeyTemplate template = { 0 };
#endif

    if (!pRsaKey || !pTpm2Rsa)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointers, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    keySize = 0;
    /*
     * Get Key Size
     */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (OK != CRYPTO_INTERFACE_RSA_getKeyParametersAlloc( MOC_RSA(hwAccelCtx)
            pRsaKey, &template, MOC_GET_PUBLIC_KEY_DATA, akt_rsa))
    {
        DB_PRINT("%s.%d Failed to get RSA public key length, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    keySize = (sbyte4) template.nLen;
#else
    if (OK != VLONG_byteStringFromVlong(RSA_N(pRsaKey),
            NULL, &(keySize)))
    {
        DB_PRINT("%s.%d Failed to get RSA public key length, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }
#endif

    if (keySize > (sbyte4) sizeof(pTpm2Rsa->buffer))
    {
        rc = TSS2_SYS_RC_GENERAL_FAILURE;
        DB_PRINT("%s.%d RSA Key size too large\n", __FUNCTION__,
        __LINE__);
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (OK != DIGI_MEMCPY(pTpm2Rsa->buffer, template.pN, keySize))
    {
        DB_PRINT("%s.%d Failed to extract RSA public key, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }
#else
    if (OK != VLONG_byteStringFromVlong(RSA_N(pRsaKey),
            pTpm2Rsa->buffer, &(keySize)))
    {
        DB_PRINT("%s.%d Failed to extract RSA public key, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }
#endif

    pTpm2Rsa->size = keySize;

    rc = TSS2_RC_SUCCESS;
exit:

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    CRYPTO_INTERFACE_RSA_freeKeyTemplate(pRsaKey, &template, akt_rsa);
#endif

    return rc;
}

/*
 * Convert TPM2 public RSA key into RSAKey. Essentially extacting the TPM2 public key into
 * the mocana format.
 */
TSS2_RC SAPI2_UTILS_convertTpm2RsaPublicToRSAKey(
        MOC_RSA(hwAccelDescr hwAccelCtx)
        TPM2B_PUBLIC_KEY_RSA *pRsa,
        RSAKey **ppKey,
        ubyte4 exponent
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    byteBoolean destroyKeyOnError = FALSE;

    if (!pRsa || !ppKey || *ppKey)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointers, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (OK != CRYPTO_INTERFACE_RSA_createKey((void **)ppKey, akt_rsa, NULL))
#else
    if (OK != RSA_createKey(ppKey))
#endif
    {
        DB_PRINT("\nFailed to create RSA public key\n");
        goto exit;
    }

    destroyKeyOnError = TRUE;

    /*
     * if exponent is 0, the tpm defaults to 0x10001
     */
    if (0 == exponent)
        exponent = 0x10001;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (OK != CRYPTO_INTERFACE_RSA_setPublicKeyParameters(MOC_RSA(hwAccelCtx) *ppKey, exponent,
            pRsa->buffer,
            pRsa->size,
            NULL, akt_rsa))
#else
    if (OK != RSA_setPublicKeyParameters(MOC_RSA(hwAccelCtx) *ppKey, exponent,
            pRsa->buffer,
            pRsa->size,
            NULL))
#endif
    {
        DB_PRINT("\nFailed to set rsa key public parameters\n");
        goto exit;
    }

    rc = TSS2_RC_SUCCESS;
exit:
    if (rc != TSS2_RC_SUCCESS && destroyKeyOnError)
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_RSA_freeKey((void **)ppKey, NULL, akt_rsa);
#else
        RSA_freeKey(ppKey, NULL);
#endif
    return rc;
}

TSS2_RC SAPI2_UTILS_generateRsaSeed(
        MOC_RSA(hwAccelDescr hwAccelCtx)
        RSAKey* pRsaPublicKey,
        ubyte oaepHashOid,
        const ubyte *pLabel,
        ubyte4 labelLen,
        ubyte *pSeedOut,
        ubyte4 seedLen,
        TPM2B_ENCRYPTED_SECRET *pEncryptedSecretOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    MSTATUS status = ERR_GENERAL;
    ubyte4 encryptedSeedOaepLen = 0;
    ubyte *pEncryptedSeedOaep = NULL;

    if (!pRsaPublicKey || !pSeedOut || seedLen == 0 || !pEncryptedSecretOut)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointers, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /*
     * Seed is a random number for RSA secret sharing.
     */
    status = RANDOM_numberGenerator(g_pRandomContext, pSeedOut, seedLen);
    if (OK != status)
    {
        rc = TSS2_SYS_RC_GENERAL_FAILURE;
        DB_PRINT("%s.%d Failed to get random seed\n", __FUNCTION__,
        __LINE__);
        goto exit;
    }

    /*
     * seed is encrypted using OAEP.
     */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (OK != (status = CRYPTO_INTERFACE_PKCS1_rsaOaepEncrypt( MOC_RSA(hwAccelCtx)
        g_pRandomContext, pRsaPublicKey, oaepHashOid, MOC_PKCS1_ALG_MGF1,
        oaepHashOid, pSeedOut, seedLen, pLabel, labelLen,
        &pEncryptedSeedOaep, &encryptedSeedOaepLen)))
#else
    if (OK != (status = PKCS1_rsaesOaepEncrypt(MOC_RSA(hwAccelCtx) g_pRandomContext,
            pRsaPublicKey,
            oaepHashOid, PKCS1_MGF1_FUNC,
            pSeedOut, seedLen,
            pLabel, labelLen,
            &pEncryptedSeedOaep, &encryptedSeedOaepLen)))
#endif
    {
        DB_PRINT("%s.%d Failed to OAEP encrypt random seed\n", __FUNCTION__,
        __LINE__);
        goto exit;
    }

    if (encryptedSeedOaepLen > sizeof(pEncryptedSecretOut->secret))
    {
        rc = TSS2_SYS_RC_BAD_SIZE;
        DB_PRINT("%s.%d Encrypted seed length large.\n", __FUNCTION__,
        __LINE__);
        goto exit;
    }

    pEncryptedSecretOut->size = encryptedSeedOaepLen;
    if (OK != (status = DIGI_MEMCPY(pEncryptedSecretOut->secret, pEncryptedSeedOaep,
            encryptedSeedOaepLen)))
    {
        DB_PRINT("%s.%d Failed to memcpy encrypted random seed\n", __FUNCTION__,
        __LINE__);
        goto exit;
    }

    rc = TSS2_RC_SUCCESS;
    status = OK;
exit:
    if (pEncryptedSeedOaep)
        DIGI_FREE((void **)&pEncryptedSeedOaep);

    return rc;
}

#ifdef __ENABLE_DIGICERT_ECC__
/*
 * Get Mocana EC Curve from TPM2 Curve ID
 */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
TSS2_RC SAPI2_UTILS_getECCurveFromTpm2EccCurveID(
        TPM2_ECC_CURVE curveID,
        ubyte4 *pEccCurveId
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;

    if (!pEccCurveId)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointers, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    switch (curveID)
    {
    case TPM2_ECC_NIST_P224:
        *pEccCurveId = cid_EC_P224;
        break;
    case TPM2_ECC_NIST_P256:
        *pEccCurveId = cid_EC_P256;
        break;
    case TPM2_ECC_NIST_P384:
        *pEccCurveId = cid_EC_P384;
        break;
    case TPM2_ECC_NIST_P521:
        *pEccCurveId = cid_EC_P521;
        break;
    default:
        DB_PRINT("%s.%d Unknown curve ID, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        break;
    }
    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}
#else
TSS2_RC SAPI2_UTILS_getECCurveFromTpm2EccCurveID(
        TPM2_ECC_CURVE curveID,
        PEllipticCurvePtr *pECcurve
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;

    if (!pECcurve)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointers, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    switch (curveID)
    {
    case TPM2_ECC_NIST_P224:
        *pECcurve = EC_P224;
        break;
    case TPM2_ECC_NIST_P256:
        *pECcurve = EC_P256;
        break;
    case TPM2_ECC_NIST_P384:
        *pECcurve = EC_P384;
        break;
    case TPM2_ECC_NIST_P521:
        *pECcurve = EC_P521;
        break;
    default:
        DB_PRINT("%s.%d Unknown curve ID, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        break;
    }
    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}
#endif

/*
 * Get TPM2 curveID from Mocana EC curve
 */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
TSS2_RC SAPI2_UTILS_getTpm2EccCurveIDFromECCurve(
        ubyte4 eccCurveId,
        TPM2_ECC_CURVE *pCurveID
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;

    if (!pCurveID)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointers, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    *pCurveID = TPM2_ECC_NONE;

    if (eccCurveId == cid_EC_P224)
        *pCurveID = TPM2_ECC_NIST_P224;
    else if (eccCurveId == cid_EC_P256)
        *pCurveID = TPM2_ECC_NIST_P256;
    else if (eccCurveId == cid_EC_P384)
        *pCurveID = TPM2_ECC_NIST_P384;
    else if (eccCurveId == cid_EC_P521)
        *pCurveID = TPM2_ECC_NIST_P521;

    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}
#else
TSS2_RC SAPI2_UTILS_getTpm2EccCurveIDFromECCurve(
        PEllipticCurvePtr pECcurve,
        TPM2_ECC_CURVE *pCurveID
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;

    if (!pCurveID)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointers, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    *pCurveID = TPM2_ECC_NONE;

    if (pECcurve == EC_P224)
        *pCurveID = TPM2_ECC_NIST_P224;
    else if (pECcurve == EC_P256)
        *pCurveID = TPM2_ECC_NIST_P256;
    else if (pECcurve == EC_P384)
        *pCurveID = TPM2_ECC_NIST_P384;
    else if (pECcurve == EC_P521)
        *pCurveID = TPM2_ECC_NIST_P521;

    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}
#endif

/*
 * This function converts an ECCKey into a TPM2 public and private ECC key.
 * This will typically be used when we need to load a mocana ecc key into
 * the TPM.
 */
TSS2_RC SAPI2_UTILS_convertEccKeyToTpm2Ecc(
        MOC_ECC(hwAccelDescr hwAccelCtx)
        ECCKey *pEccKey,
        TPMS_ECC_POINT *pEccPublicKey,
        TPM2B_ECC_PARAMETER *pEccPrivateKey
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    sbyte4 priKeySize = 0;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    MEccKeyTemplate template = { 0 };
#endif

    if (!pEccKey || !pEccPublicKey || !pEccPrivateKey)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointers, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    rc = SAPI2_UTILS_convertEccPointToTpm2Point(MOC_ECC(hwAccelCtx) pEccKey, pEccPublicKey);
    if (TSS2_RC_SUCCESS != rc)
    {
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (OK != CRYPTO_INTERFACE_EC_getElementByteStringLen(
            (void *) pEccKey, (ubyte4 *) &priKeySize, akt_ecc))
        goto exit;

    if (OK != CRYPTO_INTERFACE_EC_getKeyParametersAlloc( MOC_ECC(hwAccelCtx)
            (void *) pEccKey, &template, MOC_GET_PRIVATE_KEY_DATA, akt_ecc))
        goto exit;
#else
    if (OK != PRIMEFIELD_getElementByteStringLen(EC_P256->pPF, (sbyte4 *)&priKeySize))
        goto exit;
#endif

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if ( (priKeySize > (sbyte4) sizeof(pEccPrivateKey->buffer)) ||
         (template.privateKeyLen > sizeof(pEccPrivateKey->buffer)) )
#else
    if (priKeySize > (sbyte4) sizeof(pEccPrivateKey->buffer))
#endif
    {
        rc = TSS2_SYS_RC_BAD_SIZE;
        DB_PRINT("%s.%d Invalid key size, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (OK != DIGI_MEMSET(
            pEccPrivateKey->buffer, 0x00,
            (priKeySize - (sbyte4) template.privateKeyLen)))
        goto exit;

    if (OK != DIGI_MEMCPY(
            pEccPrivateKey->buffer + (priKeySize - (sbyte4) template.privateKeyLen),
            template.pPrivateKey, template.privateKeyLen))
        goto exit;
#else
    if (OK != PRIMEFIELD_writeByteString( EC_P256->pPF, pEccKey->k,
            pEccPrivateKey->buffer, priKeySize))
        goto exit;
#endif

    pEccPrivateKey->size = priKeySize;
    rc = TSS2_RC_SUCCESS;
exit:
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    CRYPTO_INTERFACE_EC_freeKeyTemplate((void *) pEccKey, &template, akt_ecc);
#endif
    return rc;
}

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
/* Possible to consolidate this with the tpm2EccKeyFromPublicPoint
 * function in smp_tpm2_api.c depending on how libraries are built.
 */
static MSTATUS tpm2EccKeyFromPublicPoint(
    MOC_ECC(hwAccelDescr hwAccelCtx)
    ECCKey **ppRetKey,
    ubyte4 keyType,
    ubyte4 eccCurveId,
    ubyte *pX,
    ubyte2 xLen,
    ubyte *pY,
    ubyte2 yLen,
    ubyte compressionType
    )
{
    MSTATUS status;
    ubyte *pPoint = NULL;
    ubyte4 pointLen;
    ECCKey *pNewKey = NULL;

    status = ERR_NULL_POINTER;
    if ( (NULL == ppRetKey) || (NULL == pX) || (NULL == pY) )
        goto exit;

    /* This function only allows software key creation.
     */
    status = ERR_EC;
    if (akt_ecc != keyType)
        goto exit;

    /* Create the new key.
     */
    if (OK != (status = CRYPTO_INTERFACE_EC_newKeyEx(
            eccCurveId, &pNewKey, keyType, NULL)))
        goto exit;

    /* Extract the element length
     */
    if (OK != (status = CRYPTO_INTERFACE_EC_getElementByteStringLen(
            pNewKey, &pointLen, keyType)))
        goto exit;

    /* Calculate the point lengths without padded 0's.
     */
    while ( (1 < xLen) && (0 == *pX) )
    {
        pX++;
        xLen--;
    }
    while ( (1 < yLen) && (0 == *pY) )
    {
        pY++;
        yLen--;
    }

    /* Ensure both values are equal to or less then element length.
     */
    status = ERR_BAD_LENGTH;
    if ( (yLen > pointLen) || (xLen > pointLen) )
        goto exit;

    /* Allocate memory for the point.
     */
    if (OK != (status = DIGI_CALLOC((void **) &pPoint, 1, pointLen * 2 + 1)))
        goto exit;

    /* Create the point array. The first byte is the compression type. The
     * next part of the array is the x coordinate which is then followed by the
     * y coordinate.
     */
    *pPoint = compressionType;
    if (OK != (status = DIGI_MEMCPY(pPoint + 1 + (pointLen - xLen), pX, xLen)))
        goto exit;

    if (OK != (status = DIGI_MEMCPY(
            pPoint + 1 + pointLen + (pointLen - yLen), pY, yLen)))
        goto exit;

    /* Set the public portion of the ECC key.
     */
    if (OK != (status = CRYPTO_INTERFACE_EC_setKeyParameters( MOC_ECC(hwAccelCtx)
            pNewKey, pPoint, pointLen * 2 + 1, NULL, 0, keyType)))
        goto exit;

    *ppRetKey = pNewKey;
    pNewKey = NULL;

exit:

    if (NULL != pNewKey)
        CRYPTO_INTERFACE_EC_deleteKey((void **) &pNewKey, keyType);

    if (NULL != pPoint)
        DIGI_FREE((void **) &pPoint);

    return status;
}
#endif

/*
 * This function converts from TPMS_ECC_POINT to ECCKey.
 */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
TSS2_RC SAPI2_UTILS_convertTpm2EccPublicToEccKey(
        MOC_ECC(hwAccelDescr hwAccelCtx)
        TPMS_ECC_POINT *pTpm2EccPoint,
        ubyte4 eccCurveId,
        ECCKey **ppEccKey
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    ECCKey *pEccKey = NULL;

    if (!ppEccKey || *ppEccKey || !pTpm2EccPoint)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointers, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (OK != tpm2EccKeyFromPublicPoint( MOC_ECC(hwAccelCtx)
            ppEccKey, akt_ecc, eccCurveId, pTpm2EccPoint->x.buffer,
            pTpm2EccPoint->x.size, pTpm2EccPoint->y.buffer,
            pTpm2EccPoint->y.size, 0x04))
    {
        DB_PRINT("%s.%d Unable to create ECC key, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pEccKey = *ppEccKey;

    rc = TSS2_RC_SUCCESS;
exit:
    if (TSS2_RC_SUCCESS != rc)
        CRYPTO_INTERFACE_EC_deleteKey((void **) ppEccKey, akt_ecc);
    return rc;
}
#else
TSS2_RC SAPI2_UTILS_convertTpm2EccPublicToEccKey(
        TPMS_ECC_POINT *pTpm2EccPoint,
        PEllipticCurvePtr pECcurve,
        ECCKey **ppEccKey
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    ECCKey *pEccKey = NULL;

    if (!ppEccKey || *ppEccKey || !pTpm2EccPoint || !pECcurve)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointers, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (OK != EC_newKey(pECcurve, ppEccKey))
    {
        DB_PRINT("%s.%d Unable to create ECC key, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pEccKey = *ppEccKey;

    if (OK != PRIMEFIELD_setToByteString(pECcurve->pPF, pEccKey->Qx,
            pTpm2EccPoint->x.buffer,
            pTpm2EccPoint->x.size))
        goto exit;

    if (OK != PRIMEFIELD_setToByteString(pECcurve->pPF, pEccKey->Qy,
            pTpm2EccPoint->y.buffer,
            pTpm2EccPoint->y.size))
        goto exit;

    rc = TSS2_RC_SUCCESS;
exit:
    if (TSS2_RC_SUCCESS != rc)
        EC_deleteKey(ppEccKey);
    return rc;
}
#endif

/*
 * This extracts the ecc public point from the mocana format and converts it into the TPM2
 * format.
 */
TSS2_RC SAPI2_UTILS_convertEccPointToTpm2Point(
        MOC_ECC(hwAccelDescr hwAccelCtx)
        ECCKey *pEccKey,
        TPMS_ECC_POINT *pTpm2EccPoint
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    sbyte4 xlen = 0;
    sbyte4 ylen = 0;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    MEccKeyTemplate template = { 0 };
#endif

    if (!pEccKey || !pTpm2EccPoint)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointers, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (OK != CRYPTO_INTERFACE_EC_getElementByteStringLen(
            (void *) pEccKey, (ubyte4 *) &xlen, akt_ecc))
        goto exit;

    ylen = xlen;
#else
    if (OK != PRIMEFIELD_getElementByteStringLen(pEccKey->pCurve->pPF, &xlen))
        goto exit;

    if (OK != PRIMEFIELD_getElementByteStringLen(pEccKey->pCurve->pPF, &ylen))
        goto exit;
#endif

    pTpm2EccPoint->x.size = xlen;
    pTpm2EccPoint->y.size = ylen;

    if (pTpm2EccPoint->x.size > sizeof(pTpm2EccPoint->x.buffer) ||
            pTpm2EccPoint->y.size > sizeof(pTpm2EccPoint->y.buffer))
    {
        rc = TSS2_SYS_RC_BAD_SIZE;
        DB_PRINT("%s.%d Invalid size for ecc point, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (OK != CRYPTO_INTERFACE_EC_getKeyParametersAlloc(MOC_ECC(hwAccelCtx)
            (void *) pEccKey, &template, MOC_GET_PUBLIC_KEY_DATA, akt_ecc))
        goto exit;

    if ((sbyte4) template.publicKeyLen != (1 + xlen + ylen))
        goto exit;

    if (OK != DIGI_MEMCPY(
            pTpm2EccPoint->x.buffer, template.pPublicKey + 1, xlen))
        goto exit;

    if (OK != DIGI_MEMCPY(
            pTpm2EccPoint->y.buffer, template.pPublicKey + 1 + xlen, ylen))
        goto exit;
#else
    if (OK != PRIMEFIELD_writeByteString(pEccKey->pCurve->pPF, pEccKey->Qx,
            pTpm2EccPoint->x.buffer, pTpm2EccPoint->x.size))
        goto exit;

    if (OK != PRIMEFIELD_writeByteString(pEccKey->pCurve->pPF, pEccKey->Qy,
            pTpm2EccPoint->y.buffer, pTpm2EccPoint->y.size))
        goto exit;
#endif

    rc = TSS2_RC_SUCCESS;
exit:
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    CRYPTO_INTERFACE_EC_freeKeyTemplate((void *) pEccKey, &template, akt_ecc);
#endif
    return rc;
}

TSS2_RC SAPI2_UTILS_generateECCSeed(
        MOC_ECC(hwAccelDescr hwAccelCtx)
        ECCKey *pEccPublicKey,
        const ubyte *pLabel,
        ubyte4 labelLen,
        TPM2_ALG_ID kdfeHashAlg,
        ubyte *pSeedOut,
        ubyte4 seedLen,
        TPM2B_ENCRYPTED_SECRET *pEncryptedSecret
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    MSTATUS status = ERR_GENERAL;
    sbyte4 sharedSecretLen = 0;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    ubyte4 eccCurveId;
#else
    PEllipticCurvePtr pECcurve = NULL;
#endif
    ECCKey *pECDHKey = NULL;
    ubyte *pSharedSecret = NULL;
    TPMS_ECC_POINT ecdhKeyTpm2Form = { 0 };
    TPMS_ECC_POINT publicKeyTpm2Form  = { 0 };
    ubyte4 serializedOffset = 0;

    if (!pEccPublicKey || !pSeedOut || (seedLen == 0) || !pEncryptedSecret)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointers, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /*
     * For ECC EK's, we perform ECDH. So generate an epheremeral key pair, which becomes
     * the encrypted secret, from which the TPM will derive the seed.
     */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (OK != (status = CRYPTO_INTERFACE_EC_getCurveIdFromKey(
            (void *) pEccPublicKey, &eccCurveId, akt_ecc)))
        goto exit;
#else
    pECcurve = pEccPublicKey->pCurve;
#endif

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (OK != (status = CRYPTO_INTERFACE_EC_generateKeyPairAlloc(MOC_ECC(hwAccelCtx)
            eccCurveId, (void **) &pECDHKey, RANDOM_rngFun, g_pRandomContext,
            akt_ecc, NULL)))
    {
        DB_PRINT("%s.%d Failed to generate new EC key\n", __FUNCTION__,
        __LINE__);
        goto exit;
    }
#else
    if (OK != (status = EC_newKey(pECcurve, &pECDHKey)))
    {
        DB_PRINT("%s.%d Failed to create new EC key\n", __FUNCTION__,
        __LINE__);
        goto exit;
    }

    if (OK != (status = EC_generateKeyPair(pECcurve, RANDOM_rngFun,g_pRandomContext,
            pECDHKey->k, pECDHKey->Qx,
            pECDHKey->Qy)))
    {
        DB_PRINT("%s.%d Failed to generate new EC key\n", __FUNCTION__,
        __LINE__);
        goto exit;
    }
#endif

    rc = SAPI2_UTILS_convertEccPointToTpm2Point(MOC_ECC(hwAccelCtx) pECDHKey, &ecdhKeyTpm2Form);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to convert EC key to tpm2 form\n", __FUNCTION__,
        __LINE__);
        goto exit;
    }

    rc = SAPI2_UTILS_convertEccPointToTpm2Point(MOC_ECC(hwAccelCtx) pEccPublicKey, &publicKeyTpm2Form);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to convert EC key to tpm2 form\n", __FUNCTION__,
                __LINE__);
        goto exit;
    }
    /*
     * The encrypted secret for ECC EK is the marshalled public point.
     */
    status = TAP_SERIALIZE_serialize(&TPM2_SHADOW_TPMS_ECC_POINT, TAP_SD_IN,
            (ubyte*)&ecdhKeyTpm2Form, sizeof(ecdhKeyTpm2Form),
            pEncryptedSecret->secret, sizeof(pEncryptedSecret->secret),
            &serializedOffset);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to serialized ECDH public point\n", __FUNCTION__,
        __LINE__);
        goto exit;
    }

    pEncryptedSecret->size = serializedOffset;

    /*
     * Use the generated ephemeral key and the EC publicKey, to generate the shared secret. THis is fed
     * through KDFe, to generate the seed. the TPM will use the public point of the key pair generated
     * to derive the shared secret and the seed.
     */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (OK != (status = CRYPTO_INTERFACE_ECDH_generateSharedSecretFromKeys( MOC_ECC(hwAccelCtx)
            (void *) pECDHKey, (void *) pEccPublicKey, &pSharedSecret,
            (ubyte4 *) &sharedSecretLen, 1, NULL, akt_ecc)))
#else
    if (OK != (status = ECDH_generateSharedSecretAux(pECcurve,
            pEccPublicKey->Qx,
            pEccPublicKey->Qy,
            pECDHKey->k,
            &pSharedSecret, &sharedSecretLen, 1)))
#endif
    {
        DB_PRINT("%s.%d Failed to get ECDH shared secret\n", __FUNCTION__,
        __LINE__);
        goto exit;
    }

    if (TSS2_RC_SUCCESS != SAPI2_UTILS_TPM2_KDFE(kdfeHashAlg,
            pSharedSecret, sharedSecretLen,
            (const char *)pLabel,
            ecdhKeyTpm2Form.x.buffer, ecdhKeyTpm2Form.x.size,
            publicKeyTpm2Form.x.buffer, publicKeyTpm2Form.x.size,
            pSeedOut, seedLen
            ))
    {
        status = ERR_INTERNAL_ERROR;
        DB_PRINT("%s.%d Failed to generate seed from KDFe\n", __FUNCTION__,
        __LINE__);
        goto exit;
    }

    rc = TSS2_RC_SUCCESS;
    status = OK;
exit:
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (pECDHKey)
        CRYPTO_INTERFACE_EC_deleteKey((void **) &pECDHKey, akt_ecc);
#else
    if (pECDHKey)
        EC_deleteKey(&pECDHKey);
#endif

    if (pSharedSecret)
        DIGI_FREE((void **)&pSharedSecret);
    return rc;
}
#endif /* #ifdef __ENABLE_DIGICERT_ECC__ */
#endif /* ifdef __ENABLE_DIGICERT_TPM2__ */
#endif /* if (defined(__ENABLE_DIGICERT_TPM2__) || defined(__ENABLE_DIGICERT_SMP_PKCS11__)) */
