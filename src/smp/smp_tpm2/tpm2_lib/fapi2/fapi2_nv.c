/**
 * @file fapi2_nv.c
 * @brief This file contains functions to use the TPM2 NV RAM.
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
#include "../../../../crypto/hw_accel.h"
#include "../../../../common/debug_console.h"
#include "../tpm_common/tpm_error_utils.h"
#include "fapi2.h"
#include "fapi2_internal.h"


/* TPM well-known secret for platform authentication */
static TPM2B_AUTH wellknownPlatformAuth =
            {
                20,
                {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
            };

/*
 * This API creates/defines an NV index in the TPM.
 * The NV index defined by this API creates an NV index that
 * can be authorized by the authValue provided here or with
 * the owner hierarchy authValue. The NV Index created does
 * not allow partial writes. It can also be locked from further
 * writes. The owner hierarchy authValue is expected to be set
 * appropriately in the FAPI2_CONTEXT to successfully execute
 * this API.
 */
TSS2_RC FAPI2_NV_define(
        FAPI2_CONTEXT *pCtx,
        NVDefineIn *pIn
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TSS2_RC exit_rc = TSS2_RC_SUCCESS;
    TPM2B_NV_PUBLIC nvPublic = { 0 };
    NVDefineSpaceIn nvDefineSpaceIn = { 0 };
    NVDefineSpaceOut nvDefineSpaceOut = { 0 };
    MOCTPM2_OBJECT_HANDLE *pAuthSession = NULL;
    MOCTPM2_OBJECT_HANDLE *pNvHandle = NULL;
    PolicyAuthNode defaultPolicy = { 0 };
    PolicyAuthNode *pObjectPolicy = NULL;
    ubyte2 numPolicyTerms = 0;

    if (!pCtx || !pIn)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (!pCtx->authValues.ownerAuthValid)
    {
        rc = TSS2_SYS_RC_NOT_PERMITTED;
        DB_PRINT("%s.%d Invalid authValue for owner hierarchy."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    TPM2B_SIZE_CHECK(&pIn->nvAuth, pCtx->nameAlgSize);

    if ((pIn->nvIndex < TPM2_NV_INDEX_FIRST) ||
            (pIn->nvIndex > TPM2_NV_INDEX_LAST))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid nv index specified, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((pIn->nvIndexType != TPM2_NT_ORDINARY) &&
            (pIn->nvIndexType != TPM2_NT_EXTEND) &&
            (pIn->nvIndexType != TPM2_NT_COUNTER) &&
            (pIn->nvIndexType != TPM2_NT_BITS))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid nv index type specified, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /*
     * For extend index's it doesnt make sense to have an extend index
     * whose size is greater than the TPM2_MAX_NV_BUFFER size. If the
     * index size were greater than that, there would be no way to extend
     * data into the index in one transaction, since only TPM2_MAX_NV_BUFFER
     * bytes of data can be sent to the TPM in any one NV extend command.
     */
    if ((pIn->nvIndexType == TPM2_NT_EXTEND) &&
            (pIn->dataSize > pCtx->maxNvTransactionSize))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Extend index size > max nv transaction size"
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (pIn->dataSize > pCtx->maxNvIndexSize)
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid nv index size specified. Too large, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    rc = FAPI2_UTILS_startSession(pCtx, &pAuthSession);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to Start session."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((TPM2_NT_COUNTER == pIn->nvIndexType) ||
            (TPM2_NT_BITS == pIn->nvIndexType))
        pIn->dataSize = 8;

    nvPublic.nvPublic.nvIndex = pIn->nvIndex;
    nvPublic.nvPublic.nameAlg = pCtx->nameAlg;
    nvPublic.nvPublic.dataSize = pIn->dataSize;
    nvPublic.nvPublic.attributes = TPMA_NV_OWNERWRITE |
            TPMA_NV_POLICYWRITE |
            TPMA_NV_WRITEDEFINE | TPMA_NV_GLOBALLOCK |
            TPMA_NV_OWNERREAD | TPMA_NV_POLICYREAD;

    nvPublic.nvPublic.attributes |= (pIn->nvIndexType << 4);

    if ((pIn->numPolicyTerms != 0) && (pIn->pPolicy))
    {
        numPolicyTerms = pIn->numPolicyTerms;
        pObjectPolicy = pIn->pPolicy;
    }
    else
    {
        /*
         * Setup policy only for non platform authorization handles
         */ 
        if (TPM2_RH_PLATFORM != pIn->authHandle)
        {
            numPolicyTerms = 1;
            defaultPolicy.policyType = FAPI2_POLICY_AUTH_VALUE;
            pObjectPolicy = &defaultPolicy;
        }
    }

    if (numPolicyTerms && pObjectPolicy)
    {
        rc = FAPI2_UTILS_fillPolicyDigest(pCtx, numPolicyTerms, pObjectPolicy,
                &nvPublic.nvPublic.authPolicy);
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed to get policy digest."
                    ", rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
    }

    if (pIn->disableDA)
        nvPublic.nvPublic.attributes |= TPMA_NV_NO_DA;

    switch(pIn->authHandle)
    {
        case TPM2_RH_PLATFORM:
            {
                nvDefineSpaceIn.authHandle = pIn->authHandle;
                nvDefineSpaceIn.pAuthHandleAuth = (0 < pIn->authHandleAuth.size) ?
                             &pIn->authHandleAuth : &wellknownPlatformAuth;
                nvPublic.nvPublic.attributes |= TPMA_NV_PLATFORMCREATE | 
                                            TPMA_NV_PPWRITE | TPMA_NV_PPREAD | TPMA_NV_AUTHREAD;
                nvPublic.nvPublic.attributes &= ~TPMA_NV_OWNERWRITE;
                nvPublic.nvPublic.attributes &= ~TPMA_NV_POLICYREAD;
                nvPublic.nvPublic.attributes &= ~TPMA_NV_POLICYWRITE;
                nvPublic.nvPublic.attributes &= ~TPMA_NV_GLOBALLOCK;
            }
            break;

        case TPM2_RH_OWNER:
        default:
            {
                nvDefineSpaceIn.authHandle = TPM2_RH_OWNER;
                nvDefineSpaceIn.pAuthHandleAuth = &(pCtx->authValues.ownerAuth);
            }
            break;
    }


    nvDefineSpaceIn.pAuthSession = pAuthSession;
    nvDefineSpaceIn.pPublicInfo = &nvPublic;
    nvDefineSpaceIn.pNvAuth = &pIn->nvAuth;

    rc = SAPI2_NV_NVDefineSpace(pCtx->pSapiCtx, &nvDefineSpaceIn,
            &nvDefineSpaceOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to define nv space."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pNvHandle = nvDefineSpaceOut.pNvIndexHandle;

    rc = TSS2_RC_SUCCESS;
exit:
    if (pAuthSession)
    {
        exit_rc = FAPI2_UTILS_closeSession(pCtx,
                &pAuthSession);
        if (TSS2_RC_SUCCESS == rc)
            rc = exit_rc;
    }

    if (pNvHandle)
        exit_rc = FAPI2_UTILS_destroyHandle(pCtx, &pNvHandle);

    if (TSS2_RC_SUCCESS == rc)
        rc = exit_rc;

    return rc;
}

/*
 * This API writes to an already defined/created NV index.
 */
TSS2_RC FAPI2_NV_writeOp(
        FAPI2_CONTEXT *pCtx,
        NVWriteOpIn *pIn
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TSS2_RC exit_rc = TSS2_RC_SUCCESS;
    UtilsCreateObjectIn createObjectIn = { 0 };
    UtilsCreateObjectOut createObjectOut = { 0 };
    UtilsCreateHandleIn createHandleIn = { 0 };
    UtilsCreateHandleOut createHandleOut = { 0 };
    FAPI2_OBJECT *pNvObject = NULL;
    MOCTPM2_OBJECT_HANDLE *pNvHandle = NULL;
    TPMS_NV_PUBLIC *pNvPublic = NULL;
    ubyte nvIndexType = 0xFF;
    NVWriteIn nvWriteIn = { 0 };
    NVIncrementIn nvIncrementIn = { 0 };
    NVExtendIn nvExtendIn = { 0 };
    NVSetBitsIn nvSetBitsIn = { 0 };
    NVWriteLockIn nvWriteLockIn = { 0 };
    MOCTPM2_OBJECT_HANDLE *pAuthSession = NULL;
    TPM2B_MAX_NV_BUFFER *pNvWriteData = NULL;
    ubyte4 remaining = 0;
    ubyte4 offset = 0;
    EaExecutePolicyIn eaExecutePolicyIn = { 0 };
    EaExecutePolicyOut eaExecutePolicyOut = { 0 };
    TPMI_RH_PROVISION authHandle = TPM2_RH_OWNER;
    TPM2B_AUTH *pAuthHandleAuth = NULL;

    if (!pCtx || !pIn)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((pIn->nvAuth.size == 0) && (!pCtx->authValues.ownerAuthValid))
    {
        rc = TSS2_SYS_RC_NOT_PERMITTED;
        DB_PRINT("%s.%d Invalid authValue for owner hierarchy."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    TPM2B_SIZE_CHECK(&pIn->nvAuth, pCtx->nameAlgSize);

    if ((pIn->nvIndex < TPM2_NV_INDEX_FIRST) ||
            (pIn->nvIndex > TPM2_NV_INDEX_LAST))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid nv index specified, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    createObjectIn.tpm2Handle = pIn->nvIndex;
#if defined(__RTOS_WIN32__) && !defined(__USE_TPM_EMULATOR__)
    if (pIn->nvAuth.size != 0)
    {
        createObjectIn.numPolicyTerms = 1;
        if (OK != DIGI_CALLOC(&createObjectIn.pObjectPolicy, 1, 
                        sizeof(*createObjectIn.pObjectPolicy)))
        {
            rc = TSS2_SYS_RC_GENERAL_FAILURE;
            DB_PRINT("%s.%d Failed to allocate memory for PolicyObjectNode, rc 0x%02x = %s\n",
                __FUNCTION__, __LINE__, rc, tss2_err_string(rc));
        }
        createObjectIn.pObjectPolicy[0].policyType = FAPI2_POLICY_AUTH_VALUE;
    }
#endif /*__RTOS_WIN32__ && !__USE_TPM_EMULATOR__*/
    rc = FAPI2_UTILS_createObject(pCtx, &createObjectIn,
            &createObjectOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to create object for NV, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pNvObject = createObjectOut.pObject;
    pNvPublic = &pNvObject->public.nvPublic.nvPublic;

    if (pNvPublic->attributes & TPMA_NV_WRITELOCKED)
    {
        rc = TSS2_SYS_RC_NOT_PERMITTED;
        DB_PRINT("%s.%d Index write locked, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /*
     * bits 7:4 contain the type information.
     */
    nvIndexType = (pNvPublic->attributes >> 4) & 0xF;

    createHandleIn.pObject = pNvObject;
    rc = FAPI2_UTILS_createHandle(pCtx, &createHandleIn,
            &createHandleOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to create handle for NV, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pNvHandle = createHandleOut.pHandle;

    /*
     * Use policy authorization if we are using the NV index for authorization. If we use
     * owner authorization, use regular HMAC session until we have support policies for
     * hierarchies.
     */
    if (pIn->nvAuth.size != 0)
    {
        rc = FAPI2_UTILS_getObjectAuthSession(pCtx, pNvObject, &pAuthSession);
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed to Start session."
                    ", rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
    }
    else
    {
        rc = FAPI2_UTILS_startSession(pCtx, &pAuthSession);
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed to Start session."
                    ", rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
    }

    switch(pIn->authHandle)
    {
        case TPM2_RH_PLATFORM:
            {
                authHandle = pIn->authHandle;
                pAuthHandleAuth = (0 < pIn->authHandleAuth.size) ?
                                 &pIn->authHandleAuth : &wellknownPlatformAuth;
            }
            break;

        case TPM2_RH_OWNER:
        default:
            {
                authHandle = TPM2_RH_OWNER;
                pAuthHandleAuth = &(pCtx->authValues.ownerAuth);
            }
            break;
    }

    switch (pIn->writeOp)
    {
    case FAPI2_NV_WRITE_OP_WRITE:
        if (nvIndexType != TPM2_NT_ORDINARY)
        {
            rc = TSS2_SYS_RC_BAD_VALUE;
            DB_PRINT("%s.%d Cannot write to non-ordinary index, rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        TPM2B_SIZE_CHECK(&(pIn->write.writeData),
                TPM2B_MAX_SIZE(&(pIn->write.writeData)));

        if (pIn->write.writeData.size != pNvPublic->dataSize)
        {
            rc = TSS2_SYS_RC_BAD_VALUE;
            DB_PRINT("%s.%d data size does not match nv index"
                    "data size, rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        /*
         * Need to split writes if the write size greater than size allowed
         * by TPM for read/write.
         */
        if (OK != DIGI_CALLOC((void **)&pNvWriteData, 1,sizeof(*pNvWriteData)))
        {
            rc = TSS2_SYS_RC_IO_ERROR;
            DB_PRINT("%s.%d Failed to allocate memory, rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        nvWriteIn.pAuthSession = pAuthSession;
        nvWriteIn.pData = pNvWriteData;
        nvWriteIn.pNvIndexHandle = pNvHandle;
        if (pIn->nvAuth.size != 0)
        {
            nvWriteIn.useNvHandleForAuth = TRUE;
            nvWriteIn.pAuthHandleAuth = &pIn->nvAuth;
        }
        else
        {
            nvWriteIn.useNvHandleForAuth = FALSE;
            nvWriteIn.authHandle = authHandle;
            nvWriteIn.pAuthHandleAuth = pAuthHandleAuth;
        }

        remaining = pIn->write.writeData.size;

        while (remaining > 0)
        {
            pNvWriteData->size =
                    (remaining > pCtx->maxNvTransactionSize) ?
                            pCtx->maxNvTransactionSize : remaining;

            DIGI_MEMCPY(pNvWriteData->buffer,
                    &(pIn->write.writeData.buffer[offset]), pNvWriteData->size);

            nvWriteIn.offset = offset;

            rc = SAPI2_NV_NVWrite(pCtx->pSapiCtx, &nvWriteIn);
            if (TSS2_RC_SUCCESS != rc)
            {
                DB_PRINT("%s.%d Failed to write NV Index, rc 0x%02x = %s\n",
                        __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
                goto exit;
            }

            remaining -= pNvWriteData->size;
            offset += pNvWriteData->size;

            /*
             * re-execute the policy, if the object has a policy. Since the sessions are
             * started with the continueSession attribute set, the TPM starts a new epoch
             * every time the policy session is used for authorization and clears the
             * policyDigest. Hence, successive use of the same session, without re-executing
             * the policy will fail authorization.
             * If the session does not have the continue session attribute, we would need
             * to flush the policySession and restart it every time. Executing the policy
             * on an existing session instead, is more efficient.
             */
            if (pNvObject->numPolicyTerms && (pIn->nvAuth.size != 0))
            {
                eaExecutePolicyIn.pSession = pAuthSession;
                eaExecutePolicyIn.numPolicyTerms = pNvObject->numPolicyTerms;
                eaExecutePolicyIn.pObjectPolicy = pNvObject->objectPolicy;
                rc = FAPI2_EA_executePolicy(pCtx, &eaExecutePolicyIn, &eaExecutePolicyOut);
                if (TSS2_RC_SUCCESS != rc)
                {
                    DB_PRINT("%s.%d Failed to execute object policy."
                            ", rc 0x%02x = %s\n",
                            __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
                    goto exit;
                }
            }

        }

        break;
    case FAPI2_NV_WRITE_OP_INCREMENT:
        if (nvIndexType != TPM2_NT_COUNTER)
        {
            rc = TSS2_SYS_RC_BAD_VALUE;
            DB_PRINT("%s.%d Cannot increment to non-counter index, rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        nvIncrementIn.pAuthSession = pAuthSession;
        nvIncrementIn.pNvIndexHandle = pNvHandle;
        if (pIn->nvAuth.size != 0)
        {
            nvIncrementIn.useNvHandleForAuth = TRUE;
            nvIncrementIn.pAuthHandleAuth = &pIn->nvAuth;
        }
        else
        {
            nvIncrementIn.authHandle = authHandle;
            nvIncrementIn.pAuthHandleAuth = pAuthHandleAuth;
        }

        rc = SAPI2_NV_NVIncrement(pCtx->pSapiCtx, &nvIncrementIn);
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed to increment NV Index, rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        break;
    case FAPI2_NV_WRITE_OP_SET_BITS:
        if (nvIndexType != TPM2_NT_BITS)
        {
            rc = TSS2_SYS_RC_BAD_VALUE;
            DB_PRINT("%s.%d Cannot increment to non-bitfield index, rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
        nvSetBitsIn.pAuthSession = pAuthSession;
        nvSetBitsIn.pNvIndexHandle = pNvHandle;
        nvSetBitsIn.pBits = &(pIn->write.writeValBits);
        if (pIn->nvAuth.size != 0)
        {
            nvSetBitsIn.useNvHandleForAuth = TRUE;
            nvSetBitsIn.pAuthHandleAuth = &pIn->nvAuth;
        }
        else
        {
            nvSetBitsIn.authHandle = authHandle;
            nvSetBitsIn.pAuthHandleAuth = pAuthHandleAuth;
        }

        rc = SAPI2_NV_NVSetBits(pCtx->pSapiCtx, &nvSetBitsIn);
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed to set bits in NV Index, rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        break;
    case FAPI2_NV_WRITE_OP_EXTEND:
        if (nvIndexType != TPM2_NT_EXTEND)
        {
            rc = TSS2_SYS_RC_BAD_VALUE;
            DB_PRINT("%s.%d Cannot extend to non-extend index, rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        TPM2B_SIZE_CHECK(&(pIn->write.writeData),
                TPM2B_MAX_SIZE(&(pIn->write.writeData)));

        if (pIn->write.writeData.size != pNvPublic->dataSize)
        {
            rc = TSS2_SYS_RC_BAD_VALUE;
            DB_PRINT("%s.%d data size does not match nv index"
                    "data size, rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        nvExtendIn.pAuthSession = pAuthSession;
        nvExtendIn.pData = &pIn->write.writeData;
        nvExtendIn.pNvIndexHandle = pNvHandle;
        if (pIn->nvAuth.size != 0)
        {
            nvExtendIn.useNvHandleForAuth = TRUE;
            nvExtendIn.pAuthHandleAuth = &pIn->nvAuth;
        }
        else
        {
            nvExtendIn.useNvHandleForAuth = FALSE;
            nvExtendIn.authHandle = authHandle;
            nvExtendIn.pAuthHandleAuth = pAuthHandleAuth;
        }

        rc = SAPI2_NV_NVExtend(pCtx->pSapiCtx, &nvExtendIn);
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed to extend NV Index, rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        break;
    case FAPI2_NV_WRITE_OP_WRITE_LOCK:
        if (!(pNvPublic->attributes & TPMA_NV_WRITEDEFINE))
        {
            rc = TSS2_SYS_RC_NOT_PERMITTED;
            DB_PRINT("%s.%d Index cannot be write locked, rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        nvWriteLockIn.pAuthSession = pAuthSession;
        nvWriteLockIn.pNvIndexHandle = pNvHandle;
        if (pIn->nvAuth.size != 0)
        {
            nvWriteLockIn.useNvHandleForAuth = TRUE;
            nvWriteLockIn.pAuthHandleAuth = &pIn->nvAuth;
        }
        else
        {
            nvWriteLockIn.useNvHandleForAuth = FALSE;
            nvWriteLockIn.authHandle = authHandle;
            nvWriteLockIn.pAuthHandleAuth = pAuthHandleAuth;
        }

        rc = SAPI2_NV_NVWriteLock(pCtx->pSapiCtx, &nvWriteLockIn);
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed to write lock NV Index, rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        break;
    default:
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid write operation, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
        break;
    }

    rc = TSS2_RC_SUCCESS;
exit:
#if defined(__RTOS_WIN32__) && !defined(__USE_TPM_EMULATOR__)
    if (NULL != createObjectIn.pObjectPolicy)
        DIGI_FREE(&createObjectIn.pObjectPolicy);
#endif /*__RTOS_WIN32__ && !__USE_TPM_EMULATOR__*/

    if (pNvWriteData)
        shredMemory((ubyte **)&pNvWriteData, sizeof(*pNvWriteData), TRUE);

    if (pAuthSession)
    {
        exit_rc = FAPI2_UTILS_closeSession(pCtx,
                &pAuthSession);
        if (TSS2_RC_SUCCESS == rc)
            rc = exit_rc;
    }

    if (pNvObject)
    {
        exit_rc = FAPI2_UTILS_destroyObject(&pNvObject);
        if (TSS2_RC_SUCCESS == rc)
            rc = exit_rc;
    }

    if (pNvHandle)
        exit_rc = FAPI2_UTILS_destroyHandle(pCtx, &pNvHandle);

    if (TSS2_RC_SUCCESS == rc)
        rc = exit_rc;

    return rc;
}

/*
 * This API reads an already defined/created NV index.
 */
TSS2_RC FAPI2_NV_readOp(
        FAPI2_CONTEXT *pCtx,
        NVReadOpIn *pIn,
        NVReadOpOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TSS2_RC exit_rc = TSS2_RC_SUCCESS;
    UtilsCreateObjectIn createObjectIn = { 0 };
    UtilsCreateObjectOut createObjectOut = { 0 };
    UtilsCreateHandleIn createHandleIn = { 0 };
    UtilsCreateHandleOut createHandleOut = { 0 };
    FAPI2_OBJECT *pNvObject = NULL;
    MOCTPM2_OBJECT_HANDLE *pNvHandle = NULL;
    TPMS_NV_PUBLIC *pNvPublic = NULL;
    MOCTPM2_OBJECT_HANDLE *pAuthSession = NULL;
    NVReadIn nvReadIn = { 0 };
    NVReadOut nvReadOut = { 0 };
    ubyte4 remaining = 0;
    ubyte4 offset = 0;
    EaExecutePolicyIn eaExecutePolicyIn = { 0 };
    EaExecutePolicyOut eaExecutePolicyOut = { 0 };

    if (!pCtx || !pIn || !pOut)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((pIn->nvAuth.size == 0) && (!pCtx->authValues.ownerAuthValid))
    {
        rc = TSS2_SYS_RC_NOT_PERMITTED;
        DB_PRINT("%s.%d Invalid authValue for owner hierarchy."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    TPM2B_SIZE_CHECK(&pIn->nvAuth, pCtx->nameAlgSize);

    if ((pIn->nvIndex < TPM2_NV_INDEX_FIRST) ||
            (pIn->nvIndex > TPM2_NV_INDEX_LAST))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid nv index specified, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    createObjectIn.tpm2Handle = pIn->nvIndex;
#if defined(__RTOS_WIN32__) && !defined(__USE_TPM_EMULATOR__)
    if (pIn->nvAuth.size != 0)
    {
        createObjectIn.numPolicyTerms = 1;
        if (OK != DIGI_CALLOC(&createObjectIn.pObjectPolicy, 1,
            sizeof(*createObjectIn.pObjectPolicy)))
        {
            rc = TSS2_SYS_RC_GENERAL_FAILURE;
            DB_PRINT("%s.%d Failed to allocate memory for PolicyObjectNode, rc 0x%02x = %s\n",
                __FUNCTION__, __LINE__, rc, tss2_err_string(rc));
        }
        createObjectIn.pObjectPolicy[0].policyType = FAPI2_POLICY_AUTH_VALUE;
    }
#endif /*__RTOS_WIN32__ && !__USE_TPM_EMULATOR__*/

    rc = FAPI2_UTILS_createObject(pCtx, &createObjectIn,
            &createObjectOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to create object for NV, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pNvObject = createObjectOut.pObject;
    pNvPublic = &pNvObject->public.nvPublic.nvPublic;

    createHandleIn.pObject = pNvObject;
    rc = FAPI2_UTILS_createHandle(pCtx, &createHandleIn,
            &createHandleOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to create handle for NV, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pNvHandle = createHandleOut.pHandle;

    if (pIn->nvAuth.size != 0)
    {
        rc = FAPI2_UTILS_getObjectAuthSession(pCtx, pNvObject, &pAuthSession);
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed to Start session."
                    ", rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
    }
    else
    {
        rc = FAPI2_UTILS_startSession(pCtx, &pAuthSession);
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed to Start session."
                    ", rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
    }

    nvReadIn.pNvIndexHandle = pNvHandle;
    nvReadIn.pAuthSession = pAuthSession;
    if (pIn->nvAuth.size != 0)
    {
        nvReadIn.useNvHandleForAuth = TRUE;
        nvReadIn.pAuthHandleAuth = &pIn->nvAuth;
    }
    else
    {
        switch(pIn->authHandle)
        {
            case TPM2_RH_PLATFORM:
                {
                    nvReadIn.authHandle = pIn->authHandle;
                    nvReadIn.pAuthHandleAuth = (0 < pIn->authHandleAuth.size) ?
                                 &pIn->authHandleAuth : &wellknownPlatformAuth;
                }
                break;

            case TPM2_RH_OWNER:
            default:
                {
                    nvReadIn.authHandle = TPM2_RH_OWNER;
                    nvReadIn.pAuthHandleAuth = &(pCtx->authValues.ownerAuth);
                }
                break;
        }
    }

    remaining = pNvPublic->dataSize;

    while (remaining > 0)
    {
        nvReadIn.size = (remaining > pCtx->maxNvTransactionSize) ?
                pCtx->maxNvTransactionSize:remaining;
        nvReadIn.offset = offset;

        rc = SAPI2_NV_NVRead(pCtx->pSapiCtx, &nvReadIn, &nvReadOut);
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed to read nv index."
                    ", rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        if (nvReadIn.size != nvReadOut.data.size)
        {
            rc = TSS2_FAPI_RC_INSUFFICIENT_BUFFER;
            DB_PRINT("%s.%d NV Read size and returned size dont match."
                    ", rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        DIGI_MEMCPY((void *)&(pOut->readData.buffer[offset]),
                nvReadOut.data.buffer, nvReadOut.data.size);

        remaining -= nvReadIn.size;
        offset += nvReadIn.size;

        /*
         * re-execute the policy, if the object has a policy. Since the sessions are
         * started with the continueSession attribute set, the TPM starts a new epoch
         * every time the policy session is used for authorization and clears the
         * policyDigest. Hence, successive use of the same session, without re-executing
         * the policy will fail authorization.
         * If the session does not have the continue session attribute, we would need
         * to flush the policySession and restart it every time. Executing the policy
         * on an existing session instead, is more efficient.
         */
        if (pNvObject->numPolicyTerms && (pIn->nvAuth.size != 0))
        {
            eaExecutePolicyIn.pSession = pAuthSession;
            eaExecutePolicyIn.numPolicyTerms = pNvObject->numPolicyTerms;
            eaExecutePolicyIn.pObjectPolicy = pNvObject->objectPolicy;
            rc = FAPI2_EA_executePolicy(pCtx, &eaExecutePolicyIn, &eaExecutePolicyOut);
            if (TSS2_RC_SUCCESS != rc)
            {
                DB_PRINT("%s.%d Failed to execute object policy."
                        ", rc 0x%02x = %s\n",
                        __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
                goto exit;
            }
        }

    }

    pOut->readData.size = pNvPublic->dataSize;

    rc = TSS2_RC_SUCCESS;
exit:
#if defined(__RTOS_WIN32__) && !defined(__USE_TPM_EMULATOR__)
    if (NULL != createObjectIn.pObjectPolicy)
        DIGI_FREE(&createObjectIn.pObjectPolicy);
#endif /*__RTOS_WIN32__ && !__USE_TPM_EMULATOR__*/

    if (pAuthSession)
    {
        exit_rc = FAPI2_UTILS_closeSession(pCtx,
                &pAuthSession);
        if (TSS2_RC_SUCCESS == rc)
            rc = exit_rc;
    }

    if (pNvObject)
    {
        exit_rc = FAPI2_UTILS_destroyObject(&pNvObject);
        if (TSS2_RC_SUCCESS == rc)
            rc = exit_rc;
    }

    if (pNvHandle)
        exit_rc = FAPI2_UTILS_destroyHandle(pCtx, &pNvHandle);

    if (TSS2_RC_SUCCESS == rc)
        rc = exit_rc;

    return rc;
}


/*
 * This API reads the public portion an already defined/created NV index.
 */
TSS2_RC FAPI2_NV_readPublic(
        FAPI2_CONTEXT *pCtx,
        NVReadPubIn *pIn,
        NVReadPubOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    MSTATUS status = OK;
    NVReadPublicIn  readPublicIn  = { 0 };
    NVReadPublicOut readPublicOut = { 0 };

    if (!pCtx || !pIn || !pOut)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((pIn->nvIndex < TPM2_NV_INDEX_FIRST) ||
            (pIn->nvIndex > TPM2_NV_INDEX_LAST))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid NV index specified, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    readPublicIn.pNvIndexHandle = NULL;
    readPublicIn.nvIndex =  pIn->nvIndex;

    rc = SAPI2_NV_NVReadPublic(pCtx->pSapiCtx, &readPublicIn, &readPublicOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to read public data for NV index."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    status = DIGI_MEMCPY((ubyte *)&(pOut->nvPublic.nvPublic),
                        (ubyte *)&(readPublicOut.nvPublic.nvPublic),
                        readPublicOut.nvPublic.size);
    if (OK != status)
    {
        rc = TSS2_FAPI_RC_IO_ERROR;
        goto exit;
    }
    pOut->nvPublic.size = readPublicOut.nvPublic.size;

    status = DIGI_MEMCPY((ubyte *)&(pOut->nvName.name),
                        (ubyte *)&(readPublicOut.nvName.name),
                         readPublicOut.nvName.size);
    if (OK != status)
    {
        rc = TSS2_FAPI_RC_IO_ERROR;
        goto exit;
    }
    pOut->nvName.size = readPublicOut.nvName.size;

    rc = TSS2_RC_SUCCESS;

exit:

    return rc;
}


/*
 * This API undefines a previously defined NV index. The owner
 * hierarchy authValue must be set correctly in the FAPI2_CONTEXT
 * for this command to succeed.
 */
TSS2_RC FAPI2_NV_undefine(
        FAPI2_CONTEXT *pCtx,
        NVUndefineIn *pIn
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TSS2_RC exit_rc = TSS2_RC_SUCCESS;
    UtilsCreateObjectIn createObjectIn = { 0 };
    UtilsCreateObjectOut createObjectOut = { 0 };
    UtilsCreateHandleIn createHandleIn = { 0 };
    UtilsCreateHandleOut createHandleOut = { 0 };
    FAPI2_OBJECT *pNvObject = NULL;
    MOCTPM2_OBJECT_HANDLE *pNvHandle = NULL;
    MOCTPM2_OBJECT_HANDLE *pAuthSession = NULL;
    NVUndefineSpaceIn nvUndefineSpaceIn = { 0 };

    if (!pCtx || !pIn)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (!pCtx->authValues.ownerAuthValid)
    {
        rc = TSS2_SYS_RC_NOT_PERMITTED;
        DB_PRINT("%s.%d Invalid authValue for owner hierarchy."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((pIn->nvIndex < TPM2_NV_INDEX_FIRST) ||
            (pIn->nvIndex > TPM2_NV_INDEX_LAST))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid nv index specified, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    createObjectIn.tpm2Handle = pIn->nvIndex;

    rc = FAPI2_UTILS_createObject(pCtx, &createObjectIn,
            &createObjectOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to create object for NV, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pNvObject = createObjectOut.pObject;

    createHandleIn.pObject = pNvObject;
    rc = FAPI2_UTILS_createHandle(pCtx, &createHandleIn,
            &createHandleOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to create handle for NV, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pNvHandle = createHandleOut.pHandle;

    rc = FAPI2_UTILS_startSession(pCtx, &pAuthSession);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to Start session."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    switch(pIn->authHandle)
    {
        case TPM2_RH_PLATFORM:
            {
                nvUndefineSpaceIn.authHandle = pIn->authHandle;
                 nvUndefineSpaceIn.pAuthHandleAuth = (0 < pIn->authHandleAuth.size) ?
                                 &pIn->authHandleAuth : &wellknownPlatformAuth;
            }
            break;

        case TPM2_RH_OWNER:
        default:
            {
                nvUndefineSpaceIn.authHandle = TPM2_RH_OWNER;
                nvUndefineSpaceIn.pAuthHandleAuth = &(pCtx->authValues.ownerAuth);
            }
            break;
    }
    nvUndefineSpaceIn.pAuthSession = pAuthSession;
    nvUndefineSpaceIn.ppNvIndexHandle = &pNvHandle;

    rc = SAPI2_NV_NVUndefineSpace(pCtx->pSapiCtx, &nvUndefineSpaceIn);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to undefine nv index."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pNvHandle = NULL;
    rc = TSS2_RC_SUCCESS;
exit:
    if (pAuthSession)
    {
        exit_rc = FAPI2_UTILS_closeSession(pCtx,
                &pAuthSession);
        if (TSS2_RC_SUCCESS == rc)
            rc = exit_rc;
    }

    if (pNvObject)
    {
        exit_rc = FAPI2_UTILS_destroyObject(&pNvObject);
        if (TSS2_RC_SUCCESS == rc)
            rc = exit_rc;
    }

    if (pNvHandle)
        exit_rc = FAPI2_UTILS_destroyHandle(pCtx, &pNvHandle);

    if (TSS2_RC_SUCCESS == rc)
        rc = exit_rc;

    return rc;
}
#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */
