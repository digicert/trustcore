/**
 * @file fapi2_ea.c
 * @brief This file contains code and structures required for using the TPM2's
 * enhanced policy authorization
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
#include "../../../../crypto/hw_accel.h"
#include "../../../../crypto/sha256.h"
#include "../../../../common/debug_console.h"
#include "../tpm_common/tpm_error_utils.h"
#include "fapi2.h"
#include "fapi2_internal.h"

static TSS2_RC FAPI2_EA_executePolicyAuthValue(
        FAPI2_CONTEXT *pCtx,
        MOCTPM2_OBJECT_HANDLE *pSession
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    PolicyAuthValueIn policyAuthValueIn = { 0 };

    if (!pSession || !pCtx)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid inputs, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    policyAuthValueIn.pPolicySession = pSession;
    rc = SAPI2_EA_PolicyAuthValue(pCtx->pSapiCtx, &policyAuthValueIn);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to execute TPM2_PolicyAuthValue, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    rc = TSS2_RC_SUCCESS;
exit:
    return rc;

}

static TSS2_RC FAPI2_EA_executePolicyObjectSecret(
        FAPI2_CONTEXT *pCtx,
        MOCTPM2_OBJECT_HANDLE *pSession,
        PolicyAuthNode *pPolicySecret
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TSS2_RC exit_rc = TSS2_RC_SUCCESS;
    PolicyObjectSecret *pObjectSecret = NULL;
    TPM2B_NONCE *pNonceTpm = NULL;
    PolicySecretIn policySecretIn = { 0 };
    PolicySecretOut policySecretOut = { 0 };
    FAPI2_OBJECT *pAuthorizingObject = NULL;
    TPM2B_DIGEST emptyDigest = { 0 };
    MOCTPM2_OBJECT_HANDLE *pAuthorizingObjectHandle = NULL;
    MOCTPM2_OBJECT_HANDLE *pAuthSession = NULL;
    ContextFlushObjectIn flushObjectIn = { 0 };
    TPM2B_AUTH *pAuthValue = NULL;

    if (!pSession || !pCtx || !pPolicySecret ||
            (pPolicySecret->policyType != FAPI2_POLICY_OBJECT_SECRET))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid inputs, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pObjectSecret = &(pPolicySecret->policyInfo.policyObjectSecret);

    /*
     * Nonce TPM is always nonceNewer, since the last response will have contained
     * the nonce sent by the TPM.
     */
    rc = SAPI2_SESSION_getNonceNewer(pSession, &pNonceTpm);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to get nonceTpm, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    switch (pObjectSecret->authEntitySelector)
    {
    case 1:
    {
        switch (pObjectSecret->authEntity.authorizingHierarchy)
        {
        case TPM2_RH_OWNER:
            if (pCtx->authValues.ownerAuthValid)
            {
                pAuthValue = &pCtx->authValues.ownerAuth;
            }
            else
            {
                rc = TSS2_SYS_RC_NOT_PERMITTED;
                DB_PRINT("%s.%d Invalid authValue for owner hierarchy, rc 0x%02x = %s\n", __FUNCTION__,
                        __LINE__, rc, tss2_err_string(rc));
                goto exit;
            }
            break;
        case TPM2_RH_ENDORSEMENT:
            if (pCtx->authValues.endorsementAuthValid)
            {
                pAuthValue = &pCtx->authValues.endorsementAuth;
            }
            else
            {
                rc = TSS2_SYS_RC_NOT_PERMITTED;
                DB_PRINT("%s.%d Invalid authValue for endorsement hierarchy, rc 0x%02x = %s\n", __FUNCTION__,
                        __LINE__, rc, tss2_err_string(rc));
                goto exit;
            }
            break;
        case TPM2_RH_LOCKOUT:
            if (pCtx->authValues.lockoutAuthValid)
            {
                pAuthValue = &pCtx->authValues.lockoutAuth;
            }
            else
            {
                rc = TSS2_SYS_RC_NOT_PERMITTED;
                DB_PRINT("%s.%d Invalid authValue for lockout hierarchy, rc 0x%02x = %s\n", __FUNCTION__,
                        __LINE__, rc, tss2_err_string(rc));
                goto exit;
            }
            break;
        default:
            rc = TSS2_SYS_RC_BAD_VALUE;
            DB_PRINT("%s.%d Invalid authorizing hierarchy specified, rc 0x%02x = %s\n", __FUNCTION__,
                    __LINE__, rc, tss2_err_string(rc));
            goto exit;
            break;
        }

        rc = SAPI2_HANDLES_createObjectHandle(pObjectSecret->authEntity.authorizingHierarchy,
                NULL, &pAuthorizingObjectHandle);
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed to createHandle for hierarchy, rc 0x%02x = %s\n", __FUNCTION__,
                    __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        rc = FAPI2_UTILS_startSession(pCtx, &pAuthSession);
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed to start session, rc 0x%02x = %s\n", __FUNCTION__,
                    __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
        break;
    }
    case 2:
    {

        rc = FAPI2_CONTEXT_lookupObject(pCtx,
                &(pObjectSecret->authEntity.authorizingObject), &pAuthorizingObject);
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed to lookup authorizing object, rc 0x%02x = %s\n", __FUNCTION__,
                    __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        if (!pAuthorizingObject->authValueRequired || !pAuthorizingObject->authValueValid)
        {
            rc = TSS2_SYS_RC_NOT_PERMITTED;
            DB_PRINT("%s.%d authorizing Objects policy does not contain TPM2_PolicyAuthValue term"
                    "or its authValue is not set., rc 0x%02x = %s\n", __FUNCTION__,
                    __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        rc = FAPI2_UTILS_loadObjectTree(pCtx, pAuthorizingObject, &pAuthorizingObjectHandle);
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed to create handle for authorizing object."
                    ", rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        rc = FAPI2_UTILS_getObjectAuthSession(pCtx, pAuthorizingObject, &pAuthSession);
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed to Start session."
                    ", rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        pAuthValue = &(pAuthorizingObject->authValue);
        break;
    }
    default:
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid authEntitySelector"
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
        break;
    }

    policySecretIn.pAuthObject = pAuthorizingObjectHandle;
    policySecretIn.pAuthSession = pAuthSession;
    policySecretIn.pAuthObjectAuth = pAuthValue;
    policySecretIn.pPolicySession = pSession;
    policySecretIn.pNonceTpm = pNonceTpm;
    policySecretIn.pPolicyRef = &(pObjectSecret->policyRef);

    /*
     * For now we dont use expiration and cpHashA. Support for this could be added later.
     * This means that the output ticket and timeout are irrelavent and TPM2_PolicyTicket
     * would not be supported.
     */
    policySecretIn.pCpHash = &emptyDigest;
    policySecretIn.expiration = 0;

    rc = SAPI2_EA_PolicySecret(pCtx->pSapiCtx, &policySecretIn, &policySecretOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to execute policy secret."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    rc = TSS2_RC_SUCCESS;
exit:
    if (pAuthSession)
    {
        exit_rc = FAPI2_UTILS_closeSession(pCtx,
                &pAuthSession);
        if (TSS2_RC_SUCCESS == rc)
            rc = exit_rc;
    }

    if (pAuthorizingObjectHandle)
    {
        exit_rc = FAPI2_UTILS_destroyHandle(pCtx, &pAuthorizingObjectHandle);
        if (TSS2_RC_SUCCESS == rc)
            rc = exit_rc;
    }

    if (pAuthorizingObject)
    {
        flushObjectIn.objName = pAuthorizingObject->objectName;
        exit_rc = FAPI2_CONTEXT_flushObject(pCtx, &flushObjectIn);
    }

    if (TSS2_RC_SUCCESS == rc)
        rc = exit_rc;

    return rc;
}

static TSS2_RC FAPI2_EA_executePolicyPcr(
        FAPI2_CONTEXT *pCtx,
        MOCTPM2_OBJECT_HANDLE *pSession,
        PolicyAuthNode *pPolicyPcr
)
{
        MSTATUS status = OK;
        TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
        PolicyPCRIn policyPcrIn = { 0 };
        TPML_PCR_SELECTION pcrSelectionList = { 0 };
        IntegrityPcrReadIn pcrIn = { 0 };
        IntegrityPcrReadOut pcrOut = { 0 };
        DataDigestIn digestIn = {0};
        DataDigestOut digestOut = {0};
        ubyte *pDigestBuf = NULL;
        ubyte4 pcrDigestSize = SHA256_RESULT_SIZE, digestIndex = 0;
        ubyte4 dataOffset = 0;
    
        if (!pSession || !pCtx || !pPolicyPcr)
        {
            rc = TSS2_SYS_RC_BAD_REFERENCE;
            DB_PRINT("%s.%d Invalid inputs, rc 0x%02x = %s\n", __FUNCTION__,
                    __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
    
        policyPcrIn.pPolicySession = pSession;
        if (0 == pPolicyPcr->policyInfo.policyPcr.pcrBitmask )
        {
            rc = TSS2_SYS_RC_BAD_REFERENCE;
            DB_PRINT("%s.%d empty pcr mask, rc 0x%02x = %s\n", __FUNCTION__,
                        __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        /* All PCR digests are of the same size */
        status = DIGI_CALLOC((void **)&pDigestBuf,
                1, (8 * pcrDigestSize));
        if (OK != status)
        {
            rc = TSS2_SYS_RC_GENERAL_FAILURE ;
            DB_PRINT("%s.%d Error allocating buffer for PCR data, status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }

        pcrIn.hashAlg = TPM2_ALG_SHA256 ;
        pcrIn.pcrSelection = pPolicyPcr->policyInfo.policyPcr.pcrBitmask ;
        rc = FAPI2_INTEGRITY_pcrRead(pCtx, &pcrIn, &pcrOut) ;
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed to read PCR index %d, rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, (int)pcrIn.pcrSelection, rc, tss2_err_string(rc));
            goto exit;
        }
        
        if (pcrOut.pcrDigests.digests[0].size)
        {
            for (digestIndex = 0; digestIndex < pcrOut.pcrDigests.count; digestIndex++)
            {
                status = DIGI_MEMCPY(&pDigestBuf[dataOffset*pcrDigestSize], 
                            pcrOut.pcrDigests.digests[digestIndex].buffer,
                            pcrDigestSize); 
                if (OK != status)
                {
                    rc = TSS2_SYS_RC_GENERAL_FAILURE ;
                    DB_PRINT("%s.%d Error copying %d PCR data bytes, status = %d\n",
                                __FUNCTION__, __LINE__, pcrDigestSize,
                                status);
                    goto exit;
                }
        
                dataOffset++;
            }
        }
        else
        {
            rc = TSS2_SYS_RC_GENERAL_FAILURE ;
            DB_PRINT("%s.%d PCR index data length 0\n",
                        __FUNCTION__,__LINE__);
            goto exit;
        }

        digestIn.hashAlg = TPM2_ALG_SHA256;
        digestIn.pBuffer = pDigestBuf;
        digestIn.bufferLen = dataOffset*pcrDigestSize;
        rc = FAPI2_DATA_digest(pCtx, &digestIn, &digestOut);
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed to compute digest, rc 0x%02x = %s\n", __FUNCTION__,
                    __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
        
        pcrSelectionList.count = 1;
        pcrSelectionList.pcrSelections[0].hash = TPM2_ALG_SHA256;
        pcrSelectionList.pcrSelections[0].sizeofSelect =  3;
        pcrSelectionList.pcrSelections[0].pcrSelect[0] = (pPolicyPcr->policyInfo.policyPcr.pcrBitmask>>0) & 0xff ;
        pcrSelectionList.pcrSelections[0].pcrSelect[1] = (pPolicyPcr->policyInfo.policyPcr.pcrBitmask>>8) & 0xff ;
        pcrSelectionList.pcrSelections[0].pcrSelect[2] = (pPolicyPcr->policyInfo.policyPcr.pcrBitmask>>16) & 0xff ;
        
        policyPcrIn.pPcrs = &pcrSelectionList ;
        policyPcrIn.pPCRdigest = &digestOut.digest ;
        rc = SAPI2_EA_PolicyPCR(pCtx->pSapiCtx, &policyPcrIn);
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed to execute TPM2_PolicyPcr, rc 0x%02x = %s\n", __FUNCTION__,
                    __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
    
        rc = TSS2_RC_SUCCESS;
    exit:
        if(NULL != pDigestBuf)
            DIGI_FREE((void **)&pDigestBuf) ;
        return rc;

}

static TSS2_RC FAPI2_EA_executePolicyCommandCode(
        FAPI2_CONTEXT *pCtx,
        MOCTPM2_OBJECT_HANDLE *pSession,
        PolicyAuthNode *pPolicyCC
)
{
        TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
        PolicyCommandCodeIn policyCCIn = { 0 };
    
        if (!pSession || !pCtx || !pPolicyCC)
        {
            rc = TSS2_SYS_RC_BAD_REFERENCE;
            DB_PRINT("%s.%d Invalid inputs, rc 0x%02x = %s\n", __FUNCTION__,
                    __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
    
        policyCCIn.pPolicySession = pSession;
        policyCCIn.code = pPolicyCC->policyInfo.policyCC.code ;
        rc = SAPI2_EA_PolicyCommandCode(pCtx->pSapiCtx, &policyCCIn);
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed to execute TPM2_PolicyCommandCode, rc 0x%02x = %s\n", __FUNCTION__,
                    __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
    
        rc = TSS2_RC_SUCCESS;
    exit:
        return rc;

}

TSS2_RC FAPI2_EA_executePolicy(
        FAPI2_CONTEXT *pCtx,
        EaExecutePolicyIn *pIn,
        EaExecutePolicyOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TSS2_RC exit_rc = TSS2_RC_SUCCESS;
    MOCTPM2_OBJECT_HANDLE *pSession = NULL;
    byteBoolean destroyTrialSession = FALSE;
    PolicyGetDigestIn getDigestIn = { 0 };
    PolicyGetDigestOut getDigestOut = { 0 };
    ubyte2 i = 0;

    if (!pCtx || !pIn || !pOut || !pIn->pObjectPolicy ||
            (0 == pIn->numPolicyTerms))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid inputs, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (!pIn->pSession)
    {
        rc = FAPI2_UTILS_startPolicySession(pCtx, &pSession, TRUE);
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed to start trial policy session"
                    ", rc 0x%02x = %s\n", __FUNCTION__,
                    __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
        destroyTrialSession = TRUE;
    }
    else
    {
        if (!IS_TPM2_POLICY_SESSION_HANDLE(pIn->pSession->tpm2Handle))
        {
            DB_PRINT("%s.%d Session provided is not a policy session."
                    ", rc 0x%02x = %s\n", __FUNCTION__,
                    __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        pSession = pIn->pSession;
    }

    /*
     * Execute policy terms.
     */
    for (i = 0; i < pIn->numPolicyTerms; i++)
    {
        switch (pIn->pObjectPolicy[i].policyType)
        {
        case FAPI2_POLICY_AUTH_VALUE:
            rc = FAPI2_EA_executePolicyAuthValue(pCtx, pSession);
            if (TSS2_RC_SUCCESS != rc)
                goto exit;
            break;
        case FAPI2_POLICY_OBJECT_SECRET:
            rc = FAPI2_EA_executePolicyObjectSecret(pCtx, pSession,
                    &(pIn->pObjectPolicy[i]));
            if (TSS2_RC_SUCCESS != rc)
                goto exit;
            break;
        case FAPI2_POLICY_PCR:
            rc = FAPI2_EA_executePolicyPcr(pCtx, pSession, &(pIn->pObjectPolicy[i]));
            if (TSS2_RC_SUCCESS != rc)
                goto exit;
            break;
        case FAPI2_POLICY_COMMAND_CODE:
            rc = FAPI2_EA_executePolicyCommandCode(pCtx, pSession, &(pIn->pObjectPolicy[i]));
            if (TSS2_RC_SUCCESS != rc)
                goto exit;
            break;
        default:
            DB_PRINT("%s.%d Unknown policy node."
                    ", rc 0x%02x = %s\n", __FUNCTION__,
                    __LINE__, rc, tss2_err_string(rc));
            goto exit;
            break;
        }
    }

    /*
     * Get policy digest from session.
     */
    getDigestIn.pPolicySession = pSession;
    rc = SAPI2_EA_PolicyGetDigest(pCtx->pSapiCtx, &getDigestIn, &getDigestOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to get policy digest."
                ", rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pOut->policyDigest = getDigestOut.policyDigest;
    rc = TSS2_RC_SUCCESS;
exit:
    if (destroyTrialSession)
        exit_rc = FAPI2_UTILS_closeSession(pCtx, &pSession);

    if (TSS2_RC_SUCCESS == rc)
        rc = exit_rc;


    return rc;
}
#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */
