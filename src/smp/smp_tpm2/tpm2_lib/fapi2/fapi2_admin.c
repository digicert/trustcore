/**
 * @file fapi2_admin.c
 * @brief This file contains code and structures required for provisioning
 * the TPM2.
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
#include "../../../../common/debug_console.h"
#include "../tpm_common/tpm_error_utils.h"
#include "fapi2.h"
#include "fapi2_internal.h"

PolicyAuthNode tcgEKPolicy = {
        .policyType = FAPI2_POLICY_OBJECT_SECRET,
        .policyInfo.policyObjectSecret.policyRef = { 0 },
        .policyInfo.policyObjectSecret.authEntitySelector = 1,
        .policyInfo.policyObjectSecret.authEntity.authorizingHierarchy = TPM2_RH_ENDORSEMENT
};

/*
 * This API clears the TPM2 using TPM2_Clear(). All existing TPM objects
 * are invalidated and all authValues are cleared. This requires lockout
 * authorization or platform authorization. Platform authorization will
 * typically not be available since it is set by firmware/OEM.
 */
TSS2_RC FAPI2_ADMIN_releaseOwnership(
        FAPI2_CONTEXT *pCtx
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TSS2_RC exit_rc = TSS2_RC_SUCCESS;
    MOCTPM2_OBJECT_HANDLE *pAuthSession = NULL;
    ClearIn clearIn = { 0 } ;
    TPM2B_AUTH *pOldLockoutAuth = NULL;

    if (!pCtx)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (!pCtx->authValues.lockoutAuthValid)
    {
        rc = TSS2_SYS_RC_NOT_PERMITTED;
        DB_PRINT("%s.%d Invalid authValue for lockout hierarchy."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pOldLockoutAuth = &pCtx->authValues.lockoutAuth;

    rc = FAPI2_UTILS_startSession(pCtx, &pAuthSession);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Unalbe to start auth session, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /*
     * Clear the TPM using current lockout authValue and
     * TPM2_Clear command.
     */
    clearIn.authHandle = TPM2_RH_LOCKOUT;
    clearIn.pAuthAuthHandle = pOldLockoutAuth;
    clearIn.pAuthSession = pAuthSession;

    rc = SAPI2_HIERARCHY_Clear(pCtx->pSapiCtx, &clearIn);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to clear TPM ownership, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /*
     * Clear out handles to EK and objects now that the TPM is cleared.
     */
    if (pCtx->primaryKeys.pEKHandle)
        FAPI2_UTILS_destroyHandle(pCtx,
                &pCtx->primaryKeys.pEKHandle);

    if (pCtx->primaryKeys.pSRKHandle)
        FAPI2_UTILS_destroyHandle(pCtx,
                &pCtx->primaryKeys.pSRKHandle);

    if (pCtx->primaryKeys.pEK)
        FAPI2_UTILS_destroyObject(&pCtx->primaryKeys.pEK);

    if (pCtx->primaryKeys.pSRK)
        FAPI2_UTILS_destroyObject(&pCtx->primaryKeys.pSRK);


    rc = TSS2_RC_SUCCESS;
exit:
    if (pAuthSession)
        exit_rc = FAPI2_UTILS_closeSession(pCtx,
                &pAuthSession);

    if (TSS2_RC_SUCCESS == rc)
        rc = exit_rc;

    return rc;
}

/*
 * This API clears the TPM2 using TPM2_Clear(). It uses default platform
 * authorization credentials. All existing TPM objects
 * are invalidated and all authValues are cleared. 
 */
TSS2_RC FAPI2_ADMIN_forceClear(
        FAPI2_CONTEXT *pCtx
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TSS2_RC exit_rc = TSS2_RC_SUCCESS;
    MOCTPM2_OBJECT_HANDLE *pAuthSession = NULL;
    ClearIn clearIn = { 0 } ;
    TPM2B_AUTH platformAuth = {0};

    if (!pCtx)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    rc = FAPI2_UTILS_startSession(pCtx, &pAuthSession);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Unalbe to start auth session, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /*
     * Clear the TPM using default Platform auth and
     * TPM2_Clear command.
     */
    clearIn.authHandle = TPM2_RH_PLATFORM;
    clearIn.pAuthAuthHandle = &platformAuth;
    clearIn.pAuthSession = pAuthSession;

    rc = SAPI2_HIERARCHY_Clear(pCtx->pSapiCtx, &clearIn);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to clear TPM ownership, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /*
     * Clear out handles to EK and objects now that the TPM is cleared.
     */
    if (pCtx->primaryKeys.pEKHandle)
        FAPI2_UTILS_destroyHandle(pCtx,
                &pCtx->primaryKeys.pEKHandle);

    if (pCtx->primaryKeys.pSRKHandle)
        FAPI2_UTILS_destroyHandle(pCtx,
                &pCtx->primaryKeys.pSRKHandle);

    if (pCtx->primaryKeys.pEK)
        FAPI2_UTILS_destroyObject(&pCtx->primaryKeys.pEK);

    if (pCtx->primaryKeys.pSRK)
        FAPI2_UTILS_destroyObject(&pCtx->primaryKeys.pSRK);


    rc = TSS2_RC_SUCCESS;
exit:
    if (pAuthSession)
        exit_rc = FAPI2_UTILS_closeSession(pCtx,
                &pAuthSession);

    if (TSS2_RC_SUCCESS == rc)
        rc = exit_rc;

    return rc;
}

TSS2_RC FAPI2_ADMIN_takeOwnership(
        FAPI2_CONTEXT *pCtx,
        AdminTakeOwnershipIn *pIn
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TSS2_RC exit_rc = TSS2_RC_SUCCESS;
    MOCTPM2_OBJECT_HANDLE *pAuthSession = NULL;
    ClearIn clearIn = { 0 } ;
    HierarchyChangeAuthIn hierarchyChangeAuthIn = { 0 };
    TPM2B_AUTH emptyAuth = { 0 };
    TPM2B_AUTH *pOldLockoutAuth = NULL;
    ContextSetHierarchyAuthIn setHierarchyAuths = { 0 };

    if (!pCtx || !pIn)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (!pCtx->authValues.lockoutAuthValid)
    {
        rc = TSS2_SYS_RC_NOT_PERMITTED;
        DB_PRINT("%s.%d Invalid authValue for lockout hierarchy."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    TPM2B_SIZE_CHECK(&pIn->newOwnerAuth, pCtx->tpmContextHashAlgLen);
    TPM2B_SIZE_CHECK(&pIn->newLockOutAuth, pCtx->tpmContextHashAlgLen);
    TPM2B_SIZE_CHECK(&pIn->newEndorsementAuth, pCtx->tpmContextHashAlgLen);

    pOldLockoutAuth = &pCtx->authValues.lockoutAuth;

    rc = FAPI2_UTILS_startSession(pCtx, &pAuthSession);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Unalbe to start auth session, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /*
     * Clear the TPM using current lockout authValue and
     * TPM2_Clear command.
     */
    clearIn.authHandle = TPM2_RH_LOCKOUT;
    clearIn.pAuthAuthHandle = pOldLockoutAuth;
    clearIn.pAuthSession = pAuthSession;

    rc = SAPI2_HIERARCHY_Clear(pCtx->pSapiCtx, &clearIn);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to clear TPM ownership, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /*
     * Clear out EK and SRK handles and objects now that the TPM is cleared.
     */
    if (pCtx->primaryKeys.pEKHandle)
        FAPI2_UTILS_destroyHandle(pCtx,
                &pCtx->primaryKeys.pEKHandle);

    if (pCtx->primaryKeys.pSRKHandle)
        FAPI2_UTILS_destroyHandle(pCtx,
                &pCtx->primaryKeys.pSRKHandle);

    if (pCtx->primaryKeys.pEK)
        FAPI2_UTILS_destroyObject(&pCtx->primaryKeys.pEK);

    if (pCtx->primaryKeys.pSRK)
        FAPI2_UTILS_destroyObject(&pCtx->primaryKeys.pSRK);

    /*
     * Close session since the above session may have been salted and
     * the salting key may not be valid any more.
     */
    rc = FAPI2_UTILS_closeSession(pCtx,
                    &pAuthSession);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to change owner authValue, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /*
     * restart a session.
     */
    rc = FAPI2_UTILS_startSession(pCtx, &pAuthSession);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Unalbe to start auth session, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /* Set the new owner hierarchy authValue */
    hierarchyChangeAuthIn.authHandle = TPM2_RH_OWNER;
    hierarchyChangeAuthIn.pCurrentAuth = &emptyAuth;
    hierarchyChangeAuthIn.pNewAuth = &pIn->newOwnerAuth;
    hierarchyChangeAuthIn.pAuthSession = pAuthSession;

    rc = SAPI2_HIERARCHY_HierarchyChangeAuth(pCtx->pSapiCtx,
            &hierarchyChangeAuthIn);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to change owner authValue, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /* Set the new endorsement hierarchy authValue */
    hierarchyChangeAuthIn.authHandle = TPM2_RH_ENDORSEMENT;
    hierarchyChangeAuthIn.pCurrentAuth = &emptyAuth;
    hierarchyChangeAuthIn.pNewAuth = &pIn->newEndorsementAuth;
    hierarchyChangeAuthIn.pAuthSession = pAuthSession;

    rc = SAPI2_HIERARCHY_HierarchyChangeAuth(pCtx->pSapiCtx,
            &hierarchyChangeAuthIn);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to change privacy admin authValue, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /*
     * Set the new lockout hierarchy authValue. Set this last since, if
     * changing authValues of owner or endorsement hierarchy fails,
     * the oldLockoutAuth can still be used to clear the TPM.
     */
    hierarchyChangeAuthIn.authHandle = TPM2_RH_LOCKOUT;
    hierarchyChangeAuthIn.pCurrentAuth = &emptyAuth;
    hierarchyChangeAuthIn.pNewAuth = &pIn->newLockOutAuth;
    hierarchyChangeAuthIn.pAuthSession = pAuthSession;

    rc = SAPI2_HIERARCHY_HierarchyChangeAuth(pCtx->pSapiCtx,
            &hierarchyChangeAuthIn);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to change lockout authValue, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    setHierarchyAuths.endorsementAuth = pIn->newEndorsementAuth;
    setHierarchyAuths.lockoutAuth = pIn->newLockOutAuth;
    setHierarchyAuths.ownerAuth = pIn->newOwnerAuth;
    rc = FAPI2_CONTEXT_setHierarchyAuth(pCtx, &setHierarchyAuths);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to change lockout authValue, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    rc = TSS2_RC_SUCCESS;
exit:
    if (pAuthSession)
        exit_rc = FAPI2_UTILS_closeSession(pCtx,
                &pAuthSession);

    if (TSS2_RC_SUCCESS == rc)
        rc = exit_rc;

    return rc;
}

/* 
   This function checks to see if the specified NV Index is configured.
   If so, reads the contents
 */
static MSTATUS FAPI2_getNonceFromNV(FAPI2_CONTEXT *pCtx,
        NVReadOpIn *pNvIn, NVReadOpOut *pNvOut)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    MSTATUS status = ERR_GENERAL;
    MgmtCapabilityIn capIn = {0};
    MgmtCapabilityOut capOut = {0};
    ubyte4 i = 0;

    capIn.capability = TPM2_CAP_HANDLES;
    capIn.property = 0x01c00000;
    capIn.propertyCount = 64;
    rc = FAPI2_MGMT_getCapability(pCtx, &capIn, &capOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d FAPI2_MGMT_getCapability error, rc = 0x%02x\n",
                __FUNCTION__, __LINE__, rc);
        goto exit;
    }

    /* Map capability data to entityIdList */
    if (capOut.moreData)
    {
        /* Error out for now */
        DB_PRINT("%s.%d FAPI2_MGMT_getCapability nvHandles exceed limit of 64\n", 
                __FUNCTION__, __LINE__);
        status = ERR_TAP_CMD_FAILED;
        goto exit;
    }

    for (i = 0; i < capOut.capabilityData.data.handles.count; i++)
    {
        if (pNvIn->nvIndex == capOut.capabilityData.data.handles.handle[i])
        {
            rc = FAPI2_NV_readOp(pCtx, pNvIn, pNvOut);
            if (TSS2_RC_SUCCESS == rc)
                status = OK;
            break;
        }
    }

exit:
    return status;
}

/*
 * This function creates the RSA or ECC endorsement key for the TPM
 * using the default templates provided in the
 * TCG EK Credential Profile document.
 * If the EK is deemed to be privacy sensitive, the key is created as a
 * restricted decryption key. If not, it will be created as a restricted
 * signing key, essentially making the EK an attestation key(AK or AIK).
 * An authValue may be provided in the input. If an authValue of size 0 is
 * provided, the authValue is set to the endorsement hierarchy password.
 * The authValue supplied is only used if the key is not privacy sensitive.
 * The TCG default policy will be used, which requires the endorsement hierarchy
 * password to use the EK.
 * The authPolicy is set per the TCG EK Credential Profile document as well.
 * No values are returned since the EK will be persisted at a known location.
 * If the key is an RSA key:
 * RSA Key size: 2048 bits, exponent = 65535, Signature scheme:RSASSA_PKSC1V1.5
 * with SHA256 or NULL if the EK is privacy sensitive.
 * if the key is an ECC Key:
 * ECC curveID: TPM2_ECC_NIST_P256, Signature scheme:TPM2_ALG_ECDSA if the
 * key is an attestation key(not privacy sensitive) and
 * TPM2_ALG_NULL if the EK is privacy sensitive.
 * The EK is created at the handle FAPI2_RH_EK
 */
TSS2_RC FAPI2_ADMIN_createEK(
        FAPI2_CONTEXT *pCtx,
        AdminCreateEKIn *pIn
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TSS2_RC exit_rc = TSS2_RC_SUCCESS;
    AsymCreatePrimaryKeyIn keyIn = { 0 };
    AsymCreatePrimaryKeyOut keyOut = { 0 };
    TPM2B_DATA outsideInfo = { 0 };
    NVReadOpIn nvIn = {0};
    NVReadOpOut nvOut = {0};
    MSTATUS status = OK;

    if (!pCtx || !pIn)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((pIn->keyAlg != TPM2_ALG_RSA) && (pIn->keyAlg != TPM2_ALG_ECC))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid key algorithm, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    TPM2B_SIZE_CHECK(&pIn->EKAuth, pCtx->nameAlgSize);

    /*
     * EK is always in endorsement hierarchy
     */
    keyIn.hierarchy = TPM2_RH_ENDORSEMENT;

    /*
     * We will discard the creation data. Anybody need this data should be
     * using advanced API's. We also dont use outside info.
     */
    keyIn.pcrSelection = 0;
    keyIn.pOutsideInfo = &outsideInfo;

    if (pIn->EKAuth.size != 0 && !pIn->isPrivacySensitive)
        keyIn.pNewKeyAuth = &pIn->EKAuth;
    else
        keyIn.pNewKeyAuth = &pCtx->authValues.endorsementAuth;

    keyIn.persistentHandle = FAPI2_RH_EK;

    keyIn.keyAlg = pIn->keyAlg;

    if (pIn->keyAlg == TPM2_ALG_RSA)
    {
        keyIn.keyInfo.rsaInfo.keySize = 2048;
        keyIn.keyInfo.rsaInfo.exponent = 0;
        keyIn.keyInfo.rsaInfo.hashAlg = TPM2_ALG_SHA256;

        if (pIn->isPrivacySensitive)
        {
            keyIn.keyInfo.rsaInfo.keyType = FAPI2_ASYM_TYPE_STORAGE;
            keyIn.keyInfo.rsaInfo.scheme = TPM2_ALG_NULL;
        }
        else
        {
            keyIn.keyInfo.rsaInfo.keyType = FAPI2_ASYM_TYPE_ATTESTATION;
            keyIn.keyInfo.rsaInfo.scheme = TPM2_ALG_RSASSA;
        }

        keyIn.externalEntryopy.rsaEntropy.size = 256;

        nvIn.nvIndex = TPM2_RSA_NONCE_NV_INDEX;
        status = FAPI2_getNonceFromNV(pCtx, &nvIn, &nvOut);
        if (OK == status)
        {
            DB_PRINT("%s.%d Using RSA Nonce of %d bytes read from index 0x%08x\n",__FUNCTION__,__LINE__,
                    (int)nvOut.readData.size, (int)nvIn.nvIndex);
            /* Populate the buffer with the Nonce */
            if (nvOut.readData.size < keyIn.externalEntryopy.rsaEntropy.size)
            {
                status = DIGI_MEMCPY(keyIn.externalEntryopy.rsaEntropy.buffer,
                        nvOut.readData.buffer, nvOut.readData.size);
                if (OK != status)
                {
                    DB_PRINT("%s.%d Failed to copy RSA EK nonce, status 0x%02x\n",
                            __FUNCTION__,__LINE__, status);
                }
            }
            else
            {
                DB_PRINT("%s.%d Nonce size of %d exceeds configured entropy of %d bytes\n",
                        __FUNCTION__,__LINE__, (int)nvOut.readData.size,
                        (int)keyIn.externalEntryopy.rsaEntropy.size);
            }
        }
    }
    else
    {
        keyIn.keyInfo.eccInfo.curveID = TPM2_ECC_NIST_P256;

        if (pIn->isPrivacySensitive)
        {
            keyIn.keyInfo.eccInfo.keyType = FAPI2_ASYM_TYPE_STORAGE;
            keyIn.keyInfo.eccInfo.scheme = TPM2_ALG_NULL;
        }
        else
        {
            keyIn.keyInfo.eccInfo.keyType = FAPI2_ASYM_TYPE_ATTESTATION;
            keyIn.keyInfo.eccInfo.scheme = TPM2_ALG_ECDSA;
        }
        keyIn.externalEntryopy.eccEntropy.x.size = 32;
        keyIn.externalEntryopy.eccEntropy.y.size = 32;

        nvIn.nvIndex = TPM2_ECC_NONCE_NV_INDEX;
        status = FAPI2_getNonceFromNV(pCtx, &nvIn, &nvOut);
        if (OK == status)
        {
            DB_PRINT("%s.%d Using ECC Nonce of %d bytes read from index 0x%08x\n",__FUNCTION__,__LINE__,
                    (int)nvOut.readData.size, (int)nvIn.nvIndex);
            /* Populate the buffer with the Nonce */
            if (nvOut.readData.size < keyIn.externalEntryopy.eccEntropy.x.size)
            {
                status = DIGI_MEMCPY(keyIn.externalEntryopy.eccEntropy.x.buffer,
                        nvOut.readData.buffer, nvOut.readData.size);
                if (OK != status)
                {
                    DB_PRINT("%s.%d Failed to copy ECC EK X nonce, status 0x%02x\n",
                            __FUNCTION__,__LINE__, status);
                }
            }
            else
            {
                DB_PRINT("%s.%d Nonce size of %d exceeds configured entropy of %d bytes\n",
                        __FUNCTION__,__LINE__, (int)nvOut.readData.size,
                        (int)keyIn.externalEntryopy.eccEntropy.x.size);
            }

            if (nvOut.readData.size < keyIn.externalEntryopy.eccEntropy.y.size)
            {
                status = DIGI_MEMCPY(keyIn.externalEntryopy.eccEntropy.y.buffer,
                        nvOut.readData.buffer, nvOut.readData.size);
                if (OK != status)
                {
                    DB_PRINT("%s.%d Failed to copy ECC EK Y nonce, status 0x%02x\n",
                            __FUNCTION__,__LINE__, status);
                }
            }
            else
            {
                DB_PRINT("%s.%d Nonce size of %d exceeds configured entropy of %d bytes\n",
                        __FUNCTION__,__LINE__, (int)nvOut.readData.size,
                        (int)keyIn.externalEntryopy.eccEntropy.y.size);
            }
        }
    }

    /*
     * If key is not privacy sensitive, use TCG template.
     * Admin with policy needs to be enabled.
     */
    if (pIn->isPrivacySensitive)
    {
        keyIn.numPolicyTerms = 1;
        keyIn.pPolicy = &tcgEKPolicy;
        keyIn.additionalAttributes = TPMA_OBJECT_FIXEDTPM |
                TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN |
                TPMA_OBJECT_ADMINWITHPOLICY | TPMA_OBJECT_DECRYPT | TPMA_OBJECT_RESTRICTED;
    }

    rc = FAPI2_ASYM_createPrimaryAsymKey(pCtx, NULL, &keyIn, &keyOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to Create RSA EK, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /*
     * Destroy the primary key object returned. We dont need it for EK's.
     */
    rc = FAPI2_UTILS_destroyObject(&keyOut.pKey);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to destroy FAPI object, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    rc = TSS2_RC_SUCCESS;
exit:

    if (TSS2_RC_SUCCESS == rc)
        rc = exit_rc;

    return rc;
}

/*
 * This function creates the RSA or ECC storage root key for the TPM
 * using the default templates provided in the
 * TCG EK Credential Profile document.
 * An authValue may be provided in the input. If an authValue of size 0
 * us provided, the authValue is used as is.
 * No values are returned since the SRK will be persisted at a known location.
 * If the key is an RSA key:
 * RSA Key size: 2048 bits, exponent = 65535.
 * if the key is an ECC Key:
 * ECC curveID: TPM2_ECC_NIST_P256
 * The SRK is created at the handle FAPI2_RH_SRK
 */
TSS2_RC FAPI2_ADMIN_createSRK(
        FAPI2_CONTEXT *pCtx,
        AdminCreateSRKIn *pIn
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TSS2_RC exit_rc = TSS2_RC_SUCCESS;
    AsymCreatePrimaryKeyIn keyIn = { 0 };
    AsymCreatePrimaryKeyOut keyOut = { 0 };
    TPM2B_DATA outsideInfo = { 0 };

    if (!pCtx || !pIn)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((pIn->keyAlg != TPM2_ALG_RSA) && (pIn->keyAlg != TPM2_ALG_ECC))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid key algorithm, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    TPM2B_SIZE_CHECK(&pIn->SRKAuth, pCtx->nameAlgSize);
    /*
     * SRK is always in the owner hierarchy
     */
    keyIn.hierarchy = TPM2_RH_OWNER;

    /*
     * We will discard the creation data. Anybody need this data should be
     * using advanced API's. We also dont use outside info.
     */
    keyIn.pcrSelection = 0;
    keyIn.pOutsideInfo = &outsideInfo;

    keyIn.pNewKeyAuth = &pIn->SRKAuth;

    if (0 == pIn->SRKAuth.size)
    {
        /*
         * Disable dictionary attack protection on SRK per the TCG
         * provisioning guidance documents, for well known SRK.
         */
        keyIn.disableDA = TRUE;
    }

    keyIn.persistentHandle = FAPI2_RH_SRK;

    keyIn.keyAlg = pIn->keyAlg;

    if (pIn->keyAlg == TPM2_ALG_RSA)
    {
        keyIn.keyInfo.rsaInfo.keySize = 2048;
        keyIn.keyInfo.rsaInfo.exponent = 0;
        keyIn.keyInfo.rsaInfo.hashAlg = TPM2_ALG_SHA256;
        keyIn.keyInfo.rsaInfo.keyType = FAPI2_ASYM_TYPE_STORAGE;
        keyIn.keyInfo.rsaInfo.scheme = TPM2_ALG_NULL;

        /*
         * use key location as creation entropy, in case createAK is called
         * multiple times for the same key type and details.
         */
        keyIn.externalEntryopy.rsaEntropy.size = sizeof(keyIn.persistentHandle);
        if (OK != DIGI_MEMCPY((void *)keyIn.externalEntryopy.rsaEntropy.buffer,
                (void *)&(keyIn.persistentHandle), sizeof(keyIn.persistentHandle)))
        {
            rc = TSS2_SYS_RC_IO_ERROR;
            DB_PRINT("%s.%d Failed to memcpy, rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
    }
    else
    {
        keyIn.keyInfo.eccInfo.curveID = TPM2_ECC_NIST_P256;
        keyIn.keyInfo.eccInfo.keyType = FAPI2_ASYM_TYPE_STORAGE;
        keyIn.keyInfo.eccInfo.scheme = TPM2_ALG_NULL;

        /*
         * use key location as creation entropy, in case createAK is called
         * multiple times for the same key type and details.
         */
        keyIn.externalEntryopy.eccEntropy.x.size = sizeof(keyIn.persistentHandle);
        if (OK != DIGI_MEMCPY((void *)keyIn.externalEntryopy.eccEntropy.x.buffer,
                (void *)&(keyIn.persistentHandle), sizeof(keyIn.persistentHandle)))
        {
            rc = TSS2_SYS_RC_IO_ERROR;
            DB_PRINT("%s.%d Failed to memcpy, rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
    }

    rc = FAPI2_ASYM_createPrimaryAsymKey(pCtx, NULL, &keyIn, &keyOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to Create RSA EK, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /*
     * Destroy the primary key object returned. We dont need it for SRK's.
     */
    rc = FAPI2_UTILS_destroyObject(&keyOut.pKey);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to destroy FAPI object, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    rc = TSS2_RC_SUCCESS;
exit:

    if (TSS2_RC_SUCCESS == rc)
        rc = exit_rc;

    return rc;
}

/*
 * This function creates the RSA or ECC Attestation Key for the TPM
 * using the template provided in the input parameters.
 * No values are returned since the AK will be persisted at a known location.
 * Attestation Keys are primary keys in this FAPI design per the recommendation
 * in TPM library specification Part 1 C4.2.2.
 */

TSS2_RC FAPI2_ADMIN_createAK(
        FAPI2_CONTEXT *pCtx,
        AdminCreateAKIn *pIn
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TSS2_RC exit_rc = TSS2_RC_SUCCESS;
    AsymCreatePrimaryKeyIn keyIn = { 0 };
    AsymCreatePrimaryKeyOut keyOut = { 0 };
    TPM2B_DATA outsideInfo = { 0 };

    if (!pCtx || !pIn)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((pIn->keyAlg != TPM2_ALG_RSA) && (pIn->keyAlg != TPM2_ALG_ECC))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid key algorithm, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((pIn->persistentHandle == FAPI2_RH_EK) ||
            (pIn->persistentHandle == FAPI2_RH_SRK) ||
            (pIn->persistentHandle < FAPI2_RH_PERSISTENT_ENDORSEMENT_START) ||
            (pIn->persistentHandle > FAPI2_RH_PERSISTENT_ENDORSEMENT_END))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid persistent handle specified, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    TPM2B_SIZE_CHECK(&pIn->AKAuth, pCtx->nameAlgSize);

    /*
     * Attestation keys are under endorsement hierarchy.
     */
    keyIn.hierarchy = TPM2_RH_ENDORSEMENT;
    keyIn.pNewKeyAuth = &pIn->AKAuth;
    keyIn.pOutsideInfo = &outsideInfo;
    keyIn.keyAlg = pIn->keyAlg;
    keyIn.persistentHandle = pIn->persistentHandle;

    /*
     * Force keyType to be FAPI2_ASYM_TYPE_ATTESTATION
     */
    if (pIn->keyAlg == TPM2_ALG_RSA)
    {
        if (pIn->keyInfo.rsaInfo.keyType != FAPI2_ASYM_TYPE_ATTESTATION)
            pIn->keyInfo.rsaInfo.keyType = FAPI2_ASYM_TYPE_ATTESTATION;

        keyIn.keyInfo.rsaInfo = pIn->keyInfo.rsaInfo;
        /*
         * use key location as creation entropy, in case createAK is called
         * multiple times for the same key type and details.
         */
        keyIn.externalEntryopy.rsaEntropy.size = sizeof(keyIn.persistentHandle);
        if (OK != DIGI_MEMCPY((void *)keyIn.externalEntryopy.rsaEntropy.buffer,
                (void *)&(keyIn.persistentHandle), sizeof(keyIn.persistentHandle)))
        {
            rc = TSS2_SYS_RC_IO_ERROR;
            DB_PRINT("%s.%d Failed to memcpy, rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
    }
    else
    {
        if (pIn->keyInfo.eccInfo.keyType != FAPI2_ASYM_TYPE_ATTESTATION)
                    pIn->keyInfo.eccInfo.keyType = FAPI2_ASYM_TYPE_ATTESTATION;

        keyIn.keyInfo.eccInfo = pIn->keyInfo.eccInfo;

        /*
         * use key location as creation entropy, in case createAK is called
         * multiple times for the same key type and details.
         */
        keyIn.externalEntryopy.eccEntropy.x.size = sizeof(keyIn.persistentHandle);
        if (OK != DIGI_MEMCPY((void *)keyIn.externalEntryopy.eccEntropy.x.buffer,
                (void *)&(keyIn.persistentHandle), sizeof(keyIn.persistentHandle)))
        {
            rc = TSS2_SYS_RC_IO_ERROR;
            DB_PRINT("%s.%d Failed to memcpy, rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
    }

    rc = FAPI2_ASYM_createPrimaryAsymKey(pCtx, NULL, &keyIn, &keyOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to Create RSA AK, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /*
     * Destroy the primary key object returned. We dont need it for AK's.
     */
    rc = FAPI2_UTILS_destroyObject(&keyOut.pKey);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to destroy FAPI object, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    rc = TSS2_RC_SUCCESS;
exit:

    if (TSS2_RC_SUCCESS == rc)
        rc = exit_rc;

    return rc;
}

/*
 * This API can be used to get the public key of primary keys from the TPM.
 */
TSS2_RC FAPI2_ADMIN_getPrimaryPublicKey(
        FAPI2_CONTEXT *pCtx,
        AdminGetPrimaryPublicKeyIn *pIn,
        AdminGetPrimaryPublicKeyOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TSS2_RC exit_rc = TSS2_RC_SUCCESS;
    TPMT_PUBLIC *pPublic = NULL;
    FAPI2_OBJECT *pObject = NULL;
    UtilsCreateObjectIn createObjectIn = { 0 };
    UtilsCreateObjectOut createObjectOut = { 0 };

    if (!pCtx || !pIn || !pOut)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((FAPI2_RH_EK != pIn->persistentHandle) && (FAPI2_RH_SRK != pIn->persistentHandle))
    {
        if ((pIn->persistentHandle < FAPI2_RH_PERSISTENT_ENDORSEMENT_START) ||
                (pIn->persistentHandle > FAPI2_RH_PERSISTENT_ENDORSEMENT_END))
        {
            rc = TSS2_SYS_RC_BAD_VALUE;
            DB_PRINT("%s.%d Invalid persistent handle specified, rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
    }
    /*
     * For SRK and EK, the context should contain the public information already. If
     * the context does not contain them, the TPM is not provisioned and there is no
     * point in going to the TPM to read the public area again.
     */
    if (FAPI2_RH_EK == pIn->persistentHandle)
    {
        if (NULL == pCtx->primaryKeys.pEK)
        {
            rc = TSS2_SYS_RC_BAD_VALUE;
            DB_PRINT("%s.%d EK not provisioned in the TPM yet, rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        pPublic = &pCtx->primaryKeys.pEK->public.objectPublic.publicArea;
    }
    else if (FAPI2_RH_SRK == pIn->persistentHandle)
    {
        if (NULL == pCtx->primaryKeys.pSRK)
        {
            rc = TSS2_SYS_RC_BAD_VALUE;
            DB_PRINT("%s.%d SRK not provisioned in the TPM yet, rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        pPublic = &(pCtx->primaryKeys.pSRK->public.objectPublic.publicArea);
    }
    else
    {
        createObjectIn.tpm2Handle = pIn->persistentHandle;
        rc = FAPI2_UTILS_createObject(pCtx, &createObjectIn, &createObjectOut);
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed to create object for persistent handle. Unable to get public key"
                    ", rc 0x%02x = %s\n",
                            __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
        pObject = createObjectOut.pObject;
        pPublic = &(pObject->public.objectPublic.publicArea);
    }

    pOut->keyAlg = pPublic->type;

    switch (pPublic->type)
    {
    case TPM2_ALG_RSA:
        pOut->publicKey.rsaPublic = pPublic->unique.rsa;
        break;
    case TPM2_ALG_ECC:
        pOut->publicKey.eccPublic = pPublic->unique.ecc;
        break;
    default:
        rc = TSS2_SYS_RC_GENERAL_FAILURE;
        DB_PRINT("%s.%d Key is not an RSA or ECC asymmetric key, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
        break;
    }

    rc = TSS2_RC_SUCCESS;

exit:
    if (pObject)
        exit_rc = FAPI2_UTILS_destroyObject(&pObject);

    if (TSS2_RC_SUCCESS == rc)
        rc = exit_rc;

    return rc;
}

/*
 * This API clears locked out TPM2 using TPM2_DictonaryAttackLockReset(). 
 * It uses Lockout Hierarchy authorization for this purpose.
 */
MOC_EXTERN TSS2_RC FAPI2_ADMIN_clearDALockout(
        FAPI2_CONTEXT *pCtx
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TSS2_RC exit_rc = TSS2_RC_SUCCESS;
    MOCTPM2_OBJECT_HANDLE *pAuthSession = NULL;
    DALockoutResetIn daLockReset = { 0 } ;
    TPM2B_AUTH *pOldLockoutAuth = NULL;

    if (!pCtx)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (!pCtx->authValues.lockoutAuthValid)
    {
        rc = TSS2_SYS_RC_NOT_PERMITTED;
        DB_PRINT("%s.%d Invalid authValue for lockout hierarchy."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pOldLockoutAuth = &pCtx->authValues.lockoutAuth;

    rc = FAPI2_UTILS_startSession(pCtx, &pAuthSession);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Unable to start auth session, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /*
     * Clear TPM lockout using current lockout authValue and
     * TPM2_DictionaryAttackLockReset command.
     */
    daLockReset.authHandle = TPM2_RH_LOCKOUT;
    daLockReset.pAuthAuthHandle = pOldLockoutAuth;
    daLockReset.pAuthSession = pAuthSession;

    rc = SAPI2_HIERARCHY_DALockoutReset(pCtx->pSapiCtx, &daLockReset);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to reset DA lockout, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    rc = TSS2_RC_SUCCESS;
exit:
    if (pAuthSession)
        exit_rc = FAPI2_UTILS_closeSession(pCtx,
                &pAuthSession);

    if (TSS2_RC_SUCCESS == rc)
        rc = exit_rc;

    return rc;
}

/*
 * This API programs DA lockout parameters on TPM2 using TPM2_DictonaryAttackParameters(). 
 * It uses Lockout Hierarchy authorization for this purpose.
 */
MOC_EXTERN TSS2_RC FAPI2_ADMIN_setDAParameters(
        FAPI2_CONTEXT *pCtx, ubyte4 maxAuthFailures, ubyte4 recoveryTime,
        ubyte4 lockoutRecoveryTime
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TSS2_RC exit_rc = TSS2_RC_SUCCESS;
    MOCTPM2_OBJECT_HANDLE *pAuthSession = NULL;
    DALockoutParametersIn daParameters = { 0 } ;
    TPM2B_AUTH *pOldLockoutAuth = NULL;

    if (!pCtx)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (!pCtx->authValues.lockoutAuthValid)
    {
        rc = TSS2_SYS_RC_NOT_PERMITTED;
        DB_PRINT("%s.%d Invalid authValue for lockout hierarchy."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pOldLockoutAuth = &pCtx->authValues.lockoutAuth;

    rc = FAPI2_UTILS_startSession(pCtx, &pAuthSession);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Unable to start auth session, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /*
     * Clear TPM lockout using current lockout authValue and
     * TPM2_DictionaryAttackLockReset command.
     */
    daParameters.authHandle = TPM2_RH_LOCKOUT;
    daParameters.pAuthAuthHandle = pOldLockoutAuth;
    daParameters.pAuthSession = pAuthSession;
    daParameters.lockoutParameters.newMaxTries = maxAuthFailures;
    daParameters.lockoutParameters.newRecoveryTime = recoveryTime;
    daParameters.lockoutParameters.lockoutRecovery = lockoutRecoveryTime;

    rc = SAPI2_HIERARCHY_DALockoutParameters(pCtx->pSapiCtx, &daParameters);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to set DA lockout parameters, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    rc = TSS2_RC_SUCCESS;
exit:
    if (pAuthSession)
        exit_rc = FAPI2_UTILS_closeSession(pCtx,
                &pAuthSession);

    if (TSS2_RC_SUCCESS == rc)
        rc = exit_rc;

    return rc;
}

#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */
