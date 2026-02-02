/**
 * @file fapi2_sym.c
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
#include "../../../../crypto/aes.h"
#include "../../../../crypto/sha1.h"
#include "../../../../crypto/sha256.h"
#include "../../../../crypto/sha512.h"

/*
 * This API creates a symmetric key that can be used for encryption/decryption.
 * The key created through this API cannot be used for signing.
 */
TSS2_RC FAPI2_SYM_createCipherKey(
        FAPI2_CONTEXT *pCtx,
        SymCreateCipherKeyIn *pIn,
        SymCreateCipherKeyOut*pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TSS2_RC exit_rc = TSS2_RC_SUCCESS;
    TSS2_RC exit_rc1 = TSS2_RC_SUCCESS;
    TSS2_RC exit_rc2 = TSS2_RC_SUCCESS;
    TSS2_RC exit_rc3 = TSS2_RC_SUCCESS;
    CreateIn createIn = { 0 };
    CreateOut createOut = { 0 };
    TPM2B_SENSITIVE_CREATE sensitiveInfo = { 0 };
    TPM2B_PUBLIC inPublic = { 0 };
    TPM2B_DATA outsideInfo = { 0 };
    TPML_PCR_SELECTION pcrSelectionList = { 0 };
    MOCTPM2_OBJECT_HANDLE *pAuthSession = { 0 };
    MOCTPM2_OBJECT_HANDLE *pObjAuthSession = { 0 };
    UtilsCreateObjectIn createObjectIn = { 0 };
    UtilsCreateObjectOut createObjectOut = { 0 };
    ContextLoadObjectExIn loadIn = { 0 };
    ContextLoadObjectExOut loadOut = { 0 };
    ContextFlushObjectIn flushObjectIn = { 0 };
    FAPI2_OBJECT *pParentKeyObject = NULL;
    byteBoolean flushObjectOnFailure = FALSE;
    MOCTPM2_OBJECT_HANDLE *pParentKeyHandle = NULL;
    byteBoolean destroyParentKeyHandle = FALSE;
    PolicyAuthNode defaultPolicy = { 0 };
    PolicyAuthNode *pObjectPolicy = NULL;
    ubyte2 numPolicyTerms = 0;
    PolicyAuthNode dupPolicy = { 0 };
    EaExecutePolicyIn eaExecutePolicyIn = { 0 };
    EaExecutePolicyOut eaExecutePolicyOut = { 0 };

    if (!pCtx || !pIn || !pOut)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (pIn->pParentName && (pIn->pParentName->size != 0))
    {

        rc = FAPI2_CONTEXT_lookupObject(pCtx, pIn->pParentName, &pParentKeyObject);
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Unable to find parent loaded in the context. "
                    "rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        rc = FAPI2_UTILS_loadObjectTree(pCtx, pParentKeyObject, &pParentKeyHandle);
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed to create object for parent key."
                    ", rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        destroyParentKeyHandle = TRUE;
    }
    else
    {
        /*
         * Select SRK as default.
         */
        if (NULL == pCtx->primaryKeys.pSRK)
        {
            rc = TSS2_SYS_RC_BAD_CONTEXT;
            DB_PRINT("%s.%d No SRK found in FAPI Context"
                    ", TPM Unprovisioned or default SRK not found, "
                    "rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        pParentKeyObject = pCtx->primaryKeys.pSRK;
    }

    if ((pParentKeyObject->authValueRequired) && (!pParentKeyObject->authValueValid))
    {
        rc = TSS2_FAPI_RC_NOT_PERMITTED;
        DB_PRINT("%s.%d authValue not set for parent object."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    TPM2B_SIZE_CHECK(&pIn->keyAuth, pCtx->nameAlgSize);

    if (pIn->symAlg != TPM2_ALG_AES)
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d symAlg is not a supported type, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((pIn->keyBits != 128) && (pIn->keyBits != 192) && (pIn->keyBits != 256))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid key size specified, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((pIn->symMode != TPM2_ALG_NULL) &&
            (pIn->symMode != TPM2_ALG_CTR) &&
            (pIn->symMode != TPM2_ALG_OFB) &&
            (pIn->symMode != TPM2_ALG_CBC) &&
            (pIn->symMode != TPM2_ALG_CFB) &&
            (pIn->symMode != TPM2_ALG_ECB))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid symmetric encryption mode specified, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    rc = FAPI2_UTILS_getObjectAuthSession(pCtx, pParentKeyObject, &pAuthSession);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to Start session."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((pIn->numPolicyTerms != 0) && (pIn->pPolicy))
    {
        numPolicyTerms = pIn->numPolicyTerms;
        pObjectPolicy = pIn->pPolicy;
    }
    else
    {
        numPolicyTerms = 1;
        defaultPolicy.policyType = FAPI2_POLICY_AUTH_VALUE;
        pObjectPolicy = &defaultPolicy;
    }

    rc = FAPI2_UTILS_startPolicySession(pCtx, &pObjAuthSession, TRUE);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to start auth session"
                    ", rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    eaExecutePolicyIn.numPolicyTerms = numPolicyTerms;
    eaExecutePolicyIn.pObjectPolicy = pObjectPolicy;
    eaExecutePolicyIn.pSession = pObjAuthSession;
    rc = FAPI2_EA_executePolicy(pCtx, &eaExecutePolicyIn, &eaExecutePolicyOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to execute auth session"
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    inPublic.size = sizeof(inPublic.publicArea);
    inPublic.publicArea.type = TPM2_ALG_SYMCIPHER;
    inPublic.publicArea.nameAlg = pCtx->nameAlg;
    inPublic.publicArea.objectAttributes = TPMA_OBJECT_FIXEDTPM |
            TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN |
            TPMA_OBJECT_DECRYPT | TPMA_OBJECT_SIGN_ENCRYPT | TPMA_OBJECT_USERWITHAUTH |
            TPMA_OBJECT_ADMINWITHPOLICY;
    inPublic.publicArea.parameters.symDetail.sym.algorithm = pIn->symAlg;

    /*
     * TODO: Switch on pIn->symAlg if something other than AES is supported
     */
    if (pIn->symAlg == TPM2_ALG_AES)
    {
        inPublic.publicArea.parameters.symDetail.sym.keyBits.aes = pIn->keyBits;
        inPublic.publicArea.parameters.symDetail.sym.mode.aes = pIn->symMode;
    }

    if(pIn->bEnableBackup)
    {
        inPublic.publicArea.objectAttributes &= ~(TPMA_OBJECT_FIXEDTPM |
                TPMA_OBJECT_FIXEDPARENT);

        dupPolicy.policyInfo.policyCC.code = TPM2_CC_Duplicate;
        dupPolicy.policyType = FAPI2_POLICY_COMMAND_CODE;
        eaExecutePolicyIn.numPolicyTerms = 1;
        eaExecutePolicyIn.pObjectPolicy = &dupPolicy;
        eaExecutePolicyIn.pSession = pObjAuthSession;

        rc = FAPI2_EA_executePolicy(pCtx, &eaExecutePolicyIn, &eaExecutePolicyOut);
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed to execute auth session"
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
    }
    inPublic.publicArea.authPolicy = eaExecutePolicyOut.policyDigest;

    /*
     * Size will be backfilled by serialization for TPM2B's that encapsulate
     * a structure.
     */
    sensitiveInfo.size = sizeof(sensitiveInfo.sensitive.userAuth);
    sensitiveInfo.sensitive.userAuth = pIn->keyAuth;

    createIn.pParentHandle = pCtx->primaryKeys.pSRKHandle;
    createIn.pInSensitive = &sensitiveInfo;
    createIn.pInPublic = &inPublic;
    createIn.pOutsideInfo = &outsideInfo;
    createIn.pCreationPCR = &pcrSelectionList;
    createIn.pAuthParentHandle = &pCtx->primaryKeys.pSRK->authValue;
    createIn.pAuthSession = pAuthSession;

    /*
     * Create the Key!
     */
    rc = SAPI2_OBJECT_Create(pCtx->pSapiCtx, &createIn, &createOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to create object for new key."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /*
     * Create FAPI2 Object representing the new non persistent key.
     */
    createObjectIn.tpm2Handle = 0;
    createObjectIn.pAuthValue = &pIn->keyAuth;
    createObjectIn.pPrivate = &createOut.outPrivate;
    createObjectIn.pPublic = &createOut.outPublic;
    createObjectIn.pCreationData = &createOut.creationData;
    createObjectIn.pCreationHash = &createOut.creationHash;
    createObjectIn.pCreationTicket = &createOut.creationTicket;
    createObjectIn.numPolicyTerms = numPolicyTerms;
    createObjectIn.pObjectPolicy = pObjectPolicy;

    rc = FAPI2_UTILS_createObject(pCtx, &createObjectIn, &createObjectOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to create FAPI object."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    loadIn.pObj = createObjectOut.pObject;
    /*
     * authValue must already be set during creation inside FAPI2_OBJECT.
     */
    loadIn.pAuthObj = NULL;
    rc = FAPI2_CONTEXT_loadObjectEx(pCtx, &loadIn, &loadOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to load object into context, "
                "rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    flushObjectOnFailure = TRUE;

    rc = FAPI2_UTILS_serialize(&createObjectOut.pObject, FALSE, &pOut->key);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to get serialized key, "
                "rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }
    pOut->keyName = loadOut.objName;

    rc = TSS2_RC_SUCCESS;
exit:
    if (pAuthSession)
    {
        exit_rc1 = FAPI2_UTILS_closeSession(pCtx,
                &pAuthSession);
    }

    if (pObjAuthSession)
    {
        exit_rc2 = FAPI2_UTILS_closeSession(pCtx,
                &pObjAuthSession);
        if (TSS2_RC_SUCCESS == exit_rc1)
            exit_rc1 = exit_rc2;
    }
    
    /*
     * Destroy handle created for the parent object.
     */
    if (pParentKeyHandle && destroyParentKeyHandle)
        exit_rc2 = FAPI2_UTILS_destroyHandle(pCtx, &pParentKeyHandle);

    if (rc != TSS2_RC_SUCCESS)
    {
        if (flushObjectOnFailure)
        {
            flushObjectIn.objName = loadOut.objName;
            exit_rc3 = FAPI2_CONTEXT_flushObject(pCtx, &flushObjectIn);
        }
        else
        {
            if (createObjectOut.pObject)
            {
                exit_rc3 = FAPI2_UTILS_destroyObject(&createObjectOut.pObject);
            }
        }
    }

    if (pParentKeyObject)
    {
        flushObjectIn.objName = pParentKeyObject->objectName;
        exit_rc = FAPI2_CONTEXT_flushObject(pCtx, &flushObjectIn);
    }

    if (TSS2_RC_SUCCESS == rc)
    {
        /* If there are multiple errors, return the first one encountered */
        if (TSS2_RC_SUCCESS != exit_rc1)
            rc = exit_rc1;
        else if (TSS2_RC_SUCCESS != exit_rc2)
            rc = exit_rc2;
        else if (TSS2_RC_SUCCESS != exit_rc3)
            rc = exit_rc3;
        else
            rc = exit_rc;
    }

    return rc;
}

/*
 * This API creates a symmetric key that can be used for symmetric signing(ex: HMAC, CMAC etc).
 * The key created through this API cannot be used for encryption/decryption.
 * The size of the hmac key created depends on the nameAlg for a given object.
 * The default nameAlg in a FAPI2 context is SHA256, so the size of the HMAC
 * key created is 256 bits. The key size can be changed by changing the nameAlg
 * in a FAPI2 context. Changing of nameAlg is not supported currently so a
 * symmetric signing key has a size of 256 bits.
 */

TSS2_RC FAPI2_SYM_createSigningKey(
        FAPI2_CONTEXT *pCtx,
        SymCreateSigningKeyIn *pIn,
        SymCreateSigningKeyOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TSS2_RC exit_rc = TSS2_RC_SUCCESS;
    TSS2_RC exit_rc1 = TSS2_RC_SUCCESS;
    TSS2_RC exit_rc2 = TSS2_RC_SUCCESS;
    TSS2_RC exit_rc3 = TSS2_RC_SUCCESS;
    CreateIn createIn = { 0 };
    CreateOut createOut = { 0 };
    TPM2B_SENSITIVE_CREATE sensitiveInfo = { 0 };
    TPM2B_PUBLIC inPublic = { 0 };
    TPM2B_DATA outsideInfo = { 0 };
    TPML_PCR_SELECTION pcrSelectionList = { 0 };
    MOCTPM2_OBJECT_HANDLE *pAuthSession = { 0 };
    MOCTPM2_OBJECT_HANDLE *pObjAuthSession = { 0 };
    UtilsCreateObjectIn createObjectIn = { 0 };
    UtilsCreateObjectOut createObjectOut = { 0 };
    ContextLoadObjectExIn loadIn = { 0 };
    ContextLoadObjectExOut loadOut = { 0 };
    ContextFlushObjectIn flushObjectIn = { 0 };
    FAPI2_OBJECT *pParentKeyObject = NULL;
    byteBoolean flushObjectOnFailure = FALSE;
    MOCTPM2_OBJECT_HANDLE *pParentKeyHandle = NULL;
    byteBoolean destroyParentKeyHandle = FALSE;
    PolicyAuthNode defaultPolicy = { 0 };
    PolicyAuthNode *pObjectPolicy = NULL;
    ubyte2 numPolicyTerms = 0;
    PolicyAuthNode dupPolicy = { 0 };
    EaExecutePolicyIn eaExecutePolicyIn = { 0 };
    EaExecutePolicyOut eaExecutePolicyOut = { 0 };

    if (!pCtx || !pIn || !pOut)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (pIn->pParentName && (pIn->pParentName->size != 0))
    {

        rc = FAPI2_CONTEXT_lookupObject(pCtx, pIn->pParentName, &pParentKeyObject);
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Unable to find parent loaded in the context. "
                    "rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        rc = FAPI2_UTILS_loadObjectTree(pCtx, pParentKeyObject, &pParentKeyHandle);
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed to create object for parent key."
                    ", rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        destroyParentKeyHandle = TRUE;
    }
    else
    {
        /*
         * Select SRK as default.
         */
        if (NULL == pCtx->primaryKeys.pSRK)
        {
            rc = TSS2_SYS_RC_BAD_CONTEXT;
            DB_PRINT("%s.%d No SRK found in FAPI Context"
                    ", TPM Unprovisioned or default SRK not found, "
                    "rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        pParentKeyObject = pCtx->primaryKeys.pSRK;
    }

    if ((pParentKeyObject->authValueRequired) && (!pParentKeyObject->authValueValid))
    {
        rc = TSS2_FAPI_RC_NOT_PERMITTED;
        DB_PRINT("%s.%d authValue not set for parent object."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    TPM2B_SIZE_CHECK(&pIn->keyAuth, pCtx->nameAlgSize);

    if (pIn->sigScheme != TPM2_ALG_HMAC)
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid symmetric signing scheme specified, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((pIn->hashAlg != TPM2_ALG_SHA256) &&
            (pIn->hashAlg != TPM2_ALG_SHA384) &&
            (pIn->hashAlg != TPM2_ALG_SHA512))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid hash algorithm specified, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    rc = FAPI2_UTILS_getObjectAuthSession(pCtx, pParentKeyObject, &pAuthSession);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to Start session."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((pIn->numPolicyTerms != 0) && (pIn->pPolicy))
    {
        numPolicyTerms = pIn->numPolicyTerms;
        pObjectPolicy = pIn->pPolicy;
    }
    else
    {
        numPolicyTerms = 1;
        defaultPolicy.policyType = FAPI2_POLICY_AUTH_VALUE;
        pObjectPolicy = &defaultPolicy;
    }

    rc = FAPI2_UTILS_startPolicySession(pCtx, &pObjAuthSession, TRUE);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to start auth session"
                    ", rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    eaExecutePolicyIn.numPolicyTerms = numPolicyTerms;
    eaExecutePolicyIn.pObjectPolicy = pObjectPolicy;
    eaExecutePolicyIn.pSession = pObjAuthSession;
    rc = FAPI2_EA_executePolicy(pCtx, &eaExecutePolicyIn, &eaExecutePolicyOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to execute auth session"
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    inPublic.size = sizeof(inPublic.publicArea);
    inPublic.publicArea.type = TPM2_ALG_KEYEDHASH;
    inPublic.publicArea.nameAlg = pCtx->nameAlg;
    inPublic.publicArea.objectAttributes = TPMA_OBJECT_FIXEDTPM |
            TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN |
            TPMA_OBJECT_SIGN_ENCRYPT | TPMA_OBJECT_USERWITHAUTH |
            TPMA_OBJECT_ADMINWITHPOLICY;

    inPublic.publicArea.parameters.keyedHashDetail.scheme.scheme = pIn->sigScheme;

    /*
     * TODO: Switch on pIn->sigScheme if something other than HMAC is supported
     */
    if (TPM2_ALG_HMAC == pIn->sigScheme)
    {
        inPublic.publicArea.parameters.keyedHashDetail.scheme.details.hmac.hashAlg = pIn->hashAlg;
    }

    if(pIn->bEnableBackup)
    {
        inPublic.publicArea.objectAttributes &= ~(TPMA_OBJECT_FIXEDTPM |
                TPMA_OBJECT_FIXEDPARENT);

        dupPolicy.policyInfo.policyCC.code = TPM2_CC_Duplicate;
        dupPolicy.policyType = FAPI2_POLICY_COMMAND_CODE;
        eaExecutePolicyIn.numPolicyTerms = 1;
        eaExecutePolicyIn.pObjectPolicy = &dupPolicy;
        eaExecutePolicyIn.pSession = pObjAuthSession;

        rc = FAPI2_EA_executePolicy(pCtx, &eaExecutePolicyIn, &eaExecutePolicyOut);
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed to execute auth session"
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
    }
    inPublic.publicArea.authPolicy = eaExecutePolicyOut.policyDigest;

    /*
     * Size will be backfilled by serialization for TPM2B's that encapsulate
     * a structure.
     */
    sensitiveInfo.size = sizeof(sensitiveInfo.sensitive.userAuth);
    sensitiveInfo.sensitive.userAuth = pIn->keyAuth;

    createIn.pParentHandle = pCtx->primaryKeys.pSRKHandle;
    createIn.pInSensitive = &sensitiveInfo;
    createIn.pInPublic = &inPublic;
    createIn.pOutsideInfo = &outsideInfo;
    createIn.pCreationPCR = &pcrSelectionList;
    createIn.pAuthParentHandle = &pCtx->primaryKeys.pSRK->authValue;
    createIn.pAuthSession = pAuthSession;

    /*
     * Create the Key!
     */
    rc = SAPI2_OBJECT_Create(pCtx->pSapiCtx, &createIn, &createOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to create object for new key."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /*
     * Create FAPI2 Object representing the new non persistent key.
     */
    createObjectIn.tpm2Handle = 0;
    createObjectIn.pAuthValue = &pIn->keyAuth;
    createObjectIn.pPrivate = &createOut.outPrivate;
    createObjectIn.pPublic = &createOut.outPublic;
    createObjectIn.pCreationData = &createOut.creationData;
    createObjectIn.pCreationHash = &createOut.creationHash;
    createObjectIn.pCreationTicket = &createOut.creationTicket;
    createObjectIn.numPolicyTerms = numPolicyTerms;
    createObjectIn.pObjectPolicy = pObjectPolicy;

    rc = FAPI2_UTILS_createObject(pCtx, &createObjectIn, &createObjectOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to create FAPI object."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    loadIn.pObj = createObjectOut.pObject;
    /*
     * authValue must already be set during creation inside FAPI2_OBJECT.
     */
    loadIn.pAuthObj = NULL;
    rc = FAPI2_CONTEXT_loadObjectEx(pCtx, &loadIn, &loadOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to load object into context, "
                "rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    flushObjectOnFailure = TRUE;

    rc = FAPI2_UTILS_serialize(&createObjectOut.pObject, FALSE, &pOut->key);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to get serialized key, "
                "rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }
    pOut->keyName = loadOut.objName;

    rc = TSS2_RC_SUCCESS;
exit:

    if (pAuthSession)
    {
        exit_rc1 = FAPI2_UTILS_closeSession(pCtx,
                &pAuthSession);
    }

    if (pObjAuthSession)
    {
        exit_rc2 = FAPI2_UTILS_closeSession(pCtx,
                &pObjAuthSession);
        if (TSS2_RC_SUCCESS == exit_rc1)
            exit_rc1 = exit_rc2;
    }

    /*
     * Destroy handle created for the parent object.
     */
    if (pParentKeyHandle && destroyParentKeyHandle)
        exit_rc2 = FAPI2_UTILS_destroyHandle(pCtx, &pParentKeyHandle);

    if (rc != TSS2_RC_SUCCESS)
    {
        if (flushObjectOnFailure)
        {
            flushObjectIn.objName = loadOut.objName;
            exit_rc3 = FAPI2_CONTEXT_flushObject(pCtx, &flushObjectIn);
        }
        else
        {
            if (createObjectOut.pObject)
            {
                exit_rc3 = FAPI2_UTILS_destroyObject(&createObjectOut.pObject);
            }
        }
    }

    if (pParentKeyObject)
    {
        flushObjectIn.objName = pParentKeyObject->objectName;
        exit_rc = FAPI2_CONTEXT_flushObject(pCtx, &flushObjectIn);
    }

    if (TSS2_RC_SUCCESS == rc)
    {
        /* If there are multiple errors, return the first one encountered */
        if (TSS2_RC_SUCCESS != exit_rc1)
            rc = exit_rc1;
        else if (TSS2_RC_SUCCESS != exit_rc2)
            rc = exit_rc2;
        else if (TSS2_RC_SUCCESS != exit_rc3)
            rc = exit_rc3;
        else
            rc = exit_rc;
    }

    return rc;
}

/*
 * This API uses a symmetric key in the TPM to encrypt or decrypt caller provided data
 * in the caller specified mode.
 */
TSS2_RC FAPI2_SYM_encryptDecrypt(
        FAPI2_CONTEXT *pCtx,
        SymEncryptDecryptIn *pIn,
        SymEncryptDecryptOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TSS2_RC exit_rc = TSS2_RC_SUCCESS;
    TPMI_ALG_SYM_MODE symMode = TPM2_ALG_NULL;
    TPMT_PUBLIC *pPublic = NULL;
    FAPI2_OBJECT *pKey = NULL;
    MOCTPM2_OBJECT_HANDLE *pKeyHandle = NULL;
    MOCTPM2_OBJECT_HANDLE *pAuthSession = NULL;
    EncryptDecryptIn encryptDecryptIn = { 0 };
    EncryptDecryptOut encryptDecryptOut = { 0 };
    TPM2B_MAX_BUFFER *pMaxBuffer = NULL;
    ubyte4 remaining = 0;
    ubyte *pInBuffer = NULL;
    ubyte *pOutBuffer = NULL;
    ubyte *pOutput = NULL;
    ContextFlushObjectIn flushObjectIn = { 0 };
    EaExecutePolicyIn eaExecutePolicyIn = { 0 };
    EaExecutePolicyOut eaExecutePolicyOut = { 0 };

    if (!pCtx || !pIn || !pOut)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    TPM2B_SIZE_CHECK(&pIn->keyName, TPM2B_MAX_SIZE(&pIn->keyName));
    TPM2B_SIZE_CHECK(&pIn->iv, TPM2B_MAX_SIZE(&pIn->iv));

    if ((pIn->symMode != TPM2_ALG_NULL) &&
            (pIn->symMode != TPM2_ALG_CTR) &&
            (pIn->symMode != TPM2_ALG_OFB) &&
            (pIn->symMode != TPM2_ALG_CBC) &&
            (pIn->symMode != TPM2_ALG_CFB) &&
            (pIn->symMode != TPM2_ALG_ECB))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid symmetric encryption mode specified, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

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

    if ((pPublic->type != TPM2_ALG_SYMCIPHER) ||
            (pPublic->objectAttributes & TPMA_OBJECT_RESTRICTED) ||
            (!(pPublic->objectAttributes & TPMA_OBJECT_DECRYPT)) ||
            (!(pPublic->objectAttributes & TPMA_OBJECT_SIGN_ENCRYPT)) ||
            (pPublic->parameters.symDetail.sym.algorithm != TPM2_ALG_AES))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid key type provided, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    symMode = pPublic->parameters.symDetail.sym.mode.aes;

    /*
     * mode is NULL in both the input and the key public area. This means no mode is
     * specified.
     */
    if ((TPM2_ALG_NULL == symMode) && (TPM2_ALG_NULL == pIn->symMode))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Mode not specified during creation or as input, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /*
     * If mode was not specified during creation, ie it is NULL in the object public area
     * use pIn->symMode. pIn->symMode validate above to be correct.
     */
    if (TPM2_ALG_NULL == symMode)
    {
        symMode = pIn->symMode;
    }

    /*
     * Size of input data must be a multiple of block size for ECB and CBC mode
     * of operation.
     */
    if ((TPM2_ALG_ECB == symMode) || (TPM2_ALG_CBC == symMode))
    {
        /*
         * TODO: Switch on algorithm specific block size. For now we only support AES
         */
        if ((pIn->bufferLen % AES_BLOCK_SIZE) != 0)
        {
            rc = TSS2_SYS_RC_BAD_VALUE;
            DB_PRINT("%s.%d bufferLen not a multiple of block size for ECB/CBC mode, rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
    }

    if (OK != DIGI_CALLOC((void **)&pMaxBuffer, 1, sizeof(*pMaxBuffer)))
    {
        rc = TSS2_SYS_RC_INSUFFICIENT_BUFFER;
        DB_PRINT("%s.%d Failed to allocate memory"
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /*
     * Allocate output buffer, must be equal to input buffer length.
     */
    if (OK != DIGI_CALLOC((void **)&pOutput, 1, pIn->bufferLen))
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

    if (pIn->isDecryption)
        encryptDecryptIn.decrypt = YES;
    else
        encryptDecryptIn.decrypt = NO;

    encryptDecryptIn.mode = symMode;
    encryptDecryptIn.pInData = pMaxBuffer;
    encryptDecryptIn.pAuthSession = pAuthSession;
    encryptDecryptIn.pObjectHandle = pKeyHandle;
    encryptDecryptIn.pAuthObjectHandle = &pKey->authValue;
    encryptDecryptIn.pIvIn = &pIn->iv;

    remaining = pIn->bufferLen;
    pInBuffer = pIn->pBuffer;
    pOutBuffer = pOutput;

    while (remaining > 0)
    {
        pMaxBuffer->size = (remaining >= TPM2_MAX_DIGEST_BUFFER) ?
                TPM2_MAX_DIGEST_BUFFER : remaining;

        DIGI_MEMCPY(pMaxBuffer->buffer, pInBuffer, pMaxBuffer->size);

        rc = SAPI2_SYM_EncryptDecrypt(pCtx->pSapiCtx, &encryptDecryptIn, &encryptDecryptOut);
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed to encrypt/decrypt buffer."
                    ", rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        if (encryptDecryptOut.outData.size != pMaxBuffer->size)
        {
            rc = TSS2_SYS_RC_MALFORMED_RESPONSE;
            DB_PRINT("%s.%d Output data size not equal to input data size."
                    ", rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        /*
         * re-execute the policy, if the object has a policy. Since the sessions are
         * started with the continueSession attribute set, the TPM starts a new epoch
         * every time the policy session is used for authorization and clears the
         * policyDigest. Hence, successive use of the same session, without re-executing
         * the policy will fail authorization.
         * If the session does not have the continue session attribute, we would need
         * to flush the policySession and restart it every time. Executing the policy
         * on an existing session instead, is more efficient.
         *
         * NOTE: FAPI2_EA_executePolicy needs an object Auth session (hence the latter if clause)
         * TO DO check that this is still ok with streaming.
         */
        if (pKey->numPolicyTerms && !(pPublic->objectAttributes & TPMA_OBJECT_USERWITHAUTH))
        {
            eaExecutePolicyIn.pSession = pAuthSession;
            eaExecutePolicyIn.numPolicyTerms = pKey->numPolicyTerms;
            eaExecutePolicyIn.pObjectPolicy = pKey->objectPolicy;
            rc = FAPI2_EA_executePolicy(pCtx, &eaExecutePolicyIn, &eaExecutePolicyOut);
            if (TSS2_RC_SUCCESS != rc)
            {
                DB_PRINT("%s.%d Failed to execute object policy."
                        ", rc 0x%02x = %s\n",
                        __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
                goto exit;
            }
        }
        DIGI_MEMCPY(pOutBuffer, encryptDecryptOut.outData.buffer, pMaxBuffer->size);

        encryptDecryptIn.pIvIn = &encryptDecryptOut.IvOut;
        remaining -= pMaxBuffer->size;
        pInBuffer += pMaxBuffer->size;
        pOutBuffer += pMaxBuffer->size;
    }

    pOut->outLen = pIn->bufferLen;
    pOut->pOutBuffer = pOutput;
    pOutput = NULL;

    rc = TSS2_RC_SUCCESS;
exit:

    if (pOutput && pIn && pIn->bufferLen)
        shredMemory((ubyte **)(&pOutput), pIn->bufferLen, TRUE);

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

/*
 * This API uses a symmetric key in the TPM to sign(HMAC, CMAC etc) a digest provided
 * by the caller. Currently only HMAC is supported.
 */
TSS2_RC FAPI2_SYM_sign(
        FAPI2_CONTEXT *pCtx,
        SymSignIn *pIn,
        SymSignOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TSS2_RC exit_rc = TSS2_RC_SUCCESS;
    TPMT_PUBLIC *pPublic = NULL;
    SignIn signIn = { 0 };
    SignOut signOut = { 0 };
    MOCTPM2_OBJECT_HANDLE *pKeyHandle = NULL;
    MOCTPM2_OBJECT_HANDLE *pAuthSession = NULL;
    FAPI2_OBJECT *pKey = NULL;
    TPMI_ALG_KEYEDHASH_SCHEME sigScheme = TPM2_ALG_NULL;
    TPMI_ALG_HASH hashAlg = TPM2_ALG_NULL;
    TPMT_TK_HASHCHECK signHashCheck = { 0 };
    TPMT_SIG_SCHEME commandSigScheme = { 0 };
    ContextFlushObjectIn flushObjectIn = { 0 };

    if (!pCtx || !pIn || !pOut)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    TPM2B_SIZE_CHECK(&pIn->signDigest, TPM2B_MAX_SIZE(&pIn->signDigest));
    TPM2B_SIZE_CHECK(&pIn->keyName, TPM2B_MAX_SIZE(&pIn->keyName));

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
            (!(pPublic->objectAttributes & TPMA_OBJECT_SIGN_ENCRYPT)))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid key type provided, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    sigScheme = pPublic->parameters.keyedHashDetail.scheme.scheme;

    if (TPM2_ALG_NULL == sigScheme)
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d scheme not specified during creation or as input, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    hashAlg = pPublic->parameters.keyedHashDetail.scheme.details.hmac.hashAlg;
    if (TPM2_ALG_NULL == hashAlg)
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d hash algo not specified during creation or as input, rc 0x%02x = %s\n",
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

     /*
      * Provide NULL hash check ticket, since this digest is not
      * created by the TPM.
      */
     signHashCheck.tag = TPM2_ST_HASHCHECK;
     signHashCheck.hierarchy = TPM2_RH_NULL;
     signHashCheck.digest.size = 0;

     commandSigScheme.scheme = sigScheme;

     /*
      * TODO switch on scheme to fill out hashALg
      */
     commandSigScheme.details.hmac.hashAlg = hashAlg;

     signIn.pObjectHandle = pKeyHandle;
     signIn.pDigest = &pIn->signDigest;
     signIn.pInScheme = &commandSigScheme;
     signIn.pValidation = &signHashCheck;
     signIn.pAuthObjectHandle =&(pKey->authValue);
     signIn.pAuthSession = pAuthSession;

     rc = SAPI2_SIGNATURE_Sign(pCtx->pSapiCtx, &signIn, &signOut);
     if (TSS2_RC_SUCCESS != rc)
     {
         DB_PRINT("%s.%d Failed to Sign digest."
                 ", rc 0x%02x = %s\n",
                 __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
         goto exit;
     }

     if (signOut.signature.sigAlg != sigScheme)
     {
         rc = TSS2_SYS_RC_MALFORMED_RESPONSE;
         DB_PRINT("%s.%d Invalid sigScheme returned by TPM."
                 ", rc 0x%02x = %s\n",
                 __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
         goto exit;
     }

     if (TPM2_ALG_HMAC == sigScheme)
     {
         switch (signOut.signature.signature.hmac.hashAlg)
         {
            case TPM2_ALG_SHA256:
                pOut->signature.size = sizeof(signOut.signature.signature.hmac.digest.sha256);
                DIGI_MEMCPY(pOut->signature.buffer,
                        signOut.signature.signature.hmac.digest.sha256,
                        pOut->signature.size);
                break;
            case TPM2_ALG_SHA384:
                pOut->signature.size = sizeof(signOut.signature.signature.hmac.digest.sha384);
                DIGI_MEMCPY(pOut->signature.buffer,
                        signOut.signature.signature.hmac.digest.sha384,
                        pOut->signature.size);
                break;
            case TPM2_ALG_SHA512:
                pOut->signature.size = sizeof(signOut.signature.signature.hmac.digest.sha512);
                DIGI_MEMCPY(pOut->signature.buffer,
                        signOut.signature.signature.hmac.digest.sha512,
                        pOut->signature.size);
                break;
            default:
                rc = TSS2_SYS_RC_GENERAL_FAILURE;
                DB_PRINT("%s.%d unexpected condition."
                        ", rc 0x%02x = %s\n",
                        __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
                goto exit;
         }
     }
     else
     {
         rc = TSS2_SYS_RC_GENERAL_FAILURE;
         DB_PRINT("%s.%d unexpected condition."
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

/*
 * This API uses a symmetric key to verify a symmetric signature(HMAC, CMAC etc) on a digest
 * provided by the caller.
 */
TSS2_RC FAPI2_SYM_verifySig(
        FAPI2_CONTEXT *pCtx,
        SymVerifySigIn *pIn,
        SymVerifySigOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TSS2_RC exit_rc = TSS2_RC_SUCCESS;
    TPMT_PUBLIC *pPublic = NULL;
    TPMT_SIGNATURE signature = { 0 };
    TPMI_ALG_HASH hashAlg = TPM2_ALG_NULL;
    MOCTPM2_OBJECT_HANDLE *pKeyHandle = NULL;
    VerifySignatureIn verifySigIn = { 0 };
    VerifySignatureOut verifySigOut = { 0 };
    FAPI2_OBJECT *pKey = NULL;
    TPMI_ALG_KEYEDHASH_SCHEME sigScheme = TPM2_ALG_NULL;
    ContextFlushObjectIn flushObjectIn = { 0 };

    if (!pCtx || !pIn || !pOut)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    TPM2B_SIZE_CHECK(&pIn->digest, TPM2B_MAX_SIZE(&pIn->digest));
    TPM2B_SIZE_CHECK(&pIn->keyName, TPM2B_MAX_SIZE(&pIn->keyName));

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
            (!(pPublic->objectAttributes & TPMA_OBJECT_SIGN_ENCRYPT)))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid key type provided, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    sigScheme = pPublic->parameters.keyedHashDetail.scheme.scheme;

    if (TPM2_ALG_NULL == sigScheme)
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d scheme not specified during creation or as input, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    hashAlg = pPublic->parameters.keyedHashDetail.scheme.details.hmac.hashAlg;
    if (TPM2_ALG_NULL == hashAlg)
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d hash algo not specified during creation or as input, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pOut->sigValid = FALSE;

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

    signature.sigAlg = sigScheme;
    signature.signature.hmac.hashAlg = hashAlg;

    switch (hashAlg)
    {
    case TPM2_ALG_SHA256:
        DIGI_MEMCPY(signature.signature.hmac.digest.sha256,
                pIn->signature.buffer,
                sizeof(signature.signature.hmac.digest.sha256));
        break;
    case TPM2_ALG_SHA384:
        DIGI_MEMCPY(signature.signature.hmac.digest.sha384,
                pIn->signature.buffer,
                sizeof(signature.signature.hmac.digest.sha384));
        break;
    case TPM2_ALG_SHA512:
        DIGI_MEMCPY(signature.signature.hmac.digest.sha512,
                pIn->signature.buffer,
                sizeof(signature.signature.hmac.digest.sha512));
        break;
    default:
        rc = TSS2_SYS_RC_GENERAL_FAILURE;
        DB_PRINT("%s.%d unexpected condition."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    verifySigIn.pDigest = &pIn->digest;
    verifySigIn.pObjectHandle = pKeyHandle;
    verifySigIn.pSignature = &signature;

    rc = SAPI2_SIGNATURE_VerifySignature(pCtx->pSapiCtx, &verifySigIn,
            &verifySigOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed signature verification."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ( TPM2_ST_VERIFIED == verifySigOut.validation.tag)
        pOut->sigValid = TRUE;
    else
        pOut->sigValid = FALSE;

    rc = TSS2_RC_SUCCESS;
exit:
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

static MSTATUS
FAPI2_computeBufferHash(MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte* buffer,
                         ubyte4 bytesToHash, ubyte hash[CERT_MAXDIGESTSIZE],
                         ubyte2 *hashSize, TPMI_ALG_HASH name_alg)
{
    MSTATUS status;

    if ((!buffer) || (!hash) || (!hashSize))
    {
        return ERR_NULL_POINTER;
    }

    DIGI_MEMSET( hash, 0, CERT_MAXDIGESTSIZE);

    switch ( name_alg)
    {
        case TPM2_ALG_SHA1:
        {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            status = CRYPTO_INTERFACE_SHA1_completeDigest(MOC_HASH(hwAccelCtx) buffer, bytesToHash, hash);
#else
            status = SHA1_completeDigest(MOC_HASH(hwAccelCtx) buffer, bytesToHash, hash);
#endif
            *hashSize = SHA1_RESULT_SIZE;
            break;
        }


#ifndef __DISABLE_DIGICERT_SHA256__
        case TPM2_ALG_SHA256:
        {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            status = CRYPTO_INTERFACE_SHA256_completeDigest( MOC_HASH(hwAccelCtx) (ubyte*) buffer, bytesToHash, hash);
#else
            status = SHA256_completeDigest( MOC_HASH(hwAccelCtx) (ubyte*) buffer, bytesToHash, hash);
#endif
            *hashSize = SHA256_RESULT_SIZE;
            break;
        }
#endif

#ifndef __DISABLE_DIGICERT_SHA384__
        case TPM2_ALG_SHA384:
        {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            status = CRYPTO_INTERFACE_SHA384_completeDigest( MOC_HASH(hwAccelCtx) (ubyte*) buffer, bytesToHash, hash);
#else
            status = SHA384_completeDigest( MOC_HASH(hwAccelCtx) (ubyte*) buffer, bytesToHash, hash);
#endif
            *hashSize = SHA384_RESULT_SIZE;
            break;
        }
#endif

#ifndef __DISABLE_DIGICERT_SHA512__
        case TPM2_ALG_SHA512:
        {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            status = CRYPTO_INTERFACE_SHA512_completeDigest( MOC_HASH(hwAccelCtx) (ubyte*) buffer, bytesToHash, hash);
#else
            status = SHA512_completeDigest( MOC_HASH(hwAccelCtx) (ubyte*) buffer, bytesToHash, hash);
#endif
            *hashSize = SHA512_RESULT_SIZE;
            break;
        }
#endif

        default:
            status = ERR_CERT_UNSUPPORTED_DIGEST;
            break;
    }

    return status;

} /* CRYPTO_ComputeBufferHash */



static TSS2_RC FAPI2_SYM_getSYMTemplate(
        FAPI2_CONTEXT *pCtx,
        TPM2B_PUBLIC *pPublic,
        FapisSymCreateExternalKeyIn *pIn)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;

    if (!pPublic || !pCtx)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }
    if (OK != DIGI_MEMSET((ubyte *)pPublic, 0, sizeof(*pPublic)))
    {
        DB_PRINT("%s.%d Failed memset"
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }


    pPublic->publicArea.nameAlg = pCtx->nameAlg;   
    pPublic->publicArea.objectAttributes |= TPMA_OBJECT_NODA;
 
    if ((pIn->symAlg == TPM2_ALG_AES))
    {
        TPMT_SYM_DEF_OBJECT *s = &pPublic->publicArea.parameters.symDetail.sym;
        pPublic->publicArea.type = TPM2_ALG_SYMCIPHER;
        s->algorithm = TPM2_ALG_AES;
        s->keyBits.sym = pIn->keyBits;
        s->mode.sym = pIn->symMode;
        pPublic->publicArea.objectAttributes |= TPMA_OBJECT_DECRYPT;
    
    }
    else if (pIn->symAlg == TPM2_ALG_HMAC)
    {
        pPublic->publicArea.type = TPM2_ALG_KEYEDHASH;
        pPublic->publicArea.parameters.keyedHashDetail.scheme.scheme = TPM2_ALG_HMAC;
        pPublic->publicArea.parameters.keyedHashDetail.scheme.details.hmac.hashAlg =
                pIn->hashAlg;
        pPublic->publicArea.objectAttributes |= TPMA_OBJECT_SIGN_ENCRYPT;
    }
    else
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid sym key type"
                    ", rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }
    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}

TSS2_RC FAPI2_util_calc_unique(TPMI_ALG_HASH name_alg,
        TPM2B_PRIVATE_VENDOR_SPECIFIC *key, TPM2B_DIGEST *seed,
        TPM2B_DIGEST *unique_data) 
{
    ubyte2 hash_size;
    int rc;
    TPM2B_MAX_BUFFER buf = { .size = key->size + seed->size };

    if (buf.size > sizeof(buf.buffer)) {
        DB_PRINT("%s.%d Seed and key size are too big\n", __FUNCTION__, __LINE__);
        return TSS2_SYS_RC_BAD_VALUE;
    }

    DIGI_MEMCPY(buf.buffer, seed->buffer, seed->size);
    DIGI_MEMCPY(&buf.buffer[seed->size], key->buffer, key->size);

    rc = FAPI2_computeBufferHash(MOC_HASH(hwAccelCtx) buf.buffer, buf.size, unique_data->buffer, &hash_size, name_alg);
    if (rc) 
    {
        DB_PRINT("%s.%d Hash calculation failed\n", __FUNCTION__, __LINE__);
        return TSS2_SYS_RC_GENERAL_FAILURE;
    }
    unique_data->size = hash_size;

    return TSS2_RC_SUCCESS;
}


TSS2_RC FAPI2_SYM_createExternalSymKey(
        FAPI2_CONTEXT *pCtx,
        FapisSymCreateExternalKeyIn  *pIn,
        SymCreateKeyOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TPM2B_PUBLIC inPublic = { 0 };
    TPM2B_SENSITIVE inSensitive = { 0 };
    GetRandomIn getRandomIn = { 0 };
    GetRandomOut getRandomOut = { 0 };
    UtilsCreateObjectIn createObjectIn = { 0 };
    UtilsCreateObjectOut createObjectOut = { 0 };
    ContextLoadObjectExIn loadIn = { 0 };
    ContextLoadObjectExOut loadOut = { 0 };
    PolicyAuthNode defaultPolicy = { 0 };
    PolicyAuthNode *pObjectPolicy = NULL;
    byteBoolean flushObjectOnFailure = FALSE;
    ContextFlushObjectIn flushObjectIn = { 0 };
    ubyte2 numPolicyTerms = 0;

    if (!pCtx || !pIn || !pOut || !pIn->pKeyAuth || 
            !pIn->pSymKeyBuffer || (0==pIn->symKeyBufferLen))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    TPM2B_SIZE_CHECK(pIn->pKeyAuth, pCtx->nameAlgSize);

    if ((pIn->symAlg != TPM2_ALG_AES) && (pIn->symAlg != TPM2_ALG_HMAC))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d symAlg is not a supported type, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((pIn->symAlg == TPM2_ALG_AES))
    {
        if((pIn->keyBits != 128) && (pIn->keyBits != 192) && (pIn->keyBits != 256))
        {
            rc = TSS2_SYS_RC_BAD_VALUE;
            DB_PRINT("%s.%d Invalid key size specified, rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        if ((pIn->symMode != TPM2_ALG_CTR) &&
                (pIn->symMode != TPM2_ALG_OFB) &&
                (pIn->symMode != TPM2_ALG_CBC) &&
                (pIn->symMode != TPM2_ALG_CFB) &&
                (pIn->symMode != TPM2_ALG_ECB))
        {
            rc = TSS2_SYS_RC_BAD_VALUE;
            DB_PRINT("%s.%d Invalid symmetric encryption mode specified, rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
    }

    if ((pIn->symAlg == TPM2_ALG_HMAC))
    {
        if ((pIn->hashAlg != TPM2_ALG_SHA256) &&
                (pIn->hashAlg != TPM2_ALG_SHA384) &&
                (pIn->hashAlg != TPM2_ALG_SHA512))
        {
            rc = TSS2_SYS_RC_BAD_VALUE;
            DB_PRINT("%s.%d Invalid hash algorithm specified, rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
    }


    rc = FAPI2_SYM_getSYMTemplate(pCtx, &inPublic,
                pIn);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to get symmetric key template."
                    ", rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }
    TPM2B_DIGEST *seed = &inSensitive.sensitiveArea.seedValue;
    seed->size = pCtx->nameAlgSize;
    if (seed->size != 0) {
        getRandomIn.bytesRequested = seed->size;
        rc = SAPI2_RNG_GetRandom(
            pCtx->pSapiCtx,
            &getRandomIn,
            &getRandomOut
        );

        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed to get random number."
                    ", rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
        *seed = getRandomOut.randomBytes;
    }
    if ((pIn->symAlg == TPM2_ALG_AES))
    {
        inSensitive.sensitiveArea.sensitiveType = TPM2_ALG_SYMCIPHER;
        TPM2B_SYM_KEY *s = &inSensitive.sensitiveArea.sensitive.sym;
        s->size = (pIn->keyBits >> 3);
        DIGI_MEMCPY(s->buffer, pIn->pSymKeyBuffer, s->size);
    }
    else if (pIn->symAlg == TPM2_ALG_HMAC)
    {
        inSensitive.sensitiveArea.sensitiveType = TPM2_ALG_KEYEDHASH;
        if ( pIn->symKeyBufferLen > FAPI2_HMAC_MAX_SIZE || pIn->symKeyBufferLen == 0) 
        {
            rc = TSS2_SYS_RC_BAD_VALUE;
            DB_PRINT("%s.%d Invalid key size, got %lu bytes, expected not more than 64 bytes, rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, pIn->symKeyBufferLen, rc, tss2_err_string(rc));
            goto exit;
        }
        TPM2B_SENSITIVE_DATA *b = &inSensitive.sensitiveArea.sensitive.bits;
        b->size = pIn->symKeyBufferLen;
        DIGI_MEMCPY(b->buffer, pIn->pSymKeyBuffer, b->size);
    }
    TPM2B_DIGEST *unique = &inPublic.publicArea.unique.sym;
    TPM2B_PRIVATE_VENDOR_SPECIFIC *key = &inSensitive.sensitiveArea.sensitive.any;
    TPMI_ALG_HASH name_alg = inPublic.publicArea.nameAlg;
    
    rc = FAPI2_util_calc_unique(name_alg, key, seed, unique);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to get unique for public."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }
    inSensitive.sensitiveArea.authValue = *(pIn->pKeyAuth);
    if ((pIn->numPolicyTerms != 0) && (pIn->pPolicy))
    {
        numPolicyTerms = pIn->numPolicyTerms;
        pObjectPolicy = pIn->pPolicy;
    }
    else
    {
        numPolicyTerms = 1;
        defaultPolicy.policyType = FAPI2_POLICY_AUTH_VALUE;
        pObjectPolicy = &defaultPolicy;
    }

    rc = FAPI2_UTILS_fillPolicyDigest(pCtx, numPolicyTerms, pObjectPolicy,
            &inPublic.publicArea.authPolicy);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to get policy digest."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    inPublic.size = sizeof(inPublic.publicArea);

    /*
     * Create FAPI2 Object representing the external key.
     */
    createObjectIn.pAuthValue = pIn->pKeyAuth;
    createObjectIn.pSensitive = &inSensitive;
    createObjectIn.pPublic = &inPublic;
    createObjectIn.numPolicyTerms = numPolicyTerms;
    createObjectIn.pObjectPolicy = pObjectPolicy;

    rc = FAPI2_UTILS_createObject(pCtx, &createObjectIn, &createObjectOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to create FAPI object."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    loadIn.pObj = createObjectOut.pObject;
    /*
     * authValue must already be set during creation inside FAPI2_OBJECT.
     */
    loadIn.pAuthObj = NULL;
    rc = FAPI2_CONTEXT_loadObjectEx(pCtx, &loadIn, &loadOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to load object into context, "
                "rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    flushObjectOnFailure = TRUE;

    rc = FAPI2_UTILS_serialize(&createObjectOut.pObject, FALSE, &pOut->key);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to get serialized key, "
                "rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }
    pOut->keyName = loadOut.objName;

exit:

    if (rc != TSS2_RC_SUCCESS)
    {
        if (flushObjectOnFailure)
        {
            flushObjectIn.objName = loadOut.objName;
            (void) FAPI2_CONTEXT_flushObject(pCtx, &flushObjectIn);
        }
        else
        {
            if (createObjectOut.pObject)
            {
                (void) FAPI2_UTILS_destroyObject(&createObjectOut.pObject);
            }
        }
    }

    return rc;
}

TSS2_RC FAPI2_SYM_ImportDuplicateKey(
    FAPI2_CONTEXT *pCtx,
    FAPI2_ImportIn *pIn,
    FAPI2_ImportOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TSS2_RC exit_rc = TSS2_RC_SUCCESS;
    MOCTPM2_OBJECT_HANDLE *pAuthSession = NULL;
    FAPI2_OBJECT *pParentKeyObject = NULL;
    MOCTPM2_OBJECT_HANDLE *pParentKeyHandle = NULL;
    byteBoolean destroyParentKeyHandle = FALSE;
    byteBoolean flushObjectOnFailure = FALSE;
    ImportIn importIn = {0};
    ImportOut importOut = {0};
    UtilsCreateObjectIn createObjectIn = { 0 };
    UtilsCreateObjectOut createObjectOut = { 0 };
    ContextFlushObjectIn flushObjectIn = { 0 };
    ContextLoadObjectExIn loadIn = { 0 };
    ContextLoadObjectExOut loadOut = { 0 };
    PolicyAuthNode defaultPolicy = { 0 };
    FAPI2_DuplicateOut Fapi2_dupOut = {0};

    if (!pCtx || !pIn || !pOut)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }
    if ( (pIn->parentName.size != 0))
    {

        rc = FAPI2_CONTEXT_lookupObject(pCtx, &pIn->parentName, &pParentKeyObject);
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Unable to find parent loaded in the context. "
                    "rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        rc = FAPI2_UTILS_loadObjectTree(pCtx, pParentKeyObject, &pParentKeyHandle);
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed to create object for parent key."
                    ", rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        destroyParentKeyHandle = TRUE;
    }
    else
    {
        /*
         * Select SRK as default.
         */
        if (NULL == pCtx->primaryKeys.pSRK)
        {
            rc = TSS2_SYS_RC_BAD_CONTEXT;
            DB_PRINT("%s.%d No SRK found in FAPI Context"
                    ", TPM Unprovisioned or default SRK not found, "
                    "rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        pParentKeyObject = pCtx->primaryKeys.pSRK;
        pParentKeyHandle = pCtx->primaryKeys.pSRKHandle;
    }
    if ((pParentKeyObject->authValueRequired) && (!pParentKeyObject->authValueValid))
    {
        rc = TSS2_FAPI_RC_NOT_PERMITTED;
        DB_PRINT("%s.%d authValue not set for parent object."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }
    rc = FAPI2_UTILS_deserialize_Duplicate(pIn->pFapiDup, &Fapi2_dupOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to deserialize the FapiDuplicate structure."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }
    rc = FAPI2_UTILS_getObjectAuthSession(pCtx, pParentKeyObject, &pAuthSession);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to Start session."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }
    importIn.pParentHandle =  pParentKeyHandle;
    importIn.pDuplicate =     &Fapi2_dupOut.duplicate;
    importIn.pEncryptionKey = &Fapi2_dupOut.encryptionKeyOut;
    importIn.pInSymSeed =     &Fapi2_dupOut.outSymSeed;
    importIn.pObjectPublic =  &Fapi2_dupOut.objectPublic;
    importIn.pSymmetricAlg = &Fapi2_dupOut.symmetricAlg;
    importIn.pAuthSession = pAuthSession ;
    importIn.pAuthParentHandle = &(pParentKeyObject->authValue);
    rc = SAPI2_OBJECT_ImportDuplicateKey(pCtx->pSapiCtx, &importIn, &importOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to execute Import function"
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    defaultPolicy.policyType = FAPI2_POLICY_NO_DEFAULT;

    /*
     * Create FAPI2 Object representing the new non persistent key.
     */
    createObjectIn.tpm2Handle = 0;
    createObjectIn.pAuthValue = NULL;
    createObjectIn.pPrivate = &importOut.outPrivate;
    createObjectIn.pPublic = importIn.pObjectPublic;
    createObjectIn.pCreationData = NULL;
    createObjectIn.pCreationHash = NULL;
    createObjectIn.pCreationTicket = NULL;
    createObjectIn.parentHandle = pParentKeyHandle->tpm2Handle;
    createObjectIn.pParentName = &(pIn->parentName);
    createObjectIn.numPolicyTerms = 1;
    createObjectIn.pObjectPolicy = &defaultPolicy;

    rc = FAPI2_UTILS_createObject(pCtx, &createObjectIn, &createObjectOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to create FAPI object."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    loadIn.pObj = createObjectOut.pObject;
    /*
     * Must already be set during creation
     */
    loadIn.pAuthObj = NULL;
    rc = FAPI2_CONTEXT_loadObjectEx(pCtx, &loadIn, &loadOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to load object into context, "
                "rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    flushObjectOnFailure = TRUE;
    rc = FAPI2_UTILS_serialize(&createObjectOut.pObject, FALSE, &pOut->object);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to get serialized key, "
                "rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pOut->keyName = loadOut.objName;
    pOut->keyAlg = Fapi2_dupOut.objectPublic.publicArea.type;
    rc = TSS2_RC_SUCCESS;
exit:
    if (TSS2_RC_SUCCESS != rc)
    {
        if (flushObjectOnFailure)
        {
            flushObjectIn.objName = loadOut.objName;
            FAPI2_CONTEXT_flushObject(pCtx, &flushObjectIn);
        }
        else
        {
            if (createObjectOut.pObject)
            {
                FAPI2_UTILS_destroyObject(&createObjectOut.pObject);
            }
        }
    }
    if (pAuthSession)
    {
        exit_rc = FAPI2_UTILS_closeSession(pCtx, &pAuthSession);
        if (TSS2_RC_SUCCESS == rc)
            rc = exit_rc;
    }
    if (pParentKeyHandle && destroyParentKeyHandle)
    {
        exit_rc = FAPI2_UTILS_destroyHandle(pCtx, &pParentKeyHandle);
        if (TSS2_RC_SUCCESS == rc)
            rc = exit_rc;
    }

    if (TSS2_RC_SUCCESS == rc)
        rc = exit_rc;

    return rc; 
}
#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */
