/**
 * @file fapi2_utils.c
 * @brief This file contains utility functions to be used with FAPI
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

/*
 * This function protects the given data blob using the TPM. The
 * blob is encrypted and integrity protected by the TPM and can
 * only be unsealed/unprotected using the same authValue. With TPM2.0
 * sealing data is no more than creating an object with TPM2_Create.
 * The authValue of the SRK is expected to be set and correct in the
 * context as the sealed object will be created under the SRK.
 * DA Protection for the sealed object is disabled.
 */
TSS2_RC FAPI2_DATA_seal(FAPI2_CONTEXT *pCtx,
        DataSealIn *pIn,
        DataSealOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TSS2_RC exit_rc = TSS2_RC_SUCCESS;
    TSS2_RC exit_rc1 = TSS2_RC_SUCCESS;
    TSS2_RC exit_rc2 = TSS2_RC_SUCCESS;
    TSS2_RC exit_rc3 = TSS2_RC_SUCCESS;
    CreateIn createIn = { 0 };
    CreateOut createOut = { 0 };
    MOCTPM2_OBJECT_HANDLE *pAuthSession = NULL;
    TPM2B_DATA outsideInfo = { 0 };
    TPML_PCR_SELECTION pcrSelectionList = { 0 };
    TPM2B_PUBLIC inPublic = { 0 };
    TPM2B_SENSITIVE_CREATE sensitiveInfo = { 0 };
    UtilsCreateObjectIn createObjectIn = { 0 };
    UtilsCreateObjectOut createObjectOut = { 0 };
    FAPI2_OBJECT *pParentKeyObject = NULL;
    MOCTPM2_OBJECT_HANDLE *pParentKeyHandle = NULL;
    byteBoolean destroyParentKeyHandle = FALSE;
    ContextFlushObjectIn flushObjectIn = { 0 };
    PolicyAuthNode defaultPolicy = { 0 };
    PolicyAuthNode *pObjectPolicy = NULL;
    ubyte2 numPolicyTerms = 0;

    if (!pCtx || !pIn || !pOut)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    TPM2B_SIZE_CHECK(&pIn->authValue, pCtx->nameAlgSize);
    TPM2B_SIZE_CHECK(&pIn->dataToSeal, TPM2B_MAX_SIZE(&pIn->dataToSeal));

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

    rc = FAPI2_UTILS_getObjectAuthSession(pCtx, pParentKeyObject, &pAuthSession);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to Start session."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    inPublic.publicArea.type = TPM2_ALG_KEYEDHASH;
    inPublic.publicArea.nameAlg = pCtx->nameAlg;
    inPublic.publicArea.objectAttributes = TPMA_OBJECT_FIXEDTPM |
            TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_NODA;
    inPublic.publicArea.parameters.keyedHashDetail.scheme.scheme =
            TPM2_ALG_NULL;

    sensitiveInfo.sensitive.userAuth = pIn->authValue;
    sensitiveInfo.sensitive.data = pIn->dataToSeal;

    createIn.pParentHandle = pParentKeyHandle;
    createIn.pAuthParentHandle = &(pParentKeyObject->authValue);
    createIn.pAuthSession = pAuthSession;
    createIn.pCreationPCR = &pcrSelectionList;
    createIn.pOutsideInfo = &outsideInfo;
    createIn.pInPublic = &inPublic;
    createIn.pInSensitive = &sensitiveInfo;

    /*
     * Create the sealed data object
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
     * Create FAPI2 Object representing the sealed object.
     */
    createObjectIn.tpm2Handle = 0;
    createObjectIn.pAuthValue = &pIn->authValue;
    createObjectIn.pPrivate = &createOut.outPrivate;
    createObjectIn.pPublic = &createOut.outPublic;
    createObjectIn.pCreationData = &createOut.creationData;
    createObjectIn.pCreationHash = &createOut.creationHash;
    createObjectIn.pCreationTicket = &createOut.creationTicket;
    createObjectIn.parentHandle = pParentKeyObject->objectHandle;
    createObjectIn.pParentName = &(pParentKeyObject->objectName);
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

    rc = FAPI2_UTILS_serialize(&createObjectOut.pObject, TRUE,
            &pOut->sealedObject);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to serialize FAPI2 OBJECT."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    createObjectOut.pObject = NULL;

    rc = TSS2_RC_SUCCESS;
exit:
    if (pAuthSession)
        exit_rc1 = FAPI2_UTILS_closeSession(pCtx,
                &pAuthSession);

    /*
     * Destroy handle created for the parent object.
     */
    if (pParentKeyHandle && destroyParentKeyHandle)
        exit_rc2 = FAPI2_UTILS_destroyHandle(pCtx, &pParentKeyHandle);

    if (TSS2_RC_SUCCESS != rc)
    {
        if (createObjectOut.pObject)
        {
            exit_rc3 = FAPI2_UTILS_destroyObject(&createObjectOut.pObject);
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
 * This function unseals a sealed data blob from the TPM.
 */
TSS2_RC FAPI2_DATA_unseal(
        FAPI2_CONTEXT *pCtx,
        DataUnsealIn *pIn,
        DataUnsealOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TSS2_RC exit_rc = TSS2_RC_SUCCESS;
    MOCTPM2_OBJECT_HANDLE *pAuthSession = NULL;
    TPMT_PUBLIC *pPublic = NULL;
    UnsealIn unsealIn = { 0 };
    UnsealOut unsealOut = { 0 };
    MOCTPM2_OBJECT_HANDLE *pItemHandle = NULL;
    FAPI2_OBJECT *pObject = NULL;
    PolicyAuthNode defaultPolicy = { 0 };
    PolicyAuthNode *pObjectPolicy = NULL;
    ubyte2 numPolicyTerms = 0;

    if (!pCtx || !pIn || !pOut)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    TPM2B_SIZE_CHECK(&pIn->authValue, pCtx->nameAlgSize);
    TPM2B_SIZE_CHECK(&pIn->sealedObject, TPM2B_MAX_SIZE(&pIn->sealedObject));

    rc = FAPI2_UTILS_deserialize(&pIn->sealedObject, &pObject);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to deserialized sealed object, "
                "rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    rc = FAPI2_UTILS_setObjectAuth(pObject, &pIn->authValue);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to set authValue for object, "
                "rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pPublic = &pObject->public.objectPublic.publicArea;

    pPublic->type = TPM2_ALG_KEYEDHASH;
    pPublic->nameAlg = pCtx->nameAlg;
    pPublic->objectAttributes = TPMA_OBJECT_FIXEDTPM |
            TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_NODA;
    pPublic->parameters.keyedHashDetail.scheme.scheme =
            TPM2_ALG_NULL;
    /*
     * Create handle and get the object loaded into the TPM.
     */
    rc = FAPI2_UTILS_loadObjectTree(pCtx, pObject, &pItemHandle);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to create handle for sealed object."
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
    rc = FAPI2_UTILS_createPolicySessionAndExecutePolicy(
                pCtx,
                numPolicyTerms,
                pObjectPolicy,
                &(pPublic->authPolicy),
                 &pAuthSession
    );
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to start auth session, rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }


    unsealIn.pItemHandle = pItemHandle;
    unsealIn.pAuthItemHandle = &(pObject->authValue);
    unsealIn.pAuthSession = pAuthSession;

    rc = SAPI2_OBJECT_Unseal(pCtx->pSapiCtx, &unsealIn, &unsealOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to unseal object."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pOut->unsealedData = unsealOut.outData;
    rc = TSS2_RC_SUCCESS;
exit:
    if (pObject)
    {
        exit_rc = FAPI2_UTILS_destroyObject(&pObject);
        if (TSS2_RC_SUCCESS == rc)
            rc = exit_rc;
    }

    if (pAuthSession)
    {
        exit_rc = FAPI2_UTILS_closeSession(pCtx,
                &pAuthSession);
        if (TSS2_RC_SUCCESS == rc)
            rc = exit_rc;
    }

    if (pItemHandle)
        exit_rc = FAPI2_UTILS_destroyHandle(pCtx, &pItemHandle);

    if (TSS2_RC_SUCCESS == rc)
        rc = exit_rc;

    return rc;
}

/*
 * Digests arbitrary length buffers using the TPM and specified hash algorithm. Returns
 * the digest and validation ticket indicating if the digested buffer began with the
 * value TPM2_GENERATED_VALUE. This is useful while performing signatures with restricted
 * signing keys.
 */
TSS2_RC FAPI2_DATA_digestInternal(
        FAPI2_CONTEXT *pCtx,
        DataDigestInternalIn *pIn,
        DataDigestInternalOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TSS2_RC exit_rc = TSS2_RC_SUCCESS;
    RngGetRandomDataIn getRandomIn = { 0 };
    RngGetRandomDataOut sequenceAuth = { 0 };
    HashSequenceStartIn sequenceStartIn = { 0 };
    HashSequenceStartOut sequenceHandle = { 0 };
    SequenceUpdateIn sequenceUpdate = { 0 };
    SequenceCompleteIn sequenceCompleteIn = { 0 };
    SequenceCompleteOut sequenceCompleteOut = { 0 };
    ubyte4 remaining = 0;
    TPM2B_MAX_BUFFER *pMaxBuffer = NULL;
    ubyte *pInBuffer = NULL;
    MOCTPM2_OBJECT_HANDLE *pAuthSession = NULL;

    if (!pCtx || !pIn || !pOut || (!pIn->pBuffer))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (0 == pIn->bufferLen)
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid buffer lenght, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((pIn->hashAlg != TPM2_ALG_SHA256) && (pIn->hashAlg != TPM2_ALG_SHA384) &&
            (pIn->hashAlg != TPM2_ALG_SHA512))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid hash algorithm, rc 0x%02x = %s\n",
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

    getRandomIn.bytesRequested = 32;
    rc = FAPI2_RNG_getRandomData(pCtx, &getRandomIn, &sequenceAuth);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to get random data for sequence auth, rc 0x%02x = %s\n",
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

    sequenceStartIn.hashAlg = pIn->hashAlg;
    sequenceStartIn.pSequenceAuth = &sequenceAuth.randomBytes;
    rc = SAPI2_SEQUENCE_HashSequenceStart(pCtx->pSapiCtx, &sequenceStartIn, &sequenceHandle);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to start hash sequence, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    sequenceUpdate.pAuthSession = pAuthSession;
    sequenceUpdate.pMaxBuffer = pMaxBuffer;
    sequenceUpdate.pHashSequenceHandle = sequenceHandle.pHashSequenceHandle;
    sequenceUpdate.pSequenceAuth = &sequenceAuth.randomBytes;

    remaining = pIn->bufferLen;
    pInBuffer = pIn->pBuffer;

    while (remaining > TPM2_MAX_DIGEST_BUFFER)
    {
        pMaxBuffer->size = TPM2_MAX_DIGEST_BUFFER;

        DIGI_MEMCPY(pMaxBuffer->buffer, pInBuffer, pMaxBuffer->size);

        rc = SAPI2_SEQUENCE_SequenceUpdate(pCtx->pSapiCtx, &sequenceUpdate);
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed to update hash sequence, rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        remaining -= pMaxBuffer->size;
        pInBuffer += pMaxBuffer->size;
    }

    pMaxBuffer->size = remaining;
    DIGI_MEMCPY(pMaxBuffer->buffer, pInBuffer, pMaxBuffer->size);

    sequenceCompleteIn.hierarchy = pIn->ticketHierarchy;
    sequenceCompleteIn.pAuthSession = pAuthSession;
    sequenceCompleteIn.pSequenceAuth = &sequenceAuth.randomBytes;
    sequenceCompleteIn.ppHashSequenceHandle = &sequenceHandle.pHashSequenceHandle;
    sequenceCompleteIn.pMaxBuffer = pMaxBuffer;
    rc = SAPI2_SEQUENCE_SequenceComplete(pCtx->pSapiCtx, &sequenceCompleteIn, &sequenceCompleteOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to complete hash sequence, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    sequenceHandle.pHashSequenceHandle = NULL;

    pOut->digest = sequenceCompleteOut.result;
    pOut->validation = sequenceCompleteOut.validation;

    rc = TSS2_RC_SUCCESS;
exit:
    if (pMaxBuffer)
        shredMemory((ubyte **)(&pMaxBuffer), sizeof(*pMaxBuffer), TRUE);

    if (pAuthSession)
    {
        exit_rc = FAPI2_UTILS_closeSession(pCtx,
                &pAuthSession);
        if (TSS2_RC_SUCCESS == rc)
            rc = exit_rc;
    }

    if (sequenceHandle.pHashSequenceHandle)
        exit_rc = FAPI2_UTILS_destroyHandle(pCtx, &sequenceHandle.pHashSequenceHandle);

    if (TSS2_RC_SUCCESS == rc)
        rc = exit_rc;

    return rc;
}
/*
 * This function uses the TPM to digest a given data buffer using the specified
 * hash algorithm.
 */
TSS2_RC FAPI2_DATA_digest(
        FAPI2_CONTEXT *pCtx,
        DataDigestIn *pIn,
        DataDigestOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    DataDigestInternalIn digestIn = { 0 };
    DataDigestInternalOut digestOut = { 0 };

    if (!pCtx || !pIn || !pOut || (!pIn->pBuffer))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    digestIn.hashAlg = pIn->hashAlg;
    digestIn.bufferLen = pIn->bufferLen;
    digestIn.pBuffer = pIn->pBuffer;
    /*
     * Null hierarchy since we dont care about the ticket here.
     */
    digestIn.ticketHierarchy = TPM2_RH_NULL;

    rc = FAPI2_DATA_digestInternal(pCtx, &digestIn, &digestOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Invalid hash algorithm, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pOut->digest = digestOut.digest;

    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}
#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */
