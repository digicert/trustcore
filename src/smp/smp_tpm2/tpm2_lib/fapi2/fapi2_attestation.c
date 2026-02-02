/**
 * @file fapi2_credential.c
 * @brief This file contains code and structures required to implement the TPM2 privacy CA
 * credential activation protocol.
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

/*
 * This API can be used to get a PCR quote signed by the TPM. An Attestation key
 * must be provided to sign the quote structure. Typically, a nonce is provided
 * to this API to ensure freshness of the quote but any other qualifying data
 * may be used.
 */
TSS2_RC FAPI2_ATTESTATION_getQuote(
        FAPI2_CONTEXT *pCtx,
        AttestationGetQuoteIn *pIn,
        AttestationGetQuoteOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TSS2_RC exit_rc = TSS2_RC_SUCCESS;
    MgmtGetPcrSelectionIn getPcrSelectionIn = { 0 };
    MgmtGetPcrSelectionOut getPcrSelectionOut = { 0 };
    QuoteIn quoteIn = { 0 };
    QuoteOut quoteOut = { 0 };
    FAPI2_OBJECT *pKey = NULL;
    MOCTPM2_OBJECT_HANDLE *pKeyHandle = NULL;
    MOCTPM2_OBJECT_HANDLE *pAuthSession = NULL;
    TPMT_PUBLIC *pPublic = NULL;
    TPMT_SIG_SCHEME sigScheme = { 0 };
    TPML_PCR_SELECTION pcrSelectionList = { 0 };
    ContextFlushObjectIn flushObjectIn = { 0 };

    if (!pCtx || !pIn || !pOut)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    TPM2B_SIZE_CHECK(&pIn->quoteKey, TPM2B_MAX_SIZE(&pIn->quoteKey));
    TPM2B_SIZE_CHECK(&pIn->qualifyingData, TPM2B_MAX_SIZE(&pIn->qualifyingData));

    rc = FAPI2_CONTEXT_lookupObject(pCtx, &pIn->quoteKey, &pKey);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Unable to find quote key object, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((pKey->authValueRequired) && (!pKey->authValueValid))
    {
        rc = TSS2_FAPI_RC_NOT_PERMITTED;
        DB_PRINT("%s.%d Key does not have authValue set, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (pKey->isExternal)
    {
        rc = TSS2_FAPI_RC_NOT_PERMITTED;
        DB_PRINT("%s.%d External Keys cannot be used for quote, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pPublic = &pKey->public.objectPublic.publicArea;

    if ((pPublic->type != TPM2_ALG_RSA) && (pPublic->type != TPM2_ALG_ECC))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Key type not ECC or RSA., rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (!(pPublic->objectAttributes & TPMA_OBJECT_RESTRICTED) ||
            !(pPublic->objectAttributes & TPMA_OBJECT_SIGN_ENCRYPT))
    {
        rc = TSS2_FAPI_RC_NOT_PERMITTED;
        DB_PRINT("%s.%d Quote Key is not a restricted signing key, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /*
     * Validate the pcrSelection provided for creation data.
     * if a pcr that does not exist is selected, return an error.
     */

    getPcrSelectionIn.hashAlg = pCtx->nameAlg;
    rc = FAPI2_MGMT_getPCRSelection(pCtx, &getPcrSelectionIn,
            &getPcrSelectionOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to get TPM pcr infromation."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (pIn->pcrSelection & ~(getPcrSelectionOut.pcrSelection))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid pcr selection specified."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /*
     * The key must already have sigScheme set appropriately
     * during creation.
     */
    sigScheme.scheme = pKey->public.objectPublic.publicArea.parameters.asymDetail.scheme.scheme;
    sigScheme.details.any.hashAlg =
            pKey->public.objectPublic.publicArea.parameters.asymDetail.scheme.details.anySig.hashAlg;

    /*
     * For now we support only 1 PCR bank. Cannot see a use
     * for multiple for the forseeable future!
     */
    if (pIn->pcrSelection != 0)
    {
        pcrSelectionList.count = 1;
        pcrSelectionList.pcrSelections[0].hash = pCtx->nameAlg;
        pcrSelectionList.pcrSelections[0].sizeofSelect =
                getPcrSelectionOut.numBytesPcrSelection;
        DIGI_MEMCPY(pcrSelectionList.pcrSelections[0].pcrSelect,
                &pIn->pcrSelection,
                sizeof(pcrSelectionList.pcrSelections[0].pcrSelect));
    }

    /*
     * Create handle for the key. This will load the key into the TPM.
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

    quoteIn.pAuthSession = pAuthSession;
    quoteIn.pAuthSignHandle = &pKey->authValue;
    quoteIn.pQualifyingData = &pIn->qualifyingData;
    quoteIn.pScheme = &sigScheme;
    quoteIn.pSignHandle = pKeyHandle;
    quoteIn.pPcrSelection = &pcrSelectionList;

    rc = SAPI2_ATTESTATION_Quote(pCtx->pSapiCtx, &quoteIn, &quoteOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to get TPM quote."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (pPublic->type == TPM2_ALG_RSA)
    {
        pOut->keyAlg = TPM2_ALG_RSA;
        if (TPM2_ALG_RSAPSS == sigScheme.scheme)
            pOut->signature.rsaSignature =
                    quoteOut.signature.signature.rsapss.sig;

        if (TPM2_ALG_RSASSA == sigScheme.scheme)
            pOut->signature.rsaSignature =
                    quoteOut.signature.signature.rsassa.sig;
    }
    else if (pPublic->type == TPM2_ALG_ECC)
    {
        pOut->keyAlg = TPM2_ALG_ECC;
        if (TPM2_ALG_ECDSA == sigScheme.scheme)
        {
            pOut->signature.eccSignature.signatureR =
                    quoteOut.signature.signature.ecdsa.signatureR;
            pOut->signature.eccSignature.signatureS =
                    quoteOut.signature.signature.ecdsa.signatureS;
        }

        if (TPM2_ALG_ECSCHNORR == sigScheme.scheme)
        {
            pOut->signature.eccSignature.signatureR =
                    quoteOut.signature.signature.ecdsa.signatureR;
            pOut->signature.eccSignature.signatureS =
                    quoteOut.signature.signature.ecdsa.signatureS;
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

    pOut->quoted = quoteOut.quote;

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
#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */
