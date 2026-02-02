/**
 * @file fapi2_admin.c
 * @brief This file contains code and structures required for managing
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

/*
 * For RSA Keys, we currently support only 2048 and 3072 key bits.
 * Software should probably be using ECC if > 3072 bit keys are
 * required. Hash algorithm used to digest the message may be
 * SHA256, 384 or 512. The TPM2 may return an error since it may
 * not support SHA384 and SHA512. Key type must be one of the key
 * types defined in fapi2_asym.h. Exponent must be a prime greater
 * than 2 or 0. No validation is performed on exponent.
 */
static TSS2_RC FAPI2_ASYM_getRSATemplate(
        FAPI2_CONTEXT *pCtx,
        TPMT_PUBLIC *pRsaPublic,
        ubyte2 keySize,
        ubyte4 exponent,
        TPMI_ALG_HASH hashAlg,
        TPMI_ALG_RSA_SCHEME scheme,
        FAPI2_ASYM_TYPE keyType
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;

    if (!pRsaPublic || !pCtx)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((keySize != 2048) && (keySize != 3072) && (keySize != 4096))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d RSA key size must be 2048, 3072, or 4096 bits"
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((hashAlg != TPM2_ALG_SHA1) && 
            (hashAlg != TPM2_ALG_SHA256) && 
            (hashAlg != TPM2_ALG_SHA384) &&
            (hashAlg != TPM2_ALG_SHA512))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Hash algorithm must be SHA1, 256, 384 or 512"
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((keyType != FAPI2_ASYM_TYPE_SIGNING) &&
            (keyType != FAPI2_ASYM_TYPE_DECRYPT) &&
            (keyType != FAPI2_ASYM_TYPE_STORAGE) &&
            (keyType != FAPI2_ASYM_TYPE_ATTESTATION) &&
            (keyType != FAPI2_ASYM_TYPE_GENERAL))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid key usage selected"
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((scheme != TPM2_ALG_RSAPSS) &&
            (scheme != TPM2_ALG_RSASSA) &&
            (scheme != TPM2_ALG_RSAES) &&
            (scheme != TPM2_ALG_OAEP) &&
            (scheme != TPM2_ALG_NULL))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid scheme selected"
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (OK != DIGI_MEMSET((ubyte *)pRsaPublic, 0, sizeof(*pRsaPublic)))
    {
        DB_PRINT("%s.%d Failed memset"
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pRsaPublic->type = TPM2_ALG_RSA;
    pRsaPublic->nameAlg = pCtx->nameAlg;
    pRsaPublic->objectAttributes = TPMA_OBJECT_FIXEDTPM |
            TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN;
    pRsaPublic->parameters.rsaDetail.keyBits = keySize;
    pRsaPublic->parameters.rsaDetail.exponent = exponent;
    pRsaPublic->parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_NULL;
    pRsaPublic->parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;

    switch (keyType)
    {
    case FAPI2_ASYM_TYPE_SIGNING:
        if ((scheme != TPM2_ALG_RSAPSS) &&
                (scheme != TPM2_ALG_RSASSA) &&
                (scheme != TPM2_ALG_NULL))
        {
            rc = TSS2_SYS_RC_BAD_VALUE;
            DB_PRINT("%s.%d Invalid scheme selected for signing key"
                    ", rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
        pRsaPublic->objectAttributes |= TPMA_OBJECT_SIGN_ENCRYPT;
        pRsaPublic->parameters.rsaDetail.scheme.scheme = scheme;
        if (scheme == TPM2_ALG_RSAPSS)
            pRsaPublic->parameters.rsaDetail.scheme.details.rsapss.hashAlg =
                    hashAlg;
        if (scheme == TPM2_ALG_RSASSA)
            pRsaPublic->parameters.rsaDetail.scheme.details.rsassa.hashAlg =
                    hashAlg;
        break;
    case FAPI2_ASYM_TYPE_DECRYPT:
        if ((scheme != TPM2_ALG_RSAES) &&
                (scheme != TPM2_ALG_OAEP) &&
                (scheme != TPM2_ALG_NULL))
        {
            rc = TSS2_SYS_RC_BAD_VALUE;
            DB_PRINT("%s.%d Invalid scheme selected for decryption key"
                    ", rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
        pRsaPublic->objectAttributes |= TPMA_OBJECT_DECRYPT;
        pRsaPublic->parameters.rsaDetail.scheme.scheme = scheme;
        if (scheme == TPM2_ALG_OAEP)
            pRsaPublic->parameters.rsaDetail.scheme.details.oaep.hashAlg =
                    hashAlg;
        break;
    case FAPI2_ASYM_TYPE_STORAGE:
        pRsaPublic->objectAttributes |= TPMA_OBJECT_RESTRICTED;
        pRsaPublic->objectAttributes |= TPMA_OBJECT_DECRYPT;
        pRsaPublic->parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_AES;
        pRsaPublic->parameters.rsaDetail.symmetric.mode.aes = TPM2_ALG_CFB;
        pRsaPublic->parameters.rsaDetail.symmetric.keyBits.aes = 128;
        /*
         * See key pairing in 11.4.6 symmetric encryption
         * part 1, TPM library specification.
         */
        if (keySize > 2048)
            pRsaPublic->parameters.rsaDetail.symmetric.keyBits.aes = 256;
        break;
    case FAPI2_ASYM_TYPE_ATTESTATION:
        if ((scheme != TPM2_ALG_RSAPSS) &&
                (scheme != TPM2_ALG_RSASSA))
        {
            rc = TSS2_SYS_RC_BAD_VALUE;
            DB_PRINT("%s.%d Invalid scheme selected for restricted signing key"
                    ", rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
        pRsaPublic->objectAttributes |= TPMA_OBJECT_RESTRICTED;
        pRsaPublic->objectAttributes |= TPMA_OBJECT_SIGN_ENCRYPT;
        pRsaPublic->parameters.rsaDetail.scheme.scheme = scheme;
        if (scheme == TPM2_ALG_RSAPSS)
            pRsaPublic->parameters.rsaDetail.scheme.details.rsapss.hashAlg =
                    hashAlg;
        if (scheme == TPM2_ALG_RSASSA)
            pRsaPublic->parameters.rsaDetail.scheme.details.rsassa.hashAlg =
                    hashAlg;
        break;
    case FAPI2_ASYM_TYPE_GENERAL:
        pRsaPublic->objectAttributes |= TPMA_OBJECT_SIGN_ENCRYPT;
        pRsaPublic->objectAttributes |= TPMA_OBJECT_DECRYPT;
        break;
    default:
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid RSA key type"
                    ", rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
    }

    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}

/*
 * For ECC Keys, we currently support NIST curves from P192
 * to P521. BN curves for ECDAA are not implemented by nanoCRYPTO
 * and have been omitted here.
 * Hash algorithm used to digest the message may be
 * SHA256, 384 or 512. The TPM2 may return an error since it may
 * not support SHA384 and SHA512. Key type must be on of the key
 * types defined in fapi2_asym.h.
 */
static TSS2_RC FAPI2_ASYM_getECCTemplate(
        FAPI2_CONTEXT *pCtx,
        TPMT_PUBLIC *pECCPublic,
        TPMI_ECC_CURVE curveID,
        TPMI_ALG_ECC_SCHEME scheme,
        FAPI2_ASYM_TYPE keyType
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TPMI_ALG_HASH hashAlg = TPM2_ALG_NULL;

    if (!pECCPublic || !pCtx)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((curveID != TPM2_ECC_NIST_P192) &&
            (curveID != TPM2_ECC_NIST_P224) &&
            (curveID != TPM2_ECC_NIST_P256) &&
            (curveID != TPM2_ECC_NIST_P384) &&
            (curveID != TPM2_ECC_NIST_P521))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid/unsupported curve selected"
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /*
     * Automatically select sensible scheme hashAlg based on the curve.
     */
    if ((curveID == TPM2_ECC_NIST_P192) || (curveID == TPM2_ECC_NIST_P224)
            || (curveID == TPM2_ECC_NIST_P256))
        hashAlg = TPM2_ALG_SHA256;

    if (curveID == TPM2_ECC_NIST_P384)
        hashAlg = TPM2_ALG_SHA384;

    if (curveID == TPM2_ECC_NIST_P521)
        hashAlg = TPM2_ALG_SHA512;

    if ((keyType != FAPI2_ASYM_TYPE_SIGNING) &&
            (keyType != FAPI2_ASYM_TYPE_DECRYPT) &&
            (keyType != FAPI2_ASYM_TYPE_STORAGE) &&
            (keyType != FAPI2_ASYM_TYPE_ATTESTATION) &&
            (keyType != FAPI2_ASYM_TYPE_GENERAL))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid key usage selected"
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((scheme != TPM2_ALG_ECDSA) &&
            (scheme != TPM2_ALG_ECSCHNORR) &&
            (scheme != TPM2_ALG_ECDH) &&
            (scheme != TPM2_ALG_NULL))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid scheme selected"
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (OK != DIGI_MEMSET((ubyte *)pECCPublic, 0, sizeof(*pECCPublic)))
    {
        DB_PRINT("%s.%d Failed memset"
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pECCPublic->type = TPM2_ALG_ECC;
    pECCPublic->nameAlg = pCtx->nameAlg;
    pECCPublic->objectAttributes = TPMA_OBJECT_FIXEDTPM |
            TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN;
    pECCPublic->parameters.eccDetail.kdf.scheme = TPM2_ALG_NULL;
    pECCPublic->parameters.eccDetail.curveID = curveID;
    pECCPublic->parameters.eccDetail.symmetric.algorithm = TPM2_ALG_NULL;
    pECCPublic->parameters.eccDetail.scheme.scheme = TPM2_ALG_NULL;

    switch (keyType)
    {
    case FAPI2_ASYM_TYPE_SIGNING:
        if ((scheme != TPM2_ALG_ECDSA) &&
                (scheme != TPM2_ALG_ECSCHNORR) &&
                (scheme != TPM2_ALG_NULL))
        {
            rc = TSS2_SYS_RC_BAD_VALUE;
            DB_PRINT("%s.%d Invalid scheme selected for signing key"
                    ", rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
        pECCPublic->objectAttributes |= TPMA_OBJECT_SIGN_ENCRYPT;
        pECCPublic->parameters.eccDetail.scheme.scheme = scheme;
        if (scheme == TPM2_ALG_ECDSA)
            pECCPublic->parameters.eccDetail.scheme.details.ecdsa.hashAlg =
                    hashAlg;
        if (scheme == TPM2_ALG_ECSCHNORR)
            pECCPublic->parameters.eccDetail.scheme.details.ecSchnorr.hashAlg =
                    hashAlg;
        break;
    case FAPI2_ASYM_TYPE_DECRYPT:
        if ((scheme != TPM2_ALG_ECDH) &&
                (scheme != TPM2_ALG_NULL))
        {
            rc = TSS2_SYS_RC_BAD_VALUE;
            DB_PRINT("%s.%d Invalid scheme selected for decryption key"
                    ", rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
        pECCPublic->objectAttributes |= TPMA_OBJECT_DECRYPT;
        pECCPublic->parameters.eccDetail.scheme.scheme = scheme;
        if (scheme == TPM2_ALG_ECDH)
            pECCPublic->parameters.eccDetail.scheme.details.ecdh.hashAlg =
                    hashAlg;
        break;
    case FAPI2_ASYM_TYPE_STORAGE:
        pECCPublic->objectAttributes |= TPMA_OBJECT_RESTRICTED;
        pECCPublic->objectAttributes |= TPMA_OBJECT_DECRYPT;
        pECCPublic->parameters.eccDetail.symmetric.algorithm = TPM2_ALG_AES;
        pECCPublic->parameters.eccDetail.symmetric.mode.aes = TPM2_ALG_CFB;
        pECCPublic->parameters.eccDetail.symmetric.keyBits.aes = 128;
        /*
         * See key pairing in 11.4.6 symmetric encryption
         * part 1, TPM library specification.
         */
        if (curveID > TPM2_ECC_NIST_P256)
            pECCPublic->parameters.eccDetail.symmetric.keyBits.aes = 256;
        break;
    case FAPI2_ASYM_TYPE_ATTESTATION:
        if ((scheme != TPM2_ALG_ECDSA) &&
                (scheme != TPM2_ALG_ECSCHNORR))
        {
            rc = TSS2_SYS_RC_BAD_VALUE;
            DB_PRINT("%s.%d Invalid scheme selected for signing key"
                    ", rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
        pECCPublic->objectAttributes |= TPMA_OBJECT_RESTRICTED;
        pECCPublic->objectAttributes |= TPMA_OBJECT_SIGN_ENCRYPT;
        pECCPublic->parameters.eccDetail.scheme.scheme = scheme;
        if (scheme == TPM2_ALG_ECDSA)
            pECCPublic->parameters.eccDetail.scheme.details.ecdsa.hashAlg =
                    hashAlg;
        if (scheme == TPM2_ALG_ECSCHNORR)
            pECCPublic->parameters.eccDetail.scheme.details.ecSchnorr.hashAlg =
                    hashAlg;
        break;
    case FAPI2_ASYM_TYPE_GENERAL:
        pECCPublic->objectAttributes |= TPMA_OBJECT_SIGN_ENCRYPT;
        pECCPublic->objectAttributes |= TPMA_OBJECT_DECRYPT;
        break;
    default:
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid RSA key type"
                    ", rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
    }

    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}

/*
 * This is an advanced API, that must only be used when the application
 * writer knows exactly what is being done. This API provides lots of
 * flexibility to be able to create any supported asymmetric key under
 * the endorsement or storage hierarchy.
 * The API expects the hierarchy authValues to be set in the FAPI2_CONTEXT.
 * It is recommended to use the FAPI2_ADMIN_* API's for provisioning the
 * TPM that uses this API with the most commonly used parameters.
 */
TSS2_RC FAPI2_ASYM_createPrimaryAsymKey(
        FAPI2_CONTEXT *pCtx,
        TPM2B_AUTH *pPlatformAuth,
        AsymCreatePrimaryKeyIn *pIn,
        AsymCreatePrimaryKeyOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TSS2_RC exit_rc = TSS2_RC_SUCCESS;
    TPM2B_PUBLIC inPublic = { 0 };
    CreatePrimaryIn createPrimaryIn = { 0 };
    CreatePrimaryOut createPrimaryOut = { 0 };
    EvictControlIn evictControlIn = { 0 };
    EvictControlOut evictControlOut = { 0 };
    MgmtGetPcrSelectionIn getPcrSelectionIn = { 0 };
    MgmtGetPcrSelectionOut getPcrSelectionOut = { 0 };
    MOCTPM2_OBJECT_HANDLE *pAuthSession = { 0 };
    TPM2B_SENSITIVE_CREATE sensitiveInfo = { 0 };
    TPM2B_AUTH emptyAuth = { 0 };
    TPM2B_AUTH *pHierarchyAuth = &emptyAuth;
    UtilsCreateObjectIn createObjectIn = { 0 };
    UtilsCreateObjectOut createObjectOut = { 0 };
    TPML_PCR_SELECTION pcrSelectionList = { 0 };
    PolicyAuthNode defaultPolicy = { 0 };
    PolicyAuthNode *pObjectPolicy = NULL;
    ubyte2 numPolicyTerms = 0;

    if (!pCtx || !pIn || !pOut || !pIn->pNewKeyAuth || !pIn->pOutsideInfo)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    TPM2B_SIZE_CHECK(pIn->pNewKeyAuth, pCtx->nameAlgSize);
    TPM2B_SIZE_CHECK(pIn->pOutsideInfo, TPM2B_MAX_SIZE(pIn->pOutsideInfo));

    if (pOut->pKey != NULL)
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d pKey has a value. This must be NULL, possible memory leak"
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((pIn->hierarchy != TPM2_RH_OWNER) &&
        (pIn->hierarchy != TPM2_RH_ENDORSEMENT) &&
        (pIn->hierarchy != TPM2_RH_NULL) &&
        (pIn->hierarchy != TPM2_RH_PLATFORM))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid hierarchy specified."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /*
     * Require ownerAuth for evictControl.
     */
    if (!pCtx->authValues.ownerAuthValid)
    {
        rc = TSS2_SYS_RC_NOT_PERMITTED;
        DB_PRINT("%s.%d Invalid authValue for owner hierarchy."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((pIn->keyAlg != TPM2_ALG_RSA) && (pIn->keyAlg != TPM2_ALG_ECC))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid key algorithm specified."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((pIn->persistentHandle < TPM2_PERSISTENT_FIRST) ||
            ((pIn->persistentHandle > TPM2_PERSISTENT_LAST)))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid persistent handle specified."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

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

    /*
     * Validate the pcrSelection provided for creation data.
     * if a pcr that does not exist is selected, return an error.
     */

    if (pIn->pcrSelection & ~(getPcrSelectionOut.pcrSelection))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid pcr selection specified."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /*
     * Set authValue based on hierarchy under which the object is being
     * created. For the NULL hierarchy, there is no password.
     */


    if (pIn->hierarchy == TPM2_RH_OWNER)
    {
        if ((pIn->persistentHandle < FAPI2_RH_PERSISTENT_OWNER_START) ||
                (pIn->persistentHandle > FAPI2_RH_PERSISTENT_OWNER_END))
        {
            rc = TSS2_SYS_RC_BAD_VALUE;
            DB_PRINT("%s.%d Invalid persistent handle specified under owner hierarchy."
                    ", rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        pHierarchyAuth = &(pCtx->authValues.ownerAuth);


    }
    else if (pIn->hierarchy == TPM2_RH_ENDORSEMENT)
    {
        if (pCtx->authValues.endorsementAuthValid)
        {
            pHierarchyAuth = &(pCtx->authValues.endorsementAuth);
        }
        else
        {
            rc = TSS2_SYS_RC_NOT_PERMITTED;
            DB_PRINT("%s.%d Invalid authValue for endorsement hierarchy."
                    ", rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

    }
    else if (pIn->hierarchy == TPM2_RH_PLATFORM)
    {
        pHierarchyAuth = pPlatformAuth;
    }

    /*
     * keyInfo is validated when TPMT_PUBLIC is being created by the
     * helper functions
     */
    if (pIn->keyAlg == TPM2_ALG_RSA)
    {
        rc = FAPI2_ASYM_getRSATemplate(pCtx, &inPublic.publicArea,
                pIn->keyInfo.rsaInfo.keySize,
                pIn->keyInfo.rsaInfo.exponent,
                pIn->keyInfo.rsaInfo.hashAlg,
                pIn->keyInfo.rsaInfo.scheme,
                pIn->keyInfo.rsaInfo.keyType);

        inPublic.publicArea.unique.rsa = pIn->externalEntryopy.rsaEntropy;
    }
    else if (pIn->keyAlg == TPM2_ALG_ECC)
    {
        rc = FAPI2_ASYM_getECCTemplate(pCtx, &inPublic.publicArea,
                pIn->keyInfo.eccInfo.curveID,
                pIn->keyInfo.eccInfo.scheme,
                pIn->keyInfo.eccInfo.keyType);

        inPublic.publicArea.unique.ecc = pIn->externalEntryopy.eccEntropy;
    }

    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to get asymmetric key template."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (pIn->disableDA)
        inPublic.publicArea.objectAttributes |= TPMA_OBJECT_NODA;

    inPublic.publicArea.objectAttributes |= pIn->additionalAttributes;

    /*
     * Start regular session. For now, we dont support policy for hierarchy seeds.
     */
    rc = FAPI2_UTILS_startSession(pCtx, &pAuthSession);
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
    else if ((FAPI2_RH_EK == pIn->persistentHandle) || (FAPI2_RH_SRK == pIn->persistentHandle))
    {
        numPolicyTerms = 1;
        defaultPolicy.policyType = FAPI2_POLICY_AUTH_VALUE;
        pObjectPolicy = &defaultPolicy;
    }

    if (0 < numPolicyTerms)
    {
        rc = FAPI2_UTILS_fillPolicyDigest(pCtx, numPolicyTerms, pObjectPolicy,
                &inPublic.publicArea.authPolicy);
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed to get policy digest."
                    ", rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
    }

    /*
     * Size will be backfilled by serialization for TPM2B's that encapsulate
     * a structure.
     */
    sensitiveInfo.sensitive.userAuth = *(pIn->pNewKeyAuth);
    sensitiveInfo.size = sensitiveInfo.sensitive.userAuth.size + sensitiveInfo.sensitive.data.size;
 
    createPrimaryIn.primaryHandle = pIn->hierarchy;
    createPrimaryIn.pInSensitive = &sensitiveInfo;
    createPrimaryIn.pInPublic = &inPublic;
    createPrimaryIn.pOutsideInfo = pIn->pOutsideInfo;
    createPrimaryIn.pCreationPCR = &pcrSelectionList;
    /*
     * For now we support only 1 PCR bank. Cannot see a use
     * for multiple for the forseeable future!
     */
    if (pIn->pcrSelection != 0)
    {
        createPrimaryIn.pCreationPCR->count = 1;
        createPrimaryIn.pCreationPCR->pcrSelections[0].hash = pCtx->nameAlg;
        createPrimaryIn.pCreationPCR->pcrSelections[0].sizeofSelect =
                getPcrSelectionOut.numBytesPcrSelection;
        DIGI_MEMCPY(createPrimaryIn.pCreationPCR->pcrSelections[0].pcrSelect,
                &pIn->pcrSelection,
                sizeof(createPrimaryIn.pCreationPCR->pcrSelections[0].pcrSelect));
    }
    createPrimaryIn.pAuthPrimaryHandle = pHierarchyAuth;
    createPrimaryIn.pAuthSession = pAuthSession;

    /*
     * Create the object!
     */
    rc = SAPI2_HIERARCHY_CreatePrimary(
            pCtx->pSapiCtx,
            &createPrimaryIn,
            &createPrimaryOut
    );
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to Create primary key."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /*
     * Make the primary object persistent. All primary objects will be
     * made persistent unconditionally. Since this requires hierarchy
     * authValues, this is expected to be performed only by admins.
     */
    if (TPM2_RH_PLATFORM == pIn->hierarchy)
        evictControlIn.authHandle = TPM2_RH_PLATFORM;
    else
        evictControlIn.authHandle = TPM2_RH_OWNER;
    evictControlIn.pObjectHandle = createPrimaryOut.pObjectHandle;
    evictControlIn.persistentHandle = pIn->persistentHandle;
    if (TPM2_RH_PLATFORM == pIn->hierarchy)
        evictControlIn.pAuthAuthHandle = pPlatformAuth;
    else
        evictControlIn.pAuthAuthHandle = &pCtx->authValues.ownerAuth;
    evictControlIn.pAuthSession = pAuthSession;

    rc = SAPI2_CTX_MGMT_EvictControl(pCtx->pSapiCtx,
            &evictControlIn, &evictControlOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to make primary key persistent."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /*
     * Create FAPI2 Object representing the primary object.
     */
    createObjectIn.tpm2Handle = pIn->persistentHandle;
    createObjectIn.pAuthValue = pIn->pNewKeyAuth;
    createObjectIn.pPrivate = NULL;
    createObjectIn.pPublic = &createPrimaryOut.outPublic;
    createObjectIn.pCreationData = &createPrimaryOut.creationData;
    createObjectIn.pCreationHash = &createPrimaryOut.creationHash;
    createObjectIn.pCreationTicket = &createPrimaryOut.creationTicket;
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

    pOut->pKey = createObjectOut.pObject;

    rc = TSS2_RC_SUCCESS;

exit:

    /*
     * Flush the transient object and destroy the handle created by
     * SAPI2_HIERARCHY_CreatePrimary(). Note, SAPI2_CTX_MGMT_EvictControl
     * returns a new handle to the persistent object and at this point
     * there are 2 copies of the key, one at the transient handle and
     * one at the persistent handle. Here, we remove the transient handle.
     */
    if (createPrimaryOut.pObjectHandle)
    {
        exit_rc = FAPI2_UTILS_destroyHandle(pCtx, &createPrimaryOut.pObjectHandle);
        if (TSS2_RC_SUCCESS != exit_rc)
        {
            DB_PRINT("%s.%d Failed to flush transient key object."
                    ", rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, exit_rc, tss2_err_string(exit_rc));
            if (TSS2_RC_SUCCESS == rc)
                rc = exit_rc;
        }
    }

    /*
     * Destroy handle to persistent object. Persistent object will still
     * remain in TPM memory.
     */
    if (evictControlOut.pPersistentHandle)
    {
        exit_rc = FAPI2_UTILS_destroyHandle(pCtx, &evictControlOut.pPersistentHandle);
        if (TSS2_RC_SUCCESS != exit_rc)
        {
            DB_PRINT("%s.%d Failed to destroy persistent key handle."
                    ", rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, exit_rc, tss2_err_string(exit_rc));
            if (TSS2_RC_SUCCESS == rc)
                rc = exit_rc;
        }
    }

    if (pAuthSession)
        exit_rc = FAPI2_UTILS_closeSession(pCtx,
                &pAuthSession);

    if (TSS2_RC_SUCCESS == rc)
        rc = exit_rc;

    return rc;
}

/*
 * This is an advanced API, that must only be used when the application
 * writer knows exactly what is being done. This API provides lots of
 * flexibility to be able to create any supported asymmetric key under
 * ANY primary key in the endorsement or storage hierarchy.
 * It is recommended to use the FAPI2_ASYM_createAsymKey API's for key creation since
 * they use the most commonly used parameters.
 * This API creates an asymmetric key under the parent handle specified
 * and returns the key object.
 */
TSS2_RC FAPI2_ASYM_createChildAsymKey(
        FAPI2_CONTEXT *pCtx,
        AsymCreateChildKeyIn *pIn,
        AsymCreateChildKeyOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TSS2_RC exit_rc = TSS2_RC_SUCCESS;
    MOCTPM2_OBJECT_HANDLE *pAuthSession = { 0 };
    MOCTPM2_OBJECT_HANDLE *pObjAuthSession = { 0 };
    MOCTPM2_OBJECT_HANDLE *pParentHandle = NULL;
    MgmtGetPcrSelectionIn getPcrSelectionIn = { 0 };
    MgmtGetPcrSelectionOut getPcrSelectionOut = { 0 };
    TPM2B_PUBLIC inPublic = { 0 };
    TPM2B_SENSITIVE_CREATE sensitiveInfo = { 0 };
    UtilsCreateObjectIn createObjectIn = { 0 };
    UtilsCreateObjectOut createObjectOut = { 0 };
    CreateIn createIn = { 0 };
    CreateOut createOut = { 0 };
    TPML_PCR_SELECTION pcrSelectionList = { 0 };
    byteBoolean destroyParentHandle = FALSE;
    PolicyAuthNode defaultPolicy = { 0 };
    PolicyAuthNode dupPolicy = { 0 };
    PolicyAuthNode *pObjectPolicy = NULL;
    ubyte2 numPolicyTerms = 0;
    EaExecutePolicyIn eaExecutePolicyIn = { 0 };
    EaExecutePolicyOut eaExecutePolicyOut = { 0 };

    if (!pCtx || !pIn || !pOut ||
            (!pIn->pNewKeyAuth) ||(!pIn->pOutsideInfo) ||
            (NULL != pOut->pKey) || (!pIn->pParentKey))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((pIn->pParentKey->authValueRequired) && (!pIn->pParentKey->authValueValid))
    {
        rc = TSS2_FAPI_RC_NOT_PERMITTED;
        DB_PRINT("%s.%d authValue not set for parent object."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    TPM2B_SIZE_CHECK(pIn->pNewKeyAuth, pCtx->nameAlgSize);
    TPM2B_SIZE_CHECK(pIn->pOutsideInfo, TPM2B_MAX_SIZE(pIn->pOutsideInfo));

    /*
     * If the parent key is a primary/persistent key:
     * Check parent handle is in the range 0x81000000 - 0x8100FFFF
     * or is in the range 0x81010000 - 0x8101FFFF. It is an error
     * if parent Handle is not in those ranges.
     * Checks on non persistent parents will be done by FAPI2_UTILS_loadObjectTree().
     *
     * Persistent key range can change depending on what version of specs the
     * TPM2 is implemented for. Cannot enforce range check here.
     */

    if ((pIn->keyAlg != TPM2_ALG_RSA) && (pIn->keyAlg != TPM2_ALG_ECC))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid key algorithm specified."
                ", rc 0x%02x = %s\n",
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

    rc = TSS2_SYS_RC_BAD_VALUE;
    /*
     * keyInfo is validated when TPMT_PUBLIC is being created by the
     * helper functions
     */
    if (pIn->keyAlg == TPM2_ALG_RSA)
    {
        rc = FAPI2_ASYM_getRSATemplate(pCtx, &inPublic.publicArea,
                pIn->keyInfo.rsaInfo.keySize,
                pIn->keyInfo.rsaInfo.exponent,
                pIn->keyInfo.rsaInfo.hashAlg,
                pIn->keyInfo.rsaInfo.scheme,
                pIn->keyInfo.rsaInfo.keyType);
    }
    else if (pIn->keyAlg == TPM2_ALG_ECC)
    {
        rc = FAPI2_ASYM_getECCTemplate(pCtx, &inPublic.publicArea,
                pIn->keyInfo.eccInfo.curveID,
                pIn->keyInfo.eccInfo.scheme,
                pIn->keyInfo.eccInfo.keyType);
    }

    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to get asymmetric key template."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (pIn->disableDA)
        inPublic.publicArea.objectAttributes |= TPMA_OBJECT_NODA;

    inPublic.publicArea.objectAttributes |= (TPMA_OBJECT_USERWITHAUTH |
                TPMA_OBJECT_ADMINWITHPOLICY);

    /* Permit Attestation keys to execute the Activate command with Admin Role
       by not enforcing ADMINWITHPOLICY attribute, thus enabling use of regular
       HMAC session
       */
    if ( ((pIn->keyAlg == TPM2_ALG_RSA) && 
            (FAPI2_ASYM_TYPE_ATTESTATION == pIn->keyInfo.rsaInfo.keyType))
        ||
            ((pIn->keyAlg == TPM2_ALG_ECC) && 
             (FAPI2_ASYM_TYPE_ATTESTATION == pIn->keyInfo.eccInfo.keyType))) 
    {
        inPublic.publicArea.objectAttributes &= ~(TPMA_OBJECT_ADMINWITHPOLICY);
    }

    if(pIn->bEnableBackup)
    {
        inPublic.publicArea.objectAttributes &= ~(TPMA_OBJECT_FIXEDTPM |
                TPMA_OBJECT_FIXEDPARENT);
    }

    /*
     * Create MOCTPM2_OBJECT_HANDLE for the parent key if it is
     * not the SRK or EK from the context. This is an optimization.
     */
    if ((pIn->pParentKey != pCtx->primaryKeys.pEK) &&
            (pIn->pParentKey != pCtx->primaryKeys.pSRK))
    {
        rc = FAPI2_UTILS_loadObjectTree(pCtx, pIn->pParentKey, &pParentHandle);
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed to create object for primary key."
                    ", rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        /*
         * We need to destroy the parent handle since we created it here.
         * For SRK and EK, since we used cached values from the context,
         * we dont destroy them.
         */
        destroyParentHandle = TRUE;
    }
    else
    {
        if (pIn->pParentKey == pCtx->primaryKeys.pEK)
            pParentHandle = pCtx->primaryKeys.pEKHandle;

        if (pIn->pParentKey == pCtx->primaryKeys.pSRK)
            pParentHandle = pCtx->primaryKeys.pSRKHandle;
    }

    rc = FAPI2_UTILS_getObjectAuthSession(pCtx, pIn->pParentKey, &pAuthSession);
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
    if(pIn->bEnableBackup) 
    {
        dupPolicy.policyInfo.policyCC.code = TPM2_CC_Duplicate ;
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
    sensitiveInfo.sensitive.userAuth = *(pIn->pNewKeyAuth);

    createIn.pParentHandle = pParentHandle;
    createIn.pInSensitive = &sensitiveInfo;
    createIn.pInPublic = &inPublic;
    createIn.pOutsideInfo = pIn->pOutsideInfo;
    createIn.pCreationPCR = &pcrSelectionList;

    /*
     * For now we support only 1 PCR bank. Cannot see a use
     * for multiple for the forseeable future!
     */
    if (pIn->pcrSelection != 0)
    {
        createIn.pCreationPCR->count = 1;
        createIn.pCreationPCR->pcrSelections[0].hash = pCtx->nameAlg;
        createIn.pCreationPCR->pcrSelections[0].sizeofSelect =
                getPcrSelectionOut.numBytesPcrSelection;
        DIGI_MEMCPY(createIn.pCreationPCR->pcrSelections[0].pcrSelect,
                &pIn->pcrSelection,
                sizeof(createIn.pCreationPCR->pcrSelections[0].pcrSelect));
    }

    createIn.pAuthParentHandle = &pIn->pParentKey->authValue;
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
    createObjectIn.pAuthValue = pIn->pNewKeyAuth;
    createObjectIn.pPrivate = &createOut.outPrivate;
    createObjectIn.pPublic = &createOut.outPublic;
    createObjectIn.pCreationData = &createOut.creationData;
    createObjectIn.pCreationHash = &createOut.creationHash;
    createObjectIn.pCreationTicket = &createOut.creationTicket;
    createObjectIn.parentHandle = pIn->pParentKey->objectHandle;
    createObjectIn.pParentName = &(pIn->pParentKey->objectName);
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

    pOut->pKey = createObjectOut.pObject;

    rc = TSS2_RC_SUCCESS;
exit:
    if (pAuthSession)
    {
        exit_rc = FAPI2_UTILS_closeSession(pCtx,
                &pAuthSession);
        if (TSS2_RC_SUCCESS == rc)
            rc = exit_rc;
    }
    if (pObjAuthSession)
    {
        exit_rc = FAPI2_UTILS_closeSession(pCtx,
                &pObjAuthSession);
        if (TSS2_RC_SUCCESS == rc)
            rc = exit_rc;
    }

    /*
     * Destroy handle created for the parent object.
     */
    if (pParentHandle && destroyParentHandle)
        exit_rc = FAPI2_UTILS_destroyHandle(pCtx, &pParentHandle);

    if (TSS2_RC_SUCCESS == rc)
        rc = exit_rc;

    return rc;
}


/*
 * This function creates an asymmetric key as specified by the input parameters
 * and returns a key object that can be used immediately or stored for future
 * usage.
 * The key is created under the storage root key, and the application is
 * expected to have set the password for the SRK in the context,
 * if it is not the well known password.
 */
TSS2_RC FAPI2_ASYM_createAsymKey(
        FAPI2_CONTEXT *pCtx,
        AsymCreateKeyIn *pIn,
        AsymCreateKeyOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TSS2_RC exit_rc = TSS2_RC_SUCCESS;
    AsymCreateChildKeyIn asymKeyIn = { 0 };
    AsymCreateChildKeyOut asymKeyOut = { 0 };
    TPM2B_DATA outsideInfo = { 0 };
    ContextLoadObjectExIn loadIn = { 0 };
    ContextLoadObjectExOut loadOut = { 0 };
    AsymGetPublicKeyIn pubKeyIn = { 0 };
    AsymGetPublicKeyOut pubKeyOut = { 0 };
    FAPI2_OBJECT *pParentKeyObject = NULL;
    ContextFlushObjectIn flushObjectIn = { 0 };
    byteBoolean flushObjectOnFailure = FALSE;
    EvictControlIn evictControlIn = { 0 };
    EvictControlOut evictControlOut = { 0 };
    MOCTPM2_OBJECT_HANDLE *pAuthSession = { 0 };

    if (!pCtx || !pIn || !pOut)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    TPM2B_SIZE_CHECK(&pIn->keyAuth, pCtx->nameAlgSize);

    if ((pIn->keyAlg != TPM2_ALG_RSA) && (pIn->keyAlg != TPM2_ALG_ECC))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid key alg supplied, "
                "rc 0x%02x = %s\n",
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

    asymKeyIn.pParentKey = pParentKeyObject;
    asymKeyIn.pNewKeyAuth = &pIn->keyAuth;
    asymKeyIn.pOutsideInfo = &outsideInfo;
    asymKeyIn.keyAlg = pIn->keyAlg;
    asymKeyIn.bEnableBackup = pIn->bEnableBackup;

    if (TPM2_ALG_RSA == pIn->keyAlg)
        asymKeyIn.keyInfo.rsaInfo = pIn->keyInfo.rsaInfo;
    else
        asymKeyIn.keyInfo.eccInfo = pIn->keyInfo.eccInfo;

    asymKeyIn.objectId = pIn->objectId;

    rc = FAPI2_ASYM_createChildAsymKey(pCtx, &asymKeyIn, &asymKeyOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to create child key under SRK, "
                "rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    loadIn.pObj = asymKeyOut.pKey;
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
    rc = FAPI2_UTILS_serialize(&asymKeyOut.pKey, FALSE, &pOut->key);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to get serialized key, "
                "rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pubKeyIn.keyName = loadOut.objName;
    rc = FAPI2_ASYM_getPublicKey(pCtx, &pubKeyIn, &pubKeyOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to get public key, "
                "rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pOut->keyName = loadOut.objName;
    pOut->keyAlg = pubKeyOut.keyAlg;
    pOut->publicKey = pubKeyOut.publicKey;

    /* For persistent keys, need to call evict control using the object id */
    if (pIn->objectId)
    {
        MOCTPM2_OBJECT_HANDLE *pKeyHandle = {0};

        rc = FAPI2_UTILS_loadObjectTree(pCtx, asymKeyOut.pKey, &pKeyHandle); 
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed to create handle to persist key, "
                    "rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        /*
         * Start regular session. 
         */
        rc = FAPI2_UTILS_startSession(pCtx, &pAuthSession);
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed to Start session."
                    ", rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        /* Use the key handle to persist the object */

        /*
         * Make the key object persistent.
         */
        evictControlIn.authHandle = TPM2_RH_OWNER;
        evictControlIn.pObjectHandle = pKeyHandle;
        evictControlIn.persistentHandle = pIn->objectId;
        evictControlIn.pAuthAuthHandle = &pCtx->authValues.ownerAuth;
        evictControlIn.pAuthSession = pAuthSession;

        rc = SAPI2_CTX_MGMT_EvictControl(pCtx->pSapiCtx,
                &evictControlIn, &evictControlOut);
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed to make primary key persistent."
                    ", rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
    }

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
            if (asymKeyOut.pKey)
            {
                FAPI2_UTILS_destroyObject(&asymKeyOut.pKey);
            }
        }
    }

    if (pParentKeyObject)
    {
        flushObjectIn.objName = pParentKeyObject->objectName;
        exit_rc = FAPI2_CONTEXT_flushObject(pCtx, &flushObjectIn);
    }

    /*
     * Destroy handle to persistent object. Persistent object will still
     * remain in TPM memory.
     */
    if (evictControlOut.pPersistentHandle)
    {
        exit_rc = FAPI2_UTILS_destroyHandle(pCtx, &evictControlOut.pPersistentHandle);
        if (TSS2_RC_SUCCESS != exit_rc)
        {
            DB_PRINT("%s.%d Failed to destroy persistent key handle."
                    ", rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, exit_rc, tss2_err_string(exit_rc));
            if (TSS2_RC_SUCCESS == rc)
                rc = exit_rc;
        }
    }

    if (pAuthSession)
        exit_rc = FAPI2_UTILS_closeSession(pCtx,
                &pAuthSession);

    if (TSS2_RC_SUCCESS == rc)
        rc = exit_rc;

    return rc;
}

/*
 * This function creates an asymmetric signature on the digest provided by
 * the input parameters. It also takes in a ticket. if the signing key is a
 * restricted signing key, a validation ticket, produced by the TPM,
 * proving that the digest does not begin with TPM2_GENERATED_VALUE
 * must be provided. This ticket is generated if the TPM2_Hash or TPM hash
 * sequence commands are used. This means that the buffer to be signed by a
 * restricted signing key, must be digested by the TPM using the aforementioned
 * commands.
 */
TSS2_RC FAPI2_ASYM_signInternal(
        FAPI2_CONTEXT *pCtx,
        AsymSignInternalIn *pIn,
        AsymSignInternalOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TSS2_RC exit_rc = TSS2_RC_SUCCESS;
    TPMT_PUBLIC *pPublic = NULL;
    SignIn signIn = { 0 };
    SignOut signOut = { 0 };
    MOCTPM2_OBJECT_HANDLE *pKeyHandle = NULL;
    MOCTPM2_OBJECT_HANDLE *pAuthSession = NULL;
    TPMI_ALG_HASH hashAlg = TPM2_ALG_NULL;
    TPMT_SIG_SCHEME sigScheme = { 0 };
    TPMT_TK_HASHCHECK signHashCheck = { 0 };
    FAPI2_OBJECT *pKey = NULL;

    if (!pCtx || !pIn || !pOut || (!pIn->pSignDigest) || (!pIn->pKey))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    TPM2B_SIZE_CHECK(pIn->pSignDigest, TPM2B_MAX_SIZE(pIn->pSignDigest));

    pKey = pIn->pKey;

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

    /*
     * If key is a restricted key, it can be used
     * to sign digests that were created by the TPM itself, which
     * provides a ticket validating that the digest created by it was
     * not an attestation structure, to prevent spoofing of attestation
     * structure. Ensure that a validation ticket is provided.
     */
    if (pPublic->objectAttributes & TPMA_OBJECT_RESTRICTED)
    {
        if (!pIn->pValidationTicket)
        {
            rc = TSS2_SYS_RC_BAD_REFERENCE;
            DB_PRINT("%s.%d No validation provided for restricted signing key"
                    ", rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        if (TPM2_ST_HASHCHECK != pIn->pValidationTicket->tag)
        {
            rc = TSS2_SYS_RC_BAD_VALUE;
            DB_PRINT("%s.%d Invalid tag for validation ticket, rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
    }

    /*
     * Cannot sign with a key that does not have the sign attribute set.
     */
    if (!(pPublic->objectAttributes & TPMA_OBJECT_SIGN_ENCRYPT))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Key does not have sign attribute set. Not a signing"
                "key., rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /*
     * Ensure key is of expected type
     */
    if ((pPublic->type != TPM2_ALG_RSA) && (pPublic->type != TPM2_ALG_ECC))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Key type not ECC or RSA., rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /*
     * For RSA keys, scheme must be TPM2_ALG_RSAPSS or TPM2_ALG_RSASSA,
     * if the scheme is not in the key's public data.
     */
    if (pPublic->type == TPM2_ALG_RSA)
    {
        if (TPM2_ALG_NULL == pPublic->parameters.rsaDetail.scheme.scheme)
        {
            if ((pIn->sigScheme != TPM2_ALG_RSAPSS) &&
                    (pIn->sigScheme != TPM2_ALG_RSASSA))
            {
                rc = TSS2_SYS_RC_BAD_VALUE;
                DB_PRINT("%s.%d RSA Key does not contain default scheme,"
                        "Invalid scheme provided for signature., rc 0x%02x = %s\n",
                        __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
                goto exit;
            }

            if ((pIn->hashAlg != TPM2_ALG_SHA1) &&
                    (pIn->hashAlg != TPM2_ALG_SHA256) &&
                    (pIn->hashAlg != TPM2_ALG_SHA384) &&
                    (pIn->hashAlg != TPM2_ALG_SHA512))
            {
                rc = TSS2_SYS_RC_BAD_VALUE;
                DB_PRINT("%s.%d RSA Key invalid hash alg, rc 0x%02x = %s\n",
                        __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
                goto exit;
            }

            sigScheme.scheme = pIn->sigScheme;
            if (TPM2_ALG_RSAPSS == pIn->sigScheme)
                sigScheme.details.rsapss.hashAlg = pIn->hashAlg;

            if (TPM2_ALG_RSASSA == pIn->sigScheme)
                sigScheme.details.rsassa.hashAlg = pIn->hashAlg;
        }
        else
        {
            if ((TPM2_ALG_RSAPSS != pPublic->parameters.rsaDetail.scheme.scheme)
                    &&(TPM2_ALG_RSASSA != pPublic->parameters.rsaDetail.scheme.scheme))
            {
                rc = TSS2_SYS_RC_BAD_VALUE;
                DB_PRINT("%s.%d RSA Key invalid signature scheme., rc 0x%02x = %s\n",
                        __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
                goto exit;
            }

            sigScheme.scheme = pPublic->parameters.rsaDetail.scheme.scheme;

            if (TPM2_ALG_RSAPSS == pPublic->parameters.rsaDetail.scheme.scheme)
                sigScheme.details.rsapss.hashAlg =
                        pPublic->parameters.rsaDetail.scheme.details.rsapss.hashAlg;

            if (TPM2_ALG_RSASSA == pPublic->parameters.rsaDetail.scheme.scheme)
                sigScheme.details.rsassa.hashAlg =
                        pPublic->parameters.rsaDetail.scheme.details.rsassa.hashAlg;
        }
    }
    else if (pPublic->type == TPM2_ALG_ECC)
    {
        if (TPM2_ALG_NULL == pPublic->parameters.eccDetail.scheme.scheme)
        {
            if ((pIn->sigScheme != TPM2_ALG_ECDSA) &&
                    (pIn->sigScheme != TPM2_ALG_ECSCHNORR))
            {
                rc = TSS2_SYS_RC_BAD_VALUE;
                DB_PRINT("%s.%d ECC Key does not contain default scheme,"
                        "Invalid scheme provided for signature., rc 0x%02x = %s\n",
                        __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
                goto exit;
            }

            sigScheme.scheme = pIn->sigScheme;

            /*
             * Automatically select sensible scheme hashAlg based on the curve.
             */
            hashAlg = TPM2_ALG_SHA256;

            if (pPublic->parameters.eccDetail.curveID == TPM2_ECC_NIST_P384)
                hashAlg = TPM2_ALG_SHA384;

            if (pPublic->parameters.eccDetail.curveID == TPM2_ECC_NIST_P521)
                hashAlg = TPM2_ALG_SHA512;

            if (TPM2_ALG_ECDSA == pIn->sigScheme)
                sigScheme.details.ecdsa.hashAlg = hashAlg;

            if (TPM2_ALG_ECSCHNORR == pIn->sigScheme)
                sigScheme.details.eschnorr.hashAlg = hashAlg;

        }
        else
        {
            if ((TPM2_ALG_ECDSA != pPublic->parameters.eccDetail.scheme.scheme)
                    &&(TPM2_ALG_ECSCHNORR != pPublic->parameters.eccDetail.scheme.scheme))
            {
                rc = TSS2_SYS_RC_BAD_VALUE;
                DB_PRINT("%s.%d EC Key invalid signature scheme, rc 0x%02x = %s\n",
                        __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
                goto exit;
            }

            sigScheme.scheme = pPublic->parameters.eccDetail.scheme.scheme;

            if (TPM2_ALG_ECDSA == pPublic->parameters.eccDetail.scheme.scheme)
                sigScheme.details.ecdsa.hashAlg =
                        pPublic->parameters.eccDetail.scheme.details.ecdsa.hashAlg;

            if (TPM2_ALG_ECSCHNORR == pPublic->parameters.eccDetail.scheme.scheme)
                sigScheme.details.eschnorr.hashAlg =
                        pPublic->parameters.eccDetail.scheme.details.ecSchnorr.hashAlg;
        }
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

    /*
     * If validation ticket is not provided, ie this is not a restricted signing key,
     * Provide NULL hash check ticket, since this digest is not
     * created by the TPM.
     */
    if (!pIn->pValidationTicket)
    {
        signHashCheck.tag = TPM2_ST_HASHCHECK;
        signHashCheck.hierarchy = TPM2_RH_NULL;
        signHashCheck.digest.size = 0;
    }
    else
    {
        signHashCheck = *(pIn->pValidationTicket);
    }

    signIn.pObjectHandle = pKeyHandle;
    signIn.pDigest = pIn->pSignDigest;
    signIn.pInScheme = &sigScheme;
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

    if (signOut.signature.sigAlg != sigScheme.scheme)
    {
        rc = TSS2_SYS_RC_MALFORMED_RESPONSE;
        DB_PRINT("%s.%d Invalid sigScheme returned by TPM."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (pPublic->type == TPM2_ALG_RSA)
    {
        pOut->keyAlg = TPM2_ALG_RSA;
        if (TPM2_ALG_RSAPSS == sigScheme.scheme)
            pOut->signature.rsaSignature =
                    signOut.signature.signature.rsapss.sig;

        if (TPM2_ALG_RSASSA == sigScheme.scheme)
            pOut->signature.rsaSignature =
                    signOut.signature.signature.rsassa.sig;
    }
    else if (pPublic->type == TPM2_ALG_ECC)
    {
        pOut->keyAlg = TPM2_ALG_ECC;
        if (TPM2_ALG_ECDSA == sigScheme.scheme)
        {
            pOut->signature.eccSignature.signatureR =
                    signOut.signature.signature.ecdsa.signatureR;
            pOut->signature.eccSignature.signatureS =
                    signOut.signature.signature.ecdsa.signatureS;
        }

        if (TPM2_ALG_ECSCHNORR == sigScheme.scheme)
        {
            pOut->signature.eccSignature.signatureR =
                    signOut.signature.signature.ecdsa.signatureR;
            pOut->signature.eccSignature.signatureS =
                    signOut.signature.signature.ecdsa.signatureS;
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
        exit_rc = FAPI2_UTILS_destroyHandle(pCtx, &pKeyHandle);

    if (TSS2_RC_SUCCESS == rc)
        rc = exit_rc;

    return rc;
}

/*
 * This function creates an asymmetric signature on the digest provided by
 * the input parameters, using a restricted signing key. The difference
 * between resitrctedSign() and the normal sign is that the TPM must digest
 * the data before performing a signature. This is to ensure that an
 * attestation structure cannot be spoofed. This API can be used on a unrestricted
 * signing keys, whose schemes were provided during key creation. Digesting using
 * the TPM is slow, so this facility must be used with care. For restricted signing
 * keys, there is no other option but to have the data digested by the TPM.
 */
TSS2_RC FAPI2_ASYM_restrictedSign(
        FAPI2_CONTEXT *pCtx,
        AsymRestrictedSignIn *pIn,
        AsymRestrictedSignOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TSS2_RC exit_rc = TSS2_RC_SUCCESS;
    FAPI2_OBJECT *pKey = NULL;
    AsymSignInternalIn signInternalIn = { 0 };
    AsymSignInternalOut signInternalOut = { 0 };
    DataDigestInternalIn digestIn = { 0 };
    DataDigestInternalOut digestOut = { 0 };
    TPMT_PUBLIC *pPublic = NULL;
    TPMI_ALG_HASH hashAlg = TPM2_ALG_NULL;
    TPMI_ALG_SIG_SCHEME sigScheme = TPM2_ALG_NULL;
    ContextFlushObjectIn flushObjectIn = { 0 };

    if (!pCtx || !pIn || !pOut)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    TPM2B_SIZE_CHECK(&pIn->keyName, TPM2B_MAX_SIZE(&pIn->keyName));

    rc = FAPI2_CONTEXT_lookupObject(pCtx, &pIn->keyName, &pKey);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Unable to find key object, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (pKey->isExternal)
    {
        rc = TSS2_FAPI_RC_NOT_PERMITTED;
        DB_PRINT("%s.%d Restricted Key cannot be an external key, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pPublic = &pKey->public.objectPublic.publicArea;

    /*
     * Ensure key is of expected type
     */
    if ((pPublic->type != TPM2_ALG_RSA) && (pPublic->type != TPM2_ALG_ECC))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Key type not ECC or RSA., rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /*
     * For RSA keys, scheme must be TPM2_ALG_RSAPSS or TPM2_ALG_RSASSA,
     * if the scheme is not in the key's public data.
     */
    if (pPublic->type == TPM2_ALG_RSA)
    {
        if (TPM2_ALG_NULL == pPublic->parameters.rsaDetail.scheme.scheme)
        {
            if ((pIn->sigScheme != TPM2_ALG_RSAPSS) &&
                (pIn->sigScheme != TPM2_ALG_RSASSA))
            {
                rc = TSS2_SYS_RC_BAD_VALUE;
                DB_PRINT("%s.%d RSA Key does not contain default scheme,"
                        "Invalid scheme provided for signature., rc 0x%02x = %s\n",
                        __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
                goto exit;
            }

            if ((pIn->hashAlg != TPM2_ALG_SHA1) &&
                (pIn->hashAlg != TPM2_ALG_SHA256) &&
                (pIn->hashAlg != TPM2_ALG_SHA384) &&
                (pIn->hashAlg != TPM2_ALG_SHA512))
            {
                rc = TSS2_SYS_RC_BAD_VALUE;
                DB_PRINT("%s.%d RSA Key invalid hash alg, rc 0x%02x = %s\n",
                        __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
                goto exit;
            }

            sigScheme = pIn->sigScheme;
            hashAlg = pIn->hashAlg;
        }
        else
        {
            if ((TPM2_ALG_RSAPSS != pPublic->parameters.rsaDetail.scheme.scheme) &&
                (TPM2_ALG_RSASSA != pPublic->parameters.rsaDetail.scheme.scheme))
            {
                rc = TSS2_SYS_RC_BAD_VALUE;
                DB_PRINT("%s.%d RSA Key invalid signature scheme., rc 0x%02x = %s\n",
                        __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
                goto exit;
            }

            if (TPM2_ALG_RSAPSS == pPublic->parameters.rsaDetail.scheme.scheme)
                hashAlg = pPublic->parameters.rsaDetail.scheme.details.rsapss.hashAlg;

            if (TPM2_ALG_RSASSA == pPublic->parameters.rsaDetail.scheme.scheme)
                hashAlg = pPublic->parameters.rsaDetail.scheme.details.rsassa.hashAlg;
        }
    }
    else if (pPublic->type == TPM2_ALG_ECC)
    {
        if (TPM2_ALG_NULL == pPublic->parameters.eccDetail.scheme.scheme)
        {
            if (pIn->sigScheme != TPM2_ALG_ECDSA)
            {
                rc = TSS2_SYS_RC_BAD_VALUE;
                DB_PRINT("%s.%d EC input scheme not recognized,"
                        "Invalid scheme provided for signature., rc 0x%02x = %s\n",
                        __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
                goto exit;
            }

            if ((pIn->hashAlg != TPM2_ALG_SHA1) &&
                (pIn->hashAlg != TPM2_ALG_SHA256) &&
                (pIn->hashAlg != TPM2_ALG_SHA384) &&
                (pIn->hashAlg != TPM2_ALG_SHA512))
            {
                rc = TSS2_SYS_RC_BAD_VALUE;
                DB_PRINT("%s.%d EC invalid hash alg, rc 0x%02x = %s\n",
                        __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
                goto exit;
            }

            sigScheme = pIn->sigScheme;
            hashAlg = pIn->hashAlg;
        }
        else
        {

            if ((TPM2_ALG_ECDSA != pPublic->parameters.eccDetail.scheme.scheme)
                    &&(TPM2_ALG_ECSCHNORR != pPublic->parameters.eccDetail.scheme.scheme))
            {
                rc = TSS2_SYS_RC_BAD_VALUE;
                DB_PRINT("%s.%d EC Key invalid signature scheme, rc 0x%02x = %s\n",
                        __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
                goto exit;
            }

            if (TPM2_ALG_ECDSA == pPublic->parameters.eccDetail.scheme.scheme)
                hashAlg = pPublic->parameters.eccDetail.scheme.details.ecdsa.hashAlg;

            if (TPM2_ALG_ECSCHNORR == pPublic->parameters.eccDetail.scheme.scheme)
                hashAlg = pPublic->parameters.eccDetail.scheme.details.ecSchnorr.hashAlg;
        }
    }

    digestIn.hashAlg = hashAlg;
    digestIn.bufferLen = pIn->bufferLen;
    digestIn.pBuffer = pIn->pBuffer;
    /*
     * Use owner hierarchy for all non-persistent objects, since they must be under
     * the storage hierarchy;
     */
    if (0 == pKey->objectHandle)
    {
        digestIn.ticketHierarchy = TPM2_RH_OWNER;
    }
    else if (((pKey->objectHandle >= FAPI2_RH_PERSISTENT_OWNER_START) &&
            (pKey->objectHandle <= FAPI2_RH_PERSISTENT_OWNER_END)))
    {
        /*
         * Use owner hierarchy for ticket if we are in persistent owner range.
         */
        digestIn.ticketHierarchy = TPM2_RH_OWNER;
    }
    else
    {
        /*
         * Use ADMIN hierarchy for ticket if we are in persistent endorsement range.
         */
        digestIn.ticketHierarchy = TPM2_RH_ENDORSEMENT;
    }

    rc = FAPI2_DATA_digestInternal(pCtx, &digestIn, &digestOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Unable to digest provided data, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    signInternalIn.pKey = pKey;
    signInternalIn.pValidationTicket = &digestOut.validation;
    signInternalIn.pSignDigest = &digestOut.digest;
    signInternalIn.sigScheme = sigScheme;
    signInternalIn.hashAlg = hashAlg;

    rc = FAPI2_ASYM_signInternal(pCtx, &signInternalIn, &signInternalOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to sign data, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pOut->keyAlg = signInternalOut.keyAlg;
    pOut->signature = signInternalOut.signature;

    rc = TSS2_RC_SUCCESS;
exit:
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
 * This function creates an asymmetric signature on the digest provided by
 * the input parameters.
 */
TSS2_RC FAPI2_ASYM_sign(
        FAPI2_CONTEXT *pCtx,
        AsymSignIn *pIn,
        AsymSignOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TSS2_RC exit_rc = TSS2_RC_SUCCESS;
    FAPI2_OBJECT *pKey = NULL;
    AsymSignInternalIn signInternalIn = { 0 };
    AsymSignInternalOut signInternalOut = { 0 };
    ContextFlushObjectIn flushObjectIn = { 0 };

    if (!pCtx || !pIn || !pOut)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    TPM2B_SIZE_CHECK(&pIn->keyName, TPM2B_MAX_SIZE(&pIn->keyName));

    rc = FAPI2_CONTEXT_lookupObject(pCtx, &pIn->keyName, &pKey);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Unable to find key object, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    signInternalIn.pKey = pKey;
    signInternalIn.pValidationTicket = NULL;
    signInternalIn.pSignDigest = &pIn->signDigest;
    signInternalIn.sigScheme = pIn->sigScheme;
    signInternalIn.hashAlg = pIn->hashAlg;

    rc = FAPI2_ASYM_signInternal(pCtx, &signInternalIn, &signInternalOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to sign data, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pOut->keyAlg = signInternalOut.keyAlg;
    pOut->signature = signInternalOut.signature;

    rc = TSS2_RC_SUCCESS;
exit:
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
 * This is an advanced API that must only be used when the application writer
 * knows exactly what is being done. This API allows the creation of a FAPI2
 * OBJECT that can be loaded in the TPM using TPM2_LoadExternal. This is useful
 * incase the TPM needs to be used as a crypto engine/accelerator. WHen the
 * returned object is used, it will always be loaded in the NULL hierarchy.
 * The returned key can be serialized and deserialized like TPM generated keys.
 */
TSS2_RC FAPI2_ASYM_createExternalAsymKey(
        FAPI2_CONTEXT *pCtx,
        AsymCreateExternalKeyIn *pIn,
        AsymCreateExternalKeyOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TPM2B_PUBLIC inPublic = { 0 };
    TPM2B_SENSITIVE inSensitive = { 0 };
    UtilsCreateObjectIn createObjectIn = { 0 };
    UtilsCreateObjectOut createObjectOut = { 0 };
    PolicyAuthNode defaultPolicy = { 0 };
    PolicyAuthNode *pObjectPolicy = NULL;
    ubyte2 numPolicyTerms = 0;

    if (!pCtx || !pIn || !pOut || !pIn->pKeyAuth)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    TPM2B_SIZE_CHECK(pIn->pKeyAuth, pCtx->nameAlgSize);

    if ((pIn->keyAlg != TPM2_ALG_RSA) && (pIn->keyAlg != TPM2_ALG_ECC))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid key alg supplied, "
                "rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (pIn->keyAlg == TPM2_ALG_RSA)
    {
        if ((pIn->keyInfo.rsaInfo.keyType != FAPI2_ASYM_TYPE_SIGNING) &&
                (pIn->keyInfo.rsaInfo.keyType != FAPI2_ASYM_TYPE_GENERAL) &&
                (pIn->keyInfo.rsaInfo.keyType != FAPI2_ASYM_TYPE_DECRYPT))
        {
            rc = TSS2_SYS_RC_BAD_VALUE;
            DB_PRINT("%s.%d Invalid key type supplied, "
                    "rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        rc = FAPI2_ASYM_getRSATemplate(pCtx, &inPublic.publicArea,
                pIn->keyInfo.rsaInfo.keySize,
                pIn->keyInfo.rsaInfo.exponent,
                pIn->keyInfo.rsaInfo.hashAlg,
                pIn->keyInfo.rsaInfo.scheme,
                pIn->keyInfo.rsaInfo.keyType);
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed to get asymmetric key template."
                    ", rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        if (NULL == pIn->publicKey.pRsaPublic)
        {
            rc = TSS2_SYS_RC_BAD_REFERENCE;
            DB_PRINT("%s.%d RSA ublic key not supplied, "
                    "rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        TPM2B_SIZE_CHECK(pIn->publicKey.pRsaPublic,
                TPM2B_MAX_SIZE(pIn->publicKey.pRsaPublic));

        inPublic.publicArea.objectAttributes &= ~(TPMA_OBJECT_FIXEDTPM |
                TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN);
        inPublic.publicArea.objectAttributes |= TPMA_OBJECT_NODA;

        inPublic.publicArea.unique.rsa = *(pIn->publicKey.pRsaPublic);

        if (pIn->privateKey.pRsaPrivate)
        {
            TPM2B_SIZE_CHECK(pIn->privateKey.pRsaPrivate,
                            TPM2B_MAX_SIZE(pIn->privateKey.pRsaPrivate));

            inSensitive.sensitiveArea.sensitiveType = inPublic.publicArea.type;
            inSensitive.sensitiveArea.authValue = *(pIn->pKeyAuth);
            inSensitive.sensitiveArea.sensitive.rsa = *(pIn->privateKey.pRsaPrivate);
        }
    }
    else if (pIn->keyAlg == TPM2_ALG_ECC)
    {
        if ((pIn->keyInfo.eccInfo.keyType != FAPI2_ASYM_TYPE_SIGNING) &&
                (pIn->keyInfo.eccInfo.keyType != FAPI2_ASYM_TYPE_GENERAL) &&
                (pIn->keyInfo.eccInfo.keyType != FAPI2_ASYM_TYPE_DECRYPT))
        {
            rc = TSS2_SYS_RC_BAD_VALUE;
            DB_PRINT("%s.%d Invalid key type supplied, "
                    "rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        rc = FAPI2_ASYM_getECCTemplate(pCtx, &inPublic.publicArea,
                pIn->keyInfo.eccInfo.curveID,
                pIn->keyInfo.eccInfo.scheme,
                pIn->keyInfo.eccInfo.keyType);
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed to get asymmetric key template."
                    ", rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        if (NULL == pIn->publicKey.pEccPublic)
        {
            rc = TSS2_SYS_RC_BAD_REFERENCE;
            DB_PRINT("%s.%d ECC public key not supplied, "
                    "rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
        TPM2B_SIZE_CHECK(&pIn->publicKey.pEccPublic->x,
                        TPM2B_MAX_SIZE(&pIn->publicKey.pEccPublic->x));
        TPM2B_SIZE_CHECK(&pIn->publicKey.pEccPublic->y,
                                TPM2B_MAX_SIZE(&pIn->publicKey.pEccPublic->y));

        inPublic.publicArea.objectAttributes &= ~(TPMA_OBJECT_FIXEDTPM |
                TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN);

        inPublic.publicArea.objectAttributes |= TPMA_OBJECT_NODA;

        inPublic.publicArea.unique.ecc = *(pIn->publicKey.pEccPublic);

        if (pIn->privateKey.pEccPrivate)
        {
            TPM2B_SIZE_CHECK(pIn->privateKey.pEccPrivate,
                                TPM2B_MAX_SIZE(pIn->privateKey.pEccPrivate));

            inSensitive.sensitiveArea.sensitiveType = inPublic.publicArea.type;
            inSensitive.sensitiveArea.authValue = *(pIn->pKeyAuth);
            inSensitive.sensitiveArea.sensitive.ecc = *(pIn->privateKey.pEccPrivate);
        }
    }
    else
    {
        rc = TSS2_SYS_RC_GENERAL_FAILURE;
        DB_PRINT("%s.%d Unexpected situation, "
                "rc 0x%02x = %s\n",
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

    pOut->pKey = createObjectOut.pObject;
    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}

/*
 * This function verifies a given asymmetric signature on the provided digest,
 * using a given key. This is a public key operation, which is done in hardware
 * on the TPM. Hence, a context is required to be able to talk to the hardware.
 * Signature verification can be done in software without having to go to the
 * TPM which will likely be faster, given the overhead of communicating with the
 * TPM, loading key objects etc. This is provided purely for completeness of API
 * and may have some uses for testing applications.
 */
TSS2_RC FAPI2_ASYM_verifySig(
        FAPI2_CONTEXT *pCtx,
        AsymVerifySigIn *pIn,
        AsymVerifySigOut *pOut
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

    pOut->sigValid = FALSE;

    pPublic = &pKey->public.objectPublic.publicArea;

    /*
     * Cannot verify with a key that does not have the sign attribute set.
     */
    if (!(pPublic->objectAttributes & TPMA_OBJECT_SIGN_ENCRYPT))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Key does not have sign attribute set. Not a signing"
                "key., rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /*
     * Ensure key is of expected type
     */
    if ((pPublic->type != TPM2_ALG_RSA) && (pPublic->type != TPM2_ALG_ECC))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Key type not ECC or RSA., rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /*
     * For RSA keys, scheme must be TPM2_ALG_RSAPSS or TPM2_ALG_RSASSA,
     * if the scheme is not in the key's public data.
     */
    if (pPublic->type == TPM2_ALG_RSA)
    {
        TPM2B_SIZE_CHECK(&pIn->signature.rsaSignature,
                TPM2B_MAX_SIZE(&pIn->signature.rsaSignature));

        if (TPM2_ALG_NULL == pPublic->parameters.rsaDetail.scheme.scheme)
        {
            if ((pIn->sigScheme != TPM2_ALG_RSAPSS) &&
                    (pIn->sigScheme != TPM2_ALG_RSASSA))
            {
                rc = TSS2_SYS_RC_BAD_VALUE;
                DB_PRINT("%s.%d RSA Key does not contain default scheme,"
                        "Invalid scheme provided for signature., rc 0x%02x = %s\n",
                        __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
                goto exit;
            }

            if ((pIn->hashAlg != TPM2_ALG_SHA1) &&
                    (pIn->hashAlg != TPM2_ALG_SHA256) &&
                    (pIn->hashAlg != TPM2_ALG_SHA384) &&
                    (pIn->hashAlg != TPM2_ALG_SHA512))
            {
                rc = TSS2_SYS_RC_BAD_VALUE;
                DB_PRINT("%s.%d RSA Key invalid hash alg, rc 0x%02x = %s\n",
                        __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
                goto exit;
            }

            signature.sigAlg = pIn->sigScheme;

            if (TPM2_ALG_RSAPSS == signature.sigAlg)
            {
                signature.signature.rsapss.hash = pIn->hashAlg;
                signature.signature.rsapss.sig =
                        pIn->signature.rsaSignature;
            }

            if (TPM2_ALG_RSASSA == signature.sigAlg)
            {
                signature.signature.rsassa.hash = pIn->hashAlg;
                signature.signature.rsassa.sig =
                        pIn->signature.rsaSignature;
            }
        }
        else
        {
            if ((TPM2_ALG_RSAPSS != pPublic->parameters.rsaDetail.scheme.scheme)
                    &&(TPM2_ALG_RSASSA != pPublic->parameters.rsaDetail.scheme.scheme))
            {
                rc = TSS2_SYS_RC_BAD_VALUE;
                DB_PRINT("%s.%d RSA Key invalid signature scheme., rc 0x%02x = %s\n",
                        __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
                goto exit;
            }

            signature.sigAlg = pPublic->parameters.rsaDetail.scheme.scheme;

            if (TPM2_ALG_RSAPSS == signature.sigAlg)
            {
                signature.signature.rsapss.hash =
                        pPublic->parameters.rsaDetail.scheme.details.rsapss.hashAlg;
                signature.signature.rsapss.sig =
                        pIn->signature.rsaSignature;
            }

            if (TPM2_ALG_RSASSA == signature.sigAlg)
            {
                signature.signature.rsassa.hash =
                        pPublic->parameters.rsaDetail.scheme.details.rsassa.hashAlg;
                signature.signature.rsassa.sig =
                        pIn->signature.rsaSignature;
            }
        }
    }
    else if (pPublic->type == TPM2_ALG_ECC)
    {
        TPM2B_SIZE_CHECK(&(pIn->signature.eccSignature.signatureR),
                        TPM2B_MAX_SIZE(&(pIn->signature.eccSignature.signatureR)));

        TPM2B_SIZE_CHECK(&(pIn->signature.eccSignature.signatureS),
                        TPM2B_MAX_SIZE(&(pIn->signature.eccSignature.signatureS)));

        if (TPM2_ALG_NULL == pPublic->parameters.eccDetail.scheme.scheme)
        {
            if ((pIn->sigScheme != TPM2_ALG_ECDSA) &&
                    (pIn->sigScheme != TPM2_ALG_ECSCHNORR))
            {
                rc = TSS2_SYS_RC_BAD_VALUE;
                DB_PRINT("%s.%d ECC Key does not contain default scheme,"
                        "Invalid scheme provided for signature., rc 0x%02x = %s\n",
                        __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
                goto exit;
            }

            signature.sigAlg = pIn->sigScheme;

            /*
             * Automatically select sensible scheme hashAlg based on the curve.
             */
            hashAlg = TPM2_ALG_SHA256;

            if (pPublic->parameters.eccDetail.curveID == TPM2_ECC_NIST_P384)
                hashAlg = TPM2_ALG_SHA384;

            if (pPublic->parameters.eccDetail.curveID == TPM2_ECC_NIST_P521)
                hashAlg = TPM2_ALG_SHA512;

            if (TPM2_ALG_ECDSA == pIn->sigScheme)
            {
                signature.signature.ecdsa.hash = hashAlg;
                signature.signature.ecdsa.signatureR =
                        pIn->signature.eccSignature.signatureR;
                signature.signature.ecdsa.signatureS =
                        pIn->signature.eccSignature.signatureS;
            }

            if (TPM2_ALG_ECSCHNORR == pIn->sigScheme)
            {
                signature.signature.ecschnorr.hash = hashAlg;
                signature.signature.ecschnorr.signatureR =
                        pIn->signature.eccSignature.signatureR;
                signature.signature.ecschnorr.signatureS =
                        pIn->signature.eccSignature.signatureS;
            }
        }
        else
        {
            if ((TPM2_ALG_ECDSA != pPublic->parameters.eccDetail.scheme.scheme)
                    &&(TPM2_ALG_ECSCHNORR != pPublic->parameters.eccDetail.scheme.scheme))
            {
                rc = TSS2_SYS_RC_BAD_VALUE;
                DB_PRINT("%s.%d EC Key invalid signature scheme, rc 0x%02x = %s\n",
                        __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
                goto exit;
            }

            signature.sigAlg = pPublic->parameters.eccDetail.scheme.scheme;

            if (TPM2_ALG_ECDSA == pPublic->parameters.eccDetail.scheme.scheme)
            {
                signature.signature.ecdsa.hash =
                        pPublic->parameters.eccDetail.scheme.details.ecdsa.hashAlg;;
                signature.signature.ecdsa.signatureR =
                        pIn->signature.eccSignature.signatureR;
                signature.signature.ecdsa.signatureS =
                        pIn->signature.eccSignature.signatureS;
            }

            if (TPM2_ALG_ECSCHNORR == pPublic->parameters.eccDetail.scheme.scheme)
            {
                signature.signature.ecschnorr.hash =
                        pPublic->parameters.eccDetail.scheme.details.ecdsa.hashAlg;
                signature.signature.ecschnorr.signatureR =
                        pIn->signature.eccSignature.signatureR;
                signature.signature.ecschnorr.signatureS =
                        pIn->signature.eccSignature.signatureS;
            }
        }
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
    if (pKey)
    {
        flushObjectIn.objName = pKey->objectName;
        exit_rc = FAPI2_CONTEXT_flushObject(pCtx, &flushObjectIn);
        if (TSS2_RC_SUCCESS == rc)
            rc = exit_rc;
    }

    if (pKeyHandle)
        exit_rc = FAPI2_UTILS_destroyHandle(pCtx, &pKeyHandle);

    if (TSS2_RC_SUCCESS == rc)
        rc = exit_rc;

    return rc;
}

static TSS2_RC FAPI2_ASYM_RSAEncryptDecryptEx(
        FAPI2_CONTEXT *pCtx,
        AsymRsaEncryptIn *pIn,
        AsymRsaEncryptOut *pOut,
        byteBoolean encrypt
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TSS2_RC exit_rc = TSS2_RC_SUCCESS;
    TPMT_PUBLIC *pPublic = NULL;
    RSAEncryptIn rsaEncryptIn = { 0 };
    RSAEncryptOut rsaEncryptOut = { 0 };
    RSADecryptIn rsaDecryptIn = { 0 };
    RSADecryptOut rsaDecryptOut = { 0 };
    TPMT_RSA_DECRYPT inScheme = { 0 };
    MOCTPM2_OBJECT_HANDLE *pKeyHandle = NULL;
    MOCTPM2_OBJECT_HANDLE *pAuthSession = NULL;
    FAPI2_OBJECT *pKey = NULL;
    ContextFlushObjectIn flushObjectIn = { 0 };

    if (!pCtx || !pIn || !pOut)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    TPM2B_SIZE_CHECK(&pIn->message, TPM2B_MAX_SIZE(&pIn->message));
    TPM2B_SIZE_CHECK(&pIn->keyName, TPM2B_MAX_SIZE(&pIn->keyName));
    TPM2B_SIZE_CHECK(&pIn->label, TPM2B_MAX_SIZE(&pIn->label));

    rc = FAPI2_CONTEXT_lookupObject(pCtx, &pIn->keyName, &pKey);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Unable to find key object, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }
    /*
     * authValue msut be set for decryption, if object requires authValue for use.
     */
    if (!encrypt && ((pKey->authValueRequired) && (!pKey->authValueValid)))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d AuthValue not set for Key, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pPublic = &pKey->public.objectPublic.publicArea;

    /*
     * If key is a restricted key, it cannot be used to encrypt.
     */
    if (pPublic->objectAttributes & TPMA_OBJECT_RESTRICTED)
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Cannot sign with restricted key, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /*
     * Cannot encrypt with a key that does not have the decrypt attribute set.
     */
    if (!(pPublic->objectAttributes & TPMA_OBJECT_DECRYPT))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Key does not have encrypt attribute set. Not a signing"
                "key., rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /*
     * Ensure key is of expected type
     */
    if (pPublic->type != TPM2_ALG_RSA)
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Key type not RSA., rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (TPM2_ALG_NULL == pPublic->parameters.rsaDetail.scheme.scheme)
    {
        if ((pIn->scheme != TPM2_ALG_OAEP) &&
                (pIn->scheme != TPM2_ALG_RSAES) &&
                (pIn->scheme != TPM2_ALG_NULL))
        {
            rc = TSS2_SYS_RC_BAD_VALUE;
            DB_PRINT("%s.%d RSA Key does not contain default scheme,"
                    "Invalid scheme provided for signature., rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        inScheme.scheme = pIn->scheme;

        if (TPM2_ALG_OAEP == pIn->scheme)
        {
            if ((pIn->hashAlg != TPM2_ALG_SHA1) &&
                    (pIn->hashAlg != TPM2_ALG_SHA256) &&
                    (pIn->hashAlg != TPM2_ALG_SHA384) &&
                    (pIn->hashAlg != TPM2_ALG_SHA512))
            {
                rc = TSS2_SYS_RC_BAD_VALUE;
                DB_PRINT("%s.%d Invalid hashAlg for OAEP encryption, rc 0x%02x = %s\n",
                        __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
                goto exit;
            }

            inScheme.details.oaep.hashAlg = pIn->hashAlg;
        }
    }
    else
    {
        if ((pPublic->parameters.rsaDetail.scheme.scheme != TPM2_ALG_OAEP) &&
                (pPublic->parameters.rsaDetail.scheme.scheme != TPM2_ALG_RSAES) &&
                (pPublic->parameters.rsaDetail.scheme.scheme != TPM2_ALG_NULL))
        {
            rc = TSS2_SYS_RC_BAD_VALUE;
            DB_PRINT("%s.%d Invalid RSA decryption key scheme, rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        inScheme.scheme = pPublic->parameters.rsaDetail.scheme.scheme;

        if (TPM2_ALG_OAEP == pPublic->parameters.rsaDetail.scheme.scheme)
        {
            if ((pPublic->parameters.rsaDetail.scheme.details.oaep.hashAlg != TPM2_ALG_SHA1) &&
                    (pPublic->parameters.rsaDetail.scheme.details.oaep.hashAlg != TPM2_ALG_SHA256) &&
                    (pPublic->parameters.rsaDetail.scheme.details.oaep.hashAlg != TPM2_ALG_SHA384) &&
                    (pPublic->parameters.rsaDetail.scheme.details.oaep.hashAlg != TPM2_ALG_SHA512))
            {
                rc = TSS2_SYS_RC_BAD_VALUE;
                DB_PRINT("%s.%d Invalid hashAlg for OAEP encryption, rc 0x%02x = %s\n",
                        __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
                goto exit;
            }

            inScheme.details.oaep.hashAlg =
                    pPublic->parameters.rsaDetail.scheme.details.oaep.hashAlg;
        }
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

    if (encrypt)
    {
        rsaEncryptIn.pObjectHandle = pKeyHandle;
        rsaEncryptIn.pInScheme = &inScheme;
        rsaEncryptIn.pMessage = &pIn->message;
        rsaEncryptIn.pLabel = &pIn->label;

        rc = SAPI2_ASYM_RSAEncrypt(pCtx->pSapiCtx, &rsaEncryptIn, &rsaEncryptOut);
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed to Encrypt message."
                    ", rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        pOut->encryptedData = rsaEncryptOut.outData;
    }
    else
    {
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

        rsaDecryptIn.pObjectHandle = pKeyHandle;
        rsaDecryptIn.pInScheme = &inScheme;
        rsaDecryptIn.pCipherText = &pIn->message;
        rsaDecryptIn.pLabel = &pIn->label;
        rsaDecryptIn.pAuthSession = pAuthSession;
        rsaDecryptIn.pAuthObjectHandle = &pKey->authValue;

        rc = SAPI2_ASYM_RSADecrypt(pCtx->pSapiCtx, &rsaDecryptIn, &rsaDecryptOut);
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed to Decrypt message."
                    ", rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
        pOut->encryptedData = rsaDecryptOut.message;
    }
    rc = TSS2_RC_SUCCESS;
exit:
    if (pKey)
    {
        flushObjectIn.objName = pKey->objectName;
        exit_rc = FAPI2_CONTEXT_flushObject(pCtx, &flushObjectIn);
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

    if (pKeyHandle)
        exit_rc = FAPI2_UTILS_destroyHandle(pCtx, &pKeyHandle);

    if (TSS2_RC_SUCCESS == rc)
        rc = exit_rc;

    return rc;
}

TSS2_RC FAPI2_ASYM_RSAencrypt(
        FAPI2_CONTEXT *pCtx,
        AsymRsaEncryptIn *pIn,
        AsymRsaEncryptOut *pOut
)
{
    return FAPI2_ASYM_RSAEncryptDecryptEx(pCtx, pIn, pOut, TRUE);
}

/*
 * This function decrypts a given cipher text using the given key. THis is a
 * private key operation and the key's authValue is expected to be set when
 * this API is called.
 */
TSS2_RC FAPI2_ASYM_RSAdecrypt(
        FAPI2_CONTEXT *pCtx,
        AsymRsaDecryptIn *pIn,
        AsymRsaDecryptOut *pOut
)
{
    AsymRsaEncryptIn in = { 0 };
    AsymRsaEncryptOut out = { 0 };
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;

    if (!pCtx || !pIn || !pOut)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    TPM2B_SIZE_CHECK(&pIn->cipherText, TPM2B_MAX_SIZE(&pIn->cipherText));

    in.keyName = pIn->keyName;
    in.label = pIn->label;
    in.message = pIn->cipherText;
    in.scheme = pIn->scheme;
    in.hashAlg = pIn->hashAlg;

    rc = FAPI2_ASYM_RSAEncryptDecryptEx(pCtx, &in, &out, FALSE);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to Decrypt message."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pOut->plainText = out.encryptedData;

    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}

/*
 * This API can be used to get the public key of a loaded TPM key.
 */
TSS2_RC FAPI2_ASYM_getPublicKey(
        FAPI2_CONTEXT *pCtx,
        AsymGetPublicKeyIn *pIn,
        AsymGetPublicKeyOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TSS2_RC exit_rc = TSS2_RC_SUCCESS;
    FAPI2_OBJECT *pKey = NULL;
    TPMT_PUBLIC *pPublic = NULL;
    ContextFlushObjectIn flushObjectIn = { 0 };

    if (!pCtx || !pIn || !pOut)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
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

    pPublic = &pKey->public.objectPublic.publicArea;

    if ((pPublic->type != TPM2_ALG_RSA) && (pPublic->type != TPM2_ALG_ECC))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Key is not an RSA or ECC asymmetric key, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
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
    if (pKey)
    {
        flushObjectIn.objName = pKey->objectName;
        exit_rc = FAPI2_CONTEXT_flushObject(pCtx, &flushObjectIn);
    }

    if (TSS2_RC_SUCCESS == rc)
        rc = exit_rc;

    return rc;
}

TSS2_RC FAPI2_ASYM_DuplicateKey(
        FAPI2_CONTEXT *pCtx,
        FAPI2_DuplicateIn *pIn,
        FAPI2B_DUPLICATE *pSerializedDup
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TSS2_RC exit_rc = TSS2_RC_SUCCESS;
    MSTATUS status = ERR_GENERAL;
    MOCTPM2_OBJECT_HANDLE *pKeyHandle = NULL;
    LoadExternalIn   newParent = { 0 };
    LoadExternalOut  parentHandle = {0};
    ContextFlushObjectIn flushObjectIn = { 0 };
    MOCTPM2_OBJECT_HANDLE *pAuthSession = NULL;
    TPMT_PUBLIC *pPublic = NULL;
    TPM2B_PUBLIC_BLOB *pNewParent = NULL;
    FAPI2_OBJECT *pObject = NULL;
    TPM2B_PUBLIC newParentkey = { 0 };
    PolicyAuthNode defaultPolicy = { 0 };
    PolicyAuthNode *pObjectPolicy = NULL;
    ubyte2 numPolicyTerms = 0;
    ubyte4 serializedSize = 0;
    EaExecutePolicyIn eaExecutePolicyIn = { 0 };
    EaExecutePolicyOut eaExecutePolicyOut = { 0 };
    DuplicateIn dupIn = { 0 };
    DuplicateOut dupOut = { 0 };
    TPM2B_DATA encryptKeyIn = {0};
    TPMT_SYM_DEF_OBJECT symmetricAlg = {0};
    FAPI2_DuplicateOut Fapi2_dupOut = {0};
    
    if ((NULL == pCtx)  || (NULL == pIn) || (NULL == pSerializedDup))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid input pointers, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }
    if(!pIn->pNewParent)
    {
        DB_PRINT("%s.%d New Parent cant be NULL for duplication. ",
                    __FUNCTION__,__LINE__);
        goto exit;
    
    }
    TPM2B_SIZE_CHECK(&pIn->keyName, TPM2B_MAX_SIZE(&pIn->keyName));

    rc = FAPI2_CONTEXT_lookupObject(pCtx, &pIn->keyName, &pObject);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Unable to find key object, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pPublic = &pObject->public.objectPublic.publicArea;
    if(pPublic->objectAttributes & TPMA_OBJECT_FIXEDTPM)
    {
        DB_PRINT("%s.%d Object with FIXEDTPM can not be duplicated ",
                __FUNCTION__,__LINE__);
        rc = TSS2_FAPI_RC_NOT_PERMITTED ;
        goto exit;
    }
    pNewParent = pIn->pNewParent ;
    status = SAPI2_SERIALIZE_serialize(SAPI2_ST_TPM2B_PUBLIC, TAP_SD_OUT,
            (ubyte*)pNewParent->buffer, pNewParent->size,
            (ubyte *)&newParentkey, sizeof(TPM2B_PUBLIC), &serializedSize);
    if (OK != status)
    {
        rc = TSS2_SYS_RC_GENERAL_FAILURE;
        DB_PRINT("%s.%d Failed to deserialize new parent public key, status = %d\n", __FUNCTION__,
                __LINE__, status);
        goto exit;
    }
    
    newParent.pInPublic = &newParentkey ;
    newParent.hierarchy = pIn->newParentHierarchy ;
    
    rc = SAPI2_OBJECT_LoadExternal(pCtx->pSapiCtx, &newParent,
                    &parentHandle);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to load external object, rc 0x%02x = %s\n",
                        __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }


    rc = FAPI2_UTILS_loadObjectTree(pCtx, pObject, &pKeyHandle);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to create object for parent key."
                    ", rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((pObject->numPolicyTerms != 0))
    {
        numPolicyTerms = pObject->numPolicyTerms;
        pObjectPolicy = pObject->objectPolicy;
    }
    else
    {
        numPolicyTerms = 1;
        defaultPolicy.policyType = FAPI2_POLICY_AUTH_VALUE;
        pObjectPolicy = &defaultPolicy;
    }
    rc = FAPI2_UTILS_startPolicySession(pCtx, &pAuthSession, FALSE);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to start auth session"
                    ", rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    eaExecutePolicyIn.numPolicyTerms = numPolicyTerms;
    eaExecutePolicyIn.pObjectPolicy = pObjectPolicy;
    eaExecutePolicyIn.pSession = pAuthSession;
    rc = FAPI2_EA_executePolicy(pCtx, &eaExecutePolicyIn, &eaExecutePolicyOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to execute auth session"
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }
    numPolicyTerms = 1;
    defaultPolicy.policyInfo.policyCC.code = TPM2_CC_Duplicate ;
    defaultPolicy.policyType = FAPI2_POLICY_COMMAND_CODE;
    pObjectPolicy = &defaultPolicy;
    eaExecutePolicyIn.numPolicyTerms = numPolicyTerms;
    eaExecutePolicyIn.pObjectPolicy = pObjectPolicy;
    eaExecutePolicyIn.pSession = pAuthSession;

    rc = FAPI2_EA_executePolicy(pCtx, &eaExecutePolicyIn, &eaExecutePolicyOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to execute auth session"
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }
    symmetricAlg.algorithm = TPM2_ALG_NULL ;
    dupIn.pHandle = pKeyHandle ;
    dupIn.pNewParentHandle = parentHandle.pObjectHandle ;
    dupIn.pAuthHandle =  &(pObject->authValue) ;
    dupIn.pAuthSession = pAuthSession ;
    dupIn.pEncryptKeyIn = &encryptKeyIn ;
    dupIn.pSymmetricAlg = &symmetricAlg ;
    rc = SAPI2_OBJECT_DuplicateKey(pCtx->pSapiCtx, &dupIn, &dupOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to execute Duplicate function"
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }
    Fapi2_dupOut.duplicate = dupOut.duplicate ;
    Fapi2_dupOut.encryptionKeyOut = dupOut.encryptionKeyOut ;
    Fapi2_dupOut.outSymSeed = dupOut.outSymSeed ;
    Fapi2_dupOut.symmetricAlg = symmetricAlg;
    Fapi2_dupOut.objectPublic = pObject->public.objectPublic ;
    rc = FAPI2_UTILS_serialize_Duplicate(&Fapi2_dupOut,
                      pSerializedDup) ;
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to serialize Duplicate structure"
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    exit:
    if (pAuthSession)
    {
        exit_rc = FAPI2_UTILS_closeSession(pCtx, &pAuthSession);
        if (TSS2_RC_SUCCESS == rc)
            rc = exit_rc;
    }
    if (pObject)
    {
        flushObjectIn.objName = pObject->objectName;
        exit_rc = FAPI2_CONTEXT_flushObject(pCtx, &flushObjectIn);
        if (TSS2_RC_SUCCESS == rc)
            rc = exit_rc;
    }
    if (pKeyHandle)
    {
        exit_rc = FAPI2_UTILS_destroyHandle(pCtx, &pKeyHandle);
        if (TSS2_RC_SUCCESS == rc)
            rc = exit_rc;
    }
    if (parentHandle.pObjectHandle)
        exit_rc = FAPI2_UTILS_destroyHandle(pCtx, &parentHandle.pObjectHandle);

    if (TSS2_RC_SUCCESS == rc)
        rc = exit_rc;

    return rc ;
    
}

TSS2_RC FAPI2_ASYM_ImportDuplicateKey(
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
    AsymGetPublicKeyIn pubKeyIn = { 0 };
    AsymGetPublicKeyOut pubKeyOut = { 0 };
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
    createObjectIn.numPolicyTerms = 0;
    createObjectIn.pObjectPolicy = NULL;

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

    pubKeyIn.keyName = loadOut.objName;
    rc = FAPI2_ASYM_getPublicKey(pCtx, &pubKeyIn, &pubKeyOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to get public key, "
                "rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pOut->keyName = loadOut.objName;
    pOut->keyAlg = pubKeyOut.keyAlg;
    pOut->publicKey = pubKeyOut.publicKey;

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
