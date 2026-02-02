/**
 * @file fapi2_asym_internal.h
 * @brief This file contains code and structures required for creating
 * and operating on TPM asymmetric keys. This is an internal file and
 * must not be used by applications.
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
#ifndef __FAPI2_ASYM_INTERNAL_H__
#define __FAPI2_ASYM_INTERNAL_H__

#include "../../../../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_TPM2__))
#include "../tpm2_types.h"
#include "fapi2_context.h"

typedef struct {
    /*
     * Permanent hierarchy handle, under which the primary
     * object must be created. This can be TPM2_RH_OWNER for the
     * object to be created in the owner hierarchy or TPM2_RH_ENDORSEMENT
     * for creating the object in the endorsement hierarchy. This
     * may be TPM2_RH_NULL, in which case the object will be available
     * for one boot cycle. The authValue for the hierarchy under which
     * the key is being created must be set in the FAPI2_CONTEXT passed
     * to this API.
     */
    TPMI_RH_HIERARCHY hierarchy;

    /*
     * Each bit in the 32 bit number, represents a PCR. Setting Bit 0
     * includes PCR0, bit 1 includes PCR 1 and so on.
     * The PCR selection selects what PCR's need to be included in
     * the creation data returned by the TPM2 upon creation of an object.
     * The creation data can later be used to Certify an objects creation
     * using TPM2_CertifyCreation.
     */
    ubyte4 pcrSelection;

    /*
     * authValue of the key being created. This cannot be NULL but can be
     * a TPM2B_AUTH of size 0.
     * The size of the authValue can be no larger than the name
     * algorithm of the object.
     * SHA256 by used by default, so the authValue can be no longer
     * than 32 bytes.
     */
    TPM2B_AUTH *pNewKeyAuth;

    /*
     * Data that will be included in the creation data for this
     * object to provide permanent, verifiable linkage between
     * this object and some object owner data.
     * This cannot be NULL but can be a TPM2B_DATA of size 0.
     */
    TPM2B_DATA *pOutsideInfo;

    /*
     * Asymmetric Key information.
     * Identifies the key algorithm of the key being created.
     * Acceptable values are TPM2_ALG_RSA, TPM2_ALG_ECC.
     * This is used to select the structure in the keyInfo.
     */
    TPMI_ALG_PUBLIC keyAlg;

    /*
     * See documentation for FAPI2_RSA_INFO and FAPI2_ECC_INFO
     */
    union {
        FAPI2_RSA_INFO rsaInfo;
        FAPI2_ECC_INFO eccInfo;
    } keyInfo;

    /*
     * During creation of primary keys, external entropy can be provided.
     * This is useful in situations where a user does not trust the hierarchy
     * seed to have enough entropy or simply to create different primary
     * keys with the same template, for example, creating multiple RSA AK's
     * or ECC AK's. If external entropy is not provided, the same key is
     * created for the same template, which is not ideal behavior.
     * The sizes are bound by the structure size of the TPM2B's included
     * in TPM2B_PUBLIC_KEY_RSA and TPMS_ECC_POINT.
     * keyAlg is used to select the union.
     */
    union {
        TPM2B_PUBLIC_KEY_RSA rsaEntropy;
        TPMS_ECC_POINT eccEntropy;
    } externalEntryopy;
    /*
     * The handle location at which the object will be made persistent.
     * This API will use the owner password to make an object persistent.
     * Under the owner hierarchy, the following are acceptable values:
     * 0x81000000 - 0x8100FFFF
     * Under the endrosement hierarchy, the follow are acceptable values:
     * 0x81010000 - 0x8101FFFF
     * These values are reserved per the TCG registry of reserved handles.
     */
    TPMI_DH_PERSISTENT persistentHandle;

    /*
     * Set this to true to disable the TPM's dictionary attack protection
     * on the key.
     */
    byteBoolean disableDA;

    /*
     * Policy nodes. Number of policy terms can be 0 and policy nodes
     * can be NULL. If NULL, the default policy of FAPI2_POLICY_AUTH_VALUE
     * will be used
     */
    ubyte2 numPolicyTerms;
    PolicyAuthNode *pPolicy;

    /*
     * Overrides for default attributes. If this is supplied, this is blindly
     * or'd to the objects attributes before creation. Caller is responsible
     * for being aware of each attribute from the TPM specification.
     */
    TPMA_OBJECT additionalAttributes;
} AsymCreatePrimaryKeyIn;

typedef struct {
    /*
     * The FAPI2_OBJECT structure returned contains information such as
     * authValue, Creation Data, and the public area for the created
     * primary object. This can be serialized and stored(authValue will
     * not be serialized), if the user requires to use the Creation Data
     * in the future. If Creation Data is not important to the caller,
     * the object need not be serialized and stored and the caller only
     * needs to remember the persistent handle for the created primary
     * object. The public area can and will be read off the TPM and the
     * object can be recreated without the creation data, just using the
     * persistent handle.
     */
    FAPI2_OBJECT *pKey;
} AsymCreatePrimaryKeyOut;

typedef struct {
    /*
     * The key object of the parent key.
     * The parent may be a non-persistent or persistent/primary key.
     * If this is a non-persistent key, then all its non-persistent
     * parent keys must be loaded in the FAPI2_CONTEXT, and their
     * authValues set, otherwise key creation will fail.
     * If this key's parent is a primary key, it will be persistent on
     * the TPM and will be used automatically. However, the authValue
     * for the persistent/primary key must be set.
     *
     * If this key is a persistent/primary key:
     * All primary keys are persistent and must be under the
     * owner or endorsement hierarchy,
     * so the acceptable values are between 0x81000000 - 0x8100FFFF(owner
     * hierarchy) or 0x81010000 - 0x8101FFFF(endorsement hierarchy), as
     * created by FAPI2_ASYM_createPrimaryAsymKey. This should typically
     * be the EK or an SRK. The authValue used will be the one present
     * in the provided FAPI2_OBJECT. Use the appropriate API's to set
     * authValues in the FAPI2_OBJECT.
     */
    FAPI2_OBJECT *pParentKey;

    /*
     * Each bit in the 32 bit number, represents a PCR. Setting Bit 0
     * includes PCR0, bit 1 includes PCR 1 and so on.
     * The PCR selection selects what PCR's need to be included in
     * the creation data returned by the TPM2 upon creation of an object.
     * The creation data can later be used to Certify an objects creation
     * using TPM2_CertifyCreation.
     */
    ubyte4 pcrSelection;

    /*
     * authValue of the key being created. This cannot be NULL but can be
     * a TPM2B_AUTH of size 0.
     * The size of the authValue can be no larger than the name
     * algorithm of the object.
     * SHA256 by used by default, so the authValue can be no longer
     * than 32 bytes.
     */
    TPM2B_AUTH *pNewKeyAuth;

    /*
     * Data that will be included in the creation data for this
     * object to provide permanent, verifiable linkage between
     * this object and some object owner data.
     * This cannot be NULL but can be a TPM2B_DATA of size 0.
     */
    TPM2B_DATA *pOutsideInfo;

    /*
     * Asymmetric Key information.
     * Identifies the key algorithm of the key being created.
     * Acceptable values are TPM2_ALG_RSA, TPM2_ALG_ECC.
     * This is used to select the structure in the keyInfo.
     */
    TPMI_ALG_PUBLIC keyAlg;

    /*
     * See documentation for FAPI2_RSA_INFO and FAPI2_ECC_INFO
     */
    union {
        FAPI2_RSA_INFO rsaInfo;
        FAPI2_ECC_INFO eccInfo;
    } keyInfo;

    /*
     * Set this to true to disable the TPM's dictionary attack protection
     * on the key.
     */
    byteBoolean disableDA;
    byteBoolean bEnableBackup ; 

    /*
     * Policy nodes. Number of policy terms can be 0 and policy nodes
     * can be NULL. If NULL, the default policy of FAPI2_POLICY_AUTH_VALUE
     * will be used
     */
    ubyte2 numPolicyTerms;
    PolicyAuthNode *pPolicy;

    /*
     * If newly created key is to be persisted, this value must be set
     */
    ubyte4 objectId;
} AsymCreateChildKeyIn;

typedef struct {
    /*
     * The FAPI2_OBJECT structure returned contains information such as
     * authValue, Creation Data, and the public area for the created
     * object. This can be serialized and stored(authValue will
     * not be serialized). The FAPI2_OBJECT must be provided when the
     * key is being used(to sign,verify etc)
     */
    FAPI2_OBJECT *pKey;
} AsymCreateChildKeyOut;


typedef struct {
    /*
     * authValue to be used for the new asymmetric Key. This MUST be provided
     * and cannot be NULL.
     * The size of the authValue can be no larger than the name
     * algorithm of the object.
     * SHA256 by used by default, so the authValue can be no longer
     * than 32 bytes.
     */
    TPM2B_AUTH *pKeyAuth;

    /*
     * This value must be TPM2_ALG_RSA or TPM2_ALG_ECC. This decides
     * if the TPM loadable key object created is an RSA key or ECC key.
     */
    TPMI_ALG_PUBLIC keyAlg;

    /*
     * Information regarding the asymmetric key to be created.
     * The keyType must be FAPI2_ASYM_TYPE_SIGNING, FAPI2_ASYM_TYPE_DECRYPT
     * or FAPI2_ASYM_TYPE_GENERAL. scheme must be set based on the appropriate
     * keyTYpe as documented in FAPI2_RSA/ECC_INFO.
     */
    union {
        FAPI2_RSA_INFO rsaInfo;
        FAPI2_ECC_INFO eccInfo;
    } keyInfo;

    /*
     * Public key information for the appropriate key type.
     * For RSA keys, the buffer must contain the public modulus.
     * For ECC keys, the buffer must contain the x & y coordinates
     * of the public point. These cannot be NULL or empty buffers.
     */
    union {
        TPM2B_PUBLIC_KEY_RSA    *pRsaPublic;
        TPMS_ECC_POINT          *pEccPublic;
    } publicKey;

    /*
     * Private key information for the appropriate key type. THis
     * is optional and they may be NULL. This would
     * create a TPM loadable object that can perform only public
     * key operations. If the private key is provided, private key
     * operations may be performed using the returned object.
     * If these pointers are not NULL, they must not be an empty
     * buffer. For RSA Keys, the private buffer contains the prime
     * factor P. For ECC, it contains the private key integer.
     */
    union {
        TPM2B_PRIVATE_KEY_RSA           *pRsaPrivate;
        TPM2B_ECC_PARAMETER             *pEccPrivate;
    } privateKey;

    /*
     * Policy nodes. Number of policy terms can be 0 and policy nodes
     * can be NULL. If NULL, the default policy of FAPI2_POLICY_AUTH_VALUE
     * will be used
     */
    ubyte2 numPolicyTerms;
    PolicyAuthNode *pPolicy;

} AsymCreateExternalKeyIn;

typedef struct {
    FAPI2_OBJECT *pKey;
} AsymCreateExternalKeyOut;

typedef struct {
    /*
     * The key provided must be of type FAPI2_ASYM_TYPE_SIGNING,
     * FAPI2_ASYM_TYPE_GENERAL or FAPI2_ASYM_TYPE_ATTESTATION.
     * Other types are invalid. The authValue used is the value that
     * is present in the object structure.
     * If the object was serialized and then deserialized,
     * the key is expected to have the authValue set before
     * this private key operation can be performed.
     */
    FAPI2_OBJECT *pKey;

    /*
     * Digest to be signed.
     */
    TPM2B_DIGEST *pSignDigest;

    /*
     * Ticket produced by TPM2_Hash() or TPM2 hash sequence commands validating
     * that the digest does not start with TPM2_GENERATED_VALUE.
     */
    TPMT_TK_HASHCHECK *pValidationTicket;

    /*
     * Signature scheme. This MUST be provided if the key is of type
     * FAPI2_ASYM_TYPE_GENERAL. For keys of type FAPI2_ASYM_TYPE_SIGNING/ATTESTATION
     * the values provided here will be ignored, and the ones provided during
     * key creation will be used. If no scheme was provided during key creation,
     * the scheme must be provided here.
     * For RSA signatures, valid schemes are:
     *      TPM2_ALG_RSAPSS, TPM2_ALG_RSASSA(PKCS1v5)
     * For ECC signatures, valid schemes are:
     *      TPM2_ALG_ECDSA, TPM2_ALG_ECSCHNORR
     */
    TPMI_ALG_SIG_SCHEME sigScheme;

    /*
     * Hash algorithm to be used with the signing scheme.
     * For RSA signatures: valid values are TPM2_ALG_SHA256, TPM2_ALG_SHA384 and
     * TPM2_ALG_SHA512.
     * For EC signatures: must be TPM2_ALG_NULL. hashAlg is automatically
     * selected.
     * SHA256 is selected for TPM2_ECC_NIST_P192, TPM2_ECC_NIST_P224
     * and TPM2_ECC_NIST_P256.
     * SHA384 for TPM2_ECC_NIST_P384, and SHA512 for TPM2_ECC_NIST_P521.
     */
    TPMI_ALG_HASH hashAlg;
} AsymSignInternalIn;

typedef struct {
    /*
     * This value is TPM2_ALG_RSA or TPM2_ALG_ECC. This serves as the selector
     * for the signature union.
     */
    TPMI_ALG_PUBLIC keyAlg;

    /*
     * rsaSignature contains the signature buffer if the chosen scheme
     * was TPM2_ALG_RSASSA or TPM2_ALG_RSAPSS.
     * eccSignature contains the signature buffer for R and S if the
     * chosen signature scheme was TPM2_ALG_ECDSA or TPM2_ALG_ECSCHNORR.
     * The caller of the API must use the appropriate structure in the
     * union since there is no selector returned(Implicit based on
     * input parameters).
     */
    FAPI2_SIGNATURE_UNION signature;
} AsymSignInternalOut;

/*
 * This is an advanced API, that must only be used when the application
 * writer knows exactly what is being done. This API provides lots of
 * flexibility to be able to create any supported asymmetric key under
 * the endorsement or storage hierarchy. This creates a primary key on the
 * TPM and can be used to create EK's, SRK's, AK's etc.
 * The API expects the hierarchy authValues to be set in the FAPI2_CONTEXT.
 * It is recommended to use the FAPI2_ADMIN_* API's for provisioning the
 * TPM that uses this API with the most commonly used parameters.
 * This API will use the owner password to make an object persistent.
 */
MOC_EXTERN TSS2_RC FAPI2_ASYM_createPrimaryAsymKey(
        FAPI2_CONTEXT *pCtx,
        TPM2B_AUTH *pPlatformAuth,
        AsymCreatePrimaryKeyIn *pIn,
        AsymCreatePrimaryKeyOut *pOut
);

/*
 * This is an advanced API, that must only be used when the application
 * writer knows exactly what is being done. This API provides lots of
 * flexibility to be able to create any supported asymmetric key under
 * ANY primary key in the endorsement or storage hierarchy.
 * It is recommended to use the FAPI_KEY_* API's for key creation since
 * they use the most commonly used parameters.
 * This API creates an asymmetric key under the parent handle specified
 * and returns the key object.
 */
TSS2_RC FAPI2_ASYM_createChildAsymKey(
        FAPI2_CONTEXT *pCtx,
        AsymCreateChildKeyIn *pIn,
        AsymCreateChildKeyOut *pOut
);

/*
 * This is an advanced API that must only be used when the application writer
 * knows exactly what is being done. This API allows the creation of a FAPI2
 * OBJECT that can be loaded in the TPM using TPM2_LoadExternal. This is useful
 * incase the TPM needs to be used as a crypto engine/accelerator. WHen the
 * returned object is used, it will always be loaded in the NULL hierarchy.
 * The returned key can be serialized and deserialized like TPM generated keys.
 */
MOC_EXTERN TSS2_RC FAPI2_ASYM_createExternalAsymKey(
        FAPI2_CONTEXT *pCtx,
        AsymCreateExternalKeyIn *pIn,
        AsymCreateExternalKeyOut *pOut
);

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
);

#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */
#endif /* __FAPI2_ASYM_INTERNAL_H__ */
