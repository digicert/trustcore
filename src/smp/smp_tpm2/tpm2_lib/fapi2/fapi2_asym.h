/**
 * @file fapi2_asym.h
 * @brief This file contains code and structures required for creating
 * and operating on TPM asymmetric keys.
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
#ifndef __FAPI2_ASYM_H__
#define __FAPI2_ASYM_H__

#include "../../../../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_TPM2__))
#include "../tpm2_types.h"
#include "fapi2_context.h"

/*
 * This function creates an asymmetric key as specified by the input parameters
 * and returns a key object that can be used immediately or stored for future
 * usage.
 * The key is created under the storage root key, and the application is
 * expected to have set the password for the SRK in the context,
 * if it is not the well known password.
 */
MOC_EXTERN TSS2_RC FAPI2_ASYM_createAsymKey(
        FAPI2_CONTEXT *pCtx,
        AsymCreateKeyIn *pIn,
        AsymCreateKeyOut *pOut
);

/*
 * This function creates an asymmetric signature on the digest provided by
 * the input parameters.
 */
MOC_EXTERN TSS2_RC FAPI2_ASYM_sign(
        FAPI2_CONTEXT *pCtx,
        AsymSignIn *pIn,
        AsymSignOut *pOut
);

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
MOC_EXTERN TSS2_RC FAPI2_ASYM_restrictedSign(
        FAPI2_CONTEXT *pCtx,
        AsymRestrictedSignIn *pIn,
        AsymRestrictedSignOut *pOut
);

/*
 * This function verifies a given asymmetric signature on the provided digest,
 * using a given key. This is a public key operation, which is done in hardware
 * on the TPM. Hence, a context is required to be able to talk to the hardware.
 * Signature verification can be done in software without having to go to the
 * TPM which will likely be faster, given the overhead of communicating with the
 * TPM, loading key objects etc. This is provided purely for completeness of API
 * and may have some uses for testing applications.
 */
MOC_EXTERN TSS2_RC FAPI2_ASYM_verifySig(
        FAPI2_CONTEXT *pCtx,
        AsymVerifySigIn *pIn,
        AsymVerifySigOut *pOut
);

/*
 * This function encrypts a given message and label(if the scheme supports it)
 * using the given key. THis is a public key operation, which is done in hardware
 * on the TPM. Hence, a context is required to be able to talk to hardware.
 * RSA encryption can be done in software without having to go to the TPM, which
 * will likely be faster.
 */
MOC_EXTERN TSS2_RC FAPI2_ASYM_RSAencrypt(
        FAPI2_CONTEXT *pCtx,
        AsymRsaEncryptIn *pIn,
        AsymRsaEncryptOut *pOut
);

/*
 * This function decrypts a given cipher text using the given key. THis is a
 * private key operation and the key's authValue is expected to be set when
 * this API is called.
 */
MOC_EXTERN TSS2_RC FAPI2_ASYM_RSAdecrypt(
        FAPI2_CONTEXT *pCtx,
        AsymRsaDecryptIn *pIn,
        AsymRsaDecryptOut *pOut
);

/*
 * This API can be used to get the public key of a loaded TPM key.
 */
MOC_EXTERN TSS2_RC FAPI2_ASYM_getPublicKey(
        FAPI2_CONTEXT *pCtx,
        AsymGetPublicKeyIn *pIn,
        AsymGetPublicKeyOut *pOut
);

MOC_EXTERN TSS2_RC FAPI2_ASYM_DuplicateKey(
        FAPI2_CONTEXT *pCtx,
        FAPI2_DuplicateIn *pIn,
        FAPI2B_DUPLICATE *pSerializedDup
);

MOC_EXTERN TSS2_RC FAPI2_ASYM_ImportDuplicateKey(
        FAPI2_CONTEXT *pCtx,
        FAPI2_ImportIn *pIn,
        FAPI2_ImportOut *pOut
);

#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */
#endif /* __FAPI2_ASYM_H__ */
