/**
 * @file fapi2_credential.h
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
#ifndef __FAPI2_CREDENTIAL_H__
#define __FAPI2_CREDENTIAL_H__

#include "../../../../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_TPM2__))
#include "../tpm2_types.h"
#include "fapi2_context.h"

/*
 * This API is used as a part of the TPM specification credential protection protocol,
 * to activate a credential supplied by a CA. Activation of a credential typically means
 * a successful unwrapping of a symmetric key that was used by the CA to wrap a certificate.
 * The secret can only be unwrapped if the TPM has the asymmetric encryption key and the key
 * for which the credential applies, loaded inside the TPM.
 * See TPM2 specs for more details on the credential protection protocol.
 */
MOC_EXTERN TSS2_RC FAPI2_CREDENTIAL_activate(
        FAPI2_CONTEXT *pCtx,
        CredentialActivateIn *pIn,
        CredentialActivateOut *pOut
);

/*
 * This is a helper API that can be used by a credential provider(that has TPM hardware/emulator),
 * to create a credential blob per the credential protection protocol, that can only
 * be decrypted by the TPM to which the secret is wrapped. The typical use for this
 * API is on a CA server that has a TPM or a TPM emulator and does not want to
 * implement the credential creation protocol, since it is already available on the
 * TPM. This is also useful for testing the make/activate credential protocol.
 * See TPM2 specs for more details on the credential protection protocol.
 * This API requires a context since it uses the TPM directly to create the credential blob.
 */
MOC_EXTERN TSS2_RC FAPI2_CREDENTIAL_make(
        FAPI2_CONTEXT *pCtx,
        CredentialMakeIn *pIn,
        CredentialMakeOut *pOut
);

/*
 * This API is used in the privacy CA protocol of generating and activating a credential
 * for a TPM key. This returns a base 64 encoded blob of data that contains the public
 * attributes of an encryption key(EK) and of the key for which the credential is being
 * requested for. The blob is then used by the credential provider(typically privacy CA)
 * to determine if a credential can be provided for the given key. The format of the blob
 * is specific to Mocana and is not a TCG standard. The blob is consumed by a companion
 * library, that may be used on the server, to unwrap and use the blob.
 * This API is restrictive in what keys it allows the blob to be created for, ie: it
 * expects the EK to be a restricted decryption key, which is fixed to a particular TPM
 * and whose sensitive data originated inside the TPM.
 * The key for which the credential is being requested for must be a restricted signing key
 * fixed to a TPM and whose sensitive data originated in the TPM.
 */
MOC_EXTERN TSS2_RC FAPI2_CREDENTIAL_getCSRAttr(
        FAPI2_CONTEXT *pCtx,
        CredentialGetCsrAttrIn *pIn,
        CredentialGetCsrAttrOut *pOut
);

/*
 * This API can be used to recover the secret wrapped by a credential provider for
 * a given key and a TPM encryption key. This is merely a wrapper around
 * FAPI2_CREDENTIAL_activate. It decodes the base64 blob and calls the
 * FAPI2_CREDENTIAL_activate API to return the secret.
 */
MOC_EXTERN TSS2_RC FAPI2_CREDENTIAL_unwrapSecret(
        FAPI2_CONTEXT *pCtx,
        CredentialUnwrapSecretIn *pIn,
        CredentialUnwrapSecretOut *pOut
);
#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */
#endif /* __FAPI2_CREDENTIAL_H__ */
