/**
 * @file fapi2_sym.h
 * @brief This file contains code and structures required for creating and using the TPM2
 * as a symmetric crypto engine.
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
#ifndef __FAPI2_SYM_H__
#define __FAPI2_SYM_H__

#include "../../../../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_TPM2__))
#include "../tpm2_types.h"
#include "fapi2_context.h"

/*
 * This API creates a symmetric key that can be used for encryption/decryption.
 * The key created through this API cannot be used for signing.
 */
MOC_EXTERN TSS2_RC FAPI2_SYM_createCipherKey(
        FAPI2_CONTEXT *pCtx,
        SymCreateCipherKeyIn *pIn,
        SymCreateCipherKeyOut *pOut
);

/*
 * This API creates a symmetric key that can be used for symmetric signing(ex: HMAC, CMAC etc).
 * The key created through this API cannot be used for encryption/decryption.
 * The size of the hmac key created depends on the nameAlg for a given object.
 * The default nameAlg in a FAPI2 context is SHA256, so the size of the HMAC
 * key created is 256 bits. The key size can be changed by changing the nameAlg
 * in a FAPI2 context. Changing of nameAlg is not supported currently so a
 * symmetric signing key has a size of 256 bits.
 */

MOC_EXTERN TSS2_RC FAPI2_SYM_createSigningKey(
        FAPI2_CONTEXT *pCtx,
        SymCreateSigningKeyIn *pIn,
        SymCreateSigningKeyOut *pOut
);

/*
 * This API uses a symmetric key in the TPM to encrypt or decrypt caller provided data
 * in the caller specified mode.
 */
MOC_EXTERN TSS2_RC FAPI2_SYM_encryptDecrypt(
        FAPI2_CONTEXT *pCtx,
        SymEncryptDecryptIn *pIn,
        SymEncryptDecryptOut *pOut
);

/*
 * This API uses a symmetric key in the TPM to sign(HMAC, CMAC etc) a digest provided
 * by the caller. Currently only HMAC is supported.
 */
MOC_EXTERN TSS2_RC FAPI2_SYM_sign(
        FAPI2_CONTEXT *pCtx,
        SymSignIn *pIn,
        SymSignOut *pOut
);

/*
 * This API uses a symmetric key to verify a symmetric signature(HMAC, CMAC etc) on a digest
 * provided by the caller.
 */
MOC_EXTERN TSS2_RC FAPI2_SYM_verifySig(
        FAPI2_CONTEXT *pCtx,
        SymVerifySigIn *pIn,
        SymVerifySigOut *pOut
);

typedef struct {
    TPM2B_AUTH *pKeyAuth;

    /*
     * Symmetric Alg that will be used with the Symmetric Key. This can be:
     * TPM2_ALG_AES - For AES encryption/decryption Keys
     * Only AES is supported by FAPI currently. This field is present to expand support
     * to other symmetric ciphers in the future.
     * TPM2_ALG_HMAC - performs HMAC signature.
     * As of now only HMAC signature is supported. Other signature schemes may be added
     * in the future.
     */
    TPM2_ALG_ID symAlg;

    /*
     * Length of the symmetric key in bits. This can be 128, 192 or 256 bits. Other
     * values will return errors. A given TPM may or may not implement any
     * or all of these key sizes. These are the key sizes that FAPI supports.
     */
    ubyte2 keyBits;

    /*
     * Mode of operation for the symmetric cipher. The following values are acceptable:
     * TPM2_ALG_CTR, TPM2_ALG_OFB, TPM2_ALG_CBC, TPM2_ALG_CFB, TPM2_ALG_ECB.
     * TPM2_ALG_NULL if the mode will be supplied during the invocation of the encrypt/decrypt
     * API. This option can be used in case the key is expected to be used with multiple
     * modes.
     * Note that a given TPM may or may not implement any or all of these modes. These
     * are the modes that FAPI is aware of and supports.
     */
    TPMI_ALG_SYM_MODE symMode;

    /*
     * Hash algorithm to be used when signing. The valid values are:
     * TPM2_ALG_SHA256, TPM2_ALG_SHA384 and TPM2_ALG_SHA512. Note that a given TPM
     * may not support any or all of the above algorithms. These are the algorithms
     * that FAPI is aware of and supports.
     * This is only used if sigScheme is a valid scheme such as TPM2_ALG_HMAC, and is ignored
     * otherwise.
     */
    TPMI_ALG_HASH hashAlg;

    ubyte *pSymKeyBuffer;
    ubyte4 symKeyBufferLen;

    ubyte2 numPolicyTerms;
    PolicyAuthNode *pPolicy;

} FapisSymCreateExternalKeyIn;

typedef struct {
    FAPI2_OBJECT *pKey;
} FapiSymCreateExternalKeyOut;

#define FAPI2_HMAC_MAX_SIZE  64

MOC_EXTERN TSS2_RC FAPI2_SYM_createExternalSymKey(
    FAPI2_CONTEXT *pCtx,
    FapisSymCreateExternalKeyIn  *pIn,
    SymCreateKeyOut *pOut
);

MOC_EXTERN TSS2_RC FAPI2_SYM_ImportDuplicateKey(
    FAPI2_CONTEXT *pCtx,
    FAPI2_ImportIn *pIn,
    FAPI2_ImportOut *pOut
);

#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */
#endif /* __FAPI2_SYM_H__ */
