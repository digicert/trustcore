/*
 * ecc_edwards_dsa.h
 *
 * Header for Edward's Curve Digital Signature (edDSA) operations.
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

/**
 * @file       ecc_edwards_dsa.h
 *
 * @brief      Header for Edward's curve Digital Signature (EDDSA) related methods.
 *
 * @details    Documentation file for Edward's curve Digital Signature (EDDSA) related methods.
 *
 * @flags      To enable the methods in this file one must define
 *             + \c \__ENABLE_MOCANA_ECC__
 *             and at least one or more of the following flags
 *             + \c \__ENABLE_MOCANA_ECC_EDDSA_25519__
 *             + \c \__ENABLE_MOCANA_ECC_EDDSA_448__
 *
 * @filedoc    ecc_edwards_dsa.h
 */

/*------------------------------------------------------------------*/

#ifndef __ECC_EDWARDS_DSA_HEADER__
#define __ECC_EDWARDS_DSA_HEADER__

#include "../crypto/ecc_edwards_keys.h"

#ifdef __cplusplus
extern "C" {
#endif

/* verifyStatus bit positions for edDSA_VerifySignature */
#define MOCANA_EDDSA_VERIFY_FAIL             0x00000001
#define MOCANA_EDDSA_VERIFY_R_INVALID        0x00000002
#define MOCANA_EDDSA_VERIFY_S_INVALID        0x00000004
#define MOCANA_EDDSA_VERIFY_PUB_KEY_INVALID  0x00000008

typedef struct edDSA_CTX
{

    ubyte *pPubKey;
    union
    {
        ubyte *pPrivKey;   /* needed for sign only */
        ubyte *pSignature; /* needed for verify only */
    };
    ubyte *pCtx;
    ubyte4 ctxLen;
    edECCCurve curve;
    BulkHashAlgo shaSuite;
    union
    {
        void *pShaCtx;
        void *pECCKey;     /* access for alternative implementations */
    };
    ubyte4 verifyStatus;   /* needed for verify only */
    byteBoolean initialized;
    byteBoolean preHash;
    ubyte4 enabled;        /* flag for alternative implementations */

} edDSA_CTX;
  

/**
 * @brief    Signs a message via the EdDSA algorithm.
 *
 * @details  Signs a message via the EdDSA algorithm. The appropriate SHA Suite must
 *           be passed in. This is SHA2-512 for curve25519 and SHA3-SHAKE256 for
 *           curve448.
 *
 * @param pKey          Pointer to the private signing key.
 * @param pMessage      Buffer holding the message to be signed.
 * @param messageLen    The length of the message in bytes.
 * @param pSignature    Buffer that will hold the resulting signature.
 * @param bufferSize    The length of the buffer \c pSignature in bytes.
 * @param pSignatureLen Contents will be set to the number of bytes actually written to
 *                      the \c pSignature buffer.
 * @param pShaSuite     The SHA suite used by the EdDSA algorithm. This must be
 *                      SHA2-512 for curve25519 and SHA3-SHAKE256 for curve448.
 * @param preHash       Set to \c TRUE (1) for EdDSAph "pre-hash" mode.
 * @param pCtx          Optional. For curve25519 set to non-null for Ed25519ctx mode.
 *                      For curve448 the context is optional for pure Ed448 or pre-hash mode.
 * @param ctxLen        The length of the context in bytes. This cannot be more than 255.
 * @param pExtCtx       An extended context reserved for future use.
 *
 * @return      \c OK (0) if successful, otherwise a negative number error
 *              code from merrors.h
 */
MOC_EXTERN MSTATUS edDSA_Sign(MOC_ECC(hwAccelDescr hwAccelCtx) edECCKey *pKey, ubyte *pMessage, ubyte4 messageLen, ubyte *pSignature,
                              ubyte4 bufferSize, ubyte4 *pSignatureLen, BulkHashAlgo *pShaSuite, byteBoolean preHash, ubyte *pCtx, ubyte4 ctxLen, void *pExtCtx);

/**
 * @brief    A one shot verify of a message via the EdDSA algorithm.
 *
 * @details  A one shot verify of a message via the EdDSA algorithm. The appropriate SHA
 *           Suite must be passed in. This is SHA2-512 for curve25519 and SHA3-SHAKE256 for
 *           curve448.
 *
 * @param pKey          Pointer to the public key.
 * @param pMessage      Buffer holding the message to be verified.
 * @param messageLen    The length of the message in bytes.
 * @param pSignature    Buffer holding the signature to be verified.
 * @param signatureLen  The length of the signature in bytes.
 * @param pVerifyStatus Contents will be set to 0 for a valid signature and a nonzero value
 *                      for an invalid signature.
 * @param pShaSuite     The SHA suite used by the EdDSA algorithm. This must be
 *                      SHA2-512 for curve25519 and SHA3-SHAKE256 for curve448.
 * @param preHash       Set to \c TRUE (1) for EdDSAph "pre-hash" mode.
 * @param pCtx          Optional. For curve25519 set to non-null for Ed25519ctx mode.
 *                      For curve448 the context is optional for pure Ed448 or pre-hash mode.
 * @param ctxLen        The length of the context in bytes. This cannot be more than 255.
 * @param pExtCtx       An extended context reserved for future use.
 *
 * @warning     Be sure to check for both a return status of OK and a verify status
 *              of 0 before accepting that a signature is valid.
 *
 * @return      \c OK (0) if successful execution of the method, otherwise a negative number error
 *              code from merrors.h
 */
MOC_EXTERN MSTATUS edDSA_VerifySignature(MOC_ECC(hwAccelDescr hwAccelCtx) edECCKey *pKey, ubyte *pMessage, ubyte4 messageLen, ubyte *pSignature,
                                         ubyte4 signatureLen, ubyte4 *pVerifyStatus, BulkHashAlgo *pShaSuite, byteBoolean preHash, ubyte *pCtx, ubyte4 ctxLen, void *pExtCtx);


/**
 * @brief    Initializes an \c edDSA_CTX for use in the EdDSA sign algorithm.
 *
 * @details  Initializes an \c edDSA_CTX for use in the EdDSA sign algorithm. The appropriate SHA
 *           Suite must be passed in. This is SHA2-512 for curve25519 and SHA3-SHAKE256 for
 *           curve448.
 *
 * @param pEdDSA_ctx    Pointer to the context to be initialized.
 * @param pKey          Pointer to the public key.
 * @param pSignature    Buffer holding the signature to be verified.
 * @param signatureLen  The length of the signature in bytes.
 * @param pShaSuite     The SHA suite used by the EdDSA algorithm. This must be
 *                      SHA2-512 for curve25519 and SHA3-SHAKE256 for curve448.
 * @param pCtx          Optional. For curve25519 set to non-null for Ed25519ctx mode.
 *                      For curve448 the context is optional for pre-hash mode.
 * @param ctxLen        The length of the context in bytes. This cannot be more than 255.
 * @param pExtCtx       An extended context reserved for future use.
 *
 * @return            \c OK (0) if successful, otherwise a negative number error
 *                    code from merrors.h
 */
MOC_EXTERN MSTATUS edDSA_initSignPreHash(MOC_ECC(hwAccelDescr hwAccelCtx) edDSA_CTX *pEdDSA_ctx, edECCKey *pKey, BulkHashAlgo *pShaSuite, ubyte *pCtx, ubyte4 ctxLen, void *pExtCtx);

/**
 * @brief    Initializes an \c edDSA_CTX for use in the EdDSA verify algorithm.
 *
 * @details  Initializes an \c edDSA_CTX for use in the EdDSA verify algorithm. The appropriate SHA
 *           Suite must be passed in. This is SHA2-512 for curve25519 and SHA3-SHAKE256 for
 *           curve448.
 *
 * @param pEdDSA_ctx    Pointer to the context to be initialized.
 * @param pKey          Pointer to the public key.
 * @param pSignature    Buffer holding the signature to be verified.
 * @param signatureLen  The length of the signature in bytes.
 * @param pShaSuite     The SHA suite used by the EdDSA algorithm. This must be
 *                      SHA2-512 for curve25519 and SHA3-SHAKE256 for curve448.
 * @param preHash       Set to \c TRUE (1) for EdDSAph "pre-hash" mode.
 * @param pCtx          Optional. For curve25519 set to non-null for Ed25519ctx mode.
 *                      For curve448 the context is optional for pure Ed448 or pre-hash mode.
 * @param ctxLen        The length of the context in bytes. This cannot be more than 255.
 * @param pExtCtx       An extended context reserved for future use.
 *
 * @return            \c OK (0) if successful, otherwise a negative number error
 *                    code from merrors.h
 */
MOC_EXTERN MSTATUS edDSA_initVerify(MOC_ECC(hwAccelDescr hwAccelCtx) edDSA_CTX *pEdDSA_ctx, edECCKey *pKey, ubyte *pSignature,
                                    ubyte4 signatureLen, BulkHashAlgo *pShaSuite, byteBoolean preHash, ubyte *pCtx, ubyte4 ctxLen, void *pExtCtx);

/**
 * @brief    Updates an \c edDSA_CTX with data.
 *
 * @details  Updates an \c edDSA_CTX with some portion of the data to be signed or verified.
 *           You may call this API as many times as is appropriate.
 *
 * @param pEdDSA_ctx    Pointer to a previous initialized context.
 * @param pMessage      Buffer holding the message or portion of the message to be signed or verified.
 * @param messageLen    The length of the message or portion of the message in bytes.
 * @param pExtCtx       An extended context reserved for future use.
 *
 * @return            \c OK (0) if successful, otherwise a negative number error
 *                    code from merrors.h
 */
MOC_EXTERN MSTATUS edDSA_update(MOC_ECC(hwAccelDescr hwAccelCtx) edDSA_CTX *pEdDSA_ctx, ubyte *pMessage, ubyte4 messageLen, void *pExtCtx);

/**
 * @brief    Finalizes an \c edDSA_CTX and outputs the signature.
 *
 * @details  Finalizes an \c edDSA_CTX and outputs the signature.
 *
 * @param pEdDSA_ctx    Pointer to a previous initialized context.
 * @param pSignature    Buffer that will hold the resulting signature.
 * @param bufferSize    The length of the buffer \c pSignature in bytes.
 * @param pSignatureLen Contents will be set to the number of bytes actually written to
 *                      the \c pSignature buffer.
 * @param pExtCtx       An extended context reserved for future use.
 *
 * @return            \c OK (0) if successful, otherwise a negative number error
 *                    code from merrors.h
 */
MOC_EXTERN MSTATUS edDSA_finalSign(MOC_ECC(hwAccelDescr hwAccelCtx) edDSA_CTX *pEdDSA_ctx, ubyte *pSignature, ubyte4 bufferSize, ubyte4 *pSignatureLen, void *pExtCtx);

/**
 * @brief    Finalizes an \c edDSA_CTX context and writes the verify status.
 *
 * @details  Finalizes an \c edDSA_CTX context and writes the verify status.
 *
 * @param pEdDSA_ctx    Pointer to a previous initialized and updated context.
 * @param pVerifyStatus Contents will be set to 0 for a valid signature and a nonzero value
 *                      for an invalid signature.
 * @param pExtCtx       An extended context reserved for future use.
 *
 * @warning             Be sure to check for both a return status of OK and a verify status
 *                      of 0 before accepting that a signature is valid.
 *
 * @return            \c OK (0) if successful, otherwise a negative number error
 *                    code from merrors.h
 */
MOC_EXTERN MSTATUS edDSA_finalVerify(MOC_ECC(hwAccelDescr hwAccelCtx) edDSA_CTX *pEdDSA_ctx, ubyte4 *pVerifyStatus, void *pExtCtx);

#ifdef __cplusplus
}
#endif

#endif /* __ECC_EDWARDS_DSA_HEADER__ */
