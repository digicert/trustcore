/*
 * crypto_interface_eddsa.h
 *
 * Cryptographic Interface header file for declaring EdDSA functions
 * for the Crypto Interface.
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
@file       crypto_interface_eddsa.h
@brief      Cryptographic Interface header file for declaring EdDSA functions.
@details    Cryptographic Interface header file for declaring EdDSA functions.

@filedoc    crypto_interface_eddsa.h
*/
#ifndef __CRYPTO_INTERFACE_EDDSA_HEADER__
#define __CRYPTO_INTERFACE_EDDSA_HEADER__

#include "../cap/capasym.h"

#ifdef __cplusplus
extern "C" {
#endif
    
/**
 * @brief    Signs a message via the EdDSA algorithm.
 *
 * @details  Signs a message via the EdDSA algorithm.
 *
 * @param pKey          Pointer to the private signing key.
 * @param pMessage      Buffer holding the message to be signed.
 * @param messageLen    The length of the message in bytes.
 * @param pSignature    Buffer that will hold the resulting signature.
 * @param bufferSize    The length of the buffer \c pSignature in bytes.
 * @param pSignatureLen Contents will be set to the number of bytes actually written to
 *                      the \c pSignature buffer.
 * @param preHash       Set to \c TRUE (1) for EdDSAph "pre-hash" mode.
 * @param pCtx          Optional. For curve25519 set to non-null for Ed25519ctx mode.
 *                      For curve448 the context is optional for pure Ed448 or pre-hash mode.
 * @param ctxLen        The length of the context in bytes. This cannot be more than 255.
 * @param pExtCtx       An extended context reserved for future use.
 *
 * @return      \c OK (0) if successful, otherwise a negative number error
 *              code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EdDSA_Sign(MOC_ECC(hwAccelDescr hwAccelCtx) ECCKey *pKey, ubyte *pMessage, ubyte4 messageLen, ubyte *pSignature,
                                               ubyte4 bufferSize, ubyte4 *pSignatureLen, byteBoolean preHash, ubyte *pCtx, ubyte4 ctxLen, void *pExtCtx);

/**
 * @brief    A one shot verify of a message via the EdDSA algorithm.
 *
 * @details  A one shot verify of a message via the EdDSA algorithm.
 *
 * @param pKey          Pointer to the public key.
 * @param pMessage      Buffer holding the message to be verified.
 * @param messageLen    The length of the message in bytes.
 * @param pSignature    Buffer holding the signature to be verified.
 * @param signatureLen  The length of the signature in bytes.
 * @param pVerifyStatus Contents will be set to 0 for a valid signature and a nonzero value
 *                      for an invalid signature.
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
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EdDSA_VerifySignature(MOC_ECC(hwAccelDescr hwAccelCtx) ECCKey *pKey, ubyte *pMessage, ubyte4 messageLen, ubyte *pSignature,
                                                          ubyte4 signatureLen, ubyte4 *pVerifyStatus, byteBoolean preHash, ubyte *pCtx, ubyte4 ctxLen, void *pExtCtx);


/**
 * @brief    Initializes an \c edDSA_CTX for use in the EdDSA sign algorithm.
 *
 * @details  Initializes an \c edDSA_CTX for use in the EdDSA sign algorithm.
 *
 * @param pEdDSA_ctx    Pointer to the context to be initialized.
 * @param pKey          Pointer to the public key.
 * @param pSignature    Buffer holding the signature to be verified.
 * @param signatureLen  The length of the signature in bytes.
 * @param pCtx          Optional. For curve25519 set to non-null for Ed25519ctx mode.
 *                      For curve448 the context is optional for pre-hash mode.
 * @param ctxLen        The length of the context in bytes. This cannot be more than 255.
 * @param pExtCtx       An extended context reserved for future use.
 *
 * @return            \c OK (0) if successful, otherwise a negative number error
 *                    code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EdDSA_initSignPreHash(MOC_ECC(hwAccelDescr hwAccelCtx) edDSA_CTX *pEdDSA_ctx, ECCKey *pKey, ubyte *pCtx, ubyte4 ctxLen, void *pExtCtx);

/**
 * @brief    Initializes an \c edDSA_CTX for use in the EdDSA verify algorithm.
 *
 * @details  Initializes an \c edDSA_CTX for use in the EdDSA verify algorithm.
 *
 * @param pEdDSA_ctx    Pointer to the context to be initialized.
 * @param pKey          Pointer to the public key.
 * @param pSignature    Buffer holding the signature to be verified.
 * @param signatureLen  The length of the signature in bytes.
 * @param preHash       Set to \c TRUE (1) for EdDSAph "pre-hash" mode.
 * @param pCtx          Optional. For curve25519 set to non-null for Ed25519ctx mode.
 *                      For curve448 the context is optional for pure Ed448 or pre-hash mode.
 * @param ctxLen        The length of the context in bytes. This cannot be more than 255.
 * @param pExtCtx       An extended context reserved for future use.
 *
 * @return            \c OK (0) if successful, otherwise a negative number error
 *                    code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EdDSA_initVerify(MOC_ECC(hwAccelDescr hwAccelCtx) edDSA_CTX *pEdDSA_ctx, ECCKey *pKey, ubyte *pSignature,
                                                     ubyte4 signatureLen, byteBoolean preHash, ubyte *pCtx, ubyte4 ctxLen, void *pExtCtx);

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
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EdDSA_update(MOC_ECC(hwAccelDescr hwAccelCtx) edDSA_CTX *pEdDSA_ctx, ubyte *pMessage, ubyte4 messageLen, void *pExtCtx);

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
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EdDSA_finalSign(MOC_ECC(hwAccelDescr hwAccelCtx) edDSA_CTX *pEdDSA_ctx, ubyte *pSignature, ubyte4 bufferSize, ubyte4 *pSignatureLen, void *pExtCtx);

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
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EdDSA_finalVerify(MOC_ECC(hwAccelDescr hwAccelCtx) edDSA_CTX *pEdDSA_ctx, ubyte4 *pVerifyStatus, void *pExtCtx);

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_EDDSA_HEADER__ */
