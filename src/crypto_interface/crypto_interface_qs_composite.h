/*
 * crypto_interface_qs_composite.h
 *
 * Composite signature APIs for quantum safe and classical crypto.
 *
 * Copyright (c) Digicert 2025. All Rights Reserved.
 * Proprietary and Confidential Material.
 */

/**
@file       crypto_interface_qs_composite.h
@brief      Cryptographic Interface header file for declaring common Quantum Safe methods.

@filedoc    crypto_interface_qs_composite.h
*/
#ifndef __CRYPTO_INTERFACE_QS_COMPOSITE_HEADER__
#define __CRYPTO_INTERFACE_QS_COMPOSITE_HEADER__

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/random.h"
#include "../crypto/pubcrypto.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief    Gets the signature length for a composite signature.
 *
 * @details  Gets the signature length for a composite signature.
 *
 * @param pKey          The composite key of type \c akt_hybrid.
 * @param addLenPrefix  If \c true, the quantum safe signature len 
 *                      is added as a prefix (required by SSL).
 * @param pSignatureLen Contents will be set to the resulting length in bytes.      
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_QS_compositeGetSigLen(
    MOC_ASYM(hwAccelDescr hwAccelCtx)
    AsymmetricKey *pKey,
    byteBoolean addLenPrefix,
    ubyte4 *pSignatureLen
);

/**
 * @brief    Computes a composite signature.
 *
 * @details  Computes a composite signature.
 *
 * @param pKey          The composite private key of type \c akt_hybrid.
 * @param addLenPrefix  If \c true, the quantum safe signature len 
 *                      is added as a prefix (required by SSL).
 * @param rngFun        Function pointer to a random number generation function.
 *                      Required for some composite signature definitions.
 *                  
 * @param rngArg        Input data or context into the random number generation function.
 *                      This must be a \c randomContext* type for RSA-PSS composite signatures.
 * @param pDomain       The domain (required by SSL and SSH).
 * @param domainLen     The length of the domain in bytes.
 * @param pMessage      The input message to be verified.
 * @param messageLen    The message length in bytes.
 * @param pSignature    Buffer to hold the resulting signature.
 * @param bufferSize    The length of the signature buffer in bytes.
 * @param pSignatureLen Contents will be set to the resulting signature length in bytes.      
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_QS_compositeSign(
    MOC_ASYM(hwAccelDescr hwAccelCtx)
    AsymmetricKey *pKey,
    byteBoolean addLenPrefix,
    RNGFun rngFun,
    void* rngArg,
    ubyte *pDomain,
    ubyte4 domainLen,
    ubyte *pMessage,
    ubyte4 messageLen,
    ubyte *pSignature,
    ubyte4 bufferSize,
    ubyte4 *pSignatureLen
);
 
 /**
 * @brief    Verifies a composite signature.
 *
 * @details  Verifies a composite signature.
 *
 * @param pKey          The composite public key of type \c akt_hybrid.
 * @param addLenPrefix  If \c true, the quantum safe signature len 
 *                      is added as a prefix (required by SSL).
 * @param pDomain       The domain (required by SSL and SSH).
 * @param domainLen     The length of the domain in bytes.
 * @param pMessage      The input message to be verified.
 * @param messageLen    The messageLen in bytes.
 * @param pSignature    The signature to be verified.
 * @param signatureLen  The length of the signature in bytes.
 * @param pVerifyStatus Contents will be set to 0 for a valid signature
 *                      and non-zero otherwise.      
 *
 * @warning    Be sure to check for both a return status of \c OK and a \c pVerifyStatus
 *             of \c 0 before accepting that a signature is valid.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_QS_compositeVerify(
    MOC_ASYM(hwAccelDescr hwAccelCtx)
    AsymmetricKey *pKey,
    byteBoolean addLenPrefix,
    ubyte *pDomain,
    ubyte4 domainLen,
    ubyte *pMessage,
    ubyte4 messageLen,
    ubyte *pSignature,
    ubyte4 signatureLen,
    ubyte4 *pVerifyStatus
);

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_QS_COMPOSITE_HEADER__ */
