/*
 * crypto_interface_qs_sig.h
 *
 * Cryptographic Interface header file for declaring Signature based authentication methods.
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
@file       crypto_interface_qs_sig.h
@brief      Cryptographic Interface header file for declaring Signature based authentication methods.

@filedoc    crypto_interface_qs_sig.h
*/
#ifndef __CRYPTO_INTERFACE_QS_SIG_HEADER__
#define __CRYPTO_INTERFACE_QS_SIG_HEADER__

#include "../crypto_interface/crypto_interface_qs.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief    Gets the length or maximum length of a signature associated with a QS context in bytes.
 *
 * @details  Gets the length of a signature associated with a QS context in bytes. For the algorithm
 *           FN-DSA (Falcon) this method gets the maximum length that a singature can be.
 *
 * @param pCtx        Pointer to the QS context.
 * @param pSigLen     Contents will be set to the length of the signature or maximum length in bytes.
 *
 * @warning  For FN-DSA (Falcon) remember the contents of pSigLen just represent the maximum length of a signature.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_QS_SIG_getSignatureLen(QS_CTX *pCtx, ubyte4 *pSigLen);

/**
 * @brief    Performs the signature generation algorithm.
 *
 * @details  Performs the signature generation algorithm.
 *
 * @param pCtx           Pointer to a previously allocated context.
 * @param rngFun         Function pointer to a random number generation function.
 * @param pRngFunArg     Input data or context into the random number generation function
 * @param pData          Buffer holding the input message.
 * @param dataLen        The length of the message in bytes.
 * @param pSignature     Buffer that will hold the resulting signature.
 * @param sigBufferLen   The length of the \c pSignature buffer in bytes.
 * @param pActualSigLen  Contents will be set to the actual length of the signature, 
 *                       ie the number of bytes written to \c pSignature.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_QS_SIG_sign(MOC_HASH(hwAccelDescr hwAccelCtx) QS_CTX *pCtx, RNGFun rngFun, void *pRngFunArg, ubyte *pData, ubyte4 dataLen,
                                                ubyte *pSignature, ubyte4 sigBufferLen, ubyte4 *pActualSigLen);

/**
 * @brief    Performs the signature generation algorithm for a previously digested message.
 *
 * @details  Performs the signature generation algorithm for a previously digested message.
 *
 * @flags
 *   To enable this function, the following flag must be defined:
 *     __ENABLE_DIGICERT_PQC_SIG_STREAMING__
 *
 * @param pCtx           Pointer to a previously allocated context.
 * @param rngFun         Function pointer to a random number generation function.
 * @param pRngFunArg     Input data or context into the random number generation function
 * @param digestId       The digest identifier from crypto.h.
 * @param pData          Buffer holding the input digest.
 * @param dataLen        The length of the digest in bytes.
 * @param pSignature     Buffer that will hold the resulting signature.
 * @param sigBufferLen   The length of the \c pSignature buffer in bytes.
 * @param pActualSigLen  Contents will be set to the actual length of the signature,
 *                       ie the number of bytes written to \c pSignature.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_QS_SIG_signDigest(MOC_HASH(hwAccelDescr hwAccelCtx) QS_CTX *pCtx, RNGFun rngFun, void *pRngFunArg,
                                                      ubyte digestId, ubyte *pData, ubyte4 dataLen,
                                                      ubyte *pSignature, ubyte4 sigBufferLen, ubyte4 *pActualSigLen);

/**
 * @brief    Performs the signature generation algorithm.
 *
 * @details  Performs the signature generation algorithm. This method allocates a buffer
 *           for the signature. Be sure to free this buffer whwn done with it.
 *
 * @param pCtx           Pointer to a previously allocated context.
 * @param rngFun         Function pointer to a random number generation function.
 * @param pRngFunArg     Input data or context into the random number generation function
 * @param pData          Buffer holding the input message or digest of the message.
 * @param dataLen        The length of the data in bytes.
 * @param ppSignature    Pointer to the location of the newly allocated buffer
 *                       that will contain the output signature.
 * @param pSignatureLen  Contents will be set to the length of the signature in bytes. For FALCON This
 *                       may be fewer bytes than what is allocated for \c ppSignature.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_QS_SIG_signAlloc(MOC_HASH(hwAccelDescr hwAccelCtx) QS_CTX *pCtx, RNGFun rngFun, void *pRngFunArg, ubyte *pData, ubyte4 dataLen,
                                                     ubyte **ppSignature, ubyte4 *pSignatureLen);

/**
 * @brief    Performs the signature verification algorithm.
 *
 * @details  Performs the signature verification algorithm.
 *
 * @param pCtx           Pointer to a previously allocated context.
 * @param pData          Buffer holding the input message.
 * @param dataLen        The length of the message in bytes.
 * @param pSignature     Buffer holding the signature to be verified.
 * @param signatureLen   The length of the signature in bytes.
 * @param pVerifyStatus  Contents will be set to 0 for a valid signature
 *                       and non-zero otherwise.
 *
 * @warning  Be sure to check both a status of \c OK (0) and a \c pVerifyStatus
 *           of \c 0 before accepting that a signature is valid.
 *
 * @return   \c OK (0) for successful completion of the method regardless of whether the
 *           signature is valid for the input data, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_QS_SIG_verify(MOC_HASH(hwAccelDescr hwAccelCtx) QS_CTX *pCtx, ubyte *pData, ubyte4 dataLen,
                                                  ubyte *pSignature, ubyte4 signatureLen, ubyte4 *pVerifyStatus);

/**
 * @brief    Performs the signature verification algorithm for a previously digested message.
 *
 * @details  Performs the signature verification algorithm for a previously digested message.
 *
 * @flags
 *   To enable this function, the following flag must be defined:
 *     __ENABLE_DIGICERT_PQC_SIG_STREAMING__
 *
 * @param pCtx           Pointer to a previously allocated context.
 * @param digestId       The digest identifier from crypto.h.
 * @param pData          Buffer holding the input digest.
 * @param dataLen        The length of the digest in bytes.
 * @param pSignature     Buffer holding the signature to be verified.
 * @param signatureLen   The length of the signature in bytes.
 * @param pVerifyStatus  Contents will be set to 0 for a valid signature
 *                       and non-zero otherwise.
 *
 * @warning  Be sure to check both a status of \c OK (0) and a \c pVerifyStatus
 *           of \c 0 before accepting that a signature is valid.
 *
 * @return   \c OK (0) for successful completion of the method regardless of whether the
 *           signature is valid for the input data, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_QS_SIG_verifyDigest(MOC_HASH(hwAccelDescr hwAccelCtx) QS_CTX *pCtx, ubyte digestId,
                                                        ubyte *pData, ubyte4 dataLen, ubyte *pSignature, ubyte4 signatureLen,
                                                        ubyte4 *pVerifyStatus);

/**
 * @brief    Initializes the signature or verification algorithm for streaming mode.
 *
 * @details  Initializes the signature or verification algorithm for streaming mode.
 *
 * @flags
 *   To enable this function, the following flag must be defined:
 *     __ENABLE_DIGICERT_PQC_SIG_STREAMING__
 *
 * @param pCtx           Pointer to a previously allocated context.
 * @param isExternalMu   Indicates to implicitly digest input data as per draft.
 * @param digestId       For \c isExternalMu false, the identifier of the pre-hash
 *                       digest from crypto.h. For \c isExternalMu true this is ignored.
 * @param pContextStr    Optional context string for cipher personalization.
 * @param ctxStrLen      The length of the context string in bytes. Cannot exceed 255.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_QS_SIG_streamingInit(QS_CTX *pCtx, byteBoolean isExternalMu, ubyte digestId,
                                                         ubyte *pContextStr, ubyte4 ctxStrLen);

/**
 * @brief    Updates an initilized context with a stream of data.
 *
 * @details  Updates an initilized context with a stream of data. This method can be called
 *           as many times as needed.
 *
 * @flags
 *   To enable this function, the following flag must be defined:
 *     __ENABLE_DIGICERT_PQC_SIG_STREAMING__
 *
 * @param pCtx           Pointer to a previously initialized context.
 * @param pData          Buffer holding the input data.
 * @param dataLen        The length of the data in bytes.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */                                                   
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_QS_SIG_streamingUpdate(QS_CTX *pCtx, ubyte *pData, ubyte4 dataLen);

/**
 * @brief    Finalizes an updated context, producing the output signature.
 *
 * @details  Finalizes an updated context, producing the output signature.
 *
 * @flags
 *   To enable this function, the following flag must be defined:
 *     __ENABLE_DIGICERT_PQC_SIG_STREAMING__
 *
 * @param pCtx           Pointer to a previously updated context.
 * @param rngFun         Function pointer to a random number generation function.
 * @param pRngArg        Input data or context into the random number generation function
 * @param pSignature     Buffer that will hold the resulting signature.
 * @param sigBufferLen   The length of the \c pSignature buffer in bytes.
 * @param pActualSigLen  Contents will be set to the actual length of the signature, 
 *                       ie the number of bytes written to \c pSignature.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */                                                   
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_QS_SIG_streamingSignFinal(QS_CTX *pCtx, RNGFun rngFun, void *pRngArg,
                                                              ubyte *pSignature, ubyte4 sigBufferLen, ubyte4 *pActualSigLen);

/**
 * @brief    Finalizes an updated context, verifying the signature.
 *
 * @details  Finalizes an updated context, verifying the signature.
 *
 * @flags
 *   To enable this function, the following flag must be defined:
 *     __ENABLE_DIGICERT_PQC_SIG_STREAMING__
 *
 * @param pCtx           Pointer to a previously updated context.
 * @param pSignature     Buffer holding the signature to be verified.
 * @param signatureLen   The length of the signature in bytes.
 * @param pVerifyStatus  Contents will be set to 0 for a valid signature
 *                       and non-zero otherwise.
 *
 * @warning    Be sure to check for both a return status of \c OK and a \c pVerifyStatus
 *             of \c 0 before accepting that a signature is valid.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */                                                   
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_QS_SIG_streamingVerifyFinal(QS_CTX *pCtx, ubyte *pSignature, ubyte4 signatureLen,
                                                                ubyte4 *pVerifyStatus);

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_QS_SIG_HEADER__ */
