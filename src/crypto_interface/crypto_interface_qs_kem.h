/*
 * crypto_interface_qs_kem.h
 *
 * Cryptographic Interface header file for declaring Key Encapsulation Mechanism methods.
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
@file       crypto_interface_qs_kem.h
@brief      Cryptographic Interface header file for declaring Key Encapsulation Mechanism methods.

@filedoc    crypto_interface_qs_kem.h
*/
#ifndef __CRYPTO_INTERFACE_QS_KEM_HEADER__
#define __CRYPTO_INTERFACE_QS_KEM_HEADER__

#include "../crypto_interface/crypto_interface_qs.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief    Gets the length of the ciphertext associated with a QS algorithm in bytes.
 *
 * @details  Gets the length of the ciphertext associated with a QS algorithm in bytes.
 *
 * @param algo        The algorithm identifier.
 * @param pCipherLen  Contents will be set to the length of the ciphertext in bytes.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_QS_KEM_getCipherTextLenFromAlgo(ubyte4 algo, ubyte4 *pCipherLen);

/**
 * @brief    Gets the length of the ciphertext associated with a QS context in bytes.
 *
 * @details  Gets the length of the ciphertext associated with a QS context in bytes.
 *
 * @param pCtx        Pointer to the QS context.
 * @param pCipherLen  Contents will be set to the length of the ciphertext in bytes.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_QS_KEM_getCipherTextLen(QS_CTX *pCtx, ubyte4 *pCipherLen);

/**
 * @brief    Gets the length of a shared secret associated with a QS context in bytes.
 *
 * @details  Gets the length of a shared secret associated with a QS context in bytes.
 *
 * @param pCtx             Pointer to the QS context.
 * @param pSharedSecretLen Contents will be set to the length of the shared secret in bytes.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_QS_KEM_getSharedSecretLen(QS_CTX *pCtx, ubyte4 *pSharedSecretLen);

/**
 * @brief    Performs the key encapsulation algorithm.
 *
 * @details  Performs the key encapsulation algorithm.
 *
 * @param pCtx              Pointer to a previously allocated context.
 * @param rngFun            Function pointer to a random number generation function.
 * @param pRngFunArg        Input data or context into the random number generation function
 *                          pointer.
 * @param pCipherText       Buffer that will hold the resulting ciphertext.
 * @param cipherTextLen     The length of the \c pCipherText buffer in bytes.
 * @param pSharedSecret     Buffer that will hold the resulting shared secret.
 * @param sharedSecretLen   The length of the \c pSharedSecret buffer in bytes.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_QS_KEM_encapsulate(MOC_HASH(hwAccelDescr hwAccelCtx) QS_CTX *pCtx,
                                                       RNGFun rngFun, void *pRngFunArg,
                                                       ubyte *pCipherText, ubyte4 cipherTextLen,
                                                       ubyte *pSharedSecret, ubyte4 sharedSecretLen);

/**
 * @brief    Performs the key encapsulation algorithm.
 *
 * @details  Performs the key encapsulation algorithm. This method allocates two buffers,
 *           one for the ciphertext and one for the shared secret. Be sure to free these
 *           buffers when done with them.
 *
 * @param pCtx              Pointer to a previously allocated context.
 * @param rngFun            Function pointer to a random number generation function.
 * @param pRngFunArg        Input data or context into the random number generation function
 *                          pointer.
 * @param ppCipherText      Pointer to the location of the newly allocated buffer
 *                          that will contain the output ciphertext.
 * @param pCipherTextLen    Contents will be set to the length of the ciphertext in bytes.
 * @param ppSharedSecret    Pointer to the location of the newly allocated buffer
 *                          that will contain the output shared secret.
 * @param pSharedSecretLen  Contents will be set to the length of the shared secret in bytes.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_QS_KEM_encapsulateAlloc(MOC_HASH(hwAccelDescr hwAccelCtx) QS_CTX *pCtx,
                                                            RNGFun rngFun, void *pRngFunArg,
                                                            ubyte **ppCipherText, ubyte4* pCipherTextLen,
                                                            ubyte **ppSharedSecret, ubyte4 *pSharedSecretLen);

/**
 * @brief    Performs the key decapsulation algorithm.
 *
 * @details  Performs the key decapsulation algorithm.
 *
 * @param pCtx              Pointer to a previously allocated context.
 * @param pCipherText       Buffer holding the input ciphertext.
 * @param cipherTextLen     The length of the ciphertext in bytes.
 * @param pSharedSecret     Buffer that will hold the resulting shared secret.
 * @param sharedSecretLen   The length of the \c pSharedSecret buffer in bytes.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_QS_KEM_decapsulate(MOC_HASH(hwAccelDescr hwAccelCtx) QS_CTX *pCtx,
                                                       ubyte *pCipherText, ubyte4 cipherTextLen,
                                                       ubyte *pSharedSecret, ubyte4 sharedSecretLen);

/**
 * @brief    Performs the key decapsulation algorithm.
 *
 * @details  Performs the key decapsulation algorithm. This method allocates a buffer
 *           for the shared secret. Be sure to free this buffer whwn done with it.
 *
 * @param pCtx              Pointer to a previously allocated context.
 * @param pCipherText       Buffer holding the input ciphertext.
 * @param cipherTextLen     The length of the ciphertext in bytes.
 * @param ppSharedSecret    Pointer to the location of the newly allocated buffer
 *                          that will contain the output shared secret.
 * @param pSharedSecretLen  Contents will be set to the length of the shared secret in bytes.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_QS_KEM_decapsulateAlloc(MOC_HASH(hwAccelDescr hwAccelCtx) QS_CTX *pCtx,
                                                            ubyte *pCipherText, ubyte4 cipherTextLen,
                                                            ubyte **ppSharedSecret, ubyte4 *pSharedSecretLen);

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_QS_KEM_HEADER__ */
