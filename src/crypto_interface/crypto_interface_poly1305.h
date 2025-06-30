/**
 * @file crypto_interface_poly1305.h
 *
 * @brief Cryptographic Interface header file for declaring Poly1305 functions.
 *
 * @filedoc crypto_interface_poly1305.h
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

#ifndef __CRYPTO_INTERFACE_POLY1305_HEADER__
#define __CRYPTO_INTERFACE_POLY1305_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   Initialize a Poly1305 context, and load in the provided key.
 *          Once initialized, you can use this context as input to
 *          CRYPTO_INTERFACE_Poly1305Update & CRYPTO_INTERFACE_Poly1305Final
 *          to create a MAC.
 *
 * @param pCtx  Pointer to the Poly1305 context to be initialized.
 * @param pKey  Key material used for the MAC operation.
 *
 * @return      \c OK (0) if successful, otherwise a negative number
 *              error code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_Poly1305Init (
  MOC_HASH(hwAccelDescr hwAccelCtx) Poly1305Ctx *pCtx,
  const ubyte pKey[32]
  );

/**
 * @brief    Update the intermediate MAC value in a Poly1305 context.
 *           Applications can repeatedly call this function to calculate a MAC
 *           for different data items.
 *
 * @param pCtx    Pointer to the Poly1305 context.
 * @param pM      Pointer to input data.
 * @param bytes   Number of bytes of input data to read (\p text).
 *
 * @return        \c OK (0) if successful, otherwise a negative number
 *                error code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_Poly1305Update (
  MOC_HASH(hwAccelDescr hwAccelCtx) Poly1305Ctx *pCtx,
  const ubyte *pM,
  ubyte4 bytes
  );

/**
 * @brief     Calculate the final MAC value, and return it through the
 *            \p pMac parameter.
 *
 * @param pCtx   Pointer to the Poly1305 context.
 * @param pMac   On return, pointer to resultant MAC value.
 *
 * @return       \c OK (0) if successful, otherwise a negative number
 *               error code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_Poly1305Final (
  MOC_HASH(hwAccelDescr hwAccelCtx) Poly1305Ctx *pCtx,
  ubyte pMac[16]
  );

/**
 * @brief     Calculate the MAC value in one function call.  This function
 *            simply contains the calls to Init, Update & Final.  The MAC value
 *            is returned through the \p pMac parameter.
 *
 * @param pMac    On return, pointer to resultant MAC value.
 * @param pM      Pointer to input data.
 * @param bytes   Length of the input data buffer.
 * @param pKey    Key material used for the MAC operation.
 *
 * @return      \c OK (0) if successful, otherwise a negative number
 *              error code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_Poly1305_completeDigest (
  MOC_HASH(hwAccelDescr hwAccelCtx) ubyte pMac[16],
  const ubyte *pM,
  ubyte4 bytes,
  const ubyte pKey[32]
  );

/**
 * @brief Makes a clone of a previously allocated \c Poly1305Ctx.
 *
 * @details Makes a clone of a previously allocated \c Poly1305Ctx.
 *
 * @param pDest   Pointer to an already allocated destination context.
 * @param pSrc    Pointer to the context to be copied.
 *
 * @return           \c OK (0) if successful, otherwise a negative number
 *                   error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_Poly1305_cloneCtx (
  MOC_HASH(hwAccelDescr hwAccelCtx) Poly1305Ctx *pDest,
  Poly1305Ctx *pSrc
  );

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_POLY1305_HEADER__ */
