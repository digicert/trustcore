/*
 * aes_xts.h
 *
 * AES-XTS Implementation
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

/*! \file aes_xts.h AES developer API header.
This header file contains definitions, enumerations, structures, and function
declarations used for AES encryption and decryption.

\since 3.0.6
\version 5.0.5 and later

! Flags
There are no flag dependencies to enable the functions in this header file.

! External Functions
This file contains the following public ($extern$) function declarations:
- CreateAESXTSCtx
- DeleteAESXTSCtx
- DoAESXTS

*/


/*------------------------------------------------------------------*/

#ifndef __AES_XTS_HEADER__
#define __AES_XTS_HEADER__

#include "../cap/capdecl.h"

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
#include "../crypto_interface/crypto_interface_aes_xts_priv.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif


/*------------------------------------------------------------------*/

/*  The structure for key information */
typedef struct aesXTSCipherContext
{
    aesCipherContext    *pKey1;
    aesCipherContext    *pKey2;
    MocSymCtx         pMocSymCtx;
    ubyte             enabled;

} aesXTSCipherContext, AES_XTS_Ctx;



/*------------------------------------------------------------------*/
/*  Function prototypes  */

/**
 * @brief Create a new AES-XTS context.
 *
 * @param pKeyMaterial  Pointer to the buffer containing the concatenation of key1
 *                      and key2.
 * @param keyLength     The total length of the keyMaterial, or the length of both
 *                      key1 and key2. For AES-128 use 256, for AES-256 use 512,
 *                      no other values will be accepted.
 * @param encrypt       TRUE to encrypt data, FALSE otherwise.
 * @return              \c NULL if any error; otherwise pointer to created AES-XTS
 * context.
 */
MOC_EXTERN BulkCtx  CreateAESXTSCtx(MOC_SYM(hwAccelDescr hwAccelCtx) const ubyte *pKeyMaterial, sbyte4 keyLength, sbyte4 encrypt);
MOC_EXTERN BulkCtx  CreateAESXTSCtxExt(MOC_SYM(hwAccelDescr hwAccelCtx) const ubyte *pKeyMaterial, sbyte4 keyLength, sbyte4 encrypt, void *pExtCtx);
    
/**
 * @brief Delete an existing AES-XTS context.
 *
 * @param pCtx Pointer to the AES-XTS context to delete.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h.
 */
MOC_EXTERN MSTATUS  DeleteAESXTSCtx(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *pCtx);
MOC_EXTERN MSTATUS  DeleteAESXTSCtxExt(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *pCtx, void *pExtCtx);

/**
 * @brief Encrypt or decrypt data using AES in XTS mode. Note this function
 *        operates on the data in place.
 *
 * @param pCtx     AES-XTS to use for this operation.
 * @param pData    Buffer containing the data to encrypt or decrypt. The
 *                 operation is in place so it will contain the result upon
 *                 return.
 * @param dataLen  The number of bytes to encrypt or decrypt.
 * @param encrypt  TRUE to encrypt data, FALSE to decrypt data.
 * @param pTweak   Initialization vector, ie tweak valuem, for the operation,
 *                 must be exactly 16 bytes.
 * @return         \c OK (0) if successful; otherwise a negative number error
 *                 code definition from merrors.h.
 */
MOC_EXTERN MSTATUS  DoAESXTS(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pData, sbyte4 dataLen,
            sbyte4 encrypt, ubyte *pTweak);
MOC_EXTERN MSTATUS  DoAESXTSExt(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pData, sbyte4 dataLen,
            sbyte4 encrypt, ubyte *pTweak, void *pExtCtx);
    
/* algo specific API -- might be easier to use in some cases */

/**
 * @brief Initialize a previously allocated AES-XTS context.
 *
 * @param pCtx      Caller allocated context to be keyed.
 * @param pKey1     Key 1 to use for this operation.
 * @param pKey2     Key 2 to use for this operation.
 * @param keyLength Length of a single key, must be either 128 or 256.
 * @param encrypt   TRUE to encrypt data, FALSE to decrypt data.
 * @return          \c OK (0) if successful; otherwise a negative number error
 *                  code definition from merrors.h.
 */
MOC_EXTERN MSTATUS AESXTSInit( MOC_SYM(hwAccelDescr hwAccelCtx)
                                aesXTSCipherContext *pCtx,
                                const ubyte *pKey1, const ubyte *pKey2,
                                sbyte4 keyLength, sbyte4 encrypt);

MOC_EXTERN MSTATUS AESXTSInitExt( MOC_SYM(hwAccelDescr hwAccelCtx)
                                  aesXTSCipherContext *pCtx,
                                  const ubyte *pKey1, const ubyte *pKey2,
                                  sbyte4 keyLength, sbyte4 encrypt, void *pExtCtx);
    
/**
 * @brief Encrypt some data using AES in XTS mode. Note this operation is in
 *        place.
 *
 * @param pCtx     The AES-XTS context to use to encrypt the data.
 * @param pTweak   The tweak value for this encryption operation.
 * @param pPlain   The plaintext to be encrypted.
 * @param plainLen Size in bytes of the plaintext data.
 * @return         \c OK (0) if successful; otherwise a negative number error code
 *                 definition from merrors.h.
 */
MOC_EXTERN MSTATUS AESXTSEncrypt( MOC_SYM(hwAccelDescr hwAccelCtx)
                                  aesXTSCipherContext *pCtx,
                                  ubyte pTweak[AES_BLOCK_SIZE],
                                  ubyte *pPlain, ubyte4 plainLen);
MOC_EXTERN MSTATUS AESXTSEncryptExt( MOC_SYM(hwAccelDescr hwAccelCtx)
                                     aesXTSCipherContext *pCtx,
                                     ubyte pTweak[AES_BLOCK_SIZE],
                                     ubyte *pPlain, ubyte4 plainLen, void *pExtCtx);
/**
 * @brief Decrypt some data using AES in XTS mode. Note this operation is in
 *        place.
 *
 * @param pCtx      The AES-XTS context to use to decrypt the data.
 * @param pTweak    The tweak value for this decryption operation.
 * @param pCipher   The data to be decrypted.
 * @param cipherLen Size in bytes of the data to be decrypted.
 * @return          \c OK (0) if successful; otherwise a negative number error code
 *                  definition from merrors.h.
 */
MOC_EXTERN MSTATUS AESXTSDecrypt( MOC_SYM(hwAccelDescr hwAccelCtx)
                                  aesXTSCipherContext *pCtx,
                                  ubyte pTweak[AES_BLOCK_SIZE],
                                  ubyte *pCipher, ubyte4 cipherLen);

MOC_EXTERN MSTATUS AESXTSDecryptExt( MOC_SYM(hwAccelDescr hwAccelCtx)
                                     aesXTSCipherContext *pCtx,
                                     ubyte pTweak[AES_BLOCK_SIZE],
                                     ubyte *pCipher, ubyte4 cipherLen, void *pExtCtx);

/**
 * @brief Clone an AES-XTS context.
 *
 * @param pCtx      Pointer to an instantiated BulkCtx.
 * @param ppNewCtx  Double pointer to the BulkCtx to be created and populated
 *                    with the data from the source context.
 * @return          \c OK (0) if successful; otherwise a negative number error
 *                  code definition from merrors.h.
 */
MOC_EXTERN MSTATUS CloneAESXTSCtx( MOC_SYM(hwAccelDescr hwAccelCtx)
                                  BulkCtx pCtx, BulkCtx *ppNewCtx);

#ifdef __cplusplus
}
#endif

#endif /* __AES_XTS_HEADER__ */

