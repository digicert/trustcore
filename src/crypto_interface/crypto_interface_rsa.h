/*
 * crypto_interface_rsa.h
 *
 * Cryptographic Interface header file for declaring RSA functions
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
@file       crypto_interface_rsa.h
@brief      Cryptographic Interface header file for declaring RSA functions.
@details    Add details here.

@filedoc    crypto_interface_rsa.h
*/
#ifndef __CRYPTO_INTERFACE_RSA_HEADER__
#define __CRYPTO_INTERFACE_RSA_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Create a new RSA key. This will allocate the RSA key shell. The caller is
 * responsible for freeing the memory by calling RSA_freeKey.
 *
 * @param ppNewKey       Pointer to the location that will recieve the new key.
 * @param keyType        The key type, must be akt_rsa.
 * @param pKeyAttributes Pointer to a key attribute structure.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_createKey(
  void** ppNewKey,
  ubyte4 keyType,
  void *pKeyAttributes
  );

/* Generate a new RSA keypair */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_generateKeyAlloc(
  MOC_RSA(hwAccelDescr hwAccelCtx) randomContext *pRandomContext,
  void **ppNewKey,
  ubyte4 keySize,
  vlong **ppVlongQueue,
  ubyte4 keyType,
  void *pKeyAttributes
  );

/**
 * Create a new RSA key. This will allocate the RSA key shell. The caller is
 * responsible for freeing the memory by calling CRYPTO_INTERFACE_RSA_freeKeyAux.
 *
 * @param ppNewKey       Pointer to the location that will recieve the new key.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_createKeyAux(
  RSAKey **ppNewKey
  );

/**
 * Free an RSA key.
 *
 * @param ppRsaKey       Double pointer to the key to be deleted.
 * @param ppVlongQueue   Optional vlong queue.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_freeKeyAux(
  RSAKey **ppRsaKey,
  vlong **ppVlongQueue
  );

/**
 * Uses an RSA key to sign the plain text and write to pCipherText
 *
 * @param pKey          Pointer to the key used in signing
 * @param pPlainText    Pointer to plain text buffer
 * @param plainTextLen  size of plain text buffer
 * @param pCipherText   Pointer to buffer for cipher text
 * @param ppVlongQueue Optional vlong queue.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_signMessageAux(
  MOC_RSA(hwAccelDescr hwAccelCtx) const RSAKey *pKey,
  const ubyte *pPlainText,
  ubyte4 plainTextLen,
  ubyte *pCipherText,
  vlong **ppVlongQueue
  );

/**
 * Uses an RSA key to verify the signature and write to pCipherText
 *
 * @param pKey          Pointer to the key used in signing
 * @param pCipherText   Pointer to buffer for cipher text
 * @param pPlainText    Pointer to plain text buffer
 * @param plainTextLen  Pointer to number of bytes written to pPlainText
 * @param ppVlongQueue Optional vlong queue.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_verifySignatureAux(
  MOC_RSA(hwAccelDescr hwAccelCtx) const RSAKey *pKey,
  const ubyte *pCipherText,
  ubyte *pPlainText,
  ubyte4 *pPlainTextLen,
  vlong **ppVlongQueue
  );

  /**
 * @brief      Verify the digest of a message.
 *
 * @details    This function verifies the digest of a message, 
 *             using the provided RSA public key.
 *
 * @param [in]  hwAccelCtx    (Reserved for future use.)
 * @param [in]  pKey          Pointer to RSA public key.
 * @param [in]  pMsgDigest    Pointer to Msg Digest to be verified.
 * @param [in]  digestLen     The length of the message digest in bytes.
 * @param [in]  pSignature    Pointer to the signature to be verified.
 * @param [in]  sigLen        The length of the signature in bytes.
 * @param [out] pIsValid      Contents will be set with \c TRUE if the signature
 *                            is valid and \c FALSE if otherwise.
 * @param [out] ppVlongQueue  On return, pointer to location in the \c vlong queue
 *                            that contains this function's intermediate value,
 *                            which can subsequently be used and eventually
 *                            discarded. (Before ending, your application should
 *                            be sure to free the entire queue.)
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @warning    Be sure to check for both a return status of \c OK and a \c pIsValid
 *             of \c TRUE before accepting that a signature is valid.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_verifyDigest(MOC_RSA(hwAccelDescr hwAccelCtx)
                                                     RSAKey *pKey,
                                                     ubyte *pMsgDigest,
                                                     ubyte4 digestLen,
                                                     ubyte* pSignature,
                                                     ubyte4 sigLen,
                                                     intBoolean *pIsValid,
                                                     vlong **ppVlongQueue);


/**
 * @brief      Performs all signature scheme steps on raw data, 
 *             ie data digestation, digest info creation, and signing.
 *
 * @details    Performs all signature scheme steps on raw data, 
 *             ie data digestation, digest info creation, and signing.
 *
 * @note       This function uses a private key.
 *
 * @flags
 *   To enable this function, the following flag must be defined:
 *     __ENABLE_DIGICERT_RSA_SIGN_DATA__
 *
 * @param [in]  pKey          Pointer to RSA private key.
 * @param [in]  pData         Buffer holding the data to be signed.
 * @param [in]  dataLen       The length of the data in bytes.
 * @param [in]  hashId        One of the enum values in crypto.h indicating
 *                            which hash algorithm should be used to digest
 *                            the data.
 * @param [out] pSignature    Buffer to hold the resulting signature. This buffer
 *                            must have enough space based on the key size.
 * @param [out] ppVlongQueue  On return, pointer to location in the \c vlong queue
 *                            that contains this function's intermediate value,
 *                            which can subsequently be used and eventually
 *                            discarded. (Before ending, your application should
 *                            be sure to free the entire queue.)
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_signData(
  MOC_RSA(hwAccelDescr hwAccelCtx)
  RSAKey *pKey,
  ubyte *pData,
  ubyte4 dataLen,
  ubyte hashId,
  ubyte *pSignature,
  vlong **ppVlongQueue);

/**
 * @brief      Performs all signature verification steps on raw data, 
 *             ie data digestation, digest info creation, and signing.
 *
 * @details    Performs all signature verification steps on raw data, 
 *             ie data digestation, digest info creation, and signing.
 *
 * @note       This function uses a public key.
 *
 * @flags
 *   To enable this function, the following flag must be defined:
 *     __ENABLE_DIGICERT_RSA_SIGN_DATA__
 *
 * @param [in]  pKey          Pointer to RSA public key.
 * @param [in]  pData         Buffer holding the data to be verified.
 * @param [in]  dataLen       The length of the data in bytes.
 * @param [in]  hashId        One of the enum values in crypto.h indicating
 *                            which hash algorithm should be used to digest
 *                            the data.
 * @param [in]  pSignature    Buffer holding the signature to be verified.
 * @param [in]  signatureLen  The length of the signature in bytes.
 * @param [out] pIsValid      Contents will be set with \c TRUE if the signature
 *                            is valid and \c FALSE if otherwise.
 * @param [out] ppVlongQueue  On return, pointer to location in the \c vlong queue
 *                            that contains this function's intermediate value,
 *                            which can subsequently be used and eventually
 *                            discarded. (Before ending, your application should
 *                            be sure to free the entire queue.)
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @warning    Be sure to check for both a return status of \c OK and a \c pIsValid
 *             of \c TRUE before accepting that a signature is valid.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_verifyData(
  MOC_RSA(hwAccelDescr hwAccelCtx)
  RSAKey *pKey,
  ubyte *pData,
  ubyte4 dataLen,
  ubyte hashId,
  ubyte *pSignature,
  ubyte4 signatureLen,
  intBoolean *pIsValid,
  vlong **ppVlongQueue);

/**
 * Get length of cipher text associated with RSA key
 *
 * @param pKey              Pointer to the key used in signing
 * @param pCipherTextLen    Pointer to length of cipher text
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_getCipherTextLengthAux (
  MOC_RSA(hwAccelDescr hwAccelCtx)
  const RSAKey *pKey,
  sbyte4 *pCipherTextLen
  );

/**
 * Set the public parameters of an RSA key. The caller must provide the RSA
 * exponent as a ubyte4 and the RSA modulus as a byte string.
 *
 * @param pKey         The key object to be set.
 * @param exponent     The RSA exponent.
 * @param pModulus     The RSA modulus as a byte string.
 * @param modulusLen   The length of the RSA modulus.
 * @param ppVlongQueue Optional vlong queue.
 *
 * @return          \c OK (0) if successful, otherwise a negative number error
 *                  code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_setPublicKeyParametersAux(
  MOC_RSA(hwAccelDescr hwAccelCtx)
  RSAKey *pKey,
  ubyte4 exponent,
  const ubyte *pModulus,
  ubyte4 modulusLen,
  vlong **ppVlongQueue
  );

/**
 * Set the public parameters of an RSA key. The caller must provide the RSA
 * exponent as a ubyte4 and the RSA modulus as a byte string.
 *
 * @param pKey          The key object to be set.
 * @param pPubExpo      Pointer to buffer containing exponent
 * @param pubExpoLen    The RSA exponent length.
 * @param pModulus      The RSA modulus as a byte string.
 * @param modulusLen    The length of the RSA modulus.
 * @param ppVlongQueue  Optional vlong queue.
 *
 * @return          \c OK (0) if successful, otherwise a negative number error
 *                  code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_setPublicKeyData(
  MOC_RSA(hwAccelDescr hwAccelCtx)
  RSAKey *pKey,
  ubyte *pPubExpo,
  ubyte4 pubExpoLen,
  const ubyte *pModulus,
  ubyte4 modulusLen,
  vlong **ppVlongQueue
  );


/**
 * Set all the parameters in a RSA key. The caller must provide the RSA
 * exponent, RSA modulus, RSA prime, and RSA subprime values.
 *
 * @param pKey         The key object to set.
 * @param exponent     The RSA exponent as 4 byte integer.
 * @param pModulus     The RSA modulus as a byte string.
 * @param modulusLen   The RSA modulus length.
 * @param pPrime1      The RSA prime as a byte string.
 * @param prime1Len    The RSA prime length.
 * @param pPrime2      The RSA subprime as a byte string.
 * @param prime2Len    The RSA subprime length.
 * @param ppVlongQueue Optional vlong queue.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_setAllKeyParameters (
  MOC_RSA(hwAccelDescr hwAccelCtx)
  RSAKey *pKey,
  ubyte4 exponent,
  const ubyte *modulus,
  ubyte4 modulusLen,
  const ubyte *prime1,
  ubyte4 prime1Len,
  const ubyte *prime2,
  ubyte4 prime2Len,
  vlong **ppVlongQueue
  );

/**
 * Set all the parameters in a RSA key. The caller must provide the RSA
 * exponent, RSA modulus, RSA prime, and RSA subprime values.
 *
 * @param pKey         The key object to set.
 * @param pPubExpo     The RSA exponent as a byte string.
 * @param pubExpoLen   The RSA exponent length.
 * @param pModulus     The RSA modulus as a byte string.
 * @param modulusLen   The RSA modulus length.
 * @param pPrime1      The RSA prime as a byte string.
 * @param prime1Len    The RSA prime length.
 * @param pPrime2      The RSA subprime as a byte string.
 * @param prime2Len    The RSA subprime length.
 * @param ppVlongQueue Optional vlong queue.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_setAllKeyDataAux(
  MOC_RSA(hwAccelDescr hwAccelCtx)
  RSAKey *pKey,
  ubyte *pPubExpo,
  ubyte4 pubExpoLen,
  const ubyte *pModulus,
  ubyte4 modulusLen,
  const ubyte *pPrime1,
  ubyte4 prime1Len,
  const ubyte *pPrime2,
  ubyte4 prime2Len,
  vlong **ppVlongQueue
  );

/**
 * Allocates and sets the appropriate key parameters of pTemplate with the data
 * in the key. The caller must provide an allocated MRsaKeyTemplate structure,
 * which will then have its internal pointers allocated by this function. Note
 * it is the callers responsibility to free this memory using
 * RSA_freeKeyTemplate. The reqType should be either MOC_GET_PUBLIC_KEY_DATA or
 * MOC_GET_PRIVATE_KEY_DATA. Tha latter option will get both the private and
 * public key parameters. and as such can only be used with a private key.
 * Retrieving the public data from a private key is allowed, retrieving the
 * private data from a public key is impossible and will result in an error. See
 * the documentation for MRsaKeyTemplate in capasym.h for more info on the
 * format of template data.
 *
 * @param pKey      The key to retrieve data from.
 * @param pTemplate Pointer to an exisiting MRsaKeyTemplate structure. The
 *                  internal pointers within structure will be allocated by this
 *                  function.
 * @param keyType   Type of data to retrieve. This must be
 *                  MOC_GET_PUBLIC_KEY_DATA or MOC_GET_PRIVATE_KEY_DATA.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_getKeyParametersAllocAux(
  MOC_RSA(hwAccelDescr hwAccelCtx)
  RSAKey *pKey,
  MRsaKeyTemplate *pTemplate,
  ubyte keyType
  );

/**
 * Free the RSA key template.
 *
 * @param pKey      The key used to delete the key template. This key is not
 *                  always required.
 * @param pTemplate Template to free.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_freeKeyTemplateAux(
  RSAKey *pKey,
  MRsaKeyTemplate *pTemplate
  );

/**
 * Apply the public key to the input data. The input data must be the same
 * length as the RSA modulus. The output buffer will be allocated by this
 * function and must be freed by the caller.
 *
 * @param pKey         The key used to perform the operation. This must contain
 *                     RSA public key data.
 * @param pInput       The input data to process. Must be the same length as the
 *                     RSA modulus.
 * @param inputLen     The input data length.
 * @param ppOutput     The output buffer. This buffer will be allocated by this
 *                     function and must be freed by the caller using DIGI_FREE.
 * @param ppVlongQueue Optional vlong queue.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_applyPublicKeyAux(
  MOC_RSA(hwAccelDescr hwAccelCtx)
  RSAKey *pKey,
  ubyte *pInput,
  ubyte4 inputLen,
  ubyte **ppOutput,
  vlong **ppVlongQueue
  );

/**
 * Apply the private key to the input data. The input data must be the same
 * length as the RSA modulus. The output buffer will be allocated by this
 * function and must be freed by the caller.
 *
 * @param pKey         The key used to perform the operation. This must contain
 *                     RSA private key data.
 * @param rngFun       Function pointer to a random number generation function.
 * @param pRngFunArg   Input data into the random number generation function
 *                     pointer.
 * @param pInput       The input data to process. Must be the same length as the
 *                     RSA modulus.
 * @param inputLen     The input data length.
 * @param ppOutput     The output buffer. This buffer will be allocated by this
 *                     function and must be freed by the caller using DIGI_FREE.
 * @param ppVlongQueue Optional vlong queue.
 * @param keyType      The key type, must be akt_rsa or akt_tap_rsa.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_applyPrivateKeyAux(
  MOC_RSA(hwAccelDescr hwAccelCtx)
  RSAKey *pKey,
  RNGFun rngFun,
  void *rngFunArg,
  ubyte *pInput,
  ubyte4 inputLen,
  ubyte **ppOutput,
  vlong **ppVlongQueue
  );

/**
 * @brief      Creates RSA encryption.
 *
 * @details    This function creates RSA encryption of the given input buffer.
 *             It supports TAP Key and SW key for calculating RSA encryption.
 *
 * @param pKey          Pointer to RSAKey. It could be MocAsymkey or RSAKey.
 * @param pPlainText    Pointer to the plain text to be signed.
 * @param plainTextLen  Pointer to the length of the plain text.
 * @param pCipherText   Pointer to the cipher text.
 * @param rngFun        Random function pointer.
 * @param pRngFunArg    Argument to the random function.
 * @param ppVlongQueue  Double Pointer to the vlong.
 *
 * @inc_file   crypto_interface_rsa.h
 *
 * @return     \c OK (0) if sucessful; otherwise a negative number error code
 *             defintion from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @funcdoc    crypto_interface_rsa.h
 */
MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_RSA_encryptAux(
  MOC_RSA(hwAccelDescr hwAccelCtx) const RSAKey *pKey,
  const ubyte *pPlainText,
  ubyte4 plainTextLen,
  ubyte *pCipherText,
  RNGFun rngFun,
  void *pRngFunArg,
  vlong **ppVlongQueue
  );

/**
 * @brief      Decrypts the given cipher text using RSA decryption.
 *
 * @details    This function decrypts given cipher text using RSA decryption.
 *             It supports TAP Key and SW key for doing RSA decryption.
 *
 * @param pRSAKey       Pointer to RSAKey. It could be MocAsymkey or RSAKey.
 * @param pCipherText   Pointer to the cipher text.
 * @param pPlainText    Pointer to the plain text to be signed.
 * @param pPlainTextLen Pointer to the length of the plain text.
 * @param rngFun        Random function pointer.
 * @param rngFunArg     Argument to the random function.
 * @param ppVlongQueue  Double Pointer to the vlong.
 *
 * @inc_file   crypto_interface_rsa.h
 *
 * @return     \c OK (0) if sucessful; otherwise a negative number error code
 *             defintion from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @funcdoc    crypto_interface_rsa.h
 */
MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_RSA_decryptAux(
  MOC_RSA(hwAccelDescr hwAccelCtx) const RSAKey *pKey,
  const ubyte *pCipherText,
  ubyte *pPlainText,
  ubyte4 *pPlainTextLen,
  RNGFun rngFun,
  void *pRngFunArg,
  vlong **ppVlongQueue
  );

/**
 * @brief Make an RSAKey object from a byte string
 *
 * @param ppKey         Pointer to an RSAKey pointer that will store newly
 *                      created object.
 * @param pByteString   Pointer to buffer storing key bytes
 * @param len           Length of pByteString
 * @param ppVlongQueue Double Pointer to the vlong.
 *
 * @inc_file   crypto_interface_rsa.h
 *
 * @return     \c OK (0) if sucessful; otherwise a negative number error code
 *             defintion from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @funcdoc    crypto_interface_rsa.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_keyFromByteString (
  MOC_RSA(hwAccelDescr hwAccelCtx) RSAKey **ppKey,
  const ubyte* pByteString,
  ubyte4 len,
  vlong** ppVlongQueue
  );

/**
 * @brief Generate a key pair for pRsaKey using pRandomContext for entropy
 *
 * @param pRandomContext    Pointer to random context used for entropy.
 * @param pRsaKey           Pointer to an RSAKey object.
 * @param keySize           ubyte4 containing size of key.
 * @param ppVlongQueue Double Pointer to the vlong.
 *
 * @inc_file   crypto_interface_rsa.h
 *
 * @return     \c OK (0) if sucessful; otherwise a negative number error code
 *             defintion from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @funcdoc    crypto_interface_rsa.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_generateKey (
  MOC_RSA(hwAccelDescr hwAccelCtx) randomContext *pRandomContext,
  RSAKey *pRsaKey,
  ubyte4 keySize,
  vlong **ppVlongQueue
  );

/**
 * @brief      Convert RSA key to a string of (PKCS&nbsp;\#1) bytes.
 *
 * @param pKey          Pointer to RSAKey that will be used to get byte string.
 * @param pBuffer       Pointer to buffer where byte string will be stored.
 * @param keySize       ubyte4 containing size of key
 * @param ppVlongQueue  Double Pointer to the vlong.
 *
 * @inc_file   crypto_interface_rsa.h
 *
 * @return     \c OK (0) if sucessful; otherwise a negative number error code
 *             defintion from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @funcdoc    crypto_interface_rsa.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_byteStringFromKey (
  MOC_RSA(hwAccelDescr hwAccelCtx) const RSAKey *pKey,
  ubyte *pBuffer,
  ubyte4 *pRetLen
  );

/**
 * @brief      Clone (copy) an RSA key.
 *
 * @param ppNewKey     Double pointer to cloned RSAKey.
 * @param pSrc         Pointer RSAKey that will be cloned.
 * @param ppVlongQueue Double Pointer to the vlong.
 *
 * @inc_file   crypto_interface_rsa.h
 *
 * @return     \c OK (0) if sucessful; otherwise a negative number error code
 *             defintion from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @funcdoc    crypto_interface_rsa.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_cloneKey (
  MOC_RSA(hwAccelDescr hwAccelCtx)
  RSAKey **ppNewKey,
  const RSAKey *pSrc,
  vlong **ppVlongQueue
  );

/**
 * @brief      Determine whether two RSA keys are equal.
 *
 * @param pKey1     Pointer to an RSAKey that will be compared.
 * @param pKey2     Pointer to other RSAKey that will be compared.
 * @param pRes      Pointer to result of comparison.
 *
 * @inc_file   crypto_interface_rsa.h
 *
 * @return     \c OK (0) if sucessful; otherwise a negative number error code
 *             defintion from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @funcdoc    crypto_interface_rsa.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_equalKey (
  MOC_RSA(hwAccelDescr hwAccelCtx)
  const RSAKey *pKey1,
  const RSAKey *pKey2,
  byteBoolean *pRes
  );

/**
 * @brief      Determine whether two RSA keys are equal.
 *
 * @param pKey1     Pointer to an RSAKey that will be compared.
 * @param pKey2     Pointer to other RSAKey that will be compared.
 * @param pRes      Pointer to result of comparison.
 *
 * @inc_file   crypto_interface_rsa.h
 *
 * @return     \c OK (0) if sucessful; otherwise a negative number error code
 *             defintion from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @funcdoc    crypto_interface_rsa.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_getKeyParametersAllocAux (
  MOC_RSA(hwAccelDescr hwAccelCtx)
  RSAKey *pKey,
  MRsaKeyTemplate *pTemplate,
  ubyte keyType
  );

/**
 * Used to generated PKCS 1.5 padded data.
 *
 * @param pKey              The RSA key to use for this operation.
 * @param operation         PKCS 1.5 includes a block type byte used to denote the
 *                          type of operation being performed. This must be
 *                          MOC_ASYM_KEY_FUNCTION_SIGN for signing.
 * @param rngFun            The RNG function pointer used to generated random
 *                          bytes.
 * @param rngFunArg         The RNG function pointer argument.
 * @param pM                The plaintext message to be padded.
 * @param mLen              Length in bytes of the input message to be padded.
 * @param ppRetPaddedMsg    Pointer to the pointer which will be allocated by this
 *                          function and which will recieve the resulting PKCS 1.5
 *                          encoded message.
 * @param pRetPaddedMsgLen  Pointer to the location that will recieve the byte
 *                          length of the resulting PKCS 1.5 encoded message.
 *
 * @return               \c OK (0) if successful; otherwise a negative number
 *                       error code definition from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_pkcs15Pad(
  MOC_RSA(hwAccelDescr hwAccelCtx)
  RSAKey *pKey,
  ubyte4 operation,
  RNGFun rngFun,
  void *pRngFunArg,
  ubyte *pM,
  ubyte4 mLen,
  ubyte **ppRetPaddedMsg,
  ubyte4 *pRetPaddedMsgLen
  );

/**
 * Gets the bitlength of an RSA key
 *
 * @param pKey     The RSA key in question.
 * @param pBitLen  Contents will be set to the key's bitlength
 *
 * @return               \c OK (0) if successful; otherwise a negative number
 *                       error code definition from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_getKeyBitLen(
  MOC_RSA(hwAccelDescr hwAccelCtx)
  RSAKey *pKey,
  ubyte4 *pBitLen
);

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_RSA_HEADER__ */
