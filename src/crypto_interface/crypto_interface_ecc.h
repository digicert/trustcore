/*
 * crypto_interface_ecc.h
 *
 * Cryptographic Interface header file for declaring ECC functions
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
@file       crypto_interface_ecc.h
@brief      Cryptographic Interface header file for declaring ECC functions.
@details    Add details here.

@filedoc    crypto_interface_ecc.h
*/
#ifndef __CRYPTO_INTERFACE_ECC_HEADER__
#define __CRYPTO_INTERFACE_ECC_HEADER__

#include "../cap/capasym.h"

#ifdef __cplusplus
extern "C" {
#endif
    
/**
 * Create a new key from a curve identifier. This function will allocate a new
 * key object, it is the callers responsibility to free this memory by calling
 * CRYPTO_INTERFACE_EC_deleteKeyAux.
 *
 * @param curveId        One of the cid_EC_* values from ca_mgmt.h indicating the
 *                       curve this key should be created on.
 * @param ppNewKey       Pointer to the location that will receive the new key.
 * @param keyType        The key type, must be akt_tap_ecc if this is a TAP key,
 *                       and akt_ecc otherwise.
 * @param pKeyAttributes Pointer to a key attribute structure.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_newKeyEx (
  ubyte4 curveId,
  ECCKey** ppNewKey,
  ubyte4 keyType,
  void *pKeyAttributes
  );

/**
 * Determines if a key is a private key or a public key.
 *
 * @param pKey     Pointer to a previously existing key
 * @param pResult  Will be set to TRUE if a private key, FALSE if a public key
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 **/
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_isKeyPrivate (
  ECCKey *pKey,
  intBoolean *pResult
  );

/**
 * Generate a key pair on the curve specified from the curve id. Note that in
 * general this should be used instead of EC_generateKeyPairEx. This function
 * will allocate the ECCKey for you, it is the callers responsibility to free
 * the key object using EC_deleteKey. Note that this API can generate both
 * TAP and SW keys.
 *
 * @param curveId        One of the cid_EC_* values from ca_mgmt.h indicating the
 *                       curve this key should be created on.
 * @param ppNewKey       Pointer to the location that will recieve the generated key.
 * @param rngFun         Function pointer for generating the random values. If you have
 *                       a randomContext you would like to use, simply pass
 *                       RANDOM_rngFun for this param and the randomContext as the rngArg.
 * @param rngArg         Argument to the rngFun. If you have a randomContext you would
 *                       like to use, pass in RANDOM_rngFun for the rngFun and pass the
 *                       randomContext here as the argument.
 * @param keyType        The key type, must be akt_tap_ecc if this is a TAP key,
 *                       and akt_ecc otherwise.
 * @param pKeyAttributes Pointer to a key attribute structure.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_generateKeyPairAlloc (
  MOC_ECC(hwAccelDescr hwAccelCtx)
  ubyte4 curveId,
  void **ppNewKey,
  RNGFun rngFun,
  void* rngArg,
  ubyte4 keyType,
  void *pKeyAttributes
  );

/**
 * Create a new key from a curve identifier. This function will allocate a new
 * key object, it is the callers responsibility to free this memory by calling
 * EC_deleteKey. Note that this API can only create SW keys.
 *
 * @param curveId        One of the cid_EC_* values from ca_mgmt.h indicating the
 *                       curve this key should be created on.
 * @param ppNewKey       Pointer to the location that will recieve the new key.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_newKeyAux (
  ubyte4 curveId,
  ECCKey** ppNewKey
  );

/**
 * Free an ECC Key.
 *
 * @param ppKey   Double pointer to the key to be deleted.
 *
 * @return        \c OK (0) if successful, otherwise a negative number error
 *                code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_deleteKeyAux (
  ECCKey **ppKey
  );

/**
 * Allocates and clones an existing key. When done with the clone it is the callers
 * responsibility to free the memory of it by calling CRYPTO_INTERFACE_EC_deleteKeyAux.
 *
 * @param ppNewKey Pointer to the location that will receive the new clone.
 * @param pSrc     Pointer to the existing key that is to be cloned.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_cloneKeyAux (
  MOC_ECC(hwAccelDescr hwAccelCtx)
  ECCKey **ppNewKey,
  ECCKey *pSrc
  );

/**
 * Tests if the public key portion of two ECCKeys are equal. WARNING: This
 * does not compare the private key portion.
 *
 * @param pKey1    Pointer to the first key.
 * @param pKey2    Pointer to the second key.
 * @param pRes     Pointer to a byteBoolean that will be set to TRUE if the
 *                 public key is identical and FALSE otherwise.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_equalKeyAux (
  MOC_ECC(hwAccelDescr hwAccelCtx)
  ECCKey *pKey1,
  ECCKey *pKey2,
  byteBoolean *pRes
  );

/**
 * Validate that a given public and private key are consistent. That is to
 * say, this funciton verifies that k * G = Q, where k is the private key scalar,
 * G is generator of the curve, and Q is the public key point. If no public key
 * is provided then the private key is checked for internal consistency.
 *
 * @param pPrivateKey The private value to check against, if no public key is
 *                    provided then this key will also be used for the public
 *                    values.
 * @param pPublicKey  The optional public key to check.
 * @param pVfy        Pointer to the boolean that will receive the verification
 *                    result, TRUE if the keys are consistent and FALSE
 *                    otherwise.
 *
 * @return            \c OK (0) if successful, otherwise a negative number error
 *                    code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_verifyKeyPairAux (
  MOC_ECC(hwAccelDescr hwAccelCtx)
  ECCKey *pPrivateKey,
  ECCKey *pPublicKey,
  byteBoolean *pVfy
  );

/**
 * Check that the public key is valid, which ensures the public point is
 * valid and lies on the curve. For Edward's edDH curves every compressed
 * for public key is valid and pIsValid is always set to TRUE.
 *
 * @param pKey       The public key to be verified.
 * @param pIsValid   Pointer to the byteBoolean that will receive the result
 *                   of the verification check, TRUE if the provided key is
 *                   valid and false otherwise.
 *
 * @return          \c OK (0) if successful, otherwise a negative number error
 *                  code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_verifyPublicKeyAux (
  MOC_ECC(hwAccelDescr hwAccelCtx)
  ECCKey *pKey,
  byteBoolean *pIsValid
  );

/**
 * Get the length of an individual prime field element when represented as a
 * bytestring. For Edward's edDSA curves this is the length of the compressed
 * form, ie 32 bytes for curve25519 and 57 bytes for curve448.
 *
 * @param pKey  The key to retrieve the element bytestring length from.
 * @param pLen  Pointer to the location that will receive the element length.
 *
 * @return      \c OK (0) if successful, otherwise a negative number error
 *              code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_getElementByteStringLenAux (
  ECCKey *pKey,
  ubyte4 *pLen
  );

/**
 * Retrieve the curve identifier from a key previously created with
 * CRYPTO_INTERFACE_EC_newKeyAux or generated with
 * CRYPTO_INTERFACE_EC_generateKeyPairAllocAux.
 *
 * @param pKey      The key to retrieve the curve identifier from.
 * @param pCurveId  The curve identifier, see ca_mgmt.h for possible values.
 *
 * @return          \c OK (0) if successful, otherwise a negative number error
 *                  code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_getCurveIdFromKeyAux (
  ECCKey *pKey,
  ubyte4 *pCurveId
  );

/**
 * Get the length of the public value based on the curve ID. Use this API with
 * the cid_EC_* curve IDs.
 *
 * @param curveId  One of the cid_EC_* values from ca_mgmt.h indicating the
 *                 curve the length should be retrieved from.
 * @param pLen     Pointer to the location that will receive the point length.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_getPointByteStringLenByCurveId (
  ubyte4 curveId,
  ubyte4 *pLen
  );

/**
 * Get the length of the bytestring representation of the public key, typically
 * used to determine the buffer size for
 * CRYPTO_INTERFACE_EC_writePublicKeyToBufferAux. For Edward's curves
 * this is the length of the usual compressed public key form.
 *
 * @param pKey  The key to retrieve the element bytestring length from.
 * @param pLen  Pointer to the location that will receive the point length.
 *
 * @return      \c OK (0) if successful, otherwise a negative number error
 *              code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_getPointByteStringLenAux (
  ECCKey *pKey,
  ubyte4 *pLen
  );

/**
 * Allocates and sets the appropriate keys parameters of pTemplate with
 * that from the passed in pKey. The caller must provide an allocated
 * MEccKeyTemplate structure, which will then have its internal pointers
 * allocated by this function. Note it is the callers responsibility to
 * free this memory using CRYPTO_INTERFACE_EC_freeKeyTemplateAux. keyType
 * should be one of MOC_GET_PUBLIC_KEY_DATA or MOC_GET_PRIVATE_KEY_DATA.
 * The latter option will get both the private and public key parameters
 * and as such can only be used with a private key. Retrieving the
 * public data from a private key is allowed, retrieving private data
 * from a public key is impossible and will result in an error. See the
 * documentation for MEccKeyTemplate in capasym.h for more info on the
 * format of the received key data.
 *
 * @param pKey      The key to retrieve data from.
 * @param pTemplate Pointer to an existing MEccKeyTemplate structure, the
 *                  internal pointers within the structure will be allocated
 *                  by this function.
 * @param keyType   Type of key data to receive, must be one of
 *                  MOC_GET_PUBLIC_KEY_DATA or MOC_GET_PRIVATE_KEY_DATA.
 *
 * @return          \c OK (0) if successful, otherwise a negative number
 *                  error code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_getKeyParametersAllocAux (
  MOC_ECC(hwAccelDescr hwAccelCtx)
  ECCKey *pKey,
  MEccKeyTemplate *pTemplate,
  ubyte reqType
  );

/**
 * Frees the key data stored within the provided template structure.
 *
 * @param pKey      Pointer to the original key the data was retrieved from.
 * @param pTemplate Pointer to a key template structure previously filled using
 *                  CRYPTO_INTERFACE_EC_getKeyParametersAllocAux.
 *
 * @return          \c OK (0) if successful, otherwise a negative number
 *                  error code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_freeKeyTemplateAux (
  ECCKey *pKey,
  MEccKeyTemplate *pTemplate
  );

/**
 * Sets the public key portion of an ECCKey and optionally the private key
 * portion. If the private key portion, ie pScalar, is provided, the key
 * will be treated as a private key, and otherwise it will be treated as a
 * public key.
 *
 * @param pKey       Pointer to a previously allocated key.
 * @param pPoint     Pointer to a buffer representing the public key point. For
 *                   prime curves this is in an uncompressed form, ie the
 *                   uncompressed form byte 0x04 followed by x and then y in
 *                   Big Endian binary. For Edward's curves this is the usual
 *                   Little Endian compressed form. If not provided, the public
 *                   key will still be set in pKey from the private key.
 * @param pointLen   The length of the pPoint buffer in bytes.
 * @param pScalar    Pointer to a buffer representing the private key scalar.
 *                   For prime curves this is in Big Endian. For Edward's
 *                   curves this is the usual Little Endian based form. This
 *                   parameter is optional and may be NULL.
 * @param scalarLen  The length of the pScalar buffer in bytes.
 *
 * @return           \c OK (0) if successful, otherwise a negative number error
 *                   code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_setKeyParametersAux (
  MOC_ECC(hwAccelDescr hwAccelCtx)
  ECCKey *pKey,
  ubyte *pPoint,
  ubyte4 pointLen,
  ubyte *pScalar,
  ubyte4 scalarLen
  );
  
/**
 * @brief   Sets the private key parameter of an ECCKey.
 *
 * @details Sets the private key parameter of an ECCKey. The public key
 *          will be left empty. This API is not available for EdDSA keys.
 *
 * @param pKey       Pointer to a previously allocated key.
 * @param pScalar    Pointer to a buffer representing the private key scalar.
 *                   For prime curves this is in Big Endian. For Edward's
 *                   curves this is the usual Little Endian based form.
 * @param scalarLen  The length of the scalar in bytes.
 *
 * @return  \c OK (0) if successful, otherwise a negative number error
 *          code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_setPrivateKey(
  MOC_ECC(hwAccelDescr hwAccelCtx)
  ECCKey *pKey,
  ubyte *pScalar,
  ubyte4 scalarLen
  );

/**
 * Write the public point to a buffer. The function
 * CRYPTO_INTERFACE_EC_getPointByteStringLenAux can be used to determine how large
 * the public key buffer needs to be. For prime curves the public key is encoded
 * as a single byte to indicate compression status, which is always 0x04
 * (uncompressed) for this function, followed by public values X and Y as big
 * endian bytestrings, zero padded to element length if necessary. This format is
 * described in the Standards for Efficient Cryptography 1: Elliptic Curve
 * Cryptography Ver 1.9 section 2.3.3. For Edward's form curves the usual
 * compressed form public key is written.
 *
 * @param pKey        The key from which the public values are to be extracted
 *                    and written to the provided buffer.
 * @param pBuffer     Pointer to allocated memory that will receive the encoded
 *                    public key.
 * @param bufferSize  The size in bytes of the memory block pointed to by pBuffer,
 *                    must be large enough for the encoded public key. You can use
 *                    CRYPTO_INTERFACE_EC_getPointByteStringLenAux to determine
 *                    this length.
 *
 * @return            \c OK (0) if successful, otherwise a negative number error
 *                    code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_writePublicKeyToBufferAux (
  MOC_ECC(hwAccelDescr hwAccelCtx)
  ECCKey *pKey,
  ubyte *pBuffer,
  ubyte4 bufferSize
  );

/**
 * Allocate a new buffer and writes the public point to it. For prime curves
 * the public key is encoded as a single byte to indicate compression status,
 * which is always 0x04 (uncompressed) for this function, followed by public values
 * X and Y as big endian bytestrings, zero padded to element length if necessary.
 * This format is described in the Standards for Efficient Cryptography 1: Elliptic
 * Curve Cryptography Ver 1.9 section 2.3.3. For Edward's form curves the usual
 * compressed form public key is written.
 *
 * @param pKey        The key from which the public values are to be extracted
 *                    and written to the provided buffer.
 * @param ppBuffer    Double pointer that will be allocated and filled with the
 *                    bytestring representation of the public key.
 * @param pBufferSize The size in bytes of bytestring representation of the
 *                    public key.
 *
 * @return            \c OK (0) if successful, otherwise a negative number error
 *                    code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_writePublicKeyToBufferAllocAux (
  MOC_ECC(hwAccelDescr hwAccelCtx)
  ECCKey *pKey,
  ubyte **ppBuffer,
  ubyte4 *pBufferSize
  );

/**
 * Create a new ECC public key from the bytestring representation of public
 * point. For prime curves the public key must be encoded in the uncompressed
 * form, ie the public key encoding must be a single byte to indicate
 * compression status, always 0x04 for this function, followed by public values
 * X and Y as big endian bytestrings, zero padded to element length if necessary.
 * This format is described in the Standards for Efficient Cryptography 1: Elliptic
 * Curve Cryptography Ver 1.9 section 2.3.3. For Edward's form curves the public
 * key must be in the usual compressed form.
 *
 * @param curveId        One of the cid_EC_* values from ca_mgmt.h
 *                       indicating the curve this key should be created on.
 * @param ppNewKey       Pointer to the location that will receive the new
 *                       public key.
 * @param pByteString    Pointer to a bytestring representation of an ECC
 *                       public key.
 * @param byteStringLen  The length in bytes of the bytestring.
 *
 * @return               \c OK (0) if successful, otherwise a negative number
 *                       error code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_newPublicKeyFromByteStringAux (
  MOC_ECC(hwAccelDescr hwAccelCtx)
  ubyte4 curveId,
  ECCKey **ppNewKey,
  ubyte *pByteString,
  ubyte4 byteStringLen
  );

/**
 * Generate a key pair previously allocated with CRYPTO_INTERFACE_EC_newKeyAux. Note
 * that in general the CRYPTO_INTERFACE_EC_generateKeyPairAllocAux method is
 * recommended for generation.
 *
 * @param pKey       Pointer to an ECCKey shell previously allocated with
 *                   CRYPTO_INTERFACE_EC_newKeyAux.
 * @param rngFun     Function pointer for generating the random values. If you have
 *                   a randomContext you would like to use, simply pass
 *                   RANDOM_rngFun for this param and the randomContext as the rngArg.
 * @param pRngFunArg Argument to the rngFun. If you have a randomContext you would
 *                   like to use, pass in RANDOM_rngFun for the rngFun and pass the
 *                   randomContext here as the argument.
 *
 * @return       \c OK (0) if successful, otherwise a negative number error
 *               code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_generateKeyPairAux (
  MOC_ECC(hwAccelDescr hwAccelCtx)
  ECCKey *pKey,
  RNGFun rngFun,
  void *pRngFunArg
  );

/**
 * Generate a key pair on the curve specified from the curve id. Note that in
 * general this should be used instead of CRYPTO_INTERFACE_EC_generateKeyPairAux.
 * This function will allocate the ECCKey for you, it is the callers responsibility
 * to free the key object using CRYPTO_INTERFACE_EC_deleteKeyAux.
 *
 * @param curveId     One of the cid_EC_* values from ca_mgmt.h indicating the
 *                    curve this key should be created on.
 * @param ppKey       Pointer to the location that will receive the generated key.
 * @param rngFun      Function pointer for generating the random values. If you have
 *                    a randomContext you would like to use, simply pass
 *                    RANDOM_rngFun for this param and the randomContext as the rngArg.
 * @param pRngFunArg  Argument to the rngFun. If you have a randomContext you would
 *                    like to use, pass in RANDOM_rngFun for the rngFun and pass the
 *                    randomContext here as the argument.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_generateKeyPairAllocAux (
  MOC_ECC(hwAccelDescr hwAccelCtx)
  ubyte4 curveId,
  ECCKey **ppKey,
  RNGFun rngFun,
  void *pRngFunArg
  );

/**
 * Perform an ECDSA signing operation on the provided digest, producing the raw
 * signature value. This method may only be used with prime curves. The signature
 * is represented as the concatenation of r and s as big endian bytestrings, zero
 * padded if necessary to ensure each bytestring is exactly elementLen. If you dont
 * know how long the signature will be, you can call this function with a NULL
 * pSignature and a bufferSize of zero. This will result in a return code of
 * ERR_BUFFER_TOO_SMALL and the length of the raw signature will be placed into
 * pSignatureLen. For callers who wish to precompute the buffer size, it will
 * always be exactly (2 * elementLen), where elementLen is the bytestring length
 * of each element on the curve as determined by
 * CRYPTO_INTERFACE_EC_getElementByteStringLenAux.
 *
 * @param pKey             The private key to be used to sign the hash.
 * @param rngFun           Function pointer for generating the random values. If
 *                         you have a randomContext you would like to use, simply
 *                         pass RANDOM_rngFun for this param and the randomContext
 *                         as the rngArg.
 * @param rngArg           Argument to the rngFun. If you have a randomContext you
 *                         would like to use, pass in RANDOM_rngFun for the rngFun
 *                         and pass the randomContext here as the argument.
 * @param pHash            Buffer that contains the hash to be signed.
 * @param hashLen          Length in bytes of the hashed data.
 * @param pSignature       Caller allocated buffer that will receive the raw
 *                         signature.
 * @param bufferSize       Size in bytes of the pSignature buffer.
 * @param pSignatureLen    Pointer to the location that will receive the length
 *                         in bytes of the signature.
 *
 * @return                 \c OK (0) if successful, otherwise a negative number
 *                         error code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_ECDSA_signDigestAux (
  MOC_ECC(hwAccelDescr hwAccelCtx)
  ECCKey *pKey,
  RNGFun rngFun,
  void *rngArg,
  ubyte *pHash,
  ubyte4 hashLen,
  ubyte *pSignature,
  ubyte4 bufferSize,
  ubyte4 *pSignatureLen
  );

/**
 * Verify individual signature values with the provided public key. This method
 * is for prime curves only. Note that this function returns OK even if the
 * verification failed. For this function, a non zero return code means we were
 * not able to properly inspect the signature for verification. This could be due
 * to invalid input such as a NULL pointer or invalid length. If the return
 * status if OK that does not mean the signature verified, rather that we were
 * able to properly check the provided signature. If we were able to check the
 * signature and it didnt verify, then the value pointed to by pVerifyFailures
 * will be non zero. If the return code is OK and the value pointed to by
 * pVerifyFailures is zero, the signature verified.
 *
 * @param pPublicKey      Pointer to the public key used to verify this signature.
 * @param pHash           Buffer containing the original hash that was signed.
 * @param hashLen         Length in bytes of the hashed data.
 * @param pR              Buffer containing the R portion of the signature,
 *                        encoded as a big endian bytestring.
 * @param rLen            Length in bytes of the data in pR buffer.
 * @param pS              Buffer containing the S portion of the signature,
 *                        encoded as a big endian bytestring.
 * @param sLen            Length in bytes of the data in pS buffer.
 * @param pVerifyFailures Pointer to the location that will receive the result
 *                        of the verification check. If that value is zero upon
 *                        return, the signature verified.
 *
 * @return         \c OK (0) for successful completion of the method regardless of
 *                 the validity of the signature. Otherwise a negative number error
 *                 code from merrors.h is returned.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_ECDSA_verifySignatureDigestAux (
  MOC_ECC(hwAccelDescr hwAccelCtx)
  ECCKey *pPublicKey,
  ubyte *pHash,
  ubyte4 hashLen,
  ubyte *pR,
  ubyte4 rLen,
  ubyte *pS,
  ubyte4 sLen,
  ubyte4 *pVerifyFailures
  );

/**
 * Generate an ECDH shared secret from a public and private key. If the keys passed
 * in are prime curve keys then this is the classical ECDH algorithm. If the keys
 * are Edward's form keys then this is the edDH algorithm (which only differs from
 * ECDH in the curve form and key forms). Note that this function will allocate the
 * shared secret and it is the callers responsibility to free that memory using
 * DIGI_FREE.
 *
 * @param pPrivateKey      Pointer to the private key for this operation.
 * @param pPublicKey       Pointer to the public key for this operation.
 * @param ppSharedSecret   Double pointer that will be allocated by this function
 *                         and filled with the shared secret material.
 * @param pSharedSecretLen Pointer to the location that will receive the length of
 *                         the shared secret value in bytes.
 * @param flag             For prime curves only. Flag indicating whether to use
 *                         both the x and y coordinates or just the x coordinate.
 *                         A flag of 1 is for x only, a flag of 0 is for x
 *                         concatenated with y. Each coordinate will be zero
 *                         padded if necassary to the field element length.
 * @param pKdfInfo         Pointer to possible information on a KDF to apply during
 *                         the secret generation process, unused at this time so
 *                         simply pass NULL.
 *
 * @return                 \c OK (0) if successful, otherwise a negative number
 *                         error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_ECDH_generateSharedSecretFromKeysAux (
  MOC_ECC(hwAccelDescr hwAccelCtx)
  ECCKey *pPrivateKey,
  ECCKey *pPublicKey,
  ubyte **ppSharedSecret,
  ubyte4 *pSharedSecretLen,
  sbyte4 flag,
  void *pKdfInfo
  );

/**
 * Generate an ECDH shared secret from private key and bytestring representation
 * of the public point. If the pPrivateKey passed in is a prime curve key then
 * this is the classical ECDH algorithm. If the key is an Edward's form key then
 * this is the edDH algorithm (which only differs from ECDH in the curve form and
 * key forms). For prime curves the public point must be encoded as an uncompressed
 * point per Standards for Efficient Cryptography 1: Elliptic Curve Cryptography
 * Ver 1.9 section 2.3.3.
 *
 * @param pPrivateKey        Pointer to the private key for this operation.
 * @param pPointByteString   Pointer to the bytestring representation of the
 *                           public key to use for this operation.
 * @param pointByteStringLen Length in bytes of the public point bytestring.
 * @param ppSharedSecret     Double pointer that will be allocated by this function
 *                           and filled with the shared secret material.
 * @param pSharedSecretLen   Pointer to the location that will receive the length of
 *                           the shared secret value in bytes.
 * @param flag               For prime curves only. Flag indicating whether to use
 *                           both the x and y coordinates or just the x coordinate.
 *                           A flag of 1 is for x only, a flag of 0 is for x
 *                           concatenated with y. Each coordinate will be zero
 *                           padded if necassary to the field element length.
 * @param pKdfInfo           Pointer to possible information on a KDF to apply during
 *                           the secret generation process, unused at this time so
 *                           simply pass NULL.
 *
 * @return                   \c OK (0) if successful, otherwise a negative number
 *                           error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_ECDH_generateSharedSecretFromPublicByteStringAux (
  MOC_ECC(hwAccelDescr hwAccelCtx)
  ECCKey *pPrivateKey,
  ubyte *pPublicPointByteString,
  ubyte4 pointByteStringLen,
  ubyte **ppSharedSecret,
  ubyte4 *pSharedSecretLen,
  sbyte4 flag,
  void *pKdfInfo
  );

/**
 * @brief   Generates a Diffie-Hellman shared secret via one of the major modes.
 *
 * @details Generates a Diffie-Hellman shared secret via one of the major modes.
 *          This method allocates a buffer to hold the secret. Be sure to FREE
 *          this buffer when done with it.
 *
 * @param mode                  One of the following macro values
 *                              + \c FULL_UNIFIED
 *                              + \c FULL_MQV
 *                              + \c EPHEMERAL_UNIFIED
 *                              + \c ONE_PASS_UNIFIED_U
 *                              + \c ONE_PASS_UNIFIED_V
 *                              + \c ONE_PASS_MQV_U
 *                              + \c ONE_PASS_MQV_V
 *                              + \c ONE_PASS_DH_U
 *                              + \c ONE_PASS_DH_V
 *                              + \c STATIC_UNIFIED                        
 *                  
 * @param pStatic               Our private static key.                             
 * @param pEphemeral            Our private ephemeral key.
 * @param pOtherPartysStatic    The other party's static public key as an uncompressed form byte array.
 * @param otherStaticLen        The length of the uncompressed form static key byte array in bytes.  
 * @param pOtherPartysEphemeral The other party's ephemeral public key as an uncompressed form byte array.
 * @param otherEphemeralLen     The length of the uncompressed form ephemeral key byte array in bytes.  
 * @param ppSharedSecret        Pointer to the location of the newly allocated buffer that will
 *                              store the shared secret.
 * @param pSharedSecretLen      Contents will be set to the length of the shared secret in bytes.
 *
 * @return  \c OK (0) if successful, otherwise a negative number error
 *          code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_ECDH_keyAgreementScheme(
    MOC_ECC(hwAccelDescr hwAccelCtx)
    ubyte4 mode, 
    ECCKey *pStatic, 
    ECCKey *pEphemeral, 
    ubyte *pOtherPartysStatic, 
    ubyte4 otherStaticLen,
    ubyte *pOtherPartysEphemeral,
    ubyte4 otherEphemeralLen,
    ubyte **ppSharedSecret,
    ubyte4 *pSharedSecretLen);

/**
 * Performs an ECDSA sign operation on the message provided. If the pPrivateKey
 * param is a prime curve key then this is the classical ECDSA algorithm. If the
 * pPrivateKey is an Edward's form key then this is the edDSA algorithm.
 *
 * @param pPrivateKey      Pointer to the private key to be used.
 * @param rngFun           For prime curves only. Function pointer for generating
 *                         the random values. If you have a randomContext you would
 *                         like to use, simply pass RANDOM_rngFun for this param
 *                         and the randomContext as the rngArg. Enter NULL for
 *                         Edward's curves.
 * @param pRngArg          For prime curves only. Argument to the rngFun. If you
 *                         have a randomContext you would like to use, pass in
 *                         RANDOM_rngFun for the rngFun and pass the randomContext.
 *                         here as the argument.
 * @param hashAlgo         For prime curves only. One of the enum values in crypto.h
 *                         indicating which hash algorithm should be used to digest
 *                         the message.
 * @param pMessage         Buffer that contains the message to be signed.
 * @param messageLen       Length in bytes of the message data.
 * @param pSignature       Caller allocated buffer that will receive the raw
 *                         signature.
 * @param bufferSize       Size in bytes of the pSignature buffer.
 * @param pSignatureLen    Pointer to the location that will receive the length
 *                         in bytes of the signature.
 * @param pExtCtx          An extended context reserved for future use.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_ECDSA_signMessageExt (
  MOC_ECC(hwAccelDescr hwAccelCtx)
  ECCKey *pPrivateKey,
  RNGFun rngFUN,
  void *pRngArg,
  ubyte hashAlgo,
  ubyte *pMessage,
  ubyte4 messageLen,
  ubyte *pSignature,
  ubyte4 bufferSize,
  ubyte4 *pSignatureLen,
  void *pExtCtx
  );

/**
 * Performs an ECDSA verify operation on the message provided. If the pPublicKey
 * param is a prime curve key then this is the classical ECDSA algorithm. If the
 * pPublicKey is an Edward's form key then this is the edDSA algorithm.
 *
 * @param pPublicKey       Pointer to the public key to be used.
 * @param hashAlgo         For prime curves only. One of the enum values in crypto.h
 *                         indicating which hash algorithm should be used to digest
 *                         the message.
 * @param pMessage         Buffer that contains the message to be verified.
 * @param messageLen       Length in bytes of the message data.
 * @param pSignature       Buffer holding the signature to be verified.
 * @param signatureLen     Size in bytes of the pSignature buffer.
 * @param pVerifyFailures  Will be set to zero for a valid signature and to a non-zero
 *                         value on an invalid signature.
 * @param pExtCtx          An extended context reserved for future use.
 *
 * @return         \c OK (0) for successful completion of the method regardless of
 *                 the validity of the signature. Otherwise a negative number error
 *                 code from merrors.h is returned.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_ECDSA_verifyMessageExt (
  MOC_ECC(hwAccelDescr hwAccelCtx)
  ECCKey *pPublicKey,
  ubyte hashAlgo,
  ubyte *pMessage,
  ubyte4 messageLen,
  ubyte *pSignature,
  ubyte4 signatureLen,
  ubyte4 *pVerifyFailures,
  void *pExtCtx
  );

/**
 * Initializes a context for an ECDSA verify operation. If the pPublicKey
 * param is a prime curve key then this is the classical ECDSA algorithm. If the
 * pPublicKey is an Edward's form key then this is the edDSA algorithm.
 *
 * @param pCtx             Pointer to the ECDSA_CTX to be initialized.
 * @param pPublicKey       Pointer to the public key to be used.
 * @param hashAlgo         For prime curves only. One of the enum values in crypto.h
 *                         indicating which hash algorithm should be used to digest
 *                         the message.
 * @param pSignature       Buffer holding the signature to be verified.
 * @param signatureLen     Size in bytes of the pSignature buffer.
 * @param pExtCtx          An extended context reserved for future use.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_ECDSA_initVerifyExt (
  MOC_ECC(hwAccelDescr hwAccelCtx)
  ECDSA_CTX *pCtx,
  ECCKey *pPublicKey,
  ubyte hashAlgo,
  ubyte *pSignature,
  ubyte4 signatureLen,
  void *pExtCtx
  );

/**
 * Updates a context for an ECDSA verify operation. \c ECDSA_updateVerify may be
 * called as many times as appropriate.
 *
 * @param pCtx        Pointer to a previously initialized context.
 * @param pMessage    Buffer that contains the message or a portion of
 *                    the message to be verified.
 * @param messageLen  Length in bytes of this portion of the message data.
 * @param pExtCtx     An extended context reserved for future use.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_ECDSA_updateVerifyExt (
  MOC_ECC(hwAccelDescr hwAccelCtx)
  ECDSA_CTX *pCtx,
  ubyte *pMessage,
  ubyte4 messageLen,
  void *pExtCtx
  );

/**
 * Finalizes a context for an ECDSA verify operation and computes whether
 * the signature is valid.
 *
 * @param pCtx             Pointer to a previously initialized context.
 * @param pVerifyFailures  Will be set to zero for a valid signature and to a non-zero
 *                         value on an invalid signature.
 * @param pExtCtx          An extended context reserved for future use.
 *
 * @return         \c OK (0) for successful completion of the method regardless of
 *                 the validity of the signature. Otherwise a negative number error
 *                 code from merrors.h is returned.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_ECDSA_finalVerifyExt (
  MOC_ECC(hwAccelDescr hwAccelCtx)
  ECDSA_CTX *pCtx,
  ubyte4 *pVerifyFailures,
  void *pExtCtx
  );

/**
 * Perform an EdDSA signing operation on the provided input. This API allows
 * for HashEdDSA and EdDSActx mode. If you dont know how long the signature
 * will be, you can call this function with a NULL pSignature and a 
 * bufferSize of zero. This will result in a return code of ERR_BUFFER_TOO_SMALL
 * and the length of the raw signature will be placed into pSignatureLen.
 *
 * @param pKey             The private key to be used to sign the digest.
 * @param pInput           Buffer that contains the input to be signed. This is
 *                         the digest for pre-hash mode, or the message otherwise.
 * @param inputLen         Length in bytes of the input.
 * @param isPreHash        \c TRUE for pre hash or HashEdDSA.
 * @param pCtx             Optional. The context byte array for EdDSActx mode.
 * @param ctxLen           The context length in bytes.
 * @param pSignature       Caller allocated buffer that will receive the raw
 *                         signature.
 * @param bufferSize       Size in bytes of the pSignature buffer.
 * @param pSignatureLen    Pointer to the location that will receive the length
 *                         in bytes of the signature.
 * @param pExtCtx          An extended context reserved for future use.
 *
 * @return                 \c OK (0) if successful, otherwise a negative number
 *                         error code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EdDSA_signInput (
    MOC_ECC(hwAccelDescr hwAccelCtx)
    ECCKey *pKey,
    ubyte *pInput,
    ubyte4 inputLen,
    byteBoolean isPreHash,
    ubyte *pCtx,
    ubyte4 ctxLen,
    ubyte *pSignature,
    ubyte4 bufferSize,
    ubyte4 *pSignatureLen,
    void *pExtCtx
    );

/**
 * Performs an EdDSA verify operation on the input provided. This API can be used
 * for HashEdDSA and EdDSActx mode.
 *
 * @param pKey             Pointer to the public key to be used.
 * @param pInput           Buffer that contains the input to be verified. This is
 *                         the digest for pre-hash mode, or the message otherwise.
 * @param inputLen         Length in bytes of the input.
 * @param isPreHash        \c TRUE for pre hash or HashEdDSA.
 * @param pCtx             Optional. The context byte array for EdDSActx mode.
 * @param ctxLen           The context length in bytes.
 * @param pSignature       Buffer holding the signature to be verified.
 * @param signatureLen     Size in bytes of the pSignature buffer.
 * @param pVerifyFailures  Will be set to zero for a valid signature and to a non-zero
 *                         value on an invalid signature.
 * @param pExtCtx          An extended context reserved for future use.
 *
 * @return         \c OK (0) for successful completion of the method regardless of
 *                 the validity of the signature. Otherwise a negative number error
 *                 code from merrors.h is returned.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EdDSA_verifyInput (
    MOC_ECC(hwAccelDescr hwAccelCtx)
    ECCKey *pKey,
    ubyte *pInput,
    ubyte4 inputLen,
    byteBoolean isPreHash,
    ubyte *pCtx,
    ubyte4 ctxLen,
    ubyte *pSignature,
    ubyte4 signatureLen,
    ubyte4 *pVerifyFailures,
    void *pExtCtx
    );

/**
 * Creates mutex's for ecc combs so that only a single thread can create and
 * persist a globally used comb. This method should only be called once at the
 * beginning of your application.
 *
 * @return         \c OK (0) for successful completion. Otherwise a negative number error
 *                 code from merrors.h is returned.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_createCombMutexes(void);


/**
 * Delete's all created global combs for ecc and the associated mutex's. This method
 * should only be called once at the end of your application.
 *
 * @return         \c OK (0) for successful completion. Otherwise a negative number error
 *                 code from merrors.h is returned.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_deleteAllCombsAndMutexes(void);

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_ECC_HEADER__ */
