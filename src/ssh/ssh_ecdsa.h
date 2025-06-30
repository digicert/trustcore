/*
 * ssh_ecdsa.h
 *
 * SSH DSS/DSA Host Keys
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

#ifndef __SSH_ECDSA_HEADER__
#define __SSH_ECDSA_HEADER__

/**
 * @brief Generates an SSH ECDSA public key blob.
 *
 * @details Generates an SSH ECDSA public key blob.
 * If pPubKeyBuffer is NULL, the required buffer length is returned in pPubKeyBufferLen.
 *
 * @flags
 * To enable this function, the following flags must be defined in moptions.h:
 * + \c __ENABLE_MOCANA_ECC__
 * + \c __ENABLE_MOCANA_SSH_SERVER__ or \c __ENABLE_MOCANA_SSH_CLIENT__
 *
 * @param pECCKey          Pointer to ECC key
 * @param curveId          Curve identifier
 * @param pPubKeyBuffer    Output: buffer for the encoded key blob (can be NULL to query length)
 * @param pPubKeyBufferLen Input: buffer size; Output: actual length required
 * @return  \c OK (0) if successful; otherwise a negative number error code
 *           definition from merrors.h. To retrieve a string containing an
 *           English text error identifier corresponding to the function's
 *           returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS SSH_ECDSA_generateEccKeyBlob(MOC_ECC(hwAccelDescr hwAccelCtx) ECCKey *pECCKey,  ubyte4 curveId, ubyte *pPubKeyBuffer, ubyte4 *pPubKeyBufferLen);

/**
 * @brief Builds an SSH ECDSA certificate blob from the given ECC key.
 *
 * @details Encodes the ECC public key and curve identifier in SSH wire format and allocates a buffer for the certificate blob.
 *
 * @flags
 * To enable this function, the following flags must be defined in moptions.h:
 * + \c __ENABLE_MOCANA_ECC__
 * + \c __ENABLE_MOCANA_SSH_SERVER__ or \c __ENABLE_MOCANA_SSH_CLIENT__
 *
 * @param pKey           Pointer to ECC key
 * @param isServer       TRUE for server, FALSE for client
 * @param ppCertificate  Output: pointer to allocated certificate blob
 * @param pRetLen        Output: length of the certificate blob
 * @return \c OK (0) if successful; otherwise a negative number error code
 *          definition from merrors.h. To retrieve a string containing an
 *          English text error identifier corresponding to the function's
 *          returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS SSH_ECDSA_buildEcdsaCertificate(MOC_ECC(hwAccelDescr hwAccelCtx) AsymmetricKey *pKey, intBoolean isServer, ubyte **ppCertificate, ubyte4 *pRetLen);

/**
 * @brief Signs a hash using ECDSA and returns r and s values in MPINT format.
 * 
 * @details Signs a given hash using ECDSA and returns the signature components r and s in MPINT format.
 * 
 * @flags
 * To enable this function, the following flags must be defined in moptions.h:
 * + \c __ENABLE_MOCANA_ECC__
 * + \c __ENABLE_MOCANA_SSH_SERVER__ or \c __ENABLE_MOCANA_SSH_CLIENT__
 * 
 * @param pECCKey       Pointer to ECC key
 * @param pHash         Pointer to the hash to be signed
 * @param hashLen       Length of the hash
 * @param ppMpintR      Output: pointer to the MPINT representation of r
 * @param pMpintRLen    Output: length of the MPINT r
 * @param ppMpintS      Output: pointer to the MPINT representation of s
 * @param pMpintSLen    Output: length of the MPINT s
 * 
 * @return \c OK (0) if successful; otherwise a negative number error code
 *         definition from merrors.h. To retrieve a string containing an
 *         English text error identifier corresponding to the function's
 *         returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS SSH_ECDSA_signHash(MOC_ECC(hwAccelDescr hwAccelCtx) ECCKey *pECCKey, const ubyte* pHash, ubyte4 hashLen, ubyte **ppMpintR, ubyte4 *pMpintRLen, ubyte **ppMpintS, ubyte4 *pMpintSLen);

/**
 * @brief Builds an SSH ECDSA signature blob for the given hash and ECC key.
 *
 * @details Generates an ECDSA signature blob for the given hash using the specified ECC key.
 *
 * @flags
 * To enable this function, the following flags must be defined in moptions.h:
 * + \c __ENABLE_MOCANA_ECC__
 * + \c __ENABLE_MOCANA_SSH_SERVER__ or \c __ENABLE_MOCANA_SSH_CLIENT__
 *
 * @param pKey              Pointer to ECC key
 * @param isServer          TRUE for server, FALSE for client
 * @param hash              Pointer to hash to sign
 * @param hashLen           Length of the hash
 * @param ppSignature       Output: pointer to allocated signature blob
 * @param pSignatureLength  Output: length of the signature blob
 * 
 * @return \c OK (0) if successful; otherwise a negative number error code
 *         definition from merrors.h. To retrieve a string containing an
 *         English text error identifier corresponding to the function's
 *         returned error status, use the \c DISPLAY_ERROR macro. 
 */
MOC_EXTERN MSTATUS SSH_ECDSA_buildEcdsaSignature(MOC_ECC(hwAccelDescr hwAccelCtx) AsymmetricKey *pKey, intBoolean isServer, const ubyte* hash, ubyte4 hashLen, ubyte **ppSignature, ubyte4 *pSignatureLength);

/**
 * @brief Builds an SSH ECDSA or Ed25519 signature blob for the given hash and ECC key.
 *
 * @details Generates a signature using the specified hash algorithm and encodes it in SSH wire format.
 * Supports both ECDSA and Ed25519 curves.
 *
 * @flags
 * To enable this function, the following flags must be defined in moptions.h:
 * + \c __ENABLE_MOCANA_ECC__
 * + \c __ENABLE_MOCANA_SSH_SERVER__ or \c __ENABLE_MOCANA_SSH_CLIENT__
 *
 * @param pKey              Pointer to ECC key
 * @param hashAlgo          Hash algorithm identifier
 * @param hash              Pointer to hash to sign
 * @param hashLen           Length of the hash
 * @param ppSignature       Output: pointer to allocated signature blob
 * @param pSignatureLength  Output: length of the signature blob
 * 
 * @return \c OK (0) if successful; otherwise a negative number error code
 *         definition from merrors.h. To retrieve a string containing an
 *         English text error identifier corresponding to the function's
 *         returned error status, use the \c DISPLAY_ERROR macro. 
 */
MOC_EXTERN MSTATUS SSH_ECDSA_buildEcdsaSignatureEx(MOC_ECC(hwAccelDescr hwAccelCtx) AsymmetricKey *pKey, ubyte hashAlgo, const ubyte* hash, ubyte4 hashLen, ubyte **ppSignature, ubyte4 *pSignatureLength);

/**
 * @brief Calculates the maximum length of an SSH ECDSA signature blob.
 *
 * @details Computes the size needed to hold an SSH-formatted ECDSA signature for the given key.
 * 
 * @flags
 * To enable this function, the following flags must be defined in moptions.h:
 * + \c __ENABLE_MOCANA_ECC__
 * + \c __ENABLE_MOCANA_SSH_SERVER__ or \c __ENABLE_MOCANA_SSH_CLIENT__
 *
 * @param pKey              Pointer to ECC key
 * @param isServer          TRUE for server, FALSE for client
 * @param pSignatureLength  Output: maximum signature length in bytes
 * 
 * @return \c OK (0) if successful; otherwise a negative number error code
 *         definition from merrors.h. To retrieve a string containing an
 *         English text error identifier corresponding to the function's
 *         returned error status, use the \c DISPLAY_ERROR macro. 
 */
MOC_EXTERN MSTATUS SSH_ECDSA_calcEcdsaSignatureLength(AsymmetricKey *pKey, intBoolean isServer, ubyte4 *pSignatureLength);

/**
 * @brief Verifies an SSH ECDSA signature for the given hash and public key.
 *
 * @details Verifies the ECDSA signature against the provided hash and public key.
 * 
 * @flags
 * To enable this function, the following flags must be defined in moptions.h:
 * + \c __ENABLE_MOCANA_ECC__
 * + \c __ENABLE_MOCANA_SSH_SERVER__ or \c __ENABLE_MOCANA_SSH_CLIENT__
 *
 * @param pPublicKey        Pointer to ECC public key
 * @param isServer          TRUE for server, FALSE for client
 * @param hash              Pointer to hash
 * @param hashLen           Length of the hash
 * @param pSignature        SSH signature blob to verify
 * @param pIsGoodSignature  Output: TRUE if signature is valid, FALSE otherwise
 * @param ppVlongQueue      Output: pointer to a queue of vlongs used during verification
 * 
 * @return \c OK (0) if successful; otherwise a negative number error code
 *         definition from merrors.h. To retrieve a string containing an
 *         English text error identifier corresponding to the function's
 *         returned error status, use the \c DISPLAY_ERROR macro. 
 */
MOC_EXTERN MSTATUS SSH_ECDSA_verifyEcdsaSignature(MOC_ECC(hwAccelDescr hwAccelCtx) AsymmetricKey *pPublicKey, intBoolean isServer, const ubyte* hash, ubyte4 hashLen, sshStringBuffer* pSignature, intBoolean *pIsGoodSignature, vlong **ppVlongQueue);

/**
 * @brief Verifies ECDSA signature r and s values against a hash and ECC key.
 *
 * @details Verifies the ECDSA signature using the r and s values provided in an SSH string buffer.
 * 
 * @flags
 * To enable this function, the following flags must be defined in moptions.h:
 * + \c __ENABLE_MOCANA_ECC__
 * + \c __ENABLE_MOCANA_SSH_SERVER__ or \c __ENABLE_MOCANA_SSH_CLIENT__
 *
 * @param pECCKey           Pointer to ECC public key
 * @param hash              Pointer to hash that was signed
 * @param hashLen           Length of the hash
 * @param rsString          SSH string buffer containing r and s values
 * @param pIsGoodSignature  Output: TRUE if signature is valid, FALSE otherwise
 * @param ppVlongQueue      Output: pointer to a queue of vlongs used during verification
 * 
 * @return \c OK (0) if successful; otherwise a negative number error code
 *         definition from merrors.h. To retrieve a string containing an
 *         English text error identifier corresponding to the function's
 *         returned error status, use the \c DISPLAY_ERROR macro. 
 */
MOC_EXTERN MSTATUS SSH_ECDSA_verifyRSValue(MOC_ECC(hwAccelDescr hwAccelCtx) ECCKey *pECCKey, const ubyte* hash, ubyte4 hashLen, sshStringBuffer* rsString, intBoolean *pIsGoodSignature, vlong **ppVlongQueue);

/**
 * @brief Verifies an SSH Ed25519 signature for the given data and public key.
 *
 * @details Verifies the Ed25519 signature against the provided data and public key.
 *
 * @flags
 * To enable this function, the following flags must be defined in moptions.h:
 * + \c __ENABLE_MOCANA_ECC__
 * + \c __ENABLE_MOCANA_SSH_SERVER__ or \c __ENABLE_MOCANA_SSH_CLIENT__
 * 
 * @param pPublicKey        Pointer to Ed25519 public key
 * @param hashAlgo          Hash algorithm identifier
 * @param pData             Pointer to data that was signed
 * @param dataLen           Length of the data
 * @param pSignature        SSH signature blob to verify
 * @param pIsGoodSignature  Output: TRUE if signature is valid, FALSE otherwise
 * @param ppVlongQueue      Output: pointer to a queue of vlongs used during verification
 * 
 * @return \c OK (0) if successful; otherwise a negative number error code
 *         definition from merrors.h. To retrieve a string containing an
 *         English text error identifier corresponding to the function's
 *         returned error status, use the \c DISPLAY_ERROR macro. 
 */
MOC_EXTERN MSTATUS SSH_ECDSA_verifyEdDSASignature(MOC_ECC(hwAccelDescr hwAccelCtx) AsymmetricKey *pPublicKey, ubyte hashAlgo, const ubyte* pData, ubyte4 dataLen, sshStringBuffer* pSignature, intBoolean *pIsGoodSignature, vlong **ppVlongQueue);

/**
 * @brief Extracts and loads an SSH ECDSA or Ed25519 public key from an SSH key blob.
 *
 * @details extracts and loads an SSH ECDSA or Ed25519 public key from the provided SSH string buffer.
 * 
 * @flags
 * To enable this function, the following flags must be defined in moptions.h:
 * + \c __ENABLE_MOCANA_ECC__
 * + \c __ENABLE_MOCANA_SSH_SERVER__ or \c __ENABLE_MOCANA_SSH_CLIENT__
 *
 * @param pPublicKeyBlob    SSH string buffer containing the public key blob
 * @param pPublicKey        Output: AsymmetricKey structure to populate
 * @param index             Offset in the blob where the key starts
 * @param ppVlongQueue      Output: pointer to a queue of vlongs used during extraction
 *
 * @return \c OK (0) if successful; otherwise a negative number error code
 *         definition from merrors.h. To retrieve a string containing an
 *         English text error identifier corresponding to the function's
 *         returned error status, use the \c DISPLAY_ERROR macro. 
 */
MOC_EXTERN MSTATUS SSH_ECDSA_extractEcdsaCertificate(MOC_ASYM(hwAccelDescr hwAccelCtx) sshStringBuffer* pPublicKeyBlob, AsymmetricKey* pPublicKey, ubyte4 index, vlong **ppVlongQueue);

#endif /* __SSH_ECDSA_HEADER__ */

