/*
 * ssh_hybrid.h
 *
 * SSH Hybrid Host Keys
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

#ifndef __SSH_HYBRID_HEADER__
#define __SSH_HYBRID_HEADER__

/**
 * Checks if a hybrid algorithm entry name matches a supported algorithm.
 *
 * @param pHybridEntryName Input algorithm name as an SSH string buffer.
 * @param pFound           Output: set to 0 if found, -1 otherwise.
 * 
 * @return  \c OK (0) if successful; otherwise a negative number error code
 *          definition from merrors.h. To retrieve a string containing an
 *          English text error identifier corresponding to the function's
 *          returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS SSH_HYBRID_verifyAlgorithmName(const sshStringBuffer *pHybridEntryName, sbyte4 *pFound);

/**
 * Checks if a hybrid algorithm name matches a supported algorithm.
 *
 * @param pHybridName      Input algorithm name as a byte array.
 * @param hybridName       Length of the input algorithm name.
 * @param pFound           Output: set to 0 if found, -1 otherwise.
 * 
 * @return  \c OK (0) if successful; otherwise a negative number error code
 *          definition from merrors.h. To retrieve a string containing an
 *          English text error identifier corresponding to the function's
 *          returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS SSH_HYBRID_verifyAlgorithmNameEx(const ubyte *pHybridName, ubyte4 hybridName, sbyte4 *pFound);

/**
 * Retrieves the SSH algorithm name for a given hybrid key/certificate.
 *
 * @param curveId        ECC curve identifier.
 * @param qsAlgoId       Post-quantum algorithm identifier.
 * @param isCertificate  Nonzero for certificate, zero for key.
 * @param ppAlgoName     Output: pointer to the SSH string buffer with the algorithm name.
 * @return  \c OK (0) if successful; otherwise a negative number error code
 *          definition from merrors.h. To retrieve a string containing an
 *          English text error identifier corresponding to the function's
 *          returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS SSH_HYBRID_getHybridAlgorithmName(ubyte4 curveId, ubyte4 qsAlgoId, ubyte4 isCertificate, sshStringBuffer **ppAlgoName);

/**
 * Looks up curve and PQ algorithm IDs for a given hybrid algorithm name.
 *
 * @param pHybridEntryName Input SSH string buffer with algorithm name.
 * @param pCurveId         Output: curve ID.
 * @param pQsAlgoId        Output: post-quantum algorithm ID.
 * 
 * @return  \c OK (0) if successful; otherwise a negative number error code
 *          definition from merrors.h. To retrieve a string containing an
 *          English text error identifier corresponding to the function's
 *          returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS SSH_HYBRID_getHybridIdsByName(const sshStringBuffer* pHybridEntryName, ubyte4 *pCurveId, ubyte4 *pQsAlgoId);

/**
 * Extracts a hybrid (ECC + post-quantum) public key from an SSH key blob.
 *
 * @param pPublicKeyBlob  Input SSH key blob.
 * @param pPublicKey      Output: filled asymmetric key structure.
 * @param index           Index
 * @param ppVlongQueue    Output: pointer to a queue of vlongs.
 * @return  \c OK (0) if successful; otherwise a negative number error code
 *          definition from merrors.h. To retrieve a string containing an
 *          English text error identifier corresponding to the function's
 *          returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS SSH_HYBRID_extractHybridKey(MOC_ASYM(hwAccelDescr hwAccelCtx) sshStringBuffer* pPublicKeyBlob, AsymmetricKey *pPublicKey, ubyte4 index, vlong **ppVlongQueue);

/**
 * Builds an SSH hybrid public key blob from a hybrid AsymmetricKey.
 *
 * @param pKey               Input: hybrid AsymmetricKey.
 * @param isCertificate      Nonzero for certificate, zero for key.
 * @param isServer           Nonzero for server, zero for client.
 * @param ppPublicKeyBlob    Output: pointer to allocated SSH key blob.
 * @param pPublicKeyBlobLen  Output: length of the key blob.
 * 
 * @return  \c OK (0) if successful; otherwise a negative number error code
 *          definition from merrors.h. To retrieve a string containing an
 *          English text error identifier corresponding to the function's
 *          returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS SSH_HYBRID_buildHybridKey(MOC_ASYM(hwAccelDescr hwAccelCtx) AsymmetricKey *pPublicKey, intBoolean isCertificate,
                                             intBoolean isServer, ubyte **ppPublicKeyBlob, ubyte4 *pPublicKeyBlobLen);
/**
 * Calculates the maximum possible length of a hybrid SSH signature.
 *
 * @param pKey              Input: hybrid AsymmetricKey.
 * @param isCertificate     Nonzero for certificate, zero for key.
 * @param pSignatureLength  Output: maximum signature length in bytes.
 * 
 * @return  \c OK (0) if successful; otherwise a negative number error code
 *          definition from merrors.h. To retrieve a string containing an
 *          English text error identifier corresponding to the function's
 *          returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS SSH_HYBRID_calcHybridSignatureLength(MOC_ASYM(hwAccelDescr hwAccelCtx) AsymmetricKey *pKey, intBoolean isCertificate, ubyte4 *pSignatureLength);

/**
 * Builds a hybrid (ECC + post-quantum) SSH signature in wire format.
 *
 * @param pKey              Input: hybrid AsymmetricKey.
 * @param isCertificate     Nonzero for certificate, zero for key.
 * @param isServer          Nonzero for server, zero for client.
 * @param pHash             Input hash to sign.
 * @param hashLen           Length of the hash.
 * @param ppSignature       Output: pointer to allocated signature blob.
 * @param pSignatureLength  Output: length of the signature blob.
 * 
 * @return  \c OK (0) if successful; otherwise a negative number error code
 *          definition from merrors.h. To retrieve a string containing an
 *          English text error identifier corresponding to the function's
 *          returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS SSH_HYBRID_buildHybridSignature(MOC_ASYM(hwAccelDescr hwAccelCtx) AsymmetricKey *pKey, intBoolean isCertificate,
                                                   intBoolean isServer, const ubyte* hash,
                                                   ubyte4 hashLen, ubyte **ppSignature, ubyte4 *pSignatureLength);

/**
 * Verifies a hybrid (ECC + post-quantum) SSH signature.
 *
 * @param pPublicKey        Input: hybrid public key.
 * @param isServer          Nonzero for server, zero for client.
 * @param hash              Input hash to verify.
 * @param hashLen           Length of the hash.
 * @param pSignature        Input: SSH signature blob.
 * @param pIsGoodSignature  Output: set to 1 if signature is valid, 0 otherwise.
 * @param ppVlongQueue      Output: pointer to vlong queue.
 * 
 * @return  \c OK (0) if successful; otherwise a negative number error code
 *          definition from merrors.h. To retrieve a string containing an
 *          English text error identifier corresponding to the function's
 *          returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS SSH_HYBRID_verifyHybridSignature(MOC_ASYM(hwAccelDescr hwAccelCtx) AsymmetricKey *pPublicKey, intBoolean isServer, const ubyte* hash, ubyte4 hashLen, sshStringBuffer* pSignature, intBoolean *pIsGoodSignature, vlong **ppVlongQueue);

#endif /* __SSH_HYBRID_HEADER__ */

