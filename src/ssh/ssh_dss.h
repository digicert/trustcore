/*
 * ssh_dss.h
 *
 * SSH DSS/DSA Host Keys
 *
 * Copyright 2026 DigiCert, Inc. All Rights Reserved.
 *
 * DigiCert® TrustCore SDK and TrustEdge are licensed under a dual-license model:
 *
 * 1. **Open Source License**: GNU Affero General Public License v3.0 (AGPL v3).
 * See: https://github.com/digicert/trustcore/blob/main/LICENSE.md
 * 2. **Commercial License**: Available under DigiCert's Master Services Agreement.
 * See: https://www.digicert.com/master-services-agreement/
 *
 * *Use of TrustCore SDK or TrustEdge outside the scope of AGPL v3 requires a commercial license.*
 * *Contact DigiCert at sales@digicert.com for more details.*
 *
 */

#ifndef __SSH_DSS_HEADER__
#define __SSH_DSS_HEADER__

/**
 * @brief Builds an SSH DSA certificate blob from the given DSA key.
 *
 * @details Extracts DSA parameters, encodes them in SSH format, and outputs the certificate blob.
 * 
 * @flags 
 * To enable this function, the following flags must be defined in moptions.h:
 * + \c __ENABLE_DIGICERT_SSH_DSA_SUPPORT__
 * + \c __ENABLE_DIGICERT_SSH_SERVER__ or \c __ENABLE_DIGICERT_SSH_CLIENT__
 * 
 * @param pKey           Pointer to DSA key
 * @param isServer       TRUE for server, FALSE for client
 * @param ppCertificate  Output: pointer to allocated certificate blob
 * @param pRetLen        Output: length of the certificate blob
 * 
 * @return  \c OK (0) if successful; otherwise a negative number error code
 *           definition from merrors.h. To retrieve a string containing an
 *           English text error identifier corresponding to the function's
 *           returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS SSH_DSS_buildDssCertificate(MOC_DSA(hwAccelDescr hwAccelCtx) AsymmetricKey *pKey, intBoolean isServer, ubyte **ppCertificate, ubyte4 *pRetLen);

/**
 * @brief Builds an SSH DSA signature blob for the given message and key.
 *
 * @details Computes the DSA signature and formats it in SSH signature blob format.
 * 
 * @flags 
 * To enable this function, the following flags must be defined in moptions.h:
 * + \c __ENABLE_DIGICERT_SSH_DSA_SUPPORT__
 * + \c __ENABLE_DIGICERT_SSH_SERVER__ or \c __ENABLE_DIGICERT_SSH_CLIENT__
 * 
 * @param pKey             Pointer to DSA key
 * @param isServer         TRUE for server, FALSE for client
 * @param pM               Pointer to the message to be signed
 * @param ppSignature      Output: pointer to allocated signature blob
 * @param pSignatureLength Output: length of the signature blob
 * @param ppVlongQueue     Output: pointer to a queue of vlongs 
 * 
 * @return  \c OK (0) if successful; otherwise a negative number error code
 *          definition from merrors.h. To retrieve a string containing an
 *          English text error identifier corresponding to the function's
 *          returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS SSH_DSS_buildDssSignature(MOC_DSA(hwAccelDescr hwAccelCtx) AsymmetricKey *pKey, intBoolean isServer, vlong *pM, ubyte **ppSignature, ubyte4 *pSignatureLength, vlong **ppVlongQueue);

/**
 * @brief Calculates the length of an SSH DSA signature blob.
 *
 * @details Computes the buffer size needed for a DSA signature in SSH format.
 *
 * @flags 
 * To enable this function, the following flags must be defined in moptions.h:
 * + \c __ENABLE_DIGICERT_SSH_DSA_SUPPORT__
 * + \c __ENABLE_DIGICERT_SSH_SERVER__ or \c __ENABLE_DIGICERT_SSH_CLIENT__
 * 
 * @param pKey              Pointer to DSA key (unused)
 * @param isServer          TRUE for server, FALSE for client
 * @param pSignatureLength  Output: calculated signature length in bytes
 * @param hashLen           Length of the hash used
 * @return \c OK (0) if successful; otherwise a negative number error code
 *          definition from merrors.h. To retrieve a string containing an
 *          English text error identifier corresponding to the function's
 *          returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS SSH_DSS_calcDssSignatureLength(AsymmetricKey *pKey, intBoolean isServer, ubyte4 *pSignatureLength,ubyte4 hashLen);

/**
 * @brief Verifies an SSH DSA signature for a given message and public key.
 *
 * @details Checks the SSH-formatted DSA signature against the message and public key.
 *
 * @flags
 * To enable this function, the following flags must be defined in moptions.h:
 * + \c __ENABLE_DIGICERT_SSH_DSA_SUPPORT__
 * + \c __ENABLE_DIGICERT_SSH_SERVER__ or \c __ENABLE_DIGICERT_SSH_CLIENT__
 *
 * @param pPublicKey       Pointer to DSA public key
 * @param isServer         TRUE for server, FALSE for client
 * @param pM               Pointer to the message to verify
 * @param pSignature       Pointer to SSH-formatted signature buffer
 * @param pIsGoodSignature Output: TRUE if signature is valid, FALSE otherwise
 * @param ppVlongQueue     Output: pointer to a queue of vlongs
 * @return \c OK (0) if successful; otherwise a negative number error code
 *         definition from merrors.h. To retrieve a string containing an
 *         English text error identifier corresponding to the function's
 *         returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS SSH_DSS_verifyDssSignature(MOC_DSA(hwAccelDescr hwAccelCtx) AsymmetricKey *pPublicKey, intBoolean isServer, vlong *pM, sshStringBuffer* pSignature, intBoolean *pIsGoodSignature, vlong **ppVlongQueue);

/**
 * @brief Extracts DSA public key parameters from an SSH key blob.
 *
 * @details Extracts DSA parameters from the SSH key blob and sets them in the given key structure.
 *
 * @flags
 * To enable this function, the following flags must be defined in moptions.h:
 * + \c __ENABLE_DIGICERT_SSH_DSA_SUPPORT__
 * + \c __ENABLE_DIGICERT_SSH_SERVER__ or \c __ENABLE_DIGICERT_SSH_CLIENT__
 *
 * @param pPublicKeyBlob   Pointer to SSH key blob
 * @param pPublicKey       Output: pointer to DSA public key structure
 * @param index            Index in the blob to start extraction
 * @param ppVlongQueue     Output: pointer to a queue of vlongs 
 * 
 * @return \c OK (0) if successful; otherwise a negative number error code
 *         definition from merrors.h. To retrieve a string containing an
 *         English text error identifier corresponding to the function's
 *         returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS SSH_DSS_extractDssCertificate(MOC_ASYM(hwAccelDescr hwAccelCtx) sshStringBuffer* pPublicKeyBlob, AsymmetricKey* pPublicKey, ubyte4 index, vlong **ppVlongQueue);

#endif /* __SSH_DSS_HEADER__ */

