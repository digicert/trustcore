/*
 * ssh_cert.h
 *
 * SSH Certificate Processing Center Header
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


/*------------------------------------------------------------------*/

#ifndef __SSH_CERT_HEADER__
#define __SSH_CERT_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SSH_RSA_MIN_SIZE
#define SSH_RSA_MIN_SIZE            (1024)
#endif

#define SSH_RSA_2048_SIZE           (2048)

#ifndef SSH_RSA_MAX_SIZE
#define SSH_RSA_MAX_SIZE            (4096)
#endif

#define SSH_RFC_DSA_SIZE            (1024)

#define SSH_ECDSA_P192_SIZE         (192)
#define SSH_ECDSA_P224_SIZE         (224)
#define SSH_ECDSA_P256_SIZE         (256)
#define SSH_ECDSA_P384_SIZE         (384)
#define SSH_ECDSA_P521_SIZE         (521)
#define SSH_ECDSA_MAX_SIZE          (521)

/*------------------------------------------------------------------*/
/**
 * @brief Converts SSH authentication type and key parameters to a certificate key algorithm.
 *
 * @details Maps the SSH authentication type (e.g., RSA, ECDSA, PQC, Hybrid) and key parameters
 * to internal certificate key algorithm IDs and public key type, for use in certificate selection.
 *
 * @param authType         SSH authentication type
 * @param qsAlgoId         Quantum-safe algorithm ID (if applicable)
 * @param keySize          Key size in bits
 * @param pRetPubKeyType   Output:  public key type
 * @param ppAlgoIdList     Output: allocated algorithm ID list
 * @param pAlgoIdListLen   Output: length of algorithm ID list
 *
 * @return  \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS SSH_CERT_convertAuthTypeToKeyAlgo(ubyte4 authType, ubyte4 qsAlgoId, ubyte4 keySize, ubyte4 *pRetPubKeyType, 
                                                     ubyte4 **ppAlgoIdList, ubyte4 *pAlgoIdListLen);

#if (defined(__ENABLE_DIGICERT_SSH_SERVER__))
/**
 *  @brief Builds a raw DSA certificate.
 * 
 *  @param pContextSSH       Pointer to the SSH context
 *  @param pCertificate      (Unused)
 *  @param certificateLength (Unused)
 * 
 *  @return \c OK (0) if successful; otherwise a negative number error code
 *         definition from merrors.h. To retrieve a string containing an
 *         English text error identifier corresponding to the function's
 *         returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS SSH_CERT_buildRawDsaCert(sshContext *pContextSSH, ubyte *pCertificate, ubyte4 certificateLength);

/**
 *  @brief Builds a raw RSA certificate.
 * 
 *  @param pContextSSH       Pointer to the SSH context
 *  @param pCertificate      (Unused)
 *  @param certificateLength (Unused)
 * 
 *  @return \c OK (0) if successful; otherwise a negative number error code
 *         definition from merrors.h. To retrieve a string containing an
 *         English text error identifier corresponding to the function's
 *         returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS SSH_CERT_buildRawRsaCert(sshContext *pContextSSH, ubyte *pCertificate, ubyte4 certificateLength);

#if (defined(__ENABLE_DIGICERT_PQC__))
/**
 *  @brief Builds a raw PQC X.509v3 certificate.
 * 
 *  @param pContextSSH       Pointer to the SSH context
 *  @param pCertificate      Certificate chain
 *  @param certificateLength Number of certificates in the chain
 * 
 *  @return \c OK (0) if successful; otherwise a negative number error code
 *         definition from merrors.h. To retrieve a string containing an
 *         English text error identifier corresponding to the function's
 *         returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS SSH_CERT_buildCertQs(sshContext *pContextSSH, SizedBuffer *pCertificates, ubyte4 numCertificates);
#endif

#if defined(__ENABLE_DIGICERT_PQC_COMPOSITE__)
/**
 *  @brief Builds a hybrid X.509v3 certificate.
 * 
 *  @param pContextSSH       Pointer to the SSH context
 *  @param pCertificates     Certificate chain
 *  @param numCertificates   Number of certificates in the chain
 * 
 *  @return \c OK (0) if successful; otherwise a negative number error code
 *         definition from merrors.h. To retrieve a string containing an
 *         English text error identifier corresponding to the function's
 *         returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS SSH_CERT_buildCertHybrid(sshContext *pContextSSH, SizedBuffer *pCertificates, ubyte4 numCertificates);
#endif

#if (defined(__ENABLE_DIGICERT_ECC__))
/**
 *  @brief Builds a raw ECDSA certificate.
 * 
 *  @param pContextSSH       Pointer to the SSH context
 *  @param pCertificate      (Unused)
 *  @param certificateLength (Unused)
 * 
 *  @return \c OK (0) if successful; otherwise a negative number error code
 *         definition from merrors.h. To retrieve a string containing an
 *         English text error identifier corresponding to the function's
 *         returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS SSH_TRANS_buildRawEcdsaCert(sshContext *pContextSSH, ubyte *pCertificate, ubyte4 certificateLength);

/**
 * @brief Builds a raw ECDSA X.509v3 certificate for P256.
 * @param pContextSSH       Pointer to the SSH context
 * @param pCertificates     Certificate chain
 * @param numCertificates   Number of certificates in the chain
 * 
 * @return \c OK (0) if successful; otherwise a negative number error code
 *         definition from merrors.h. To retrieve a string containing an
 *         English text error identifier corresponding to the function's
 *         returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS SSH_CERT_buildCertECDSAP256(sshContext *pContextSSH, SizedBuffer *pCertificates, ubyte4 numCertificates);

/**
 * @brief Builds a raw ECDSA X.509v3 certificate for P384.
 * @param pContextSSH       Pointer to the SSH context
 * @param pCertificates     Certificate chain
 * @param numCertificates   Number of certificates in the chain
 * 
 * @return \c OK (0) if successful; otherwise a negative number error code
 *         definition from merrors.h. To retrieve a string containing an
 *         English text error identifier corresponding to the function's
 *         returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS SSH_CERT_buildCertECDSAP384(sshContext *pContextSSH, SizedBuffer *pCertificates, ubyte4 numCertificates);

/**
 * @brief Builds a raw ECDSA X.509v3 certificate for P521.
 * @param pContextSSH       Pointer to the SSH context
 * @param pCertificates     Certificate chain
 * @param numCertificates   Number of certificates in the chain
 * 
 * @return \c OK (0) if successful; otherwise a negative number error code
 *         definition from merrors.h. To retrieve a string containing an
 *         English text error identifier corresponding to the function's
 *         returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS SSH_CERT_buildCertECDSAP521(sshContext *pContextSSH, SizedBuffer *pCertificates, ubyte4 numCertificates);
#endif

/**
 * @brief Builds an SSH RSA X.509v3 certificate.
 * 
 * @param pContextSSH       Pointer to the SSH context
 * @param pCertificates     Certificate chain
 * @param numCertificates   Number of certificates in the chain
 * 
 * @return \c OK (0) if successful; otherwise a negative number error code
 *        definition from merrors.h. To retrieve a string containing an
 *        English text error identifier corresponding to the function's
 *        returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS SSH_CERT_buildCertRSA(sshContext *pContextSSH, SizedBuffer *pCertificates, ubyte4 numCertificates);

/**
 * @brief Builds an SSH RSA 2048 X.509v3 certificate.
 * 
 * @param pContextSSH       Pointer to the SSH context
 * @param pCertificates     Certificate chain
 * @param numCertificates   Number of certificates in the chain
 * 
 * @return \c OK (0) if successful; otherwise a negative number error code
 *       definition from merrors.h. To retrieve a string containing an
 *       English text error identifier corresponding to the function's
 *       returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS SSH_CERT_buildCertRSA2048(sshContext *pContextSSH, SizedBuffer *pCertificates, ubyte4 numCertificates);
#endif
#ifdef __cplusplus
}
#endif


#endif /* __SSH_CERT_HEADER__ */
