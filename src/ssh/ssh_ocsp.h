/*
 * ssh_ocsp.h
 *
 * OCSP for SSH support of Certificates Specific Methods Header
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


#ifndef __SSH_OCSP_HEADER__
#define __SSH_OCSP_HEADER__

#if ((defined(__ENABLE_DIGICERT_SSH_OCSP_SUPPORT__)) && (defined(__ENABLE_DIGICERT_OCSP_CLIENT__)))

/**
 * Gets an OCSP response for a certificate and issuer.
 *
 * @param pResponderUrl     OCSP responder URL (optional, may be NULL).
 * @param ocspTimeout       OCSP timeout (if enabled).
 * @param pCertificate      Certificate to check.
 * @param certLen           Length of certificate.
 * @param pIssuerCert       Issuer certificate.
 * @param issuerCertLen     Length of issuer certificate.
 * @param ppResponse        Output: pointer to OCSP response buffer.
 * @param pRetResponseLen   Output: length of OCSP response.
 * 
 * @return  \c OK (0) if successful; otherwise a negative number error code
 *           definition from merrors.h. To retrieve a string containing an
 *           English text error identifier corresponding to the function's
 *           returned error status, use the \c DISPLAY_ERROR macro.
 */
#if (defined(__ENABLE_DIGICERT_OCSP_TIMEOUT_CONFIG__))
MOC_EXTERN MSTATUS SSH_OCSP_getOcspResponse(sbyte *pResponderUrl, ubyte4 ocspTimeout, ubyte *pCertificate, ubyte4 certLen, ubyte *pIssuerCert, ubyte4 issuerCertLen, ubyte **ppResponse, ubyte4 *pRetResponseLen);
#else
MOC_EXTERN MSTATUS SSH_OCSP_getOcspResponse(sbyte *pResponderUrl, ubyte *pCertificate, ubyte4 certLen, ubyte *pIssuerCert, ubyte4 issuerCertLen, ubyte **ppResponse, ubyte4 *pRetResponseLen);
#endif /* __ENABLE_DIGICERT_OCSP_TIMEOUT_CONFIG__ */

/**
 * Validates an OCSP response for a certificate and issuer.
 *
 * @param pCertificate      Certificate to check.
 * @param certLen           Length of certificate.
 * @param pIssuerCert       Issuer certificate.
 * @param issuerLen         Length of issuer certificate.
 * @param pResponse         OCSP response bytes.
 * @param responseLen       Length of OCSP response.
 * @param pCertOcspStatus   Output: 0=good, 1=revoked, 2=unknown.
 * @param pIsValid          Output: 1 if response is valid, 0 otherwise.
 * 
 * @return  \c OK (0) if successful; otherwise a negative number error code
 *           definition from merrors.h. To retrieve a string containing an
 *           English text error identifier corresponding to the function's
 *           returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS SSH_OCSP_validateOcspResponse(ubyte *pCertificate, ubyte4 certLen, ubyte *pIssuerCert, ubyte4 issuerCertLen, ubyte* pResponse, ubyte4 responseLen, ubyte* pCertOcspStatus, ubyte* pIsValid);

#endif /* __ENABLE_DIGICERT_SSH_OCSP_SUPPORT__ && __ENABLE_DIGICERT_OCSP_CLIENT__ */
#endif /* __SSH_OCSP_HEADER__ */
