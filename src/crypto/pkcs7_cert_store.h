/*
 * pkcs7_cert_store.h
 *
 * PKCS7 Callbacks implemented using Certificate Store
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

#ifndef __PKCS7_CERT_STORE_HEADER__
#define __PKCS7_CERT_STORE_HEADER__

#ifdef __cplusplus
extern "C" {
#endif


#if !defined(__DISABLE_DIGICERT_CERTIFICATE_PARSING__)


struct ASN1_ITEM;
/* implementation of the PKCS#7 and PKCS#12 callbacks using a cert store */

/* this callback is used to retrieve the private key that 
 corresponds to an issuer and serial number; key will
 be released by PKCS7 stack */
MOC_EXTERN MSTATUS
CERT_STORE_PKCS7_GetPrivateKey(const void* arg, CStream cs,
                               struct ASN1_ITEM* pSerialNumber,
                               struct ASN1_ITEM* pIssuerName,
                               struct AsymmetricKey* pKey);

/* this callback is used to verify that this certificate is recognized
 as valid */
MOC_EXTERN MSTATUS
CERT_STORE_PKCS7_ValidateRootCertificate(const void* arg, CStream cs,
                                         struct ASN1_ITEM* pCertificate,
                                         sbyte4 chainLength);

/* this callback is used to get a certificate given the issuer name and
 serial number; the ppCertificate will be released by the PKCS7 stack */
MOC_EXTERN MSTATUS
CERT_STORE_PKCS7_GetCertificate(const void* arg, CStream cs,
                                struct ASN1_ITEM* pSerialNumber,
                                struct ASN1_ITEM* pIssuer,
                                ubyte** ppCertificate,
                                ubyte4* certificateLength);

/* used by PKCS#12 */
extern struct PKCS7_Callbacks CERT_STORE_PKCS7Callbacks;

#endif /* !defined(__DISABLE_DIGICERT_CERTIFICATE_PARSING__) */

#ifdef __cplusplus
}
#endif

#endif /* __PKCS7_CERT_STORE_HEADER__ */
