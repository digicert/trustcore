/*
 * ocsp_client.h
 *
 * OCSP Client Specific Methods Header
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
@file       ocsp_client.h
@brief      NanoCert OCSP Client developer API header.
@details    This header file contains definitions, structures, and function
            declarations used by OCSP Client developer API functions.

@since 4.2
@version 5.3 and later

@flags
To enable this file's definitions, you must define the following flag in moptions.h:
+ \c \__ENABLE_DIGICERT_OCSP_CLIENT__

@filedoc    ocsp_client.h
*/

#ifndef __OCSP_CLIENT_HEADER__
#define __OCSP_CLIENT_HEADER__

#if (defined(__ENABLE_DIGICERT_OCSP_CLIENT__))

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __ENABLE_DIGICERT_OCSP_CERT_VERIFY__
#include "../../crypto/cert_chain.h"
#endif

/*------------------------------------------------------------------*/

/* API's exposed to the application developers                      */
MOC_EXTERN MSTATUS OCSP_CLIENT_createContext(ocspContext **ppOcspContext);
MOC_EXTERN MSTATUS OCSP_CLIENT_createContextLocal(ocspContext **ppOcspContext);
MOC_EXTERN MSTATUS OCSP_CLIENT_generateRequest(ocspContext *pOcspContext, extensions *pExts, ubyte4 extCount, ubyte **ppRetRequest, ubyte4     *pRetRequestLen);
MOC_EXTERN MSTATUS OCSP_CLIENT_getResponderIdfromCert(ubyte *pCert, ubyte4 certLen, ubyte **uriStr);
/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
MOC_EXTERN MSTATUS OCSP_CLIENT_getResponderIdfromCertExtension(ASN1_ITEM *pExtension, CStream cs, ubyte **uriStr);
MOC_EXTERN MSTATUS OCSP_CLIENT_getResponseStatus(ocspContext *pOcspContext, OCSP_responseStatus *pStatus);
MOC_EXTERN MSTATUS OCSP_CLIENT_parseResponse(ocspContext *pOcspContext, ubyte* pResponses, ubyte4 responsesLen);
MOC_EXTERN MSTATUS OCSP_CLIENT_getProducedAt(ocspContext *pOcspContext, TimeDate *pTime);
MOC_EXTERN MSTATUS OCSP_CLIENT_getCurrentCertStatus(ocspContext *pOcspContext, OCSP_certStatus **ppStatus);
MOC_EXTERN MSTATUS OCSP_CLIENT_getCurrentCertId(ocspContext *pOcspContext, OCSP_certID **ppCertId);
MOC_EXTERN MSTATUS OCSP_CLIENT_getCurrentThisUpdate(ocspContext *pOcspContext, TimeDate *pTime);
MOC_EXTERN MSTATUS OCSP_CLIENT_getCurrentNextUpdate(ocspContext *pOcspContext, TimeDate *pTime, byteBoolean *pIsNextUpdate);
MOC_EXTERN MSTATUS OCSP_CLIENT_goToNextResponse(ocspContext *pOcspContext);
MOC_EXTERN MSTATUS OCSP_CLIENT_releaseContext(ocspContext **ppOcspContext);
MOC_EXTERN MSTATUS OCSP_CLIENT_releaseContextLocal(ocspContext **ppOcspContext);

#ifdef __ENABLE_DIGICERT_OCSP_CERT_VERIFY__
MOC_EXTERN MSTATUS
OCSP_CLIENT_getCertStatus(sbyte *pOcspCAUrl, ubyte *pCertificate, ubyte4 certLen,
                         certChainPtr pCertChain, const ubyte *pAnchorCert, ubyte4 anchorCertLen) ;
#endif /* __ENABLE_DIGICERT_OCSP_CERT_VERIFY__ */

#ifdef __cplusplus
}
#endif

#endif /* __ENABLE_DIGICERT_OCSP_CLIENT__ */
#endif /* __OCSP_CLIENT_HEADER__ */
