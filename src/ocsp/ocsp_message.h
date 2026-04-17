/*
 * ocsp_message.h
 *
 * OCSP definitions and message generation and parsing routines
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

#ifndef __OCSP_MESSAGE_HEADER__
#define __OCSP_MESSAGE_HEADER__

#if (defined(__ENABLE_DIGICERT_OCSP_CLIENT__))

#ifdef __cplusplus
extern "C" {
#endif

/*------------------------------------------------------------------*/

/* APIs to be used internally by ocsp_client and not to be exposed  */
MOC_EXTERN MSTATUS OCSP_MESSAGE_generateSingleRequest(ocspContext *pOcspContext, OCSP_singleRequestInfo *pSingleRequestInfo, OCSP_singleRequest *pSingleRequest);
MOC_EXTERN MSTATUS OCSP_MESSAGE_generateRequestInternal(ocspContext *pOcspContext, OCSP_singleRequest** pRequests,ubyte4 requestCount, extensions *pExts, ubyte4 extCount, ubyte** ppRetRequest, ubyte4* pRetRequestLen);
MOC_EXTERN MSTATUS OCSP_MESSAGE_parseResponse(ocspContext *pOcspContext, ubyte* pResponses, ubyte4 responsesLen);
MOC_EXTERN MSTATUS OCSP_MESSAGE_getResponseStatus(ocspContext *pOcspContext, OCSP_responseStatus *pStatus);
MOC_EXTERN MSTATUS OCSP_MESSAGE_getResponderId(ocspContext *pOcspContext, OCSP_responderId **ppResponderId);
MOC_EXTERN MSTATUS OCSP_MESSAGE_goToNextResponse(ocspContext *pOcspContext);
MOC_EXTERN MSTATUS OCSP_MESSAGE_getProducedAt(ocspContext *pOcspContext, TimeDate *pTime);
MOC_EXTERN MSTATUS OCSP_MESSAGE_getExtensions(ocspContext *pOcspContext, extensions **ppExts, ubyte4 *pExtCount);
MOC_EXTERN MSTATUS OCSP_MESSAGE_getCurrentCertId(ocspContext *pOcspContext, OCSP_certID **ppCertId);
MOC_EXTERN MSTATUS OCSP_MESSAGE_getCurrentThisUpdate(ocspContext *pOcspContext, TimeDate *pTime);
MOC_EXTERN MSTATUS OCSP_MESSAGE_getCurrentNextUpdate(ocspContext *pOcspContext, TimeDate *pTime, byteBoolean *pIsNextUpdate);
MOC_EXTERN MSTATUS OCSP_MESSAGE_getCurrentSingleExtensions(ocspContext *pOcspContext, extensions **ppExts, ubyte4 *pExtCount);
MOC_EXTERN MSTATUS OCSP_MESSAGE_getCurrentCertStatus(ocspContext *pOcspContext, OCSP_certStatus **ppStatus);
MOC_EXTERN MSTATUS OCSP_MESSAGE_generateSingleRequestEx(ocspContext *pOcspContext, ubyte* pCertSerialNo, ubyte4 serialNoLen, OCSP_singleRequestInfo *pSingleRequestInfo, OCSP_singleRequest *pSingleRequest);
MOC_EXTERN MSTATUS OCSP_MESSAGE_addExtension(DER_ITEMPTR pRequestExt, extensions *pExt);
MOC_EXTERN MSTATUS OCSP_MESSAGE_addNonce(ocspContext *pOcspContext, DER_ITEMPTR pRequestExt);

#ifdef __cplusplus
}
#endif

#endif /* __ENABLE_DIGICERT_OCSP_CLIENT__ */
#endif  /* __OCSP_MESSAGE_HEADER__ */
