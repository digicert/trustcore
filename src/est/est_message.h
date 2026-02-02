/**
 * @file  est_message.h
 * @brief EST definitions and message generation and parsing routines
 *
 * Copyright 2026 DigiCert Project Authors. All Rights Reserved.
 *
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert's Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt
 *   or https://www.digicert.com/master-services-agreement/
 *
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

#ifndef __EST_MESSAGE_HEADER__
#define __EST_MESSAGE_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__ENABLE_DIGICERT_EST_CLIENT__)

struct pkcsCtxInternal;
/*------------------------------------------------------------------*/

/* EST OID definitions */
/*
        Private OID Definitions

        The OIDs used in defining pkiStatus are VeriSign self-maintained
        OIDs. Please note, work is in progress to replace the VeriSign owned
        object identifiers with the standard object identifiers. Once the
        standarlization is completed, this documentation will be updated.

        id-VeriSign   OBJECT_IDENTIFIER ::= {2 16 US(840) 1 VeriSign(113733)}
        id-pki        OBJECT_IDENTIFIER ::= {id-VeriSign pki(1)}
        id-attributes OBJECT_IDENTIFIER ::= {id-pki attributes(9)}
        id-messageType  OBJECT_IDENTIFIER ::= {id-attributes messageType(2)}
        id-pkiStatus    OBJECT_IDENTIFIER ::= {id-attributes pkiStatus(3)}
        id-failInfo     OBJECT_IDENTIFIER ::= {id-attributes failInfo(4)}
        id-senderNonce  OBJECT_IDENTIFIER ::= {id-attributes senderNonce(5)}
        id-recipientNonce OBJECT_IDENTIFIER ::= {id-attributes recipientNonce(6)}
        id-transId        OBJECT_IDENTIFIER ::= {id-attributes transId(7)}
        id-extensionReq   OBJECT_IDENTIFIER ::= {id-attributes extensionReq(8)}
*/
MOC_EXTERN const ubyte est_verisign_OID[]; /*2 16 840 1 113733*/
MOC_EXTERN const ubyte est_verisign_pki_OID[]; /*2 16 840 1 113733 1*/
MOC_EXTERN const ubyte est_verisign_pkiAttrs_OID[]; /*2 16 840 1 113733 1 9*/
MOC_EXTERN const ubyte est_verisign_pkiAttrs_messageType_OID[]; /*2 16 840 1 113733 1 9 2*/
MOC_EXTERN const ubyte est_verisign_pkiAttrs_pkiStatus_OID[]; /*2 16 840 1 113733 1 9 3*/
MOC_EXTERN const ubyte est_verisign_pkiAttrs_failInfo_OID[]; /*2 16 840 1 113733 1 9 4*/
MOC_EXTERN const ubyte est_verisign_pkiAttrs_senderNonce_OID[]; /*2 16 840 1 113733 1 9 5*/
MOC_EXTERN const ubyte est_verisign_pkiAttrs_recipientNonce_OID[]; /*2 16 840 1 113733 1 9 6*/
MOC_EXTERN const ubyte est_verisign_pkiAttrs_transId_OID[]; /*2 16 840 1 113733 1 9 7*/
MOC_EXTERN const ubyte est_verisign_pkiAttrs_extensionReq_OID[]; /*2 16 840 1 113733 1 9 8*/

/*------------------------------------------------------------------*/

/* exported routines */

MOC_EXTERN MSTATUS
EST_MESSAGE_generateDegenerateSignedData(MOC_HW(hwAccelDescr hwAccelCtx) ubyte *pCertificate, ubyte4 certificateLen,
                                          ASN1_ITEMPTR pCACertificates[/*numCACerts*/], /* could be NULL if no CA certs supplied */
                                          CStream pCAStreams[/*numCACerts*/],
                                          sbyte4 numCACerts,
                                          ubyte *pCrl, ubyte4 crlLen,
                                          ASN1_ITEMPTR pCrls[/*numCrls*/],
                                          CStream pCrlStreams[/*numCrls*/],
                                          sbyte4 numCrls,
                                          ubyte **ppSigned, ubyte4 *pSignedLen);

/* Parse a PKCS# 7 response message. This routine does the following:
 *  1. verify signedData signature etc
 *  2. get messageType, transactionId and status
 *  3. if status is SUCCESS, retrieve certificates or crls;
 *     if status is Pending, caller of this method should start timed periodic polling;
 *     if status is failure, the reason for failure is in the failureInfo.
 *   The response content is recorded in estContext.pReceivedData.
 *   If the response content is certificate(s), an extra ASN1 item is included
 *   to encapsulate the certificate/certificates for easy parsing by an ASN1 parser;
 *   If the response content is crl(s), it is retrieved.
 *   For other response types, this routine is not called.
 *   Instead, the raw response content is recorded in estContext.pReceivedData.
 *
 *   pCertRep is the pkcs7 data returned by server.
*/
MOC_EXTERN MSTATUS
EST_MESSAGE_parsePkcsResponse(pkcsCtxInternal *pPkcsCtx,
	estContext *pEstContext, EST_responseType type, ubyte* pCertRep, ubyte4 certRepLen);

/* Parse a PKCS# 7 response message. This routine does the following:
 *  1. verify signedData signature etc
 *  2. get messageType, transactionId and status
 *  3. if status is SUCCESS, retrieve certificates or crls;
 *     if status is Pending, caller of this method should start timed periodic polling;
 *     if status is failure, the reason for failure is in the failureInfo.
 *   The response content is recorded in pResp.
 *   If the response content is certificate(s), an extra ASN1 item is included
 *   to encapsulate the certificate/certificates for easy parsing by an ASN1 parser;
 *   If the response content is crl(s), it is retrieved.
 *   For other response types, this routine is not called.
 *   Instead, the raw response content is recorded in estContext.pReceivedData.
 *
 *   pCertRep is the pkcs7 data returned by server.
*/
MOC_EXTERN MSTATUS
EST_MESSAGE_parseResponse(EST_responseType type, ubyte* pCertRep, ubyte4 certRepLen, ubyte **pResp, ubyte4 *respLen);

MOC_EXTERN MSTATUS
EST_MESSAGE_CertReqToCSR( const ubyte* pCertReq, ubyte4 certReqLen,
                    ubyte** ppCsr, ubyte4* pCsrLength);

#endif /* #ifdef __ENABLE_DIGICERT_EST_CLIENT__ */

#ifdef __cplusplus
}
#endif

#endif  /*#ifndef __EST_MESSAGE_HEADER__ */
