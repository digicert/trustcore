/**
 * @file  scep_message.h
 * @brief SCEP definitions and message generation and parsing routines
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 *
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert's Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt
 *   or https://www.digicert.com/master-services-agreement/
 *
 * For commercial licensing, contact DigiCert at sales@digicert.com.
 *
 */

/**
@file       scep_message.h
@ingroup    nanofunc_scep_message_tree
@brief      SCEP Message APIs.
@details    This file contains APIs to prepare PKCS#7 request
            and parse the PKCS#7 response.
@flags      This file requires the following flag to be defined:
    + \c \__ENABLE_DIGICERT_SCEP_CLIENT__

@filedoc    scep_message.h
*/


#ifndef __SCEP_MESSAGE_HEADER__
#define __SCEP_MESSAGE_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __ENABLE_DIGICERT_SCEP_CLIENT__

struct pkcsCtxInternal;
/*------------------------------------------------------------------*/

/* SCEP OID definitions */
/*
@private
@internal
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
MOC_EXTERN const ubyte verisign_OID[]; /*2 16 840 1 113733*/
MOC_EXTERN const ubyte verisign_pki_OID[]; /*2 16 840 1 113733 1*/
MOC_EXTERN const ubyte verisign_pkiAttrs_OID[]; /*2 16 840 1 113733 1 9*/
MOC_EXTERN const ubyte verisign_pkiAttrs_messageType_OID[]; /*2 16 840 1 113733 1 9 2*/
MOC_EXTERN const ubyte verisign_pkiAttrs_pkiStatus_OID[]; /*2 16 840 1 113733 1 9 3*/
MOC_EXTERN const ubyte verisign_pkiAttrs_failInfo_OID[]; /*2 16 840 1 113733 1 9 4*/
MOC_EXTERN const ubyte verisign_pkiAttrs_senderNonce_OID[]; /*2 16 840 1 113733 1 9 5*/
MOC_EXTERN const ubyte verisign_pkiAttrs_recipientNonce_OID[]; /*2 16 840 1 113733 1 9 6*/
MOC_EXTERN const ubyte verisign_pkiAttrs_transId_OID[]; /*2 16 840 1 113733 1 9 7*/
MOC_EXTERN const ubyte verisign_pkiAttrs_extensionReq_OID[]; /*2 16 840 1 113733 1 9 8*/

/*------------------------------------------------------------------*/

/* exported routines */

/**
@ingroup    func_scep_message
@brief      Generate PKCS#7 request message.

@details    Generate PKCS#7 request message. This routine does the following:
            1. envelope the payload with an encryption key encrypted with CA/RA's public key;
            2. creating transaction attributes
            3. sign 1 and 2 with requester's certificate (could be self-signed)
            4. encapsulate 3 inside contentInfo with SignedData type
            The generated PKCS#7 request message is returned in ppPkiMessage.

@param pPkcsCtx         Pointer to the pkcsCtxInternal structure.
@param pScepContext     Pointer to the scepContext structure.
@param ppPkiMesage      On return, pointer to the PKCS#7 request.
@param pPkuMessageLen   On return, length of the PKCS#7 request.

@inc_file   scep_message.h

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    scep_message.h
*/
MOC_EXTERN MSTATUS
SCEP_MESSAGE_generatePkiRequestMessage(pkcsCtxInternal *pPkcsCtx,
                                       scepContext *pScepContext,
                                       ubyte** ppPkiMessage, ubyte4* pPkiMessageLen);
/**
@ingroup    func_scep_message
@brief      Generate a PKCS#7 degenerate signed data.

@details    Generates a PKCS#7 degenerate signed data.

@param pCertificate     Pointer to the certificate which is used for signing.
@param certificateLen   Length of the certificate which is used for signing.
@param pCACertificates  Pointer to the list of ca certificates.
@param pCAStreams       Pointer to the CA streams.
@param numCACerts       Number of CA certificates.
@param pCrl             Pointer to the CRL.
@param crlLen           Length of the CRL
@param pCrlStreams      Pointer to the list of CA streams.
@param numCrls          Number of the CRLs.
@param ppSigned         On return, pointer to the signed data.
@param pSignedLen       On return, length of the signed data.

@inc_file   scep_message.h

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    scep_message.h
*/
MOC_EXTERN MSTATUS
SCEP_MESSAGE_generateDegenerateSignedData(ubyte *pCertificate, ubyte4 certificateLen,
                                          ASN1_ITEMPTR pCACertificates[/*numCACerts*/], /* could be NULL if no CA certs supplied */
                                          CStream pCAStreams[/*numCACerts*/],
                                          sbyte4 numCACerts,
                                          ubyte *pCrl, ubyte4 crlLen,
                                          ASN1_ITEMPTR pCrls[/*numCrls*/],
                                          CStream pCrlStreams[/*numCrls*/],
                                          sbyte4 numCrls,
                                          ubyte **ppSigned, ubyte4 *pSignedLen);

/**
@ingroup    func_scep_message
@brief      Generate a PKCS#7 response message.

@details    Parse a PKCS#7 response message. This routine does the following:
            1. verify signedData signature etc
            2. get messageType, transactionId and status
            3. if status is SUCCESS, retrieve certificates or CRLs;
              if status is Pending, caller of this method should start timed periodic polling;
              if status is failure, the reason for failure is in the failureInfo.
            The response content is recorded in scepContext.pReceivedData.
            If the response content is certificate(s), an extra ASN1 item is included
            to encapsulate the certificate/certificates for easy parsing by an ASN1 parser;
            If the response content is CRL(s), it is retrieved.
            For other response types, this routine is not called.
            Instead, the raw response content is recorded in scepContext.pReceivedData.

@param pPkcsCtx         Pointer to the pkcsCtxInternal structure.
@param pScepContext     Pointer to the scepContext structure.
@param type             Type of the SCEP response. Possible values:
                         \ref x_pki_message
                         \ref x_x509_ca_cert
                         \ref x_x509_ca_ra_cert
                         \ref x_x509_ca_ra_cert_chain
                         \ref xml
@param pCertRep         On return, pointer to the certificate returned by the server.
@param certRepLen       On return, length of the certificate returned by the server.

@inc_file   scep_message.h

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    scep_message.h
*/
MOC_EXTERN MSTATUS
SCEP_MESSAGE_parsePkcsResponse(pkcsCtxInternal *pPkcsCtx,
                               scepContext *pScepContext, SCEP_responseType type,
                               ubyte* pCertRep, ubyte4 certRepLen);
/**
@ingroup    func_scep_message
@brief      Parses the PKCS#7 envelop data.

@details    This function parses the PKCS#7 envelop data.

@param pPkcsCtx         Pointer to the pkcsCtxInternal structure.
@param pScepContext     Pointer to the scepContext structure.
@param pRequest         Pointer to the PKCS#7 envelop data to be parsed.
@param requestLen       Length of the PKCS#7 envelop data length.

@inc_file   scep_message.h

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    scep_message.h
*/
MOC_EXTERN MSTATUS
SCEP_MESSAGE_parsePkiRequest(pkcsCtxInternal *pPkcsCtx, scepContext *pScepContext,
                             ubyte *pRequest, ubyte4 requestLen);

/**
@ingroup    func_scep_message
@brief      This function breaks the CSR request into number of lines.

@details    This function breaks the CSR request into number of lines
            based on the line length limit.

@param pLineCsr         Pointer to the request.
@param lineCsrLength    Length of the request.
@param ppRetCsr         On return, pointer to the final request.
@param requestLen       On return, length of the final request.

@inc_file   scep_message.h

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    scep_message.h
*/
MOC_EXTERN MSTATUS
SCEP_MESSAGE_breakIntoLines(ubyte* pLineCsr, ubyte4 lineCsrLength,
        ubyte **ppRetCsr, ubyte4 *p_retCsrLength);

/**
@ingroup    func_scep_message
@brief      Generates PKCS#10 CSR request.

@details    This function generates PKCS#10 CSR request.

@param key              Pointer to the asymmetric key with which CSR
                        to be signed.
@param pReqInfo         Pointer to the requestInfo structure.
@param pPayLoad         On return, pointer to the PKCS#10 CSR request.
@param pPayLoadLen      On return, pointer to the PKCS#10 CSR request length.

@inc_file   scep_message.h

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    scep_message.h
*/
MOC_EXTERN MSTATUS
SCEP_MESSAGE_generatePayLoad(AsymmetricKey *key, requestInfo *pReqInfo, ubyte** pPayLoad, ubyte4* pPayLoadLen);


#endif /* #ifdef __ENABLE_DIGICERT_SCEP_CLIENT__ */

#ifdef __cplusplus
}
#endif

#endif  /*#ifndef __SCEP_MESSAGE_HEADER__ */
