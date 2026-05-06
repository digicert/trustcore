/*
 * trustedge_scep_api.h
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
 */

/**
@file       trustedge_scep_api.h
@brief      SCEP client sample APIs.
@details    This file contains SCEP client sample APIs.

@filedoc    trustedge_scep_api.h
*/

/*------------------------------------------------------------------*/

#ifndef __TRUSTEDGE_SCEP_API_HEADER__
#define __TRUSTEDGE_SCEP_API_HEADER__
/* Server type values using MOC as the default */
#define MOC_SCEP_SERVER     0
#define EJBCA_SCEP_SERVER   1
#define ECDSA_SCEP_SERVER   2
#define WIN2003_SCEP_SERVER 3
#define WIN2008_SCEP_SERVER 4
#define WIN2012_SCEP_SERVER 5
#define WIN2016_SCEP_SERVER 6
#define GEN_GET_SERVER      7
#define GEN_POST_SERVER     8

/* Server type string values for use in argument parsing */
#define MOC_SCEP_SERVER_STR      "MOC"     /* Used as default */
#define EJBCA_SCEP_SERVER_STR    "EJBCA"
#define ECDSA_SCEP_SERVER_STR    "ECDSA"
#define WIN2003_SCEP_SERVER_STR  "WIN2003"
#define WIN2008_SCEP_SERVER_STR  "WIN2008"
#define WIN2012_SCEP_SERVER_STR  "WIN2012"
#define WIN2016_SCEP_SERVER_STR  "WIN2016"
#define GEN_GET_SERVER_STR       "GEN_GET"
#define GEN_POST_SERVER_STR      "GEN_POST"

/*------------------------------------------------------------------*/

#define USER    0
#define ADMIN   1

#define  DEF_SCEP_SERVER_TYPE     MOC_SCEP_SERVER
#define  DEF_SCEP_CHALLENGE_PASS  "password"
#define  DEF_FILENAME             "filename"
#define  DEF_FILEPATH             "."
#define  DEF_FILESEP              '/'
#define  KEY_TYPE_RSA             "RSA"
#define  KEY_TYPE_ECDSA           "ECDSA"
#ifdef __ENABLE_DIGICERT_TAP__
#define KEY_SOURCE_TPM2           "TPM2"
#define KEY_SOURCE_STSAFE         "STSAFE"
#endif

/*  Definitions for input der file names */
#define  SCEP_CA_CERT_FILE_DER        "moc_CA.der"
#define  SCEP_CA_CERT_FILE_PEM        "moc_CA.pem"
#define  SCEP_CEP_CERT_FILE_DER       "moc_CEP.der"
#define  SCEP_CEP_CERT_FILE_PEM       "moc_CEP.pem"

#define  SCEP_XCHG_CERT_FILE_DER      "moc_XCHG.der"
#define  SCEP_XCHG_CERT_FILE_PEM      "moc_XCHG.pem"
#define  SCEP_ADMIN_CERT_FILE_DER     "moc_ADMIN.der"
#define  SCEP_ADMIN_CERT_FILE_PEM     "moc_ADMIN.pem"

/* Definitions for output file names, etc. NOTE: MOST IF NOT ALL OF THESE ARE NO LONGER USED */
#define KEYBLOB_FILE              "KeyBlob"
#define ADMINKEYBLOB_FILE         "AdminKeyBlob"
#define GENKEYBLOB_FILE           "GenKeyBlob"
#define GENPEMKEY_FILE            "GenPemKey.pem"
#define GENDERKEY_FILE            "GenDerKey.der"
#define RENEWALKEYBLOB_FILE       "renewalKeyBlob"
#define RENEWALPEMKEY_FILE        "renewalPemKey.pem"
#define RENEWALDERKEY_FILE        "renewalDerKey.der"
#define TPMKEYBLOB_FILE           "tpmKeyBlob"
#define REQUESTER_CERT_FILE       "requester_cert.der"
#define REQUESTER_CERT_FILE1      "requester_cert1.der"
#define RENEWED_CERT_FILE         "renewed_cert.der"
#define GET_CERT_FILE             "clientcert"
#define GET_CA_CERT_FILE          "cacert"
#define GET_CA_CERT_CHAIN_FILE    "cacertchain.der"
#define GET_CRL_FILE              "certlist"
#define GET_NEXT_CA_CERT_FILE     "nextcacert"
#define GET_CA_CAPS_FILE          "cacaps"
#define REVOKE_CERT_TEXT_FILE     "revoke_cert.txt"
#define REGISTER_ENTITY_TEXT_FILE "register_entity.txt"
#define UNKNOWN_MESSAGE_TEXT_FILE "unknown_message.txt"
#define PUBLISH_CRL_TEXT_FILE     "publish_CRL.txt"

#define SCEPC_DEF_KEYSIZE          	(2048)
#define MAX_LINE_LENGTH             (256)
#define MAX_NUM_SUBJECTALTNAMES     (10)

/*-------------------------------------------------------------------------------------------------------*/

typedef struct _SCEP_data
{
    /* Exchanger certificate */
    ubyte *pExchangerCertificate;

    /* Exchanger certificate length */
    ubyte4 exchangerCertLen;

    /* private key */
    ubyte *pPemKeyBlob;

    /* private key length */
    ubyte4 pemKeyBlobLen;

    ubyte *pKeyPw;
    ubyte4 keyPwLen;

} SCEP_data;

/*------------------------------------------------------------------*/

typedef MSTATUS (*pFuncPtrGetScepData)(SCEP_data **pScepData);

/*------------------------------------------------------------------*/
/**
@brief      Registers callback function, which returns SCEP data.

@details    This function registers callback function, which returns SCEP_data.

@param pCallback Pointer to callback function.

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    trustedge_scep_api.h
*/
MOC_EXTERN MSTATUS
SCEP_SAMPLE_registerScepDataCallback(void *pCallback);

/*------------------------------------------------------------------*/

/**
@brief      Generates certificate signing request.

@details    This function generates a PKCS#10 CSR based on CSR config
            attributes provided.

@param useTap             \c TRUE for TAP hw based keys.
@param hashId             The hash identifier for the CSR signing.
@param pPemKeyBlob        Pointer to the PEM key blob.
@param pemKeyBlobLen      Pointer to the length of the key blob.
@param pKeyPw             Password for pkcs8 or TAP protected keys.
@param keyPwLen           Length of the password in bytes.
@param pCsrAttributes     Pointer to the CSR config buffer.
@param csrAttrsLen        Length of the CSR config buffer.
@param pChallengePass     Pointer to the challenge password.
@param passwordLen        Length of the challenge password.
@param ppCsrBuffer        On return, pointer to the CSR buffer in DER format.
@param pCsrBufferLen      On return, pointer to the length of CSR buffer.
@param ppReqInfo          On return, pointer to the requestInfo. This pointer
                          is required to be sent to SCEP_SAMPLE_sendEnrollmentRequest API.
@param serviceMode        TRUE if scep is running in service mode

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    trustedge_scep_api.h
*/
MSTATUS
SCEP_SAMPLE_generateCSRRequest(byteBoolean useTap, ubyte4 hashId,
                               ubyte *pPemKeyBlob, ubyte4 pemKeyBlobLen,
                               ubyte *pKeyPw, ubyte4 keyPwLen,
                               ubyte *pCsrAttributes, ubyte4 csrAttrsLen,
                               sbyte *pChallengePass, ubyte4 passwordLen,
                               ubyte **ppCsrBuffer, ubyte4 *pCsrBufferLen,
                               requestInfo **ppReqInfo, byteBoolean serviceMode);

/*------------------------------------------------------------------*/

/**
@brief      Sends enrollment request to the server.

@details    This function prepares a PKI message and sends the
            enroll request over HTTP. Gets the response from server,
            parses the response and returns the enrolled certificate.

@param useTap               \c TRUE for TAP hw based keys.
@param pEncAlgoOid          OID for the symmetic key encyption alg.
@param pHashOid             OID for the hash alg.
@param pHttpContext         Pointer to the httpContext.
@param pPemKeyBlob          Pointer to the PEM key blob.
@param pemKeyBlobLen        Pointer to the length of the key blob.
@param pKeyPw               Password for pkcs8 or TAP protected keys.
@param keyPwLen             Length of the password in bytes.
@param pPkcs10Csr           Pointer to the CSR config buffer.
@param pkcs10CsrLen         Length of the CSR config buffer.
@param ppReqInfo            Pointer to the requestInfo.
@param usePost              Does the server allow POST.
@param pServerUrl           Pointer to the null terminated server URL.
@param pCACerts             Pointer to the chain of CA certificates.
@param numCaCerts           Number of CA certificates.
@param pRACerts             Pointer to the chain of RA certificates.
@param numRaCerts           Number of RA certifcates.
@param pRequesterCert       Pointer to the requester certificate.
                            In case of enroll this should be a self signed certificate.
                            In case of renew or rekey this should certificate issued by CA.
@param requestType          Type of the request. Possible values
                            enroll - 1
                            renew  - 2
                            rekey  - 3
@param pOldPemKeyBlob       Pointer to the old key, which was used for enroll.
                            This parameter is only valid in case of rekey.
@param oldPemKeyBlobLen     Length of the old key, which was used for enroll.
                            This parameter is only valid in case of rekey.
@param pOldKeyPw            Password for the existing pkcs8 or TAP protected key.
@param oldKeyPwLen          Length of the password in bytes.
@param isOaep               For RSA encryption, use oeapPadding.
@param oaepHashAlgo         For RSA-OAEP encryption, the hashAlgoId to use.
@param pOaepLabel           For RSA-OAEP encryption, the label to use.
@param ppCert               On return, pointer to the enrolled certificate.
@param pCertLen             On return, pointer to the length of enrolled certificate.
@param ppOutTransactionId   On return, pointer to the transaction ID. This pointer
                            will have some valid value only if the pOutStatus is pending
@param pOutTransactionIdLen On return, pointer to the tansaction ID length.
@param pOutStatus           On return, Pointer to the return status. Possible values:
                            scep_SUCCESS=0, scep_FAILURE=2, scep_PENDING=3.
@param pFailInfo            On return, pointer to detailed information about failure. Possible values:
                            scep_badAlg=0, scep_badMessageCheck=1, scep_badRequest=2,
                            scep_badTime=3, scep_badCertId=4

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    trustedge_scep_api.c
*/
MSTATUS
SCEP_SAMPLE_sendEnrollmentRequest(byteBoolean useTap,
                                  const ubyte *pEncAlgoOid, const ubyte *pHashOid,
                                  httpContext *pHttpContext,
                                  ubyte *pPemKeyBlob, ubyte4 pemKeyBlobLen,
                                  ubyte *pKeyPw, ubyte4 keyPwLen,
                                  ubyte *pPkcs10Csr, ubyte4 pkcs10CsrLen,
                                  requestInfo **ppReqInfo,
                                  byteBoolean usePost, ubyte *pServerUrl,
                                  struct certDescriptor pCACerts[], ubyte4 numCaCerts,
                                  struct certDescriptor pRACerts[], ubyte4 numRaCerts,
                                  struct certDescriptor *pRequesterCert, ubyte4 requestType,
                                  ubyte *pOldPemKeyBlob, ubyte4 oldPemKeyBlobLen,
                                  ubyte *pOldKeyPw, ubyte4 oldKeyPwLen,
                                  ubyte isOaep, sbyte *pOaepLabel, ubyte4 oaepHashAlgo,
                                  ubyte **ppCert, ubyte4 *pCertLen,
                                  sbyte **ppOutTransactionId, ubyte4 *pOutTransactionIdLen,
                                  ubyte4 *pOutStatus, SCEP_failInfo *pFailInfo);

/*------------------------------------------------------------------*/

/**
@brief      Sends pending enrollment request to the server.

@details    This function prepares a PKI message and send the
            enroll request over HTTP. Get the response from server,
            parse the response and returns the enrolled certificate.
            This can be used only in case of previous request of
            enrollment is pending on server.

@param useTap             \c TRUE for TAP hw based keys.
@param pEncAlgoOid        OID for the symmetic key encyption alg.
@param pHashOid           OID for the hash alg.
@param pHttpContext       Pointer to the httpContext.
@param pPemKeyBlob        Pointer to the PEM key blob.
@param pemKeyBlobLen      Pointer to the length of the key blob.
@param keyPwLen           Length of the password in bytes.
@param pPkcs10Csr         Pointer to the CSR config buffer.
@param pPkcs10Csr         Pointer to the CSR config buffer.
@param pkcs10CsrLen       Length of the CSR config buffer.
@param ppReqInfo          Pointer to the requestInfo.
@param usePost            Does the server allow POST.
@param pServerUrl         Pointer to the server URL.
@param pCACerts           Pointer to the chain of CA certificates.
@param numCaCerts         Number of CA certificates.
@param pRACerts           Pointer to the chain of RA certificates.
@param numRaCerts         Number of RA certifcates.
@param pRequesterCert     Pointer to the requester certificate (self-signed certificate).
@param requestType        Type of the request. Possible values
                          enroll - 1
                          renew  - 2
                          rekey  - 3
@param pOldPemKeyBlob     Pointer to the old key, which was used for enroll.
                          This parameter is only valid in case of rekey.
@param oldPemKeyBlobLen   Length of the old key, which was used for enroll.
                          This parameter is only valid in case of rekey.
@param pOldKeyPw          Password for the existing pkcs8 or TAP protected key.
@param oldKeyPwLen        Length of the password in bytes.
@param pTrasactionId      Pointer to the null terminated transaction ID.
@param transactionIdLen   Length of the transaction ID.
@param pollInterval       Polling interval.
@param pollCount          Polling count.
@param isOaep             For RSA encryption, use oeapPadding.
@param oaepHashAlgo       For RSA-OAEP encryption, the hashAlgoId to use.
@param pOaepLabel         For RSA-OAEP encryption, the label to use.
@param ppCert             On return, pointer to the enrolled certificate.
@param pCertLen           On return, pointer to the length of enrolled certificate.
@param pFailInfo          On return, pointer to detailed information about failure. Possible values:
                          scep_badAlg=0, scep_badMessageCheck=1, scep_badRequest=2,
                          scep_badTime=3, scep_badCertId=4

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    trustedge_scep_api.h
*/
MSTATUS
SCEP_SAMPLE_retryPendingEnrollmentRequest(byteBoolean useTap,
                                  const ubyte *pEncAlgoOid, const ubyte *pHashOid,
                                  httpContext *pHttpContext,
                                  ubyte *pPemKeyBlob, ubyte4 pemKeyBlobLen,
                                  ubyte *pKeyPw, ubyte4 keyPwLen,
                                  ubyte *pPkcs10Csr, ubyte4 pkcs10CsrLen,
                                  requestInfo **ppReqInfo,
                                  byteBoolean usePost, ubyte *pServerUrl,
                                  struct certDescriptor pCACerts[], ubyte4 numCaCerts,
                                  struct certDescriptor pRACerts[], ubyte4 numRaCerts,
                                  struct certDescriptor *pRequesterCert, ubyte4 requestType,
                                  ubyte *pOldPemKeyBlob, ubyte4 oldPemKeyBlobLen,
                                  ubyte *pOldKeyPw, ubyte4 oldKeyPwLen,
                                  sbyte* pTransactionID, ubyte4 transactionIdLen,
                                  const ubyte4 pollInterval, const ubyte4 pollCount,
                                  ubyte isOaep, sbyte *pOaepLabel, ubyte4 oaepHashAlgo,
                                  ubyte **ppCert, ubyte4 *pCertLen, SCEP_failInfo *pFailInfo);

/*------------------------------------------------------------------*/

/**
@brief      Sends get certs/crl/capability request to the server

@details    This function prepares a PKI message and send the
            get certs/crl/capability request over HTTP.
            Get the response from server, parse the response
            and returns the enrolled certificate/crl/capability list.

@param pHttpContext         Pointer to the httpContext.
@param usePost              Does the server allow POST.
@param pServerUrl           Pointer to the server URL.
@param ppCert               On return, pointer to the requested certificate/crl/capability list.
@param pCertLen             On return, pointer to the length of requested certificate/crl/capability list.
@param pOutStatus           On return, Pointer to the return status. Possible values:
                            scep_SUCCESS=0, scep_FAILURE=2.
@param messageType          SCEP messageType. This defines the type of operation performed by the SCEP client
@param pFailInfo            On return, pointer to detailed information about failure. Possible values:
                            scep_badAlg=0, scep_badMessageCheck=1, scep_badRequest=2,
                            scep_badTime=3, scep_badCertId=4

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    trustedge_scep_api.h
*/
MSTATUS
SCEP_SAMPLE_fetchCertCRLCapsRequest(httpContext *pHttpContext,
                                    byteBoolean usePost,
                                    ubyte *pServerUrl, ubyte **ppCert,
                                    ubyte4 *pCertLen,
                                    ubyte4 *pOutStatus,
                                    SCEP_messageType messageType,
                                    SCEP_failInfo *pFailInfo);

#endif /* __TRUSTEDGE_SCEP_API_HEADER__ */
