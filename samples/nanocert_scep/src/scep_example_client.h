/**
 * @file  scep_example_client.h
 * @brief SCEP Example Client Sample Application Header File
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 *
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt
 *   or https://www.digicert.com/master-services-agreement/
 *
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

/*------------------------------------------------------------------*/

#ifndef __SCEP_SAMPLE_API_HEADER__
#define __SCEP_SAMPLE_API_HEADER__
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

/* Server type values using MOC as the default */
#define MOC_SCEP_SERVER     0
#define EJBCA_SCEP_SERVER   1
#define ECDSA_SCEP_SERVER   2
#define WIN2003_SCEP_SERVER 3
#define WIN2008_SCEP_SERVER 4
#define WIN2012_SCEP_SERVER 5
#define WIN2016_SCEP_SERVER 6

/* Server type string values for use in argument parsing */
#define MOC_SCEP_SERVER_STR      "MOC"     /* Used as default */
#define EJBCA_SCEP_SERVER_STR    "EJBCA"
#define ECDSA_SCEP_SERVER_STR    "ECDSA"
#define WIN2003_SCEP_SERVER_STR  "WIN2003"
#define WIN2008_SCEP_SERVER_STR  "WIN2008"
#define WIN2012_SCEP_SERVER_STR  "WIN2012"
#define WIN2016_SCEP_SERVER_STR  "WIN2016"

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
#define  SCEP_CA_CERT_FILE        "scep_ca.der"
#define  SCEP_CEP_CERT_FILE       "scep_cep.der"
#define  SCEP_XCHG_CERT_FILE      "scep_xchg.der"
#define  SCEP_ADMIN_CERT_FILE     "scep_admin.der"

/* Definitions for output file names, etc. */
#define KEYBLOB_FILE              "KeyBlob"
#define ADMINKEYBLOB_FILE         "AdminKeyBlob"
#define GENKEYBLOB_FILE           "GenKeyBlob"
#define GENPEMKEY_FILE            "requester_key.pem"
#define GENDERKEY_FILE            "requester_key.der"
#define RENEWALKEYBLOB_FILE       "renewalKeyBlob"
#define RENEWALPEMKEY_FILE        "requester_renewed_key.pem"
#define RENEWALDERKEY_FILE        "renewalDerKey.der"
#define TPMKEYBLOB_FILE           "tpmKeyBlob"
#define REQUESTER_CERT_FILE       "requester_cert.der"
#define REQUESTER_CERT_FILE1      "requester_cert1.der"
#define RENEWED_CERT_FILE         "renewed_cert.der"
#define GET_CERT_FILE             "get_cert.der"
#define GET_CA_CERT_CHAIN_FILE    "cacertchain.der"
#define GET_CRL_FILE              "crls.der"
#define GET_NEXT_CA_CERT_FILE     "next_cacert.der"
#define GET_CA_CAPS_FILE          "cacaps.der"
#define REVOKE_CERT_TEXT_FILE     "revoke_cert.txt"
#define REGISTER_ENTITY_TEXT_FILE "register_entity.txt"
#define UNKNOWN_MESSAGE_TEXT_FILE "unknown_message.txt"
#define PUBLISH_CRL_TEXT_FILE     "publish_CRL.txt"

#define KEY_SOURCE_SW       "SW"
#define KEY_SOURCE_TPM1_2   "TPM1.2"
#define KEY_SOURCE_TPM2     "TPM2"
#define KEY_SOURCE_PKCS11   "PKCS11"
#define KEY_SOURCE_NXPA71   "NXPA71"
#define KEY_SOURCE_STSAFE   "STSAFE"
#define KEY_SOURCE_TEE      "TEE"

#ifdef __ENABLE_DIGICERT_TAP__
#define SCEP_DEF_TAP_MODULEID     1
#endif

#define TEMP_TPM_KEYBLOB "GenKeyBlob"


#if defined(__ENABLE_DIGICERT_TAP__)
#define SCEPC_DEF_KEYSOURCE          "SW"
#endif

#define SCEPC_DEF_KEYTYPE            "RSA"

#define SCEPC_DEF_KEYSIZE          	(2048)
#define MAX_LINE_LENGTH             (256)
#define MAX_NUM_SUBJECTALTNAMES     (10)
#define CSR_CONFIG_FILE             "csr_file"

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

@funcdoc    scep_sample_api.h
*/
MOC_EXTERN MSTATUS
SCEP_SAMPLE_registerScepDataCallback(void *pCallback);

/*------------------------------------------------------------------*/

/**
@brief      Generates Asymmetric Key.

@details    This function generates Asymmetric key. It could be
            a Software key or a TAP key based on the
            keysource parameter.

@param pKeySource              Type of the source. Possible values:
                                SW
                                TPM2
@param pKeyType                Pointer to the key type.
@param keySize                 Size of the key.
@param mh                      Pointer to MOCTAP_HANDLE.
@param pTapContext             Pointer to the TAP_Context.
@param pEntityCredentialList   Pointer to the entitiy credentials.
@param pCredList               Pointer to the key credential list.
@param keyUsage                Key usage value.
@param signScheme              Sign scheme to be used.
@param encScheme               Encryption scheme to be used.
@param ppPemKeyBlob            On return, pointer to the PEM key blob.
@param pPemKeyBlobLen          On return, pointer to the length of the key blob.

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    scep_sample_api.h
*/
MSTATUS
SCEP_SAMPLE_generateAsymKey(sbyte *pKeySource,
                            sbyte *pKeyType,
                            ubyte4 keySize,
#ifdef __ENABLE_DIGICERT_TAP__
                            TAP_Context *pTapContext,
                            TAP_EntityCredentialList *pEntityCredentialList,
                            TAP_CredentialList *pCredList,
                            ubyte keyUsage,
                            ubyte signScheme,
                            ubyte encScheme,
#endif
                            ubyte **ppPemKeyBlob,
                            ubyte4 *pPemKeyBlobLen);

/*------------------------------------------------------------------*/

/**
@brief      Generates certificate signing request.

@details    This function generates a PKCS#10 CSR based on CSR config
            attributes provided.

@param pKeySource         Pointer to the keysource.
@param MOCTAP_HANDLE      Pointer to the TAP handle.
@param pPemKeyBlob        Pointer to the PEM key blob.
@param pemKeyBlobLen      Pointer to the length of the key blob.
@param pCsrAttributes     Pointer to the CSR config buffer.
@param csrAttrsLen        Length of the CSR config buffer.
@param pChallengePass     Pointer to the challenge password.
@param passwordLen        Length of the challenge password.
@param ppCsrBuffer        On return, pointer to the CSR buffer in DER format.
@param pCsrBufferLen      On return, pointer to the length of CSR buffer.
@param ppReqInfo          On return, pointer to the requestInfo. This pointer
                          is required to be sent to SCEP_SAMPLE_sendEnrollmentRequest API.

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    scep_sample_api.h
*/
MSTATUS
SCEP_SAMPLE_generateCSRRequest(sbyte *pKeySource,
                               ubyte *pPemKeyBlob, ubyte4 pemKeyBlobLen,
                               ubyte *pCsrAttributes, ubyte4 csrAttrsLen,
                               sbyte *pChallengePass, ubyte4 passwordLen,
                               ubyte **ppCsrBuffer, ubyte4 *pCsrBufferLen,
                               requestInfo **ppReqInfo);

/*------------------------------------------------------------------*/

/**
@brief      Sends enrollment request to the server.

@details    This function prepares a PKI message and sends the
            enroll request over HTTP. Gets the response from server,
            parses the response and returns the enrolled certificate.

@param pKeySource           Pointer to the keysource.
@param MOCTAP_HANDLE        Pointer to the TAP handle.
@param pHttpContext         Pointer to the httpContext.
@param pPemKeyBlob          Pointer to the PEM key blob.
@param pemKeyBlobLen        Pointer to the length of the key blob.
@param pPkcs10Csr           Pointer to the CSR config buffer.
@param pkcs10CsrLen         Length of the CSR config buffer.
@param pReqInfo             Pointer to the requestInfo.
@param pServerType          Pointer to the null terminated server type.
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
@param  isOaep              For RSA encryption, use oeapPadding. Define
                            \c __ENABLE_DIGICERT_CMS_RSA_OAEP__ for this arg to appear.
@param  oaepHashAlgo        For RSA-OAEP encryption, the hashAlgoId to use. Define
                            \c __ENABLE_DIGICERT_CMS_RSA_OAEP__ for this arg to appear.
@param  pOaepLabel          For RSA-OAEP encryption, the label to use. Define
                            \c __ENABLE_DIGICERT_CMS_RSA_OAEP__ for this arg to appear.
@param ppCert               On return, pointer to the enrolled certificate.
@param pCertLen             On return, pointer to the length of enrolled certificate.
@param ppOutTransactionId   On return, pointer to the transaction ID. This pointer
                            will have some valid value only if the pOutStatus is pending
@param pOutTransactionIdLen On return, pointer to the tansaction ID length.
@param pOutStatus           On return, Pointer to the return status. Possible values:
                            scep_SUCCESS=0, scep_FAILURE=2, scep_PENDING=3.

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    scep_sample_api.c
*/
MSTATUS
SCEP_SAMPLE_sendEnrollmentRequest(sbyte *pKeySource,
                                  httpContext *pHttpContext,
                                  ubyte *pPemKeyBlob, ubyte4 pemKeyBlobLen,
                                  ubyte *pPkcs10Csr, ubyte4 pkcs10CsrLen,
                                  requestInfo *pReqInfo,
                                  ubyte *pServerType, ubyte *pServerUrl,
                                  struct certDescriptor pCACerts[], ubyte4 numCaCerts,
                                  struct certDescriptor pRACerts[], ubyte4 numRaCerts,
                                  struct certDescriptor *pRequesterCert, ubyte4 requestType,
                                  ubyte *pOldPemKeyBlob, ubyte4 oldPemKeyBlobLen,
#ifdef __ENABLE_DIGICERT_CMS_RSA_OAEP__
                                  ubyte isOaep, sbyte *pOaepLabel, ubyte4 oaepHashAlgo,
#endif
                                  ubyte **ppCert, ubyte4 *pCertLen,
                                  sbyte **ppOutTransactionId, ubyte4 *pOutTransactionIdLen,
                                  ubyte4 *pOutStatus);

/*------------------------------------------------------------------*/

/**
@brief      Sends pending enrollment request to the server.

@details    This function prepares a PKI message and send the
            enroll request over HTTP. Get the response from server,
            parse the response and returns the enrolled certificate.
            This can be used only in case of previous request of
            enrollment is pending on server.

@param pKeySource         Pointer to the keysource.
@param MOCTAP_HANDLE      Pointer to the TAP handle.
@param pHttpContext       Pointer to the httpContext.
@param pPemKeyBlob        Pointer to the PEM key blob.
@param pemKeyBlobLen      Pointer to the length of the key blob.
@param pPkcs10Csr         Pointer to the CSR config buffer.
@param pkcs10CsrLen       Length of the CSR config buffer.
@param pServerType        Pointer to the null terminated server type.
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
@param pTrasactionId      Pointer to the null terminated transaction ID.
@param transactionIdLen   Length of the transaction ID.
@param pollInterval       Polling interval.
@param pollCount          Polling count.
@param  isOaep            For RSA encryption, use oeapPadding. Define
                          \c __ENABLE_DIGICERT_CMS_RSA_OAEP__ for this arg to appear.
@param  oaepHashAlgo      For RSA-OAEP encryption, the hashAlgoId to use. Define
                          \c __ENABLE_DIGICERT_CMS_RSA_OAEP__ for this arg to appear.
@param  pOaepLabel        For RSA-OAEP encryption, the label to use. Define
                          \c __ENABLE_DIGICERT_CMS_RSA_OAEP__ for this arg to appear.
@param ppCert             On return, pointer to the enrolled certificate.
@param pCertLen           On return, pointer to the length of enrolled certificate.

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    scep_sample_api.h
*/
MSTATUS
SCEP_SAMPLE_retryPendingEnrollmentRequest(sbyte *pKeySource,
                                  httpContext *pHttpContext,
                                  ubyte *pPemKeyBlob, ubyte4 pemKeyBlobLen,
                                  ubyte *pPkcs10Csr, ubyte4 pkcs10CsrLen,
                                  requestInfo *pReqInfo,
                                  ubyte *pServerType, ubyte *pServerUrl,
                                  struct certDescriptor pCACerts[], ubyte4 numCaCerts,
                                  struct certDescriptor pRACerts[], ubyte4 numRaCerts,
                                  struct certDescriptor *pRequesterCert, ubyte4 requestType,
                                  ubyte *pOldPemKeyBlob, ubyte4 oldPemKeyBlobLen,
                                  sbyte* pTransactionID, ubyte4 transactionIdLen,
                                  const ubyte4 pollInterval, const ubyte4 pollCount,
#ifdef __ENABLE_DIGICERT_CMS_RSA_OAEP__
                                  ubyte isOaep, sbyte *pOaepLabel, ubyte4 oaepHashAlgo,
#endif
                                  ubyte **ppCert, ubyte4 *pCertLen);

/*------------------------------------------------------------------*/

#endif /* __SCEP_SAMPLE_API_HEADER__ */
