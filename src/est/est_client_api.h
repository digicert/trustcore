/**
 * @file  est_client_api.h
 * @brief EST Client developer API header.
 *
 * @ingroup    nanoaide_tree
 * @details    This header file contains definitions and function
 *             declarations used by EST Clients.
 * @flags      This file requires that the following flags be defined:
 *     + \c \__ENABLE_DIGICERT_EST_CLIENT__
 *     + \c \__ENABLE_DIGICERT_EXAMPLES__
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

/*------------------------------------------------------------------*/

#ifndef __EST_CLIENT_API_HEADER__
#define __EST_CLIENT_API_HEADER__

#include "../cert_enroll/cert_enroll.h"

/*! @cond */
#if (defined (__ENABLE_DIGICERT_EST_CLIENT__) && defined (__ENABLE_DIGICERT_EXAMPLES__))
/*! @endcond */


#ifdef __cplusplus
extern "C" {
#endif

/*! EST_SIMPLE_ENROLL_PKCS - Simpleenroll MIME type */
#define EST_SIMPLE_ENROLL_PKCS          "application/pkcs10"
/*! EST_FULL_CMC_PKCS      - Fullcmc PKCS7 MIME type */
#define EST_FULL_CMC_PKCS               "application/pkcs7"
/*! EST_FULL_CMC_PKCS      - Fullcmc CMC request MIME type */
#define EST_FULL_CMC_MIME_PKCS          "application/pkcs7-mime; smime-type=CMC-request"
/*! EST_PKCS7_MIME         - PKCS7 MIME type */
#define EST_PKCS7_MIME                  "application/pkcs7-mime"


/*! ENROLL -  Request a new certificate  */
#define ENROLL      ((ubyte4)0)
/*! RENEW  -  Renew an existing certificate */
#define RENEW       ((ubyte4)1)
/*! REKEY  -  Renew certificate using a new private key */
#define REKEY       ((ubyte4)2)

/*------------------------------------------------------------------*/

#define MOC_NUM_EXT_KEY_USG_FIELDS 6
#define EST_ENDPOINT_SCHEME       "https"
#define EST_ENDPOINT_WELL_KNOWN   "/.well-known/est/"

typedef struct extKeyUsageInfo
{
    ubyte serverAuth;
    ubyte clientAuth;
    ubyte codeSign;
    ubyte emailProt;
    ubyte timeStamp;
    ubyte ocspSign;
} extKeyUsageInfo;

/**
@ingroup    aide_functions
@brief      This function reopens SSLHandle Connection

@details    This function will first close the current SSLHandle Connection,
             and then open a new SSL Connection.

@param pCertStore              Pointer to the native CertStore.
@param pHttpContext            Pointer to the httpContext.
@param pServerIdentity         Pointer to the server name.
@param serverIdentityLen       Length of the server name.
@param pServerIpAddr           Pointer to the server IP.
@param serverAddrLen           Length of the server IP.
@param portNo                  Port number.
@param pSSLConnectionInstance  On return, Pointer to connection state of SSL.
@param ocspRequired            If TRUE, client will request an OCSP status.
@param enforcePQC              If TRUE, enforces usage of PQC algorithms.

@inc_file   est_client_api.h

@return     \c OK (0) if successful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    est_client_api.h
*/
MOC_EXTERN MSTATUS
EST_reOpenSSLConnection(struct certStore *pCertStore, httpContext *pHttpContext,
										sbyte *pServerIdentity, ubyte4 serverIdentityLen,
										ubyte *pServerIpAddr, ubyte4 serverAddrLen,
										ubyte4 portNo, sbyte4 *pSSLConnectionInstance,
										intBoolean ocspRequired, intBoolean enforcePQC);

/**
@ingroup    aide_functions
@brief      Creates a synchronous client connection context.

@details    This function creates a connection context for secure
             HTTP(S) synchronous connection with a remote server.

@param pCertStore              Pointer to the native CertStore.
@param pServerIpAddr           Pointer to server IP.
@param serverAddrLen           Server IP length.
@param port                    Port number.
@param pServerIdentity         Pointer to the server name.
@param serverIdentityLen       Length of the server name.
@param pConnectionSSLInstance  On return, Pointer to the SSL connection instance.
@param ppHttpContext           On return, Double pointer to the httpContext.
@param pTLSCertAlias           Mutual auth Certificate alias
@param tlsCertAliasLen         Mutual auth Certificate alias length
@param ocspRequired            If TRUE, client will request an OCSP status.
@param enforcePQC              If TRUE, enforces usage of PQC algorithms.

@inc_file   est_client_api.h

@return     \c OK (0) if successful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    est_client_api.h
*/
MOC_EXTERN MSTATUS
EST_openConnection(struct certStore *pCertStore, ubyte *pServerIpAddr,
										ubyte4 serverAddrLen, ubyte4 port, ubyte *pServerIdentity,
										ubyte4 serverIdentityLen, sbyte4 *pConnectionSSLInstance,
										httpContext **ppHttpContext, sbyte *pTLSCertAlias, ubyte4 tlsCertAliasLen,
										intBoolean ocspRequired, intBoolean enforcePQC);

/**
@ingroup    aide_functions
@brief      Closes the connection and release resources.

@details    This function closes a synchronous SSL session.

@param pHttpContext            Pointer to the httpContext.
@param connectionSSLInstance   Connection state of SSL.

@inc_file   est_client_api.h

@return     \c OK (0) if successful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    est_client_api.h
*/
MOC_EXTERN MSTATUS
EST_closeConnection(httpContext *pHttpContext, ubyte4 connectionSSLInstance);

/**
@ingroup    aide_functions
@brief      Sends a cacerts request to the server.

@details    This function sends a cacerts request to the server.

@param pHttpContext            Pointer to the httpContext.
@param connectionSSLInstance   Connection state of SSL.
@param pRequestUrl             Pointer to request URL.
@param requestUrlLen           Request URL length.
@param pServerIdentity         Pointer to the server name.
@param serverIdentityLen       Length of the server name.

@inc_file   est_client_api.h

@return     \c OK (0) if successful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    est_client_api.h
*/
MOC_EXTERN MSTATUS
EST_sendCaCertsRequest(httpContext *pHttpContext, ubyte4 connectionSSLInstance,
										ubyte *pRequestUrl, ubyte4 requestUrlLen,
										ubyte *pServerIdentity, ubyte4 serverIdentityLen,
										sbyte *pUserAgent);

/**
@ingroup    aide_functions
@brief      Sends a csrAttrs request to the server.

@details    This function sends a csrattrs request to the server.

@param pHttpContext            Pointer to the httpContext.
@param connectionSSLInstance   Connection state of SSL.
@param pRequestUrl             Pointer to request URL.
@param requestUrlLen           Length of the request URL.
@param pServerIdentity         Pointer to the server name.
@param serverIdentityLen       Length of the server name.

@inc_file   est_client_api.h

@return     \c OK (0) if successful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    est_client_api.h
*/
MOC_EXTERN MSTATUS
EST_sendCsrAttrsRequest(httpContext *pHttpContext, ubyte4 connectionSSLInstance,
										ubyte *pRequestUrl, ubyte4 requestUrlLen,
										ubyte *pServerIdentity, ubyte4 serverIdentityLen,
										sbyte *pUserAgent);

/**
@ingroup    aide_functions
@brief      Sends a fullcmc request to the server.

@details    This function sends a fullcmc request to the server.

@param pHttpContext            Pointer to the httpContext.
@param connectionSSLInstance   Connection state of SSL.
@param pRequestUrl             Pointer to request URL.
@param requestUrlLen           Length of the request URL.
@param csrReqLen               Length of the CSR request.
@param pServerIdentity         Pointer to the server name.
@param serverIdentityLen       Length of the server name.
@param requestType             Type of the request. Possible values:
                               \ref ENROLL
                               \ref RENEW
                               \ref REKEY

@inc_file   est_client_api.h

@return     \c OK (0) if successful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    est_client_api.h
*/
MOC_EXTERN MSTATUS
EST_sendFullCmcRequest(httpContext *pHttpContext, ubyte4 connectionSSLInstance,
										ubyte *pRequestUrl, ubyte4 requestUrlLen,
										ubyte4 csrReqLen, ubyte *pServerIdentity,
										ubyte4 serverIdentityLen, ubyte4 requestType,
										sbyte *pUserAgent);

/**
@ingroup    aide_functions
@brief      Sends a serverkeygen request to the server.

@details    This function sends a serverkeygen request to the server.

@param pHttpContext          Pointer to the httpContext.
@param connectionSSLInstance Connection state of SSL.
@param pRequestUrl           Pointer to request URL.
@param requestUrlLen         Length of the request URL.
@param csrReqLen             Length of the CSR request.
@param pServerIdentity       Pointer to the server name.
@param serverIdentityLen     Length of the server name.

@inc_file   est_client_api.h

@return     \c OK (0) if successful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    est_client_api.h
*/
MOC_EXTERN MSTATUS
EST_sendServerKeyGenRequest(httpContext *pHttpContext, ubyte4 connectionSSLInstance,
										ubyte *pRequestUrl, ubyte4 requestUrlLen,
										ubyte4 csrReqLen, ubyte *pServerIdentity,
										ubyte4 serverIdentityLen, sbyte *pUserAgent);

/**
@ingroup    aide_functions
@brief      Sends a simpleenroll request to the server.

@details    This function sends a simpleenroll request to the server.

@param pHttpContext          Pointer to the httpContext.
@param connectionSSLInstance Connection state of SSL.
@param pRequestUrl           Pointer to request URL.
@param requestUrlLen         Length of the request URL.
@param csrReqLen             Length of the CSR request.
@param pServerIdentity       Pointer to the server name.
@param serverIdentityLen     Length of the server name.

@inc_file   est_client_api.h

@return     \c OK (0) if successful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    est_client_api.h
*/
MOC_EXTERN MSTATUS
EST_sendSimpleEnrollRequest(httpContext *pHttpContext, ubyte4 connectionSSLInstance,
										ubyte *pRequestUrl, ubyte4 requestUrlLen,
										ubyte4 csrReqLen, ubyte *pServerIdentity,
										ubyte4 serverIdentityLen, sbyte *pUserAgent);


/**
@ingroup    aide_functions
@brief      Sends a simplereenroll request to the server.

@details    This function sends a simplereenroll request to the server.

@param pHttpContext          Pointer to the httpContext.
@param connectionSSLInstance Connection state of SSL.
@param pRequestUrl           Pointer to request URL.
@param requestUrlLen         Length of the request URL.
@param csrReqLen             Length of the CSR request.
@param pServerIdentity       Pointer to the server name.
@param serverIdentityLen     Length of the server name.

@inc_file   est_client_api.h

@return     \c OK (0) if successful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    est_client_api.h
*/
MOC_EXTERN MSTATUS
EST_sendSimpleReEnrollRequest(httpContext *pHttpContext, ubyte4 connectionSSLInstance,
										ubyte *pRequestUrl, ubyte4 requestUrlLen,
										ubyte4 csrReqLen, ubyte *pServerIdentity,
										ubyte4 serverIdentityLen, sbyte *pUserAgent);


/**
@ingroup    aide_functions
@brief      Generates the CSR Request from the config file provided.

@details    This function generates the CSR Request based on the
            configuration file passed.

@param pCertStore             Pointer to the certstore.
@param connectionSSLInstance  SSL connection instance
@param pConfigFile            Pointer to the configuration file path.
                              <br>Example content of configuration file:
@verbatim
# Subject
countryName=US
commonName=Estclient
stateOrProvinceName=California
localityName=San Francisco
organizationName=Digicert Inc
organizationalUnitName=Engineering
# Requested Extensions
hasBasicConstraints=true
isCA=false
certPathLen=-1
keyUsage=digitalSignature, keyEncipherment
# subjectAltNames numSANS; value, type; value, type
subjectAltNames=2;*.googleusercontent.com, 2;*.blogspot.com, 2
@endverbatim

@param pExtendedAttrsFile     Pointer to the file which contains extended attributes.
@param config_type            Whether JSON or TOML CSR config.
@param pKeyAlias              Pointer to the key alias to be searched in.
@param keyAliasLen            Key alias length.
@param pKey                   (Optional) AsymmetricKey corresponding to the key
                              alias. If this is NULL, the key is retrieved from
                              the certstore using the alias.
@param keyType                Type of the key. Possible values:
                              \ref akt_undefined
                              \ref akt_rsa
                              \ref akt_ecc
                              \ref akt_dsa
                              \ref akt_custom.

@param pHashType              Name of the digest algorithm Ex: "SHA256".
@param hashTypeLen            Length of the digest name.
@param pPCsr                  On return, Double pointer to the CSR.
@param pCsrLen                On return, Pointer to the CSR length.

@inc_file   est_client_api.h

@return     \c OK (0) if successful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    est_client_api.h
*/
MOC_EXTERN MSTATUS EST_generateCSRRequestFromConfig(
    MOC_HW(hwAccelDescr hwAccelCtx)
    struct certStore *pCertStore,
    sbyte4 connectionSSLInstance,
    ubyte *pConfigFile,
    ubyte *pExtendedAttrsFile,
    ubyte4 config_type,
    ubyte *pKeyAlias,
    ubyte4 keyAliasLen,
    AsymmetricKey *pKey,
    ubyte4 keyType,
    CertEnrollAlg keyAlgorithm,
    ubyte *pHashType,
    ubyte4 hashTypeLen,
    ubyte **pPCsr,
    ubyte4 *pCsrLen);

/**
@ingroup    aide_functions
@brief      Generates the CSR Request from the config file provided.

@details    This function generates the CSR Request based on the
            configuration file passed.

@param pCertStore             Pointer to the certstore.
@param connectionSSLInstance  SSL connection instance
@param pConfigFile            Pointer to the configuration file path.
                              <br>Example content of configuration file:
@verbatim
# Subject
countryName=US
commonName=Estclient
stateOrProvinceName=California
localityName=San Francisco
organizationName=Digicert Inc
organizationalUnitName=Engineering
# Requested Extensions
hasBasicConstraints=true
isCA=false
certPathLen=-1
keyUsage=digitalSignature, keyEncipherment
# subjectAltNames numSANS; value, type; value, type
subjectAltNames=2;*.googleusercontent.com, 2;*.blogspot.com, 2
@endverbatim

@param pExtendedAttrsFile     Pointer to the file which contains extended attributes.
@param config_type            Whether JSON or TOML CSR config.
@param pKeyAlias              Pointer to the key alias to be searched in.
@param keyAliasLen            Key alias length.
@param pKey                   (Optional) AsymmetricKey corresponding to the key
                              alias. If this is NULL, the key is retrieved from
                              the certstore using the alias.
@param keyType                Type of the key. Possible values:
                              \ref akt_undefined
                              \ref akt_rsa
                              \ref akt_ecc
                              \ref akt_dsa
                              \ref akt_custom.

@param pHashType              Name of the digest algorithm Ex: "SHA256".
@param hashTypeLen            Length of the digest name.
@param pPCsr                  On return, Double pointer to the CSR.
@param pCsrLen                On return, Pointer to the CSR length.
@param ppPolicyOids           Optional policy OIDs.

@inc_file   est_client_api.h

@return     \c OK (0) if successful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    est_client_api.h
*/
MOC_EXTERN MSTATUS EST_generateCSRRequestFromConfigWithPolicy(
    MOC_HW(hwAccelDescr hwAccelCtx)
    struct certStore *pCertStore,
    sbyte4 connectionSSLInstance,
    ubyte *pConfigFile,
    ubyte *pExtendedAttrsFile,
    ubyte4 config_type,
    ubyte *pKeyAlias,
    ubyte4 keyAliasLen,
    AsymmetricKey *pKey,
    ubyte4 keyType,
    CertEnrollAlg keyAlgorithm,
    ubyte *pHashType,
    ubyte4 hashTypeLen,
    ubyte **pPCsr,
    ubyte4 *pCsrLen,
    ExtendedEnrollFlow extFlow,
    EvalFunction evalFunction,
    void *pEvalFunctionArg);

/**
@ingroup    aide_functions
@brief      This API generates the CSR Request from the conf file.

@details    This function generates the CSR Request from config file.
            Use this API to generate a serverkey gen CSR request.
            <p> To specify an asymmetric encryption key to be used to encrypt the
            server-generated private key, client has to sent the keyAlias parameter.
            This keyAlias is used to retrieve the certificate from the cert store.

@param pCertStore            Pointer to the certstore.
@param pCsrConfig            Pointer to the config file.
@param pExtendedAttrConfig   Pointer to the extended attr config file.
@param config_type           Whether JSON or TOML CSR config.
@param pEncryptionAlgId      Pointer to keyEncryption algorithm id.
@param encryptionAlgIdLen    Length of the keyEncryption algorithm id.
@param pKeyAlias             Pointer to the key alias with which we retrieve the certificate
                             required to build the SMimeCapabilities for Asymmetric key.
@param keyAliasLen           Length of the key alias.
@param keyType               Type of the key. Possible values:
                              \ref akt_undefined
                              \ref akt_rsa
                              \ref akt_ecc
                              \ref akt_dsa
                              \ref akt_custom.

@param pHashType             Pointer to the digest name Ex: "SHA256".
@param hashTypeLen           Length of the digest name.
@param connectionSSLInstance SSL connection instance
@param pPCsr                 On return, Double pointer to the CSR.
@param pCsrLen               On return, Pointer to the CSR length.

@inc_file   est_client_api.h

@return     \c OK (0) if successful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function generates CSR with out signature and subject public key info.

@funcdoc    est_client_api.h
*/
MOC_EXTERN MSTATUS EST_generateCSRRequestFromConfigEx(
    MOC_HW(hwAccelDescr hwAccelCtx)
    struct certStore *pCertStore,
    ubyte *pCsrConfig,
    ubyte *pExtendedAttrConfig,
    ubyte4 config_type,
    ubyte *pEncryptionAlgId,
    ubyte4 encryptionAlgIdLen,
    ubyte *pKeyAlias,
    ubyte4 keyAliasLen,
    ubyte4 keyType,
    CertEnrollAlg keyAlgorithm,
    ubyte *pHashType,
    ubyte4 hashTypeLen,
    sbyte4 connectionSSLInstance,
    ubyte **pPCsr,
    ubyte4 *pCsrLen);

/**
@ingroup    aide_functions
@brief      This API generates the CSR Request from the conf file.

@details    This function generates the CSR Request from config file.
            Use this API to generate a serverkey gen CSR request.
            <p> To specify an asymmetric encryption key to be used to encrypt the
            server-generated private key, client has to sent the keyAlias parameter.
            This keyAlias is used to retrieve the certificate from the cert store.

@param pCertStore            Pointer to the certstore.
@param pCsrConfig            Pointer to the config file.
@param pExtendedAttrConfig   Pointer to the extended attr config file.
@param config_type           Whether JSON or TOML CSR config.
@param pEncryptionAlgId      Pointer to keyEncryption algorithm id.
@param encryptionAlgIdLen    Length of the keyEncryption algorithm id.
@param pKeyAlias             Pointer to the key alias with which we retrieve the certificate
                             required to build the SMimeCapabilities for Asymmetric key.
@param keyAliasLen           Length of the key alias.
@param keyType               Type of the key. Possible values:
                              \ref akt_undefined
                              \ref akt_rsa
                              \ref akt_ecc
                              \ref akt_dsa
                              \ref akt_custom.

@param pHashType             Pointer to the digest name Ex: "SHA256".
@param hashTypeLen           Length of the digest name.
@param connectionSSLInstance SSL connection instance
@param pPCsr                 On return, Double pointer to the CSR.
@param pCsrLen               On return, Pointer to the CSR length.
@param ppPolicyOids          Optional policy OIDs.

@inc_file   est_client_api.h

@return     \c OK (0) if successful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function generates CSR with out signature and subject public key info.

@funcdoc    est_client_api.h
*/
MOC_EXTERN MSTATUS EST_generateCSRRequestFromConfigExWithPolicy(
    MOC_HW(hwAccelDescr hwAccelCtx)
    struct certStore *pCertStore,
    ubyte *pCsrConfig,
    ubyte *pExtendedAttrConfig,
    ubyte4 config_type,
    ubyte *pEncryptionAlgId,
    ubyte4 encryptionAlgIdLen,
    ubyte *pKeyAlias,
    ubyte4 keyAliasLen,
    ubyte4 keyType,
    CertEnrollAlg keyAlgorithm,
    ubyte *pHashType,
    ubyte4 hashTypeLen,
    sbyte4 connectionSSLInstance,
    ubyte **pPCsr,
    ubyte4 *pCsrLen,
    ExtendedEnrollFlow extFlow,
    EvalFunction evalFunction,
    void *pEvalFunctionArg);

/**
@ingroup    aide_functions
@brief      This API computes the extensions and subject of a certificate from a csr file.

@details    This API computes the extensions and subject of a certificate from a csr file.
            This method will allocate data for the subject so be sure to call
            \c CA_MGMT_freeCertDistinguishedName on the subject when done.

@param pCsrFile      Path the the input csr file.
@param pExtensions   Pointer to the extensions structure that will be filled with appropriate data.
@param ppSubject    Pointer to the location that will receive an allocated subject (aka distinguished name) structure.

@inc_file   est_client_api.h

@return     \c OK (0) if successful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    est_client_api.h
*/
MOC_EXTERN MSTATUS EST_parseCSR(sbyte *pCsrFile, certExtensions *pExtensions, certDistinguishedName **ppSubject);


/**
@ingroup    aide_functions
@brief      Sets the cookie data.

@details    Sets the request body in the cookie to be used in subsequent HTTP POST call.

@param pHttpContext  Pointer to the httpContext.
@param pRequestBody  Pointer to the request body.
@param reqBodyLen    Length of the request body.

@inc_file   est_client_api.h

@return     \c OK (0) if successful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    est_client_api.h
*/
MOC_EXTERN MSTATUS
EST_setCookie(httpContext *pHttpContext, ubyte *pRequestBody, ubyte4 reqBodyLen);

/**
@ingroup    aide_functions
@brief      Releases the cookie

@details    This function releases the request cookie.

@param pHttpContext  Pointer to the requestCookie.

@inc_file   est_client_api.h

@return     \c OK (0) if successful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    est_client_api.h
*/
MOC_EXTERN MSTATUS
EST_freeCookie(httpContext *pHttpContext);


/**
@ingroup    aide_functions
@brief      Generates a fullcmc/PKCS7 request.

@details    This function generates a fullcmc/PKCS7 request based on the CSR attributes
            and the extended attributes passed to this function.
            <p>
            This function creates a PKCS7 request in case if the request type is
            RENEW/REKEY. It creates a fullcmc request for ENROLL request type.
            We are generating PKCS7 request which includes extended
            attributes mentioned by Microsoft CA like certificateRenewal OID for
            RENEW/REKEY request types.

@param pCertStore             Pointer to the cert store handle.
@param pCsrAttrs              Pointer to the CSR attributes.
@param csrAttrsLen            Length of the CSR attributes buffer.
@param pExtendedCsrAttrs      Pointer to the extended CSR attributes.
@param extendedCsrAttrsLen    Length of extended CSR attributes buffer.
@param pKeyAlias              Pointer to the key alias with which CSR has to be signed.
@param keyAliasLen            Length of the key alias with which CSR has to be signed.
@param keyType                Type of the key. Possible values:
                              \ref akt_undefined
                              \ref akt_rsa
                              \ref akt_ecc
                              \ref akt_dsa
                              \ref akt_custom.

@param pNewKeyAlias           Pointer to the key alias with which the certificate can be retrieved.
@param newKeyAliasLen         Length of the key alias.
@param newKeyType             Type of the key as mentioned above.
@param pHashType              Digest algorithm name Ex: "SHA256".
@param hashTypeLen            Length of the digest name.
@param connectionSSLInstance  SSL connection state.
@param requestType            Type of the request. Possible values:
                              \ref ENROLL
                              \ref RENEW
                              \ref REKEY
@param renewInlineCert        A flag to add old inline certificate in CSR.
                              If 0 old certificate will not be added to CSR otherwise included to CSR attributes.
@param pPOut                  On return, Double pointer to the fullcmc/pkcs7 request.
@param pOutLen                On return, Pointer to the length of the request.

@inc_file   est_client_api.h

@return     \c OK (0) if successful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    est_client_api.h
*/
MOC_EXTERN MSTATUS
EST_createPKCS7Request(MOC_HW(hwAccelDescr hwAccelCtx) struct certStore *pCertStore, ubyte *pCsrAttrs,
										ubyte4 csrAttrsLen, ubyte *pExtendedCsrAttrs,
										ubyte4 extendedCsrAttrsLen, ubyte *pKeyAlias,
										ubyte4 keyAliasLen, ubyte4 keyType,
										ubyte *pNewKeyAlias, ubyte4 newKeyAliasLen,
										ubyte4 newKeyType, ubyte *pHashType,
										ubyte4 hashTypeLen, sbyte4 connectionSSLInstance,
										ubyte4 requestType, intBoolean renewInlineCert,
                                        ubyte **pPOut, ubyte4 *pOutLen);

/**
@ingroup    aide_functions
@brief      Generates a fullcmc/PKCS7 request from config file.

@details    This function generates a fullcmc/PKCS7 request from config file.
            <p>
            This function creates a PKCS7 request in case if the request type is
            RENEW/REKEY. It creates a fullcmc request for ENROLL request type.
            We are generating PKCS7 request which includes extended
            attributes mentioned by Microsoft CA like certificateRenewal OID for
            RENEW/REKEY request types.

@param pCertStore              Pointer to the cert store handle.
@param pCsrConfig              Pointer to the CSR config file.
@param pExtendedCsrAttrsConfig Pointer to the extended attrs config file.
@param config_type             Whether JSON or TOML CSR config.
@param pKeyAlias               Pointer to the key alias with which CSR has to be signed.
@param keyAliasLen             Length of the key alias with which CSR has to be signed.
@param pKey                    (Optional) AsymmetricKey corresponding to the key
                               alias. If this is NULL, the key is retrieved from
                               the certstore using the alias.
@param keyType                 Type of the key. Possible values:
                               \ref akt_undefined
                               \ref akt_rsa
                               \ref akt_ecc
                               \ref akt_dsa
                               \ref akt_custom.

@param pNewKeyAlias            Pointer to the key alias with which the certificate can be retrieved.
@param newKeyAliasLen          Length of the key alias.
@param newKeyType              Type of the key as mentioned above.
@param pHashType               Digest algorithm name Ex: "SHA256".
@param hashTypeLen             Length of the digest name.
@param connectionSSLInstance   SSL connection state.
@param requestType             Type of the request. Possible values:
                               \ref ENROLL
                               \ref RENEW
                               \ref REKEy
@param renewInlineCert         A flag to add old inline certificate in CSR.
                               If 0 old certificate will not be added to CSR otherwise included to CSR attributes.
@param pPOut                   On return, Double pointer to the fullcmc/pkcs7 request.
@param pOutLen                 On return, Pointer to the length of the request.

@inc_file   est_client_api.h

@return     \c OK (0) if successful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    est_client_api.h
*/
MOC_EXTERN MSTATUS EST_createPKCS7RequestFromConfig(
    MOC_HW(hwAccelDescr hwAccelCtx)
    struct certStore *pCertStore,
    ubyte *pCsrConfig,
    ubyte *pExtendedCsrAttrsConfig,
    ubyte4 config_type,
    ubyte *pKeyAlias,
    ubyte4 keyAliasLen,
    AsymmetricKey *pKey,
    ubyte4 keyType,
    CertEnrollAlg keyAlgorithm,
    ubyte *pNewKeyAlias,
    ubyte4 newKeyAliasLen,
    ubyte4 newKeyType,
    ubyte *pHashType,
    ubyte4 hashTypeLen,
    sbyte4 connectionSSLInstance,
    ubyte4 requestType,
    intBoolean renewInlineCert,
    ubyte **pPOut,
    ubyte4 *pOutLen);

/**
@ingroup    aide_functions
@brief      Generates a fullcmc/PKCS7 request from config file.

@details    This function generates a fullcmc/PKCS7 request from config file.
            <p>
            This function creates a PKCS7 request in case if the request type is
            RENEW/REKEY. It creates a fullcmc request for ENROLL request type.
            We are generating PKCS7 request which includes extended
            attributes mentioned by Microsoft CA like certificateRenewal OID for
            RENEW/REKEY request types.

@param pCertStore              Pointer to the cert store handle.
@param pCsrConfig              Pointer to the CSR config file.
@param pExtendedCsrAttrsConfig Pointer to the extended attrs config file.
@param config_type             Whether JSON or TOML CSR config.
@param pKeyAlias               Pointer to the key alias with which CSR has to be signed.
@param keyAliasLen             Length of the key alias with which CSR has to be signed.
@param pKey                    (Optional) AsymmetricKey corresponding to the key
                               alias. If this is NULL, the key is retrieved from
                               the certstore using the alias.
@param keyType                 Type of the key. Possible values:
                               \ref akt_undefined
                               \ref akt_rsa
                               \ref akt_ecc
                               \ref akt_dsa
                               \ref akt_custom.

@param pNewKeyAlias            Pointer to the key alias with which the certificate can be retrieved.
@param newKeyAliasLen          Length of the key alias.
@param newKeyType              Type of the key as mentioned above.
@param pHashType               Digest algorithm name Ex: "SHA256".
@param hashTypeLen             Length of the digest name.
@param connectionSSLInstance   SSL connection state.
@param requestType             Type of the request. Possible values:
                               \ref ENROLL
                               \ref RENEW
                               \ref REKEy
@param renewInlineCert         A flag to add old inline certificate in CSR.
                               If 0 old certificate will not be added to CSR otherwise included to CSR attributes.
@param pPOut                   On return, Double pointer to the fullcmc/pkcs7 request.
@param pOutLen                 On return, Pointer to the length of the request.
@param ppPolicyOids            Optional policy OIDs.

@inc_file   est_client_api.h

@return     \c OK (0) if successful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    est_client_api.h
*/
MOC_EXTERN MSTATUS EST_createPKCS7RequestFromConfigWithPolicy(
    MOC_HW(hwAccelDescr hwAccelCtx)
    struct certStore *pCertStore,
    ubyte *pCsrConfig,
    ubyte *pExtendedCsrAttrsConfig,
    ubyte4 config_type,
    ubyte *pKeyAlias,
    ubyte4 keyAliasLen,
    AsymmetricKey *pKey,
    ubyte4 keyType,
    CertEnrollAlg keyAlgorithm,
    ubyte *pNewKeyAlias,
    ubyte4 newKeyAliasLen,
    ubyte4 newKeyType,
    ubyte *pHashType,
    ubyte4 hashTypeLen,
    sbyte4 connectionSSLInstance,
    ubyte4 requestType,
    intBoolean renewInlineCert,
    ubyte **pPOut,
    ubyte4 *pOutLen,
    ExtendedEnrollFlow extFlow,
    EvalFunction evalFunction,
    void *pEvalFunctionArg);

/**
@ingroup  aide_functions
@brief    Removes the PKCS7 banner.

@details  This function filters the PKCS7 banner.

@param pQuery            Pointer to the input from which the banner to be removed.
@param queryLen          Length of the input.
@param ppRetPkcs7        On return, Double pointer to the filtered reponse.
@param pRetPkcs7Length   On return, Pointer to the length of filtered response.
@param pArmorDetected    On return, Pointer to the armour detected.
                         \c TRUE if banner detected; \c FALSE otherwise.

@inc_file   est_client_api.h

@return     \c OK (0) if successful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    est_client_api.h
*/
MOC_EXTERN MSTATUS
EST_filterPkcs7Banner(ubyte *pQuery, ubyte4 queryLen, ubyte **ppRetPkcs7,
									ubyte4 *pRetPkcs7Length, byteBoolean *pArmorDetected);

/**
@ingroup aide_functions
@brief   Gets the Asymmetric key blob from PKCS7 Envelop Data.

@details This API extracts the key from PKCS7 Envelop Data.
         <p> Call this API when the Signed data is encrypted with a
         Symmetric key i.e when the serverkeygen request contains
         a decryptKeyIdentifier OID. When the Signed Data is encrypted
         with an Asymmetric key then use the function
         EST_getPemKeyFromCmsEnvelopeData() to get the private
         key from CMS Envelop Data. This is because CMS APIs only
         support encryption/decryption with Asymmetric keys.
         <p> Certificate store handle is required to get the certificate from
         the certStore which is used to verify the CMS Signed data.

@param pCertStore     Pointer to the cert store.
@param pEnvelopData   Pointer to the PKCS7 Envelop Data.
@param envelopDataLen Length of the  PKCS7 envelop data.
@param ppKeyBlob      On return, Double pointer to the keyblob.
@param pKeyBlobLen    On return, Pointer to the keyblob length.

@inc_file   est_client_api.h

@return     \c OK (0) if successful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    est_client_api.h
*/
MOC_EXTERN MSTATUS
EST_getPemKeyFromPkcs7EnvelopeData(MOC_HW(hwAccelDescr hwAccelCtx) struct certStore *pCertStore,
												ubyte *pEnvelopData, ubyte4 envelopDataLen,
												ubyte **ppKeyBlob, ubyte4 *pKeyBlobLen);

/**
@ingroup aide_functions
@brief   Get the Asymmetric key blob from CMS Envelop Data.

@details This API extracts the key from CMS Envelop Data.
          <p> Call this API when the CMS Signed data is encrypted with an
          Asymmetric key i.e when the serverkeygen request contains
          an AsymdecryptKeyIdentifier OID. When the Signed Data is encrypted
          with a Symmetric key then use the function
          EST_getPemKeyFromPkcs7EnvelopeData() to get the private
          key from CMS Envelop Data. This is because CMS APIs only
          support encryption/decryption with Asymmetric keys.
          <p> Certificate store handle is required to get the certificate from
          the certStore which is used to verify the CMS Signed data and
          also to get the private key which is used to decrypt the encrypted
          Signed data inside Envelop Data.
          <p> It is mandatory for the client, calling this function to make
          sure to have the above required certificates and the private key to
          be in the cert store.

@param pCertStore     Pointer to the cert store.
@param pEnvelopData   Pointer to the PKCS7 Envelop Data.
@param envelopDataLen Length of the  PKCS7 envelop data.
@param ppPemKeyBlob   On return, Double pointer to the keyBlob.
@param pPemKeyBlobLen On return, Pointer to the keyBlob length.

@inc_file   est_client_api.h

@return     \c OK (0) if successful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    est_client_api.h
*/
MOC_EXTERN MSTATUS
EST_getPemKeyFromCmsEnvelopeData(MOC_HW(hwAccelDescr hwAccelCtx) struct certStore *pCertStore, ubyte *pEnvelopData,
												ubyte4 envelopDataLen, ubyte **ppPemKeyBlob,
												ubyte4 *pPemKeyBlobLen);

/**
@ingroup    aide_functions
@brief      This API parses PKCS7 response and returns the certificates.
            This API should be called to retrieve the certificate for Attestation
            flow.

@details    This function retrieves the certificates from the response.

@param pAsymKey        Pointer to the key with which the CSR is signed.
@param pHttpResp       Pointer to PKCS7 response content from which the certificates
                       to be retrieved.
@param httpRespLen     Length of the response content.
@param pContentType    Pointer to the content type of the response.
@param contentTypeLen  Length of the content type.
@param pPCertificates  On return, Double pointer to the list of certificates.
@param pNumCerts       On return, Pointer to number of certificates.

@inc_file   est_client_api.h

@return     \c OK (0) if successful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    est_client_api.h
*/
MOC_EXTERN MSTATUS
EST_handleFullcmcEnrollResponse(MOC_HW(hwAccelDescr hwAccelCtx) AsymmetricKey *pAsymKey, ubyte *pHttpResp, ubyte4 httpRespLen, ubyte *pContentType, ubyte4 contentTypeLen, struct SizedBuffer  **pPCertificates, ubyte4 *pNumCerts);

/**
@ingroup aide_functions
@brief   This API parses the multi-part content.

@details This API parses the multi-part response and returns the
          certificates data, key data and their corresponding content types.
          <p> As per RFC 7030, the response content type from a serverkeygen response
          would be multipart/mixed. The response contains the key and
          enrolled certificate separated with a boundary.

@param pResponse              Pointer to the multi-part response content.
@param responseLen            Length of the multi-part response.
@param pContentType           Pointer to the content type.
@param contentTypeLen         Length of the content type.
@param pPKey                  On return, Double pointer to the key blob.
@param pKeyLength             On return, Pointer to the keyblob length.
@param pPKeyContentType       On return, Double pointer to the content type of the key.
@param pKeyContentTypeLen     On return, Pointer to key content type length.
@param pPPkcs7Cert            On return, Double pointer to the PKCS7 data.
@param pPPkcs7CertLen         On return, Pointer to length of the PKCS7 data.
@param pPCertContentType      On return, Double pointer to the PKCS7 content type.
@param pCertContentTypeLen    On return, Pointer to PKCS7 content type length.
@param isPendingRetry         Indicates if the scenario is pending retry.
@param httpStatusCode         Http response status associated with the httpContext in the response.

@inc_file   est_client_api.h

@return     \c OK (0) if successful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    est_client_api.h
*/
MOC_EXTERN MSTATUS
EST_filterMultiPartContent(ubyte *pResponse, ubyte4 responseLen,
											ubyte *pContentType, ubyte4 contentTypeLen,
											ubyte **pPKey, ubyte4 *pKeyLength,
											ubyte **pPKeyContentType, ubyte4 *pKeyContentTypeLen,
											ubyte **pPPkcs7Cert, ubyte4 *pPPkcs7CertLen,
											ubyte **pPCertContentType, ubyte4 *pCertContentTypeLen, byteBoolean isPendingRetry, ubyte4 httpStatusCode);


/**
@ingroup    aide_functions
@brief      This API filters the new line and feed characters.

@details    This function filters the new line and feed characters.

@param pOrigMsg       Pointer to response received from the Server.
                      Updated response would be updated to the same buffer.
@param origLen        Response length.
@param pFilteredLen   On return, Pointer to new length.

@inc_file   est_client_api.h

@return     \c OK (0) if successful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    est_client_api.h
*/
MOC_EXTERN MSTATUS
EST_filterPkcs7Message(ubyte *pOrigMsg, ubyte4 origLen, ubyte4 *pFilteredLen);


/**
@ingroup    aide_functions
@brief      This API parses PKCS7 response and returns the certificates.

@details    This function retrieves the certificates from the response.

@param pContentType    Pointer to the content type of the response.
@param contentTypeLen  Length of the content type.
@param pHttpResp       Pointer to PKCS7 response content from which the certificates
                       to be retrieved.
@param httpRespLen     Length of the response content.
@param pAsymKey        Pointer to an asymmetric key (private or public) for certificate
                       chain filtering. If provided (non-NULL), the function filters and
                       returns only the certificate chain corresponding to this key.
                       If NULL, all certificates from the response are returned.
@param pPCertificates  On return, Double pointer to the list of certificates.
@param pNumCerts       On return, Pointer to number of certificates.

@inc_file   est_client_api.h

@return     \c OK (0) if successful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    est_client_api.h
*/
MOC_EXTERN MSTATUS
EST_receiveResponse(ubyte *pContentType, ubyte4 contentTypeLen, ubyte *pHttpResp,
							ubyte4 httpRespLen, AsymmetricKey *pAsymKey,
							struct SizedBuffer  **pPCertificates,
							ubyte4 *pNumCerts);


/**
@ingroup    aide_functions
@brief      Handles the response data received from socket.

@details    This a callback function which handles the response data from
             HTTP socket.

@param pHttpContext          Pointer to the HTTP context.
@param pDataReceived         Pointer to the response data.
@param dataLength            Pointer to the response data length.
@param isContinueFromBlock   Check if continue from block.

@inc_file   est_client_api.h

@return     \c OK (0) if successful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    est_client_api.h
*/
MOC_EXTERN MSTATUS
EST_responseBodyCallbackHandle(httpContext *pHttpContext, ubyte *pDataReceived,
											ubyte4 dataLength, sbyte4 isContinueFromBlock);

/**
@ingroup    aide_functions
@brief      This API copies the request body.

@details    This a callback function which copies the request body.

@param pHttpContext        Pointer to the HTTP context.
@param pPDataToSend        On return, Double pointer to the request.
@param pDataLength         On return, Pointer to the request length.
@param pRequestBodyCookie  Pointer to the cookie body.

@inc_file   est_client_api.h

@return     \c OK (0) if successful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    est_client_api.h
*/
MOC_EXTERN MSTATUS
EST_requestBodyCallback(httpContext *pHttpContext, ubyte **pPDataToSend,
											ubyte4 *pDataLength, void *pRequestBodyCookie);
/**
@ingroup    aide_functions
@brief      This API can be used to validate the received certificate is issued
            by CA cert.

@details    This API creates a certificate chain from received certificate and CA certificate
            and validate it by configuring for time and certStore.

@param pCertStore          Pointer to the cert store. [CA Certs will also prasent]
@param pReceivedCert       Pointer to received certificate.
@param receivedCertLen     Received certificate length.
@param pTime               Optional time to use when validating certificate.

@inc_file   est_client_api.h

@return     \c OK (0) if successful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    est_client_api.h
*/
MOC_EXTERN MSTATUS
EST_validateReceivedCertificate(MOC_HW(hwAccelDescr hwAccelCtx)
    struct certStore *pCertStore, ubyte *pReceivedCert, ubyte4 receivedCertLen,
    TimeDate *pTime);


/**
@ingroup    aide_functions
@brief      This API parses the endpoint into server name and URL.

@details    This function parses the endpoint and extracts the server name and URL.

@param pEndpoint           Pointer to the endpoint string.
@param ppServerName        On return, double pointer to the server name.
@param ppUrl               On return, double pointer to the URL.

@inc_file   est_client_api.h

@return     \c OK (0) if successful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    est_client_api.h
*/
MOC_EXTERN MSTATUS
EST_parseEndpoint(sbyte *pEndpoint, sbyte **ppServerName, sbyte **ppUrl);

/**
 * @private
 * @internal
 *
 * @ingroup	func_est_client_comm
 *
 * @brief	This callback is used to initialize TPM KeyContext.
 *
 * @return OK on success
 * @return Negative number error code definition from merrors.h. To retrieve a string containing an
 *         English text error identifier corresponding to the function's
 *         returned error status, use the \c DISPLAY_ERROR macro.
 */
typedef MSTATUS (*EST_initTPM12KeyContext)(AsymmetricKey *pKey);

/**
 * @private
 * @internal
 *
 * @ingroup	func_est_client_comm
 *
 * @brief	This callback is used to deinitialize TPM KeyContext.
 *
 * @return OK on success
 * @return Negative number error code definition from merrors.h. To retrieve a string containing an
 *         English text error identifier corresponding to the function's
 *         returned error status, use the \c DISPLAY_ERROR macro.
 */
typedef MSTATUS (*EST_deinitTPM12KeyContext)();

/**
 * @private
 * @internal
 *
 * @ingroup	func_est_client_comm
 *
 *
 * @brief	This function sets the TPM12 KeyContext callback.
 *
 * @param [in]	initTPM12Keycontext      Reference to EST_initTPM12KeyContext callback.
 * @param [in]	deinitTPM12Keycontext    Reference to EST_deinitTPM12KeyContext callback.
 *
 * @return OK on success
 * @return Negative number error code definition from merrors.h. To retrieve a string containing an
 *         English text error identifier corresponding to the function's
 *         returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN
MSTATUS EST_setTPM12KeyContextCallbacks(EST_initTPM12KeyContext initTPM12KeyContext, EST_deinitTPM12KeyContext deinitTPM12KeyContext);

#ifdef __ENABLE_DIGICERT_TAP__
/**
 * @private
 * @internal
 *
 * @ingroup	func_est_client_comm
 *
 *
 * @brief	Function pointer declaration for a callback to get tap context,
 *          entity credentials and key credentials from the client.
 *
 *
 * @param [in]	ppTapContext     On return, Pointer to the TapContext.
 * @param [in]  ppTapEntityCred  On return, Pointer to the TAP_EntityCredentialList.
 * @param [in]  ppTapKeyCred     On return, Pointer to the TAP_CredentialList.
 *
 * @return OK on success
 * @return Negative number error code definition from merrors.h. To retrieve a string containing an
 *         English text error identifier corresponding to the function's
 *         returned error status, use the \c DISPLAY_ERROR macro.
 */
typedef MSTATUS (*EST_getTapContext)(TAP_Context **ppTapContext,
        TAP_EntityCredentialList **ppTapEntityCred,
        TAP_CredentialList **ppTapKeyCred,
        byteBoolean getContext);

extern MSTATUS EST_CLIENT_registerTapCtxCallback(
    EST_getTapContext getTapContext);

#endif

#ifdef __cplusplus
}
#endif
#endif /* defined (__ENABLE_DIGICERT_EST_CLIENT__) && defined (__ENABLE_DIGICERT_EXAMPLES__)) */

#endif /* #ifndef __EST_CLIENT_API_HEADER__ */
