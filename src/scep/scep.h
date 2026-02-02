/**
 * @file  scep.h
 * @brief SCEP general definitions
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
@file       scep.h
@brief      NanoCert SCEP developer API header.
@details    This header file contains definitions, structures, and function
            declarations used by the NanoCert SCEP %client.

@since 2.02
@version 5.3 and later

@flags
To build products using this header file, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SCEP_CLIENT__

Whether the following flag is defined determines which additional header files are included:

@filedoc    scep.h
*/

#ifndef __SCEP_HEADER__
#define __SCEP_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __ENABLE_DIGICERT_SCEP_CLIENT__

/*------------------------------------------------------------------*/

/* PKIOperation is not really a SCEP messageType,
 * rather an operation type that covers PKCSReq, GetCertInitial, GetCert, and GetCRL
 */
typedef enum
{
scep_CertRep=3, scep_PKIOperation = 18, scep_PKCSReq=19,  scep_GetCertInitial=20, scep_GetCert=21, scep_GetCRL=22,
/* the following messageType codes are not defined by SCEP draft */
scep_RevokeCert=23, scep_PublishCRL=24, scep_ApproveCertEnroll=25, scep_RegisterEndEntity = 26,
scep_GetCACert=27, scep_GetNextCACert=28, scep_GetCACertChain=29, scep_GetCACaps=30,
scep_UNKNOWN=99
} SCEP_messageType;

/* pkiStatus */
typedef enum
{
scep_SUCCESS=0, scep_FAILURE=2, scep_PENDING=3
} SCEP_pkiStatus;

/* failinfo */
typedef enum
{
scep_badAlg=0, scep_badMessageCheck=1, scep_badRequest=2, scep_badTime=3, scep_badCertId=4
} SCEP_failInfo;

typedef enum certRevokeReasonFlags
{
        scep_unused = 0, scep_keyCompromise = 1, scep_cACompromise = 2, scep_affiliationChanged = 3,
        scep_superseded = 4, scep_cessationOfOperation = 5, scep_certificateHold = 6,
        scep_privilegeWithdrawn = 7, scep_aACompromise = 8
} certRevokeReasonFlags;

typedef struct
{
    ubyte* name;
    ubyte4 nameLen;
} SCEP_nameStr;

typedef struct
{
    SCEP_nameStr nameStr;
    intBoolean  isSupported;
} SCEP_operationsInfo;

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN SCEP_operationsInfo mScepOperations[];

#define SCEP_operationsOffset scep_PKCSReq

/* response type: HTTP response ContentType */
typedef enum
{
   x_pki_message, x_x509_ca_cert, x_x509_ca_ra_cert, x_x509_ca_ra_cert_chain, xml
} SCEP_responseType;

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN SCEP_nameStr mScepResponseTypes[];
#define NUM_SCEP_RESPONSETYPES   5

struct hashTableOfPtrs;

typedef enum SCEP_opMode
{
    scep_AUTO = 1, scep_MANUAL = 2
} SCEP_opMode;

/* callbacks for initializing the SCEP server */

/**
@brief      Context required to construct and parse PKCS&nbsp;\#7 messages.

@details    This structure stores the context required to construct and parse
            PKCS&nbsp;\#7 request and response messages. For
            non-PKCS&nbsp;\#7 messages, this structure can be set to NULL.

@since 2.02
@version 2.45 and later

@flags
To use this structure, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SCEP_CLIENT__

*/
typedef struct pkcsCtx
{
    /* parameters and callbacks for pki based messages */
/**
@brief      RA distinguished name.
@details    RA (registration authority) distinguished name.
*/
    certDistinguishedName   *pRACertInfo;

/**
@brief      CA distinguished name.
@details    CA (certificate authority) distinguished name. If the CA and RA
            distinguished names are the same, they point to the same
            information structure.
*/
    certDistinguishedName   *pCACertInfo;

/**
@brief      Requestor's distinguished name.
@details    Requestor's distinguished name.
*/
    certDistinguishedName   *pRequesterCertInfo;

/**
@brief      Structure containing callback function pointers for PKCS \#7
              messages.
@details    Structure containing callback function pointers for PKCS \#7
              messages.
*/
    PKCS7_Callbacks         callbacks;

/**
@brief      Random number generator setting.
@details    Random number generator setting.
*/
    RNGFun rngFun;
/**
@brief      Random number generator setting.
@details    Random number generator setting.
*/
    void* rngFunArg;

/**
@brief      PKI operation algorithm for message digest.
@details    PKI operation algorithm for message digest. If not set, a default
              (SHA-1) is used.
*/
    const ubyte             *digestAlgoOID;

/**
@brief      PKI operation algorithm for message encryption.
@details    PKI operation algorithm for message encryption. If not set, a
              default (Triple-DES) is used.
*/
    const ubyte             *encryptAlgoOID;

} pkcsCtx;

/**
@brief      Configuration settings and callback function pointers for SCEP
              clients and servers.

@details    This structure is used for SCEP %client and server configuration.
            Which products and features you've included (by defining the
            appropriate flags in moptions.h) determine which data fields are
            present in this structure. Each included callback function should
            be customized for your application and then registered by
            assigning it to the appropriate structure function pointer(s).

@since 2.02
@version 5.3 and later

@flags
To use this structure, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SCEP_CLIENT__

*/
typedef struct scepSettings
{
/**
@brief      Context for building and parsing PKCS&nbsp;\#7 messages.
@details    Context for building and parsing PKCS&nbsp;\#7 messages.
*/
    struct pkcsCtx pkcsCtx;

    /* callbacks for fetching a certificate or keypair from the store */

/**
@brief      Get a certificate from the trusted certificate store based on a
            distinguished name.

@details    This callback function retrieves a certificate from the trusted
            certificate store based on the provided distinguished name.

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to this
callback pointer.

@note       If you accept certificates from only a single trusted source,
            just return that source. Mocana NanoCert will verify the returned
            certificate.

@note       To avoid memory leaks, be sure to call Mocana SoT Platform free
            certificate functions where appropriate.

@ingroup    scep_callback_functions

@since 2.02
@version 2.45 and later

@flags
To enable this callback, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SCEP_CLIENT__

@param reserved         (Reserved for future use.)
@param pLookupCertDN    Pointer to a distinguished name structure to be used
                          to lookup a certificate in the trusted certificate
                          store.
@param pReturnCert      Pointer to a structure in which to store the
                          resulting certificate information. Only the
                          certificate and certificate length fields are
                          required; the public and private key fields are not
                          relevant.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     If SCEP is configured to use digital certificates for
            authentication, you should define and customize this hookup function for your application.

@callbackdoc    scep.h
*/
    sbyte4 (*funcPtrCertificateStoreLookup) (void* reserved, struct certDistinguishedName *pLookupCertDN, struct certDescriptor *pReturnCert);

/**
@brief      Release memory associated with a previous call to
            scepSettings::funcPtrCertificateStoreLookup.

@details    This callback function releases memory associated with a previous
            call to scepSettings::funcPtrCertificateStoreLookup.

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to this
callback pointer.

@ingroup    scep_callback_functions

@since 2.02
@version 2.45 and later

@flags
To enable this callback, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SCEP_CLIENT__

@param reserved     (Reserved for future use.)
@param pFreeCert    Pointer to the certificate to free.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     If SCEP is configured to use digital certificates for
            authentication, you should define and customize this hookup
            function for your application.

@callbackdoc    scep.h
*/
    sbyte4 (*funcPtrCertificateStoreRelease)(void* reserved, struct certDescriptor* pFreeCert);

/**
@brief      Get a certificate's authentication keys.

@details    This callback function retrieves a certificate's authentication keys
            based on the provided distinguished name.

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to this
callback pointer.

@ingroup    scep_callback_functions

@since 2.02
@version 2.45 and later

@flags
To enable this callback, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SCEP_CLIENT__

@param reserved         (Reserved for future use.)
@param pLookupKeyDN     Pointer to a distinguished name structure to be used
                          to lookup a certificate's authentication keys.
@param keyBlob          On return, pointer to key blob (containing
                          public/private key pair).
@param keyBlobLen       On return, pointer to number of bytes in returned
                          key blob (\c keyBlob).
@param signKeyBlob      On return, pointer to signing key blob (containing
                          public/private key pair).
@param signKeyBlobLen   On return, pointer to number of bytes in returned
                          signing key blob (\c keyBlob).
@param pKeyRequired     On return, Pointer to the key required flag.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     If SCEP is configured to use digital certificates for
            authentication, you should define and customize this hookup
            function for your application.

@callbackdoc    scep.h
*/
    sbyte4 (*funcPtrKeyPairLookup) (void* reserved, struct certDistinguishedName *pLookupKeyDN, ubyte** keyBlob, ubyte4* keyBlobLen, ubyte** signKeyBlob, ubyte4* signKeyBlobLen, intBoolean *pKeyRequired);

/**
@brief      Get a certificate's custom extension.

@details    This callback function retrieves a certificate's custom
            extension. The function must look up the user privileges based on
            the provided DN, build the custom extension in DER format, and
            return it through the \p ppExtensions parameter.

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to this
callback pointer.

@ingroup    scep_callback_functions

@since 5.3
@version 5.3 and later

@flags
To enable this callback, the following flag must be defined in moptions.h:

@param reserved         (Reserved for future use.)
@param pLookupCertDN    Pointer to a distinguished name structure to be used
                          to lookup a certificate's custom extension.
@param ppExtension      On return, pointer to the custom extension.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     If SCEP is configured to use digital certificates for
            authentication, you should define and customize this hookup
            function for your application.

@callbackdoc    scep.h
*/
} scepSettings;

/*------------------------------------------------------------------*/


/* Structs for holding parameters for the various SCEP requests: */

/**
@brief      Parameters required for certificate enrollment requests
            (\c PKCSReq).
@details    Parameters required for certificate enrollment requests
            (\c PKCSReq).

@since 2.02
@version 2.45 and later

@flags
To use this structure, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SCEP_CLIENT__

*/
typedef struct
{
/**
@brief      Requestor's public key.
@details    Requestor's public key.
*/
    AsymmetricKey pubKey;

/**
@brief      Requestor's distinguished name.
@details    Requestor's distinguished name.
*/
    certDistinguishedName   *pSubject;
/**
@brief      PKCS&nbsp;\#9 attributes: challenge password and certificate
            %extensions.
@details    PKCS&nbsp;\#9 attributes: challenge password and certificate
            %extensions.
*/
    requestAttributes       *pReqAttrs;
} certInfoAndReqAttrs;

typedef certInfoAndReqAttrs certInfoAndReqAttrsType;

/**
@brief      Parameters required for server poll requests (\c GetCertInitial).
@details    Parameters required for server poll requests (\c GetCertInitial).

@since 2.02
@version 2.45 and later

@flags
To use this structure, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SCEP_CLIENT__

*/
typedef struct
{
/**
@brief      Certificate issuer's distinguished name.
@details    Certificate issuer's distinguished name.
*/
    certDistinguishedName *pIssuer;
/**
@brief      Requestor's distinguished name.
@details    Requestor's distinguished name.
*/
    certDistinguishedName *pSubject;
} issuerAndSubject;

typedef issuerAndSubject issuerAndSubjectType;

/**
@brief      Parameters required for end entity certificate retrieval requests
            (\c GetCert).
@details    Parameters required for end entity certificate retrieval requests
            (\c GetCert).

@since 2.02
@version 2.45 and later

@flags
To use this structure, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SCEP_CLIENT__

*/
typedef struct
{
/**
@brief      Issuer's distinguished name.
@details    Issuer's distinguished name.
*/
    certDistinguishedName *pIssuer;

/**
@brief      Serial number (issued by the CA) of the requestor's certificate.
@details    Serial number (issued by the CA) of the requestor's certificate.
*/
    ubyte* serialNo;
/**
@brief      Number of bytes in the serial number (\c serialNo).
@details    Number of bytes in the serial number (\c serialNo).
*/
    ubyte4 serialNoLen;
} issuerAndSerialNo;

typedef issuerAndSerialNo issuerAndSerialNoType;

/**
@brief      Parameters required for CRL retrieval requests (\c GetCRL).
@details    Parameters required for CRL retrieval requests (\c GetCRL).

@since 2.02
@version 2.45 and later

@flags
To use this structure, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SCEP_CLIENT__

*/
typedef struct
{
/**
@brief      CA certificate issuer's distinguished name.
@details    CA certificate issuer's distinguished name.
*/
    certDistinguishedName *pIssuer;

/**
@brief      CA certificate's serial number.
@details    CA certificate's serial number.
*/
    ubyte* serialNo;

/**
@brief      Number of bytes in the serial number (\c serialNo).
@details    Number of bytes in the serial number (\c serialNo).
*/
    ubyte4 serialNoLen;

/**
@brief      (Optional) Pointer to DER-encoded ASN1 structure identifying
            source of CRL, as defined in RFC&nbsp;3280.
@details    (Optional) Pointer to DER-encoded ASN1 structure identifying
            source of CRL, as defined in RFC&nbsp;3280.

@note       Not all SCEP servers require this information; if your server
            does not require it, set this value to NULL.
*/
    ubyte* distPts;    /* this is ASN1 encoded whole thing. we may want to break it down later. */

/**
@brief      Number of bytes in the distribution point pointer (\c distPts).
@details    Number of bytes in the distribution point pointer (\c distPts).

@note       If you set \c distPts to NULL, set this value to NULL also.
*/
    ubyte4 distPtsLen;
} issuerSerialNoAndDistPts;

typedef issuerSerialNoAndDistPts issuerSerialNoAndDistPtsType;

/**
@brief      Parameters required for \c GetCACert, \c GetNextCACert,
            \c GetCACertChain, \c GetCACaps, and \c PublishCRL requests.
@details    Parameters required for \c GetCACert, \c GetNextCACert,
            \c GetCACertChain, \c GetCACaps, and \c PublishCRL requests.

@since 2.02
@version 2.45 and later

@flags
To use this structure, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SCEP_CLIENT__

*/
typedef struct
{
/**
@brief      CA identifier, such as the %common name (CN) of the CA
            distinguished name.
@details    CA identifier, such as the %common name (CN) of the CA
            distinguished name.

@note       Not all SCEP servers require a CA identifier.
*/
    ubyte* ident;

/**
@brief      Number of bytes in the identifier buffer (\c ident).
2details    Number of bytes in the identifier buffer (\c ident).
*/
    ubyte4 identLen;
} caIdent;

typedef caIdent caIdentType;

/**
@brief      Parameters required for certificate revokation requests
            (\c RevokeCert).
@details    Parameters required for certificate revokation requests
            (\c RevokeCert).

@since 2.45
@version 2.45 and later

@flags
To use this structure, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SCEP_CLIENT__

*/
typedef struct
{
/**
@brief      Pointer to serial number of certificate to revoke.
@details    Pointer to serial number of certificate to revoke.
*/
    ubyte* serialNo;

/**
@brief      Number of bytes pointed to by serial number pointer (\c serialNo).
@details    Number of bytes pointed to by serial number pointer (\c serialNo).
*/
    ubyte4 serialNoLen;

/**
@brief      Revokation %reason.
@details    Revokation %reason: any of the \c certRevokeReasonFlags
            enumerated values (see scep.h).
*/
    certRevokeReasonFlags reason;
} revokeCert;

typedef revokeCert revokeCertType;

/**
@brief      Parameters required for end entity registration requests
            (\c RegisterEndEntity).
@details    Parameters required for end entity registration requests
            (\c RegisterEndEntity).

@since 2.45
@version 2.45 and later

@flags
To use this structure, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SCEP_CLIENT__

*/
typedef struct
{
/**
@brief      Pointer to end entity's distinguished name.
@details    Pointer to end entity's distinguished name.
*/
    certDistinguishedName *pSubject;

/**
@brief      Pointer to %password (preshared secret between the end entity and
            SCEP server).
@details    Pointer to %password (preshared secret between the end entity and
            SCEP server).
*/
    sbyte *password;
} endEntityInfo;

typedef endEntityInfo endEntityInfoType;

/**
@brief      Parameters required for certificate enrollment approval requests
            (\c ApproveCertEnroll).
@details    Parameters required for certificate enrollment approval requests
            (\c ApproveCertEnroll).

@since 2.45
@version 2.45 and later

@flags
To use this structure, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SCEP_CLIENT__

*/
typedef struct
{
/**
@brief      Pointer to (NULL-terminated) transaction Id string.
@details    Pointer to (NULL-terminated) transaction Id string.
*/
    sbyte *transactionId; /* transactionId string, ended in NULL */
} transactionId;

typedef transactionId transactionIdType;

/**
@brief      Information unique to a request's message type.

@details    This structure is used to specify information unique to each
            message type. Which parameter (the \c requestInfo \c value field)
            is required depends on the SCEP operation:

Operation|Parameter to specify
---------|-------------------|
|\c PKCSReq|\c certInfoAndReqAttrs|
|\c GetCertInitial|\c issuerAndSubject|
|\c GetCert|\c issuerAndSerialNo|
|\c GetCRL|\c issuerSerialNoAndDistPts|
|\c GetCACert|\c caIdent|
|\c GetNextCACert|\c caIdent|
|\c GetCACertChain|\c caIdent|
|\c GetCACaps|\c caIdent|
|* \c RevokeCert|\c revokeCert|
|* \c RegisterEndEntity|\c endEntityInfo|
|* \c PublishCRL|\c caIdent|
|* \c ApproveCertEnroll|\c transactionId|

@note   Operations marked with an asterisk (*) are Mocana NanoCert
        %extensions to the SCEP specification. All such operations require
        adminstrative privileges.

@since 2.02
@version 2.45 and later

@flags
To use this structure, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SCEP_CLIENT__

*/
typedef struct
{
/**
@brief      SCEP message %type.
@details    SCEP message %type: any of the \c SCEP_messageType enumerated
            values (defined in scep.h).
*/
    SCEP_messageType type;

/**
@brief      Structure containing the parameters needed for the given SCEP
            message %type.
@details    Structure containing the parameters needed for the given SCEP
            message %type.
*/
    union
    {
      certInfoAndReqAttrsType certInfoAndReqAttrs;
      issuerAndSubjectType issuerAndSubject;
      issuerAndSerialNoType issuerAndSerialNo;
      issuerSerialNoAndDistPtsType issuerSerialNoAndDistPts;
      caIdentType caIdent;
      revokeCertType revokeCert;
      endEntityInfoType endEntityInfo;
      transactionIdType transactionId;
    } value;
} requestInfo;
/*------------------------------------------------------------------*/

MOC_EXTERN scepSettings* SCEP_scepSettings(void);

#endif /* __ENABLE_DIGICERT_SCEP_CLIENT__ */

#ifdef __cplusplus
}
#endif

#endif  /*#ifndef __SCEP_HEADER__ */
