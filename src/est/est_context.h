/**
 * @file  est_context.h
 * @brief EST context management header file.
 *
 * @flags
 *  To enable this file's functions, the following flags must be defined in moptions.h:
 *  + \c \__ENABLE_DIGICERT_EST_CLIENT__
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

#ifndef __EST_HEADER__
#define __EST_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__ENABLE_DIGICERT_EST_CLIENT__)

#include "../common/absstream.h"
#include "../common/random.h"
#include "../crypto/crypto.h"
#include "../crypto/pubcrypto.h"
#include "../crypto/pkcs7.h"
#include "../crypto/pkcs10.h"
#include "../common/memfile.h"
#include "../common/tree.h"
#include "../asn1/parseasn1.h"

/*------------------------------------------------------------------*/

/* messageType */
typedef enum
{
	est_cacert=0, est_simpleenroll=1, est_simplereenroll=2, est_fullcmc=3, est_serverkeygen=4, est_csrattrs=5
} EST_messageType;

/* pkiStatus */
typedef enum
{
est_SUCCESS=0, est_FAILURE=2, est_PENDING=3
} EST_pkiStatus;

/* failinfo */
typedef enum
{
est_badAlg=0, est_badMessageCheck=1, est_badRequest=2, est_badTime=3, est_badCertId=4
} EST_failInfo;


typedef struct
{
    ubyte* name;
    ubyte4 nameLen;
} EST_nameStr;

/* response type: http response ContentType */
typedef enum
{
   x_pki_message, /* "application/x-pki-message" */
   x_csrattrs, /* "application/csrattrs" */
   x_pkcs7_cert, /* "application/pkcs7-mime" */
   x_pkcs7_simple_cert, /* "application/pkcs7-mime;smime-type=certs-only" */
   x_pkcs7_multipart_mixed, /* "application/pkcs7-mime;smime-type=multipart-mixed" */
   x_pkcs7_fullcmc_response /* "application/pkcs7-mime;smime-type=CMC-response" */
} EST_responseType;

/**
 * @private
 * @internal
 */
MOC_EXTERN EST_nameStr mEstContentTypeMediaTypes[];
#define NUM_EST_MEDIA_TYPES         (3)
MOC_EXTERN EST_nameStr mEstContentTypePkcs7Parameter[];
#define NUM_EST_PKCS7_MIME_PARAMS   (3)
#define EST_CONTENT_TYPE_SEPERATOR  ';'
#define EST_SMIME_TYPE              "smime-type="
#define EST_SMIME_TYPE_LEN          (11)

struct hashTableOfPtrs;

typedef enum EST_opMode
{
    est_AUTO = 1, est_MANUAL = 2
} EST_opMode;

/**
 * @brief	This structure stores the context required to construct and parse
 *          PKCS&nbsp;\#7 request and response messages. For
 *          non-PKCS&nbsp;\#7 messages, this structure can be set to NULL.
 *
 */
typedef struct pkcsCtx
{
    /* parameters and callbacks for pki based messages */
/**
* @brief	  	RA (registration authority) distinguished name.
*/
    certDistinguishedName   *pRACertInfo;

/**
* @brief    	CA (certificate authority) distinguished name. If the CA and RA
*           	distinguished names are the same, they point to the same
*            	information structure.
*/
    certDistinguishedName   *pCACertInfo;

/**
* @brief		Requestor's distinguished name.
*/
    certDistinguishedName   *pRequesterCertInfo;

/**
* @brief		Structure containing callback function pointers for PKCS \#7 messages
*
*/
    PKCS7_Callbacks         callbacks;

/**
* @brief		Random number generator setting.
*/
    RNGFun rngFun;

/**
* @brief		Random number generator setting.
*/
    void* rngFunArg;

/**
* @brief	    PKI operation algorithm for message digest. If not set, a default (SHA-1_ is used.
*/
    const ubyte             *digestAlgoOID;

/**
* @brief		PKI operation algorithm for message encryption. If not set, a default (Triple-DES) is used.
*/
    const ubyte             *encryptAlgoOID;

} pkcsCtx;


/**
* @brief	  	This structure is used for EST %client configuration.
*             	Which products and features you've included (by defining the
*              	appropriate flags in moptions.h) determine which data fields are
*             	present in this structure. Each included callback function should
*           	be customized for your application and then registered by
*              	assigning it to the appropriate structure function pointer(s).
*
*/
typedef struct estSettings
{
/**
* @brief	    Context for building and parsing PKCS&nbsp;\#7 messages.
*/
    struct pkcsCtx pkcsCtx;

    /* callbacks for fetching a certificate or keypair from the store */

/**
* @ingroup    	est_callback_functions
*
* @brief	  	This callback function retrieves a certificate from the trusted
*            	certificate store based on the provided distinguished name.
*
*
* 				Callback registration happens at session creation and initialization by
* 				assigning your custom callback function (which can have any name) to this
* 				callback pointer.
*
* @note       	If you accept certificates from only a single trusted source,
*            	just return that source. Mocana NanoCert will verify the returned
*            	certificate.
*
* @memory       To avoid memory leaks, be sure to call Mocana SoT Platform free
*            	certificate functions where appropriate.
*
*
* @param [in]	reserved         (Reserved for future use.)
* @param [in]	pLookupCertDN    Pointer to a distinguished name structure to be used
*                          		 to lookup a certificate in the trusted certificate store.
*
* @param [out]	pReturnCert      Pointer to a structure in which to store the
*                          		 resulting certificate information. Only the
*                          		 certificate and certificate length fields are
*                          		 required; the public and private key fields are not
*                          		 relevant.
* @return OK on success
* @return Negative number error code definition from merrors.h. To retrieve a string containing an
*         English text error identifier corresponding to the function's
*         returned error status, use the \c DISPLAY_ERROR macro.
*
* @remark    If EST is configured to use digital certificates for
*            authentication, you should define and customize this hookup function for your application.
*
*/
    sbyte4 (*funcPtrCertificateStoreLookup) (void* reserved, struct certDistinguishedName *pLookupCertDN, struct certDescriptor *pReturnCert);

/**
* @ingroup   	est_callback_functions
*
* @brief    	This callback function releases memory associated with a previous
*            	call to estSettings::funcPtrCertificateStoreLookup.
*
*				Callback registration happens at session creation and initialization by
* 				assigning your custom callback function (which can have any name) to this
*				callback pointer.
*
*
* @param [in]		reserved     (Reserved for future use.)
* @param [in,out]	pFreeCert    Pointer to the certificate to free.
*
* @return OK on success
* @return Negative number error code definition from merrors.h. To retrieve a string containing an
*         English text error identifier corresponding to the function's
*         returned error status, use the \c DISPLAY_ERROR macro.
*
* @remark     	If EST is configured to use digital certificates for
*           	authentication, you should define and customize this hookup
*            	function for your application.
*
*/
    sbyte4 (*funcPtrCertificateStoreRelease)(void* reserved, struct certDescriptor* pFreeCert);

/**
* @ingroup		est_callback_functions
*
* @brief		This callback function retrieves a certificate's authentication keys
*             	based on the provided distinguished name.
*
* 				Callback registration happens at session creation and initialization by
* 				assigning your custom callback function (which can have any name) to this
* 				callback pointer.
*
* @param [in] 	reserved        (Reserved for future use.)
* @param [in]	pLookupKeyDN    Pointer to a distinguished name structure to be used
*                           	to lookup a certificate's authentication keys.
* @param [out]	keyBlob         On return, pointer to key blob (containing
*                          		public/private key pair).
* @param [out]	keyBlobLen      On return, pointer to number of bytes in returned
*                          		key blob (\c keyBlob).
*
* @return OK on success
* @return Negative number error code definition from merrors.h. To retrieve a string containing an
*         English text error identifier corresponding to the function's
*         returned error status, use the \c DISPLAY_ERROR macro.
*
*
* @remark    If EST is configured to use digital certificates for
*            authentication, you should define and customize this hookup
*            function for your application.
*
*/
    sbyte4 (*funcPtrKeyPairLookup) (void* reserved, struct certDistinguishedName *pLookupKeyDN, ubyte** keyBlob, ubyte4* keyBlobLen);
} estSettings;

/* Structs for holding parameters for the various EST requests: */

/**
*
* @brief	    Parameters required for certificate enrollment requests
*            	(\c PKCSReq).
*
*/
typedef struct
{
/**
* @brief	    Requestor's public key.
*/
    AsymmetricKey pubKey;

/**
* @brief	    Requestor's distinguished name.
*/
    certDistinguishedName   *pSubject;
/**
* @brief	    PKCS&nbsp;\#9 attributes: challenge password and certificate
*            	%extensions.
*/
    requestAttributesEx     *pReqAttrs;
} certInfoAndReqAttrs;

typedef certInfoAndReqAttrs certInfoAndReqAttrsType;

/**
*
* @brief	    Parameters required for \c GetCACert, \c GetNextCACert,
*            	\c GetCACertChain, \c GetCACaps, and \c PublishCRL requests.
*
*/
typedef struct
{
/**
*
* @brief	    CA identifier, such as the %common name (CN) of the CA
*            	distinguished name.
*
* @note       	Not all EST servers require a CA identifier.
*/
    ubyte* ident;

/**
* @brief	    Number of bytes in the identifier buffer (\c ident).
*/
    ubyte4 identLen;
} caIdent;

typedef caIdent caIdentType;

typedef struct
{
/**
* @brief	    EST message %type: any of the \c EST_messageType enumerated
*           	values (defined in est.h).
*/
    EST_messageType type;

/**
*
* @brief	    Structure containing the parameters needed for the given EST
*            	message %type.
*/
    union
    {
      certInfoAndReqAttrsType certInfoAndReqAttrs;
      caIdentType caIdent;
    } value;
} requestInfo;
/*------------------------------------------------------------------*/

MOC_EXTERN estSettings* EST_estSettings(void);

/* types of roles */
#define EST_CLIENT             0x1

/* the following are EST internal structures */
/*!
\exclude
*/
typedef struct pkcsCtxInternal
{
    /* pki message params */
    AsymmetricKey           key; /* contains the private key */
    /* RA certificate info */
    ASN1_ITEMPTR            pRACertificate;
    CStream                 RACertStream;
    MemFile                 RAMemFile;
    certDescriptor          RACertDescriptor;
    /* CA certificate info, could be the same as RA */
    certDistinguishedName   *pCASubject;
    ASN1_ITEMPTR            pCACertificate;
    CStream                 CACertStream;
    MemFile                 CAMemFile;
    certDescriptor          CACertDescriptor;

    PKCS7_Callbacks         callbacks;
    /* requester certificate info, either self-signed or CA issued */
    ASN1_ITEMPTR            pRequesterCert;
    CStream                 requesterCertStream;
    MemFile                 requesterCertMemFile;
    certDescriptor          requesterCertDescriptor;

    /* pki message algorithms.
    * if not set, defaults are:
    * sha-1 for digest algorithm;
    * sha1WithRSAEncryption for signature algorithm;
    * Triple-DES for encryption algorithm. */
    const ubyte         *digestAlgoOID;
    const ubyte         *digestEncryptAlgoOID;
    const ubyte         *encryptAlgoOID;
    const ubyte         *signAlgoOID;
    /* random function and arg */
    RNGFun rngFun;
    void* rngFunArg;
} pkcsCtxInternal;

typedef struct transactionAttributes
{
    sbyte* transactionID; /* PrintableString */
    ubyte4 transactionIDLen;
    ubyte4 messageType; /* PrintableString -- Decimal value as a string */
    ubyte4 pkiStatus; /* PrintableString -- Decimal value as a string */
    ubyte4 failinfo; /* PrintableString -- Decimal value as a string */
    sbyte* senderNonce; /* OctetString -- 16 bytes*/
    ubyte4 senderNonceLen;
    sbyte* recipientNonce; /* OctetString -- 16 bytes*/
    ubyte4 recipientNonceLen;
} transactionAttributes;

/**
@cond
*/
enum estClientStates
{
    certNonExistant,
    certGetInitial,
    certReqPending,
    certIssued,
    finishedState
};
/**
@endcond
*/

/**
@cond
*/
typedef struct
{
    byteBoolean                             useHttpPOST;
    sbyte4                                  roleType;           /* client, server, etc */
    union
    {
        struct
        {
            enum    estClientStates state;          			/* current client state */
        } client;
    } estProcess;

    pkcsCtxInternal                         *pPkcsCtx;
    requestInfo                             *pReqInfo;
    transactionAttributes                   *pTransAttrs;

    ubyte*                                  pReceivedData;      /* pending received data */
    ubyte4                                  receivedDataLength; /* number of bytes pending */

    ubyte*                                  pSendingData;      	/* pending received data */
    ubyte4                                  sendingDataLength;  /* number of bytes pending */

} estContext;
/**
@endcond
*/

#define EST_STATE(X)        (X)->estProcess.client.state

/*------------------------------------------------------------------*/
/**
 * @ingroup		func_est_context_mgmt
 *
 *
 * @brief		This function creates and initializes an estContext.
 *
 * @param [in,out]	ppNewContext	On return, pointer to created estContext.
 * @param [in,out]	roleType		Type of role; \c EST_CLIENT is the only supported role.
 *
 * @return OK on success
 * @return Negative number error code definition from merrors.h. To retrieve a string containing an
 *         English text error identifier corresponding to the function's
 *         returned error status, use the \c DISPLAY_ERROR macro.
 *
 */
MOC_EXTERN MSTATUS EST_CONTEXT_createContext(estContext **ppNewContext, sbyte4 roleType);

/**
 * @ingroup		func_est_context_mgmt
 *
 *
 * @brief		This function resets (clears) the specified estContext so it can be
 * 				reused for subsequent EST operations.
 *
 * @param [in,out]	pEstContext 	Pointer to EST context to reset (clear).
 *
 * @return OK on success
 * @return Negative number error code definition from merrors.h. To retrieve a string containing an
 *         English text error identifier corresponding to the function's
 *         returned error status, use the \c DISPLAY_ERROR macro.
 *
 */
MOC_EXTERN MSTATUS EST_CONTEXT_resetContext(estContext *pEstContext);

/* if reset for continue, do not clear up transactionId or transport request method, i.e. GET or POST */
/**
 * @private
 * @internal
 *
 * @note		This function is for Mocana internal code use only, and should not be included
 * 				in the API documentation.
 *
 */
MOC_EXTERN MSTATUS EST_CONTEXT_resetContextEx(estContext *pEstContext, intBoolean resetForContinue);

/**
 * @ingroup		func_est_context_mgmt
 *
 *
 * @brief		This function releases (frees) the specified estContext and its resources.
 *
 * @param [in,out]	ppReleaseContext 	Pointer to EST context to release (free).
 *
 * @return OK on success
 * @return Negative number error code definition from merrors.h. To retrieve a string containing an
 *         English text error identifier corresponding to the function's
 *         returned error status, use the \c DISPLAY_ERROR macro.
 *
 */
MOC_EXTERN MSTATUS EST_CONTEXT_releaseContext(estContext **ppReleaseContext);

/**
 * @private
 * @internal
 *
 * @note		This function is for Mocana internal code use only, and should not be included
 * 				in the API documentation.
 *
 */
MOC_EXTERN MSTATUS EST_CONTEXT_releaseRequestInfo(requestInfo *pReqInfo);

#endif /* #if defined(__ENABLE_DIGICERT_EST_CLIENT__) */

#ifdef __cplusplus
}
#endif

#endif  /*#ifndef __EST_HEADER__ */
