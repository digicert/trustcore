/*
 * trustedge_scep_context.h
 *
 * SCEP context definition
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
@file       trustedge_scep_context.h
@brief      NanoCert SCEP developer API header.
@details    This header file contains definitions, structures, and function
            declarations used by NanoCert SCEP developer API functions.

@since 2.02
@version 2.02 and later

@flags
To build products using this header file, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SCEP_CLIENT__

@filedoc    trustedge_scep_context.h
*/
#ifndef __TRUSTEDGE_SCEP_CONTEXT_HEADER__
#define __TRUSTEDGE_SCEP_CONTEXT_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__ENABLE_DIGICERT_SCEP_CLIENT__)

/* types of roles */
#define SCEP_CLIENT             0x1
#define SCEP_SERVER             0x2

struct entity;
struct entityTransAttr;

/* the following are SCEP internal structures */
/*!
\exclude
*/
typedef struct pkcsCtxInternal
{
    /* pki message params */
    AsymmetricKey           *pKey; /* contains the private key which includes in CSR */
    AsymmetricKey           *pSignKey; /* contains the signing private key */
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
    const ubyte         *encryptAlgoOID;
    /* PKCS#10 CSR as payload */
    ubyte         *pPayLoad;
    ubyte4         payLoadLen;
    /* random function and arg */
    RNGFun rngFun;
    void* rngFunArg;

    /* oaep params*/
    ubyte isOaep;
    ubyte4 oaepHashAlgo;
    sbyte *pOaepLabel;

    byteBoolean isTap;
    byteBoolean isTapPw;
    
} pkcsCtxInternal;

/**
@cond
*/
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
@endcond
*/

/**
@cond
*/
enum scepClientStates
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
enum scepServerStates
{
    scep_serverStart,
    scep_requestNewCert,
    scep_renewalCert,
    scep_serverErrorFinsished,
    scep_serverFinished
};
/**
@endcond
*/

/**
@cond
*/
typedef struct
{
#ifdef __ENABLE_DIGICERT_SCEP_CLIENT__
    /* transport information */
    byteBoolean                              useHttpPOST;
#endif

    sbyte4                                  roleType;           /* client, server, etc */
    union
    {
        struct
        {
            enum    scepClientStates state;          /* current client state */
        } client;
        /* server state goes here */
        struct
        {
            enum scepServerStates state;            /* current server state */
            struct entity              *pEntity;
            sbyte               *pEntityDn;
            struct entityTransAttr     *pEntTransAttr;
            sbyte4  msgid;              /* ldap async operations returned msgid */
        } server;
    } scepProcess;

    pkcsCtxInternal                          *pPkcsCtx;
    requestInfo                             *pReqInfo;
    transactionAttributes                   *pTransAttrs;

    ubyte*                                  pReceivedData;       /* pending received data */
    ubyte4                                  receivedDataLength;  /* number of bytes pending */

    ubyte*                                  pSendingData;       /* pending received data */
    ubyte4                                  sendingDataLength;  /* number of bytes pending */

} scepContext;
/**
@endcond
*/

#define SCEP_CLIENT_STATE(X)        (X)->scepProcess.client.state
#define SCEP_SERVER_STATE(X)        (X)->scepProcess.server.state

/*------------------------------------------------------------------*/

/**
@brief      Create and initialize a scepContext.

@details    This function creates and initializes a scepContext.

@ingroup    func_trustedge_scep_context_mgmt

@since 2.02
@version 2.02 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SCEP_CLIENT__

@inc_file trustedge_scep_context.h

@param ppNewContext     On return, pointer to created scepContext.
@param roleType         Type of role; \c SCEP_CLIENT is the only supported role.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    trustedge_scep_context.h
*/
MOC_EXTERN MSTATUS SCEP_CONTEXT_createContext(scepContext **ppNewContext, sbyte4 roleType);

/**
@brief      Reset (clear) scepContext for later reuse

@details    This function resets (clears) the specified scepContext so it can
            be reused for subsequent SCEP operations.

@ingroup    func_trustedge_scep_context_mgmt

@since 2.02
@version 2.02 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SCEP_CLIENT__

@inc_file trustedge_scep_context.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@param pScepContext Pointer to SCEP context to reset (clear)

@funcdoc    trustedge_scep_context.h
*/
MOC_EXTERN MSTATUS SCEP_CONTEXT_resetContext(scepContext *pScepContext);
/* if reset for continue, do not clear up transactionId or transport request method, i.e. GET or POST */

MOC_EXTERN MSTATUS SCEP_CONTEXT_resetContextEx(scepContext *pScepContext, intBoolean resetForContinue);

/**
@brief      Release (free) a scepContext and its resources.

@details    This function releases (frees) the specified scepContext and its
            resources.

@ingroup    func_trustedge_scep_context_mgmt

@since 2.02
@version 3.06 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SCEP_CLIENT__

@inc_file trustedge_scep_context.h

@param ppReleaseContext Pointer to SCEP context to release (free).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    trustedge_scep_context.h
*/
MOC_EXTERN MSTATUS SCEP_CONTEXT_releaseContext(scepContext **ppReleaseContext);

MOC_EXTERN MSTATUS SCEP_CONTEXT_releaseRequestInfo(requestInfo *pReqInfo);

/*------------------------------------------------------------------*/

#endif /* #ifdef __ENABLE_DIGICERT_SCEP_CLIENT__ */

#ifdef __cplusplus
}
#endif
#endif  /*#ifndef __TRUSTEDGE_SCEP_CONTEXT_HEADER__ */
