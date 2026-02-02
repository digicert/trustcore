/**
 * @file  scep_context.h
 * @brief SCEP context definition
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
@file       scep_context.h
@brief      NanoCert SCEP developer API header.
@details    This header file contains definitions, structures, and function
            declarations used by NanoCert SCEP developer API functions.

@since 2.02
@version 2.02 and later

@flags
To build products using this header file, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SCEP_CLIENT__

Whether the following flag is defined determines which additional header files are included:

@filedoc    scep_context.h
*/
#ifndef __SCEP_CONTEXT_HEADER__
#define __SCEP_CONTEXT_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __ENABLE_DIGICERT_SCEP_CLIENT__

/* types of roles */
#define SCEP_CLIENT             0x1

struct entity;
struct entityTransAttr;

/* the following are SCEP internal structures */
/*!
\exclude
*/
typedef struct pkcsCtxInternal
{
    /* pki message params */
    AsymmetricKey           key; /* contains the private key which includes in CSR */
    AsymmetricKey           signKey; /* contains the signing private key */
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
    /* PKCS#10 CSR as payload */
    ubyte         *pPayLoad;
    ubyte4         payLoadLen;
    /* random function and arg */
    RNGFun rngFun;
    void* rngFunArg;

#ifdef __ENABLE_DIGICERT_CMS_RSA_OAEP__
    /* oaep params*/
    ubyte isOaep;
    ubyte4 oaepHashAlgo;
    sbyte *pOaepLabel;
#endif

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
typedef struct
{
    /* transport information */
    byteBoolean                              useHttpPOST;

    sbyte4                                  roleType;           /* client, server, etc */
    union
    {
        struct
        {
            enum    scepClientStates state;          /* current client state */
        } client;
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

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS SCEP_CONTEXT_createContext(scepContext **ppNewContext, sbyte4 roleType);
MOC_EXTERN MSTATUS SCEP_CONTEXT_resetContext(scepContext *pScepContext);
/* if reset for continue, do not clear up transactionId or transport request method, i.e. GET or POST */
MOC_EXTERN MSTATUS SCEP_CONTEXT_resetContextEx(scepContext *pScepContext, intBoolean resetForContinue);
MOC_EXTERN MSTATUS SCEP_CONTEXT_releaseContext(scepContext **ppReleaseContext);
MOC_EXTERN MSTATUS SCEP_CONTEXT_releaseRequestInfo(requestInfo *pReqInfo);

/*------------------------------------------------------------------*/

#endif /* #ifdef __ENABLE_DIGICERT_SCEP_CLIENT__ */

#ifdef __cplusplus
}
#endif
#endif  /*#ifndef __SCEP_CONTEXT_HEADER__ */
