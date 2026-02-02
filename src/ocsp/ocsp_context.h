/*
 * ocsp_context.h
 *
 * OCSP Context Definition
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * For commercial licensing, contact DigiCert at sales@digicert.com.* *
 */


#ifndef __OCSP_CONTEXT_HEADER__
#define __OCSP_CONTEXT_HEADER__

#if (defined(__ENABLE_DIGICERT_OCSP_CLIENT__))

#ifdef __cplusplus
extern "C" {
#endif

/* types of roles */
#define OCSP_CLIENT             (0x1)
#define OCSP_SERVER             (0x2)


/*------------------------------------------------------------------*/

/*!
\exclude
*/

enum ocspClientStates
{
    ocspInit,
    ocspRequestSent,
    ocspResponseParsed,
    ocspSingleResponseRetrieved,
    ocspFinishedState

};


/*------------------------------------------------------------------*/

/* internal */
typedef struct ocspContext
{
    sbyte4                              roleType;               /* client, server, etc */
    union
    {
        struct
        {
            enum ocspClientStates       state;                  /* current client state */
            OCSP_responseStatus         status;                 /* parsed response status */
            ASN1_ITEMPTR                pResponseRoot;          /* OCSPResponse, corresponding to response of ResponseBytes; the buffer is in pReceivedData */
            MemFile                     memFile;
            CStream                     cs;
            ASN1_ITEMPTR                pSingleResponse;        /* a temp pointer to the current singleResponse */
            byteBoolean                 hasSingleIssuer;        /* with multiple certIds present, whether they have the same issuer; if not responder can only come from locally configured trustedResponder list */

            certDistinguishedName*      pIssuerInfo;            /* this info comes from cert */
            ASN1_ITEMPTR                pIssuerRoot;            /* issuer cert */
            MemFile                     issuerMemFile;
            CStream                     issuerCs;
            ubyte*                      issuerCertBuf;
            ubyte*                      issuerNameHash;         /* cached for possible reuse */
            ubyte*                      issuerPubKeyHash;       /* length is 20 bytes for sha-1 */
            ubyte4                      hashSize;               /* cached value                 */

            ASN1_ITEMPTR                pResponderCert;         /* responder cert, could point to issuer cert or attached certs */
            CStream                     responderCs;

            MemFile                     trustedMemFile;         /* chosen trusted responder info */
            CStream                     trustedCs;

            ubyte*                      nonce;                  /* cached nonce; for verification against that of response */
            ubyte4                      nonceLen;

            OCSP_certID**               cachedCertId;            /* cached certID to be used while validating the response */

        } client;

        /* Todo: Server specific data */
    } ocspProcess;

    ubyte*                              pReceivedData;          /* pending received data */
    ubyte4                              receivedDataLength;     /* number of bytes pending */

    ocspSettings*                       pOcspSettings;
    hwAccelDescr                        hwAccelCtx;

} ocspContext;

#define OCSP_CLIENT_STATE(X)        (X)->ocspProcess.client.state


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS OCSP_CONTEXT_createContext(ocspContext **ppNewContext, sbyte4 roleType);

/* reset for reuse */
MOC_EXTERN MSTATUS OCSP_CONTEXT_resetContext(ocspContext *pOcspContext);
MOC_EXTERN MSTATUS OCSP_CONTEXT_releaseContext(ocspContext **ppReleaseContext);

/* Each context created by this API will have their own OCSP settings */
MOC_EXTERN MSTATUS OCSP_CONTEXT_createContextLocal(ocspContext **ppNewContext, sbyte4 roleType);
MOC_EXTERN MSTATUS OCSP_CONTEXT_releaseContextLocal(ocspContext **ppReleaseContext);

#ifdef __cplusplus
}
#endif

#endif /* __ENABLE_DIGICERT_OCSP_CLIENT__ */
#endif /* __OCSP_CONTEXT_HEADER__ */
