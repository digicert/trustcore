/*
 * ocsp.h
 *
 * OCSP general definitions
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

#ifndef __OCSP_HEADER__
#define __OCSP_HEADER__

#if (defined(__ENABLE_DIGICERT_OCSP_CLIENT__))

#ifdef __cplusplus
extern "C" {
#endif

/*------------------------------------------------------------------*/

typedef struct OCSP_singleRequestInfo
{
    ubyte*         pCert;
    ubyte4         certLen;
    extensions*    pSingleExts;
    ubyte4         extCount;

} OCSP_singleRequestInfo;

typedef enum OCSP_certStatusFlag
{
    ocsp_good    = 0,
    ocsp_revoked = 1,
    ocsp_unknown = 2

} OCSP_certStatusFlag;

typedef enum OCSP_certRevokeReasonFlags
{
    ocsp_unused               = 0,
    ocsp_keyCompromise        = 1,
    ocsp_cACompromise         = 2,
    ocsp_affiliationChanged   = 3,
    ocsp_superseded           = 4,
    ocsp_cessationOfOperation = 5,
    ocsp_certificateHold      = 6,
    ocsp_privilegeWithdrawn   = 7,
    ocsp_aACompromise         = 8

} OCSP_certRevokeReasonFlags;

typedef struct OCSP_certStatus
{
    OCSP_certStatusFlag           flag;
    TimeDate                      revocationTime;
    OCSP_certRevokeReasonFlags    revokeReasonFlag;

} OCSP_certStatus;

typedef enum OCSP_responseStatus
{
    ocsp_successful       = 0,
    ocsp_malformedRequest = 1,
    ocsp_internalError    = 2,
    ocsp_tryLater         = 3,
    ocsp_sigRequired      = 5,
    ocsp_unauthorized     = 6,
    ocsp_status_unknown   = -1

} OCSP_responseStatus;

typedef enum OCSP_responderIdType
{
    ocsp_byName    = 1,
    ocsp_byKeyHash = 2

} OCSP_responderIdType;


/*------------------------------------------------------------------*/

typedef struct OCSP_responderId
{
    OCSP_responderIdType type;

    union
    {
        certDistinguishedName*    pName;
        ubyte*                    keyHash;

    } value;

} OCSP_responderId;

/* internal type defs */
typedef struct OCSP_certID
{
    const ubyte*    hashAlgo;
    ubyte4          hashLength;
    ubyte*          nameHash;
    ubyte*          keyHash;
    ubyte*          serialNumber;
    ubyte4          serialNumberLength;

} OCSP_certID;

typedef struct OCSP_singleRequest
{
    OCSP_certID    certId;
    extensions*    singleRequestExtensions;
    ubyte4         extNumber;

} OCSP_singleRequest;

typedef struct OCSP_certInfo
{
    ubyte* pCertPath;
    ubyte4 certLen;

}OCSP_certInfo;

/*! Configuration settings for OCSP Client.
This structure is used for OCSP Client configuration.
 */

typedef struct ocspSettings
{
    sbyte*                    pResponderUrl;           /* optional, NULL terminated url string for responderaccess; if NULL
                                                          this info is expected to come from the certificate AIA extension */
    const ubyte*              hashAlgo;                /* oid, if absent, default is sha-1 */
    sbyte4                    timeSkewAllowed;         /* unit is second; Optional (1 minute by default) */
    byteBoolean               shouldSign;              /* true if the request should be signed (default is FALSE)*/
    const ubyte*              signingAlgo;             /* oid. if absent, default is sha-1WithRSAEncryption */
    byteBoolean               shouldAddNonce;          /* (indicate whether to add nonce extension in request); default FALSE */
    byteBoolean               shouldAddServiceLocator; /* (if info available in certs) default FALSE */
#if 0
    RNGFun                    rngFun;
    void*                     rngFunArg;
#endif
    ubyte4                    certCount;               /* the number of certificates in question */
    OCSP_singleRequestInfo*   pCertInfo;               /* info about each cert in question       */
    OCSP_certInfo*            pIssuerCertInfo;         /* infor about corresponding issuers      */

    ubyte*                    pIssuerCert;             /* Reading raw Issuer cert file *Internal**/
    ubyte4                    issuerCertLen;           /* length of raw issuer cert * Internal * */

    ubyte*                    pSignerCert;             /* Pointer to signer certificate          */
    ubyte4                    signerCertLen;           /* length of signer cert                  */

    ubyte*                    pPrivKey;                /* Pointer to private key                 */
    ubyte4                    privKeyLen;              /* length of private key                  */

    OCSP_certInfo*            pTrustedResponders;      /* locally configured responders to trust */
    ubyte4                    trustedResponderCount;
    ubyte4                    recvTimeout;             /* Configurable timeout for TCP_recv while waiting for OCSP response */
} ocspSettings;


/*------------------------------------------------------------------*/

MOC_EXTERN ocspSettings* OCSP_ocspSettings(void);

#ifdef __cplusplus
}
#endif

#endif /* (defined(__ENABLE_DIGICERT_OCSP_CLIENT__)) */
#endif /* __OCSP_HEADER__ */
