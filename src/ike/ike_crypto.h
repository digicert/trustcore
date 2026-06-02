/**
 * @file  ike_crypto.h
 * @brief IKE cryptographic operations.
 *
 * @details    IKE cryptographic suite definitions and DH group declarations.
 * @since      1.41
 * @version    6.5.1 and later
 * @flags      Compilation flags required:
 *     To enable any of this file's functions, the following flag must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_IKE_SERVER__
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
 *
 */


/*------------------------------------------------------------------*/
/* internal use only */

#ifndef __IKE_CRYPTO_HEADER__
#define __IKE_CRYPTO_HEADER__

#if defined(__ENABLE_DIGICERT_IKE_SERVER__)

#ifdef __cplusplus
extern "C" {
#endif


#include "../crypto/pubcrypto.h"
struct ikePeerConfig;

/*------------------------------------------------------------------*/

/* [v2] */

/* bulk PRF algorithms descriptions */
typedef MSTATUS (*InitBulkCtxFunc)  (MOC_SYM(hwAccelDescr hwAccelCtx) const ubyte keyMaterial[/*keyLength*/], sbyte4 keyLength, BulkCtx ctx);
typedef MSTATUS (*UpdateBulkCtxFunc)(MOC_SYM(hwAccelDescr hwAccelCtx) const ubyte *data, sbyte4 datalength, BulkCtx ctx);
typedef MSTATUS (*FinalBulkCtxFunc) (MOC_SYM(hwAccelDescr hwAccelCtx) ubyte *result, BulkCtx ctx);

typedef struct BulkPrfAlgo
{
    ubyte4                  digestSize;
    BulkCtxAllocFunc        allocFunc;
    BulkCtxFreeFunc         freeFunc;
    InitBulkCtxFunc         initFunc;
    UpdateBulkCtxFunc       updateFunc;
    FinalBulkCtxFunc        finalFunc;
} BulkPrfAlgo;


/*------------------------------------------------------------------*/

struct BulkHashAlgo;

typedef struct IKE_hashSuiteInfo
{
#if defined(__ENABLE_ALL_DEBUGGING__) && defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__)
    sbyte      *name1, *name2;
#endif
#ifdef __ENABLE_IKE_SIG_AUTH_RFC7427__
    ubyte2      wSigHash;       /* [v2] hash algorithm for AUTH_MTD_SIG */
#endif
    ubyte2      wHashAlgo;      /* [v1] OAKLEY hash algorithm attribute */
    ubyte2      wTfmId;         /* [v2] PRF_ transform ID */

    struct BulkHashAlgo *pBHAlgo;   /* the hash functions */
    struct BulkPrfAlgo *pBPAlgo;    /* the prf functions [v2] */

    intBoolean  bDisabled[2][2];/* [v1, v2][I, R] */
} IKE_hashSuiteInfo;


/*------------------------------------------------------------------*/

struct BulkEncryptionAlgo;

typedef struct IKE_cipherSuiteInfo
{
    ubyte2      wEncrAlgo;      /* [v1] OAKLEY encryption algorithm attribute */
    ubyte2      wTfmId;         /* [v2] ENCR_ transform ID */

    ubyte2      wIvLen;         /* length of IV (initialization vector) */
    ubyte2      wKeyLen;        /* encryption key length (in bytes, minimum); 0=unspecified */
    ubyte2      wKeyLenEnd;     /* encryption key length (in bytes, maximum); 0=unspecified */

    intBoolean  bFixedKeyLen;   /* fixed key length? */

    const struct BulkEncryptionAlgo *
                pBEAlgo;        /* the encryption functions */

    intBoolean  bDisabled[2][2];/* [v1, v2][I, R] */

    const struct AeadAlgo *
                pAeadAlgo;     /* authenticated encryption functions */
} IKE_cipherSuiteInfo;


/*------------------------------------------------------------------*/

/* [v2] */
typedef struct IKE_macSuiteInfo
{
#if defined(__ENABLE_ALL_DEBUGGING__) && defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__)
    sbyte      *name;
#endif
    ubyte2      wTfmId;         /* AUTH_ transform ID */

    ubyte2      wIcvLen;        /* ICV (integrity check value) length */
    ubyte2      wKeyLen;        /* authentication key length (in bytes) */

    MSTATUS (*hmacFunc)(MOC_HASH(hwAccelDescr hwAccelCtx)
                        const ubyte* key, sbyte4 keyLen,
                        const ubyte* text, sbyte4 textLen, ubyte result[]);

    intBoolean  bDisabled[2];   /* [I, R] */
} IKE_macSuiteInfo;


/*------------------------------------------------------------------*/

struct PrimeEllipticCurve;

typedef struct IKE_dhGroupInfo
{
    ubyte2      wTfmId;         /* transform ID */
    ubyte4      dwGroupNum;
    ubyte4      curveId;
    intBoolean  bDisabled[2][2];/* [v1, v2][I, R] */
    ubyte4      qsAlgoId;
} IKE_dhGroupInfo;


/*------------------------------------------------------------------*/

typedef struct IKE_authMtdInfo
{
    ubyte2      wAuthMtd;       /* [v1] OAKLEY auth method attribute */
    ubyte       oAuthMtd;       /* [v2] AUTH_MTD_ value */

#ifdef __ENABLE_DIGICERT_ECC__
    ubyte4      curveId;
    const struct BulkHashAlgo *pBHAlgo;
#endif
#ifdef __ENABLE_DIGICERT_PQC__
    ubyte4      qsAlgoId;
#endif
    intBoolean  bEnabled[2];    /* [v1] [I, R] */

    /* [v2] Auth method is not negotiated and each endpoint can authenticate
     * itself using a different mechanism.
     */
    intBoolean  bDisabledIn[2], /* In/Peer [I, R] */
                bEnabledOut[2]; /* Out/Host [I, R] */

} IKE_authMtdInfo;


/*------------------------------------------------------------------*/

extern IKE_hashSuiteInfo    *IKE_hashSuiteEx(struct ikePeerConfig*, ubyte2 wHashAlgo, ubyte2 wTfmId);
extern IKE_hashSuiteInfo    *IKE_getHashSuiteEx(struct ikePeerConfig*, sbyte4 i);

extern IKE_cipherSuiteInfo  *IKE_cipherSuiteEx(struct ikePeerConfig*, ubyte2 wEncrAlgo, ubyte2 wTfmId,
                                             ubyte2 wKeyLen, ubyte2 *pwKeyLen);
extern IKE_cipherSuiteInfo  *IKE_getCipherSuiteEx(struct ikePeerConfig*, sbyte4 i);

extern IKE_dhGroupInfo      *IKE_dhGroupEx(struct ikePeerConfig*, ubyte2 wTfmId);
extern IKE_dhGroupInfo      *IKE_getDhGroupEx(struct ikePeerConfig*, sbyte4 i);
extern IKE_dhGroupInfo      *IKE_getKeyExchangeGroup(struct ikePeerConfig*, sbyte4 i, ubyte4 proposalNum);

extern IKE_authMtdInfo      *IKE_authMtdEx(struct ikePeerConfig*, ubyte2 wAuthMtd, ubyte oAuthMtd);
extern IKE_authMtdInfo      *IKE_getAuthMtdEx(struct ikePeerConfig*, sbyte4 i);

/* [v2] */

extern IKE_macSuiteInfo     *IKE_macSuiteEx(struct ikePeerConfig*, ubyte2 wTfmId);
extern IKE_macSuiteInfo     *IKE_getMacSuiteEx(struct ikePeerConfig*, sbyte4 i);

/* Old Functions */

extern IKE_hashSuiteInfo    *IKE_hashSuite(ubyte2 wHashAlgo, ubyte2 wTfmId);
extern IKE_hashSuiteInfo    *IKE_getHashSuite(sbyte4 i);
extern IKE_cipherSuiteInfo  *IKE_cipherSuite(ubyte2 wEncrAlgo, ubyte2 wTfmId,
                                             ubyte2 wKeyLen, ubyte2 *pwKeyLen);
extern IKE_cipherSuiteInfo  *IKE_getCipherSuite(sbyte4 i);
extern IKE_dhGroupInfo      *IKE_dhGroup(ubyte2 wTfmId);
extern IKE_dhGroupInfo      *IKE_getDhGroup(sbyte4 i);
extern IKE_authMtdInfo      *IKE_authMtd(ubyte2 wAuthMtd, ubyte oAuthMtd);
extern IKE_authMtdInfo      *IKE_getAuthMtd(sbyte4 i);
extern IKE_macSuiteInfo     *IKE_macSuite(ubyte2 wTfmId);
extern IKE_macSuiteInfo     *IKE_getMacSuite(sbyte4 i);

/* End of old functions */

extern MSTATUS IKE_getSigHashAlgo(ubyte oSigAlgo,
                                  const ubyte** ppId, ubyte2 *pIdLen,
                                  const struct BulkHashAlgo **ppBHAlgo);
extern MSTATUS IKE_getHashAlgoByInfo(const ubyte* info, ubyte2 len, /* PKCS1 DigestInfo */
                                     ubyte2 *pIdLen, const struct BulkHashAlgo **ppBHAlgo);

#ifdef __ENABLE_IKE_SIG_AUTH_RFC7427__
extern IKE_hashSuiteInfo    *IKE_sigHashSuite(struct ikePeerConfig*, ubyte2 ht);

extern MSTATUS IKE_getSigAlgo(ubyte4 akt, /* akt_rsa or akt_ecc */
                              ubyte2 ht, /* hash algo value in RFC7427 7. */
                              ubyte *poSigAlgo, /* RSA only */
                              const ubyte **ppId, ubyte *pLen,
                              const struct BulkHashAlgo **ppBHAlgo);

extern MSTATUS IKE_getSigAlgoById(const ubyte *id, ubyte len,
                                  ubyte4 *akt, const struct BulkHashAlgo **ppBHAlgo);
#endif


/*------------------------------------------------------------------*/

extern MSTATUS IKE_initPropEx(struct ikePeerConfig* config,
                              ubyte2 wType,    /* see Phase 1 OAKLEY_ 'attribute type' [v1] in "ike_defs.h" */
                              ubyte2 wValue,   /* see Phase 1 OAKLEY_ 'attribute value' */
                              ubyte2 wKeyLen,  /* 0=any or n/a (in bytes) */
                              sbyte4 dir,      /* 0=both, 1=responder, 2=initiator */
                              intBoolean on);  /* TRUE=enable, FALSE=disbale */

extern MSTATUS IKE2_initPropEx(struct ikePeerConfig* config,
                               ubyte oType,    /* see 'Transform Types' [v2] in "ike_defs.h" */
                               ubyte2 wId,     /* see 'Transform ID's' */
                               ubyte2 wKeyLen, /* 0=any or n/a (in bytes) */
                               sbyte4 dir,     /* 0=both, 1=responder, 2=initiator */
                               intBoolean on); /* TRUE=enable, FALSE=disbale */

extern MSTATUS IKE2_initAuthMtdEx(struct ikePeerConfig* config,
                                  ubyte oAuthMtd, /* see [v2] Auth Methods in "ike_defs.h" */
                                  sbyte4 endpoint,/* 0=both, 1=IN/peer, 2=OUT/host */
                                  sbyte4 dir,     /* 0=both, 1=responder, 2=initiator */
                                  intBoolean on); /* TRUE=enable, FALSE=disbale */


/*------------------------------------------------------------------*/

struct ikesa;
extern MSTATUS IKE_newSaIv(MOC_HASH(hwAccelDescr hwAccelCtx)
                           struct ikesa *pxSa, ubyte4 *pdwMsgId,
                           ubyte *poIv);

extern MSTATUS IKE_cryptoInit(void);
extern MSTATUS IKE_cryptoUninit(void);

#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
extern MSTATUS IKE_getHwAccelChannel(hwAccelDescr *pHwAccelCtx);
extern MSTATUS IKE_releaseHwAccelChannel(hwAccelDescr *pHwAccelCtx);
#endif

#ifdef __IKE_MULTI_THREADED__
#define IKE_sha1Alloc   SHA1_allocDigest
#define IKE_sha1Free    SHA1_freeDigest

#define IKE_md5Alloc    MD5Alloc_m
#define IKE_md5Free     MD5Free_m
#else
extern MSTATUS IKE_sha1Alloc(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context);
extern MSTATUS IKE_sha1Free(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context);

extern MSTATUS IKE_md5Alloc(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context);
extern MSTATUS IKE_md5Free(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context);
#endif

/* Internal Digicert function */
extern MSTATUS IKE_initSuiteInfo(struct ikePeerConfig* config);

#ifdef __cplusplus
}
#endif

#endif /* __ENABLE_DIGICERT_IKE_SERVER__ */

#endif /* __IKE_CRYPTO_HEADER__ */

