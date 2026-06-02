/**
 * @file  ike_childsa.h
 * @brief IKE Child SA cryptographic suites.
 *
 * @details    IKE Child SA algorithm definitions and structures.
 * @since      1.41
 * @version    6.5.1 and later
 * @flags      Compilation flags required:
 *     To enable any of this file's functions, one of the following flag must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_IKE_SERVER__
 *     Additionally, the following flag must be defined in moptions.h:
 *     +   \c \__ENABLE_DIGICERT_PFKEY__
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

#ifndef __IKE_CHILDSA_HEADER__
#define __IKE_CHILDSA_HEADER__

#if defined(__ENABLE_DIGICERT_IKE_SERVER__) || defined(__ENABLE_DIGICERT_PFKEY__)

#ifdef __cplusplus
extern "C" {
#endif


/*------------------------------------------------------------------*/
/* key sizes */

/* Warning: Must update as needed (e.g. when new PF_KEY algorithms
   are supported.  See "ike_childsa.c".
 */
#ifndef __ENABLE_DIGICERT_PFKEY__

#define CHILDSA_ENCRKEY_MAX IKE_ENCRKEY_MAX
#define CHILDSA_AUTHKEY_MAX IKE_AUTHKEY_MAX

#else

#define CHILDSA_AUTHKEY_MAX     (64)    /* SHA512_RESULT_SIZE */

#if   !defined(__DISABLE_DIGICERT_SHA384__)
#define CHILDSA_ENCRKEY_MAX     (96)    /* 2xSHA384_RESULT_SIZE > 56 (blowfish) */
#elif !defined(__DISABLE_DIGICERT_SHA512__)
#define CHILDSA_ENCRKEY_MAX     (64)    /* SHA512_RESULT_SIZE > 56 (blowfish) */
#elif !defined(__DISABLE_DIGICERT_SHA256__)
#define CHILDSA_ENCRKEY_MAX     (64)    /* 2xSHA256_RESULT_SIZE > 56 (blowfish) */
#else
#define CHILDSA_ENCRKEY_MAX     (60)    /* 3xSHA1_RESULT_SIZE > 56 (blowfish) */
#endif

#endif


/*------------------------------------------------------------------*/

typedef struct CHILDSA_encrInfo
{
#if defined(__ENABLE_ALL_DEBUGGING__) && defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__)
    sbyte      *name;
#endif
    ubyte       oTfmId;         /* [v1] ESP_ transform payload ID */
    ubyte2      wTfmId;         /* [v2] ENCR_ transform ID */

    ubyte       oEncrAlgo;      /* IPsec encr. algorithm ID; see "ipsec_defs.h" */

    ubyte2      wKeyLen;        /* encryption key length (in bytes, minimum); 0=unspecified */
    ubyte2      wKeyLenEnd;     /* encryption key length (in bytes, maximum); 0=unspecified */

    intBoolean  bFixedKeyLen;   /* fixed key length? */

    ubyte       oNonceLen;      /* e.g. gcm/gmac or aes-ctr or aes-ccm */
    ubyte       oTagLen;        /* AEAD algo tag size (ICV) */
    intBoolean  bAeadNull;      /* NULL-encr? */
#ifdef __ENABLE_DIGICERT_PFKEY__
    intBoolean  bSupported;
#endif
} CHILDSA_encrInfo;


/*------------------------------------------------------------------*/

typedef struct CHILDSA_authInfo
{
#if defined(__ENABLE_ALL_DEBUGGING__) && defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__)
    sbyte      *name;
#endif
    ubyte2      wAuthAlgo;      /* [v1] auth. algo. atttribute */
    ubyte       oTfmId;         /* [v1] AH_ transform payload ID */
    ubyte2      wTfmId;         /* [v2] AUTH_ transform ID */

    ubyte       oAuthAlgo;      /* IPsec auth. algorithm ID; see "ipsec_defs.h" */

    ubyte2      wKeyLen;        /* auth. key length (in bytes) */

#ifdef __ENABLE_DIGICERT_PFKEY__
    intBoolean  bSupported;
#endif
} CHILDSA_authInfo;


/*------------------------------------------------------------------*/

extern CHILDSA_encrInfo *CHILDSA_findAeadAlgo(ubyte oTfmId,
                                              ubyte2 wTfmId,
                                              ubyte oEncrAlgo,
                                              ubyte aeadTag,
                                              ubyte2 wKeyLen,
                                              ubyte2 *pwKeyLen);
#define CHILDSA_findEncrAlgo(a, b, c, d, e) CHILDSA_findAeadAlgo(a, b, c, 0, d, e)

extern CHILDSA_encrInfo*
CHILDSA_findAeadAlgoWithConstraint
                    (ubyte2 maxBitStrength,
                     ubyte oTfmId,
                     ubyte2 wTfmId,
                     ubyte oEncrAlgo,
                     ubyte aeadTag,
                     ubyte2 wKeyLen,
                     ubyte2 *pwKeyLen);
#define CHILDSA_findEncrAlgoWithConstraint(a, b, c, d, e, f) CHILDSA_findAeadAlgoWithConstraint(a, b, c, d, 0, e, f)

extern CHILDSA_encrInfo *CHILDSA_getEncrAlgo(sbyte4 i);

extern CHILDSA_authInfo *CHILDSA_findAuthAlgo(ubyte2 wAuthAlgo,
                                              ubyte oTfmId,
                                              ubyte2 wTfmId,
                                              ubyte oAuthAlgo);

extern CHILDSA_authInfo *CHILDSA_getAuthAlgo(sbyte4 i);

extern ubyte2 CHILDSA_cipherEffectiveBitStrength(ubyte2 wEncrAlgo,
                                                 ubyte2 wKeyLen);

extern ubyte2 CHILDSA_cipherMaxKeyLengthWithConstraint(ubyte2 encrAlgo,
                                                       ubyte2 wTfmId,
                                                       ubyte2 oEncrAlgo,
                                                       ubyte2 wKeyLenMin,
                                                       ubyte2 wKeyLenMax,
                                                       ubyte2 maxStrength);
/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_IPCOMP__

typedef struct CHILDSA_compInfo
{
#if defined(__ENABLE_ALL_DEBUGGING__) && defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__)
    sbyte      *name;
#endif
    ubyte       oTfmId;         /* IPCOMP_ transform ID */

} CHILDSA_compInfo;

extern CHILDSA_compInfo *CHILDSA_findCompAlgo(ubyte oTfmId);
extern CHILDSA_compInfo *CHILDSA_getCompAlgo(sbyte4 i);

#endif /* __ENABLE_DIGICERT_IPCOMP__ */


#ifdef __cplusplus
}
#endif

#endif /* defined(__ENABLE_DIGICERT_IKE_SERVER__) || defined(__ENABLE_DIGICERT_PFKEY__) */

#endif /* __IKE_CHILDSA_HEADER__ */

