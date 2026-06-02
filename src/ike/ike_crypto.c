/**
 * @file  ike_crypto.c
 * @brief IKE cryptographic operations.
 *
 * @details    IKE cryptographic suites including DH groups and PQC hybrid algorithms.
 * @since      1.41
 * @version    6.5.1 and later
 * @flags      Compilation flags required:
 *     To enable this file's functions, the following flag must be defined in
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

#include "../common/moptions.h"

#if defined(__ENABLE_DIGICERT_IKE_SERVER__)

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../crypto/secmod.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/random.h"
#include "../common/vlong.h"
#include "../common/mem_pool.h"
#include "../crypto/dh.h"
#include "../crypto/md2.h"
#include "../crypto/md4.h"
#include "../crypto/md5.h"
#include "../crypto/sha1.h"
#include "../crypto/sha256.h"
#include "../crypto/sha512.h"
#include "../crypto/blake2.h"
#include "../crypto/crypto.h"
#include "../crypto/hmac.h"
#include "../crypto/des.h"
#include "../crypto/three_des.h"
#include "../crypto/blowfish.h"
#include "../crypto/aes.h"
#include "../crypto/aes_ctr.h"
#include "../crypto/gcm.h"
#include "../crypto/aes_ccm.h"
#include "../crypto/aes_xcbc_mac_96.h"
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../crypto_interface/crypto_interface_aes.h"
#include "../crypto_interface/crypto_interface_aes_xcbc_mac_96.h"
#include "../crypto_interface/crypto_interface_aes_gcm.h"
#include "../crypto_interface/crypto_interface_aes_ccm.h"
#include "../crypto_interface/crypto_interface_chacha20.h"
#include "../crypto_interface/crypto_interface_blake2.h"
#include "../crypto_interface/crypto_interface_sha1.h"
#include "../crypto_interface/crypto_interface_md5.h"
#endif
#ifdef __ENABLE_DIGICERT_ECC__
#include "../crypto/primefld.h"
#include "../crypto/primeec.h"
#endif
#include "../crypto/ca_mgmt.h"
#include "../crypto/pubcrypto.h"
#include "../ike/ike.h"
#include "../harness/harness.h"
#include "../ipsec/ipsec_defs.h"
#include "../ike/ike_defs.h"
#include "../ike/ike_crypto.h"
#include "../ike/ike_cert.h"


/*------------------------------------------------------------------*/

/* Warning: Must update IKE_HASH_MAX and IKE_ENCRKEY_MAX in
   "ikesa.h" when new algorithms are supported and added to
   this file.
 */


/*------------------------------------------------------------------*/

#ifndef __DISABLE_AES_CIPHERS__
#ifndef __DISABLE_AES_XCBC_CIPHER__
static MSTATUS AES_XCBC_alloc(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context);
static MSTATUS AES_XCBC_free(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context);
#endif
#endif

#ifdef __ENABLE_DIGICERT_PQC__
#define NOHASH_MAX_DIGEST_LEN  3000
#else
#define NOHASH_MAX_DIGEST_LEN  1500
#endif

typedef struct NO_HASH_CTX
{
    ubyte pMsgCopy[NOHASH_MAX_DIGEST_LEN];
    ubyte4 msgCopyLen;

} NO_HASH_CTX;

static MSTATUS NO_HASH_allocDigest(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pCtx)
{
    if (NULL == pCtx)
        return ERR_NULL_POINTER;

    return DIGI_MALLOC(pCtx, sizeof(NO_HASH_CTX));
}

static MSTATUS NO_HASH_initDigest(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx ctx)
{
    if (NULL == ctx)
        return ERR_NULL_POINTER;

    ((NO_HASH_CTX *) ctx)->msgCopyLen = 0;
    return OK;
}

static MSTATUS NO_HASH_updateDigest(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx ctx, const ubyte *pMessage, ubyte4 messageLen)
{
    MSTATUS status = ERR_NULL_POINTER;
    NO_HASH_CTX *pCtx = (NO_HASH_CTX *) ctx;

    if (NULL == pCtx || (messageLen && NULL == pMessage))
        goto exit;

    if(messageLen > (NOHASH_MAX_DIGEST_LEN - pCtx->msgCopyLen))
        goto exit;

    if (messageLen)
    {
        status = DIGI_MEMCPY(pCtx->pMsgCopy + pCtx->msgCopyLen, pMessage, messageLen);
        if (OK != status)
            goto exit;

        pCtx->msgCopyLen += messageLen;
    }
    /* else no-op */

exit:

    return status;
}

static MSTATUS NO_HASH_finalDigest(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte *pResult)
{
    NO_HASH_CTX *pCtx = (NO_HASH_CTX *) ctx;

    if (NULL == pCtx || NULL == pResult)
        return ERR_NULL_POINTER;

    if (pCtx->msgCopyLen)
    {
        /* ok to ignore return codes */
        DIGI_MEMCPY(pResult, pCtx->pMsgCopy, pCtx->msgCopyLen);
        DIGI_MEMSET(pCtx->pMsgCopy, 0x00, pCtx->msgCopyLen);
        pCtx->msgCopyLen = 0;
    }

    return OK;
}

static MSTATUS NO_HASH_freeDigest(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pCtx)
{
    if (NULL == pCtx)
        return ERR_NULL_POINTER;

    return DIGI_FREE(pCtx);
}


/*------------------------------------------------------------------*/
static BulkHashAlgo NoHashSuite =
{
    NOHASH_MAX_DIGEST_LEN , 0, NO_HASH_allocDigest, NO_HASH_freeDigest,
    NO_HASH_initDigest, NO_HASH_updateDigest, NO_HASH_finalDigest, NULL, NULL, NULL, ht_none
};

static BulkHashAlgo SHASuite =
    { SHA1_RESULT_SIZE/*20*/, SHA1_BLOCK_SIZE, IKE_sha1Alloc, IKE_sha1Free,
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
      (BulkCtxInitFunc) CRYPTO_INTERFACE_SHA1_initDigest, (BulkCtxUpdateFunc) CRYPTO_INTERFACE_SHA1_updateDigest,
      (BulkCtxFinalFunc) CRYPTO_INTERFACE_SHA1_finalDigest, NULL, NULL, NULL, ht_sha1 };
#else
      (BulkCtxInitFunc)SHA1_initDigestHandShake, (BulkCtxUpdateFunc)SHA1_updateDigestHandShake, (BulkCtxFinalFunc)SHA1_finalDigestHandShake, NULL, NULL, NULL, ht_sha1 };
#endif

static BulkHashAlgo MD5Suite =
    { MD5_RESULT_SIZE/*16*/, MD5_BLOCK_SIZE, IKE_md5Alloc, IKE_md5Free,
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
      (BulkCtxInitFunc) CRYPTO_INTERFACE_MD5Init_m, (BulkCtxUpdateFunc) CRYPTO_INTERFACE_MD5Update_m, (BulkCtxFinalFunc) CRYPTO_INTERFACE_MD5Final_m, NULL, NULL, NULL, ht_md5 };
#else
      (BulkCtxInitFunc) MD5init_HandShake, (BulkCtxUpdateFunc)MD5update_HandShake, (BulkCtxFinalFunc)MD5final_HandShake, NULL, NULL, NULL, ht_md5 };
#endif

#ifdef __ENABLE_DIGICERT_BLAKE_2B__
static MSTATUS BLAKE2B_initEx(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx pCtx)
{
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    return CRYPTO_INTERFACE_BLAKE_2B_init(MOC_HASH(hwAccelCtx) pCtx, MOC_BLAKE2B_MAX_OUTLEN, NULL, 0);
#else
    return BLAKE2B_init(MOC_HASH(hwAccelCtx) pCtx, MOC_BLAKE2B_MAX_OUTLEN, NULL, 0);
#endif
}

static BulkHashAlgo BLAKE2BSuite =
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    { MOC_BLAKE2B_MAX_OUTLEN, MOC_BLAKE2B_BLOCKLEN,
        CRYPTO_INTERFACE_BLAKE_2B_alloc, CRYPTO_INTERFACE_BLAKE_2B_delete,
        BLAKE2B_initEx, (BulkCtxUpdateFunc)CRYPTO_INTERFACE_BLAKE_2B_update,
        (BulkCtxFinalFunc)CRYPTO_INTERFACE_BLAKE_2B_final, NULL, NULL, NULL, ht_blake2b };
#else
    { MOC_BLAKE2B_MAX_OUTLEN, MOC_BLAKE2B_BLOCKLEN, BLAKE2B_alloc, BLAKE2B_delete,
      (BulkCtxInitFunc)BLAKE2B_initEx, (BulkCtxUpdateFunc)BLAKE2B_update,
      (BulkCtxFinalFunc)BLAKE2B_final, NULL, NULL, NULL, ht_blake2b };
#endif
#endif /* __ENABLE_DIGICERT_BLAKE_2B__ */

#ifdef __ENABLE_DIGICERT_BLAKE_2S__
static MSTATUS BLAKE2S_initEx(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx pCtx)
{
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    return CRYPTO_INTERFACE_BLAKE_2S_init(MOC_HASH(hwAccelCtx) pCtx, MOC_BLAKE2S_MAX_OUTLEN, NULL, 0);
#else
    return BLAKE2S_init(MOC_HASH(hwAccelCtx) pCtx, MOC_BLAKE2S_MAX_OUTLEN, NULL, 0);
#endif
}

static BulkHashAlgo BLAKE2SSuite =
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    { MOC_BLAKE2S_MAX_OUTLEN, MOC_BLAKE2S_BLOCKLEN,
        CRYPTO_INTERFACE_BLAKE_2S_alloc, CRYPTO_INTERFACE_BLAKE_2S_delete,
        BLAKE2S_initEx, (BulkCtxUpdateFunc)CRYPTO_INTERFACE_BLAKE_2S_update,
      (BulkCtxFinalFunc)CRYPTO_INTERFACE_BLAKE_2S_final, NULL, NULL, NULL, ht_blake2s };
#else
    { MOC_BLAKE2S_MAX_OUTLEN, MOC_BLAKE2S_BLOCKLEN, BLAKE2S_alloc, BLAKE2S_delete,
      (BulkCtxInitFunc)BLAKE2S_initEx, (BulkCtxUpdateFunc)BLAKE2S_update,
      (BulkCtxFinalFunc)BLAKE2S_final, NULL, NULL, NULL, ht_blake2s };
#endif
#endif /* __ENABLE_DIGICERT_BLAKE_2S__ */

#ifndef __DISABLE_AES_CIPHERS__
#ifndef __DISABLE_AES_XCBC_CIPHER__
MOC_EXTERN MSTATUS AES_XCBC_PRF_128_initEx(
    MOC_SYM(hwAccelDescr hwAccelCtx)
    const ubyte pKeyMaterial[/*keyLength*/],
    sbyte4 keyLength,
    AES_XCBC_PRF_128_Ctx *pCtx
    )
{
    MSTATUS status;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_AES_XCBC_clear(MOC_SYM(hwAccelCtx) pCtx);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_AES_XCBC_PRF_128_init(MOC_SYM(hwAccelCtx)
        pKeyMaterial, keyLength, pCtx);
#else
    status = AES_XCBC_clear(MOC_SYM(hwAccelCtx) pCtx);
    if (OK != status)
        goto exit;
    status = AES_XCBC_PRF_128_init(MOC_SYM(hwAccelCtx)
        pKeyMaterial, keyLength, pCtx);
#endif
exit:
    return status;

}

static BulkPrfAlgo AESxSuite =
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    { AES_XCBC_PRF_128_RESULT_SIZE/*16*/, AES_XCBC_alloc, AES_XCBC_free,
      (InitBulkCtxFunc)AES_XCBC_PRF_128_initEx, (UpdateBulkCtxFunc)CRYPTO_INTERFACE_AES_XCBC_MAC_96_update, (FinalBulkCtxFunc)CRYPTO_INTERFACE_AES_XCBC_PRF_128_final };
#else
    { AES_XCBC_PRF_128_RESULT_SIZE/*16*/, AES_XCBC_alloc, AES_XCBC_free,
      (InitBulkCtxFunc)AES_XCBC_PRF_128_initEx, (UpdateBulkCtxFunc)AES_XCBC_PRF_128_update, (FinalBulkCtxFunc)AES_XCBC_PRF_128_final };
#endif
#endif
#endif
#ifdef __ENABLE_DIGICERT_MD2__
static BulkHashAlgo MD2Suite =
    { MD2_RESULT_SIZE/*16*/, MD2_BLOCK_SIZE, MD2Alloc, MD2Free,
      (BulkCtxInitFunc)MD2Init, (BulkCtxUpdateFunc)MD2Update, (BulkCtxFinalFunc)MD2Final, NULL, NULL, NULL, ht_md2 };
#endif

#ifdef __ENABLE_DIGICERT_MD4__
static BulkHashAlgo MD4Suite =
    { MD4_RESULT_SIZE/*16*/, MD4_BLOCK_SIZE, MD4Alloc, MD4Free,
      (BulkCtxInitFunc)MD4Init, (BulkCtxUpdateFunc)MD4Update, (BulkCtxFinalFunc)MD4Final, NULL, NULL, NULL, ht_md4 };
#endif

#ifndef __DISABLE_DIGICERT_SHA224__
static BulkHashAlgo SHA224Suite =
    { SHA224_RESULT_SIZE/*28*/, SHA224_BLOCK_SIZE, SHA224_allocDigest, SHA224_freeDigest,
      (BulkCtxInitFunc)SHA224_initDigest, (BulkCtxUpdateFunc)SHA224_updateDigest, (BulkCtxFinalFunc)SHA224_finalDigest, NULL, NULL, NULL, ht_sha224 };
#endif

#ifndef __DISABLE_DIGICERT_SHA256__
static BulkHashAlgo SHA256Suite =
    { SHA256_RESULT_SIZE/*32*/, SHA256_BLOCK_SIZE, SHA256_allocDigest, SHA256_freeDigest,
      (BulkCtxInitFunc)SHA256_initDigest, (BulkCtxUpdateFunc)SHA256_updateDigest, (BulkCtxFinalFunc)SHA256_finalDigest, NULL, NULL, NULL, ht_sha256 };
#endif

#ifndef __DISABLE_DIGICERT_SHA384__
static BulkHashAlgo SHA384Suite =
    { SHA384_RESULT_SIZE/*48*/, SHA384_BLOCK_SIZE, SHA384_allocDigest, SHA384_freeDigest,
      (BulkCtxInitFunc)SHA384_initDigest, (BulkCtxUpdateFunc)SHA384_updateDigest, (BulkCtxFinalFunc)SHA384_finalDigest, NULL, NULL, NULL, ht_sha384 };
#endif

#ifndef __DISABLE_DIGICERT_SHA512__
static BulkHashAlgo SHA512Suite =
    { SHA512_RESULT_SIZE/*64*/, SHA512_BLOCK_SIZE, SHA512_allocDigest, SHA512_freeDigest,
      (BulkCtxInitFunc)SHA512_initDigest, (BulkCtxUpdateFunc)SHA512_updateDigest, (BulkCtxFinalFunc)SHA512_finalDigest, NULL, NULL, NULL, ht_sha512 };
#endif

#if defined(__ENABLE_ALL_DEBUGGING__) && defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__)
#define ALGONAMES(_n1, _n2) (sbyte *)_n1, (sbyte *)_n2,
#else
#define ALGONAMES(_n1, _n2)
#endif

#ifdef __ENABLE_IKE_SIG_AUTH_RFC7427__
#define SIGAUTH(_a) (ubyte2)_a,
#else
#define SIGAUTH(_a)
#endif

static IKE_hashSuiteInfo mHashSuites[] =
{/* { wHashAlgo [v1],       wTfmId [v2],        pBHAlgo,        pBPAlgo },
  */
#ifndef __DISABLE_AES_CIPHERS__
#ifndef __DISABLE_AES_XCBC_CIPHER__
    { ALGONAMES(NULL,       "AES128_XCBC"   )   SIGAUTH(0)      /* [v2] */
      OAKLEY_HASH_NA,/*!!!*/PRF_AES128_XCBC,    NULL,           &AESxSuite, { {TRUE, TRUE} } },
#endif
#endif

#ifndef __DISABLE_DIGICERT_SHA512__
    { ALGONAMES("SHA2-512", "HMAC_SHA2_512" )   SIGAUTH(HASH_SHA2_512)
      OAKLEY_SHA2_512,      PRF_HMAC_SHA2_512,  &SHA512Suite
#ifdef __ENABLE_DIGICERT_IKE_UNSECURE_HASH__
                                                            ,   NULL,       { {TRUE} }
#else
                                                            ,   NULL,       { {FALSE} }
#endif
                                                                                       },
#endif
#ifndef __DISABLE_DIGICERT_SHA384__
    { ALGONAMES("SHA2-384", "HMAC_SHA2_384" )   SIGAUTH(HASH_SHA2_384)
      OAKLEY_SHA2_384,      PRF_HMAC_SHA2_384,  &SHA384Suite
#ifdef __ENABLE_DIGICERT_IKE_UNSECURE_HASH__
                                                            ,   NULL,       { {TRUE} }
#else
                                                            ,   NULL,       { {FALSE} }
#endif
                                                                                       },
#endif
#ifndef __DISABLE_DIGICERT_SHA256__
    { ALGONAMES("SHA2-256", "HMAC_SHA2_256" )   SIGAUTH(HASH_SHA2_256)
      OAKLEY_SHA2_256,      PRF_HMAC_SHA2_256,  &SHA256Suite
#ifdef __ENABLE_DIGICERT_IKE_UNSECURE_HASH__
                                                            ,   NULL,       { {TRUE} }
#else
                                                            ,   NULL,       { {FALSE} }
#endif
                                                                                       },
#endif

#if defined(__ENABLE_IKE_SIG_AUTH_RFC7427__)
#if defined(__ENABLE_DIGICERT_ECC_EDDSA_25519__) || defined(__ENABLE_DIGICERT_ECC_EDDSA_448__)
    { ALGONAMES(NULL, "IDENTITY") SIGAUTH(HASH_IDENTITY)
      OAKLEY_HASH_NA, PRF_NA, NULL, NULL,    {{TRUE,TRUE},{TRUE,TRUE}} },
#endif
#endif
#ifdef __ENABLE_DIGICERT_BLAKE_2B__
    { ALGONAMES("BLAKE2-2B", "BLAKE2-2B" )   SIGAUTH(0)
      OAKLEY_BLAKE2_2B,      PRF_HMAC_BLAKE2_2B,    &BLAKE2BSuite
#ifdef __ENABLE_DIGICERT_IKE_UNSECURE_HASH__
                                                            ,   NULL,       { {TRUE} }
#else
                                                            ,   NULL,       { {FALSE} }
#endif
                                                                                       },
#endif
#ifdef __ENABLE_DIGICERT_BLAKE_2S__
    { ALGONAMES("BLAKE2-2S", "BLAKE2-2S" )   SIGAUTH(0)
      OAKLEY_BLAKE2_2S,     PRF_HMAC_BLAKE2_2S,     &BLAKE2SSuite
#ifdef __ENABLE_DIGICERT_IKE_UNSECURE_HASH__
                                                            ,   NULL,       { {TRUE} }
#else
                                                            ,   NULL,       { {FALSE} }
#endif
                                                                                       },
#endif

#if defined(__ENABLE_DIGICERT_IKE_UNSECURE_HASH__)
    { ALGONAMES("SHA1",     "HMAC_SHA1"     )   SIGAUTH(HASH_SHA1)
      OAKLEY_SHA,           PRF_HMAC_SHA1,      &SHASuite, NULL, { {FALSE} }  },

    { ALGONAMES("MD5",      "HMAC_MD5"      )   SIGAUTH(0)
      OAKLEY_MD5,           PRF_HMAC_MD5,       &MD5Suite, NULL, { {FALSE} }  },

#elif defined(__ENABLE_IKE_SIG_AUTH_RFC7427__)
    { ALGONAMES("SHA1",     NULL            )   SIGAUTH(HASH_SHA1)
      OAKLEY_HASH_NA,/*!!!*/PRF_NA,/*!!!*/      &SHASuite, NULL, {{TRUE,TRUE},{TRUE,TRUE}}},
#endif
};

#define NUM_IKE_HASH_SUITES     (sizeof(mHashSuites)/sizeof(IKE_hashSuiteInfo))

#ifndef __DISABLE_AES_CIPHERS__
#ifdef __ENABLE_DIGICERT_GCM__
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__

#if defined(__ENABLE_DIGICERT_GCM_64K__)
   #define CreateGcmCtx CRYPTO_INTERFACE_GCM_createCtx_64k
   #define DeleteGcmCtx CRYPTO_INTERFACE_GCM_deleteCtx_64k
   #define CipherGcm    CRYPTO_INTERFACE_GCM_cipher_64k
   #define CloneGcm     CRYPTO_INTERFACE_GCM_clone_64k
#elif defined(__ENABLE_DIGICERT_GCM_4K__)
   #define CreateGcmCtx CRYPTO_INTERFACE_GCM_createCtx_4k
   #define DeleteGcmCtx CRYPTO_INTERFACE_GCM_deleteCtx_4k
   #define CipherGcm    CRYPTO_INTERFACE_GCM_cipher_4k
   #define CloneGcm     CRYPTO_INTERFACE_GCM_clone_4k
#else /*#elif defined(__ENABLE_DIGICERT_GCM_256B__) */
   #define CreateGcmCtx CRYPTO_INTERFACE_GCM_createCtx_256b
   #define DeleteGcmCtx CRYPTO_INTERFACE_GCM_deleteCtx_256b
   #define CipherGcm    CRYPTO_INTERFACE_GCM_cipher_256b
   #define CloneGcm     CRYPTO_INTERFACE_GCM_clone_256b
#endif

#else

#if defined(__ENABLE_DIGICERT_GCM_64K__)
    #define CreateGcmCtx GCM_createCtx_64k
    #define DeleteGcmCtx GCM_deleteCtx_64k
    #define CipherGcm    GCM_cipher_64k
    #define CloneGcm    GCM_clone_64k
#elif defined(__ENABLE_DIGICERT_GCM_4K__)
    #define CreateGcmCtx GCM_createCtx_4k
    #define DeleteGcmCtx GCM_deleteCtx_4k
    #define CipherGcm    GCM_cipher_4k
    #define CloneGcm    GCM_clone_4k
#else /*#elif defined(__ENABLE_DIGICERT_GCM_256B__) */
    #define CreateGcmCtx GCM_createCtx_256b
    #define DeleteGcmCtx GCM_deleteCtx_256b
    #define CipherGcm    GCM_cipher_256b
    #define CloneGcm    GCM_clone_256b
#endif
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */

/*  { salt, iv, icv,    createFunc,     deleteFunc,     cipherFunc } */
static AeadAlgo AesGcm16Suite =
    { 4,    8,  16,     CreateGcmCtx,   DeleteGcmCtx,   CipherGcm, CloneGcm };

static AeadAlgo AesGcm12Suite =
    { 4,    8,  12,     CreateGcmCtx,   DeleteGcmCtx,   CipherGcm, CloneGcm };

static AeadAlgo AesGcm8Suite =
    { 4,    8,  8,      CreateGcmCtx,   DeleteGcmCtx,   CipherGcm, CloneGcm };
#endif /* __ENABLE_DIGICERT_GCM__ */

#ifndef __DISABLE_AES_CCM__
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
/*  { salt, iv, icv,    createFunc,     deleteFunc,     cipherFunc } */
static AeadAlgo AesCcm16Suite =
    { 3,    8,  16,      CRYPTO_INTERFACE_AES_CCM_createCtx,   CRYPTO_INTERFACE_AES_CCM_deleteCtx,   CRYPTO_INTERFACE_AES_CCM_cipher, CRYPTO_INTERFACE_CloneAESCtx };
static AeadAlgo AesCcm12Suite =
    { 3,    8,  12,      CRYPTO_INTERFACE_AES_CCM_createCtx,   CRYPTO_INTERFACE_AES_CCM_deleteCtx,   CRYPTO_INTERFACE_AES_CCM_cipher, CRYPTO_INTERFACE_CloneAESCtx };
static AeadAlgo AesCcm8Suite =
    { 3,    8,  8,      CRYPTO_INTERFACE_AES_CCM_createCtx,   CRYPTO_INTERFACE_AES_CCM_deleteCtx,   CRYPTO_INTERFACE_AES_CCM_cipher, CRYPTO_INTERFACE_CloneAESCtx };
#else
static AeadAlgo AesCcm16Suite =
    { 3,    8,  16,      AESCCM_createCtx,   AESCCM_deleteCtx,   AESCCM_cipher, AESCCM_clone  };
static AeadAlgo AesCcm12Suite =
    { 3,    8,  12,      AESCCM_createCtx,   AESCCM_deleteCtx,   AESCCM_cipher, AESCCM_clone };
static AeadAlgo AesCcm8Suite =
    { 3,    8,  8,      AESCCM_createCtx,   AESCCM_deleteCtx,   AESCCM_cipher, AESCCM_clone };
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */
#endif /* __DISABLE_AES_CCM__ */
#endif /* __DISABLE_AES_CIPHERS__ */

#if defined(__ENABLE_DIGICERT_CHACHA20__) && defined(__ENABLE_DIGICERT_POLY1305__)
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
static AeadAlgo Chacha20Poly1305Suite =
    { 4,    8,  16,      CRYPTO_INTERFACE_ChaCha20Poly1305_createCtx,   CRYPTO_INTERFACE_ChaCha20Poly1305_deleteCtx,   CRYPTO_INTERFACE_ChaCha20Poly1305_cipher, CRYPTO_INTERFACE_ChaCha20Poly1305_cloneCtx };
#else
static AeadAlgo Chacha20Poly1305Suite =
    { 4,    8,  16,      ChaCha20Poly1305_createCtx,   ChaCha20Poly1305_deleteCtx,   ChaCha20Poly1305_cipher, ChaCha20Poly1305_cloneCtx };
#endif
#endif

/*------------------------------------------------------------------*/

#define KEYLEN(_kl) (_kl), (_kl), TRUE
#define KEYLENS(_kl, _klend) (_kl), (_klend), FALSE
#define VARKEYLEN(_kl) (_kl), (_kl), FALSE


static IKE_cipherSuiteInfo mCipherSuites[] =
{/* { wEncrAlgo [v1],       wTfmId [v2],
      wIvLen,               wKeyLen/End/Fixed,           pBEAlgo,        bDisabled, pBAeadAlgo },
  */
#if defined(__ENABLE_DIGICERT_CHACHA20__) && defined(__ENABLE_DIGICERT_POLY1305__)
    {               0, ENCR_CHACHA20_POLY1305,
      AES_BLOCK_SIZE/2,       KEYLEN(32),                     NULL, {{TRUE, TRUE}}, &Chacha20Poly1305Suite },
#endif
#if (!defined(__DISABLE_AES_CCM__) && !defined(__DISABLE_AES_CIPHERS__))
#ifndef __DISABLE_AES256_CIPHER__
    {               0, ENCR_AES_CCM_16,
      AES_BLOCK_SIZE/2,       VARKEYLEN(32),                  NULL, {{TRUE, TRUE}}, &AesCcm16Suite },
    {               0, ENCR_AES_CCM_12,
      AES_BLOCK_SIZE/2,       VARKEYLEN(32),                  NULL, {{TRUE, TRUE}}, &AesCcm12Suite },
    {               0,  ENCR_AES_CCM_8,
      AES_BLOCK_SIZE/2,       VARKEYLEN(32),                  NULL, {{TRUE, TRUE}},  &AesCcm8Suite },
#endif
#ifndef __DISABLE_AES192_CIPHER__
    {               0, ENCR_AES_CCM_16,
      AES_BLOCK_SIZE/2,       VARKEYLEN(24),                  NULL, {{TRUE, TRUE}}, &AesCcm16Suite },
    {               0, ENCR_AES_CCM_12,
      AES_BLOCK_SIZE/2,       VARKEYLEN(24),                  NULL, {{TRUE, TRUE}}, &AesCcm12Suite },
    {               0,  ENCR_AES_CCM_8,
      AES_BLOCK_SIZE/2,       VARKEYLEN(24),                  NULL, {{TRUE, TRUE}},  &AesCcm8Suite },
#endif
#ifndef __DISABLE_AES128_CIPHER__
    {               0, ENCR_AES_CCM_16,
      AES_BLOCK_SIZE/2,       VARKEYLEN(16),                  NULL, {{TRUE, TRUE}}, &AesCcm16Suite },
    {               0, ENCR_AES_CCM_12,
      AES_BLOCK_SIZE/2,       VARKEYLEN(16),                  NULL, {{TRUE, TRUE}}, &AesCcm12Suite },
    {               0,  ENCR_AES_CCM_8,
      AES_BLOCK_SIZE/2,       VARKEYLEN(16),                  NULL, {{TRUE, TRUE}},  &AesCcm8Suite },
#endif
#endif /* (defined(__DISABLE_AES_CCM__) && !defined(__DISABLE_AES256_CIPHER__)) */

#if (defined(__ENABLE_DIGICERT_GCM__) && !defined(__DISABLE_AES_CIPHERS__))
#ifndef __DISABLE_AES256_CIPHER__
    {               0, ENCR_AES_GCM_16,
      AES_BLOCK_SIZE/2,       VARKEYLEN(32),                  NULL, {{TRUE, TRUE}}, &AesGcm16Suite },
    {               0, ENCR_AES_GCM_12,
      AES_BLOCK_SIZE/2,       VARKEYLEN(32),                  NULL, {{TRUE, TRUE}}, &AesGcm12Suite },
    {               0,  ENCR_AES_GCM_8,
      AES_BLOCK_SIZE/2,       VARKEYLEN(32),                  NULL, {{TRUE, TRUE}},  &AesGcm8Suite },
#endif
#ifndef __DISABLE_AES192_CIPHER__
    {               0, ENCR_AES_GCM_16,
      AES_BLOCK_SIZE/2,       VARKEYLEN(24),                  NULL, {{TRUE, TRUE}},  &AesGcm16Suite },
    {               0, ENCR_AES_GCM_12,
      AES_BLOCK_SIZE/2,       VARKEYLEN(24),                  NULL, {{TRUE, TRUE}},  &AesGcm12Suite },
    {               0,  ENCR_AES_GCM_8,
      AES_BLOCK_SIZE/2,       VARKEYLEN(24),                  NULL, {{TRUE, TRUE}},   &AesGcm8Suite },
#endif
#ifndef __DISABLE_AES128_CIPHER__
    {               0, ENCR_AES_GCM_16,
      AES_BLOCK_SIZE/2,       VARKEYLEN(16),                  NULL, {{TRUE, TRUE}},  &AesGcm16Suite },
    {               0, ENCR_AES_GCM_12,
      AES_BLOCK_SIZE/2,       VARKEYLEN(16),                  NULL, {{TRUE, TRUE}},  &AesGcm12Suite },
    {               0,  ENCR_AES_GCM_8,
      AES_BLOCK_SIZE/2,       VARKEYLEN(16),                  NULL, {{TRUE, TRUE}},   &AesGcm8Suite },
#endif
#endif /* (defined(__ENABLE_DIGICERT_GCM__) && !defined(__DISABLE_AES256_CIPHER__)) */

#ifndef __DISABLE_3DES_CIPHERS__
    { OAKLEY_3DES_CBC,      ENCR_3DES,
      THREE_DES_BLOCK_SIZE, KEYLEN(THREE_DES_KEY_LENGTH),/*24*/ &CRYPTO_TripleDESSuite, { {FALSE} }, NULL },

#ifdef __ENABLE_2KEY_3DES_CIPHER__
    { OAKLEY_3DES_CBC,      ENCR_3DES,
      THREE_DES_BLOCK_SIZE, VARKEYLEN(2*DES_KEY_LENGTH),/*16*/  &CRYPTO_TwoKeyTripleDESSuite,   { {TRUE} }, NULL },
#endif
#endif
#ifndef __DISABLE_AES_CIPHERS__
#ifndef __DISABLE_AES128_CIPHER__
    { OAKLEY_AES_CBC,       ENCR_AES_CBC,
      AES_BLOCK_SIZE,       VARKEYLEN(16),                      &CRYPTO_AESSuite, { {FALSE} }, NULL },
#endif
#ifndef __DISABLE_AES192_CIPHER__
    { OAKLEY_AES_CBC,       ENCR_AES_CBC,
      AES_BLOCK_SIZE,       VARKEYLEN(24),                      &CRYPTO_AESSuite, { {FALSE} }, NULL },
#endif
#ifndef __DISABLE_AES256_CIPHER__
    { OAKLEY_AES_CBC,       ENCR_AES_CBC,
      AES_BLOCK_SIZE,       VARKEYLEN(32),                      &CRYPTO_AESSuite, { {FALSE} }, NULL },
#endif
#endif
#ifdef __ENABLE_BLOWFISH_CIPHERS__
    { OAKLEY_BLOWFISH_CBC,  ENCR_BLOWFISH,
      BLOWFISH_BLOCK_SIZE,  KEYLENS(4, MAXKEYBYTES),/*4...56*/  &CRYPTO_BlowfishSuite,          { {TRUE} }, NULL },
#endif
#ifdef __ENABLE_DES_CIPHER__
    { OAKLEY_DES_CBC,       ENCR_DES,
      DES_BLOCK_SIZE,       KEYLEN(DES_KEY_LENGTH),/*8*/        &CRYPTO_DESSuite,               { {TRUE} }, NULL },
#endif
};

#define NUM_IKE_CIPHER_SUITES   (sizeof(mCipherSuites)/sizeof(IKE_cipherSuiteInfo))


/*------------------------------------------------------------------*/

#ifndef __DISABLE_AES_CIPHERS__
#ifndef __DISABLE_AES_XCBC_CIPHER__

static MSTATUS
AES_XCBC_MAC_96(MOC_HASH(hwAccelDescr hwAccelCtx)
                const ubyte* key, sbyte4 keyLen,
                const ubyte* text, sbyte4 textLen,
                ubyte result[AES_XCBC_MAC_96_RESULT_SIZE])
{
    MSTATUS status;
    AES_XCBC_MAC_96_Ctx *p_context = NULL;

    if (AES_BLOCK_SIZE != keyLen)
    {
        status = ERR_AES_BAD_KEY_LENGTH;
        goto exit;
    }

    if (OK > (status = AES_XCBC_alloc(MOC_HASH(hwAccelCtx) (BulkCtx *) &p_context)))
        goto exit;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (OK > (status = CRYPTO_INTERFACE_AES_XCBC_MAC_96_init(MOC_SYM(hwAccelCtx) key, p_context)))
        goto exit;
    if (OK > (status = CRYPTO_INTERFACE_AES_XCBC_MAC_96_update(MOC_SYM(hwAccelCtx) text, textLen, p_context)))
        goto exit;
    status = CRYPTO_INTERFACE_AES_XCBC_MAC_96_final(MOC_SYM(hwAccelCtx) result, p_context);
#else
    if (OK > (status = AES_XCBC_MAC_96_init(MOC_SYM(hwAccelCtx) key, p_context)))
        goto exit;
    if (OK > (status = AES_XCBC_MAC_96_update(MOC_SYM(hwAccelCtx) text, textLen, p_context)))
        goto exit;
    status = AES_XCBC_MAC_96_final(MOC_SYM(hwAccelCtx) result, p_context);
#endif
exit:
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (NULL != p_context)
        CRYPTO_INTERFACE_AES_XCBC_clear(MOC_HASH(hwAccelCtx)p_context);
#endif
    if (p_context) AES_XCBC_free(MOC_HASH(hwAccelCtx) (BulkCtx *) &p_context);
    return status;
} /* AES_XCBC_MAC_96 */

#endif
#endif


/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_SHA256__
static MSTATUS
HMAC_SHA256_quick(MOC_HASH(hwAccelDescr hwAccelCtx)
                  const ubyte* pKey, sbyte4 keyLen,
                  const ubyte* pText, sbyte4 textLen,
                  ubyte result[SHA256_RESULT_SIZE])
{
    return HmacQuick(MOC_HASH(hwAccelCtx) pKey, keyLen, pText, textLen, result, &SHA256Suite);
}
#endif

#ifndef __DISABLE_DIGICERT_SHA384__
static MSTATUS
HMAC_SHA384_quick(MOC_HASH(hwAccelDescr hwAccelCtx)
                  const ubyte* pKey, sbyte4 keyLen,
                  const ubyte* pText, sbyte4 textLen,
                  ubyte result[SHA384_RESULT_SIZE])
{
    return HmacQuick(MOC_HASH(hwAccelCtx) pKey, keyLen, pText, textLen, result, &SHA384Suite);
}
#endif

#ifndef __DISABLE_DIGICERT_SHA512__
static MSTATUS
HMAC_SHA512_quick(MOC_HASH(hwAccelDescr hwAccelCtx)
                  const ubyte* pKey, sbyte4 keyLen,
                  const ubyte* pText, sbyte4 textLen,
                  ubyte result[SHA512_RESULT_SIZE])
{
    return HmacQuick(MOC_HASH(hwAccelCtx) pKey, keyLen, pText, textLen, result, &SHA512Suite);
}
#endif


/*------------------------------------------------------------------*/

#if defined(__ENABLE_ALL_DEBUGGING__) && defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__)
#define ALGONAME(_n) (sbyte *)_n,
#else
#define ALGONAME(_n)
#endif

static IKE_macSuiteInfo mMacSuites[] =
{/* { wTfmId,                       wIcvLen,
      wKeyLen,                      hmacFunc        },
  */
#ifndef __DISABLE_AES_CIPHERS__
#ifndef __DISABLE_AES_XCBC_CIPHER__
    { ALGONAME("AES_XCBC_96")
      AUTH_AES_XCBC_96,             AES_XCBC_MAC_96_RESULT_SIZE/*12*/,
      AES_BLOCK_SIZE/*16*/,         AES_XCBC_MAC_96, { FALSE } },
#endif
#endif

#ifndef __DISABLE_DIGICERT_SHA512__
    { ALGONAME("HMAC_SHA2_512_256")
      AUTH_HMAC_SHA2_512_256,       SHA512_RESULT_SIZE/2,
      SHA512_RESULT_SIZE/*64*/,     HMAC_SHA512_quick, { FALSE } },
#endif

#ifndef __DISABLE_DIGICERT_SHA384__
    { ALGONAME("HMAC_SHA2_384_192")
      AUTH_HMAC_SHA2_384_192,       SHA384_RESULT_SIZE/2,
      SHA384_RESULT_SIZE/*48*/,     HMAC_SHA384_quick, { FALSE } },
#endif

#ifndef __DISABLE_DIGICERT_SHA256__
    { ALGONAME("HMAC_SHA2_256_128")
      AUTH_HMAC_SHA2_256_128,       SHA256_RESULT_SIZE/2,
      SHA256_RESULT_SIZE/*32*/,     HMAC_SHA256_quick, { FALSE } },
#endif

#ifdef __ENABLE_DIGICERT_IKE_UNSECURE_HASH__
    { ALGONAME("HMAC_SHA1_96")
      AUTH_HMAC_SHA1_96,            12,
      SHA_HASH_RESULT_SIZE/*20*/,   HMAC_SHA1_quick, { FALSE } },

    { ALGONAME("HMAC_MD5_96")
      AUTH_HMAC_MD5_96,             12,
      MD5_DIGESTSIZE/*16*/,         HMAC_MD5_quick, { FALSE } },
#endif

};

#define NUM_IKE_MAC_SUITES     (sizeof(mMacSuites)/sizeof(IKE_macSuiteInfo))

#ifdef __ENABLE_DIGICERT_PQC__
#ifndef __DISABLE_DIGICERT_ECC_P256__
static ubyte4 hybridP256Index = 0;
#define CURVE_P256 1
#else
#define CURVE_P256 0
#endif
#ifndef __DISABLE_DIGICERT_ECC_P384__
static ubyte4 hybridP384Index = 0;
#define CURVE_P384 1
#else
#define CURVE_P384 0
#endif
#ifndef __DISABLE_DIGICERT_ECC_P521__
static ubyte4 hybridP521Index = 0;
#define CURVE_P521 1
#else
#define CURVE_P521 0
#endif
#else
#define CURVE_P256 0
#define CURVE_P384 0
#define CURVE_P521 0
#endif /* __ENABLE_DIGICERT_PQC__ */

static ubyte4 classicAlgIndex = 0;

static ubyte4 proposalCount = CURVE_P256 + CURVE_P384 + CURVE_P521 + 1;

static ubyte4 keyExchangeIndexes[4] = { 0, 0, 0, 0 };
static ubyte4 keyExchangeType[4]    = { 0, 0, 0, 0 };

static ubyte4 getProposalOffset(ubyte4 proposalNum)
{
    return keyExchangeIndexes[proposalNum];
}

extern ubyte4 getKeyExchangeCount()
{
    return proposalCount;
}

/*------------------------------------------------------------------*/

static IKE_dhGroupInfo mDhGroups[] =
{/*   wTfmId,                   dwGroupNum,     CurveId */    /* {  [v1],   [v2]  } bDisabled [I] */
#if (defined(__ENABLE_DIGICERT_ECC__) && defined(__ENABLE_DIGICERT_PQC__))
#ifndef __DISABLE_DIGICERT_ECC_P384__
    { OAKLEY_GROUP_P384_MLKEM768,           DH_GROUP_20,    cid_EC_P384,  { {0} }, cid_PQC_MLKEM_768  },
#endif /* __DISABLE_DIGICERT_ECC_P384__ */
#ifndef __DISABLE_DIGICERT_ECC_P256__
    { OAKLEY_GROUP_P256_MLKEM512,           DH_GROUP_19,   cid_EC_P256, { {0} }, cid_PQC_MLKEM_512 },
#endif /* __DISABLE_DIGICERT_ECC_P256__ */
#ifndef __DISABLE_DIGICERT_ECC_P521__
    { OAKLEY_GROUP_P521_MLKEM1024,          DH_GROUP_21,    cid_EC_P521,  { {0} }, cid_PQC_MLKEM_1024  },
#endif /* __DISABLE_DIGICERT_ECC_P521__ */
#endif /* defined(__ENABLE_DIGICERT_ECC__) || defined(__ENABLE_DIGICERT_PQC__) */
#ifndef __ENABLE_DIGICERT_FIPS_MODULE__
#ifndef __DISABLE_DIGICERT_IKE_DH_GROUP_2__
    { OAKLEY_GROUP_MODP1024,    DH_GROUP_2, 0, { {0} }, 0 },
#endif
#ifndef __DISABLE_DIGICERT_IKE_DH_GROUP_1__
    { OAKLEY_GROUP_MODP768,     DH_GROUP_1, 0, { {0} }, 0 },
#endif
#ifdef __ENABLE_DIGICERT_IKE_DH_GROUP_5__
    { OAKLEY_GROUP_MODP1536,    DH_GROUP_5, 0, { {0} }, 0 },
#else
    { OAKLEY_GROUP_MODP1536,    DH_GROUP_5,        0,         { {TRUE}         }, 0 },
#endif
#endif /* __ENABLE_DIGICERT_FIPS_MODULE__ */
    { OAKLEY_GROUP_MODP2048,    DH_GROUP_14, 0, { {0} }, 0 },
    { OAKLEY_GROUP_MODP3072,    DH_GROUP_15, 0, { {0} }, 0 },
    { OAKLEY_GROUP_MODP4096,    DH_GROUP_16, 0, { {0} }, 0 },
    { OAKLEY_GROUP_MODP6144,    DH_GROUP_17, 0, { {0} }, 0 },
    { OAKLEY_GROUP_MODP8192,    DH_GROUP_18, 0, { {0} }, 0 },
#ifndef __ENABLE_DIGICERT_FIPS_MODULE__
    { OAKLEY_GROUP_MODP2048_256,DH_GROUP_24,       0,        { {TRUE}, {TRUE} }, 0 },
#endif
#ifdef __ENABLE_DIGICERT_ECC__
#ifndef __DISABLE_DIGICERT_ECC_P256__
    { OAKLEY_GROUP_ECP256,      DH_GROUP_19,    cid_EC_P256, { {0} }, 0 },
#endif /* __DISABLE_DIGICERT_ECC_P256__ */
#ifndef __DISABLE_DIGICERT_ECC_P384__
    { OAKLEY_GROUP_ECP384,      DH_GROUP_20,    cid_EC_P384, { {0} }, 0 },
#endif /* __DISABLE_DIGICERT_ECC_P384__ */
#ifndef __DISABLE_DIGICERT_ECC_P521__
    { OAKLEY_GROUP_ECP521,      DH_GROUP_21,    cid_EC_P521, { {0} }, 0 },
#endif /* __DISABLE_DIGICERT_ECC_P521__ */
#ifndef __ENABLE_DIGICERT_FIPS_MODULE__
#ifdef __ENABLE_DIGICERT_ECC_P192__
    { OAKLEY_GROUP_ECP192,      DH_GROUP_25,    cid_EC_P192, { {TRUE}, {TRUE} }, 0 },
#endif
#ifndef __DISABLE_DIGICERT_ECC_P224__
    { OAKLEY_GROUP_ECP224,      DH_GROUP_26,    cid_EC_P224, { {TRUE}, {TRUE} }, 0 },
#endif
#ifdef __ENABLE_DIGICERT_ECC_EDDH_25519__
    { OAKLEY_GROUP_ED25519,      DH_GROUP_31,   cid_EC_X25519, { {TRUE, TRUE} }, 0 },
#endif
#ifdef __ENABLE_DIGICERT_ECC_EDDH_448__
    { OAKLEY_GROUP_ED448,      DH_GROUP_32,     cid_EC_X448,  { {TRUE, TRUE} }, 0 },
#endif
#endif /* __ENABLE_DIGICERT_FIPS_MODULE__ */

#endif /* __ENABLE_DIGICERT_ECC__ */
    { 0, 0, 0, { {0} }, 0 }
};

#define NUM_IKE_DH_GROUPS     (sizeof(mDhGroups)/sizeof(IKE_dhGroupInfo))

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_PQC__
static void generateKeyExchangeValues(ikePeerConfig* config)
{
    ubyte4 index = 0;
#ifndef __DISABLE_DIGICERT_ECC_P384__
    /* starting index of each */
    for (int i = 0;i <NUM_IKE_DH_GROUPS ; i++)
    {
        if ((0 < config->dhGroups[i].qsAlgoId) && (cid_EC_P384 == config->dhGroups[i].curveId))
            break;
        hybridP384Index++;
    }
    keyExchangeType[index] = cid_EC_P384;
    keyExchangeIndexes[index++] = hybridP384Index;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P256__
    for (int i = 0;i <NUM_IKE_DH_GROUPS ; i++)
    {
        if ((0 < config->dhGroups[i].qsAlgoId) && (cid_EC_P256 == config->dhGroups[i].curveId))
            break;
        hybridP256Index++;
    }
    keyExchangeType[index] = cid_EC_P256;
    keyExchangeIndexes[index++] = hybridP256Index;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P521__
    /* starting index of each */
    for (int i = 0;i <NUM_IKE_DH_GROUPS ; i++)
    {
        if ((0 < config->dhGroups[i].qsAlgoId) && (cid_EC_P521 == config->dhGroups[i].curveId))
            break;
        hybridP521Index++;
    }
    keyExchangeType[index] = cid_EC_P521;
    keyExchangeIndexes[index++] = hybridP521Index;
#endif
    for (int i = 0;i <NUM_IKE_DH_GROUPS ; i++)
    {
        if (0 == config->dhGroups[i].qsAlgoId)
            break;
        classicAlgIndex++;
    }
    keyExchangeType[index] = 0;
    keyExchangeIndexes[index] = classicAlgIndex;

}
#endif /* __ENABLE_DIGICERT_PQC__ */

/*------------------------------------------------------------------*/

static IKE_authMtdInfo mAuthMtds[] =
{/*   wAuthMtd [v1],            oAuthMtd [v2] */
#ifdef __ENABLE_DIGICERT_ECC__
#if !(defined(__DISABLE_DIGICERT_ECC_P521__) || defined(__DISABLE_DIGICERT_SHA512__))
    { OAKLEY_ECDSA_521,         AUTH_MTD_ECDSA_521, cid_EC_P521,   &SHA512Suite,
#ifdef __ENABLE_DIGICERT_PQC__
      0,
#endif
      {0}, {0}, {0}
    },
#ifdef __ENABLE_DIGICERT_PQC__
    { OAKLEY_P521_MLDSA_87,                 AUTH_MTD_P521_MLDSA_87,                  cid_EC_P521,  &SHA512Suite, cid_PQC_MLDSA_87, {0}, {0}, {0} },
    { OAKLEY_P521_FNDSA1024,                AUTH_MTD_P521_FNDSA1024,                 cid_EC_P521,  &SHA512Suite, cid_PQC_FNDSA_1024, {0}, {0}, {0} },
#endif
#endif
#if !(defined(__DISABLE_DIGICERT_ECC_P384__) || defined(__DISABLE_DIGICERT_SHA384__))
    { OAKLEY_ECDSA_384,         AUTH_MTD_ECDSA_384, cid_EC_P384,   &SHA384Suite,
#ifdef __ENABLE_DIGICERT_PQC__
      0,
#endif
      {0}, {0}, {0}
    },
#ifdef __ENABLE_DIGICERT_PQC__
    { OAKLEY_P384_MLDSA_65,                 AUTH_MTD_P384_MLDSA_65,                  cid_EC_P384,  &SHA384Suite, cid_PQC_MLDSA_65, {0}, {0}, {0} },
#endif
#endif
#if !(defined(__DISABLE_DIGICERT_ECC_P256__) || defined(__DISABLE_DIGICERT_SHA256__))
    { OAKLEY_ECDSA_256,         AUTH_MTD_ECDSA_256, cid_EC_P256,   &SHA256Suite,
#ifdef __ENABLE_DIGICERT_PQC__
      0,
#endif
      {0}, {0}, {0}
    },
#ifdef __ENABLE_DIGICERT_PQC__
    { OAKLEY_P256_MLDSA_44,                 AUTH_MTD_P256_MLDSA_44,                 cid_EC_P256,  &SHA256Suite, cid_PQC_MLDSA_44, {0}, {0}, {0} },
    { OAKLEY_P256_FNDSA512,                 AUTH_MTD_P256_FNDSA512,                 cid_EC_P256,  &SHA256Suite, cid_PQC_FNDSA_512, {0}, {0}, {0} },
#endif
#endif
#if defined(__ENABLE_IKE_SIG_AUTH_RFC7427__) && defined(__ENABLE_DIGICERT_ECC_EDDSA_25519__)
    { AUTH_MTD_SIG,         AUTH_MTD_SIG, cid_EC_Ed25519, NULL,
#ifdef __ENABLE_DIGICERT_PQC__
      0,
#endif
      {0}, {0}, {0}
    },
#endif
#if defined(__ENABLE_IKE_SIG_AUTH_RFC7427__) && defined(__ENABLE_DIGICERT_ECC_EDDSA_448__)
    { AUTH_MTD_SIG,         AUTH_MTD_SIG, cid_EC_Ed448, NULL,
#ifdef __ENABLE_DIGICERT_PQC__
      0,
#endif
      {0}, {0}, {0}
    },
#endif
#endif /* __ENABLE_DIGICERT_ECC__ */

    { OAKLEY_RSA_SIG,           AUTH_MTD_RSA_SIG,
#ifdef __ENABLE_DIGICERT_ECC__
      0, NULL,
#endif
#ifdef __ENABLE_DIGICERT_PQC__
      0,
#endif
      {0}, {0}, {0}
    },

#ifdef __ENABLE_DIGICERT_ECC__
    { OAKLEY_ECDSA_SIG,         0xff,/*!!!*/ 0, NULL,
#ifdef __ENABLE_DIGICERT_PQC__
      0,
#endif
      {0}, {0}, {0}
    },
#endif

    { OAKLEY_PRESHARED_KEY,     AUTH_MTD_SHARED_KEY,
#ifdef __ENABLE_DIGICERT_ECC__
      0, NULL,
#endif
#ifdef __ENABLE_DIGICERT_PQC__
      0,
#endif
      {0}, {0}, {0}
    },
};

#define NUM_IKE_AUTH_MTDS     (sizeof(mAuthMtds)/sizeof(IKE_authMtdInfo))

/*------------------------------------------------------------------*/

extern IKE_hashSuiteInfo*
IKE_getHashSuite(sbyte4 i)
{
    return IKE_getHashSuiteEx(IKE_globalPeerConfig(), i);
}

extern IKE_hashSuiteInfo*
IKE_getHashSuiteEx(ikePeerConfig* config, sbyte4 i)
{
    IKE_hashSuiteInfo *pHashSuite = NULL;

    if ((0 <= i) && ((sbyte4) NUM_IKE_HASH_SUITES > i))
        pHashSuite = &(config->hashSuites[i]);

    return pHashSuite;
} /* IKE_getHashSuite */


/*------------------------------------------------------------------*/

extern IKE_cipherSuiteInfo*
IKE_getCipherSuite(sbyte4 i)
{
    return IKE_getCipherSuiteEx(IKE_globalPeerConfig(), i);
}

extern IKE_cipherSuiteInfo*
IKE_getCipherSuiteEx(ikePeerConfig* config, sbyte4 i)
{
    IKE_cipherSuiteInfo *pCipherSuite = NULL;

    if ((0 <= i) && ((sbyte4) NUM_IKE_CIPHER_SUITES > i))
        pCipherSuite = &(config->cipherSuites[i]);

    return pCipherSuite;
} /* IKE_getCipherSuite */


/*------------------------------------------------------------------*/

extern IKE_hashSuiteInfo*
IKE_hashSuite(ubyte2 wHashAlgo, ubyte2 wTfmId)
{
    return IKE_hashSuiteEx(IKE_globalPeerConfig(), wHashAlgo, wTfmId);
}

extern IKE_hashSuiteInfo*
IKE_hashSuiteEx(ikePeerConfig* config, ubyte2 wHashAlgo, ubyte2 wTfmId)
{
    ubyte4 i;
    IKE_hashSuiteInfo *pHashSuite = NULL;

    for (i=0; i < NUM_IKE_HASH_SUITES; i++, pHashSuite = NULL)
    {
        pHashSuite = &(config->hashSuites[i]);

        if (((OAKLEY_HASH_NA != wHashAlgo) && /*!!!*/
             (wHashAlgo == pHashSuite->wHashAlgo)) ||
            ((PRF_NA != wTfmId) && /*!!!*/
             (wTfmId == pHashSuite->wTfmId)))
        {
            break;
        }
    }

    return pHashSuite;
} /* IKE_hashSuite */


/*------------------------------------------------------------------*/

extern IKE_cipherSuiteInfo*
IKE_cipherSuite(ubyte2 wEncrAlgo, ubyte2 wTfmId,
                ubyte2 wKeyLen, ubyte2 *pwKeyLen)
{
    return IKE_cipherSuiteEx(IKE_globalPeerConfig(), wEncrAlgo, wTfmId, wKeyLen, pwKeyLen);
}

extern IKE_cipherSuiteInfo*
IKE_cipherSuiteEx(ikePeerConfig* config, ubyte2 wEncrAlgo, ubyte2 wTfmId,
                ubyte2 wKeyLen, ubyte2 *pwKeyLen)
{
    IKE_cipherSuiteInfo *pCipherSuite = NULL;
    ubyte4 i;

    IKE_cipherSuiteInfo* pCipherSuiteBest = NULL;
    ubyte2 wKeyLenBest = 0;

    for (i=0; i < NUM_IKE_CIPHER_SUITES; i++, pCipherSuite = NULL)
    {
        pCipherSuite = &(config->cipherSuites[i]);

        if (((0 < pCipherSuite->wEncrAlgo) &&
            (wEncrAlgo == pCipherSuite->wEncrAlgo)) ||
            (wTfmId == pCipherSuite->wTfmId))
        {
            ubyte2 wKeyLenMin = pCipherSuite->wKeyLen;
            ubyte2 wKeyLenMax = pCipherSuite->wKeyLenEnd;

            if (!wKeyLen) /* default */
            {
                if (pwKeyLen) *pwKeyLen = wKeyLenMax;
                goto exit;
            }

            /* exact match */
            if ((wKeyLen >= wKeyLenMin) &&
                ((0 == wKeyLenMax) || (wKeyLen <= wKeyLenMax)))
            {
                if (pwKeyLen) *pwKeyLen = wKeyLen;
                goto exit;
            }

            /* best match */
            if (pwKeyLen)
            {
                if (pCipherSuiteBest)
                {
                    if (wKeyLen < wKeyLenMin)
                    {
                        if ((wKeyLen > wKeyLenBest) ||
                            ((wKeyLen < wKeyLenBest) && (wKeyLenMin < wKeyLenBest)))
                            goto match;
                    }
                    else/* if ((0 != wKeyLenMax) && (wKeyLen > wKeyLenMax))*/
                    {
                        if ((wKeyLen > wKeyLenBest) && (wKeyLenMax > wKeyLenBest))
                            goto match;
                    }
                    continue;
                }
match:
                wKeyLenBest = ((wKeyLen < wKeyLenMin) ? wKeyLenMin : wKeyLenMax);
                pCipherSuiteBest = pCipherSuite;
            }
        }
    } /* for */

    if (pwKeyLen && pCipherSuiteBest)
    {
        *pwKeyLen = wKeyLenBest;
        pCipherSuite = pCipherSuiteBest;
    }

exit:
    return pCipherSuite;
} /* IKE_cipherSuite */


/*------------------------------------------------------------------*/
/* [v2] */

extern IKE_macSuiteInfo*
IKE_macSuite(ubyte2 wTfmId)
{
    return IKE_macSuiteEx(IKE_globalPeerConfig(), wTfmId);
}

extern IKE_macSuiteInfo*
IKE_macSuiteEx(ikePeerConfig* config, ubyte2 wTfmId)
{
    ubyte4 i;
    IKE_macSuiteInfo *pMacSuite = NULL;

    for (i=0; i < NUM_IKE_MAC_SUITES; i++, pMacSuite = NULL)
    {
        pMacSuite = &(config->macSuites[i]);

        if (wTfmId == pMacSuite->wTfmId)
        {
            break;
        }
    }

    return pMacSuite;
} /* IKE_macSuite */


/*------------------------------------------------------------------*/
/* [v2] */

extern IKE_macSuiteInfo*
IKE_getMacSuite(sbyte4 i)
{
    return IKE_getMacSuiteEx(IKE_globalPeerConfig(), i);
}

extern IKE_macSuiteInfo*
IKE_getMacSuiteEx(ikePeerConfig* config, sbyte4 i)
{
    IKE_macSuiteInfo *pMacSuite = NULL;

    if ((0 <= i) && ((sbyte4) NUM_IKE_MAC_SUITES > i))
        pMacSuite = &(config->macSuites[i]);

    return pMacSuite;
} /* IKE_getMacSuite */


/*------------------------------------------------------------------*/

extern IKE_dhGroupInfo*
IKE_dhGroup(ubyte2 wTfmId)
{
    return IKE_dhGroupEx(IKE_globalPeerConfig(), wTfmId);
}

extern IKE_dhGroupInfo*
IKE_dhGroupEx(ikePeerConfig* config, ubyte2 wTfmId)
{
    IKE_dhGroupInfo *pDhGroup = NULL;
    ubyte4 i;

    for (i=0; i < NUM_IKE_DH_GROUPS; i++)
    {
        if (wTfmId == config->dhGroups[i].wTfmId)
        {
            pDhGroup = &(config->dhGroups[i]);
            goto exit;
        }
    }

exit:
    return pDhGroup;
} /* IKE_dhGroupEx */


/*------------------------------------------------------------------*/

extern IKE_dhGroupInfo*
IKE_getDhGroup(sbyte4 i)
{
    return IKE_getDhGroupEx(IKE_globalPeerConfig(), i);
}

extern IKE_dhGroupInfo*
IKE_getDhGroupEx(ikePeerConfig* config, sbyte4 i)
{
    IKE_dhGroupInfo *pDhGroup = NULL;

    if ((0 <= i) && ((sbyte4) NUM_IKE_DH_GROUPS > i))
        pDhGroup =&(config->dhGroups[i]);

    return pDhGroup;
} /* IKE_getDhGroupEx */

/*------------------------------------------------------------------*/

static IKE_dhGroupInfo*
IKE_getClassicGroupEx(ikePeerConfig* config, sbyte4 i)
{
    IKE_dhGroupInfo *pDhGroup = NULL;

    if ((0 <= i) && ((sbyte4) NUM_IKE_DH_GROUPS > i) && (0 == config->dhGroups[i].qsAlgoId))
    {
        pDhGroup =&(config->dhGroups[i]);
    }

    return pDhGroup;
} /* IKE_getClassicGroupEx */

/*------------------------------------------------------------------*/

static IKE_dhGroupInfo*
IKE_getHybridGroupEx(ikePeerConfig* config, sbyte4 i, ubyte4 curveId)
{
    IKE_dhGroupInfo *pDhGroup = NULL;

    if ((0 <= i) && ((sbyte4) NUM_IKE_DH_GROUPS > i) && (0 < config->dhGroups[i].qsAlgoId) && (config->dhGroups[i].curveId == curveId))
    {
        pDhGroup =&(config->dhGroups[i]);
    }

    return pDhGroup;
} /* IKE_getHybridGroupEx */

/*------------------------------------------------------------------*/

extern IKE_dhGroupInfo*
IKE_getKeyExchangeGroup(ikePeerConfig* config, sbyte4 i, ubyte4 proposalNum)
{
    IKE_dhGroupInfo *pDhGroup = NULL;

    if (1 < proposalCount)
    {
        /* last proposal should be classical algorithms */
        if (proposalNum == (proposalCount - 1))
        {
            return IKE_getClassicGroupEx(config, i + getProposalOffset(proposalNum));
        }
        else
        {
            return IKE_getHybridGroupEx(config, i + getProposalOffset(proposalNum), keyExchangeType[proposalNum]);
        }
    }
    else
    {
        /* only 1 proposal, no QS algorithms */
        return IKE_getClassicGroupEx(config, i);
    }
} /* IKE_getKeyExchangeGroup */

/*------------------------------------------------------------------*/

extern IKE_authMtdInfo *
IKE_authMtd(ubyte2 wAuthMtd, ubyte oAuthMtd)
{
    return IKE_authMtdEx(IKE_globalPeerConfig(), wAuthMtd, oAuthMtd);
}

extern IKE_authMtdInfo *
IKE_authMtdEx(ikePeerConfig* config, ubyte2 wAuthMtd, ubyte oAuthMtd)
{
    ubyte4 i;
    IKE_authMtdInfo *pAuthMtd = NULL;

    for (i=0; i < NUM_IKE_AUTH_MTDS; i++, pAuthMtd = NULL)
    {
        pAuthMtd = &(config->authMtds[i]);

        if ((wAuthMtd == pAuthMtd->wAuthMtd) ||
            ((0xff != oAuthMtd) && /*!!!*/
             (oAuthMtd == pAuthMtd->oAuthMtd)))
        {
            break;
        }
    }

    return pAuthMtd;
} /* IKE_authMtd */


/*------------------------------------------------------------------*/

extern IKE_authMtdInfo *
IKE_getAuthMtd(sbyte4 i)
{
    return IKE_getAuthMtdEx(IKE_globalPeerConfig(), i);
}

extern IKE_authMtdInfo *
IKE_getAuthMtdEx(ikePeerConfig* config, sbyte4 i)
{
    IKE_authMtdInfo *pAuthMtd = NULL;

    if ((0 <= i) && ((sbyte4) NUM_IKE_AUTH_MTDS > i))
        pAuthMtd =&(config->authMtds[i]);

    return pAuthMtd;
} /* IKE_getAuthMtd */


/*------------------------------------------------------------------*/

#define _I 0
#define _R 1

extern MSTATUS
IKE_initPropEx(ikePeerConfig* config, ubyte2 wType, ubyte2 wValue, ubyte2 wKeyLen,
             sbyte4 dir, intBoolean on)
{
    MSTATUS status = OK;

    if (NULL == config)
    {
        status = ERR_IKE_NO_PEER_CONFIG;
        goto exit;
    }

    if (dir && (1 != dir) && (2 != dir))
    {
        status = ERR_IKE;
        goto exit;
    }

    switch (wType)
    {
    case OAKLEY_ENCRYPTION_ALGORITHM :
    {
        ubyte4 i, count = 0, found = 0;
        for (i=0; i < NUM_IKE_CIPHER_SUITES; i++)
        {
            IKE_cipherSuiteInfo *pCipherSuite = &(config->cipherSuites[i]);
            if (wValue == pCipherSuite->wEncrAlgo)
            {
                ubyte2 wKeyLenMin = pCipherSuite->wKeyLen;
                ubyte2 wKeyLenMax = pCipherSuite->wKeyLenEnd;

                found++;
                if ((0 == wKeyLen) ||
                    ((wKeyLen >= wKeyLenMin) &&
                     ((0 == wKeyLenMax) || (wKeyLen <= wKeyLenMax))))
                {
                    if (!dir || (2==dir)) pCipherSuite->bDisabled[0][_I] = !on;
                    if (!dir || (1==dir)) pCipherSuite->bDisabled[0][_R] = !on;
                    count++;
                }
            }
        }
        if (!count) status = (found ? ERR_IKE_MISMATCH_KEYLEN
                                    : ERR_IKE_MISMATCH_ENCR_ALGO);
        break;
    }
    case OAKLEY_HASH_ALGORITHM :
    {
        IKE_hashSuiteInfo *pHashSuite = IKE_hashSuiteEx(config, wValue, 0);
        if (NULL == pHashSuite)
        {
            status = ERR_IKE_MISMATCH_HASH_ALGO;
            goto exit;
        }
        if (!dir || (2==dir)) pHashSuite->bDisabled[0][_I] = !on;
        if (!dir || (1==dir)) pHashSuite->bDisabled[0][_R] = !on;
        break;
    }
    case OAKLEY_GROUP_DESCRIPTION :
    {
        IKE_dhGroupInfo *pDhGroup = IKE_dhGroupEx(config, wValue);
        if (NULL == pDhGroup)
        {
            status = ERR_IKE_MISMATCH_DH_GROUP;
            goto exit;
        }
        if (!dir || (2==dir)) pDhGroup->bDisabled[0][_I] = !on;
        if (!dir || (1==dir)) pDhGroup->bDisabled[0][_R] = !on;
        break;
    }
    case OAKLEY_AUTHENTICATION_METHOD :
    {
        IKE_authMtdInfo *pAuthMtd = IKE_authMtdEx(config, wValue, 0);
        if (NULL == pAuthMtd)
        {
            status = ERR_IKE_MISMATCH_AUTH_METHOD;
            goto exit;
        }

        if (on) /* enable only if certificate is applicable */
        {
            switch (wValue)
            {
            case OAKLEY_PRESHARED_KEY :
                if (NULL == config->ikePSKey)
                {
                    status = ERR_IKE_NULL_PSK;
                    goto exit;
                }
                break;
            case OAKLEY_RSA_SIG :
#ifdef __ENABLE_DIGICERT_ECC__
            case OAKLEY_ECDSA_SIG :
            case OAKLEY_ECDSA_256 :
            case OAKLEY_ECDSA_384 :
            case OAKLEY_ECDSA_521 :
#endif
#ifdef __ENABLE_DIGICERT_PQC__
        case OAKLEY_P256_MLDSA_44:
        case OAKLEY_P256_FNDSA512:
        case OAKLEY_P384_MLDSA_65:
        case OAKLEY_P521_FNDSA1024:
        case OAKLEY_P521_MLDSA_87:
#endif
                if (0 >= config->ikeCertChainLen)
                {
                    status = ERR_IKE_NO_CERT;
                    goto exit;
                }

#ifdef __ENABLE_DIGICERT_ECC__
                if (wValue != config->ikeCertChain[0].wAuthMtd)
                {
                    status = ERR_IKE_BAD_CERT_TYPE;
                    goto exit;
                }
#endif
                break;
            default :
                break;
            } /* switch */
        }

        if (!dir || (2==dir)) pAuthMtd->bEnabled[_I] = on;
        if (!dir || (1==dir)) pAuthMtd->bEnabled[_R] = on;
        break;
    }
    default :
        status = ERR_IKE_BAD_ATTR;
        break;
    }


exit:
    return status;
} /* IKE_initProp */


/*------------------------------------------------------------------*/
/* [v2] */

extern MSTATUS
IKE2_initAuthMtdEx(struct ikePeerConfig* config,
                   ubyte oAuthMtd,  /* see [v2] Auth Methods in "ike_defs.h" */
                   sbyte4 endpoint, /* 0=both, 1=IN/peer, 2=OUT/host */
                   sbyte4 dir,      /* 0=both, 1=responder, 2=initiator */
                   intBoolean on)   /* TRUE=enable, FALSE=disbale */
{
    MSTATUS status = OK;

    IKE_authMtdInfo *pAuthMtd;

    if (NULL == config)
    {
        status = ERR_IKE_NO_PEER_CONFIG;
        goto exit;
    }

    if (dir && (1 != dir) && (2 != dir))
    {
        status = ERR_IKE;
        goto exit;
    }

    if (endpoint && (1 != endpoint) && (2 != endpoint))
    {
        status = ERR_IKE;
        goto exit;
    }

    if ((0xff == oAuthMtd) || /* !!! */
        (NULL == (pAuthMtd = IKE_authMtdEx(config, 0, oAuthMtd))))
    {
        status = ERR_IKE_MISMATCH_AUTH_METHOD;
        goto exit;
    }

    if (on) /* enable only if PSK/certificate is applicable */
    {
        switch (oAuthMtd)
        {
        case AUTH_MTD_SHARED_KEY :
            if (NULL == config->ikePSKey)
            {
                status = ERR_IKE_NULL_PSK;
                goto exit;
            }
            break;
        case AUTH_MTD_RSA_SIG :
#ifdef __ENABLE_IKE_SIG_AUTH_RFC7427__
        case AUTH_MTD_SIG :
#endif
#ifdef __ENABLE_DIGICERT_ECC__
        case AUTH_MTD_ECDSA_256 :
        case AUTH_MTD_ECDSA_384 :
        case AUTH_MTD_ECDSA_521 :
#endif
            if (1 == endpoint) /* IN/peer */
            {
                break;
            }

            if (0 >= config->ikeCertChainLen)
            {
                if (2 == endpoint) /* OUT/host */
                {
                    status = ERR_IKE_NO_CERT;
                    goto exit;
                }
                endpoint = 1; /* !!! */
            }

#ifdef __ENABLE_DIGICERT_ECC__
            if (oAuthMtd != config->ikeCertChain[0].oAuthMtd)
            {
                if (2 == endpoint) /* OUT/host */
                {
                    status = ERR_IKE_BAD_CERT_TYPE;
                    goto exit;
                }
                endpoint = 1; /* !!! */
            }
#endif
            break;
        default : /* shouldn't get here */
            break;
        } /* switch */
    }

    if (!dir || (2==dir))
    {
        if (!endpoint || (2==endpoint)) pAuthMtd->bEnabledOut[_I] = on;
        if (!endpoint || (1==endpoint)) pAuthMtd->bDisabledIn[_I] = !on;
    }

    if (!dir || (1==dir))
    {
        if (!endpoint || (2==endpoint)) pAuthMtd->bEnabledOut[_R] = on;
        if (!endpoint || (1==endpoint)) pAuthMtd->bDisabledIn[_R] = !on;
    }

exit:
    return status;
} /* IKE2_initAuthMtdEx */


/*------------------------------------------------------------------*/
/* [v2] */

extern MSTATUS
IKE2_initPropEx(ikePeerConfig* config, ubyte oType, ubyte2 wId, ubyte2 wKeyLen,
              sbyte4 dir, intBoolean on)
{
    MSTATUS status = OK;

    if (NULL == config)
    {
        status = ERR_IKE_NO_PEER_CONFIG;
        goto exit;
    }

    if (dir && (1 != dir) && (2 != dir))
    {
        status = ERR_IKE;
        goto exit;
    }

    switch (oType)
    {
    case TFM_ENCR :
    {
        ubyte4 i, count = 0, found = 0;
        for (i=0; i < NUM_IKE_CIPHER_SUITES; i++)
        {
            IKE_cipherSuiteInfo *pCipherSuite = &(config->cipherSuites[i]);
            if (wId == pCipherSuite->wTfmId)
            {
                ubyte2 wKeyLenMin = pCipherSuite->wKeyLen;
                ubyte2 wKeyLenMax = pCipherSuite->wKeyLenEnd;

                found++;
                if ((0 == wKeyLen) ||
                    ((wKeyLen >= wKeyLenMin) &&
                     ((0 == wKeyLenMax) || (wKeyLen <= wKeyLenMax))))
                {
                    if (!dir || (2==dir)) pCipherSuite->bDisabled[1][_I] = !on;
                    if (!dir || (1==dir)) pCipherSuite->bDisabled[1][_R] = !on;
                    count++;
                }
            }
        }
        if (!count) status = (found ? ERR_IKE_MISMATCH_KEYLEN
                                    : ERR_IKE_MISMATCH_ENCR_ALGO);
        break;
    }
    case TFM_PRF :
    {
        IKE_hashSuiteInfo *pHashSuite = IKE_hashSuiteEx(config, 0, wId);
        if (NULL == pHashSuite)
        {
            status = ERR_IKE_MISMATCH_PRF;
            goto exit;
        }
        if (!dir || (2==dir)) pHashSuite->bDisabled[1][_I] = !on;
        if (!dir || (1==dir)) pHashSuite->bDisabled[1][_R] = !on;
        break;
    }
    case TFM_INTEG :
    {
        IKE_macSuiteInfo *pMacSuite = IKE_macSuiteEx(config, wId);
        if (NULL == pMacSuite)
        {
            status = ERR_IKE_MISMATCH_AUTH_ALGO;
            goto exit;
        }
        if (wKeyLen && (wKeyLen != pMacSuite->wKeyLen))
        {
            status = ERR_IKE_MISMATCH_KEYLEN;
            goto exit;
        }
        if (!dir || (2==dir)) pMacSuite->bDisabled[_I] = !on;
        if (!dir || (1==dir)) pMacSuite->bDisabled[_R] = !on;
        break;
    }
    case TFM_DH :
    {
        IKE_dhGroupInfo *pDhGroup = IKE_dhGroupEx(config, wId);
        if (NULL == pDhGroup)
        {
            status = ERR_IKE_MISMATCH_DH_GROUP;
            goto exit;
        }
        if (!dir || (2==dir)) pDhGroup->bDisabled[1][_I] = !on;
        if (!dir || (1==dir)) pDhGroup->bDisabled[1][_R] = !on;
        break;
    }
    default :
        status = ERR_IKE_BAD_TRANSFORM;
        break;
    }

exit:
    return status;
} /* IKE2_initProp */


/*------------------------------------------------------------------*/
/* PKCS #1 hash algorithm identifier; see RFC3447 A.2.4 (p51) */

#ifdef __ENABLE_DIGICERT_MD2__
static
const ubyte md2_ID[]  =   { 0x30, 0x20, 0x30, 0x0c, 0x06,
                            0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x02,
                            0x05, 0x00, 0x04, 0x10  };
#endif
#ifdef __ENABLE_DIGICERT_MD4__
static
const ubyte md4_ID[]  =   { 0x30, 0x20, 0x30, 0x0c, 0x06,
                            0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x04, /* ??? */
                            0x05, 0x00, 0x04, 0x10  };
#endif
static
const ubyte md5_ID[]  =   { 0x30, 0x20, 0x30, 0x0c, 0x06,
                            0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05,
                            0x05, 0x00, 0x04, 0x10  };
static
const ubyte sha1_ID[] =   { 0x30, 0x21, 0x30, 0x09, 0x06,
                            0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a,
                            0x05, 0x00, 0x04, 0x14  };
#ifndef __DISABLE_DIGICERT_SHA224__
static
const ubyte sha224_ID[] = { 0x30, 0x61, 0x30, 0x0d, 0x06, /* ??? */
                            0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, /* ??? */
                            0x05, 0x00, 0x04, 0x50  }; /* ??? */
#endif
#ifndef __DISABLE_DIGICERT_SHA256__
static
const ubyte sha256_ID[] = { 0x30, 0x31, 0x30, 0x0d, 0x06,
                            0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
                            0x05, 0x00, 0x04, 0x20  };
#endif
#ifndef __DISABLE_DIGICERT_SHA384__
static
const ubyte sha384_ID[] = { 0x30, 0x41, 0x30, 0x0d, 0x06,
                            0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
                            0x05, 0x00, 0x04, 0x30  };
#endif
#ifndef __DISABLE_DIGICERT_SHA512__
static
const ubyte sha512_ID[] = { 0x30, 0x51, 0x30, 0x0d, 0x06,
                            0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
                            0x05, 0x00, 0x04, 0x40  };
#endif

static struct PKCS1_hashId
    {   ubyte sig;              const ubyte *id;    ubyte2 len;         BulkHashAlgo *pBHAlgo;   }

mHashId[] =
{
#ifdef __ENABLE_DIGICERT_MD2__
    {   md2withRSAEncryption,       md2_ID,         sizeof(md2_ID),     &MD2Suite   },
#endif
#ifdef __ENABLE_DIGICERT_MD4__
    {   md4withRSAEncryption,       md4_ID,         sizeof(md4_ID),     &MD4Suite   },
#endif
    {   md5withRSAEncryption,       md5_ID,         sizeof(md5_ID),     &MD5Suite   },
    {   sha1withRSAEncryption,      sha1_ID,        sizeof(sha1_ID),    &SHASuite   },

#ifndef __DISABLE_DIGICERT_SHA224__
    {   sha224withRSAEncryption,    sha224_ID,      sizeof(sha224_ID),  &SHA224Suite},
#endif
#ifndef __DISABLE_DIGICERT_SHA256__
    {   sha256withRSAEncryption,    sha256_ID,      sizeof(sha256_ID),  &SHA256Suite},
#endif
#ifndef __DISABLE_DIGICERT_SHA384__
    {   sha384withRSAEncryption,    sha384_ID,      sizeof(sha384_ID),  &SHA384Suite},
#endif
#ifndef __DISABLE_DIGICERT_SHA512__
    {   sha512withRSAEncryption,    sha512_ID,      sizeof(sha512_ID),  &SHA512Suite},
#endif
};

#define NUM_PKCS1_HASH_ID (sizeof(mHashId)/sizeof(struct PKCS1_hashId))


/*------------------------------------------------------------------*/
/* [v2] */

extern MSTATUS
IKE_getSigHashAlgo(ubyte oSigAlgo,
                   const ubyte** ppId, ubyte2 *pIdLen,
                   const struct BulkHashAlgo **ppBHAlgo)
{
    /* See RFC3447 9.2 (p42), RFC4306 3.8 (p63) & RFC4718 3.2 (p10) */
    MSTATUS status = OK;
    ubyte4 i;

    if (!ppId && !pIdLen && !ppBHAlgo)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Strongswan 5.5.0 BUG: RSA signature can only use SHA1 as its hash algo! */

    for (i=0; i < NUM_PKCS1_HASH_ID; i++)
    {
        struct PKCS1_hashId *pHashId = &mHashId[i];
        if (oSigAlgo == pHashId->sig)
        {
            if (ppBHAlgo) *ppBHAlgo = pHashId->pBHAlgo;
            if (pIdLen) *pIdLen = pHashId->len;
            if (ppId) *ppId = pHashId->id;
            goto exit;
        }
    }

    /* use SHA-1 as the default; see RFC4718 3.2 (p10) */
    if (ppId) *ppId = sha1_ID;
    if (pIdLen) *pIdLen = sizeof(sha1_ID);
    if (ppBHAlgo) *ppBHAlgo = &SHASuite;

exit:
    return status;
} /* IKE_getSigHashAlgo */


/*------------------------------------------------------------------*/
/* [v2] */

extern MSTATUS
IKE_getHashAlgoByInfo(const ubyte* info, ubyte2 len, ubyte2 *pIdLen,
                      const struct BulkHashAlgo **ppBHAlgo)
{
    MSTATUS status = OK;
    ubyte4 i;

    if (!pIdLen && !ppBHAlgo)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    for (i=0; i < NUM_PKCS1_HASH_ID; i++)
    {
        struct PKCS1_hashId *pHashId = &mHashId[i];

        if (len >= pHashId->len)
        {
            sbyte4 compareResult;
            if (OK > (status = DIGI_MEMCMP(info, pHashId->id, pHashId->len, &compareResult)))
                goto exit;

            if (0 == compareResult)
            {
                if (ppBHAlgo) *ppBHAlgo = pHashId->pBHAlgo;
                if (pIdLen) *pIdLen = pHashId->len;
                goto exit;
            }
        }
    }

    status = ERR_IKE_BAD_HASH;

exit:
    return status;
} /* IKE_getHashAlgoByInfo */


/*------------------------------------------------------------------*/
/* [v2] */

#ifdef __ENABLE_IKE_SIG_AUTH_RFC7427__

/* AlgorithmIdentifier ASN.1 objects; see RFC7427 Appendix A (p12) */

static const ubyte sha1RSA_ID[] = {
    0x30, 0x0d,
        0x06, 0x09,
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05,
        0x05, 0x00 };
#ifndef __DISABLE_DIGICERT_SHA256__
static const ubyte sha256RSA_ID[] = {
    0x30, 0x0d,
        0x06, 0x09,
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
        0x05, 0x00 };
#endif
#ifndef __DISABLE_DIGICERT_SHA384__
static const ubyte sha384RSA_ID[] = {
    0x30, 0x0d,
        0x06, 0x09,
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c,
        0x05, 0x00 };
#endif
#ifndef __DISABLE_DIGICERT_SHA512__
static const ubyte sha512RSA_ID[] = {
    0x30, 0x0d,
        0x06, 0x09,
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d,
        0x05, 0x00 };
#endif

#ifdef __ENABLE_DIGICERT_ECC__
static const ubyte sha1ECDSA_ID[] = {
    0x30, 0x09,
        0x06, 0x07,
            0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x01 };
#ifndef __DISABLE_DIGICERT_SHA256__
static const ubyte sha256ECDSA_ID[] = {
    0x30, 0x0a,
        0x06, 0x08,
            0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02 };
#endif
#ifndef __DISABLE_DIGICERT_SHA384__
static const ubyte sha384ECDSA_ID[] = {
    0x30, 0x0a,
        0x06, 0x08,
            0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03 };
#endif
#ifndef __DISABLE_DIGICERT_SHA512__
static const ubyte sha512ECDSA_ID[] = {
    0x30, 0x0a,
        0x06, 0x08,
            0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04 };
#endif

#ifdef __ENABLE_DIGICERT_ECC_EDDSA_25519__
static const ubyte EdDSA25519_OID[] = {
    0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70 };
#endif

#ifdef __ENABLE_DIGICERT_ECC_EDDSA_448__
static const ubyte EdDSA448_OID[] = {
    0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x71 };
#endif

#endif /* __ENABLE_DIGICERT_ECC__ */

static struct PKIX_sigId
{   const ubyte *id;    ubyte len;           ubyte4 akt; ubyte2 ht;     BulkHashAlgo *pBHAlgo; ubyte sig; }

mSigId[] =
{
    {   sha1RSA_ID,     sizeof(sha1RSA_ID),     akt_rsa, HASH_SHA1,     &SHASuite,      sha1withRSAEncryption },

#ifndef __DISABLE_DIGICERT_SHA256__
    {   sha256RSA_ID,   sizeof(sha256RSA_ID),   akt_rsa, HASH_SHA2_256, &SHA256Suite,   sha256withRSAEncryption },
#endif
#ifndef __DISABLE_DIGICERT_SHA384__
    {   sha384RSA_ID,   sizeof(sha384RSA_ID),   akt_rsa, HASH_SHA2_384, &SHA384Suite,   sha384withRSAEncryption },
#endif
#ifndef __DISABLE_DIGICERT_SHA512__
    {   sha512RSA_ID,   sizeof(sha512RSA_ID),   akt_rsa, HASH_SHA2_512, &SHA512Suite,   sha512withRSAEncryption },
#endif

#ifdef __ENABLE_DIGICERT_ECC__
    {   sha1ECDSA_ID,   sizeof(sha1ECDSA_ID),   akt_ecc, HASH_SHA1,     &SHASuite, 0 },

#ifndef __DISABLE_DIGICERT_SHA256__
    {   sha256ECDSA_ID, sizeof(sha256ECDSA_ID), akt_ecc, HASH_SHA2_256, &SHA256Suite, 0 },
#endif
#ifndef __DISABLE_DIGICERT_SHA384__
    {   sha384ECDSA_ID, sizeof(sha384ECDSA_ID), akt_ecc, HASH_SHA2_384, &SHA384Suite, 0 },
#endif
#ifndef __DISABLE_DIGICERT_SHA512__
    {   sha512ECDSA_ID, sizeof(sha512ECDSA_ID), akt_ecc, HASH_SHA2_512, &SHA512Suite, 0 },
#endif
#if defined(__ENABLE_IKE_SIG_AUTH_RFC7427__) && defined(__ENABLE_DIGICERT_ECC_EDDSA_25519__)
    {   EdDSA25519_OID, sizeof(EdDSA25519_OID), akt_ecc, HASH_IDENTITY, &NoHashSuite, cid_EC_Ed25519 },
#endif
#if defined(__ENABLE_IKE_SIG_AUTH_RFC7427__) && defined(__ENABLE_DIGICERT_ECC_EDDSA_448__)
    {   EdDSA448_OID, sizeof(EdDSA448_OID), akt_ecc, HASH_IDENTITY, &NoHashSuite, cid_EC_Ed448 },

#endif
#endif /* __ENABLE_DIGICERT_ECC__ */
};

#define NUM_PKIX_SIG_ID (sizeof(mSigId)/sizeof(struct PKIX_sigId))


/*------------------------------------------------------------------*/

extern MSTATUS
IKE_getSigAlgoById(const ubyte *id, ubyte len,
                   ubyte4 *akt, const struct BulkHashAlgo **ppBHAlgo)
{
    MSTATUS status = OK;
    ubyte4 i;

    if (!id || (!akt && !ppBHAlgo))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    for (i=0; i < NUM_PKIX_SIG_ID; i++)
    {
        struct PKIX_sigId *pSigId = &mSigId[i];

        if (len == pSigId->len)
        {
            sbyte4 compareResult;
            if (OK > (status = DIGI_MEMCMP(id, pSigId->id, len, &compareResult)))
                goto exit;

            if (0 == compareResult)
            {
                if (ppBHAlgo) *ppBHAlgo = pSigId->pBHAlgo;
                if (akt) *akt = pSigId->akt;
                goto exit;
            }
        }
    }

    status = ERR_IKE_BAD_SIG;

exit:
    return status;
} /* IKE_getSigAlgoById */


/*------------------------------------------------------------------*/

extern MSTATUS
IKE_getSigAlgo(ubyte4 akt, ubyte2 ht,
               ubyte *poSigAlgo, /* RSA only */
               const ubyte **ppId, ubyte *pLen,
               const struct BulkHashAlgo **ppBHAlgo)
{
    MSTATUS status = OK;
    ubyte4 i;

    if (!poSigAlgo && !ppId && !pLen && !ppBHAlgo)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    for (i=0; i < NUM_PKIX_SIG_ID; i++)
    {
        struct PKIX_sigId *pSigId = &mSigId[i];
        if ((akt == pSigId->akt) && (ht == pSigId->ht))
        {
            if (ppBHAlgo) *ppBHAlgo = pSigId->pBHAlgo;
            if (poSigAlgo) *poSigAlgo = pSigId->sig;
            if (pLen) *pLen = pSigId->len;
            if (ppId) *ppId = pSigId->id;
            goto exit;
        }
    }

exit:
    return status;
} /* IKE_getSigAlgo */


/*------------------------------------------------------------------*/

extern IKE_hashSuiteInfo *
IKE_sigHashSuite(ikePeerConfig *config, ubyte2 wSigHash)
{
    IKE_hashSuiteInfo *pHashSuite = NULL;

    ubyte4 i;
    for (i=0; i < NUM_IKE_HASH_SUITES; i++, pHashSuite = NULL)
    {
        pHashSuite = &(config->hashSuites[i]);
        if (wSigHash && (wSigHash == pHashSuite->wSigHash))
        {
            break;
        }
    }

    return pHashSuite;
} /* IKE_sigHashSuite */

#endif /* __ENABLE_IKE_SIG_AUTH_RFC7427__ */


/*------------------------------------------------------------------*/

#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)

static hwAccelDescr m_hwAccelCtx = 0;

extern MSTATUS
IKE_getHwAccelChannel(hwAccelDescr *pHwAccelCtx)
{
    MSTATUS status = OK;

    if (NULL == pHwAccelCtx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_HARNESS__
    if (0 == m_hwAccelCtx)
    {
        status = ERR_HARDWARE_ACCEL_CREATE_CTX;
        goto exit;
    }
#endif
    *pHwAccelCtx = m_hwAccelCtx;

exit:
    return status;
}

extern MSTATUS
IKE_releaseHwAccelChannel(hwAccelDescr *pHwAccelCtx)
{
    MSTATUS status = OK;

    if (NULL == pHwAccelCtx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (*pHwAccelCtx != m_hwAccelCtx)
    {
        status = ERR_HARDWARE_ACCEL_BAD_CTX;
        goto exit;
    }

    *pHwAccelCtx = 0;

exit:
    return status;
}

#endif /* defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__) */


/*------------------------------------------------------------------*/

#ifndef __IKE_MULTI_THREADED__
static poolHeaderDescr m_shaPool = { NULL };
static poolHeaderDescr m_md5Pool = { NULL };
#ifndef __DISABLE_AES_CIPHERS__
static poolHeaderDescr m_aesPool = { NULL };
#endif
#endif

extern MSTATUS
IKE_cryptoInit(void)
{
    MSTATUS status = OK;

#ifndef __IKE_MULTI_THREADED__
    void*   pTempMemBuffer = NULL;
    ubyte4  poolObjSize;
#endif

#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    if (0 != m_hwAccelCtx)
        goto exit;

    if (OK > (status = (MSTATUS) HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_IKE, &m_hwAccelCtx)))
    {
        m_hwAccelCtx = 0;
        goto exit;
    }
#endif

#ifndef __IKE_MULTI_THREADED__
    poolObjSize = ((sizeof(shaDescrHS) + 7) / 8) * 8; /* multiple of 8, i.e. sizeof(void*) on 64-bit */
    if (OK > (status = CRYPTO_ALLOC(m_hwAccelCtx, poolObjSize * 5, TRUE, &pTempMemBuffer)))
        goto exit;

/*    DEBUG_RELABEL_MEMORY(pTempMemBuffer);*/

    if (OK > (status = MEM_POOL_initPool(&m_shaPool, pTempMemBuffer, poolObjSize * 5, poolObjSize)))
        goto exit;

    poolObjSize = ((sizeof(MD5_CTXHS) + 7) / 8) * 8;
    if (OK > (status = CRYPTO_ALLOC(m_hwAccelCtx, poolObjSize * 5, TRUE, &pTempMemBuffer)))
        goto exit;

/*    DEBUG_RELABEL_MEMORY(pTempMemBuffer);*/

    if (OK > (status = MEM_POOL_initPool(&m_md5Pool, pTempMemBuffer, poolObjSize * 5, poolObjSize)))
        goto exit;

#ifndef __DISABLE_AES_CIPHERS__
#ifndef __DISABLE_AES_XCBC_CIPHER__
    poolObjSize = ((sizeof(AES_XCBC_PRF_128_Ctx) + 7) / 8) * 8;
    if (OK > (status = CRYPTO_ALLOC(m_hwAccelCtx, poolObjSize * 5, TRUE, &pTempMemBuffer)))
        goto exit;

/*    DEBUG_RELABEL_MEMORY(pTempMemBuffer);*/

    if (OK > (status = MEM_POOL_initPool(&m_aesPool, pTempMemBuffer, poolObjSize * 5, poolObjSize)))
        goto exit;
#endif
#endif
#endif /* !__IKE_MULTI_THREADED__ */

#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__) || \
    !defined(__IKE_MULTI_THREADED__)
exit:
    if (OK > status) IKE_cryptoUninit();
#endif
    return status;
} /* IKE_cryptoInit */


/*------------------------------------------------------------------*/

extern MSTATUS
IKE_cryptoUninit(void)
{
    MSTATUS status = OK;

#ifndef __IKE_MULTI_THREADED__
    void *pTemp = NULL;

    if (OK <= (status = MEM_POOL_uninitPool(&m_shaPool, &pTemp)))
        CRYPTO_FREE(m_hwAccelCtx, TRUE, &pTemp);

    if (OK <= (status = MEM_POOL_uninitPool(&m_md5Pool, &pTemp)))
        CRYPTO_FREE(m_hwAccelCtx, TRUE, &pTemp);

#ifndef __DISABLE_AES_CIPHERS__
    if (OK <= (status = MEM_POOL_uninitPool(&m_aesPool, &pTemp)))
        CRYPTO_FREE(m_hwAccelCtx, TRUE, &pTemp);
#endif
#endif /* !__IKE_MULTI_THREADED__ */

#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
#ifdef __ENABLE_DIGICERT_HARNESS__
    if (0 != m_hwAccelCtx)
#endif
    {
        status = HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_IKE, &m_hwAccelCtx);
        m_hwAccelCtx = 0;
    }
#endif

    return status;
} /* IKE_cryptoUninit */


/*------------------------------------------------------------------*/

#ifndef __IKE_MULTI_THREADED__

extern MSTATUS
IKE_sha1Alloc(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context)
{
#if (defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__))\
    && defined(__ENABLE_DIGICERT_HARNESS__)
    if (hwAccelCtx != m_hwAccelCtx)
        return SHA1_allocDigest(hwAccelCtx, pp_context);
    else
#elif defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
    return SHA1_allocDigest(MOC_HASH(hwAccelCtx) pp_context);
#endif
    return MEM_POOL_getPoolObject(&m_shaPool, (void **)pp_context);
}

extern MSTATUS
IKE_md5Alloc(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context)
{
#if (defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__))\
    && defined(__ENABLE_DIGICERT_HARNESS__)
    if (hwAccelCtx != m_hwAccelCtx)
        return MD5Alloc_m(hwAccelCtx, pp_context);
    else
#elif defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
    return MD5Alloc_m(MOC_HASH(hwAccelCtx) pp_context);
#endif
    return MEM_POOL_getPoolObject(&m_md5Pool, (void **)pp_context);
}

#ifndef __DISABLE_AES_CIPHERS__
#ifndef __DISABLE_AES_XCBC_CIPHER__

static MSTATUS
AES_XCBC_alloc(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context)
{
    MSTATUS status;
#if (defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__))\
    && defined(__ENABLE_DIGICERT_HARNESS__)
    if (hwAccelCtx != m_hwAccelCtx)
    {
        status = CRYPTO_ALLOC(hwAccelCtx, sizeof(AES_XCBC_PRF_128_Ctx), TRUE, (void**)pp_context);
        if (OK != status)
            return status;

        return DIGI_MEMSET((ubyte *) *pp_context, 0x00, sizeof(AES_XCBC_PRF_128_Ctx));
    }
    else
#endif
    {
        status =  MEM_POOL_getPoolObject(&m_aesPool, (void **)pp_context);
        if (OK != status)
            return status;

        return DIGI_MEMSET((ubyte *) *pp_context, 0x00, sizeof(AES_XCBC_PRF_128_Ctx));
    }
}
#endif
#endif


/*------------------------------------------------------------------*/

extern MSTATUS
IKE_sha1Free(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context)
{
#if (defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__))\
    && defined(__ENABLE_DIGICERT_HARNESS__)
    if (hwAccelCtx != m_hwAccelCtx)
        return SHA1_freeDigest(hwAccelCtx, pp_context);
    else
#elif defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
    return SHA1_freeDigest(MOC_HASH(hwAccelCtx) pp_context);
#endif
    return MEM_POOL_putPoolObject(&m_shaPool, (void **)pp_context);
}

extern MSTATUS
IKE_md5Free(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context)
{
#if (defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__))\
    && defined(__ENABLE_DIGICERT_HARNESS__)
    if (hwAccelCtx != m_hwAccelCtx)
        return MD5Free_m(hwAccelCtx, pp_context);
    else
#elif defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
    return MD5Free_m(MOC_HASH(hwAccelCtx) pp_context);
#endif
    return MEM_POOL_putPoolObject(&m_md5Pool, (void **)pp_context);
}

#ifndef __DISABLE_AES_CIPHERS__
#ifndef __DISABLE_AES_XCBC_CIPHER__
static MSTATUS
AES_XCBC_free(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context)
{
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    MSTATUS status;
    status = CRYPTO_INTERFACE_AES_XCBC_clear(MOC_HASH(hwAccelCtx) *pp_context);
    if (OK != status)
        return status;
#endif
#if (defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__))\
    && defined(__ENABLE_DIGICERT_HARNESS__)
    if (hwAccelCtx != m_hwAccelCtx)
        return CRYPTO_FREE(hwAccelCtx, TRUE, (void**)pp_context);
    else
#endif
    return MEM_POOL_putPoolObject(&m_aesPool, (void **)pp_context);
}
#endif
#endif


#else

/*------------------------------------------------------------------*/

#ifndef __DISABLE_AES_CIPHERS__
#ifndef __DISABLE_AES_XCBC_CIPHER__

static MSTATUS
AES_XCBC_alloc(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context)
{
    MSTATUS status;
    status = CRYPTO_ALLOC(hwAccelCtx, sizeof(AES_XCBC_PRF_128_Ctx), TRUE, (void**)pp_context);
    if (OK != status)
        return status;

    return DIGI_MEMSET((ubyte *) *pp_context, 0x00, sizeof(AES_XCBC_PRF_128_Ctx));
}

static MSTATUS
AES_XCBC_free(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context)
{
    return CRYPTO_FREE(hwAccelCtx, TRUE, (void**)pp_context);
}

#endif
#endif

#endif /* __IKE_MULTI_THREADED__ */


/*------------------------------------------------------------------*/

/*!
\exclude
*/
#define INIT_SUITE(confmember, source)          \
    config->confmember = MALLOC(sizeof(source));\
    if (!config->confmember)                    \
    {                                           \
        status = ERR_MEM_ALLOC_FAIL;            \
        goto exit;                              \
    }                                           \
    DIGI_MEMCPY((ubyte*) (config->confmember),   \
               (ubyte*)source, sizeof(source)); \


/*!
\exclude
*/

extern MSTATUS
IKE_initSuiteInfo(ikePeerConfig* config)
{
    MSTATUS status = OK;

    if (!config)
    {
        status = ERR_IKE_NO_PEER_CONFIG;
        goto exit;
    }

    /* Already initialized..  Don't re-do it */
    if (config->hashSuites)
        goto exit;

    INIT_SUITE(hashSuites, mHashSuites)
    INIT_SUITE(cipherSuites, mCipherSuites)
    INIT_SUITE(macSuites, mMacSuites)
    INIT_SUITE(dhGroups, mDhGroups)
    INIT_SUITE(authMtds, mAuthMtds)

#ifdef __ENABLE_DIGICERT_PQC__
    generateKeyExchangeValues(config);
#endif

exit:
    return status;
}

#else
static void
dummy(void)
{
    return;
}
#endif /* defined(__ENABLE_DIGICERT_IKE_SERVER__) */

