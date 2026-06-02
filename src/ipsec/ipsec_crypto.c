/**
 * @file  ipsec_crypto.c
 * @brief NanoSec IPsec cryptography suites implementation.
 *
 * @details    This file contains IPsec cryptographic algorithm implementations.
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

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/random.h"
#include "../common/mem_part.h"
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
#include "../crypto/aes_xcbc_mac_96.h"
#include "../crypto/aes_ctr.h"
#include "../crypto/aes_ccm.h"
#include "../crypto/gcm.h"
#include "../crypto/chacha20.h"
#include "../harness/harness.h"
#include "../ipsec/ipsec_defs.h"
#include "../ipsec/ipsec_crypto.h"

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../cap/capsym.h"
#include "../crypto_interface/crypto_interface_aes.h"
#include "../crypto_interface/crypto_interface_aes_gcm.h"
#include "../crypto_interface/crypto_interface_hmac.h"
#include "../crypto_interface/crypto_interface_aes_xcbc_mac_96.h"
#include "../crypto_interface/crypto_interface_aes_ctr.h"
#include "../crypto_interface/crypto_interface_aes_ccm.h"
#include "../crypto_interface/crypto_interface_blake2.h"
#include "../crypto_interface/crypto_interface_chacha20.h"
#include "../crypto_interface/crypto_interface_sha256.h"
#include "../crypto_interface/crypto_interface_sha512.h"
#include "../crypto_interface/crypto_interface_random.h"
#endif

/*------------------------------------------------------------------*/



#ifndef __DISABLE_AES_CIPHERS__
#ifndef __DISABLE_AES_XCBC_CIPHER__
static MSTATUS AES_XCBC_MAC(MOC_HASH(hwAccelDescr hwAccelCtx)
                            const ubyte* key, sbyte4 keyLen,
                            const ubyte* text, sbyte4 textLen,
                            ubyte result[]);
#endif
#endif

#ifndef __DISABLE_DIGICERT_SHA256__
static MSTATUS HMAC_SHA256_quick(MOC_HASH(hwAccelDescr hwAccelCtx)
                                 const ubyte* pKey, sbyte4 keyLen,
                                 const ubyte* pText, sbyte4 textLen,
                                 ubyte result[]);
#endif

#ifndef __DISABLE_DIGICERT_SHA384__
static MSTATUS HMAC_SHA384_quick(MOC_HASH(hwAccelDescr hwAccelCtx)
                                 const ubyte* pKey, sbyte4 keyLen,
                                 const ubyte* pText, sbyte4 textLen,
                                 ubyte result[]);
#endif

#ifndef __DISABLE_DIGICERT_SHA512__
static MSTATUS HMAC_SHA512_quick(MOC_HASH(hwAccelDescr hwAccelCtx)
                                 const ubyte* pKey, sbyte4 keyLen,
                                 const ubyte* pText, sbyte4 textLen,
                                 ubyte result[]);
#endif

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
#endif /* __ENABLE_DIGICERT_GCM__ */

#if defined(__ENABLE_DIGICERT_BLAKE_2B__) || defined(__ENABLE_DIGICERT_BLAKE_2S__)
#define BLAKE_KEYLEN 32
#define BLAKE_ICVLEN 16
#endif

#ifdef __ENABLE_DIGICERT_BLAKE_2B__
MOC_EXTERN MSTATUS BLAKE2B_completeEx(MOC_HASH(hwAccelDescr hwAccelCtx)
    const ubyte *pKey, sbyte4 keyLen, const ubyte *pData, sbyte4 dataLen, ubyte pOutput[])
{
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    return CRYPTO_INTERFACE_BLAKE_2B_complete(MOC_HASH(hwAccelCtx) (ubyte *) pKey, keyLen, (ubyte *) pData, dataLen, pOutput, BLAKE_ICVLEN);
#else
    return BLAKE2B_complete(MOC_HASH(hwAccelCtx) (ubyte *) pKey, keyLen, (ubyte *) pData, dataLen, pOutput, BLAKE_ICVLEN);
#endif
}
#endif
#ifdef __ENABLE_DIGICERT_BLAKE_2S__
MOC_EXTERN MSTATUS BLAKE2S_completeEx(MOC_HASH(hwAccelDescr hwAccelCtx)
    const ubyte *pKey, sbyte4 keyLen, const ubyte *pData, sbyte4 dataLen, ubyte pOutput[])
{
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    return CRYPTO_INTERFACE_BLAKE_2S_complete(MOC_HASH(hwAccelCtx) (ubyte *) pKey, keyLen, (ubyte *) pData, dataLen, pOutput, BLAKE_ICVLEN);
#else
    return BLAKE2S_complete(MOC_HASH(hwAccelCtx) (ubyte *) pKey, keyLen, (ubyte *) pData, dataLen, pOutput, BLAKE_ICVLEN);
#endif
}
#endif

/*------------------------------------------------------------------*/

static SADB_hmacSuiteInfo mHmacSuites[] =
{/*   oAuthAlgo,          wDigestOrgLen,         wIcvLen, wKeyLen,  hmacFunc */
#ifdef __ENABLE_DIGICERT_BLAKE_2B__
    { IPSEC_AUTHALG_BLAKE2_2B, BLAKE_ICVLEN, BLAKE_ICVLEN, BLAKE_KEYLEN, BLAKE2B_completeEx },
#endif
#ifdef __ENABLE_DIGICERT_BLAKE_2S__
    { IPSEC_AUTHALG_BLAKE2_2S, BLAKE_ICVLEN, BLAKE_ICVLEN, BLAKE_KEYLEN, BLAKE2S_completeEx },
#endif
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    { IPSEC_AUTHALG_SHA1, SHA_HASH_RESULT_SIZE/*20*/, 12, 20,       CRYPTO_INTERFACE_HMAC_SHA1_quick },

    { IPSEC_AUTHALG_MD5,  MD5_DIGESTSIZE/*16*/,       12, 16,       CRYPTO_INTERFACE_HMAC_MD5_quick  },
#else
    { IPSEC_AUTHALG_SHA1, SHA_HASH_RESULT_SIZE/*20*/, 12, 20,       HMAC_SHA1_quick },

    { IPSEC_AUTHALG_MD5,  MD5_DIGESTSIZE/*16*/,       12, 16,       HMAC_MD5_quick  },
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */

#ifndef __DISABLE_AES_CIPHERS__
#ifndef __DISABLE_AES_XCBC_CIPHER__
    { IPSEC_AUTHALG_AES,  AES_XCBC_MAC_96_RESULT_SIZE/*12*/,
                                                      12, AES_BLOCK_SIZE/*16*/, AES_XCBC_MAC },
#endif
#endif
#ifndef __DISABLE_DIGICERT_SHA256__
    { IPSEC_AUTHALG_SHA256, SHA256_RESULT_SIZE/*32*/, 16, 32,       HMAC_SHA256_quick },
#endif
#ifndef __DISABLE_DIGICERT_SHA384__
    { IPSEC_AUTHALG_SHA384, SHA384_RESULT_SIZE/*48*/, 24, 48,       HMAC_SHA384_quick },
#endif
#ifndef __DISABLE_DIGICERT_SHA512__
    { IPSEC_AUTHALG_SHA512, SHA512_RESULT_SIZE/*64*/, 32, 64,       HMAC_SHA512_quick },
#endif
};

#define NUM_SADB_HMAC_SUITES     (sizeof(mHmacSuites)/sizeof(SADB_hmacSuiteInfo))


/*------------------------------------------------------------------*/

/* RFC 3686 - Usage of AES-CTR in IPsec
 *
 * - Encryptor must generate an unique per-packet IV.
 * - Same key and IV MUST NOT be used more than once.
 * - Encryptor may generate the IV in any way that ensures uniqueness. Common
 *   approaches for generation include incrementing a counter for each packet
 *   and linear feedback shift registers (LFSRs).
 * - Nonce must be unpredictable prior to establishment of the IPsec security
 *   association that is making use of AES-CTR.
 * - Nonce values cannot persist accross security associations. A new security
 *   association must get a fresh nonce.
 * - Sender can precompute the keystream to reduce packet latency.
 * - Using the same key, nonce, and IV is catastrophic.
 * - Static keys are not allowed. Implementations must use fresh keys.
 * - IKE can provide fresh keys and nonce values.
 * - AES-CTR MUST use an authentication method such as HMAC-SHA-1-96.
 * - The initial AES-CTR block is defined as the following
 *       CTRBLK = NONCE || IV || ONE
 *   and it is incremented by one after a single block is processed.
 * - 128 bit keys MUST be supported and 192 and 256 bit keys MAY be supported.
 * - If the plaintext is smaller then the output then the output may be
 *   truncated. This means the plaintext does not need to be padded. To provide
 *   limited traffic flow confidentiality padding MAY be included as specified
 *   in ESP.
 * - ESP payload is defined as
 *       IV (8 octets)
 *       Encrypted Payload (variable)
 *       Authentication Data (variable)
 * - Section 4 of the RFC seems to imply that the counter (last 32 bits of the
 *   AES-CTR block) is used on a per packet basis and reset to one for any new
 *   packets.
 * - IKE provides two traffic keys for AES-CTR. Using a single key could lead
 *   to the sender and reciever using the same IV value from some packets. If
 *   the same key is used for inbound and outbound traffic then the ESP
 *   implementation MUST ensure that the sender and reciever are using different
 *   nonce values.
 * - ESP with Enhanced Sequence Numbers can allow for a 2^64 pakcets in a
 *   single security association with a single key. Implementations should
 *   generate a fresh key before 2^64 blocks are encrypted with the same key.
 */
#ifndef __DISABLE_AES_CIPHERS__
static BulkEncryptionAlgo AesCtrSuite = { 1,
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
                            CRYPTO_INTERFACE_CreateAesCtrCtx, CRYPTO_INTERFACE_DeleteAESCTRCtx, CRYPTO_INTERFACE_DoAesCtrEx, CRYPTO_INTERFACE_CloneAESCTRCtx };
#else
                            CreateAesCtrCtx, DeleteAESCTRCtx, DoAesCtrEx, CloneAESCTRCtx};
#endif

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
#endif
#endif

#ifdef __ENABLE_DIGICERT_GCM__
/*  { salt, iv, icv,    createFunc,     deleteFunc,     cipherFunc } */
static AeadAlgo AesGcm16Suite =
    { 4,    8,  16,     CreateGcmCtx,   DeleteGcmCtx,   CipherGcm, CloneGcm };

static AeadAlgo AesGcm12Suite =
    { 4,    8,  12,     CreateGcmCtx,   DeleteGcmCtx,   CipherGcm, CloneGcm };

static AeadAlgo AesGcm8Suite =
    { 4,    8,  8,      CreateGcmCtx,   DeleteGcmCtx,   CipherGcm, CloneGcm };
#endif /* __ENABLE_DIGICERT_GCM__ */
#endif

#if defined(__ENABLE_DIGICERT_CHACHA20__) && defined(__ENABLE_DIGICERT_POLY1305__)
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
static AeadAlgo Chacha20Poly1305Suite =
    { 4,    8,  16,      CRYPTO_INTERFACE_ChaCha20Poly1305_createCtx,   CRYPTO_INTERFACE_ChaCha20Poly1305_deleteCtx,   CRYPTO_INTERFACE_ChaCha20Poly1305_cipher, CRYPTO_INTERFACE_ChaCha20Poly1305_cloneCtx };
#else
static AeadAlgo Chacha20Poly1305Suite =
    { 4,    8,  16,      ChaCha20Poly1305_createCtx,   ChaCha20Poly1305_deleteCtx,   ChaCha20Poly1305_cipher, ChaCha20Poly1305_cloneCtx };
#endif
#endif

#define AEADLEN(_kl, _n)        (_kl), (_kl), (_n) /* salt included */
#define AEADSPEC                , NULL, FALSE

#define KEYLEN_EX(_kl, _n)      (_kl), (_kl), (_n)  AEADSPEC
#define KEYLEN(_kl)             (_kl), (_kl),    0  AEADSPEC
#define KEYLENS(_kl, _klend)    (_kl), (_klend), 0  AEADSPEC

static SADB_cipherSuiteInfo mCipherSuites[] =
{/* { oEncrAlgo,
      wIvLen,               wKeyLen/End,                        pBEAlgo }, */
#ifdef __ENABLE_DES_CIPHER__
    { IPSEC_ENCALG_DES,
      DES_BLOCK_SIZE,       KEYLEN(DES_KEY_LENGTH),/*8*/        &CRYPTO_DESSuite },
#endif
#ifndef __DISABLE_3DES_CIPHERS__
    { IPSEC_ENCALG_3DES,
      THREE_DES_BLOCK_SIZE, KEYLEN(THREE_DES_KEY_LENGTH),/*24*/ &CRYPTO_TripleDESSuite },

#ifdef __ENABLE_2KEY_3DES_CIPHER__
    { IPSEC_ENCALG_3DES,
      THREE_DES_BLOCK_SIZE, KEYLEN(2*DES_KEY_LENGTH),/*16*/     &CRYPTO_TwoKeyTripleDESSuite },
#endif
#endif
#ifdef __ENABLE_BLOWFISH_CIPHERS__
    { IPSEC_ENCALG_BLOWFISH,
      BLOWFISH_BLOCK_SIZE,  KEYLENS(4, MAXKEYBYTES),/*4...56*/  &CRYPTO_BlowfishSuite },
#endif
#ifndef __DISABLE_AES_CIPHERS__
#ifndef __DISABLE_AES128_CIPHER__
    { IPSEC_ENCALG_AES,
      AES_BLOCK_SIZE,       KEYLEN(16),                         &CRYPTO_AESSuite },

    { IPSEC_ENCALG_AES_CTR,
      8,                    KEYLEN_EX(20, 4),                   &AesCtrSuite },
#ifdef __ENABLE_DIGICERT_GCM__
    { IPSEC_ENCALG_AES_GCM,
      8,                    AEADLEN(20, 4),                     &AesGcm16Suite, FALSE, NULL },
    { IPSEC_ENCALG_AES_GCM,
      8,                    AEADLEN(20, 4),                     &AesGcm12Suite, FALSE, NULL },
    { IPSEC_ENCALG_AES_GCM,
      8,                    AEADLEN(20, 4),                     &AesGcm8Suite, FALSE, NULL },
    { IPSEC_ENCALG_AES_GMAC,
      8,                    AEADLEN(20, 4),                     &AesGcm16Suite, TRUE, NULL },
#endif
#ifndef __DISABLE_AES_CCM__
    { IPSEC_ENCALG_AES_CCM,
      8,                    AEADLEN(19, 3),                     &AesCcm16Suite, FALSE, NULL },
    { IPSEC_ENCALG_AES_CCM,
      8,                    AEADLEN(19, 3),                     &AesCcm12Suite, FALSE, NULL },
    { IPSEC_ENCALG_AES_CCM,
      8,                    AEADLEN(19, 3),                     &AesCcm8Suite, FALSE, NULL },
#endif
#endif
#ifndef __DISABLE_AES192_CIPHER__
    { IPSEC_ENCALG_AES,
      AES_BLOCK_SIZE,       KEYLEN(24),                         &CRYPTO_AESSuite },

    { IPSEC_ENCALG_AES_CTR,
      8,                    KEYLEN_EX(28, 4),                   &AesCtrSuite },
#ifdef __ENABLE_DIGICERT_GCM__
    { IPSEC_ENCALG_AES_GCM,
      8,                    AEADLEN(28, 4),                     &AesGcm16Suite, FALSE, NULL },
    { IPSEC_ENCALG_AES_GCM,
      8,                    AEADLEN(28, 4),                     &AesGcm12Suite, FALSE, NULL },
    { IPSEC_ENCALG_AES_GCM,
      8,                    AEADLEN(28, 4),                     &AesGcm8Suite, FALSE, NULL },
    { IPSEC_ENCALG_AES_GMAC,
      8,                    AEADLEN(28, 4),                     &AesGcm16Suite, TRUE, NULL },
#endif
#ifndef __DISABLE_AES_CCM__
    { IPSEC_ENCALG_AES_CCM,
      8,                    AEADLEN(27, 3),                     &AesCcm16Suite, FALSE, NULL },
    { IPSEC_ENCALG_AES_CCM,
      8,                    AEADLEN(27, 3),                     &AesCcm12Suite, FALSE, NULL },
    { IPSEC_ENCALG_AES_CCM,
      8,                    AEADLEN(27, 3),                     &AesCcm8Suite, FALSE, NULL },
#endif
#endif
#ifndef __DISABLE_AES256_CIPHER__
    { IPSEC_ENCALG_AES,
      AES_BLOCK_SIZE,       KEYLEN(32),                         &CRYPTO_AESSuite },

    { IPSEC_ENCALG_AES_CTR,
      8,                    KEYLEN_EX(36, 4),                   &AesCtrSuite },
#ifdef __ENABLE_DIGICERT_GCM__
    { IPSEC_ENCALG_AES_GCM,
      8,                    AEADLEN(36, 4),                     &AesGcm16Suite, FALSE, NULL },
    { IPSEC_ENCALG_AES_GCM,
      8,                    AEADLEN(36, 4),                     &AesGcm12Suite, FALSE, NULL },
    { IPSEC_ENCALG_AES_GCM,
      8,                    AEADLEN(36, 4),                     &AesGcm8Suite, FALSE, NULL },
    { IPSEC_ENCALG_AES_GMAC,
      8,                    AEADLEN(36, 4),                     &AesGcm16Suite, TRUE, NULL },
#endif
#ifndef __DISABLE_AES_CCM__
    { IPSEC_ENCALG_AES_CCM,
      8,                    AEADLEN(35, 3),                     &AesCcm16Suite, FALSE, NULL },
    { IPSEC_ENCALG_AES_CCM,
      8,                    AEADLEN(35, 3),                     &AesCcm12Suite, FALSE, NULL },
    { IPSEC_ENCALG_AES_CCM,
      8,                    AEADLEN(35, 3),                     &AesCcm8Suite, FALSE, NULL },
#endif
#endif
#endif
#if defined(__ENABLE_DIGICERT_CHACHA20__) && defined(__ENABLE_DIGICERT_POLY1305__)
    { IPSEC_ENCALG_CHACHA20_POLY1305,
      8,                    AEADLEN(36, 4),                     &Chacha20Poly1305Suite, FALSE, NULL },
#endif
};

#define NUM_SADB_CIPHER_SUITES   (sizeof(mCipherSuites)/sizeof(SADB_cipherSuiteInfo))


/*------------------------------------------------------------------*/

#ifdef __IPSEC_SINGLE_PASS_SUPPORT__
static struct SADB_singlePassSuiteInfo
{
    const BulkEncryptionAlgo   *pBEAlgo;
    ubyte                       oAuthAlgo;
    typeForSinglePass           typeIn, typeOut;

} mSinglePassSuites[] =
{
#ifdef __ENABLE_DES_CIPHER__
    { &CRYPTO_DESSuite,         IPSEC_AUTHALG_SHA1, SINGLE_PASS_DES_SHA1_IN,    SINGLE_PASS_DES_SHA1_OUT    },
    { &CRYPTO_DESSuite,         IPSEC_AUTHALG_MD5,  SINGLE_PASS_DES_MD5_IN,     SINGLE_PASS_DES_MD5_OUT     },
#endif
#ifndef __DISABLE_3DES_CIPHERS__
    { &CRYPTO_TripleDESSuite,   IPSEC_AUTHALG_SHA1, SINGLE_PASS_3DES_SHA1_IN,   SINGLE_PASS_3DES_SHA1_OUT   },
    { &CRYPTO_TripleDESSuite,   IPSEC_AUTHALG_MD5,  SINGLE_PASS_3DES_MD5_IN,    SINGLE_PASS_3DES_MD5_OUT    },
#endif
#ifndef __DISABLE_AES_CIPHERS__
    { &CRYPTO_AESSuite,         IPSEC_AUTHALG_SHA1, SINGLE_PASS_AES_SHA1_IN,    SINGLE_PASS_AES_SHA1_OUT    },
    { &CRYPTO_AESSuite,         IPSEC_AUTHALG_MD5,  SINGLE_PASS_AES_MD5_IN,     SINGLE_PASS_AES_MD5_OUT     },
#endif
    { NULL,                     0,                  NO_SINGLE_PASS,             NO_SINGLE_PASS              }
};

#define NUM_SINGLE_PASS_SUITES     (sizeof(mSinglePassSuites)/sizeof(struct SADB_singlePassSuiteInfo))


/*------------------------------------------------------------------*/

extern ubyte4
IPSEC_getSinglePassType(SADB_cipherSuiteInfo *pCipherSuite,
                        SADB_hmacSuiteInfo *pHmacSuite,
                        intBoolean bIn)
{
    const BulkEncryptionAlgo *pBEAlgo = pCipherSuite->pBEAlgo;
    ubyte oAuthAlgo = pHmacSuite->oAuthAlgo;
    typeForSinglePass type = NO_SINGLE_PASS;

    sbyte4 i;
    for (i=0; i < NUM_SINGLE_PASS_SUITES; i++)
    {
        if ((pBEAlgo == mSinglePassSuites[i].pBEAlgo) &&
            (oAuthAlgo == mSinglePassSuites[i].oAuthAlgo))
        {
            type = (bIn ? mSinglePassSuites[i].typeIn : mSinglePassSuites[i].typeOut);
            break;
        }
    }

    return (ubyte4)type;
} /* IPSEC_getSinglePassType */

#endif /* __IPSEC_SINGLE_PASS_SUPPORT__ */


/*------------------------------------------------------------------*/

extern SADB_cipherSuiteInfo*
IPSEC_getCipherSuite(sbyte4 i)
{
    SADB_cipherSuiteInfo *pCipherSuite = NULL;

    if ((ubyte4)i < NUM_SADB_CIPHER_SUITES)
        pCipherSuite = &(mCipherSuites[i]);

    return pCipherSuite;
} /* IPSEC_getCipherSuite */


/*------------------------------------------------------------------*/

extern SADB_hmacSuiteInfo*
IPSEC_getHmacSuite(sbyte4 i)
{
    SADB_hmacSuiteInfo *pHmacSuite = NULL;

    if ((ubyte4)i < NUM_SADB_HMAC_SUITES)
        pHmacSuite = &(mHmacSuites[i]);

    return pHmacSuite;
} /* IPSEC_getHmacSuite */


/*------------------------------------------------------------------*/

extern sbyte4
IPSEC_getMaxCipherSuites(void)
{
    return ((sbyte4)NUM_SADB_CIPHER_SUITES);
} /* IPSEC_getMaxCipherSuites */


/*------------------------------------------------------------------*/

extern sbyte4
IPSEC_getMaxHmacSuites(void)
{
    return ((sbyte4)NUM_SADB_HMAC_SUITES);
} /* IPSEC_getMaxHmacSuites */


/*------------------------------------------------------------------*/

extern SADB_hmacSuiteInfo*
IPSEC_hmacSuite(ubyte oAuthAlgo)
{
    SADB_hmacSuiteInfo *pHmacSuite = NULL;
    ubyte4 i;

    for (i=0; i < NUM_SADB_HMAC_SUITES; i++)
    {
        if (oAuthAlgo == mHmacSuites[i].oAuthAlgo)
        {
            pHmacSuite = &(mHmacSuites[i]);
            goto exit;
        }
    }

exit:
    return pHmacSuite;
} /* IPSEC_hmacSuite */


/*------------------------------------------------------------------*/

extern SADB_cipherSuiteInfo*
IPSEC_cipherSuite(ubyte oEncrAlgo,
                  ubyte oAeadIcvLen,
                  ubyte2 wKeyLen, ubyte2 *pwKeyLen)
{
    SADB_cipherSuiteInfo *pCipherSuite = NULL;
    ubyte4 i;

    SADB_cipherSuiteInfo* pCipherSuiteBest = NULL;
    ubyte2 wKeyLenBest = 0;

    for (i=0; i < NUM_SADB_CIPHER_SUITES; i++, pCipherSuite = NULL)
    {
        pCipherSuite = &(mCipherSuites[i]);

        if (oEncrAlgo == pCipherSuite->oEncrAlgo)
        {
            ubyte2 wKeyLenMin = pCipherSuite->wKeyLen;
            ubyte2 wKeyLenMax = pCipherSuite->wKeyLenEnd;

            if (oAeadIcvLen)
            {
                AeadAlgo *pAeadAlgo = pCipherSuite->pAeadAlgo;
                if (!pAeadAlgo || (oAeadIcvLen != (ubyte) pAeadAlgo->tagSize))
                    continue;
            }

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
} /* IPSEC_cipherSuite */


/*------------------------------------------------------------------*/

#ifndef __DISABLE_AES_CIPHERS__
static MSTATUS
AES_XCBC_MAC(MOC_HASH(hwAccelDescr hwAccelCtx)
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

    if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, sizeof(AES_XCBC_MAC_96_Ctx), TRUE, (void**) &p_context)))
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
    if (p_context) CRYPTO_FREE(hwAccelCtx, TRUE, (void**) &p_context);
    return status;
} /* AES_XCBC_MAC */

#endif /* __DISABLE_AES_CIPHERS__ */

/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_SHA256__
static BulkHashAlgo SHA256Suite =
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    { SHA256_RESULT_SIZE/*32*/, SHA256_BLOCK_SIZE, CRYPTO_INTERFACE_SHA256_allocDigest, CRYPTO_INTERFACE_SHA256_freeDigest,
      (BulkCtxInitFunc) CRYPTO_INTERFACE_SHA256_initDigest, (BulkCtxUpdateFunc) CRYPTO_INTERFACE_SHA256_updateDigest,
      (BulkCtxFinalFunc) CRYPTO_INTERFACE_SHA256_finalDigest, NULL, NULL, NULL, ht_sha256 };
#else
    { SHA256_RESULT_SIZE/*32*/, SHA256_BLOCK_SIZE, SHA256_allocDigest, SHA256_freeDigest,
      (BulkCtxInitFunc)SHA256_initDigest, (BulkCtxUpdateFunc)SHA256_updateDigest, (BulkCtxFinalFunc)SHA256_finalDigest, NULL, NULL, NULL, ht_sha256 };
#endif

static MSTATUS
HMAC_SHA256_quick(MOC_HASH(hwAccelDescr hwAccelCtx)
                  const ubyte* pKey, sbyte4 keyLen,
                  const ubyte* pText, sbyte4 textLen,
                  ubyte result[SHA256_RESULT_SIZE])
{
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    return CRYPTO_INTERFACE_HmacQuick(MOC_HASH(hwAccelCtx) pKey, keyLen, pText, textLen, result, &SHA256Suite);
#else
    return HmacQuick(MOC_HASH(hwAccelCtx) pKey, keyLen, pText, textLen, result, &SHA256Suite);
#endif
}
#endif /* __DISABLE_DIGICERT_SHA256__ */

#ifndef __DISABLE_DIGICERT_SHA384__
static BulkHashAlgo SHA384Suite =
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    { SHA384_RESULT_SIZE/*48*/, SHA384_BLOCK_SIZE, CRYPTO_INTERFACE_SHA512_allocDigest, CRYPTO_INTERFACE_SHA512_freeDigest,
      (BulkCtxInitFunc) CRYPTO_INTERFACE_SHA384_initDigest, (BulkCtxUpdateFunc) CRYPTO_INTERFACE_SHA512_updateDigest,
      (BulkCtxFinalFunc) CRYPTO_INTERFACE_SHA384_finalDigest, NULL, NULL, NULL, ht_sha384 };
#else
    { SHA384_RESULT_SIZE/*48*/, SHA384_BLOCK_SIZE, SHA384_allocDigest, SHA384_freeDigest,
      (BulkCtxInitFunc)SHA384_initDigest, (BulkCtxUpdateFunc)SHA384_updateDigest, (BulkCtxFinalFunc)SHA384_finalDigest, NULL, NULL, NULL, ht_sha384 };
#endif

static MSTATUS
HMAC_SHA384_quick(MOC_HASH(hwAccelDescr hwAccelCtx)
                  const ubyte* pKey, sbyte4 keyLen,
                  const ubyte* pText, sbyte4 textLen,
                  ubyte result[SHA384_RESULT_SIZE])
{
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    return CRYPTO_INTERFACE_HmacQuick(MOC_HASH(hwAccelCtx) pKey, keyLen, pText, textLen, result, &SHA384Suite);
#else
    return HmacQuick(MOC_HASH(hwAccelCtx) pKey, keyLen, pText, textLen, result, &SHA384Suite);
#endif
}
#endif /* __DISABLE_DIGICERT_SHA384__ */

#ifndef __DISABLE_DIGICERT_SHA512__
static BulkHashAlgo SHA512Suite =
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    { SHA512_RESULT_SIZE/*64*/, SHA512_BLOCK_SIZE, CRYPTO_INTERFACE_SHA512_allocDigest, CRYPTO_INTERFACE_SHA512_freeDigest,
      (BulkCtxInitFunc) CRYPTO_INTERFACE_SHA512_initDigest, (BulkCtxUpdateFunc) CRYPTO_INTERFACE_SHA512_updateDigest,
      (BulkCtxFinalFunc) CRYPTO_INTERFACE_SHA512_finalDigest, NULL, NULL, NULL, ht_sha512 };
#else
    { SHA512_RESULT_SIZE/*64*/, SHA512_BLOCK_SIZE, SHA512_allocDigest, SHA512_freeDigest,
      (BulkCtxInitFunc)SHA512_initDigest, (BulkCtxUpdateFunc)SHA512_updateDigest, (BulkCtxFinalFunc)SHA512_finalDigest, NULL, NULL, NULL, ht_sha512 };
#endif

static MSTATUS
HMAC_SHA512_quick(MOC_HASH(hwAccelDescr hwAccelCtx)
                  const ubyte* pKey, sbyte4 keyLen,
                  const ubyte* pText, sbyte4 textLen,
                  ubyte result[SHA512_RESULT_SIZE])
{
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    return CRYPTO_INTERFACE_HmacQuick(MOC_HASH(hwAccelCtx) pKey, keyLen, pText, textLen, result, &SHA512Suite);
#else
    return HmacQuick(MOC_HASH(hwAccelCtx) pKey, keyLen, pText, textLen, result, &SHA512Suite);
#endif
}
#endif /* __DISABLE_DIGICERT_SHA512__ */


#if defined(__ENABLE_DIGICERT_IPSEC_SERVICE__)

/*------------------------------------------------------------------*/

#if defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__)

static hwAccelDescr m_hwAccelCtx[2] = { 0 };

extern MSTATUS
IPSEC_getHwAccelChannel(hwAccelDescr *pHwAccelCtx, intBoolean bIn)
{
    MSTATUS status = OK;

    if (NULL == pHwAccelCtx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_HARNESS__
    if (0 == m_hwAccelCtx[bIn ? 1 : 0])
    {
        status = ERR_HARDWARE_ACCEL_CREATE_CTX;
        goto exit;
    }
#endif
    *pHwAccelCtx = m_hwAccelCtx[bIn ? 1 : 0];

exit:
    return status;
}

extern MSTATUS
IPSEC_releaseHwAccelChannel(hwAccelDescr *pHwAccelCtx)
{
    MSTATUS status = OK;

    if (NULL == pHwAccelCtx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ((*pHwAccelCtx != m_hwAccelCtx[0]) &&
        (*pHwAccelCtx != m_hwAccelCtx[1]))
    {
        status = ERR_HARDWARE_ACCEL_BAD_CTX;
        goto exit;
    }

    *pHwAccelCtx = 0;

exit:
    return status;
}

#endif /* defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) */


/*------------------------------------------------------------------*/

extern MSTATUS
IPSEC_cryptoInit(void)
{
    MSTATUS status = OK;

#if defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__)
    int i;
#endif

#if defined(__DISABLE_DIGICERT_INIT__)
#ifdef __ENABLE_DIGICERT_MEM_PART__
    if (OK > (status = MEM_PART_init()))
        goto exit;
#endif
    if (OK > (status = (MSTATUS) HARDWARE_ACCEL_INIT()))
    {
#ifdef __ENABLE_DIGICERT_MEM_PART__
        MEM_PART_uninit();
#endif
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (OK > (status = CRYPTO_INTERFACE_RANDOM_acquireContextEx(&g_pRandomContext, MODE_DRBG_CTR)))
#else
    if (OK > (status = RANDOM_acquireContext(&g_pRandomContext)))
#endif
    {
        HARDWARE_ACCEL_UNINIT();
#ifdef __ENABLE_DIGICERT_MEM_PART__
        MEM_PART_uninit();
#endif
        goto exit;
    }
#endif /* __DISABLE_DIGICERT_INIT__ */

#if defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__)
    for (i=0; i < 2; i++)
    {
        if (0 == m_hwAccelCtx[i])
        {
            if (OK > (status = (MSTATUS)
#if defined(__ENABLE_DIGICERT_HARNESS__) && defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
                HARNESS_openChannel(MOCANA_IPSEC, &(m_hwAccelCtx[i]), 4096, 2048)
#else
                HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_IPSEC, &(m_hwAccelCtx[i]))
#endif
                ))
            {
                IPSEC_cryptoUninit();
                goto exit;
            }
        }
    }
#endif

#if defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || \
    defined(__DISABLE_DIGICERT_INIT__)
exit:
#endif
    return status;
}

extern MSTATUS
IPSEC_cryptoUninit(void)
{
    MSTATUS status = OK;

#if defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__)
    int i;
    for (i=0; i < 2; i++)
    {
#ifdef __ENABLE_DIGICERT_HARNESS__
        if (0 != m_hwAccelCtx[i])
#endif
        {
            status = HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_IPSEC, &(m_hwAccelCtx[i]));
            m_hwAccelCtx[i] = 0;
        }
    }
#endif

#if defined(__DISABLE_DIGICERT_INIT__)

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    CRYPTO_INTERFACE_RANDOM_releaseContextEx(&g_pRandomContext);
#else
    RANDOM_releaseContext(&g_pRandomContext);
#endif

    HARDWARE_ACCEL_UNINIT();

#ifdef __ENABLE_DIGICERT_MEM_PART__
    MEM_PART_uninit();
#endif
#endif /* __DISABLE_DIGICERT_INIT__ */

    return status;
}


#endif /* defined(__ENABLE_DIGICERT_IPSEC_SERVICE__) */

