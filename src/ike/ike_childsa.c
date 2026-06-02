/**
 * @file  ike_childsa.c
 * @brief IKE Child SA (Phase 2) processing.
 *
 * @details    IKEv1 Quick Mode and IKEv2 Child SA cryptographic suites.
 * @since      1.41
 * @version    6.5.1 and later
 * @flags      Compilation flags required:
 *     To enable this file's functions, one of the following flags must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_IKE_SERVER__
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

#include "../common/moptions.h"

#if defined(__ENABLE_DIGICERT_IKE_SERVER__) || defined(__ENABLE_DIGICERT_PFKEY__)

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
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
#include "../crypto/crypto.h"
#include "../crypto/hmac.h"
#include "../crypto/des.h"
#include "../crypto/three_des.h"
#include "../crypto/blowfish.h"
#include "../crypto/aes.h"
#include "../crypto/aes_xcbc_mac_96.h"
#include "../harness/harness.h"
#include "../ipsec/ipsec_defs.h"
#include "../ike/ike.h"
#include "../ike/ike_defs.h"
#include "../ike/ike_childsa.h"


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_PFKEY__
/* Warning: Must update CHILDSA_ENCRKEY_MAX and CHILDSA_AUTHKEY_MAX
   in "ike_childsa.h" when new PF_KEY algorithms are supported and
   added to this file.
 */
#define PFKEY_SUP 0
#else
#define PFKEY_SUP
#endif

/*------------------------------------------------------------------*/

#if defined(__ENABLE_ALL_DEBUGGING__) && defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__)
#define ALGONAME(_n) (sbyte *)_n,
#else
#define ALGONAME(_n)
#endif

#define KEYLEN(_kl) (_kl), (_kl), TRUE
#define KEYLENS(_kl, _klend) (_kl), (_klend), FALSE
#define VARKEYLEN(_kl) (_kl), (_kl), FALSE


static CHILDSA_encrInfo mEncrInfo[] =
{/* { name,
      oTfmId,       wTfmId,         oEncrAlgo,
      wKeyLen/End/Fixed,                    },
  */
#if !defined(__DISABLE_3DES_CIPHERS__) || defined(__ENABLE_DIGICERT_PFKEY__)
    { ALGONAME("3des")
      ESP_3DES,     ENCR_3DES,      IPSEC_ENCALG_3DES,
      KEYLEN(THREE_DES_KEY_LENGTH)/*24*/, 0, 0, 0, PFKEY_SUP },

#if defined(__ENABLE_2KEY_3DES_CIPHER__) || defined(__ENABLE_DIGICERT_PFKEY__)
    { ALGONAME("3des")
      ESP_3DES,     ENCR_3DES,      IPSEC_ENCALG_3DES,
      VARKEYLEN(2*DES_KEY_LENGTH)/*16*/, 0, 0, 0, PFKEY_SUP },
#endif
#endif
#if !defined(__DISABLE_AES_CIPHERS__) || defined(__ENABLE_DIGICERT_PFKEY__)
#if !defined(__DISABLE_AES128_CIPHER__) || defined(__ENABLE_DIGICERT_PFKEY__)
    { ALGONAME("aes")
      ESP_AES,      ENCR_AES_CBC,   IPSEC_ENCALG_AES,
      VARKEYLEN(16), 0, 0, 0, PFKEY_SUP },
    { ALGONAME("ctr")
      ESP_AES_CTR,  ENCR_AES_CTR,   IPSEC_ENCALG_AES_CTR,
      VARKEYLEN(16), 4, 0, 0, PFKEY_SUP },
#if defined(__ENABLE_DIGICERT_GCM__) || defined(__ENABLE_DIGICERT_PFKEY__)
    { ALGONAME("gcm-16")
      ESP_AES_GCM_16, ENCR_AES_GCM_16, IPSEC_ENCALG_AES_GCM,
      VARKEYLEN(16), 4, 16, 0, PFKEY_SUP  },
    { ALGONAME("gcm-12")
      ESP_AES_GCM_12, ENCR_AES_GCM_12, IPSEC_ENCALG_AES_GCM,
      VARKEYLEN(16), 4, 12, 0, PFKEY_SUP },
    { ALGONAME("gcm-8")
      ESP_AES_GCM_8, ENCR_AES_GCM_8, IPSEC_ENCALG_AES_GCM,
      VARKEYLEN(16), 4, 8, 0, PFKEY_SUP },
    { ALGONAME("gmac")
      ESP_NULL_AES_GMAC, ENCR_NULL_AES_GMAC, IPSEC_ENCALG_AES_GMAC,
      VARKEYLEN(16), 4, 16, TRUE, PFKEY_SUP},
#endif /* defined(__ENABLE_DIGICERT_GCM__) || defined(__ENABLE_DIGICERT_PFKEY__) */
#if !defined(__DISABLE_AES_CCM__)
    { ALGONAME("ccm-16")
      ESP_AES_CCM_16, ESP_AES_CCM_16, IPSEC_ENCALG_AES_CCM,
      VARKEYLEN(16), 3, 16, 0, PFKEY_SUP },
    { ALGONAME("ccm-12")
      ESP_AES_CCM_12, ESP_AES_CCM_12, IPSEC_ENCALG_AES_CCM,
      VARKEYLEN(16), 3, 12, 0, PFKEY_SUP },
    { ALGONAME("ccm-8")
      ESP_AES_CCM_8, ESP_AES_CCM_8, IPSEC_ENCALG_AES_CCM,
      VARKEYLEN(16), 3, 8, 0, PFKEY_SUP },
#endif /* !defined(__DISABLE_AES_CCM__) */
#endif /* !defined(__DISABLE_AES128_CIPHER__) || defined(__ENABLE_DIGICERT_PFKEY__) */

#if !defined(__DISABLE_AES192_CIPHER__) || defined(__ENABLE_DIGICERT_PFKEY__)
    { ALGONAME("aes")
      ESP_AES,      ENCR_AES_CBC,   IPSEC_ENCALG_AES,
      VARKEYLEN(24), 0, 0, 0, PFKEY_SUP },
    { ALGONAME("ctr")
      ESP_AES_CTR,  ENCR_AES_CTR,   IPSEC_ENCALG_AES_CTR,
      VARKEYLEN(24), 4, 0, 0, PFKEY_SUP },
#if defined(__ENABLE_DIGICERT_GCM__) || defined(__ENABLE_DIGICERT_PFKEY__)
    { ALGONAME("gcm-16")
      ESP_AES_GCM_16, ENCR_AES_GCM_16, IPSEC_ENCALG_AES_GCM,
      VARKEYLEN(24), 4, 16, 0, PFKEY_SUP },
    { ALGONAME("gcm-12")
      ESP_AES_GCM_12, ENCR_AES_GCM_12, IPSEC_ENCALG_AES_GCM,
      VARKEYLEN(24), 4, 12, 0, PFKEY_SUP },
    { ALGONAME("gcm-8")
      ESP_AES_GCM_8, ENCR_AES_GCM_8, IPSEC_ENCALG_AES_GCM,
      VARKEYLEN(24), 4, 8, 0, PFKEY_SUP },
    { ALGONAME("gmac")
      ESP_NULL_AES_GMAC, ENCR_NULL_AES_GMAC, IPSEC_ENCALG_AES_GMAC,
      VARKEYLEN(24), 4, 16, TRUE, PFKEY_SUP },
#endif
#if !defined(__DISABLE_AES_CCM__)
    { ALGONAME("ccm-16")
      ESP_AES_CCM_16, ESP_AES_CCM_16, IPSEC_ENCALG_AES_CCM,
      VARKEYLEN(24), 3, 16, 0, PFKEY_SUP },
    { ALGONAME("ccm-12")
      ESP_AES_CCM_12, ESP_AES_CCM_12, IPSEC_ENCALG_AES_CCM,
      VARKEYLEN(24), 3, 12, 0, PFKEY_SUP },
    { ALGONAME("ccm-8")
      ESP_AES_CCM_8, ESP_AES_CCM_8, IPSEC_ENCALG_AES_CCM,
      VARKEYLEN(24), 3, 8, 0, PFKEY_SUP },
#endif /* !defined(__DISABLE_AES_CCM__) */
#endif /* !defined(__DISABLE_AES192_CIPHER__) || defined(__ENABLE_DIGICERT_PFKEY__) */
#if !defined(__DISABLE_AES256_CIPHER__) || defined(__ENABLE_DIGICERT_PFKEY__)
    { ALGONAME("aes")
      ESP_AES,      ENCR_AES_CBC,   IPSEC_ENCALG_AES,
      VARKEYLEN(32), 0, 0, 0, PFKEY_SUP },
    { ALGONAME("ctr")
      ESP_AES_CTR,  ENCR_AES_CTR,   IPSEC_ENCALG_AES_CTR,
      VARKEYLEN(32), 4, 0, 0, PFKEY_SUP },
#if defined(__ENABLE_DIGICERT_GCM__) || defined(__ENABLE_DIGICERT_PFKEY__)
    { ALGONAME("gcm-16")
      ESP_AES_GCM_16, ENCR_AES_GCM_16, IPSEC_ENCALG_AES_GCM,
      VARKEYLEN(32), 4, 16, 0, PFKEY_SUP },
    { ALGONAME("gcm-12")
      ESP_AES_GCM_12, ENCR_AES_GCM_12, IPSEC_ENCALG_AES_GCM,
      VARKEYLEN(32), 4, 12, 0, PFKEY_SUP },
    { ALGONAME("gcm-8")
      ESP_AES_GCM_8, ENCR_AES_GCM_8, IPSEC_ENCALG_AES_GCM,
      VARKEYLEN(32), 4, 8, 0, PFKEY_SUP },
    { ALGONAME("gmac")
      ESP_NULL_AES_GMAC, ENCR_NULL_AES_GMAC, IPSEC_ENCALG_AES_GMAC,
      VARKEYLEN(32), 4, 16, TRUE, PFKEY_SUP },
#endif
#if !defined(__DISABLE_AES_CCM__)
    { ALGONAME("ccm-16")
      ESP_AES_CCM_16, ESP_AES_CCM_16, IPSEC_ENCALG_AES_CCM,
      VARKEYLEN(32), 3, 16, 0, PFKEY_SUP },
    { ALGONAME("ccm-12")
      ESP_AES_CCM_12, ESP_AES_CCM_12, IPSEC_ENCALG_AES_CCM,
      VARKEYLEN(32), 3, 12, 0, PFKEY_SUP },
    { ALGONAME("ccm-8")
      ESP_AES_CCM_8, ESP_AES_CCM_8, IPSEC_ENCALG_AES_CCM,
      VARKEYLEN(32), 3, 8, 0, PFKEY_SUP },

#endif /* !defined(__DISABLE_AES_CCM__) */
#endif /* !defined(__DISABLE_AES256_CIPHER__) || defined(__ENABLE_DIGICERT_PFKEY__) */
#endif /* !defined(__DISABLE_AES_CIPHERS__) || defined(__ENABLE_DIGICERT_PFKEY__) */

#if ((defined(__ENABLE_DIGICERT_CHACHA20__) && defined(__ENABLE_DIGICERT_POLY1305__)) || \
        defined(__ENABLE_DIGICERT_PFKEY__))
    { ALGONAME("chacha20-poly1305")
      ESP_CHACHA20_POLY1305, ESP_CHACHA20_POLY1305, IPSEC_ENCALG_CHACHA20_POLY1305,
      KEYLEN(32), 4, 16, 0, PFKEY_SUP },
#endif
#if defined(__ENABLE_BLOWFISH_CIPHERS__) || defined(__ENABLE_DIGICERT_PFKEY__)
    { ALGONAME("blowfish")
      ESP_BLOWFISH, ENCR_BLOWFISH,  IPSEC_ENCALG_BLOWFISH,
      KEYLENS(4, MAXKEYBYTES)/*4...56*/ , 0, 0, 0, PFKEY_SUP },
#endif
#if defined(__ENABLE_DES_CIPHER__) || defined(__ENABLE_DIGICERT_PFKEY__)
    { ALGONAME("des")
      ESP_DES,      ENCR_DES,       IPSEC_ENCALG_DES,
      KEYLEN(DES_KEY_LENGTH)/*8*/ , 0, 0, 0, PFKEY_SUP },
#endif
#if defined(__ENABLE_DIGICERT_PFKEY__)
    { ALGONAME("null")
      ESP_NULL,     ENCR_NULL,      0,
      KEYLEN(0), 0, 0, 0, PFKEY_SUP },
#endif
};

#define NUM_ENCR_ALGOS (sizeof(mEncrInfo)/sizeof(CHILDSA_encrInfo))


/*------------------------------------------------------------------*/

static CHILDSA_authInfo mAuthInfo[] =
{/* { name,
      wAuthAlgo,                    oTfmId,
      wTfmId,                       oAuthAlgo,
      wKeyLen                       },
  */
#ifdef __ENABLE_DIGICERT_BLAKE_2B__
    { ALGONAME("blake2b")
      AUTH_ALGORITHM_HMAC_BLAKE2_2B,    AH_BLAKE2B,
      AUTH_HMAC_BLAKE2_2B,              IPSEC_AUTHALG_BLAKE2_2B,
      32, PFKEY_SUP },
#endif
#ifdef __ENABLE_DIGICERT_BLAKE_2S__
    { ALGONAME("blake2s")
      AUTH_ALGORITHM_HMAC_BLAKE2_2S,    AH_BLAKE2S,
      AUTH_HMAC_BLAKE2_2S,              IPSEC_AUTHALG_BLAKE2_2S,
      32, PFKEY_SUP },
#endif
    { ALGONAME("sha1")
      AUTH_ALGORITHM_HMAC_SHA,      AH_SHA,
      AUTH_HMAC_SHA1_96,            IPSEC_AUTHALG_SHA1,
      SHA_HASH_RESULT_SIZE/*20*/, PFKEY_SUP },

    { ALGONAME("md5")
      AUTH_ALGORITHM_HMAC_MD5,      AH_MD5,
      AUTH_HMAC_MD5_96,             IPSEC_AUTHALG_MD5,
      MD5_DIGESTSIZE/*16*/, PFKEY_SUP },

#if !defined(__DISABLE_AES_CIPHERS__) || defined(__ENABLE_DIGICERT_PFKEY__)
#ifndef __DISABLE_AES_XCBC_CIPHER__
    { ALGONAME("aes-xcbc")
      AUTH_ALGORITHM_AES_XCBC_MAC,  AH_AES_XCBC,
      AUTH_AES_XCBC_96,             IPSEC_AUTHALG_AES,
      AES_BLOCK_SIZE/*16*/, PFKEY_SUP },
#endif
#endif
#if !defined(__DISABLE_DIGICERT_SHA256__) || defined(__ENABLE_DIGICERT_PFKEY__)
    { ALGONAME("sha2-256")
      AUTH_ALGORITHM_HMAC_SHA2_256, AH_SHA2_256,
      AUTH_HMAC_SHA2_256_128,       IPSEC_AUTHALG_SHA256,
      SHA256_RESULT_SIZE/*32*/, PFKEY_SUP },
#endif
#if !defined(__DISABLE_DIGICERT_SHA384__) || defined(__ENABLE_DIGICERT_PFKEY__)
    { ALGONAME("sha2-384")
      AUTH_ALGORITHM_HMAC_SHA2_384, AH_SHA2_384,
      AUTH_HMAC_SHA2_384_192,       IPSEC_AUTHALG_SHA384,
      SHA384_RESULT_SIZE/*48*/, PFKEY_SUP },
#endif
#if !defined(__DISABLE_DIGICERT_SHA512__) || defined(__ENABLE_DIGICERT_PFKEY__)
    { ALGONAME("sha2-512")
      AUTH_ALGORITHM_HMAC_SHA2_512, AH_SHA2_512,
      AUTH_HMAC_SHA2_512_256,       IPSEC_AUTHALG_SHA512,
      SHA512_RESULT_SIZE/*64*/, PFKEY_SUP },
#endif
};

#define NUM_AUTH_ALGOS (sizeof(mAuthInfo)/sizeof(CHILDSA_authInfo))


/*------------------------------------------------------------------*/

extern CHILDSA_encrInfo*
CHILDSA_getEncrAlgo(sbyte4 i)
{
    CHILDSA_encrInfo *pEncrAlgo = NULL;

    if ((0 <= i) && ((sbyte4) NUM_ENCR_ALGOS > i))
        pEncrAlgo = &(mEncrInfo[i]);

    return pEncrAlgo;
} /* CHILDSA_getEncrAlgo */

/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_CONSTRAINT_CIPHER__
static ubyte2 CHILDSA_cipherEffectiveBitStrengthIPSec(ubyte2 wEncrAlgo, ubyte2 wKeyLen)
{
    ubyte2 bitStrength = 0;

    switch(wEncrAlgo)
    {
        case IPSEC_ENCALG_DES:
            bitStrength = 56;
            break;
        case IPSEC_ENCALG_3DES:
            bitStrength = 112;
            if (wKeyLen == 16)
            {
                bitStrength = 80;
            }
            break;
        case IPSEC_ENCALG_BLOWFISH:
            if (0 == wKeyLen || wKeyLen >= 16)
            {
                bitStrength = 128;
            }
            else
            {
                bitStrength = 8*wKeyLen;
            }
            break;
        case IPSEC_ENCALG_AES:
        case IPSEC_ENCALG_AES_CTR:
        case IPSEC_ENCALG_AES_CCM:
        case IPSEC_ENCALG_AES_GCM:
        case IPSEC_ENCALG_AES_GMAC:
            if (32 == wKeyLen || 0 == wKeyLen)
            {
                bitStrength = 256;
            }
            else if (16 == wKeyLen)
            {
                bitStrength = 128;
            }
            else if (24 == wKeyLen)
            {
                bitStrength = 192;
            }
            break;
        case IPSEC_ENCALG_CHACHA20_POLY1305:
            bitStrength = 256;
            break;
        default:
            break;
    };

    return bitStrength;
}

/*------------------------------------------------------------------*/

static ubyte2 CHILDSA_cipherMaxKeyLengthWithConstraintIPSec(ubyte2 oEncrAlgo, ubyte2 wKeyLenMin, ubyte2 wKeyLenMax, ubyte2 maxStrength)
{
    ubyte2 keyLength = 0;
    ubyte2 strength;

    strength = CHILDSA_cipherEffectiveBitStrengthIPSec(oEncrAlgo, wKeyLenMax);
    if (wKeyLenMax > 0 && wKeyLenMin == wKeyLenMax && strength > maxStrength)
    {
        keyLength = 0;
        goto exit;
    }

    keyLength = wKeyLenMax;
    switch(oEncrAlgo)
    {
        case IPSEC_ENCALG_DES:
            if (keyLength == 0)
                keyLength = 8;

            if (strength > maxStrength)
            {
                keyLength = 0;
            }
            break;
        case IPSEC_ENCALG_3DES:
            if (keyLength == 0)
                keyLength = 24;
            if (strength <= maxStrength)
            {
                goto exit;
            }

            keyLength = 16;

            strength = CHILDSA_cipherEffectiveBitStrengthIPSec(oEncrAlgo, keyLength);
            if (strength > maxStrength)
            {
                keyLength = 0;
            }
            break;
        case IPSEC_ENCALG_BLOWFISH:
            if (keyLength == 0)
                keyLength = 56;
            while (4 <= keyLength)
            {
                strength = CHILDSA_cipherEffectiveBitStrengthIPSec(oEncrAlgo, keyLength);
                if (strength <= maxStrength)
                  break;

                keyLength -= 4;
            }

            if (strength > maxStrength)
            {
                keyLength = 0;
            }
            break;
        case IPSEC_ENCALG_AES:
        case IPSEC_ENCALG_AES_CTR:
        case IPSEC_ENCALG_AES_CCM:
        case IPSEC_ENCALG_AES_GCM:
        case IPSEC_ENCALG_AES_GMAC:
            if (keyLength == 0)
                keyLength = 32;
            while (keyLength >= 16)
            {
                strength = CHILDSA_cipherEffectiveBitStrengthIPSec(oEncrAlgo, keyLength);
                if (strength <= maxStrength)
                  break;

                keyLength -= 8;
            }

            if (strength > maxStrength)
            {
                keyLength = 0;
            }
            break;
        case IPSEC_ENCALG_CHACHA20_POLY1305:
            keyLength = 32;
            if (strength > maxStrength)
            {
                keyLength = 0;
            }
            break;
    };
exit:
    return keyLength;
}

/*------------------------------------------------------------------*/

extern ubyte2 CHILDSA_cipherEffectiveBitStrength(ubyte2 wEncrAlgo, ubyte2 wKeyLen)
{
    ubyte2 bitStrength = 0;

    switch(wEncrAlgo)
    {
        case ENCR_DES:
            bitStrength = 56;
            break;
        case ENCR_3DES:
            bitStrength = 112;
            if (wKeyLen == 16)
            {
                bitStrength = 80;
            }
            break;
        case ENCR_BLOWFISH:
            if (0 == wKeyLen || wKeyLen >= 16)
            {
                bitStrength = 128;
            }
            else
            {
                bitStrength = 8*wKeyLen;
            }
            break;
        case ENCR_NULL:
            bitStrength = 0;
            break;
        case ENCR_AES_CBC:
        case ENCR_AES_CTR:
        case ENCR_AES_CCM_8:
        case ENCR_AES_CCM_12:
        case ENCR_AES_CCM_16:
        case ENCR_AES_GCM_8:
        case ENCR_AES_GCM_12:
        case ENCR_AES_GCM_16:
        case ENCR_NULL_AES_GMAC:
            if (32 == wKeyLen || 0 == wKeyLen)
            {
                bitStrength = 256;
            }
            else if (16 == wKeyLen)
            {
                bitStrength = 128;
            }
            else if (24 == wKeyLen)
            {
                bitStrength = 192;
            }
            break;
        case ENCR_CHACHA20_POLY1305:
            bitStrength = 256;
            break;
        default:
            break;
    };

    return bitStrength;
}

/*------------------------------------------------------------------*/

extern ubyte2 CHILDSA_cipherMaxKeyLengthWithConstraint(ubyte2 oTfmId, ubyte2 wTfmId, ubyte2 oEncrAlgo, ubyte2 wKeyLenMin, ubyte2 wKeyLenMax, ubyte2 maxStrength)
{
    ubyte2 strength;
    ubyte2 keyLength = 0;
    ubyte2 tfmId = oTfmId;

    if (0 < wTfmId)
    {
        tfmId = wTfmId;
    }

    if (oTfmId == 0 && wTfmId == 0)
    {
        return CHILDSA_cipherMaxKeyLengthWithConstraintIPSec(oEncrAlgo, wKeyLenMin, wKeyLenMax, maxStrength);
    }

    strength = CHILDSA_cipherEffectiveBitStrength(tfmId, wKeyLenMax);
    if (wKeyLenMax > 0 && wKeyLenMin == wKeyLenMax && strength > maxStrength)
    {
        keyLength = 0;
        goto exit;
    }

    keyLength = wKeyLenMax;
        switch(tfmId)
    {
        case ENCR_DES:
            if (keyLength == 0)
                keyLength = 8;
            if (strength > maxStrength)
            {
                keyLength = 0;
            }
            break;
        case ENCR_3DES:
            if (keyLength == 0)
                keyLength = 24;
            if (strength <= maxStrength)
            {
                goto exit;
            }

            keyLength = 16;

            strength = CHILDSA_cipherEffectiveBitStrength(tfmId, keyLength);
            if (strength > maxStrength)
            {
                keyLength = 0;
            }
            break;
        case ENCR_BLOWFISH:
            if (keyLength == 0)
                keyLength = 56;
            while (4 <= keyLength)
            {
                strength = CHILDSA_cipherEffectiveBitStrength(tfmId, keyLength);
                if (strength <= maxStrength)
                  break;

                keyLength -= 4;
            }

            if (strength > maxStrength)
            {
                keyLength = 0;
            }
            break;
        case ENCR_NULL:
            keyLength = 0;
            break;
        case ENCR_AES_CBC:
        case ENCR_AES_CTR:
        case ENCR_AES_CCM_8:
        case ENCR_AES_CCM_12:
        case ENCR_AES_CCM_16:
        case ENCR_AES_GCM_8:
        case ENCR_AES_GCM_12:
        case ENCR_AES_GCM_16:
        case ENCR_NULL_AES_GMAC:
            if (keyLength == 0)
                keyLength = 32;
            while (keyLength >= 16)
            {
                strength = CHILDSA_cipherEffectiveBitStrength(tfmId, keyLength);
                if (strength <= maxStrength)
                  break;

                keyLength -= 8;
            }

            if (strength > maxStrength)
            {
                keyLength = 0;
            }
            break;
        case ENCR_CHACHA20_POLY1305:
            if (keyLength == 0)
                keyLength = 32;
            if (strength > maxStrength)
            {
                keyLength = 0;
            }
            break;
    };
exit:
    return keyLength;
}

#endif /* __DISABLE_DIGICERT_CONSTRAINT_CIPHER__ */

/*------------------------------------------------------------------*/

extern CHILDSA_encrInfo*
CHILDSA_findAeadAlgoWithConstraint
                    (ubyte2 maxBitStrength,
                     ubyte oTfmId,
                     ubyte2 wTfmId,
                     ubyte oEncrAlgo,
                     ubyte aeadTag,
                     ubyte2 wKeyLen, ubyte2 *pwKeyLen)
{
    CHILDSA_encrInfo *pEncrAlgo = NULL;
    ubyte4 i;

    CHILDSA_encrInfo* pEncrAlgoBest = NULL;
    ubyte2 wKeyLenBest = 0;

    for (i=0; i < NUM_ENCR_ALGOS; i++, pEncrAlgo = NULL)
    {
        pEncrAlgo = &(mEncrInfo[i]);

        if ((oTfmId == pEncrAlgo->oTfmId)       ||
            (wTfmId == pEncrAlgo->wTfmId)       ||
            (oEncrAlgo == pEncrAlgo->oEncrAlgo))
        {
            ubyte2 wKeyLenMin = pEncrAlgo->wKeyLen;
            ubyte2 wKeyLenMax = pEncrAlgo->wKeyLenEnd;

            if (maxBitStrength > 0)
            {
#ifndef __DISABLE_DIGICERT_CONSTRAINT_CIPHER__

              /* if key length is 0, no key length meets the bit strength constraint */
                ubyte2 keyLen = CHILDSA_cipherMaxKeyLengthWithConstraint(oTfmId, wTfmId, oEncrAlgo, wKeyLenMin, wKeyLenMax, maxBitStrength);
                if (0 == keyLen)
                {
                    /*  skip this cipher */
                    continue;
                }
                wKeyLenMax = keyLen;
#endif
            }

            if (aeadTag) /* specific AEAD tag size */
            {
                if (aeadTag != pEncrAlgo->oTagLen) /* mismatch */
                {
                    continue;
                }
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
                if (pEncrAlgoBest)
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
                pEncrAlgoBest = pEncrAlgo;
            }
        }
    } /* for */

    if (pwKeyLen && pEncrAlgoBest)
    {
        *pwKeyLen = wKeyLenBest;
        pEncrAlgo = pEncrAlgoBest;
    }

exit:
    return pEncrAlgo;
} /* CHILDSA_findAeadAlgoWithConstraint */


/*------------------------------------------------------------------*/

extern CHILDSA_encrInfo*
CHILDSA_findAeadAlgo
                    (ubyte oTfmId,
                     ubyte2 wTfmId,
                     ubyte oEncrAlgo,
                     ubyte aeadTag,
                     ubyte2 wKeyLen, ubyte2 *pwKeyLen)
{
    return CHILDSA_findAeadAlgoWithConstraint(0, oTfmId, wTfmId,
        oEncrAlgo, aeadTag, wKeyLen, pwKeyLen);
} /* CHILDSA_findEncrAlgo */


/*------------------------------------------------------------------*/

extern CHILDSA_authInfo*
CHILDSA_findAuthAlgo(ubyte2 wAuthAlgo,
                     ubyte oTfmId,
                     ubyte2 wTfmId,
                     ubyte oAuthAlgo)
{
    ubyte4 i;
    CHILDSA_authInfo *pAuthAlgo = NULL;

    for (i=0; i < NUM_AUTH_ALGOS; i++, pAuthAlgo = NULL)
    {
        pAuthAlgo = &(mAuthInfo[i]);

        if ((wAuthAlgo == pAuthAlgo->wAuthAlgo) ||
            (oTfmId == pAuthAlgo->oTfmId) ||
            (wTfmId == pAuthAlgo->wTfmId) ||
            (oAuthAlgo == pAuthAlgo->oAuthAlgo))
        {
            break;
        }
    }

    return pAuthAlgo;
} /* CHILDSA_findAuthAlgo */


/*------------------------------------------------------------------*/

extern CHILDSA_authInfo*
CHILDSA_getAuthAlgo(sbyte4 i)
{
    CHILDSA_authInfo *pAuthAlgo = NULL;

    if ((0 <= i) && ((sbyte4) NUM_AUTH_ALGOS > i))
        pAuthAlgo = &(mAuthInfo[i]);

    return pAuthAlgo;
} /* CHILDSA_getAuthAlgo */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_IPCOMP__

static CHILDSA_compInfo mCompInfo[] =
{/* { name,                 oTfmId          }, */
    { ALGONAME("lzs")       IPCOMP_LZS      },
};

#define NUM_COMP_ALGOS (sizeof(mCompInfo)/sizeof(CHILDSA_compInfo))


/*------------------------------------------------------------------*/

extern CHILDSA_compInfo*
CHILDSA_findCompAlgo(ubyte oTfmId)
{
    sbyte4 i;
    CHILDSA_compInfo *pCompAlgo = NULL;

    for (i=0; i < NUM_COMP_ALGOS; i++, pCompAlgo = NULL)
    {
        pCompAlgo = &(mCompInfo[i]);

        if (oTfmId == pCompAlgo->oTfmId)
        {
            break;
        }
    }

    return pCompAlgo;
} /* CHILDSA_findCompAlgo */


/*------------------------------------------------------------------*/

extern CHILDSA_compInfo*
CHILDSA_getCompAlgo(sbyte4 i)
{
    CHILDSA_compInfo *pCompAlgo = NULL;

    if ((0 <= i) && (NUM_COMP_ALGOS > i))
        pCompAlgo = &(mCompInfo[i]);

    return pCompAlgo;
} /* CHILDSA_getCompAlgo */

#endif /* __ENABLE_DIGICERT_IPCOMP__ */


#else
static void
dummy(void)
{
    return;
}
#endif /* defined(__ENABLE_DIGICERT_IKE_SERVER__) || defined(__ENABLE_DIGICERT_PFKEY__) */

