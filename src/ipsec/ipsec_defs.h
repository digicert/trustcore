/**
 * @file  ipsec_defs.h
 * @brief NanoSec IPsec definitions header.
 *
 * @details    This file contains IPsec constant definitions and enumerations.
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

#ifndef __IPSEC_DEFS_HEADER__
#define __IPSEC_DEFS_HEADER__


/*------------------------------------------------------------------*/
/* key sizes */

/* Note: Must update as needed (e.g. when new algorithms are added) */

#if !defined(__DISABLE_DIGICERT_SHA512__)
#define IPSEC_AUTHKEY_MAX       64  /* SHA512_RESULT_SIZE */    /* hmac-sha2-512-256 */
#define IPSEC_DIGEST_MAX        64
#define IPSEC_ICV_MAX           32  /* SHA512_RESULT_SIZE/2 */
#elif !defined(__DISABLE_DIGICERT_SHA384__)
#define IPSEC_AUTHKEY_MAX       48  /* SHA384_RESULT_SIZE */    /* hmac-sha2-384-128 */
#define IPSEC_DIGEST_MAX        48
#define IPSEC_ICV_MAX           24  /* SHA384_RESULT_SIZE/2 */
#elif !defined(__DISABLE_DIGICERT_SHA256__)
#define IPSEC_AUTHKEY_MAX       32  /* SHA256_RESULT_SIZE */    /* hmac-sha2-256-128 */
#define IPSEC_DIGEST_MAX        32
#define IPSEC_ICV_MAX           16  /* SHA256_RESULT_SIZE/2 */
#else
#define IPSEC_AUTHKEY_MAX       20  /* SHA_HASH_RESULT_SIZE */  /* hmac-sha1-96 */
#define IPSEC_DIGEST_MAX        20
  #define IPSEC_ICV_MAX         16
#endif

#ifndef __DISABLE_AES_CIPHERS__
#define IPSEC_IV_MAX            (16)/* AES_BLOCK_SIZE */        /* aes */
#else
#define IPSEC_IV_MAX            (8)
#endif

#if defined(__ENABLE_BLOWFISH_CIPHERS__)
#define IPSEC_ENCRKEY_MAX       (56)/* MAXKEYBYTES */           /* blowfish */
#elif !(defined(__DISABLE_AES256_CIPHER__) || defined(__DISABLE_AES_CIPHERS__))
#define IPSEC_ENCRKEY_MAX       (36)/* 32 + 4 (nonce/salt) */   /* aes-ctr-256 or aes-256-gcm/gmac */
/*#define IPSEC_ENCRKEY_MAX     (32)*/                          /* aes-256 */
#elif !(defined(__DISABLE_AES192_CIPHER__) || defined(__DISABLE_AES_CIPHERS__))
#define IPSEC_ENCRKEY_MAX       (28)/* 24 + 4 (nonce/salt) */   /* aes-ctr-192 or aes-192-gcm/gmac */
/*#define IPSEC_ENCRKEY_MAX     (24)*/                          /* aes-192 */
#elif !defined(__DISABLE_3DES_CIPHERS__)
#define IPSEC_ENCRKEY_MAX       (24)/*THREE_DES_KEY_LENGTH*/    /* 3des */
#elif !(defined(__DISABLE_AES128_CIPHER__) || defined(__DISABLE_AES_CIPHERS__))
#define IPSEC_ENCRKEY_MAX       (20)/* 16 + 4 (nonce/salt) */   /* aes-ctr-128 or aes-128-gcm/gmac */
/*#define IPSEC_ENCRKEY_MAX     (16)*/                          /* aes-128 */
#elif defined(__ENABLE_DES_CIPHER__)
#define IPSEC_ENCRKEY_MAX       (8) /* DES_KEY_LENGTH */        /* des */
#endif


/*------------------------------------------------------------------*/

/* auth. algorithm */
#define IPSEC_AUTHALG_ANY       (0)     /* for SPD */
#define IPSEC_AUTHALG_MD5       (1)
#define IPSEC_AUTHALG_SHA1      (2)
#define IPSEC_AUTHALG_AES       (3)     /* AES-XCBC-MAC-96 */
#define IPSEC_AUTHALG_SHA256    (4)
#define IPSEC_AUTHALG_SHA384    (5)
#define IPSEC_AUTHALG_SHA512    (6)
#define IPSEC_AUTHALG_BLAKE2_2B (7)
#define IPSEC_AUTHALG_BLAKE2_2S (8)

/* encryption algorithm */
#define IPSEC_ENCALG_ANY        (0)     /* for SPD */
#define IPSEC_ENCALG_DES        (1)
#define IPSEC_ENCALG_3DES       (2)
#define IPSEC_ENCALG_BLOWFISH   (3)
#define IPSEC_ENCALG_AES        (4)
#define IPSEC_ENCALG_AES_CTR    (5)
#define IPSEC_ENCALG_AES_GCM    (6)
#define IPSEC_ENCALG_AES_GMAC   (7)
#define IPSEC_ENCALG_AES_CCM    (8)
#define IPSEC_ENCALG_CHACHA20_POLY1305 (9)

/* IPsec mode */
#define IPSEC_MODE_DONTCARE     (0)
#define IPSEC_MODE_TRANSPORT    (1)     /* transport mode */
#define IPSEC_MODE_TUNNEL       (2)     /* tunnelling mode */

/* IPsec protocol - for SPD */
#define IPSEC_PROTO_AH          (0)     /* AH (auth only) */
#define IPSEC_PROTO_ESP         (1)     /* ESP encr (no auth) */
#define IPSEC_PROTO_ESP_AUTH    (2)     /* ESP encr & auth */
#define IPSEC_PROTO_ESP_NULL    (3)     /* ESP null-encr & auth */

/* IPsec action - for SPD */
#define IPSEC_ACTION_DROP       (1)     /* drop */
#define IPSEC_ACTION_APPLY      (2)     /* apply - protect outbound traffic */
#define IPSEC_ACTION_PERMIT     (3)     /* permit - protect inbound traffic */
#define IPSEC_ACTION_BYPASS     (4)     /* bypass */

/* IPsec direction - for SPD */
#define IPSEC_DIR_INBOUND       0x01
#define IPSEC_DIR_OUTBOUND      0x02
    /* Note: the above spec. is ignored by permit/apply. */
#define IPSEC_DIR_MIRRORED      0x10


#endif /* __IPSEC_DEFS_HEADER__ */

