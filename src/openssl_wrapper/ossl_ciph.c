/*
 * ossl_ciph.c
 *
 * Copyright 2026 DigiCert Project Authors. All Rights Reserved.
 *
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt
 *   or https://www.digicert.com/master-services-agreement/
 *
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */
#define OPENSSL_SUPPRESS_DEPRECATED

/*
 * VxWorks7 & VxWorks6.9 have openssl .h files in different locations
 */
#ifdef __RTOS_VXWORKS__
#include <openssl/x509.h>
#include <openssl/pem.h>
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
#include <openssl/err.h>
#else /* !__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__ || __ENABLE_DIGICERT_OPENSSL_LIB_3_0__ */
#include <err.h>
#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__ || __ENABLE_DIGICERT_OPENSSL_LIB_3_0__ */
#else
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#else
#include "crypto/x509/x509.h"
#include <crypto/pem/pem.h>
#include <crypto/err/err.h>
#endif
#endif

#include "../common/moptions.h"
#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"

#include "ossl_types.h"

#include "../openssl_wrapper/ssl.h"
#include "../openssl_wrapper/ossl_ssl.h"

STACK_OF(SSL_CIPHER) *OSSL_sslCreateCipherList(const SSL_METHOD *ssl_method,
                                    const char *str,
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
                                    STACK_OF(SSL_CIPHER) *tls13_ciphersuites,
#endif
                                    STACK_OF(SSL_CIPHER) **cipher_list,
                                    STACK_OF(SSL_CIPHER) **cipher_list_by_id);

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)

# define OSSL_NELEM(x)    (sizeof(x)/sizeof((x)[0]))

const ssl_cipher_table ssl_cipher_table_cipher[SSL_ENC_NUM_IDX] = {
    {SSL_DES, NID_des_cbc},     /* SSL_ENC_DES_IDX 0 */
    {SSL_3DES, NID_des_ede3_cbc}, /* SSL_ENC_3DES_IDX 1 */
    {SSL_RC4, NID_rc4},         /* SSL_ENC_RC4_IDX 2 */
    {SSL_RC2, NID_rc2_cbc},     /* SSL_ENC_RC2_IDX 3 */
    {SSL_IDEA, NID_idea_cbc},   /* SSL_ENC_IDEA_IDX 4 */
    {SSL_eNULL, NID_undef},     /* SSL_ENC_NULL_IDX 5 */
    {SSL_AES128, NID_aes_128_cbc}, /* SSL_ENC_AES128_IDX 6 */
    {SSL_AES256, NID_aes_256_cbc}, /* SSL_ENC_AES256_IDX 7 */
    {SSL_CAMELLIA128, NID_camellia_128_cbc}, /* SSL_ENC_CAMELLIA128_IDX 8 */
    {SSL_CAMELLIA256, NID_camellia_256_cbc}, /* SSL_ENC_CAMELLIA256_IDX 9 */
    {SSL_eGOST2814789CNT, NID_gost89_cnt}, /* SSL_ENC_GOST89_IDX 10 */
    {SSL_SEED, NID_seed_cbc},   /* SSL_ENC_SEED_IDX 11 */
    {SSL_AES128GCM, NID_aes_128_gcm}, /* SSL_ENC_AES128GCM_IDX 12 */
    {SSL_AES256GCM, NID_aes_256_gcm}, /* SSL_ENC_AES256GCM_IDX 13 */
    {SSL_AES128CCM, NID_aes_128_ccm}, /* SSL_ENC_AES128CCM_IDX 14 */
    {SSL_AES256CCM, NID_aes_256_ccm}, /* SSL_ENC_AES256CCM_IDX 15 */
    {SSL_AES128CCM8, NID_aes_128_ccm}, /* SSL_ENC_AES128CCM8_IDX 16 */
    {SSL_AES256CCM8, NID_aes_256_ccm}, /* SSL_ENC_AES256CCM8_IDX 17 */
    {SSL_eGOST2814789CNT12, NID_gost89_cnt_12}, /* SSL_ENC_GOST8912_IDX 18 */
    {SSL_CHACHA20POLY1305, NID_chacha20_poly1305}, /* SSL_ENC_CHACHA_IDX 19 */
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    {SSL_ARIA128GCM, NID_aria_128_gcm}, /* SSL_ENC_ARIA128GCM_IDX 20 */
    {SSL_ARIA256GCM, NID_aria_256_gcm}, /* SSL_ENC_ARIA256GCM_IDX 21 */
#endif
};

/* NB: make sure indices in this table matches values above */
const ssl_cipher_table ssl_cipher_table_mac[SSL_MD_NUM_IDX] = {
    {SSL_MD5, NID_md5},         /* SSL_MD_MD5_IDX 0 */
    {SSL_SHA1, NID_sha1},       /* SSL_MD_SHA1_IDX 1 */
    {SSL_GOST94, NID_id_GostR3411_94}, /* SSL_MD_GOST94_IDX 2 */
    {SSL_GOST89MAC, NID_id_Gost28147_89_MAC}, /* SSL_MD_GOST89MAC_IDX 3 */
    {SSL_SHA256, NID_sha256},   /* SSL_MD_SHA256_IDX 4 */
    {SSL_SHA384, NID_sha384},   /* SSL_MD_SHA384_IDX 5 */
    {SSL_GOST12_256, NID_id_GostR3411_2012_256}, /* SSL_MD_GOST12_256_IDX 6 */
    {SSL_GOST89MAC12, NID_gost_mac_12}, /* SSL_MD_GOST89MAC12_IDX 7 */
    {SSL_GOST12_512, NID_id_GostR3411_2012_512}, /* SSL_MD_GOST12_512_IDX 8 */
    {0, NID_md5_sha1},          /* SSL_MD_MD5_SHA1_IDX 9 */
    {0, NID_sha224},            /* SSL_MD_SHA224_IDX 10 */
    {0, NID_sha512}             /* SSL_MD_SHA512_IDX 11 */
};

static const ssl_cipher_table ssl_cipher_table_kx[] = {
    {SSL_kRSA,      NID_kx_rsa},
    {SSL_kECDHE,    NID_kx_ecdhe},
    {SSL_kDHE,      NID_kx_dhe},
    {SSL_kECDHEPSK, NID_kx_ecdhe_psk},
    {SSL_kDHEPSK,   NID_kx_dhe_psk},
    {SSL_kRSAPSK,   NID_kx_rsa_psk},
    {SSL_kPSK,      NID_kx_psk},
    {SSL_kSRP,      NID_kx_srp},
    {SSL_kGOST,     NID_kx_gost},
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    {SSL_kANY,      NID_kx_any}
#endif
};

static const ssl_cipher_table ssl_cipher_table_auth[] = {
    {SSL_aRSA,    NID_auth_rsa},
    {SSL_aECDSA,  NID_auth_ecdsa},
    {SSL_aPSK,    NID_auth_psk},
    {SSL_aDSS,    NID_auth_dss},
    {SSL_aGOST01, NID_auth_gost01},
    {SSL_aGOST12, NID_auth_gost12},
    {SSL_aSRP,    NID_auth_srp},
    {SSL_aNULL,   NID_auth_null},
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    {SSL_aANY,    NID_auth_any}
#endif
};

#endif /* defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__) */

/**
 * Returns string which indicates the SSL/TLS protocol version that first
 * defined the cipher.  This is currently SSLv2 or TLSv1/SSLv3.  In some
 * cases it should possibly return "TLSv1.2" but does not; use
 * SSL_CIPHER_description() instead.  If cipher is NULL, "(NONE)" is returned.
 *
 * (from OpenSSL docs)
 */
char *SSL_CIPHER_get_version(const SSL_CIPHER *c)
{
    int i;

    if (c == NULL)
        return ("(NONE)");
    i = (int)(c->id >> 24L);
    if (i == 3)
        return ("TLSv1/SSLv3");
    else if (i == 2)
        return ("SSLv2");
    else
        return ("unknown");
}

/**
 * Returns a pointer to the name of cipher. If the argument is the NULL
 * pointer, a pointer to the constant value "NONE" is returned.
 *
 * (from OpenSSL docs)
 */
 const char  *SSL_CIPHER_get_name(const SSL_CIPHER *c)
{
    if (c != NULL)
        return (c->name);
    return ("(NONE)");
}

/**
 * Returns the number of secret bits used for cipher. If alg_bits is not NULL,
 * it contains the number of bits processed by the chosen algorithm. If
 * cipher is NULL, 0 is returned.
 *
 * (from OpenSSL docs)
 */
int SSL_CIPHER_get_bits(const SSL_CIPHER *c, int *alg_bits)
{
    int ret = 0;

    if (c != NULL) {
        if (alg_bits != NULL)
            *alg_bits = c->alg_bits;
        ret = c->strength_bits;
    }
    return (ret);
}

unsigned long SSL_CIPHER_get_id(const SSL_CIPHER *c)
{
    if (c != NULL)
        return c->id;
    return 0;
}

int SSL_set_cipher_list(SSL *s, const char *str)
{
    STACK_OF(SSL_CIPHER) *sk = NULL;
    ubyte4 i = 0;

    sk = OSSL_sslCreateCipherList(s->method, str,
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
                                  s->tls13_ciphersuites,
#endif
                                  &s->cipher_list,
                                  &s->cipher_list_by_id);

    if(NULL == sk)
    {
        return 0;
    }

    s->numCipherIds = sk_SSL_CIPHER_num(sk);

    if (0 == s->numCipherIds)
    {
        SSLerr(SSL_F_SSL_SET_CIPHER_LIST, SSL_R_NO_CIPHER_MATCH);
        return 0;
    }

    sk = s->cipher_list_by_id;
    for (i = 0; i < s->numCipherIds; i++)
    {
        s->cipherIds[i] = (ubyte2)(((SSL_CIPHER*)sk_SSL_CIPHER_value(sk,i))->id) & 0xFFFF;
    }

    return 1;
}

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)

/*------------------------------------------------------------------*/

static int ssl_cipher_info_find(const ssl_cipher_table * table,
                                size_t table_cnt, uint32_t mask)
{
    size_t i;
    for (i = 0; i < table_cnt; i++, table++) {
        if (table->mask == mask)
            return (int)i;
    }
    return -1;
}

#define ssl_cipher_info_lookup(table, x) \
    ssl_cipher_info_find(table, OSSL_NELEM(table), x)

/*------------------------------------------------------------------*/

int SSL_CIPHER_get_auth_nid(const SSL_CIPHER *c)
{
    int ret = NID_undef;
    int i;

    if (NULL == c)
    {
        goto exit;
    }

    i = ssl_cipher_info_lookup(ssl_cipher_table_auth, c->algorithm_auth);

    if (i == -1)
    {
        goto exit;
    }

    ret = ssl_cipher_table_auth[i].nid;

exit:

    return ret;
}

/*------------------------------------------------------------------*/

int SSL_CIPHER_get_digest_nid(const SSL_CIPHER *c)
{
    int ret = NID_undef;
    int i;

    if (NULL == c)
    {
        goto exit;
    }

    i = ssl_cipher_info_lookup(ssl_cipher_table_mac, c->algorithm_mac);

    if (i == -1)
    {
        goto exit;
    }

    ret = ssl_cipher_table_mac[i].nid;

exit:

    return ret;
}

/*------------------------------------------------------------------*/

int SSL_CIPHER_is_aead(const SSL_CIPHER *c)
{
    if (NULL == c)
    {
        return -1;
    }

    return (c->algorithm_mac & SSL_AEAD) ? 1 : 0;
}

/*------------------------------------------------------------------*/

int SSL_CIPHER_get_cipher_nid(const SSL_CIPHER *c)
{
    int ret = NID_undef;
    int i;

    if (c == NULL)
    {
        goto exit;
    }

    i = ssl_cipher_info_lookup(ssl_cipher_table_cipher, c->algorithm_enc);

    if (i == -1)
    {
        goto exit;
    }

    ret = ssl_cipher_table_cipher[i].nid;

exit:

    return ret;
}

/*------------------------------------------------------------------*/

int SSL_CIPHER_get_kx_nid(const SSL_CIPHER *c)
{
    int ret = NID_undef;
    int i;

    if (c == NULL)
    {
        goto exit;
    }

    i = ssl_cipher_info_lookup(ssl_cipher_table_kx, c->algorithm_mkey);

    if (i == -1)
    {
        goto exit;
    }

    ret = ssl_cipher_table_kx[i].nid;

exit:

    return ret;
}

/*------------------------------------------------------------------*/

#endif
