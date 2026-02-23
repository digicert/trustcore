/*
 * e_moc_EVP_ciphers.h
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

#ifndef E_MOC_EVP_CIPHERS_H
#define E_MOC_EVP_CIPHERS_H

#include <stdio.h>
#include <string.h>

#include <openssl/opensslconf.h>

#if OPENSSL_VERSION_NUMBER < 0x010101060

#include <openssl/engine.h>
#ifndef OPENSSL_NO_EC
#include <crypto/ec/ec_lcl.h>
#endif
#include <crypto/evp/evp_locl.h>
#if !defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) && !defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__)
#ifndef OPENSSL_NO_ECDSA
#include <crypto/ecdsa/ecs_locl.h>
#endif
#ifndef OPENSSL_NO_ECDH
#include <crypto/ecdh/ech_locl.h>
#endif
#endif
#ifdef __RTOS_VXWORKS__
#include <openssl/pem.h>
#else
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__)
#include <openssl/pem.h>
#else
#include <crypto/pem/pem.h>
#endif
#endif

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__)
#include <crypto/bn/bn_lcl.h>
#include <crypto/dh/dh_locl.h>
#include <crypto/dsa/dsa_locl.h>
#include <crypto/rsa/rsa_locl.h>

#include <internal/evp_int.h>
#include <internal/x509_int.h>
#include <internal/asn1_int.h>
#endif

#else

#include <include/openssl/pem.h>
#include <include/openssl/x509.h>
#include <include/openssl/engine.h>
#include <include/openssl/pkcs12.h>
#ifdef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
#include <include/openssl/rand.h>
#endif

#include <include/crypto/evp.h>
#include <include/crypto/rand.h>
#include <include/crypto/asn1.h>
#include <include/crypto/x509.h>

#include <crypto/evp/evp_local.h>
#include <crypto/bn/bn_local.h>
#include <crypto/dsa/dsa_local.h>
#include <crypto/dh/dh_local.h>
#include <crypto/rsa/rsa_local.h>
#include <crypto/ec/ec_local.h>

#endif /* OPENSSL_VERSION_NUMBER < 0x010101060 */

#include "compat_funcs.h"
#include "mocana_glue.h"

#ifndef AES_BLOCK_SIZE
#define AES_BLOCK_SIZE 16
#endif

#ifndef AES_KEY_SIZE_128
#define AES_KEY_SIZE_128 16
#endif

#ifndef AES_IV_LEN
#define AES_IV_LEN       16
#endif

# ifdef MOC_EVP_DEBUG
#  define DIGI_EVP_DGB(x, ...) fprintf(stderr, "MOC_EVP_DBG: " x, __VA_ARGS__)
#  define DIGI_EVP_INFO(x, ...) fprintf(stderr, "DIGI_EVP_INFO: " x, __VA_ARGS__)
#  define DIGI_EVP_WARN(x, ...) fprintf(stderr, "DIGI_EVP_WARN: " x, __VA_ARGS__)
# else
#  define DIGI_EVP_DGB(x, ...)
#  define DIGI_EVP_INFO(x, ...)
#  define DIGI_EVP_WARN(x, ...)
# endif

# define DIGI_EVP_ERR(x, ...) fprintf(stderr, "DIGI_EVP_ERR: " x, __VA_ARGS__)
# define DIGI_EVP_PERR(x, ...) \
                do { \
                    fprintf(stderr, "DIGI_EVP_PERR: " x, __VA_ARGS__); \
                    perror(NULL); \
                } while(0)
# define DIGI_EVP_PWARN(x, ...) \
                do { \
                    fprintf(stderr, "DIGI_EVP_PERR: " x, __VA_ARGS__); \
                    perror(NULL); \
                } while(0)

/* Note chacha20_poly1305 aead has its own EVP methods so is not part of the below macro */
#define IS_AEAD_CIPHER(ctx) \
        ((EVP_CIPHER_CTX_nid(ctx) == NID_aes_128_gcm) || (EVP_CIPHER_CTX_nid(ctx) == NID_aes_128_ccm) || \
        (EVP_CIPHER_CTX_nid(ctx) == NID_aes_192_gcm) || (EVP_CIPHER_CTX_nid(ctx) == NID_aes_192_ccm) || \
        (EVP_CIPHER_CTX_nid(ctx) == NID_aes_256_gcm) || (EVP_CIPHER_CTX_nid(ctx) == NID_aes_256_ccm))

#define IS_AES_CTR_CIPHER(ctx) \
        ((EVP_CIPHER_CTX_nid(ctx) == NID_aes_128_ctr) || (EVP_CIPHER_CTX_nid(ctx) == NID_aes_192_ctr) || \
        (EVP_CIPHER_CTX_nid(ctx) == NID_aes_256_ctr))

#define IS_AES_XTS_CIPHER(ctx) \
        ((EVP_CIPHER_CTX_nid(ctx) == NID_aes_128_xts) || (EVP_CIPHER_CTX_nid(ctx) == NID_aes_256_xts))

#endif /* E_MOC_EVP_CIPHERS_H */
