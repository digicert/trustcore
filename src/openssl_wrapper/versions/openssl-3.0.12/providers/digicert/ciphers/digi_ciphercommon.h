/*
 * digi_ciphercommon.h
 *
 * Provider for OSSL 3.0 Adapted from OpenSSL provider code.
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
/*
 * Copyright 2019-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "openssl/params.h"
#include "openssl/core_dispatch.h"
#include "openssl/core_names.h"
#include "openssl/evp.h"
#include "internal/cryptlib.h"
#include "crypto/modes.h"
#include "openssl/evp.h"
#include "crypto/evp.h"
#include "openssl/aes.h"
#include "openssl/../../crypto/evp/evp_local.h"
#include "crypto/poly1305.h"

# define MAXCHUNK    ((size_t)1 << 30)
# define MAXBITCHUNK ((size_t)1 << (sizeof(size_t) * 8 - 4))

#define GENERIC_BLOCK_SIZE 16
#define MAX_CIPHER_KEY_SIZE   64  /* aes-xts requires double key size */
#define IV_STATE_UNINITIALISED 0  /* initial state is not initialized */
#define IV_STATE_BUFFERED      1  /* iv has been copied to the iv buffer */
#define IV_STATE_COPIED        2  /* iv has been copied from the iv buffer */
#define IV_STATE_FINISHED      3  /* the iv has been used - so don't reuse it */

#define PROV_CIPHER_FUNC(type, name, args) typedef type (* OSSL_##name##_fn)args

typedef struct dp_cipher_ctx_st DP_CIPHER_CTX;

/* Internal flags that can be queried */
#define PROV_CIPHER_FLAG_AEAD             0x0001
#define PROV_CIPHER_FLAG_CUSTOM_IV        0x0002
#define PROV_CIPHER_FLAG_CTS              0x0004
#define PROV_CIPHER_FLAG_TLS1_MULTIBLOCK  0x0008
#define PROV_CIPHER_FLAG_RAND_KEY         0x0010
/* Internal flags that are only used within the provider */
#define PROV_CIPHER_FLAG_VARIABLE_LENGTH  0x0100
#define PROV_CIPHER_FLAG_INVERSE_CIPHER   0x0200

/********************* CIPHER CTX for non-aead ***********************/

struct dp_cipher_ctx_st {
    block128_f block;
    union {
        cbc128_f cbc;
        ctr128_f ctr;
        ecb128_f ecb;
    } stream;

    unsigned int mode;
    size_t keylen;           /* key size (in bytes) */
    size_t ivlen;
    size_t blocksize;
    size_t bufsz;            /* Number of bytes in buf */
    unsigned int cts_mode;   /* Use to set the type for CTS modes */
    unsigned int pad : 1;    /* Whether padding should be used or not */
    unsigned int enc : 1;    /* Set to 1 for encrypt, or 0 otherwise */
    unsigned int iv_set : 1; /* Set when the iv is copied to the iv/oiv buffers */
    unsigned int updated : 1; /* Set to 1 during update for one shot ciphers */
    unsigned int variable_keylength : 1;
    unsigned int inverse_cipher : 1; /* set to 1 to use inverse cipher */
    unsigned int use_bits : 1; /* Set to 0 for cfb1 to use bits instead of bytes */

    unsigned int tlsversion; /* If TLS padding is in use the TLS version number */
    unsigned char *tlsmac;   /* tls MAC extracted from the last record */
    int alloced;             /*
                              * Whether the tlsmac data has been allocated or
                              * points into the user buffer.
                              */
    size_t tlsmacsize;       /* Size of the TLS MAC */
    int removetlspad;        /* Whether TLS padding should be removed or not */
    size_t removetlsfixed;   /*
                              * Length of the fixed size data to remove when
                              * processing TLS data (equals mac size plus
                              * IV size if applicable)
                              */

    /*
     * num contains the number of bytes of |iv| which are valid for modes that
     * manage partial blocks themselves.
     */
    unsigned int num;
    int isRc5;
    unsigned int rounds; /* for rc5, the number of rounds */

    /* The original value of the iv */
    unsigned char oiv[GENERIC_BLOCK_SIZE];
    /* Buffer of partial blocks processed via update calls */
    unsigned char buf[GENERIC_BLOCK_SIZE];
    unsigned char iv[GENERIC_BLOCK_SIZE];
    unsigned char key[MAX_CIPHER_KEY_SIZE]; /* 64 */
    unsigned int need_iv : 1;
    unsigned int need_dir : 1;
    unsigned int key_set : 1;
    unsigned int dir_set : 1;  /* enc or dec */
    unsigned int ctx_init : 1;
    const void *ks; /* Pointer to algorithm specific key data */
    OSSL_LIB_CTX *libctx;
    EVP_CIPHER_CTX *pEvpCtx;
};

/********************* CIPHER CTX for GCM ***********************/

#define GCM_IV_DEFAULT_SIZE 12 /* IV's for AES_GCM should normally be 12 bytes */
#define GCM_IV_MAX_SIZE     (1024 / 8)
#define GCM_TAG_MAX_SIZE    16

typedef struct dp_gcm_ctx_st
{
    unsigned int mode;          /* The mode that we are using */
    size_t keylen;
    size_t ivlen;
    size_t taglen;
    size_t tls_aad_pad_sz;
    size_t tls_aad_len;         /* TLS AAD length */
    uint64_t tls_enc_records;   /* Number of TLS records encrypted */

    /*
     * num contains the number of bytes of |iv| which are valid for modes that
     * manage partial blocks themselves.
     */
    size_t num;
    size_t bufsz;               /* Number of bytes in buf */
    uint64_t flags;

    unsigned int iv_state;      /* set to one of IV_STATE_XXX */
    unsigned int enc:1;         /* Set to 1 if we are encrypting or 0 otherwise */
    unsigned int pad:1;         /* Whether padding should be used or not */
    unsigned int key_set:1;     /* Set if key initialised */
    unsigned int iv_gen_rand:1; /* No IV was specified, so generate a rand IV */
    unsigned int iv_gen:1;      /* It is OK to generate IVs */

    unsigned char iv[GCM_IV_MAX_SIZE]; /* Buffer to use for IV's */
    unsigned char buf[AES_BLOCK_SIZE]; /* Buffer of partial blocks processed via update calls */
    unsigned char key[MAX_CIPHER_KEY_SIZE/2]; /* 32 */
    unsigned int dir_set:1;     /* enc or dec */
    unsigned int ctx_init:1;

    OSSL_LIB_CTX *libctx;    /* needed for rand calls */
    GCM128_CONTEXT gcm;
    ctr128_f ctr;
    const void *ks;
    EVP_CIPHER_CTX *pEvpCtx;

} DP_GCM_CTX;

/********************* CIPHER CTX for CCM ***********************/

typedef struct dp_ccm_st
{
    unsigned int enc : 1;
    unsigned int key_set : 1;  /* Set if key initialised */
    unsigned int iv_set : 1;   /* Set if an iv is set */
    unsigned int tag_set : 1;  /* Set if tag is valid */
    unsigned int len_set : 1;  /* Set if message length set */
    size_t l, m;               /* L and M parameters from RFC3610 */
    size_t keylen;
    size_t tls_aad_len;        /* TLS AAD length */
    size_t tls_aad_pad_sz;
    unsigned char iv[GENERIC_BLOCK_SIZE];
    unsigned char buf[GENERIC_BLOCK_SIZE];
    unsigned char key[MAX_CIPHER_KEY_SIZE/2]; /* 32 */
    unsigned int dir_set : 1;  /* enc or dec */
    unsigned int ctx_init : 1;
    CCM128_CONTEXT ccm_ctx;
    ccm128_f str;
    EVP_CIPHER_CTX *pEvpCtx;
} DP_CCM_CTX;

/********************* CIPHER CTX for CHACHAPOLY ***********************/

#define NO_TLS_PAYLOAD_LENGTH ((size_t)-1)
#define CHACHA20_POLY1305_IVLEN 12

typedef struct dp_chachapoly_st
{
    unsigned int enc : 1;
    unsigned int nonce[12 / 4];
    unsigned char tag[POLY1305_BLOCK_SIZE];
    unsigned char tls_aad[POLY1305_BLOCK_SIZE];
    struct { uint64_t aad, text; } len;
    unsigned int aad : 1;
    unsigned int mac_inited : 1;
    size_t tag_len, nonce_len;
    size_t tls_payload_length;
    size_t tls_aad_pad_sz;
    unsigned char iv[GENERIC_BLOCK_SIZE];
    unsigned char key[MAX_CIPHER_KEY_SIZE/2]; /* 32 */
    unsigned int ctx_init : 1;
    unsigned int key_set : 1;  /* Set if key initialised */
    unsigned int iv_set : 1;   /* Set if an iv is set */
    EVP_CIPHER_CTX *pEvpCtx;

} DP_CHACHAPOLY_CTX;

/********************************************************************/

void digiprov_cipher_generic_reset_ctx(DP_CIPHER_CTX *ctx);
OSSL_FUNC_cipher_encrypt_init_fn digiprov_cipher_generic_einit;
OSSL_FUNC_cipher_decrypt_init_fn digiprov_cipher_generic_dinit;
OSSL_FUNC_cipher_update_fn digiprov_cipher_generic_block_update;
OSSL_FUNC_cipher_final_fn digiprov_cipher_generic_block_final;
OSSL_FUNC_cipher_update_fn digiprov_cipher_generic_stream_update;
OSSL_FUNC_cipher_final_fn digiprov_cipher_generic_stream_final;
OSSL_FUNC_cipher_cipher_fn digiprov_cipher_generic_cipher;
OSSL_FUNC_cipher_get_ctx_params_fn digiprov_cipher_generic_get_ctx_params;
OSSL_FUNC_cipher_set_ctx_params_fn digiprov_cipher_generic_set_ctx_params;
OSSL_FUNC_cipher_gettable_params_fn     digiprov_cipher_generic_gettable_params;
OSSL_FUNC_cipher_gettable_ctx_params_fn digiprov_cipher_generic_gettable_ctx_params;
OSSL_FUNC_cipher_settable_ctx_params_fn digiprov_cipher_generic_settable_ctx_params;
OSSL_FUNC_cipher_set_ctx_params_fn digiprov_cipher_var_keylen_set_ctx_params;
OSSL_FUNC_cipher_settable_ctx_params_fn digiprov_cipher_var_keylen_settable_ctx_params;
OSSL_FUNC_cipher_gettable_ctx_params_fn digiprov_cipher_aead_gettable_ctx_params;
OSSL_FUNC_cipher_settable_ctx_params_fn digiprov_cipher_aead_settable_ctx_params;

int digiprov_cipher_generic_get_params(OSSL_PARAM params[], unsigned int md,
                                   uint64_t flags,
                                   size_t kbits, size_t blkbits, size_t ivbits);

void digiprov_cipher_generic_initkey(void *vctx, size_t kbits, size_t blkbits,
                                 size_t ivbits, unsigned int mode,
                                 uint64_t flags,
                                 void *hw, void *provctx);

int digiprov_aes_set_mode(void *vctx, size_t kbits, size_t ivbits, unsigned int mode);
int digiprov_des_set_mode(void *vctx, size_t kbits, size_t ivbits, unsigned int mode);
int digiprov_tdes_set_mode(void *vctx, size_t kbits, size_t ivbits, unsigned int mode);
int digiprov_blowfish_set_mode(void *vctx, size_t kbits, size_t ivbits, unsigned int mode);
int digiprov_rc4_set_mode(void *vctx, size_t kbits, size_t ivbits, unsigned int mode);
int digiprov_rc5_set_mode(void *vctx, size_t kbits, size_t ivbits, unsigned int mode);

int digiprov_cipher_newevp(EVP_CIPHER_CTX **ppCtx);
void digiprov_cipher_freeevp(EVP_CIPHER_CTX **ppCtx);
void digiprov_cipher_generic_freectx(void *vctx);
void *digiprov_cipher_generic_dupctx(void *vctx);

#define IMPLEMENT_generic_cipher_func(alg, UCALG, lcmode, UCMODE, flags, kbits,\
                                      blkbits, ivbits, typ)                    \
const OSSL_DISPATCH digiprov_##alg##kbits##lcmode##_functions[] = {            \
    { OSSL_FUNC_CIPHER_NEWCTX,                                                 \
      (void (*)(void)) alg##_##kbits##_##lcmode##_newctx },                    \
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void)) digiprov_cipher_generic_freectx },\
    { OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void)) digiprov_cipher_generic_dupctx }, \
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))digiprov_cipher_generic_einit },   \
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))digiprov_cipher_generic_dinit },   \
    { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))digiprov_cipher_generic_##typ##_update },\
    { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))digiprov_cipher_generic_##typ##_final },  \
    { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))digiprov_cipher_generic_cipher },        \
    { OSSL_FUNC_CIPHER_GET_PARAMS,                                             \
      (void (*)(void)) alg##_##kbits##_##lcmode##_get_params },                \
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS,                                         \
      (void (*)(void))digiprov_cipher_generic_get_ctx_params },                    \
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,                                         \
      (void (*)(void))digiprov_cipher_generic_set_ctx_params },                    \
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,                                        \
      (void (*)(void))digiprov_cipher_generic_gettable_params },                   \
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,                                    \
      (void (*)(void))digiprov_cipher_generic_gettable_ctx_params },               \
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,                                    \
     (void (*)(void))digiprov_cipher_generic_settable_ctx_params },                \
    { 0, NULL }                                                                \
};

#define IMPLEMENT_var_keylen_cipher_func(alg, UCALG, lcmode, UCMODE, flags,    \
                                         kbits, blkbits, ivbits, typ)          \
const OSSL_DISPATCH digiprov_##alg##kbits##lcmode##_functions[] = {                \
    { OSSL_FUNC_CIPHER_NEWCTX,                                                 \
      (void (*)(void)) alg##_##kbits##_##lcmode##_newctx },                    \
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void)) digiprov_cipher_generic_freectx }, \
    { OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void)) digiprov_cipher_generic_dupctx }, \
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))digiprov_cipher_generic_einit },\
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))digiprov_cipher_generic_dinit },\
    { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))digiprov_cipher_generic_##typ##_update },\
    { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))digiprov_cipher_generic_##typ##_final },  \
    { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))digiprov_cipher_generic_cipher },   \
    { OSSL_FUNC_CIPHER_GET_PARAMS,                                             \
      (void (*)(void)) alg##_##kbits##_##lcmode##_get_params },                \
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS,                                         \
      (void (*)(void))digiprov_cipher_generic_get_ctx_params },                    \
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,                                         \
      (void (*)(void))digiprov_cipher_var_keylen_set_ctx_params },                 \
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,                                        \
      (void (*)(void))digiprov_cipher_generic_gettable_params },                   \
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,                                    \
      (void (*)(void))digiprov_cipher_generic_gettable_ctx_params },               \
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,                                    \
     (void (*)(void))digiprov_cipher_var_keylen_settable_ctx_params },             \
    { 0, NULL }                                                                \
};

#define IMPLEMENT_generic_cipher_genfn(alg, UCALG, lcmode, UCMODE, flags,      \
                                       kbits, blkbits, ivbits, typ)            \
static OSSL_FUNC_cipher_get_params_fn alg##_##kbits##_##lcmode##_get_params;   \
static int alg##_##kbits##_##lcmode##_get_params(OSSL_PARAM params[])          \
{                                                                              \
    return digiprov_cipher_generic_get_params(params, EVP_CIPH_##UCMODE##_MODE,\
                                              flags, kbits, blkbits, ivbits);  \
}                                                                              \
static OSSL_FUNC_cipher_newctx_fn alg##_##kbits##_##lcmode##_newctx;           \
static void * alg##_##kbits##_##lcmode##_newctx(void *provctx)                 \
{                                                                              \
     MSTATUS status = OK;                                                      \
     DP_CIPHER_CTX *ctx = NULL;                                                \
     if (!digiprov_is_running())                                               \
         return NULL;                                                          \
     status = DIGI_CALLOC((void **) &ctx, 1, sizeof(*ctx));                     \
     if (OK != status)                                                         \
         return NULL;                                                          \
     digiprov_cipher_generic_initkey(ctx, kbits, blkbits, ivbits,              \
                                     EVP_CIPH_##UCMODE##_MODE, flags,          \
                                     NULL, provctx);                           \
     if (!digiprov_cipher_newevp(&ctx->pEvpCtx))                               \
     {                                                                         \
        digiprov_cipher_generic_freectx(ctx); ctx = NULL;                      \
     }                                                                         \
     if (!digiprov_##alg##_set_mode(ctx, kbits, ivbits, EVP_CIPH_##UCMODE##_MODE)) \
     {                                                                         \
        digiprov_cipher_generic_freectx(ctx); ctx = NULL;                      \
     }                                                                         \
     return ctx;                                                               \
}                                                                              \

#define IMPLEMENT_generic_cipher(alg, UCALG, lcmode, UCMODE, flags, kbits,     \
                                 blkbits, ivbits, typ)                         \
IMPLEMENT_generic_cipher_genfn(alg, UCALG, lcmode, UCMODE, flags, kbits,       \
                               blkbits, ivbits, typ)                           \
IMPLEMENT_generic_cipher_func(alg, UCALG, lcmode, UCMODE, flags, kbits,        \
                              blkbits, ivbits, typ)

#define IMPLEMENT_var_keylen_cipher(alg, UCALG, lcmode, UCMODE, flags, kbits,  \
                                    blkbits, ivbits, typ)                      \
IMPLEMENT_generic_cipher_genfn(alg, UCALG, lcmode, UCMODE, flags, kbits,       \
                               blkbits, ivbits, typ)                           \
IMPLEMENT_var_keylen_cipher_func(alg, UCALG, lcmode, UCMODE, flags, kbits,     \
                                 blkbits, ivbits, typ)

#define CIPHER_DEFAULT_GETTABLE_CTX_PARAMS_START(name)                         \
static const OSSL_PARAM name##_known_gettable_ctx_params[] = {                 \
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),                         \
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),                          \
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, NULL),                          \
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_NUM, NULL),                              \
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_ROUNDS, NULL),                           \
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, NULL, 0),                    \
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, NULL, 0),

#define CIPHER_DEFAULT_GETTABLE_CTX_PARAMS_END(name)                           \
    OSSL_PARAM_END                                                             \
};                                                                             \
const OSSL_PARAM * name##_gettable_ctx_params(ossl_unused void *cctx,          \
                                              ossl_unused void *provctx)       \
{                                                                              \
    return name##_known_gettable_ctx_params;                                   \
}

#define CIPHER_DEFAULT_SETTABLE_CTX_PARAMS_START(name)                         \
static const OSSL_PARAM name##_known_settable_ctx_params[] = {                 \
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, NULL),                          \
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_NUM, NULL),
#define CIPHER_DEFAULT_SETTABLE_CTX_PARAMS_END(name)                           \
    OSSL_PARAM_END                                                             \
};                                                                             \
const OSSL_PARAM * name##_settable_ctx_params(ossl_unused void *cctx,          \
                                              ossl_unused void *provctx)       \
{                                                                              \
    return name##_known_settable_ctx_params;                                   \
}

int digiprov_cipher_generic_initiv(DP_CIPHER_CTX *ctx, const unsigned char *iv, size_t ivlen);

size_t digprov_cipher_fillblock(unsigned char *buf, size_t *buflen,
                             size_t blocksize,
                             const unsigned char **in, size_t *inlen);
int digiprov_cipher_trailingdata(unsigned char *buf, size_t *buflen,
                             size_t blocksize,
                             const unsigned char **in, size_t *inlen);

#define UNINITIALISED_SIZET ((size_t)-1)

#define AEAD_FLAGS (PROV_CIPHER_FLAG_AEAD | PROV_CIPHER_FLAG_CUSTOM_IV)

#define IMPLEMENT_aead_cipher(alg, lc, UCMODE, flags, kbits, blkbits, ivbits)  \
static OSSL_FUNC_cipher_get_params_fn digiprov_##alg##_##kbits##_##lc##_get_params; \
static int digiprov_##alg##_##kbits##_##lc##_get_params(OSSL_PARAM params[])   \
{                                                                              \
    return digiprov_cipher_generic_get_params(params, EVP_CIPH_##UCMODE##_MODE,\
                                              flags, kbits, blkbits, ivbits);  \
}                                                                              \
static OSSL_FUNC_cipher_newctx_fn digiprov_##alg##kbits##lc##_newctx;          \
static void * digiprov_##alg##kbits##lc##_newctx(void *provctx)                \
{                                                                              \
    return digiprov_##alg##_##lc##_newctx(provctx, kbits, ivbits);             \
}                                                                              \
const OSSL_DISPATCH digiprov_##alg##kbits##lc##_functions[] = {                \
    { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))digiprov_##alg##kbits##lc##_newctx },\
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))digiprov_##alg##_##lc##_freectx }, \
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))digiprov_##lc##_einit },      \
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))digiprov_##lc##_dinit },      \
    { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))digiprov_##lc##_stream_update },    \
    { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))digiprov_##lc##_stream_final },      \
    { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))digiprov_##lc##_cipher },           \
    { OSSL_FUNC_CIPHER_GET_PARAMS,                                             \
      (void (*)(void)) digiprov_##alg##_##kbits##_##lc##_get_params },         \
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS,                                         \
      (void (*)(void)) digiprov_##lc##_get_ctx_params },                       \
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,                                         \
      (void (*)(void)) digiprov_##lc##_set_ctx_params },                       \
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,                                        \
      (void (*)(void))digiprov_cipher_generic_gettable_params },               \
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,                                    \
      (void (*)(void))digiprov_cipher_aead_gettable_ctx_params },              \
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,                                    \
      (void (*)(void))digiprov_cipher_aead_settable_ctx_params },              \
    { 0, NULL }                                                                \
}
