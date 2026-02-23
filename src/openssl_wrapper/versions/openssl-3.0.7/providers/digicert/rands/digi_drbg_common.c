/*
 * digi_drbg_common.c ADAPTED FROM OPENSSL CODE
 *
 * NIST DRBG CTR implementations for OSSL 3.0 provider
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
 * Copyright 2019-2021 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2019, Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
/*---------------------------------------------------------------------------------------------------------*/

#include "../../../src/common/moptions.h"
#include "../../../src/common/mtypes.h"
#include "../../../src/common/mdefs.h"
#include "../../../src/common/merrors.h"
#include "../../../src/common/mstdlib.h"
#ifdef __ENABLE_DIGICERT_USE_GP_RAND_ENTROPY__
#include "../../../src/common/random.h"
#endif

#include "openssl/err.h"
#include "openssl/proverr.h"
#include "openssl/rand.h"
#include "openssl/crypto.h"
#include "crypto/modes.h"
#include "internal/thread_once.h"
#include "prov/implementations.h"
#include "prov/providercommon.h"
#include "prov/provider_ctx.h"
#include "../../implementations/rands/drbg_local.h"
#include "internal/deprecated.h"
#include "crypto/rand.h"
#include "crypto/cryptlib.h"
#include "prov/seeding.h"
#include "crypto/rand_pool.h"

#include "digi_drbg_common.h"

#include "digiprov.h"

#if !defined(__ENABLE_DIGICERT_USE_GP_RAND_ENTROPY__) && defined(__ENABLE_DIGICERT_FIPS_MODULE__)

/* FROM implementations/rands/crngt.c */
#include "openssl/evp.h"
#include "openssl/core_dispatch.h"
#include "openssl/params.h"
#include "openssl/self_test.h"

typedef struct dp_crng_test_global_st 
{
    unsigned char crngt_prev[EVP_MAX_MD_SIZE];
    EVP_MD *md;
    int preloaded;
    CRYPTO_RWLOCK *lock;
} DP_CRNG_TEST_GLOBAL;

static int crngt_get_entropy(PROV_CTX *provctx, const EVP_MD *digest,
                             unsigned char *buf, unsigned char *md,
                             unsigned int *md_size)
{
    int r;
    size_t n;
    unsigned char *p;

    n = ossl_prov_get_entropy(provctx, &p, 0, CRNGT_BUFSIZ, CRNGT_BUFSIZ);
    if (n == CRNGT_BUFSIZ) {
        r = EVP_Digest(p, CRNGT_BUFSIZ, md, md_size, digest, NULL);
        if (r != 0)
            (void) DIGI_MEMCPY(buf, p, CRNGT_BUFSIZ);
        ossl_prov_cleanup_entropy(provctx, p, n);
        return r != 0;
    }
    if (n != 0)
        ossl_prov_cleanup_entropy(provctx, p, n);
    return 0;
}

static void rand_crng_ossl_ctx_free(void *vcrngt_glob)
{
    DP_CRNG_TEST_GLOBAL *crngt_glob = vcrngt_glob;

    CRYPTO_THREAD_lock_free(crngt_glob->lock);
    EVP_MD_free(crngt_glob->md);
    (void) DIGI_FREE((void **) &crngt_glob);
}

static void *rand_crng_ossl_ctx_new(OSSL_LIB_CTX *ctx)
{
    MSTATUS status = OK;
    DP_CRNG_TEST_GLOBAL *crngt_glob = NULL;
    
    status = DIGI_CALLOC((void **) &crngt_glob, 1, sizeof(DP_CRNG_TEST_GLOBAL));
    if (OK != status)
        return NULL;

    if ((crngt_glob->md = EVP_MD_fetch(ctx, "SHA256", "")) == NULL) {
        (void) DIGI_FREE((void **) &crngt_glob);
        return NULL;
    }

    if ((crngt_glob->lock = CRYPTO_THREAD_lock_new()) == NULL) {
        EVP_MD_free(crngt_glob->md);
        (void) DIGI_FREE((void **) &crngt_glob);
        return NULL;
    }

    return crngt_glob;
}

static const OSSL_LIB_CTX_METHOD rand_crng_ossl_ctx_method = 
{
    OSSL_LIB_CTX_METHOD_DEFAULT_PRIORITY,
    rand_crng_ossl_ctx_new,
    rand_crng_ossl_ctx_free,
};

static int prov_crngt_compare_previous(const unsigned char *prev,
                                       const unsigned char *cur,
                                       size_t sz)
{
    sbyte4 cmp = -1;
    MSTATUS status = DIGI_MEMCMP(prev, cur, sz, &cmp);

    if (OK != status)
        return 0;
    if (!cmp)
    {
        ossl_set_error_state(OSSL_SELF_TEST_TYPE_CRNG);
        return 0;
    }
    return 1;
}

static size_t digiprov_crngt_get_entropy(PROV_DRBG *drbg, unsigned char **pout,
                                         int entropy, size_t min_len, size_t max_len,
                                         int prediction_resistance)
{
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned char buf[CRNGT_BUFSIZ];
    unsigned char *ent, *entp, *entbuf;
    unsigned int sz;
    size_t bytes_needed;
    size_t r = 0, s, t;
    int crng_test_pass = 1;
    OSSL_LIB_CTX *libctx = ossl_prov_ctx_get0_libctx(drbg->provctx);
    DP_CRNG_TEST_GLOBAL *crngt_glob
        = ossl_lib_ctx_get_data(libctx, OSSL_LIB_CTX_RAND_CRNGT_INDEX,
                                &rand_crng_ossl_ctx_method);
    OSSL_CALLBACK *stcb = NULL;
    void *stcbarg = NULL;
    OSSL_SELF_TEST *st = NULL;

    if (crngt_glob == NULL)
        return 0;

    if (!CRYPTO_THREAD_write_lock(crngt_glob->lock))
        return 0;

    if (!crngt_glob->preloaded) {
        if (!crngt_get_entropy(drbg->provctx, crngt_glob->md, buf,
                               crngt_glob->crngt_prev, NULL)) {
            (void) DIGI_MEMSET(buf, 0x00, sizeof(buf));
            goto unlock_return;
        }
        crngt_glob->preloaded = 1;
    }

    /*
     * Calculate how many bytes of seed material we require, rounded up
     * to the nearest byte.  If the entropy is of less than full quality,
     * the amount required should be scaled up appropriately here.
     */
    bytes_needed = (entropy + 7) / 8;
    if (bytes_needed < min_len)
        bytes_needed = min_len;
    if (bytes_needed > max_len)
        goto unlock_return;

    entp = ent = OPENSSL_secure_malloc(bytes_needed);
    if (ent == NULL)
        goto unlock_return;

    OSSL_SELF_TEST_get_callback(libctx, &stcb, &stcbarg);
    if (stcb != NULL) {
        st = OSSL_SELF_TEST_new(stcb, stcbarg);
        if (st == NULL)
            goto err;
        OSSL_SELF_TEST_onbegin(st, OSSL_SELF_TEST_TYPE_CRNG,
                               OSSL_SELF_TEST_DESC_RNG);
    }

    for (t = bytes_needed; t > 0;) {
        /* Care needs to be taken to avoid overrunning the buffer */
        s = t >= CRNGT_BUFSIZ ? CRNGT_BUFSIZ : t;
        entbuf = t >= CRNGT_BUFSIZ ? entp : buf;
        if (!crngt_get_entropy(drbg->provctx, crngt_glob->md, entbuf, md, &sz))
            goto err;
        if (t < CRNGT_BUFSIZ)
            (void) DIGI_MEMCPY(entp, buf, t);
        /* Force a failure here if the callback returns 1 */
        if (OSSL_SELF_TEST_oncorrupt_byte(st, md))
            (void) DIGI_MEMCPY(md, crngt_glob->crngt_prev, sz);
        if (!prov_crngt_compare_previous(crngt_glob->crngt_prev, md, sz)) {
            crng_test_pass = 0;
            goto err;
        }
        /* Update for next block */
        (void) DIGI_MEMCPY(crngt_glob->crngt_prev, md, sz);
        entp += s;
        t -= s;
    }
    r = bytes_needed;
    *pout = ent;
    ent = NULL;

 err:
    OSSL_SELF_TEST_onend(st, crng_test_pass);
    OSSL_SELF_TEST_free(st);
    OPENSSL_secure_clear_free(ent, bytes_needed);

 unlock_return:
    CRYPTO_THREAD_unlock(crngt_glob->lock);
    return r;
}
#endif /* !defined(__ENABLE_DIGICERT_USE_GP_RAND_ENTROPY__) && defined(__ENABLE_DIGICERT_FIPS_MODULE__) */

#if defined(__ENABLE_DIGICERT_USE_GP_RAND_ENTROPY__) || defined(__ENABLE_DIGICERT_FIPS_MODULE__)
static void digiprov_crngt_cleanup_entropy(ossl_unused PROV_DRBG *drbg,
                                           unsigned char *out, size_t outlen)
{
    OPENSSL_secure_clear_free(out, outlen);
}
#endif

#if defined(__ENABLE_DIGICERT_USE_GP_RAND_ENTROPY__)
static size_t digiprov_get_gp_rand_entropy(PROV_DRBG *drbg, unsigned char **pout,
                                           int entropy, size_t min_len, size_t max_len)
{
    unsigned char *pEnt = NULL;
    size_t bytes_needed = 0;
    sbyte4 ret = 0;

    MOC_UNUSED(drbg);

    if (NULL == g_pRandomContext)
        return 0;

    bytes_needed = (entropy + 7) / 8;
    if (bytes_needed < min_len)
        bytes_needed = min_len;
    if (bytes_needed > max_len)
    {
        bytes_needed = 0;
        goto exit;
    }

    pEnt = OPENSSL_secure_malloc(bytes_needed);
    if (NULL == pEnt)
    {   bytes_needed = 0;
        goto exit;
    }

    ret = RANDOM_rngFun(g_pRandomContext, (ubyte4) bytes_needed, pEnt);
    if (0 != ret)
    {
        OPENSSL_secure_clear_free(pEnt, bytes_needed);
        bytes_needed = 0;
        goto exit;
    }

    *pout = pEnt; pEnt = NULL;

exit:

    return bytes_needed;
}
#endif /* __ENABLE_DIGICERT_USE_GP_RAND_ENTROPY__ */

/****************************************************************/
/* FROM openssl's drbg.c */

static const char ossl_pers_string[] = DRBG_DEFAULT_PERS_STRING;
static const OSSL_DISPATCH *digiprov_find_call(const OSSL_DISPATCH *dispatch, int function);
static int digiprov_rand_drbg_restart(PROV_DRBG *drbg);

int digiprov_drbg_lock(void *vctx)
{
    PROV_DRBG *drbg = vctx;

    if (drbg == NULL || drbg->lock == NULL)
        return 1;
    return CRYPTO_THREAD_write_lock(drbg->lock);
}

void digiprov_drbg_unlock(void *vctx)
{
    PROV_DRBG *drbg = vctx;

    if (drbg != NULL && drbg->lock != NULL)
        CRYPTO_THREAD_unlock(drbg->lock);
}

static int digiprov_drbg_lock_parent(PROV_DRBG *drbg)
{
    void *parent = drbg->parent;

    if (parent != NULL
            && drbg->parent_lock != NULL
            && !drbg->parent_lock(parent)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_PARENT_LOCKING_NOT_ENABLED);
        return 0;
    }
    return 1;
}

static void digiprov_drbg_unlock_parent(PROV_DRBG *drbg)
{
    void *parent = drbg->parent;

    if (parent != NULL && drbg->parent_unlock != NULL)
        drbg->parent_unlock(parent);
}

static int digiprov_get_parent_strength(PROV_DRBG *drbg, unsigned int *str)
{
    OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
    void *parent = drbg->parent;
    int res;

    if (drbg->parent_get_ctx_params == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_UNABLE_TO_GET_PARENT_STRENGTH);
        return 0;
    }

    *params = OSSL_PARAM_construct_uint(OSSL_RAND_PARAM_STRENGTH, str);
    if (!digiprov_drbg_lock_parent(drbg)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_UNABLE_TO_LOCK_PARENT);
        return 0;
    }
    res = drbg->parent_get_ctx_params(parent, params);
    digiprov_drbg_unlock_parent(drbg);
    if (!res) {
        ERR_raise(ERR_LIB_PROV, PROV_R_UNABLE_TO_GET_PARENT_STRENGTH);
        return 0;
    }
    return 1;
}

static unsigned int digiprov_get_parent_reseed_count(PROV_DRBG *drbg)
{
    OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
    void *parent = drbg->parent;
    unsigned int r = 0;

    *params = OSSL_PARAM_construct_uint(OSSL_DRBG_PARAM_RESEED_COUNTER, &r);
    if (!digiprov_drbg_lock_parent(drbg)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_UNABLE_TO_LOCK_PARENT);
        goto err;
    }
    if (!drbg->parent_get_ctx_params(parent, params))
        r = 0;
    digiprov_drbg_unlock_parent(drbg);
    return r;

 err:
    r = tsan_load(&drbg->reseed_counter) - 2;
    if (r == 0)
        r = UINT_MAX;
    return r;
}

size_t digiprov_drbg_get_seed(
    void *vdrbg, unsigned char **pout,
    int entropy, size_t min_len,
    size_t max_len, int prediction_resistance,
    const unsigned char *adin, size_t adin_len)
{
    MSTATUS status = OK;
    PROV_DRBG *drbg = (PROV_DRBG *)vdrbg;
    size_t bytes_needed;
    unsigned char *buffer = NULL;

    /* Figure out how many bytes we need */
    bytes_needed = entropy >= 0 ? (entropy + 7) / 8 : 0;
    if (bytes_needed < min_len)
        bytes_needed = min_len;
    if (bytes_needed > max_len)
        bytes_needed = max_len;

    /* Allocate storage */
    status = DIGI_MALLOC((void **) &buffer, (ubyte4) bytes_needed);
    if (OK != status)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    /*
     * Get random data.  Include our DRBG address as
     * additional input, in order to provide a distinction between
     * different DRBG child instances.
     *
     * Note: using the sizeof() operator on a pointer triggers
     *       a warning in some static code analyzers, but it's
     *       intentional and correct here.
     */
    if (!digiprov_prov_drbg_generate(drbg, buffer, bytes_needed,
                                     drbg->strength, prediction_resistance,
                                     (unsigned char *)&drbg, sizeof(drbg)))
    {
        (void) DIGI_MEMSET_FREE(&buffer, bytes_needed);
        ERR_raise(ERR_LIB_PROV, PROV_R_GENERATE_ERROR);
        return 0;
    }
    *pout = buffer;
    return bytes_needed;
}

/* Implements the cleanup_entropy() callback */
void digiprov_drbg_clear_seed(ossl_unused void *vdrbg, unsigned char *out, size_t outlen)
{
    if (NULL != out) (void) DIGI_MEMSET_FREE(&out, outlen);
}

static size_t digiprov_get_entropy(PROV_DRBG *drbg, unsigned char **pout, int entropy,
                          size_t min_len, size_t max_len,
                          int prediction_resistance)
{
    size_t bytes;
    unsigned int p_str;

    if (drbg->parent == NULL)
#if defined(__ENABLE_DIGICERT_USE_GP_RAND_ENTROPY__)
        return digiprov_get_gp_rand_entropy(drbg, pout, entropy, min_len, max_len);
#elif defined(__ENABLE_DIGICERT_FIPS_MODULE__)
        return digiprov_crngt_get_entropy(drbg, pout, entropy, min_len, max_len, prediction_resistance);
#else
        return ossl_prov_get_entropy(drbg->provctx, pout, entropy, min_len,
                                     max_len);
#endif

    if (drbg->parent_get_seed == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_PARENT_CANNOT_SUPPLY_ENTROPY_SEED);
        return 0;
    }
    if (!digiprov_get_parent_strength(drbg, &p_str))
        return 0;
    if (drbg->strength > p_str) {
        /*
         * We currently don't support the algorithm from NIST SP 800-90C
         * 10.1.2 to use a weaker DRBG as source
         */
        ERR_raise(ERR_LIB_PROV, PROV_R_PARENT_STRENGTH_TOO_WEAK);
        return 0;
    }

    /*
     * Our lock is already held, but we need to lock our parent before
     * generating bits from it.  Note: taking the lock will be a no-op
     * if locking is not required (while drbg->parent->lock == NULL).
     */
    if (!digiprov_drbg_lock_parent(drbg))
        return 0;
    /*
     * Get random data from parent.  Include our DRBG address as
     * additional input, in order to provide a distinction between
     * different DRBG child instances.
     *
     * Note: using the sizeof() operator on a pointer triggers
     *       a warning in some static code analyzers, but it's
     *       intentional and correct here.
     */
    bytes = drbg->parent_get_seed(drbg->parent, pout, drbg->strength,
                                  min_len, max_len, prediction_resistance,
                                  (unsigned char *)&drbg, sizeof(drbg));
    digiprov_drbg_unlock_parent(drbg);
    return bytes;
}

static void digiprov_cleanup_entropy(PROV_DRBG *drbg, unsigned char *out, size_t outlen)
{
    if (drbg->parent == NULL) 
    {
#if defined(__ENABLE_DIGICERT_USE_GP_RAND_ENTROPY__) || defined(__ENABLE_DIGICERT_FIPS_MODULE__)
        digiprov_crngt_cleanup_entropy(drbg, out, outlen);
#else
        ossl_prov_cleanup_entropy(drbg->provctx, out, outlen);
#endif
    } else if (drbg->parent_clear_seed != NULL) {
        if (!digiprov_drbg_lock_parent(drbg))
            return;
        drbg->parent_clear_seed(drbg, out, outlen);
        digiprov_drbg_unlock_parent(drbg);
    }
}

#ifndef PROV_RAND_GET_RANDOM_NONCE
typedef struct prov_drbg_nonce_global_st {
    CRYPTO_RWLOCK *rand_nonce_lock;
    int rand_nonce_count;
} PROV_DRBG_NONCE_GLOBAL;

/*
 * drbg_ossl_ctx_new() calls drgb_setup() which calls rand_drbg_get_nonce()
 * which needs to get the rand_nonce_lock out of the OSSL_LIB_CTX...but since
 * drbg_ossl_ctx_new() hasn't finished running yet we need the rand_nonce_lock
 * to be in a different global data object. Otherwise we will go into an
 * infinite recursion loop.
 */
static void *prov_drbg_nonce_ossl_ctx_new(OSSL_LIB_CTX *libctx)
{
    MSTATUS status = OK;
    PROV_DRBG_NONCE_GLOBAL *dngbl = NULL;
    
    status = DIGI_CALLOC((void **) &dngbl, 1, sizeof(*dngbl));
    if (OK != status)
        return NULL;

    dngbl->rand_nonce_lock = CRYPTO_THREAD_lock_new();
    if (dngbl->rand_nonce_lock == NULL) 
    {
        (void) DIGI_FREE((void **) &dngbl);
        return NULL;
    }

    return dngbl;
}

static void prov_drbg_nonce_ossl_ctx_free(void *vdngbl)
{
    PROV_DRBG_NONCE_GLOBAL *dngbl = vdngbl;

    if (dngbl == NULL)
        return;

    CRYPTO_THREAD_lock_free(dngbl->rand_nonce_lock);

    (void) DIGI_FREE((void **) &dngbl);
}

static const OSSL_LIB_CTX_METHOD drbg_nonce_ossl_ctx_method = {
    OSSL_LIB_CTX_METHOD_DEFAULT_PRIORITY,
    prov_drbg_nonce_ossl_ctx_new,
    prov_drbg_nonce_ossl_ctx_free,
};

/* Get a nonce from the operating system */
static size_t prov_drbg_get_nonce(PROV_DRBG *drbg, unsigned char **pout,
                                  size_t min_len, size_t max_len)
{
    size_t ret = 0, n;
    unsigned char *buf = NULL;
    OSSL_LIB_CTX *libctx = ossl_prov_ctx_get0_libctx(drbg->provctx);
    PROV_DRBG_NONCE_GLOBAL *dngbl
        = ossl_lib_ctx_get_data(libctx, OSSL_LIB_CTX_DRBG_NONCE_INDEX,
                                &drbg_nonce_ossl_ctx_method);
    struct {
        void *drbg;
        int count;
    } data;

    if (dngbl == NULL)
        return 0;

    if (drbg->parent != NULL && drbg->parent_nonce != NULL) {
        n = drbg->parent_nonce(drbg->parent, NULL, 0, drbg->min_noncelen,
                               drbg->max_noncelen);
        /* cleanup nonce is a provider_core handler, so leave OPENSSL_malloc here */
        if (n > 0 && (buf = OPENSSL_malloc(n)) != NULL)
        {
            ret = drbg->parent_nonce(drbg->parent, buf, 0,
                                     drbg->min_noncelen, drbg->max_noncelen);
            if (ret == n) {
                *pout = buf;
                return ret;
            }
            OPENSSL_free(buf);
        }
    }

    /* Use the built in nonce source plus some of our specifics */
    DIGI_MEMSET((ubyte *) &data, 0, sizeof(data));
    data.drbg = drbg;
    CRYPTO_atomic_add(&dngbl->rand_nonce_count, 1, &data.count,
                      dngbl->rand_nonce_lock);
    return ossl_prov_get_nonce(drbg->provctx, pout, min_len, max_len,
                               &data, sizeof(data));
}
#endif /* PROV_RAND_GET_RANDOM_NONCE */

int digiprov_prov_drbg_instantiate(PROV_DRBG *drbg, unsigned int strength,
                                   int prediction_resistance,
                                   const unsigned char *pers, size_t perslen)
{
    unsigned char *nonce = NULL, *entropy = NULL;
    size_t noncelen = 0, entropylen = 0;
    size_t min_entropy, min_entropylen, max_entropylen;

    if (strength > drbg->strength) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INSUFFICIENT_DRBG_STRENGTH);
        goto end;
    }
    min_entropy = drbg->strength;
    min_entropylen = drbg->min_entropylen;
    max_entropylen = drbg->max_entropylen;

    if (pers == NULL) {
        pers = (const unsigned char *)ossl_pers_string;
        perslen = sizeof(ossl_pers_string);
    }
    if (perslen > drbg->max_perslen) {
        ERR_raise(ERR_LIB_PROV, PROV_R_PERSONALISATION_STRING_TOO_LONG);
        goto end;
    }

    if (drbg->state != EVP_RAND_STATE_UNINITIALISED) {
        if (drbg->state == EVP_RAND_STATE_ERROR)
            ERR_raise(ERR_LIB_PROV, PROV_R_IN_ERROR_STATE);
        else
            ERR_raise(ERR_LIB_PROV, PROV_R_ALREADY_INSTANTIATED);
        goto end;
    }

    drbg->state = EVP_RAND_STATE_ERROR;

    if (drbg->min_noncelen > 0) {
        if (drbg->parent_nonce != NULL) {
            noncelen = drbg->parent_nonce(drbg->parent, NULL, drbg->strength,
                                          drbg->min_noncelen,
                                          drbg->max_noncelen);
            if (noncelen == 0) {
                ERR_raise(ERR_LIB_PROV, PROV_R_ERROR_RETRIEVING_NONCE);
                goto end;
            }
            /* cleanup is a provider_core handler, so leave OPENSSL_malloc here */
            nonce = OPENSSL_malloc(noncelen);
            if (nonce == NULL) {
                ERR_raise(ERR_LIB_PROV, PROV_R_ERROR_RETRIEVING_NONCE);
                goto end;
            }
            if (noncelen != drbg->parent_nonce(drbg->parent, nonce,
                                               drbg->strength,
                                               drbg->min_noncelen,
                                               drbg->max_noncelen)) {
                ERR_raise(ERR_LIB_PROV, PROV_R_ERROR_RETRIEVING_NONCE);
                goto end;
            }
#ifndef PROV_RAND_GET_RANDOM_NONCE
        } else if (drbg->parent != NULL) {
#endif
            /*
             * NIST SP800-90Ar1 section 9.1 says you can combine getting
             * the entropy and nonce in 1 call by increasing the entropy
             * with 50% and increasing the minimum length to accommodate
             * the length of the nonce. We do this in case a nonce is
             * required and there is no parental nonce capability.
             */
            min_entropy += drbg->strength / 2;
            min_entropylen += drbg->min_noncelen;
            max_entropylen += drbg->max_noncelen;
        }
#ifndef PROV_RAND_GET_RANDOM_NONCE
        else { /* parent == NULL */
            noncelen = prov_drbg_get_nonce(drbg, &nonce, drbg->min_noncelen, 
                                           drbg->max_noncelen);
            if (noncelen < drbg->min_noncelen
                    || noncelen > drbg->max_noncelen) {
                ERR_raise(ERR_LIB_PROV, PROV_R_ERROR_RETRIEVING_NONCE);
                goto end;
            }
        }
#endif
    }

    drbg->reseed_next_counter = tsan_load(&drbg->reseed_counter);
    if (drbg->reseed_next_counter) {
        drbg->reseed_next_counter++;
        if (!drbg->reseed_next_counter)
            drbg->reseed_next_counter = 1;
    }

    entropylen = digiprov_get_entropy(drbg, &entropy, min_entropy,
                                      min_entropylen, max_entropylen,
                                      prediction_resistance);
    if (entropylen < min_entropylen
            || entropylen > max_entropylen) {
        ERR_raise(ERR_LIB_PROV, PROV_R_ERROR_RETRIEVING_ENTROPY);
        goto end;
    }

    if (!drbg->instantiate(drbg, entropy, entropylen, nonce, noncelen,
                           pers, perslen)) {
        digiprov_cleanup_entropy(drbg, entropy, entropylen);
        ERR_raise(ERR_LIB_PROV, PROV_R_ERROR_INSTANTIATING_DRBG);
        goto end;
    }
    digiprov_cleanup_entropy(drbg, entropy, entropylen);

    drbg->state = EVP_RAND_STATE_READY;
    drbg->generate_counter = 1;
    drbg->reseed_time = time(NULL);
    tsan_store(&drbg->reseed_counter, drbg->reseed_next_counter);

 end:
    if (nonce != NULL)
        ossl_prov_cleanup_nonce(drbg->provctx, nonce, noncelen);
    if (drbg->state == EVP_RAND_STATE_READY)
        return 1;
    return 0;
}

int digiprov_prov_drbg_uninstantiate(PROV_DRBG *drbg)
{
    drbg->state = EVP_RAND_STATE_UNINITIALISED;
    return 1;
}

int digiprov_prov_drbg_reseed(PROV_DRBG *drbg, int prediction_resistance,
                              const unsigned char *ent, size_t ent_len,
                              const unsigned char *adin, size_t adinlen)
{
    unsigned char *entropy = NULL;
    size_t entropylen = 0;


    if (!digiprov_is_running())
        return 0;

    if (drbg->state != EVP_RAND_STATE_READY) {
        /* try to recover from previous errors */
        digiprov_rand_drbg_restart(drbg);

        if (drbg->state == EVP_RAND_STATE_ERROR) {
            ERR_raise(ERR_LIB_PROV, PROV_R_IN_ERROR_STATE);
            return 0;
        }
        if (drbg->state == EVP_RAND_STATE_UNINITIALISED) {
            ERR_raise(ERR_LIB_PROV, PROV_R_NOT_INSTANTIATED);
            return 0;
        }
    }

    if (ent != NULL) {
        if (ent_len < drbg->min_entropylen) {
            ERR_raise(ERR_LIB_RAND, RAND_R_ENTROPY_OUT_OF_RANGE);
            drbg->state = EVP_RAND_STATE_ERROR;
            return 0;
        }
        if (ent_len > drbg->max_entropylen) {
            ERR_raise(ERR_LIB_RAND, RAND_R_ENTROPY_INPUT_TOO_LONG);
            drbg->state = EVP_RAND_STATE_ERROR;
            return 0;
        }
    }

    if (adin == NULL) {
        adinlen = 0;
    } else if (adinlen > drbg->max_adinlen) {
        ERR_raise(ERR_LIB_PROV, PROV_R_ADDITIONAL_INPUT_TOO_LONG);
        return 0;
    }

    drbg->state = EVP_RAND_STATE_ERROR;

    drbg->reseed_next_counter = tsan_load(&drbg->reseed_counter);
    if (drbg->reseed_next_counter) 
    {
        drbg->reseed_next_counter++;
        if (!drbg->reseed_next_counter)
            drbg->reseed_next_counter = 1;
    }

    if (ent != NULL) 
    {
#if defined(__ENABLE_DIGICERT_FIPS_MODULE__)
        /*
         * NIST SP-800-90A mandates that entropy *shall not* be provided
         * by the consuming application. Instead the data is added as additional
         * input.
         *
         * (NIST SP-800-90Ar1, Sections 9.1 and 9.2)
         */
        if (!drbg->reseed(drbg, NULL, 0, ent, ent_len)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_UNABLE_TO_RESEED);
            return 0;
        }
#else
        if (!drbg->reseed(drbg, ent, ent_len, adin, adinlen)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_UNABLE_TO_RESEED);
            return 0;
        }
        /* There isn't much point adding the same additional input twice */
        adin = NULL;
        adinlen = 0;
#endif
    }

    /* Reseed using our sources in addition */
    entropylen = digiprov_get_entropy(drbg, &entropy, drbg->strength,
                                      drbg->min_entropylen, drbg->max_entropylen,
                                      prediction_resistance);
    if (entropylen < drbg->min_entropylen
            || entropylen > drbg->max_entropylen) {
        ERR_raise(ERR_LIB_PROV, PROV_R_ERROR_RETRIEVING_ENTROPY);
        goto end;
    }

    if (!drbg->reseed(drbg, entropy, entropylen, adin, adinlen))
        goto end;

    drbg->state = EVP_RAND_STATE_READY;
    drbg->generate_counter = 1;
    drbg->reseed_time = time(NULL);
    tsan_store(&drbg->reseed_counter, drbg->reseed_next_counter);
    if (drbg->parent != NULL)
        drbg->parent_reseed_counter = digiprov_get_parent_reseed_count(drbg);

 end:
    digiprov_cleanup_entropy(drbg, entropy, entropylen);
    if (drbg->state == EVP_RAND_STATE_READY)
        return 1;
    return 0;
}

int digiprov_prov_drbg_generate(PROV_DRBG *drbg, unsigned char *out, size_t outlen,
                                unsigned int strength, int prediction_resistance,
                                const unsigned char *adin, size_t adinlen)
{
    int fork_id;
    int reseed_required = 0;

    if (!digiprov_is_running())
        return 0;

    if (drbg->state != EVP_RAND_STATE_READY) {
        /* try to recover from previous errors */
        digiprov_rand_drbg_restart(drbg);

        if (drbg->state == EVP_RAND_STATE_ERROR) {
            ERR_raise(ERR_LIB_PROV, PROV_R_IN_ERROR_STATE);
            return 0;
        }
        if (drbg->state == EVP_RAND_STATE_UNINITIALISED) {
            ERR_raise(ERR_LIB_PROV, PROV_R_NOT_INSTANTIATED);
            return 0;
        }
    }
    if (strength > drbg->strength) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INSUFFICIENT_DRBG_STRENGTH);
        return 0;
    }

    if (outlen > drbg->max_request) {
        ERR_raise(ERR_LIB_PROV, PROV_R_REQUEST_TOO_LARGE_FOR_DRBG);
        return 0;
    }
    if (adinlen > drbg->max_adinlen) {
        ERR_raise(ERR_LIB_PROV, PROV_R_ADDITIONAL_INPUT_TOO_LONG);
        return 0;
    }

    fork_id = openssl_get_fork_id();

    if (drbg->fork_id != fork_id) {
        drbg->fork_id = fork_id;
        reseed_required = 1;
    }

    if (drbg->reseed_interval > 0) {
        if (drbg->generate_counter >= drbg->reseed_interval)
            reseed_required = 1;
    }
    if (drbg->reseed_time_interval > 0) {
        time_t now = time(NULL);
        if (now < drbg->reseed_time
            || now - drbg->reseed_time >= drbg->reseed_time_interval)
            reseed_required = 1;
    }
    if (drbg->parent != NULL
            && digiprov_get_parent_reseed_count(drbg) != drbg->parent_reseed_counter)
        reseed_required = 1;

    if (reseed_required || prediction_resistance) {
        if (!digiprov_prov_drbg_reseed(drbg, prediction_resistance, NULL, 0, adin, adinlen)) 
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_RESEED_ERROR);
            return 0;
        }
        adin = NULL;
        adinlen = 0;
    }

    if (!drbg->generate(drbg, out, outlen, adin, adinlen)) {
        drbg->state = EVP_RAND_STATE_ERROR;
        ERR_raise(ERR_LIB_PROV, PROV_R_GENERATE_ERROR);
        return 0;
    }

    drbg->generate_counter++;

    return 1;
}

static int digiprov_rand_drbg_restart(PROV_DRBG *drbg)
{
    /* repair error state */
    if (drbg->state == EVP_RAND_STATE_ERROR)
        drbg->uninstantiate(drbg);

    /* repair uninitialized state */
    if (drbg->state == EVP_RAND_STATE_UNINITIALISED)
        /* reinstantiate drbg */
        digiprov_prov_drbg_instantiate(drbg, drbg->strength, 0, NULL, 0);

    return drbg->state == EVP_RAND_STATE_READY;
}

/* Provider support from here down */
static const OSSL_DISPATCH *digiprov_find_call(const OSSL_DISPATCH *dispatch, int function)
{
    if (dispatch != NULL)
        while (dispatch->function_id != 0) {
            if (dispatch->function_id == function)
                return dispatch;
            dispatch++;
        }
    return NULL;
}

int digiprov_drbg_enable_locking(void *vctx)
{
    PROV_DRBG *drbg = vctx;

    if (drbg != NULL && drbg->lock == NULL) {
        if (drbg->parent_enable_locking != NULL)
            if (!drbg->parent_enable_locking(drbg->parent)) {
                ERR_raise(ERR_LIB_PROV, PROV_R_PARENT_LOCKING_NOT_ENABLED);
                return 0;
            }
        drbg->lock = CRYPTO_THREAD_lock_new();
        if (drbg->lock == NULL) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_CREATE_LOCK);
            return 0;
        }
    }
    return 1;
}

PROV_DRBG *digiprov_rand_drbg_new (
     void *provctx, void *parent, const OSSL_DISPATCH *p_dispatch,
     int (*dnew)(PROV_DRBG *ctx),
     int (*instantiate)(PROV_DRBG *drbg,
                        const unsigned char *entropy, size_t entropylen,
                        const unsigned char *nonce, size_t noncelen,
                        const unsigned char *pers, size_t perslen),
     int (*uninstantiate)(PROV_DRBG *ctx),
     int (*reseed)(PROV_DRBG *drbg, const unsigned char *ent, size_t ent_len,
                   const unsigned char *adin, size_t adin_len),
     int (*generate)(PROV_DRBG *, unsigned char *out, size_t outlen,
                     const unsigned char *adin, size_t adin_len))
{
    MSTATUS status = OK;
    PROV_DRBG *drbg = NULL;
    unsigned int p_str;
    const OSSL_DISPATCH *pfunc;

    if (!digiprov_is_running())
        return NULL;

    status = DIGI_CALLOC((void **) &drbg, 1, sizeof(*drbg));
    if (OK != status)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    drbg->provctx = provctx;
    drbg->instantiate = instantiate;
    drbg->uninstantiate = uninstantiate;
    drbg->reseed = reseed;
    drbg->generate = generate;
    drbg->fork_id = openssl_get_fork_id();

    /* Extract parent's functions */
    drbg->parent = parent;
    if ((pfunc = digiprov_find_call(p_dispatch, OSSL_FUNC_RAND_ENABLE_LOCKING)) != NULL)
        drbg->parent_enable_locking = OSSL_FUNC_rand_enable_locking(pfunc);
    if ((pfunc = digiprov_find_call(p_dispatch, OSSL_FUNC_RAND_LOCK)) != NULL)
        drbg->parent_lock = OSSL_FUNC_rand_lock(pfunc);
    if ((pfunc = digiprov_find_call(p_dispatch, OSSL_FUNC_RAND_UNLOCK)) != NULL)
        drbg->parent_unlock = OSSL_FUNC_rand_unlock(pfunc);
    if ((pfunc = digiprov_find_call(p_dispatch, OSSL_FUNC_RAND_GET_CTX_PARAMS)) != NULL)
        drbg->parent_get_ctx_params = OSSL_FUNC_rand_get_ctx_params(pfunc);
    if ((pfunc = digiprov_find_call(p_dispatch, OSSL_FUNC_RAND_NONCE)) != NULL)
        drbg->parent_nonce = OSSL_FUNC_rand_nonce(pfunc);
    if ((pfunc = digiprov_find_call(p_dispatch, OSSL_FUNC_RAND_GET_SEED)) != NULL)
        drbg->parent_get_seed = OSSL_FUNC_rand_get_seed(pfunc);
    if ((pfunc = digiprov_find_call(p_dispatch, OSSL_FUNC_RAND_CLEAR_SEED)) != NULL)
        drbg->parent_clear_seed = OSSL_FUNC_rand_clear_seed(pfunc);

    /* Set some default maximums up */
    drbg->max_entropylen = DRBG_MAX_LENGTH;
    drbg->max_noncelen = DRBG_MAX_LENGTH;
    drbg->max_perslen = DRBG_MAX_LENGTH;
    drbg->max_adinlen = DRBG_MAX_LENGTH;
    drbg->generate_counter = 1;
    drbg->reseed_counter = 1;
    drbg->reseed_interval = RESEED_INTERVAL;
    drbg->reseed_time_interval = TIME_INTERVAL;

    if (!dnew(drbg))
        goto err;

    if (parent != NULL) {
        if (!digiprov_get_parent_strength(drbg, &p_str))
            goto err;
        if (drbg->strength > p_str) {
            /*
             * We currently don't support the algorithm from NIST SP 800-90C
             * 10.1.2 to use a weaker DRBG as source
             */
            ERR_raise(ERR_LIB_PROV, PROV_R_PARENT_STRENGTH_TOO_WEAK);
            goto err;
        }
    }
#ifdef TSAN_REQUIRES_LOCKING
    if (!digiprov_drbg_enable_locking(drbg))
        goto err;
#endif
    return drbg;

 err:
    digiprov_rand_drbg_free(drbg);
    return NULL;
}

void digiprov_rand_drbg_free(PROV_DRBG *drbg)
{
    if (drbg == NULL)
        return;

    CRYPTO_THREAD_lock_free(drbg->lock);
    (void) DIGI_FREE((void **) &drbg);
}

int digiprov_drbg_get_ctx_params(PROV_DRBG *drbg, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STATE);
    if (p != NULL && !OSSL_PARAM_set_int(p, drbg->state))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STRENGTH);
    if (p != NULL && !OSSL_PARAM_set_int(p, drbg->strength))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_REQUEST);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, drbg->max_request))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_DRBG_PARAM_MIN_ENTROPYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, drbg->min_entropylen))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_DRBG_PARAM_MAX_ENTROPYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, drbg->max_entropylen))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_DRBG_PARAM_MIN_NONCELEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, drbg->min_noncelen))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_DRBG_PARAM_MAX_NONCELEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, drbg->max_noncelen))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_DRBG_PARAM_MAX_PERSLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, drbg->max_perslen))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_DRBG_PARAM_MAX_ADINLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, drbg->max_adinlen))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_DRBG_PARAM_RESEED_REQUESTS);
    if (p != NULL && !OSSL_PARAM_set_uint(p, drbg->reseed_interval))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_DRBG_PARAM_RESEED_TIME);
    if (p != NULL && !OSSL_PARAM_set_time_t(p, drbg->reseed_time))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL);
    if (p != NULL && !OSSL_PARAM_set_time_t(p, drbg->reseed_time_interval))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_DRBG_PARAM_RESEED_COUNTER);
    if (p != NULL
            && !OSSL_PARAM_set_uint(p, tsan_load(&drbg->reseed_counter)))
        return 0;
    return 1;
}

int digiprov_drbg_set_ctx_params(PROV_DRBG *drbg, const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;

    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_RESEED_REQUESTS);
    if (p != NULL && !OSSL_PARAM_get_uint(p, &drbg->reseed_interval))
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL);
    if (p != NULL && !OSSL_PARAM_get_time_t(p, &drbg->reseed_time_interval))
        return 0;
    return 1;
}
