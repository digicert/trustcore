/*
 * digi_drbg_common.h
 *
 * Header file for common drbg functions. ADAPTED FROM OPENSSL CODE
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
/*
 * Copyright 2019-2021 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2019, Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#ifndef __DIGI_DRBG_COMMON_HEADER__
#define __DIGI_DRBG_COMMON_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

int digiprov_drbg_lock(void *vctx);
void digiprov_drbg_unlock(void *vctx);

size_t digiprov_drbg_get_seed(
    void *vdrbg, unsigned char **pout,
    int entropy, size_t min_len,
    size_t max_len, int prediction_resistance,
    const unsigned char *adin, size_t adin_len);


/* Implements the cleanup_entropy() callback */
void digiprov_drbg_clear_seed(ossl_unused void *vdrbg, unsigned char *out, size_t outlen);

int digiprov_prov_drbg_instantiate(PROV_DRBG *drbg, unsigned int strength,
                                   int prediction_resistance,
                                   const unsigned char *pers, size_t perslen);

int digiprov_prov_drbg_uninstantiate(PROV_DRBG *drbg);

int digiprov_prov_drbg_reseed(PROV_DRBG *drbg, int prediction_resistance,
                              const unsigned char *ent, size_t ent_len,
                              const unsigned char *adin, size_t adinlen);

int digiprov_prov_drbg_generate(PROV_DRBG *drbg, unsigned char *out, size_t outlen,
                                unsigned int strength, int prediction_resistance,
                                const unsigned char *adin, size_t adinlen);

int digiprov_drbg_enable_locking(void *vctx);

PROV_DRBG *digiprov_rand_drbg_new(
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
                     const unsigned char *adin, size_t adin_len));

void digiprov_rand_drbg_free(PROV_DRBG *drbg);

int digiprov_drbg_get_ctx_params(PROV_DRBG *drbg, OSSL_PARAM params[]);

int digiprov_drbg_set_ctx_params(PROV_DRBG *drbg, const OSSL_PARAM params[]);

#ifdef __cplusplus
}
#endif

#endif /* __DIGI_DRBG_COMMON_HEADER__ */
