/*
 * digi_pqc_kem.c
 *
 * PQC KEM (key encapsulation mechanism) implementations for OSSL 3.0 provider
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

/* ---------------------------------------------------------------------------------------------------*/

#include "../../../src/common/moptions.h"

#ifdef __ENABLE_DIGICERT_PQC__

#include "../../../src/common/mtypes.h"
#include "../../../src/common/mdefs.h"
#include "../../../src/common/merrors.h"
#include "../../../src/common/mstdlib.h"
#include "../../../src/common/mrtos.h"
#include "../../../src/common/vlong.h"
#include "../../../src/common/random.h"
#include "../../../src/crypto/ca_mgmt.h"
#include "../../../src/crypto_interface/crypto_interface_qs.h"
#include "../../../src/crypto_interface/crypto_interface_qs_kem.h"

#ifdef ASN1_ITEM
#undef ASN1_ITEM
#endif

#include "mocana_glue.h"
#include "digicert_common.h"

#include "openssl/evp.h"
#include "prov/names.h"
#include "openssl/core_dispatch.h"
#include "openssl/core_names.h"
#include "openssl/params.h"
#include "openssl/objects.h"
#include "openssl/provider.h"
#include "openssl/err.h"
#include "openssl/proverr.h"
#include "internal/sizes.h"
#include "internal/nelem.h"
#include "prov/provider_ctx.h"
#include "crypto/evp.h"
#include "openssl/../../crypto/evp/evp_local.h"
#include "digiprov.h"
#include "pqc.h"
#include "internal/deprecated.h"

#include "openssl/crypto.h"
#include "internal/packet.h"
#include "internal/cryptlib.h"

typedef struct
{
    OSSL_LIB_CTX *libctx;
    DP_PQC_KEY *pKey;
    int operation;

} DP_PQCKEM_CTX;

sbyte4 DIGI_EVP_RandomRngFun(void *pRngFunArg, ubyte4 length, ubyte *pBuffer);
static int digiprov_pqc_kem_set_ctx_params(void *vctx, const OSSL_PARAM params[]);
void digiprov_pqc_key_free(DP_PQC_KEY *pKey);
int digiprov_pqc_validate_key_for_op(DP_PQC_KEY *pKey, int operation);
extern int digiprov_pqc_key_up_ref(DP_PQC_KEY *pKey);

static void *digiprov_pqc_kem_newctx(void *provctx)
{
    MSTATUS status = OK;
    DP_PQCKEM_CTX *pCtx = NULL;

    if (!digiprov_is_running())
        return NULL;

    status = DIGI_CALLOC((void **)&pCtx, 1, sizeof(DP_PQCKEM_CTX));
    if (OK != status)
        goto exit;

    pCtx->libctx = PROV_LIBCTX_OF(provctx);

exit:

    return pCtx;
}

static int digiprov_pqc_kem_init(void *vctx, void *pqc, const OSSL_PARAM params[], int operation)
{
    DP_PQCKEM_CTX *pCtx = (DP_PQCKEM_CTX *) vctx;
    DP_PQC_KEY *pKey = (DP_PQC_KEY *) pqc;

    if (!digiprov_is_running())
        return 0;
    
    pCtx->operation = operation;
    
    if (pKey == NULL)
    {
        if (pCtx->pKey != NULL)
        {
            /* there is nothing to do on reinit */
            return 1;
        }
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return 0;
    }
    else
    {
        if (!digiprov_pqc_key_up_ref(pKey))
            return 0;

        if (NULL != pCtx->pKey)
        {
            digiprov_pqc_key_free(pCtx->pKey);
        }
        pCtx->pKey = pKey;
    }

    if (!digiprov_pqc_kem_set_ctx_params(pCtx, params))
        return 0;

    return 1;
}

static int digiprov_pqc_encapsulate_init(void *vctx, void *pqc, const OSSL_PARAM params[])
{
    return digiprov_pqc_kem_init(vctx, pqc, params, EVP_PKEY_OP_ENCAPSULATE);
}

static int digiprov_pqc_decapsulate_init(void *vctx, void *pqc, const OSSL_PARAM params[])
{
    return digiprov_pqc_kem_init(vctx, pqc, params, EVP_PKEY_OP_DECAPSULATE);
}

static int digiprov_pqc_encapsulate(void *vctx, unsigned char *out, size_t *outlen, unsigned char *secret, size_t *secretlen)
{
    MSTATUS status = OK;
    DP_PQCKEM_CTX *pCtx = (DP_PQCKEM_CTX *) vctx;
    DP_PQC_KEY *pKey;
    ubyte4 cipherLen = 0;
    ubyte4 ssLen = 0;

    if (!digiprov_is_running())
        return 0;

    if (NULL == pCtx)
        return 0;

    pKey = (DP_PQC_KEY *) pCtx->pKey;
    if (NULL == pKey)
        return 0;

    if (!digiprov_pqc_validate_key_for_op(pKey, pCtx->operation))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
        return 0;
    }

    status = CRYPTO_INTERFACE_QS_KEM_getCipherTextLen((QS_CTX *) pKey->pKeyData, &cipherLen);
    if (OK != status)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET); /* only possible error case */
        return 0;        
    }

    status = CRYPTO_INTERFACE_QS_KEM_getSharedSecretLen((QS_CTX *) pKey->pKeyData, &ssLen);
    if (OK != status)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET); /* only possible error case */
        return 0;        
    }

    if (out == NULL || secret == NULL)
    {
        if (NULL != outlen) *outlen = (size_t) cipherLen;
        if (NULL != secretlen) *secretlen = (size_t) ssLen;
        if (NULL == outlen && NULL == secretlen)
            return 0;

        return 1;
    }

    status = CRYPTO_INTERFACE_QS_KEM_encapsulate((QS_CTX *) pKey->pKeyData, DIGI_EVP_RandomRngFun, NULL, (ubyte *) out,
                                                 cipherLen, (ubyte *) secret, ssLen);
    if (OK != status)
        goto exit;

    *outlen = (size_t) cipherLen;
    *secretlen = (size_t) ssLen;

exit:

    return (OK == status ? 1 : 0);
}

static int digiprov_pqc_decapsulate(void *vctx, unsigned char *out, size_t *outlen, const unsigned char *in, size_t inlen)
{
    MSTATUS status = OK;
    DP_PQCKEM_CTX *pCtx = (DP_PQCKEM_CTX *) vctx;
    DP_PQC_KEY *pKey;
    ubyte4 ssLen = 0;

    if (!digiprov_is_running())
        return 0;

    if (NULL == pCtx)
        return 0;

    pKey = (DP_PQC_KEY *) pCtx->pKey;
    if (NULL == pKey)
        return 0;

    if (!digiprov_pqc_validate_key_for_op(pKey, pCtx->operation))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
        return 0;
    }

    status = CRYPTO_INTERFACE_QS_KEM_getSharedSecretLen((QS_CTX *) pKey->pKeyData, &ssLen);
    if (OK != status)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET); /* only possible error case */
        return 0;        
    }

    if (out == NULL)
    {
        if (NULL != outlen) *outlen = (size_t) ssLen;
            return 1;
        return 0;
    }

    status = CRYPTO_INTERFACE_QS_KEM_decapsulate((QS_CTX *) pKey->pKeyData, (ubyte *) in, (ubyte4) inlen,
                                                 (ubyte *) out, ssLen);
    if (OK != status)
        goto exit;

    *outlen = (size_t) ssLen;

exit:

    return (OK == status ? 1 : 0);
}

static void digiprov_pqc_kem_freectx(void *vctx)
{
    DP_PQCKEM_CTX *pCtx = (DP_PQCKEM_CTX *)vctx;

    digiprov_pqc_key_free(pCtx->pKey); /* might just lower the reference count */

    (void) DIGI_FREE((void **) &pCtx);
}

static void *digiprov_pqc_kem_dupctx(void *vctx)
{
    MSTATUS status = OK;
    DP_PQCKEM_CTX *pCtx = (DP_PQCKEM_CTX *) vctx;
    DP_PQCKEM_CTX *pNewCtx = NULL;

    if (!digiprov_is_running())
        return NULL;

    status = DIGI_CALLOC((void **) &pNewCtx, 1, sizeof(*pNewCtx));
    if (OK != status)
        return NULL;

    pNewCtx->libctx = pCtx->libctx;
    pNewCtx->operation = pCtx->operation;

    /* we don't deep copy the key, just update the ref count */
    if (NULL != pCtx->pKey && !digiprov_pqc_key_up_ref(pCtx->pKey))
        goto err;

    pNewCtx->pKey = pCtx->pKey;

    return pNewCtx;

 err:
    digiprov_pqc_kem_freectx(pNewCtx);
    return NULL; 
}

static int digiprov_pqc_kem_get_ctx_params(void *vctx, OSSL_PARAM *params)
{
    return vctx != NULL;
}

static const OSSL_PARAM digiprov_known_gettable_ctx_params[] = 
{
    OSSL_PARAM_END
};

static const OSSL_PARAM *digiprov_pqc_kem_gettable_ctx_params(ossl_unused void *vctx, ossl_unused void *provctx)
{
    return digiprov_known_gettable_ctx_params;
}

static int digiprov_pqc_kem_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    DP_PQCKEM_CTX *pCtx = (DP_PQCKEM_CTX *) vctx;
    const OSSL_PARAM *p;

    if (pCtx == NULL)
        return 0;
    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_KEM_PARAM_OPERATION);
    if (p != NULL) 
    {
        if (p->data_type != OSSL_PARAM_UTF8_STRING)
            return 0;

        if (DIGI_STRCMP((const sbyte *) p->data, (const sbyte *) "ML-KEM")) /* error if trying to use a different KEM than ML-KEM (for now) */
            return 0;
    }

    return 1;
}

static const OSSL_PARAM digiprov_known_settable_ctx_params[] = 
{
    OSSL_PARAM_utf8_string(OSSL_KEM_PARAM_OPERATION, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *digiprov_pqc_kem_settable_ctx_params(ossl_unused void *vctx, ossl_unused void *provctx)
{
    return digiprov_known_settable_ctx_params;
}

const OSSL_DISPATCH digiprov_pqc_kem_functions[] = 
{
    { OSSL_FUNC_KEM_NEWCTX,              (void (*)(void))digiprov_pqc_kem_newctx },
    { OSSL_FUNC_KEM_ENCAPSULATE_INIT,    (void (*)(void))digiprov_pqc_encapsulate_init },
    { OSSL_FUNC_KEM_ENCAPSULATE,         (void (*)(void))digiprov_pqc_encapsulate },
    { OSSL_FUNC_KEM_DECAPSULATE_INIT,    (void (*)(void))digiprov_pqc_decapsulate_init },
    { OSSL_FUNC_KEM_DECAPSULATE,         (void (*)(void))digiprov_pqc_decapsulate },
    { OSSL_FUNC_KEM_FREECTX,             (void (*)(void))digiprov_pqc_kem_freectx },
    { OSSL_FUNC_KEM_DUPCTX,              (void (*)(void))digiprov_pqc_kem_dupctx },
    { OSSL_FUNC_KEM_GET_CTX_PARAMS,      (void (*)(void))digiprov_pqc_kem_get_ctx_params },
    { OSSL_FUNC_KEM_GETTABLE_CTX_PARAMS, (void (*)(void))digiprov_pqc_kem_gettable_ctx_params },
    { OSSL_FUNC_KEM_SET_CTX_PARAMS,      (void (*)(void))digiprov_pqc_kem_set_ctx_params },
    { OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS, (void (*)(void))digiprov_pqc_kem_settable_ctx_params },
    { 0, NULL }
};

#endif /* #ifdef __ENABLE_DIGICERT_PQC__ */
