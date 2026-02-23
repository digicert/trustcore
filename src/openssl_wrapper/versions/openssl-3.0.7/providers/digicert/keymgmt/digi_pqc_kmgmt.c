/*
 * digi_pqc_keymgmt.c
 *
 * PQC keygen implementations for OSSL 3.0 provider
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

/*---------------------------------------------------------------------------------------------------------*/

#include "../../../src/common/moptions.h"

#ifdef __ENABLE_DIGICERT_PQC__

#include "../../../src/common/mtypes.h"
#include "../../../src/common/mdefs.h"
#include "../../../src/common/merrors.h"
#include "../../../src/common/mstdlib.h"
#include "../../../src/common/mrtos.h"
#include "../../../src/common/random.h"
#include "../../../src/crypto/ca_mgmt.h"
#include "../../../src/cap/capasym.h"
#include "../../../src/crypto_interface/crypto_interface_qs.h"
#include "../../../src/crypto_interface/crypto_interface_qs_sig.h"

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
#include "internal/param_build_set.h"

#define PQC_POSSIBLE_SELECTIONS \
    (OSSL_KEYMGMT_SELECT_KEYPAIR)

/* min and max cid's from ca_mgmt.h, update if new algs are added */
#define DP_PQC_SIGN_MIN_CID cid_PQC_MLDSA_44
#define DP_PQC_SIGN_MAX_CID cid_PQC_SLHDSA_SHAKE_256F
#define DP_PQC_KEM_MIN_CID  cid_PQC_MLKEM_512
#define DP_PQC_KEM_MAX_CID  cid_PQC_MLKEM_1024
#define MLKEM_PRIV_SEED_LEN 32

struct dp_pqc_gen_ctx 
{
    OSSL_LIB_CTX *libctx;
    size_t cid;
    size_t secSize;
    int selection;
};

sbyte4 DIGI_EVP_RandomRngFun(void *pRngFunArg, ubyte4 length, ubyte *pBuffer);
static int digiprov_pqc_set_params_internal(void *key, const OSSL_PARAM params[], byteBoolean allowEmptyPub);
extern void digiprov_pqc_key_free(DP_PQC_KEY *pKey);

extern int digiprov_pqc_key_up_ref(DP_PQC_KEY *pKey)
{
    int i;

    if (CRYPTO_UP_REF(&pKey->references, &i, pKey->lock) <= 0)
        return 0;

    REF_PRINT_COUNT("PQC_KEY", r);
    REF_ASSERT_ISNT(i < 2);
    return ((i > 1) ? 1 : 0);
}

static DP_PQC_KEY *digiprov_pqc_new_key(OSSL_LIB_CTX *libctx, size_t cid, size_t secSize, const char *propq)
{
    MSTATUS status = OK;
    DP_PQC_KEY *pRet = NULL;
    QS_CTX *pNew = NULL;

    if (!digiprov_is_running())
        return NULL;
 
    status = DIGI_CALLOC((void **) &pRet, 1, sizeof(DP_PQC_KEY));
    if (OK != status)
        return NULL;

    status = CRYPTO_INTERFACE_QS_newCtx(&pNew, cid);
    if (OK != status)
        goto err;

    pRet->pKeyData = (void *) pNew; pNew = NULL;
    pRet->cid = cid;
    pRet->secSize = secSize;
    pRet->libctx = libctx;
    pRet->references = 1;

    if (propq != NULL) 
    {
        status = digiprov_strdup((void **) &pRet->propq, propq);
        if (OK != status)
            goto err;
    }

    pRet->lock = CRYPTO_THREAD_lock_new();
    if (pRet->lock == NULL)
        goto err;

    return pRet;

err:

   if (NULL != pNew)
   {
       (void) CRYPTO_INTERFACE_QS_deleteCtx(&pNew);
   }

   if (NULL != pRet)
   {
       digiprov_pqc_key_free(pRet);
   }

   return NULL;
}

extern void digiprov_pqc_key_free(DP_PQC_KEY *pKey)
{
    int i = 0;

    if (pKey == NULL)
        return;

    CRYPTO_DOWN_REF(&pKey->references, &i, pKey->lock);
    REF_PRINT_COUNT("PQC_KEY", pKey);
    if (i > 0)
        return;
    REF_ASSERT_ISNT(i < 0);

    if (NULL != pKey->propq)
    {
        (void) DIGI_FREE((void **)&pKey->propq);
    }

    if (NULL != pKey->pKeyData)
    {
        (void) CRYPTO_INTERFACE_QS_deleteCtx((QS_CTX **) &pKey->pKeyData);
        pKey->secSize = 0;
        pKey->cid = 0;
    }

    CRYPTO_THREAD_lock_free(pKey->lock);
    (void) DIGI_MEMSET_FREE((ubyte **) &pKey, sizeof(DP_PQC_KEY));
}

static int digiprov_pqc_has(const void *keydata, int selection)
{
    DP_PQC_KEY *pKey = (DP_PQC_KEY *) keydata;
    int ok = 0;

    if (!digiprov_is_running())
        return 0;

    if (pKey != NULL)
    {
        ok = 1;

        if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
            ok = ok && pKey->hasPubKey;

        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
            ok = ok && pKey->hasPrivKey;
    }
    return ok;
}

static int digiprov_pqc_match(const void *keydata1, const void *keydata2, int selection)
{
    MSTATUS status = OK;
    DP_PQC_KEY *pKey1 = (DP_PQC_KEY *) keydata1;
    DP_PQC_KEY *pKey2 = (DP_PQC_KEY *) keydata2;
    int ok = 1;

    if (!digiprov_is_running())
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0)
        ok = ok && (pKey1->cid == pKey2->cid);
     
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) 
    {
        ubyte4 keyType = MOC_ASYM_KEY_TYPE_PUBLIC;
        byteBoolean isEqual = TRUE;

        if (1 != pKey1->hasPubKey || 1 != pKey2->hasPubKey)
            return 0;
        
        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        {
            if (1 != pKey1->hasPrivKey || 1 != pKey2->hasPrivKey)
                return 0;

            keyType = MOC_ASYM_KEY_TYPE_PRIVATE;
        }

        status = CRYPTO_INTERFACE_QS_equalKey((QS_CTX *) pKey1->pKeyData, (QS_CTX *) pKey2->pKeyData, keyType, &isEqual);
        if (OK != status || TRUE != isEqual)
        {
            return 0;
        }
    }

    return ok;
}

static int digiprov_pqc_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    DP_PQC_KEY *pKey = keydata;

    if (!digiprov_is_running())
        return 0;
    
    if (pKey == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return 0;

    return digiprov_pqc_set_params_internal(pKey, params, TRUE);
}

static int digiprov_pqc_export(void *keydata, int selection, OSSL_CALLBACK *param_cb, void *cbarg)
{
    MSTATUS status = OK;
    DP_PQC_KEY *pKey = keydata;
    OSSL_PARAM_BLD *tmpl = NULL;
    OSSL_PARAM *params = NULL;
    ubyte *pPri = NULL;
    ubyte4 priLen = 0;
    ubyte *pPub = NULL;
    ubyte4 pubLen = 0;
    int ret = 0;

    if (!digiprov_is_running())
        return 0;
    
    if (pKey == NULL)
        return 0;

    tmpl = OSSL_PARAM_BLD_new();
    if (tmpl == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) 
    {  
        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY))
        {
            status = CRYPTO_INTERFACE_QS_getPrivateKeyAlloc((QS_CTX *) pKey->pKeyData, &pPri, &priLen);
            if (OK != status)
                goto exit;

            if (!ossl_param_build_set_octet_string(tmpl, params, OSSL_PKEY_PARAM_PRIV_KEY, (unsigned char *) pPri, (size_t) priLen))
                goto exit;
        }

        if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY))
        {
            status = CRYPTO_INTERFACE_QS_getPublicKeyAlloc((QS_CTX *) pKey->pKeyData, &pPub, &pubLen);
            if (OK != status)
                goto exit;

            if (!ossl_param_build_set_octet_string(tmpl, params, OSSL_PKEY_PARAM_PUB_KEY, (unsigned char *) pPub, (size_t) pubLen))
                goto exit;
        }

    }

    params = OSSL_PARAM_BLD_to_param(tmpl);
    if (params == NULL)
        goto exit;

    ret = param_cb(params, cbarg);
    OSSL_PARAM_free(params); /* params only allocated right above, no need to free in exit block */

exit:

    OSSL_PARAM_BLD_free(tmpl);
    
    if (NULL != pPub)
    {
        (void) DIGI_MEMSET_FREE(&pPub, pubLen);
    }

    if (NULL != pPri)
    {
        (void) DIGI_MEMSET_FREE(&pPri, priLen);
    }

    return ret;
}

static const OSSL_PARAM PQC_KEY_TYPES[] = 
{
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *digiprov_pqc_imexport_types(int selection)
{
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
        return PQC_KEY_TYPES;
    return NULL;
}

static int digiprov_pqc_get_params(void *key, OSSL_PARAM params[])
{
    MSTATUS status = OK;
    DP_PQC_KEY *pKey = key;
    OSSL_PARAM *p = NULL;
    ubyte *pPub = NULL;
    ubyte4 pubLen = 0;
    ubyte *pPri = NULL;
    ubyte4 priLen = 0;
    int ret = 1;

    if (!digiprov_is_running())
        return 0;
    
    if (pKey == NULL)
        return 0;
    
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS)) != NULL
        && !OSSL_PARAM_set_int(p, pKey->secSize))
        return 0;

    /* We use the signature len for now, may need to use privLen for mldsa if export/import pri keys doesn't work */
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE)) != NULL)
    {
        ubyte4 len = 0;
        
        if (pKey->cid >= DP_PQC_SIGN_MIN_CID || pKey->cid <= DP_PQC_SIGN_MAX_CID)
        {
            /* For ML-DSA the largest size is the private key, but for now signature len is ok
               For SLH-DSA the largest size is the sig len */
            status = CRYPTO_INTERFACE_QS_SIG_getSignatureLen((QS_CTX *) pKey->pKeyData, &len);
        }
        else if (pKey->cid >= DP_PQC_KEM_MIN_CID || pKey->cid <= DP_PQC_KEM_MAX_CID)
        {
            /* For ML-KEM the largest size is the private key, which is twice that of 
               the public key plus another 32 byte seed */
            status = CRYPTO_INTERFACE_QS_getPublicKeyLen((QS_CTX *) pKey->pKeyData, &len);
            len = len * 2 + MLKEM_PRIV_SEED_LEN;
        } /* else len is still 0 */
        if (OK != status)
            return 0;

        if(!OSSL_PARAM_set_int(p, (int) len))
            return 0;
    }
    
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY)) != NULL) 
    {
        status = CRYPTO_INTERFACE_QS_getPublicKeyAlloc((QS_CTX *) pKey->pKeyData, &pPub, &pubLen);
        if (OK != status)
            return 0;
        
        /* from here on pPub is allocated so goto exit on error */
        if (!OSSL_PARAM_set_octet_string(p, (void *) pPub, (size_t) pubLen))
        {
            ret = 0;
            goto exit;
        }
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PRIV_KEY)) != NULL) 
    {
        status = CRYPTO_INTERFACE_QS_getPrivateKeyAlloc((QS_CTX *) pKey->pKeyData, &pPri, &priLen);
        if (OK != status)
        {
            ret = 0;
            goto exit;
        }
        
        /* from here on pPub is allocated so goto exit on error */
        if (!OSSL_PARAM_set_octet_string(p, (void *) pPri, (size_t) priLen))
        {
            ret = 0;
            goto exit;
        }
    }

    /* For now treat an encoded public key the same, once the encoding specs are standardized we can change this */
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY)) != NULL) 
    {
        if (NULL == pPub)
        {
            status = CRYPTO_INTERFACE_QS_getPublicKeyAlloc((QS_CTX *) pKey->pKeyData, &pPub, &pubLen);
            if (OK != status)
            {
                ret = 0;
                goto exit;
            }
        }

        if (!OSSL_PARAM_set_octet_string(p, (void *) pPub, (size_t) pubLen))
        {
            ret = 0;
            goto exit;
        }
    }

exit:

    if (NULL != pPub)
    {
        (void) DIGI_MEMSET_FREE(&pPub, pubLen);
    }

    if (NULL != pPri)
    {
        (void) DIGI_MEMSET_FREE(&pPri, priLen);
    }

    return ret;
}

static const OSSL_PARAM digiprov_pqc_gettable_params[] = 
{
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_END
};


static int digiprov_set_property_query(DP_PQC_KEY *pKey, const char *propq)
{
    MSTATUS status = OK;

    if (NULL == pKey)
        return 0;

    if (NULL != pKey->propq)
    {
        status = DIGI_FREE((void **) &pKey->propq);
        if (OK != status)
            return 0;
    }

    if (propq != NULL) 
    {
        status = digiprov_strdup((void **) &pKey->propq, propq);
        if (OK != status)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            return 0;
        }
    }
    return 1;
}

static int digiprov_pqc_set_params_internal(void *key, const OSSL_PARAM params[], byteBoolean allowEmptyPub)
{
    MSTATUS status = OK;
    DP_PQC_KEY *pKey = key;
    const OSSL_PARAM *p = NULL;
    byteBoolean pubSet = FALSE;

    if (params == NULL)
        return 1;

    if (!digiprov_is_running())
        return 0;
    
    if (pKey == NULL)
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
    if (p != NULL) 
    {
        if (p->data_type != OSSL_PARAM_OCTET_STRING)
            return 0;

        if (p->data != NULL && p->data_size)
        {
            /* this call will validate the length (p->data_size) is correct */
            status = CRYPTO_INTERFACE_QS_setPublicKey((QS_CTX *) pKey->pKeyData, (ubyte *) p->data, (ubyte4) p->data_size);
            if (OK != status)
                return 0;
            
            pKey->hasPubKey = 1;
            pubSet = TRUE;
        }
        else if (!allowEmptyPub) /* error if not allowed */
        {
            return 0;
        } /* else continue and ignore the empty public key */
    }
    
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
    if (p != NULL) 
    {
        if (p->data_type != OSSL_PARAM_OCTET_STRING)
            return 0;

        if (p->data != NULL && p->data_size)
        {
            /* this call will validate the length (p->data_size) is correct */
            status = CRYPTO_INTERFACE_QS_setPrivateKey((QS_CTX *) pKey->pKeyData, (ubyte *) p->data, (ubyte4) p->data_size);
            if (OK != status)
                return 0;
            
            pKey->hasPrivKey = 1;
        }
        else
        {
            return 0;
        }
    }

    /* For now also do the same with an encoded public key, but error if user entered both pub and encoded pub */
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    if (p != NULL) 
    {
        if (pubSet)
            return 0;

        if (p->data_type != OSSL_PARAM_OCTET_STRING)
            return 0;

        /* this call will validate the length (p->data_size) is correct */
        status = CRYPTO_INTERFACE_QS_setPublicKey((QS_CTX *) pKey->pKeyData, (ubyte *) p->data, (ubyte4) p->data_size);
        if (OK != status)
            return 0;
        
        pKey->hasPubKey = 1;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PROPERTIES);
    if (p != NULL) 
    {
        if (p->data_type != OSSL_PARAM_UTF8_STRING || !digiprov_set_property_query(pKey, p->data))
            return 0;
    }

    return 1;
}

static int digiprov_pqc_set_params(void *key, const OSSL_PARAM params[])
{
    return digiprov_pqc_set_params_internal(key, params, FALSE);
}

static const OSSL_PARAM pqc_settable_params[] = 
{
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *digiprov_pqc_settable_params(void *provctx)
{
    return pqc_settable_params;
}

static void *digiprov_pqc_gen_init(void *provctx, int selection, size_t cid, size_t secSize, const OSSL_PARAM params[])
{
    MSTATUS status = OK;
    OSSL_LIB_CTX *libctx = PROV_LIBCTX_OF(provctx);
    struct dp_pqc_gen_ctx *pGenCtx = NULL;
    MOC_UNUSED(params);

    if (!digiprov_is_running())
        return NULL;
    
    if ((selection & (PQC_POSSIBLE_SELECTIONS)) == 0)
        return NULL;

    status = DIGI_CALLOC((void **) &pGenCtx, 1, sizeof(*pGenCtx));
    if (OK != status)
        return NULL;

    pGenCtx->libctx = libctx;
    pGenCtx->selection = selection;
    pGenCtx->cid = cid;
    pGenCtx->secSize = secSize;
    
    return pGenCtx;
}

static void *digiprov_pqc_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
    MSTATUS status = OK;
    struct dp_pqc_gen_ctx *pGenCtx = genctx;
    DP_PQC_KEY *pKey = NULL;

    if (!digiprov_is_running())
        return NULL;
    
    if (NULL == pGenCtx)
        return NULL;

    pKey = digiprov_pqc_new_key(pGenCtx->libctx, pGenCtx->cid, pGenCtx->secSize, NULL);
    if (NULL == pKey)
        return NULL;

    if ((pGenCtx->selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
    {
        status = CRYPTO_INTERFACE_QS_generateKeyPair((QS_CTX *) pKey->pKeyData, DIGI_EVP_RandomRngFun, NULL);
        if (OK != status)
            goto err;

        pKey->hasPubKey = 1;
        pKey->hasPrivKey = 1;
    }
    
    return pKey;

err:

    if (NULL != pKey)
    {
        digiprov_pqc_key_free(pKey);
    }

    return NULL;
}

static void digiprov_pqc_gen_cleanup(void *genctx)
{
    struct dp_pqc_gen_ctx *pGenCtx = genctx;

    if (NULL != pGenCtx)
    {
        (void) DIGI_FREE((void **) &pGenCtx);
    }
}

static void *digiprov_pqc_load(const void *reference, size_t reference_sz)
{
    DP_PQC_KEY *pKey = NULL;

    if (digiprov_is_running() && reference_sz == sizeof(pKey))
    {
        /* The contents of the reference is the address to our object */
        pKey = *(DP_PQC_KEY **)reference;
        /* We grabbed, so we detach it */
        *(DP_PQC_KEY **)reference = NULL;
        return pKey;
    }
    return NULL;
}

static void *digiprov_pqc_dup(const void *keydata_from, int selection)
{
    MSTATUS status = OK;
    DP_PQC_KEY *pKey = (DP_PQC_KEY *) keydata_from;
    DP_PQC_KEY *pRet = NULL;

    if (!digiprov_is_running())
        return NULL;
    
    status = DIGI_CALLOC((void **) &pRet, 1, sizeof(DP_PQC_KEY));
    if (OK != status)
        goto exit;

    pRet->lock = CRYPTO_THREAD_lock_new();
    if (pRet->lock == NULL) 
    {
        status = ERR_GENERAL;
        goto exit;
    }

    pRet->libctx = pKey->libctx;
    pRet->cid = pKey->cid;
    pRet->secSize = pKey->secSize;
    pRet->hasPubKey = pKey->hasPubKey;
    pRet->hasPrivKey = pKey->hasPrivKey;

    pRet->references = 1;

    if (NULL != pKey->propq) 
    {
        status = digiprov_strdup((void **) &pRet->propq, pKey->propq);
        if (OK != status)
            goto exit;
    }

    if (NULL != pKey->pKeyData)
    {
        status = CRYPTO_INTERFACE_QS_cloneCtx((QS_CTX **) &pRet->pKeyData, (QS_CTX *) pKey->pKeyData); 
        if (OK != status)
            goto exit;
    }

exit:
    
    if (OK != status && NULL != pRet)
    {
        digiprov_pqc_key_free(pRet);
        pRet = NULL;
    }

    return (void *) pRet;
}

extern int digiprov_pqc_validate_key_for_op(DP_PQC_KEY *pKey, int operation)
{
    switch(operation)
    {
        case EVP_PKEY_OP_SIGN:

            /* make sure it's a private signing key */
            if (pKey->hasPrivKey && pKey->cid >= DP_PQC_SIGN_MIN_CID && pKey->cid <= DP_PQC_SIGN_MAX_CID)
                return 1;
            break;
        
        case EVP_PKEY_OP_VERIFY:

            /* make sure it's a public verify key */
            if (pKey->hasPubKey && pKey->cid >= DP_PQC_SIGN_MIN_CID && pKey->cid <= DP_PQC_SIGN_MAX_CID)
                return 1;
            break;

        case EVP_PKEY_OP_ENCAPSULATE:

            /* make sure it's a public encapsulate key */
            if (pKey->hasPubKey && pKey->cid >= DP_PQC_KEM_MIN_CID && pKey->cid <= DP_PQC_KEM_MAX_CID)
                return 1;
            break;

        case EVP_PKEY_OP_DECAPSULATE:

            /* make sure it's a private decapsulate key */
            if (pKey->hasPrivKey && pKey->cid >= DP_PQC_KEM_MIN_CID && pKey->cid <= DP_PQC_KEM_MAX_CID)
                return 1;
            break;

        default:
            return 0;
    }

    return 0;
}

static int digiprov_pqc_validate(const void *keydata, int selection, int checktype)
{
    DP_PQC_KEY *pKey = (DP_PQC_KEY *) keydata;
    int ok = 1;

    if (!digiprov_is_running())
        return 0;
    
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        ok = ok && pKey->hasPubKey;

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        ok = ok && pKey->hasPrivKey;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == OSSL_KEYMGMT_SELECT_KEYPAIR)
    {
        byteBoolean isValid = FALSE;
        MSTATUS status = CRYPTO_INTERFACE_QS_validateKeyPair((QS_CTX *) pKey->pKeyData, DIGI_EVP_RandomRngFun, NULL, &isValid);
        if (OK != status || TRUE != isValid)
        {
            return 0;
        }
    }

    return ok;
}

#define MAKE_KEYMGMT_FUNCTIONS(alg, cid, secSize)\
    static void *digiprov_##alg##_new_key(void *provctx)\
    {\
        return digiprov_pqc_new_key(PROV_LIBCTX_OF(provctx), cid, secSize, NULL);\
    }\
    static void *digiprov_##alg##_gen_init(void *provctx, int selection, const OSSL_PARAM params[])\
    {\
        return digiprov_pqc_gen_init(provctx, selection, cid, secSize, params);\
    }\
    const OSSL_DISPATCH digiprov_##alg##_keymgmt_functions[] = { \
        { OSSL_FUNC_KEYMGMT_NEW,                 (void (*)(void))digiprov_##alg##_new_key }, \
        { OSSL_FUNC_KEYMGMT_FREE,                (void (*)(void))digiprov_pqc_key_free }, \
        { OSSL_FUNC_KEYMGMT_GET_PARAMS,          (void (*)(void))digiprov_pqc_get_params }, \
        { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,     (void (*)(void))digiprov_pqc_gettable_params }, \
        { OSSL_FUNC_KEYMGMT_SET_PARAMS,          (void (*)(void))digiprov_pqc_set_params }, \
        { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,     (void (*)(void))digiprov_pqc_settable_params }, \
        { OSSL_FUNC_KEYMGMT_HAS,                 (void (*)(void))digiprov_pqc_has }, \
        { OSSL_FUNC_KEYMGMT_MATCH,               (void (*)(void))digiprov_pqc_match }, \
        { OSSL_FUNC_KEYMGMT_VALIDATE,            (void (*)(void))digiprov_pqc_validate }, \
        { OSSL_FUNC_KEYMGMT_IMPORT,              (void (*)(void))digiprov_pqc_import }, \
        { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,        (void (*)(void))digiprov_pqc_imexport_types }, \
        { OSSL_FUNC_KEYMGMT_EXPORT,              (void (*)(void))digiprov_pqc_export }, \
        { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,        (void (*)(void))digiprov_pqc_imexport_types }, \
        { OSSL_FUNC_KEYMGMT_GEN_INIT,            (void (*)(void))digiprov_##alg##_gen_init }, \
        { OSSL_FUNC_KEYMGMT_GEN,                 (void (*)(void))digiprov_pqc_gen }, \
        { OSSL_FUNC_KEYMGMT_GEN_CLEANUP,         (void (*)(void))digiprov_pqc_gen_cleanup }, \
        { OSSL_FUNC_KEYMGMT_LOAD,                (void (*)(void))digiprov_pqc_load }, \
        { OSSL_FUNC_KEYMGMT_DUP,                 (void (*)(void))digiprov_pqc_dup }, \
        { 0, NULL } \
    };

MAKE_KEYMGMT_FUNCTIONS(mldsa44, cid_PQC_MLDSA_44, 128)
MAKE_KEYMGMT_FUNCTIONS(mldsa65, cid_PQC_MLDSA_65, 192)
MAKE_KEYMGMT_FUNCTIONS(mldsa87, cid_PQC_MLDSA_87, 256)
MAKE_KEYMGMT_FUNCTIONS(mlkem512, cid_PQC_MLKEM_512, 128)
MAKE_KEYMGMT_FUNCTIONS(mlkem768, cid_PQC_MLKEM_768, 192)
MAKE_KEYMGMT_FUNCTIONS(mlkem1024, cid_PQC_MLKEM_1024, 256)
MAKE_KEYMGMT_FUNCTIONS(slhdsa_sha2_128f, cid_PQC_SLHDSA_SHA2_128F, 128)
MAKE_KEYMGMT_FUNCTIONS(slhdsa_sha2_128s, cid_PQC_SLHDSA_SHA2_128S, 128)
MAKE_KEYMGMT_FUNCTIONS(slhdsa_sha2_192f, cid_PQC_SLHDSA_SHA2_192F, 192)
MAKE_KEYMGMT_FUNCTIONS(slhdsa_sha2_192s, cid_PQC_SLHDSA_SHA2_192F, 192)
MAKE_KEYMGMT_FUNCTIONS(slhdsa_sha2_256f, cid_PQC_SLHDSA_SHA2_256F, 256)
MAKE_KEYMGMT_FUNCTIONS(slhdsa_sha2_256s, cid_PQC_SLHDSA_SHA2_256F, 256)
MAKE_KEYMGMT_FUNCTIONS(slhdsa_shake_128f, cid_PQC_SLHDSA_SHAKE_128F, 128)
MAKE_KEYMGMT_FUNCTIONS(slhdsa_shake_128s, cid_PQC_SLHDSA_SHAKE_128S, 128)
MAKE_KEYMGMT_FUNCTIONS(slhdsa_shake_192f, cid_PQC_SLHDSA_SHAKE_192F, 192)
MAKE_KEYMGMT_FUNCTIONS(slhdsa_shake_192s, cid_PQC_SLHDSA_SHAKE_192S, 192)
MAKE_KEYMGMT_FUNCTIONS(slhdsa_shake_256f, cid_PQC_SLHDSA_SHAKE_256F, 256)
MAKE_KEYMGMT_FUNCTIONS(slhdsa_shake_256s, cid_PQC_SLHDSA_SHAKE_256S, 256)

#endif /* #ifdef __ENABLE_DIGICERT_PQC__ */
