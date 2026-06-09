/*
 * digi_mlx_kmgmt.c
 *
 * MLX PQC/ECC Hybrid keyexch keygen implementations for OSSL 3.0 provider
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
#include "../../../src/cap/capasym.h"
#include "../../../src/common/vlong.h"
#include "../../../src/common/random.h"
#include "../../../src/crypto/ca_mgmt.h"
#include "../../../src/crypto/primeec.h"
#include "../../../src/crypto/ecc.h"
#include "../../../src/crypto_interface/crypto_interface_ecc.h"
#include "../../../src/crypto_interface/crypto_interface_qs.h"

#include "mocana_glue.h"
#include "digicert_common.h"

#ifdef CONTEXT
#undef CONTEXT
#endif

#ifdef BOOLEAN
#undef BOOLEAN
#endif

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

#define SecP256r1MLKEM768 0
#define SecP384r1MLKEM1024 1
#define X25519MLKEM768 2
#define X448MLKEM1024 3

static OSSL_FUNC_keymgmt_gen_fn digi_mlx_kem_gen;
static OSSL_FUNC_keymgmt_gen_cleanup_fn digi_mlx_kem_gen_cleanup;
static OSSL_FUNC_keymgmt_gen_set_params_fn digi_mlx_kem_gen_set_params;
static OSSL_FUNC_keymgmt_gen_settable_params_fn digi_mlx_kem_gen_settable_params;
static OSSL_FUNC_keymgmt_get_params_fn digi_mlx_kem_get_params;
static OSSL_FUNC_keymgmt_gettable_params_fn digi_mlx_kem_gettable_params;
static OSSL_FUNC_keymgmt_set_params_fn digi_mlx_kem_set_params;
static OSSL_FUNC_keymgmt_settable_params_fn digi_mlx_kem_settable_params;
static OSSL_FUNC_keymgmt_has_fn digi_mlx_kem_has;
static OSSL_FUNC_keymgmt_match_fn digi_mlx_kem_match;
static OSSL_FUNC_keymgmt_import_fn digi_mlx_kem_import;
static OSSL_FUNC_keymgmt_export_fn digi_mlx_kem_export;
static OSSL_FUNC_keymgmt_import_types_fn digi_mlx_kem_imexport_types;
static OSSL_FUNC_keymgmt_export_types_fn digi_mlx_kem_imexport_types;
static OSSL_FUNC_keymgmt_dup_fn digi_mlx_kem_dup;

static const int minimal_selection = OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS | OSSL_KEYMGMT_SELECT_PRIVATE_KEY;

sbyte4 DIGI_EVP_RandomRngFun(void *pRngFunArg, ubyte4 length, ubyte *pBuffer);

typedef struct _DP_MLX_GEN_CTX 
{
    OSSL_LIB_CTX *libctx;
    char *propq;
    int selection;
    unsigned int variant;

} DP_MLX_GEN_CTX;

static int digi_mlx_kem_set_property_query(void *pIn, const char *propq, byteBoolean isGenCtx)
{
    MSTATUS status = OK;
    char *pCopy = NULL;

    if (NULL == pIn)
        return 0;

    if (propq != NULL) 
    {
        status = digiprov_strdup((void **) &pCopy, propq);
        if (OK != status)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            return 0;
        }
    }

    if (isGenCtx)
    {
        DP_MLX_GEN_CTX *pGen = pIn;
        (void) DIGI_FREE((void **) &pGen->propq);
        pGen->propq = pCopy; pCopy = NULL;
    }
    else
    {
        DP_MLX_KEY *pKey = pIn;
        (void) DIGI_FREE((void **) &pKey->propq);
        pKey->propq = pCopy; pCopy = NULL;
    }

    return 1;
}

static void digi_mlx_kem_key_free(void *vkey)
{
    DP_MLX_KEY *pKey = (DP_MLX_KEY *) vkey;

    if (NULL == pKey)
        return;

    if (NULL != pKey->propq)
    {
        (void) DIGI_FREE((void **)&pKey->propq);
    }

    if (NULL != pKey->pPQCKeyData)
    {
        (void) CRYPTO_INTERFACE_QS_deleteCtx((QS_CTX **) &pKey->pPQCKeyData);
    }

    if (NULL != pKey->pECCKeyData)
    {
        (void) CRYPTO_INTERFACE_EC_deleteKeyAux((ECCKey **) &pKey->pECCKeyData);
    }

    (void) DIGI_MEMSET_FREE((ubyte **) &pKey, sizeof(DP_MLX_KEY));
}

static void * digi_mlx_kem_key_new(unsigned int v, OSSL_LIB_CTX *libctx, char *propq)
{
    MSTATUS status;
    DP_MLX_KEY *pRet = NULL;
    QS_CTX *pNewQs = NULL;
    ECCKey *pNewEcc = NULL;

    if (!digiprov_is_running())
        return NULL;

    status = DIGI_CALLOC((void **) &pRet, 1, sizeof(DP_MLX_KEY));
    if (OK != status)
        return NULL;

    /* With only 4 variant options we'll just do a simple switch rather than create tables
       variable names are self explanatory, no need for MACROS for each constant */
    switch(v)
    {
        case SecP256r1MLKEM768:
            pRet->secSize = 192;
            pRet->cidECC = cid_EC_P256;
            pRet->pqcPrivLen = 2400;
            pRet->pqcPubLen = 1184;
            pRet->pqcCipherLen = 1088;
            pRet->curvePrivLen = 32;
            pRet->curvePubLen = 65;
            pRet->curveSSLen = 32;
            pRet->curveFirst = 1;
            break;
            
        case SecP384r1MLKEM1024:
            pRet->secSize = 256;
            pRet->cidECC = cid_EC_P384;
            pRet->pqcPrivLen = 3168;
            pRet->pqcPubLen = 1568;
            pRet->pqcCipherLen = 1568;
            pRet->curvePrivLen = 48;
            pRet->curvePubLen = 97;
            pRet->curveSSLen = 48;
            pRet->curveFirst = 1;
            break;

        case X25519MLKEM768:
            pRet->secSize = 192;
            pRet->cidECC = cid_EC_X25519;
            pRet->pqcPrivLen = 2400;
            pRet->pqcPubLen = 1184;
            pRet->pqcCipherLen = 1088;
            pRet->curvePrivLen = 32;
            pRet->curvePubLen = 32;
            pRet->curveSSLen = 32;
            pRet->curveFirst = 0;
            break;

        case X448MLKEM1024:
            pRet->secSize = 256;
            pRet->cidECC = cid_EC_X448;
            pRet->pqcPrivLen = 3168;
            pRet->pqcPubLen = 1568;
            pRet->pqcCipherLen = 1568;
            pRet->curvePrivLen = 56;
            pRet->curvePubLen = 56;
            pRet->curveSSLen = 56;
            pRet->curveFirst = 0;
            break;       

        default:
            (void) DIGI_FREE((void **) &pRet);
            return NULL;
    }

    /* use secSize as proxy for the ML-KEM alg */
    status = CRYPTO_INTERFACE_QS_newCtx(&pNewQs, 192 == pRet->secSize ? cid_PQC_MLKEM_768 : cid_PQC_MLKEM_1024);
    if (OK != status)
        goto err;

    status = CRYPTO_INTERFACE_EC_newKeyAux (pRet->cidECC, &pNewEcc);
    if (OK != status)
        goto err;

    pRet->pPQCKeyData = (void *) pNewQs; pNewQs = NULL;
    pRet->pECCKeyData = (void *) pNewEcc; pNewEcc = NULL;
    pRet->libctx = libctx;
    pRet->state = DP_MLX_HAVE_NOKEYS;
    
    if (propq != NULL) 
    {
        status = digiprov_strdup((void **) &pRet->propq, propq);
        if (OK != status)
            goto err;
    }

    return (void *) pRet;

err:

    if (NULL != pNewQs)
    {
        (void) CRYPTO_INTERFACE_QS_deleteCtx(&pNewQs);
    }

    if (NULL != pNewEcc)
    {
        (void) CRYPTO_INTERFACE_EC_deleteKeyAux(&pNewEcc);
    }

    if (NULL != pRet)
    {
        digi_mlx_kem_key_free(pRet);
    }

    return NULL;
}

static int digi_mlx_kem_has(const void *vkey, int selection)
{
    const DP_MLX_KEY *key = vkey;

    /* A NULL key MUST fail to have anything */
    if (!digiprov_is_running() || key == NULL)
        return 0;

    switch (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) {
    case 0:
        return 1;
    case OSSL_KEYMGMT_SELECT_PUBLIC_KEY:
        return digi_mlx_kem_have_pubkey(key);
    default:
        return digi_mlx_kem_have_prvkey(key);
    }
}

static int digi_mlx_kem_match(const void *vkey1, const void *vkey2, int selection)
{
    MSTATUS status;
    const DP_MLX_KEY *key1 = vkey1;
    const DP_MLX_KEY *key2 = vkey2;
    int have_pub1 = digi_mlx_kem_have_pubkey(key1);
    int have_pub2 = digi_mlx_kem_have_pubkey(key2);
    byteBoolean isEqual = FALSE;

    if (!digiprov_is_running())
        return 0;

    /* Compare domain parameters, we can use secSize as a proxy for mlkem
       As with openssl's provider we don't guard against completely corrupted data */
    if (key1->cidECC != key2->cidECC || key1->secSize != key2->secSize)
        return 0;

    if (!(selection & OSSL_KEYMGMT_SELECT_KEYPAIR)) /* we are done */
        return 1;

    if (have_pub1 ^ have_pub2)
        return 0;

    /* As in other providers, equal when both have no key material. */
    if (!have_pub1)
        return 1;

    /* As with openssl provider we just compare public keys */
    status = CRYPTO_INTERFACE_QS_equalKey((QS_CTX *) key1->pPQCKeyData, (QS_CTX *) key2->pPQCKeyData, MOC_ASYM_KEY_TYPE_PUBLIC, &isEqual);
    if (OK != status || TRUE != isEqual)
    {
        return 0;
    }

    status = CRYPTO_INTERFACE_EC_equalKeyAux((ECCKey *) key1->pECCKeyData, (ECCKey *) key2->pECCKeyData, &isEqual);
    if (OK != status || TRUE != isEqual)
    {
        return 0;
    }

    return 1;
}

static int digi_mlx_kem_get_key_alloc(DP_MLX_KEY *pKey, byteBoolean isPriv, ubyte **ppKeyBuf, ubyte4 *pKeyLen)
{
    MSTATUS status = OK;
    ubyte *pKeyBuf = NULL;
    ubyte4 keyLen = 0;
    ubyte *pPtr = NULL;
    MEccKeyTemplate template = {0};

    /* input validation checks already done */

    if (isPriv)
    {
        keyLen = pKey->curvePrivLen + pKey->pqcPrivLen;
        status = DIGI_MALLOC((void **) &pKeyBuf, keyLen);
        if (OK != status)
            goto exit;

        pPtr = pKeyBuf + pKey->curveFirst * pKey->curvePrivLen;
        status = CRYPTO_INTERFACE_QS_getPrivateKey((QS_CTX *) pKey->pPQCKeyData, pPtr, pKey->pqcPrivLen);
        if (OK != status)
            goto exit;

        status = CRYPTO_INTERFACE_EC_getKeyParametersAllocAux((ECCKey *) pKey->pECCKeyData, &template, MOC_GET_PRIVATE_KEY_DATA);
        if (OK != status)
            goto exit;

        pPtr = pKeyBuf + (1 - pKey->curveFirst) * pKey->pqcPrivLen;
        status = DIGI_MEMCPY(pPtr, template.pPrivateKey, template.privateKeyLen);
    }
    else
    {
        keyLen = pKey->curvePubLen + pKey->pqcPubLen;
        status = DIGI_MALLOC((void **) &pKeyBuf, keyLen);
        if (OK != status)
            goto exit;

        pPtr = pKeyBuf + pKey->curveFirst * pKey->curvePubLen;
        status = CRYPTO_INTERFACE_QS_getPublicKey((QS_CTX *) pKey->pPQCKeyData, pPtr, pKey->pqcPubLen);
        if (OK != status)
            goto exit;

        status = CRYPTO_INTERFACE_EC_getKeyParametersAllocAux((ECCKey *) pKey->pECCKeyData, &template, MOC_GET_PUBLIC_KEY_DATA);
        if (OK != status)
            goto exit;

        pPtr = pKeyBuf + (1 - pKey->curveFirst) * pKey->pqcPubLen;
        status = DIGI_MEMCPY(pPtr, template.pPublicKey, template.publicKeyLen);
    }

    *ppKeyBuf = pKeyBuf; pKeyBuf = NULL;
    *pKeyLen = keyLen;

exit:

     (void) CRYPTO_INTERFACE_EC_freeKeyTemplateAux((ECCKey *) pKey->pECCKeyData, &template);

     if (NULL != pKeyBuf)
     {
        (void) DIGI_MEMSET_FREE(&pKeyBuf, keyLen);
     }

     return (OK == status ? 1 : 0); 
}

static int digi_mlx_kem_export(void *vkey, int selection, OSSL_CALLBACK *param_cb, void *cbarg)
{
    DP_MLX_KEY *pKey = vkey;
    OSSL_PARAM_BLD *tmpl = NULL;
    OSSL_PARAM *params = NULL;
    ubyte *pPriv = NULL;
    ubyte4 privLen = 0;
    ubyte *pPub = NULL;
    ubyte4 pubLen = 0;
    int ret = 0;

    if (!digiprov_is_running() || pKey == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return 0;

    /* Fail when no key material has yet been provided */
    if (!digi_mlx_kem_have_pubkey(pKey))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return 0;
    }

    tmpl = OSSL_PARAM_BLD_new();
    if (tmpl == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY))
    {
        if (!digi_mlx_kem_get_key_alloc(pKey, TRUE, &pPriv, &privLen))
            goto exit;

        if (!ossl_param_build_set_octet_string(tmpl, params, OSSL_PKEY_PARAM_PRIV_KEY, (unsigned char *) pPriv, (size_t) privLen))
            goto exit;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY))
    {
        if (!digi_mlx_kem_get_key_alloc(pKey, FALSE, &pPub, &pubLen))
            goto exit;

        if (!ossl_param_build_set_octet_string(tmpl, params, OSSL_PKEY_PARAM_PUB_KEY, (unsigned char *) pPub, (size_t) pubLen))
            goto exit;
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

    if (NULL != pPriv)
    {
        (void) DIGI_MEMSET_FREE(&pPriv, privLen);
    }

    return ret;
}

static const OSSL_PARAM *digi_mlx_kem_imexport_types(int selection)
{
    static const OSSL_PARAM key_types[] = 
    {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
        OSSL_PARAM_END
    };

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
        return key_types;
    
    return NULL;
}

static int digi_mlx_kem_set_params_internal(void *key, const OSSL_PARAM params[], byteBoolean allowEmptyPub)
{
    MSTATUS status = OK;
    DP_MLX_KEY *pKey = key;
    const OSSL_PARAM *p = NULL;
    byteBoolean pubSet = FALSE;
    ubyte *pPtr = NULL;
    ubyte4 ptrLen = 0;

    if (params == NULL)
        return 1;

    if (!digiprov_is_running() || NULL == pKey)
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
    if (p != NULL) 
    {
        /* Key mutation is reportedly generally not allowed */
        if (digi_mlx_kem_have_pubkey(pKey)) 
        {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE, "keys cannot be mutated");
            return 0;
        }

        if (p->data_type != OSSL_PARAM_OCTET_STRING)
            return 0;

        if (p->data != NULL && p->data_size)
        {
            if ((ubyte4) p->data_size != pKey->curvePubLen + pKey->pqcPubLen) 
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
                return 0;
            }

            pPtr = (ubyte *) p->data + pKey->curveFirst * pKey->curvePubLen;
            ptrLen = (ubyte4) p->data_size - pKey->curvePubLen;
            status = CRYPTO_INTERFACE_QS_setPublicKey((QS_CTX *) pKey->pPQCKeyData, pPtr, ptrLen);
            if (OK != status)
                return 0;
            
            pPtr = (ubyte *) p->data + (1 - pKey->curveFirst) * pKey->pqcPubLen;
            ptrLen = (ubyte4) p->data_size - pKey->pqcPubLen;
            status = CRYPTO_INTERFACE_EC_setKeyParametersAux ((ECCKey *) pKey->pECCKeyData, pPtr, ptrLen, NULL, 0);
            if (OK != status)
                return 0;

            pKey->state = DP_MLX_HAVE_PUBKEY;
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
        /* Key mutation is reportedly generally not allowed */
        if (digi_mlx_kem_have_prvkey(pKey)) 
        {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE, "keys cannot be mutated");
            return 0;
        }

        if (p->data_type != OSSL_PARAM_OCTET_STRING)
            return 0;

        if (NULL == p->data || (ubyte4) p->data_size != pKey->curvePrivLen + pKey->pqcPrivLen) 
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
            return 0;
        }

        pPtr = (ubyte *) p->data + pKey->curveFirst * pKey->curvePrivLen;
        ptrLen = (ubyte4) p->data_size - pKey->curvePrivLen;
        status = CRYPTO_INTERFACE_QS_setPrivateKey((QS_CTX *) pKey->pPQCKeyData, pPtr, ptrLen);
        if (OK != status)
            return 0;

        pPtr = (ubyte *) p->data + (1 - pKey->curveFirst) * pKey->pqcPrivLen;
        ptrLen = (ubyte4) p->data_size - pKey->pqcPrivLen;
        status = CRYPTO_INTERFACE_EC_setKeyParametersAux ((ECCKey *) pKey->pECCKeyData, NULL, 0, pPtr, ptrLen);
        if (OK != status)
            return 0;
        
        pKey->state = DP_MLX_HAVE_PRVKEY;
    }

    /* For now also do the same with an encoded public key, but error if user entered both pub and encoded pub */
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    if (p != NULL) 
    {
        /* Key mutation is reportedly generally not allowed */
        if (pubSet || digi_mlx_kem_have_pubkey(pKey)) 
        {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE, "keys cannot be mutated");
            return 0;
        }

        if (p->data_type != OSSL_PARAM_OCTET_STRING)
            return 0;

        if (NULL == p->data || (ubyte4) p->data_size != pKey->curvePubLen + pKey->pqcPubLen) 
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
            return 0;
        }

        pPtr = (ubyte *) p->data + pKey->curveFirst * pKey->curvePubLen;
        ptrLen = (ubyte4) p->data_size - pKey->curvePubLen;
        status = CRYPTO_INTERFACE_QS_setPublicKey((QS_CTX *) pKey->pPQCKeyData, pPtr, ptrLen);
        if (OK != status)
            return 0;
        
        pPtr = (ubyte *) p->data + (1 - pKey->curveFirst) * pKey->pqcPubLen;
        ptrLen = (ubyte4) p->data_size - pKey->pqcPubLen;
        status = CRYPTO_INTERFACE_EC_setKeyParametersAux ((ECCKey *) pKey->pECCKeyData, pPtr, ptrLen, NULL, 0);
        if (OK != status)
            return 0;

        pKey->state = DP_MLX_HAVE_PUBKEY;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PROPERTIES);
    if (p != NULL) 
    {
        if (p->data_type != OSSL_PARAM_UTF8_STRING || !digi_mlx_kem_set_property_query((void *) pKey, p->data, FALSE))
            return 0;
    }

    return 1;
}

static int digi_mlx_kem_set_params(void *key, const OSSL_PARAM params[])
{    
    return digi_mlx_kem_set_params_internal(key, params, FALSE);
}

static int digi_mlx_kem_import(void *vkey, int selection, const OSSL_PARAM params[])
{
    DP_MLX_KEY *key = vkey;

    if (!digiprov_is_running() || key == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return 0;

    return digi_mlx_kem_set_params_internal(key, params, TRUE);
}

static const OSSL_PARAM *digi_mlx_kem_gettable_params(void *provctx)
{
    static const OSSL_PARAM arr[] = 
    {
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
        OSSL_PARAM_END
    };

    return arr;
}

static int digi_mlx_kem_get_params(void *vkey, OSSL_PARAM params[])
{
    DP_MLX_KEY *pKey = vkey;
    OSSL_PARAM *p = NULL;
    ubyte *pPriv = NULL;
    ubyte4 privLen = 0;
    ubyte *pPub = NULL;
    ubyte4 pubLen = 0;
    int ret = 0;

    if (!digiprov_is_running() || pKey == NULL)
        return 0;

    /* The reported "bit" count is those of the ML-KEM key */
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
    if (p != NULL)
    {
        int bits = 1024;
        
        /* use secSize as a proxy to get the ML-KEM key bits */
        if (192 == pKey->secSize)
            bits = 768;

        if (!OSSL_PARAM_set_int(p, bits))
            return 0;
    }

    /* The reported security bits are those of the ML-KEM key */
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
    if (p != NULL)
        if (!OSSL_PARAM_set_int(p, pKey->secSize))
            return 0;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
    if (p != NULL)
        if (!OSSL_PARAM_set_int(p, pKey->pqcCipherLen + pKey->curvePubLen))
            return 0;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PRIV_KEY);
    if (p != NULL)
    {
        if (!digi_mlx_kem_get_key_alloc(pKey, TRUE, &pPriv, &privLen))
            return 0;

        /* from here on pPriv is allocated so goto exit on error */
        if (!OSSL_PARAM_set_octet_string(p, (void *) pPriv, (size_t) privLen))
            goto exit;
    }

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    if (p != NULL)
    {
        if (!digi_mlx_kem_get_key_alloc(pKey, FALSE, &pPub, &pubLen))
            goto exit;

        if (!OSSL_PARAM_set_octet_string(p, (void *) pPub, (size_t) pubLen))
            goto exit;
    }      

    ret = 1;

exit:

    if (NULL != pPub)
    {
        (void) DIGI_MEMSET_FREE(&pPub, pubLen);
    }

    if (NULL != pPriv)
    {
        (void) DIGI_MEMSET_FREE(&pPriv, privLen);
    }

    return ret;
}

static const OSSL_PARAM *digi_mlx_kem_settable_params(void *provctx)
{
    static const OSSL_PARAM arr[] =
    {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_PROPERTIES, NULL, 0),
        OSSL_PARAM_END
    };

    return arr;
}

static int digi_mlx_kem_gen_set_params(void *vgctx, const OSSL_PARAM params[])
{
    DP_MLX_GEN_CTX *gctx = vgctx;
    const OSSL_PARAM *p;

    if (gctx == NULL)
        return 0;

    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PROPERTIES);
    if (p != NULL) 
    {
        if (p->data_type != OSSL_PARAM_UTF8_STRING || !digi_mlx_kem_set_property_query((void *) gctx, p->data, TRUE))
            return 0;
    }
    return 1;
}

static void *digi_mlx_kem_gen_init(int variant, OSSL_LIB_CTX *libctx,
                                   int selection, const OSSL_PARAM params[])
{
    MSTATUS status;
    DP_MLX_GEN_CTX *gctx = NULL;

    /*
     * We can only generate private keys, check that the selection is
     * appropriate.
     */
    if (!digiprov_is_running() || (selection & minimal_selection) == 0)
        return NULL;

    status = DIGI_CALLOC((void **) &gctx, 1, sizeof(DP_MLX_GEN_CTX));
    if (OK != status)
        return NULL;

    gctx->variant = variant;
    gctx->libctx = libctx;
    gctx->selection = selection;
    
    if (digi_mlx_kem_gen_set_params(gctx, params))
        return gctx;

    digi_mlx_kem_gen_cleanup(gctx);
    return NULL;
}

static const OSSL_PARAM *digi_mlx_kem_gen_settable_params(ossl_unused void *vgctx,
                                                          ossl_unused void *provctx)
{
    static OSSL_PARAM settable[] = 
    {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PROPERTIES, NULL, 0),
        OSSL_PARAM_END
    };

    return settable;
}

static void *digi_mlx_kem_gen(void *vgctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
    MSTATUS status;
    DP_MLX_GEN_CTX *gctx = vgctx;
    DP_MLX_KEY *pKey;
    MOC_UNUSED(osslcb);
    MOC_UNUSED(cbarg);

    if (gctx == NULL || (gctx->selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
        return NULL;

    if ((pKey = digi_mlx_kem_key_new(gctx->variant, gctx->libctx, gctx->propq)) == NULL)
        return NULL;

    if ((gctx->selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return pKey;

    status = CRYPTO_INTERFACE_QS_generateKeyPair((QS_CTX *) pKey->pPQCKeyData, DIGI_EVP_RandomRngFun, NULL);
    if (OK != status)
        goto err;

    status = CRYPTO_INTERFACE_EC_generateKeyPairAux ((ECCKey *) pKey->pECCKeyData, DIGI_EVP_RandomRngFun, NULL);
    if (OK != status)
        goto err;

    pKey->state = DP_MLX_HAVE_PRVKEY;
    return pKey;

err:

    digi_mlx_kem_key_free(pKey);
    return NULL;
}

static void digi_mlx_kem_gen_cleanup(void *vgctx)
{
    DP_MLX_GEN_CTX *gctx = vgctx;

    if (gctx == NULL)
        return;

    if (NULL != gctx->propq)
    {
        (void) DIGI_FREE((void **)&gctx->propq);
    }
    (void) DIGI_FREE((void **) &gctx);
}

static void *digi_mlx_kem_dup(const void *vkey, int selection)
{
    MSTATUS status;
    const DP_MLX_KEY *pKey = vkey;
    DP_MLX_KEY *pRet = NULL;

    if (!digiprov_is_running() || NULL == pKey)
        return NULL;

    status = DIGI_CALLOC((void **) &pRet, 1, sizeof(DP_MLX_KEY));
    if (OK != status)
        return NULL;

    *pRet = *pKey;

    /* pointers need deep copy */
    pRet->propq = NULL;
    pRet->pPQCKeyData = NULL;
    pRet->pECCKeyData = NULL;

    if (pKey->propq != NULL) 
    {
        status = digiprov_strdup((void **) &pRet->propq, pKey->propq);
        if (OK != status)
            goto err;
    }

    switch (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) 
    {
        case 0:

            /* still fill out the key shells */
            status = CRYPTO_INTERFACE_QS_newCtx((QS_CTX **) &pRet->pPQCKeyData, 192 == pKey->secSize ? cid_PQC_MLKEM_768 : cid_PQC_MLKEM_1024);
            if (OK != status)
                goto err;

            status = CRYPTO_INTERFACE_EC_newKeyAux (pKey->cidECC, (ECCKey **) &pRet->pECCKeyData);
            if (OK != status)
                goto err;
            
            break;

        case OSSL_KEYMGMT_SELECT_KEYPAIR:

            status = CRYPTO_INTERFACE_QS_cloneCtx((QS_CTX **) &pRet->pPQCKeyData, (QS_CTX *) pKey->pPQCKeyData); 
            if (OK != status)
                goto err;

            status = CRYPTO_INTERFACE_EC_cloneKeyAux((ECCKey **) &pRet->pECCKeyData, (ECCKey *) pKey->pECCKeyData);
            if (OK != status)
                goto err;

            break;

        default:
            ERR_raise_data(ERR_LIB_PROV, PROV_R_UNSUPPORTED_SELECTION,
                        "duplication of partial key material not supported");
            break;
    }

    return pRet;

err:

    digi_mlx_kem_key_free(pRet);
    return NULL;
}


#define DECLARE_DISPATCH(curve, mlkem, variant) \
    static OSSL_FUNC_keymgmt_new_fn digi_mlx_##curve##_kem_new; \
    static void *digi_mlx_##curve##_kem_new(void *provctx) \
    { \
        OSSL_LIB_CTX *libctx; \
                              \
        libctx = provctx == NULL ? NULL : PROV_LIBCTX_OF(provctx); \
        return digi_mlx_kem_key_new(variant, libctx, NULL); \
    } \
    static OSSL_FUNC_keymgmt_gen_init_fn digi_mlx_##curve##_kem_gen_init; \
    static void *digi_mlx_##curve##_kem_gen_init(void *provctx, int selection, \
                                           const OSSL_PARAM params[]) \
    { \
        OSSL_LIB_CTX *libctx; \
                              \
        libctx = provctx == NULL ? NULL : PROV_LIBCTX_OF(provctx); \
        return digi_mlx_kem_gen_init(variant, libctx, selection, params); \
    } \
    const OSSL_DISPATCH digiprov_mlx_##curve##_##mlkem##_keymgmt_functions[] = { \
        { OSSL_FUNC_KEYMGMT_NEW, (OSSL_FUNC) digi_mlx_##curve##_kem_new }, \
        { OSSL_FUNC_KEYMGMT_FREE, (OSSL_FUNC) digi_mlx_kem_key_free }, \
        { OSSL_FUNC_KEYMGMT_GET_PARAMS, (OSSL_FUNC) digi_mlx_kem_get_params }, \
        { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (OSSL_FUNC) digi_mlx_kem_gettable_params }, \
        { OSSL_FUNC_KEYMGMT_SET_PARAMS, (OSSL_FUNC) digi_mlx_kem_set_params }, \
        { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (OSSL_FUNC) digi_mlx_kem_settable_params }, \
        { OSSL_FUNC_KEYMGMT_HAS, (OSSL_FUNC) digi_mlx_kem_has }, \
        { OSSL_FUNC_KEYMGMT_MATCH, (OSSL_FUNC) digi_mlx_kem_match }, \
        { OSSL_FUNC_KEYMGMT_GEN_INIT, (OSSL_FUNC) digi_mlx_##curve##_kem_gen_init }, \
        { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (OSSL_FUNC) digi_mlx_kem_gen_set_params }, \
        { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (OSSL_FUNC) digi_mlx_kem_gen_settable_params }, \
        { OSSL_FUNC_KEYMGMT_GEN, (OSSL_FUNC) digi_mlx_kem_gen }, \
        { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (OSSL_FUNC) digi_mlx_kem_gen_cleanup }, \
        { OSSL_FUNC_KEYMGMT_DUP, (OSSL_FUNC) digi_mlx_kem_dup }, \
        { OSSL_FUNC_KEYMGMT_IMPORT, (OSSL_FUNC) digi_mlx_kem_import }, \
        { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (OSSL_FUNC) digi_mlx_kem_imexport_types }, \
        { OSSL_FUNC_KEYMGMT_EXPORT, (OSSL_FUNC) digi_mlx_kem_export }, \
        { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (OSSL_FUNC) digi_mlx_kem_imexport_types }, \
        OSSL_DISPATCH_END \
    }

DECLARE_DISPATCH(x25519, mlkem768, X25519MLKEM768);
DECLARE_DISPATCH(x448, mlkem1024, X448MLKEM1024);
DECLARE_DISPATCH(p256, mlkem768, SecP256r1MLKEM768);
DECLARE_DISPATCH(p384, mlkem1024, SecP384r1MLKEM1024);

#endif /* #ifdef __ENABLE_DIGICERT_PQC__ */
