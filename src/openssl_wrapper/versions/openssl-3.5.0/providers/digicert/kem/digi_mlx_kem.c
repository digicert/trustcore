/*
 * digi_mlx_kem.c
 *
 * COMPOSITE PQC/ECC KEM (key encapsulation mechanism) implementations for OSSL 3.5 provider
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

/* ---------------------------------------------------------------------------------------------------*/

#include "../../../src/common/moptions.h"

#if defined(__ENABLE_DIGICERT_PQC__)

#include "../../../src/common/mtypes.h"
#include "../../../src/common/mdefs.h"
#include "../../../src/common/merrors.h"
#include "../../../src/common/mstdlib.h"
#include "../../../src/common/mrtos.h"
#include "../../../src/common/vlong.h"
#include "../../../src/common/random.h"
#include "../../../src/crypto/ca_mgmt.h"
#include "../../../src/crypto/primeec.h"
#include "../../../src/crypto/ecc.h"
#include "../../../src/crypto_interface/crypto_interface_ecc.h"
#include "../../../src/crypto_interface/crypto_interface_qs.h"
#include "../../../src/crypto_interface/crypto_interface_qs_kem.h"

#ifdef ASN1_ITEM
#undef ASN1_ITEM
#endif

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

#include "openssl/crypto.h"
#include "internal/packet.h"
#include "internal/cryptlib.h"

static OSSL_FUNC_kem_newctx_fn digi_mlx_kem_newctx;
static OSSL_FUNC_kem_freectx_fn digi_mlx_kem_freectx;
static OSSL_FUNC_kem_encapsulate_init_fn digi_mlx_kem_encapsulate_init;
static OSSL_FUNC_kem_encapsulate_fn digi_mlx_kem_encapsulate;
static OSSL_FUNC_kem_decapsulate_init_fn digi_mlx_kem_decapsulate_init;
static OSSL_FUNC_kem_decapsulate_fn digi_mlx_kem_decapsulate;
static OSSL_FUNC_kem_set_ctx_params_fn digi_mlx_kem_set_ctx_params;
static OSSL_FUNC_kem_settable_ctx_params_fn digi_mlx_kem_settable_ctx_params;

/* ML-KEM shared secret len is 32 for all security sizes */
#define DP_MLKEM_SECRET_BYTES 32

sbyte4 DIGI_EVP_RandomRngFun(void *pRngFunArg, ubyte4 length, ubyte *pBuffer);

typedef struct 
{
    OSSL_LIB_CTX *libctx;
    DP_MLX_KEY *key;
    int op;

} DP_MLX_CTX;

static void *digi_mlx_kem_newctx(void *provctx)
{
    DP_MLX_CTX *ctx;

    if ((ctx = OPENSSL_malloc(sizeof(*ctx))) == NULL)
        return NULL;

    ctx->libctx = PROV_LIBCTX_OF(provctx);
    ctx->key = NULL;
    ctx->op = 0;
    return ctx;
}

static void digi_mlx_kem_freectx(void *vctx)
{
    OPENSSL_free(vctx);
}

static int digi_mlx_kem_init(void *vctx, int op, void *key,
                             ossl_unused const OSSL_PARAM params[])
{
    DP_MLX_CTX *ctx = vctx;

    if (!digiprov_is_running())
        return 0;

    ctx->key = key;
    ctx->op = op;
    return 1;
}

static int digi_mlx_kem_encapsulate_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    DP_MLX_KEY *key = vkey;

    if (!digi_mlx_kem_have_pubkey(key)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return 0;
    }
    return digi_mlx_kem_init(vctx, EVP_PKEY_OP_ENCAPSULATE, key, params);
}

static int digi_mlx_kem_decapsulate_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    DP_MLX_KEY *key = vkey;

    if (!digi_mlx_kem_have_prvkey(key)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return 0;
    }
    return digi_mlx_kem_init(vctx, EVP_PKEY_OP_DECAPSULATE, key, params);
}

static const OSSL_PARAM *digi_mlx_kem_settable_ctx_params(ossl_unused void *vctx,
                                                          ossl_unused void *provctx)
{
    static const OSSL_PARAM params[] = { OSSL_PARAM_END };

    return params;
}

static int digi_mlx_kem_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    return 1;
}

static int digi_mlx_kem_encapsulate(void *vctx, unsigned char *ctext, size_t *clen,
                                    unsigned char *shsec, size_t *slen)
{
    DP_MLX_KEY *key = ((DP_MLX_CTX *) vctx)->key;
    size_t encap_clen;
    size_t encap_slen;
    ubyte *cbuf = NULL;
    ubyte *sbuf = NULL;
    MSTATUS status;
    ECCKey *pEccEphem = NULL; /* ephemeral private key */
    ubyte *pEccSS = NULL;
    ubyte4 eccSSLen = 0;

    if (!digiprov_is_running())
        return 0;

    if (!digi_mlx_kem_have_pubkey(key)) 
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return 0;
    }

    encap_clen = key->pqcCipherLen + key->curvePubLen;
    encap_slen = DP_MLKEM_SECRET_BYTES + key->curveSSLen;

    if (ctext == NULL) 
    {
        if (clen == NULL && slen == NULL)
            return 0;
        if (clen != NULL)
            *clen = encap_clen;
        if (slen != NULL)
            *slen = encap_slen;
        return 1;
    }

    if (shsec == NULL) 
    {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NULL_OUTPUT_BUFFER,
                       "null shared-secret output buffer");
        return 0;
    }

    if (clen == NULL) 
    {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NULL_LENGTH_POINTER,
                       "null ciphertext input/output length pointer");
        return 0;
    } 
    else if (*clen < encap_clen) 
    {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL,
                       "ciphertext buffer too small");
        return 0;
    } 
    else 
    {
        *clen = encap_clen;
    }

    if (slen == NULL) 
    {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NULL_LENGTH_POINTER,
                       "null shared secret input/output length pointer");
        return 0;
    } 
    else if (*slen < encap_slen) 
    {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL,
                       "shared-secret buffer too small");
        return 0;
    } 
    else 
    {
        *slen = encap_slen;
    }

    /* ML-KEM encapsulation */
    cbuf = (ubyte *) (ctext + key->curveFirst * key->curvePubLen);
    sbuf = (ubyte *) (shsec + key->curveFirst * key->curveSSLen);
    
    status = CRYPTO_INTERFACE_QS_KEM_encapsulate((QS_CTX *) key->pPQCKeyData, DIGI_EVP_RandomRngFun, NULL,
                                                 cbuf, key->pqcCipherLen, sbuf, DP_MLKEM_SECRET_BYTES);
    if (OK != status)
        goto exit;

    /* ECDHE encapsulation */
    cbuf = (ubyte *) (ctext + (1 - key->curveFirst) * key->pqcCipherLen);
    sbuf = (ubyte *) (shsec + (1 - key->curveFirst) * DP_MLKEM_SECRET_BYTES);
    
    status = CRYPTO_INTERFACE_EC_newKeyAux (key->cidECC, &pEccEphem);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_EC_generateKeyPairAux(pEccEphem, DIGI_EVP_RandomRngFun, NULL);
    if (OK != status)
        goto exit;

    /* compute the shared secret, get our public key, use cbuf as temp space  */
    status = CRYPTO_INTERFACE_EC_writePublicKeyToBufferAux((ECCKey *) key->pECCKeyData, cbuf, key->curvePubLen);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_ECDH_generateSharedSecretFromPublicByteStringAux(pEccEphem, cbuf, key->curvePubLen,
                                                                               &pEccSS, &eccSSLen, ECDH_X_CORD_ONLY, NULL);
    if (OK != status)
        goto exit;

    /* sanity check */
    if (eccSSLen != key->curveSSLen)
    {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR,
                       "unexpected ecc shared secret output size: %lu", (unsigned long) eccSSLen);
        status = ERR_INTERNAL_ERROR;
        goto exit;
    }
    
    status = DIGI_MEMCPY(sbuf, pEccSS, eccSSLen);
    if (OK != status)
        goto exit;

    /* now write in the ephemeral public before/after the ciphertext */
    status = CRYPTO_INTERFACE_EC_writePublicKeyToBufferAux(pEccEphem, cbuf, key->curvePubLen);
 
exit:

    if (NULL != pEccSS)
    {
        (void) DIGI_MEMSET_FREE(&pEccSS, eccSSLen); 
    }
    if (NULL != pEccEphem)
    {
        (void) CRYPTO_INTERFACE_EC_deleteKeyAux(&pEccEphem);
    }

    return (OK == status ? 1 : 0);
}

static int digi_mlx_kem_decapsulate(void *vctx, uint8_t *shsec, size_t *slen,
                                    const uint8_t *ctext, size_t clen)
{
    DP_MLX_KEY *key = ((DP_MLX_CTX *) vctx)->key;
    ubyte *cbuf;
    ubyte *sbuf;
    size_t decap_slen;
    size_t decap_clen;
    MSTATUS status;
    ubyte *pEccSS = NULL;
    ubyte4 eccSSLen = 0;

    if (!digiprov_is_running())
        return 0;

    if (!digi_mlx_kem_have_prvkey(key)) 
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return 0;
    }

    decap_slen = DP_MLKEM_SECRET_BYTES + key->curveSSLen;
    decap_clen = key->pqcCipherLen + key->curvePubLen;

    if (shsec == NULL) 
    {
        if (slen == NULL)
            return 0;
        *slen = decap_slen;
        return 1;
    }

    /* For now tolerate newly-deprecated NULL length pointers. */
    if (slen == NULL) 
    {
        slen = &decap_slen;
    } 
    else if (*slen < decap_slen) 
    {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL,
                       "shared-secret buffer too small");
        return 0;
    } 
    else 
    {
        *slen = decap_slen;
    }

    if (clen != decap_clen) 
    {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_WRONG_CIPHERTEXT_SIZE,
                       "wrong decapsulation input ciphertext size: %lu",
                       (unsigned long) clen);
        return 0;
    }

    /* ML-KEM decapsulation */
    cbuf = (ubyte *) (ctext + key->curveFirst * key->curvePubLen);
    sbuf = (ubyte *) (shsec + key->curveFirst * key->curveSSLen);
    
    status = CRYPTO_INTERFACE_QS_KEM_decapsulate((QS_CTX *) key->pPQCKeyData, cbuf, key->pqcCipherLen,
                                                  sbuf, DP_MLKEM_SECRET_BYTES);
    if (OK != status)
        goto exit;

    /* ECDH decapsulation */
    cbuf = (ubyte *) (ctext + (1 - key->curveFirst) * key->pqcCipherLen);
    sbuf = (ubyte *) (shsec + (1 - key->curveFirst) * DP_MLKEM_SECRET_BYTES);

    status = CRYPTO_INTERFACE_ECDH_generateSharedSecretFromPublicByteStringAux ((ECCKey *) key->pECCKeyData,
                 cbuf, key->curvePubLen, &pEccSS, &eccSSLen, ECDH_X_CORD_ONLY, NULL);
    if (OK != status)
        goto exit;

    /* sanity check */
    if (eccSSLen != key->curveSSLen)
    {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR,
                       "unexpected ecc shared secret output size: %lu", (unsigned long) eccSSLen);
        status = ERR_INTERNAL_ERROR;
        goto exit;
    }
    
    status = DIGI_MEMCPY(sbuf, pEccSS, eccSSLen);

exit:

    if (NULL != pEccSS)
    {
        (void) DIGI_MEMSET_FREE(&pEccSS, eccSSLen); 
    }

    return (OK == status ? 1 : 0);
}

const OSSL_DISPATCH digiprov_pqc_mlx_kem_functions[] =
{
    { OSSL_FUNC_KEM_NEWCTX, (OSSL_FUNC) digi_mlx_kem_newctx },
    { OSSL_FUNC_KEM_ENCAPSULATE_INIT, (OSSL_FUNC) digi_mlx_kem_encapsulate_init },
    { OSSL_FUNC_KEM_ENCAPSULATE, (OSSL_FUNC) digi_mlx_kem_encapsulate },
    { OSSL_FUNC_KEM_DECAPSULATE_INIT, (OSSL_FUNC) digi_mlx_kem_decapsulate_init },
    { OSSL_FUNC_KEM_DECAPSULATE, (OSSL_FUNC) digi_mlx_kem_decapsulate },
    { OSSL_FUNC_KEM_FREECTX, (OSSL_FUNC) digi_mlx_kem_freectx },
    { OSSL_FUNC_KEM_SET_CTX_PARAMS, (OSSL_FUNC) digi_mlx_kem_set_ctx_params },
    { OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS, (OSSL_FUNC) digi_mlx_kem_settable_ctx_params },
    OSSL_DISPATCH_END
};

#endif /* #ifdef __ENABLE_DIGICERT_PQC__ */
