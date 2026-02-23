/*
 * digi_eddsa_sig.c
 *
 * EDDSA implementations for OSSL 3.0 provider Adapded from OPENSSL code
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
 * Copyright 2019 Red Hat, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
/*---------------------------------------------------------------------------------------------------------*/
/* We need to use some deprecated APIs */
#define OPENSSL_SUPPRESS_DEPRECATED

#include "../../../src/common/moptions.h"
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
#include "internal/deprecated.h"

#include "openssl/crypto.h"
#include "crypto/ec.h"
#include "prov/der_ecx.h"
#include "openssl/obj_mac.h"
#include "internal/packet.h"

typedef struct 
{
    OSSL_LIB_CTX *libctx;
    ECX_KEY *key;

    /* The Algorithm Identifier of the signature algorithm */
    unsigned char aid_buf[OSSL_MAX_ALGORITHM_ID_SIZE];
    unsigned char *aid;
    size_t  aid_len;

} DP_EDDSA_CTX;

sbyte4 DIGI_EVP_RandomRngFun(void *pRngFunArg, ubyte4 length, ubyte *pBuffer);

void digiprov_ecx_key_free(ECX_KEY *key);

static int digiprov_DER_w_algorithmIdentifier_ED25519(WPACKET *pkt, int cont, ECX_KEY *ec)
{
    return ossl_DER_w_begin_sequence(pkt, cont)
        /* No parameters (yet?) */
        && ossl_DER_w_precompiled(pkt, -1, ossl_der_oid_id_Ed25519,
                                  sizeof(ossl_der_oid_id_Ed25519))
        && ossl_DER_w_end_sequence(pkt, cont);
}

static int digiprov_DER_w_algorithmIdentifier_ED448(WPACKET *pkt, int cont, ECX_KEY *ec)
{
    return ossl_DER_w_begin_sequence(pkt, cont)
        /* No parameters (yet?) */
        && ossl_DER_w_precompiled(pkt, -1, ossl_der_oid_id_Ed448,
                                  sizeof(ossl_der_oid_id_Ed448))
        && ossl_DER_w_end_sequence(pkt, cont);
}

static void *digiprov_eddsa_newctx(void *provctx, const char *propq_unused)
{
    MSTATUS status = OK;
    DP_EDDSA_CTX *pCtx = NULL;

    if (!digiprov_is_running())
        return NULL;

    status = DIGI_CALLOC((void **)&pCtx, 1, sizeof(DP_EDDSA_CTX));
    if (OK != status)
        goto exit;

    pCtx->libctx = PROV_LIBCTX_OF(provctx);

exit:

    return pCtx;
}

static int digiprov_eddsa_digest_signverify_init(void *vpeddsactx, const char *mdname,
                                                 void *vedkey, ossl_unused const OSSL_PARAM params[])
{
    DP_EDDSA_CTX *peddsactx = (DP_EDDSA_CTX *)vpeddsactx;
    ECX_KEY *edkey = (ECX_KEY *)vedkey;
    WPACKET pkt;
    int ret;

    if (!digiprov_is_running())
        return 0;

    if (mdname != NULL && mdname[0] != '\0') {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
        return 0;
    }

    if (edkey == NULL) {
        if (peddsactx->key != NULL)
            /* there is nothing to do on reinit */
            return 1;
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return 0;
    }

    if (!ossl_ecx_key_up_ref(edkey)) {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * We do not care about DER writing errors.
     * All it really means is that for some reason, there's no
     * AlgorithmIdentifier to be had, but the operation itself is
     * still valid, just as long as it's not used to construct
     * anything that needs an AlgorithmIdentifier.
     */
    peddsactx->aid_len = 0;
    ret = WPACKET_init_der(&pkt, peddsactx->aid_buf, sizeof(peddsactx->aid_buf));
    switch (edkey->type) {
    case ECX_KEY_TYPE_ED25519:
        ret = ret && digiprov_DER_w_algorithmIdentifier_ED25519(&pkt, -1, edkey);
        break;
    case ECX_KEY_TYPE_ED448:
        ret = ret && digiprov_DER_w_algorithmIdentifier_ED448(&pkt, -1, edkey);
        break;
    default:
        /* Should never happen */
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        digiprov_ecx_key_free(edkey);
        return 0;
    }
    if (ret && WPACKET_finish(&pkt)) {
        WPACKET_get_total_written(&pkt, &peddsactx->aid_len);
        peddsactx->aid = WPACKET_get_curr(&pkt);
    }
    WPACKET_cleanup(&pkt);

    peddsactx->key = edkey;

    return 1;
}

static int digiprov_eddsa_sign(ubyte4 curveId, void *vpeddsactx, unsigned char *sigret, size_t *siglen,
                               size_t sigsize, const unsigned char *tbs, size_t tbslen)
{
    MSTATUS status = OK;
    DP_EDDSA_CTX *peddsactx = (DP_EDDSA_CTX *)vpeddsactx;
    const ECX_KEY *edkey = peddsactx->key;
    ECCKey *pKey = NULL;
    ubyte4 retSigLen = 0;
    size_t curveSigLen = (cid_EC_Ed25519 == curveId ? ED25519_SIGSIZE : ED448_SIGSIZE);

    if (!digiprov_is_running())
        return 0;

    if (sigret == NULL) 
    {
        *siglen = curveSigLen;
        return 1;
    }
    if (sigsize < curveSigLen) 
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }
    
    status = CRYPTO_INTERFACE_EC_newKeyAux(curveId, &pKey);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_EC_setKeyParametersAux(pKey, (ubyte * )edkey->pubkey, (ubyte4)edkey->keylen, 
                                                     (ubyte *) edkey->privkey, (ubyte4) edkey->keylen);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_ECDSA_signMessageExt (pKey, DIGI_EVP_RandomRngFun, NULL, 0, (ubyte *) tbs,
                                                    (ubyte4) tbslen, (ubyte *) sigret, (ubyte4) sigsize, &retSigLen, NULL);
    if (OK != status)
        goto exit;

    *siglen = (size_t) retSigLen;

exit:

    if (NULL != pKey)
    {
        (void) CRYPTO_INTERFACE_EC_deleteKeyAux(&pKey);
    }

    return (OK == status ? 1 : 0);
}

static int digiprov_ed25519_digest_sign(void *vpeddsactx, unsigned char *sigret, size_t *siglen,
                                        size_t sigsize, const unsigned char *tbs, size_t tbslen)
{
    return digiprov_eddsa_sign(cid_EC_Ed25519, vpeddsactx, sigret, siglen, sigsize, tbs, tbslen);
}

static int digiprov_ed448_digest_sign(void *vpeddsactx, unsigned char *sigret, size_t *siglen, 
                                      size_t sigsize, const unsigned char *tbs, size_t tbslen)
{
    return digiprov_eddsa_sign(cid_EC_Ed448, vpeddsactx, sigret, siglen, sigsize, tbs, tbslen);
}

static int digiprov_eddsa_verify(ubyte4 curveId, void *vpeddsactx, const unsigned char *sig, size_t siglen,
                                 const unsigned char *tbs, size_t tbslen)
{
    MSTATUS status = OK;
    DP_EDDSA_CTX *peddsactx = (DP_EDDSA_CTX *)vpeddsactx;
    const ECX_KEY *edkey = peddsactx->key;
    ECCKey *pKey = NULL;
    ubyte4 vStatus = 1;

    if (!digiprov_is_running())
        return 0;
    
    status = CRYPTO_INTERFACE_EC_newKeyAux(curveId, &pKey);
    if (OK != status)
        goto exit;

    /* just set the public key */
    status = CRYPTO_INTERFACE_EC_setKeyParametersAux(pKey, (ubyte * )edkey->pubkey, (ubyte4)edkey->keylen, NULL, 0);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_ECDSA_verifyMessageExt(pKey, 0, (ubyte *) tbs, (ubyte4) tbslen,
                                                     (ubyte *) sig, (ubyte4) siglen, &vStatus, NULL);
exit:

    if (NULL != pKey)
    {
        (void) CRYPTO_INTERFACE_EC_deleteKeyAux(&pKey);
    }

    return ((OK == status && 0 == vStatus) ? 1 : 0);
}

static int digiprov_ed25519_digest_verify(void *vpeddsactx, const unsigned char *sig, size_t siglen,
                                          const unsigned char *tbs, size_t tbslen)
{
    return digiprov_eddsa_verify(cid_EC_Ed25519, vpeddsactx, sig, siglen, tbs, tbslen);
}

static int digiprov_ed448_digest_verify(void *vpeddsactx, const unsigned char *sig, size_t siglen,
                                        const unsigned char *tbs, size_t tbslen)
{
    return digiprov_eddsa_verify(cid_EC_Ed448, vpeddsactx, sig, siglen, tbs, tbslen);
}

static void digiprov_eddsa_freectx(void *vpeddsactx)
{
    DP_EDDSA_CTX *peddsactx = (DP_EDDSA_CTX *)vpeddsactx;

    digiprov_ecx_key_free(peddsactx->key);

    (void) DIGI_FREE((void **) &peddsactx);
}

static void *digiprov_eddsa_dupctx(void *vpeddsactx)
{
    MSTATUS status = OK;
    DP_EDDSA_CTX *srcctx = (DP_EDDSA_CTX *)vpeddsactx;
    DP_EDDSA_CTX *dstctx = NULL;

    if (!digiprov_is_running())
        return NULL;

    status = DIGI_CALLOC((void **) &dstctx, 1, sizeof(*srcctx));
    if (OK != status)
        return NULL;

    *dstctx = *srcctx;
    dstctx->key = NULL;

    if (srcctx->key != NULL && !ossl_ecx_key_up_ref(srcctx->key)) {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    dstctx->key = srcctx->key;

    return dstctx;
 err:
    digiprov_eddsa_freectx(dstctx);
    return NULL;
}

static int digiprov_eddsa_get_ctx_params(void *vpeddsactx, OSSL_PARAM *params)
{
    DP_EDDSA_CTX *peddsactx = (DP_EDDSA_CTX *)vpeddsactx;
    OSSL_PARAM *p;

    if (peddsactx == NULL)
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
    if (p != NULL && !OSSL_PARAM_set_octet_string(p, peddsactx->aid,
                                                  peddsactx->aid_len))
        return 0;

    return 1;
}

static const OSSL_PARAM known_gettable_ctx_params[] = 
{
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *digiprov_eddsa_gettable_ctx_params(ossl_unused void *vpeddsactx,
                                                            ossl_unused void *provctx)
{
    return known_gettable_ctx_params;
}

const OSSL_DISPATCH digiprov_ed25519_functions[] =
{
    { OSSL_FUNC_SIGNATURE_NEWCTX,              (void (*)(void))digiprov_eddsa_newctx },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,    (void (*)(void))digiprov_eddsa_digest_signverify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN,         (void (*)(void))digiprov_ed25519_digest_sign },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,  (void (*)(void))digiprov_eddsa_digest_signverify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY,       (void (*)(void))digiprov_ed25519_digest_verify },
    { OSSL_FUNC_SIGNATURE_FREECTX,             (void (*)(void))digiprov_eddsa_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX,              (void (*)(void))digiprov_eddsa_dupctx },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,      (void (*)(void))digiprov_eddsa_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void (*)(void))digiprov_eddsa_gettable_ctx_params },
    { 0, NULL }
};

const OSSL_DISPATCH digiprov_ed448_functions[] =
{
    { OSSL_FUNC_SIGNATURE_NEWCTX,              (void (*)(void))digiprov_eddsa_newctx },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,    (void (*)(void))digiprov_eddsa_digest_signverify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN,         (void (*)(void))digiprov_ed448_digest_sign },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,  (void (*)(void))digiprov_eddsa_digest_signverify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY,       (void (*)(void))digiprov_ed448_digest_verify },
    { OSSL_FUNC_SIGNATURE_FREECTX,             (void (*)(void))digiprov_eddsa_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX,              (void (*)(void))digiprov_eddsa_dupctx },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,      (void (*)(void))digiprov_eddsa_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void (*)(void))digiprov_eddsa_gettable_ctx_params },
    { 0, NULL }
};
