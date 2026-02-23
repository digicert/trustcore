/*
 * digi_decode_der2tap.c
 *
 * Provider for OSSL 3.0
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
 * low level APIs are deprecated for public use, but still ok for
 * internal use.
 */

#define OPENSSL_SUPPRESS_DEPRECATED

#include "../../../src/common/moptions.h"

#ifdef __ENABLE_DIGICERT_TAP__

#include "../../../src/common/mtypes.h"
#include "../../../src/common/mdefs.h"
#include "../../../src/common/merrors.h"
#include "../../../src/common/mstdlib.h"
#include "../../../src/crypto/hw_accel.h"
#include "../../../src/crypto/pubcrypto.h"
#include "../../../src/crypto/rsa.h"
#include "../../../src/crypto/primeec.h"
#include "../../../src/crypto/ecc.h"
#include "../../../src/crypto_interface/cryptointerface.h"
#include "../../../src/crypto_interface/crypto_interface_rsa.h"
#include "../../../src/crypto_interface/crypto_interface_ecc.h"
#include "../../../src/crypto_interface/crypto_interface_rsa_tap.h"
#include "../../../src/crypto_interface/crypto_interface_ecc_tap.h"

#ifdef ASN1_ITEM
#undef ASN1_ITEM
#endif

#include "mocana_glue.h"
#include "digiprov.h"

#ifdef SHA256_CTX
#undef SHA256_CTX
#endif

#ifdef SHA512_CTX
#undef SHA512_CTX
#endif

#include "internal/deprecated.h"

#include "openssl/core_dispatch.h"
#include "openssl/core_names.h"
#include "openssl/core_object.h"
#include "openssl/crypto.h"
#include "openssl/err.h"
#include "openssl/params.h"
#include "openssl/proverr.h"

#include "crypto/ec.h"
#include "crypto/evp.h"
#include "crypto/rsa.h"
#include "prov/bio.h"

#include "openssl/rsa.h"
#include "crypto/rsa/rsa_local.h"

#include "openssl/ec.h"
#include "crypto/ec/ec_local.h"

#ifndef DP_DER2TAP_MAX_PW_LEN
#define DP_DER2TAP_MAX_PW_LEN 128
#endif

int ossl_read_der(PROV_CTX *provctx, OSSL_CORE_BIO *cin,  unsigned char **data, long *len);
void freeExtraData(void *pParent, void *pData, CRYPTO_EX_DATA *pExData, int index, long arg, void *pArg);
int moc_get_rsa_ex_app_data(void);
int moc_get_ecc_ex_app_data(void);
void DIGI_EVP_maskCred(ubyte *pIn, ubyte4 inLen);

/*
 * Context used for DER to key decoding.
 */
typedef struct _DP_DER2TAP_CTX 
{
    PROV_CTX *provctx;
    int selection;

} DP_DER2TAP_CTX;

/* ---------------------------------------------------------------------- */

static DP_DER2TAP_CTX * digiprov_der2tap_newctx(void *provctx)
{
    MSTATUS status = OK;
    DP_DER2TAP_CTX *ctx = NULL;
    
    status = DIGI_CALLOC((void **) &ctx, 1, sizeof(DP_DER2TAP_CTX));
    if (OK != status)
        return NULL;

    ctx->provctx = provctx;
    
    return ctx;
}

static void digiprov_der2tap_freectx(void *vctx)
{
    (void) DIGI_MEMSET_FREE((ubyte **) &vctx, sizeof(DP_DER2TAP_CTX));
}

static MSTATUS digiprov_is_tap_key(ubyte *pDer, ubyte4 derLen, byteBoolean *pHasCreds)
{
    MSTATUS status;
    ubyte *pGetAlgId = NULL;
    ubyte4 getAlgIdLen;
    ubyte *pGetKeyData = NULL;
    ubyte4 getKeyDataLen;
    sbyte4 isPrivate;
    sbyte4 cmpResult;
    ubyte pRsaTapOid[MOP_RSA_TAP_ALG_ID_LEN] =
    {
        MOP_RSA_TAP_ALG_ID
    };
    ubyte pEccTapOid[MOP_ECC_TAP_KEY_ALG_ID_LEN] =
    {
        MOP_ECC_TAP_KEY_ALG_ID
    };
    /* internal method, no null checks necc */

    *pHasCreds = FALSE;

    status = CRYPTO_findKeyInfoComponents(
        pDer, derLen, &pGetAlgId, &getAlgIdLen, &pGetKeyData, &getKeyDataLen,
        &isPrivate);
    if (OK != status)
        goto exit;

    /* Check for RSA TAP OID */
    status = ASN1_compareOID (
        pRsaTapOid, MOP_RSA_TAP_ALG_ID_LEN, pGetAlgId, getAlgIdLen,
        NULL, &cmpResult);
    if (OK != status)
        goto exit;

    if (0 != cmpResult)
    {
        /* Check for RSA TAP PW OID */
        pRsaTapOid[MOP_TAP_PW_OID_INDEX] |= MOP_TAP_PW_MASK;
        status = ASN1_compareOID (
            pRsaTapOid, MOP_RSA_TAP_ALG_ID_LEN, pGetAlgId, getAlgIdLen,
            NULL, &cmpResult);
        if (OK != status)
            goto exit;

        if (0 != cmpResult)
        {
            /* Check for ECC TAP OID */
            status = ASN1_compareOID (
                pEccTapOid, MOP_ECC_TAP_KEY_ALG_ID_LEN, pGetAlgId, getAlgIdLen,
                NULL, &cmpResult);
            if (OK != status)
                goto exit;

            if (0 != cmpResult)
            { 
                /* Check for ECC TAP PW OID */
                pEccTapOid[MOP_TAP_PW_OID_INDEX] |= MOP_TAP_PW_MASK;
                status = ASN1_compareOID (
                    pEccTapOid, MOP_ECC_TAP_KEY_ALG_ID_LEN, pGetAlgId, getAlgIdLen,
                    NULL, &cmpResult);
                if (OK != status)
                    goto exit;

                if (0 != cmpResult)
                {
                    status = ERR_KEY;
                    goto exit;
                }
                *pHasCreds = TRUE;
            }
        }
        else
        {
            *pHasCreds = TRUE;
        }
    }

exit:

    return status;
}

static int digiprov_der2tap_decode(void *vctx, OSSL_CORE_BIO *cin, int selection,
                                   OSSL_CALLBACK *data_cb, void *data_cbarg,
                                   OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    MSTATUS status = OK;
    AsymmetricKey asymKey = {0};

    DP_DER2TAP_CTX *ctx = (DP_DER2TAP_CTX *) vctx;
    unsigned char *der = NULL;
    long der_len = 0;
    int ok = 0;

    void *key = NULL;
    MOC_EVP_KEY_DATA *pMocKeyData = NULL;
    ubyte *pDerCopy = NULL;
    ubyte4 derCopyLen = 0;
    RSA *rsa = NULL;
    EC_KEY *ecc = NULL;
    const char *pTypeEcc = "EC";
    const char *pTypeRsa = "RSA";
    const char *pType = pTypeRsa; /* default */
    
    RSAKey *pRsa = NULL;
    MRsaKeyTemplate templateRsa = {0};
    ECCKey *pEcc = NULL;
    MEccKeyTemplate templateEcc = {0};
    BN_CTX *pBnCtx = NULL;
    
    ctx->selection = selection;

#if defined(__ENABLE_DIGICERT_OSSL_TAP_PASSWORD__)
    ubyte pwBuf[DP_DER2TAP_MAX_PW_LEN] = {0};
    size_t pwLen = 0;
    
    ubyte *pCred = NULL;
    ubyte4 credLen = 0;
#endif
    byteBoolean hasCreds = FALSE;

    if (selection == 0)
        selection = OSSL_KEYMGMT_SELECT_PRIVATE_KEY;
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) == 0) 
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }

    ok = ossl_read_der(ctx->provctx, cin, &der, &der_len);
    if (!ok)
        goto end;

    /* Determine if key is TAP key or not based on OID */
    status = digiprov_is_tap_key(der, der_len, &hasCreds);
    if (OK != status)
        goto end;

    /* This is a TAP key, if conversion from AsymmetricKey key
     * structure to OpenSSL key structure fails then let the caller know this
     * decoder failed and to not continue to other decoders */
    ok = 0;

#if !defined(__ENABLE_DIGICERT_OSSL_TAP_PASSWORD__)
    if (hasCreds)
    {
        status = ERR_TAP_RC_AUTH_FAIL;
        goto end;
    }
#endif

    status = CRYPTO_initAsymmetricKey (&asymKey);
    if (OK != status)
       goto end;

#if defined(__ENABLE_DIGICERT_OSSL_TAP_PASSWORD__)
    if (hasCreds)
    {
        if (NULL != pw_cb && pw_cb((char *) pwBuf, sizeof(pwBuf), &pwLen, NULL, pw_cbarg) && pwLen > 0)
        {
            status = CRYPTO_deserializeAsymKeyWithCreds(der, (ubyte4) der_len, NULL, pwBuf, (ubyte4) pwLen, NULL, &asymKey);
            if (OK != status)
                goto end;

            /* mask and save a copy of the pw */
            credLen = (ubyte4) pwLen;
            DIGI_EVP_maskCred(pwBuf, credLen);

            status = DIGI_MALLOC_MEMCPY((void **) &pCred, credLen, (void *) pwBuf, credLen);
            if (OK != status)
                goto end;
        }
        else
        {
            status = ERR_INVALID_INPUT;
            goto end;
        }
    }
    else
#endif
    {
        status = CRYPTO_deserializeAsymKey(der, (ubyte4) der_len, NULL, &asymKey);
        if (OK != status)
            goto end;
    }

    if (akt_tap_rsa != asymKey.type && akt_tap_ecc != asymKey.type)
       goto end;

    status = DIGI_CALLOC((void **) &pMocKeyData, 1, sizeof(MOC_EVP_KEY_DATA));
    if (OK != status)
        goto end;

#if defined(__ENABLE_DIGICERT_OSSL_TAP_PASSWORD__)
    /* if there was a credential, store it in a masked state */
    pMocKeyData->pCred = pCred; pCred = NULL;
    pMocKeyData->credLen = credLen;
#endif

    /* create a new buffer allocated by us since our freeExtraData handler will handle free-ing */
    derCopyLen = (ubyte4) der_len;
    status = DIGI_MALLOC_MEMCPY((void **) &pDerCopy, derCopyLen, (void *) der, derCopyLen);
    if (OK != status)
        goto end;

    pMocKeyData->pContents = pDerCopy;
    pMocKeyData->contentsLen = derCopyLen;

    if(akt_tap_rsa == asymKey.type)
    {
        status = CRYPTO_INTERFACE_getRSAPublicKey(&asymKey, &pRsa);
        if (OK != status)
            goto end;

        status = CRYPTO_INTERFACE_RSA_getKeyParametersAllocAux(pRsa, &templateRsa, MOC_GET_PUBLIC_KEY_DATA);
        if (OK != status)
            goto end;

        rsa = RSA_new();
        if (NULL == rsa)
            goto end;
     
        RSA_set_ex_data(rsa, moc_get_rsa_ex_app_data(), pMocKeyData); pMocKeyData = NULL;

        rsa->n = BN_bin2bn(templateRsa.pN, templateRsa.nLen, NULL);
        rsa->e = BN_bin2bn(templateRsa.pE, templateRsa.eLen, NULL);

        key = (void *) rsa;
    }
    else /* akt_tap_ecc == asymKey.type */
    {
        ubyte4 curveId;
        int osslEcCurveId;

        status = CRYPTO_INTERFACE_getECCPublicKey(&asymKey, &pEcc);
        if (OK != status)
            goto end;

        status = CRYPTO_INTERFACE_EC_getKeyParametersAllocAux(pEcc, &templateEcc, MOC_GET_PUBLIC_KEY_DATA);
        if (OK != status)
            goto end;
        
        status = CRYPTO_INTERFACE_EC_getCurveIdFromKeyAux(pEcc, &curveId);
        if (OK != status)
            goto end;

        switch (curveId)
        {
            case cid_EC_P192:
                osslEcCurveId = NID_X9_62_prime192v1;
                break;
            case cid_EC_P224:
                osslEcCurveId = NID_secp224r1;
                break;
            case cid_EC_P256:
                osslEcCurveId = NID_X9_62_prime256v1;
                break;
            case cid_EC_P384:
                osslEcCurveId = NID_secp384r1;
                break;
            case cid_EC_P521:
                osslEcCurveId = NID_secp521r1;
                break;

            default:
                status = ERR_EC_UNSUPPORTED_CURVE;
                goto end;
        }

        pBnCtx = BN_CTX_new();
        if (NULL == pBnCtx)
            goto end;

        ecc = EC_KEY_new_by_curve_name(osslEcCurveId);
        if (NULL == ecc)
            goto end;

        EC_KEY_set_ex_data(ecc, moc_get_ecc_ex_app_data(), pMocKeyData); pMocKeyData = NULL;
        
        ecc->pub_key = EC_POINT_new(ecc->group);
        if (NULL == ecc->pub_key)
            goto end;

        (void) EC_POINT_oct2point(ecc->group, ecc->pub_key, templateEcc.pPublicKey, (size_t) templateEcc.publicKeyLen, pBnCtx);

        key = (void *) ecc;
        pType = pTypeEcc;
    }

    OPENSSL_free(der);
    der = NULL;

    if (NULL != key) 
    {
        OSSL_PARAM params[4];
        int object_type = OSSL_OBJECT_PKEY;

        params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);
        params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE, (char *)pType, 0);
        /* The address of the key becomes the octet string */
        params[2] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE, &key, sizeof(key));
        params[3] = OSSL_PARAM_construct_end();

        ok = data_cb(params, data_cbarg);
    }

 end:

 #if defined(__ENABLE_DIGICERT_OSSL_TAP_PASSWORD__)   
    if (pwLen > 0)
    {
        (void) DIGI_MEMSET(pwBuf, 0x00, (ubyte4) pwLen); 
    }

    if (NULL != pCred)
    {
        (void) DIGI_MEMSET_FREE(&pCred, credLen);
    }

    if (akt_tap_rsa == asymKey.type)
    {
        (void) CRYPTO_INTERFACE_TAP_RsaUnloadKey(asymKey.key.pRSA);
    }
    else if (akt_tap_ecc == asymKey.type)
    {
        (void) CRYPTO_INTERFACE_TAP_EccUnloadKey(asymKey.key.pECC);
    }
#endif

    if (NULL != key)
    {
        if(pType == pTypeRsa)
        {
            RSA_free((RSA *) key);
        }
        else /* pType == pTypeEcc */
        {
            EC_KEY_free((EC_KEY *) key);
        }
        key = NULL;
    }

    if (NULL != pRsa)
    {
        (void) CRYPTO_INTERFACE_RSA_freeKeyTemplateAux(pRsa, &templateRsa);
        (void) CRYPTO_INTERFACE_RSA_freeKeyAux(&pRsa, NULL);
    }

    if (NULL != pEcc)
    {
        (void) CRYPTO_INTERFACE_EC_freeKeyTemplateAux(pEcc, &templateEcc);
        (void) CRYPTO_INTERFACE_EC_deleteKeyAux(&pEcc);
    }

    if (NULL != pBnCtx)
    {
        BN_CTX_free(pBnCtx);
    }

    (void) CRYPTO_uninitAsymmetricKey(&asymKey, NULL);

    /* error case only */
    if (NULL != pMocKeyData) (void) freeExtraData(NULL, pMocKeyData, NULL, 0, 0, NULL); 
    if (NULL != der) OPENSSL_free(der);
    
    return ok;
}

const OSSL_DISPATCH digiprov_der_to_tap_decoder_functions[] =
{
    { OSSL_FUNC_DECODER_NEWCTX,         (void (*)(void))digiprov_der2tap_newctx },
    { OSSL_FUNC_DECODER_FREECTX,        (void (*)(void))digiprov_der2tap_freectx },
    { OSSL_FUNC_DECODER_DECODE,         (void (*)(void))digiprov_der2tap_decode },
    { 0, NULL }
};

#endif /* __ENABLE_DIGICERT_TAP__ */
