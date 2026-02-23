/*
 * moc_ec_pmeth.c
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
#ifdef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
#define OPENSSL_SUPPRESS_DEPRECATED
#endif

#include "e_moc_EVP_ciphers.h"

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
#include "internal/cryptlib.h"
#define VERSION_1_1_0_OR_1_1_1C_OR_3_0 
#endif

typedef struct {
    /* Key and paramgen group */
    EC_GROUP *gen_group;
    /* message digest */
    const EVP_MD *md;
    /* Duplicate key if custom cofactor needed */
    EC_KEY *co_key;
    /* Cofactor mode */
    signed char cofactor_mode;
    /* KDF (if any) to use for ECDH */
    char kdf_type;
    /* Message digest to use for key derivation */
    const EVP_MD *kdf_md;
    /* User key material */
    unsigned char *kdf_ukm;
    size_t kdf_ukmlen;
    /* KDF output length */
    size_t kdf_outlen;
} MOC_EC_PKEY_CTX;

static int moc_ec_init(EVP_PKEY_CTX *ctx)
{
#if defined (VERSION_1_1_0_OR_1_1_1C_OR_3_0)
    MOC_EC_PKEY_CTX *dctx;

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    if ((dctx = OPENSSL_zalloc(sizeof(*dctx))) == NULL) {
        ECerr(EC_F_PKEY_EC_INIT, ERR_R_MALLOC_FAILURE);
        return 0;
    }
#elif defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__)
    dctx = OPENSSL_zalloc(sizeof(*dctx));
    if (dctx == NULL)
        return 0;
#endif

    dctx->cofactor_mode = -1;
    dctx->kdf_type = EVP_PKEY_ECDH_KDF_NONE;
    ctx->data = dctx;
    return 1;
#else
    MOC_EC_PKEY_CTX *dctx;
    dctx = OPENSSL_malloc(sizeof(MOC_EC_PKEY_CTX));
    if (!dctx)
        return 0;
    dctx->gen_group = NULL;
    dctx->md = NULL;

    dctx->cofactor_mode = -1;
    dctx->co_key = NULL;
    dctx->kdf_type = EVP_PKEY_ECDH_KDF_NONE;
    dctx->kdf_md = NULL;
    dctx->kdf_outlen = 0;
    dctx->kdf_ukm = NULL;
    dctx->kdf_ukmlen = 0;

    ctx->data = dctx;

    return 1;
#endif
}

static int moc_ec_copy(EVP_PKEY_CTX *dst, 
#ifdef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
const
#endif
EVP_PKEY_CTX *src)
{
    MOC_EC_PKEY_CTX *dctx, *sctx;
    if (!moc_ec_init(dst))
        return 0;
    sctx = src->data;
    dctx = dst->data;
    if (sctx->gen_group) {
        dctx->gen_group = EC_GROUP_dup(sctx->gen_group);
        if (!dctx->gen_group)
            return 0;
    }
    dctx->md = sctx->md;

    if (sctx->co_key) {
        dctx->co_key = EC_KEY_dup(sctx->co_key);
        if (!dctx->co_key)
            return 0;
    }
    dctx->kdf_type = sctx->kdf_type;
    dctx->kdf_md = sctx->kdf_md;
    dctx->kdf_outlen = sctx->kdf_outlen;
    if (sctx->kdf_ukm) {
#if defined (VERSION_1_1_0_OR_1_1_1C_OR_3_0)
        dctx->kdf_ukm = OPENSSL_memdup(sctx->kdf_ukm, sctx->kdf_ukmlen);
#else
        dctx->kdf_ukm = BUF_memdup(sctx->kdf_ukm, sctx->kdf_ukmlen);
#endif
        if (!dctx->kdf_ukm)
            return 0;
    } else
        dctx->kdf_ukm = NULL;
    dctx->kdf_ukmlen = sctx->kdf_ukmlen;
    return 1;
}

static void moc_ec_cleanup(EVP_PKEY_CTX *ctx)
{
    MOC_EC_PKEY_CTX *dctx = ctx->data;
    if (dctx) {
        if (dctx->gen_group)
            EC_GROUP_free(dctx->gen_group);
        if (dctx->co_key)
            EC_KEY_free(dctx->co_key);
        if (dctx->kdf_ukm)
            OPENSSL_free(dctx->kdf_ukm);
        OPENSSL_free(dctx);
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__)
        ctx->data = NULL;
#endif
    }
}

static int moc_ec_sign(EVP_PKEY_CTX* ctx, unsigned char *sig, size_t *siglen,
                 const unsigned char *tbs, size_t tbslen)
{
    int ret, type;
    unsigned int sltmp;
    MOC_EC_PKEY_CTX *dctx = ctx->data;
    EC_KEY *ec = ctx->pkey->pkey.ec;
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__)
    const int sig_sz = ECDSA_size(ec);

    /* ensure cast to size_t is safe */
    if (!ossl_assert(sig_sz > 0))
        return 0;

    if (sig == NULL) {
        *siglen = (size_t)sig_sz;
        return 1;
    }

    if (*siglen < (size_t)sig_sz) {
        ECerr(EC_F_PKEY_EC_SIGN, EC_R_BUFFER_TOO_SMALL);
        return 0;
    }
#else
    if (!sig)
    {
        *siglen = ECDSA_size(ec);
        return 1;
    }
    else if (*siglen < (size_t)ECDSA_size(ec))
    {
        ECerr(EC_F_PKEY_EC_SIGN, EC_R_BUFFER_TOO_SMALL);
        return 0;
    }
#endif

    if (dctx->md)
        type = EVP_MD_type(dctx->md);
    else
        type = NID_sha1;

    ret = ECDSA_sign(type, tbs, tbslen, sig, &sltmp, ec);

    if (ret <= 0)
        return ret;
    *siglen = (size_t)sltmp;
    return 1;
}

static int moc_ec_verify(EVP_PKEY_CTX* ctx, const unsigned char *sig, size_t siglen,
                 const unsigned char *tbs, size_t tbslen)
{
    int ret, type;
    MOC_EC_PKEY_CTX *dctx = ctx->data;
    EC_KEY *ec = ctx->pkey->pkey.ec;

    if (dctx->md)
        type = EVP_MD_type(dctx->md);
    else
        type = NID_sha1;

    ret = ECDSA_verify(type, tbs, (int)tbslen, sig, (int)siglen, ec);

    return ret;
}

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
static int moc_ec_keygen(
    EVP_PKEY_CTX *pCtx,
    EVP_PKEY *pKey
    )
{
    MSTATUS status;
    randomContext *pRandCtx = NULL;
    ubyte4 eccCurveId;
    ECCKey *pNewKey = NULL;
    MEccKeyTemplate template = { 0 };
    EC_KEY *pEcKey = NULL;
    int curveName, retVal = 0;
#if !defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) && !defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) && !defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    ubyte elementLen;
    BIGNUM *pK = NULL, *pX = NULL, *pY = NULL;
#endif

    if (NULL == pCtx->pkey)
    {
        ECerr(EC_F_PKEY_EC_KEYGEN, EC_R_NO_PARAMETERS_SET);
        return 0;
    }

    curveName = pCtx->pkey->pkey.ec->group->curve_name;
    pEcKey = EC_KEY_new_by_curve_name(curveName);
    if (!pEcKey)
        goto exit;

    if (NULL == g_pRandomContext)
    {
        status = RANDOM_acquireContext(&pRandCtx);
        if (OK != status)
            goto exit;
    }
    else
    {
        pRandCtx = g_pRandomContext;
    }

    switch (curveName)
    {
        case NID_X9_62_prime192v1:
            eccCurveId = cid_EC_P192;
            break;

        case NID_secp224r1:
            eccCurveId = cid_EC_P224;
            break;

        case NID_X9_62_prime256v1:
            eccCurveId = cid_EC_P256;      
            break;

        case NID_secp384r1:
            eccCurveId = cid_EC_P384;
            break;

        case NID_secp521r1:
            eccCurveId = cid_EC_P521;
            break;

        default:
            status = ERR_EC_UNSUPPORTED_CURVE;
            goto exit;
    }

    /* Generate an ECC key based on the curve provided. Only the software flow is
     * supported so pass in akt_ecc.
     */
    status = CRYPTO_INTERFACE_EC_generateKeyPairAlloc(
        eccCurveId, (void **) &pNewKey, RANDOM_rngFun, pRandCtx, akt_ecc, NULL);
    if (OK != status)
        goto exit;

    /* Extract all the key information from the new ECC key.
     */
    status = CRYPTO_INTERFACE_EC_getKeyParametersAlloc(
        pNewKey, &template, MOC_GET_PRIVATE_KEY_DATA, akt_ecc);
    if (OK != status)
        goto exit;

    status = ERR_EC;

#if defined (VERSION_1_1_0_OR_1_1_1C_OR_3_0)
    retVal = EC_KEY_oct2key(
        pEcKey, template.pPublicKey, template.publicKeyLen, NULL);
    if (1 != retVal)
        goto exit;

    retVal = EC_KEY_oct2priv(
        pEcKey, template.pPrivateKey, template.privateKeyLen);
    if (1 != retVal)
        goto exit;
#else
    /* Convert the private key into a BIGNUM and store it into the OpenSSL
     * EC key.
     */
    pK = BN_bin2bn(template.pPrivateKey, template.privateKeyLen, NULL);
    EC_KEY_set_private_key(pEcKey, pK);

    /* Convert the public key into BIGNUM's and load them into the OpenSSL
     * EC key.
     */
    elementLen = (template.publicKeyLen - 1) / 2;

    pX = BN_bin2bn(template.pPublicKey + 1, elementLen, NULL);
    if (NULL == pX)
        goto exit;

    pY = BN_bin2bn(template.pPublicKey + elementLen + 1, elementLen, NULL);
    if (NULL == pY)
        goto exit;

    if (!EC_KEY_set_public_key_affine_coordinates(pEcKey, pX, pY))
        goto exit;
#endif /* VERSION_1_1_0_OR_1_1_1C_OR_3_0 */

    if (!EVP_PKEY_assign_EC_KEY(pKey, pEcKey))
        goto exit;

    if (!EVP_PKEY_copy_parameters(pKey, pCtx->pkey))
        goto exit;

    status = OK;
    retVal = 1;
    pEcKey = NULL;

exit:

#if !defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) && !defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) && !defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    if (NULL != pK)
        BN_free(pK);

    if (NULL != pX)
        BN_free(pX);

    if (NULL != pY)
        BN_free(pY);
#endif

    if (NULL != pEcKey)
        EC_KEY_free(pEcKey);

    if (pRandCtx && (g_pRandomContext != pRandCtx))
        RANDOM_releaseContext(&pRandCtx);

    CRYPTO_INTERFACE_EC_freeKeyTemplate(pNewKey, &template, akt_ecc);

    if (NULL != pNewKey)
        CRYPTO_INTERFACE_EC_deleteKey((void **) &pNewKey, akt_ecc);

    return retVal;
}
#else
static int moc_ec_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    int curve_name = 0;
    MSTATUS status;
    PEllipticCurvePtr pECurve = NULL;
    randomContext*  pRandomContext = NULL;
    ECCKey *ecKey = NULL;
    EC_KEY *ec = NULL;
    PrimeFieldPtr pPF = NULL;
    ubyte* kPtr = NULL;
    ubyte* qxPtr = NULL;
    ubyte* qyPtr = NULL;
    int size = 0;
    BIGNUM *bn_kPtr = 0;
    BIGNUM *bn_qxPtr = 0;
    BIGNUM *bn_qyPtr = 0;
    MOC_EC_PKEY_CTX *dctx = NULL;
    
    if (ctx == NULL)
    {
        return 0;
    }

    dctx = ctx->data;
    
    if (ctx->pkey == NULL && dctx->gen_group == NULL)
    {
        ECerr(EC_F_PKEY_EC_KEYGEN, EC_R_NO_PARAMETERS_SET);
        return 0;
    }

    if (ctx->pkey)
    {
        curve_name = ctx->pkey->pkey.ec->group->curve_name;
    }
    ec = EC_KEY_new_by_curve_name(curve_name);
    if (!ec)
        return 0;

    if (g_pRandomContext == NULL)
    {
        if (OK > (status = RANDOM_acquireContext(&pRandomContext)))
        {
            return 0;
        }
    }
    else
    {
        pRandomContext = g_pRandomContext;
    }	

    switch (curve_name)
    {
        case NID_X9_62_prime192v1:
            pECurve = EC_P192;
        break;
        case NID_secp224r1:
	    pECurve = EC_P224;
        break;
        case NID_X9_62_prime256v1:
            pECurve = EC_P256;		
        break;
        case NID_secp384r1:
            pECurve = EC_P384;
        break;
        case NID_secp521r1:
            pECurve = EC_P521;
        break;
        default:
        status = ERR_EC_UNSUPPORTED_CURVE;
        goto exit;
    }

    if (OK > (status = EC_newKey(pECurve, &ecKey)))
    {
        goto exit;
    }
    if (OK > (status = EC_generateKeyPair(ecKey->pCurve, RANDOM_rngFun, pRandomContext,
                                          ecKey->k, ecKey->Qx, ecKey->Qy)))
    {
        goto exit;
    }
    pPF = EC_getUnderlyingField(pECurve);
    
    /* get the PFEPtr of k */
    if (OK > (status = PRIMEFIELD_getAsByteString(pPF, ecKey->k, (ubyte**)&kPtr, &size)))
    {
        goto exit;
    }
    bn_kPtr = BN_bin2bn(kPtr, size, NULL);
    /* set the private key to ec */
    EC_KEY_set_private_key(ec,bn_kPtr);

    /* get the PFEPtr of Qx */
    if (OK > (status = PRIMEFIELD_getAsByteString(pPF, ecKey->Qx, (ubyte**)&qxPtr, &size)))
    {
        goto exit;
    }
    bn_qxPtr = BN_bin2bn(qxPtr, size, NULL);
    /* get the PFEPtr of Qy */
    if (OK > (status = PRIMEFIELD_getAsByteString(pPF, ecKey->Qy, (ubyte**)&qyPtr, &size)))
    {
        goto exit;
    }
    bn_qyPtr = BN_bin2bn(qyPtr, size, NULL);
    /* set the public key to ec */
    EC_KEY_set_public_key_affine_coordinates(ec, bn_qxPtr, bn_qyPtr);

    /* Assign pkey */
    EVP_PKEY_assign_EC_KEY(pkey, ec);

    if (ctx->pkey)
    {
       /* Note: if error return, pkey is freed by parent routine */
       if (!EVP_PKEY_copy_parameters(pkey, ctx->pkey))
       {
           status = -1;
           goto exit;
       }
    } 
    else
    {
        if (!EC_KEY_set_group(ec, dctx->gen_group))
        {
            status = -1;
	    goto exit;
        }
    }
     
    status = OK;
 exit:
    if (pRandomContext && (g_pRandomContext != pRandomContext))
    {
        RANDOM_releaseContext(&pRandomContext);
    }
    DIGI_FREE((void**)&qxPtr);
    DIGI_FREE((void**)&qyPtr);
    DIGI_FREE((void**)&kPtr);
    if(bn_qyPtr) BN_free(bn_qyPtr);
    if(bn_qxPtr) BN_free(bn_qxPtr);
    if(bn_kPtr) BN_free(bn_kPtr);
    if (OK > EC_deleteKey(&ecKey))
        status = -1;
    return (status < 0) ? 0 : 1;
}
#endif

static int moc_ec_keyparamgen(EVP_PKEY_CTX*ctx, EVP_PKEY* pkey)
{
    EC_KEY *ec = NULL;
    MOC_EC_PKEY_CTX *dctx = ctx->data;
    int ret = 0;
    if (dctx->gen_group == NULL)
    {
        ECerr(EC_F_PKEY_EC_PARAMGEN, EC_R_NO_PARAMETERS_SET);
        return 0;
    }
    ec = EC_KEY_new();
    if (ec == NULL)
        return 0;
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__)
    if (!(ret = EC_KEY_set_group(ec, dctx->gen_group))
        || !ossl_assert(ret = EVP_PKEY_assign_EC_KEY(pkey, ec)))
        EC_KEY_free(ec);
#else
    ret = EC_KEY_set_group(ec, dctx->gen_group);
    if (ret)
        EVP_PKEY_assign_EC_KEY(pkey, ec);
    else
        EC_KEY_free(ec);
#endif
    return ret;
}

static int moc_ec_ctrl(EVP_PKEY_CTX* ctx, int type, int p1, void *p2)
{
    MOC_EC_PKEY_CTX *dctx = ctx->data;
    EC_GROUP *group;
    switch (type)
    {
        case EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID:
            group = EC_GROUP_new_by_curve_name(p1);
            if (group == NULL)
            {
                ECerr(EC_F_PKEY_EC_CTRL, EC_R_INVALID_CURVE);
                return 0;
            }
            if (dctx->gen_group != NULL)
                EC_GROUP_free(dctx->gen_group);
            dctx->gen_group = group;
            return 1;
        case EVP_PKEY_CTRL_EC_PARAM_ENC:
            if (!dctx->gen_group)
            {
                ECerr(EC_F_PKEY_EC_CTRL, EC_R_NO_PARAMETERS_SET);
                return 0;
            }
            EC_GROUP_set_asn1_flag(dctx->gen_group, p1);
            return 1;
        case EVP_PKEY_CTRL_EC_ECDH_COFACTOR:
            if (p1 == -2) {
                if (dctx->cofactor_mode != -1)
                    return dctx->cofactor_mode;
                else {
                    EC_KEY *ec_key = ctx->pkey->pkey.ec;
                    return EC_KEY_get_flags(ec_key) & EC_FLAG_COFACTOR_ECDH ? 1 :
                        0;
                }
            } else if (p1 < -1 || p1 > 1)
                return -2;
            dctx->cofactor_mode = p1;
            if (p1 != -1) {
                EC_KEY *ec_key = ctx->pkey->pkey.ec;
                if (!ec_key->group)
                    return -2;
                /* If cofactor is 1 cofactor mode does nothing */
#if defined (VERSION_1_1_0_OR_1_1_1C_OR_3_0)
                if (BN_is_one((const BIGNUM *) ec_key->group->cofactor))
                    return 1;
#else
                if (BN_is_one(&ec_key->group->cofactor))
                    return 1;
#endif
                if (!dctx->co_key) {
                    dctx->co_key = EC_KEY_dup(ec_key);
                    if (!dctx->co_key)
                        return 0;
                }
                if (p1)
                    EC_KEY_set_flags(dctx->co_key, EC_FLAG_COFACTOR_ECDH);
                else
                    EC_KEY_clear_flags(dctx->co_key, EC_FLAG_COFACTOR_ECDH);
            } else if (dctx->co_key) {
                EC_KEY_free(dctx->co_key);
                dctx->co_key = NULL;
            }
            return 1;
        case EVP_PKEY_CTRL_EC_KDF_TYPE:
            if (p1 == -2)
                return dctx->kdf_type;
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__)
            if (p1 != EVP_PKEY_ECDH_KDF_NONE && p1 != EVP_PKEY_ECDH_KDF_X9_63)
                return -2;
#else
            if (p1 != EVP_PKEY_ECDH_KDF_NONE && p1 != EVP_PKEY_ECDH_KDF_X9_62)
                return -2;
#endif
            dctx->kdf_type = p1;
            return 1;
        case EVP_PKEY_CTRL_EC_KDF_MD:
            dctx->kdf_md = p2;
            return 1;
        case EVP_PKEY_CTRL_GET_EC_KDF_MD:
            *(const EVP_MD **)p2 = dctx->kdf_md;
            return 1;
        case EVP_PKEY_CTRL_EC_KDF_OUTLEN:
            if (p1 <= 0)
                return -2;
            dctx->kdf_outlen = (size_t)p1;
            return 1;
        case EVP_PKEY_CTRL_GET_EC_KDF_OUTLEN:
            *(int *)p2 = (int)dctx->kdf_outlen;
            return 1;
        case EVP_PKEY_CTRL_EC_KDF_UKM:
            if (dctx->kdf_ukm)
                OPENSSL_free(dctx->kdf_ukm);
            dctx->kdf_ukm = p2;
            if (p2)
                dctx->kdf_ukmlen = p1;
            else
                dctx->kdf_ukmlen = 0;
            return 1;

        case EVP_PKEY_CTRL_GET_EC_KDF_UKM:
            *(unsigned char **)p2 = dctx->kdf_ukm;
            return (int)dctx->kdf_ukmlen;
        case EVP_PKEY_CTRL_MD:
            if (EVP_MD_type((const EVP_MD *)p2) != NID_sha1 &&
                EVP_MD_type((const EVP_MD *)p2) != NID_ecdsa_with_SHA1 &&
                EVP_MD_type((const EVP_MD *)p2) != NID_sha224 &&
                EVP_MD_type((const EVP_MD *)p2) != NID_sha256 &&
                EVP_MD_type((const EVP_MD *)p2) != NID_sha384 &&
                EVP_MD_type((const EVP_MD *)p2) != NID_sha512
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__)
                && EVP_MD_type((const EVP_MD *)p2) != NID_sha3_224 &&
                EVP_MD_type((const EVP_MD *)p2) != NID_sha3_256 &&
                EVP_MD_type((const EVP_MD *)p2) != NID_sha3_384 &&
                EVP_MD_type((const EVP_MD *)p2) != NID_sha3_512
#endif
                )
            {
                ECerr(EC_F_PKEY_EC_CTRL, EC_R_INVALID_DIGEST_TYPE);
                return 0;
            }
            dctx->md = p2;
            return 1;

        case EVP_PKEY_CTRL_GET_MD:
            *(const EVP_MD **)p2 = dctx->md;
            return 1;
        case EVP_PKEY_CTRL_PEER_KEY:
            /* Default behaviour is OK */
        case EVP_PKEY_CTRL_DIGESTINIT:
        case EVP_PKEY_CTRL_PKCS7_SIGN:
        case EVP_PKEY_CTRL_CMS_SIGN:
            return 1;
        default:
            return -2;
    }
}

static int moc_ec_ctrl_str(EVP_PKEY_CTX* ctx, const char* type, const char* value)
{
#if !defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) && !defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) && !defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    if (!value)
    {
        return 0;
    }
#endif
    if (strcmp(type, "ec_paramgen_curve") == 0)
    {
         int nid;
        nid = EC_curve_nist2nid(value);
        if (nid == NID_undef)
            nid = OBJ_sn2nid(value);
        if (nid == NID_undef)
            nid = OBJ_ln2nid(value);
        if (nid == NID_undef)
        {
            ECerr(EC_F_PKEY_EC_CTRL_STR, EC_R_INVALID_CURVE);
            return 0;
        }
        return EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid);
    }
    else if (!strcmp(type, "ec_param_enc"))
    {
        int param_enc;
        if (!strcmp(value, "explicit"))
            param_enc = 0;
        else if (!strcmp(value, "named_curve"))
            param_enc = OPENSSL_EC_NAMED_CURVE;
        else
            return -2;
        return EVP_PKEY_CTX_set_ec_param_enc(ctx, param_enc);
    }
    else if (!strcmp(type, "ecdh_kdf_md"))
    {
        const EVP_MD *md;
        if (!(md = EVP_get_digestbyname(value)))
        {
            ECerr(EC_F_PKEY_EC_CTRL_STR, EC_R_INVALID_DIGEST);
            return 0;
        }
        return EVP_PKEY_CTX_set_ecdh_kdf_md(ctx, md);
    }
    else if (!strcmp(type, "ecdh_cofactor_mode"))
    {
        int co_mode;
        co_mode = atoi(value);
        return EVP_PKEY_CTX_set_ecdh_cofactor_mode(ctx, co_mode);
    }
    return -2;
}

static int moc_ec_derive(EVP_PKEY_CTX *ctx, unsigned char *key,
                          size_t *keylen)
{
    int ret;
    size_t outlen;
    const EC_POINT *pubkey = NULL;
    EC_KEY *eckey;
    MOC_EC_PKEY_CTX *dctx = ctx->data;
    if (!ctx->pkey || !ctx->peerkey) {
        ECerr(EC_F_PKEY_EC_DERIVE, EC_R_KEYS_NOT_SET);
        return 0;
    }

    eckey = dctx->co_key ? dctx->co_key : ctx->pkey->pkey.ec;

    if (!key) {
        const EC_GROUP *group;
        group = EC_KEY_get0_group(eckey);
        *keylen = (EC_GROUP_get_degree(group) + 7) / 8;
        return 1;
    }
    pubkey = EC_KEY_get0_public_key(ctx->peerkey->pkey.ec);

    /*
     * NB: unlike PKCS#3 DH, if *outlen is less than maximum size this is not
     * an error, the result is truncated.
     */

    outlen = *keylen;

    ret = ECDH_compute_key(key, outlen, pubkey, eckey, 0);
    if (ret <= 0)
        return 0;
    *keylen = ret;
    return 1;
}

static int moc_ec_kdf_derive(EVP_PKEY_CTX *ctx, unsigned char *key,
                          size_t *keylen)
{
    MOC_EC_PKEY_CTX *dctx = ctx->data;
    unsigned char *ktmp = NULL;
    size_t ktmplen;
    int rv = 0;
    if (dctx->kdf_type == EVP_PKEY_ECDH_KDF_NONE)
        return moc_ec_derive(ctx, key, keylen);
    if (!key) {
        *keylen = dctx->kdf_outlen;
        return 1;
    }
    if (*keylen != dctx->kdf_outlen)
        return 0;
    if (!moc_ec_derive(ctx, NULL, &ktmplen))
        return 0;
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__)
    if ((ktmp = OPENSSL_malloc(ktmplen)) == NULL) {
        ECerr(EC_F_PKEY_EC_KDF_DERIVE, ERR_R_MALLOC_FAILURE);
        return 0;
    }
#else
    ktmp = OPENSSL_malloc(ktmplen);
    if (!ktmp)
        return 0;
#endif
    if (!moc_ec_derive(ctx, ktmp, &ktmplen))
        goto err;
    /* Do KDF stuff */
    if (!ECDH_KDF_X9_62(key, *keylen, ktmp, ktmplen,
                        dctx->kdf_ukm, dctx->kdf_ukmlen, dctx->kdf_md))
        goto err;
    rv = 1;

 err:
#if defined (VERSION_1_1_0_OR_1_1_1C_OR_3_0)
    OPENSSL_clear_free(ktmp, ktmplen);
#else
    if (ktmp) {
        OPENSSL_cleanse(ktmp, ktmplen);
        OPENSSL_free(ktmp);
    }
#endif
    return rv;
}

static const EVP_PKEY_METHOD moc_ec_pkey_meth = {
    EVP_PKEY_EC,
    0,
    moc_ec_init,
    moc_ec_copy,
    moc_ec_cleanup,

    0,
    moc_ec_keyparamgen,

    0,
    moc_ec_keygen,

    0,
    moc_ec_sign,

    0,
    moc_ec_verify,

    0, 0,

    0, 0, 0, 0,

    0, 0,

    0, 0,

    0,
#ifndef OPENSSL_NO_ECDH
    moc_ec_kdf_derive,
#else
    0,
#endif

    moc_ec_ctrl,
    moc_ec_ctrl_str
};


void MOC_registerECMeth(EVP_PKEY_METHOD **ec_pmeth)
{
    *ec_pmeth = (EVP_PKEY_METHOD*)&moc_ec_pkey_meth;
}

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__)

#if defined(__ENABLE_DIGICERT_ECC_EDDH_25519__) || defined(__ENABLE_DIGICERT_ECC_EDDH_448__) || \
    defined(__ENABLE_DIGICERT_ECC_EDDSA_25519__) || defined(__ENABLE_DIGICERT_ECC_EDDSA_448__)

static MSTATUS MOC_EVP_convertEdMocToOssl(ECCKey *pMocKey, ECX_KEY **ppOsslKey)
{
    MSTATUS status;
    ECX_KEY *pNewKey = NULL;
    MEccKeyTemplate template = {0};

    if ( (NULL == pMocKey) || (NULL == ppOsslKey) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Extract all the key information from the new ECC key.
     */
    status = CRYPTO_INTERFACE_EC_getKeyParametersAllocAux(
        pMocKey, &template, MOC_GET_PRIVATE_KEY_DATA);
    if (OK != status)
        goto exit;

    pNewKey = OPENSSL_zalloc(sizeof(ECX_KEY));
    if (NULL == pNewKey)
        goto exit;

    status = DIGI_MEMCPY(
        pNewKey->pubkey, template.pPublicKey, template.publicKeyLen);
    if (OK != status)
        goto exit;

    pNewKey->privkey = OPENSSL_secure_malloc(template.privateKeyLen);
    if (NULL == pNewKey->privkey)
        goto exit;

    status = DIGI_MEMCPY(
        pNewKey->privkey, template.pPrivateKey, template.privateKeyLen);
    if (OK != status)
        goto exit;

    *ppOsslKey = pNewKey;
    pNewKey = NULL;

exit:

    if (NULL != pNewKey)
    {
        if (NULL != pNewKey->privkey)
        {
            OPENSSL_secure_free(pNewKey->privkey);
        }
        OPENSSL_free(pNewKey);
    }

    CRYPTO_INTERFACE_EC_freeKeyTemplateAux(pMocKey, &template);

    return status;
}

static MSTATUS MOC_EVP_convertEdOsslToMoc(EVP_PKEY *pOsslKey, ECCKey **ppMocKey)
{
    MSTATUS status;
    ubyte4 curveId;
    ECCKey *pNewKey = NULL;
    ECX_KEY *pEcxKey;
    unsigned char *pPriv = NULL;
    unsigned char *pPub = NULL;
    size_t privLen = 0;
    size_t pubLen = 0;

    if ( (NULL == pOsslKey) || (NULL == ppMocKey) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pEcxKey = pOsslKey->pkey.ecx;

    switch (EVP_PKEY_base_id(pOsslKey))
    {
#if defined(__ENABLE_DIGICERT_ECC_EDDH_25519__)
        case EVP_PKEY_X25519:
            curveId = cid_EC_X25519;
            break;
#endif

#if defined(__ENABLE_DIGICERT_ECC_EDDSA_25519__)
        case EVP_PKEY_ED25519:
            curveId = cid_EC_Ed25519;
            break;
#endif

#if defined(__ENABLE_DIGICERT_ECC_EDDH_448__)
        case EVP_PKEY_X448:
            curveId = cid_EC_X448;
            break;
#endif

#if defined(__ENABLE_DIGICERT_ECC_EDDSA_448__)
        case EVP_PKEY_ED448:
            curveId = cid_EC_Ed448;
            break;
#endif

        default:
            status = ERR_INVALID_INPUT;
            goto exit;
    }

    status = CRYPTO_INTERFACE_EC_newKeyAux(curveId, &pNewKey);
    if (OK != status)
        goto exit;

    status = ERR_EC;

    if (NULL != pEcxKey->privkey)
    {
        if (1 != EVP_PKEY_get_raw_private_key(pOsslKey, NULL, &privLen))
            goto exit;

        pPriv = OPENSSL_secure_malloc(privLen);
        if (NULL == pPriv)
            goto exit;

        if (1 != EVP_PKEY_get_raw_private_key(pOsslKey, pPriv, &privLen))
            goto exit;
    }

    if (1 != EVP_PKEY_get_raw_public_key(pOsslKey, NULL, &pubLen))
        goto exit;

    pPub = OPENSSL_secure_malloc(pubLen);
    if (NULL == pPub)
        goto exit;

    if (1 != EVP_PKEY_get_raw_public_key(pOsslKey, pPub, &pubLen))
        goto exit;

    status = CRYPTO_INTERFACE_EC_setKeyParametersAux(
        pNewKey, pPub, pubLen, pPriv, privLen);
    if (OK != status)
        goto exit;

    *ppMocKey = pNewKey;
    pNewKey = NULL;

exit:

    if (NULL != pPub)
        OPENSSL_secure_free(pPub);

    if (NULL != pPriv)
        OPENSSL_secure_free(pPriv);

    if (NULL != pNewKey)
        CRYPTO_INTERFACE_EC_deleteKeyAux(&pNewKey);

    return status;
}

static int moc_pkey_ecx_keygen(EVP_PKEY_CTX *pCtx, EVP_PKEY *pPkey)
{
    MSTATUS status;
    randomContext *pRandCtx = NULL;
    ECCKey *pNewKey = NULL;
    MEccKeyTemplate template = {0};
    ubyte4 curveId;
    int rval = 0;
    ECX_KEY *pOsslKey = NULL;

    if (NULL == g_pRandomContext)
    {
        status = RANDOM_acquireContext(&pRandCtx);
        if (OK != status)
            goto exit;
    }
    else
    {
        pRandCtx = g_pRandomContext;
    }

    /* Convert OpenSSL ID to Mocana Ed curve ID */
    switch (pCtx->pmeth->pkey_id)
    {
#if defined(__ENABLE_DIGICERT_ECC_EDDH_25519__)
        case EVP_PKEY_X25519:
            curveId = cid_EC_X25519;
            break;
#endif

#if defined(__ENABLE_DIGICERT_ECC_EDDSA_25519__)
        case EVP_PKEY_ED25519:
            curveId = cid_EC_Ed25519;
            break;
#endif

#if defined(__ENABLE_DIGICERT_ECC_EDDH_448__)
        case EVP_PKEY_X448:
            curveId = cid_EC_X448;
            break;
#endif

#if defined(__ENABLE_DIGICERT_ECC_EDDSA_448__)
        case EVP_PKEY_ED448:
            curveId = cid_EC_Ed448;
            break;
#endif

        default:
            goto exit;
    }

    /* Create new key */
    status = CRYPTO_INTERFACE_EC_generateKeyPairAllocAux(
        curveId, &pNewKey, RANDOM_rngFun, pRandCtx);
    if (OK != status)
        goto exit;

    /* Extract all the key information from the new ECC key.
     */
    status = CRYPTO_INTERFACE_EC_getKeyParametersAlloc(
        pNewKey, &template, MOC_GET_PRIVATE_KEY_DATA, akt_ecc);
    if (OK != status)
        goto exit;

    /* Convert Mocana key to OpenSSL key */
    status = MOC_EVP_convertEdMocToOssl(pNewKey, &pOsslKey);
    if (OK != status)
        goto exit;

    EVP_PKEY_assign(pPkey, pCtx->pmeth->pkey_id, pOsslKey);
    pOsslKey = NULL;
    /* Set success value */
    rval = 1;

exit:

    CRYPTO_INTERFACE_EC_freeKeyTemplateAux(pNewKey, &template);

    if (NULL != pNewKey)
        CRYPTO_INTERFACE_EC_deleteKeyAux(&pNewKey);

    if (pRandCtx && (g_pRandomContext != pRandCtx))
        RANDOM_releaseContext(&pRandCtx);

    return rval;
}

#if defined(__ENABLE_DIGICERT_ECC_EDDH_25519__) || defined(__ENABLE_DIGICERT_ECC_EDDH_448__)

static int moc_pkey_ecx_derive(
    EVP_PKEY_CTX *pCtx, unsigned char *pKey, size_t *pKeyLen)
{
    MSTATUS status;
    ECCKey *pMocKey = NULL;
    unsigned char *pPub = NULL;
    size_t pubLen = 0;
    int rval = 0;
    ubyte *pSecret = NULL;
    ubyte4 secretLen = 0;

    if ( (NULL == pCtx->pkey) || (NULL == pCtx->peerkey) )
        goto exit;

    status = MOC_EVP_convertEdOsslToMoc(pCtx->pkey, &pMocKey);
    if (OK != status)
        goto exit;

    status = ERR_EC;

    if (1 != EVP_PKEY_get_raw_public_key(pCtx->peerkey, NULL, &pubLen))
        goto exit;

    pPub = OPENSSL_secure_malloc(pubLen);
    if (NULL == pPub)
        goto exit;

    if (1 != EVP_PKEY_get_raw_public_key(pCtx->peerkey, pPub, &pubLen))
        goto exit;

    status = CRYPTO_INTERFACE_ECDH_generateSharedSecretFromPublicByteStringAux(
        pMocKey, pPub, pubLen, &pSecret, &secretLen, 0, NULL);
    if (OK != status)
        goto exit;

    if (NULL != pKey)
    {
        status = DIGI_MEMCPY(pKey, pSecret, secretLen);
        if (OK != status)
            goto exit;
    }

    *pKeyLen = secretLen;
    rval = 1;

exit:

    if (NULL != pSecret)
        DIGI_MEMSET_FREE(&pSecret, secretLen);

    if (NULL != pPub)
        OPENSSL_secure_free(pPub);

    if (NULL != pMocKey)
        CRYPTO_INTERFACE_EC_deleteKeyAux(&pMocKey);

    return rval;
}

static int moc_pkey_ecx_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    /* Only need to handle peer key for derivation */
    if (type == EVP_PKEY_CTRL_PEER_KEY)
        return 1;
    return -2;
}

#endif /* __ENABLE_DIGICERT_ECC_EDDH_25519__ || __ENABLE_DIGICERT_ECC_EDDH_448__ */

#if defined(__ENABLE_DIGICERT_ECC_EDDSA_25519__) || defined(__ENABLE_DIGICERT_ECC_EDDSA_448__)

static int moc_pkey_ecd_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    switch (type) {
    case EVP_PKEY_CTRL_MD:
        /* Only NULL allowed as digest */
        if (p2 == NULL || (const EVP_MD *)p2 == EVP_md_null())
            return 1;
        ECerr(EC_F_PKEY_ECD_CTRL, EC_R_INVALID_DIGEST_TYPE);
        return 0;

    case EVP_PKEY_CTRL_DIGESTINIT:
        return 1;
    }
    return -2;
}

static int moc_pkey_ecd_digestsign(
    EVP_MD_CTX *pCtx, unsigned char *pSig, size_t *pSigLen,
    const unsigned char *pMsg, size_t msgLen)
{
    MSTATUS status;
    ECCKey *pMocKey = NULL;
    ubyte4 sigLen;
    int rval = 0;

    status = MOC_EVP_convertEdOsslToMoc(
        EVP_MD_CTX_pkey_ctx(pCtx)->pkey, &pMocKey);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_EC_getElementByteStringLenAux(
        pMocKey, &sigLen);
    if (OK != status)
        goto exit;

    sigLen *= 2;
    if (NULL == pSig)
    {
        *pSigLen = sigLen;
        rval = 1;
        goto exit;
    }

    if (*pSigLen < sigLen)
    {
        ECerr(EC_F_PKEY_ECD_DIGESTSIGN25519, EC_R_BUFFER_TOO_SMALL);
        goto exit;
    }

    status = CRYPTO_INTERFACE_ECDSA_signMessageExt(
        pMocKey, NULL, NULL, 0, (ubyte *) pMsg, msgLen, pSig, *pSigLen,
        &sigLen, NULL);
    if (OK != status)
        goto exit;

    *pSigLen = sigLen;
    rval = 1;

exit:

    if (NULL != pMocKey)
        CRYPTO_INTERFACE_EC_deleteKeyAux(&pMocKey);

    return rval;
}

static int moc_pkey_ecd_digestverify(
    EVP_MD_CTX *pCtx, const unsigned char *pSig, size_t sigLen,
    const unsigned char *pMsg, size_t msgLen)
{
    MSTATUS status;
    ECCKey *pMocKey = NULL;
    ubyte4 length, vfyRes;
    int rval = 0;

    status = MOC_EVP_convertEdOsslToMoc(
        EVP_MD_CTX_pkey_ctx(pCtx)->pkey, &pMocKey);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_EC_getElementByteStringLenAux(
        pMocKey, &length);
    if (OK != status)
        goto exit;

    length *= 2;
    if (length != sigLen)
        goto exit;

    status = CRYPTO_INTERFACE_ECDSA_verifyMessageExt(
        pMocKey, 0, (ubyte *) pMsg, msgLen, (ubyte *) pSig, sigLen,
        &vfyRes, NULL);
    if (OK != status)
        goto exit;

    if (0 == vfyRes)
        rval = 1;

exit:

    if (NULL != pMocKey)
        CRYPTO_INTERFACE_EC_deleteKeyAux(&pMocKey);

    return rval;
}

#endif /* __ENABLE_DIGICERT_ECC_EDDSA_25519__ || __ENABLE_DIGICERT_ECC_EDDSA_448__ */

#endif /* __ENABLE_DIGICERT_ECC_EDDH_25519__ || __ENABLE_DIGICERT_ECC_EDDH_448__ || __ENABLE_DIGICERT_ECC_EDDSA_25519__ || __ENABLE_DIGICERT_ECC_EDDSA_448__ */

#if defined(__ENABLE_DIGICERT_ECC_EDDH_25519__)

static const EVP_PKEY_METHOD moc_ecx25519_pkey_meth = {
    EVP_PKEY_X25519,
    0, 0, 0, 0, 0, 0, 0,
    moc_pkey_ecx_keygen,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    moc_pkey_ecx_derive,
    moc_pkey_ecx_ctrl,
    0
};

void MOC_registerEcx25519Meth(EVP_PKEY_METHOD **ec_pmeth)
{
    *ec_pmeth = (EVP_PKEY_METHOD*)&moc_ecx25519_pkey_meth;
}

#endif /* __ENABLE_DIGICERT_ECC_EDDH_25519__ */

#if defined(__ENABLE_DIGICERT_ECC_EDDH_448__)

static const EVP_PKEY_METHOD moc_ecx448_pkey_meth = {
    EVP_PKEY_X448,
    0, 0, 0, 0, 0, 0, 0,
    moc_pkey_ecx_keygen,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    moc_pkey_ecx_derive,
    moc_pkey_ecx_ctrl,
    0
};

void MOC_registerEcx448Meth(EVP_PKEY_METHOD **ec_pmeth)
{
    *ec_pmeth = (EVP_PKEY_METHOD*)&moc_ecx448_pkey_meth;
}

#endif /* __ENABLE_DIGICERT_ECC_EDDH_448__ */

#if defined(__ENABLE_DIGICERT_ECC_EDDSA_25519__)

static const EVP_PKEY_METHOD moc_ed25519_pkey_meth = {
    EVP_PKEY_ED25519, EVP_PKEY_FLAG_SIGCTX_CUSTOM,
    0, 0, 0, 0, 0, 0,
    moc_pkey_ecx_keygen,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    moc_pkey_ecd_ctrl,
    0,
    moc_pkey_ecd_digestsign,
    moc_pkey_ecd_digestverify
};

void MOC_registerEd25519Meth(EVP_PKEY_METHOD **ec_pmeth)
{
    *ec_pmeth = (EVP_PKEY_METHOD*)&moc_ed25519_pkey_meth;
}

#endif /* __ENABLE_DIGICERT_ECC_EDDSA_25519__ */

#if defined(__ENABLE_DIGICERT_ECC_EDDSA_448__)

static const EVP_PKEY_METHOD moc_ed448_pkey_meth = {
    EVP_PKEY_ED448, EVP_PKEY_FLAG_SIGCTX_CUSTOM,
    0, 0, 0, 0, 0, 0,
    moc_pkey_ecx_keygen,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    moc_pkey_ecd_ctrl,
    0,
    moc_pkey_ecd_digestsign,
    moc_pkey_ecd_digestverify
};

void MOC_registerEd448Meth(EVP_PKEY_METHOD **ec_pmeth)
{
    *ec_pmeth = (EVP_PKEY_METHOD*)&moc_ed448_pkey_meth;
}

#endif /* __ENABLE_DIGICERT_ECC_EDDSA_448__ */

#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__ */