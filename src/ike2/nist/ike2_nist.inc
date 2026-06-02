/*
 * ike2_nist.inc
 *
 * Functions for testing IKEV2 against SP 800-135
 *
 */

#ifdef __ENABLE_DIGICERT_SP800_135_ACVP__

#if defined(__ENABLE_ALL_DEBUGGING__) && defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__)
#define ALGONAMES(_n1, _n2) (sbyte *)_n1, (sbyte *)_n2,
#else
#define ALGONAMES(_n1, _n2)
#endif

#ifdef __ENABLE_IKE_SIG_AUTH_RFC7427__
#define SIGAUTH(_a) (ubyte2)_a,
#else
#define SIGAUTH(_a)
#endif

static BulkHashAlgo SHASuite =
    { SHA1_RESULT_SIZE/*20*/, SHA1_BLOCK_SIZE, IKE_sha1Alloc, IKE_sha1Free,
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
      (BulkCtxInitFunc) CRYPTO_INTERFACE_SHA1_initDigest, (BulkCtxUpdateFunc) CRYPTO_INTERFACE_SHA1_updateDigest, 
      (BulkCtxFinalFunc) CRYPTO_INTERFACE_SHA1_finalDigest, NULL, NULL, NULL, ht_sha1 };
#else
      (BulkCtxInitFunc)SHA1_initDigestHandShake, (BulkCtxUpdateFunc)SHA1_updateDigestHandShake, (BulkCtxFinalFunc)SHA1_finalDigestHandShake, NULL, NULL, NULL, ht_sha1 };
#endif

#ifndef __DISABLE_DIGICERT_SHA256__
static BulkHashAlgo SHA256Suite =
    { SHA256_RESULT_SIZE/*32*/, SHA256_BLOCK_SIZE, SHA256_allocDigest, SHA256_freeDigest,
      (BulkCtxInitFunc)SHA256_initDigest, (BulkCtxUpdateFunc)SHA256_updateDigest, (BulkCtxFinalFunc)SHA256_finalDigest, NULL, NULL, NULL, ht_sha256 };
#endif

#ifndef __DISABLE_DIGICERT_SHA384__
static BulkHashAlgo SHA384Suite =
    { SHA384_RESULT_SIZE/*48*/, SHA384_BLOCK_SIZE, SHA384_allocDigest, SHA384_freeDigest,
      (BulkCtxInitFunc)SHA384_initDigest, (BulkCtxUpdateFunc)SHA384_updateDigest, (BulkCtxFinalFunc)SHA384_finalDigest, NULL, NULL, NULL, ht_sha384 };
#endif

#ifndef __DISABLE_DIGICERT_SHA512__
static BulkHashAlgo SHA512Suite =
    { SHA512_RESULT_SIZE/*64*/, SHA512_BLOCK_SIZE, SHA512_allocDigest, SHA512_freeDigest,
      (BulkCtxInitFunc)SHA512_initDigest, (BulkCtxUpdateFunc)SHA512_updateDigest, (BulkCtxFinalFunc)SHA512_finalDigest, NULL, NULL, NULL, ht_sha512 };
#endif

static IKE_hashSuiteInfo mHashSuites2[] =
{/* { wHashAlgo [v1],       wTfmId [v2],        pBHAlgo,        pBPAlgo },
  */
#ifndef __DISABLE_DIGICERT_SHA512__
    { ALGONAMES("SHA2-512", "HMAC_SHA2_512" )   SIGAUTH(HASH_SHA2_512)
      OAKLEY_SHA2_512,      PRF_HMAC_SHA2_512,  &SHA512Suite
#ifdef __ENABLE_DIGICERT_IKE_UNSECURE_HASH__
                                                            ,   NULL,       { {TRUE} }
#endif
                                                                                       },
#endif
#ifndef __DISABLE_DIGICERT_SHA384__
    { ALGONAMES("SHA2-384", "HMAC_SHA2_384" )   SIGAUTH(HASH_SHA2_384)
      OAKLEY_SHA2_384,      PRF_HMAC_SHA2_384,  &SHA384Suite
#ifdef __ENABLE_DIGICERT_IKE_UNSECURE_HASH__
                                                            ,   NULL,       { {TRUE} }
#endif
                                                                                       },
#endif
#ifndef __DISABLE_DIGICERT_SHA256__
    { ALGONAMES("SHA2-256", "HMAC_SHA2_256" )   SIGAUTH(HASH_SHA2_256)
      OAKLEY_SHA2_256,      PRF_HMAC_SHA2_256,  &SHA256Suite
#ifdef __ENABLE_DIGICERT_IKE_UNSECURE_HASH__
                                                            ,   NULL,       { {TRUE} }
#endif
                                                                                       },
#endif

#if defined(__ENABLE_DIGICERT_IKE_UNSECURE_HASH__)
    { ALGONAMES("SHA1",     "HMAC_SHA1"     )   SIGAUTH(HASH_SHA1)
      OAKLEY_SHA,           PRF_HMAC_SHA1,      &SHASuite  }
#endif
};

#define NUM_IKE_HASH_SUITES2     (sizeof(mHashSuites2)/sizeof(IKE_hashSuiteInfo))

#define VARKEYLEN(_kl) (_kl), (_kl), FALSE

static IKE_cipherSuiteInfo mCipherSuites2[] = {
    { OAKLEY_AES_CBC,       ENCR_AES_CBC,
      AES_BLOCK_SIZE,       VARKEYLEN(32),                      &CRYPTO_AESSuite }
};

struct ike2xg testXg = {0};

#include "../../ike2/nist/ike2_nist.h"

MSTATUS setIKESA(IKE_context pCtx, IKESA pSa)
{
    if ( (NULL == pSa) || (NULL == pCtx) )
    {
        return ERR_NULL_POINTER;
    }

    if (NULL != pCtx->pxSa)
    {
        FreeSa(pCtx->pxSa);
    }

    pCtx->pxSa = pSa;

    return OK;
}

MSTATUS setIKEOldSA(IKE_context pCtx, IKESA pSa)
{
    MSTATUS status = OK;
    IKE2XG pxXg = NULL;
    IPSECSA pIpsec = NULL;

    if ( (NULL == pSa) || (NULL == pCtx) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == pCtx->pxXg)
    {
        pxXg = &testXg;

        status = DIGI_CALLOC((void **)&pIpsec, 1, sizeof(struct ipsecsa));
        if (OK != status)
            goto exit;

        pxXg->oExchange = IKE_XCHG_AUTH;
        pxXg->pxIPsecSa = pIpsec;
        pCtx->pxXg = pxXg;
        pxXg = NULL;
    }

    pCtx->pxXg->pxSa = pSa;

exit:
    return status;
}

MSTATUS setIKEChildDkmLen(IKE_context pCtx, ubyte hashAlg, ubyte4 childDkmLen)
{
    MSTATUS status = OK;
    ubyte4 digestLen = 0;
    IKE2XG pxXg = NULL;
    IPSECSA pxIPsecSa = NULL;
    IPSECPPS pxIPsecPps = NULL;

    if ( (NULL == pCtx) || (NULL == pCtx->pxXg) || (NULL == pCtx->pxXg->pxIPsecSa) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    switch(hashAlg)
    {
        case ht_sha1:
            digestLen = 20;
            break;

        case ht_sha256:
            digestLen = 32;
            break;

        case ht_sha384:
            digestLen = 48;
            break;
        
        case ht_sha512:
            digestLen = 64;
            break;
        
        default:
            status = ERR_INVALID_INPUT;
            goto exit;
    }

    if (childDkmLen > (((CHILDSA_AUTHKEY_MAX + CHILDSA_ENCRKEY_MAX) * 2) + digestLen))
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    pxXg = pCtx->pxXg;
    pxIPsecSa = pxXg->pxIPsecSa;
    pxIPsecPps = &(pxIPsecSa->axP2Sa[0].axChildSa[0].ipsecPps);
    pxIPsecPps->wAuthAlgo = 1;
    pxIPsecSa->axP2Sa[0].oChildSaLen = 1;
    pxIPsecPps->wAuthKeyLen = CHILDSA_AUTHKEY_MAX + CHILDSA_ENCRKEY_MAX;
    g_childDkmLen = childDkmLen;

exit:  
    return status;
}

MSTATUS setIKEDkmLen(IKESA pSa, ubyte hashAlg, ubyte4 dkmLen)
{
    MSTATUS status = OK;
    ubyte4 digestLen = 0;
    ubyte alg = 0;
    ubyte4 i = 0;
    ubyte found = 0;

    if (NULL == pSa)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    switch(hashAlg)
    {
        case ht_sha1:
            alg = OAKLEY_SHA;
            digestLen = 20;
            break;

        case ht_sha256:
            alg = OAKLEY_SHA2_256;
            digestLen = 32;
            break;

        case ht_sha384:
            alg = OAKLEY_SHA2_384;
            digestLen = 48;
            break;
        
        case ht_sha512:
            alg = OAKLEY_SHA2_512;
            digestLen = 64;
            break;
        
        default:
            status = ERR_INVALID_INPUT;
            goto exit;
    }

    if (dkmLen > (IKE_HASH_MAX*3 + IKE_AUTHKEY_MAX*2 + IKE_ENCRKEY_MAX*2))
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    pSa->wEncrKeyLen = IKE_ENCRKEY_MAX;
    pSa->wAuthKeyLen = IKE_AUTHKEY_MAX;

    for (i = 0; i < NUM_IKE_HASH_SUITES2; i++)
    {
        if (alg == mHashSuites2[i].wHashAlgo)
        {
            pSa->pHashSuite = &mHashSuites2[i];
            found = 1;
            break;
        }
    }

    if (0 == found)
    {
        status = ERR_NOT_FOUND;
    }

    pSa->pCipherSuite = &mCipherSuites2[0];
    g_dkmLen = dkmLen;

exit:
    return status;
}

MSTATUS setIKENewSharedSecret(IKE_context pCtx, ubyte *pValue, ubyte4 valueLen)
{
    MSTATUS status = OK;
    IPSECSA pxIPsecSa = NULL;

    if ( (NULL == pCtx) || (NULL == pCtx->pxXg) || (NULL == pCtx->pxXg->pxIPsecSa) || (NULL == pValue) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pxIPsecSa = pCtx->pxXg->pxIPsecSa;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_DH_allocateServerExt(g_pRandomContext, &pxIPsecSa->p_dhContext, 14, NULL);
#else
    status = DH_allocateServer(g_pRandomContext, &pxIPsecSa->p_dhContext, 14);
#endif
    if (OK != status)
        goto exit;

    if (NULL != pxIPsecSa->pDhSharedSecret)
    {
        DIGI_FREE((void **)&pxIPsecSa->pDhSharedSecret);
    }

    status = DIGI_MALLOC((void **)&pxIPsecSa->pDhSharedSecret, valueLen);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY((void *)pxIPsecSa->pDhSharedSecret, pValue, valueLen);
    if (OK != status)
        goto exit;

    pxIPsecSa->dhSharedSecretLen = valueLen;

exit:
    return status;
}

MSTATUS setIKEValue(IKESA pSa, ubyte type, ubyte *pValue, ubyte4 valueLen)
{
    MSTATUS status = OK;

    if ( (NULL == pSa) || (NULL == pValue) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    switch(type)
    {
        case IkeInitiatorNonce:
            {
                status = DIGI_MALLOC((void **)&pSa->poNonce[_I], valueLen);
                if (OK != status)
                    goto exit;

                status = DIGI_MEMCPY((void *)pSa->poNonce[_I], (void *)pValue, valueLen);
                if (OK != status)
                    goto exit;

                pSa->wNonceLen[_I] = valueLen;
                break;
            }
        
        case IkeResponderNonce:
            {
                status = DIGI_MALLOC((void **)&pSa->poNonce[_R], valueLen);
                if (OK != status)
                    goto exit;

                status = DIGI_MEMCPY((void *)pSa->poNonce[_R], (void *)pValue, valueLen);
                if (OK != status)
                    goto exit;
                
                pSa->wNonceLen[_R] = valueLen;
                break;
            }
        
        case IkeInitiatorIndex:
            {
                if (IKE_COOKIE_SIZE != valueLen)
                {
                    status = ERR_BAD_LENGTH;
                    goto exit;
                }

                status = DIGI_MEMCPY((void *)pSa->poCky_I, (void *)pValue, valueLen);
                if (OK != status)
                    goto exit;
                
                break;
            }
        
        case IkeResponderIndex:
            {
                if (IKE_COOKIE_SIZE != valueLen)
                {
                    status = ERR_BAD_LENGTH;
                    goto exit;
                }

                status = DIGI_MEMCPY((void *)pSa->poCky_R, (void *)pValue, valueLen);
                if (OK != status)
                    goto exit;
                
                break;
            }
        
        case IkeSharedSecret:
            {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
                status = CRYPTO_INTERFACE_DH_allocateServerExt(g_pRandomContext, &pSa->p_dhContext, 14, NULL);
#else
                status = DH_allocateServer(g_pRandomContext, &pSa->p_dhContext, 14);
#endif
                if (OK != status)
                    goto exit;

                if (NULL != pSa->pDhSharedSecret)
                {
                    DIGI_FREE((void **)&pSa->pDhSharedSecret);
                }

                status = DIGI_MALLOC((void **)&pSa->pDhSharedSecret, valueLen);
                if (OK != status)
                    goto exit;

                status = DIGI_MEMCPY((void *)pSa->pDhSharedSecret, (void *)pValue, valueLen);
                if (OK != status)
                    goto exit;
                
                pSa->dhSharedSecretLen = valueLen;
                break;
            }

        default:
            status = ERR_INVALID_INPUT;
            goto exit;
    }

exit:
    return status;
}

MSTATUS getIKEValue(IKE_context ctx, ubyte type, ubyte **ppValue, ubyte4 *pValueLen)
{
    MSTATUS status = OK;
    IKESA pSa = NULL;
    ubyte *pTemp = NULL;
    ubyte4 tempLen = 0;

    if (NULL == ctx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pSa = ctx->pxSa;

    if (NULL == pSa)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    switch(type)
    {
        case IkeSKEYSEED:
            {
                if (NULL == g_pSKeySeed)
                {
                    status = ERR_INTERNAL_ERROR;
                    goto exit;
                }

                tempLen = g_sKeySeedLen;
                status = DIGI_MALLOC((void **)&pTemp, tempLen);
                if (OK != status)
                    goto exit;

                status = DIGI_MEMCPY((void *)pTemp, g_pSKeySeed, tempLen);
                if (OK != status)
                    goto exit;

                DIGI_MEMSET_FREE(&g_pSKeySeed, g_sKeySeedLen);
                g_sKeySeedLen = 0;

                *ppValue = pTemp;
                pTemp = NULL;
                *pValueLen = tempLen;
                break;
            }
        
        case IkeDKM:
            {
                tempLen = g_dkmLen;
                status = DIGI_MALLOC((void **)&pTemp, tempLen);
                if (OK != status)
                    goto exit;

                status = DIGI_MEMCPY((void *)pTemp, pSa->u.v2.SK, tempLen);
                if (OK != status)
                    goto exit;

                *ppValue = pTemp;
                pTemp = NULL;
                *pValueLen = tempLen;
                break;
            }
        
        case IkeDKMChildSa:
            {
                if (NULL == g_pChildDkm)
                {
                    status = ERR_INTERNAL_ERROR;
                    goto exit;
                }

                tempLen = g_childDkmLen;
                status = DIGI_MALLOC((void **)&pTemp, tempLen);
                if (OK != status)
                    goto exit;

                status = DIGI_MEMCPY((void *)pTemp, g_pChildDkm, tempLen);
                if (OK != status)
                    goto exit;

                DIGI_MEMSET_FREE(&g_pChildDkm, g_childDkmLen);

                *ppValue = pTemp;
                pTemp = NULL;
                *pValueLen = tempLen;
                break;
            }

        default:
            status = ERR_INVALID_INPUT;
            break;
    }

exit:
    return status;
}

#endif
