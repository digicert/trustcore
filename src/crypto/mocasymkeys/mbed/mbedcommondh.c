/*
 * mbedcommondh.c
 *
 * Operator for Software version of DH MocAsym Key.
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

#include "../../../crypto/mocasym.h"


#ifdef __ENABLE_DIGICERT_DH_MBED__

/*
 Macros for pre-defined Diffie-Hellman groups,
 analogous to those in dh.h
 */
#define DH_GROUP_TBD                    0
#define DH_GROUP_1                      1
#define DH_GROUP_2                      2
#define DH_GROUP_5                      5
#define DH_GROUP_14                    14
#define DH_GROUP_15                    15
#define DH_GROUP_16                    16
#define DH_GROUP_17                    17
#define DH_GROUP_18                    18
#define DH_GROUP_24                    24

#define DH_GROUP_FFDHE2048          0x100
#define DH_GROUP_FFDHE3072          0x101
#define DH_GROUP_FFDHE4096          0x102
#define DH_GROUP_FFDHE6144          0x103
#define DH_GROUP_FFDHE8192          0x104

#include "../../../crypto/mocasymkeys/mbed/mbedcommondh.h"
#include "../../../crypto/mocsymalgs/mbed/mbedrandom.h"

static const ubyte gpCommonG[] = {0x02}; /* common to all rfc 7919 and 3526 groups */

#ifndef __DISABLE_DIGICERT_DH_RFC7919_GROUPS__
static const ubyte gpGroupFFDHE2048[] = MBEDTLS_DHM_RFC7919_FFDHE2048_P_BIN;
static const ubyte gpGroupFFDHE3072[] = MBEDTLS_DHM_RFC7919_FFDHE3072_P_BIN;
static const ubyte gpGroupFFDHE4096[] = MBEDTLS_DHM_RFC7919_FFDHE4096_P_BIN;
static const ubyte gpGroupFFDHE6144[] = MBEDTLS_DHM_RFC7919_FFDHE6144_P_BIN;
static const ubyte gpGroupFFDHE8192[] = MBEDTLS_DHM_RFC7919_FFDHE8192_P_BIN;
#endif

#ifndef __DISABLE_DIGICERT_DH_MBED_GROUPS__
static const ubyte gpGroup14[] = MBEDTLS_DHM_RFC3526_MODP_2048_P_BIN;
static const ubyte gpGroup15[] = MBEDTLS_DHM_RFC3526_MODP_3072_P_BIN;
static const ubyte gpGroup16[] = MBEDTLS_DHM_RFC3526_MODP_4096_P_BIN;
#endif

#ifdef __ENABLE_DIGICERT_DH_MBED_DIGICERT_GROUPS__

#include "../../../cap/capasym_dh_params.h"

/* Mocana's pre-defined Diffie-Hellman groups */
static const ubyte gpGroup1[] = MOCANA_DH_group1;
static const ubyte gpGroup2[] = MOCANA_DH_group2;
static const ubyte gpGroup5[] = MOCANA_DH_group5;

static const ubyte gpGroup17[] = MOCANA_DH_group17;
static const ubyte gpGroup18[] = MOCANA_DH_group18;
static const ubyte gpGroup24[] = MOCANA_DH_group24;
static const ubyte gpGroup24_g[] = MOCANA_DH_group24_G;

#endif /* __ENABLE_DIGICERT_DH_MBED_DIGICERT_GROUPS__ */

/*---------------------------------------------------------------------------*/

static MSTATUS DhCopyMbedCtx(mbedtls_dhm_context *pDest, mbedtls_dhm_context *pSrc, byteBoolean copyPrivData)
{
    MSTATUS status = ERR_MBED_FAILURE;
    
    mbedtls_dhm_init(pDest); /* zeroes the context */

    if (mbedtls_mpi_copy(&(pDest->P), &(pSrc->P)))
        goto exit;
    
    if (mbedtls_mpi_copy(&(pDest->G), &(pSrc->G)))
        goto exit;
    
    if (copyPrivData)
    {
        if (mbedtls_mpi_copy(&(pDest->X), &(pSrc->X)))
            goto exit;
    }
    
    if (mbedtls_mpi_copy(&(pDest->GX), &(pSrc->GX)))
        goto exit;
    
    if (mbedtls_mpi_copy(&(pDest->GY), &(pSrc->GY)))
        goto exit;
    
    if (copyPrivData)
    {
        if (mbedtls_mpi_copy(&(pDest->K), &(pSrc->K)))
            goto exit;
        
        if (mbedtls_mpi_copy(&(pDest->RP), &(pSrc->RP)))
            goto exit;
        
        if (mbedtls_mpi_copy(&(pDest->Vi), &(pSrc->Vi)))
            goto exit;
        
        if (mbedtls_mpi_copy(&(pDest->Vf), &(pSrc->Vf)))
            goto exit;
        
        if (mbedtls_mpi_copy(&(pDest->pX), &(pSrc->pX)))
            goto exit;
    }
    
    pDest->len = pSrc->len;
    status = OK;

exit:
    
    if (OK != status)
    {   /* the following will free all ctx params */
        mbedtls_dhm_free(pDest);
    }
    
    return status;
}

/*---------------------------------------------------------------------------*/

static MSTATUS DhMbedSetPredefinedGroup(mbedtls_mpi *p, mbedtls_mpi *g, ubyte4 groupNum)
{
    MSTATUS status = ERR_MBED_FAILURE;
    
    switch (groupNum)
    {
            
#ifdef __ENABLE_DIGICERT_DH_MBED_DIGICERT_GROUPS__
        case DH_GROUP_1:
            
            if (mbedtls_mpi_read_binary(p, gpGroup1, sizeof(gpGroup1)))
                goto exit;
            
            if (mbedtls_mpi_read_binary(g, gpCommonG, sizeof(gpCommonG)))
                goto exit;
            
            status = OK;
            break;
 
        case DH_GROUP_2:
            
            if (mbedtls_mpi_read_binary(p, gpGroup2, sizeof(gpGroup2)))
                goto exit;
            
            if (mbedtls_mpi_read_binary(g, gpCommonG, sizeof(gpCommonG)))
                goto exit;
            
            status = OK;
            break;
            
        case DH_GROUP_5:
            
            if (mbedtls_mpi_read_binary(p, gpGroup5, sizeof(gpGroup5)))
                goto exit;
            
            if (mbedtls_mpi_read_binary(g, gpCommonG, sizeof(gpCommonG)))
                goto exit;
            
            status = OK;
            break;
            
#endif /* __ENABLE_DIGICERT_DH_MBED_DIGICERT_GROUPS__ */
#ifndef __DISABLE_DIGICERT_DH_MBED_GROUPS__
            
        case DH_GROUP_14:
            
            if (mbedtls_mpi_read_binary(p, gpGroup14, sizeof(gpGroup14)))
                goto exit;
            
            if (mbedtls_mpi_read_binary(g, gpCommonG, sizeof(gpCommonG)))
                goto exit;
            
            status = OK;
            break;
            
        case DH_GROUP_15:
        
            if (mbedtls_mpi_read_binary(p, gpGroup15, sizeof(gpGroup15)))
                goto exit;
            
            if (mbedtls_mpi_read_binary(g, gpCommonG, sizeof(gpCommonG)))
                goto exit;
            
            status = OK;
            break;
            
        case DH_GROUP_16:

            if (mbedtls_mpi_read_binary(p, gpGroup16, sizeof(gpGroup16)))
                goto exit;
            
            if (mbedtls_mpi_read_binary(g, gpCommonG, sizeof(gpCommonG)))
                goto exit;
            
            status = OK;
            break;
            
#endif /* __DISABLE_DIGICERT_DH_MBED_GROUPS__ */
#ifdef __ENABLE_DIGICERT_DH_MBED_DIGICERT_GROUPS__

        case DH_GROUP_17:
            
            if (mbedtls_mpi_read_binary(p, gpGroup17, sizeof(gpGroup17)))
                goto exit;
            
            if (mbedtls_mpi_read_binary(g, gpCommonG, sizeof(gpCommonG)))
                goto exit;
            
            status = OK;
            break;
            
        case DH_GROUP_18:
            
            if (mbedtls_mpi_read_binary(p, gpGroup18, sizeof(gpGroup18)))
                goto exit;
            
            if (mbedtls_mpi_read_binary(g, gpCommonG, sizeof(gpCommonG)))
                goto exit;
            
            status = OK;
            break;
            
        case DH_GROUP_24:
            
            if (mbedtls_mpi_read_binary(p, gpGroup24, sizeof(gpGroup24)))
                goto exit;
            
            if (mbedtls_mpi_read_binary(g, gpGroup24_g, sizeof(gpGroup24_g)))
                goto exit;
            
            status = OK;
            break;

#endif /* __ENABLE_DIGICERT_DH_MBED_DIGICERT_GROUPS__ */
#ifndef __DISABLE_DIGICERT_DH_RFC7919_GROUPS__
            
        case DH_GROUP_FFDHE2048:
            
            if (mbedtls_mpi_read_binary(p, gpGroupFFDHE2048, sizeof(gpGroupFFDHE2048)))
                goto exit;
            
            if (mbedtls_mpi_read_binary(g, gpCommonG, sizeof(gpCommonG)))
                goto exit;
            
            status = OK;
            break;
            
        case DH_GROUP_FFDHE3072:
            
            if (mbedtls_mpi_read_binary(p, gpGroupFFDHE3072, sizeof(gpGroupFFDHE3072)))
                goto exit;
            
            if (mbedtls_mpi_read_binary(g, gpCommonG, sizeof(gpCommonG)))
                goto exit;
            
            status = OK;
            break;
            
        case DH_GROUP_FFDHE4096:
            
            if (mbedtls_mpi_read_binary(p, gpGroupFFDHE4096, sizeof(gpGroupFFDHE4096)))
                goto exit;
            
            if (mbedtls_mpi_read_binary(g, gpCommonG, sizeof(gpCommonG)))
                goto exit;
            
            status = OK;
            break;
            
        case DH_GROUP_FFDHE6144:
            
            if (mbedtls_mpi_read_binary(p, gpGroupFFDHE6144, sizeof(gpGroupFFDHE6144)))
                goto exit;
            
            if (mbedtls_mpi_read_binary(g, gpCommonG, sizeof(gpCommonG)))
                goto exit;
            
            status = OK;
            break;
            
        case DH_GROUP_FFDHE8192:
            
            if (mbedtls_mpi_read_binary(p, gpGroupFFDHE8192, sizeof(gpGroupFFDHE8192)))
                goto exit;
            
            if (mbedtls_mpi_read_binary(g, gpCommonG, sizeof(gpCommonG)))
                goto exit;
            
            status = OK;
            break;
        
#endif /* __DISABLE_DIGICERT_DH_RFC7919_GROUPS__ */
        default:
            status = ERR_MBED_DH_UNSUPPORTED_GROUP;
    }
    
exit:
    
    return status;
}


/*---------------------------------------------------------------------------*/

MSTATUS DhMbedGenerateKeyPair(
    MocCtx pMocCtx,
    MKeyPairGenInfo *pInputInfo,
    MKeyPairGenResult *pOutputInfo
    )
{
    MSTATUS status = ERR_NULL_POINTER;

    mbedtls_dhm_context *pDhCtx = NULL;
    MDhKeyGenParams *pKeyGenParams = NULL;
    MocAsymKey pPub = NULL, pPri = NULL;
    ubyte *pPubBuffer = NULL;
    ubyte4 pubLen = 0;
    
    mbedtls_mpi p;
    mbedtls_mpi g;
    
    if ( NULL == pInputInfo->pRandInfo ||
         NULL == pInputInfo->pRandInfo->RngFun ||
         NULL == pInputInfo->pOperatorInfo ||
         NULL == pOutputInfo->ppPubKey ||
         NULL == pOutputInfo->ppPriKey)
        goto exit;

    mbedtls_mpi_init(&p);
    mbedtls_mpi_init(&g);

    pKeyGenParams = (MDhKeyGenParams *) (pInputInfo->pOperatorInfo);
    
    if (NULL == pKeyGenParams->pKeyTemplate)
        goto exit;
    
    if (DH_GROUP_TBD == pKeyGenParams->pKeyTemplate->groupNum)  /* custom group */
    {
        status = ERR_MBED_DH_GROUP_PARAMS_NOT_SET;
        if (NULL == pKeyGenParams->pKeyTemplate->pP || NULL == pKeyGenParams->pKeyTemplate->pG)
            goto exit;
        
        status = ERR_MBED_FAILURE;
        if (mbedtls_mpi_read_binary(&p, pKeyGenParams->pKeyTemplate->pP, pKeyGenParams->pKeyTemplate->pLen))
            goto exit;
        
        if (mbedtls_mpi_read_binary(&g, pKeyGenParams->pKeyTemplate->pG, pKeyGenParams->pKeyTemplate->gLen))
            goto exit;
    }
    else  /* pre-defined group */
    {
        status = DhMbedSetPredefinedGroup(&p, &g, pKeyGenParams->pKeyTemplate->groupNum);
        if (ERR_MBED_DH_UNSUPPORTED_GROUP == status)
            goto exit;
        else if (OK != status)
        {
            status = ERR_MBED_FAILURE;
            goto exit;
        }
    }

    status = DIGI_MALLOC((void **) &pDhCtx, sizeof(mbedtls_dhm_context));
    if (OK != status)
        goto exit;

    mbedtls_dhm_init(pDhCtx);

    status = ERR_MBED_FAILURE;
    if (mbedtls_dhm_set_group(pDhCtx, &p, &g))
        goto exit;

    /* allocate space for a throw away copy of the public key */
    pubLen = (ubyte4) pDhCtx->len;
    status = DIGI_MALLOC((void **) &pPubBuffer, pubLen);
    if (OK != status)
        goto exit;
    
    /* for pKeyGenParams->isServer TRUE or FALSE, either way we just gen a priv/pub key pair */
    status = ERR_MBED_FAILURE;
    if(mbedtls_dhm_make_public(pDhCtx, pKeyGenParams->pKeyTemplate->yLen, pPubBuffer, pDhCtx->len, MocMbedRngFun, pInputInfo->pRandInfo))
      goto exit;
    
    status = CRYPTO_createMocAsymKey(
        KeyOperatorDh, NULL, pMocCtx, MOC_ASYM_KEY_TYPE_PRIVATE,
        &pPri);
    if (OK != status)
        goto exit;

    pPri->pKeyData = pDhCtx;

    status = CRYPTO_getPubFromPri(pPri, &pPub, NULL);
    if (OK != status)
        goto exit;

    *(pOutputInfo->ppPubKey) = pPub;
    *(pOutputInfo->ppPriKey) = pPri;

    pPub = NULL;
    pPri = NULL;
    pDhCtx = NULL;
    
exit:

    mbedtls_mpi_free(&p);
    mbedtls_mpi_free(&g);

    if (NULL != pPubBuffer)
    {
        DIGI_MEMSET(pPubBuffer, 0x00, pubLen);
        DIGI_FREE((void **) &pPubBuffer);
        
    }

    if (NULL != pDhCtx)
    {
        mbedtls_dhm_free(pDhCtx);
        DIGI_FREE((void **) &pDhCtx);
    }

    return status;
}

/*---------------------------------------------------------------------------*/

MSTATUS DhMbedGetPubFromPri(
    MocAsymKey pMocAsymKey,
    MocAsymKey *ppRetKey
    )
{
    MSTATUS status;
    
    mbedtls_dhm_context *pDhCtx = NULL, *pDhPubCtx = NULL;
    MocAsymKey pNewPub = NULL;
    
    status = ERR_NULL_POINTER;
    if ( NULL == pMocAsymKey || NULL == ppRetKey || NULL == pMocAsymKey->pKeyData )
        goto exit;
    
    pDhCtx = (mbedtls_dhm_context *) pMocAsymKey->pKeyData;
    
    status = DIGI_MALLOC((void **) &pDhPubCtx, sizeof(mbedtls_dhm_context));
    if (OK != status)
        goto exit;
    
    /* copy the public data only from the ctx */
    status = DhCopyMbedCtx(pDhPubCtx, pDhCtx, FALSE);
    if (OK != status)
        goto exit;
    
    status = CRYPTO_createMocAsymKey(KeyOperatorDh, NULL, pMocAsymKey->pMocCtx,
                                     MOC_ASYM_KEY_TYPE_PUBLIC, &pNewPub);
    if (OK != status)
        goto exit;
    
    pNewPub->pKeyData = pDhPubCtx;
    pDhPubCtx = NULL;
    
    *ppRetKey = pNewPub;
    pNewPub = NULL;
    
exit:
    
    if (NULL != pNewPub)
        CRYPTO_freeMocAsymKey(&pNewPub, NULL);
    
    if (NULL != pDhPubCtx)
    {
        mbedtls_dhm_free(pDhPubCtx);
        DIGI_FREE((void **) &pDhPubCtx);
    }
    
    return status;
}

/*---------------------------------------------------------------------------*/

MSTATUS DhMbedCloneKey (
    MocAsymKey pMocAsymKey,
    MocAsymKey *ppNewKey
    )
{
    MSTATUS status = ERR_NULL_POINTER;

    mbedtls_dhm_context *pNewCtx = NULL;
    mbedtls_dhm_context *pInfo = NULL;
    MocAsymKey pNewKey = NULL;

    if (NULL == pMocAsymKey || NULL == ppNewKey || NULL == pMocAsymKey->pKeyData)
        goto exit;
    
    pInfo = (mbedtls_dhm_context *) pMocAsymKey->pKeyData;
    
    status = DIGI_MALLOC((void **) &pNewCtx, sizeof(mbedtls_dhm_context));
    if (OK != status)
        goto exit;
    
    /* copy the entire ctx */
    status = DhCopyMbedCtx(pNewCtx, pInfo, TRUE);
    if (OK != status)
        goto exit;

    status = CRYPTO_createMocAsymKey(
        KeyOperatorDh, NULL, pMocAsymKey->pMocCtx,
        MOC_ASYM_KEY_TYPE_UNKNOWN, &pNewKey); /* unknown is ok as we'll set localType below */
    if (OK != status)
        goto exit;

    pNewKey->pKeyData = pNewCtx;
    pNewKey->localType = pMocAsymKey->localType;
    pNewKey->pMocCtx = pMocAsymKey->pMocCtx;
    pNewKey->KeyOperator = pMocAsymKey->KeyOperator;
    *ppNewKey = pNewKey;
    pNewKey = NULL;
    pNewCtx = NULL;

exit:

    if (NULL != pNewCtx)
    {
        mbedtls_dhm_free(pNewCtx);
        DIGI_FREE((void **) &pNewCtx);
    }

    if (NULL != pNewKey)
        CRYPTO_freeMocAsymKey(&pNewKey, NULL);

    return status;
}

/*---------------------------------------------------------------------------*/

MSTATUS DhMbedSetKeyData (
    MocAsymKey pMocAsymKey,
    MDhKeyTemplate *pTemplate
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    mbedtls_dhm_context *pDhCtx = NULL;
    byteBoolean keyAllocated = FALSE;
    mbedtls_mpi p;
    mbedtls_mpi g;

    if ( NULL == pMocAsymKey || NULL == pTemplate )
        goto exit;
    
    mbedtls_mpi_init(&p);
    mbedtls_mpi_init(&g);
    
    pDhCtx = (mbedtls_dhm_context *) pMocAsymKey->pKeyData;
    
    if (NULL == pDhCtx)
    {
        status = DIGI_MALLOC((void **) &(pDhCtx), sizeof(mbedtls_dhm_context));
        if (OK != status)
            goto exit;
        
        keyAllocated = TRUE;
        mbedtls_dhm_init(pDhCtx);
    }

    status = ERR_MBED_FAILURE;
    pMocAsymKey->localType = MOC_LOCAL_KEY_DH_PUB_OPERATOR; /* default */
    
    if (DH_GROUP_TBD != pTemplate->groupNum)
    {
        /* Try to get P and G from the pre-defined groups */
        status = DhMbedSetPredefinedGroup(&p, &g, pTemplate->groupNum);
        if (ERR_MBED_DH_UNSUPPORTED_GROUP == status)
            goto exit;
        else if (OK != status)
        {
            status = ERR_MBED_FAILURE;
            goto exit;
        }
        
        if (mbedtls_dhm_set_group(pDhCtx, &p, &g))
        {
            status = ERR_MBED_FAILURE;
            goto exit;
        }
    }
    else
    {
        /* Set as many of the domain and key parameters as we can */
        if (NULL != pTemplate->pP && pTemplate->pLen)
        {
            if (mbedtls_mpi_read_binary(&(pDhCtx->P), pTemplate->pP, pTemplate->pLen))
                goto exit;
            
            pDhCtx->len = mbedtls_mpi_size(&(pDhCtx->P));
        }
        if (NULL != pTemplate->pG && pTemplate->gLen)
        {
            if (mbedtls_mpi_read_binary(&(pDhCtx->G), pTemplate->pG, pTemplate->gLen))
                goto exit;
        }
        
        /* Q is not used in mbed, we call the private key exponent Y, mbed calls it X */
        if (NULL != pTemplate->pY && pTemplate->yLen)
        {
            if (mbedtls_mpi_read_binary(&(pDhCtx->X), pTemplate->pY, pTemplate->yLen))
                goto exit;
            
            pMocAsymKey->localType = MOC_LOCAL_KEY_DH_PRI_OPERATOR; /* private key */
        }
        
        /* We call our public key F, mbed calls it GX */
        if (NULL != pTemplate->pF && pTemplate->fLen)
        {
            if (mbedtls_mpi_read_binary(&(pDhCtx->GX), pTemplate->pF, pTemplate->fLen))
                goto exit;
        }
    }
  
    pMocAsymKey->KeyOperator = KeyOperatorDh;
    pMocAsymKey->pKeyData = pDhCtx;
    pDhCtx = NULL;
    status = OK;
    
exit:
    
    mbedtls_mpi_free(&p);
    mbedtls_mpi_free(&g);
    
    if (NULL != pDhCtx)
    {
        mbedtls_dhm_free(pDhCtx);
        
        /*
         Only free pDhCtx if allocated this time (and not in a previous call).
         Make sure to set pMocAsymKey->pKeyData to NULL too.
         */
        if (keyAllocated)
        {
            DIGI_FREE((void **) &pDhCtx);
            pMocAsymKey->pKeyData = NULL;
        }
    }
    
    return status;
}

/*---------------------------------------------------------------------------*/

MSTATUS DhMbedGetKeyDataAlloc (
    MocAsymKey pMocAsymKey,
    MDhKeyTemplate *pTemplate,
    ubyte *pInputInfo
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte reqType;
    ubyte *pP = NULL;
    ubyte *pG = NULL;
    ubyte *pY = NULL;
    ubyte *pF = NULL;

    ubyte4 pLen = 0, gLen = 0, yLen = 0, fLen = 0;
    mbedtls_dhm_context *pDhCtx;

    if (NULL == pMocAsymKey || NULL == pMocAsymKey->pKeyData || NULL == pTemplate || NULL == pInputInfo)
        goto exit;

    pDhCtx = (mbedtls_dhm_context *) pMocAsymKey->pKeyData;
    reqType = *pInputInfo;
    
    /* Must have the proper key type flag defined */
    status = ERR_INVALID_ARG;
    if ( MOC_GET_PUBLIC_KEY_DATA != reqType && MOC_GET_PRIVATE_KEY_DATA != reqType )
        goto exit;
    
    /* Process P */
    pLen = (ubyte4) mbedtls_mpi_size(&(pDhCtx->P));
    if (pLen)
    {
        status = DIGI_MALLOC((void **)&pP, pLen);
        if (OK != status)
            goto exit;
        
        status = ERR_MBED_FAILURE;
        if (mbedtls_mpi_write_binary(&(pDhCtx->P), pP, pLen))
            goto exit;
    }
    
    /* Process G */
    gLen = (ubyte4) mbedtls_mpi_size(&(pDhCtx->G));
    if (gLen)
    {
        status = DIGI_MALLOC((void **)&pG, gLen);
        if (OK != status)
            goto exit;
        
        status = ERR_MBED_FAILURE;
        if (mbedtls_mpi_write_binary(&(pDhCtx->G), pG, gLen))
            goto exit;
    }
    
    /* mbed does not have Q */
    
    /* If private data was requested, process the private fields */
    if (MOC_GET_PRIVATE_KEY_DATA == reqType)
    {
        /* Process Y (which mbed calls X) */
        yLen = (ubyte4) mbedtls_mpi_size(&(pDhCtx->X));
        if (yLen)
        {
            status = DIGI_MALLOC((void **)&pY, yLen);
            if (OK != status)
                goto exit;
            
            status = ERR_MBED_FAILURE;
            if (mbedtls_mpi_write_binary(&(pDhCtx->X), pY, yLen))
                goto exit;
        
        }
    }
    
    /* Process F (which mbed calls GX) */
    fLen = (ubyte4) mbedtls_mpi_size(&(pDhCtx->GX));
    if (fLen)
    {
        status = DIGI_MALLOC((void **)&pF, fLen);
        if (OK != status)
            goto exit;
        
        status = ERR_MBED_FAILURE;
        if (mbedtls_mpi_write_binary(&(pDhCtx->GX), pF, fLen))
            goto exit;
    }
  
    /* no errors, set the template */
    pTemplate->pP = pP;
    pTemplate->pLen = pLen;
    pTemplate->pG = pG;
    pTemplate->gLen = gLen;
    pTemplate->pQ = NULL;    /* mbed does not have Q */
    pTemplate->qLen = 0;
    pTemplate->pY = pY;
    pTemplate->yLen = yLen;
    pTemplate->pF = pF;
    pTemplate->fLen = fLen;
    pP = NULL;
    pG = NULL;
    pY = NULL;
    pF = NULL;

    status = OK;
    
exit:
    
    if (NULL != pP)
    {
        DIGI_MEMSET(pP, 0x00, pLen);
        DIGI_FREE((void **)&pP);
    }
    if (NULL != pG)
    {
        DIGI_MEMSET(pG, 0x00, gLen);
        DIGI_FREE((void **)&pG);
    }
    if (NULL != pY)
    {
        DIGI_MEMSET(pY, 0x00, yLen);
        DIGI_FREE((void **)&pY);
    }
    if (NULL != pF)
    {
        DIGI_MEMSET(pF, 0x00, fLen);
        DIGI_FREE((void **)&pF);
    }
    
    return status;
}

/*---------------------------------------------------------------------------*/

MSTATUS DhMbedReturnPubValAlloc (
    MocAsymKey pMocAsymKey,
    MKeyOperatorDataReturn *pPubVal
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    mbedtls_dhm_context *pDhCtx;
    ubyte *pF = NULL;
    ubyte4 fLen;
    
    if (NULL == pMocAsymKey || NULL == pPubVal || NULL == pMocAsymKey->pKeyData)
        goto exit;
    
    pDhCtx = (mbedtls_dhm_context *) pMocAsymKey->pKeyData;
    
    fLen = (ubyte4) mbedtls_mpi_size(&(pDhCtx->GX));
    
    status = ERR_MBED_DH_NO_PUBLIC_KEY;
    if (!fLen)
        goto exit;

    status = DIGI_MALLOC((void **) &pF, fLen);
    if (OK != status)
        goto exit;
    
    status = ERR_MBED_FAILURE;
    if (mbedtls_mpi_write_binary(&(pDhCtx->GX), pF, fLen))
        goto exit;

    *(pPubVal->ppData) = pF;
    *(pPubVal->pLength) = fLen;
    
    pF = NULL;
    
    status = OK;
    
exit:
    
    if (NULL != pF)
    {
        DIGI_MEMSET(pF, 0x00, fLen);
        DIGI_FREE((void **) &pF);
    }
    
    return status;
}

/*---------------------------------------------------------------------------*/

MSTATUS DhMbedComputeSharedSecret (
    MocAsymKey pMocAsymKey,
    MKeyOperatorData *pPubVal,
    MKeyOperatorBuffer *pSharedSecret
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    mbedtls_dhm_context *pDhCtx;
    ubyte4 secretLen;
    size_t outLen = 0;
    
    if (NULL == pMocAsymKey || NULL == pPubVal || NULL == pSharedSecret || NULL == pMocAsymKey->pKeyData)
        goto exit;
    
    pDhCtx = (mbedtls_dhm_context *) pMocAsymKey->pKeyData;

    secretLen = (ubyte4) pDhCtx->len;
    
    /* check if the buffer was allocated with enough space */
    status = ERR_BUFFER_TOO_SMALL;
    if (pSharedSecret->bufferSize < secretLen)
    {
        *(pSharedSecret->pLength) = (ubyte4) secretLen; /* set the space needed for the user */
        goto exit;
    }

    *(pSharedSecret->pLength) = 0; /* set to 0 in case of error */
    
    status = ERR_MBED_FAILURE;
    if (mbedtls_dhm_read_public(pDhCtx, pPubVal->pData, pPubVal->length))
        goto exit;
    
    if (NULL != pPubVal->pAdditionalOpInfo) /* then call with the RNG for blinding purposes */
    {
        if (mbedtls_dhm_calc_secret(pDhCtx, pSharedSecret->pBuffer, secretLen, &outLen, MocMbedRngFun, pPubVal->pAdditionalOpInfo))
            goto exit;
    }
    else
    {
        if (mbedtls_dhm_calc_secret(pDhCtx, pSharedSecret->pBuffer, secretLen, &outLen, NULL, NULL))
            goto exit;
    }
    *(pSharedSecret->pLength) = (ubyte4) outLen;
    
    status = OK;
    
exit:
    
    return status;
}

/*---------------------------------------------------------------------------*/

MSTATUS DhMbedFreeKey (
    MocAsymKey pMocAsymKey
    )
{
    MSTATUS status = OK;
    
    if ( NULL == pMocAsymKey)
        return ERR_NULL_POINTER;
    
    if (NULL != pMocAsymKey->pKeyData)
    {
        mbedtls_dhm_free((mbedtls_dhm_context *) pMocAsymKey->pKeyData);
        status = DIGI_FREE( &(pMocAsymKey->pKeyData) );
    }
    
    return status;
}
#endif
