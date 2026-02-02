/*
 * dh.c
 *
 * Diffie-Hellman Key Exchange
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

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_DH_INTERNAL__

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#if ((!defined(__DIFFIE_HELLMAN_HARDWARE__)) && (!defined(__DISABLE_DIGICERT_DIFFIE_HELLMAN__)))

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mstdlib.h"
#include "../common/random.h"
#include "../common/vlong.h"
#include "../common/vlong_priv.h"
#include "../common/memory_debug.h"
#include "../crypto/dh.h"

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
#include "../crypto/fips.h"
#include "../crypto/fips_priv.h"
#endif

/*------------------------------------------------------------------*/

#include "../cap/capasym_dh_params.h"

#ifndef __ENABLE_DIGICERT_FIPS_MODULE__
/* 768 bit prime */
static const ubyte gpGroup1[] = MOCANA_DH_group1;

/* 1024 bit prime */
static const ubyte gpGroup2[] = MOCANA_DH_group2;

/* 1536 bit prime */
static const ubyte gpGroup5[] = MOCANA_DH_group5;
#endif

/* 2048 bit prime */
static const ubyte gpGroup14[] = MOCANA_DH_group14;

/* 3072 bit prime */
static const ubyte gpGroup15[] = MOCANA_DH_group15;

/* 4096 bit prime */
static const ubyte gpGroup16[] = MOCANA_DH_group16;

/* 6144 bit prime */
static const ubyte gpGroup17[] = MOCANA_DH_group17;

/* 8192 bit prime */
static const ubyte gpGroup18[] = MOCANA_DH_group18;

#ifndef __ENABLE_DIGICERT_FIPS_MODULE__
/* 2048 bit prime */
static const ubyte gpGroup24[] = MOCANA_DH_group24;

/* 2048 bit generator */
static const ubyte gpGroup24_g[] = MOCANA_DH_group24_G;
#endif

#ifndef __DISABLE_DIGICERT_DH_RFC7919_GROUPS__
/* ffdhe2048 */
static const ubyte gpGroupFFDHE2048[] = MOCANA_DH_FFDHE2048;

/* ffdhe3072 */
static const ubyte gpGroupFFDHE3072[] = MOCANA_DH_FFDHE3072;

/* ffdhe4096 */
static const ubyte gpGroupFFDHE4096[] = MOCANA_DH_FFDHE4096;

/* ffdhe6144 */
static const ubyte gpGroupFFDHE6144[] = MOCANA_DH_FFDHE6144;

/* ffdhe8192 */
static const ubyte gpGroupFFDHE8192[] = MOCANA_DH_FFDHE8192;
#endif

/*------------------------------------------------------------------*/

/* NIST.SP.800-56Ar3 Table 25 Appendix D indicates the security strength
 * that should be used for the RFC 3526 safe prime groups, ie groups 14-18.
 * The keyLength in bits N must be 2s <= N <= len(Q) where s is the
 * maximum allowed security strength. We set N to 2s and by definition
 * of safe prime it is a given that N <= len(Q).
 */
static ubyte4 groupToKeyLength(ubyte4 groupNum)
{
    ubyte4 keyLength = 0; /* in bytes */
    
    switch (groupNum)
    {
        case DH_GROUP_14:
        case DH_GROUP_FFDHE2048:
            
            /* keyLength is the same for each pair of groups */
            keyLength = MOCANA_DH_group14_keyLen; /* 112 bit s, 224 bit key */
            break;
            
        case DH_GROUP_15:
        case DH_GROUP_FFDHE3072:
            
            keyLength = MOCANA_DH_group15_keyLen; /* 128 bit s, 256 bit key */
            break;
            
        case DH_GROUP_16:
        case DH_GROUP_FFDHE4096:
            
            keyLength = MOCANA_DH_group16_keyLen; /* 152 bit s, 304 bit key */
            break;
            
        case DH_GROUP_17:
        case DH_GROUP_FFDHE6144:
            
            keyLength = MOCANA_DH_group17_keyLen; /* 176 bit s, 352 bit key */
            break;
            
        case DH_GROUP_18:
        case DH_GROUP_FFDHE8192:
            
            keyLength = MOCANA_DH_group18_keyLen; /* 200 bit s, 400 bit key */
            break;
            
        default:
            keyLength = MOCANA_DH_NUM_Y_BYTES;
            break;
    }
    
    return keyLength;
}

/*------------------------------------------------------------------*/

static MSTATUS safeGroupMatch(const vlong *pP, const vlong *pG, ubyte4 *pMnLen, ubyte4 *pMaxLen, vlong **ppVlongQueue)
{
    MSTATUS status = ERR_FALSE;
    sbyte4 compare = 0;
    ubyte4 L = VLONG_bitLength(pP); /* Get the actual bit length of the prime P */
    vlong *pCandidate = NULL;
    
    /* internal method, NULL checks not necc */
    /* The generator should be 2 for all the approved safe groups */
    compare = VLONG_compareUnsigned(pG, 2);
    if (compare)
        goto exit;
    
    switch (L)
    {
        case 2048:
            
            status = VLONG_vlongFromByteString(gpGroup14, sizeof(gpGroup14), &pCandidate, ppVlongQueue);
            if (OK != status)
                goto exit;
            
            compare = VLONG_compareSignedVlongs(pP, pCandidate);
            if (compare)
            {
#if !defined(__DISABLE_DIGICERT_DH_RFC7919_GROUPS__)
                status = VLONG_freeVlong(&pCandidate, ppVlongQueue);
                if (OK != status)
                    goto exit;
                
                status = VLONG_vlongFromByteString(gpGroupFFDHE2048, sizeof(gpGroupFFDHE2048), &pCandidate, ppVlongQueue);
                if (OK != status)
                    goto exit;
                
                status = ERR_FALSE;
                compare = VLONG_compareSignedVlongs(pP, pCandidate);
                if (compare)
                    goto exit;
#else
                status = ERR_FALSE;
                goto exit;
#endif
            }
            
            /* Either pair of groups has the same min and max keyLengths */
            *pMnLen = MOCANA_DH_group14_keyLen;   /* 112 bit s, 224 bit key */
            *pMaxLen = 255; /* 2047 bits rounded down */
            break;
            
        case 3072:
            
            status = VLONG_vlongFromByteString(gpGroup15, sizeof(gpGroup15), &pCandidate, ppVlongQueue);
            if (OK != status)
                goto exit;
            
            compare = VLONG_compareSignedVlongs(pP, pCandidate);
            if (compare)
            {
#if !defined(__DISABLE_DIGICERT_DH_RFC7919_GROUPS__)
                status = VLONG_freeVlong(&pCandidate, ppVlongQueue);
                if (OK != status)
                    goto exit;
                
                status = VLONG_vlongFromByteString(gpGroupFFDHE3072, sizeof(gpGroupFFDHE3072), &pCandidate, ppVlongQueue);
                if (OK != status)
                    goto exit;
                
                status = ERR_FALSE;
                compare = VLONG_compareSignedVlongs(pP, pCandidate);
                if (compare)
                    goto exit;
#else
                status = ERR_FALSE;
                goto exit;
#endif
            }
            
            /* Either pair of groups has the same min and max keyLengths */
            *pMnLen = MOCANA_DH_group15_keyLen;   /* 128 bit s, 256 bit key */
            *pMaxLen = 383; /* 3071 bits rounded down */
            break;
            
        case 4096:
            
            status = VLONG_vlongFromByteString(gpGroup16, sizeof(gpGroup16), &pCandidate, ppVlongQueue);
            if (OK != status)
                goto exit;
            
            compare = VLONG_compareSignedVlongs(pP, pCandidate);
            if (compare)
            {
#if !defined(__DISABLE_DIGICERT_DH_RFC7919_GROUPS__)
                status = VLONG_freeVlong(&pCandidate, ppVlongQueue);
                if (OK != status)
                    goto exit;
                
                status = VLONG_vlongFromByteString(gpGroupFFDHE4096, sizeof(gpGroupFFDHE4096), &pCandidate, ppVlongQueue);
                if (OK != status)
                    goto exit;
                
                status = ERR_FALSE;
                compare = VLONG_compareSignedVlongs(pP, pCandidate);
                if (compare)
                    goto exit;
#else
                status = ERR_FALSE;
                goto exit;
#endif
            }
            
            /* Either pair of groups has the same min and max keyLengths */
            *pMnLen = MOCANA_DH_group16_keyLen;   /* 152 bit s, 304 bit key */
            *pMaxLen = 511; /* 4097 bits rounded down */
            break;
            
        case 6144:
            
            status = VLONG_vlongFromByteString(gpGroup17, sizeof(gpGroup17), &pCandidate, ppVlongQueue);
            if (OK != status)
                goto exit;
            
            compare = VLONG_compareSignedVlongs(pP, pCandidate);
            if (compare)
            {
#if !defined(__DISABLE_DIGICERT_DH_RFC7919_GROUPS__)
                status = VLONG_freeVlong(&pCandidate, ppVlongQueue);
                if (OK != status)
                    goto exit;
                
                status = VLONG_vlongFromByteString(gpGroupFFDHE6144, sizeof(gpGroupFFDHE6144), &pCandidate, ppVlongQueue);
                if (OK != status)
                    goto exit;
                
                status = ERR_FALSE;
                compare = VLONG_compareSignedVlongs(pP, pCandidate);
                if (compare)
                    goto exit;
#else
                status = ERR_FALSE;
                goto exit;
#endif
            }
            
            /* Either pair of groups has the same min and max keyLengths */
            *pMnLen = MOCANA_DH_group17_keyLen;   /* 176 bit s, 352 bit key */
            *pMaxLen = 767; /* 6143 bits rounded down */
            break;
            
        case 8192:
            
            status = VLONG_vlongFromByteString(gpGroup18, sizeof(gpGroup18), &pCandidate, ppVlongQueue);
            if (OK != status)
                goto exit;
            
            compare = VLONG_compareSignedVlongs(pP, pCandidate);
            if (compare)
            {
#if !defined(__DISABLE_DIGICERT_DH_RFC7919_GROUPS__)
                status = VLONG_freeVlong(&pCandidate, ppVlongQueue);
                if (OK != status)
                    goto exit;
                
                status = VLONG_vlongFromByteString(gpGroupFFDHE8192, sizeof(gpGroupFFDHE8192), &pCandidate, ppVlongQueue);
                if (OK != status)
                    goto exit;
                
                status = ERR_FALSE;
                compare = VLONG_compareSignedVlongs(pP, pCandidate);
                if (compare)
                    goto exit;
#else
                status = ERR_FALSE;
                goto exit;
#endif
            }
            
            /* Either pair of groups has the same min and max keyLengths */
            *pMnLen = MOCANA_DH_group18_keyLen;    /* 200 bit s, 400 bit key */
            *pMaxLen = 1023; /* 8191 bits rounded down */
            break;
            
        default:
            goto exit;
    }
    
    status = OK;
    
exit:
    
    VLONG_freeVlong(&pCandidate, ppVlongQueue); /* purposely ignore return value */
    
    return status;
}

/*------------------------------------------------------------------*/

static MSTATUS DH_generateY(randomContext *pRandomContext, vlong *pQ, ubyte4 lengthY, vlong** ppY, vlong** ppVlongQueue)
{
    ubyte* yBuf = 0;
    MSTATUS status = OK;
    vlong *pMax = NULL;
    vlong *pNewY = NULL;
    
    /* internal method, Null checks not necc */
    if (NULL == (yBuf = (ubyte*) MALLOC(lengthY)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    
    /* We follow NIST.SP.800-56Ar3 5.6.1.1.4 Key-Pair Generation by Testing Candidates
     
     Here we have lengthY is in bytes so that N is (8 * lengthY).
     The calling method has either 1) already validated that
     
     2s <= N <= len(Q) where s is the maximum securiy strength allowed by P and Q
     
     OR, for the safe prime groups, it has fixed lengthY so that these
     inequalities implicitly hold.
     
     We just need to start with Step 3, Generate N random bits, but get the
     value M ready for Step 5 and 6 where M = min(2^N, Q).
     
     For safe prime groups, Q = (P-1)/2 will not be provided to this method and
     N is already validated so that 2^N < Q.
     */
    if ( NULL == pQ || (lengthY * 8) < VLONG_bitLength(pQ) )
    {
        /* Set M to 2^N */
        status = VLONG_allocVlong(&pMax, ppVlongQueue);
        if (OK != status)
            goto exit;
        
        /* make it have at least enough words for 2^N */
        status = VLONG_reallocVlong(pMax, (lengthY/sizeof(vlong_unit)) + 1);
        if (OK != status)
            goto exit;
        
        /* set the Nth bit */
        status = VLONG_setVlongBit(pMax, lengthY * 8);
        if (OK != status)
            goto exit;
    }
    else  /* Q < 2^N, set M to Q   */
    {
        status = VLONG_makeVlongFromVlong(pQ, &pMax, ppVlongQueue);
        if (OK != status)
            goto exit;
    }
    
    /* Now make pMax = M - 2 */
    
    status = VLONG_decrement(pMax, ppVlongQueue);
    if (OK != status)
        goto exit;
    
    status = VLONG_decrement(pMax, ppVlongQueue);
    if (OK != status)
        goto exit;
    
    do {
        
        if (NULL != pNewY)
        {
            status = VLONG_freeVlong(&pNewY, ppVlongQueue);
            if (OK != status)
                goto exit;
        }
        
        /* Step 3 */
        if (OK > (status = RANDOM_numberGenerator(pRandomContext, yBuf, lengthY)))
            goto exit;
        
        if (OK > (status = VLONG_vlongFromByteString(yBuf, lengthY, &pNewY, ppVlongQueue)))
            goto exit;
    }
    while( 0 <= VLONG_compareSignedVlongs(pNewY, pMax) );  /* step 6 */
    
    /* Step 7, add 1 */
    status = VLONG_increment(pNewY, ppVlongQueue);
    if (OK != status)
        goto exit;
    
    DEBUG_RELABEL_MEMORY(*ppY);
    
    *ppY = pNewY; pNewY = NULL;
    
exit:
    
    VLONG_freeVlong(&pMax, ppVlongQueue); /* purposely ignore return codes */
    VLONG_freeVlong(&pNewY, ppVlongQueue);
    
    if (yBuf)
    {
        DIGI_MEMSET(yBuf, 0x00, lengthY);
        DIGI_FREE((void **) &yBuf);
    }
    
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
DH_getP(ubyte4 groupNum, vlong **ppRetP)
{
    MSTATUS status;
    const ubyte* bytes;
    sbyte4 len;

    if (OK > ( status = DH_getPByteString(groupNum, &bytes, &len)))
    {
        return status;
        }
    return VLONG_vlongFromByteString(bytes, len, ppRetP, 0);
    }


/*------------------------------------------------------------------*/

extern MSTATUS
DH_getPByteString(ubyte4 groupNum, const ubyte** ppBytes, sbyte4* pLen)
    {
    MSTATUS status = OK;

    switch (groupNum)
        {
#ifndef __ENABLE_DIGICERT_FIPS_MODULE__
        case DH_GROUP_1:
            *ppBytes = gpGroup1;
            *pLen = sizeof(gpGroup1);
            break;

        case DH_GROUP_2:
            *ppBytes = gpGroup2;
            *pLen = sizeof(gpGroup2);
            break;

        case DH_GROUP_5:
            *ppBytes = gpGroup5;
            *pLen = sizeof(gpGroup5);
            break;
#endif
        case DH_GROUP_14:
            *ppBytes = gpGroup14;
            *pLen = sizeof(gpGroup14);
            break;

        case DH_GROUP_15:
            *ppBytes = gpGroup15;
            *pLen = sizeof(gpGroup15);
            break;

       case DH_GROUP_16:
            *ppBytes = gpGroup16;
            *pLen = sizeof(gpGroup16);
            break;

        case DH_GROUP_17:
            *ppBytes = gpGroup17;
            *pLen = sizeof(gpGroup17);
            break;

        case DH_GROUP_18:
            *ppBytes = gpGroup18;
            *pLen = sizeof(gpGroup18);
            break;
#ifndef __ENABLE_DIGICERT_FIPS_MODULE__
        case DH_GROUP_24:
            *ppBytes = gpGroup24;
            *pLen = sizeof(gpGroup24);
            break;
#endif
#ifndef __DISABLE_DIGICERT_DH_RFC7919_GROUPS__
            
        case DH_GROUP_FFDHE2048:
            *ppBytes = gpGroupFFDHE2048;
            *pLen = sizeof(gpGroupFFDHE2048);
            break;
                
        case DH_GROUP_FFDHE3072:
            *ppBytes = gpGroupFFDHE3072;
            *pLen = sizeof(gpGroupFFDHE3072);
            break;
                
        case DH_GROUP_FFDHE4096:
            *ppBytes = gpGroupFFDHE4096;
            *pLen = sizeof(gpGroupFFDHE4096);
            break;
                
        case DH_GROUP_FFDHE6144:
            *ppBytes = gpGroupFFDHE6144;
            *pLen = sizeof(gpGroupFFDHE6144);
            break;
                
        case DH_GROUP_FFDHE8192:
            *ppBytes = gpGroupFFDHE8192;
            *pLen = sizeof(gpGroupFFDHE8192);
            break;
#endif
                
        default:
        status = ERR_CRYPTO_DH_UNSUPPORTED_GROUP;
        goto exit;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
DH_getG(ubyte4 groupNum, vlong **ppRetG)
{
    MSTATUS status;

#ifndef __ENABLE_DIGICERT_FIPS_MODULE__
    if (DH_GROUP_24 == groupNum)
    {
        status = VLONG_vlongFromByteString(gpGroup24_g, sizeof(gpGroup24_g), ppRetG, 0);
    }
    else
#endif
    {
        status = VLONG_makeVlongFromUnsignedValue(MOCANA_DH_common_G, ppRetG, 0);
    }

    return status;
}


/*------------------------------------------------------------------*/

MSTATUS DH_allocateServer(MOC_DH(hwAccelDescr hwAccelCtx) randomContext *pRandomContext, diffieHellmanContext **pp_dhContext, ubyte4 groupNum)
{
    return DH_allocateServerExt(MOC_DH(hwAccelCtx) pRandomContext, pp_dhContext, groupNum, NULL);
}

MSTATUS DH_allocateServerExt(MOC_DH(hwAccelDescr hwAccelCtx) randomContext *pRandomContext, diffieHellmanContext **pp_dhContext, ubyte4 groupNum, void *pExtCtx)
{
    FIPS_LOG_DECL_SESSION;
    vlong*  pMpintY     = NULL;
    vlong*  pMpintF     = NULL;
    vlong*  pVlongQueue = NULL;
    MSTATUS status = ERR_NULL_POINTER;
    
    MOC_UNUSED(pExtCtx);

    if (NULL == pp_dhContext)
        return ERR_NULL_POINTER;
    
    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_DH); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_DH,groupNum);

    if (NULL == (*pp_dhContext = (diffieHellmanContext*) MALLOC(sizeof(diffieHellmanContext))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    else
        DIGI_MEMSET((ubyte *)(*pp_dhContext), 0x00, sizeof(diffieHellmanContext));

    /* Compute G (Generator) */
    if (OK > (status = DH_getG(groupNum, &COMPUTED_VLONG_G(*pp_dhContext))))
        goto exit;

    DEBUG_RELABEL_MEMORY(COMPUTED_VLONG_G(*pp_dhContext));

    /* Compute P */
    if (OK > (status = DH_getP(groupNum, &COMPUTED_VLONG_P(*pp_dhContext))))
        goto exit;

    if (OK > (status = DH_generateY(pRandomContext, NULL, groupToKeyLength(groupNum), &pMpintY, NULL)))
        goto exit;

    /* Compute F */
    if (OK > (status = VLONG_modexp(MOC_MOD(hwAccelCtx) COMPUTED_VLONG_G(*pp_dhContext), pMpintY, COMPUTED_VLONG_P(*pp_dhContext), &pMpintF, &pVlongQueue)))
        goto exit;

    /* save vlong variables here */
    COMPUTED_VLONG_Y(*pp_dhContext) = pMpintY; pMpintY = NULL;
    COMPUTED_VLONG_F(*pp_dhContext) = pMpintF; pMpintF = NULL;

exit:
    
    /* free in case of an error after allocation, ignore ERR_NULL_POINTER return if it was never allocated */
    if (OK != status)
        DH_freeDhContext(pp_dhContext, &pVlongQueue);
        
    VLONG_freeVlong(&pMpintY, 0);
    VLONG_freeVlong(&pMpintF, 0);
    VLONG_freeVlongQueue(&pVlongQueue);

    FIPS_LOG_END_ALG(FIPS_ALGO_DH,groupNum);
    return status;
}


/* The original DH_allocateClient method now with a flag for also adding the group generator to the context */
static MSTATUS DH_allocateClient_internal(MOC_DH(hwAccelDescr hwAccelCtx) randomContext *pRandomContext,
                                          diffieHellmanContext **pp_dhContext, ubyte4 groupNum, byteBoolean isAddG, void *pExtCtx)
{
    FIPS_LOG_DECL_SESSION;
    vlong*  pMpintY    = NULL;
    MSTATUS status = ERR_NULL_POINTER;

    MOC_UNUSED(pExtCtx);
    
    if (NULL == pp_dhContext)
        return ERR_NULL_POINTER;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_DH); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_DH,groupNum);
    
    if (NULL == (*pp_dhContext = (diffieHellmanContext*) MALLOC(sizeof(diffieHellmanContext))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    
    DIGI_MEMSET((ubyte *)(*pp_dhContext), 0x00, sizeof(diffieHellmanContext));
    
    /* Compute Y */
    if (OK > (status = DH_generateY(pRandomContext, NULL, groupToKeyLength(groupNum), &pMpintY, NULL)))
        goto exit;
    
    /* Get P and possibly G */
    if (DH_GROUP_TBD != groupNum)
    {
        if (OK > (status = DH_getP(groupNum, &COMPUTED_VLONG_P(*pp_dhContext))))
            goto exit;
        
        if (isAddG)
        {
            if (OK > (status = DH_getG(groupNum, &COMPUTED_VLONG_G(*pp_dhContext))))
                goto exit;
        }
    }
    
    /* save vlong variables here */
    COMPUTED_VLONG_Y(*pp_dhContext) = pMpintY; pMpintY = NULL;
    
exit:
    
    /* free in case of an error after allocation, ignore ERR_NULL_POINTER return if it was never allocated */
    if (OK != status)
        DH_freeDhContext(pp_dhContext, NULL);
    
    VLONG_freeVlong(&pMpintY, NULL);

    FIPS_LOG_END_ALG(FIPS_ALGO_DH,groupNum);
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
DH_allocateClient(MOC_DH(hwAccelDescr hwAccelCtx) randomContext *pRandomContext, diffieHellmanContext **pp_dhContext, ubyte4 groupNum)
{
    return DH_allocateClient_internal(MOC_DH(hwAccelCtx) pRandomContext, pp_dhContext, groupNum, FALSE, NULL);
}

/* new version of the same method as above except the group generator will also be added to the context */
MSTATUS DH_allocateClientAuxExt(MOC_DH(hwAccelDescr hwAccelCtx) randomContext *pRandomContext, diffieHellmanContext **pp_dhContext, ubyte4 groupNum, void *pExtCtx)
{
    return DH_allocateClient_internal(MOC_DH(hwAccelCtx) pRandomContext, pp_dhContext, groupNum, TRUE, pExtCtx);
}

MSTATUS DH_allocateClientAux(MOC_DH(hwAccelDescr hwAccelCtx) randomContext *pRandomContext, diffieHellmanContext **pp_dhContext, ubyte4 groupNum)
{
    return DH_allocateClient_internal(MOC_DH(hwAccelCtx) pRandomContext, pp_dhContext, groupNum, TRUE, NULL);
}

/*------------------------------------------------------------------*/

MSTATUS DH_allocate(diffieHellmanContext **pp_dhContext)
{
    return DH_allocateExt(pp_dhContext, NULL);
}

MSTATUS DH_allocateExt(diffieHellmanContext **pp_dhContext, void *pExtCtx)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pp_dhContext)
        goto exit;
    
    MOC_UNUSED(pExtCtx);

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_DH); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_DH,0);

   if (NULL == (*pp_dhContext = (diffieHellmanContext*) MALLOC(sizeof(diffieHellmanContext))))
   {
       status = ERR_MEM_ALLOC_FAIL;
       goto exit;
   }

   status = DIGI_MEMSET((ubyte *)(*pp_dhContext), 0x00, sizeof(diffieHellmanContext));

exit:
   /* DIGI_MEMSET will always set status back to OK, no need to free on error */
    
   FIPS_LOG_END_ALG(FIPS_ALGO_DH,0);
   return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
DH_setPG(MOC_DH(hwAccelDescr hwAccelCtx) randomContext *pRandomContext, ubyte4 lengthY, diffieHellmanContext *p_dhContext, const vlong *P, const vlong *G)
{
    FIPS_LOG_DECL_SESSION;
    vlong*  pMpintY     = NULL;
    vlong*  pMpintF     = NULL;
    vlong*  pVlongQueue = NULL;
    MSTATUS status = ERR_NULL_POINTER;

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
    ubyte4 lenYmin = 0;
    ubyte4 lenYmax = 0;
#endif /* __ENABLE_DIGICERT_FIPS_MODULE__ */

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_DH); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_DH,0);

    if (NULL == pRandomContext || NULL == p_dhContext || NULL == P || NULL == G)
        goto exit;
    
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
    /* We need to validate length Y is large enough. First check if P, G are from a safe prime group */
    status = safeGroupMatch(P, G, &lenYmin, &lenYmax, NULL);
    if (OK == status)
    {
        if (lengthY < lenYmin || lengthY > lenYmax)
        {
            status = ERR_DH_INVALID_KEYLENGTH;
            goto exit;
        }
    }
    else  /* it is not a safe prime group, it will have been validated to have been a FIPS 186-4 group. */
    {
        /* if Q is given then it should be 224 or 256 bits only, validate that lengthY is also the same number */
        if( NULL != COMPUTED_VLONG_Q(p_dhContext) )
        {
            if ( lengthY * 8 !=  VLONG_bitLength(COMPUTED_VLONG_Q(p_dhContext)) )
            {
                status = ERR_DH_INVALID_KEYLENGTH;
                goto exit;
            }
        }
        else /* Q is not given but should still be either 224 or 256 bits */
        {
            if (lengthY != 28 && lengthY != 32)
            {
                status = ERR_DH_INVALID_KEYLENGTH;
                goto exit;
            }
        }
    }
#endif
    
    /* Set P */
    if (OK > (status = VLONG_makeVlongFromVlong(P, &COMPUTED_VLONG_P(p_dhContext), &pVlongQueue)))
        goto exit;

    DEBUG_RELABEL_MEMORY(COMPUTED_VLONG_P(p_dhContext));

    /* Set G (Generator) */
    if (OK > (status = VLONG_makeVlongFromVlong(G, &COMPUTED_VLONG_G(p_dhContext), &pVlongQueue)))
        goto exit;

    DEBUG_RELABEL_MEMORY(COMPUTED_VLONG_G(p_dhContext));

    if (OK > (status = DH_generateY(pRandomContext, COMPUTED_VLONG_Q(p_dhContext), lengthY, &pMpintY, NULL)))
        goto exit;

    DEBUG_RELABEL_MEMORY(pMpintY);

    /* Compute F */
    if (OK > (status = VLONG_modexp(MOC_MOD(hwAccelCtx) COMPUTED_VLONG_G(p_dhContext), pMpintY, COMPUTED_VLONG_P(p_dhContext), &pMpintF, &pVlongQueue)))
        goto exit;

    DEBUG_RELABEL_MEMORY(pMpintF);

    /* save vlong variables here */
    COMPUTED_VLONG_Y(p_dhContext) = pMpintY; pMpintY = NULL;
    COMPUTED_VLONG_F(p_dhContext) = pMpintF; pMpintF = NULL;

exit:
    VLONG_freeVlong(&pMpintY, 0);
    VLONG_freeVlong(&pMpintF, 0);
    VLONG_freeVlongQueue(&pVlongQueue);

    FIPS_LOG_END_ALG(FIPS_ALGO_DH,0);
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
DH_setPGQ(MOC_DH(hwAccelDescr hwAccelCtx) randomContext *pRandomContext, ubyte4 lengthY, diffieHellmanContext *p_dhContext, const vlong *P, const vlong *G, const vlong *Q)
{
    vlong*  pVlongQueue = NULL;
    MSTATUS status = ERR_NULL_POINTER;
    
    if (NULL == Q) /* Other input params validated by the DH_setPG call below */
        goto exit;

    /* Set Q first so that the call to DH_setPG can use it to further validate the private key */
    if (OK > (status = VLONG_makeVlongFromVlong(Q, &COMPUTED_VLONG_Q(p_dhContext), &pVlongQueue)))
        goto exit;

    /* Set PG using above funct. It will check FIPS status for us.
     * It also generates private key Y and public key F.
     */
    if (OK > (status = DH_setPG(MOC_DH(hwAccelCtx) pRandomContext, lengthY, p_dhContext, P, G)))
    	goto exit;

    DEBUG_RELABEL_MEMORY(COMPUTED_VLONG_Q(p_dhContext));

exit:
    VLONG_freeVlongQueue(&pVlongQueue);

    return status;
}


/*------------------------------------------------------------------*/

MSTATUS DH_freeDhContext(diffieHellmanContext **pp_dhContext, vlong **ppVlongQueue)
{
    return DH_freeDhContextExt(pp_dhContext, ppVlongQueue, NULL);
}

MSTATUS DH_freeDhContextExt(diffieHellmanContext **pp_dhContext, vlong **ppVlongQueue, void *pExtCtx)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;

    MOC_UNUSED(pExtCtx);
    
    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_DH); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_DH,0);

    if ((NULL == pp_dhContext) || (NULL == *pp_dhContext))
        status = ERR_NULL_POINTER;
    else
    {
        VLONG_freeVlong(&COMPUTED_VLONG_G(*pp_dhContext), ppVlongQueue);
        VLONG_freeVlong(&COMPUTED_VLONG_Y(*pp_dhContext), ppVlongQueue);
        VLONG_freeVlong(&COMPUTED_VLONG_F(*pp_dhContext), ppVlongQueue);
        VLONG_freeVlong(&COMPUTED_VLONG_E(*pp_dhContext), ppVlongQueue);
        VLONG_freeVlong(&COMPUTED_VLONG_K(*pp_dhContext), ppVlongQueue);
        VLONG_freeVlong(&COMPUTED_VLONG_P(*pp_dhContext), ppVlongQueue);
        VLONG_freeVlong(&COMPUTED_VLONG_Q(*pp_dhContext), ppVlongQueue);
#ifndef __DISABLE_DIGICERT_DH_BLINDING__
        VLONG_freeVlong(&COMPUTED_VLONG_PY(*pp_dhContext), ppVlongQueue);
        VLONG_freeVlong(&COMPUTED_VLONG_VI(*pp_dhContext), ppVlongQueue);
        VLONG_freeVlong(&COMPUTED_VLONG_VF(*pp_dhContext), ppVlongQueue);
#endif
        
        FREE(*pp_dhContext);
        *pp_dhContext = NULL;
    }

    FIPS_LOG_END_ALG(FIPS_ALGO_DH,0);
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
DH_computeKeyExchange(MOC_DH(hwAccelDescr hwAccelCtx) diffieHellmanContext *p_dhContext, vlong **ppVlongQueue)
{
    FIPS_LOG_DECL_SESSION;
    vlong*  pMpintK    = NULL;
    vlong*  pPminus1   = NULL;
    vlong*  pJust1     = NULL;
    MSTATUS status = ERR_NULL_POINTER;
    int pubkeyGood = FALSE;
    int sharedSecretGood = FALSE;

    if (NULL == p_dhContext)
        goto exit;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_DH); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_DH,0);

   /* Make sure we have all that we need. If we don't we'll be wiping this context out. (see below)... */
   if ( (NULL == COMPUTED_VLONG_P(p_dhContext)) || (NULL == COMPUTED_VLONG_G(p_dhContext)) ||
		(NULL == COMPUTED_VLONG_Y(p_dhContext)) || (NULL == COMPUTED_VLONG_E(p_dhContext)) )
   {
       status = ERR_KEY_EXCHANGE;
       goto exit;
   }

    /* If needed, Compute F for clients */
    if (NULL == COMPUTED_VLONG_F(p_dhContext))
    {
        if (OK > (status = VLONG_modexp(MOC_MOD(hwAccelCtx)
                                        COMPUTED_VLONG_G(p_dhContext), COMPUTED_VLONG_Y(p_dhContext),
                                        COMPUTED_VLONG_P(p_dhContext), &COMPUTED_VLONG_F(p_dhContext), ppVlongQueue)))
        {
            goto exit;
        }
    }

    DEBUG_RELABEL_MEMORY(COMPUTED_VLONG_F(p_dhContext));

/* New Validation rules... (SP800-56Ar2)
 	 Note: e is our dh_e field.
     2 <= e <= P-2  ==  1 < e < P-1
	 1 = e^Q mod P
*/
    if ( (OK > (status = VLONG_makeVlongFromVlong(COMPUTED_VLONG_P(p_dhContext), &pPminus1, ppVlongQueue) )) ||
    		(OK > (status = VLONG_decrement(pPminus1, ppVlongQueue) )) )
    {
        goto exit;
    }

    /* 1 < e < P-1 */
	if ((1 != (VLONG_compareUnsigned(COMPUTED_VLONG_E(p_dhContext), 1) )) ||
		(1 != (VLONG_compareSignedVlongs(pPminus1, COMPUTED_VLONG_E(p_dhContext)) )) )
	{
	   status = ERR_BAD_CLIENT_E;
	   goto exit;
	}

    if (NULL != COMPUTED_VLONG_Q(p_dhContext))
    {
        /* 1 = e^Q mod P */
        if (OK > (status = VLONG_modexp(MOC_MOD(hwAccelCtx)
            		 						COMPUTED_VLONG_E(p_dhContext), COMPUTED_VLONG_Q(p_dhContext),
                                            COMPUTED_VLONG_P(p_dhContext), &pJust1, ppVlongQueue)))
    	{
    	   goto exit;
    	}
        if (0 != (VLONG_compareUnsigned(pJust1, 1) ))
    	{
    	   status = ERR_BAD_CLIENT_E;
    	   goto exit;
    	}
    } /* Q provided */

    pubkeyGood = TRUE;

    /* Compute K (Shared Secret) */
    if (OK > (status = VLONG_modexp(MOC_MOD(hwAccelCtx) COMPUTED_VLONG_E(p_dhContext), COMPUTED_VLONG_Y(p_dhContext), COMPUTED_VLONG_P(p_dhContext), &pMpintK, ppVlongQueue)))
    {
    	sharedSecretGood = FALSE;
    	goto exit;
    } else {

#ifdef __ENABLE_DIGICERT_DH_MODES__
        if ( 1 != VLONG_compareUnsigned(pMpintK, 1) || 1 != VLONG_compareSignedVlongs(pPminus1, pMpintK) )
	    {
           sharedSecretGood = FALSE;
           status = ERR_KEY_EXCHANGE;
           goto exit;
        }
#endif
        sharedSecretGood = TRUE;
        COMPUTED_VLONG_K(p_dhContext) = pMpintK; pMpintK = NULL;
        DEBUG_RELABEL_MEMORY(COMPUTED_VLONG_K(p_dhContext));

#ifndef __ENABLE_DIGICERT_DH_MODES__
        /* Delete Ephemeral private key (SP800-56Ar2) */
    	VLONG_freeVlong(&COMPUTED_VLONG_Y(p_dhContext), ppVlongQueue);
#endif
    }

exit:
	VLONG_freeVlong(&pMpintK, ppVlongQueue);
	VLONG_freeVlong(&pPminus1, ppVlongQueue);
	VLONG_freeVlong(&pJust1, ppVlongQueue);

	if ( (pubkeyGood == FALSE) || (sharedSecretGood == FALSE) )
	{
		/* If Pub-Key validation fails, zero everything else out... (SP800-56Ar2) */
        VLONG_freeVlong(&COMPUTED_VLONG_P(p_dhContext), ppVlongQueue);
        VLONG_freeVlong(&COMPUTED_VLONG_G(p_dhContext), ppVlongQueue);
        VLONG_freeVlong(&COMPUTED_VLONG_Q(p_dhContext), ppVlongQueue);
        /* Destroy ephemeral stuff */
        VLONG_freeVlong(&COMPUTED_VLONG_Y(p_dhContext), ppVlongQueue);
        VLONG_freeVlong(&COMPUTED_VLONG_F(p_dhContext), ppVlongQueue);
        VLONG_freeVlong(&COMPUTED_VLONG_E(p_dhContext), ppVlongQueue);
        VLONG_freeVlong(&COMPUTED_VLONG_K(p_dhContext), ppVlongQueue);
	}

    FIPS_LOG_END_ALG(FIPS_ALGO_DH,0);
    return status;

} /* DH_computeKeyExchange */

/* ----------------------------------------------------------------------------------------------- */

MSTATUS DH_setKeyParameters(MOC_DH(hwAccelDescr hwAccelCtx) diffieHellmanContext *pTargetCtx, MDhKeyTemplate *pSrcTemplate)
{
    return DH_setKeyParametersExt(MOC_DH(hwAccelCtx) pTargetCtx, pSrcTemplate, NULL);
}

MSTATUS DH_setKeyParametersExt(MOC_DH(hwAccelDescr hwAccelCtx) diffieHellmanContext *pTargetCtx, MDhKeyTemplate *pSrcTemplate, void *pExtCtx)
{
    MSTATUS status = ERR_NULL_POINTER;
    vlong *pTempG = NULL;
    vlong *pTempP = NULL;
    vlong *pTempQ = NULL;
    vlong *pTempY = NULL;
    vlong *pTempF = NULL;
    
    MOC_UNUSED(pExtCtx);
    
    if (NULL == pTargetCtx || NULL == pSrcTemplate)
        goto exit;
  
    if (DH_GROUP_TBD != pSrcTemplate->groupNum)
    {
        /* Set P and G based on the predefined group. Ignore all params in the template */
        status = DH_getP(pSrcTemplate->groupNum, &pTempP);
        if (OK != status)
            goto exit;
        
        status = DH_getG(pSrcTemplate->groupNum, &pTempG);
        if (OK != status)
            goto exit;
    }
    else
    {
        if (NULL != pSrcTemplate->pG && pSrcTemplate->gLen)
        {
            status = VLONG_vlongFromByteString(pSrcTemplate->pG, pSrcTemplate->gLen, &pTempG, NULL);
            if (OK != status)
                goto exit;
        }
        
        if (NULL != pSrcTemplate->pP && pSrcTemplate->pLen)
        {
            status = VLONG_vlongFromByteString(pSrcTemplate->pP, pSrcTemplate->pLen, &pTempP, NULL);
            if (OK != status)
                goto exit;
        }
        
        if (NULL != pSrcTemplate->pQ && pSrcTemplate->qLen)
        {
            status = VLONG_vlongFromByteString(pSrcTemplate->pQ, pSrcTemplate->qLen, &pTempQ, NULL);
            if (OK != status)
                goto exit;
        }
        
        if (NULL != pSrcTemplate->pY && pSrcTemplate->yLen)
        {
            status = VLONG_vlongFromByteString(pSrcTemplate->pY, pSrcTemplate->yLen, &pTempY, NULL);
            if (OK != status)
                goto exit;
        }
        
        if (NULL != pSrcTemplate->pF && pSrcTemplate->fLen)
        {
            status = VLONG_vlongFromByteString(pSrcTemplate->pF, pSrcTemplate->fLen, &pTempF, NULL);
            if (OK != status)
                goto exit;
        }
    }
    /*
     No errors, go ahead and free any existing values that were already there.
     If existing value was NULL then ERR_NULL_POINTER is returned and ignored
     */
    VLONG_freeVlong(&COMPUTED_VLONG_G(pTargetCtx), NULL);
    VLONG_freeVlong(&COMPUTED_VLONG_P(pTargetCtx), NULL);
    VLONG_freeVlong(&COMPUTED_VLONG_Q(pTargetCtx), NULL);
    VLONG_freeVlong(&COMPUTED_VLONG_Y(pTargetCtx), NULL);
    VLONG_freeVlong(&COMPUTED_VLONG_F(pTargetCtx), NULL);
    
    COMPUTED_VLONG_G(pTargetCtx) = pTempG; pTempG = NULL;
    COMPUTED_VLONG_P(pTargetCtx) = pTempP; pTempP = NULL;
    COMPUTED_VLONG_Q(pTargetCtx) = pTempQ; pTempQ = NULL;
    COMPUTED_VLONG_Y(pTargetCtx) = pTempY; pTempY = NULL;
    COMPUTED_VLONG_F(pTargetCtx) = pTempF; pTempF = NULL;

    status = OK;
exit:
    
    /* free on error or ignore ERR_NULL_POINTER returns on success */
    VLONG_freeVlong(&pTempG, NULL);
    VLONG_freeVlong(&pTempP, NULL);
    VLONG_freeVlong(&pTempQ, NULL);
    VLONG_freeVlong(&pTempY, NULL);
    VLONG_freeVlong(&pTempF, NULL);
    
    return status;
}

/* ----------------------------------------------------------------------------------------------- */

MSTATUS DH_getKeyParametersAlloc(MOC_DH(hwAccelDescr hwAccelCtx) MDhKeyTemplate *pTargetTemplate, diffieHellmanContext *pSrcCtx, ubyte keyType)
{
    return DH_getKeyParametersAllocExt(MOC_DH(hwAccelCtx) pTargetTemplate, pSrcCtx, keyType, NULL);
}

MSTATUS DH_getKeyParametersAllocExt(MOC_DH(hwAccelDescr hwAccelCtx) MDhKeyTemplate *pTargetTemplate, diffieHellmanContext *pSrcCtx, ubyte keyType, void *pExtCtx)
{
    MSTATUS status = ERR_NULL_POINTER;
    sbyte4 len;
    
    MOC_UNUSED(pExtCtx);
    
    if (NULL == pTargetTemplate || NULL == pSrcCtx)
        goto exit;

    status = ERR_INVALID_ARG;
    if (MOC_GET_PUBLIC_KEY_DATA != keyType && MOC_GET_PRIVATE_KEY_DATA != keyType)
        goto exit;

    if (NULL != COMPUTED_VLONG_G(pSrcCtx))
    {
        /* get the length needed */
        status = VLONG_byteStringFromVlong(COMPUTED_VLONG_G(pSrcCtx), NULL, &len);
        if (OK != status)
            goto exit;
        
        status = DIGI_MALLOC((void **) &pTargetTemplate->pG, len);
        if (OK != status)
            goto exit;
        
        status = VLONG_byteStringFromVlong(COMPUTED_VLONG_G(pSrcCtx), pTargetTemplate->pG, &len);
        if (OK != status)
            goto exit;
        
        pTargetTemplate->gLen = (ubyte4) len;
    }
    
    if (NULL != COMPUTED_VLONG_P(pSrcCtx))
    {
        /* get the length needed */
        status = VLONG_byteStringFromVlong(COMPUTED_VLONG_P(pSrcCtx), NULL, &len);
        if (OK != status)
            goto exit;
        
        status = DIGI_MALLOC((void **) &pTargetTemplate->pP, len);
        if (OK != status)
            goto exit;
        
        status = VLONG_byteStringFromVlong(COMPUTED_VLONG_P(pSrcCtx), pTargetTemplate->pP, &len);
        if (OK != status)
            goto exit;
        
        pTargetTemplate->pLen = (ubyte4) len;
    }
    
    if (NULL != COMPUTED_VLONG_Q(pSrcCtx))
    {
        /* get the length needed */
        status = VLONG_byteStringFromVlong(COMPUTED_VLONG_Q(pSrcCtx), NULL, &len);
        if (OK != status)
            goto exit;
        
        status = DIGI_MALLOC((void **) &pTargetTemplate->pQ, len);
        if (OK != status)
            goto exit;
        
        status = VLONG_byteStringFromVlong(COMPUTED_VLONG_Q(pSrcCtx), pTargetTemplate->pQ, &len);
        if (OK != status)
            goto exit;
        
        pTargetTemplate->qLen = (ubyte4) len;
    }
  
    if (MOC_GET_PRIVATE_KEY_DATA == keyType)
    {
        if( NULL != COMPUTED_VLONG_Y(pSrcCtx))
        {
            /* get the length needed */
            status = VLONG_byteStringFromVlong(COMPUTED_VLONG_Y(pSrcCtx), NULL, &len);
            if (OK != status)
                goto exit;
          
            status = DIGI_MALLOC((void **) &pTargetTemplate->pY, len);
            if (OK != status)
                goto exit;
        
            status = VLONG_byteStringFromVlong(COMPUTED_VLONG_Y(pSrcCtx), pTargetTemplate->pY, &len);
            if (OK != status)
                goto exit;
        
            pTargetTemplate->yLen = (ubyte4) len;
        }
        else
        {
            status = ERR_KEY_EXCHANGE;
            goto exit;
        }
    }
    
    if (NULL != COMPUTED_VLONG_F(pSrcCtx))
    {
        /* get the length needed */
        status = VLONG_byteStringFromVlong(COMPUTED_VLONG_F(pSrcCtx), NULL, &len);
        if (OK != status)
            goto exit;
        
        status = DIGI_MALLOC((void **) &pTargetTemplate->pF, len);
        if (OK != status)
            goto exit;
        
        status = VLONG_byteStringFromVlong(COMPUTED_VLONG_F(pSrcCtx), pTargetTemplate->pF, &len);
        if (OK != status)
            goto exit;
        
        pTargetTemplate->fLen = (ubyte4) len;
    }
    
    pTargetTemplate->groupNum = DH_GROUP_TBD; /* 0 */
  
exit:
    
    return status;
}

/* ----------------------------------------------------------------------------------------------- */

MSTATUS DH_freeKeyTemplate(diffieHellmanContext *pCtx, MDhKeyTemplate *pTemplate)
{
    return DH_freeKeyTemplateExt(pCtx, pTemplate, NULL);
}

MSTATUS DH_freeKeyTemplateExt(diffieHellmanContext *pCtx, MDhKeyTemplate *pTemplate, void *pExtCtx)
{
    MOC_UNUSED(pExtCtx);
    MOC_UNUSED(pCtx); /* not needed, only here for crypto interface reasons */
  
    if (NULL == pTemplate) /* ok no-op */
        return OK;

    if (NULL != pTemplate->pG)
    {
        DIGI_MEMSET(pTemplate->pG, 0x00, pTemplate->gLen); /* ok to ignore return codes */
        DIGI_FREE((void **) &pTemplate->pG);
    }
    
    if (NULL != pTemplate->pP)
    {
        DIGI_MEMSET(pTemplate->pP, 0x00, pTemplate->pLen);
        DIGI_FREE((void **) &pTemplate->pP);
    }
    
    if (NULL != pTemplate->pQ)
    {
        DIGI_MEMSET(pTemplate->pQ, 0x00, pTemplate->qLen);
        DIGI_FREE((void **) &pTemplate->pQ);
    }
    
    if (NULL != pTemplate->pY)
    {
        DIGI_MEMSET(pTemplate->pY, 0x00, pTemplate->yLen);
        DIGI_FREE((void **) &pTemplate->pY);
    }
    
    if (NULL != pTemplate->pF)
    {
        DIGI_MEMSET(pTemplate->pF, 0x00, pTemplate->fLen);
        DIGI_FREE((void **) &pTemplate->pF);
    }
    
    pTemplate->groupNum = DH_GROUP_TBD; /* 0 */
  
    return OK;
}

/* ----------------------------------------------------------------------------------------------- */

MSTATUS DH_generateKeyPair(MOC_DH(hwAccelDescr hwAccelCtx) diffieHellmanContext *pCtx, randomContext *pRandomContext, ubyte4 numBytes)
{
    return DH_generateKeyPairExt(MOC_DH(hwAccelCtx) pCtx, pRandomContext, numBytes, NULL);
}

MSTATUS DH_generateKeyPairExt(MOC_DH(hwAccelDescr hwAccelCtx) diffieHellmanContext *pCtx, randomContext *pRandomContext, ubyte4 numBytes, void *pExtCtx)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = ERR_NULL_POINTER;
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
    ubyte4 lenYmin = 0;
    ubyte4 lenYmax = 0;
#endif /* __ENABLE_DIGICERT_FIPS_MODULE__ */

    MOC_UNUSED(pExtCtx);

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_DH); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_DH,0);

    if (NULL == pCtx || NULL == pRandomContext)
        goto exit;
    
    /* we must have p and g already set */
    status = ERR_KEY_EXCHANGE;
    if (NULL == COMPUTED_VLONG_G(pCtx) || NULL == COMPUTED_VLONG_P(pCtx))
        goto exit;
    
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
    /* We need to validate length Y is large enough. First check if P, G are from a safe prime group */
    status = safeGroupMatch(COMPUTED_VLONG_P(pCtx), COMPUTED_VLONG_G(pCtx), &lenYmin, &lenYmax, NULL);
    if (OK == status)
    {
        if (numBytes < lenYmin || numBytes > lenYmax)
        {
            status = ERR_DH_INVALID_KEYLENGTH;
            goto exit;
        }
    }
    else  /* it is not a safe prime group, it will have been validated to have been a FIPS 186-4 group. */
    {
        /* if Q is given then it should be 224 or 256 bits only, validate that lengthY is also the same number */
        if( NULL != COMPUTED_VLONG_Q(pCtx) )
        {
            if ( numBytes * 8 !=  VLONG_bitLength(COMPUTED_VLONG_Q(pCtx)) )
            {
                status = ERR_DH_INVALID_KEYLENGTH;
                goto exit;
            }
        }
        else /* Q is not given but should still be either 224 or 256 bits */
        {
            if (numBytes != 28 && numBytes != 32)
            {
                status = ERR_DH_INVALID_KEYLENGTH;
                goto exit;
            }
        }
    }
#else
    status = ERR_DH_INVALID_KEYLENGTH;
    if (!numBytes)
        goto exit;
#endif
    
    /* ok here for q to be NULL */
    status = DH_generateY(pRandomContext, COMPUTED_VLONG_Q(pCtx), numBytes, &COMPUTED_VLONG_Y(pCtx), NULL);
    if (OK != status)
        goto exit;

    /* Now compute our public key */
    status = VLONG_modexp(MOC_MOD(hwAccelCtx) COMPUTED_VLONG_G(pCtx), COMPUTED_VLONG_Y(pCtx), COMPUTED_VLONG_P(pCtx), &COMPUTED_VLONG_F(pCtx), NULL);

exit:
  FIPS_LOG_END_ALG(FIPS_ALGO_DH,0);
  return status;
}

/* ----------------------------------------------------------------------------------------------- */

MSTATUS DH_getPublicKey(MOC_DH(hwAccelDescr hwAccelCtx) diffieHellmanContext *pCtx, ubyte **ppPublicKey, ubyte4 *pPublicKeyLen)
{
    return DH_getPublicKeyExt(MOC_DH(hwAccelCtx) pCtx, ppPublicKey, pPublicKeyLen, NULL);
}

MSTATUS DH_getPublicKeyExt(MOC_DH(hwAccelDescr hwAccelCtx) diffieHellmanContext *pCtx, ubyte **ppPublicKey, ubyte4 *pPublicKeyLen, void *pExtCtx)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = ERR_NULL_POINTER;
    ubyte *pPubKey = NULL;
    sbyte4 len = 0;
    
    MOC_UNUSED(pExtCtx);

    if (NULL == pCtx || NULL == ppPublicKey || NULL == pPublicKeyLen)
        goto exit;
  
    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_DH); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_DH,0);

    status = ERR_KEY_EXCHANGE;
    if (NULL == COMPUTED_VLONG_F(pCtx))
        goto exit;
    
    /* Now write it to the buffer, first get its length */
    status = VLONG_byteStringFromVlong(COMPUTED_VLONG_F(pCtx), NULL, &len);
    if (OK != status)
        goto exit;
    
    status = DIGI_MALLOC((void **) &pPubKey, len);
    if (OK != status)
        goto exit;
    
    status = VLONG_byteStringFromVlong(COMPUTED_VLONG_F(pCtx), pPubKey, &len);
    if (OK != status)
        goto exit;
    
    *ppPublicKey = pPubKey; pPubKey = NULL;
    *pPublicKeyLen = (ubyte4) len;

exit:
    
    if (NULL != pPubKey)
    {
        DIGI_MEMSET(pPubKey, 0x00, len);
        DIGI_FREE((void **) &pPubKey);
    }
    
    FIPS_LOG_END_ALG(FIPS_ALGO_DH,0);
    return status;
}

/* ----------------------------------------------------------------------------------------------- */

MSTATUS DH_computeKeyExchangeEx(MOC_DH(hwAccelDescr hwAccelCtx) diffieHellmanContext *pCtx, randomContext *pRandomContext, ubyte *pOtherPartysPublicKey, ubyte4 publicKeyLen,
                                ubyte **ppSharedSecret, ubyte4 *pSharedSecretLen)
{
    return DH_computeKeyExchangeExExt(MOC_DH(hwAccelCtx) pCtx, pRandomContext, pOtherPartysPublicKey, publicKeyLen, ppSharedSecret, pSharedSecretLen, NULL);
}

MSTATUS DH_computeKeyExchangeExExt(MOC_DH(hwAccelDescr hwAccelCtx) diffieHellmanContext *pCtx, randomContext *pRandomContext, ubyte *pOtherPartysPublicKey, ubyte4 publicKeyLen,
                                   ubyte **ppSharedSecret, ubyte4 *pSharedSecretLen, void *pExtCtx)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = ERR_NULL_POINTER;
    ubyte *pSS = NULL;
    sbyte4 ssLen = 0;
    
#ifndef __DISABLE_DIGICERT_DH_BLINDING__
    sbyte4 pLen = 0;
    vlong *pTemp = NULL;
    vlong *pQuoUnused = NULL;

    byteBoolean pubKeyGood = FALSE;
    
#else
    MOC_UNUSED(pRandomContext);
#endif
    
    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_DH); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_DH,0);

    MOC_UNUSED(pExtCtx);
    
    if (NULL == pCtx || NULL == pOtherPartysPublicKey || NULL == ppSharedSecret || NULL == pSharedSecretLen)
        goto exit;

    status = ERR_BAD_CLIENT_E;
    if (!publicKeyLen)
        goto exit;
    
    /* free any existing E in the ctx, ok to ignore return code */
    VLONG_freeVlong(&COMPUTED_VLONG_E(pCtx), NULL);
    
    /* convert the public key to a vlong in the context */
    status = VLONG_vlongFromByteString(pOtherPartysPublicKey, publicKeyLen, &COMPUTED_VLONG_E(pCtx), NULL);
    if (OK != status)
        goto exit;
    
#ifndef __DISABLE_DIGICERT_DH_BLINDING__

    /* check on Y now for the blinding case */
    status = ERR_KEY_EXCHANGE;
    if (NULL == COMPUTED_VLONG_Y(pCtx) || NULL == COMPUTED_VLONG_P(pCtx) ||  NULL == COMPUTED_VLONG_G(pCtx))
        goto exit;
    
    /* We perform the same validations as the old computeKeyExchange method */
    
    /* If needed, Compute F for clients */
    if (NULL == COMPUTED_VLONG_F(pCtx))
    {
        status = VLONG_modexp(MOC_MOD(hwAccelCtx) COMPUTED_VLONG_G(pCtx), COMPUTED_VLONG_Y(pCtx), COMPUTED_VLONG_P(pCtx), &COMPUTED_VLONG_F(pCtx), NULL);
        if (OK != status)
            goto exit;
    }

    /*
     New Validation rules... (SP800-56Ar2)
     Note: make sure e is a proper element, 1 < e < p-1.
     */
    status = VLONG_makeVlongFromVlong(COMPUTED_VLONG_P(pCtx), &pTemp, NULL);
    if (OK != status)
        goto exit;
    
    status = VLONG_decrement(pTemp, NULL);
    if (OK != status)
        goto exit;
    
    /* 1 < e < p-1 */
    status = ERR_BAD_CLIENT_E;
    if (1 != VLONG_compareUnsigned(COMPUTED_VLONG_E(pCtx), 1) || 1 != VLONG_compareSignedVlongs(pTemp, COMPUTED_VLONG_E(pCtx)))
        goto exit;

    /* q provided, e^q mod p = 1 */

    if (NULL != COMPUTED_VLONG_Q(pCtx))
    {
        /* 1 = y^Q mod P, use pQuoUnused as a temp var */
        status = VLONG_modexp(MOC_MOD(hwAccelCtx) COMPUTED_VLONG_E(pCtx), COMPUTED_VLONG_Q(pCtx), COMPUTED_VLONG_P(pCtx), &pQuoUnused, NULL);
        if (OK != status)
            goto exit;
        
        status = ERR_BAD_CLIENT_E;
        if (0 != VLONG_compareUnsigned(pQuoUnused, 1))
            goto exit;
    }
    else
    {
        /* allocate pQuoUnused for later use */
        status = VLONG_allocVlong(&pQuoUnused, NULL);
        if (OK != status)
            goto exit;
    }
    
    pubKeyGood = TRUE;

    if (NULL != pRandomContext)
    {
        if (NULL == COMPUTED_VLONG_PY(pCtx))
        {
            /* First pass, copy y but we won't do any blinding */
            status = VLONG_makeVlongFromVlong(COMPUTED_VLONG_Y(pCtx), &COMPUTED_VLONG_PY(pCtx), NULL);
            if (OK != status)
                goto exit;
        }
        else if (0 != compareUnsignedVlongs(COMPUTED_VLONG_PY(pCtx), COMPUTED_VLONG_Y(pCtx)))
        {
            /*
             Y was changed and so again a first pass,
             reset VI and VF and we also don't do any blinding,
             ok to ignore return codes on VLONG_freeVlong
             */
            VLONG_freeVlong(&COMPUTED_VLONG_VI(pCtx), NULL);
            VLONG_freeVlong(&COMPUTED_VLONG_VF(pCtx), NULL);
            status = VLONG_copySignedValue(COMPUTED_VLONG_PY(pCtx), COMPUTED_VLONG_Y(pCtx));
            if (OK != status)
                goto exit;
        }
        else  /* y is the same as last pass, we will do blinding */
        {
            /* get the length needed */
            status = VLONG_byteStringFromVlong(COMPUTED_VLONG_P(pCtx), NULL, &pLen);
            if (OK != status)
                goto exit;
            
            if (NULL == COMPUTED_VLONG_VI(pCtx))
            {
                /* Generate the blinding value */
                status = DH_generateY(pRandomContext, NULL, pLen, &COMPUTED_VLONG_VI(pCtx), NULL);
                if (OK != status)
                    goto exit;
                
                /* free pTemp as VLONG_modularInverse needs to allocate it again */
                status = VLONG_freeVlong(&pTemp, NULL);
                if (OK != status)
                    goto exit;
                
                /* Invert and exponentiate in order to get the unblinding value, this alocates pTemp */
                status = VLONG_modularInverse(MOC_MOD(hwAccelCtx) COMPUTED_VLONG_VI(pCtx), COMPUTED_VLONG_P(pCtx), &pTemp, NULL);
                if (OK != status)
                    goto exit;
                
                status = VLONG_modexp(MOC_MOD(hwAccelCtx) pTemp, COMPUTED_VLONG_Y(pCtx), COMPUTED_VLONG_P(pCtx), &COMPUTED_VLONG_VF(pCtx), NULL);
                if (OK != status)
                    goto exit;
            }
            else
            {
                status = VLONG_FAST_SQR(pTemp, COMPUTED_VLONG_VI(pCtx), 2*pLen);
                if (OK != status)
                    goto exit;
                
                status = VLONG_unsignedDivide(pQuoUnused, pTemp, COMPUTED_VLONG_P(pCtx), COMPUTED_VLONG_VI(pCtx), NULL);
                if (OK != status)
                    goto exit;
                
                status = VLONG_FAST_SQR(pTemp, COMPUTED_VLONG_VF(pCtx), 2*pLen);
                if (OK != status)
                    goto exit;
                
                status = VLONG_unsignedDivide(pQuoUnused, pTemp, COMPUTED_VLONG_P(pCtx), COMPUTED_VLONG_VF(pCtx), NULL);
                if (OK != status)
                    goto exit;
            }
            
            status = VLONG_FAST_MULT(pTemp, COMPUTED_VLONG_E(pCtx), COMPUTED_VLONG_VI(pCtx), 2*pLen);
            if (OK != status)
                goto exit;
            
            /* ok to modify the context's E */
            status = VLONG_unsignedDivide(pQuoUnused, pTemp, COMPUTED_VLONG_P(pCtx), COMPUTED_VLONG_E(pCtx), NULL);
            if (OK != status)
                goto exit;
        }
    }

    /* free anything already stored in pCtx->dh_k. Ok to ignore return code */
    VLONG_freeVlong(&COMPUTED_VLONG_K(pCtx), NULL);
    
    /* Exponentiate (with or without the blinding) */
    status = VLONG_modexp(MOC_MOD(hwAccelCtx) COMPUTED_VLONG_E(pCtx), COMPUTED_VLONG_Y(pCtx), COMPUTED_VLONG_P(pCtx), &COMPUTED_VLONG_K(pCtx), NULL);
    if (OK != status)
        goto exit;
    
    if (NULL != pRandomContext && NULL != COMPUTED_VLONG_VF(pCtx))
    {
        /* pTemp and pQuoUnused allocated above */
        status = VLONG_FAST_MULT(pTemp, COMPUTED_VLONG_K(pCtx), COMPUTED_VLONG_VF(pCtx), 2*pLen);
        if (OK != status)
            goto exit;
        
        status = VLONG_unsignedDivide(pQuoUnused, pTemp, COMPUTED_VLONG_P(pCtx), COMPUTED_VLONG_K(pCtx), NULL);
        if (OK != status)
            goto exit;
    }

#else
    
    /* Call DH_computeKeyExchange which will take care of validation and zero-ing data on error */
    status = DH_computeKeyExchange(MOC_DH(hwAccelCtx) pCtx, NULL);
    if (OK != status)
        goto exit;
    
#endif /* __DISABLE_DIGICERT_DH_BLINDING__ */
    
    /* Get shared secret length as a byte array */
    status = VLONG_byteStringFromVlong(COMPUTED_VLONG_K(pCtx), NULL, &ssLen);
    if (OK != status)
        goto exit;
    
    /* Allocate */
    status = DIGI_MALLOC((void **) &pSS, ssLen);
    if (OK != status)
        goto exit;
    
    /* write the shared secret as a byte array */
    status = VLONG_byteStringFromVlong(COMPUTED_VLONG_K(pCtx), pSS, &ssLen);
    if (OK != status)
        goto exit;

#ifndef __DISABLE_DIGICERT_DH_BLINDING__
    if (pubKeyGood)
#endif
    {
        *ppSharedSecret = pSS; pSS = NULL;
        *pSharedSecretLen = (ubyte4) ssLen;
    }
    
exit:
    
#ifndef __DISABLE_DIGICERT_DH_BLINDING__
    
    /* ok to ignore return code if pTemp and pQuoUnused were never allocated */
    VLONG_freeVlong(&pTemp, NULL);
    VLONG_freeVlong(&pQuoUnused, NULL);
    
    if (!pubKeyGood && NULL != pCtx)
    {
        /* (SP800-56Ar2) zero everything (except E and K are done later), ok to ignore return codes */
        VLONG_freeVlong(&COMPUTED_VLONG_Y(pCtx), NULL);
        VLONG_freeVlong(&COMPUTED_VLONG_P(pCtx), NULL);
        VLONG_freeVlong(&COMPUTED_VLONG_G(pCtx), NULL);
        VLONG_freeVlong(&COMPUTED_VLONG_Q(pCtx), NULL);
        VLONG_freeVlong(&COMPUTED_VLONG_F(pCtx), NULL);
        VLONG_freeVlong(&COMPUTED_VLONG_PY(pCtx), NULL);
        VLONG_freeVlong(&COMPUTED_VLONG_VI(pCtx), NULL);
        VLONG_freeVlong(&COMPUTED_VLONG_VF(pCtx), NULL);
    }
    
#endif
    
    if (NULL != pCtx)
    {
        /* Zero the copy of the shared secret in context, ok to ignore return code */
        VLONG_freeVlong(&COMPUTED_VLONG_E(pCtx), NULL);
        VLONG_freeVlong(&COMPUTED_VLONG_K(pCtx), NULL);
    }
    
    if (NULL != pSS)
    {
        DIGI_MEMSET(pSS, 0x00, ssLen);
        DIGI_FREE((void **) &pSS);
    }
    
    FIPS_LOG_END_ALG(FIPS_ALGO_DH,0);
    return status;
}

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_DH_MODES__

static MSTATUS DHMQV_bar(vlong *pQ, vlong *pIn, vlong **ppOut)
{
    MSTATUS status = OK;
    vlong *pOut = NULL;
    ubyte4 w = 0;
    ubyte4 bpu = 0;
    ubyte4 leftOvers = 0;
    ubyte4 words = 0;
    ubyte4 i = 0;

    /* internal method, NULL checks not necc */
    
    /* w = ceil ( 1/2 * log_2(Q) ) */
    /* pQ is never an exact power of 2, so ok to take half bit length rounded up */
    w = (VLONG_bitLength(pQ) + 1)/2;
    
    bpu = sizeof(vlong_unit)*8;

    words = (w + bpu - 1) / bpu;
    leftOvers = w % bpu;

    status = VLONG_allocVlong(&pOut, NULL);
    if (OK != status)
        goto exit;

    status = VLONG_reallocVlong(pOut, leftOvers ? words : words + 1);
    if (OK != status)
        goto exit;

    pOut->numUnitsUsed = leftOvers ? words : words + 1;

    for (i = 0; i < words; i++)
    {
        pOut->pUnits[i] = pIn->pUnits[i];
    }

    /* truncate the leftover bits and set the w-th bit */
    if (leftOvers)
    {
        pOut->pUnits[words - 1] &= (FULL_MASK >> (bpu - leftOvers));
        pOut->pUnits[words - 1] |= ((vlong_unit) 0x1 << leftOvers);
    }
    else
    {
        pOut->pUnits[words] = (vlong_unit) 0x1;
        words++;
    }

    *ppOut = pOut; pOut = NULL;

exit:

    if (NULL != pOut)
    {
        (void) VLONG_freeVlong(&pOut, NULL);
    }

    return status;
}

static MSTATUS DHMQV_generateSharedSecret(
    MOC_DH(hwAccelDescr hwAccelCtx)
    diffieHellmanContext *pStatic,
    diffieHellmanContext *pEphemeral, 
    ubyte *pOtherPartysStatic, 
    ubyte4 otherStaticLen,
    ubyte *pOtherPartysEphemeral,
    ubyte4 otherEphemeralLen,
    ubyte **ppSharedSecret,
    ubyte4 *pSharedSecretLen)    
{
    MSTATUS status = OK;
    vlong *pTA = NULL;
    vlong *pTB = NULL;
    vlong *pSA = NULL;

    vlong *ptb = NULL;
    vlong *pyb = NULL;
    vlong *pTemp = NULL;
    vlong *pDummyQuo = NULL;

    ubyte *pZ = NULL;
    sbyte4 zLen = 0;

    /* internal method, NULL checks arlready done */

    /* TA */   
    status = DHMQV_bar(COMPUTED_VLONG_Q(pEphemeral), COMPUTED_VLONG_F(pEphemeral), &pTA);
    if (OK != status)
        goto exit;

    status = VLONG_allocVlong(&pSA, NULL);
    if (OK != status)
        goto exit;

    status = VLONG_allocVlong(&pTemp, NULL);
    if (OK != status)
        goto exit; 

    status = VLONG_allocVlong(&pDummyQuo, NULL);
    if (OK != status)
        goto exit;    

    /* TA * xa */
    status = VLONG_unsignedMultiply (pTemp, pTA, COMPUTED_VLONG_Y(pStatic));
    if (OK != status)
        goto exit;
 
    /* ra + TA * xa */
    status = addUnsignedVlongs(pTemp, COMPUTED_VLONG_Y(pEphemeral));
    if (OK != status)
        goto exit;

    /* SA = (ra + TA * xa) mod Q */
    status = VLONG_unsignedDivide (pDummyQuo, pTemp, COMPUTED_VLONG_Q(pEphemeral), pSA, NULL);
    if (OK != status)
        goto exit;

    status = VLONG_vlongFromByteString (pOtherPartysEphemeral, (sbyte4) otherEphemeralLen, &ptb, NULL);
    if (OK != status)
        goto exit;

    status = VLONG_vlongFromByteString (pOtherPartysStatic, (sbyte4) otherStaticLen, &pyb, NULL);
    if (OK != status)
        goto exit;
    
    /* TB */
    status = DHMQV_bar(COMPUTED_VLONG_Q(pEphemeral), ptb, &pTB);
    if (OK != status)
        goto exit;

    status = VLONG_freeVlong(&pTemp, NULL);
    if (OK != status)
        goto exit;

    /* yb^TB mod p */
    status = VLONG_modexp(MOC_MOD(hwAccelCtx) pyb, pTB, COMPUTED_VLONG_P(pEphemeral), &pTemp, NULL);
    if (OK != status)
        goto exit;

    /* tb * yb^TB mod p, reuse pyb as a temp */
    status = VLONG_unsignedMultiply(pyb, ptb, pTemp);
    if (OK != status)
        goto exit;

    status = VLONG_unsignedDivide(pDummyQuo, pyb, COMPUTED_VLONG_P(pEphemeral), pTemp, NULL);
    if (OK != status)
        goto exit;

    status = VLONG_freeVlong(&pyb, NULL);
    if (OK != status)
        goto exit;

    /* Z = (tb * yb^TB)^SA mod p, reuse pyb to store result */
    status = VLONG_modexp(MOC_MOD(hwAccelCtx) pTemp, pSA, COMPUTED_VLONG_P(pEphemeral), &pyb, NULL);
    if (OK != status)
        goto exit;

    status = VLONG_freeVlong(&pTemp, NULL);
    if (OK != status)
        goto exit;

    /* Make sure 1 < z < (p-1), get a copy of p */
    status = VLONG_makeVlongFromVlong(COMPUTED_VLONG_P(pEphemeral), &pTemp, NULL);
    if (OK != status)
        goto exit;

    status = VLONG_decrement(pTemp, NULL);
    if (OK != status)
        goto exit;

    if ( 1 != VLONG_compareUnsigned(pyb, 1) || 1 != VLONG_compareSignedVlongs(pTemp, pyb) )
    {
       status = ERR_KEY_EXCHANGE;
       goto exit;
    }

    /* get the length */
    status = VLONG_byteStringFromVlong(pyb, NULL, &zLen);
    if (OK != status)
        goto exit;

    status = DIGI_MALLOC((void **) &pZ, zLen);
    if (OK != status)
        goto exit;

    status = VLONG_byteStringFromVlong(pyb, pZ, &zLen);
    if (OK != status)
        goto exit;

    *ppSharedSecret = pZ; pZ = NULL;
    *pSharedSecretLen = (ubyte4) zLen;
    
exit:

    if (NULL != pZ)
    {
        (void) DIGI_MEMSET_FREE(&pZ, zLen);
    }
    
    (void) VLONG_freeVlong(&pTA, NULL);
    (void) VLONG_freeVlong(&pTB, NULL);
    (void) VLONG_freeVlong(&pSA, NULL);
    (void) VLONG_freeVlong(&ptb, NULL);
    (void) VLONG_freeVlong(&pyb, NULL);
    (void) VLONG_freeVlong(&pTemp, NULL);
    (void) VLONG_freeVlong(&pDummyQuo, NULL);

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS DH_keyAgreementScheme(
    MOC_DH(hwAccelDescr hwAccelCtx)
    ubyte4 mode,
    randomContext *pRandomContext,
    diffieHellmanContext *pStatic, 
    diffieHellmanContext *pEphemeral, 
    ubyte *pOtherPartysStatic, 
    ubyte4 otherStaticLen,
    ubyte *pOtherPartysEphemeral,
    ubyte4 otherEphemeralLen,
    ubyte **ppSharedSecret,
    ubyte4 *pSharedSecretLen)
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte *pSS = NULL;
    ubyte4 ssLen = 0;
    ubyte *pSS1 = NULL;
    ubyte4 ss1Len = 0;
    ubyte *pSS2 = NULL;
    ubyte4 ss2Len = 0;

    if (NULL == ppSharedSecret || NULL == pSharedSecretLen)
        goto exit;

    switch (mode)
    {
        case DH_HYBRID1:
            
            if (NULL == pStatic || NULL == pEphemeral || NULL == pOtherPartysStatic || NULL == pOtherPartysEphemeral)
                goto exit;

            /* rest of needed props will be checked in DH_computeKeyExchangeExExt */
            if (NULL == COMPUTED_VLONG_P(pStatic) || NULL == COMPUTED_VLONG_G(pStatic) || 
                NULL == COMPUTED_VLONG_P(pEphemeral) || NULL == COMPUTED_VLONG_G(pEphemeral) )
                goto exit;

            status = ERR_FF_DIFFERENT_FIELDS;
            if ( 0 != VLONG_compareSignedVlongs(COMPUTED_VLONG_P(pStatic), COMPUTED_VLONG_P(pEphemeral)) ||
                 0 != VLONG_compareSignedVlongs(COMPUTED_VLONG_G(pStatic), COMPUTED_VLONG_G(pEphemeral)) )
                 goto exit;

            /* calculate Z_s */
            status = DH_computeKeyExchangeExExt(MOC_DH(hwAccelCtx) pStatic, pRandomContext, pOtherPartysStatic, otherStaticLen, &pSS1, &ss1Len, NULL);
            if (OK != status)
                goto exit;

            /* calculate Z_e */
            status = DH_computeKeyExchangeExExt(MOC_DH(hwAccelCtx) pEphemeral, pRandomContext, pOtherPartysEphemeral, otherEphemeralLen, &pSS2, &ss2Len, NULL);
            if (OK != status)
                goto exit;
                 
            /* Z = Z_e Z_s */
            ssLen = ss1Len + ss2Len;
            status = DIGI_MALLOC((void **) &pSS, ssLen);
            if (OK != status)
                goto exit;

            status = DIGI_MEMCPY(pSS, pSS2, ss2Len);
            if (OK != status)
                goto exit;

            status = DIGI_MEMCPY(pSS + ss2Len, pSS1, ss1Len);
            if (OK != status)
                goto exit;

            /* Delete the ephemeral private key */
            status = VLONG_freeVlong(&COMPUTED_VLONG_Y(pEphemeral), NULL);
            if (OK != status)
                goto exit; 

            *ppSharedSecret = pSS; pSS = NULL;
            *pSharedSecretLen = ssLen;
            break;

        case MQV2:
 
            if (NULL == pStatic || NULL == pEphemeral || NULL == pOtherPartysStatic || NULL == pOtherPartysEphemeral)
                goto exit;

            if (NULL == COMPUTED_VLONG_P(pStatic) || NULL == COMPUTED_VLONG_G(pStatic) || 
                NULL == COMPUTED_VLONG_Q(pStatic) || NULL == COMPUTED_VLONG_Y(pStatic) || 
                NULL == COMPUTED_VLONG_F(pStatic) || 
                NULL == COMPUTED_VLONG_P(pEphemeral) || NULL == COMPUTED_VLONG_G(pEphemeral) ||
                NULL == COMPUTED_VLONG_Q(pEphemeral) || NULL == COMPUTED_VLONG_F(pEphemeral) )
                goto exit;
            
            /* P, G, Q all required for MQV */
            status = ERR_FF_DIFFERENT_FIELDS;
            if ( 0 != VLONG_compareSignedVlongs(COMPUTED_VLONG_P(pStatic), COMPUTED_VLONG_P(pEphemeral)) ||
                 0 != VLONG_compareSignedVlongs(COMPUTED_VLONG_G(pStatic), COMPUTED_VLONG_G(pEphemeral)) || 
                 0 != VLONG_compareSignedVlongs(COMPUTED_VLONG_Q(pStatic), COMPUTED_VLONG_Q(pEphemeral)) )
                 goto exit;

            status = DHMQV_generateSharedSecret(MOC_DH(hwAccelCtx) pStatic, pEphemeral, pOtherPartysStatic, otherStaticLen, 
                                                pOtherPartysEphemeral, otherEphemeralLen, &pSS, &ssLen);
            if (OK != status)
                goto exit;

            /* Delete the ephemeral private key */
            status = VLONG_freeVlong(&COMPUTED_VLONG_Y(pEphemeral), NULL);
            if (OK != status)
                goto exit; 

            *ppSharedSecret = pSS; pSS = NULL;
            *pSharedSecretLen = ssLen;
            break;

        case DH_EPHEMERAL:

            if (NULL == pEphemeral || NULL == pOtherPartysEphemeral)
                goto exit;
            
            /* calculate Z = Z_e */
            status = DH_computeKeyExchangeExExt(MOC_DH(hwAccelCtx) pEphemeral, pRandomContext, pOtherPartysEphemeral, otherEphemeralLen, &pSS, &ssLen, NULL);
            if (OK != status)
                goto exit;

            /* Delete the ephemeral private key */
            status = VLONG_freeVlong(&COMPUTED_VLONG_Y(pEphemeral), NULL);
            if (OK != status)
                goto exit; 

            *ppSharedSecret = pSS; pSS = NULL;
            *pSharedSecretLen = ssLen;
            break;
            
        case DH_HYBRID_ONE_FLOW_U:

            if (NULL == pStatic || NULL == pEphemeral || NULL == pOtherPartysStatic)
                goto exit;

            /* rest of needed props will be checked in DH_computeKeyExchangeExExt */
            if (NULL == COMPUTED_VLONG_P(pStatic) || NULL == COMPUTED_VLONG_G(pStatic) || 
                NULL == COMPUTED_VLONG_P(pEphemeral) || NULL == COMPUTED_VLONG_G(pEphemeral) )
                goto exit;
            
            status = ERR_FF_DIFFERENT_FIELDS;
            if ( 0 != VLONG_compareSignedVlongs(COMPUTED_VLONG_P(pStatic), COMPUTED_VLONG_P(pEphemeral)) ||
                 0 != VLONG_compareSignedVlongs(COMPUTED_VLONG_G(pStatic), COMPUTED_VLONG_G(pEphemeral)) )
                 goto exit;
            
            /* calculate Z_s */
            status = DH_computeKeyExchangeExExt(MOC_DH(hwAccelCtx) pStatic, pRandomContext, pOtherPartysStatic, otherStaticLen, &pSS1, &ss1Len, NULL);
            if (OK != status)
                goto exit;

            /* calculate Z_e */
            status = DH_computeKeyExchangeExExt(MOC_DH(hwAccelCtx) pEphemeral, pRandomContext, pOtherPartysStatic, otherStaticLen, &pSS2, &ss2Len, NULL);
            if (OK != status)
                goto exit;
                             
            /* Z = Z_e Z_s */
            ssLen = ss1Len + ss2Len;
            status = DIGI_MALLOC((void **) &pSS, ssLen);
            if (OK != status)
                goto exit;

            status = DIGI_MEMCPY(pSS, pSS2, ss2Len);
            if (OK != status)
                goto exit;

            status = DIGI_MEMCPY(pSS + ss2Len, pSS1, ss1Len);
            if (OK != status)
                goto exit;

            /* Delete the ephemeral private key */
            status = VLONG_freeVlong(&COMPUTED_VLONG_Y(pEphemeral), NULL);
            if (OK != status)
                goto exit; 

            *ppSharedSecret = pSS; pSS = NULL;
            *pSharedSecretLen = ssLen;
            break;

        case DH_HYBRID_ONE_FLOW_V:

            if (NULL == pStatic || NULL == pOtherPartysStatic || NULL == pOtherPartysEphemeral)
                goto exit;

            /* calculate Z_s */
            status = DH_computeKeyExchangeExExt(MOC_DH(hwAccelCtx) pStatic, pRandomContext, pOtherPartysStatic, otherStaticLen, &pSS1, &ss1Len, NULL);
            if (OK != status)
                goto exit;

            /* calculate Z_e */
            status = DH_computeKeyExchangeExExt(MOC_DH(hwAccelCtx) pStatic, pRandomContext, pOtherPartysEphemeral, otherEphemeralLen, &pSS2, &ss2Len, NULL);
            if (OK != status)
                goto exit;
                 
            /* Z = Z_e Z_s */
            ssLen = ss1Len + ss2Len;
            status = DIGI_MALLOC((void **) &pSS, ssLen);
            if (OK != status)
                goto exit;

            status = DIGI_MEMCPY(pSS, pSS2, ss2Len);
            if (OK != status)
                goto exit;

            status = DIGI_MEMCPY(pSS + ss2Len, pSS1, ss1Len);
            if (OK != status)
                goto exit;

            *ppSharedSecret = pSS; pSS = NULL;
            *pSharedSecretLen = ssLen;
            break;

        case MQV1_U:

            if (NULL == pStatic || NULL == pEphemeral || NULL == pOtherPartysStatic)
                goto exit;

            if (NULL == COMPUTED_VLONG_P(pStatic) || NULL == COMPUTED_VLONG_G(pStatic) || 
                NULL == COMPUTED_VLONG_Q(pStatic) || NULL == COMPUTED_VLONG_Y(pStatic) || 
                NULL == COMPUTED_VLONG_F(pStatic) || 
                NULL == COMPUTED_VLONG_P(pEphemeral) || NULL == COMPUTED_VLONG_G(pEphemeral) ||
                NULL == COMPUTED_VLONG_Q(pEphemeral) || NULL == COMPUTED_VLONG_F(pEphemeral) )
                goto exit;

            /* P, G, Q all required for MQV */
            status = ERR_FF_DIFFERENT_FIELDS;
            if ( 0 != VLONG_compareSignedVlongs(COMPUTED_VLONG_P(pStatic), COMPUTED_VLONG_P(pEphemeral)) ||
                 0 != VLONG_compareSignedVlongs(COMPUTED_VLONG_G(pStatic), COMPUTED_VLONG_G(pEphemeral)) ||
                 0 != VLONG_compareSignedVlongs(COMPUTED_VLONG_Q(pStatic), COMPUTED_VLONG_Q(pEphemeral)) )
                 goto exit;

            /* Use the other static key twice */
            status = DHMQV_generateSharedSecret(MOC_DH(hwAccelCtx) pStatic, pEphemeral, pOtherPartysStatic, otherStaticLen, 
                                                pOtherPartysStatic, otherStaticLen, &pSS, &ssLen);
            if (OK != status)
                goto exit;

            /* Delete the ephemeral private key */
            status = VLONG_freeVlong(&COMPUTED_VLONG_Y(pEphemeral), NULL);
            if (OK != status)
                goto exit; 

            *ppSharedSecret = pSS; pSS = NULL;
            *pSharedSecretLen = ssLen;
            break;

        case MQV1_V:

            if (NULL == pStatic || NULL == pOtherPartysStatic || NULL == pOtherPartysEphemeral)
                goto exit;

            if (NULL == COMPUTED_VLONG_P(pStatic) || NULL == COMPUTED_VLONG_G(pStatic) || 
                NULL == COMPUTED_VLONG_Q(pStatic) || NULL == COMPUTED_VLONG_Y(pStatic) || 
                NULL == COMPUTED_VLONG_F(pStatic) )
                goto exit; 

            /* use our static key twice */
            status = DHMQV_generateSharedSecret(MOC_DH(hwAccelCtx) pStatic, pStatic, pOtherPartysStatic, otherStaticLen, 
                                                pOtherPartysEphemeral, otherEphemeralLen, &pSS, &ssLen);
            if (OK != status)
                goto exit;

            *ppSharedSecret = pSS; pSS = NULL;
            *pSharedSecretLen = ssLen;
            break;

        case DH_ONE_FLOW_U:

            if (NULL == pEphemeral || NULL == pOtherPartysStatic)
                goto exit;
            
            /* calculate Z */
            status = DH_computeKeyExchangeExExt(MOC_DH(hwAccelCtx) pEphemeral, pRandomContext, pOtherPartysStatic, otherStaticLen, &pSS, &ssLen, NULL);
            if (OK != status)
                goto exit;

            /* Delete the ephemeral private key */
            status = VLONG_freeVlong(&COMPUTED_VLONG_Y(pEphemeral), NULL);
            if (OK != status)
                goto exit; 
                 
            *ppSharedSecret = pSS; pSS = NULL;
            *pSharedSecretLen = ssLen;

            break;

        case DH_ONE_FLOW_V:

            if (NULL == pStatic || NULL == pOtherPartysEphemeral)
                goto exit;

            /* calculate Z */
            status = DH_computeKeyExchangeExExt(MOC_DH(hwAccelCtx) pStatic, pRandomContext, pOtherPartysEphemeral, otherEphemeralLen, &pSS, &ssLen, NULL);
            if (OK != status)
                goto exit;
                 
            *ppSharedSecret = pSS; pSS = NULL;
            *pSharedSecretLen = ssLen;

            break;

        case DH_STATIC:

            if (NULL == pStatic || NULL == pOtherPartysStatic)
                goto exit;
            
            /* calculate Z = Z_s */
            status = DH_computeKeyExchangeExExt(MOC_DH(hwAccelCtx) pStatic, pRandomContext, pOtherPartysStatic, otherStaticLen, &pSS, &ssLen, NULL);
            if (OK != status)
                goto exit;
                 
            *ppSharedSecret = pSS; pSS = NULL;
            *pSharedSecretLen = ssLen;

            break;

        default:
            status = ERR_INVALID_ARG;
    }

exit:

    if (NULL != pSS)
    {
        (void) DIGI_MEMSET_FREE(&pSS, ssLen);
    }

    if (NULL != pSS1)
    {
        (void) DIGI_MEMSET_FREE(&pSS1, ss1Len);
    }

    if (NULL != pSS2)
    {
        (void) DIGI_MEMSET_FREE(&pSS2, ss2Len);
    }

    return status;
}
#endif /* __ENABLE_DIGICERT_DH_MODES__ */

/*------------------------------------------------------------------*/

extern MSTATUS DH_validateDomainParams(MOC_DH(hwAccelDescr hwAccelCtx) randomContext* pFipsRngCtx,
                                       diffieHellmanContext *pCtx, FFCHashType hashType, ubyte4 C,
                                       ubyte *pSeed, ubyte4 seedSize, intBoolean *pIsValid,
                                       ubyte4 *pPriKeyLen, vlong **ppVlongQueue)
{
    MSTATUS status = OK;
    
    /* methods called below will validate the appropriate input parameters are not NULL */
    
    if (NULL == pSeed) /* Ignore hashType, C, and seedLen*/
    {
        status = DH_verifySafePG(pCtx, pIsValid, pPriKeyLen, ppVlongQueue);
    }
    else
    {
        status = DH_verifyPQ_FIPS1864(MOC_DH(hwAccelCtx) pFipsRngCtx, pCtx, hashType, C,
                                      pSeed, seedSize, pIsValid, ppVlongQueue);
        if (OK != status)
            goto exit;
        if (!(*pIsValid))
            goto exit;
        
        /* And validate G is a generator */
        status = DH_verifyG(MOC_DH(hwAccelCtx) pCtx, pIsValid, ppVlongQueue);
        if (OK != status)
            goto exit;
        
        if (!(*pIsValid))
            goto exit;
        
        /* everything valid, set the pPriKeyLen if provided */
        if (NULL != pPriKeyLen)
            *pPriKeyLen = 28; /* For all FIPS 186-4 keys security strength s is 112 so min keyLen must be 224 bits or 28 bytes */
    }
    
exit:
    
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS DH_verifySafePG(diffieHellmanContext *pCtx, intBoolean *pIsValid, ubyte4 *pPriKeyLen, vlong **ppVlongQueue)
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte4 maxLen = 0;  /* we ignore maxLen, not realy necc for calling applications */
    
    if (NULL == pCtx || NULL == COMPUTED_VLONG_P(pCtx) || NULL == COMPUTED_VLONG_G(pCtx) || NULL == pIsValid || NULL == pPriKeyLen)
        goto exit;
    
    *pIsValid = FALSE;
    
    status = safeGroupMatch(COMPUTED_VLONG_P(pCtx), COMPUTED_VLONG_G(pCtx), pPriKeyLen, &maxLen, ppVlongQueue);
    if (OK == status)
    {
        *pIsValid = TRUE;
    }
    else if (ERR_FALSE == status)
    {
        status = OK;  /* pIsValid is still FALSE */
    }
    
exit:
    
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS DH_verifyPQ_FIPS1864(MOC_DH(hwAccelDescr hwAccelCtx) randomContext* pFipsRngCtx,
                                    diffieHellmanContext *pCtx, FFCHashType hashType, ubyte4 C,
                                    ubyte *pSeed, ubyte4 seedSize, intBoolean *pIsValid, vlong **ppVlongQueue)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = ERR_NULL_POINTER;
    vlong *pNewP = NULL;
    vlong *pNewQ = NULL;
    ubyte4 newC = 0;
    intBoolean isPrimePQ = FALSE;
    ubyte4 L = 0;
    ubyte4 Nin = 0;
    
    if (NULL == pFipsRngCtx || NULL == pCtx || NULL == COMPUTED_VLONG_P(pCtx) || NULL == COMPUTED_VLONG_Q(pCtx) || NULL == pIsValid) /* seed validated by the below call */
        goto exit;
    
    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_DH); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_DH,0);

    *pIsValid = FALSE;
    
    /*
     Get the actual bitlengths of P and Q, ie the bitlengths of their binary
     representations with a leading 1 (ie the most significant, leftmost bit, is 1)
     
     The least significant (rightmost) bit will be proven to be 1 once it is
     verified p and q are prime and bigger than 2.
     */
    L = VLONG_bitLength(COMPUTED_VLONG_P(pCtx));
    Nin = VLONG_bitLength(COMPUTED_VLONG_Q(pCtx));
    
    /* 5.5.1.1. Table 1 allowable FIPS 186 parameter sizes, NIST SPA 800-56A Rev 3  */
    if( !( (L == 2048 && Nin == 224) || (L == 2048 && Nin == 256) ) )
    {
        return ERR_DH_INVALID_KEYLENGTH;
    }
    status = FFC_computePQ_FIPS_1864(MOC_FFC(hwAccelCtx) pFipsRngCtx, &pNewP, &pNewQ, L, Nin,
                                     hashType, &newC, pSeed, seedSize, &isPrimePQ, ppVlongQueue);
    if (OK != status)
        goto exit;
    
    if (FALSE == isPrimePQ || newC != C || 0 != VLONG_compareSignedVlongs(COMPUTED_VLONG_P(pCtx), pNewP) || 0 != VLONG_compareSignedVlongs(COMPUTED_VLONG_Q(pCtx), pNewQ))
        goto exit;
    
    *pIsValid = TRUE;
    
exit:
    
    VLONG_freeVlong(&pNewP, ppVlongQueue); /* purposely ignore return code */
    VLONG_freeVlong(&pNewQ, ppVlongQueue);
    
    FIPS_LOG_END_ALG(FIPS_ALGO_DH,0);
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS DH_verifyG(MOC_DH(hwAccelDescr hwAccelCtx) diffieHellmanContext *pCtx, intBoolean *pIsValid, vlong **ppVlongQueue)
{
    if(NULL == pCtx)
        return ERR_NULL_POINTER;
    
    return FFC_verifyG(MOC_FFC(hwAccelCtx) COMPUTED_VLONG_P(pCtx), COMPUTED_VLONG_Q(pCtx), COMPUTED_VLONG_G(pCtx), pIsValid, ppVlongQueue);
}
#endif /* (!defined(__DIFFIE_HELLMAN_HARDWARE__)) && !defined(__DISABLE_DIGICERT_DIFFIE_HELLMAN__) */
