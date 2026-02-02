/*
 * dsa2.c
 *
 * DSA2
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

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_DSA_INTERNAL__

#include "../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_DSA__))
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mstdlib.h"
#include "../common/vlong.h"
#include "../common/random.h"
#include "../crypto/dsa.h"
#include "../crypto/dsa2.h"
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
#include "../crypto/fips.h"
#endif


/*--------------------------------------------------------------------------*/

extern MSTATUS
DSA_computeSignature2(MOC_DSA(hwAccelDescr hwAccelCtx)
                      RNGFun rngFun, void* rngArg,
                      const DSAKey *p_dsaDescr,
                      const ubyte* msg, ubyte4 msgLen,
                      vlong **ppR, vlong **ppS,
                      vlong **ppVlongQueue)
{
    MSTATUS status;
    ubyte4 qLen;
    vlong* m = 0;

    if (!rngFun || !p_dsaDescr || !msg || !ppR || !ppS)
        return ERR_NULL_POINTER;

    /* get the length of Q */
    qLen = (VLONG_bitLength( DSA_Q( p_dsaDescr)) + 7) / 8;

    /* truncate the message to qLen if necessary */
    if (qLen < msgLen)
    {
        msgLen = qLen;
    }

    if (OK > ( status = VLONG_vlongFromByteString( msg, msgLen, &m, ppVlongQueue)))
        goto exit;

    if (OK > ( status = DSA_computeSignatureEx( MOC_DSA(hwAccelCtx)
                                                rngFun, rngArg, p_dsaDescr, m,
                                                NULL, ppR, ppS, ppVlongQueue)))
    {
        goto exit;
    }

exit:

    VLONG_freeVlong( &m, ppVlongQueue);

    return status;
}


/*--------------------------------------------------------------------------*/

extern MSTATUS
DSA_verifySignature2(MOC_DSA(hwAccelDescr hwAccelCtx)
                       const DSAKey *p_dsaDescr,
                       const ubyte *msg, ubyte4 msgLen,
                       vlong *pR, vlong *pS,
                       intBoolean *isGoodSignature,
                       vlong **ppVlongQueue)
{
    MSTATUS status;
    ubyte4 qLen;
    vlong* m = 0;

    if (!p_dsaDescr || !msg || !pR || !pS || !isGoodSignature )
        return ERR_NULL_POINTER;

    /* get the length of Q */
    qLen = (VLONG_bitLength( DSA_Q( p_dsaDescr)) + 7) / 8;

    /* truncate the message to qLen if necessary */
    if (qLen < msgLen)
    {
        msgLen = qLen;
    }

    if (OK > ( status = VLONG_vlongFromByteString( msg, msgLen, &m, ppVlongQueue)))
        goto exit;

    if ( OK > (status = DSA_verifySignature(MOC_DSA(hwAccelCtx) p_dsaDescr, m, pR, pS,
                                            isGoodSignature, ppVlongQueue)))
    {
        goto exit;
    }

exit:

    VLONG_freeVlong( &m, ppVlongQueue);

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS DSA_computeSignature2Aux(MOC_DSA(hwAccelDescr hwAccelCtx) RNGFun rngFun, void *pRngArg, DSAKey *pKey, ubyte *pM, ubyte4 mLen,
                                       ubyte **ppR, ubyte4 *pRLen, ubyte **ppS, ubyte4 *pSLen, vlong **ppVlongQueue)
{
    MSTATUS status = ERR_NULL_POINTER;
    vlong *pRvlong = NULL;
    vlong *pSvlong = NULL;

    ubyte *pR = NULL;
    ubyte *pS = NULL;
    sbyte4 rsLen = 0;

    if (NULL == pKey || NULL == DSA_Q(pKey) || NULL == ppR || NULL == pRLen || NULL == ppS || NULL == pSLen) /* rng and pM checked by below call */
        goto exit;

    status = DSA_computeSignature2(MOC_DSA(hwAccelCtx) rngFun, pRngArg, pKey, pM, mLen, &pRvlong, &pSvlong, ppVlongQueue);
    if (OK != status)
        goto exit;

    rsLen = (ubyte4) (VLONG_bitLength(DSA_Q(pKey)) + 7) / 8;

    status = DIGI_MALLOC((void **) &pR, (ubyte4) rsLen);
    if (OK != status)
        goto exit;

    status = DIGI_MALLOC((void **) &pS, (ubyte4) rsLen);
    if (OK != status)
        goto exit;

    status = VLONG_byteStringFromVlong (pRvlong, pR, &rsLen);  /* This will zero pad to the correct length if needbe */
    if (OK != status)
        goto exit;

    status = VLONG_byteStringFromVlong (pSvlong, pS, &rsLen);
    if (OK != status)
        goto exit;

    /* all is good, set the output params */

    *ppR = pR; pR = NULL;
    *ppS = pS; pS = NULL;
    *pRLen = (ubyte4) rsLen;
    *pSLen = (ubyte4) rsLen;

exit:

    /* no need to chceck return values */
    (void) VLONG_freeVlong(&pRvlong, ppVlongQueue);
    (void) VLONG_freeVlong(&pSvlong, ppVlongQueue);

    if (NULL != pR)
    {
        (void) DIGI_MEMSET_FREE(&pR, rsLen);
    }

    if (NULL != pS)
    {
        (void) DIGI_MEMSET_FREE(&pS, rsLen);
    }

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS DSA_verifySignature2Aux(MOC_DSA(hwAccelDescr hwAccelCtx) DSAKey *pKey, ubyte *pM, ubyte4 mLen, ubyte *pR, ubyte4 rLen,
                                      ubyte *pS, ubyte4 sLen, intBoolean *pIsGoodSignature, vlong **ppVlongQueue)
{
    MSTATUS status = ERR_NULL_POINTER;
    vlong *pRvlong = NULL;
    vlong *pSvlong = NULL;

    if (NULL == pKey || NULL == DSA_Q(pKey) || NULL == pR || NULL == pS) /* pM and pIsGoodSignature checked by below call */
        goto exit;

    status = VLONG_vlongFromByteString(pR, rLen, &pRvlong, ppVlongQueue);
    if (OK != status)
        goto exit;

    status = VLONG_vlongFromByteString(pS, sLen, &pSvlong, ppVlongQueue);
    if (OK != status)
        goto exit;

    status = DSA_verifySignature2(MOC_DSA(hwAccelCtx) pKey, pM, mLen, pRvlong, pSvlong, pIsGoodSignature, ppVlongQueue);

exit:

    /* no need to chceck return values */
    (void) VLONG_freeVlong(&pRvlong, ppVlongQueue);
    (void) VLONG_freeVlong(&pSvlong, ppVlongQueue);

    return status;
}
#endif /* (defined(__ENABLE_DIGICERT_DSA__)) */
