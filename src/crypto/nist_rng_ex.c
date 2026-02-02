/*
 * nist_rng_ex.c
 *
 * RNG described in NIST SP800 90
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

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_NIST_CTR_DRBG_INTERNAL__


/*------------------------------------------------------------------*/

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../crypto/crypto.h"
#include "../common/random.h"
#include "../common/int64.h"
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
#include "../crypto/fips.h"
#endif

#include "../crypto/sha1.h"

#include "../harness/harness.h"
#include "../crypto/aesalgo.h"
#include "../crypto/aes.h"
#if (defined(__ENABLE_DIGICERT_AES_NI__) || defined(__ENABLE_DIGICERT_AES_NI_RUNTIME_CHECK__))
#include "../crypto/aesalgo_intel_ni.h"
#endif
#if !defined(__DISABLE_3DES_CIPHERS__)
#include "../crypto/des.h"
#include "../crypto/three_des.h"
#endif
#include "../crypto/nist_rng.h"
#include "../crypto/nist_rng_ex.h"

#include "../crypto/nist_rng_types.h"  /* This is to get the RandomContext data structures */

#ifndef __DISABLE_DIGICERT_NIST_CTR_DRBG__

/* Expose this API for nist_rng_ex.c */
#if defined(__RTOS_WIN32__)
MOC_EXTERN_DATA_DECL
#else
MOC_EXTERN
#endif
MSTATUS NIST_RNG_Init_Crypto_Ctx(MOC_SYM(hwAccelDescr hwAccelCtx)
                          NIST_CTR_DRBG_Ctx* pCtx);
/*-----------------------------------------------------------------------*/

MSTATUS NIST_CTRDRBG_generateSecret(MOC_SYM(hwAccelDescr hwAccelCtx) randomContext* pContext, ubyte *pAdditionalInput,
                                    ubyte4 additionalInputLen, ubyte *pSecret, ubyte4 secretLen)
{
    MSTATUS status = ERR_NULL_POINTER;
    RandomCtxWrapper *pWrapper = NULL;
    NIST_CTR_DRBG_Ctx *pCtx = NULL;
    ubyte4 stateLen;

    if (NULL == pContext || NULL == pSecret)
        goto exit;
    
    pWrapper = (RandomCtxWrapper *)pContext;
    pCtx = GET_CTR_DRBG_CTX(pWrapper);
    if (pCtx == NULL)
        goto exit;
    
    stateLen = pCtx->keyLenBytes + pCtx->outLenBytes;
    
    status = ERR_INVALID_ARG;
    if (secretLen < stateLen)
        goto exit;
    
    /* copy the state first */
    status = DIGI_MEMCPY(pSecret, pCtx->byteBuff, stateLen);
    if (OK != status)
        goto exit;

    /* increment to after the state, ok to modify passed by value params */
    pSecret += stateLen;
    secretLen -= stateLen;
    
    status = NIST_CTRDRBG_generate(MOC_SYM(hwAccelCtx) pContext, (const ubyte *) pAdditionalInput, additionalInputLen, pSecret, secretLen * 8);

exit:
    
    return status;
}

/*-----------------------------------------------------------------------*/

MSTATUS NIST_CTRDRBG_setStateFromSecret(MOC_SYM(hwAccelDescr hwAccelCtx) randomContext* pContext, ubyte *pAdditionalInput,
                                        ubyte4 additionalInputLen, ubyte *pSecret, ubyte4 secretLen)
{
    MSTATUS status = ERR_NULL_POINTER;
    RandomCtxWrapper *pWrapper = NULL;
    NIST_CTR_DRBG_Ctx *pCtx = NULL;
    ubyte4 stateLen;
    ubyte *pRecoveredGen = NULL;
    intBoolean differ;
    
    if (NULL == pContext || NULL == pSecret)
        goto exit;
    
    pWrapper = (RandomCtxWrapper *)pContext;
    pCtx = GET_CTR_DRBG_CTX(pWrapper);
    if (pCtx == NULL)
        goto exit;
    
    stateLen = pCtx->keyLenBytes + pCtx->outLenBytes;
    
    status = ERR_INVALID_ARG;
    if (secretLen < stateLen)
        goto exit;
    
    /* copy the state first */
    status = DIGI_MEMCPY(pCtx->byteBuff, pSecret, stateLen);
    if (OK != status)
        goto exit;
    
    /* update the block cipher key in its own context */
    status = NIST_RNG_Init_Crypto_Ctx(MOC_SYM(hwAccelCtx) pCtx);
    if (OK != status)
        goto exit;
    
    /* increment, ok to modify passed by value pointer */
    pSecret += stateLen;
    secretLen -= stateLen;
    
    status = DIGI_MALLOC((void **) &pRecoveredGen, secretLen);
    if (OK != status)
        goto exit;
    
    status = NIST_CTRDRBG_generate(MOC_SYM(hwAccelCtx) pContext, (const ubyte *) pAdditionalInput, additionalInputLen, pRecoveredGen, secretLen * 8);
    if (OK != status)
        goto exit;

    DIGI_CTIME_MATCH((void *) pRecoveredGen, (void *) pSecret, secretLen, &differ);
    /* ok to ignore DIGI_CTIME_MATCH return code */
    
    if (differ)
        status = ERR_FALSE; /* change fstatus once and for good */
    
exit:
    
    if (NULL != pRecoveredGen)
    {
        DIGI_MEMSET(pRecoveredGen, 0x00, secretLen); /* ok to ignore return codes, don't change status */
        DIGI_FREE((void **) &pRecoveredGen);
    }
    
    return status;
}

#endif /* ifndef __DISABLE_DIGICERT_NIST_CTR_DRBG__ */
