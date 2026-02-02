/*
 * smp_utils.c
 *
 * Security Module Provider utility function APIs
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
#include <sys/types.h>
#include <sys/stat.h>
#ifndef __RTOS_WIN32__
#include <unistd.h>
#endif /* __RTOS_WIN32__ */
#include <fcntl.h>
#if defined(__LINUX_RTOS__)
#include <signal.h>
#endif

#include "../../common/moptions.h"

#ifdef __ENABLE_DIGICERT_SMP__
#include "../../common/mtypes.h"
#include "../../common/mocana.h"
#include "../../common/mdefs.h"
#include "../../common/merrors.h"
#include "../../common/mrtos.h"
#include "../../common/mprintf.h"
#include "../../common/mtcp.h"
#include "../../common/mudp.h"
#include "../../common/mstdlib.h"
#include "../../common/vlong.h"
#include "../../common/random.h"
#include "../../common/prime.h"
#include "../../common/debug_console.h"
#include "../../common/memory_debug.h"
#include "../../common/moc_config.h"

#include "smp_utils.h"


/*------------------------------------------------------------------*/
MSTATUS TAP_UTILS_getMocanaError(ubyte4 smpErrorCode)
{
    MSTATUS errorCode = ERR_GENERAL;
    ubyte2  offset;

    if((smpErrorCode > 0x080) && (smpErrorCode < 0x100))
    {    
        offset = smpErrorCode - 0x080;
        errorCode = ERR_TAP_RC_FMT1 + offset;
    }

    if((smpErrorCode > 0x100) && (smpErrorCode < 0x900))
    {
        offset = smpErrorCode - 0x100;
        errorCode = ERR_TAP_RC_VER1 + offset;
    }
    if(smpErrorCode > 0x900)
    {
        offset = smpErrorCode - 0x900;
        errorCode = ERR_TAP_RC_WARN + offset;
    }

    return errorCode;
}


/*------------------------------------------------------------------*/

extern MSTATUS SMP_UTILS_freeBuffer(TAP_Buffer *pBuffer)
{
    MSTATUS status = OK;

    if (NULL == pBuffer)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL != pBuffer->pBuffer)
    {
        status = DIGI_FREE((void **)&(pBuffer->pBuffer));
        pBuffer->bufferLen = 0;
    }

exit:

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS SMP_UTILS_freePublicKey(TAP_PublicKey **ppPublicKey)
{
    MSTATUS status = OK;

    if ((NULL == ppPublicKey) || (NULL == *ppPublicKey))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = SMP_UTILS_freePublicKeyFields(*ppPublicKey);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to free public key fields. status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
    }

    status = DIGI_FREE((void **)ppPublicKey);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to free public key. status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
    }

exit:

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS SMP_UTILS_freePublicKeyFields(TAP_PublicKey *pPublicKey)
{
    MSTATUS status = OK;

    if (NULL == pPublicKey)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    switch (pPublicKey->keyAlgorithm)
    {
        case TAP_KEY_ALGORITHM_RSA:
            status = SMP_UTILS_freeRSAPublicKeyFields(&(pPublicKey->publicKey.rsaKey));
            break;
        case TAP_KEY_ALGORITHM_ECC:
            status = SMP_UTILS_freeECCPublicKeyFields(&(pPublicKey->publicKey.eccKey));
            break;
        case TAP_KEY_ALGORITHM_DSA:
            status = SMP_UTILS_freeDSAPublicKeyFields(&(pPublicKey->publicKey.dsaKey));
            break;
        default:
            status = ERR_TAP_INVALID_ALGORITHM;
            break;
    }
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to free algorithm-specific public key. status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
    }

    pPublicKey->keyAlgorithm = 0;

exit:

    return status;
}

/*------------------------------------------------------------------*/


extern MSTATUS SMP_UTILS_freeRSAPublicKeyFields(TAP_RSAPublicKey *pPublicKey)
{
    MSTATUS status = OK;

    if (NULL == pPublicKey)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL != pPublicKey->pModulus)
    {
        status = shredMemory((ubyte **)&(pPublicKey->pModulus), pPublicKey->modulusLen, TRUE);
        pPublicKey->modulusLen = 0;
    }

    if (NULL != pPublicKey->pExponent)
    {
        status = shredMemory((ubyte **)&(pPublicKey->pExponent), pPublicKey->exponentLen, TRUE);
        pPublicKey->exponentLen = 0;
    }

exit:

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS SMP_UTILS_freeECCPublicKeyFields(TAP_ECCPublicKey *pPublicKey)
{
    MSTATUS status = OK;

    if (NULL == pPublicKey)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL != pPublicKey->pPubX)
    {
        status = shredMemory((ubyte **)&(pPublicKey->pPubX), pPublicKey->pubXLen, TRUE);
        pPublicKey->pubXLen = 0;
    }

    if (NULL != pPublicKey->pPubY)
    {
        status = shredMemory((ubyte **)&(pPublicKey->pPubY), pPublicKey->pubYLen, TRUE);
        pPublicKey->pubYLen = 0;
    }

    pPublicKey->curveId = 0;

exit:

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS SMP_UTILS_freeDSAPublicKeyFields(TAP_DSAPublicKey *pPublicKey)
{
    MSTATUS status = OK;

    if (NULL == pPublicKey)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL != pPublicKey->pPrime)
    {
        status = shredMemory((ubyte **)&(pPublicKey->pPrime), pPublicKey->primeLen, TRUE);
        pPublicKey->primeLen = 0;
    }

    if (NULL != pPublicKey->pSubprime)
    {
        status = shredMemory((ubyte **)&(pPublicKey->pSubprime), pPublicKey->subprimeLen, TRUE);
        pPublicKey->subprimeLen = 0;
    }

    if (NULL != pPublicKey->pBase)
    {
        status = shredMemory((ubyte **)&(pPublicKey->pBase), pPublicKey->baseLen, TRUE);
        pPublicKey->baseLen = 0;
    }

    if (NULL != pPublicKey->pPubVal)
    {
        status = shredMemory((ubyte **)&(pPublicKey->pPubVal), pPublicKey->pubValLen, TRUE);
        pPublicKey->pubValLen = 0;
    }

exit:

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS SMP_UTILS_copyPublicKey(TAP_PublicKey *pDestKey, TAP_PublicKey *pSrcKey)
{
    MSTATUS status = OK;

    if ((NULL == pDestKey) || (NULL == pSrcKey))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pDestKey->keyAlgorithm = pSrcKey->keyAlgorithm;

    switch (pDestKey->keyAlgorithm)
    {
        case TAP_KEY_ALGORITHM_RSA:
            status = SMP_UTILS_copyRSAPublicKey(&(pDestKey->publicKey.rsaKey), &(pSrcKey->publicKey.rsaKey));
            break;
        case TAP_KEY_ALGORITHM_ECC:
            status = SMP_UTILS_copyECCPublicKey(&(pDestKey->publicKey.eccKey), &(pSrcKey->publicKey.eccKey));
            break;
        case TAP_KEY_ALGORITHM_DSA:
            status = SMP_UTILS_copyDSAPublicKey(&(pDestKey->publicKey.dsaKey), &(pSrcKey->publicKey.dsaKey));
            break;
        default:
            status = ERR_TAP_INVALID_ALGORITHM;
            break;
    }

    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy algorithm-specific public key. status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
    }

exit:

    return status;
}

/*------------------------------------------------------------------*/


extern MSTATUS SMP_UTILS_copyRSAPublicKey(TAP_RSAPublicKey *pDestKey, TAP_RSAPublicKey *pSrcKey)
{
    MSTATUS status = OK;

    if ((NULL == pDestKey) || (NULL == pSrcKey))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* copy modulus */
    pDestKey->modulusLen = pSrcKey->modulusLen;
    status = DIGI_CALLOC((void **)&(pDestKey->pModulus), 1, pDestKey->modulusLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to allocate memory. status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }
    status = DIGI_MEMCPY(pDestKey->pModulus, pSrcKey->pModulus, pDestKey->modulusLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy modulus. status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* copy exponent */
    pDestKey->exponentLen = pSrcKey->exponentLen;
    status = DIGI_CALLOC((void **)&(pDestKey->pExponent), 1, pDestKey->exponentLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to allocate memory. status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }
    status = DIGI_MEMCPY(pDestKey->pExponent, pSrcKey->pExponent, pDestKey->exponentLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy exponent. status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* copy schemes */
    pDestKey->encScheme = pSrcKey->encScheme;
    pDestKey->sigScheme = pSrcKey->sigScheme;


exit:

    return status;
}

/*------------------------------------------------------------------*/


extern MSTATUS SMP_UTILS_copyECCPublicKey(TAP_ECCPublicKey *pDestKey, TAP_ECCPublicKey *pSrcKey)
{
    MSTATUS status = OK;

    if ((NULL == pDestKey) || (NULL == pSrcKey))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* copy curve */
    pDestKey->curveId = pSrcKey->curveId;

    /* copy pPubX */
    pDestKey->pubXLen = pSrcKey->pubXLen;
    status = DIGI_CALLOC((void **)&(pDestKey->pPubX), 1, pDestKey->pubXLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to allocate memory. status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }
    status = DIGI_MEMCPY(pDestKey->pPubX, pSrcKey->pPubX, pDestKey->pubXLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy pPubX. status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* copy pPubY */
    pDestKey->pubYLen = pSrcKey->pubYLen;
    status = DIGI_CALLOC((void **)&(pDestKey->pPubY), 1, pDestKey->pubYLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to allocate memory. status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }
    status = DIGI_MEMCPY(pDestKey->pPubY, pSrcKey->pPubY, pDestKey->pubYLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy pPubY. status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* copy schemes */
    pDestKey->encScheme = pSrcKey->encScheme;
    pDestKey->sigScheme = pSrcKey->sigScheme;


exit:

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS SMP_UTILS_copyDSAPublicKey(TAP_DSAPublicKey *pDestKey, TAP_DSAPublicKey *pSrcKey)
{
    MSTATUS status = OK;

    if ((NULL == pDestKey) || (NULL == pSrcKey))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* copy prime */
    pDestKey->primeLen = pSrcKey->primeLen;
    status = DIGI_CALLOC((void **)&(pDestKey->pPrime), 1, pDestKey->primeLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to allocate memory. status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }
    status = DIGI_MEMCPY(pDestKey->pPrime, pSrcKey->pPrime, pDestKey->primeLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy pPrime. status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* copy subprime */
    pDestKey->subprimeLen = pSrcKey->subprimeLen;
    status = DIGI_CALLOC((void **)&(pDestKey->pSubprime), 1, pDestKey->subprimeLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to allocate memory. status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }
    status = DIGI_MEMCPY(pDestKey->pSubprime, pSrcKey->pSubprime, pDestKey->subprimeLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy pSubprime. status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* copy base */
    pDestKey->baseLen = pSrcKey->baseLen;
    status = DIGI_CALLOC((void **)&(pDestKey->pBase), 1, pDestKey->baseLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to allocate memory. status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }
    status = DIGI_MEMCPY(pDestKey->pBase, pSrcKey->pBase, pDestKey->baseLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy pBase. status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* copy pubVal */
    pDestKey->pubValLen = pSrcKey->pubValLen;
    status = DIGI_CALLOC((void **)&(pDestKey->pPubVal), 1, pDestKey->pubValLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to allocate memory. status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }
    status = DIGI_MEMCPY(pDestKey->pPubVal, pSrcKey->pPubVal, pDestKey->pubValLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy pPubVal. status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }


exit:

    return status;
}

#endif
