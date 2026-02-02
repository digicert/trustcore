/*
 * nist_kdf.c
 *
 * KDF  NIST 800-108
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


/*------------------------------------------------------------------*/

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_NIST_KDF_INTERNAL__

#include "../common/moptions.h"

#ifndef __DISABLE_DIGICERT_NIST_KDF__

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../harness/harness.h"
#include "../crypto/nist_prf.h"
#include "../crypto/nist_kdf.h"


/*------------------------------------------------------------------*/

MSTATUS
KDF_NIST_CounterMode( MOC_SYM(hwAccelDescr hwAccelCtx)
                      ubyte4 counterSize, void* prfContext,
                      const PRF_NIST_108* prfAlgo,
                      const ubyte* label, ubyte4 labelSize,
                      const ubyte* context, ubyte4 contextSize,
                      ubyte4 keyMaterialEncodingSize, ubyte4 littleEndian,
                      ubyte* keyMaterial, ubyte4 keyMaterialSize)
{
    MSTATUS status;
    ubyte4 prfOutputSize, inputSize, allocSize = 0;
    ubyte4 i, j;
    ubyte* pTempBuf = 0;
    ubyte* resultBuffer;

    /* validate arguments */
    if (!prfContext || !prfAlgo || !keyMaterial)
    {
        return ERR_NULL_POINTER;
    }

    if (counterSize > 4 || 0 == counterSize)
    {
        return ERR_NIST_KDF_INVALID_COUNTER_SIZE;
    }

    if (OK > ( status = prfAlgo->outputSizeFunc( MOC_SYM(hwAccelCtx)
                                                prfContext,  &prfOutputSize)))
    {
        goto exit;
    }

    /* 1. compute number of iterations necessary */
    i = (keyMaterialSize + prfOutputSize - 1) / prfOutputSize;

    /* 2. verify counter size is big enough */
    if ( (counterSize < 4) && ((i >> (counterSize * 8)) != 0) )
    {
        status = ERR_NIST_KDF_COUNTER_KEY_SIZES;
        goto exit;
    }

    /* verify keyMaterialEncodingSize is big enough */
    if ( (keyMaterialEncodingSize < 4) &&
         ((keyMaterialSize >> (keyMaterialEncodingSize * 8)) != 0) )
    {
        status = ERR_NIST_KDF_COUNTER_KEY_SIZES;
        goto exit;
    }

    /* allocate a "CRYPTO" buffer for everything -- note that we ALWAYS use
        4 bytes big endian for the length -- 800-108 does not specify the encoding */

    if (!label)
    {
        labelSize = 0;
    }

    if (!context)
    {
        contextSize = 0;
    }

    inputSize = counterSize + labelSize + 1 + contextSize + keyMaterialEncodingSize;

    allocSize = inputSize + prfOutputSize;
    if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, allocSize, TRUE, &pTempBuf)))
    {
        goto exit;
    }

    /* set up fixed part of buffer */
    if (label)
    {
        DIGI_MEMCPY( pTempBuf + counterSize, label, labelSize);
    }
    pTempBuf[counterSize + labelSize] = 0x00;
    if (context)
    {
        DIGI_MEMCPY( pTempBuf + counterSize + labelSize + 1, context,
                    contextSize);
    }
    /* set length */
    if (littleEndian)
    {
        for (j = 0; j < keyMaterialEncodingSize; ++j)
        {
            pTempBuf[inputSize + j - keyMaterialEncodingSize] =
                (ubyte) ((keyMaterialSize*8) >> (j * 8) );
        }
    }
    else
    {
        for (j = 0; j < keyMaterialEncodingSize; ++j)
        {
            pTempBuf[inputSize + j - keyMaterialEncodingSize] =
                (ubyte) ((keyMaterialSize*8) >> ((keyMaterialEncodingSize - (j+1)) * 8) );
        }
    }
    resultBuffer = pTempBuf + inputSize;

    /* loop */
    for (i = 1; keyMaterialSize; ++i)
    {
        /* set counter */
        if (littleEndian)
        {
            for (j = 0; j < counterSize; ++j)
            {
                pTempBuf[j] = (ubyte) (i >> (j*8) );
            }
        }
        else
        {
            for (j = 0; j < counterSize; ++j)
            {
                pTempBuf[j] = (ubyte) (i >> ((counterSize - (j+1)) * 8) );
            }
        }

        if (OK > (status = prfAlgo->updateFunc( MOC_SYM(hwAccelCtx)
                                                prfContext, pTempBuf,
                                                inputSize)))
        {
            goto exit;
        }

        /* get the result at the end of the crypto buffer */
        if (OK > ( status = prfAlgo->finalFunc( MOC_SYM(hwAccelCtx)
                                                prfContext, resultBuffer)))
        {
            goto exit;
        }

        /* copy to result and increment loop counters */
        if (keyMaterialSize >= prfOutputSize)
        {
            DIGI_MEMCPY( keyMaterial, resultBuffer, prfOutputSize);
            keyMaterial += prfOutputSize;
            keyMaterialSize -= prfOutputSize;
        }
        else
        {
            DIGI_MEMCPY( keyMaterial, resultBuffer, keyMaterialSize);
            keyMaterialSize = 0;
        }
    }

exit:

    if (pTempBuf)
    {
        DIGI_MEMSET( pTempBuf, 0, allocSize);
        CRYPTO_FREE( hwAccelCtx, TRUE, &pTempBuf);
    }

    return status;
}


/*------------------------------------------------------------------*/

MSTATUS
KDF_NIST_FeedbackMode( MOC_SYM(hwAccelDescr hwAccelCtx)
                         ubyte4 counterSize, void* prfContext,
                         const PRF_NIST_108* prfAlgo,
                         const ubyte* iv, ubyte4 ivSize,
                         const ubyte* label, ubyte4 labelSize,
                         const ubyte* context, ubyte4 contextSize,
                         ubyte4 keyMaterialEncodingSize, ubyte4 littleEndian,
                         ubyte* keyMaterial, ubyte4 keyMaterialSize)
{
    MSTATUS status;
    ubyte4 prfOutputSize, headerSize, inputSize, allocSize = 0;
    ubyte4 i, j;
    ubyte* pTempBuf = 0;
    ubyte* resultBuffer;

    /* validate arguments */
    if (!prfContext || !prfAlgo || !keyMaterial)
    {
        return ERR_NULL_POINTER;
    }

    /* counter size can be 0 -- optional */
    if (counterSize > 4 )
    {
        return ERR_NIST_KDF_INVALID_COUNTER_SIZE;
    }

    /* verify keyMaterialEncodingSize is big enough */
    if ( (keyMaterialEncodingSize < 4) &&
         ((keyMaterialSize >> (keyMaterialEncodingSize * 8)) != 0) )
    {
        status = ERR_NIST_KDF_COUNTER_KEY_SIZES;
        goto exit;
    }

    if (OK > ( status = prfAlgo->outputSizeFunc( MOC_SYM(hwAccelCtx)
                                                prfContext,  &prfOutputSize)))
    {
        goto exit;
    }

    /* no need to check the counter size vs. keyMaterial size in this mode
       it can roll over */

    /* allocate a "CRYPTO" buffer for everything -- note that we ALWAYS use
        4 bytes big endian for the length -- 800-108 does not specify the encoding
        800-108 also does not specify the size of the IV */
    if (!iv)
    {
        ivSize = 0;
    }
    if (!label)
    {
        labelSize = 0;
    }
    if (!context)
    {
        contextSize = 0;
    }
    /* determine the headerSize */
    headerSize = (ivSize > prfOutputSize) ? ivSize : prfOutputSize;

    /* determine the inputSize */
    inputSize = counterSize + labelSize + 1 + contextSize + keyMaterialEncodingSize;

    allocSize = headerSize + inputSize;
    if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, allocSize, TRUE, &pTempBuf)))
    {
        goto exit;
    }

    /* set up buffer -- 800-108 does not specify that the IV
    has any specific length  */
    if (label)
    {
        DIGI_MEMCPY( pTempBuf + counterSize, label, labelSize);
    }
    pTempBuf[counterSize + labelSize] = 0x00;
    if (context)
    {
        DIGI_MEMCPY( pTempBuf + counterSize + labelSize + 1, context,
                    contextSize);
    }
    /* set length */
    if (littleEndian)
    {
        for (j = 0; j < keyMaterialEncodingSize; ++j)
        {
            pTempBuf[inputSize + j - keyMaterialEncodingSize] =
                (ubyte) ((keyMaterialSize*8) >> (j * 8) );
        }
    }
    else
    {
        for (j = 0; j < keyMaterialEncodingSize; ++j)
        {
            pTempBuf[inputSize + j - keyMaterialEncodingSize] =
                (ubyte) ((keyMaterialSize*8) >> ((keyMaterialEncodingSize - (j+1)) * 8) );
        }
    }

    resultBuffer = pTempBuf + inputSize; /* also header buffer */

    if (iv)
    {
        DIGI_MEMCPY( resultBuffer, iv, ivSize);
    }

    /* loop */
    for (i = 1; keyMaterialSize; ++i)
    {
        if (ivSize)
        {
            if (OK > (status = prfAlgo->updateFunc( MOC_SYM(hwAccelCtx)
                                            prfContext, resultBuffer,
                                            ivSize)))
            {
                goto exit;
            }
        }

        /* set counter */
        if (littleEndian)
        {
            for (j = 0; j < counterSize; ++j)
            {
                pTempBuf[j] = (ubyte) (i >> (j*8) );
            }
        }
        else
        {
            for (j = 0; j < counterSize; ++j)
            {
                pTempBuf[j] = (ubyte) (i >> ((counterSize - (j+1)) * 8) );
            }
        }


        /* send the rest */
        if (OK > (status = prfAlgo->updateFunc( MOC_SYM(hwAccelCtx)
                                                prfContext, pTempBuf,
                                                inputSize)))
        {
            goto exit;
        }

        /* get the result back into the header */
        if (OK > ( status = prfAlgo->finalFunc( MOC_SYM(hwAccelCtx)
                                                prfContext, resultBuffer)))
        {
            goto exit;
        }

        ivSize = prfOutputSize;


        /* copy to result and increment loop counters */
        if (keyMaterialSize >= prfOutputSize)
        {
            DIGI_MEMCPY( keyMaterial, resultBuffer, prfOutputSize);
            keyMaterial += prfOutputSize;
            keyMaterialSize -= prfOutputSize;
        }
        else
        {
            DIGI_MEMCPY( keyMaterial, resultBuffer, keyMaterialSize);
            keyMaterialSize = 0;
        }
    }

exit:

    if (pTempBuf)
    {
        DIGI_MEMSET( pTempBuf, 0, allocSize);
        CRYPTO_FREE( hwAccelCtx, TRUE, &pTempBuf);
    }

    return status;
}


/*-------------------------------------------------------------------*/

MSTATUS
KDF_NIST_DoublePipelineMode( MOC_SYM(hwAccelDescr hwAccelCtx)
                             ubyte4 counterSize, void* prfContext,
                             const PRF_NIST_108* prfAlgo,
                             const ubyte* label, ubyte4 labelSize,
                             const ubyte* context, ubyte4 contextSize,
                             ubyte4 keyMaterialEncodingSize, ubyte4 littleEndian,
                             ubyte* keyMaterial, ubyte4 keyMaterialSize)
{
    MSTATUS status;
    ubyte4 prfOutputSize, inputSize, allocSize = 0;
    ubyte4 i, j;
    ubyte* pTempBuf = 0;
    ubyte* resultBuffer;

    /* validate arguments */
    if (!prfContext || !prfAlgo || !keyMaterial)
    {
        return ERR_NULL_POINTER;
    }

    if (counterSize > 4)
    {
        return ERR_NIST_KDF_INVALID_COUNTER_SIZE;
    }

    /* verify keyMaterialEncodingSize is big enough */
    if ( (keyMaterialEncodingSize < 4) &&
         ((keyMaterialSize >> (keyMaterialEncodingSize * 8)) != 0) )
    {
        status = ERR_NIST_KDF_COUNTER_KEY_SIZES;
        goto exit;
    }

    if (OK > ( status = prfAlgo->outputSizeFunc( MOC_SYM(hwAccelCtx)
                                                prfContext,  &prfOutputSize)))
    {
        goto exit;
    }

    /* no need to check the counter size vs. keyMaterial size in this mode
       it can roll over */

    /* allocate a "CRYPTO" buffer for everything -- note that we ALWAYS use
        4 bytes big endian for the length -- 800-108 does not specify the encoding */

    if (!label)
    {
        labelSize = 0;
    }

    if (!context)
    {
        contextSize = 0;
    }

    inputSize = prfOutputSize + counterSize + labelSize + 1 +
                contextSize + keyMaterialEncodingSize;

    allocSize = inputSize + prfOutputSize;
    if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, allocSize, TRUE, &pTempBuf)))
    {
        goto exit;
    }

    /* set up fixed part of buffer */
    if (label)
    {
        DIGI_MEMCPY( pTempBuf + prfOutputSize + counterSize, label, labelSize);
    }
    pTempBuf[prfOutputSize + counterSize + labelSize] = 0x00;
    if (context)
    {
        DIGI_MEMCPY( pTempBuf + prfOutputSize + counterSize + labelSize + 1, context,
                    contextSize);
    }
    /* set length */
    if (littleEndian)
    {
        for (j = 0; j < keyMaterialEncodingSize; ++j)
        {
            pTempBuf[inputSize + j - keyMaterialEncodingSize] =
                (ubyte) ((keyMaterialSize*8) >> (j * 8) );
        }
    }
    else
    {
        for (j = 0; j < keyMaterialEncodingSize; ++j)
        {
            pTempBuf[inputSize + j - keyMaterialEncodingSize] =
                (ubyte) ((keyMaterialSize*8) >> ((keyMaterialEncodingSize - (j+1)) * 8) );
        }
    }

    resultBuffer = pTempBuf + inputSize;

    /* get the first value of A, A(0) = PRF (Label||0x00||Context||L2) */
    if (OK > (status = prfAlgo->updateFunc( MOC_SYM(hwAccelCtx)
                                            prfContext,
                                            pTempBuf + (prfOutputSize + counterSize),
                                            inputSize - (prfOutputSize+counterSize))))
    {
        goto exit;
    }

    /* get the result at the beginning of the crypto buffer */
    if (OK > ( status = prfAlgo->finalFunc( MOC_SYM(hwAccelCtx)
                                            prfContext, pTempBuf)))
    {
        goto exit;
    }

    /* loop */
    for (i = 1; keyMaterialSize; ++i)
    {
        /* A(i) = PRF(A(i-1)) */
        if (OK > (status = prfAlgo->updateFunc( MOC_SYM(hwAccelCtx)
                                                prfContext, pTempBuf,
                                                prfOutputSize)))
        {
            goto exit;
        }

        /* get the result back into the buffer */
        if (OK > ( status = prfAlgo->finalFunc( MOC_SYM(hwAccelCtx)
                                                prfContext, pTempBuf)))
        {
            goto exit;
        }

        /* 2nd PRF operation */
        /* set counter */
        if (littleEndian)
        {
            for (j = 0; j < counterSize; ++j)
            {
                pTempBuf[j+prfOutputSize] = (ubyte) (i >> (j*8) );
            }
        }
        else
        {
            for (j = 0; j < counterSize; ++j)
            {
                pTempBuf[j+prfOutputSize] = (ubyte) (i >> ((counterSize - (j+1)) * 8) );
            }
        }

        if (OK > (status = prfAlgo->updateFunc( MOC_SYM(hwAccelCtx)
                                                prfContext, pTempBuf,
                                                inputSize)))
        {
            goto exit;
        }

        /* get the result back at the end of the buffer */
        if (OK > ( status = prfAlgo->finalFunc( MOC_SYM(hwAccelCtx)
                                                prfContext, resultBuffer)))
        {
            goto exit;
        }

        /* copy to result and increment loop counters */
        if (keyMaterialSize >= prfOutputSize)
        {
            DIGI_MEMCPY( keyMaterial, resultBuffer, prfOutputSize);
            keyMaterial += prfOutputSize;
            keyMaterialSize -= prfOutputSize;
        }
        else
        {
            DIGI_MEMCPY( keyMaterial, resultBuffer, keyMaterialSize);
            keyMaterialSize = 0;
        }
    }

exit:

    if (pTempBuf)
    {
        DIGI_MEMSET( pTempBuf, 0, allocSize);
        CRYPTO_FREE( hwAccelCtx, TRUE, &pTempBuf);
    }

    return status;
}

#endif /* ifndef __DISABLE_DIGICERT_NIST_KDF__ */
