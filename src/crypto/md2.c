/*
 * md2.c
 *
 * Message Digest 2(MD2)
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

#include "../common/moptions.h"

#ifdef __ENABLE_DIGICERT_MD2__

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../crypto/md2.h"
#include "../harness/harness.h"

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
#include "../crypto/fips.h"
#include "../crypto/fips_priv.h"
#endif

/*------------------------------------------------------------------*/

/* Permutation of 0..255 constructed from the digits of pi. It gives a
   "random" nonlinear byte substitution operation.
 */
static ubyte PI_SUBST[256] = {
  41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161, 236, 240, 6,
  19, 98, 167, 5, 243, 192, 199, 115, 140, 152, 147, 43, 217, 188,
  76, 130, 202, 30, 155, 87, 60, 253, 212, 224, 22, 103, 66, 111, 24,
  138, 23, 229, 18, 190, 78, 196, 214, 218, 158, 222, 73, 160, 251,
  245, 142, 187, 47, 238, 122, 169, 104, 121, 145, 21, 178, 7, 63,
  148, 194, 16, 137, 11, 34, 95, 33, 128, 127, 93, 154, 90, 144, 50,
  39, 53, 62, 204, 231, 191, 247, 151, 3, 255, 25, 48, 179, 72, 165,
  181, 209, 215, 94, 146, 42, 172, 86, 170, 198, 79, 184, 56, 210,
  150, 164, 125, 182, 118, 252, 107, 226, 156, 116, 4, 241, 69, 157,
  112, 89, 100, 113, 135, 32, 134, 91, 207, 101, 230, 45, 168, 2, 27,
  96, 37, 173, 174, 176, 185, 246, 28, 70, 97, 105, 52, 64, 126, 15,
  85, 71, 163, 35, 221, 81, 175, 58, 195, 92, 249, 206, 186, 197,
  234, 38, 44, 83, 13, 110, 133, 40, 132, 9, 211, 223, 205, 244, 65,
  129, 77, 82, 106, 220, 55, 200, 108, 193, 171, 250, 36, 225, 123,
  8, 12, 189, 177, 74, 120, 136, 149, 139, 227, 99, 232, 109, 233,
  203, 213, 254, 59, 0, 29, 57, 242, 239, 183, 14, 102, 88, 208, 228,
  166, 119, 114, 248, 235, 117, 75, 10, 49, 68, 80, 180, 143, 237,
  31, 26, 219, 153, 141, 51, 159, 17, 131, 20
};


/*------------------------------------------------------------------*/

/* transforms state and updates checksum based on block */
static void MD2Transform(ubyte state[16], ubyte checksum[16],
                         const ubyte block[16])
{
    ubyte4 i, j, t;
    ubyte x[48];

    /* form hash block from state, block, state ^ block */
    DIGI_MEMCPY(x, state, 16);
    DIGI_MEMCPY(x+16, block, 16);
    for(i = 0; i < 16; i++)
    x[i+32] = (ubyte)(state[i] ^ block[i]);

    /* Hash block(18 rounds) */
    t = 0;
    for(i = 0; i < 18; i++)
    {
        for(j = 0; j < 48; j++)
            t = x[j] ^= PI_SUBST[t];

        t =(t + i) & 0xff;
    }

    /* save new state */
    DIGI_MEMCPY(state, x, 16);

    /* update checksum */
    t = checksum[15];
    for(i = 0; i < 16; i++)
    t = checksum[i] ^= PI_SUBST[block[i] ^ t];

    /* clear memory */
    DIGI_MEMSET(x, 0x00, sizeof(x));
}


/*------------------------------------------------------------------*/

extern MSTATUS
MD2Alloc(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context)
{
    return CRYPTO_ALLOC(hwAccelCtx, sizeof(MD2_CTX), TRUE, pp_context);
}


/*------------------------------------------------------------------*/

extern MSTATUS
MD2Free(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context)
{
    return CRYPTO_FREE(hwAccelCtx, TRUE, pp_context);
}


/*------------------------------------------------------------------*/

extern MSTATUS
MD2Init(MOC_HASH(hwAccelDescr hwAccelCtx) MD2_CTX *pContext)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;

    FIPS_LOG_START_ALG(NON_FIPS_ALGO_MD2,0); /* See code below */

    if(NULL == pContext)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pContext->count = 0;
    if(OK >(status = DIGI_MEMSET(pContext->state, 0x00, sizeof(pContext->state))))
        goto exit;

    status = DIGI_MEMSET(pContext->checksum, 0x00, sizeof(pContext->checksum));

exit:
    FIPS_LOG_END_ALG(NON_FIPS_ALGO_MD2,0); /* See code below */
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
MD2Update(MOC_HASH(hwAccelDescr hwAccelCtx) MD2_CTX *pContext,
          const ubyte *pInput, ubyte4 inputLen)
{
    FIPS_LOG_DECL_SESSION;
    ubyte4  i, index, partLen;
    MSTATUS status;

    FIPS_LOG_START_ALG(NON_FIPS_ALGO_MD2,0); /* See code below */

    if ((NULL == pContext) || (NULL == pInput))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* update number of bytes mod 16 */
    index = pContext->count;
    pContext->count =(index + inputLen) & 0xf;

    partLen = 16 - index;

    /* transform as many times as possible */
    if (inputLen >= partLen)
    {
        if (OK > (status = DIGI_MEMCPY(&pContext->buffer[index], pInput, partLen)))
            goto exit;

        MD2Transform(pContext->state, pContext->checksum, pContext->buffer);

        for (i = partLen; i + 15 < inputLen; i += 16)
            MD2Transform(pContext->state, pContext->checksum, &pInput[i]);

        index = 0;
    }
    else
    {
        i = 0;
    }

    /* buffer remaining pInput */
    status = DIGI_MEMCPY(&pContext->buffer[index], &pInput[i], inputLen-i);

exit:
    FIPS_LOG_END_ALG(NON_FIPS_ALGO_MD2,0); /* See code below */
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
MD2Final(MOC_HASH(hwAccelDescr hwAccelCtx) MD2_CTX *pContext, ubyte digest[16])
{
    FIPS_LOG_DECL_SESSION;
    ubyte   pad[16];
    ubyte4  index, padLen;
    MSTATUS status;

    FIPS_LOG_START_ALG(NON_FIPS_ALGO_MD2,0); /* See code below */

    if(NULL == pContext)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* pad out to multiple of 16 */
    index = pContext->count;
    padLen = 16 - index;

    if (OK > (status = DIGI_MEMSET(pad, (ubyte)padLen, padLen)))
        goto exit;

    if (OK > (status = MD2Update(MOC_HASH(hwAccelCtx) pContext, pad, padLen)))
        goto exit;

    /* Extend with checksum */
    if (OK > (status = MD2Update(MOC_HASH(hwAccelCtx) pContext, pContext->checksum, 16)))
        goto exit;

    /* Store state in digest */
    if (OK > (status = DIGI_MEMCPY(digest, pContext->state, 16)))
        goto exit;

    /* clear memory */
    status = DIGI_MEMSET((ubyte *)pContext, 0, sizeof(*pContext));

exit:
    FIPS_LOG_END_ALG(NON_FIPS_ALGO_MD2,0); /* See code below */
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
MD2_completeDigest(MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pData,
                   ubyte4 dataLen, ubyte *pOutput)
{
    FIPS_LOG_DECL_SESSION;
    MD2_CTX mdContext;
    MSTATUS status = OK;

    FIPS_LOG_START_ALG(NON_FIPS_ALGO_MD2,0); /* See code below */

    if (OK > (status = MD2Init(MOC_HASH(hwAccelCtx) &mdContext)))
        goto exit;

    if (OK > (status = MD2Update(MOC_HASH(hwAccelCtx) &mdContext, pData, dataLen)))
        goto exit;

    status = MD2Final(MOC_HASH(hwAccelCtx) &mdContext, pOutput);

exit:
    FIPS_LOG_END_ALG(NON_FIPS_ALGO_MD2,0); /* See code below */
    return status;
}

#endif /* __ENABLE_DIGICERT_MD2__ */
