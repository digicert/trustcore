/*
 * aes_ctr.c
 *
 * AES-CTR Implementation (RFC 3686)
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

/**
@file       aes_ctr.c
@brief      C source code for the NanoCrypto AES-CTR API.

@details    This file contains the NanoCrypto AES-CTR API functions.

@copydoc    overview_aes_ctr

@flags
There are no flag dependencies to enable the functions in this API.

@filedoc    aes_ctr.c

*/

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_CTR_INTERNAL__

/*------------------------------------------------------------------*/

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
#include "../crypto/fips.h"
#include "../crypto/fips_priv.h"
#endif
#include "../crypto/aes.h"
#include "../crypto/aes_ctr.h"

#if (!defined(__DISABLE_AES_CIPHERS__)) && (!defined(__DISABLE_AES_CTR_CIPHER__))

#include "../common/mrtos.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"
#include "../crypto/aesalgo.h"

#if (defined(__ENABLE_DIGICERT_AES_NI__) || defined(__ENABLE_DIGICERT_AES_NI_RUNTIME_CHECK__))
#include "../crypto/aesalgo_intel_ni.h"
#endif

#include "../crypto/aes_ecb.h"

/*------------------------------------------------------------------*/

/**
@private
@internal
@todo_add_ask    (In the 5.3.1 code but not documented; don't know why not)
@ingroup    aes_ctr_functions
*/
extern MSTATUS
AESCTRInit( MOC_SYM(hwAccelDescr hwAccelCtx) AES_CTR_Ctx* ctx,
            const ubyte* keyMaterial, sbyte4 keyLength,
            const ubyte initCounter[AES_BLOCK_SIZE])
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_AES_CTR); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_AES_CTR,keyLength);

    DIGI_MEMSET((ubyte *)ctx, 0x00, sizeof(aesCTRCipherContext));

    /* install the block */
    DIGI_MEMCPY( ctx->u.counterBlock, initCounter, AES_BLOCK_SIZE);

    ctx->pCtx = (aesCipherContext *) CreateAESECBCtx (
      MOC_SYM(hwAccelCtx) (ubyte *)keyMaterial, keyLength, 1);

    status = ERR_AES;
    if (NULL != ctx->pCtx)
        status = OK;

    FIPS_LOG_END_ALG(FIPS_ALGO_AES_CTR,keyLength);
    return (status);
}


/*------------------------------------------------------------------*/

extern BulkCtx
#ifdef __UCOS_DIRECT_RTOS__
CreateAESCTRCtx(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* keyMaterial,
                sbyte4 keyLength, sbyte4 encrypt)
#else
CreateAESCTRCtx(MOC_SYM(hwAccelDescr hwAccelCtx) const ubyte* keyMaterial,
                sbyte4 keyLength, sbyte4 encrypt)
#endif /* __UCOS_DIRECT_RTOS__ */
{
    FIPS_LOG_DECL_SESSION;
    aesCTRCipherContext *ctx = NULL;

    MOC_UNUSED(encrypt);

#if defined(__ENABLE_DIGICERT_AES_NI__)
    /* Do a runtime sanity check */
    /* With ENABLE_DIGICERT_AES_NI defined, we don't have the software option */
    if (!check_for_aes_instructions())
    {
        return NULL; /* returns NULL ctx */
    }
#endif

    FIPS_GET_STATUS_RETURN_NULL_IF_BAD(FIPS_ALGO_AES_CTR); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_AES_CTR,keyLength);

    ctx = (aesCTRCipherContext*) MALLOC(sizeof(aesCTRCipherContext));
    if (NULL != ctx)
    {
        keyLength -= AES_BLOCK_SIZE;
        if (OK > AESCTRInit(MOC_SYM(hwAccelCtx) ctx, keyMaterial,
                            keyLength, keyMaterial + keyLength))
        {
            FREE(ctx);  ctx = NULL;
        }
    }

    FIPS_LOG_END_ALG(FIPS_ALGO_AES_CTR,keyLength);
    return ctx;
}

/*------------------------------------------------------------------*/

extern MSTATUS
DeleteAESCTRCtx(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx* ctx)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;
    aesCTRCipherContext *pCtx;
#ifdef __ZEROIZE_TEST__
    int counter = 0;
#endif

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_AES_CTR); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_AES_CTR,0);

    if (NULL == ctx)
        goto exit;

    if (NULL  == (*ctx))
        goto exit;

    pCtx = (aesCTRCipherContext *)(*ctx);

#ifdef __ZEROIZE_TEST__
    counter = 0;
    FIPS_PRINT("\nAES - Before Zeroization\n");
    for( counter = 0; counter < sizeof(aesCTRCipherContext); counter++)
    {
        FIPS_PRINT("%02x",*((ubyte*)*ctx+counter));
    }
    FIPS_PRINT("\n");
#endif
    if (NULL != pCtx->pCtx)
    {
        DeleteAESECBCtx (MOC_SYM (hwAccelCtx) (BulkCtx *)&(pCtx->pCtx));
    }

    /* Zeroize the sensitive information before deleting the memory */
    DIGI_MEMSET((ubyte*)pCtx, 0x00, sizeof(aesCTRCipherContext));

#ifdef __ZEROIZE_TEST__
    FIPS_PRINT("\nAES - After Zeroization\n");
    for( counter = 0; counter < sizeof(aesCTRCipherContext); counter++)
    {
        FIPS_PRINT("%02x",*((ubyte*)*ctx+counter));
    }
    FIPS_PRINT("\n");
#endif

    FREE(*ctx);
    *ctx = NULL;

exit:

    FIPS_LOG_END_ALG(FIPS_ALGO_AES_CTR,0);
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
CloneAESCTRCtx(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, BulkCtx *ppNewCtx)
{
    MSTATUS status;
    aesCTRCipherContext *pNewCtx = NULL;
    aesCipherContext *pNewAesCtx = NULL;

    if ( (NULL == pCtx) || (NULL == ppNewCtx) )
    {
        return ERR_NULL_POINTER;
    }

    status = DIGI_MALLOC((void **)&pNewCtx, sizeof(aesCTRCipherContext));
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY((void *)pNewCtx, (void *)pCtx, sizeof(aesCTRCipherContext));
    if (OK != status)
        goto exit;

    status = DIGI_MALLOC((void **)&pNewAesCtx, sizeof(aesCipherContext));
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY((void *)pNewAesCtx, ((aesCTRCipherContext *)pCtx)->pCtx, sizeof(aesCipherContext));
    if (OK != status)
        goto exit;

    pNewCtx->pCtx = pNewAesCtx;
    pNewAesCtx = NULL;
    *ppNewCtx = pNewCtx;
    pNewCtx = NULL;

exit:
    if (NULL != pNewCtx)
    {
        DIGI_FREE((void **)&pNewCtx);
    }
    if (NULL != pNewAesCtx)
    {
        DIGI_FREE((void **)&pNewAesCtx);
    }

    return status;
}

/*------------------------------------------------------------------*/

static void
AESCTR_GetNewBlock( MOC_SYM(hwAccelDescr hwAccelCtx) aesCTRCipherContext* pCtx, sbyte4 limit)
{
    sbyte4 i;
    ubyte addend;

    limit = AES_BLOCK_SIZE - limit;
    /* encrypt the current block */
    AESALGO_blockEncryptEx (
      MOC_SYM (hwAccelCtx) pCtx->pCtx, NULL, pCtx->u.counterBlock, AES_BLOCK_SIZE * 8,
      pCtx->encBlock, &i);
    /* increment the block for next call -- time constant way */
    addend = 1;
    for ( i = AES_BLOCK_SIZE - 1; i >= limit; --i)
    {
        addend = (pCtx->u.counterBlock[i] += addend) ? 0 : addend;
    }
}


/*------------------------------------------------------------------*/

/**
@private
@internal
@todo_add_ask    (In the 5.3.1 code but not documented; don't know why not)
@ingroup    aes_ctr_functions
*/
extern MSTATUS
DoAESCTREx(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte* data, sbyte4 dataLength,
         sbyte4 encrypt, ubyte* iv, sbyte4 limit)
{
    FIPS_LOG_DECL_SESSION;
    aesCTRCipherContext*    pCtx = (aesCTRCipherContext *)ctx;
    sbyte4                  i;

    MOC_UNUSED(encrypt);

    if (NULL == pCtx)
        return ERR_NULL_POINTER;

    if ((NULL == data) && (0 < dataLength))
        return ERR_NULL_POINTER;

    if ( AES_BLOCK_SIZE < limit || limit < 0)
    {
        return ERR_INVALID_ARG;
    }

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_AES_CTR); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_AES_CTR,0);

    if (iv)
    {
        /* reset to new settings, if IV is not null */
        DIGI_MEMCPY(pCtx->u.counterBlock, iv, AES_BLOCK_SIZE);
        pCtx->offset = 0;
    }

	/* was there some bytes remaining from last call? */
	if ( pCtx->offset && dataLength > 0)
	{
		while (dataLength > 0 && pCtx->offset > 0)
		{
			*data++ ^= pCtx->encBlock[pCtx->offset];
            dataLength--;
			pCtx->offset++;
			if (AES_BLOCK_SIZE == pCtx->offset)
			{
				pCtx->offset = 0;
			}
		}
	}

	while ( dataLength >= AES_BLOCK_SIZE)
	{
#if defined(__ENABLE_DIGICERT_AES_NI__) || defined(__ENABLE_DIGICERT_AES_NI_RUNTIME_CHECK__)

		if (check_for_aes_instructions())
		{
			/* CTR data doesn't have to be a multiple of AES_BLOCK_SIZE     */
			/* So we are going to round up the number of blocks to handle   */
			/* the extra bytes                                              */
			/* Because the intel aesni will always encrypt an entire block  */
			/* I must encrypt into a temporary buffer so that I don't       */
			/* overrun the data buffer passed into the function             */
			/* Then I'll copy the result back into the data buffer using    */
			/* the exact dataLength                                         */

			/* Find the max number of blocks by rounding up */
			ubyte4 numBlocks = (dataLength+(AES_BLOCK_SIZE-1))/AES_BLOCK_SIZE;
			/* if the dataLength is a multiple of AES_BLOCK_SIZE      */
			/* then the intel aesni can process all of data           */
			/* But if there are some bytes left over, then those      */
			/* will have to be processed with the software version    */
			if (dataLength%AES_BLOCK_SIZE)
			{
				/* Only process the number of complete blocks */
				numBlocks--;
			}

			if (numBlocks)
			{
				aesNiEncDecCTR(pCtx->pCtx->rk, pCtx->pCtx->Nr, data, data, numBlocks, pCtx->u.counterBlock);

				/* move the data pointer and increment the dataLength */
				data += numBlocks*AES_BLOCK_SIZE;
				dataLength -= numBlocks*AES_BLOCK_SIZE;
			}
		}
		else
#endif
		{
			AESCTR_GetNewBlock( MOC_SYM(hwAccelCtx) pCtx, limit);
			/* XOR it with the data */
			for ( i = 0; i < AES_BLOCK_SIZE; ++i)
			{
				*data++ ^= pCtx->encBlock[i];
			}
			dataLength -= AES_BLOCK_SIZE;
		}
	}

	if ( dataLength > 0)
	{
		AESCTR_GetNewBlock( MOC_SYM(hwAccelCtx) pCtx, limit);
		/* XOR it with the data */
		for ( i = 0; (i < dataLength) && (i < AES_BLOCK_SIZE); ++i)
		{
			*data++ ^= pCtx->encBlock[i];
		}
		pCtx->offset = (ubyte)i;
	}

    FIPS_LOG_END_ALG(FIPS_ALGO_AES_CTR,0);
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
DoAESCTR(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt, ubyte* iv)
{
    return DoAESCTREx(MOC_SYM(hwAccelCtx) ctx, data, dataLength, encrypt, iv, AES_BLOCK_SIZE);
}

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS  GetCounterBlockAESCTR(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte pCounterBuffer[AES_BLOCK_SIZE])
{
    MSTATUS status = ERR_NULL_POINTER;
    aesCTRCipherContext *pCtx = (aesCTRCipherContext *)ctx;

    if ((NULL == pCtx) || (NULL == pCounterBuffer))
        goto exit;

    status = DIGI_MEMCPY(pCounterBuffer, pCtx->u.counterBlock, AES_BLOCK_SIZE);
    if (OK != status)
        goto exit;

    status = OK;
exit:
    return status;
}

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_IPSEC_SERVICE__

/**
@private
@internal
@todo_add_ask    (In the 5.3.1 code but not documented; don't know why not)
@ingroup    aes_ctr_functions
*/
extern BulkCtx
CreateAesCtrCtx(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* keyMaterial,
                sbyte4 keyLength, sbyte4 encrypt)
{
    FIPS_LOG_DECL_SESSION;
    aesCTRCipherContext *ctx = NULL;

    MOC_UNUSED(encrypt);
#if defined(__ENABLE_DIGICERT_AES_NI__)
    /* Do a runtime sanity check */
    /* With ENABLE_DIGICERT_AES_NI defined, we don't have the software option */
    if (!check_for_aes_instructions())
        return NULL;
#endif

    FIPS_GET_STATUS_RETURN_NULL_IF_BAD(FIPS_ALGO_AES_CTR); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_AES_CTR,(keyLength-4)); /* See below decrement */

    ctx = (aesCTRCipherContext*) MALLOC(sizeof(aesCTRCipherContext));
    if (NULL != ctx)
    {
        DIGI_MEMSET((ubyte *)ctx, 0x00, sizeof(aesCTRCipherContext));
        keyLength -= 4;

        /* Copy over the nonce. According to RFC 3686 the KEYMAT data (KEYMAT =
         * key material) will be [ key || nonce ] where the key can be 16, 24,
         * or 32 bytes and the nonce must be 4 bytes.
         */
        DIGI_MEMCPY(ctx->u.counterBlock, keyMaterial + keyLength, 4);

        /* RFC 3686 specifies that AES-CTR for IPsec must start with a block
         * counter of 1, so the block counter will be set here.
         */
        ctx->u.counterBlock[12] = 0x00;
        ctx->u.counterBlock[13] = 0x00;
        ctx->u.counterBlock[14] = 0x00;
        ctx->u.counterBlock[15] = 0x01;

        ctx->pCtx = (aesCipherContext *) CreateAESECBCtx(
            MOC_SYM(hwAccelCtx) keyMaterial, keyLength, 1);
        if (NULL == ctx->pCtx)
        {
            FREE(ctx);
            ctx = NULL;
        }
    }

    FIPS_LOG_END_ALG(FIPS_ALGO_AES_CTR,keyLength);
    return ctx;
}


/*------------------------------------------------------------------*/

/**
@private
@internal
@todo_add_ask    (In the 5.3.1 code but not documented; don't know why not.
                 Differs only in the signature's upper/lower-case usage from
                 the documented function, DoAESCTR().)
@ingroup    aes_ctr_functions
*/
extern MSTATUS
DoAesCtr(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte* data,
                         sbyte4 dataLength, sbyte4 encrypt, ubyte* iv)
{
    aesCTRCipherContext *pCtx = (aesCTRCipherContext *)ctx;

    /* install IV in the counter block */
    DIGI_MEMCPY(&(pCtx->u.counterBlock[4]), iv, 8);

    return DoAESCTREx(MOC_SYM(hwAccelCtx) ctx, data, dataLength, encrypt, NULL, AES_BLOCK_SIZE);
}


/*------------------------------------------------------------------*/

/**
@private
@internal
@todo_add_ask    (In the 5.3.1 code but not documented; don't know why not.
                 Differs only in the signature's upper/lower-case usage from
                 the documented function, DoAESCTR().)
@ingroup    aes_ctr_functions
*/
extern MSTATUS
DoAesCtrEx(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte* data,
                         sbyte4 dataLength, sbyte4 encrypt, ubyte* iv)
{
    aesCTRCipherContext *pCtx = (aesCTRCipherContext *)ctx;

    /* install IV in the counter block */
    DIGI_MEMCPY(&(pCtx->u.counterBlock[4]), iv, 8);
    /* reset the counter to 1 */
    pCtx->u.ctr[3] = 0;
    pCtx->u.counterBlock[AES_BLOCK_SIZE - 1] = 1;
    /* put the offset at 0 */
    pCtx->offset = 0;

    return DoAESCTREx(MOC_SYM(hwAccelCtx) ctx, data, dataLength, encrypt, NULL, AES_BLOCK_SIZE);
}

#endif /* __ENABLE_DIGICERT_IPSEC_SERVICE__ */


#endif /* (!defined(__DISABLE_AES_CIPHERS__) && !defined(__AES_HARDWARE_CIPHER__)) */
