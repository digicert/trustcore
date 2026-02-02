/*
 * three_des.c
 *
 * 3DES Encipher & Decipher
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
@file       three_des.c
@brief      C source code for the NanoCrypto 3DES API.

@details    This file contains the NanoCrypto 3DES API functions.

@copydoc    overview_three_des

@flags
To enable the 3DES functions, the following flag must \b not be defined:
+ \c \__DISABLE_3DES_CIPHERS__

@filedoc    three_des.c
*/

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_TDES_INTERNAL__

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#if (!defined(__DISABLE_3DES_CIPHERS__))

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../crypto/des.h"
#include "../crypto/three_des.h"
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
#include "../crypto/fips.h"
#include "../crypto/fips_priv.h"
#endif


/*------------------------------------------------------------------*/


/**
@dont_show
@internal

Doc Note: This function is for Mocana internal white box testing, and
should not be included in the API documentation.
*/
extern MSTATUS
THREE_DES_initKey(ctx3des *p_3desContext, const ubyte *pKey, sbyte4 keyLen)
{
    MSTATUS status;

    if ((NULL == p_3desContext) || (NULL == pKey))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (THREE_DES_KEY_LENGTH != keyLen)
    {
        status = ERR_3DES_BAD_KEY_LENGTH;
        goto exit;
    }

    if (OK > (status = DES_initKey(&p_3desContext->firstKey,  pKey, DES_KEY_LENGTH)))
        goto exit;

    if (OK > (status = DES_initKey(&p_3desContext->secondKey, pKey+DES_KEY_LENGTH, DES_KEY_LENGTH)))
        goto exit;

    status = DES_initKey(&p_3desContext->thirdKey,  pKey+(DES_KEY_LENGTH*2), DES_KEY_LENGTH);

exit:
    return status;

} /* THREE_DES_initKey */


/*------------------------------------------------------------------*/

/**
@dont_show
@internal

Doc Note: This function is for Mocana internal white box testing, and
should not be included in the API documentation.
*/
extern MSTATUS
THREE_DES_encipher(ctx3des *p_3desContext, ubyte *pSrc, ubyte *pDest, ubyte4 numBytes)
{
    MSTATUS status;

    if ((NULL == p_3desContext) || (NULL == pSrc) || (NULL == pDest))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = DES_encipher(&p_3desContext->firstKey,  pSrc, pDest, numBytes);
    if (OK > status)
        goto exit;

    status = DES_decipher(&p_3desContext->secondKey, pDest, pDest, numBytes);
    if (OK > status)
        goto exit;

    status = DES_encipher(&p_3desContext->thirdKey,  pDest, pDest, numBytes);

exit:
    return status;

} /* THREE_DES_encipher */


/*------------------------------------------------------------------*/

/**
@dont_show
@internal

Doc Note: This function is for Mocana internal white box testing, and
should not be included in the API documentation.
*/
extern MSTATUS
THREE_DES_decipher(ctx3des *p_3desContext, ubyte *pSrc, ubyte *pDest, ubyte4 numBytes)
{
    MSTATUS status;

    if ((NULL == p_3desContext) || (NULL == pSrc) || (NULL == pDest))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = DES_decipher(&p_3desContext->thirdKey,  pSrc, pDest, numBytes);
    if (OK > status)
        goto exit;

    status = DES_encipher(&p_3desContext->secondKey, pDest, pDest, numBytes);
    if (OK > status)
        goto exit;

    status = DES_decipher(&p_3desContext->firstKey,  pDest, pDest, numBytes);

exit:
    return status;

} /* THREE_DES_decipher */

/*------------------------------------------------------------------*/

/**
@dont_show
@internal

Doc Note: This function is for Mocana internal white box testing, and
should not be included in the API documentation.
*/

extern MSTATUS
THREE_DES_clearKey(ctx3des *p_3desContext)
{
    MSTATUS status;

    if (NULL == p_3desContext)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = DIGI_MEMSET((ubyte *)p_3desContext, 0, sizeof(ctx3des));

exit:
    return status;

} /* THREE_DES_clearKey */

#if (!defined(__3DES_HARDWARE_CIPHER__))
/*------------------------------------------------------------------*/

extern BulkCtx
Create3DESCtx(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt)
{
    FIPS_LOG_DECL_SESSION;
    DES3Ctx* ctx = NULL;

    FIPS_GET_STATUS_RETURN_NULL_IF_BAD(FIPS_ALGO_3DES); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_3DES,keyLength);

   ctx = (DES3Ctx*) MALLOC(sizeof(DES3Ctx));

    if (NULL != ctx)
    {
        if (encrypt)
        {
            if (OK > THREE_DES_initKey(&(ctx->encryptKey), keyMaterial, keyLength))
            {
                FREE(ctx);  ctx = NULL;
            }
        }
        else
        {
            if (OK > THREE_DES_initKey(&(ctx->decryptKey), keyMaterial, keyLength))
            {
                FREE(ctx);  ctx = NULL;
            }
        }
    }

    FIPS_LOG_END_ALG(FIPS_ALGO_3DES,keyLength);
    return ctx;
}

/*------------------------------------------------------------------*/

extern MSTATUS
Delete3DESCtx(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *ctx)
{
    FIPS_LOG_DECL_SESSION;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_3DES); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_3DES,0);

    if (*ctx)
    {
#ifdef __ZEROIZE_TEST__
        int counter = 0;
        FIPS_PRINT("\nTES - Before Zeroization\n");
        for( counter = 0; counter < sizeof(DES3Ctx); counter++)
        {
            FIPS_PRINT("%x",*((ubyte*)*ctx+counter));
        }
        FIPS_PRINT("\n");
#endif
        /* Zeroize the sensitive information before deleting the memory */
        DIGI_MEMSET((ubyte*) *ctx,0x00,sizeof(DES3Ctx));
#ifdef __ZEROIZE_TEST__
        FIPS_PRINT("\nTES - After Zeroization\n");
        for( counter = 0; counter < sizeof(DES3Ctx); counter++)
        {
            FIPS_PRINT("%x",*((ubyte*)*ctx+counter));
        }
        FIPS_PRINT("\n");
#endif
        FREE(*ctx);
        *ctx = NULL;
    }

    FIPS_LOG_END_ALG(FIPS_ALGO_3DES,0);
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
Reset3DESCtx(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *ctx)
{
    MOC_UNUSED(ctx);

    return OK;
}

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS Do3DesCbcWithPkcs5Pad (
  MOC_SYM(hwAccelDescr hwAccelCtx)
  BulkCtx ctx,
  ubyte *pDataToProcess,
  ubyte4 dataLength,
  ubyte *pProcessedData,
  ubyte4 bufferSize,
  ubyte4 *pProcessedDataLen,
  sbyte4 encryptFlag,
  ubyte *pInitVector
  )
{
  FIPS_LOG_DECL_SESSION;
  MSTATUS status;
  ubyte4 bufSize, padLen, index;
  ubyte pTemp[THREE_DES_BLOCK_SIZE];

  FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_3DES); /* may return here */
  FIPS_LOG_START_ALG(FIPS_ALGO_3DES,0);

  status = ERR_NULL_POINTER;
  if ( (NULL == ctx) || (NULL == pDataToProcess) ||
       (NULL == pProcessedData) || (NULL == pInitVector) )
    goto exit;

  /* If the output buffer is NULL, the caller wants to know how big it needs to
   * be, so the bufSize is 0.
   */
  bufSize = 0;
  if (NULL != pProcessedData)
    bufSize = bufferSize;

  /* If encrypting, the output size will be the input size + padLen.
   * If decrypting, the output size is the input size. Yes, it will be shorter,
   * but we don't know how much shorter, so just make sure we have the max size
   * available.
   */
  padLen = dataLength % THREE_DES_BLOCK_SIZE;
  if (0 != encryptFlag)
  {
    /* If encrypting, padLen can be BLOCK_SIZE.
     */
    padLen = THREE_DES_BLOCK_SIZE - padLen;
  }
  else
  {
    /* If decrypting, the total length must be a multiple of BLOCK_SIZE.
     */
    status = ERR_3DES_BAD_LENGTH;
    if (0 != padLen)
      goto exit;
  }

  *pProcessedDataLen = dataLength + padLen;
  status = ERR_BUFFER_TOO_SMALL;
  if (bufSize < (dataLength + padLen))
    goto exit;

  /* We're going to call Do3DES, which operates in place. So we need to copy the
   * input data into the output buffer.
   * If encrypting, we'll append the pad bytes.
   */
  if (pDataToProcess != pProcessedData)
  {
    status = DIGI_MEMCPY (
      (void *)pProcessedData, (void *)pDataToProcess, dataLength);
    if (OK != status)
      goto exit;
  }

  if (0 != encryptFlag)
  {
    status = DIGI_MEMSET (
      (void *)(pProcessedData + dataLength), padLen, padLen);
    if (OK != status)
      goto exit;
  }

  /* The call to Do3DES overwrites the IV buffer, so copy the input IV into a
   * temp buffer so we don't overwrite the buffer the caller passed in.
   */
  status = DIGI_MEMCPY (
    (void *)pTemp, (void *)pInitVector, THREE_DES_BLOCK_SIZE);
  if (OK != status)
    goto exit;

  /* If encrypting, this is the last thing we need to do.
   */
  status = Do3DES (
    MOC_SYM (hwAccelCtx) ctx, pProcessedData, dataLength + padLen,
    encryptFlag, pTemp);
  if ( (OK != status) || (0 != encryptFlag) )
    goto exit;

  /* If we reach this point, we're decrypting, strip the pad bytes.
   * The last byte is the pad count.
   */
  padLen = pProcessedData[dataLength - 1];

  /* If the pad is incorrect, it probably means we used the wrong key. But return
   * PAD_PAD nonetheless.
   */
  status = ERR_CRYPTO_BAD_PAD;
  if ( (1 > padLen) || (8 < padLen) )
    goto exit;

  /* Make sure all pad bytes are the same value.
   */
  for (index = dataLength - padLen; index < dataLength; ++index)
  {
    if ((ubyte)padLen != pProcessedData[index])
      goto exit;
  }

  /* The actual data length to return is dataLength - padLen
   */
  *pProcessedDataLen = dataLength - padLen;

  status = OK;

exit:

  FIPS_LOG_END_ALG(FIPS_ALGO_3DES,0);
  return (status);
}

/*------------------------------------------------------------------*/

extern MSTATUS
Do3DES(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte* data, sbyte4 dataLength,
       sbyte4 encrypt, ubyte* iv)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_3DES); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_3DES,0);

    if (ctx)
    {
        DES3Ctx *p_3desContext = (DES3Ctx *)ctx;

        if (dataLength % THREE_DES_BLOCK_SIZE)
        {
            status = ERR_3DES_BAD_LENGTH;
            goto exit;
        }

        if (encrypt)
        {
            while (dataLength > 0)
            {
                /* XOR block with iv */
                sbyte4 i;

                for (i = 0; i < DES_BLOCK_SIZE; ++i)
                {
                    data[i] ^= iv[i];
                }

                /* encrypt */
                THREE_DES_encipher(&(p_3desContext->encryptKey), data, data, THREE_DES_BLOCK_SIZE);

                /* save into iv */
                DIGI_MEMCPY(iv, data, DES_BLOCK_SIZE);

                /* advance */
                dataLength -= DES_BLOCK_SIZE;
                data += DES_BLOCK_SIZE;
            }
        }
        else
        {
            while ( dataLength > 0)
            {
                sbyte4 i;
                ubyte nextIV[ DES_BLOCK_SIZE];

                /* save block in next IV */
                DIGI_MEMCPY( nextIV, data, DES_BLOCK_SIZE);

                /* decrypt */
                THREE_DES_decipher(&(p_3desContext->decryptKey), data, data, THREE_DES_BLOCK_SIZE);

                /* XOR with iv */
                for (i = 0; i < DES_BLOCK_SIZE; ++i)
                {
                    data[i] ^= iv[i];
                }

                /* put nextIV into iv */
                DIGI_MEMCPY(iv, nextIV, DES_BLOCK_SIZE);

                /* advance */
                dataLength -= DES_BLOCK_SIZE;
                data += DES_BLOCK_SIZE;
            }
        }
    }

exit:

    FIPS_LOG_END_ALG(FIPS_ALGO_3DES,0);
    return status;
}

#endif /* (!defined(__3DES_HARDWARE_CIPHER__)) */


/*------------------------------------------------------------------*/

extern MSTATUS
Clone3DESCtx(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, BulkCtx *ppNewCtx)
{
    MSTATUS status;
    DES3Ctx *pNewCtx = NULL;

    if ( (NULL == pCtx) || (NULL == ppNewCtx) )
    {
        return ERR_NULL_POINTER;
    }

    status = DIGI_MALLOC((void **)&pNewCtx, sizeof(DES3Ctx));
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY((void *)pNewCtx, (void *)pCtx, sizeof(DES3Ctx));
    if (OK != status)
        goto exit;

    *ppNewCtx = pNewCtx;
    pNewCtx = NULL;

exit:
    if (NULL != pNewCtx)
    {
        DIGI_FREE((void **)&pNewCtx);
    }

    return status;
}

/*------------------------------------------------------------------*/

#if (!defined(__DISABLE_3DES_TWO_KEY_CIPHER__))

/* support for 2keyTripleDes */
extern BulkCtx
Create2Key3DESCtx(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* keyMaterial,
                  sbyte4 keyLength, sbyte4 encrypt)
{
    FIPS_LOG_DECL_SESSION;
    BulkCtx *ptr = NULL;

    ubyte scratch[THREE_DES_KEY_LENGTH];

    FIPS_LOG_START_ALG(FIPS_ALGO_3DES,keyLength);

    if ((NULL == keyMaterial) || (keyLength != 2 * DES_KEY_LENGTH))
    {
        ptr = NULL;
        goto exit;
    }

    DIGI_MEMCPY( scratch, keyMaterial, 2 * DES_KEY_LENGTH);
    DIGI_MEMCPY( scratch + 2 * DES_KEY_LENGTH, keyMaterial, DES_KEY_LENGTH);

    ptr = Create3DESCtx( MOC_SYM(hwAccelCtx) scratch, THREE_DES_KEY_LENGTH, encrypt);

exit:
    FIPS_LOG_END_ALG(FIPS_ALGO_3DES,keyLength);
    return ptr;
}

#endif /* (!defined(__DISABLE_3DES_TWO_KEY_CIPHER__)) */
#endif /* (!defined(__DISABLE_3DES_CIPHERS__)) */
