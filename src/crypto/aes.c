/*
 * aes.c
 *
 * AES Implementation
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
@file       aes.c
@brief      C Source file for NanoCrypto AES symmetric cipher functions
            in CBC, CFB, and OFB modes.

@details    This file contains the NanoCrypto functions for AES symmetric cipher
            functions in CBC (Cipher Block Chaining), CFB (Cipher FeedBack), and
            OFB (Output FeedBack) modes.

@copydoc    overview_aes_ccm

@flags
To enable any of the functions in aes.{c,h}, the following flags must \b not
be defined in moptions.h:
+ \c \__DISABLE_AES_CIPHERS__
+ \c \__AES_HARDWARE_CIPHER__

@filedoc    aes.c
*/

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_INTERNAL__

/*------------------------------------------------------------------*/

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#if !defined(__DISABLE_AES_CIPHERS__) && !defined(__AES_HARDWARE_CIPHER__)

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"
#include "../crypto/aesalgo.h"
#include "../crypto/aes.h"
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
#include "../crypto/fips.h"
#include "../crypto/fips_priv.h"
#endif

#if (defined(__ENABLE_DIGICERT_AES_NI__) || defined(__ENABLE_DIGICERT_AES_NI_RUNTIME_CHECK__))
#include "../crypto/aesalgo_intel_ni.h"
#endif

/*------------------------------------------------------------------*/

MOC_EXTERN BulkCtx
CreateAESCtx(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt)
{
    FIPS_LOG_DECL_SESSION;
    aesCipherContext* ctx = NULL;

    FIPS_GET_STATUS_RETURN_NULL_IF_BAD(FIPS_ALGO_AES_CBC); /* may return here */

#if defined(__ENABLE_DIGICERT_AES_NI__)
    /* Do a runtime sanity check */
    /* With ENABLE_DIGICERT_AES_NI defined, we don't have the software option */
    if (!check_for_aes_instructions())
    {
        return NULL; /* returns NULL ctx */
    }
#endif

    FIPS_LOG_START_ALG(FIPS_ALGO_AES_CBC,keyLength);

    ctx = (aesCipherContext*) MALLOC(sizeof(aesCipherContext));

    if (NULL != ctx)
    {
        DIGI_MEMSET((ubyte *)ctx, 0x00, sizeof(aesCipherContext));

        if (OK > AESALGO_makeAesKeyEx (
          MOC_SYM (hwAccelCtx) ctx, 8 * keyLength, keyMaterial, encrypt, MODE_CBC))
        {
            FREE(ctx);  ctx = NULL;
        }
    }

    FIPS_LOG_END_ALG(FIPS_ALGO_AES_CBC,keyLength);
    return ctx;
}

/*------------------------------------------------------------------*/

extern BulkCtx
CreateAESCFBCtx(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt)
{
    FIPS_LOG_DECL_SESSION;
    aesCipherContext* ctx = NULL;

    FIPS_GET_STATUS_RETURN_NULL_IF_BAD(FIPS_ALGO_AES_CFB); /* may return here */

#if defined(__ENABLE_DIGICERT_AES_NI__)
    /* Do a runtime sanity check */
    /* With ENABLE_DIGICERT_AES_NI defined, we don't have the software option */
    if (!check_for_aes_instructions())
    	return NULL;
#endif

    FIPS_LOG_START_ALG(FIPS_ALGO_AES_CFB,keyLength);

    ctx = (aesCipherContext*) MALLOC(sizeof(aesCipherContext));

    if (NULL != ctx)
    {
        DIGI_MEMSET((ubyte *)ctx, 0x00, sizeof(aesCipherContext));

        if (OK > AESALGO_makeAesKeyEx (
          MOC_SYM (hwAccelCtx) ctx, 8 * keyLength, keyMaterial, encrypt, MODE_CFB128))
        {
            FREE(ctx);  ctx = NULL;
        }
    }

    FIPS_LOG_END_ALG(FIPS_ALGO_AES_CFB,keyLength);
    return ctx;
}

/*------------------------------------------------------------------*/

extern BulkCtx
CreateAESCFB1Ctx(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt)
{
    FIPS_LOG_DECL_SESSION;
    aesCipherContext* ctx = NULL;

    FIPS_GET_STATUS_RETURN_NULL_IF_BAD(FIPS_ALGO_AES_CFB); /* may return here */

#if defined(__ENABLE_DIGICERT_AES_NI__)
    /* Do a runtime sanity check */
    /* With ENABLE_DIGICERT_AES_NI defined, we don't have the software option */
    if (!check_for_aes_instructions())
    	return NULL;
#endif

    FIPS_LOG_START_ALG(FIPS_ALGO_AES_CFB,keyLength);

    ctx = (aesCipherContext*) MALLOC(sizeof(aesCipherContext));

    if (NULL != ctx)
    {
        DIGI_MEMSET((ubyte *)ctx, 0x00, sizeof(aesCipherContext));

        if (OK > AESALGO_makeAesKeyEx (
          MOC_SYM (hwAccelCtx) ctx, 8 * keyLength, keyMaterial, encrypt, MODE_CFB1))
        {
            FREE(ctx);  ctx = NULL;
        }
    }

    FIPS_LOG_END_ALG(FIPS_ALGO_AES_CFB,keyLength);
    return ctx;
}

/*------------------------------------------------------------------*/

extern BulkCtx
CreateAESOFBCtx(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt)
{
    FIPS_LOG_DECL_SESSION;
    aesCipherContext* ctx = NULL;

    FIPS_GET_STATUS_RETURN_NULL_IF_BAD(FIPS_ALGO_AES_OFB); /* may return here */

#if defined(__ENABLE_DIGICERT_AES_NI__)
    /* Do a runtime sanity check */
    /* With ENABLE_DIGICERT_AES_NI defined, we don't have the software option */
    if (!check_for_aes_instructions())
        return NULL; /* returns NULL ctx */
#endif

    FIPS_LOG_START_ALG(FIPS_ALGO_AES_OFB,keyLength);

    ctx = (aesCipherContext*) MALLOC(sizeof(aesCipherContext));

    if (NULL != ctx)
    {
        DIGI_MEMSET((ubyte *)ctx, 0x00, sizeof(aesCipherContext));

        if (OK > AESALGO_makeAesKeyEx (
          MOC_SYM (hwAccelCtx) ctx, 8 * keyLength, keyMaterial, encrypt, MODE_OFB))
        {
            FREE(ctx);  ctx = NULL;
        }
    }

    FIPS_LOG_END_ALG(FIPS_ALGO_AES_OFB,keyLength);
    return ctx;
}

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
DeleteAESCtx(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx* ctx)
{
    FIPS_LOG_DECL_SESSION;
    FIPS_LOG_DECL_FALGO;
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
    aesCipherContext* pAesContext = NULL;
#endif /* __ENABLE_DIGICERT_FIPS_MODULE__ */
#ifdef __ZEROIZE_TEST__
    int counter = 0;
#endif
    if (NULL == ctx)
        return OK; /* Nothing to do */

    if (*ctx)
    {
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
        pAesContext = (aesCipherContext *)*ctx;
        FIPS_GET_AES_FALGO(FAlgoId,pAesContext->mode);
        FIPS_GET_STATUS_RETURN_IF_BAD(FAlgoId); /* may return here */
        FIPS_LOG_START_ALG(FAlgoId,0);
#endif /* __ENABLE_DIGICERT_FIPS_MODULE__ */

#ifdef __ZEROIZE_TEST__
        counter = 0;
        FIPS_PRINT("\nAES - Before Zeroization\n");
        for( counter = 0; counter < sizeof(aesCipherContext); counter++)
        {
            FIPS_PRINT("%02x",*((ubyte*)*ctx+counter));
        }
        FIPS_PRINT("\n");
#endif
        /* Zeroize the sensitive information before deleting the memory */
        DIGI_MEMSET((ubyte*)*ctx,0x00,sizeof(aesCipherContext));
#ifdef __ZEROIZE_TEST__
        FIPS_PRINT("\nAES - After Zeroization\n");
        for( counter = 0; counter < sizeof(aesCipherContext); counter++)
        {
            FIPS_PRINT("%02x",*((ubyte*)*ctx+counter));
        }
        FIPS_PRINT("\n");
#endif
        FREE(*ctx);
        *ctx = NULL;

        FIPS_LOG_END_ALG(FAlgoId,0);
    }
    return OK;
}

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
DoAES(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt, ubyte* iv)
{
    FIPS_LOG_DECL_SESSION;
    FIPS_LOG_DECL_FALGO;
    sbyte4              retLength;
    aesCipherContext*   pAesContext = (aesCipherContext *)ctx;
    MSTATUS             status = OK;

    if (NULL == pAesContext || (MODE_ECB != pAesContext->mode && NULL == iv))
    {
        return ERR_NULL_POINTER;
    }

    FIPS_GET_AES_FALGO(FAlgoId,pAesContext->mode);
    FIPS_GET_STATUS_RETURN_IF_BAD(FAlgoId); /* may return here */
    FIPS_LOG_START_ALG(FAlgoId,0);

    if ((MODE_ECB == pAesContext->mode || MODE_CBC == pAesContext->mode) && 0 != (dataLength % AES_BLOCK_SIZE))
    {
        status = ERR_AES_BAD_LENGTH;
        goto exit;
    }

    if (encrypt)
      status = AESALGO_blockEncryptEx (
        MOC_SYM(hwAccelCtx) pAesContext, iv, data, 8 * dataLength, data, &retLength);
    else
      status = AESALGO_blockDecryptEx (
        MOC_SYM(hwAccelCtx) pAesContext, iv, data, 8 * dataLength, data, &retLength);

#ifdef __ENABLE_ALL_DEBUGGING__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_TRANSPORT, (sbyte *)"DoAES: cipher failed, error = ", status);
#endif

exit:
    FIPS_LOG_END_ALG(FAlgoId,0);
    return status;
}

extern MSTATUS AESALGO_makeAesKeyEx (
  MOC_SYM(hwAccelDescr hwAccelCtx)
  aesCipherContext *pAesContext,
  sbyte4 keyLen,
  const ubyte *keyMaterial,
  sbyte4 encrypt,
  sbyte4 mode
  )
{
  /* This is the software version, it just calls the old function.
   */
  return (AESALGO_makeAesKey (pAesContext, keyLen, keyMaterial, encrypt, mode));
}

/*------------------------------------------------------------------*/
/**
@private
@internal
@todo_add_ask    (New in .c file since 5.3.1; labeled as "internal
                  prototypes" in aes.h)
@ingroup    aes_cbc_functions
*/
extern MSTATUS
AESALGO_makeAesKey(aesCipherContext *pAesContext, sbyte4 keyLen, const ubyte *keyMaterial,
                   sbyte4 encrypt, sbyte4 mode)
{
    FIPS_LOG_DECL_SESSION;
    FIPS_LOG_DECL_FALGO;
    MSTATUS status = OK;

    if ((NULL == pAesContext) || (NULL == keyMaterial))
    {
        return ERR_NULL_POINTER;
    }

    FIPS_GET_AES_FALGO(FAlgoId,mode);
    FIPS_GET_STATUS_RETURN_IF_BAD(FAlgoId); /* may return here */
    FIPS_LOG_START_ALG(FAlgoId,(keyLen/8));

    if ((keyLen == 128) || (keyLen == 192) || (keyLen == 256))
    {
        pAesContext->keyLen = keyLen;
    }
    else
    {
        status = ERR_AES_BAD_KEY_LENGTH;
        goto exit;
    }

    pAesContext->encrypt = encrypt;
    pAesContext->mode = mode;


    /* special case here: */
    /* For CFB or OFB decrypt, we use enc key schedule to decrypt data. */
    if ((mode == MODE_CFB128) || (mode == MODE_CFB1) || (mode == MODE_OFB)) {
        encrypt = TRUE;
    }

    if (encrypt)
    {
        pAesContext->Nr = aesKeySetupEnc(pAesContext->rk, keyMaterial, keyLen);
    }
    else
    {
        pAesContext->Nr = aesKeySetupDec(pAesContext->rk, keyMaterial, keyLen);
    }

exit:
    FIPS_LOG_END_ALG(FAlgoId,(keyLen/8));
    return status;

} /* AESALGO_makeAesKey */

/*------------------------------------------------------------------*/

extern MSTATUS
CloneAESCtx(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, BulkCtx *ppNewCtx)
{
    MSTATUS status;
    aesCipherContext *pNewCtx = NULL;

    if ( (NULL == pCtx) || (NULL == ppNewCtx) )
    {
        return ERR_NULL_POINTER;
    }

    status = DIGI_MALLOC((void **)&pNewCtx, sizeof(aesCipherContext));
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY((void *)pNewCtx, (void *)pCtx, sizeof(aesCipherContext));
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

extern MSTATUS AESALGO_clearKey(aesCipherContext *pAesContext)
{
    MSTATUS status;

    if (NULL == pAesContext)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = DIGI_MEMSET((ubyte *)pAesContext, 0, sizeof(aesCipherContext));

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS ResetAESCtx(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *ctx)
{
    MOC_UNUSED(ctx);

    return OK;
}

#if !defined(__ENABLE_DIGICERT_AES_NI__) && !defined(__ENABLE_DIGICERT_AES_NI_RUNTIME_CHECK__)
/*------------------------------------------------------------------*/

extern MSTATUS AESALGO_blockEncryptEx (
  MOC_SYM(hwAccelDescr hwAccelCtx)
  aesCipherContext *pAesContext,
  ubyte* iv,
  ubyte *input,
  sbyte4 inputLen,
  ubyte *outBuffer,
  sbyte4 *pRetLength
  )
{
  /* This is the software version, it just calls the old function.
   */
  return (AESALGO_blockEncrypt (
    pAesContext, iv, input, inputLen, outBuffer, pRetLength));
}

/**
@private
@internal
@todo_add_ask    (New in .c file since 5.3.1; labeled as "internal
                  prototypes" in aes.h)
@ingroup    aes_cbc_functions
*/
extern MSTATUS
AESALGO_blockEncrypt(aesCipherContext *pAesContext, ubyte* iv,
                     ubyte *input, sbyte4 inputLen, ubyte *outBuffer,
                     sbyte4 *pRetLength)
{
    FIPS_LOG_DECL_SESSION;
    FIPS_LOG_DECL_FALGO;
    sbyte4  i, numBlocks;
    ubyte4  block[AES_BLOCK_SIZE/4];   /* use a ubyte4[] for alignment */
    MSTATUS status = OK;

    if ((NULL == pAesContext) || (NULL == input))
    {
        return ERR_NULL_POINTER;
    }

    FIPS_GET_AES_FALGO(FAlgoId,pAesContext->mode);
    FIPS_GET_STATUS_RETURN_IF_BAD(FAlgoId); /* may return here */
    FIPS_LOG_START_ALG(FAlgoId,0);

    if (FALSE == pAesContext->encrypt)
    {
        status = ERR_AES_BAD_OPERATION;
        goto exit;
    }

    /* AES_BLOCK_SIZE is in bytes, inputLen is in bits. */
    if (0 >= inputLen)
    {
        *pRetLength = 0;
        goto exit; /* nothing to do */
    }
    else if ( (MODE_ECB == pAesContext->mode || MODE_CBC == pAesContext->mode) && 0 != inputLen%(AES_BLOCK_SIZE*8) )
    {
        status = ERR_AES_BAD_LENGTH;
        *pRetLength = 0;
        goto exit;
    }

    numBlocks = inputLen/(AES_BLOCK_SIZE*8);

    switch (pAesContext->mode)
    {
        case MODE_ECB:
        {
            for (i = numBlocks; i > 0; i--)
            {
                aesEncrypt(pAesContext->rk, pAesContext->Nr, input, outBuffer);
                input += AES_BLOCK_SIZE;
                outBuffer += AES_BLOCK_SIZE;
            }
            break;
        }

        case MODE_CBC:
        {
            if ((NULL == iv))
            {
                status = ERR_NULL_POINTER;
                goto exit;
            }
#if __LONG_MAX__ == __INT_MAX__
            if ( (((ubyte4)(uintptr)input) | ((ubyte4)(uintptr)iv)) & 3) /* one or both are not aligned on 4 byte boundary */
#else
                if ( (((ubyte8)(uintptr)input) | ((ubyte8)(uintptr)iv)) & 3) /* one or both are not aligned on 4 byte boundary */
#endif
                {
                    for (i = numBlocks; i > 0; i--)
                    {
                        sbyte4 j;
                        for (j = 0; j < AES_BLOCK_SIZE; ++j)
                        {
                            ((ubyte*)block)[j] = (input[j] ^ iv[j]);
                        }
                        aesEncrypt(pAesContext->rk, pAesContext->Nr, (ubyte*) block, outBuffer);
                        DIGI_MEMCPY(iv, outBuffer, AES_BLOCK_SIZE);
                        input += AES_BLOCK_SIZE;
                        outBuffer += AES_BLOCK_SIZE;
                    }
                }
                else /* assume we can use 4 bytes ops */
                {
                    for (i = numBlocks; i > 0; i--)
                    {
                        block[0] = ((ubyte4*)input)[0] ^ ((ubyte4*)iv)[0];
                        block[1] = ((ubyte4*)input)[1] ^ ((ubyte4*)iv)[1];
                        block[2] = ((ubyte4*)input)[2] ^ ((ubyte4*)iv)[2];
                        block[3] = ((ubyte4*)input)[3] ^ ((ubyte4*)iv)[3];

                        aesEncrypt(pAesContext->rk, pAesContext->Nr, (ubyte*) block, outBuffer);
                        DIGI_MEMCPY(iv, outBuffer, AES_BLOCK_SIZE);
                        input += AES_BLOCK_SIZE;
                        outBuffer += AES_BLOCK_SIZE;
                    }
                }
            break;
        }

        case MODE_CFB1:
        {
            sbyte4 t;
            ubyte *tmpBlock = (ubyte*) block;
 
            DIGI_MEMCPY(outBuffer, input, ((inputLen+7)/8));
            for (i = 0; i < inputLen; i++) 
            {
                aesEncrypt(pAesContext->rk, pAesContext->Nr, iv, tmpBlock);
                outBuffer[i >> 3] ^= (tmpBlock[0] & 0x80U) >> (i & 7);
                for (t = 0; t < 15; t++) 
                {
                    iv[t] = (ubyte)((iv[t] << 1) | (iv[t + 1] >> 7));
                }
                iv[15] = (ubyte)((iv[15] << 1) | ((outBuffer[i >> 3] >> (7 - (i & 7))) & 1));
            }

            break;
        }

        case MODE_CFB128:
        {
            sbyte4 j;
            ubyte *tmpBlock = (ubyte*) block;
            sbyte4 leftOverBits = inputLen % 128;

            if(NULL == iv)
            {
                status = ERR_NULL_POINTER;
                goto exit;
            }

            for (i = numBlocks; i > 0; i--)
            {
                aesEncrypt(pAesContext->rk, pAesContext->Nr, iv, tmpBlock);
                for (j = 0; j< AES_BLOCK_SIZE; j++)
                {
                    iv[j] = input[j] ^ tmpBlock[j];
                }
                DIGI_MEMCPY(outBuffer, iv, AES_BLOCK_SIZE);
                outBuffer += AES_BLOCK_SIZE;
                input += AES_BLOCK_SIZE;
            }

            if (leftOverBits)
            {
                aesEncrypt(pAesContext->rk, pAesContext->Nr, iv, tmpBlock);
                for (j = 0; j < ((leftOverBits+7)/8); j++)
                {
                    outBuffer[j] = input[j] ^ tmpBlock[j];
                }
            }

            break;
        }

        case MODE_OFB:
        {
            sbyte4 j;
            ubyte *tmpBlock = (ubyte *) block;
            sbyte4 leftOverBits = inputLen % 128;

            if(NULL == iv)
            {
                status = ERR_NULL_POINTER;
                goto exit;
            }

            for (i = numBlocks; i > 0; i--)
            {
                aesEncrypt(pAesContext->rk, pAesContext->Nr, iv, tmpBlock);
                DIGI_MEMCPY(iv, tmpBlock, AES_BLOCK_SIZE);
                for (j = 0; j< AES_BLOCK_SIZE; j++)
                {
                    outBuffer[j] = input[j] ^ tmpBlock[j];
                }
                outBuffer += AES_BLOCK_SIZE;
                input += AES_BLOCK_SIZE;
            }

            if (leftOverBits)
            {
                aesEncrypt(pAesContext->rk, pAesContext->Nr, iv, tmpBlock);
                for (j = 0; j < ((leftOverBits+7)/8); j++)
                {
                    outBuffer[j] = input[j] ^ tmpBlock[j];
                }
            }

            break;
        }

        default:
        {
            status = ERR_AES_BAD_CIPHER_MODE;
            goto exit;
        }
    }

    *pRetLength = (128 * numBlocks);

exit:
    FIPS_LOG_END_ALG(FAlgoId,0);
    return status;

} /* AESALGO_blockEncrypt */


/*------------------------------------------------------------------*/

extern MSTATUS AESALGO_blockDecryptEx (
  MOC_SYM(hwAccelDescr hwAccelCtx)
  aesCipherContext *pAesContext,
  ubyte* iv,
  ubyte *input,
  sbyte4 inputLen,
  ubyte *outBuffer,
  sbyte4 *pRetLength
  )
{
  /* This is the software version, it just calls the old function.
   */
  return (AESALGO_blockDecrypt (
    pAesContext, iv, input, inputLen, outBuffer, pRetLength));
}

/**
@private
@internal
@todo_add_ask    (New in .c file since 5.3.1; labeled as "internal
                  prototypes" in aes.h)
@ingroup    aes_cbc_functions
*/
extern MSTATUS
AESALGO_blockDecrypt(aesCipherContext *pAesContext, ubyte* iv,
                     ubyte *input, sbyte4 inputLen, ubyte *outBuffer,
                     sbyte4 *pRetLength)
{
    FIPS_LOG_DECL_SESSION;
    FIPS_LOG_DECL_FALGO;
    sbyte4  i, numBlocks;
    ubyte4  block[AES_BLOCK_SIZE/4];  /* use a ubyte4[] for alignment */
    MSTATUS status = OK;

    if ((NULL == pAesContext) || (NULL == input))
    {
        return ERR_NULL_POINTER;
    }

    FIPS_GET_AES_FALGO(FAlgoId,pAesContext->mode);
    FIPS_GET_STATUS_RETURN_IF_BAD(FAlgoId); /* may return here */
    FIPS_LOG_START_ALG(FAlgoId,0);

    if ((pAesContext->mode != MODE_CFB1) && (pAesContext->encrypt))
    {
        status = ERR_AES_BAD_OPERATION;
        goto exit;
    }

    /* AES_BLOCK_SIZE is in bytes, inputLen is in bits. */
    if (0 >= inputLen)
    {
        *pRetLength = 0;
        goto exit; /* nothing to do */
    }
    else if ( (MODE_ECB == pAesContext->mode || MODE_CBC == pAesContext->mode) && 0 != inputLen%(AES_BLOCK_SIZE*8) )
    {
        status = ERR_AES_BAD_LENGTH;
        *pRetLength = 0;
        goto exit;
    }

    numBlocks = inputLen/(AES_BLOCK_SIZE*8);

    switch (pAesContext->mode)
    {
        case MODE_ECB:
        {
            for (i = numBlocks; i > 0; i--)
            {
                aesDecrypt(pAesContext->rk, pAesContext->Nr, input, outBuffer);
                input += AES_BLOCK_SIZE;
                outBuffer += AES_BLOCK_SIZE;
            }
            break;
        }

        case MODE_CBC:
        {
            if (NULL == iv)
            {
                status = ERR_NULL_POINTER;
                goto exit;
            }
#if __LONG_MAX__ == __INT_MAX__
            if ( ((ubyte4) (uintptr)iv) & 3)
#else
                if ( ((ubyte8) (uintptr)iv) & 3)
#endif
                {
                    for (i = numBlocks; i > 0; i--)
                    {
                        sbyte4 j;

                        aesDecrypt(pAesContext->rk, pAesContext->Nr, input, (ubyte*)block);
                        for (j = 0; j < AES_BLOCK_SIZE; ++j)
                        {
                            ((ubyte*)block)[j] ^= iv[j];
                        }
                        DIGI_MEMCPY(iv, input, AES_BLOCK_SIZE);
                        DIGI_MEMCPY(outBuffer, block, AES_BLOCK_SIZE);
                        input += AES_BLOCK_SIZE;
                        outBuffer += AES_BLOCK_SIZE;
                    }
                }
                else
                {
                    for (i = numBlocks; i > 0; i--)
                    {
                        aesDecrypt(pAesContext->rk, pAesContext->Nr, input, (ubyte*) block);

                        block[0] ^= ((ubyte4*)iv)[0];
                        block[1] ^= ((ubyte4*)iv)[1];
                        block[2] ^= ((ubyte4*)iv)[2];
                        block[3] ^= ((ubyte4*)iv)[3];

                        DIGI_MEMCPY(iv, input, AES_BLOCK_SIZE);
                        DIGI_MEMCPY(outBuffer, block, AES_BLOCK_SIZE);
                        input += AES_BLOCK_SIZE;
                        outBuffer += AES_BLOCK_SIZE;
                    }
                }
            break;
        }

        case MODE_CFB1:
        {
            sbyte4 t;
            ubyte *tmpBlock = (ubyte*) block;

            DIGI_MEMCPY(outBuffer, input, ((inputLen+7)/8));
            for (i = 0; i < inputLen; i++) {
                aesEncrypt(pAesContext->rk, pAesContext->Nr, iv, tmpBlock);
                for (t = 0; t < 15; t++) 
                {
                    iv[t] = (ubyte)((iv[t] << 1) | (iv[t + 1] >> 7));
                }
                iv[15] = (ubyte)((iv[15] << 1) | ((input[i >> 3] >> (7 - (i & 7))) & 1));
                outBuffer[i >> 3] ^= (tmpBlock[0] & 0x80U) >> (i & 7);
            }

            break;
        }

        case MODE_CFB128:
        {
            sbyte4 j;
            ubyte *tmpBlock = (ubyte *) block;
            sbyte4 leftOverBits = inputLen % 128;

            if(NULL == iv)
            {
                status = ERR_NULL_POINTER;
                goto exit;
            }

            for (i = numBlocks; i > 0; i--)
            {
                aesEncrypt(pAesContext->rk, pAesContext->Nr, iv, tmpBlock);
                for (j = 0; j< AES_BLOCK_SIZE; j++)
                {
                    iv[j] = input[j];   /* save curr input for next iv. */
                    outBuffer[j] = input[j] ^ tmpBlock[j];
                }
                outBuffer += AES_BLOCK_SIZE;
                input += AES_BLOCK_SIZE;
            }

            if (leftOverBits)
            {
                aesEncrypt(pAesContext->rk, pAesContext->Nr, iv, tmpBlock);
                for (j = 0; j < ((leftOverBits+7)/8); j++)
                {
                    outBuffer[j] = input[j] ^ tmpBlock[j];
                }
            }

            break;
        }

        case MODE_OFB:
        {
            sbyte4 j;
            ubyte *tmpBlock = (ubyte *) block;
            sbyte4 leftOverBits = inputLen % 128;

            if(NULL == iv)
            {
                status = ERR_NULL_POINTER;
                goto exit;
            }

            for (i = numBlocks; i > 0; i--)
            {
                aesEncrypt(pAesContext->rk, pAesContext->Nr, iv, tmpBlock);
                DIGI_MEMCPY(iv, tmpBlock, AES_BLOCK_SIZE);
                for (j = 0; j< AES_BLOCK_SIZE; j++)
                {
                    outBuffer[j] = input[j] ^ tmpBlock[j];
                }
                outBuffer += AES_BLOCK_SIZE;
                input += AES_BLOCK_SIZE;
            }

            if (leftOverBits)
            {
                aesEncrypt(pAesContext->rk, pAesContext->Nr, iv, tmpBlock);
                for (j = 0; j < ((leftOverBits+7)/8); j++)
                {
                    outBuffer[j] = input[j] ^ tmpBlock[j];
                }
            }

            break;
        }

        default:
        {
            status = ERR_AES_BAD_OPERATION;
            break;
        }
    }

    *pRetLength = (128 * numBlocks);

exit:
    FIPS_LOG_END_ALG(FAlgoId,0);
    return status;

} /* AESALGO_blockDecrypt */

#endif /* (!defined(__ENABLE_DIGICERT_AES_NI__) */

#endif /* (!defined(__DISABLE_AES_CIPHERS__) && !defined(__AES_HARDWARE_CIPHER__)) */
