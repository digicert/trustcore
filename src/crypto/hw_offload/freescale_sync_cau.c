/*
 * freescale_sync_cau.c
 *
 * Freescale Coldfire CAU Hardware Acceleration Synchronous Adapter
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


#include "../../common/moptions.h"

#if (defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) && defined(__ENABLE_FREESCALE_COLDFIRE_CAU_HARDWARE_ACCEL__))

#include <mqx.h>

#include "../../common/mtypes.h"
#include "../../common/mocana.h"
#include "../../common/merrors.h"
#include "../../common/int64.h"
#include "../../crypto/hw_accel.h"

#include "../../common/mdefs.h"
#include "../../common/mrtos.h"
#include "../../common/mtcp.h"
#include "../../common/mstdlib.h"
#include "../../common/debug_console.h"
#include "../../crypto/crypto.h"
#include "../../crypto/md45.h"
#include "../../crypto/md5.h"
#include "../../crypto/sha1.h"
#include "../../crypto/sha256.h"
#include "../../crypto/des.h"
#include "../../crypto/three_des.h"
#include "../../crypto/aes.h"

#include "../../harness/harness.h"

/* cau_api.h is part of the CAU/mmCAU package provided by Freescale.
   The include directive depends on where the file is copied/installed. */
#include "../../cau_api.h"

#define CAU_DEBUG

/*------------------------------------------------------------------*/

#define FSL_CAU_MAX_KEY_SIZE    (32)
#define LEN_64_MASK             0x0000003F

/*------------------------------------------------------------------*/

typedef struct
{
    sbyte4      encrypt;                            /* key used for encrypting or decrypting? */
    ubyte       key[FSL_CAU_MAX_KEY_SIZE];          /* raw key in this case */
    sbyte4      keyLength;                          /* length of the key (in bytes) */

    ubyte4      keySchedule[60];                    /* used by AES */
    int         nr;                                 /* used by AES */

} fslCipherContext;


/*------------------------------------------------------------------*/

static ubyte parityBitLookup[128] =
{
    1,0,0,1,0,1,1,0,0,1,1,0,1,0,0,1,0,1,1,0,1,0,0,1,1,0,0,1,0,1,1,0,
    0,1,1,0,1,0,0,1,1,0,0,1,0,1,1,0,1,0,0,1,0,1,1,0,0,1,1,0,1,0,0,1,
    0,1,1,0,1,0,0,1,1,0,0,1,0,1,1,0,1,0,0,1,0,1,1,0,0,1,1,0,1,0,0,1,
    1,0,0,1,0,1,1,0,0,1,1,0,1,0,0,1,0,1,1,0,1,0,0,1,1,0,0,1,0,1,1,0
};

/*------------------------------------------------------------------*/


#if FREESCALE_CAU_MUTEX_ENABLE 
static RTOS_MUTEX       fsl_cau_mutex = 0;
#define FREESCALE_CAU_MUTEX_WAIT()    RTOS_mutexWait(fsl_cau_mutex) 
#define FREESCALE_CAU_MUTEX_RELEASE() RTOS_mutexRelease(fsl_cau_mutex) 
#else
#define FREESCALE_CAU_MUTEX_WAIT()    {} 
#define FREESCALE_CAU_MUTEX_RELEASE() {} 
#endif

/*------------------------------------------------------------------*/

#ifdef __COLDFIRE__




/*
sbyte4 cau_aes_set_key(ubyte * keyMaterial, sbyte4 keyLength,ubyte4 * keySchedule );
sbyte4 cau_aes_encrypt(ubyte * tempBlock, ubyte4 * keySchedule, int nr, ubyte * pDest);
sbyte4 cau_aes_decrypt(ubyte * pSrc, ubyte4 * pKeySchedule, int nr, ubyte * pDest);
sbyte4 cau_des_encrypt(ubyte * pTempBlock,ubyte * key, ubyte * pDest );
sbyte4 cau_des_decrypt(ubyte * pSrc, ubyte * key, ubyte *pDest);
sbyte4 cau_md5_update(ubyte * cachedHashData, int i, ubyte4 * hashBlocks);
sbyte4 cau_sha1_update(ubyte * cachedHashData, int i, ubyte4 * hashBlocks);
*/

/*------------------------------------------------------------------*/

static void
fixupParityBits(ubyte *pKeyMaterial, sbyte4 keyLength)
{
    sbyte4 index;

    for (index = 0; index < keyLength; index++)
        pKeyMaterial[index] = ((pKeyMaterial[index] & 0xfe) | parityBitLookup[pKeyMaterial[index] >> 1]);
}


/*------------------------------------------------------------------*/

static fslCipherContext *
CreateCtxCommon(ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt)
{


    fslCipherContext* ctx = NULL;


    if (NULL == (ctx = MALLOC(sizeof(fslCipherContext))))
        goto exit;

    DIGI_MEMSET((ubyte *)ctx, 0x00, sizeof(fslCipherContext));
    DIGI_MEMCPY(&(ctx->key[0]), keyMaterial, keyLength);

    ctx->keyLength = keyLength;
    ctx->encrypt = encrypt;

exit:

    return ctx;
}


/*------------------------------------------------------------------*/


#if ((!defined(__DISABLE_AES_CIPHERS__)) && defined(__AES_HARDWARE_CIPHER__))
extern BulkCtx
CreateAESCtx(ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt)
{
    unsigned char * p_keySched;
    fslCipherContext*   ctx = NULL;


    if (!((16 == keyLength) || (24 == keyLength) || (32 == keyLength)))
        goto exit;  /* bad key size */

    if (NULL != (ctx = CreateCtxCommon(keyMaterial, keyLength, encrypt)))
    {

        /* setup key schedule based on key material */
        p_keySched = MALLOC(60*4);

        cau_aes_set_key(keyMaterial, 8 * keyLength, p_keySched );


        DIGI_MEMCPY(ctx->keySchedule,p_keySched,60*4);
        /* convert key length to number of AES rounds */
        ctx->nr = (8 + ((ctx->keyLength - 8) >> 2));

        FREE(p_keySched);
    }

exit:
    return (BulkCtx)ctx;
}
#endif /* ((!defined(__DISABLE_AES_CIPHERS__)) && defined(__AES_HARDWARE_CIPHER__)) */


/*------------------------------------------------------------------*/

#if ((!defined(__DISABLE_AES_CIPHERS__)) && defined(__AES_HARDWARE_CIPHER__))
static MSTATUS
FSL_CAU_AES_encipherCBC(fslCipherContext* pContext, ubyte4 keyLength, ubyte *pSrc,
                        ubyte *pDest, ubyte4 numBytes, ubyte *pIV)
{
    ubyte   tempBlock[AES_BLOCK_SIZE];
    ubyte4  blocks = numBytes / AES_BLOCK_SIZE;
    sbyte4  i;
    MSTATUS status = OK;


    if ((NULL == pContext) || (NULL == pSrc) || (NULL == pDest))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    while (0 < blocks)
    {
        /*!!!! code could be faster, if we cast to 4-byte pointers --- not sure if it will cause bus errors */
        /* make temp copy of block to encrypt */
        DIGI_MEMCPY(tempBlock, pSrc, AES_BLOCK_SIZE);

        /* tempBlock xor pIV */
        for (i = 0; i < AES_BLOCK_SIZE; i++)
            tempBlock[i] ^= pIV[i];

        cau_aes_encrypt(tempBlock, (unsigned char *)pContext->keySchedule, pContext->nr, pDest);

        /* copy encrypt block to iv */
        DIGI_MEMCPY(pIV, pDest, AES_BLOCK_SIZE);

        pSrc  += AES_BLOCK_SIZE;
        pDest += AES_BLOCK_SIZE;
        blocks--;
    }

exit:
    return status;

} /* FSL_CAU_AES_encipherCBC */
#endif


/*------------------------------------------------------------------*/

#if ((!defined(__DISABLE_AES_CIPHERS__)) && defined(__AES_HARDWARE_CIPHER__))
static MSTATUS
FSL_CAU_AES_decipherCBC(fslCipherContext* pContext, ubyte4 keyLength, ubyte *pSrc,
                        ubyte *pDest, ubyte4 numBytes, ubyte *pIV)
{
    ubyte   tempBlock[AES_BLOCK_SIZE];
    ubyte4  blocks = numBytes / AES_BLOCK_SIZE;
    sbyte4  i;
    MSTATUS status = OK;


    if ((NULL == pContext) || (NULL == pSrc) || (NULL == pDest))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    while (0 < blocks)
    {
        /*!!!! code could be faster, if we cast to 4-byte pointers --- not sure if it will cause bus errors */
        /* save a copy of block for IV */
        DIGI_MEMCPY(tempBlock, pSrc, AES_BLOCK_SIZE);

        cau_aes_decrypt(pSrc, (unsigned char *)pContext->keySchedule, pContext->nr, pDest);

        /* tempBlock xor pIV */
        for (i = 0; i < AES_BLOCK_SIZE; i++)
            pDest[i] ^= pIV[i];

        /* copy saved encrypt block to iv */
        DIGI_MEMCPY(pIV, tempBlock, AES_BLOCK_SIZE);

        pSrc  += AES_BLOCK_SIZE;
        pDest += AES_BLOCK_SIZE;
        blocks--;
    }

exit:
    return status;

} /* FSL_CAU_AES_decipherCBC */
#endif


/*------------------------------------------------------------------*/

#if ((!defined(__DISABLE_AES_CIPHERS__)) && defined(__AES_HARDWARE_CIPHER__))
extern MSTATUS
DoAES(BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt, ubyte* iv)
{
    MSTATUS status;


    if (0 != (dataLength % AES_BLOCK_SIZE))
    {
        status = ERR_AES_BAD_LENGTH;
        goto exit;
    }

    if (encrypt)
        status = FSL_CAU_AES_encipherCBC((fslCipherContext *)ctx, (/*FSL*/ubyte4)(((fslCipherContext *)ctx)->keyLength), data, data, (/*FSL*/ubyte4)dataLength, iv);
    else
        status = FSL_CAU_AES_decipherCBC((fslCipherContext *)ctx, (/*FSL*/ubyte4)(((fslCipherContext *)ctx)->keyLength), data, data, (/*FSL*/ubyte4)dataLength, iv);

#ifdef __ENABLE_ALL_DEBUGGING__
    if (OK > status)
        DEBUG_ERROR(DEBUG_CRYPTO, "DoDES: cipher failed, error = ", status);
#endif

exit:
    return status;
}
#endif /* ((!defined(__DISABLE_AES_CIPHERS__)) && defined(__AES_HARDWARE_CIPHER__)) */


/*------------------------------------------------------------------*/

#if ((!defined(__DISABLE_AES_CIPHERS__)) && defined(__AES_HARDWARE_CIPHER__))
extern MSTATUS
DeleteAESCtx(BulkCtx* ctx)
{


    if (*ctx)
    {
        FREE(*ctx);
        *ctx = NULL;
    }

    return OK;
}
#endif /* ((!defined(__DISABLE_AES_CIPHERS__)) && defined(__AES_HARDWARE_CIPHER__)) */


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DES_CIPHER__) && defined(__DES_HARDWARE_CIPHER__))
extern BulkCtx
CreateDESCtx(MOC_SYM(hwAccelDescr hwAccelCtx) const ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt)
{


    if ((DES_KEY_LENGTH != keyLength) || (NULL == keyMaterial))
        return NULL;  /* bad key size or material */


    fixupParityBits(keyMaterial, keyLength);

    return (BulkCtx)(CreateCtxCommon(keyMaterial, keyLength, encrypt));
}
#endif /* (defined(__ENABLE_DES_CIPHER__) && defined(__DES_HARDWARE_CIPHER__)) */


/*------------------------------------------------------------------*/

#if ((!defined(__DISABLE_3DES_CIPHERS__)) && defined(__3DES_HARDWARE_CIPHER__))
extern BulkCtx
Create3DESCtx(ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt)
{


    if ((THREE_DES_KEY_LENGTH != keyLength) || (NULL == keyMaterial))
        return NULL;  /* bad key size or material */

    fixupParityBits(keyMaterial, keyLength);

    return (BulkCtx)(CreateCtxCommon(keyMaterial, keyLength, encrypt));
}
#endif


/*------------------------------------------------------------------*/

#if (((( defined(__ENABLE_DES_CIPHER__))    && (defined( __DES_HARDWARE_CIPHER__)))) || \
     (((!defined(__DISABLE_3DES_CIPHERS__)) && (defined(__3DES_HARDWARE_CIPHER__)))) )
static MSTATUS
FSL_CAU_XDES_encipherCBC(fslCipherContext* p_desContext, ubyte4 keyLength, ubyte *pSrc,
                         ubyte *pDest, ubyte4 numBytes, ubyte *pIV)
{
    ubyte   tempBlock[DES_BLOCK_SIZE];
    ubyte4  blocks = numBytes / DES_BLOCK_SIZE;
    sbyte4  i;
    MSTATUS status = OK;


    if ((NULL == p_desContext) || (NULL == pSrc) || (NULL == pDest))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (keyLength != p_desContext->keyLength)
    {
        status = (DES_BLOCK_SIZE == keyLength) ? ERR_DES_BAD_KEY_LENGTH : ERR_3DES_BAD_KEY_LENGTH;
        goto exit;
    }

    while (0 < blocks)
    {
        /*!!!! code could be faster, if we cast to 4-byte pointers --- not sure if it will cause bus errors */
        /* make temp copy of block to encrypt */
        DIGI_MEMCPY(tempBlock, pSrc, DES_BLOCK_SIZE);

        /* tempBlock xor pIV */
        for (i = 0; i < DES_BLOCK_SIZE; i++)
            tempBlock[i] ^= pIV[i];

        cau_des_encrypt(tempBlock, p_desContext->key, pDest);

        if (DES_KEY_LENGTH < p_desContext->keyLength)
        {
            /* do 3des */

            cau_des_decrypt(pDest /* pSrc ? */, DES_KEY_LENGTH + p_desContext->key, pDest);
            cau_des_encrypt(pDest /* pSrc ? */, (2 * DES_KEY_LENGTH) + p_desContext->key, pDest);
        }

        /* copy encrypt block to iv */
        DIGI_MEMCPY( pIV, pDest, DES_BLOCK_SIZE);

        pSrc  += 8;
        pDest += 8;
        blocks--;
    }

exit:
    return status;

} /* FSL_CAU_XDES_encipherCBC */
#endif


/*------------------------------------------------------------------*/

#if (((( defined(__ENABLE_DES_CIPHER__))    && (defined( __DES_HARDWARE_CIPHER__)))) || \
     (((!defined(__DISABLE_3DES_CIPHERS__)) && (defined(__3DES_HARDWARE_CIPHER__)))) )
static MSTATUS
FSL_CAU_XDES_decipherCBC(fslCipherContext* p_desContext, ubyte4 keyLength, ubyte *pSrc,
                         ubyte *pDest, ubyte4 numBytes, ubyte *pIV)
{
    ubyte   tempBlock[DES_BLOCK_SIZE];
    ubyte4  blocks = numBytes / DES_BLOCK_SIZE;
    sbyte4  i;
    MSTATUS status = OK;


    if ((NULL == p_desContext) || (NULL == pSrc) || (NULL == pDest))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (keyLength != p_desContext->keyLength)
    {
        status = (DES_BLOCK_SIZE == keyLength) ? ERR_DES_BAD_KEY_LENGTH : ERR_3DES_BAD_KEY_LENGTH;
        goto exit;
    }

    while (0 < blocks)
    {
        /*!!!! code could be faster, if we cast to 4-byte pointers --- not sure if it will cause bus errors */
        /* save a copy of block for IV */
        DIGI_MEMCPY(tempBlock, pSrc, DES_BLOCK_SIZE);

        if (DES_KEY_LENGTH == p_desContext->keyLength)
        {
            /* regular des */
            cau_des_decrypt(pSrc, p_desContext->key, pDest);
        }
        else
        {
            /* do 3des */
            cau_des_decrypt(pSrc, (2 * DES_KEY_LENGTH) + p_desContext->key, pDest);
            cau_des_encrypt(pDest, DES_KEY_LENGTH + p_desContext->key, pDest);
            cau_des_decrypt(pDest, p_desContext->key, pDest);
        }

        /* tempBlock xor pIV */
        for (i = 0; i < DES_BLOCK_SIZE; i++)
            pDest[i] ^= pIV[i];

        /* copy saved encrypt block to iv */
        DIGI_MEMCPY(pIV, tempBlock, DES_BLOCK_SIZE);

        pSrc  += 8;
        pDest += 8;
        blocks--;
    }

exit:
    return status;

} /* FSL_CAU_XDES_decipherCBC */
#endif


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DES_CIPHER__) && defined(__DES_HARDWARE_CIPHER__))
extern MSTATUS
DoDES(BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt, ubyte* iv)
{
    MSTATUS status;

    if (0 != (dataLength % DES_BLOCK_SIZE))
    {
        status = ERR_DES_BAD_LENGTH;
        goto exit;
    }

    if (encrypt)
        status = FSL_CAU_XDES_encipherCBC((fslCipherContext *)ctx, DES_KEY_LENGTH, data, data, dataLength, iv);
    else
        status = FSL_CAU_XDES_decipherCBC((fslCipherContext *)ctx, DES_KEY_LENGTH, data, data, dataLength, iv);

#ifdef __ENABLE_ALL_DEBUGGING__
    if (OK > status)
        DEBUG_ERROR(DEBUG_CRYPTO, "DoDES: cipher failed, error = ", status);
#endif

exit:
    return status;
}
#endif


/*------------------------------------------------------------------*/

#if ((!defined(__DISABLE_3DES_CIPHERS__)) && defined(__3DES_HARDWARE_CIPHER__))
extern MSTATUS
Do3DES(BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt, ubyte* iv)
{
    MSTATUS status;


    if (0 != (dataLength % THREE_DES_BLOCK_SIZE))
    {
        status = ERR_3DES_BAD_LENGTH;
        goto exit;
    }

    if (encrypt)
        status = FSL_CAU_XDES_encipherCBC((fslCipherContext *)ctx, THREE_DES_KEY_LENGTH, data, data, (/*FSL*/ubyte4)dataLength, iv);
    else
        status = FSL_CAU_XDES_decipherCBC((fslCipherContext *)ctx, THREE_DES_KEY_LENGTH, data, data, (/*FSL*/ubyte4)dataLength, iv);

#ifdef __ENABLE_ALL_DEBUGGING__
    if (OK > status)
        DEBUG_ERROR(DEBUG_CRYPTO, "Do3DES: cipher failed, error = ", status);
#endif

exit:
    return status;
}
#endif


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DES_CIPHER__) && defined(__DES_HARDWARE_CIPHER__))
extern MSTATUS
DeleteDESCtx(BulkCtx* ctx)
{



    if (*ctx)
    {
        FREE(*ctx);
        *ctx = NULL;
    }

    return OK;
}
#endif /* (defined(__ENABLE_DES_CIPHER__) && defined(__DES_HARDWARE_CIPHER__)) */


/*------------------------------------------------------------------*/

#if ((!defined(__DISABLE_3DES_CIPHERS__)) && defined(__3DES_HARDWARE_CIPHER__))
extern MSTATUS
Delete3DESCtx(BulkCtx* ctx)
{


    if (*ctx)
    {
        FREE(*ctx);
        *ctx = NULL;
    }

    return OK;
}
#endif


/*------------------------------------------------------------------*/

const ubyte FSL_CAU_PADDING[64] =
{
  0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};


/*------------------------------------------------------------------*/

/* Encodes input (ubyte4) into output (ubyte). Assumes len is a multiple of 4. */
static void
FSL_CAU_MD5_encode(ubyte *output, const ubyte4 *input, ubyte4 len)
{
    ubyte4 i, j;


    for (i = 0, j = 0; j < len; i++, j += 4)
    {
        output[j]   = (ubyte)(input[i] & 0xff);
        output[j+1] = (ubyte)((input[i] >> 8) & 0xff);
        output[j+2] = (ubyte)((input[i] >> 16) & 0xff);
        output[j+3] = (ubyte)((input[i] >> 24) & 0xff);
    }
}

static void
FSL_CAU_MD5_encode_big(ubyte *output, const ubyte4 *input, ubyte4 len)
{
    ubyte4 i, j;


    for (i = 0, j = 0; j < len; i++, j += 4)
    {
        output[j+3]   = (ubyte)(input[i] & 0xff);
        output[j+2] = (ubyte)((input[i] >> 8) & 0xff);
        output[j+1] = (ubyte)((input[i] >> 16) & 0xff);
        output[j] = (ubyte)((input[i] >> 24) & 0xff);
    }
}

static void
FSL_CAU_MD5_encode_bigAll(ubyte *output, const ubyte4 *input, ubyte4 len)
{
    ubyte4 i, j;


    for (i = (len/4-1), j = 0; j < len; i--, j += 4)
    {
        output[j]   = (ubyte)((input[i] >> 24) & 0xff);
        output[j+1] = (ubyte)((input[i] >> 16) & 0xff);
        output[j+2] = (ubyte)((input[i] >> 8) & 0xff);
        output[j+3] = (ubyte)(input[i] & 0xff);
    }
}


/*------------------------------------------------------------------*/
#ifdef __MD5_HARDWARE_HASH__

extern MSTATUS
MD5Init_m(MD5_CTX *context)
{


    context->mesgLength = 0;
    context->index = 0;

    context->hashBlocks[0] = 0x67452301L;
    context->hashBlocks[1] = 0xefcdab89L;
    context->hashBlocks[2] = 0x98badcfeL;
    context->hashBlocks[3] = 0x10325476L;

    return OK;
}
#endif


/*------------------------------------------------------------------*/


#if defined(__CUSTOM_MD5_CONTEXT__) || defined(__CUSTOM_SHA1_CONTEXT__)
#define MD_CTX_BUFF_AVAIL(c)           (MD_CTX_HASHDATA_SIZE - (c)->index)
#endif
/*------------------------------------------------------------------*/

#ifdef __MD5_ONE_STEP_HARDWARE_HASH__
extern MSTATUS
MD5_completeDigest(MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pData, ubyte4 dataLen, ubyte *pMdOutput)
{
    MD5_CTX mdContext;
    MSTATUS status;

    if (OK > (status = MD5Init_m(MOC_HASH(hwAccelCtx) &mdContext)))
        goto exit;

    if (OK > (status = MD5Update_m(MOC_HASH(hwAccelCtx) &mdContext, pData, dataLen)))
        goto exit;

    status = MD5Final_m(MOC_HASH(hwAccelCtx) &mdContext, pMdOutput);

exit:
    return status;
}
#endif

/*------------------------------------------------------------------*/
#ifdef __MD5_HARDWARE_HASH__
extern MSTATUS
MD5Alloc_m(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context)
{
    return CRYPTO_ALLOC(hwAccelCtx, sizeof(MD5_CTX), TRUE, pp_context);
}
extern MSTATUS
MD5Free_m(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context)
{
    return CRYPTO_FREE(hwAccelCtx, TRUE, pp_context);
}
#endif
/*------------------------------------------------------------------*/

#ifdef __MD5_HARDWARE_HASH__
extern MSTATUS
MD5Update_m(MD5_CTX *p_md5Context, const ubyte *pData, ubyte4 dataLen)
{
    ubyte4  multipleOf64Bytes;
    ubyte4  remainder;
    sbyte4  i;
    ubyte*  pFSLCtx    = (unsigned char *)p_md5Context->hashBlocks;
    MSTATUS status     = OK;

    p_md5Context->mesgLength += dataLen;

    if (0 == dataLen)
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    if (0 != p_md5Context->index)
    {
        /* add to remenant data from previous round(s) */
        ubyte4  availSpace;
        ubyte4  copyLen;
        ubyte4 tempBlocks[4];

        availSpace = MD_CTX_BUFF_AVAIL(p_md5Context);

        if (0 < (copyLen = (availSpace > dataLen) ? dataLen : availSpace))
        {
            DIGI_MEMCPY(p_md5Context->cachedHashData + p_md5Context->index, pData, (/*FSL*/sbyte4)copyLen);

            p_md5Context->index += copyLen;
            pData               += copyLen;
            dataLen             -= copyLen;

            if (0 == dataLen)
            {
                /* defer some bytes pending for an unexpected final */
                goto exit;
            }
        }

        /* process one 64 byte chunk */
        /* cau_md5_update(p_md5Context->cachedHashData, 1, (unsigned char *)p_md5Context->hashBlocks);
 */

        cau_md5_block_processing(p_md5Context->cachedHashData, 1, (unsigned char *)p_md5Context->hashBlocks);

        FSL_CAU_MD5_encode((ubyte *)tempBlocks,p_md5Context->hashBlocks,16);

        DIGI_MEMCPY(p_md5Context->hashBlocks,tempBlocks,16);

        /* reset index for next time */
        p_md5Context->index = 0;
    }

    /* next phase: send integer multiples of 64 bytes (>1) if we can */
    multipleOf64Bytes = dataLen & (~LEN_64_MASK);
    remainder         = dataLen & LEN_64_MASK;

    if (0 == remainder)
    {
        /* defer some bytes pending for an unexpected final */
        multipleOf64Bytes -= 64;;
        remainder = 64;
    }

    if (0 < multipleOf64Bytes)
    {
        ubyte4 tempBlocks[4];
        /* process a big chunk, 64 * N bytes */
        /* cau_md5_update((ubyte *)pData, multipleOf64Bytes, (unsigned char *)p_md5Context->hashBlocks);
 */

        cau_md5_block_processing((ubyte *)pData, (/*FSL*/sbyte4)((multipleOf64Bytes*8)/512), (unsigned char *)p_md5Context->hashBlocks);

        FSL_CAU_MD5_encode((ubyte *)tempBlocks,p_md5Context->hashBlocks,16);

        DIGI_MEMCPY(p_md5Context->hashBlocks,tempBlocks,16);
        /* move past processed data */
        pData += multipleOf64Bytes;
    }

    /* transfer remaining data to context buffer */
    DIGI_MEMCPY(p_md5Context->cachedHashData, pData, (/*FSL*/sbyte4)remainder);
    p_md5Context->index = remainder;

exit:
    return status;
}
#endif /* __MD5_HARDWARE_HASH__ */


/*------------------------------------------------------------------*/

#ifdef __MD5_HARDWARE_HASH__
extern MSTATUS
MD5Final_m(MD5_CTX *pContext, ubyte* pMd5Output)
{
    ubyte8  mesgLength;
    ubyte4  bitCount[2];
    ubyte   bits[8];
    ubyte4  count;
    ubyte4  padLen;
    sbyte4  i;
    MSTATUS status;


    if ((NULL == pContext) || (NULL == pMd5Output))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* make bit count */
    U8INIT(mesgLength, 0, pContext->mesgLength);
    mesgLength = u8_Shl(mesgLength, 3);             /* convert bytes to bits */

    /* get bit counts */
    bitCount[0] = LOW_U8(mesgLength);
    bitCount[1] = HI_U8(mesgLength);                /* will likely always be zero... */

    FSL_CAU_MD5_encode(bits, bitCount, 8);

    /* calc pad length */
    count = (ubyte4)((bitCount[0] >> 3) & 0x3f);

    padLen = ((MD5_BLOCK_SIZE - 8) <= count) ?
        ((MD5_BLOCK_SIZE + (MD5_BLOCK_SIZE - 8)) - count) : ((MD5_BLOCK_SIZE - 8) - count);

    /* hash pad */
    if (OK > (status = MD5Update_m(pContext, FSL_CAU_PADDING, padLen)))
        goto exit;

    /* hash bit length */
    if (OK > (status = MD5Update_m(pContext, bits, 8)))
        goto exit;

    /* hash in the last block */
    /* cau_sha1_update(pContext->cachedHashData, 1, (unsigned char *)pContext->hashBlocks);
 */

    cau_md5_block_processing(pContext->cachedHashData, 1, (unsigned char *)pContext->hashBlocks);
    /* output final hash */
    FSL_CAU_MD5_encode_big(pMd5Output, pContext->hashBlocks, MD5_DIGESTSIZE);

exit:
    return status;
}
#endif /* __MD5_HARDWARE_HASH__ */


/*------------------------------------------------------------------*/

#ifdef __SHA1_HARDWARE_HASH__
extern MSTATUS SHA1_initDigest(shaDescr *p_shaContext)
{



    p_shaContext->mesgLength = 0;
    p_shaContext->index = 0;

    p_shaContext->hashBlocks[0] = 0x67452301L;
    p_shaContext->hashBlocks[1] = 0xefcdab89L;
    p_shaContext->hashBlocks[2] = 0x98badcfeL;
    p_shaContext->hashBlocks[3] = 0x10325476L;
    p_shaContext->hashBlocks[4] = 0xc3d2e1f0L;



    return OK;
}
#endif

/*------------------------------------------------------------------*/

extern MSTATUS
SHA1_allocDigest(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context)
{
    return CRYPTO_ALLOC(hwAccelCtx, sizeof(shaDescr), TRUE, pp_context);
}
extern MSTATUS
SHA1_freeDigest(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context)
{
    return CRYPTO_FREE(hwAccelCtx, TRUE, pp_context);
}

/*------------------------------------------------------------------*/

extern MSTATUS
SHA1_completeDigest(MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pData, ubyte4 dataLen, ubyte *pShaOutput)
{
    shaDescr shaContext;
    MSTATUS  status;


#ifdef __ZEROIZE_TEST__
    int counter;
#endif


    if (OK > (status = SHA1_initDigest(MOC_HASH(hwAccelCtx) &shaContext)))
        goto exit;

    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) &shaContext, pData, dataLen)))
        goto exit;

    status = SHA1_finalDigest(MOC_HASH(hwAccelCtx) &shaContext, pShaOutput);

exit:
#ifdef __ZEROIZE_TEST__

        for( counter = 0; counter < sizeof(shaDescr); counter++)
        {
            printf("%02x",*((ubyte*)&shaContext+counter));
        }
#endif
    /* Zeroize the sensitive information before deleting the memory */
    DIGI_MEMSET((unsigned char *)&shaContext,0x00,sizeof(shaDescr));

#ifdef __ZEROIZE_TEST__
        printf("\nSHA1 - After Zeroization\n");
        for( counter = 0; counter < sizeof(shaDescr); counter++)
        {
            printf("%02x",*((ubyte*)&shaContext+counter));
        }
#endif

    return status;
}

/*------------------------------------------------------------------*/

#ifdef __SHA1_HARDWARE_HASH__
extern MSTATUS
SHA1_updateDigest(shaDescr *p_shaContext,
                  const ubyte *pData, ubyte4 dataLen)
{
    ubyte4  multipleOf64Bytes;
    ubyte4  remainder;
    MSTATUS status     = OK;

    if (0 == dataLen)
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    p_shaContext->mesgLength += dataLen;

    if (0 != p_shaContext->index)
    {
        /* add to remenant data from previous round(s) */
        ubyte4  availSpace;
        ubyte4  copyLen;

        availSpace = MD_CTX_BUFF_AVAIL(p_shaContext);


        if (0 < (copyLen = (availSpace > dataLen) ? dataLen : availSpace))
        {

            DIGI_MEMCPY(p_shaContext->cachedHashData + p_shaContext->index, pData, (/*FSL*/sbyte4)copyLen);

            p_shaContext->index += copyLen;
            pData               += copyLen;
            dataLen             -= copyLen;

            if (0 == dataLen)
            {
                /* defer some bytes pending for an unexpected final */
                goto exit;
            }
        }

        /* process 64 byte chunk */
        /* cau_sha1_update(p_shaContext->cachedHashData, 1, (unsigned char *)p_shaContext->hashBlocks);
 */

        cau_sha1_block_processing(p_shaContext->cachedHashData, 1, (unsigned char *)p_shaContext->hashBlocks);


        /* reset for next call */
        p_shaContext->index = 0;
    }

    /* next phase: send integer multiples of 64 bytes (>1) if we can */
    multipleOf64Bytes = dataLen & (~LEN_64_MASK);/*4294967232*/
    remainder         = dataLen & LEN_64_MASK;

    if (0 == remainder)
    {
        /* defer some bytes pending for an unexpected final */
        multipleOf64Bytes -= 64;;
        remainder = 64;
    }

    if (0 < multipleOf64Bytes)
    {
        /* process a big chunk, 64 * N bytes */
        /* cau_sha1_update((ubyte *)pData, multipleOf64Bytes, (unsigned char *)p_shaContext->hashBlocks);
 */

        cau_sha1_block_processing((ubyte *)pData, (/*FSL*/sbyte4)((multipleOf64Bytes*8)/512), (unsigned char *)p_shaContext->hashBlocks);

        /* move past processed bytes */
        pData += multipleOf64Bytes;
    }

    /* transfer remaining data to context buffer */
    DIGI_MEMCPY(p_shaContext->cachedHashData, pData, (/*FSL*/sbyte4)remainder);
    p_shaContext->index = remainder;

exit:

    return status;
}
#endif /* __SHA1_HARDWARE_HASH__ */


/*------------------------------------------------------------------*/

#ifdef __SHA1_HARDWARE_HASH__
extern MSTATUS
SHA1_finalDigest(shaDescr *p_shaContext, ubyte *pOutput)
{
    ubyte8  mesgLength;
    ubyte4  bitCount[2];
    ubyte   bits[8];
    ubyte4  count;
    ubyte4  padLen;
    MSTATUS status;


    if ((NULL == p_shaContext) || (NULL == pOutput))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* make bit count */
    U8INIT(mesgLength, 0, p_shaContext->mesgLength);
    mesgLength = u8_Shl(mesgLength, 3);             /* convert bytes to bits */

    /* get bit counts */
    bitCount[0] = LOW_U8(mesgLength);
    bitCount[1] = HI_U8(mesgLength);                /* will likely always be zero... */

    FSL_CAU_MD5_encode_bigAll(bits, bitCount, 8);


    /* calc pad length */
    count = p_shaContext->mesgLength % SHA1_BLOCK_SIZE;


    padLen = ((SHA1_BLOCK_SIZE - 8) <= count) ?
        ((SHA1_BLOCK_SIZE + (SHA1_BLOCK_SIZE - 8)) - count) : ((SHA1_BLOCK_SIZE - 8) - count);

    if (OK > (status = SHA1_updateDigest(p_shaContext, FSL_CAU_PADDING, padLen)))
        goto exit;

    /* hash bit length */
    if (OK > (status = SHA1_updateDigest(p_shaContext, bits, 8)))
        goto exit;

    /* hash in the last block */
    /* cau_sha1_update(p_shaContext->cachedHashData, 1, (unsigned char *)p_shaContext->hashBlocks);
 */
    cau_sha1_block_processing(p_shaContext->cachedHashData, 1, (unsigned char *)p_shaContext->hashBlocks);

    /* output final hash */

    FSL_CAU_MD5_encode_big(pOutput, p_shaContext->hashBlocks, SHA1_RESULT_SIZE);



exit:
    return status;

} /* SHA1_finalDigest */
#endif /* __SHA1_HARDWARE_HASH__ */

#endif /* __COLDFIRE__ */

#ifdef __KINETIS__
/*------------------------------------------------------------------*/

static void
fixupParityBits(ubyte *pKeyMaterial, sbyte4 keyLength)
{
    sbyte4 index;
    
    for (index = 0; index < keyLength; index++)
        pKeyMaterial[index] = ((pKeyMaterial[index] & 0xfe) | parityBitLookup[pKeyMaterial[index] >> 1]);
}


/*------------------------------------------------------------------*/

static fslCipherContext *
CreateCtxCommon(ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt)
{
    
    
    fslCipherContext* ctx = NULL;
    
    
    if (NULL == (ctx = MALLOC(sizeof(fslCipherContext))))
        goto exit;
    
    DIGI_MEMSET((ubyte *)ctx, 0x00, sizeof(fslCipherContext));
    DIGI_MEMCPY(&(ctx->key[0]), keyMaterial, keyLength);
    
    ctx->keyLength = keyLength;
    ctx->encrypt = encrypt;
    
exit:
	
    return ctx;
}


/*------------------------------------------------------------------*/


#if ((!defined(__DISABLE_AES_CIPHERS__)) && defined(__AES_HARDWARE_CIPHER__))
extern BulkCtx
CreateAESCtx(ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt)
{
	unsigned char * p_keySched;
    fslCipherContext*   ctx = NULL;
	
    
    if (!((16 == keyLength) || (24 == keyLength) || (32 == keyLength)))
        goto exit;  /* bad key size */
    
    if (NULL != (ctx = CreateCtxCommon(keyMaterial, keyLength, encrypt)))
    {
        
        /* setup key schedule based on key material */
        p_keySched = MALLOC(60*4);
        
        FREESCALE_CAU_MUTEX_WAIT(); 
        cau_aes_set_key(keyMaterial, 8 * keyLength, p_keySched );
        FREESCALE_CAU_MUTEX_RELEASE(); 
		
        DIGI_MEMCPY(ctx->keySchedule,p_keySched,60*4);
        /* convert key length to number of AES rounds */
        ctx->nr = (8 + ((ctx->keyLength - 8) >> 2));
        
        FREE(p_keySched);
    }
    
exit:
    return (BulkCtx)ctx;
}
#endif /* ((!defined(__DISABLE_AES_CIPHERS__)) && defined(__AES_HARDWARE_CIPHER__)) */


/*------------------------------------------------------------------*/

#if ((!defined(__DISABLE_AES_CIPHERS__)) && defined(__AES_HARDWARE_CIPHER__))
static MSTATUS
FSL_CAU_AES_encipherCBC(fslCipherContext* pContext, ubyte4 keyLength, ubyte *pSrc,
                        ubyte *pDest, ubyte4 numBytes, ubyte *pIV)
{
    ubyte   tempBlock[AES_BLOCK_SIZE];
    ubyte4  blocks = numBytes / AES_BLOCK_SIZE;
    sbyte4  i;
    MSTATUS status = OK;
    
	
    if ((NULL == pContext) || (NULL == pSrc) || (NULL == pDest))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    
    while (0 < blocks)
    {
        /*!!!! code could be faster, if we cast to 4-byte pointers --- not sure if it will cause bus errors */
        /* make temp copy of block to encrypt */
        DIGI_MEMCPY(tempBlock, pSrc, AES_BLOCK_SIZE);
        
        /* tempBlock xor pIV */
        for (i = 0; i < AES_BLOCK_SIZE; i++)
			tempBlock[i] ^= pIV[i];
        
        FREESCALE_CAU_MUTEX_WAIT(); 
        cau_aes_encrypt(tempBlock, (unsigned char *)pContext->keySchedule, pContext->nr, pDest);
        FREESCALE_CAU_MUTEX_RELEASE(); 
        
        /* copy encrypt block to iv */
        DIGI_MEMCPY(pIV, pDest, AES_BLOCK_SIZE);
        
        pSrc  += AES_BLOCK_SIZE;
        pDest += AES_BLOCK_SIZE;
        blocks--;
    }
    
exit:
    return status;
    
} /* FSL_CAU_AES_encipherCBC */
#endif


/*------------------------------------------------------------------*/

#if ((!defined(__DISABLE_AES_CIPHERS__)) && defined(__AES_HARDWARE_CIPHER__))
static MSTATUS
FSL_CAU_AES_decipherCBC(fslCipherContext* pContext, ubyte4 keyLength, ubyte *pSrc,
                        ubyte *pDest, ubyte4 numBytes, ubyte *pIV)
{
    ubyte   tempBlock[AES_BLOCK_SIZE];
    ubyte4  blocks = numBytes / AES_BLOCK_SIZE;
    sbyte4  i;
    MSTATUS status = OK;
    
	
    if ((NULL == pContext) || (NULL == pSrc) || (NULL == pDest))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    
    while (0 < blocks)
    {
        /*!!!! code could be faster, if we cast to 4-byte pointers --- not sure if it will cause bus errors */
        /* save a copy of block for IV */
        DIGI_MEMCPY(tempBlock, pSrc, AES_BLOCK_SIZE);
        
        FREESCALE_CAU_MUTEX_WAIT(); 
        cau_aes_decrypt(pSrc, (unsigned char *)pContext->keySchedule, pContext->nr, pDest);
        FREESCALE_CAU_MUTEX_RELEASE(); 
        
        /* tempBlock xor pIV */
        for (i = 0; i < AES_BLOCK_SIZE; i++)
            pDest[i] ^= pIV[i];
        
        /* copy saved encrypt block to iv */
        DIGI_MEMCPY(pIV, tempBlock, AES_BLOCK_SIZE);
        
        pSrc  += AES_BLOCK_SIZE;
        pDest += AES_BLOCK_SIZE;
        blocks--;
    }
    
exit:
    return status;
    
} /* FSL_CAU_AES_decipherCBC */
#endif


/*------------------------------------------------------------------*/

#if ((!defined(__DISABLE_AES_CIPHERS__)) && defined(__AES_HARDWARE_CIPHER__))
extern MSTATUS
DoAES(BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt, ubyte* iv)
{
    MSTATUS status;
    
    
    if (0 != (dataLength % AES_BLOCK_SIZE))
    {
        status = ERR_AES_BAD_LENGTH;
        goto exit;
    }
    
    if (encrypt)
        status = FSL_CAU_AES_encipherCBC((fslCipherContext *)ctx, (/*FSL*/ubyte4)(((fslCipherContext *)ctx)->keyLength), data, data, (/*FSL*/ubyte4)dataLength, iv);
    else
        status = FSL_CAU_AES_decipherCBC((fslCipherContext *)ctx, (/*FSL*/ubyte4)(((fslCipherContext *)ctx)->keyLength), data, data, (/*FSL*/ubyte4)dataLength, iv);
    
#ifdef __ENABLE_ALL_DEBUGGING__
    if (OK > status)
        DEBUG_ERROR(DEBUG_CRYPTO, "DoDES: cipher failed, error = ", status);
#endif
    
exit:
    return status;
}
#endif /* ((!defined(__DISABLE_AES_CIPHERS__)) && defined(__AES_HARDWARE_CIPHER__)) */


/*------------------------------------------------------------------*/

#if ((!defined(__DISABLE_AES_CIPHERS__)) && defined(__AES_HARDWARE_CIPHER__))
extern MSTATUS
DeleteAESCtx(BulkCtx* ctx)
{
    
	
    if (*ctx)
    {
        FREE(*ctx);//b06862: comment it out
        *ctx = NULL;
    }
    
    return OK;
}
#endif /* ((!defined(__DISABLE_AES_CIPHERS__)) && defined(__AES_HARDWARE_CIPHER__)) */


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DES_CIPHER__) && defined(__DES_HARDWARE_CIPHER__))
extern BulkCtx
CreateDESCtx(MOC_SYM(hwAccelDescr hwAccelCtx) const ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt)
{
    
    
    if ((DES_KEY_LENGTH != keyLength) || (NULL == keyMaterial))
        return NULL;  /* bad key size or material */
    
    
    fixupParityBits(keyMaterial, keyLength);
    
    return (BulkCtx)(CreateCtxCommon(keyMaterial, keyLength, encrypt));
}
#endif /* (defined(__ENABLE_DES_CIPHER__) && defined(__DES_HARDWARE_CIPHER__)) */


/*------------------------------------------------------------------*/

#if ((!defined(__DISABLE_3DES_CIPHERS__)) && defined(__3DES_HARDWARE_CIPHER__))
extern BulkCtx
Create3DESCtx(ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt)
{
    
    
    if ((THREE_DES_KEY_LENGTH != keyLength) || (NULL == keyMaterial))
        return NULL;  /* bad key size or material */
    
    fixupParityBits(keyMaterial, keyLength);
    
    return (BulkCtx)(CreateCtxCommon(keyMaterial, keyLength, encrypt));
}
#endif


/*------------------------------------------------------------------*/

#if (((( defined(__ENABLE_DES_CIPHER__))    && (defined( __DES_HARDWARE_CIPHER__)))) || \
(((!defined(__DISABLE_3DES_CIPHERS__)) && (defined(__3DES_HARDWARE_CIPHER__)))) )
static MSTATUS
FSL_CAU_XDES_encipherCBC(fslCipherContext* p_desContext, ubyte4 keyLength, ubyte *pSrc,
                         ubyte *pDest, ubyte4 numBytes, ubyte *pIV)
{
    ubyte   tempBlock[DES_BLOCK_SIZE];
    ubyte4  blocks = numBytes / DES_BLOCK_SIZE;
    sbyte4  i;
    MSTATUS status = OK;
    
    
    if ((NULL == p_desContext) || (NULL == pSrc) || (NULL == pDest))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    
    if (keyLength != p_desContext->keyLength)
    {
        status = (DES_BLOCK_SIZE == keyLength) ? ERR_DES_BAD_KEY_LENGTH : ERR_3DES_BAD_KEY_LENGTH;
        goto exit;
    }
    
    while (0 < blocks)
    {
        /*!!!! code could be faster, if we cast to 4-byte pointers --- not sure if it will cause bus errors */
        /* make temp copy of block to encrypt */
        DIGI_MEMCPY(tempBlock, pSrc, DES_BLOCK_SIZE);
        
        /* tempBlock xor pIV */
        for (i = 0; i < DES_BLOCK_SIZE; i++)
            tempBlock[i] ^= pIV[i];
        
        FREESCALE_CAU_MUTEX_WAIT(); 
        cau_des_encrypt(tempBlock, p_desContext->key, pDest);
        
        if (DES_KEY_LENGTH < p_desContext->keyLength)
        {
            /* do 3des */
            cau_des_decrypt(pDest /* pSrc ? */, DES_KEY_LENGTH + p_desContext->key, pDest);
            cau_des_encrypt(pDest /* pSrc ? */, (2 * DES_KEY_LENGTH) + p_desContext->key, pDest);
        }
        FREESCALE_CAU_MUTEX_RELEASE();         
        
        /* copy encrypt block to iv */
        DIGI_MEMCPY( pIV, pDest, DES_BLOCK_SIZE);
        
        pSrc  += 8;
        pDest += 8;
        blocks--;
    }
    
exit:
    return status;
    
} /* FSL_CAU_XDES_encipherCBC */
#endif


/*------------------------------------------------------------------*/

#if (((( defined(__ENABLE_DES_CIPHER__))    && (defined( __DES_HARDWARE_CIPHER__)))) || \
(((!defined(__DISABLE_3DES_CIPHERS__)) && (defined(__3DES_HARDWARE_CIPHER__)))) )
static MSTATUS
FSL_CAU_XDES_decipherCBC(fslCipherContext* p_desContext, ubyte4 keyLength, ubyte *pSrc,
                         ubyte *pDest, ubyte4 numBytes, ubyte *pIV)
{
    ubyte   tempBlock[DES_BLOCK_SIZE];
    ubyte4  blocks = numBytes / DES_BLOCK_SIZE;
    sbyte4  i;
    MSTATUS status = OK;
    
    
    if ((NULL == p_desContext) || (NULL == pSrc) || (NULL == pDest))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    
    if (keyLength != p_desContext->keyLength)
    {
        status = (DES_BLOCK_SIZE == keyLength) ? ERR_DES_BAD_KEY_LENGTH : ERR_3DES_BAD_KEY_LENGTH;
        goto exit;
    }
    
    while (0 < blocks)
    {
        /*!!!! code could be faster, if we cast to 4-byte pointers --- not sure if it will cause bus errors */
        /* save a copy of block for IV */
        DIGI_MEMCPY(tempBlock, pSrc, DES_BLOCK_SIZE);
        
        FREESCALE_CAU_MUTEX_WAIT(); 
        if (DES_KEY_LENGTH == p_desContext->keyLength)
        {
            /* regular des */
            cau_des_decrypt(pSrc, p_desContext->key, pDest);
        }
        else
        {
            /* do 3des */
            cau_des_decrypt(pSrc, (2 * DES_KEY_LENGTH) + p_desContext->key, pDest);
            cau_des_encrypt(pDest, DES_KEY_LENGTH + p_desContext->key, pDest);
            cau_des_decrypt(pDest, p_desContext->key, pDest);
        }
        FREESCALE_CAU_MUTEX_RELEASE(); 
        
        /* tempBlock xor pIV */
        for (i = 0; i < DES_BLOCK_SIZE; i++)
            pDest[i] ^= pIV[i];
        
        /* copy saved encrypt block to iv */
        DIGI_MEMCPY(pIV, tempBlock, DES_BLOCK_SIZE);
        
        pSrc  += 8;
        pDest += 8;
        blocks--;
    }
    
exit:
    return status;
    
} /* FSL_CAU_XDES_decipherCBC */
#endif


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DES_CIPHER__) && defined(__DES_HARDWARE_CIPHER__))
extern MSTATUS
DoDES(BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt, ubyte* iv)
{
    MSTATUS status;
    
    if (0 != (dataLength % DES_BLOCK_SIZE))
    {
        status = ERR_DES_BAD_LENGTH;
        goto exit;
    }
    
    FREESCALE_CAU_MUTEX_WAIT(); 
    if (encrypt)
        status = FSL_CAU_XDES_encipherCBC((fslCipherContext *)ctx, DES_KEY_LENGTH, data, data, dataLength, iv);
    else
        status = FSL_CAU_XDES_decipherCBC((fslCipherContext *)ctx, DES_KEY_LENGTH, data, data, dataLength, iv);
    FREESCALE_CAU_MUTEX_RELEASE(); 
    
#ifdef __ENABLE_ALL_DEBUGGING__
    if (OK > status)
        DEBUG_ERROR(DEBUG_CRYPTO, "DoDES: cipher failed, error = ", status);
#endif
    
exit:
    return status;
}
#endif


/*------------------------------------------------------------------*/

#if ((!defined(__DISABLE_3DES_CIPHERS__)) && defined(__3DES_HARDWARE_CIPHER__))
extern MSTATUS
Do3DES(BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt, ubyte* iv)
{
    MSTATUS status;
    
    
    if (0 != (dataLength % THREE_DES_BLOCK_SIZE))
    {
        status = ERR_3DES_BAD_LENGTH;
        goto exit;
    }
    
    FREESCALE_CAU_MUTEX_WAIT(); 
    if (encrypt)
        status = FSL_CAU_XDES_encipherCBC((fslCipherContext *)ctx, THREE_DES_KEY_LENGTH, data, data, (/*FSL*/ubyte4)dataLength, iv);
    else
        status = FSL_CAU_XDES_decipherCBC((fslCipherContext *)ctx, THREE_DES_KEY_LENGTH, data, data, (/*FSL*/ubyte4)dataLength, iv);
    FREESCALE_CAU_MUTEX_RELEASE(); 
    
#ifdef __ENABLE_ALL_DEBUGGING__
    if (OK > status)
        DEBUG_ERROR(DEBUG_CRYPTO, "Do3DES: cipher failed, error = ", status);
#endif
    
exit:
    return status;
}
#endif


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DES_CIPHER__) && defined(__DES_HARDWARE_CIPHER__))
extern MSTATUS
DeleteDESCtx(BulkCtx* ctx)
{
    
	
	
    if (*ctx)
    {
        FREE(*ctx);
        *ctx = NULL;
    }
    
    return OK;
}
#endif /* (defined(__ENABLE_DES_CIPHER__) && defined(__DES_HARDWARE_CIPHER__)) */


/*------------------------------------------------------------------*/

#if ((!defined(__DISABLE_3DES_CIPHERS__)) && defined(__3DES_HARDWARE_CIPHER__))
extern MSTATUS
Delete3DESCtx(BulkCtx* ctx)
{
    
	
    if (*ctx)
    {
        FREE(*ctx);
        *ctx = NULL;
    }
    
    return OK;
}
#endif


/*------------------------------------------------------------------*/

const ubyte FSL_CAU_PADDING[64] =
{
    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};


/*------------------------------------------------------------------*/

/* Encodes input (ubyte4) into output (ubyte). Assumes len is a multiple of 4. */
static void
FSL_CAU_MD5_encode(ubyte *output, const ubyte4 *input, ubyte4 len)
{
    ubyte4 i, j;
    
    
    for (i = 0, j = 0; j < len; i++, j += 4)
    {
        output[j]   = (ubyte)(input[i] & 0xff);
        output[j+1] = (ubyte)((input[i] >> 8) & 0xff);
        output[j+2] = (ubyte)((input[i] >> 16) & 0xff);
        output[j+3] = (ubyte)((input[i] >> 24) & 0xff);
    }
}

static void
FSL_CAU_MD5_encode_big(ubyte *output, const ubyte4 *input, ubyte4 len)
{
    
    ubyte4 i, j;
    
    
    for (i = 0, j = 0; j < len; i++, j += 4)
    {
        output[j+3]   = (ubyte)(input[i] & 0xff);
        output[j+2] = (ubyte)((input[i] >> 8) & 0xff);
        output[j+1] = (ubyte)((input[i] >> 16) & 0xff);
        output[j] = (ubyte)((input[i] >> 24) & 0xff);
    }
    
}

static void
FSL_CAU_MD5_encode_bigAll(ubyte *output, const ubyte4 *input, ubyte4 len)
{
    
    ubyte4 i, j;
    
    
    for (i = (len/4-1), j = 0; j < len; i--, j += 4)
    {
        output[j]   = (ubyte)((input[i] >> 24) & 0xff);
        output[j+1] = (ubyte)((input[i] >> 16) & 0xff);
        output[j+2] = (ubyte)((input[i] >> 8) & 0xff);
        output[j+3] = (ubyte)(input[i] & 0xff);
    }
    
}


/*------------------------------------------------------------------*/
#ifdef __MD5_HARDWARE_HASH__

extern MSTATUS
MD5Init_m(MD5_CTX *context)
{
    context->mesgLength = 0;
    context->index = 0;
    
    cau_md5_initialize_output((unsigned char *)context->hashBlocks);
    
    return OK;
}
#endif


/*------------------------------------------------------------------*/


#if defined(__CUSTOM_MD5_CONTEXT__) || defined(__CUSTOM_SHA1_CONTEXT__) || defined(__CUSTOM_SHA256_CONTEXT__)
#define MD_CTX_BUFF_AVAIL(c)           (MD_CTX_HASHDATA_SIZE - (c)->index)
#endif
/*------------------------------------------------------------------*/

#ifdef __MD5_ONE_STEP_HARDWARE_HASH__
extern MSTATUS
MD5_completeDigest(MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pData, ubyte4 dataLen, ubyte *pMdOutput)
{
    MD5_CTX mdContext;
    MSTATUS status;
    
    if (OK > (status = MD5Init_m(MOC_HASH(hwAccelCtx) &mdContext)))
        goto exit;
    
    if (OK > (status = MD5Update_m(MOC_HASH(hwAccelCtx) &mdContext, pData, dataLen)))
        goto exit;
    
    status = MD5Final_m(MOC_HASH(hwAccelCtx) &mdContext, pMdOutput);
    
exit:
    return status;
}
#endif

/*------------------------------------------------------------------*/
#ifdef __MD5_HARDWARE_HASH__
extern MSTATUS
MD5Alloc_m(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context)
{
    return CRYPTO_ALLOC(hwAccelCtx, sizeof(MD5_CTX), TRUE, pp_context);
}
extern MSTATUS
MD5Free_m(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context)
{
    return CRYPTO_FREE(hwAccelCtx, TRUE, pp_context);
}
#endif
/*------------------------------------------------------------------*/

#ifdef __MD5_HARDWARE_HASH__
extern MSTATUS
MD5Update_m(MD5_CTX *p_md5Context, const ubyte *pData, ubyte4 dataLen)
{
    ubyte4  multipleOf64Bytes;
    ubyte4  remainder;
    /*sbyte4  i;*/
    ubyte*  pFSLCtx    = (unsigned char *)p_md5Context->hashBlocks;
    MSTATUS status     = OK;
    
    p_md5Context->mesgLength += dataLen;
    
    if (0 == dataLen)
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }
    
    if (0 != p_md5Context->index)
    {
        /* add to remenant data from previous round(s) */
        ubyte4  availSpace;
        ubyte4  copyLen;
        
        availSpace = MD_CTX_BUFF_AVAIL(p_md5Context);
        
        if (0 < (copyLen = (availSpace > dataLen) ? dataLen : availSpace))
        {
            DIGI_MEMCPY(p_md5Context->cachedHashData + p_md5Context->index, pData, (/*FSL*/sbyte4)copyLen);
            
            p_md5Context->index += copyLen;
            pData               += copyLen;
            dataLen             -= copyLen;
            
            if (0 == dataLen)
            {
                /* defer some bytes pending for an unexpected final */
                goto exit;
            }
        }
        
        /* process one 64 byte chunk */
        FREESCALE_CAU_MUTEX_WAIT(); 
        cau_md5_hash_n(p_md5Context->cachedHashData, 1, (unsigned char *)p_md5Context->hashBlocks);
        FREESCALE_CAU_MUTEX_RELEASE(); 
        
        /* reset index for next time */
        p_md5Context->index = 0;
    }
    
    /* next phase: send integer multiples of 64 bytes (>1) if we can */
    multipleOf64Bytes = dataLen & (~LEN_64_MASK);
    remainder         = dataLen & LEN_64_MASK;
    
    if (0 == remainder)
    {
        /* defer some bytes pending for an unexpected final */
        multipleOf64Bytes -= 64;;
        remainder = 64;
    }
    
    if (0 < multipleOf64Bytes)
    {
        /* process a big chunk, 64 * N bytes */
        FREESCALE_CAU_MUTEX_WAIT(); 
        cau_md5_hash_n((ubyte *)pData, (/*FSL*/sbyte4)((multipleOf64Bytes*8)/512), (unsigned char *)p_md5Context->hashBlocks);
        FREESCALE_CAU_MUTEX_RELEASE(); 
		
        /* move past processed data */
        pData += multipleOf64Bytes;
    }
    
    /* transfer remaining data to context buffer */
    DIGI_MEMCPY(p_md5Context->cachedHashData, pData, (/*FSL*/sbyte4)remainder);
    p_md5Context->index = remainder;
    
exit:
    return status;
}
#endif /* __MD5_HARDWARE_HASH__ */


/*------------------------------------------------------------------*/

#ifdef __MD5_HARDWARE_HASH__
extern MSTATUS
MD5Final_m(MD5_CTX *pContext, ubyte* pMd5Output)
{
    ubyte8  mesgLength;
    ubyte4  bitCount[2];
    ubyte   bits[8];
    ubyte4  count;
    ubyte4  padLen;
    /*sbyte4  i;*/
    MSTATUS status;
    
    
    if ((NULL == pContext) || (NULL == pMd5Output))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    
    /* make bit count */
    U8INIT(mesgLength, 0, pContext->mesgLength);
    mesgLength = u8_Shl(mesgLength, 3);             /* convert bytes to bits */
    
    /* get bit counts */
    bitCount[0] = LOW_U8(mesgLength);
    bitCount[1] = HI_U8(mesgLength);                /* will likely always be zero... */
    
    FSL_CAU_MD5_encode(bits, bitCount, 8);
    
    /* calc pad length */
    count = (ubyte4)((bitCount[0] >> 3) & 0x3f);
    
    padLen = ((MD5_BLOCK_SIZE - 8) <= count) ?
    ((MD5_BLOCK_SIZE + (MD5_BLOCK_SIZE - 8)) - count) : ((MD5_BLOCK_SIZE - 8) - count);
    
    /* hash pad */
    if (OK > (status = MD5Update_m(pContext, FSL_CAU_PADDING, padLen)))
        goto exit;
    
    /* hash bit length */
    if (OK > (status = MD5Update_m(pContext, bits, 8)))
        goto exit;
    
    /* hash in the last block */
    FREESCALE_CAU_MUTEX_WAIT(); 
    cau_md5_hash_n(pContext->cachedHashData, 1, (unsigned char *)pContext->hashBlocks);
    FREESCALE_CAU_MUTEX_RELEASE(); 
    /* output final hash */
    DIGI_MEMCPY(pMd5Output, pContext->hashBlocks, MD5_DIGESTSIZE);
    
exit:
    return status;
}
#endif /* __MD5_HARDWARE_HASH__ */


/*------------------------------------------------------------------*/

#ifdef __SHA1_HARDWARE_HASH__
extern MSTATUS SHA1_initDigest(shaDescr *p_shaContext)
{
	
    p_shaContext->mesgLength = 0;
    p_shaContext->index = 0;
    
    cau_sha1_initialize_output(p_shaContext->hashBlocks);
    
    return OK;
}
#endif

/*------------------------------------------------------------------*/
#ifdef __SHA1_HARDWARE_HASH__
extern MSTATUS
SHA1_allocDigest(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context)
{
    return CRYPTO_ALLOC(hwAccelCtx, sizeof(shaDescr), TRUE, pp_context);
}
#endif
#ifdef __SHA1_HARDWARE_HASH__
extern MSTATUS
SHA1_freeDigest(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context)
{
    return CRYPTO_FREE(hwAccelCtx, TRUE, pp_context);
}
#endif
/*------------------------------------------------------------------*/
#ifdef __SHA1_ONE_STEP_HARDWARE_HASH__
extern MSTATUS
SHA1_completeDigest(MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pData, ubyte4 dataLen, ubyte *pShaOutput)
{
    shaDescr shaContext;
    MSTATUS  status;
    
    
#ifdef __ZEROIZE_TEST__
    int counter;
#endif
    
    
    if (OK > (status = SHA1_initDigest(MOC_HASH(hwAccelCtx) &shaContext)))
        goto exit;
    
    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) &shaContext, pData, dataLen)))
        goto exit;
    
    status = SHA1_finalDigest(MOC_HASH(hwAccelCtx) &shaContext, pShaOutput);
    
exit:
#ifdef __ZEROIZE_TEST__
    
    for( counter = 0; counter < sizeof(shaDescr); counter++)
    {
        printf("%02x",*((ubyte*)&shaContext+counter));
    }
#endif
    /* Zeroize the sensitive information before deleting the memory */
    DIGI_MEMSET((unsigned char *)&shaContext,0x00,sizeof(shaDescr));
    
#ifdef __ZEROIZE_TEST__
    printf("\nSHA1 - After Zeroization\n");
    for( counter = 0; counter < sizeof(shaDescr); counter++)
    {
        printf("%02x",*((ubyte*)&shaContext+counter));
    }
#endif
    
    return status;
}
#endif
/*------------------------------------------------------------------*/

#ifdef __SHA1_HARDWARE_HASH__
extern MSTATUS
SHA1_updateDigest(shaDescr *p_shaContext,
                  const ubyte *pData, ubyte4 dataLen)
{
    ubyte4  multipleOf64Bytes;
    ubyte4  remainder;
    MSTATUS status     = OK;
    
    if (0 == dataLen)
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }
    
    p_shaContext->mesgLength += dataLen;
    
    if (0 != p_shaContext->index)
    {
        /* add to remenant data from previous round(s) */
        ubyte4  availSpace;
        ubyte4  copyLen;
        
        availSpace = MD_CTX_BUFF_AVAIL(p_shaContext);
        
        if (0 < (copyLen = (availSpace > dataLen) ? dataLen : availSpace))
        {
        	
            DIGI_MEMCPY(p_shaContext->cachedHashData + p_shaContext->index, pData, (/*FSL*/sbyte4)copyLen);
            
            p_shaContext->index += copyLen;
            pData               += copyLen;
            dataLen             -= copyLen;
            
            if (0 == dataLen)
            {
                /* defer some bytes pending for an unexpected final */
                goto exit;
            }
        }
        
        /* process 64 byte chunk */
        FREESCALE_CAU_MUTEX_WAIT(); 
        cau_sha1_hash_n(p_shaContext->cachedHashData, 1, p_shaContext->hashBlocks);
        FREESCALE_CAU_MUTEX_RELEASE(); 
        
        /* reset for next call */
        p_shaContext->index = 0;
    }
    
    /* next phase: send integer multiples of 64 bytes (>1) if we can */
    multipleOf64Bytes = dataLen & (~LEN_64_MASK);/*4294967232*/
    remainder         = dataLen & LEN_64_MASK;
    
    if (0 == remainder)
    {
        /* defer some bytes pending for an unexpected final */
        multipleOf64Bytes -= 64;;
        remainder = 64;
    }
    
    if (0 < multipleOf64Bytes)
    {
        /* process a big chunk, 64 * N bytes */
        FREESCALE_CAU_MUTEX_WAIT(); 
    	cau_sha1_hash_n((ubyte *)pData, (/*FSL*/sbyte4)((multipleOf64Bytes*8)/512), p_shaContext->hashBlocks);
        FREESCALE_CAU_MUTEX_RELEASE(); 
		
        /* move past processed bytes */
        pData += multipleOf64Bytes;
    }
    
    /* transfer remaining data to context buffer */
    DIGI_MEMCPY(p_shaContext->cachedHashData, pData, (/*FSL*/sbyte4)remainder);
    p_shaContext->index = remainder;
    
exit:
	
    return status;
}
#endif /* __SHA1_HARDWARE_HASH__ */


/*------------------------------------------------------------------*/

#ifdef __SHA1_HARDWARE_HASH__
extern MSTATUS
SHA1_finalDigest(shaDescr *p_shaContext, ubyte *pOutput)
{
    ubyte8  mesgLength;
    ubyte4  bitCount[2];
    ubyte   bits[8];
    ubyte4  count;
    ubyte4  padLen;
    MSTATUS status;
    
    
    if ((NULL == p_shaContext) || (NULL == pOutput))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    
    /* make bit count */
    U8INIT(mesgLength, 0, p_shaContext->mesgLength);
    mesgLength = u8_Shl(mesgLength, 3);             /* convert bytes to bits */
    
    /* get bit counts */
    bitCount[0] = LOW_U8(mesgLength);
    bitCount[1] = HI_U8(mesgLength);                /* will likely always be zero... */
    
    FSL_CAU_MD5_encode_bigAll(bits, bitCount, 8);
    
    /* calc pad length */
    count = p_shaContext->mesgLength % SHA1_BLOCK_SIZE;
    
    
    padLen = ((SHA1_BLOCK_SIZE - 8) <= count) ?
    ((SHA1_BLOCK_SIZE + (SHA1_BLOCK_SIZE - 8)) - count) : ((SHA1_BLOCK_SIZE - 8) - count);
    
    if (OK > (status = SHA1_updateDigest(p_shaContext, FSL_CAU_PADDING, padLen)))
        goto exit;
    
    /* hash bit length */
    if (OK > (status = SHA1_updateDigest(p_shaContext, bits, 8)))
        goto exit;
    
    /* hash in the last block */
    FREESCALE_CAU_MUTEX_WAIT(); 
    cau_sha1_hash_n(p_shaContext->cachedHashData, 1, p_shaContext->hashBlocks);
    FREESCALE_CAU_MUTEX_RELEASE(); 
    
    /* output final hash */
#if (PSP_ENDIAN == MQX_BIG_ENDIAN)             
    DIGI_MEMCPY(pOutput, p_shaContext->hashBlocks, SHA1_RESULT_SIZE); 
#else
    FSL_CAU_MD5_encode_big(pOutput, p_shaContext->hashBlocks, SHA1_RESULT_SIZE);
#endif  
    
exit:
    return status;
    
} /* SHA1_finalDigest */
#endif /* __SHA1_HARDWARE_HASH__ */

/*------------------------------------------------------------------*/

#ifdef __SHA256_HARDWARE_HASH__
extern MSTATUS
SHA256_allocDigest(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context)
{
    return CRYPTO_ALLOC(hwAccelCtx, sizeof(sha256Descr), TRUE, pp_context);
}
#endif /* __SHA256_HARDWARE_HASH__ */

/*------------------------------------------------------------------*/

#ifdef __SHA256_HARDWARE_HASH__
extern MSTATUS
SHA256_freeDigest(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context)
{
    return CRYPTO_FREE(hwAccelCtx, TRUE, pp_context);
}
#endif /* __SHA256_HARDWARE_HASH__ */

/*------------------------------------------------------------------*/

#ifdef __SHA256_HARDWARE_HASH__
extern MSTATUS
SHA256_initDigest(sha256Descr *p_shaContext)
{
	
    p_shaContext->mesgLength = 0;
    p_shaContext->index = 0;
    
    cau_sha256_initialize_output(p_shaContext->hashBlocks);
    
    return OK;
}
#endif /* __SHA256_HARDWARE_HASH__ */

/*------------------------------------------------------------------*/

#ifdef __SHA256_HARDWARE_HASH__
extern MSTATUS
SHA256_updateDigest(sha256Descr *p_shaContext, const ubyte *pData, ubyte4 dataLen)
{
    ubyte4  multipleOf64Bytes;
    ubyte4  remainder;
    MSTATUS status     = OK;
    
    if (0 == dataLen)
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }
    
    p_shaContext->mesgLength += dataLen;
    
    if (0 != p_shaContext->index)
    {
        /* add to remenant data from previous round(s) */
        ubyte4  availSpace;
        ubyte4  copyLen;
        
        availSpace = MD_CTX_BUFF_AVAIL(p_shaContext);
        
        if (0 < (copyLen = (availSpace > dataLen) ? dataLen : availSpace))
        {
        	
        	DIGI_MEMCPY(p_shaContext->cachedHashData + p_shaContext->index, pData, (/*FSL*/sbyte4)copyLen);
            
            p_shaContext->index += copyLen;
            pData               += copyLen;
            dataLen             -= copyLen;
            
            if (0 == dataLen)
            {
                /* defer some bytes pending for an unexpected final */
                goto exit;
            }
        }
        
        /* process 64 byte chunk */
        FREESCALE_CAU_MUTEX_WAIT(); 
        cau_sha256_hash_n(p_shaContext->cachedHashData, 1, p_shaContext->hashBlocks);
        FREESCALE_CAU_MUTEX_RELEASE(); 
        
        /* reset for next call */
        p_shaContext->index = 0;
    }
    
    /* next phase: send integer multiples of 64 bytes (>1) if we can */
    multipleOf64Bytes = dataLen & (~LEN_64_MASK);/*4294967232*/
    remainder         = dataLen & LEN_64_MASK;
    
    if (0 == remainder)
    {
        /* defer some bytes pending for an unexpected final */
        multipleOf64Bytes -= 64;;
        remainder = 64;
    }
    
    if (0 < multipleOf64Bytes)
    {
        /* process a big chunk, 64 * N bytes */
        FREESCALE_CAU_MUTEX_WAIT(); 
    	cau_sha256_hash_n((ubyte *)pData, (/*FSL*/sbyte4)((multipleOf64Bytes*8)/512), p_shaContext->hashBlocks);
        FREESCALE_CAU_MUTEX_RELEASE(); 
		
        /* move past processed bytes */
        pData += multipleOf64Bytes;
    }
    
    /* transfer remaining data to context buffer */
    DIGI_MEMCPY(p_shaContext->cachedHashData, pData, (/*FSL*/sbyte4)remainder);
    p_shaContext->index = remainder;
    
exit:
	
    return status;
} /* SHA256_updateDigest */
#endif /* __SHA256_HARDWARE_HASH__ */

/*------------------------------------------------------------------*/
#ifdef __SHA256_ONE_STEP_HARDWARE_HASH__
extern MSTATUS
SHA256_completeDigest(MOC_HASH(hwAccelDescr hwAccelCtx) ubyte *pData, ubyte4 dataLen, ubyte *pShaOutput)
{
    sha256Descr shaContext;
    MSTATUS  status;
    
    
#ifdef __ZEROIZE_TEST__
    int counter;
#endif
    
#if( defined(__ENABLE_DIGICERT_FIPS_MODULE__) )
    if (OK != getFIPS_powerupStatus(FIPS_ALGO_SHA256))
        return getFIPS_powerupStatus(FIPS_ALGO_SHA256);
#endif /* ( defined(__ENABLE_DIGICERT_FIPS_MODULE__) ) */
    
    
    if (OK > (status = SHA256_initDigest(MOC_HASH(hwAccelCtx) &shaContext)))
        goto exit;
    
    if (OK > (status = SHA256_updateDigest(MOC_HASH(hwAccelCtx) &shaContext, pData, dataLen)))
        goto exit;
    
    status = SHA256_finalDigest(MOC_HASH(hwAccelCtx) &shaContext, pShaOutput);
    
exit:
#ifdef __ZEROIZE_TEST__
    
    for( counter = 0; counter < sizeof(sha256Descr); counter++)
    {
        printf("%02x",*((ubyte*)&shaContext+counter));
    }
#endif
    /* Zeroize the sensitive information before deleting the memory */
    DIGI_MEMSET((unsigned char *)&shaContext,0x00,sizeof(sha256Descr));
    
#ifdef __ZEROIZE_TEST__
    printf("\nSHA1 - After Zeroization\n");
    for( counter = 0; counter < sizeof(sha256Descr); counter++)
    {
        printf("%02x",*((ubyte*)&shaContext+counter));
    }
#endif
    
    return status;
}
#endif /* __SHA256_ONE_STEP_HARDWARE_HASH__ */

/*------------------------------------------------------------------*/

#ifdef __SHA256_HARDWARE_HASH__
extern MSTATUS
SHA256_finalDigest(sha256Descr *p_shaContext, ubyte *pOutput)
{
    ubyte8  mesgLength;
    ubyte4  bitCount[2];
    ubyte   bits[8];
    ubyte4  count;
    ubyte4  padLen;
    MSTATUS status;
    
    
    if ((NULL == p_shaContext) || (NULL == pOutput))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    
    /* make bit count */
    U8INIT(mesgLength, 0, p_shaContext->mesgLength);
    mesgLength = u8_Shl(mesgLength, 3);             /* convert bytes to bits */
    
    /* get bit counts */
    bitCount[0] = LOW_U8(mesgLength);
    bitCount[1] = HI_U8(mesgLength);                /* will likely always be zero... */
    
    FSL_CAU_MD5_encode_bigAll(bits, bitCount, 8);
    
    /* calc pad length */
    count = p_shaContext->mesgLength % SHA256_BLOCK_SIZE;
    
    
    padLen = ((SHA256_BLOCK_SIZE - 8) <= count) ?
    ((SHA256_BLOCK_SIZE + (SHA256_BLOCK_SIZE - 8)) - count) : ((SHA256_BLOCK_SIZE - 8) - count);
    
    if (OK > (status = SHA256_updateDigest(p_shaContext, FSL_CAU_PADDING, padLen)))
        goto exit;
    
    /* hash bit length */
    if (OK > (status = SHA256_updateDigest(p_shaContext, bits, 8)))
        goto exit;
    
    /* hash in the last block */
    FREESCALE_CAU_MUTEX_WAIT(); 
    cau_sha256_hash_n(p_shaContext->cachedHashData, 1, p_shaContext->hashBlocks);
    FREESCALE_CAU_MUTEX_RELEASE(); 
    
    /* output final hash */
#if (PSP_ENDIAN == MQX_BIG_ENDIAN)             
    DIGI_MEMCPY(pOutput, p_shaContext->hashBlocks, SHA256_RESULT_SIZE); 
#else
    FSL_CAU_MD5_encode_big(pOutput, p_shaContext->hashBlocks, SHA256_RESULT_SIZE);
#endif  
    
exit:
    return status;
    
} /* SHA256_finalDigest */
#endif /* __SHA256_HARDWARE_HASH__ */

/*------------------------------------------------------------------*/

extern sbyte4
FSLCAU_init(void)
{
    MSTATUS status = OK;
#if FREESCALE_CAU_MUTEX_ENABLE    
    if(fsl_cau_mutex == 0)
        if (OK > (status = RTOS_mutexCreate(&fsl_cau_mutex, HARNESS_DRV_MUTEX, 0)))
            goto exit;
#endif
exit:
    return (sbyte4)status;
}

/*------------------------------------------------------------------*/

extern sbyte4
FSLCAU_uninit(void)
{
#if FREESCALE_CAU_MUTEX_ENABLE
    if (fsl_cau_mutex)
    {
        RTOS_mutexFree(&fsl_cau_mutex);
        fsl_cau_mutex = 0;
    }
#endif
    return (sbyte4)OK;
}

/*------------------------------------------------------------------*/

extern sbyte4
FSLCAU_openChannel(enum moduleNames moduleId, sbyte4 *pHwAccelCookie)
{
    *pHwAccelCookie = 0;
    return (sbyte4)OK;
}


/*------------------------------------------------------------------*/

extern sbyte4
FSLCAU_closeChannel(enum moduleNames moduleId, sbyte4 *pHwAccelCookie)
{
    *pHwAccelCookie = 0;
    return (sbyte4)OK;
}


#endif /*__KINETIS__*/

#endif /* (defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) && defined(__ENABLE_FREESCALE_COLDFIRE_CAU_HARDWARE_ACCEL__)) */

