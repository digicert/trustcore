/*
 * cavium_sync_cn58xx.c
 *
 * Cavium CN58XX Hardware Acceleration Synchronous Adapter
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

#if (defined(__ENABLE_CAVIUM_CN58XX_HARDWARE_ACCEL__) && defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__))

#define OCTEON_MODEL OCTEON_CN58XX
#define USE_RUNTIME_MODEL_CHECKS 1
#define CVMX_ENABLE_PARAMETER_CHECKING 0
#define CVMX_ENABLE_CSR_ADDRESS_CHECKING 0
#define CVMX_ENABLE_POW_CHECKS 0

#include "../../common/mtypes.h"
#include "../../common/mocana.h"
#include "../../common/merrors.h"
#include "../../crypto/hw_accel.h"
#include "../../common/mdefs.h"
#include "../../common/mrtos.h"
#include "../../common/mtcp.h"
#include "../../common/mstdlib.h"
#include "../../common/random.h"
#include "../../common/vlong.h"
#include "../../common/debug_console.h"
#include "../../common/int64.h"
#include "../../common/int128.h"
#include "../../crypto/crypto.h"
#include "../../crypto/md5.h"
#include "../../crypto/md45.h"
#include "../../crypto/sha1.h"
#include "../../crypto/sha256.h"
#include "../../crypto/sha512.h"
#include "../../crypto/rsa.h"
#include "../../crypto/des.h"
#include "../../crypto/three_des.h"
#include "../../crypto/rc4algo.h"
#include "../../crypto/aes.h"
#include "../../crypto/nil.h"
#include "../../crypto/hmac.h"
#include "../../crypto/dh.h"

#include "cvmx.h"
#include "cvmx-key.h"

#if defined(__LINUX_RTOS__) && defined(__KERNEL__)
#include <linux/hardirq.h>
#endif


/*------------------------------------------------------------------*/

typedef struct
{
    sbyte4      encrypt;                            /* Key used for encrypting or decrypting? */
    uint64_t    key[4];                             /* raw key in this case */
    sbyte4      keyLength;                          /* Length of the key(in bytes) */

} cavmCipherContext;


/*------------------------------------------------------------------*/

static ubyte parityBitLookup[128] =
{
    1,0,0,1,0,1,1,0,0,1,1,0,1,0,0,1,0,1,1,0,1,0,0,1,1,0,0,1,0,1,1,0,
    0,1,1,0,1,0,0,1,1,0,0,1,0,1,1,0,1,0,0,1,0,1,1,0,0,1,1,0,1,0,0,1,
    0,1,1,0,1,0,0,1,1,0,0,1,0,1,1,0,1,0,0,1,0,1,1,0,0,1,1,0,1,0,0,1,
    1,0,0,1,0,1,1,0,0,1,1,0,1,0,0,1,0,1,1,0,1,0,0,1,1,0,0,1,0,1,1,0
};


/*------------------------------------------------------------------*/

static void
fixupParityBits(ubyte *pKeyMaterial, sbyte4 keyLength)
{
    sbyte4 index;

    for(index = 0; index < keyLength; index++)
        pKeyMaterial[index] = ((pKeyMaterial[index] & 0xfe) | parityBitLookup[pKeyMaterial[index] >> 1]);
}


/*------------------------------------------------------------------*/

extern sbyte4
CN58XX_init(void)
{
    return(sbyte4)OK;
}


/*------------------------------------------------------------------*/

extern sbyte4
CN58XX_uninit(void)
{
    return(sbyte4)OK;
}


/*------------------------------------------------------------------*/

static cavmCipherContext *
CreateCtxCommon(ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt)
{
    cavmCipherContext* ctx = NULL;

    if (OK != DIGI_MALLOC((void **)&ctx, sizeof(cavmCipherContext)))
    {
        DEBUG_PRINTNL(DEBUG_TEST, "CreateCtxCommon: DIGI_MALLOC() failed");
        goto exit;
    }

    DIGI_MEMSET((ubyte *)ctx, 0x00, sizeof(cavmCipherContext));
    DIGI_MEMCPY(&(ctx->key[0]), keyMaterial, keyLength);
    ctx->keyLength = (keyLength / 8) - 1;       /* key length in 64 bit chunks */
    ctx->encrypt = encrypt;

exit:
    return ctx;
}


/*------------------------------------------------------------------*/

#if((!defined(__DISABLE_AES_CIPHERS__)) && defined(__AES_HARDWARE_CIPHER__))
extern BulkCtx
CreateAESCtx(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt)
{
    if (!((16 == keyLength) ||(24 == keyLength) ||(32 == keyLength)))
        goto exit;  /* bad key size */

    return (BulkCtx)CreateCtxCommon(keyMaterial, keyLength, encrypt);

exit:
    return NULL;
}
#endif /*((!defined(__DISABLE_AES_CIPHERS__)) && defined(__AES_HARDWARE_CIPHER__)) */


/*------------------------------------------------------------------*/

#if((!defined(__DISABLE_AES_CIPHERS__)) && defined(__AES_HARDWARE_CIPHER__))
extern MSTATUS
DoAES(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt, ubyte* iv)
{
    uint64_t*   pData  = (uint64_t *)data;
    MSTATUS     status = OK;

    if (NULL == ctx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 != (dataLength % AES_BLOCK_SIZE))
    {
        status = ERR_AES_BAD_LENGTH;
        goto exit;
    }

    /* set the key */
    CVMX_MT_AES_KEY(((cavmCipherContext*)ctx)->key[0], 0);
    CVMX_MT_AES_KEY(((cavmCipherContext*)ctx)->key[1], 1);
    CVMX_MT_AES_KEY(((cavmCipherContext*)ctx)->key[2], 2);
    CVMX_MT_AES_KEY(((cavmCipherContext*)ctx)->key[3], 3);
    CVMX_MT_AES_KEYLENGTH(((cavmCipherContext*)ctx)->keyLength);

    /* set the iv */
    CVMX_MT_AES_IV(*((uint64_t *)iv), 0);
    CVMX_MT_AES_IV(*(1 + ((uint64_t *)iv)), 1);

    if (encrypt)
    {
        /* optimize for 64 byte packets */
        while ((AES_BLOCK_SIZE * 4) <= dataLength)
        {
            CVMX_MT_AES_ENC_CBC0(*pData);       /* 1 */
            CVMX_MT_AES_ENC_CBC1(*(pData+1));
            CVMX_MF_AES_RESULT(*pData++, 0);
            CVMX_MF_AES_RESULT(*pData++, 1);

            CVMX_MT_AES_ENC_CBC0(*pData);       /* 2 */
            CVMX_MT_AES_ENC_CBC1(*(pData+1));
            CVMX_MF_AES_RESULT(*pData++, 0);
            CVMX_MF_AES_RESULT(*pData++, 1);

            CVMX_MT_AES_ENC_CBC0(*pData);       /* 3 */
            CVMX_MT_AES_ENC_CBC1(*(pData+1));
            CVMX_MF_AES_RESULT(*pData++, 0);
            CVMX_MF_AES_RESULT(*pData++, 1);

            CVMX_MT_AES_ENC_CBC0(*pData);       /* 4 */
            CVMX_MT_AES_ENC_CBC1(*(pData+1));
            CVMX_MF_AES_RESULT(*pData++, 0);
            CVMX_MF_AES_RESULT(*pData++, 1);

            dataLength -= (4 * AES_BLOCK_SIZE);
        }

        while (AES_BLOCK_SIZE <= dataLength)
        {
            CVMX_MT_AES_ENC_CBC0(*pData);
            CVMX_MT_AES_ENC_CBC1(*(pData+1));
            CVMX_MF_AES_RESULT(*pData++, 0);
            CVMX_MF_AES_RESULT(*pData++, 1);

            dataLength -= AES_BLOCK_SIZE;
        }
    }
    else
    {
        /* optimize for 64 byte packets */
        while ((AES_BLOCK_SIZE * 4) <= dataLength)
        {
            CVMX_MT_AES_DEC_CBC0(*pData);        /* 1 */
            CVMX_MT_AES_DEC_CBC1(*(pData+1));
            CVMX_MF_AES_RESULT(*pData++, 0);
            CVMX_MF_AES_RESULT(*pData++, 1);

            CVMX_MT_AES_DEC_CBC0(*pData);        /* 2 */
            CVMX_MT_AES_DEC_CBC1(*(pData+1));
            CVMX_MF_AES_RESULT(*pData++, 0);
            CVMX_MF_AES_RESULT(*pData++, 1);

            CVMX_MT_AES_DEC_CBC0(*pData);        /* 3 */
            CVMX_MT_AES_DEC_CBC1(*(pData+1));
            CVMX_MF_AES_RESULT(*pData++, 0);
            CVMX_MF_AES_RESULT(*pData++, 1);

            CVMX_MT_AES_DEC_CBC0(*pData);        /* 4 */
            CVMX_MT_AES_DEC_CBC1(*(pData+1));
            CVMX_MF_AES_RESULT(*pData++, 0);
            CVMX_MF_AES_RESULT(*pData++, 1);

            dataLength -= (4 * AES_BLOCK_SIZE);
        }

        while (AES_BLOCK_SIZE <= dataLength)
        {
            CVMX_MT_AES_DEC_CBC0(*pData);
            CVMX_MT_AES_DEC_CBC1(*(pData+1));
            CVMX_MF_AES_RESULT(*pData++, 0);
            CVMX_MF_AES_RESULT(*pData++, 1);

            dataLength -= AES_BLOCK_SIZE;
        }
    }

    /* get the IV */
    CVMX_MF_AES_IV(*((uint64_t *)iv), 0);
    CVMX_MF_AES_IV(*(1 + ((uint64_t *)iv)), 1);

exit:
    return status;

}   /* DoAES */
#endif /*((!defined(__DISABLE_AES_CIPHERS__)) && defined(__AES_HARDWARE_CIPHER__)) */


/*------------------------------------------------------------------*/

#if((!defined(__DISABLE_AES_CIPHERS__)) && defined(__AES_HARDWARE_CIPHER__))
extern MSTATUS
DeleteAESCtx(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx* ctx)
{
    if (*ctx)
        DIGI_FREE(ctx);

    return OK;
}
#endif /*((!defined(__DISABLE_AES_CIPHERS__)) && defined(__AES_HARDWARE_CIPHER__)) */


/*------------------------------------------------------------------*/

#if(defined(__ENABLE_DES_CIPHER__) && defined(__DES_HARDWARE_CIPHER__))
extern BulkCtx
CreateDESCtx(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt)
{
    MOC_UNUSED(hwAccelCtx);

    if ((DES_KEY_LENGTH != keyLength) ||(NULL == keyMaterial))
        return NULL;  /* bad key size or material */

    fixupParityBits(keyMaterial, keyLength);

    return(BulkCtx)(CreateCtxCommon(keyMaterial, keyLength, encrypt));
}
#endif /*(defined(__ENABLE_DES_CIPHER__) && defined(__DES_HARDWARE_CIPHER__)) */


/*------------------------------------------------------------------*/

#if(defined(__ENABLE_DES_CIPHER__) && defined(__DES_HARDWARE_CIPHER__))
extern MSTATUS
DoDES(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt, ubyte* iv)
{
    uint64_t*   pData = (uint64_t *)data;
    MSTATUS     status = OK;

    if (NULL == ctx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 != (dataLength % DES_BLOCK_SIZE))
    {
        status = ERR_DES_BAD_LENGTH;
        goto exit;
    }

    /* set the key */
    CVMX_MT_3DES_KEY(((cavmCipherContext*)ctx)->key[0], 0);
    CVMX_MT_3DES_KEY(((cavmCipherContext*)ctx)->key[0], 1);     /* For DES */
    CVMX_MT_3DES_KEY(((cavmCipherContext*)ctx)->key[0], 2);     /* For DES */

    /* set the iv */
    CVMX_MT_3DES_IV(*((uint64_t *)iv));

    if (encrypt)
    {
        /* optimize for 64 byte packets */
        while ((THREE_DES_BLOCK_SIZE * 8) <= dataLength)
        {
            CVMX_MT_3DES_ENC_CBC(*pData);       /* 1 */
            CVMX_MF_3DES_RESULT(*pData);
            pData++;

            CVMX_MT_3DES_ENC_CBC(*pData);       /* 2 */
            CVMX_MF_3DES_RESULT(*pData);
            pData++;

            CVMX_MT_3DES_ENC_CBC(*pData);       /* 3 */
            CVMX_MF_3DES_RESULT(*pData);
            pData++;

            CVMX_MT_3DES_ENC_CBC(*pData);       /* 4 */
            CVMX_MF_3DES_RESULT(*pData);
            pData++;

            CVMX_MT_3DES_ENC_CBC(*pData);       /* 5 */
            CVMX_MF_3DES_RESULT(*pData);
            pData++;

            CVMX_MT_3DES_ENC_CBC(*pData);       /* 6 */
            CVMX_MF_3DES_RESULT(*pData);
            pData++;

            CVMX_MT_3DES_ENC_CBC(*pData);       /* 7 */
            CVMX_MF_3DES_RESULT(*pData);
            pData++;

            CVMX_MT_3DES_ENC_CBC(*pData);       /* 8 */
            CVMX_MF_3DES_RESULT(*pData);
            pData++;

            dataLength -= (8 * THREE_DES_BLOCK_SIZE);
        }

        while (THREE_DES_BLOCK_SIZE <= dataLength)
        {
            CVMX_MT_3DES_ENC_CBC(*pData);
            CVMX_MF_3DES_RESULT(*pData);
            pData++;

            dataLength -= THREE_DES_BLOCK_SIZE;
        }
    }
    else
    {
        /* optimize for 64 byte packets */
        while ((THREE_DES_BLOCK_SIZE * 8) <= dataLength)
        {
            CVMX_MT_3DES_DEC_CBC(*pData);       /* 1 */
            CVMX_MF_3DES_RESULT(*pData);
            pData++;

            CVMX_MT_3DES_DEC_CBC(*pData);       /* 2 */
            CVMX_MF_3DES_RESULT(*pData);
            pData++;

            CVMX_MT_3DES_DEC_CBC(*pData);       /* 3 */
            CVMX_MF_3DES_RESULT(*pData);
            pData++;

            CVMX_MT_3DES_DEC_CBC(*pData);       /* 4 */
            CVMX_MF_3DES_RESULT(*pData);
            pData++;

            CVMX_MT_3DES_DEC_CBC(*pData);       /* 5 */
            CVMX_MF_3DES_RESULT(*pData);
            pData++;

            CVMX_MT_3DES_DEC_CBC(*pData);       /* 6 */
            CVMX_MF_3DES_RESULT(*pData);
            pData++;

            CVMX_MT_3DES_DEC_CBC(*pData);       /* 7 */
            CVMX_MF_3DES_RESULT(*pData);
            pData++;

            CVMX_MT_3DES_DEC_CBC(*pData);       /* 8 */
            CVMX_MF_3DES_RESULT(*pData);
            pData++;

            dataLength -= (8 * THREE_DES_BLOCK_SIZE);
        }

        while (THREE_DES_BLOCK_SIZE <= dataLength)
        {
            CVMX_MT_3DES_DEC_CBC(*pData);
            CVMX_MF_3DES_RESULT(*pData);
            pData++;

            dataLength -= THREE_DES_BLOCK_SIZE;
        }
    }

    /* get the IV */
    CVMX_MF_3DES_IV(*((uint64_t *)iv));

exit:
    return status;
}
#endif /*(defined(__ENABLE_DES_CIPHER__) && defined(__DES_HARDWARE_CIPHER__)) */


/*------------------------------------------------------------------*/

#if(defined(__ENABLE_DES_CIPHER__) && defined(__DES_HARDWARE_CIPHER__))
extern MSTATUS
DeleteDESCtx(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx* ctx)
{
    MOC_UNUSED(hwAccelCtx);

    if (*ctx)
        DIGI_FREE(ctx);

    return OK;
}
#endif /*(defined(__ENABLE_DES_CIPHER__) && defined(__DES_HARDWARE_CIPHER__)) */


/*------------------------------------------------------------------*/

#if((!defined(__DISABLE_3DES_CIPHERS__)) && defined(__3DES_HARDWARE_CIPHER__))
extern BulkCtx
Create3DESCtx(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt)
{
    MOC_UNUSED(hwAccelCtx);

    if ((THREE_DES_KEY_LENGTH != keyLength) ||(NULL == keyMaterial))
        return NULL;

    fixupParityBits(keyMaterial, keyLength);

    return CreateCtxCommon(keyMaterial, keyLength, encrypt);
}
#endif /*((!defined(__DISABLE_3DES_CIPHERS__)) && defined(__3DES_HARDWARE_CIPHER__)) */


/*------------------------------------------------------------------*/

#if((!defined(__DISABLE_3DES_CIPHERS__)) && defined(__3DES_HARDWARE_CIPHER__))
extern MSTATUS
Do3DES(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt, ubyte* iv)
{
    uint64_t*   pData = (uint64_t *)data;
    MSTATUS     status = OK;

    if (NULL == ctx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 != (dataLength % THREE_DES_BLOCK_SIZE))
    {
        status = ERR_DES_BAD_LENGTH;
        goto exit;
    }

    /* set the key */
    CVMX_MT_3DES_KEY(((cavmCipherContext*)ctx)->key[0], 0);
    CVMX_MT_3DES_KEY(((cavmCipherContext*)ctx)->key[1], 1);
    CVMX_MT_3DES_KEY(((cavmCipherContext*)ctx)->key[2], 2);

    /* set the iv */
    CVMX_MT_3DES_IV(*((uint64_t *)iv));

    if (encrypt)
    {
        /* optimize for 64 byte packets */
        while ((THREE_DES_BLOCK_SIZE * 8) <= dataLength)
        {
            CVMX_MT_3DES_ENC_CBC(*pData);       /* 1 */
            CVMX_MF_3DES_RESULT(*pData);
            pData++;

            CVMX_MT_3DES_ENC_CBC(*pData);       /* 2 */
            CVMX_MF_3DES_RESULT(*pData);
            pData++;

            CVMX_MT_3DES_ENC_CBC(*pData);       /* 3 */
            CVMX_MF_3DES_RESULT(*pData);
            pData++;

            CVMX_MT_3DES_ENC_CBC(*pData);       /* 4 */
            CVMX_MF_3DES_RESULT(*pData);
            pData++;

            CVMX_MT_3DES_ENC_CBC(*pData);       /* 5 */
            CVMX_MF_3DES_RESULT(*pData);
            pData++;

            CVMX_MT_3DES_ENC_CBC(*pData);       /* 6 */
            CVMX_MF_3DES_RESULT(*pData);
            pData++;

            CVMX_MT_3DES_ENC_CBC(*pData);       /* 7 */
            CVMX_MF_3DES_RESULT(*pData);
            pData++;

            CVMX_MT_3DES_ENC_CBC(*pData);       /* 8 */
            CVMX_MF_3DES_RESULT(*pData);
            pData++;

            dataLength -= (8 * THREE_DES_BLOCK_SIZE);
        }

        while (THREE_DES_BLOCK_SIZE <= dataLength)
        {
            CVMX_MT_3DES_ENC_CBC(*pData);
            CVMX_MF_3DES_RESULT(*pData);
            pData++;

            dataLength -= THREE_DES_BLOCK_SIZE;
        }
    }
    else
    {
        /* optimize for 64 byte packets */
        while ((THREE_DES_BLOCK_SIZE * 8) <= dataLength)
        {
            CVMX_MT_3DES_DEC_CBC(*pData);       /* 1 */
            CVMX_MF_3DES_RESULT(*pData);
            pData++;

            CVMX_MT_3DES_DEC_CBC(*pData);       /* 2 */
            CVMX_MF_3DES_RESULT(*pData);
            pData++;

            CVMX_MT_3DES_DEC_CBC(*pData);       /* 3 */
            CVMX_MF_3DES_RESULT(*pData);
            pData++;

            CVMX_MT_3DES_DEC_CBC(*pData);       /* 4 */
            CVMX_MF_3DES_RESULT(*pData);
            pData++;

            CVMX_MT_3DES_DEC_CBC(*pData);       /* 5 */
            CVMX_MF_3DES_RESULT(*pData);
            pData++;

            CVMX_MT_3DES_DEC_CBC(*pData);       /* 6 */
            CVMX_MF_3DES_RESULT(*pData);
            pData++;

            CVMX_MT_3DES_DEC_CBC(*pData);       /* 7 */
            CVMX_MF_3DES_RESULT(*pData);
            pData++;

            CVMX_MT_3DES_DEC_CBC(*pData);       /* 8 */
            CVMX_MF_3DES_RESULT(*pData);
            pData++;

            dataLength -= (8 * THREE_DES_BLOCK_SIZE);
        }

        while (THREE_DES_BLOCK_SIZE <= dataLength)
        {
            CVMX_MT_3DES_DEC_CBC(*pData);
            CVMX_MF_3DES_RESULT(*pData);
            pData++;

            dataLength -= THREE_DES_BLOCK_SIZE;
        }
    }

    /* need to get the IV */
    CVMX_MF_3DES_IV(*((uint64_t *)iv));

exit:
    return status;
}
#endif /*((!defined(__DISABLE_3DES_CIPHERS__)) && defined(__3DES_HARDWARE_CIPHER__)) */


/*------------------------------------------------------------------*/

#if((!defined(__DISABLE_3DES_CIPHERS__)) && defined(__3DES_HARDWARE_CIPHER__))
extern MSTATUS
Delete3DESCtx(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx* ctx)
{
    MOC_UNUSED(hwAccelCtx);

    if (*ctx)
        DIGI_FREE(ctx);

    return OK;
}
#endif /*((!defined(__DISABLE_3DES_CIPHERS__)) && defined(__3DES_HARDWARE_CIPHER__)) */


/*------------------------------------------------------------------*/

#ifdef __MD5_HARDWARE_HASH__
extern MSTATUS
MD5Alloc_m(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context)
{
    if (NULL == (*pp_context = MALLOC(sizeof(MD5_CTX))))
        return ERR_MEM_ALLOC_FAIL;
    else
        return OK;
}
#endif


/*------------------------------------------------------------------*/

#ifdef __MD5_HARDWARE_HASH__
extern MSTATUS
MD5Free_m(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context)
{
    if (NULL != *pp_context)
    {
        FREE(*pp_context);
        *pp_context = NULL;
    }

    return OK;
}
#endif


/*------------------------------------------------------------------*/

#ifdef __MD5_HARDWARE_HASH__
static const ubyte MD5_PADDING[64] =
{
  0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};
#endif


/*------------------------------------------------------------------*/

/* Encodes input (ubyte4) into output (ubyte). Assumes len is a multiple of 4. */
#ifdef __MD5_HARDWARE_HASH__
static void
MD5_encode(ubyte *output, const unsigned long long *input, ubyte4 len)
{
    ubyte4 i, j;

    for (i = 0, j = 0; j < len; i++, j += 8)
    {
        output[j]   = (ubyte)(input[i] & 0xff);
        output[j+1] = (ubyte)((input[i] >> 8) & 0xff);
        output[j+2] = (ubyte)((input[i] >> 16) & 0xff);
        output[j+3] = (ubyte)((input[i] >> 24) & 0xff);
        output[j+4] = (ubyte)((input[i] >> 32) & 0xff);
        output[j+5] = (ubyte)((input[i] >> 40) & 0xff);
        output[j+6] = (ubyte)((input[i] >> 48) & 0xff);
        output[j+7] = (ubyte)((input[i] >> 56) & 0xff);
    }
}
#endif


/*------------------------------------------------------------------*/

#ifdef __MD5_HARDWARE_HASH__
extern MSTATUS
MD5Init_m(MOC_HASH(hwAccelDescr hwAccelCtx) MD5_CTX *pContext)
{
    MOC_UNUSED(hwAccelCtx);
    MSTATUS status;

    if (NULL == pContext)
    {
        status = ERR_NULL_POINTER;
    }
    else
    {
        pContext->hashBlocks[0] = 0x0123456789abcdefULL;
        pContext->hashBlocks[1] = 0xfedcba9876543210ULL;

        pContext->mesgLength      = 0;
        pContext->hashBufferIndex = 0;

        status = OK;
    }

    return status;
}
#endif


/*------------------------------------------------------------------*/

#ifdef __MD5_HARDWARE_HASH__
extern MSTATUS
MD5Update_m(MOC_HASH(hwAccelDescr hwAccelCtx) MD5_CTX *pContext,
            const ubyte *pData, ubyte4 dataLen)
{
    MSTATUS status = OK;

    if ((NULL == pContext) || (NULL == pData))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pContext->mesgLength += dataLen;

    /* some remaining from last time ?*/
    if (0 < pContext->hashBufferIndex)
    {
        ubyte4 numToCopy = MD5_BLOCK_SIZE - pContext->hashBufferIndex;

        if (numToCopy > dataLen)
            numToCopy = dataLen;

        DIGI_MEMCPY(((ubyte *)pContext->hashBuffer) + pContext->hashBufferIndex, pData, numToCopy);

        pData += numToCopy;
        dataLen -= numToCopy;
        pContext->hashBufferIndex += numToCopy;

        if (MD5_BLOCK_SIZE == pContext->hashBufferIndex)
        {
            CVMX_MT_HSH_IV(pContext->hashBlocks[0], 0);
            CVMX_MT_HSH_IV(pContext->hashBlocks[1], 1);

            CVMX_MT_HSH_DAT(pContext->hashBuffer[0], 0);
            CVMX_MT_HSH_DAT(pContext->hashBuffer[1], 1);
            CVMX_MT_HSH_DAT(pContext->hashBuffer[2], 2);
            CVMX_MT_HSH_DAT(pContext->hashBuffer[3], 3);
            CVMX_MT_HSH_DAT(pContext->hashBuffer[4], 4);
            CVMX_MT_HSH_DAT(pContext->hashBuffer[5], 5);
            CVMX_MT_HSH_DAT(pContext->hashBuffer[6], 6);
            CVMX_MT_HSH_STARTMD5(pContext->hashBuffer[7]);

            CVMX_MF_HSH_IV(pContext->hashBlocks[0], 0);
            CVMX_MF_HSH_IV(pContext->hashBlocks[1], 1);

            pContext->hashBufferIndex = 0;
        }
    }

    if (MD5_BLOCK_SIZE <= dataLen)
    {
        const uint64_t *pData64 = (const uint64_t *)pData;

        CVMX_MT_HSH_IV(pContext->hashBlocks[0], 0);
        CVMX_MT_HSH_IV(pContext->hashBlocks[1], 1);

        /* process as much as possible right now */
        while (MD5_BLOCK_SIZE <= dataLen)
        {
            CVMX_MT_HSH_DAT(*pData64++, 0);
            CVMX_MT_HSH_DAT(*pData64++, 1);
            CVMX_MT_HSH_DAT(*pData64++, 2);
            CVMX_MT_HSH_DAT(*pData64++, 3);
            CVMX_MT_HSH_DAT(*pData64++, 4);
            CVMX_MT_HSH_DAT(*pData64++, 5);
            CVMX_MT_HSH_DAT(*pData64++, 6);
            CVMX_MT_HSH_STARTMD5(*pData64++);

            dataLen -= MD5_BLOCK_SIZE;
        }

        pData = (const ubyte *)pData64;
        CVMX_MF_HSH_IV(pContext->hashBlocks[0], 0);
        CVMX_MF_HSH_IV(pContext->hashBlocks[1], 1);
    }

    /* store the rest in the buffer */
    if (dataLen > 0)
    {
        DIGI_MEMCPY(((ubyte *)pContext->hashBuffer) + pContext->hashBufferIndex, pData, dataLen);
        pContext->hashBufferIndex += dataLen;
    }

exit:
    return status;
}
#endif /* __MD5_HARDWARE_HASH__ */


/*------------------------------------------------------------------*/

#ifdef __MD5_HARDWARE_HASH__
extern MSTATUS
MD5Final_m(MOC_HASH(hwAccelDescr hwAccelCtx) MD5_CTX *pContext, ubyte *pMd5Output)
{
    ubyte   bits[8];
    ubyte4  count;
    ubyte4  padLen;
    MSTATUS status;

    if ((NULL == pContext) || (NULL == pMd5Output))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* make bit count */
    pContext->mesgLength <<= 3;
    MD5_encode(bits, &(pContext->mesgLength), 8);

    /* calc pad length */
    count = (ubyte4)(pContext->mesgLength);
    count = ((count >> 3) & 0x3f);

    padLen = ((MD5_BLOCK_SIZE - 8) <= count) ?
        ((MD5_BLOCK_SIZE + (MD5_BLOCK_SIZE - 8)) - count) : ((MD5_BLOCK_SIZE - 8) - count);

    /* hash pad */
    if (OK > (status = MD5Update_m(MOC_HASH(hwAccelCtx) pContext, MD5_PADDING, padLen)))
        goto exit;

    /* hash bit length */
    if (OK > (status = MD5Update_m(MOC_HASH(hwAccelCtx) pContext, bits, 8)))
        goto exit;

    /* output final hash */
    *(((uint64_t *)pMd5Output))     = pContext->hashBlocks[0];
    *(((uint64_t *)pMd5Output) + 1) = pContext->hashBlocks[1];

exit:
    return status;
}
#endif /* __MD5_HARDWARE_HASH__ */


/*------------------------------------------------------------------*/

#ifdef __MD5_HARDWARE_HASH__
extern MSTATUS
MD5_completeDigest(MOC_HASH(hwAccelDescr hwAccelCtx) ubyte *pData, ubyte4 dataLen, ubyte *pMdOutput)
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
#endif /* __MD5_HARDWARE_HASH__ */


/*------------------------------------------------------------------*/

#ifdef __SHA1_HARDWARE_HASH__
extern MSTATUS
SHA1_allocDigest(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context)
{
    return DIGI_MALLOC(pp_context, sizeof(shaDescr));
}
#endif


/*------------------------------------------------------------------*/

#ifdef __SHA1_HARDWARE_HASH__
extern MSTATUS
SHA1_freeDigest(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context)
{
    return DIGI_FREE(pp_context);
}
#endif


/*------------------------------------------------------------------*/

#ifdef __SHA1_HARDWARE_HASH__
extern MSTATUS
SHA1_initDigest(MOC_HASH(hwAccelDescr hwAccelCtx) shaDescr *p_shaContext)
{
    MSTATUS status;

    if (NULL == p_shaContext)
    {
        status = ERR_NULL_POINTER;
    }
    else
    {
        p_shaContext->hashBlocks[0] = 0x67452301efcdab89ULL;
        p_shaContext->hashBlocks[1] = 0x98badcfe10325476ULL;
        p_shaContext->hashBlocks[2] = 0xc3d2e1f000000000ULL;

        p_shaContext->mesgLength = 0;
        p_shaContext->hashBufferIndex = 0;

        status = OK;
    }

    return status;
}
#endif


/*------------------------------------------------------------------*/

#ifdef __SHA1_HARDWARE_HASH__
extern MSTATUS
SHA1_updateDigest(MOC_HASH(hwAccelDescr hwAccelCtx) shaDescr *p_shaContext,
                  const ubyte *pData, ubyte4 dataLen)
{
    MSTATUS status = OK;

    if ((NULL == p_shaContext) || (NULL == pData))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    p_shaContext->mesgLength += dataLen;

    /* some remaining from last time ?*/
    if (p_shaContext->hashBufferIndex > 0)
    {
        sbyte4 numToCopy = SHA1_BLOCK_SIZE - p_shaContext->hashBufferIndex;

        if ((sbyte4)dataLen < numToCopy)
            numToCopy = dataLen;

        DIGI_MEMCPY(((ubyte *)p_shaContext->hashBuffer) + p_shaContext->hashBufferIndex, pData, numToCopy);
        pData += numToCopy;
        dataLen -= numToCopy;
        p_shaContext->hashBufferIndex += numToCopy;

        if (SHA1_BLOCK_SIZE == p_shaContext->hashBufferIndex)
        {
            CVMX_MT_HSH_IV(p_shaContext->hashBlocks[0], 0);
            CVMX_MT_HSH_IV(p_shaContext->hashBlocks[1], 1);
            CVMX_MT_HSH_IV(p_shaContext->hashBlocks[2], 2);

            CVMX_MT_HSH_DAT(p_shaContext->hashBuffer[0], 0);
            CVMX_MT_HSH_DAT(p_shaContext->hashBuffer[1], 1);
            CVMX_MT_HSH_DAT(p_shaContext->hashBuffer[2], 2);
            CVMX_MT_HSH_DAT(p_shaContext->hashBuffer[3], 3);
            CVMX_MT_HSH_DAT(p_shaContext->hashBuffer[4], 4);
            CVMX_MT_HSH_DAT(p_shaContext->hashBuffer[5], 5);
            CVMX_MT_HSH_DAT(p_shaContext->hashBuffer[6], 6);
            CVMX_MT_HSH_STARTSHA(p_shaContext->hashBuffer[7]);

            CVMX_MF_HSH_IV(p_shaContext->hashBlocks[0], 0);
            CVMX_MF_HSH_IV(p_shaContext->hashBlocks[1], 1);
            CVMX_MF_HSH_IV(p_shaContext->hashBlocks[2], 2);

            p_shaContext->hashBufferIndex = 0;
        }
    }

    if (SHA1_BLOCK_SIZE <= dataLen)
    {
        const uint64_t *pData64 = (const uint64_t *)pData;

        CVMX_MT_HSH_IV(p_shaContext->hashBlocks[0], 0);
        CVMX_MT_HSH_IV(p_shaContext->hashBlocks[1], 1);
        CVMX_MT_HSH_IV(p_shaContext->hashBlocks[2], 2);

        /* process as much as possible right now */
        while (SHA1_BLOCK_SIZE <= dataLen)
        {
            CVMX_MT_HSH_DAT(*pData64++, 0);
            CVMX_MT_HSH_DAT(*pData64++, 1);
            CVMX_MT_HSH_DAT(*pData64++, 2);
            CVMX_MT_HSH_DAT(*pData64++, 3);
            CVMX_MT_HSH_DAT(*pData64++, 4);
            CVMX_MT_HSH_DAT(*pData64++, 5);
            CVMX_MT_HSH_DAT(*pData64++, 6);
            CVMX_MT_HSH_STARTSHA(*pData64++);

            dataLen -= SHA1_BLOCK_SIZE;
        }

        CVMX_MF_HSH_IV(p_shaContext->hashBlocks[0], 0);
        CVMX_MF_HSH_IV(p_shaContext->hashBlocks[1], 1);
        CVMX_MF_HSH_IV(p_shaContext->hashBlocks[2], 2);

        pData = (const ubyte *)pData64;
    }

    /* store the rest in the buffer */
    if (dataLen > 0)
    {
        DIGI_MEMCPY(((ubyte *)p_shaContext->hashBuffer) + p_shaContext->hashBufferIndex, pData, dataLen);
        p_shaContext->hashBufferIndex += dataLen;
    }

exit:
    return status;

} /* SHA1_updateDigest */

#endif /* __SHA1_HARDWARE_HASH__ */


/*------------------------------------------------------------------*/

#ifdef __SHA1_HARDWARE_HASH__
extern MSTATUS
SHA1_finalDigest(MOC_HASH(hwAccelDescr hwAccelCtx) shaDescr *p_shaContext, ubyte *pShaOutput)
{
    MSTATUS status = OK;

    if ((NULL == p_shaContext) || (NULL == pShaOutput))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* we should have room to append one byte onto the message */
    ((ubyte *)p_shaContext->hashBuffer)[p_shaContext->hashBufferIndex] = 0x80;
    p_shaContext->hashBufferIndex++;

    CVMX_MT_HSH_IV(p_shaContext->hashBlocks[0], 0);
    CVMX_MT_HSH_IV(p_shaContext->hashBlocks[1], 1);
    CVMX_MT_HSH_IV(p_shaContext->hashBlocks[2], 2);

    /* less than 8 bytes available -> extra round */
    if (p_shaContext->hashBufferIndex > SHA1_BLOCK_SIZE - 8)
    {
        while (p_shaContext->hashBufferIndex < SHA1_BLOCK_SIZE)
        {
            ((ubyte *)p_shaContext->hashBuffer)[p_shaContext->hashBufferIndex++] = 0x00;
        }

        CVMX_MT_HSH_DAT(p_shaContext->hashBuffer[0], 0);
        CVMX_MT_HSH_DAT(p_shaContext->hashBuffer[1], 1);
        CVMX_MT_HSH_DAT(p_shaContext->hashBuffer[2], 2);
        CVMX_MT_HSH_DAT(p_shaContext->hashBuffer[3], 3);
        CVMX_MT_HSH_DAT(p_shaContext->hashBuffer[4], 4);
        CVMX_MT_HSH_DAT(p_shaContext->hashBuffer[5], 5);
        CVMX_MT_HSH_DAT(p_shaContext->hashBuffer[6], 6);
        CVMX_MT_HSH_STARTSHA(p_shaContext->hashBuffer[7]);

        p_shaContext->hashBufferIndex = 0;
    }

    /* last round */
    while (p_shaContext->hashBufferIndex < SHA1_BLOCK_SIZE - 8)
    {
        ((ubyte *)p_shaContext->hashBuffer)[p_shaContext->hashBufferIndex++] = 0x00;
    }

    /* fill in message bit length */
    /* bytes to bits */
    p_shaContext->mesgLength <<= 3;

    *((uint64_t *)(&(((ubyte *)p_shaContext->hashBuffer)[SHA1_BLOCK_SIZE - 8]))) = p_shaContext->mesgLength;

    CVMX_MT_HSH_DAT(p_shaContext->hashBuffer[0], 0);
    CVMX_MT_HSH_DAT(p_shaContext->hashBuffer[1], 1);
    CVMX_MT_HSH_DAT(p_shaContext->hashBuffer[2], 2);
    CVMX_MT_HSH_DAT(p_shaContext->hashBuffer[3], 3);
    CVMX_MT_HSH_DAT(p_shaContext->hashBuffer[4], 4);
    CVMX_MT_HSH_DAT(p_shaContext->hashBuffer[5], 5);
    CVMX_MT_HSH_DAT(p_shaContext->hashBuffer[6], 6);
    CVMX_MT_HSH_STARTSHA(p_shaContext->hashBuffer[7]);

    CVMX_MF_HSH_IV(p_shaContext->hashBlocks[0], 0);
    CVMX_MF_HSH_IV(p_shaContext->hashBlocks[1], 1);
    CVMX_MF_HSH_IV(p_shaContext->hashBlocks[2], 2);

    /* return the output */
    DIGI_MEMCPY(pShaOutput, (ubyte *)(p_shaContext->hashBlocks), SHA1_RESULT_SIZE);

exit:
    return status;

} /* SHA1_finalDigest */

#endif /* __SHA1_HARDWARE_HASH__ */


/*------------------------------------------------------------------*/

#ifdef __SHA1_HARDWARE_HASH__
extern MSTATUS
SHA1_completeDigest(MOC_HASH(hwAccelDescr hwAccelCtx) ubyte *pData, ubyte4 dataLen, ubyte *pShaOutput)
{
    shaDescr shaContext;
    MSTATUS  status;

    if (OK > (status = SHA1_initDigest(MOC_HASH(hwAccelCtx) &shaContext)))
        goto exit;

    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) &shaContext, pData, dataLen)))
        goto exit;

    status = SHA1_finalDigest(MOC_HASH(hwAccelCtx) &shaContext, pShaOutput);

exit:
    return status;
}
#endif /* __SHA1_HARDWARE_HASH__ */


/*------------------------------------------------------------------*/

#define CAVM_RNG_RAND_BUF_SIZE      1024

#ifdef __DISABLE_DIGICERT_RNG__
typedef struct
{
    /* to speed up performance we will create more random bits than needed... */
    hwAccelDescr    hwAccelCtx;
    ubyte           rngBuf[CAVM_RNG_RAND_BUF_SIZE];
    ubyte4          rngBufIndex;
    ubyte4          numBytesSinceLastRng;

    intBoolean      isRngBeingCaptured;

} cavmAsyncRngCtx;
#endif


/*------------------------------------------------------------------*/

#ifdef __DISABLE_DIGICERT_RNG__
extern MSTATUS
RANDOM_acquireContext(randomContext **pp_randomContext)
{
    hwAccelDescr        hwAccelCtx;
    cavmAsyncRngCtx*    pRngCtx = NULL;
    MSTATUS             status;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx)))
        goto exit;

    if (OK != (status = DIGI_MALLOC((void **)&pRngCtx, sizeof(cavmAsyncRngCtx))))
    {
        pRngCtx->isRngBeingCaptured   = TRUE;
        pRngCtx->rngBufIndex          = CAVM_RNG_RAND_BUF_SIZE;
        pRngCtx->numBytesSinceLastRng = 0;
        pRngCtx->hwAccelCtx           = hwAccelCtx;
        *pp_randomContext             = (randomContext *)pRngCtx;

        status = DoCryptCommon(pRngCtx->hwAccelCtx, NULL, 0, NULL, 0,
                               NULL, 0, pRngCtx->rngBuf, CAVM_RNG_RAND_BUF_SIZE, NULL, 0,
                               DPD_HEADER_RNG);

    }
    else
    {
        HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);
    }

exit:
    return status;
}
#endif


/*------------------------------------------------------------------*/

#ifdef __DISABLE_DIGICERT_RNG__
extern MSTATUS
RANDOM_releaseContext(randomContext **pp_randomContext)
{
    cavmAsyncRngCtx* pRngCtx = (cavmAsyncRngCtx*)(*pp_randomContext);
    MSTATUS status;

    if (NULL == pRngCtx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    DIGI_FREE((void **)pp_randomContext);

exit:
    return status;
}
#endif


/*------------------------------------------------------------------*/

#ifdef __DISABLE_DIGICERT_RNG__
extern MSTATUS
RANDOM_numberGenerator(randomContext *pRandomContext, ubyte *pBuffer, sbyte4 bufSize)
{
    cavmAsyncRngCtx*     pRngCtx = (cavmAsyncRngCtx *)(pRandomContext);
    ubyte4              tmpBufIndex;
    sbyte4              numBytesToCopy;
    mahCompletionDescr* pCell = NULL;
    MSTATUS             status = OK;

    while (0 < bufSize)
    {
        tmpBufIndex = pRngCtx->rngBufIndex;

        /* set aside our bytes */
        numBytesToCopy = CAVM_RNG_RAND_BUF_SIZE - pRngCtx->rngBufIndex;

        if (numBytesToCopy > bufSize)
            numBytesToCopy = bufSize;

        if (0 == numBytesToCopy)
        {
            pRngCtx->rngBufIndex = 0;
            continue;
        }

        /* update counters and indices */
        pRngCtx->numBytesSinceLastRng += numBytesToCopy;
        pRngCtx->rngBufIndex += numBytesToCopy;

        /* pull bytes out of buffered rng data */
        if (pRngCtx->numBytesSinceLastRng >= (CAVM_RNG_RAND_BUF_SIZE / 2))
        {
            if (FALSE == pRngCtx->isRngBeingCaptured)
            {
                pRngCtx->isRngBeingCaptured = TRUE;

                status = DoCryptCommon(pRngCtx->hwAccelCtx, NULL, 0, NULL, 0,
                                       NULL, 0, pRngCtx->rngBuf, CAVM_RNG_RAND_BUF_SIZE, NULL, 0,
                                       DPD_HEADER_RNG);

                if (OK > status)
                    break;
            }
        }

        /* some sort of timeout code is in order here */
        DIGI_MEMCPY(pBuffer, &pRngCtx->rngBuf[tmpBufIndex], numBytesToCopy);
        bufSize = bufSize - numBytesToCopy;
        pBuffer = pBuffer + numBytesToCopy;
    }

    return status;
}
#endif


/*------------------------------------------------------------------*/

#ifdef __DISABLE_DIGICERT_RNG__
extern sbyte4
RANDOM_rngFun(void* rngFunArg, ubyte4 length, ubyte *buffer)
{
    return RANDOM_numberGenerator((randomContext *) rngFunArg,
                                    buffer, (sbyte4) length);
}
#endif

#endif /*(defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__) && defined(__ENABLE_FREESCALE_8548_HARDWARE_ACCEL__)) */

