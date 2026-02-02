/*
 * freescale_async_8315.c
 *
 * Freescale 8315 Hardware Acceleration Asynchronous Adapter
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

#if (defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__) && defined(__ENABLE_FREESCALE_8315_HARDWARE_ACCEL__))

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
#include "../../crypto/crypto.h"
#include "../../crypto/md5.h"
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

#include "../../crypto/hw_offload/freescale_8315.h"
#include "../../harness/harness.h"
#include "../../harness/harness_intf.h"

#if defined(__LINUX_RTOS__) && defined(__KERNEL__)
#include <linux/hardirq.h>
#endif


/*------------------------------------------------------------------*/

#if (defined(__HW_OFFLOAD_SINGLE_PASS_SUPPORT__))
#define MDEU_NEW_E1_CONT_BIT                    FSL_BIT(16 + 0)
#define MDEU_NEW_E1_CICV_BIT                    FSL_BIT(16 + 1)
#define MDEU_NEW_E1_SMAC_BIT                    FSL_BIT(16 + 2)
#define MDEU_NEW_E1_INIT_BIT                    FSL_BIT(16 + 3)
#define MDEU_NEW_E1_HMAC_BIT                    FSL_BIT(16 + 4)

#define AESU_E0_SINGLE_PASS_DECRYPT             (AESU_EU0 | DPD_HDR_OP_MODE_DATA_SHIFT(AES_CBC_MODE|AES_DECRYPT) | DPD_HEADER_IN_BIT)
#define AESU_E0_SINGLE_PASS_ENCRYPT             (AESU_EU0 | DPD_HDR_OP_MODE_DATA_SHIFT(AES_CBC_MODE|AES_ENCRYPT))

#define TDES_E0_SINGLE_PASS_DECRYPT             (TDES_EU0 | DPD_HDR_OP_MODE_DATA_SHIFT(TDES_CBC_MODE|TDES_DECRYPT) | DPD_HEADER_IN_BIT)
#define TDES_E0_SINGLE_PASS_ENCRYPT             (TDES_EU0 | DPD_HDR_OP_MODE_DATA_SHIFT(TDES_CBC_MODE|TDES_ENCRYPT))

#define SDES_E0_SINGLE_PASS_DECRYPT             (SDES_EU0 | DPD_HDR_OP_MODE_DATA_SHIFT(DES_CBC_MODE|DES_DECRYPT) | DPD_HEADER_IN_BIT)
#define SDES_E0_SINGLE_PASS_ENCRYPT             (SDES_EU0 | DPD_HDR_OP_MODE_DATA_SHIFT(DES_CBC_MODE|DES_ENCRYPT))

#define ARC4_E0_SINGLE_PASS_DECRYPT_START       (ARC4_EU0 | DPD_HDR_OP_MODE_DATA_SHIFT(RC4_DC)| DPD_HEADER_IN_BIT)
#define ARC4_E0_SINGLE_PASS_DECRYPT_CONTINUE    (ARC4_EU0 | DPD_HDR_OP_MODE_DATA_SHIFT(RC4_CS|RC4_DC|RC4_PP)| DPD_HEADER_IN_BIT)

#define ARC4_E0_SINGLE_PASS_ENCRYPT_START       (ARC4_EU0 | DPD_HDR_OP_MODE_DATA_SHIFT(RC4_DC))
#define ARC4_E0_SINGLE_PASS_ENCRYPT_CONTINUE    (ARC4_EU0 | DPD_HDR_OP_MODE_DATA_SHIFT(RC4_CS|RC4_DC|RC4_PP))

#define MDEU_NEW_E1_SINGLE_PASS_SHA1            (MDEU_EU1 | MDEU_NEW_E1_INIT_BIT)
#define MDEU_NEW_E1_SINGLE_PASS_MD5             (MDEU_EU1 | MDEU_NEW_E1_INIT_BIT | FSL_BIT(16 + 6))


static ubyte4 mSinglePassDpdHeaderLookup[] =
{
    /* SINGLE_PASS_AES_SHA1_IN   (0) */     (AESU_E0_SINGLE_PASS_DECRYPT | MDEU_NEW_E1_SINGLE_PASS_SHA1),
    /* SINGLE_PASS_AES_SHA1_OUT  (1) */     (AESU_E0_SINGLE_PASS_ENCRYPT | MDEU_NEW_E1_SINGLE_PASS_SHA1),
    /* SINGLE_PASS_AES_MD5_IN    (2) */     (AESU_E0_SINGLE_PASS_DECRYPT | MDEU_NEW_E1_SINGLE_PASS_MD5),
    /* SINGLE_PASS_AES_MD5_OUT   (3) */     (AESU_E0_SINGLE_PASS_ENCRYPT | MDEU_NEW_E1_SINGLE_PASS_MD5),
    /* SINGLE_PASS_3DES_SHA1_IN  (4) */     (TDES_E0_SINGLE_PASS_DECRYPT | MDEU_NEW_E1_SINGLE_PASS_SHA1),
    /* SINGLE_PASS_3DES_SHA1_OUT (5) */     (TDES_E0_SINGLE_PASS_ENCRYPT | MDEU_NEW_E1_SINGLE_PASS_SHA1),
    /* SINGLE_PASS_3DES_MD5_IN   (6) */     (TDES_E0_SINGLE_PASS_DECRYPT | MDEU_NEW_E1_SINGLE_PASS_MD5),
    /* SINGLE_PASS_3DES_MD5_OUT  (7) */     (TDES_E0_SINGLE_PASS_ENCRYPT | MDEU_NEW_E1_SINGLE_PASS_MD5),
    /* SINGLE_PASS_DES_SHA1_IN   (8) */     (SDES_E0_SINGLE_PASS_DECRYPT | MDEU_NEW_E1_SINGLE_PASS_SHA1),
    /* SINGLE_PASS_DES_SHA1_OUT  (9) */     (SDES_E0_SINGLE_PASS_ENCRYPT | MDEU_NEW_E1_SINGLE_PASS_SHA1),
    /* SINGLE_PASS_DES_MD5_IN    (10) */    (SDES_E0_SINGLE_PASS_DECRYPT | MDEU_NEW_E1_SINGLE_PASS_MD5),
    /* SINGLE_PASS_DES_MD5_OUT   (11) */    (SDES_E0_SINGLE_PASS_ENCRYPT | MDEU_NEW_E1_SINGLE_PASS_MD5),
    /* SINGLE_PASS_RC4_SHA1_IN   (12) */    (ARC4_EU0 | DPD_HDR_DESC_TLS_SSL_STREAM | MDEU_NEW_E1_SINGLE_PASS_SHA1),   /* ARC4 EU0 bits will be OR'd by single pass handlers */
    /* SINGLE_PASS_RC4_SHA1_OUT  (13) */    (ARC4_EU0 | DPD_HDR_DESC_TLS_SSL_STREAM | MDEU_NEW_E1_SINGLE_PASS_SHA1),
    /* SINGLE_PASS_RC4_MD5_IN    (14) */    (ARC4_EU0 | DPD_HDR_DESC_TLS_SSL_STREAM | MDEU_NEW_E1_SINGLE_PASS_MD5),
    /* SINGLE_PASS_RC4_MD5_OUT   (15) */    (ARC4_EU0 | DPD_HDR_DESC_TLS_SSL_STREAM | MDEU_NEW_E1_SINGLE_PASS_MD5)
#if 0
    /* SINGLE_PASS_NULL_SHA1_IN  (16) */    (AESU_E0_SINGLE_PASS_ENCRYPT | MDEU_NEW_E1_SINGLE_PASS_SHA1),
    /* SINGLE_PASS_NULL_SHA1_OUT (17) */    (AESU_E0_SINGLE_PASS_ENCRYPT | MDEU_NEW_E1_SINGLE_PASS_SHA1),
    /* SINGLE_PASS_NULL_MD5_IN   (18) */    (AESU_E0_SINGLE_PASS_ENCRYPT | MDEU_NEW_E1_SINGLE_PASS_MD5),
    /* SINGLE_PASS_NULL_MD5_OUT  (19) */    (AESU_E0_SINGLE_PASS_ENCRYPT | MDEU_NEW_E1_SINGLE_PASS_MD5)
#endif
};

/* single pass related definitions */
#define SIZEOF_SINGLE_PASS_LOOKUP_TABLE     (sizeof(mSinglePassDpdHeaderLookup) / sizeof(ubyte4))
#define FORM_LE(X,Y)                        ((X << 16) | (Y << 8))

#endif /* (defined(__HW_OFFLOAD_SINGLE_PASS_SUPPORT__)) */


/*------------------------------------------------------------------*/

#define MAX_SIZE_RC4_SBOX       (259)
#define MIN_PK_BYTES_LENGTH     (4)


/*------------------------------------------------------------------*/

typedef struct
{
    sbyte4      encrypt;                            /* Key used for encrypting or decrypting? */
    ubyte       key[256/*KEY_SIZE_256*/];           /* raw key in this case */
    sbyte4      keyLength;                          /* Length of the key(in bytes) */

} fslCipherContext;

typedef struct
{
    ubyte           rc4SboxCtx[MAX_SIZE_RC4_SBOX];  /* rc4 context */
    ubyte4          ctxSize;                        /* initial key size, after sbox length */
    intBoolean      isSboxCtxInit;                  /* are we at the start of a cipher stream? */

} fslRc4Ctx;


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
FSL8315_init(void)
{
    return(sbyte4)OK;
}


/*------------------------------------------------------------------*/

extern sbyte4
FSL8315_uninit(void)
{
    return(sbyte4)OK;
}


/*------------------------------------------------------------------*/

static fslCipherContext *
CreateCtxCommon(hwAccelDescr hwAccelCtx, ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt)
{
    fslCipherContext* ctx = NULL;

    if (OK > HARNESS_kernelAlloc(hwAccelCtx, sizeof(fslCipherContext), TRUE, (void **)&ctx))
    {
        DEBUG_PRINTNL(DEBUG_TEST, "CreateCtxCommon: HARNESS_kernelAlloc() failed");
        goto exit;
    }

    DIGI_MEMSET((ubyte *)ctx, 0x00, sizeof(fslCipherContext));
    DIGI_MEMCPY(&(ctx->key[0]), keyMaterial, keyLength);
    ctx->keyLength = keyLength;
    ctx->encrypt = encrypt;

exit:
    return ctx;
}


/*------------------------------------------------------------------*/

static MSTATUS
DoCryptCommon(hwAccelDescr hwAccelCtx,
              ubyte* p2, ubyte4 len2, ubyte* p3, ubyte4 len3,
              ubyte* p4, ubyte4 len4, ubyte* p5, ubyte4 len5,
              ubyte* p6, ubyte4 len6, ubyte4 header)
{
    void*               pSecurityStackCtx;
    intBoolean          isAsync = HARNESS_isAsyncModeEnabled(hwAccelCtx, &pSecurityStackCtx);

    mahCellDescr*       pMahCell;
    mahCompletionDescr* pCompleteDescr = NULL;
    intBoolean          isReserve = FALSE;
    MSTATUS             status;

#if defined(__LINUX_RTOS__) && defined(__KERNEL__)
    if (in_atomic() && !isAsync)
    {
        status = ERR_HARDWARE_ACCEL; /* 'sleep' will cause kernel panic! */
        goto exit;
    }
#endif

    if (OK > (status = HARNESS_reserveSouth(hwAccelCtx, &pMahCell)))
    {
        DEBUG_ERROR(DEBUG_HARNESS, "DoCryptCommon: HARNESS_reserveSouth() return status = ", status);
        goto exit;
    }

    isReserve = TRUE;

    if (isAsync) pMahCell->pSecurityStackCtx = pSecurityStackCtx;
    else pMahCell->pSecurityStackCtx = NULL;

    pMahCell->header   = header;
    pMahCell->reserved = 0;

    pMahCell->length1  = 0;
    pMahCell->pointer1 = NULL;

    pMahCell->length2  = len2 << 16;
    pMahCell->pointer2 = NULL;

#if defined(__LINUX_RTOS__) && defined(__KERNEL__)
    if (p2)
        pMahCell->pointer2 = OS_VIRTUAL_TO_PHY(p2);
#else
    if ((p2) && (OK > (status = HARNESS_mapAllocToPhysical(hwAccelCtx, p2, (void **)&pMahCell->pointer2))))
        goto exit;
#endif

    pMahCell->length3  = len3 << 16;
    pMahCell->pointer3 = NULL;

#if defined(__LINUX_RTOS__) && defined(__KERNEL__)
    if (p3)
        pMahCell->pointer3 = OS_VIRTUAL_TO_PHY(p3);
#else
    if ((p3) && (OK > (status = HARNESS_mapAllocToPhysical(hwAccelCtx, p3, (void **)&pMahCell->pointer3))))
        goto exit;
#endif

    pMahCell->length4  = len4 << 16;
    pMahCell->pointer4 = NULL;

#if defined(__LINUX_RTOS__) && defined(__KERNEL__)
    if (p4)
        pMahCell->pointer4 = OS_VIRTUAL_TO_PHY(p4);
#else
    if ((p4) && (OK > (status = HARNESS_mapAllocToPhysical(hwAccelCtx, p4, (void **)&pMahCell->pointer4))))
        goto exit;
#endif

    pMahCell->length5  = len5 << 16;
    pMahCell->pointer5 = NULL;

#if defined(__LINUX_RTOS__) && defined(__KERNEL__)
    if (p5)
        pMahCell->pointer5 = OS_VIRTUAL_TO_PHY(p5);
#else
    if ((p5) && (OK > (status = HARNESS_mapAllocToPhysical(hwAccelCtx, p5, (void **)&pMahCell->pointer5))))
        goto exit;
#endif

    pMahCell->length6  = len6 << 16;
    pMahCell->pointer6 = NULL;

#if defined(__LINUX_RTOS__) && defined(__KERNEL__)
    if (p6)
        pMahCell->pointer6 = OS_VIRTUAL_TO_PHY(p6);
#else
    if ((p6) && (OK > (status = HARNESS_mapAllocToPhysical(hwAccelCtx, p6, (void **)&pMahCell->pointer6))))
        goto exit;
#endif

    pMahCell->length7  = 0;
    pMahCell->pointer7 = NULL;

    /* fire off the crypto job */
    if (OK > (status = HARNESS_activateSouthTail(hwAccelCtx)))
        goto exit;

    isReserve = FALSE;

    if (!isAsync)
    {
        /* wait for job to finish */
        while (OK > HARNESS_getNorthChannelHead(hwAccelCtx, &pCompleteDescr))
        {
            RTOS_sleepMS(0);
        }

        HARNESS_incrementNorthChannelHead(hwAccelCtx);

        if (NULL != pCompleteDescr)
        {
            status = pCompleteDescr->hwAccelError;

            pCompleteDescr->hwAccelError = 0;
            pCompleteDescr->pSecurityStackCtx = 0;
        }
        else
            status = -1;
    }

exit:
    if (TRUE == isReserve)
        HARNESS_unreserveSouth(hwAccelCtx);

    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_HARNESS, "DoCryptCommon: return w/ error, return status = ", status);
    }

    return status;
}


/*------------------------------------------------------------------*/

#if((!defined(__DISABLE_AES_CIPHERS__)) && defined(__AES_HARDWARE_CIPHER__))
extern BulkCtx
CreateAESCtx(hwAccelDescr hwAccelCtx, ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt)
{
    fslCipherContext*   ctx = NULL;

    if (!((16 == keyLength) ||(24 == keyLength) ||(32 == keyLength)))
        goto exit;  /* bad key size */

    ctx = CreateCtxCommon(hwAccelCtx, keyMaterial, keyLength, encrypt);

exit:
    return(BulkCtx)ctx;
}
#endif /*((!defined(__DISABLE_AES_CIPHERS__)) && defined(__AES_HARDWARE_CIPHER__)) */


/*------------------------------------------------------------------*/

#if((!defined(__DISABLE_AES_CIPHERS__)) && defined(__AES_HARDWARE_CIPHER__))
extern MSTATUS
DoAES(hwAccelDescr hwAccelCtx, BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt, ubyte* iv)
{
    ubyte4          header;
    MSTATUS         status;

    if (NULL == ctx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

#if (defined(__LINUX_RTOS__) && defined(__KERNEL__)) || (defined(__QNX_RTOS__))
    if (0 == hwAccelCtx)
#else
    if (0 > hwAccelCtx)
#endif
    {
        status = ERR_HARDWARE_ACCEL_BAD_CTX;
        goto exit;
    }

    if (0 != (dataLength % AES_BLOCK_SIZE))
    {
        status = ERR_AES_BAD_LENGTH;
        goto exit;
    }

    if (SEC_MAX_LENGTH < dataLength)
    {
        status = ERR_AES_BAD_LENGTH;
        goto exit;
    }

    header = encrypt ? DPD_HEADER_AES_ENCRYPT : DPD_HEADER_AES_DECRYPT;

    if (OK > (status = DoCryptCommon(hwAccelCtx, iv, 0x10,
                                     ((fslCipherContext*)ctx)->key,((fslCipherContext*)ctx)->keyLength,
                                     data, dataLength, data, dataLength,
                                     iv, 0x10, header)))
    {
        goto exit;
    }

exit:
    return status;

}   /* DoAES */
#endif /*((!defined(__DISABLE_AES_CIPHERS__)) && defined(__AES_HARDWARE_CIPHER__)) */


/*------------------------------------------------------------------*/

#if((!defined(__DISABLE_AES_CIPHERS__)) && defined(__AES_HARDWARE_CIPHER__))
extern MSTATUS
DeleteAESCtx(hwAccelDescr hwAccelCtx, BulkCtx* ctx)
{
    if (*ctx)
        HARNESS_kernelFree(hwAccelCtx, TRUE, ctx);

    return OK;
}
#endif /*((!defined(__DISABLE_AES_CIPHERS__)) && defined(__AES_HARDWARE_CIPHER__)) */


/*------------------------------------------------------------------*/

#if(defined(__ENABLE_DES_CIPHER__) && defined(__DES_HARDWARE_CIPHER__))
extern BulkCtx
CreateDESCtx(hwAccelDescr hwAccelCtx, ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt)
{
    MOC_UNUSED(hwAccelCtx);

    if ((DES_KEY_LENGTH != keyLength) ||(NULL == keyMaterial))
        return NULL;  /* bad key size or material */

    fixupParityBits(keyMaterial, keyLength);

    return(BulkCtx)(CreateCtxCommon(hwAccelCtx, keyMaterial, keyLength, encrypt));
}
#endif /*(defined(__ENABLE_DES_CIPHER__) && defined(__DES_HARDWARE_CIPHER__)) */


/*------------------------------------------------------------------*/

#if(defined(__ENABLE_DES_CIPHER__) && defined(__DES_HARDWARE_CIPHER__))
extern MSTATUS
DoDES(hwAccelDescr hwAccelCtx, BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt, ubyte* iv)
{
    ubyte4          header;
    MSTATUS         status;

    if (NULL == ctx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

#if (defined(__LINUX_RTOS__) && defined(__KERNEL__)) || (defined(__QNX_RTOS__))
    if (0 == hwAccelCtx)
#else
    if (0 > hwAccelCtx)
#endif
    {
        status = ERR_HARDWARE_ACCEL_BAD_CTX;
        goto exit;
    }

    if (0 != (dataLength % DES_BLOCK_SIZE))
    {
        status = ERR_DES_BAD_LENGTH;
        goto exit;
    }

    if (SEC_MAX_LENGTH < dataLength)
    {
        status = ERR_DES_BAD_LENGTH;
        goto exit;
    }

    header = encrypt ? DPD_HEADER_DES_ENCRYPT : DPD_HEADER_DES_DECRYPT;

    if (OK > (status = DoCryptCommon(hwAccelCtx, iv, 0x08,
                                    ((fslCipherContext*)ctx)->key,((fslCipherContext*)ctx)->keyLength,
                                     data, dataLength, data, dataLength,
                                     iv, 0x08, header)))
    {
        goto exit;
    }

exit:
    return status;
}
#endif /*(defined(__ENABLE_DES_CIPHER__) && defined(__DES_HARDWARE_CIPHER__)) */


/*------------------------------------------------------------------*/

#if(defined(__ENABLE_DES_CIPHER__) && defined(__DES_HARDWARE_CIPHER__))
extern MSTATUS
DeleteDESCtx(hwAccelDescr hwAccelCtx, BulkCtx* ctx)
{
    MOC_UNUSED(hwAccelCtx);

    if (*ctx)
        HARNESS_kernelFree(hwAccelCtx, TRUE, ctx);

    return OK;
}
#endif /*(defined(__ENABLE_DES_CIPHER__) && defined(__DES_HARDWARE_CIPHER__)) */


/*------------------------------------------------------------------*/

#if((!defined(__DISABLE_3DES_CIPHERS__)) && defined(__3DES_HARDWARE_CIPHER__))
extern BulkCtx
Create3DESCtx(hwAccelDescr hwAccelCtx, ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt)
{
    MOC_UNUSED(hwAccelCtx);

    if ((THREE_DES_KEY_LENGTH != keyLength) ||(NULL == keyMaterial))
        return NULL;

    fixupParityBits(keyMaterial, keyLength);

    return CreateCtxCommon(hwAccelCtx, keyMaterial, keyLength, encrypt);
}
#endif /*((!defined(__DISABLE_3DES_CIPHERS__)) && defined(__3DES_HARDWARE_CIPHER__)) */


/*------------------------------------------------------------------*/

#if((!defined(__DISABLE_3DES_CIPHERS__)) && defined(__3DES_HARDWARE_CIPHER__))
extern MSTATUS
Do3DES(hwAccelDescr hwAccelCtx, BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt, ubyte* iv)
{
    ubyte4          header;
    MSTATUS         status;

    if (NULL == ctx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

#if (defined(__LINUX_RTOS__) && defined(__KERNEL__)) || (defined(__QNX_RTOS__))
    if (0 == hwAccelCtx)
#else
    if (0 > hwAccelCtx)
#endif
    {
        status = ERR_HARDWARE_ACCEL_BAD_CTX;
        goto exit;
    }

    if (0 != (dataLength % THREE_DES_BLOCK_SIZE))
    {
        status = ERR_DES_BAD_LENGTH;
        goto exit;
    }

    if (SEC_MAX_LENGTH < dataLength)
    {
        status = ERR_DES_BAD_LENGTH;
        goto exit;
    }

    header = encrypt ? DPD_HEADER_TDES_ENCRYPT : DPD_HEADER_TDES_DECRYPT;

    if (OK > (status = DoCryptCommon(hwAccelCtx, iv, 0x08,
                                     ((fslCipherContext*)ctx)->key,((fslCipherContext*)ctx)->keyLength,
                                     data, dataLength, data, dataLength,
                                     iv, 0x08, header)))
    {
        goto exit;
    }

exit:
    return status;
}
#endif /*((!defined(__DISABLE_3DES_CIPHERS__)) && defined(__3DES_HARDWARE_CIPHER__)) */


/*------------------------------------------------------------------*/

#if((!defined(__DISABLE_3DES_CIPHERS__)) && defined(__3DES_HARDWARE_CIPHER__))
extern MSTATUS
Delete3DESCtx(hwAccelDescr hwAccelCtx, BulkCtx* ctx)
{
    MOC_UNUSED(hwAccelCtx);

    if (*ctx)
        HARNESS_kernelFree(hwAccelCtx, TRUE, ctx);

    return OK;
}
#endif /*((!defined(__DISABLE_3DES_CIPHERS__)) && defined(__3DES_HARDWARE_CIPHER__)) */


/*------------------------------------------------------------------*/

#if((!defined(__DISABLE_ARC4_CIPHERS__)) && defined(__ARC4_HARDWARE_CIPHER__))
extern BulkCtx
CreateRC4Ctx(hwAccelDescr hwAccelCtx, ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt)
{
    fslRc4Ctx*  pRc4Ctx = NULL;
    MOC_UNUSED(hwAccelCtx);
    MOC_UNUSED(encrypt);

    if ((1 > keyLength) ||(256 < keyLength))
        goto exit;  /* bad key size */

    if (OK > HARNESS_kernelAlloc(hwAccelCtx, sizeof(fslRc4Ctx), TRUE, (void **)&pRc4Ctx))
        goto exit;

    DIGI_MEMSET((ubyte *)pRc4Ctx, 0x00, sizeof(fslRc4Ctx));
    DIGI_MEMCPY(pRc4Ctx->rc4SboxCtx, keyMaterial, keyLength);

    pRc4Ctx->ctxSize       = keyLength;
    pRc4Ctx->isSboxCtxInit = FALSE;

exit:
    return pRc4Ctx;
}
#endif /*((!defined(__DISABLE_ARC4_CIPHERS__)) && defined(__ARC4_HARDWARE_CIPHER__)) */


/*------------------------------------------------------------------*/

#if((!defined(__DISABLE_ARC4_CIPHERS__)) && defined(__ARC4_HARDWARE_CIPHER__))
extern MSTATUS
DoRC4(hwAccelDescr hwAccelCtx, BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt, ubyte* iv)
{
    fslRc4Ctx*      pRc4Ctx = (fslRc4Ctx *)ctx;
    ubyte4          header;
    MSTATUS         status;
    MOC_UNUSED(iv);
    MOC_UNUSED(encrypt);

    if (NULL == pRc4Ctx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

#if (defined(__LINUX_RTOS__) && defined(__KERNEL__)) || (defined(__QNX_RTOS__))
    if (0 == hwAccelCtx)
#else
    if (0 > hwAccelCtx)
#endif
    {
        status = ERR_HARDWARE_ACCEL_BAD_CTX;
        goto exit;
    }

    if (SEC_MAX_LENGTH < dataLength)
    {
        status = ERR_ARC4_BAD_LENGTH;
        goto exit;
    }

    if (FALSE == pRc4Ctx->isSboxCtxInit)
    {
        header = DPD_HEADER_RC4_CIPHER_START;
        pRc4Ctx->isSboxCtxInit = TRUE;

        if (OK > (status = DoCryptCommon(hwAccelCtx,
                                         NULL, 0,
                                         pRc4Ctx->rc4SboxCtx, pRc4Ctx->ctxSize, /* passing in key material */
                                         data, dataLength,
                                         data, dataLength,
                                         pRc4Ctx->rc4SboxCtx, MAX_SIZE_RC4_SBOX, header)))
        {
            goto exit;
        }

        pRc4Ctx->ctxSize = MAX_SIZE_RC4_SBOX;   /* subsequent calls will have the correct length */
    }
    else
    {
        header = DPD_HEADER_RC4_CIPHER_CONTINUE;

        if (OK > (status = DoCryptCommon(hwAccelCtx,
                                         pRc4Ctx->rc4SboxCtx, pRc4Ctx->ctxSize, /* passing in previous sbox ctx */
                                         NULL, 0,
                                         data, dataLength,
                                         data, dataLength,
                                         pRc4Ctx->rc4SboxCtx, MAX_SIZE_RC4_SBOX, header)))
        {
            goto exit;
        }
    }


exit:
    return status;

}   /* DoRC4 */
#endif /*((!defined(__DISABLE_ARC4_CIPHERS__)) && defined(__ARC4_HARDWARE_CIPHER__)) */


/*------------------------------------------------------------------*/

#if((!defined(__DISABLE_ARC4_CIPHERS__)) && defined(__ARC4_HARDWARE_CIPHER__))
extern MSTATUS
DeleteRC4Ctx(hwAccelDescr hwAccelCtx, BulkCtx* ctx)
{
    MOC_UNUSED(hwAccelCtx);

    if (*ctx)
        HARNESS_kernelFree(hwAccelCtx, TRUE, ctx);

    return OK;
}
#endif /*((!defined(__DISABLE_ARC4_CIPHERS__)) && defined(__ARC4_HARDWARE_CIPHER__)) */


/*------------------------------------------------------------------*/

static MSTATUS
DoMDCryptCommon(hwAccelDescr hwAccelCtx,
                ubyte* pCtxIn,  ubyte4 ctxInLen,
                ubyte* pKey,    ubyte4 keyLen,
                ubyte* pData,   ubyte4 dataLen,
                ubyte* pCtxtDigOut, ubyte4 ctxDigOutLen,
                ubyte4 header)
{
    void*               pSecurityStackCtx;
    intBoolean          isAsync = HARNESS_isAsyncModeEnabled(hwAccelCtx, &pSecurityStackCtx);

    mahCellDescr*       pMahCell;
    mahCompletionDescr* pCompleteDescr = NULL;
    intBoolean          isReserve = FALSE;
    MSTATUS             status;

#if defined(__LINUX_RTOS__) && defined(__KERNEL__)
    if (in_atomic() && !isAsync)
    {
        status = ERR_HARDWARE_ACCEL; /* 'sleep' will cause kernel panic! */
        goto exit;
    }
#endif

    if (OK > (status = HARNESS_reserveSouth(hwAccelCtx, &pMahCell)))
    {
        DEBUG_ERROR(DEBUG_HARNESS, "DoMDCryptCommon: HARNESS_reserveSouth() return status = ", status);
        goto exit;
    }

    isReserve = TRUE;

    if (isAsync) pMahCell->pSecurityStackCtx = pSecurityStackCtx;
    else pMahCell->pSecurityStackCtx = NULL;

    pMahCell->header   = header;
    pMahCell->reserved = 0;

    pMahCell->length1  = 0;
    pMahCell->pointer1 = NULL;

    pMahCell->length2  = ctxInLen << 16;
    pMahCell->pointer2 = NULL;
    if ((pCtxIn) && (OK > (status = HARNESS_mapAllocToPhysical(hwAccelCtx, pCtxIn, (void **)&pMahCell->pointer2))))
        goto exit;

    pMahCell->length3  = keyLen << 16;
    pMahCell->pointer3 = NULL;
    if ((pKey) && (OK > (status = HARNESS_mapAllocToPhysical(hwAccelCtx, pKey, (void **)&pMahCell->pointer3))))
        goto exit;

    pMahCell->length4  = dataLen << 16;
    pMahCell->pointer4 = NULL;
    if ((pData) && (OK > (status = HARNESS_mapAllocToPhysical(hwAccelCtx, pData, (void **)&pMahCell->pointer4))))
        goto exit;

    pMahCell->length5  = 0;
    pMahCell->pointer5 = NULL;

    pMahCell->length6  = ctxDigOutLen << 16;
    pMahCell->pointer6 = NULL;
    if ((pCtxtDigOut) && (OK > (status = HARNESS_mapAllocToPhysical(hwAccelCtx, pCtxtDigOut, (void **)&pMahCell->pointer6))))
        goto exit;

    pMahCell->length7  = 0;
    pMahCell->pointer7 = NULL;

    /* fire off the crypto job */
    if (OK > (status = HARNESS_activateSouthTail(hwAccelCtx)))
        goto exit;

    isReserve = FALSE;

    if (!isAsync)
    {
        /* wait for job to finish */
        while (OK > HARNESS_getNorthChannelHead(hwAccelCtx, &pCompleteDescr))
        {
            RTOS_sleepMS(0);
        }

        HARNESS_incrementNorthChannelHead(hwAccelCtx);

        if (NULL != pCompleteDescr)
        {
            status = pCompleteDescr->hwAccelError;

            pCompleteDescr->hwAccelError = 0;
            pCompleteDescr->pSecurityStackCtx = 0;
        }
        else
            status = -1;
    }

exit:
    if (TRUE == isReserve)
        HARNESS_unreserveSouth(hwAccelCtx);

    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_HARNESS, "DoMDCryptCommon: return w/ error, return status = ", status);
    }

    return status;

} /* DoMDCryptCommon */


/*------------------------------------------------------------------*/

#ifdef __HMAC_MD5_HARDWARE_HASH__
extern MSTATUS
HMAC_MD5_quick(hwAccelDescr hwAccelCtx, const ubyte* pKey, sbyte4 keyLen, const ubyte* pText, sbyte4 textLen,
               ubyte* pResult /* MD5_DIGESTSIZE */)
{
    MSTATUS status;
    ubyte *tk = NULL;

#if (defined(__LINUX_RTOS__) && defined(__KERNEL__)) || (defined(__QNX_RTOS__))
    if (0 == hwAccelCtx)
#else
    if (0 > hwAccelCtx)
#endif
    {
        status = ERR_HARDWARE_ACCEL_BAD_CTX;
        goto exit;
    }

    if (keyLen > MD5_BLOCK_SIZE)
    {
        if (OK > (status = HARNESS_kernelAlloc(hwAccelCtx, MD5_DIGESTSIZE, TRUE, (void **)&tk)))
            goto exit;

        if (OK > (status = MD5_completeDigest(MOC_HASH(hwAccelCtx) pKey, keyLen, tk)))
            goto exit;

        pKey = tk;
        keyLen = MD5_DIGESTSIZE;
    }

    status = DoMDCryptCommon(hwAccelCtx, NULL, 0, pKey, keyLen, pText, textLen,
                             pResult, MD5_DIGESTSIZE, DPD_HEADER_MD_MD5_HMAC_COMPLETE);

exit:
    if (tk)
        HARNESS_kernelFree(hwAccelCtx, TRUE, (void **)&tk);

    return status;
}
#endif


/*------------------------------------------------------------------*/

#ifdef __HMAC_SHA1_HARDWARE_HASH__
extern MSTATUS
HMAC_SHA1_quick(hwAccelDescr hwAccelCtx, const ubyte* pKey, sbyte4 keyLen, const ubyte* pText, sbyte4 textLen,
                ubyte* pResult /* SHA_HASH_RESULT_SIZE */)
{
    ubyte*      tk = NULL;
    MSTATUS     status;

#if (defined(__LINUX_RTOS__) && defined(__KERNEL__)) || (defined(__QNX_RTOS__))
    if (0 == hwAccelCtx)
#else
    if (0 > hwAccelCtx)
#endif
    {
        status = ERR_HARDWARE_ACCEL_BAD_CTX;
        goto exit;
    }

    /* if key is longer than SHA1_BLOCK_SIZE bytes reset it to key = SHA1(key) */
    if (keyLen > SHA1_BLOCK_SIZE)
    {
        if (OK > (status = HARNESS_kernelAlloc(hwAccelCtx, SHA1_RESULT_SIZE, TRUE, (void **)&tk)))
            goto exit;

        if (OK > (status = SHA1_completeDigest(MOC_HASH(hwAccelCtx) pKey, keyLen, tk)))
            goto exit;

        pKey = tk;
        keyLen = SHA1_RESULT_SIZE;
    }

    status = DoMDCryptCommon(hwAccelCtx, NULL, 0, pKey, keyLen, pText, textLen,
                             pResult, SHA_HASH_RESULT_SIZE, DPD_HEADER_MD_SHA1_HMAC_COMPLETE);

exit:
    if (tk)
        CRYPTO_FREE(hwAccelCtx, TRUE,&tk);

    return status;
}
#endif


/*------------------------------------------------------------------*/

#ifdef __HMAC_MD5_HARDWARE_HASH__
extern MSTATUS
HMAC_MD5(hwAccelDescr hwAccelCtx, const ubyte* key, sbyte4 keyLen, const ubyte* text, sbyte4 textLen,
         const ubyte* textOpt, sbyte4 textOptLen, ubyte result[MD5_DIGESTSIZE])
{
    ubyte*  pTempResult = NULL;
    ubyte*  pText = NULL;
    MSTATUS status;

#if (defined(__LINUX_RTOS__) && defined(__KERNEL__)) || (defined(__QNX_RTOS__))
    if (0 == hwAccelCtx)
#else
    if (0 > hwAccelCtx)
#endif
    {
        status = ERR_HARDWARE_ACCEL_BAD_CTX;
        goto exit;
    }

    if (OK > (status = HARNESS_kernelAlloc(hwAccelCtx, MD5_DIGESTSIZE, TRUE, (void **)&pTempResult)))
        goto exit;

    if (NULL == textOpt)
        textOptLen = 0;

    if (NULL == textOpt)
    {
        pText = text;
    }
    else
    {
        if (OK > (status = HARNESS_kernelAlloc(hwAccelCtx, textLen + textOptLen, TRUE, (void **)&pText)))
            goto exit;

        DIGI_MEMCPY(pText, text, textLen);
        DIGI_MEMCPY(pText + textLen, textOpt, textOptLen);
    }

    /* if key is longer than HMAC_BLOCK_SIZE bytes reset it to key=MD5(key) */
    if (keyLen > MD5_BLOCK_SIZE)
    {
        if (OK > (status = MD5_completeDigest(hwAccelCtx, key, keyLen, pTempResult)))
            goto exit;

        key = pTempResult;
        keyLen = MD5_DIGESTSIZE;
    }

    if (OK > (status = DoMDCryptCommon(hwAccelCtx, NULL, 0, key, keyLen, pText, textLen + textOptLen,
                                       pTempResult, MD5_DIGESTSIZE, DPD_HEADER_MD_MD5_HMAC_COMPLETE)))
    {
        goto exit;
    }

    DIGI_MEMCPY(result, pTempResult, MD5_DIGESTSIZE);

exit:
    if ((NULL != pText) && (NULL != textOpt))
        HARNESS_kernelFree(hwAccelCtx, TRUE, (void **)&pText);

    HARNESS_kernelFree(hwAccelCtx, TRUE, (void **)&pTempResult);

    return status;
}
#endif


/*------------------------------------------------------------------*/

#ifdef __HMAC_SHA1_HARDWARE_HASH__
extern MSTATUS
HMAC_SHA1(hwAccelDescr hwAccelCtx, const ubyte* key, sbyte4 keyLen, const ubyte* text, sbyte4 textLen,
          const ubyte* textOpt, sbyte4 textOptLen, ubyte result[SHA_HASH_RESULT_SIZE])
{
    ubyte*      pTempResult = NULL;
    ubyte*      pText;
    MSTATUS     status;

    pText = NULL;

#if (defined(__LINUX_RTOS__) && defined(__KERNEL__)) || (defined(__QNX_RTOS__))
    if (0 == hwAccelCtx)
#else
    if (0 > hwAccelCtx)
#endif
    {
        status = ERR_HARDWARE_ACCEL_BAD_CTX;
        goto exit;
    }

    if (OK > (status = HARNESS_kernelAlloc(hwAccelCtx, SHA_HASH_RESULT_SIZE, TRUE, (void **)&pTempResult)))
        goto exit;

    if (NULL == textOpt)
    {
        pText = text;
    }
    else
    {
        /*!!!! */
        if (OK > (status = HARNESS_kernelAlloc(hwAccelCtx, textLen + textOptLen, TRUE, (void **)&pText)))
            goto exit;

        DIGI_MEMCPY(pText, text, textLen);
        DIGI_MEMCPY(pText + textLen, textOpt, textOptLen);
    }

    /* if key is longer than HMAC_BLOCK_SIZE bytes reset it to key=MD5(key) */
    if (keyLen > SHA1_BLOCK_SIZE)
    {
        if (OK > (status = SHA1_completeDigest(hwAccelCtx, key, keyLen, pTempResult)))
        {
            goto exit;
        }

        key = pTempResult;
        keyLen =  SHA_HASH_RESULT_SIZE;
    }

    if (OK > (status = DoMDCryptCommon(hwAccelCtx, NULL, 0, key, keyLen, pText, textLen + textOptLen,
                                       pTempResult, SHA_HASH_RESULT_SIZE, DPD_HEADER_MD_SHA1_HMAC_COMPLETE)))
    {
        goto exit;
    }

    DIGI_MEMCPY(result, pTempResult, SHA_HASH_RESULT_SIZE);

exit:
    if ((NULL != pText) && (NULL != textOpt))
        HARNESS_kernelFree(hwAccelCtx, TRUE, (void **)&pText);

    HARNESS_kernelFree(hwAccelCtx, TRUE, (void **)&pTempResult);

    return status;
}
#endif


/*------------------------------------------------------------------*/

#ifdef __MD5_ONE_STEP_HARDWARE_HASH__
extern MSTATUS
MD5_completeDigest(hwAccelDescr hwAccelCtx, const ubyte *pData,
                   ubyte4 dataLen, ubyte *pMdOutput)
{
    MSTATUS     status;

    status = DoMDCryptCommon(hwAccelCtx, NULL, 0, NULL, 0, pData, dataLen,
                                       pMdOutput, MD5_DIGESTSIZE,
                                       DPD_HEADER_MD_MD5_HASH_COMPLETE);

    return status;
}
#endif


/*------------------------------------------------------------------*/

#ifdef __SHA1_ONE_STEP_HARDWARE_HASH__
extern MSTATUS
SHA1_completeDigest(hwAccelDescr hwAccelCtx, const ubyte *pData,
                    ubyte4 dataLen, ubyte *pShaOutput)
{
    MSTATUS     status;

    status = DoMDCryptCommon(hwAccelCtx, NULL, 0, NULL, 0, pData, dataLen,
                                       pShaOutput, SHA_HASH_RESULT_SIZE,
                                       DPD_HEADER_MD_SHA1_HASH_COMPLETE);

    return status;
}
#endif


/*------------------------------------------------------------------*/

#if defined(__CUSTOM_MD5_CONTEXT__) || defined(__CUSTOM_SHA1_CONTEXT__)
#define MD_CTX_BUFF_AVAIL(c)          (MD_CTX_HASHDATA_SIZE - (c)->index)
#endif


/*------------------------------------------------------------------*/

#ifdef __MD5_HARDWARE_HASH__
#ifdef PORTING_FOR_BINLIB
extern BulkCtx
MD5Alloc_m(void)
{
    return (BulkCtx) MALLOC(sizeof(MD5_CTX));
}

extern MSTATUS
MD5Free_m(BulkCtx *pp_context)
{
    if (NULL != *pp_context)
    {
        FREE(*pp_context);
        *pp_context = NULL;
    }

    return OK;
}

#else
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

extern MSTATUS
MD5Init_m(hwAccelDescr hwAccelCtx, MD5_CTX *context)
{
    MOC_UNUSED(hwAccelCtx);

    context->isAfterFirstBlock = FALSE;
    context->index = 0;

    return OK;
}
#endif


/*------------------------------------------------------------------*/

#ifdef __MD5_HARDWARE_HASH__
extern MSTATUS
MD5Update_m(hwAccelDescr hwAccelCtx, MD5_CTX *p_md5Context,
            const ubyte *pData, ubyte4 dataLen)
{
    ubyte4  multipleMsgDigestBlocks;
    ubyte4  remainder;
    ubyte*  pFSLCtx    = p_md5Context->fslCtx;
    ubyte4  fslCtxSize = MD_CTX_FSL_CTX_SIZE;
    ubyte4  header     = (ubyte4)DPD_HEADER_MD_MD5_HASH_UPDATE;
    MSTATUS status     = OK;

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

        if (0 < (copyLen = ((availSpace > dataLen) ? dataLen : availSpace)))
        {
            DIGI_MEMCPY(p_md5Context->cachedHashData + p_md5Context->index, pData, copyLen);

            p_md5Context->index += copyLen;
            pData               += copyLen;
            dataLen             -= copyLen;

            if (0 == dataLen)
            {
                /* defer some bytes pending for an unexpected final */
                goto exit;
            }
        }

        if (FALSE == p_md5Context->isAfterFirstBlock)
        {
            /* process first chunk */
            pFSLCtx    = NULL;
            fslCtxSize = 0;
            header     = (ubyte4)DPD_HEADER_MD_MD5_HASH_INIT;
        }

        /* process MD_CTX_HASHDATA_SIZE byte chunk */
        if (OK > (status = DoMDCryptCommon(hwAccelCtx,
                                           pFSLCtx, fslCtxSize,
                                           NULL, 0,
                                           p_md5Context->cachedHashData, MD_CTX_HASHDATA_SIZE,
                                           p_md5Context->fslCtx, MD_CTX_FSL_CTX_SIZE,
                                           header)))
        {
            goto exit;
        }

        if ((FALSE == p_md5Context->isAfterFirstBlock) && (MD_CTX_HASHDATA_SIZE < dataLen))
        {
            /* processed first chunk, setup for multi-chunk handling in next phase */
            pFSLCtx    = p_md5Context->fslCtx;
            fslCtxSize = MD_CTX_FSL_CTX_SIZE;
            header     = (ubyte4)DPD_HEADER_MD_MD5_HASH_UPDATE;
        }

        p_md5Context->isAfterFirstBlock = TRUE;
        p_md5Context->index = 0;
    }

    /* next phase: send integer multiples of MD_CTX_HASHDATA_SIZE bytes, if we can */
    multipleMsgDigestBlocks = dataLen & (~MD_CTX_HASHDATA_SIZE_MASK);
    remainder               = dataLen & MD_CTX_HASHDATA_SIZE_MASK;

    if (0 == remainder)
    {
        /* defer some bytes pending for an unexpected final */
        multipleMsgDigestBlocks -= MD_CTX_HASHDATA_SIZE;
        remainder = MD_CTX_HASHDATA_SIZE;
    }

    if (0 < multipleMsgDigestBlocks)
    {
        /* process a big chunk, (MD_CTX_HASHDATA_SIZE * N) bytes */
        if (FALSE == p_md5Context->isAfterFirstBlock)
        {
            /* process first chunk */
            pFSLCtx    = NULL;
            fslCtxSize = 0;
            header     = (ubyte4)DPD_HEADER_MD_MD5_HASH_INIT;
        }

        if (OK > (status = DoMDCryptCommon(hwAccelCtx,
                                           pFSLCtx, fslCtxSize,
                                           NULL, 0,
                                          (ubyte*)pData, multipleMsgDigestBlocks,
                                           p_md5Context->fslCtx, MD_CTX_FSL_CTX_SIZE,
                                           header)))
        {
            goto exit;
        }

        pData += multipleMsgDigestBlocks;

        p_md5Context->isAfterFirstBlock = TRUE;
    }

    /* transfer remaining data to context buffer */
    DIGI_MEMCPY(p_md5Context->cachedHashData, pData, remainder);
    p_md5Context->index = remainder;

exit:
    return status;
}
#endif /* __MD5_HARDWARE_HASH__ */


/*------------------------------------------------------------------*/

#ifdef __MD5_HARDWARE_HASH__
extern MSTATUS
MD5Final_m(hwAccelDescr hwAccelCtx, MD5_CTX *p_md5Context, ubyte digest[MD5_DIGESTSIZE])
{
    ubyte*  pFSLCtx    = p_md5Context->fslCtx;
    ubyte4  fslCtxSize = MD_CTX_FSL_CTX_SIZE;
    ubyte4  header     = (ubyte4)DPD_HEADER_MD_MD5_HASH_FINAL;
    MSTATUS status;

    if (0 == p_md5Context->index)
    {
        /* data should always be available */
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    if (FALSE == p_md5Context->isAfterFirstBlock)
    {
        pFSLCtx    = NULL;
        fslCtxSize = 0;
        header     = (ubyte4)DPD_HEADER_MD_MD5_HASH_COMPLETE;
    }

    status = DoMDCryptCommon(hwAccelCtx, pFSLCtx, fslCtxSize, NULL, 0,
                             p_md5Context->cachedHashData, p_md5Context->index,
                             digest, MD5_DIGESTSIZE, header);

exit:
    return status;
}
#endif /* __MD5_HARDWARE_HASH__ */


/*------------------------------------------------------------------*/

#ifdef __SHA1_HARDWARE_HASH__
#ifdef PORTING_FOR_BINLIB
extern BulkCtx
SHA1_allocDigest(void)
{
    return (shaDescr *) MALLOC(sizeof(shaDescr));
}

/*------------------------------------------------------------------*/

extern MSTATUS
SHA1_freeDigest(BulkCtx *pp_shaContext)
{
    if (NULL != *pp_shaContext)
    {
        FREE(*pp_shaContext);
        *pp_shaContext = NULL;
    }

    return OK;
}

#else
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
#endif

extern MSTATUS SHA1_initDigest(hwAccelDescr hwAccelCtx, shaDescr *p_shaContext)
{
    MOC_UNUSED(hwAccelCtx);

    p_shaContext->isAfterFirstBlock = FALSE;
    p_shaContext->index = 0;

    return OK;
}
#endif


/*------------------------------------------------------------------*/

#ifdef __SHA1_HARDWARE_HASH__
extern MSTATUS
SHA1_updateDigest(hwAccelDescr hwAccelCtx, shaDescr *p_shaContext,
                  const ubyte *pData, ubyte4 dataLen)
{
    ubyte4  multipleMsgDigestBlocks;
    ubyte4  remainder;
    ubyte*  pFSLCtx    = p_shaContext->fslCtx;
    ubyte4  fslCtxSize = MD_CTX_FSL_CTX_SIZE;
    ubyte4  header     = (ubyte4)DPD_HEADER_MD_SHA1_HASH_UPDATE;
    MSTATUS status     = OK;

    if (0 == dataLen)
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    if (0 != p_shaContext->index)
    {
        /* add to remenant data from previous round(s) */
        ubyte4  availSpace;
        ubyte4  copyLen;

        availSpace = MD_CTX_BUFF_AVAIL(p_shaContext);

        if (0 <(copyLen = (availSpace > dataLen) ? dataLen : availSpace))
        {
            DIGI_MEMCPY(p_shaContext->cachedHashData + p_shaContext->index, pData, copyLen);

            p_shaContext->index += copyLen;
            pData               += copyLen;
            dataLen             -= copyLen;

            if (0 == dataLen)
            {
                /* defer some bytes pending for an unexpected final */
                goto exit;
            }
        }

        if (FALSE == p_shaContext->isAfterFirstBlock)
        {
            /* process first chunk */
            pFSLCtx    = NULL;
            fslCtxSize = 0;
            header     = (ubyte4)DPD_HEADER_MD_SHA1_HASH_INIT;
        }

        /* process MD_CTX_HASHDATA_SIZE byte chunk */
        if (OK > (status = DoMDCryptCommon(hwAccelCtx,
                                           pFSLCtx, fslCtxSize,
                                           NULL, 0,
                                           p_shaContext->cachedHashData, MD_CTX_HASHDATA_SIZE,
                                           p_shaContext->fslCtx, MD_CTX_FSL_CTX_SIZE,
                                           header)))
        {
            goto exit;
        }

        if ((FALSE == p_shaContext->isAfterFirstBlock) &&(MD_CTX_HASHDATA_SIZE < dataLen))
        {
            /* processed first chunk, setup for multi-chunk handling in next phase */
            pFSLCtx    = p_shaContext->fslCtx;
            fslCtxSize = MD_CTX_FSL_CTX_SIZE;
            header     = (ubyte4)DPD_HEADER_MD_SHA1_HASH_UPDATE;
        }

        p_shaContext->isAfterFirstBlock = TRUE;
        p_shaContext->index = 0;
    }

    /* next phase: send integer multiples of MD_CTX_HASHDATA_SIZE bytes(>1) if we can */
    multipleMsgDigestBlocks = dataLen & (~MD_CTX_HASHDATA_SIZE_MASK);
    remainder               = dataLen & MD_CTX_HASHDATA_SIZE_MASK;

    if (0 == remainder)
    {
        /* defer some bytes pending for an unexpected final */
        multipleMsgDigestBlocks -= MD_CTX_HASHDATA_SIZE;;
        remainder = MD_CTX_HASHDATA_SIZE;
    }

    if (0 < multipleMsgDigestBlocks)
    {
        /* process a big chunk, MD_CTX_HASHDATA_SIZE * N bytes */
        if (FALSE == p_shaContext->isAfterFirstBlock)
        {
            /* process first chunk */
            pFSLCtx    = NULL;
            fslCtxSize = 0;
            header     = (ubyte4)DPD_HEADER_MD_SHA1_HASH_INIT;
        }

        if (OK > (status = DoMDCryptCommon(hwAccelCtx,
                                           pFSLCtx, fslCtxSize,
                                           NULL, 0,
                                          (ubyte*)pData, multipleMsgDigestBlocks,
                                           p_shaContext->fslCtx, MD_CTX_FSL_CTX_SIZE,
                                           header)))
        {
            goto exit;
        }

        pData += multipleMsgDigestBlocks;

        p_shaContext->isAfterFirstBlock = TRUE;
    }

    /* transfer remaining data to context buffer */
    DIGI_MEMCPY(p_shaContext->cachedHashData, pData, remainder);
    p_shaContext->index = remainder;

exit:
    return status;
}
#endif /* __SHA1_HARDWARE_HASH__ */


/*------------------------------------------------------------------*/

#ifdef __SHA1_HARDWARE_HASH__
extern MSTATUS
SHA1_finalDigest(hwAccelDescr hwAccelCtx, shaDescr *p_shaContext, ubyte *pShaOutput)
{
    ubyte*  pFSLCtx    = p_shaContext->fslCtx;
    ubyte4  fslCtxSize = MD_CTX_FSL_CTX_SIZE;
    ubyte4  header     = (ubyte4)DPD_HEADER_MD_SHA1_HASH_FINAL;
    MSTATUS status;

    if (0 == p_shaContext->index)
    {
        /* data should always be available */
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    if (FALSE == p_shaContext->isAfterFirstBlock)
    {
        pFSLCtx    = NULL;
        fslCtxSize = 0;
        header     = (ubyte4)DPD_HEADER_MD_SHA1_HASH_COMPLETE;
    }

    status = DoMDCryptCommon(hwAccelCtx, pFSLCtx, fslCtxSize, NULL, 0,
                             p_shaContext->cachedHashData, p_shaContext->index,
                             pShaOutput, SHA_HASH_RESULT_SIZE, header);

exit:
    return status;
}
#endif /* __SHA1_HARDWARE_HASH__ */



/*------------------------------------------------------------------*/

#define FSL_RNG_RAND_BUF_SIZE      1024

#ifdef __DISABLE_DIGICERT_RNG__
typedef struct
{
    /* to speed up performance we will create more random bits than needed... */
    hwAccelDescr    hwAccelCtx;
    ubyte           rngBuf[FSL_RNG_RAND_BUF_SIZE];
    ubyte4          rngBufIndex;
    ubyte4          numBytesSinceLastRng;

    intBoolean      isRngBeingCaptured;

} fslAsyncRngCtx;
#endif

#ifdef __DISABLE_DIGICERT_RNG__
extern MSTATUS
RANDOM_acquireContext(randomContext **pp_randomContext)
{
    hwAccelDescr    hwAccelCtx;
    fslAsyncRngCtx* pRngCtx = NULL;
    MSTATUS         status;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx)))
        goto exit;

    /* RNG uses async mode */
    HARNESS_enableAsyncMode(hwAccelCtx);

    if (OK <= (status = HARNESS_kernelAlloc(hwAccelCtx, sizeof(fslAsyncRngCtx), TRUE, (void **)&pRngCtx)))
    {
        pRngCtx->isRngBeingCaptured   = TRUE;
        pRngCtx->rngBufIndex          = FSL_RNG_RAND_BUF_SIZE;
        pRngCtx->numBytesSinceLastRng = 0;
        pRngCtx->hwAccelCtx           = hwAccelCtx;
        *pp_randomContext             = (randomContext *)pRngCtx;

        status = DoCryptCommon(pRngCtx->hwAccelCtx, NULL, 0, NULL, 0,
                               NULL, 0, pRngCtx->rngBuf, FSL_RNG_RAND_BUF_SIZE, NULL, 0,
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
    fslAsyncRngCtx* pRngCtx = (fslAsyncRngCtx*)(*pp_randomContext);
    MSTATUS status;

    if (NULL == pRngCtx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

#if (defined(__LINUX_RTOS__) && defined(__KERNEL__)) || (defined(__QNX_RTOS__))
    if (0 == pRngCtx->hwAccelCtx)
#else
    if (0 > pRngCtx->hwAccelCtx)
#endif
    {
        status = ERR_HARDWARE_ACCEL_BAD_CTX;
        goto exit;
    }

    if (TRUE == pRngCtx->isRngBeingCaptured)
    {
        mahCompletionDescr* pCell = NULL;

        while (OK > (status = HARNESS_getNorthChannelHead(pRngCtx->hwAccelCtx, &pCell)))
        {
#if defined(__LINUX_RTOS__) && defined(__KERNEL__)
            if (in_atomic()) /* 'sleep' will cause kernel panic! */
            {
                /*printk("%s::%s (%d): in_atomic\n", __FILE__, __FUNCTION__, __LINE__);*/
                /* better to leak than crash */
                status = ERR_HARDWARE_ACCEL_BAD_CTX;
                goto exit;
            }
#endif
            RTOS_sleepMS(0);
            continue;
        }

        HARNESS_incrementNorthChannelHead(pRngCtx->hwAccelCtx);

        pRngCtx->isRngBeingCaptured = FALSE;
    }

    HARNESS_kernelFree(pRngCtx->hwAccelCtx, TRUE, (void **)pp_randomContext);

    status = (MSTATUS)HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &pRngCtx->hwAccelCtx);

exit:
    return status;
}
#endif


/*------------------------------------------------------------------*/

#ifdef __DISABLE_DIGICERT_RNG__
extern MSTATUS
RANDOM_numberGenerator(randomContext *pRandomContext, ubyte *pBuffer, sbyte4 bufSize)
{
    fslAsyncRngCtx*     pRngCtx = (fslAsyncRngCtx *)(pRandomContext);
    ubyte4              tmpBufIndex;
    sbyte4              numBytesToCopy;
    mahCompletionDescr* pCell = NULL;
    MSTATUS             status = OK;

    if (TRUE == pRngCtx->isRngBeingCaptured)
    {
        while (OK <= (status = HARNESS_getNorthChannelHead(pRngCtx->hwAccelCtx, &pCell)))
            HARNESS_incrementNorthChannelHead(pRngCtx->hwAccelCtx);

        pRngCtx->numBytesSinceLastRng = 0;
        pRngCtx->isRngBeingCaptured = FALSE;
        status = OK;
    }

    while (0 < bufSize)
    {
        tmpBufIndex = pRngCtx->rngBufIndex;

        /* set aside our bytes */
        numBytesToCopy = FSL_RNG_RAND_BUF_SIZE - pRngCtx->rngBufIndex;

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
        if (pRngCtx->numBytesSinceLastRng >= (FSL_RNG_RAND_BUF_SIZE / 2))
        {
            if (FALSE == pRngCtx->isRngBeingCaptured)
            {
                pRngCtx->isRngBeingCaptured = TRUE;

                status = DoCryptCommon(pRngCtx->hwAccelCtx, NULL, 0, NULL, 0,
                                       NULL, 0, pRngCtx->rngBuf, FSL_RNG_RAND_BUF_SIZE, NULL, 0,
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


/*------------------------------------------------------------------*/

static MSTATUS
DoPkiCryptCommon(hwAccelDescr hwAccelCtx,
                 ubyte* pN,   ubyte4 nLen,
                 ubyte* pA,   ubyte4 aLen,
                 ubyte* pB,   ubyte4 bLen,
                 ubyte* pE,   ubyte4 eLen,
                 ubyte* pOut, ubyte4 outLen,
                 ubyte4 header)
{
    mahCellDescr*       pMahCell;
    mahCompletionDescr* pCompleteDescr = NULL;
    intBoolean          isReserve = FALSE;
    MSTATUS             status;

    if (OK > (status = HARNESS_reserveSouth(hwAccelCtx, &pMahCell)))
    {
        DEBUG_ERROR(DEBUG_HARNESS, "DoPkiCryptCommon: HARNESS_reserveSouth() return status = ", status);
        goto exit;
    }

    isReserve = TRUE;

    pMahCell->header   = header;
    pMahCell->reserved = 0;

    pMahCell->length1  = nLen << 16;
    pMahCell->pointer1 = NULL;
    if ((pN) && (OK > (status = HARNESS_mapAllocToPhysical(hwAccelCtx, pN, (void **)&pMahCell->pointer1))))
        goto exit;

    pMahCell->length2  = bLen << 16;
    pMahCell->pointer2 = NULL;
    if ((pB) && (OK > (status = HARNESS_mapAllocToPhysical(hwAccelCtx, pB, (void **)&pMahCell->pointer2))))
        goto exit;

    pMahCell->length3  = aLen << 16;
    pMahCell->pointer3 = NULL;
    if ((pA) && (OK > (status = HARNESS_mapAllocToPhysical(hwAccelCtx, pA, (void **)&pMahCell->pointer3))))
        goto exit;

    pMahCell->length4  = eLen << 16;
    pMahCell->pointer4 = NULL;
    if ((pE) && (OK > (status = HARNESS_mapAllocToPhysical(hwAccelCtx, pE, (void **)&pMahCell->pointer4))))
        goto exit;

    pMahCell->length5  = outLen << 16;
    pMahCell->pointer5 = NULL;
    if ((pOut) && (OK > (status = HARNESS_mapAllocToPhysical(hwAccelCtx, pOut, (void **)&pMahCell->pointer5))))
        goto exit;

    pMahCell->length6  = 0;
    pMahCell->pointer6 = NULL;

    pMahCell->length7  = 0;
    pMahCell->pointer7 = NULL;

    /* fire off the crypto job */
    if (OK > (status = HARNESS_activateSouthTail(hwAccelCtx)))
        goto exit;

    isReserve = FALSE;

    if (FALSE == HARNESS_isAsyncModeEnabled(hwAccelCtx, &pMahCell->pSecurityStackCtx))
    {
        /* wait for job to finish */
        while (OK > HARNESS_getNorthChannelHead(hwAccelCtx, &pCompleteDescr))
        {
            RTOS_sleepMS(0);
        }

        HARNESS_incrementNorthChannelHead(hwAccelCtx);

        if (NULL != pCompleteDescr)
        {
            status = pCompleteDescr->hwAccelError;

            pCompleteDescr->hwAccelError = 0;
            pCompleteDescr->pSecurityStackCtx = 0;
        }
        else
            status = -1;
    }

exit:
    if (TRUE == isReserve)
        HARNESS_unreserveSouth(hwAccelCtx);

    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_HARNESS, "DoPkiCryptCommon: return w/ error, return status = ", status);
    }

    return status;

} /* DoPkiCryptCommon */


/*------------------------------------------------------------------*/

static MSTATUS
FREESCALE_ASYNC_8315_vlongToArray(hwAccelDescr hwAccelCtx, const vlong* pValue, ubyte** ppRetByteArray, ubyte4* pRetByteArrayLen, sbyte4 leadingZero)
{
    ubyte4  needed;
    sbyte4  index;
    ubyte4  elem;
    ubyte*  pDest;
    MSTATUS status;

    /* clear out in case of an error */
    *ppRetByteArray   = NULL;
    *pRetByteArrayLen = 0;

    needed = ((pValue->numUnitsUsed - leadingZero) << 2) + 4;

    if (MIN_PK_BYTES_LENGTH > needed)
        needed = MIN_PK_BYTES_LENGTH;

    /* allocate necessary memory */
    if (OK > (status = HARNESS_kernelAlloc(hwAccelCtx, needed, TRUE, (void **)&pDest)))
        goto exit;

    *ppRetByteArray   = pDest;
    *pRetByteArrayLen = needed;

    for (index = pValue->numUnitsUsed - leadingZero; index >= 0; index--)
    {
        elem = VLONG_getVlongUnit(pValue, index);

        *pDest++ = (ubyte)((elem >> 24) & 0xff);
        *pDest++ = (ubyte)((elem >> 16) & 0xff);
        *pDest++ = (ubyte)((elem >>  8) & 0xff);
        *pDest++ = (ubyte)(elem & 0xff);
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
FREESCALE_ASYNC_8315_arrayToVlong(ubyte* pByteArray, ubyte4 byteArrayLen, vlong **ppRetVlong, vlong **ppVlongQueue)
{
    return VLONG_vlongFromByteString(pByteArray, byteArrayLen, ppRetVlong, ppVlongQueue);
}


/*------------------------------------------------------------------*/

#ifdef __VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__
extern MSTATUS
VLONG_modexp(hwAccelDescr hwAccelCtx, const vlong *x, const vlong *e, const vlong *m, vlong **ppRetModExp, vlong **ppVlongQueue)
{
    /* a^e mod n */
    ubyte*  pA   = NULL;
    ubyte*  pE   = NULL;
    ubyte*  pN   = NULL;
    ubyte*  pOut = NULL;
    ubyte4  aLen;
    ubyte4  eLen;
    ubyte4  nLen;
    MSTATUS status;

    if (OK > (status = FREESCALE_ASYNC_8315_vlongToArray(hwAccelCtx, x, &pA, &aLen, 1)))
        goto exit;

    if (OK > (status = FREESCALE_ASYNC_8315_vlongToArray(hwAccelCtx, e, &pE, &eLen, 1)))
        goto exit;

    if (OK > (status = FREESCALE_ASYNC_8315_vlongToArray(hwAccelCtx, m, &pN, &nLen, 1)))
        goto exit;

    if (OK > (status = HARNESS_kernelAlloc(hwAccelCtx, nLen, TRUE, (void **)&pOut)))
        goto exit;

    /* clear out the buffer, so we can determine the result length */
    /* this step may not be required, if the chip returns the result length... */
    if (OK > (status = DIGI_MEMSET(pOut, 0x00, nLen)))
        goto exit;

    if (OK > (status = DoPkiCryptCommon(hwAccelCtx, pN, nLen, pA, aLen, NULL, 0, pE, eLen, pOut, nLen, 0x58000080)))
        goto exit;

    /* convert byte array to vlong */
    status = VLONG_vlongFromByteString(pOut, nLen, ppRetModExp, ppVlongQueue);

exit:
    HARNESS_kernelFree(hwAccelCtx, TRUE, (void **)&pOut);
    HARNESS_kernelFree(hwAccelCtx, TRUE, (void **)&pN);
    HARNESS_kernelFree(hwAccelCtx, TRUE, (void **)&pE);
    HARNESS_kernelFree(hwAccelCtx, TRUE, (void **)&pA);

    return status;
}
#endif /* __VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__ */


/*------------------------------------------------------------------*/

#ifdef __RSAINT_HARDWARE__
extern MSTATUS
RSAINT_decrypt(hwAccelDescr hwAccelCtx, RSAKey *pRSAKeyInt,
               vlong *pCipher, RNGFun rngFun, void* rngFunArg,
               vlong **ppRetDecrypt, vlong **ppVlongQueue)
{
    vlong*  pm    = NULL;
    vlong*  qm    = NULL;
    vlong*  d     = NULL;
    vlong*  pm_qm = NULL;
    MSTATUS status;
    MOC_UNUSED(rngFun);         /* for RSA blinding */
    MOC_UNUSED(rngFunArg);      /* for RSA blinding */

    if (OK > (status = VLONG_allocVlong(&pm_qm, ppVlongQueue)))
        goto exit;

    /* vlong pm = p - 1; */
    if (OK > (status = VLONG_makeVlongFromVlong(RSA_P(pRSAKeyInt), &pm, ppVlongQueue)))
        goto exit;

    if (OK > (status = VLONG_decrement(pm, ppVlongQueue)))
        goto exit;

    /* vlong qm = q - vlong(1); */
    if (OK > (status = VLONG_makeVlongFromVlong(RSA_Q(pRSAKeyInt), &qm, ppVlongQueue)))
        goto exit;

    if (OK > (status = VLONG_decrement(qm, ppVlongQueue)))
        goto exit;

    /* vlong d = modinv( e, (pm)*(qm) ); */
    if (OK > (status = VLONG_vlongSignedMultiply(pm_qm, pm, qm)))
        goto exit;

    if (OK > (status = VLONG_modularInverse(MOC_MOD(hwAccelCtx) RSA_E(pRSAKeyInt), pm_qm, &d, ppVlongQueue)))
        goto exit;

    /* decrypt: m = c^d mod n */
    status = VLONG_modexp(hwAccelCtx, pCipher, d, RSA_N(pRSAKeyInt), ppRetDecrypt, ppVlongQueue);

exit:
    VLONG_freeVlong(&pm, ppVlongQueue);
    VLONG_freeVlong(&qm, ppVlongQueue);
    VLONG_freeVlong(&d,  ppVlongQueue);
    VLONG_freeVlong(&pm_qm, ppVlongQueue);

    return status;

} /* RSAINT_decrypt */
#endif


/*------------------------------------------------------------------*/

#if (defined(__HW_OFFLOAD_SINGLE_PASS_SUPPORT__))
static MSTATUS
FREESCALE_ASYNC_8315_doSinglePassCommon(hwAccelDescr hwAccelCtx,
                                        ubyte* p1, ubyte4 len1, ubyte* p2, ubyte4 len2,
                                        ubyte* p3, ubyte4 len3, ubyte* p4, ubyte4 len4,
                                        ubyte* p5, ubyte4 len5, ubyte* p6, ubyte4 len6,
                                        ubyte* p7, ubyte4 len7, ubyte4 header)
{
    void*               pSecurityStackCtx;
    intBoolean          isAsync = HARNESS_isAsyncModeEnabled(hwAccelCtx, &pSecurityStackCtx);

    mahCellDescr*       pMahCell;
    mahCompletionDescr* pCompleteDescr = NULL;
    intBoolean          isReserve = FALSE;
    MSTATUS             status;

#if defined(__LINUX_RTOS__) && defined(__KERNEL__)
    if (in_atomic() && !isAsync)
    {
        status = ERR_HARDWARE_ACCEL; /* 'sleep' will cause kernel panic! */
        goto exit;
    }
#endif

    if (OK > (status = HARNESS_reserveSouth(hwAccelCtx, &pMahCell)))
    {
        DEBUG_ERROR(DEBUG_HARNESS, "FREESCALE_ASYNC_8315_doSinglePassCommon: HARNESS_reserveSouth() return status = ", status);
        goto exit;
    }

    isReserve = TRUE;

    if (pMahCell->pSecurityStackCtx)
    {
        /* !!! previous async. context not released */
        pMahCell->pSecurityStackCtx = NULL;
    }
    if (isAsync) pMahCell->pSecurityStackCtx = pSecurityStackCtx;

    pMahCell->header   = header;
    pMahCell->reserved = 0;

    pMahCell->length1  = len1;
    pMahCell->pointer1 = NULL;
#if defined(__LINUX_RTOS__) && defined(__KERNEL__)
    if (p1)
        pMahCell->pointer1 = OS_VIRTUAL_TO_PHY(p1);
#else
    if ((p1) && (OK > (status = HARNESS_mapAllocToPhysical(hwAccelCtx, p1, (void **)&pMahCell->pointer1))))
        goto exit;
#endif

    pMahCell->length2  = len2;
    pMahCell->pointer2 = NULL;
#if defined(__LINUX_RTOS__) && defined(__KERNEL__)
    if (p2)
        pMahCell->pointer2 = OS_VIRTUAL_TO_PHY(p2);
#else
    if ((p2) && (OK > (status = HARNESS_mapAllocToPhysical(hwAccelCtx, p2, (void **)&pMahCell->pointer2))))
        goto exit;
#endif

    pMahCell->length3  = len3;
    pMahCell->pointer3 = NULL;
#if defined(__LINUX_RTOS__) && defined(__KERNEL__)
    if (p3)
        pMahCell->pointer3 = OS_VIRTUAL_TO_PHY(p3);
#else
    if ((p3) && (OK > (status = HARNESS_mapAllocToPhysical(hwAccelCtx, p3, (void **)&pMahCell->pointer3))))
        goto exit;
#endif

    pMahCell->length4  = len4;
    pMahCell->pointer4 = NULL;
#if defined(__LINUX_RTOS__) && defined(__KERNEL__)
    if (p4)
        pMahCell->pointer4 = OS_VIRTUAL_TO_PHY(p4);
#else
    if ((p4) && (OK > (status = HARNESS_mapAllocToPhysical(hwAccelCtx, p4, (void **)&pMahCell->pointer4))))
        goto exit;
#endif

    pMahCell->length5  = len5;
    pMahCell->pointer5 = NULL;
#if defined(__LINUX_RTOS__) && defined(__KERNEL__)
    if (p5)
        pMahCell->pointer5 = OS_VIRTUAL_TO_PHY(p5);
#else
    if ((p5) && (OK > (status = HARNESS_mapAllocToPhysical(hwAccelCtx, p5, (void **)&pMahCell->pointer5))))
        goto exit;
#endif

    pMahCell->length6  = len6;
    pMahCell->pointer6 = NULL;
#if defined(__LINUX_RTOS__) && defined(__KERNEL__)
    if (p6)
        pMahCell->pointer6 = OS_VIRTUAL_TO_PHY(p6);
#else
    if ((p6) && (OK > (status = HARNESS_mapAllocToPhysical(hwAccelCtx, p6, (void **)&pMahCell->pointer6))))
        goto exit;
#endif

    pMahCell->length7  = len7;
    pMahCell->pointer7 = NULL;
#if defined(__LINUX_RTOS__) && defined(__KERNEL__)
    if (p7)
        pMahCell->pointer7 = OS_VIRTUAL_TO_PHY(p7);
#else
    if ((p7) && (OK > (status = HARNESS_mapAllocToPhysical(hwAccelCtx, p7, (void **)&pMahCell->pointer7))))
        goto exit;
#endif

    /* fire off the crypto job */
    if (OK > (status = HARNESS_activateSouthTail(hwAccelCtx)))
        goto exit;

    isReserve = FALSE;

    if (!isAsync)
    {
        /* wait for job to finish */
        while (OK > HARNESS_getNorthChannelHead(hwAccelCtx, &pCompleteDescr))
        {
            RTOS_sleepMS(0);
        }

        HARNESS_incrementNorthChannelHead(hwAccelCtx);

        if (NULL != pCompleteDescr)
        {
            status = pCompleteDescr->hwAccelError;

            pCompleteDescr->hwAccelError = 0;
            pCompleteDescr->pSecurityStackCtx = 0;
        }
        else
            status = -1;
    }

exit:
    if (TRUE == isReserve)
        HARNESS_unreserveSouth(hwAccelCtx);

    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_HARNESS, "FREESCALE_ASYNC_8315_doSinglePassCommon: return w/ error, return status = ", status);
    }

    return status;

} /* FREESCALE_ASYNC_8315_doSinglePassCommon */
#endif /* (defined(__HW_OFFLOAD_SINGLE_PASS_SUPPORT__)) */


/*------------------------------------------------------------------*/

#if (defined(__HW_OFFLOAD_SINGLE_PASS_SUPPORT__))
static MSTATUS
FREESCALE_ASYNC_8315_lookupSinglePassDpdHeader(enum moduleNames protocol, ubyte4 cookie, ubyte4 *pRetDpdHeader)
{
    MSTATUS status = ERR_HARDWARE_ACCEL_SINGLE_PASS_LOOKUP_FAIL;

    if (FALSE
#if (defined(__SSL_SINGLE_PASS_SUPPORT__))
        || (MOCANA_SSL == protocol)
#endif
#if (defined(__IPSEC_SINGLE_PASS_SUPPORT__))
        || (MOCANA_IPSEC == protocol)
#endif
        )
    {
        if ((ubyte4)SIZEOF_SINGLE_PASS_LOOKUP_TABLE > cookie)
        {
            *pRetDpdHeader = mSinglePassDpdHeaderLookup[cookie];
            status = OK;
        }
    }

    return status;
}
#endif


/*------------------------------------------------------------------*/

#if (defined(__HW_OFFLOAD_SINGLE_PASS_SUPPORT__))
extern sbyte4
HWOFFLOAD_doSinglePassDecryption(hwAccelDescr hwAccelCtx, enum moduleNames protocol,
                                 typeForSinglePass singlePassInCookie, ubyte4 protocolVersion,
                                 void* pSymCipherCtx,
                                 ubyte* pHashKey, ubyte4 hashKeyLength,         /* in-only */
                                 ubyte* pHashData, ubyte4 hashDataLength,       /* in-only */
                                 ubyte* pCryptData, ubyte4 cryptDataLength,     /* in & out */
                                 ubyte* pCryptDataOut,                          /* output for IPsec only */
                                 ubyte* pCipherIV, ubyte4 cipherIvlength,       /* in & out */
                                 ubyte* pMacOut, ubyte4 macHashSize,            /* out-only */
                                 ubyte4* pRetVerfied)
{
    ubyte4  header;
    MSTATUS status;

    if (OK > (status = FREESCALE_ASYNC_8315_lookupSinglePassDpdHeader(protocol, singlePassInCookie, &header)))
        goto exit;

#if (defined(__SSL_SINGLE_PASS_SUPPORT__))
    if (MOCANA_SSL == protocol)
    {
        /* *pRetVerfied = (HW_OFFLOAD_MAC_VERIFIED); */

        if (0 == protocolVersion)
            header = header | DPD_HDR_SMAC;     /* SSL v3.0 */
        else
            header = header | DPD_HDR_HMAC;     /* TLS v1.0 */

        if (ARC4_EU0 == (OP_0_EU_SELECT_MASK & header))
        {
            fslRc4Ctx*  pRc4Ctx = (fslRc4Ctx *)pSymCipherCtx;

            if (FALSE == pRc4Ctx->isSboxCtxInit)
            {
                /* first single pass message  */
                header = header | ARC4_E0_SINGLE_PASS_DECRYPT_START;
                pRc4Ctx->isSboxCtxInit = TRUE;

                status = FREESCALE_ASYNC_8315_doSinglePassCommon(hwAccelCtx,
                                            pHashKey,            FORM_LE(hashKeyLength, 0),
                                            NULL, 0,
                                            pRc4Ctx->rc4SboxCtx, FORM_LE(pRc4Ctx->ctxSize, 0),
                                            pHashData,           FORM_LE(0, hashDataLength - cryptDataLength),
                                            pCryptData,          FORM_LE(cryptDataLength /*+ macHashSize */, macHashSize),
                                            pCryptData,          FORM_LE(cryptDataLength /* + macHashSize */, macHashSize),
                                            pRc4Ctx->rc4SboxCtx, FORM_LE(MAX_SIZE_RC4_SBOX, 0),
                                            header);
            }
            else
            {
                /* subsequent single pass messages */
                header = header | ARC4_E0_SINGLE_PASS_DECRYPT_CONTINUE;

                status = FREESCALE_ASYNC_8315_doSinglePassCommon(hwAccelCtx,
                                            pHashKey,            FORM_LE(hashKeyLength, 0),
                                            pRc4Ctx->rc4SboxCtx, FORM_LE(MAX_SIZE_RC4_SBOX, 0),
                                            NULL, 0,
                                            pHashData,           FORM_LE(0, hashDataLength - cryptDataLength),
                                            pCryptData,          FORM_LE(cryptDataLength + macHashSize, macHashSize),
                                            pCryptData,          FORM_LE(cryptDataLength + macHashSize, macHashSize),
                                            pRc4Ctx->rc4SboxCtx, FORM_LE(MAX_SIZE_RC4_SBOX, 0),
                                            header);
            }
        }
        else    /* aes, 3des, des, i.e. non-stream */
        {
            fslCipherContext* pCommonCtx = pSymCipherCtx;

            header = header | DPD_HDR_DESC_TLS_SSL_BLOCK;

            status = FREESCALE_ASYNC_8315_doSinglePassCommon(hwAccelCtx,
                                        pHashKey,   FORM_LE(hashKeyLength, 0),
                                        pCipherIV,  FORM_LE(cipherIvlength, 0),
                                        pCommonCtx->key, FORM_LE(pCommonCtx->keyLength, 0),
                                        pHashData,  FORM_LE(0, hashDataLength - cryptDataLength),
                                        pCryptData, FORM_LE(cryptDataLength, macHashSize),
                                        pCryptData, FORM_LE(cryptDataLength, macHashSize),
                                        pCipherIV,  FORM_LE(cipherIvlength, 0),
                                        header);
        }
    }
#endif  /* (defined(__SSL_SINGLE_PASS_SUPPORT__)) */
#if (defined(__IPSEC_SINGLE_PASS_SUPPORT__))
    if (MOCANA_IPSEC == protocol)
    {
        fslCipherContext* pCommonCtx = pSymCipherCtx;

        header = header | DPD_HDR_HMAC | DPD_HDR_HMAC_PD | DPD_HDR_DESC_IPSEC_ESP | MDEU_NEW_E1_CICV_BIT;

        status = FREESCALE_ASYNC_8315_doSinglePassCommon(hwAccelCtx,
                                    pHashKey,        FORM_LE(hashKeyLength, 0),
                                    pHashData,       FORM_LE(hashDataLength - cryptDataLength, 0),
                                    pCipherIV,       FORM_LE(cipherIvlength, 0),
                                    pCommonCtx->key, FORM_LE(pCommonCtx->keyLength, 0),
                                    pCryptData,      FORM_LE(cryptDataLength, macHashSize),
                                    (NULL != pCryptDataOut) ? pCryptDataOut : pCryptData,      FORM_LE(cryptDataLength, 0),
                                    NULL,            0,
                                    header);

        *pRetVerfied = FALSE; /* CICV not enabled */
    }
#endif  /* (defined(__IPSEC_SINGLE_PASS_SUPPORT__)) */

exit:
    return (sbyte4)status;

} /* HWOFFLOAD_doSinglePassDecryption */
#endif /* (defined(__HW_OFFLOAD_SINGLE_PASS_SUPPORT__)) */


/*------------------------------------------------------------------*/

#if (defined(__HW_OFFLOAD_SINGLE_PASS_SUPPORT__))
extern sbyte4
HWOFFLOAD_doSinglePassEncryption(hwAccelDescr hwAccelCtx, enum moduleNames protocol,
                                 typeForSinglePass singlePassOutCookie, ubyte4 protocolVersion,
                                 void* pSymCipherCtx,
                                 ubyte *pHashKey, ubyte4 hashKeyLength,         /* in-only */
                                 ubyte *pHashData, ubyte4 hashDataLength,       /* in-only */
                                 ubyte *pCryptData, ubyte4 cryptDataLength,     /* in & out */
                                 ubyte *pCryptDataOut,                          /* output for IPsec only */
                                 ubyte *pCipherIV, ubyte4 cipherIvlength,       /* in & out */
                                 ubyte4 macHashSize, ubyte4 padLength)
{
    ubyte4  header;
    MSTATUS status;

    if (OK > (status = FREESCALE_ASYNC_8315_lookupSinglePassDpdHeader(protocol, singlePassOutCookie, &header)))
        goto exit;

#if (defined(__SSL_SINGLE_PASS_SUPPORT__))
    if (MOCANA_SSL == protocol)
    {
        if (0 == protocolVersion)
            header = header | DPD_HDR_SMAC;     /* SSL v3.0 */
        else
            header = header | DPD_HDR_HMAC;     /* TLS v1.0 */

        if (ARC4_EU0 == (OP_0_EU_SELECT_MASK & header))
        {
            fslRc4Ctx*  pRc4Ctx = (fslRc4Ctx *)pSymCipherCtx;

            if (FALSE == pRc4Ctx->isSboxCtxInit)
            {
                /* first single pass message  */
                header = header | ARC4_E0_SINGLE_PASS_ENCRYPT_START;
                pRc4Ctx->isSboxCtxInit = TRUE;

                status = FREESCALE_ASYNC_8315_doSinglePassCommon(hwAccelCtx,
                                            pHashKey,            FORM_LE(hashKeyLength, 0),
                                            NULL, 0,
                                            pRc4Ctx->rc4SboxCtx, FORM_LE(pRc4Ctx->ctxSize, 0),
                                            pHashData,           FORM_LE(cryptDataLength - macHashSize, (hashDataLength + macHashSize) - cryptDataLength),
                                            NULL,                FORM_LE(0, macHashSize),
                                            pCryptData,          FORM_LE(cryptDataLength, 0),
                                            pRc4Ctx->rc4SboxCtx, FORM_LE(MAX_SIZE_RC4_SBOX, 0),
                                            header);
            }
            else
            {
                /* subsequent single pass messages */
                header = header | ARC4_E0_SINGLE_PASS_ENCRYPT_CONTINUE;

                status = FREESCALE_ASYNC_8315_doSinglePassCommon(hwAccelCtx,
                                            pHashKey,            FORM_LE(hashKeyLength, 0),
                                            pRc4Ctx->rc4SboxCtx, FORM_LE(MAX_SIZE_RC4_SBOX, 0),
                                            NULL, 0,
                                            pHashData,           FORM_LE(cryptDataLength - macHashSize, (hashDataLength + macHashSize) - cryptDataLength),
                                            NULL,                FORM_LE(0, macHashSize),
                                            pCryptData,          FORM_LE(cryptDataLength, 0),
                                            pRc4Ctx->rc4SboxCtx, FORM_LE(MAX_SIZE_RC4_SBOX, 0),
                                            header);
            }
        }
        else    /* aes, 3des, des, i.e. non-stream */
        {
            fslCipherContext* pCommonCtx = pSymCipherCtx;

            header = header | DPD_HDR_DESC_TLS_SSL_BLOCK;

            status = FREESCALE_ASYNC_8315_doSinglePassCommon(hwAccelCtx,
                                        pHashKey,           FORM_LE(hashKeyLength, 0),
                                        pCipherIV,          FORM_LE(cipherIvlength, 0),
                                        pCommonCtx->key,    FORM_LE(pCommonCtx->keyLength, 0),
                                        pHashData,          FORM_LE(cryptDataLength - (macHashSize + padLength), hashDataLength - (cryptDataLength - (macHashSize + padLength))),
                                        pCryptData + (cryptDataLength - (padLength)),         FORM_LE(padLength, macHashSize),
                                        pCryptData,         FORM_LE(cryptDataLength, 0),
                                        pCipherIV,          FORM_LE(cipherIvlength, 0),
                                        header);
        }
    }
#endif  /* (defined(__SSL_SINGLE_PASS_SUPPORT__)) */
#if (defined(__IPSEC_SINGLE_PASS_SUPPORT__))
    if (MOCANA_IPSEC == protocol)
    {
        fslCipherContext* pCommonCtx = pSymCipherCtx;

        header = header | DPD_HDR_HMAC | DPD_HDR_HMAC_PD | DPD_HDR_DESC_IPSEC_ESP;

        status = FREESCALE_ASYNC_8315_doSinglePassCommon(hwAccelCtx,
                                    pHashKey,        FORM_LE(hashKeyLength, 0),
                                    pHashData,       FORM_LE(hashDataLength - cryptDataLength, 0),
                                    pCipherIV,       FORM_LE(cipherIvlength, 0),
                                    pCommonCtx->key, FORM_LE(pCommonCtx->keyLength, 0),
                                    pCryptData,      FORM_LE(cryptDataLength, 0),
                                    (NULL != pCryptDataOut) ? pCryptDataOut : pCryptData,      FORM_LE(cryptDataLength, macHashSize),       /* FOR NOW */
                                    NULL,            0,
                                    header);
    }
#endif  /* (defined(__IPSEC_SINGLE_PASS_SUPPORT__)) */

exit:
    return (sbyte4)status;

} /* HWOFFLOAD_doSinglePassEncryption */
#endif /* (defined(__HW_OFFLOAD_SINGLE_PASS_SUPPORT__)) */


/*------------------------------------------------------------------*/

#if (defined(__SSL_SINGLE_PASS_SUPPORT__) && defined(__SSL_SINGLE_PASS_DECRYPT_ADJUST_SSL_RECORD_SIZE_SUPPORT__))
extern sbyte4
HWOFFLOAD_doQuickBlockDecrypt(MOC_SYM(hwAccelDescr hwAccelCtx) typeForSinglePass singlePassInCookie,
                              void* pSymCipherCtx,
                              ubyte* pCipherIV, ubyte4 cipherIvlength,
                              ubyte* pCryptData, ubyte* pIvOut)
{
    /* work around for the single pass ssl/tls decrypt bug in the 8315. JAB */
    ubyte4  header;
    MSTATUS status;

    if (OK > (status = FREESCALE_ASYNC_8315_lookupSinglePassDpdHeader(MOCANA_SSL, singlePassInCookie, &header)))
        goto exit;

    header = ((header & 0xfff00000) | DPD_HDR_DESC_COMMON_NONSNOOP);

    status = DoCryptCommon(hwAccelCtx, pCipherIV, cipherIvlength,
                           ((fslCipherContext*)pSymCipherCtx)->key,((fslCipherContext*)pSymCipherCtx)->keyLength,
                           pCryptData, cipherIvlength, pCryptData, cipherIvlength,
                           pIvOut, cipherIvlength, header);

exit:
    return (sbyte4)status;
}
#endif

#endif /*(defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) && defined(__ENABLE_FREESCALE_8315_HARDWARE_ACCEL__)) */


