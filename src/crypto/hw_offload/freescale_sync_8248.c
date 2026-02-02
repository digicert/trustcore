/*
 * freescale_sync_8248.c
 *
 * Freescale 8248 Hardware Acceleration Synchronous Adapter
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

#if (defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) && defined(__ENABLE_FREESCALE_8248_HARDWARE_ACCEL__))

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

#include "../../crypto/hw_offload/fsl_sec.h"
#include "../../crypto/hw_offload/freescale_sync_8248.h"

#define MOCANA_NONE         (-1)
#define MAX_SIZE_RC4_SBOX   (259)

#define NOT_COMPLETE            0
#define GOOD_COMPLETE           1
#define ERR_COMPLETE            (-1)


/*------------------------------------------------------------------*/

typedef struct
{
    sbyte4      encrypt;                            /* Key used for encrypting or decrypting? */
    ubyte       key[256/*KEY_SIZE_256*/];           /* raw key in this case */
    sbyte4      keyLength;                          /* Length of the key (in bytes) */

} fslCipherContext;

typedef struct
{
    ubyte           rc4SboxCtx[MAX_SIZE_RC4_SBOX];  /* rc4 context */
    ubyte4          ctxSize;                        /* initial key size, after sbox length */
    intBoolean      isSboxCtxInit;                  /* are we at the start of a cipher stream? */

} fslRc4Ctx;

typedef struct
{
    MAH_CUSTOM_HARDWARE_ACCEL_STRUCTURE

}   SECDataPacketDescriptor;

typedef struct
{
    SECDataPacketDescriptor     dpd;
    enum moduleNames            assignedModule;
    volatile ubyte4*            pFetch;
    ubyte4                      startTime;
    RTOS_MUTEX                  chMutex;

}   SECChannelInfo;

static  SECChannelInfo          mChannels[SEC_CHANNEL_COUNT];

#define CH_ID_TO_INDEX(i)       ((i)-1)
#define CH_INDEX_TO_ID(i)       ((i)+1)
#define CH_INDEX_TO_DPD_PTR(i)  &(mChannels[i].dpd)
#define LEN_64_MASK             0x0000003F


/*------------------------------------------------------------------*/

/* FORWARD DECLARATIONS */
static ubyte*   getChannelBaseAddress(int ch);


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

    for (index = 0; index < keyLength; index++)
        pKeyMaterial[index] = ((pKeyMaterial[index] & 0xfe) | parityBitLookup[pKeyMaterial[index] >> 1]);
}


/*------------------------------------------------------------------*/

extern ubyte4
FSL8248_ChIndexToISRDoneMask(int index, ubyte4 *pMask)
{
    ubyte4  mask    = 0;
    MSTATUS status  = OK;

    switch (index)
    {
        case CH_ID_TO_INDEX(SEC_CH_1):
            mask = ISR_CH1_DN_1;
            break;

        case CH_ID_TO_INDEX(SEC_CH_2):
            mask = ISR_CH2_DN_1;
            break;

        case CH_ID_TO_INDEX(SEC_CH_3):
            mask = ISR_CH3_DN_1;
            break;

        case CH_ID_TO_INDEX(SEC_CH_4):
            mask = ISR_CH4_DN_1;
            break;

        default:
            status = ERR_INDEX_OOB;
            break;
    }

    *pMask = mask;
    return status;
}


/*------------------------------------------------------------------*/

extern ubyte4
FSL8248_ChIndexToISRErrorMask(sbyte4 index, ubyte4 *pMask)
{
    ubyte4  mask    = 0;
    MSTATUS status  = OK;

    switch (index)
    {
        case CH_ID_TO_INDEX(SEC_CH_1):
            mask = ISR_CH1_ERR_1;
            break;

        case CH_ID_TO_INDEX(SEC_CH_2):
            mask = (ubyte4)ISR_CH2_ERR_1;
            break;

        case CH_ID_TO_INDEX(SEC_CH_3):
            mask = ISR_CH3_ERR_1;
            break;

        case CH_ID_TO_INDEX(SEC_CH_4):
            mask = ISR_CH4_ERR_1;
            break;

        default:
            status = ERR_INDEX_OOB;
            break;
    }

    *pMask = mask;
    return status;
}


/*------------------------------------------------------------------*/

static void
fsl8248_clearSEC_ISR(void)
{
    ubyte*                  pSECBase;
    volatile ubyte4*        pISR1;
    volatile ubyte4*        pISR2;
    volatile ubyte4*        pICR1;
    volatile ubyte4*        pICR2;

    pSECBase  = SEC_getSECBaseAddress();
    pISR1     = (volatile ubyte4*)(pSECBase + OFFSET_ISR_1);
    pISR2     = (volatile ubyte4*)(pSECBase + OFFSET_ISR_2);
    pICR1     = (volatile ubyte4*)(pSECBase + OFFSET_ICR_1);
    pICR2     = (volatile ubyte4*)(pSECBase + OFFSET_ICR_2);

    *pICR1 = *pISR1;
    *pICR2 = *pISR2;
}


/*------------------------------------------------------------------*/


static int
fsl8248_DefaultCompletion(hwAccelDescr hwAccelCookie)
{
    ubyte4                  errMask;
    ubyte*                  pSECBase;
    volatile ubyte4*        pISR1;
    ubyte4                  hdr;
    SECDataPacketDescriptor *pDPD;
    int                     result;

    pDPD = CH_INDEX_TO_DPD_PTR(hwAccelCookie);

    hdr = pDPD->header;

    if (DPD_HDR_DN_VALUE == (pDPD->header & DPD_HDR_DN_MASK))
    {
        result = GOOD_COMPLETE;    /* header DN written back. */
        goto exit;
    }

    /* we might be done because there was an error */
    if (OK > FSL8248_ChIndexToISRErrorMask(hwAccelCookie, &errMask))
    {
        result = ERR_COMPLETE;
        goto exit;
    }

    pSECBase = SEC_getSECBaseAddress();
    pISR1    = (volatile ubyte4*)(pSECBase + OFFSET_ISR_1);
    result   = (0 == (errMask & *pISR1)) ? NOT_COMPLETE : ERR_COMPLETE;

exit:
    if (NOT_COMPLETE == result)
    {
        /* yield the processor */
        RTOS_sleepMS(1);
    }

    return result;
}


/*------------------------------------------------------------------*/

static MSTATUS
fsl8248_initSECChannels(void)
{
    int                 i;
    ubyte*              pChBase;
    volatile ubyte4*    pCCCR_2;
    MSTATUS             status = OK;

    for (i = 0; i < SEC_CHANNEL_COUNT; i++)
    {
        if (OK > (status = DIGI_MEMSET((ubyte*)&mChannels[i], 0, sizeof(mChannels[i]))))
            goto exit;

        mChannels[i].assignedModule = (enum moduleNames)MOCANA_NONE;
        pChBase = getChannelBaseAddress(CH_INDEX_TO_ID(i));
        mChannels[i].pFetch = (ubyte4*)(pChBase + OFFSET_CHANNEL_FR);

        pCCCR_2 = (ubyte4*)(pChBase + OFFSET_CHANNEL_CCCR_2);

        /* set burst size to max, set writeback enable. You may want to adjust
         * the burst size to suit your runtime environment. */
        *pCCCR_2   |= (FSL_BITS(23,7) | BIT_CCCR_WE | BIT_CCCR_NT);

        if (OK > (status = RTOS_mutexCreate(&(mChannels[i].chMutex), HW_ACCEL_CHANNEL_MUTEX, i)))
            goto exit;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
fsl8248_assignChannel(enum moduleNames module, sbyte4 *pIndex)
{
    int     i;
    MSTATUS status = ERR_HARDWARE_ACCEL_OPEN_SESSION;

    for (i = 0; i < SEC_CHANNEL_COUNT; i++)
    {
        if (((enum moduleNames)MOCANA_NONE == mChannels[i].assignedModule) || (module == mChannels[i].assignedModule))
        {
            *pIndex = i;
            mChannels[i].assignedModule = module;
            status = OK;
            goto exit;
        }
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
fsl8248_unassignChannel(enum moduleNames module)
{
    int     i;
    MSTATUS status = ERR_HARDWARE_ACCEL_CLOSE_SESSION;

    for (i = 0; i < SEC_CHANNEL_COUNT; i++)
    {
        if (module == mChannels[i].assignedModule)
        {
            mChannels[i].assignedModule = (enum moduleNames)MOCANA_NONE;
            status = OK;
        }
    }

    return status;
}


/*------------------------------------------------------------------*/

/*
 * The support routines that follow need to move. The asm routines,
 * particularly, may not compile in other IDEs.
 */
ubyte*  SEC_getIMMR(void)
{
    return (unsigned char*)IMMR_ADDRESS;
}


/*------------------------------------------------------------------*/

#if defined(__ENABLE_MW_ASM__)
asm ubyte4   SEC_getMSR(void)
{
    mfmsr       r3;
}


/*------------------------------------------------------------------*/

asm void            SEC_setMSR(ubyte4 val)
{
#pragma unused(val)
    mtmsr       r3;
}
#endif /* defined(__ENABLE_MW_ASM__) */


/*------------------------------------------------------------------*/

ubyte*   SEC_getSECBaseAddress(void)
{
    ubyte4   result;
    ubyte4   secbr = *((ubyte4*)(IMMR_ADDRESS + OFFSET_SECBR));
    ubyte4   secmr = *((ubyte4*)(IMMR_ADDRESS + OFFSET_SECMR));

    result = secbr & secmr;

    return (ubyte*)result;
}


/*------------------------------------------------------------------*/

/* use SEC_CH_1, etc., which are ones-based. */
static ubyte *
getChannelBaseAddress(int ch)
{
    ubyte*  pAddr;

    pAddr = SEC_getSECBaseAddress();

    switch (ch)
    {
        case SEC_CH_1:
            pAddr += OFFSET_CHANNEL_1;
            break;

        case SEC_CH_2:
            pAddr += OFFSET_CHANNEL_2;
            break;

        case SEC_CH_3:
            pAddr += OFFSET_CHANNEL_3;
            break;

        case SEC_CH_4:
            pAddr += OFFSET_CHANNEL_4;
            break;

        default:
            pAddr = NULL;
            break;
    }

    return pAddr;
}


/*------------------------------------------------------------------*/

static void
fsl8248_siu_SECCoprocessorEnable(intBoolean enable)
{
    volatile unsigned long*     pSIUMCR;
    unsigned long               siumcr;

    pSIUMCR = (volatile unsigned long *)(IMMR_ADDRESS + OFFSET_SIUMCR);
    siumcr = *pSIUMCR;

    if (enable)
        siumcr &= ~SIUMCR_SECDIS;
    else
        siumcr |= SIUMCR_SECDIS;

    *pSIUMCR = siumcr;
}


/*------------------------------------------------------------------*/

extern sbyte4
FSL8248_init(void)
{
    MSTATUS status = OK;
    volatile ubyte4  *pSecBR = (ubyte4 *)(IMMR_ADDRESS + OFFSET_SECBR);
    volatile ubyte4  *pSecMR = (ubyte4 *)(IMMR_ADDRESS + OFFSET_SECMR);

    *pSecMR = 0xfffe0000;
    *pSecBR = IMMR_ADDRESS +0x40001;

    fsl8248_siu_SECCoprocessorEnable(TRUE);

    fsl8248_initSECChannels();

    return (sbyte4)status;
}


/*------------------------------------------------------------------*/

#if 0
extern void
FSL8248_SetSECInterrupt(intBoolean enable)
{
    volatile ubyte4* pPSIMR_L = (volatile ubyte4 *)(IMMR_ADDRESS + OFFSET_SIMR_L);
    ubyte4   bits;

    if (enable)
    {
        bits = SIMR_L_SEC;
        *pPSIMR_L |= bits;
    }
    else
    {
        bits = (ubyte4)(~SIMR_L_SEC);
        *pPSIMR_L &= bits;
    }
}
#endif


/*------------------------------------------------------------------*/

extern ubyte4
FSL8248_SetSEC_IMR_1(ubyte4 val)
{
    ubyte*              pSECBase;
    volatile ubyte4*    pIMR_1;
    ubyte4              oldVal;

    pSECBase = SEC_getSECBaseAddress();

    pIMR_1   = (volatile ubyte4*)(pSECBase + OFFSET_IMR_1);
    oldVal   = *pIMR_1;
    *pIMR_1  = val;

    return oldVal;
}


/*------------------------------------------------------------------*/

#if defined(__ENABLE_MW_ASM__)
extern void
FSL8248_SetEEInterrupt(intBoolean enable)
{
    ubyte4      msr;

    /* enable external interrupt handling */
    msr = SEC_getMSR();

    if (enable)
        msr |= MSR_EE;
    else
        msr &= ~MSR_EE;

    SEC_setMSR(msr);
}
#endif


/*------------------------------------------------------------------*/

extern sbyte4
FSL8248_uninit(void)
{
    return (sbyte4)OK;
}

/*------------------------------------------------------------------*/

#ifdef __ENABLE_MW_PROFILER__
#pragma profile on
#endif


/*------------------------------------------------------------------*/


extern sbyte4
FSL8248_openChannel(enum moduleNames moduleId, sbyte4 *pHwAccelCookie)
{
    static int      created = FALSE;
    MSTATUS         status;

    *pHwAccelCookie = -1;   /* bad id */

    status =  fsl8248_assignChannel(moduleId, pHwAccelCookie);

    return (sbyte4)status;
}


/*------------------------------------------------------------------*/

extern sbyte4
FSL8248_closeChannel(enum moduleNames moduleId, sbyte4 *pHwAccelCookie)
{
    MSTATUS status;

    status = fsl8248_unassignChannel(moduleId);
    *pHwAccelCookie = -1;   /* bad id */

    return (sbyte4)status;
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

/*
 *
 * For encrypt/decrypt:
        p2 = dpd.p2 = iv
        p3 = dpd.p3 = key
        p4 = dpd.p4 = in data to encrypt/decrypt
        p5 = dpd.p5 = out data (probably == in)
        p6 = dpd.p6 = NULL
 * For hash:
        p2 = dpd.p2 = NULL
        p3 = dpd.p3 = NULL
        p4 = dpd.p4 = in data (hash over this)
        p5 = dpd.p5 = NULL
        p6 = dpd.p6 = out hash
 * For HMAC
        p2 = dpd.p2 = NULL
        p3 = dpd.p3 = key
        p4 = dpd.p4 = in data (hash over this)
        p5 = dpd.p5 = NULL
        p6 = dpd.p6 = out hash
 * For modexp (b = a^^e mod n, all byte arrays little-endian)
        p2 = dpd.p2 = a
        p3 = dpd.p3 = e
        p4 = dpd.p4 = n
        p5 = dpd.p5 = b
        p6 = dpd.p6 = NULL
*/


static MSTATUS
DoCryptCommon(hwAccelDescr hwAccelCtx,
              ubyte* p2, ubyte4 len2, ubyte* p3, ubyte4 len3,
              ubyte* p4, ubyte4 len4, ubyte* p5, ubyte4 len5,
              ubyte* p6, ubyte4 len6, ubyte4 header)
{
    SECChannelInfo*     pChInfo = &mChannels[hwAccelCtx];
    int                 result;
    MSTATUS             status;

    if (OK > (status = RTOS_mutexWait(pChInfo->chMutex)))
        goto exit;

    pChInfo->dpd.header   = header;

    pChInfo->dpd.length1  = 0;
    pChInfo->dpd.pointer1 = NULL;

    pChInfo->dpd.length2  = len2;
    pChInfo->dpd.pointer2 = p2;
    pChInfo->dpd.length3  = len3;
    pChInfo->dpd.pointer3 = p3;
    pChInfo->dpd.length4  = len4;
    pChInfo->dpd.pointer4 = p4;
    pChInfo->dpd.length5  = len5;
    pChInfo->dpd.pointer5 = p5;
    pChInfo->dpd.length6  = len6;
    pChInfo->dpd.pointer6 = p6;

    pChInfo->dpd.length7  = 0x0;
    pChInfo->dpd.pointer7 = NULL;
    pChInfo->dpd.pNext    = NULL;

    pChInfo->startTime = RTOS_getUpTimeInMS();

    *(pChInfo->pFetch) = (ubyte4)(&pChInfo->dpd);

    while (((int)NOT_COMPLETE) == (result = fsl8248_DefaultCompletion(hwAccelCtx)))
    {
        if ((RTOS_getUpTimeInMS() - pChInfo->startTime) > FSL_SEC_SYNC_TIMEOUT_MS)
        {
            result = ERR_COMPLETE;
            break;
        }
    }

    if (OK > (status = RTOS_mutexRelease(pChInfo->chMutex)))
        goto exit;

    if (ERR_COMPLETE == result)
        status = ERR_HARDWARE_ACCEL_DO_CRYPTO;
    else
        status = OK;

    /* not sure the following is necessary if no interrupt service routine */
    fsl8248_clearSEC_ISR();

exit:
    return status;
}


/*------------------------------------------------------------------*/

#if ((!defined(__DISABLE_AES_CIPHERS__)) && defined(__AES_HARDWARE_CIPHER__))
extern BulkCtx
CreateAESCtx(hwAccelDescr hwAccelCtx, ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt)
{
    fslCipherContext*   ctx = NULL;
    MOC_UNUSED(hwAccelCtx);

    if (!((16 == keyLength) || (24 == keyLength) || (32 == keyLength)))
        goto exit;  /* bad key size */

    ctx = CreateCtxCommon(keyMaterial, keyLength, encrypt);

exit:
    return (BulkCtx)ctx;
}
#endif /* ((!defined(__DISABLE_AES_CIPHERS__)) && defined(__AES_HARDWARE_CIPHER__)) */


/*------------------------------------------------------------------*/

#if ((!defined(__DISABLE_AES_CIPHERS__)) && defined(__AES_HARDWARE_CIPHER__))
extern MSTATUS
DoAES(hwAccelDescr hwAccelCtx, BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt, ubyte* iv)
{
    ubyte           tempIV[AES_BLOCK_SIZE];
    ubyte4          header;
    MSTATUS         status;

    if (NULL == ctx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 > hwAccelCtx)
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

    if (0 == encrypt)
        DIGI_MEMCPY(tempIV, &(data[dataLength - AES_BLOCK_SIZE]), AES_BLOCK_SIZE);

    header = encrypt ? DPD_HEADER_AES_ENCRYPT : DPD_HEADER_AES_DECRYPT;

    if (OK > (status = DoCryptCommon(hwAccelCtx, iv, 0x10,
                                     ((fslCipherContext*)ctx)->key, ((fslCipherContext*)ctx)->keyLength,
                                     data, dataLength, data, dataLength,
                                     NULL, 0, header)))
    {
        goto exit;
    }

    if (0 == encrypt)
        DIGI_MEMCPY(iv, tempIV, AES_BLOCK_SIZE);
    else
        DIGI_MEMCPY(iv, &(data[dataLength - AES_BLOCK_SIZE]), AES_BLOCK_SIZE);

exit:
    return status;

}   /* DoAES */
#endif /* ((!defined(__DISABLE_AES_CIPHERS__)) && defined(__AES_HARDWARE_CIPHER__)) */


/*------------------------------------------------------------------*/

#if ((!defined(__DISABLE_AES_CIPHERS__)) && defined(__AES_HARDWARE_CIPHER__))
extern MSTATUS
DeleteAESCtx(hwAccelDescr hwAccelCtx, BulkCtx* ctx)
{
    MOC_UNUSED(hwAccelCtx);

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
CreateDESCtx(hwAccelDescr hwAccelCtx, ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt)
{
    MOC_UNUSED(hwAccelCtx);

    if ((DES_KEY_LENGTH != keyLength) || (NULL == keyMaterial))
        return NULL;  /* bad key size or material */

    fixupParityBits(keyMaterial, keyLength);

    return (BulkCtx)(CreateCtxCommon(keyMaterial, keyLength, encrypt));
}
#endif /* (defined(__ENABLE_DES_CIPHER__) && defined(__DES_HARDWARE_CIPHER__)) */


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DES_CIPHER__) && defined(__DES_HARDWARE_CIPHER__))
extern MSTATUS
DoDES(hwAccelDescr hwAccelCtx, BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt, ubyte* iv)
{
    ubyte           tempIV[DES_BLOCK_SIZE];
    ubyte4          header;
    MSTATUS         status;

    if (NULL == ctx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 > hwAccelCtx)
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

    if (0 == encrypt)
        DIGI_MEMCPY(tempIV, &(data[dataLength - DES_BLOCK_SIZE]), DES_BLOCK_SIZE);

    header = encrypt ? DPD_HEADER_DES_ENCRYPT : DPD_HEADER_DES_DECRYPT;

    if (OK > (status = DoCryptCommon(hwAccelCtx, iv, 0x8,
                                     ((fslCipherContext*)ctx)->key, ((fslCipherContext*)ctx)->keyLength,
                                     data, dataLength, data, dataLength,
                                     NULL, 0, header)))
    {
        goto exit;
    }

    if (0 == encrypt)
        DIGI_MEMCPY(iv, tempIV, DES_BLOCK_SIZE);
    else
        DIGI_MEMCPY(iv, &(data[dataLength - DES_BLOCK_SIZE]), DES_BLOCK_SIZE);

exit:
    return status;
}
#endif /* (defined(__ENABLE_DES_CIPHER__) && defined(__DES_HARDWARE_CIPHER__)) */


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DES_CIPHER__) && defined(__DES_HARDWARE_CIPHER__))
extern MSTATUS
DeleteDESCtx(hwAccelDescr hwAccelCtx, BulkCtx* ctx)
{
    MOC_UNUSED(hwAccelCtx);

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
extern BulkCtx
Create3DESCtx(hwAccelDescr hwAccelCtx, ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt)
{
    MOC_UNUSED(hwAccelCtx);

    if ((THREE_DES_KEY_LENGTH != keyLength) || (NULL == keyMaterial))
        return NULL;

    fixupParityBits(keyMaterial, keyLength);

    return CreateCtxCommon(keyMaterial, keyLength, encrypt);
}
#endif /* ((!defined(__DISABLE_3DES_CIPHERS__)) && defined(__3DES_HARDWARE_CIPHER__)) */


/*------------------------------------------------------------------*/

#if ((!defined(__DISABLE_3DES_CIPHERS__)) && defined(__3DES_HARDWARE_CIPHER__))
extern MSTATUS
Do3DES(hwAccelDescr hwAccelCtx, BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt, ubyte* iv)
{
    ubyte           tempIV[THREE_DES_BLOCK_SIZE];
    ubyte4          header;
    MSTATUS         status;

    if (NULL == ctx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 > hwAccelCtx)
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

    if (0 == encrypt)
        DIGI_MEMCPY(tempIV, &(data[dataLength - THREE_DES_BLOCK_SIZE]), THREE_DES_BLOCK_SIZE);

    header = encrypt ? DPD_HEADER_TDES_ENCRYPT : DPD_HEADER_TDES_DECRYPT;

    if (OK > (status = DoCryptCommon(hwAccelCtx, iv, 0x8,
                                     ((fslCipherContext*)ctx)->key, ((fslCipherContext*)ctx)->keyLength,
                                     data, dataLength, data, dataLength,
                                     NULL, 0, header)))
    {
        goto exit;
    }

    if (0 == encrypt)
        DIGI_MEMCPY(iv, tempIV, THREE_DES_BLOCK_SIZE);
    else
        DIGI_MEMCPY(iv, &(data[dataLength - THREE_DES_BLOCK_SIZE]), THREE_DES_BLOCK_SIZE);

exit:
    return status;
}
#endif /* ((!defined(__DISABLE_3DES_CIPHERS__)) && defined(__3DES_HARDWARE_CIPHER__)) */


/*------------------------------------------------------------------*/

#if ((!defined(__DISABLE_3DES_CIPHERS__)) && defined(__3DES_HARDWARE_CIPHER__))
extern MSTATUS
Delete3DESCtx(hwAccelDescr hwAccelCtx, BulkCtx* ctx)
{
    MOC_UNUSED(hwAccelCtx);

    if (*ctx)
    {
        FREE(*ctx);
        *ctx = NULL;
    }

    return OK;
}
#endif /* ((!defined(__DISABLE_3DES_CIPHERS__)) && defined(__3DES_HARDWARE_CIPHER__)) */


/*------------------------------------------------------------------*/

#if ((!defined(__DISABLE_ARC4_CIPHERS__)) && defined(__ARC4_HARDWARE_CIPHER__))
extern BulkCtx
CreateRC4Ctx(hwAccelDescr hwAccelCtx, ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt)
{
    fslRc4Ctx*  pRc4Ctx = NULL;
    MOC_UNUSED(hwAccelCtx);
    MOC_UNUSED(encrypt);

    if ((1 > keyLength) || (256 < keyLength))
        goto exit;  /* bad key size */

    if (NULL == (pRc4Ctx = MALLOC(sizeof(fslRc4Ctx))))
        goto exit;

    DIGI_MEMSET((ubyte *)pRc4Ctx, 0x00, sizeof(fslRc4Ctx));
    DIGI_MEMCPY(pRc4Ctx->rc4SboxCtx, keyMaterial, keyLength);

    pRc4Ctx->ctxSize       = keyLength;
    pRc4Ctx->isSboxCtxInit = FALSE;

exit:
    return pRc4Ctx;
}
#endif /* ((!defined(__DISABLE_ARC4_CIPHERS__)) && defined(__ARC4_HARDWARE_CIPHER__)) */


/*------------------------------------------------------------------*/

#if ((!defined(__DISABLE_ARC4_CIPHERS__)) && defined(__ARC4_HARDWARE_CIPHER__))
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

    if (0 > hwAccelCtx)
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
#endif /* ((!defined(__DISABLE_ARC4_CIPHERS__)) && defined(__ARC4_HARDWARE_CIPHER__)) */


/*------------------------------------------------------------------*/

#if ((!defined(__DISABLE_ARC4_CIPHERS__)) && defined(__ARC4_HARDWARE_CIPHER__))
extern MSTATUS
DeleteRC4Ctx(hwAccelDescr hwAccelCtx, BulkCtx* ctx)
{
    MOC_UNUSED(hwAccelCtx);

    if (*ctx)
    {
        FREE(*ctx);
        *ctx = NULL;
    }

    return OK;
}
#endif /* ((!defined(__DISABLE_ARC4_CIPHERS__)) && defined(__ARC4_HARDWARE_CIPHER__)) */


/*------------------------------------------------------------------*/

static MSTATUS
DoMDCryptCommon(hwAccelDescr hwAccelCtx,
                ubyte* pCtxIn,  ubyte4 ctxInLen,
                ubyte* pKey,    ubyte4 keyLen,
                ubyte* pData,   ubyte4 dataLen,
                ubyte* pDigest, ubyte4 digestLen,
                ubyte* pCtxOut, ubyte4 ctxOutLen,
                ubyte4 header)
{
    SECChannelInfo*     pChInfo = &mChannels[hwAccelCtx];
    int                 result;
    MSTATUS             status;

    if (OK > (status = RTOS_mutexWait(pChInfo->chMutex)))
        goto exit;

    pChInfo->dpd.header   = header;

    pChInfo->dpd.length1  = 0;
    pChInfo->dpd.pointer1 = NULL;
    pChInfo->dpd.length2  = ctxInLen;
    pChInfo->dpd.pointer2 = pCtxIn;
    pChInfo->dpd.length3  = keyLen;
    pChInfo->dpd.pointer3 = pKey;
    pChInfo->dpd.length4  = dataLen;
    pChInfo->dpd.pointer4 = pData;
    pChInfo->dpd.length5  = 0;
    pChInfo->dpd.pointer5 = NULL;
    pChInfo->dpd.length6  = digestLen;
    pChInfo->dpd.pointer6 = pDigest;
    pChInfo->dpd.length7  = ctxOutLen;
    pChInfo->dpd.pointer7 = pCtxOut;
    pChInfo->dpd.pNext    = NULL;

    pChInfo->startTime = RTOS_getUpTimeInMS();

    *(pChInfo->pFetch) = (ubyte4)(&pChInfo->dpd);

    while (((int)NOT_COMPLETE) == (result = fsl8248_DefaultCompletion(hwAccelCtx)))
    {
        if ((RTOS_getUpTimeInMS() - pChInfo->startTime) > FSL_SEC_SYNC_TIMEOUT_MS)
        {
            result = ERR_COMPLETE;
            break;
        }
    }

    if (OK > (status = RTOS_mutexRelease(pChInfo->chMutex)))
        goto exit;

    if (ERR_COMPLETE == result)
        status = ERR_HARDWARE_ACCEL_DO_CRYPTO;
    else
        status = OK;

    /* not sure the following is necessary if no interrupt service routine */
    fsl8248_clearSEC_ISR();

exit:
    return status;
}


/*------------------------------------------------------------------*/

#ifdef __HMAC_MD5_HARDWARE_HASH__
extern MSTATUS
HMAC_MD5(hwAccelDescr hwAccelCtx, ubyte* key, sbyte4 keyLen, ubyte* text, sbyte4 textLen,
         ubyte* textOpt, sbyte4 textOptLen, ubyte result[MD5_DIGESTSIZE])
{
    ubyte*      pText;
    ubyte       tk[MD5_DIGESTSIZE];

    MSTATUS     status;

    pText = NULL;

    if (0 > hwAccelCtx)
    {
        status = ERR_HARDWARE_ACCEL_BAD_CTX;
        goto exit;
    }
    if ((NULL == textOpt) && (0 != textOptLen))
        textOptLen = 0;

    if (NULL == textOpt)
    {
        (pText) = text;
    }
    else if (NULL == ((pText) = MALLOC(textLen + textOptLen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMCPY((pText), text, textLen);
    DIGI_MEMCPY((pText) + textLen, textOpt, textOptLen);

    /* if key is longer than HMAC_BLOCK_SIZE bytes reset it to key=MD5(key) */
    if (keyLen > HMAC_BLOCK_SIZE)
    {
        if (OK > (status = MD5_completeDigest(hwAccelCtx, key, keyLen, tk)))
            goto exit;

        key = tk;
        keyLen = MD5_DIGESTSIZE;
    }

    if (OK > (status = DoMDCryptCommon(hwAccelCtx, NULL, 0, key, keyLen, (pText), textLen + textOptLen,
                                        result, MD5_DIGESTSIZE, NULL, 0, DPD_HEADER_MD_MD5_HMAC_COMPLETE)))
    {
        goto exit;
    }

exit:
    if ((NULL != (pText)) && (NULL != textOpt))
        FREE((pText));

    return status;
}
#endif


/*------------------------------------------------------------------*/

#ifdef __HMAC_SHA1_HARDWARE_HASH__
extern MSTATUS
HMAC_SHA1(hwAccelDescr hwAccelCtx, ubyte* key, sbyte4 keyLen, ubyte* text, sbyte4 textLen,
          ubyte* textOpt, sbyte4 textOptLen, ubyte result[SHA_HASH_RESULT_SIZE])
{
    ubyte*      pText;
    ubyte       tk[SHA_HASH_RESULT_SIZE];

    MSTATUS     status;

    (pText) = NULL;

    if (0 > hwAccelCtx)
    {
        status = ERR_HARDWARE_ACCEL_BAD_CTX;
        goto exit;
    }

    if (NULL == textOpt)
    {
        (pText) = text;
    }
    else if (NULL == ((pText) = MALLOC(textLen + textOptLen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMCPY((pText), text, textLen);
    DIGI_MEMCPY((pText) + textLen, textOpt, textOptLen);

    /* if key is longer than HMAC_BLOCK_SIZE bytes reset it to key=MD5(key) */
    if (keyLen > HMAC_BLOCK_SIZE)
    {
        if (OK > (status = SHA1_completeDigest(hwAccelCtx, key, keyLen, tk)))
        {
            goto exit;
        }

        key = tk;
        keyLen =  SHA_HASH_RESULT_SIZE;
    }

    if (OK > (status = DoMDCryptCommon(hwAccelCtx, NULL, 0, key, keyLen, pText, textLen + textOptLen,
                                       result, SHA_HASH_RESULT_SIZE, NULL, 0, DPD_HEADER_MD_SHA1_HMAC_COMPLETE)))
    {
        goto exit;
    }

exit:
    if ((NULL != (pText)) && (NULL != textOpt))
        FREE((pText));

    return status;
}
#endif


/*------------------------------------------------------------------*/

#ifdef __HMAC_MD5_HARDWARE_HASH__
extern MSTATUS
HMAC_MD5_quick(hwAccelDescr hwAccelCtx, ubyte* pKey, sbyte4 keyLen, ubyte* pText, sbyte4 textLen,
               ubyte* pResult /* MD5_DIGESTSIZE */)
{
    return HMAC_MD5(hwAccelCtx, pKey, keyLen, pText, textLen, NULL, 0, pResult);
}
#endif


/*------------------------------------------------------------------*/

#ifdef __HMAC_SHA1_HARDWARE_HASH__
extern MSTATUS
HMAC_SHA1_quick(hwAccelDescr hwAccelCtx, ubyte* pKey, sbyte4 keyLen, ubyte* pText, sbyte4 textLen,
                ubyte* pResult /* SHA_HASH_RESULT_SIZE */)
{
    return HMAC_SHA1(hwAccelCtx, pKey, keyLen, pText, textLen, NULL, 0, pResult);
}
#endif


/*------------------------------------------------------------------*/

#ifdef __MD5_ONE_STEP_HARDWARE_HASH__
extern MSTATUS
MD5_completeDigest(hwAccelDescr hwAccelCtx, ubyte *pData,
                   ubyte4 dataLen, ubyte *pMdOutput)
{
    MSTATUS     status;

    status = DoMDCryptCommon(hwAccelCtx, NULL, 0, NULL, 0, pData, dataLen,
                                       pMdOutput, MD5_DIGESTSIZE, NULL, 0,
                                       DPD_HEADER_MD_MD5_HASH_COMPLETE);

    return status;
}
#endif


/*------------------------------------------------------------------*/

#ifdef __SHA1_ONE_STEP_HARDWARE_HASH__
extern MSTATUS
SHA1_completeDigest(hwAccelDescr hwAccelCtx, ubyte *pData,
                    ubyte4 dataLen, ubyte *pShaOutput)
{
    MSTATUS     status;

    status = DoMDCryptCommon(hwAccelCtx, NULL, 0, NULL, 0, pData, dataLen,
                                       pShaOutput, SHA_HASH_RESULT_SIZE, NULL, 0,
                                       DPD_HEADER_MD_SHA1_HASH_COMPLETE);

    return status;
}
#endif


/*------------------------------------------------------------------*/

#if defined(__CUSTOM_MD5_CONTEXT__) || defined(__CUSTOM_SHA1_CONTEXT__)
#define MD_CTX_BUFF_AVAIL(c)           (MD_CTX_HASHDATA_SIZE - (c)->index)
#endif


/*------------------------------------------------------------------*/

#ifdef __MD5_HARDWARE_HASH__
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
    ubyte4  multipleOf64Bytes;
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

        if (0 < (copyLen = (availSpace > dataLen) ? dataLen : availSpace))
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

        /* process 64 byte chunk */
        if (OK > (status = DoMDCryptCommon(hwAccelCtx,
                                           pFSLCtx, fslCtxSize,
                                           NULL, 0,
                                           p_md5Context->cachedHashData, MD_CTX_HASHDATA_SIZE,
                                           p_md5Context->fslCtx, MD_CTX_FSL_CTX_SIZE,
                                           NULL, 0,
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
                                           (ubyte*)pData, multipleOf64Bytes,
                                           p_md5Context->fslCtx, MD_CTX_FSL_CTX_SIZE,
                                           NULL, 0,
                                           header)))
        {
            goto exit;
        }

        pData += multipleOf64Bytes;

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
                             digest, MD5_DIGESTSIZE, NULL, 0,  header);

exit:
    return status;
}
#endif /* __MD5_HARDWARE_HASH__ */


/*------------------------------------------------------------------*/

#ifdef __SHA1_HARDWARE_HASH__
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
    ubyte4  multipleOf64Bytes;
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

        if (0 < (copyLen = (availSpace > dataLen) ? dataLen : availSpace))
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

        /* process 64 byte chunk */
        if (OK > (status = DoMDCryptCommon(hwAccelCtx,
                                           pFSLCtx, fslCtxSize,
                                           NULL, 0,
                                           p_shaContext->cachedHashData, MD_CTX_HASHDATA_SIZE,
                                           p_shaContext->fslCtx, MD_CTX_FSL_CTX_SIZE,
                                           NULL, 0,
                                           header)))
        {
            goto exit;
        }

        if ((FALSE == p_shaContext->isAfterFirstBlock) && (MD_CTX_HASHDATA_SIZE < dataLen))
        {
            /* processed first chunk, setup for multi-chunk handling in next phase */
            pFSLCtx    = p_shaContext->fslCtx;
            fslCtxSize = MD_CTX_FSL_CTX_SIZE;
            header     = (ubyte4)DPD_HEADER_MD_SHA1_HASH_UPDATE;
        }

        p_shaContext->isAfterFirstBlock = TRUE;
        p_shaContext->index = 0;
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
                                           (ubyte*)pData, multipleOf64Bytes,
                                           p_shaContext->fslCtx, MD_CTX_FSL_CTX_SIZE,
                                           NULL, 0,
                                           header)))
        {
            goto exit;
        }

        pData += multipleOf64Bytes;

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
                             pShaOutput, SHA_HASH_RESULT_SIZE, NULL, 0,  header);

exit:
    return status;
}
#endif /* __SHA1_HARDWARE_HASH__ */



/*------------------------------------------------------------------*/

#ifdef __DISABLE_DIGICERT_RNG__
extern MSTATUS
RANDOM_acquireContext(randomContext **pp_randomContext)
{
    randomContext*  hwAccelCtx;
    MSTATUS         status;

    status = FSL8248_openChannel(MOCANA_MSS, (sbyte4*)&hwAccelCtx);
    *pp_randomContext = hwAccelCtx;

    return status;
}
#endif


/*------------------------------------------------------------------*/

#ifdef __DISABLE_DIGICERT_RNG__
extern MSTATUS
RANDOM_releaseContext(randomContext **pp_randomContext)
{
    hwAccelDescr  hwAccelCtx = (sbyte4)(*pp_randomContext);
    MSTATUS status;

    if (0 > hwAccelCtx)
    {
        status = ERR_HARDWARE_ACCEL_BAD_CTX;
        goto exit;
    }

    status = FSL8248_closeChannel(MOCANA_MSS, &hwAccelCtx);

exit:
    return status;
}
#endif


/*------------------------------------------------------------------*/

#ifdef __DISABLE_DIGICERT_RNG__
extern MSTATUS
RANDOM_numberGenerator(randomContext *pRandomContext, ubyte *pBuffer, sbyte4 bufSize)
{
    hwAccelDescr      hwAccelCtx = (sbyte4)pRandomContext;

    return DoCryptCommon(hwAccelCtx, NULL, 0, NULL, 0,
                         NULL, 0, pBuffer, bufSize, NULL, 0,
                         DPD_HEADER_RNG);
}
#endif


/*------------------------------------------------------------------*/

/* pads zeroes on the right, up to pRetLen. This is so we can present
 * small numbers to the accelerator without it complaining there aren't
 * enough bits in the input.
 */
static MSTATUS
fsl8248_littleEndianByteStringFromVlong(vlong* pValue, ubyte** ppDest, ubyte4* pRetLen)
{
    ubyte4  needed;
    ubyte4  index;
    ubyte4  elem;
    ubyte*  pDest;
    MSTATUS status = OK;

    *ppDest = NULL;
    *pRetLen = 0;

    needed = pValue->numUnitsUsed << 2;
    if (MIN_PK_BYTES_LENGTH > needed)
        needed = MIN_PK_BYTES_LENGTH;

    if (NULL == (pDest = MALLOC(needed)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    *ppDest = pDest;
    *pRetLen = needed;

    DIGI_MEMSET(pDest, 0, needed);
    for (index = 0; index < pValue->numUnitsUsed; index++)
    {
        elem = VLONG_getVlongUnit(pValue, index);

        *pDest++ = (ubyte)elem;
        *pDest++ = (ubyte)((elem >>  8) & 0xff);
        *pDest++ = (ubyte)((elem >> 16) & 0xff);
        *pDest++ = (ubyte)((elem >> 24) & 0xff);
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
vlongFromLittleEndianByteString(const ubyte* byteString, sbyte4 len, vlong **ppRetVlong, vlong **ppVlongQueue)
{
    sbyte4  i;
    ubyte4  elem;
    MSTATUS status;

    if (OK > (status = VLONG_allocVlong(ppRetVlong, ppVlongQueue)))
        goto exit;

    if (OK > (status = VLONG_reallocVlong(*ppRetVlong, 1 + (len / sizeof(ubyte4)))))
        goto exit;

    for (i = 0; i < len; i += 4)
    {
        elem = byteString[i+3];
        elem = (elem << 8) | byteString[i+2];
        elem = (elem << 8) | byteString[i+1];
        elem = (elem << 8) | byteString[i+0];

        if (OK > (status = VLONG_setVlongUnit(*ppRetVlong, i / 4, elem)))
            goto exit;
    }

exit:
    return status;

}


/*------------------------------------------------------------------*/
/*
 * The length of *ppRet will always be nLen (the modulus)
 */
static MSTATUS
DoPKCryptCommonInner(hwAccelDescr hwAccelCtx,
                ubyte *pB, ubyte4 bLen, ubyte *pA, ubyte4 aLen,
                ubyte *pE, ubyte4 eLen, ubyte *pN, ubyte4 nLen,
                ubyte4 header, ubyte **ppRet)
{
    ubyte*              retBytes = NULL;
    SECChannelInfo*     pChInfo = &mChannels[hwAccelCtx];
    int                 result;
    MSTATUS             status = OK;

    if (NULL != ppRet)
    {
        if (NULL == (retBytes = MALLOC(nLen)))    /* same size as modulus */
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
        DIGI_MEMSET(retBytes, 0, nLen);
    }
    else
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (status = RTOS_mutexWait(pChInfo->chMutex)))
        goto exit;

    pChInfo->dpd.header   = header;

    pChInfo->dpd.length1  = bLen;
    pChInfo->dpd.pointer1 = pB;

    pChInfo->dpd.length2  = aLen;
    pChInfo->dpd.pointer2 = pA;
    pChInfo->dpd.length3  = eLen;
    pChInfo->dpd.pointer3 = pE;
    pChInfo->dpd.length4  = nLen;
    pChInfo->dpd.pointer4 = pN;
    pChInfo->dpd.length5  = nLen;
    pChInfo->dpd.pointer5 = retBytes;
    pChInfo->dpd.length6  = 0;
    pChInfo->dpd.pointer6 = NULL;

    pChInfo->dpd.length7  = 0;
    pChInfo->dpd.pointer7 = NULL;
    pChInfo->dpd.pNext    = NULL;

    pChInfo->startTime = RTOS_getUpTimeInMS();

    *(pChInfo->pFetch) = (ubyte4)(&pChInfo->dpd);

    while (((int)NOT_COMPLETE) == (result = fsl8248_DefaultCompletion(hwAccelCtx)))
    {
        if ((RTOS_getUpTimeInMS() - pChInfo->startTime) > FSL_SEC_SYNC_TIMEOUT_MS)
        {
            result = ERR_COMPLETE;
            break;
        }
    }

    if (OK > (status = RTOS_mutexRelease(pChInfo->chMutex)))
        goto exit;

    if (ERR_COMPLETE == result)
        status = ERR_HARDWARE_ACCEL_DO_CRYPTO;
    else
    {
        status = OK;
        *ppRet = retBytes;
        retBytes = NULL;
    }

    /* not sure the following is necessary if no interrupt service routine */
    fsl8248_clearSEC_ISR();

exit:
    if (NULL != retBytes)
        FREE(retBytes);

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
DoPKCryptCommon(hwAccelDescr hwAccelCtx,
                vlong *b, vlong *a, vlong *e, vlong *n, ubyte4 header,
                vlong **ppRet, vlong **ppVlongQueue)
{
    ubyte*              bBytes   = NULL;
    ubyte*              aBytes   = NULL;
    ubyte*              eBytes   = NULL;
    ubyte*              nBytes   = NULL;
    ubyte*              retBytes = NULL;
    SECChannelInfo*     pChInfo = &mChannels[hwAccelCtx];
    ubyte4              bNeeded, aNeeded, eNeeded, nNeeded;
    int                 result;
    MSTATUS             status = OK;

    bNeeded = aNeeded = eNeeded = nNeeded = 0;
    *ppRet = NULL;

    if (NULL != b)
        if (OK > (status = fsl8248_littleEndianByteStringFromVlong(b, &bBytes, &bNeeded)))
            goto exit;

    if (NULL != a)
        if (OK > (status = fsl8248_littleEndianByteStringFromVlong(a, &aBytes, &aNeeded)))
            goto exit;

    if (NULL != e)
        if (OK > (status = fsl8248_littleEndianByteStringFromVlong(e, &eBytes, &eNeeded)))
            goto exit;

    if (NULL != n)
        if (OK > (status = fsl8248_littleEndianByteStringFromVlong(n, &nBytes, &nNeeded)))
            goto exit;

#if 0
    if (OK > (status = DoPKCryptCommonInner(hwAccelCtx, bBytes, bNeeded, aBytes, aNeeded,
                                            eBytes, eNeeded, nBytes, nNeeded,
                                            header, &retBytes)))
    {
        goto exit;
    }
#endif

    if (NULL != ppRet)
    {
        if (NULL == (retBytes = MALLOC(nNeeded)))    /* same size as modulus */
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        DIGI_MEMSET(retBytes, 0, nNeeded);
    }

    if (OK > (status = RTOS_mutexWait(pChInfo->chMutex)))
        goto exit;

    pChInfo->dpd.header   = header;

    pChInfo->dpd.length1  = bNeeded;
    pChInfo->dpd.pointer1 = bBytes;

    pChInfo->dpd.length2  = aNeeded;
    pChInfo->dpd.pointer2 = aBytes;
    pChInfo->dpd.length3  = eNeeded;
    pChInfo->dpd.pointer3 = eBytes;
    pChInfo->dpd.length4  = nNeeded;
    pChInfo->dpd.pointer4 = nBytes;
    pChInfo->dpd.length5  = nNeeded;
    pChInfo->dpd.pointer5 = retBytes;
    pChInfo->dpd.length6  = 0;
    pChInfo->dpd.pointer6 = NULL;

    pChInfo->dpd.length7  = 0;
    pChInfo->dpd.pointer7 = NULL;
    pChInfo->dpd.pNext    = NULL;

    pChInfo->startTime    = RTOS_getUpTimeInMS();

    *(pChInfo->pFetch) = (ubyte4)(&pChInfo->dpd);

    while (((int)NOT_COMPLETE) == (result = fsl8248_DefaultCompletion(hwAccelCtx)))
    {
        if ((RTOS_getUpTimeInMS() - pChInfo->startTime) > FSL_SEC_SYNC_TIMEOUT_MS)
        {
            result = ERR_COMPLETE;
            break;
        }
    }

    if (OK > (status = RTOS_mutexRelease(pChInfo->chMutex)))
        goto exit;

    if (ERR_COMPLETE == result)
        status = ERR_HARDWARE_ACCEL_DO_CRYPTO;
    else
        status = OK;

    /* not sure the following is necessary if no interrupt service routine */
    fsl8248_clearSEC_ISR();

    if (NULL != ppRet)
        status = vlongFromLittleEndianByteString(retBytes, nNeeded, ppRet, ppVlongQueue);

exit:
    if (NULL != bBytes)
        FREE(bBytes);

    if (NULL != aBytes)
        FREE(aBytes);

    if (NULL != eBytes)
        FREE(eBytes);

    if (NULL != nBytes)
        FREE(nBytes);

    if (NULL != retBytes)
        FREE(retBytes);

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
convertToMontgomery(hwAccelDescr hwAccelCtx, ubyte *pX, ubyte4 xLen, ubyte *pM, ubyte4 mLen,ubyte **ppRetMontBasis)
{
    ubyte*  pR2ModN = NULL;
    ubyte*  pMontBasis = NULL;
    MSTATUS status;

    /* R2MODN */
    if (OK > (status = DoPKCryptCommonInner(hwAccelCtx, NULL, 0, NULL, 0,NULL, 0, pM, mLen,
                            DPD_HEADER_MOD_R2MODN, &pR2ModN)))
        goto exit;

    /* MULT1 */
    if (OK > (status = DoPKCryptCommonInner(hwAccelCtx, pR2ModN, mLen, pX, xLen,NULL, 0, pM, mLen,
                            DPD_HEADER_MODMULT1, &pMontBasis)))
        goto exit;

    *ppRetMontBasis = pMontBasis;
    pMontBasis = NULL;

exit:
    if (NULL != pR2ModN)    FREE(pR2ModN);
    if (NULL != pMontBasis) FREE(pMontBasis);

    return status;
}


/*------------------------------------------------------------------*/

#if 1
static MSTATUS
VLONG_convertToMontgomery(hwAccelDescr hwAccelCtx, const vlong* x, const vlong *m, vlong **ppRetMontBasis, vlong **ppVlongQueue)
{
    ubyte*  pX = NULL;
    ubyte*  pM = NULL;
    ubyte*  pRet = NULL;
    ubyte4  xLen;
    ubyte4  mLen;
    MSTATUS status;

    if (OK > (status = fsl8248_littleEndianByteStringFromVlong((vlong*)x, &pX, &xLen)))
        goto exit;
    if (OK > (status = fsl8248_littleEndianByteStringFromVlong((vlong*)m, &pM, &mLen)))
        goto exit;

    if (OK > (status = convertToMontgomery(hwAccelCtx, pX, xLen, pM, mLen, &pRet)))
        goto exit;

    if (OK > (status = vlongFromLittleEndianByteString(pRet, mLen, ppRetMontBasis, ppVlongQueue)))
        goto exit;

exit:
    if (NULL != pX)
        FREE(pX);

    if (NULL != pM)
        FREE(pM);

    if (NULL != pRet)
        FREE(pRet);

    return status;
}


#else
static MSTATUS
VLONG_convertToMontgomery(hwAccelDescr hwAccelCtx, const vlong* x, const vlong *m, vlong **ppRetMontBasis, vlong **ppVlongQueue)
{
    MSTATUS     status;
    vlong*      r2modN = NULL;

    if (OK > (status = VLONG_r2ModN(hwAccelCtx, m, &r2modN, ppVlongQueue)))
        goto exit;

    if (OK > (status = VLONG_ModMult1(hwAccelCtx, r2modN, x, m, ppRetMontBasis, ppVlongQueue)))
        goto exit;
exit:
    if (NULL != r2modN)
        VLONG_freeVlong(&r2modN, ppVlongQueue);

    return status;
}
#endif

/*------------------------------------------------------------------*/

#ifdef __VLONG_MOD_OPERATOR_HARDWARE_ACCELERATOR__
extern MSTATUS
VLONG_operatorModSignedVlongs(hwAccelDescr hwAccelCtx, const vlong* pDividend,
                              const vlong* pDivisor, vlong **ppRemainder, vlong **ppVlongQueue)
#if 1
{
    vlong*      one             = NULL;
    vlong*      oneMont         = NULL;
    vlong*      dividendMont    = NULL;
    MSTATUS     status;

    if (OK > (status = VLONG_makeVlongFromUnsignedValue(1, &one, ppVlongQueue)))
        goto exit;
    if (OK > (status = VLONG_convertToMontgomery(hwAccelCtx, one, pDivisor, &oneMont, ppVlongQueue)))
        goto exit;
    if (OK > (status = VLONG_convertToMontgomery(hwAccelCtx, pDividend, pDivisor, &dividendMont, ppVlongQueue)))
        goto exit;

    if (OK > (status = VLONG_ModMult2(hwAccelCtx, dividendMont, oneMont, pDivisor, ppRemainder, ppVlongQueue)))
        goto exit;

exit:
    if (NULL != one)
        VLONG_freeVlong(&one, ppVlongQueue);
    if (NULL != oneMont)
        VLONG_freeVlong(&oneMont, ppVlongQueue);
    if (NULL != dividendMont)
        VLONG_freeVlong(&dividendMont, ppVlongQueue);

    return status;
}
#else
{
    vlong*      one = NULL;
    vlong*      tmp = NULL;
    MSTATUS     status;

    if (OK > (status = VLONG_makeVlongFromUnsignedValue(1, &one, ppVlongQueue)))
        goto exit;

    if (OK > (status = VLONG_makeVlongFromVlong((vlong*)pDividend, &tmp, ppVlongQueue)))
        goto exit;

    if (OK > (status = VLONG_subtractSignedVlongs((vlong*)tmp, one, ppVlongQueue)))
        goto exit;

    if (OK > (status = VLONG_modAdd(hwAccelCtx, (vlong*)tmp, one, (vlong*)pDivisor, ppRemainder, ppVlongQueue)))
        goto exit;

exit:
    if (NULL != one)
        VLONG_freeVlong(&one, ppVlongQueue);

    if (NULL != tmp)
        VLONG_freeVlong(&tmp, ppVlongQueue);

    return status;
}
#endif

#endif /* __VLONG_MOD_OPERATOR_HARDWARE_ACCELERATOR__ */


/*------------------------------------------------------------------*/

#ifdef __VLONG_MULT_MOD_OPERATOR_HARDWARE_ACCELERATOR__
extern MSTATUS
VLONG_ModMult1(hwAccelDescr hwAccelCtx, const vlong* pA,
               const vlong* pB, const vlong* pN, vlong **ppRet, vlong **ppVlongQueue)
{
    MSTATUS status;

    if (OK > (status = DoPKCryptCommon(hwAccelCtx,
                                       (vlong*)pA, (vlong*)pB, NULL, (vlong*)pN, DPD_HEADER_MODMULT1,
                                       ppRet, ppVlongQueue)))
    {
        goto exit;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
VLONG_ModMult2(hwAccelDescr hwAccelCtx, const vlong* pA,
               const vlong* pB, const vlong* pN, vlong **ppRet, vlong **ppVlongQueue)
{
    MSTATUS status;

    if (OK > (status = DoPKCryptCommon(hwAccelCtx,
                                       (vlong*)pA, (vlong*)pB, NULL, (vlong*)pN, DPD_HEADER_MODMULT2,
                                       ppRet, ppVlongQueue)))
    {
        goto exit;
    }

exit:
    return status;
}
#endif /* __VLONG_MULT_MOD_OPERATOR_HARDWARE_ACCELERATOR__ */


/*------------------------------------------------------------------*/

#ifdef __VLONG_MODINV_OPERATOR_HARDWARE_ACCELERATOR__
extern MSTATUS
VLONG_modularInverse(hwAccelDescr hwAccelCtx, vlong *b, vlong *n, vlong **ppT, vlong **ppVlongQueue)
{
    *ppT = NULL;

    return DoPKCryptCommon(hwAccelCtx,
                           NULL, b, NULL, n, DPD_HEADER_MODINV,
                           ppT, ppVlongQueue);
}
#endif /* __VLONG_MODINV_OPERATOR_HARDWARE_ACCELERATOR__ */


/*------------------------------------------------------------------*/

#ifdef __VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__

#if 1
/* new way converts from vlong at beginning and to vlong at end only */
extern MSTATUS
VLONG_modexp(hwAccelDescr hwAccelCtx, vlong *x, vlong *e, vlong *m, vlong **ppRetModExp, vlong **ppVlongQueue)
{
    ubyte*  pX = NULL;
    ubyte*  pE = NULL;
    ubyte*  pM = NULL;
    ubyte*  pMontBasis = NULL;
    ubyte*  pRet = NULL;
    ubyte4  xLen;
    ubyte4  eLen;
    ubyte4  mLen;
#if 1
    vlong*  montBasis = NULL;
#endif
    MSTATUS status;

    if (OK > (status = fsl8248_littleEndianByteStringFromVlong((vlong*)x, &pX, &xLen)))
        goto exit;
    if (OK > (status = fsl8248_littleEndianByteStringFromVlong((vlong*)e, &pE, &eLen)))
        goto exit;
    if (OK > (status = fsl8248_littleEndianByteStringFromVlong((vlong*)m, &pM, &mLen)))
        goto exit;
#if 1   /* testing montgomery code */
    if (OK > (status = VLONG_convertToMontgomery(hwAccelCtx, x, m, &montBasis, ppVlongQueue)))
        goto exit;
#endif


    if (OK > (status = convertToMontgomery(hwAccelCtx, pX, xLen, pM, mLen, &pMontBasis)))
        goto exit;

    if (OK > (status = DoPKCryptCommonInner(hwAccelCtx, NULL, 0, pMontBasis, mLen, pE, eLen, pM, mLen,
                        DPD_HEADER_MODEXP, &pRet)))
        goto exit;

    if (OK > (status = vlongFromLittleEndianByteString(pRet, mLen, ppRetModExp, ppVlongQueue)))
        goto exit;

exit:
    if (NULL != pX) FREE(pX);
    if (NULL != pE) FREE(pE);
    if (NULL != pM) FREE(pM);
    if (NULL != pMontBasis) FREE(pMontBasis);
    if (NULL != pRet) FREE(pRet);

    return status;
}

#else
/* old way converts from and to vlongs for every SEC operation */
extern MSTATUS
VLONG_modexp(hwAccelDescr hwAccelCtx, vlong *x, vlong *e, vlong *m, vlong **ppRetModExp, vlong **ppVlongQueue)
{
    MSTATUS     status;
    vlong*      r2modN = NULL;
    vlong*      montBasis = NULL;

    if (OK > (status = VLONG_r2ModN(hwAccelCtx, m, &r2modN, ppVlongQueue)))
        goto exit;

    if (OK > (status = VLONG_ModMult1(hwAccelCtx, r2modN, x, m, &montBasis, ppVlongQueue)))
        goto exit;

    status = DoPKCryptCommon(hwAccelCtx, NULL,
                             montBasis, e, m, DPD_HEADER_MODEXP,
                             ppRetModExp, ppVlongQueue);

exit:
    if (NULL != r2modN)
        VLONG_freeVlong(&r2modN, ppVlongQueue);

    if (NULL != montBasis)
        VLONG_freeVlong(&montBasis, ppVlongQueue);

    return status;
}
#endif /* 1 */

#endif /* __VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__ */


/*------------------------------------------------------------------*/

#ifdef __VLONG_ADD_MOD_OPERATOR_HARDWARE_ACCELERATOR__

extern MSTATUS
VLONG_modAdd(hwAccelDescr hwAccelCtx, vlong *a, vlong *b, vlong *m, vlong **ppRet, vlong **ppVlongQueue)
{
    return DoPKCryptCommon(hwAccelCtx, a, b, NULL, m, DPD_HEADER_MOD_ADD,
                           ppRet, ppVlongQueue);

}

#endif /* __VLONG_ADD_MOD_OPERATOR_HARDWARE_ACCELERATOR__ */


/*------------------------------------------------------------------*/

#ifdef __VLONG_SUBTRACT_MOD_OPERATOR_HARDWARE_ACCELERATOR__

extern MSTATUS
VLONG_modSubtract(hwAccelDescr hwAccelCtx, vlong *a, vlong *b, vlong *m, vlong **ppRet, vlong **ppVlongQueue)
{
    return DoPKCryptCommon(hwAccelCtx, a, b, NULL, m, DPD_HEADER_MOD_SUBTRACT,
                           ppRet, ppVlongQueue);

}

#endif /* __VLONG_SUBTRACT_MOD_OPERATOR_HARDWARE_ACCELERATOR__ */


/*------------------------------------------------------------------*/

#ifdef __VLONG_R2MODN_OPERATOR_HARDWARE_ACCELERATOR__
extern MSTATUS
VLONG_r2ModN(hwAccelDescr hwAccelCtx, vlong *n, vlong **ppRet, vlong **ppVlongQueue)
{
    /* FUTURE: Looks like on SEC2 n moves to P2 (2nd arg of DoPKCryptCommon) */
    return DoPKCryptCommon(hwAccelCtx, NULL, NULL, NULL, n, DPD_HEADER_MOD_R2MODN,
                           ppRet, ppVlongQueue);

}
#endif /* __VLONG_SUBTRACT_MOD_OPERATOR_HARDWARE_ACCELERATOR__ */


/*------------------------------------------------------------------*/

extern MSTATUS
VLONG_pkClearMemory(hwAccelDescr hwAccelCtx)
{
    return DoPKCryptCommon(hwAccelCtx, NULL, NULL, NULL, NULL, DPD_HEADER_CLEAR_MEM,
                           NULL, NULL);

}

/*------------------------------------------------------------------*/
#ifdef __ENABLE_MW_PROFILER__
#pragma profile off
#endif
/*------------------------------------------------------------------*/


#endif /* (defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) && defined(__ENABLE_FREESCALE_8248_HARDWARE_ACCEL__)) */
