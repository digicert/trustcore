/*
 * freescale_sync_875.c
 *
 * Freescale 875 Hardware Acceleration Synchronous Adapter
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

#if (defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) && defined(__ENABLE_FREESCALE_875_HARDWARE_ACCEL__))

#include "../../common/mtypes.h"
#include "../../common/mocana.h"
#include "../../common/merrors.h"
#include "../../common/mdefs.h"
#include "../../crypto/hw_accel.h"
#include "../../common/mrtos.h"
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
#include "../../crypto/hw_offload/freescale_sync_875.h"


/*------------------------------------------------------------------*/

#define MOCANA_NONE             (-1)
#define NOT_COMPLETE            0
#define GOOD_COMPLETE           1
#define ERR_COMPLETE            (-1)


/*------------------------------------------------------------------*/

typedef struct
{
    sbyte4      encrypt;                        /* Key used for encrypting or decrypting? */
    ubyte       key[256/*KEY_SIZE_256*/];       /* raw key in this case */
    sbyte4      keyLength;                      /* Length of the key (in bytes) */

} fslCipherContext;

typedef struct
{
    MAH_CUSTOM_HARDWARE_ACCEL_STRUCTURE

}   SECDataPacketDescriptor;

typedef struct
{
    SECDataPacketDescriptor     dpd;
    enum moduleNames            assignedModule;
    volatile ubyte4*            pFetch;
    ubyte4                      timeoutMS;
    RTOS_MUTEX                  chMutex;

}   SECChannelInfo;

static  SECChannelInfo          mChannels[SEC_CHANNEL_COUNT];

#define CH_ID_TO_INDEX(i)       ((i)-1)
#define CH_INDEX_TO_ID(i)       ((i)+1)
#define CH_INDEX_TO_DPD_PTR(i)  &(mChannels[i].dpd)


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
FSL875_ChIndexToISRDoneMask(int index, ubyte4 *pMask)
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
FSL875_ChIndexToISRErrorMask(sbyte4 index, ubyte4 *pMask)
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
fsl875_clearSEC_ISR(void)
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
fsl875_DefaultCompletion(hwAccelDescr hwAccelCookie)
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
    if (OK > FSL875_ChIndexToISRErrorMask(hwAccelCookie, &errMask))
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
fsl875_initSECChannels(void)
{
    int                 i;
    ubyte*              pChBase;
    volatile ubyte4*    pCCCR_2;
    MSTATUS             status = OK;

    for (i = 0; i < SEC_CHANNEL_COUNT; i++)
    {
        if (OK > (status = DIGI_MEMSET((ubyte*)&mChannels[i], 0, sizeof(mChannels[i]))))
            goto exit;

        mChannels[i].assignedModule = MOCANA_NONE;
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
fsl875_assignChannel(enum moduleNames module, sbyte4 *pIndex)
{
    /* semaphore for exclusive access so everybody gets in */
    *pIndex = module;
    return OK;
}


/*------------------------------------------------------------------*/

static MSTATUS
fsl875_unassignChannel(enum moduleNames module)
{
    MOC_UNUSED(module);

    return OK;
}


/*------------------------------------------------------------------*/

/*
 * The support routines that follow need to move. The asm routines,
 * particularly, may not compile in other IDEs.
 */

/*------------------------------------------------------------------*/

#if defined(__ENABLE_MW_ASM__)
extern void
FSL875_SetEEInterrupt(intBoolean enable)
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


/*------------------------------------------------------------------*/

asm ubyte4   SEC_getIMMR(void)
{
    mfspr       r3, IMMR;
}


/*------------------------------------------------------------------*/

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


/*------------------------------------------------------------------*/

ubyte*   SEC_getSECBaseAddress(void)
{
    ubyte *pSECBase = (unsigned char*)((SEC_getIMMR() & IMMR_MASK_875) + 0x00020000 );

    return (ubyte*)pSECBase;
}

#else /* defined(__ENABLE_MW_ASM__) */

#error YOU MUST DEFINE THIS SOMEHOW. YOU CANNOT GET THIS VALUE FROM C CODE

ubyte*   SEC_getSECBaseAddress(void)
{
    return (ubyte*)(-1);
}
#endif /* defined(__ENABLE_MW_ASM__) */

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

#if NEVER
extern void
FSL875_SIU_SECCoprocessorEnable(intBoolean enable)
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
#endif

/*------------------------------------------------------------------*/

extern sbyte4
FSL875_init(void)
{
    MSTATUS status = OK;

    fsl875_initSECChannels();

    return (sbyte4)status;
}


/*------------------------------------------------------------------*/

extern void
FSL875_SetSECInterrupt(intBoolean enable)
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


/*------------------------------------------------------------------*/

extern ubyte4   FSL875_SetSEC_IMR_1(ubyte4 val)
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

extern sbyte4
FSL875_uninit(void)
{
    return (sbyte4)OK;
}

/*------------------------------------------------------------------*/

#ifdef __ENABLE_MW_PROFILER__
#pragma profile on
#endif


/*------------------------------------------------------------------*/


extern sbyte4
FSL875_openChannel(enum moduleNames moduleId, sbyte4 *pHwAccelCookie)
{
    static int      created = FALSE;
    MSTATUS         status;

    *pHwAccelCookie = -1;   /* bad id */

    status =  fsl875_assignChannel(moduleId, pHwAccelCookie);

    return (sbyte4)status;
}


/*------------------------------------------------------------------*/

extern sbyte4
FSL875_closeChannel(enum moduleNames moduleId, sbyte4 *pHwAccelCookie)
{
    MSTATUS status;

    status = fsl875_unassignChannel(moduleId);
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

    pChInfo->timeoutMS = RTOS_getUpTimeInMS();

    *(pChInfo->pFetch) = (volatile ubyte4)&pChInfo->dpd;

    while (((int)NOT_COMPLETE) == (result = fsl875_DefaultCompletion(hwAccelCtx)))
    {
        if ((RTOS_getUpTimeInMS() - pChInfo->timeoutMS) > FSL_SEC_SYNC_TIMEOUT_MS)
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
    fsl875_clearSEC_ISR();

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

    if (0 != (dataLength & 0x7))
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

#ifdef __HMAC_MD5_HARDWARE_HASH__
extern MSTATUS
HMAC_MD5(hwAccelDescr hwAccelCtx, ubyte* key, sbyte4 keyLen, ubyte* text, sbyte4 textLen,
         ubyte* textOpt, sbyte4 textOptLen, ubyte result[MD5_DIGESTSIZE])
{
    ubyte*      pText;

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
        (pText) = text;
    else if (NULL == ((pText) = MALLOC((ubyte4)(textLen + textOptLen)))) {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMCPY((pText), text, textLen);
    DIGI_MEMCPY((pText) + textLen, textOpt, textOptLen);

    /* if key is longer than HMAC_BLOCK_SIZE bytes reset it to key=MD5(key) */
    if (keyLen > HMAC_BLOCK_SIZE)
    {
        if (OK > (status = (DoCryptCommon(hwAccelCtx, NULL, 0, NULL, 0,
                                         key, keyLen, NULL, 0, key, MD5_DIGESTSIZE,
                                         DPD_HEADER_MD_MD5_HASH_COMPLETE))))
            goto exit;

        keyLen = MD5_DIGESTSIZE;
    }

    if (OK > (status = (DoCryptCommon(hwAccelCtx, NULL, 0, key, keyLen,
                                     (pText), textLen + textOptLen, NULL, 0, result, MD5_DIGESTSIZE,
                                     DPD_HEADER_MD_MD5_HMAC_COMPLETE))))
        goto exit;

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
    else if (NULL == ((pText) = MALLOC((ubyte4)(textLen + textOptLen))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMCPY((pText), text, textLen);
    DIGI_MEMCPY((pText) + textLen, textOpt, textOptLen);

    /* if key is longer than HMAC_BLOCK_SIZE bytes reset it to key=MD5(key) */
    if (keyLen > HMAC_BLOCK_SIZE)
    {
        if (OK > (status = (DoCryptCommon(hwAccelCtx, NULL, 0, NULL, 0,
                                         key, keyLen, NULL, 0, key, SHA_HASH_RESULT_SIZE,
                                         DPD_HEADER_MD_SHA1_HASH_COMPLETE))))
            goto exit;

        keyLen = MD5_DIGESTSIZE;
    }

    if (OK > (status = (DoCryptCommon(hwAccelCtx, NULL, 0, key, keyLen,
                                     (pText), textLen + textOptLen, NULL, 0, result, SHA_HASH_RESULT_SIZE,
                                     DPD_HEADER_MD_SHA1_HMAC_COMPLETE))))
        goto exit;

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
                   ubyte4 dataLen, ubyte *pShaOutput)
{
    MSTATUS     status;

    if (OK > (status = (DoCryptCommon(hwAccelCtx, NULL, 0, NULL, 0,
                                     pData, dataLen, NULL, 0, pShaOutput, MD5_DIGESTSIZE,
                                     DPD_HEADER_MD_MD5_HASH_COMPLETE))))
        goto exit;

exit:
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

    status = DoCryptCommon(hwAccelCtx, NULL, 0, NULL, 0,
                           pData, dataLen, NULL, 0, pShaOutput, SHA_HASH_RESULT_SIZE,
                           DPD_HEADER_MD_SHA1_HASH_COMPLETE);

    return status;
}
#endif


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
#ifdef __ENABLE_MW_PROFILER__
#pragma profile off
#endif
/*------------------------------------------------------------------*/


#endif /* (defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) && defined(__ENABLE_FREESCALE_875_HARDWARE_ACCEL__)) */
