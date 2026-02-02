/*
 * harness.h
 *
 * Mocana Acceleration Harness
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

#ifndef __HARNESS_HEADER__
#define __HARNESS_HEADER__

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_HARNESS__
#define CRYPTO_ALLOC(HW_ACCEL,SIZE,IS_CRYPTO,BUF_PTR_PTR)   HARNESS_kernelAlloc(HW_ACCEL, SIZE, IS_CRYPTO, (void **)(BUF_PTR_PTR))
#define CRYPTO_FREE(HW_ACCEL,IS_CRYPTO,BUF_PTR_PTR)         HARNESS_kernelFree(HW_ACCEL, IS_CRYPTO, (void **)(BUF_PTR_PTR))
#define CRYPTO_DEBUG_RELABEL_MEMORY(PTR)
#else
#define CRYPTO_ALLOC(HW_ACCEL,SIZE,IS_CRYPTO,BUF_PTR_PTR)   DIGI_MALLOC((void **)BUF_PTR_PTR, SIZE)
#define CRYPTO_FREE(HW_ACCEL,IS_CRYPTO,BUF_PTR_PTR)         DIGI_FREE((void **)BUF_PTR_PTR)
#ifdef __ENABLE_DIGICERT_DEBUG_MEMORY__
#define CRYPTO_DEBUG_RELABEL_MEMORY(PTR)                    dbg_relabel_memory(PTR,(ubyte *)__FILE__,__LINE__)
#else
#define CRYPTO_DEBUG_RELABEL_MEMORY(PTR)
#endif
#endif

#ifndef HARNESS_MAX_CHANNELS
#define HARNESS_MAX_CHANNELS    (20)
#endif


/*------------------------------------------------------------------*/

typedef struct mahCellDescr {
#ifdef __ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__
    MAH_CUSTOM_HARDWARE_ACCEL_STRUCTURE
#endif

    void*                   pSecurityStackCtx;
    struct mahChannelPair*  pChannelPair;
    struct mahCellDescr*    pNext;
} mahCellDescr;

typedef struct mahCompletionDescr {
    void*                   pSecurityStackCtx;
    MSTATUS                 hwAccelError;

} mahCompletionDescr;

typedef struct northBoundCircBufDescr {
    ubyte4                  head;
    ubyte4                  activeTail;
    ubyte4                  reserveTail;
    ubyte4                  channelDepthMask;               /* circular buf size ((2^n)-1, where n > 0) */

    mahCompletionDescr*     pMahCompletionCircBuf;          /* a pointer to an array of mahCompletionDescr */
    mahCompletionDescr*     pKernelMahCompletionCircBuf;    /* same but kernel space pointer */
    mahCompletionDescr*     pPhysicalMahCompletionCircBuf;  /* same but physical address pointer */

} northBoundCircBufDescr;

typedef struct southBoundCircBufDescr {
    ubyte4                  activeHead;
    ubyte4                  reserveHead;
    ubyte4                  activeTail;
    ubyte4                  reserveTail;
    ubyte4                  channelDepthMask;               /* circular buf size ((2^n)-1, where n > 0) */

    mahCellDescr*           pMahCircBuf;                    /* a pointer to an array of mahCellDescr */
    mahCellDescr*           pKernelMahCircBuf;              /* same but kernel space pointer */
    mahCellDescr*           pPhysicalMahCircBuf;            /* same but physical address pointer */

} southBoundCircBufDescr;

typedef struct mahChannelPair
{
    intBoolean              isAsyncModeEnabled;             /* should crypto jobs be handled asynchronously? */
    void*                   pSecurityStackCtx;              /* async ctx set by caller */

    /* for callback when channel's north has work completion notices */
    void(*funcCallback)(void * /* pCallbackCtx */);
    void*                   pCallbackCtx;
    void(*funcDoWork)(void * /* pDoWorkCtx */);
    void*                   pDoWorkCtx;

    northBoundCircBufDescr  northChannel;                   /* response from the hardware accelerator */
    southBoundCircBufDescr  southChannel;                   /* request to the hardware accelerator */

    void*                   pChannelContext;                /* platform specific thingy */

} mahChannelPair;


/*------------------------------------------------------------------*/

#ifndef DBUG_NO_HARNESS
MOC_EXTERN MSTATUS HARNESS_init(void);
MOC_EXTERN MSTATUS HARNESS_uninit(void);

MOC_EXTERN MSTATUS HARNESS_getNorthChannelHead(hwAccelDescr hwAccelCtx, mahCompletionDescr **ppRetCell);
MOC_EXTERN MSTATUS HARNESS_incrementNorthChannelHead(hwAccelDescr hwAccelCtx);

MOC_EXTERN MSTATUS HARNESS_reserveSouth(hwAccelDescr hwAccelCtx, mahCellDescr **ppRetCell);
MOC_EXTERN MSTATUS HARNESS_unreserveSouth(hwAccelDescr hwAccelCtx);
MOC_EXTERN MSTATUS HARNESS_activateSouthTail(hwAccelDescr hwAccelCtx);

MOC_EXTERN MSTATUS HARNESS_openChannel(enum moduleNames moduleId, hwAccelDescr *pRetChannelCookie, ubyte4 northChannelDepth, ubyte4 southChannelDepth);
MOC_EXTERN MSTATUS HARNESS_closeChannel(enum moduleNames moduleId, hwAccelDescr *pHwAccelCookie);

MOC_EXTERN MSTATUS HARNESS_kernelAlloc(hwAccelDescr hwAccelCtx, ubyte4 memBlockSize, intBoolean isCryptoBuf, void **ppRetMemBlock);
MOC_EXTERN MSTATUS HARNESS_kernelFree(hwAccelDescr hwAccelCtx, intBoolean isCryptoBuf, void **ppFreeMemBlock);

MOC_EXTERN MSTATUS HARNESS_mapAllocToKernel(hwAccelDescr hwAccelCtx, void *pBlock, void **ppRetKernelMemBlock);
MOC_EXTERN MSTATUS HARNESS_mapAllocToPhysical(hwAccelDescr hwAccelCtx, void *pBlock, void **ppRetPhysicalMemBlock);
#endif

#ifdef __ENABLE_DIGICERT_HARNESS_MEMORY_DEBUG__
MOC_EXTERN MSTATUS HARNESS_testAddress(hwAccelDescr hwAccelCtx, void *pBlock);
#endif

/* async mode APIs */
MOC_EXTERN void HARNESS_enableAsyncMode(hwAccelDescr hwAccelCtx);
MOC_EXTERN intBoolean HARNESS_isAsyncModeEnabled(hwAccelDescr hwAccelCtx, void **ppRetSecurityStackCtx);
MOC_EXTERN void HARNESS_assignAsyncCtx(hwAccelDescr hwAccelCtx, void *pSecurityStackCtx);

MOC_EXTERN void HARNESS_assignCallbackCtx(hwAccelDescr hwAccelCtx, void *pCallbackCtx);
MOC_EXTERN void HARNESS_assignAsyncCallback(hwAccelDescr hwAccelCtx, void (*funcCallback)(void *pCallbackCtx));

MOC_EXTERN void HARNESS_doWork(hwAccelDescr hwAccelCtx);

#endif /* __HARNESS_HEADER__ */
