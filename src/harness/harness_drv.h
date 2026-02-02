/*
 * harness_drv.h
 *
 * Harness Block Device Driver Interface
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

#ifndef __HARNESS_DRV_HEADER__
#define __HARNESS_DRV_HEADER__

#ifdef __cplusplus /* XXX jun */
extern "C" {
#endif

typedef ubyte4 *PhysAddr_t;
typedef ubyte  *KernAddr_t;
typedef ubyte4 *UserAddr_t;

#define HW_IOCTL_START  8000          /* IOCTL range for device specific ops */
#define HW_IOCTL_END    9000


/*------------------------------------------------------------------*/

#if defined(__RTOS_WIN32__)
#define HARNESS_DRV_WRAPPER_mapKernelToPhysicalAddr(X)  (X)
#define HARNESS_DRV_WRAPPER_mapPhysicalToKernelAddr(X)  (X)

#elif defined(__RTOS_VXWORKS__)

/* definitions */
#define __DIGICERT_ENABLE_HARNESS_RTOS_TIMER__

#define HARNESS_DRV_WRAPPER_mapKernelToPhysicalAddr(X)  (X)
#define HARNESS_DRV_WRAPPER_mapPhysicalToKernelAddr(X)  (X)

/* lookups */
#define HARNESS_DRV_WRAPPER_signalCompletion            HARNESS_DRVVXW_signalCompletion

#define HARNESS_DRV_WRAPPER_readIO16(ADDR,RET1)         HARNESS_DRVVXW_readIO16((ubyte2 *)((ADDR)),(RET1))
#define HARNESS_DRV_WRAPPER_orIO16(ADDR,BITS1)          HARNESS_DRVVXW_orIO16((ubyte2 *)((ADDR)),(BITS1))
#define HARNESS_DRV_WRAPPER_writeIO16(ADDR,VAL1)        HARNESS_DRVVXW_writeIO16((ubyte2 *)((ADDR)),(VAL1))

#define HARNESS_DRV_WRAPPER_readIO32(ADDR,RET1)         HARNESS_DRVVXW_readIO32((ubyte4 *)((ADDR)),(RET1))
#define HARNESS_DRV_WRAPPER_orIO32(ADDR,BITS1)          HARNESS_DRVVXW_orIO32((ubyte4 *)((ADDR)),(BITS1))
#define HARNESS_DRV_WRAPPER_writeIO32(ADDR,VAL1)        HARNESS_DRVVXW_writeIO32((ubyte4 *)((ADDR)),(VAL1))

#define HARNESS_DRV_WRAPPER_readIO64(ADDR,RET1,RET2)    HARNESS_DRVVXW_readIO64((ubyte4 *)((ADDR)),(RET1),(RET2))
#define HARNESS_DRV_WRAPPER_orIO64(ADDR,BITS1,BITS2)    HARNESS_DRVVXW_orIO64((ubyte4 *)((ADDR)),(BITS1),(BITS2))
#define HARNESS_DRV_WRAPPER_writeIO64(ADDR,VAL1,VAL2)   HARNESS_DRVVXW_writeIO64((ubyte4 *)((ADDR)),(VAL1),(VAL2))

/* prototypes */
MOC_EXTERN void  HARNESS_DRVVXW_readIO16 (ubyte2 *pReadAddress,  ubyte2 *pRetBits16);
MOC_EXTERN void  HARNESS_DRVVXW_orIO16   (ubyte2 *pOrAddress,    ubyte2 bits16);
MOC_EXTERN void  HARNESS_DRVVXW_writeIO16(ubyte2 *pWriteAddress, ubyte2 val16);

MOC_EXTERN void  HARNESS_DRVVXW_readIO32 (ubyte4 *pReadAddress,  ubyte4 *pRetBits32);
MOC_EXTERN void  HARNESS_DRVVXW_orIO32   (ubyte4 *pOrAddress,    ubyte4 bits32);
MOC_EXTERN void  HARNESS_DRVVXW_writeIO32(ubyte4 *pWriteAddress, ubyte4 val32);

MOC_EXTERN void  HARNESS_DRVVXW_readIO64 (ubyte4* pReadAddress,  ubyte4* pRetLo32,  ubyte4* pRetHi32);
MOC_EXTERN void  HARNESS_DRVVXW_orIO64   (ubyte4* pOrAddress,    ubyte4  loBits32,  ubyte4  hiBits32);
MOC_EXTERN void  HARNESS_DRVVXW_writeIO64(ubyte4* pWriteAddress, ubyte4  loVal32,   ubyte4  hiVal32);

#elif defined(__RTOS_LINUX__)

/* definitions */
#define __DIGICERT_ENABLE_HARNESS_RTOS_TIMER__
#define HARNESS_NAME                                    "moc_harness"

/* lookups */
#define HARNESS_DRV_WRAPPER_armTimer                    HARNESS_DRV26_armTimer
#define HARNESS_DRV_WRAPPER_mapKernelToPhysicalAddr     HARNESS_DRV26_mapKernelToPhysicalAddr
#define HARNESS_DRV_WRAPPER_mapPhysicalToKernelAddr     HARNESS_DRV26_mapPhysicalToKernelAddr

#define HARNESS_DRV_WRAPPER_signalCompletion            HARNESS_DRV26_signalCompletion

#define HARNESS_DRV_WRAPPER_readIO16(ADDR,RET1)         HARNESS_DRV26_readIO16((ubyte2 *)((ADDR)),(RET1))
#define HARNESS_DRV_WRAPPER_orIO16(ADDR,BITS1)          HARNESS_DRV26_orIO16((ubyte2 *)((ADDR)),(BITS1))
#define HARNESS_DRV_WRAPPER_writeIO16(ADDR,VAL1)        HARNESS_DRV26_writeIO16((ubyte2 *)((ADDR)),(VAL1))

#define HARNESS_DRV_WRAPPER_readIO32(ADDR,RET1)         HARNESS_DRV26_readIO32((ubyte4 *)((ADDR)),(RET1))
#define HARNESS_DRV_WRAPPER_orIO32(ADDR,BITS1)          HARNESS_DRV26_orIO32((ubyte4 *)((ADDR)),(BITS1))
#define HARNESS_DRV_WRAPPER_writeIO32(ADDR,VAL1)        HARNESS_DRV26_writeIO32((ubyte4 *)((ADDR)),(VAL1))

#define HARNESS_DRV_WRAPPER_readIO64(ADDR,RET1,RET2)    HARNESS_DRV26_readIO64((ubyte4 *)((ADDR)),(RET1),(RET2))
#define HARNESS_DRV_WRAPPER_orIO64(ADDR,BITS1,BITS2)    HARNESS_DRV26_orIO64((ubyte4 *)((ADDR)),(BITS1),(BITS2))
#define HARNESS_DRV_WRAPPER_writeIO64(ADDR,VAL1,VAL2)   HARNESS_DRV26_writeIO64((ubyte4 *)((ADDR)),(VAL1),(VAL2))
#define HARNESS_DRV_WRAPPER_getSECBASE()        HARNESS_DRV26_getSECBASE()

/* prototypes */
MOC_EXTERN void  HARNESS_DRV26_readIO16 (ubyte2 *pReadAddress,  ubyte2 *pRetBits16);
MOC_EXTERN void  HARNESS_DRV26_orIO16   (ubyte2 *pOrAddress,    ubyte2 bits16);
MOC_EXTERN void  HARNESS_DRV26_writeIO16(ubyte2 *pWriteAddress, ubyte2 val16);

MOC_EXTERN void  HARNESS_DRV26_readIO32 (ubyte4 *pReadAddress,  ubyte4 *pRetBits32);
MOC_EXTERN void  HARNESS_DRV26_orIO32   (ubyte4 *pOrAddress,    ubyte4 bits32);
MOC_EXTERN void  HARNESS_DRV26_writeIO32(ubyte4 *pWriteAddress, ubyte4 val32);

MOC_EXTERN void  HARNESS_DRV26_readIO64 (ubyte4* pReadAddress,  ubyte4* pRetLo32,  ubyte4* pRetHi32);
MOC_EXTERN void  HARNESS_DRV26_orIO64   (ubyte4* pOrAddress,    ubyte4  loBits32,  ubyte4  hiBits32);
MOC_EXTERN void  HARNESS_DRV26_writeIO64(ubyte4* pWriteAddress, ubyte4  loVal32,   ubyte4  hiVal32);

MOC_EXTERN void* HARNESS_DRV26_mapKernelToPhysicalAddr(void*);
MOC_EXTERN void* HARNESS_DRV26_armTimer(void);
MOC_EXTERN sbyte4 HARNESS_DRV_registerDoWork(void (*funcDoWork)(void *));
MOC_EXTERN void* HARNESS_DRV26_mapPhysicalToKernelAddr(void*);

MOC_EXTERN void  HARNESS_DRV26_signalCompletion(struct mahChannelPair *pChannelDescr, sbyte4 index);

#elif defined(__RTOS_QNX__)

/* definitions */
#define HARNESS_NAME                                    "moc_harness"
#define __DIGICERT_ENABLE_HARNESS_RTOS_TIMER__

/* lookups */
#define HARNESS_DRV_WRAPPER_mapKernelToPhysicalAddr     HARNESS_DRVQNX_mapKernelToPhysicalAddr
#define HARNESS_DRV_WRAPPER_mapPhysicalToKernelAddr     HARNESS_DRVQNX_mapPhysicalToKernelAddr

#define HARNESS_DRV_WRAPPER_signalCompletion            HARNESS_DRVQNX_signalCompletion

#define HARNESS_DRV_WRAPPER_readIO16(ADDR,RET1)         HARNESS_DRVQNX_readIO16((ubyte2 *)((ADDR)),(RET1))
#define HARNESS_DRV_WRAPPER_orIO16(ADDR,BITS1)          HARNESS_DRVQNX_orIO16((ubyte2 *)((ADDR)),(BITS1))
#define HARNESS_DRV_WRAPPER_writeIO16(ADDR,VAL1)        HARNESS_DRVQNX_writeIO16((ubyte2 *)((ADDR)),(VAL1))

#define HARNESS_DRV_WRAPPER_readIO32(ADDR,RET1)         HARNESS_DRVQNX_readIO32((ubyte4 *)((ADDR)),(RET1))
#define HARNESS_DRV_WRAPPER_orIO32(ADDR,BITS1)          HARNESS_DRVQNX_orIO32((ubyte4 *)((ADDR)),(BITS1))
#define HARNESS_DRV_WRAPPER_writeIO32(ADDR,VAL1)        HARNESS_DRVQNX_writeIO32((ubyte4 *)((ADDR)),(VAL1))

#define HARNESS_DRV_WRAPPER_readIO64(ADDR,RET1,RET2)    HARNESS_DRVQNX_readIO64((ubyte4 *)((ADDR)),(RET1),(RET2))
#define HARNESS_DRV_WRAPPER_orIO64(ADDR,BITS1,BITS2)    HARNESS_DRVQNX_orIO64((ubyte4 *)((ADDR)),(BITS1),(BITS2))
#define HARNESS_DRV_WRAPPER_writeIO64(ADDR,VAL1,VAL2)   HARNESS_DRVQNX_writeIO64((ubyte4 *)((ADDR)),(VAL1),(VAL2))

/* prototypes */
MOC_EXTERN void  HARNESS_DRVQNX_readIO16 (ubyte2 *pReadAddress,  ubyte2 *pRetBits16);
MOC_EXTERN void  HARNESS_DRVQNX_orIO16   (ubyte2 *pOrAddress,    ubyte2 bits16);
MOC_EXTERN void  HARNESS_DRVQNX_writeIO16(ubyte2 *pWriteAddress, ubyte2 val16);

MOC_EXTERN void  HARNESS_DRVQNX_readIO32 (ubyte4 *pReadAddress,  ubyte4 *pRetBits32);
MOC_EXTERN void  HARNESS_DRVQNX_orIO32   (ubyte4 *pOrAddress,    ubyte4 bits32);
MOC_EXTERN void  HARNESS_DRVQNX_writeIO32(ubyte4 *pWriteAddress, ubyte4 val32);

MOC_EXTERN void  HARNESS_DRVQNX_readIO64 (ubyte4* pReadAddress,  ubyte4* pRetLo32,  ubyte4* pRetHi32);
MOC_EXTERN void  HARNESS_DRVQNX_orIO64   (ubyte4* pOrAddress,    ubyte4  loBits32,  ubyte4  hiBits32);
MOC_EXTERN void  HARNESS_DRVQNX_writeIO64(ubyte4* pWriteAddress, ubyte4  loVal32,   ubyte4  hiVal32);

MOC_EXTERN void* HARNESS_DRVQNX_mapKernelToPhysicalAddr(void*);
MOC_EXTERN void* HARNESS_DRVQNX_mapPhysicalToKernelAddr(void*);

#elif defined(__RTOS_OSE__)

/* definitions */
#define __DIGICERT_ENABLE_HARNESS_RTOS_TIMER__
#define HARNESS_DRV_WRAPPER_mapKernelToPhysicalAddr        HARNESS_DRVOSE_mapKernelToPhysicalAddr

#define HARNESS_DRV_WRAPPER_mapPhysicalToKernelAddr    HARNESS_DRVOSE_mapPhysicalToKernelAddr

/* lookups */
#define HARNESS_DRV_WRAPPER_signalCompletion            HARNESS_DRVOSE_signalCompletion

#define HARNESS_DRV_WRAPPER_readIO16(ADDR,RET1)         HARNESS_DRVOSE_readIO16((ubyte2 *)((ADDR)),(RET1))
#define HARNESS_DRV_WRAPPER_orIO16(ADDR,BITS1)          HARNESS_DRVOSE_orIO16((ubyte2 *)((ADDR)),(BITS1))
#define HARNESS_DRV_WRAPPER_writeIO16(ADDR,VAL1)        HARNESS_DRVOSE_writeIO16((ubyte2 *)((ADDR)),(VAL1))

#define HARNESS_DRV_WRAPPER_readIO32(ADDR,RET1)         HARNESS_DRVOSE_readIO32((ubyte4 *)((ADDR)),(RET1))
#define HARNESS_DRV_WRAPPER_orIO32(ADDR,BITS1)          HARNESS_DRVOSE_orIO32((ubyte4 *)((ADDR)),(BITS1))
#define HARNESS_DRV_WRAPPER_writeIO32(ADDR,VAL1)        HARNESS_DRVOSE_writeIO32((ubyte4 *)((ADDR)),(VAL1))

#define HARNESS_DRV_WRAPPER_readIO64(ADDR,RET1,RET2)    HARNESS_DRVOSE_readIO64((ubyte4 *)((ADDR)),(RET1),(RET2))
#define HARNESS_DRV_WRAPPER_orIO64(ADDR,BITS1,BITS2)    HARNESS_DRVOSE_orIO64((ubyte4 *)((ADDR)),(BITS1),(BITS2))
#define HARNESS_DRV_WRAPPER_writeIO64(ADDR,VAL1,VAL2)   HARNESS_DRVOSE_writeIO64((ubyte4 *)((ADDR)),(VAL1),(VAL2))

/* prototypes */
MOC_EXTERN void  HARNESS_DRVOSE_readIO16 (ubyte2 *pReadAddress,  ubyte2 *pRetBits16);
MOC_EXTERN void  HARNESS_DRVOSE_orIO16   (ubyte2 *pOrAddress,    ubyte2 bits16);
MOC_EXTERN void  HARNESS_DRVOSE_writeIO16(ubyte2 *pWriteAddress, ubyte2 val16);

MOC_EXTERN void  HARNESS_DRVOSE_readIO32 (ubyte4 *pReadAddress,  ubyte4 *pRetBits32);
MOC_EXTERN void  HARNESS_DRVOSE_orIO32   (ubyte4 *pOrAddress,    ubyte4 bits32);
MOC_EXTERN void  HARNESS_DRVOSE_writeIO32(ubyte4 *pWriteAddress, ubyte4 val32);

MOC_EXTERN void  HARNESS_DRVOSE_readIO64 (ubyte4* pReadAddress,  ubyte4* pRetLo32,  ubyte4* pRetHi32);
MOC_EXTERN void  HARNESS_DRVOSE_orIO64   (ubyte4* pOrAddress,    ubyte4  loBits32,  ubyte4  hiBits32);
MOC_EXTERN void  HARNESS_DRVOSE_writeIO64(ubyte4* pWriteAddress, ubyte4  loVal32,   ubyte4  hiVal32);

#endif

MOC_EXTERN void(*funcDoWork)(void * /* pDoWorkCtx */);

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS HARNESS_DRV_init(void);

MOC_EXTERN MSTATUS    HARNESS_DRV_registerChannel(struct mahChannelPair *pChannelDescr);
MOC_EXTERN MSTATUS    HARNESS_DRV_unregisterChannel(struct mahChannelPair *pChannelDescr);
MOC_EXTERN sbyte4     HARNESS_DRV_findChannelIndex(struct mahChannelPair *pChannelDescr);

MOC_EXTERN MSTATUS    HARNESS_DRV_getSouthChannelHead(southBoundCircBufDescr* pSouthChannel, mahCellDescr **ppRetCell);
MOC_EXTERN MSTATUS    HARNESS_DRV_incrementSouthChannelHead(southBoundCircBufDescr* pSouthChannel);
MOC_EXTERN MSTATUS    HARNESS_DRV_incrementSouthChannelReserveHead(southBoundCircBufDescr* pSouthChannel);
MOC_EXTERN intBoolean HARNESS_DRV_dispatchSouthboundRequests(void);
MOC_EXTERN ubyte4     HARNESS_DRV_numberSouthboundRequests(void);
MOC_EXTERN void       HARNESS_DRV_callAsyncCallback(void);

MOC_EXTERN MSTATUS    HARNESS_DRV_reserveNorth(northBoundCircBufDescr* pNorthChannel, mahCompletionDescr **ppRetCell);
MOC_EXTERN MSTATUS    HARNESS_DRV_unreserveNorth(northBoundCircBufDescr* pNorthChannel);
MOC_EXTERN MSTATUS    HARNESS_DRV_activateNorthTail(northBoundCircBufDescr* pNorthChannel);

MOC_EXTERN void*      HDOS_kernelAlloc(hwAccelDescr hwAccelCtx, int size);
MOC_EXTERN void       HDOS_kernelFree(hwAccelDescr hwAccelCtx, void *block);

#ifdef __cplusplus /* XXX jun */
}
#endif

#endif /* __HARNESS_DRV_HEADER__ */

