/*
 * harness_intf.h
 *
 * Mocana Acceleration Harness Interface
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

#ifndef __HARNESS_INTF_HEADER__
#define __HARNESS_INTF_HEADER__

/*------------------------------------------------------------------*/

#if defined(__DUMMY_HARNESS_INTF__)
#define HARNESS_WRAPPER_init                HARNESS_INTF_DUMMY_init
#define HARNESS_WRAPPER_openChannel         HARNESS_INTF_DUMMY_openChannel
#define HARNESS_WRAPPER_registerChannel     HARNESS_INTF_DUMMY_registerChannel
#define HARNESS_WRAPPER_unregisterChannel   HARNESS_INTF_DUMMY_unregisterChannel
#define HARNESS_WRAPPER_closeChannel        HARNESS_INTF_DUMMY_closeChannel
#define HARNESS_WRAPPER_kernelAlloc         HARNESS_INTF_DUMMY_kernelAlloc
#define HARNESS_WRAPPER_kernelFree          HARNESS_INTF_DUMMY_kernelFree
#define HARNESS_WRAPPER_mapAllocToKernel    HARNESS_INTF_DUMMY_mapAllocToKernel
#define HARNESS_WRAPPER_mapAllocToPhysical  HARNESS_INTF_DUMMY_mapAllocToPhysical

#elif defined(__LINUX_RTOS__)
#define HARNESS_WRAPPER_openChannel         HARNESS_INTF26_openChannel
#define HARNESS_WRAPPER_registerChannel     HARNESS_INTF26_registerChannel
#define HARNESS_WRAPPER_unregisterChannel   HARNESS_INTF26_unregisterChannel
#define HARNESS_WRAPPER_closeChannel        HARNESS_INTF26_closeChannel
#define HARNESS_WRAPPER_kernelAlloc         HARNESS_INTF26_kernelAlloc
#define HARNESS_WRAPPER_kernelFree          HARNESS_INTF26_kernelFree
#define HARNESS_WRAPPER_mapAllocToKernel    HARNESS_INTF26_mapAllocToKernel
#define HARNESS_WRAPPER_mapAllocToPhysical  HARNESS_INTF26_mapAllocToPhysical
#define HARNESS_WRAPPER_doCrypto            HARNESS_INTF26_doCrypto

#if defined(__KERNEL__)
#define OS_VIRTUAL_TO_PHY(x)    (__pa(x))
#endif

#elif defined(__WIN32_RTOS__)
/*
#define HARNESS_WRAPPER_openChannel         HARNESS_INTF_WIN32_openChannel
#define HARNESS_WRAPPER_closeChannel        HARNESS_INTF_WIN32_closeChannel
*/
#define HARNESS_WRAPPER_registerChannel     HARNESS_INTF_WIN32_registerChannel
#define HARNESS_WRAPPER_unregisterChannel   HARNESS_INTF_WIN32_unregisterChannel
#define HARNESS_WRAPPER_kernelAlloc         HARNESS_INTF_WIN32_kernelAlloc
#define HARNESS_WRAPPER_kernelFree          HARNESS_INTF_WIN32_kernelFree
#define HARNESS_WRAPPER_mapAllocToKernel    HARNESS_INTF_WIN32_mapAllocToKernel
#define HARNESS_WRAPPER_mapAllocToPhysical  HARNESS_INTF_WIN32_mapAllocToPhysical
#define HARNESS_WRAPPER_doCrypto            HARNESS_INTF_WIN32_doCrypto

#elif defined(__VXWORKS_RTOS__)
#define HARNESS_WRAPPER_init                HARNESS_INTFVXW_init
#define HARNESS_WRAPPER_openChannel         HARNESS_INTFVXW_openChannel
#define HARNESS_WRAPPER_registerChannel     HARNESS_INTFVXW_registerChannel
#define HARNESS_WRAPPER_unregisterChannel   HARNESS_INTFVXW_unregisterChannel
#define HARNESS_WRAPPER_closeChannel        HARNESS_INTFVXW_closeChannel
#define HARNESS_WRAPPER_kernelAlloc         HARNESS_INTFVXW_kernelAlloc
#define HARNESS_WRAPPER_kernelFree          HARNESS_INTFVXW_kernelFree
#define HARNESS_WRAPPER_mapAllocToKernel    HARNESS_INTFVXW_mapAllocToKernel
#define HARNESS_WRAPPER_mapAllocToPhysical  HARNESS_INTFVXW_mapAllocToPhysical

#elif defined(__QNX_RTOS__)
#define HARNESS_WRAPPER_init                HARNESS_INTFQNX_init
#define HARNESS_WRAPPER_openChannel         HARNESS_INTFQNX_openChannel
#define HARNESS_WRAPPER_registerChannel     HARNESS_INTFQNX_registerChannel
#define HARNESS_WRAPPER_unregisterChannel   HARNESS_INTFQNX_unregisterChannel
#define HARNESS_WRAPPER_closeChannel        HARNESS_INTFQNX_closeChannel
#define HARNESS_WRAPPER_kernelAlloc         HARNESS_INTFQNX_kernelAlloc
#define HARNESS_WRAPPER_kernelFree          HARNESS_INTFQNX_kernelFree
#define HARNESS_WRAPPER_mapAllocToKernel    HARNESS_INTFQNX_mapAllocToKernel
#define HARNESS_WRAPPER_mapAllocToPhysical  HARNESS_INTFQNX_mapAllocToPhysical

#elif defined(__OSE_RTOS__)
#define HARNESS_WRAPPER_init                HARNESS_INTFOSE_init
#define HARNESS_WRAPPER_openChannel         HARNESS_INTFOSE_openChannel
#define HARNESS_WRAPPER_registerChannel     HARNESS_INTFOSE_registerChannel
#define HARNESS_WRAPPER_unregisterChannel   HARNESS_INTFOSE_unregisterChannel
#define HARNESS_WRAPPER_closeChannel        HARNESS_INTFOSE_closeChannel
#define HARNESS_WRAPPER_kernelAlloc         HARNESS_INTFOSE_kernelAlloc
#define HARNESS_WRAPPER_kernelFree          HARNESS_INTFOSE_kernelFree
#define HARNESS_WRAPPER_mapAllocToKernel    HARNESS_INTFOSE_mapAllocToKernel
#define HARNESS_WRAPPER_mapAllocToPhysical  HARNESS_INTFOSE_mapAllocToPhysical

#endif

#ifdef __ENABLE_DIGICERT_PKCS11_CRYPTO__
#undef HARNESS_WRAPPER_init
#undef HARNESS_WRAPPER_uninit
#undef HARNESS_WRAPPER_openChannel
#undef HARNESS_WRAPPER_closeChannel

#define HARNESS_WRAPPER_init                HARNESS_PKCS11_init
#define HARNESS_WRAPPER_uninit              HARNESS_PKCS11_uninit
#define HARNESS_WRAPPER_openChannel         HARNESS_PKCS11_openChannel
#define HARNESS_WRAPPER_closeChannel        HARNESS_PKCS11_closeChannel
#endif

/*------------------------------------------------------------------*/

#if defined(__ENABLE_FREESCALE_8555_HARDWARE_ACCEL__)

#if defined(__VXWORKS_RTOS__)
#define HARNESS_WRAPPER_intConnect          sysEpicIntConnect
#define HARNESS_WRAPPER_intEnable           sysEpicIntEnable
#define CCSRBAR_OFFSET                      0x1e000000
#define FREESCALE_MAGIC                     -64+12

#elif defined(__QNX_RTOS__)
#define CCSRBAR_OFFSET                      0
#define FREESCALE_MAGIC                     -64
#endif

#elif defined(__ENABLE_FREESCALE_8548_HARDWARE_ACCEL__)

#if defined(__VXWORKS_RTOS__)
#define HARNESS_WRAPPER_intConnect          sysEpicIntConnect
#define HARNESS_WRAPPER_intEnable           sysEpicIntEnable
#define CCSRBAR_OFFSET                      0
#define FREESCALE_MAGIC

#elif defined(__QNX_RTOS__)
#define CCSRBAR_OFFSET                      0
#define FREESCALE_MAGIC                     -64
#endif

#if defined(__OSE_RTOS__)
#define CCSRBAR_OFFSET                      0
#define FREESCALE_MAGIC                     16
#define HARNESS_INTCTL                      "dda/mpc8548/openpic"
#endif

/* Temp to checkout build - likely is incorrect */
#elif defined(__ENABLE_FREESCALE_8323_HARDWARE_ACCEL__)

#if defined(__VXWORKS_RTOS__)
#define HARNESS_WRAPPER_intConnect          intConnect
#define HARNESS_WRAPPER_intEnable           intEnable
#define CCSRBAR_OFFSET                      0x00000000
#define FREESCALE_MAGIC
#endif

#elif defined(__ENABLE_FREESCALE_8313_HARDWARE_ACCEL__)

#if defined(__VXWORKS_RTOS__)
#define HARNESS_WRAPPER_intConnect          intConnect
#define HARNESS_WRAPPER_intEnable           intEnable
#define CCSRBAR_OFFSET                      0x00000000
#define FREESCALE_MAGIC
#endif

#elif defined(__ENABLE_FREESCALE_8349_HARDWARE_ACCEL__)

#if defined(__VXWORKS_RTOS__)
#define HARNESS_WRAPPER_intConnect          intConnect
#define HARNESS_WRAPPER_intEnable           intEnable
#define CCSRBAR_OFFSET                      0
#define FREESCALE_MAGIC

#elif defined(__QNX_RTOS__)
#define FREESCALE_MAGIC                     0

#elif defined(__OSE_RTOS__)
#define FREESCALE_MAGIC                     15
#define HARNESS_INTCTL                      "dda/mpc8349/pic"

#endif

#elif defined(__ENABLE_FREESCALE_8360_HARDWARE_ACCEL__)

#if defined(__VXWORKS_RTOS__)
#define HARNESS_WRAPPER_intConnect          intConnect
#define HARNESS_WRAPPER_intEnable           intEnable
#define CCSRBAR_OFFSET                      0xfe000000
#define FREESCALE_MAGIC
#endif

#endif


/*------------------------------------------------------------------*/

typedef enum harnessIoctlMethods_s
{
    HARNESS_OPEN_CHANNEL = 0x1234,
    HARNESS_CLOSE_CHANNEL,
    HARNESS_ALLOC_CRYPTO_BUF,
    HARNESS_DEALLOC_CRYPTO_BUF,
    HARNESS_ALLOC_QUEUE_BUF,
    HARNESS_DEALLOC_QUEUE_BUF,
    HARNESS_DO_CRYPTO,
    HARNESS_DO_TIMER,
    HARNESS_DO_END,
} harnessIoctlMethods;


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS HARNESS_WRAPPER_openChannel(enum moduleNames moduleId, void **ppRetChannelContext);
MOC_EXTERN MSTATUS HARNESS_WRAPPER_registerChannel(mahChannelPair *pChannelDescr);
MOC_EXTERN MSTATUS HARNESS_WRAPPER_unregisterChannel(mahChannelPair *pChannelDescr);
MOC_EXTERN MSTATUS HARNESS_WRAPPER_closeChannel(enum moduleNames moduleId, void **pFreeChannelContext);

MOC_EXTERN MSTATUS HARNESS_WRAPPER_kernelAlloc(void *pChannelContext, ubyte4 memBlockSize, intBoolean isCryptoBuf, void **ppRetMemBlock);
MOC_EXTERN MSTATUS HARNESS_WRAPPER_kernelFree(void *pChannelContext, intBoolean isCryptoBuf, void **ppFreeMemBlock);

MOC_EXTERN MSTATUS HARNESS_WRAPPER_mapAllocToKernel(void *pChannelContext, void *pBlock, void **ppRetKernelMemBlock);
MOC_EXTERN MSTATUS HARNESS_WRAPPER_mapAllocToPhysical(void *pChannelContext, void *pBlock, void **ppRetPhysicalMemBlock);

MOC_EXTERN void    HARNESS_WRAPPER_doCrypto(void *pChannelDescr);

MOC_EXTERN MSTATUS HARNESS_WRAPPER_init(void);

#endif /* __HARNESS_INTF_HEADER__ */
