/*
 * hw_accel_async.h
 *
 * Hardware Acceleration Asynchronous Wrapper Interface
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

#ifndef __HW_ACCEL_ASYNC_HEADER__
#define __HW_ACCEL_ASYNC_HEADER__

/*------------------------------------------------------------------*/

typedef struct
{
    char*       pName;
    void*       pRegionStart;
    sbyte4      lengthOfRegion;
    void**      ppPtrToSet;

} hwAccelAsyncRegionDescr;


/*------------------------------------------------------------------*/

typedef struct
{
    char*           pName;
    unsigned int    irqNum;
    byteBoolean     isTimerIrq;
    byteBoolean     regstat;
    void            *appContext;
} hwAccelAsyncIrqDescr;


/*------------------------------------------------------------------*/

#if defined(__ENABLE_FREESCALE_8272_HARDWARE_ACCEL__)
#define HW_ACCEL_ASYNC_initDrv                  FSL8272_initDrv
/*!!!! #define HW_ACCEL_ASYNC_termDrv */
#define HW_ACCEL_ASYNC_listOfInitRegionDescrs   FSL8272_listOfInitRegionDescrs
#define HW_ACCEL_ASYNC_listOfInitIrqDescrs      FSL8272_listOfInitIrqDescrs
#define HW_ACCEL_ASYNC_verifyInit               FSL8272_verifyInit

#define HW_ACCEL_ASYNC_interruptSecHandler      FSL8272_interruptSecHandler
#define HW_ACCEL_ASYNC_timerHandler             FSL8272_timerHandler

#define HW_ACCEL_ASYNC_dispatchServiceRequests  FSL8272_dispatchServiceRequests
#define HW_ACCEL_ASYNC_initServiceRequestQueues FSL8272_initServiceRequestQueues
#define HW_ACCEL_ASYNC_addServiceRequest        FSL8272_addServiceRequest

#elif defined(__ENABLE_FREESCALE_8313_HARDWARE_ACCEL__)
#define HW_ACCEL_ASYNC_initDrv                  FSL8313_initDrv
/*!!!! #define HW_ACCEL_ASYNC_termDrv */
#define HW_ACCEL_ASYNC_listOfInitRegionDescrs   FSL8313_listOfInitRegionDescrs
#define HW_ACCEL_ASYNC_listOfInitIrqDescrs      FSL8313_listOfInitIrqDescrs
#define HW_ACCEL_ASYNC_verifyInit               FSL8313_verifyInit

#define HW_ACCEL_ASYNC_interruptSecHandler      FSL8313_interruptSecHandler
#define HW_ACCEL_ASYNC_timerHandler             FSL8313_timerHandler

#define HW_ACCEL_ASYNC_dispatchServiceRequests  FSL8313_dispatchServiceRequests
#define HW_ACCEL_ASYNC_initServiceRequestQueues FSL8313_initServiceRequestQueues
#define HW_ACCEL_ASYNC_addServiceRequest        FSL8313_addServiceRequest

#define __2_6_18_PLUS__

#elif defined(__ENABLE_FREESCALE_8315_HARDWARE_ACCEL__)
#define HW_ACCEL_ASYNC_initDrv                  FSL8315_initDrv
/*!!!! #define HW_ACCEL_ASYNC_termDrv */
#define HW_ACCEL_ASYNC_listOfInitRegionDescrs   FSL8315_listOfInitRegionDescrs
#define HW_ACCEL_ASYNC_listOfInitIrqDescrs      FSL8315_listOfInitIrqDescrs
#define HW_ACCEL_ASYNC_verifyInit               FSL8315_verifyInit

#define HW_ACCEL_ASYNC_interruptSecHandler      FSL8315_interruptSecHandler
#define HW_ACCEL_ASYNC_timerHandler             FSL8315_timerHandler

#define HW_ACCEL_ASYNC_dispatchServiceRequests  FSL8315_dispatchServiceRequests
#define HW_ACCEL_ASYNC_initServiceRequestQueues FSL8315_initServiceRequestQueues
#define HW_ACCEL_ASYNC_addServiceRequest        FSL8315_addServiceRequest

#define __2_6_23_PLUS__

#elif defined(__ENABLE_FREESCALE_8323_HARDWARE_ACCEL__)
#define HW_ACCEL_ASYNC_initDrv                  FSL8323_initDrv
/*!!!! #define HW_ACCEL_ASYNC_termDrv */
#define HW_ACCEL_ASYNC_listOfInitRegionDescrs   FSL8323_listOfInitRegionDescrs
#define HW_ACCEL_ASYNC_listOfInitIrqDescrs      FSL8323_listOfInitIrqDescrs
#define HW_ACCEL_ASYNC_verifyInit               FSL8323_verifyInit

#define HW_ACCEL_ASYNC_interruptSecHandler      FSL8323_interruptSecHandler
#define HW_ACCEL_ASYNC_timerHandler             FSL8323_timerHandler

#define HW_ACCEL_ASYNC_dispatchServiceRequests  FSL8323_dispatchServiceRequests
#define HW_ACCEL_ASYNC_initServiceRequestQueues FSL8323_initServiceRequestQueues
#define HW_ACCEL_ASYNC_addServiceRequest        FSL8323_addServiceRequest

/* WR_LINUX for 8323 is 2.6.14 and does not support of_device */
/* It also does not have KERNEL_VERSION macro */
#ifndef __WR_LINUX__
#define __2_6_18_PLUS__
#endif

#elif defined(__ENABLE_FREESCALE_8349_HARDWARE_ACCEL__)
#define HW_ACCEL_ASYNC_initDrv                  FSL8349_initDrv
/*!!!! #define HW_ACCEL_ASYNC_termDrv */
#define HW_ACCEL_ASYNC_listOfInitRegionDescrs   FSL8349_listOfInitRegionDescrs
#define HW_ACCEL_ASYNC_listOfInitIrqDescrs      FSL8349_listOfInitIrqDescrs
#define HW_ACCEL_ASYNC_verifyInit               FSL8349_verifyInit

#define HW_ACCEL_ASYNC_interruptSecHandler      FSL8349_interruptSecHandler
#define HW_ACCEL_ASYNC_timerHandler             FSL8349_timerHandler

#define HW_ACCEL_ASYNC_dispatchServiceRequests  FSL8349_dispatchServiceRequests
#define HW_ACCEL_ASYNC_initServiceRequestQueues FSL8349_initServiceRequestQueues
#define HW_ACCEL_ASYNC_addServiceRequest        FSL8349_addServiceRequest

#elif defined(__ENABLE_FREESCALE_8360_HARDWARE_ACCEL__)
#define HW_ACCEL_ASYNC_initDrv                  FSL8360_initDrv
/*!!!! #define HW_ACCEL_ASYNC_termDrv */
#define HW_ACCEL_ASYNC_listOfInitRegionDescrs   FSL8360_listOfInitRegionDescrs
#define HW_ACCEL_ASYNC_listOfInitIrqDescrs      FSL8360_listOfInitIrqDescrs
#define HW_ACCEL_ASYNC_verifyInit               FSL8360_verifyInit

#define HW_ACCEL_ASYNC_interruptSecHandler      FSL8360_interruptSecHandler
#define HW_ACCEL_ASYNC_timerHandler             FSL8360_timerHandler

#define HW_ACCEL_ASYNC_dispatchServiceRequests  FSL8360_dispatchServiceRequests
#define HW_ACCEL_ASYNC_initServiceRequestQueues FSL8360_initServiceRequestQueues
#define HW_ACCEL_ASYNC_addServiceRequest        FSL8360_addServiceRequest
#define __2_6_18_PLUS__

#elif defined(__ENABLE_FREESCALE_8548_HARDWARE_ACCEL__)
#define HW_ACCEL_ASYNC_initDrv                  FSL8548_initDrv
/*!!!! #define HW_ACCEL_ASYNC_termDrv */
#define HW_ACCEL_ASYNC_listOfInitRegionDescrs   FSL8548_listOfInitRegionDescrs
#define HW_ACCEL_ASYNC_listOfInitIrqDescrs      FSL8548_listOfInitIrqDescrs
#define HW_ACCEL_ASYNC_verifyInit               FSL8548_verifyInit

#define HW_ACCEL_ASYNC_interruptSecHandler      FSL8548_interruptSecHandler
#define HW_ACCEL_ASYNC_timerHandler             FSL8548_timerHandler

#define HW_ACCEL_ASYNC_dispatchServiceRequests  FSL8548_dispatchServiceRequests
#define HW_ACCEL_ASYNC_initServiceRequestQueues FSL8548_initServiceRequestQueues
#define HW_ACCEL_ASYNC_addServiceRequest        FSL8548_addServiceRequest

#elif defined(__ENABLE_FREESCALE_8544_HARDWARE_ACCEL__)
#define HW_ACCEL_ASYNC_initDrv                  FSL8544_initDrv
/*!!!! #define HW_ACCEL_ASYNC_termDrv */
#define HW_ACCEL_ASYNC_listOfInitRegionDescrs   FSL8544_listOfInitRegionDescrs
#define HW_ACCEL_ASYNC_listOfInitIrqDescrs      FSL8544_listOfInitIrqDescrs
#define HW_ACCEL_ASYNC_verifyInit               FSL8544_verifyInit

#define HW_ACCEL_ASYNC_interruptSecHandler      FSL8544_interruptSecHandler
#define HW_ACCEL_ASYNC_timerHandler             FSL8544_timerHandler

#define HW_ACCEL_ASYNC_dispatchServiceRequests  FSL8544_dispatchServiceRequests
#define HW_ACCEL_ASYNC_initServiceRequestQueues FSL8544_initServiceRequestQueues
#define HW_ACCEL_ASYNC_addServiceRequest        FSL8544_addServiceRequest

#define __2_6_23_PLUS__

#elif defined(__ENABLE_FREESCALE_8572_HARDWARE_ACCEL__)
#define HW_ACCEL_ASYNC_initDrv                  FSL8572_initDrv
/*!!!! #define HW_ACCEL_ASYNC_termDrv */
#define HW_ACCEL_ASYNC_listOfInitRegionDescrs   FSL8572_listOfInitRegionDescrs
#define HW_ACCEL_ASYNC_listOfInitIrqDescrs      FSL8572_listOfInitIrqDescrs
#define HW_ACCEL_ASYNC_verifyInit               FSL8572_verifyInit

#define HW_ACCEL_ASYNC_interruptSecHandler      FSL8572_interruptSecHandler
#define HW_ACCEL_ASYNC_timerHandler             FSL8572_timerHandler

#define HW_ACCEL_ASYNC_dispatchServiceRequests  FSL8572_dispatchServiceRequests
#define HW_ACCEL_ASYNC_initServiceRequestQueues FSL8572_initServiceRequestQueues
#define HW_ACCEL_ASYNC_addServiceRequest        FSL8572_addServiceRequest

#define __2_6_18_PLUS__

#elif defined(__ENABLE_FREESCALE_8379_HARDWARE_ACCEL__)
#define HW_ACCEL_ASYNC_initDrv                  FSL8379_initDrv
/*!!!! #define HW_ACCEL_ASYNC_termDrv */
#define HW_ACCEL_ASYNC_listOfInitRegionDescrs   FSL8379_listOfInitRegionDescrs
#define HW_ACCEL_ASYNC_listOfInitIrqDescrs      FSL8379_listOfInitIrqDescrs
#define HW_ACCEL_ASYNC_verifyInit               FSL8379_verifyInit

#define HW_ACCEL_ASYNC_interruptSecHandler      FSL8379_interruptSecHandler
#define HW_ACCEL_ASYNC_timerHandler             FSL8379_timerHandler

#define HW_ACCEL_ASYNC_dispatchServiceRequests  FSL8379_dispatchServiceRequests
#define HW_ACCEL_ASYNC_initServiceRequestQueues FSL8379_initServiceRequestQueues
#define HW_ACCEL_ASYNC_addServiceRequest        FSL8379_addServiceRequest

#define __2_6_18_PLUS__

#elif defined(__ENABLE_FREESCALE_8555_HARDWARE_ACCEL__)
#define HW_ACCEL_ASYNC_initDrv                  FSL8555_initDrv
/*!!!! #define HW_ACCEL_ASYNC_termDrv */
#define HW_ACCEL_ASYNC_listOfInitRegionDescrs   FSL8555_listOfInitRegionDescrs
#define HW_ACCEL_ASYNC_listOfInitIrqDescrs      FSL8555_listOfInitIrqDescrs
#define HW_ACCEL_ASYNC_verifyInit               FSL8555_verifyInit

#define HW_ACCEL_ASYNC_interruptSecHandler      FSL8555_interruptSecHandler
#define HW_ACCEL_ASYNC_timerHandler             FSL8555_timerHandler
#define HW_ACCEL_ASYNC_interruptTimerHandler    FSL8555_interruptTimerHandler

#define HW_ACCEL_ASYNC_dispatchServiceRequests  FSL8555_dispatchServiceRequests
#define HW_ACCEL_ASYNC_initServiceRequestQueues FSL8555_initServiceRequestQueues
#define HW_ACCEL_ASYNC_addServiceRequest        FSL8555_addServiceRequest

#elif defined(__ENABLE_BROADCOM_5862_HARDWARE_ACCEL__)

#define HW_ACCEL_ASYNC_initDrv                  BCM5862_initDrv
#define HW_ACCEL_ASYNC_termDrv                  BCM5862_termDrv
#define HW_ACCEL_ASYNC_listOfInitRegionDescrs   BCM5862_listOfInitRegionDescrs
#define HW_ACCEL_ASYNC_listOfInitIrqDescrs      BCM5862_listOfInitIrqDescrs
#define HW_ACCEL_ASYNC_verifyInit               BCM5862_verifyInit

#define HW_ACCEL_ASYNC_interruptSecHandler      BCM5862_interruptSecHandler
#define HW_ACCEL_ASYNC_interruptTimerHandler    BCM5862_interruptTimerHandler
#define HW_ACCEL_ASYNC_timerHandler             BCM5862_timerHandler
#define HW_ACCEL_ASYNC_ioctl                    BCM5862_ioctl

#define HW_ACCEL_ASYNC_dispatchServiceRequests  BCM5862_dispatchServiceRequests
#define HW_ACCEL_ASYNC_initServiceRequestQueues BCM5862_initServiceRequestQueues
#define HW_ACCEL_ASYNC_addServiceRequest        BCM5862_addServiceRequest

#elif (defined(__ENABLE_TEST_HARDWARE_ACCEL_LAYER__) && defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__))

#define HW_ACCEL_ASYNC_initDrv                  TESTHARNESS_initDrv
#define HW_ACCEL_ASYNC_termDrv                  TESTHARNESS_termDrv
#define HW_ACCEL_ASYNC_listOfInitRegionDescrs   TESTHARNESS_listOfInitRegionDescrs
#define HW_ACCEL_ASYNC_listOfInitIrqDescrs      TESTHARNESS_listOfInitIrqDescrs
#define HW_ACCEL_ASYNC_verifyInit               TESTHARNESS_verifyInit

#define HW_ACCEL_ASYNC_interruptSecHandler      TESTHARNESS_interruptSecHandler
#define HW_ACCEL_ASYNC_interruptTimerHandler    TESTHARNESS_interruptTimerHandler
#define HW_ACCEL_ASYNC_timerHandler             TESTHARNESS_timerHandler
#define HW_ACCEL_ASYNC_ioctl                    TESTHARNESS_ioctl

#define HW_ACCEL_ASYNC_dispatchServiceRequests  TESTHARNESS_dispatchServiceRequests
#define HW_ACCEL_ASYNC_initServiceRequestQueues TESTHARNESS_initServiceRequestQueues
#define HW_ACCEL_ASYNC_addServiceRequest        TESTHARNESS_addServiceRequest

#elif (defined(__ENABLE_MOCANA_PKCS11_CRYPTO__))
#define HW_ACCEL_ASYNC_initDrv                  DUMMYHARNESS_initDrv
#define HW_ACCEL_ASYNC_termDrv                  DUMMYHARNESS_termDrv
#define HW_ACCEL_ASYNC_listOfInitRegionDescrs   DUMMYHARNESS_listOfInitRegionDescrs
#define HW_ACCEL_ASYNC_listOfInitIrqDescrs      DUMMYHARNESS_listOfInitIrqDescrs
#define HW_ACCEL_ASYNC_verifyInit               DUMMYHARNESS_verifyInit

#define HW_ACCEL_ASYNC_interruptSecHandler      DUMMYHARNESS_interruptSecHandler
#define HW_ACCEL_ASYNC_interruptTimerHandler    DUMMYHARNESS_interruptTimerHandler
#define HW_ACCEL_ASYNC_timerHandler             DUMMYHARNESS_timerHandler
#define HW_ACCEL_ASYNC_ioctl                    DUMMYHARNESS_ioctl

#define HW_ACCEL_ASYNC_dispatchServiceRequests  DUMMYHARNESS_dispatchServiceRequests
#define HW_ACCEL_ASYNC_initServiceRequestQueues DUMMYHARNESS_initServiceRequestQueues
#define HW_ACCEL_ASYNC_addServiceRequest        DUMMYHARNESS_addServiceRequest
#endif


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS      HW_ACCEL_ASYNC_initDrv(void);
MOC_EXTERN void         HW_ACCEL_ASYNC_termDrv(void);
MOC_EXTERN MSTATUS      HW_ACCEL_ASYNC_listOfInitRegionDescrs(hwAccelAsyncRegionDescr **ppRetTable, sbyte4 *pRetNumEntries);
MOC_EXTERN MSTATUS      HW_ACCEL_ASYNC_listOfInitIrqDescrs(hwAccelAsyncIrqDescr **ppRetTable, sbyte4 *pRetNumEntries);
MOC_EXTERN MSTATUS      HW_ACCEL_ASYNC_verifyInit(void);

MOC_EXTERN intBoolean   HW_ACCEL_ASYNC_interruptSecHandler(int irqNum, void *appContext, intBoolean *pRetRearmTimer);
MOC_EXTERN intBoolean   HW_ACCEL_ASYNC_interruptTimerHandler(int irqNum, intBoolean testInterrupt);
MOC_EXTERN int          HW_ACCEL_ASYNC_timerHandler(void);
MOC_EXTERN int          HW_ACCEL_ASYNC_ioctl(int cmd, int arg);

MOC_EXTERN void         HW_ACCEL_ASYNC_initServiceRequestQueues(void);
MOC_EXTERN intBoolean   HW_ACCEL_ASYNC_addServiceRequest(mahCellDescr *pCell, ubyte4* pRetIndexHint);
MOC_EXTERN intBoolean   HW_ACCEL_ASYNC_dispatchServiceRequests(void);

#endif /* __HW_ACCEL_ASYNC_HEADER__ */
