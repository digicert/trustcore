/**
 * @file   mrtos.h
 * @brief  Mocana RTOS Abstraction Layer
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

/*------------------------------------------------------------------*/

#ifndef __MRTOS_HEADER__
#define __MRTOS_HEADER__

#include "../common/mrtos_custom.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __UCOS_DIRECT_RTOS__
#include <stdlib.h>
#endif

#ifdef __SYMBIAN32__
#include <stdlib.h>
#endif

#ifdef __AZURE_RTOS__
#include "fx_api.h"
#endif

#ifdef __MQX_RTOS__

/* Including mqx.h and bsp.h in this header causes errors when building for
   MQX 3.8.1 on CodeWarrior for MCUs 10.2
#include <mqx.h>
#include <bsp.h> */
#define MSEEK_END     IO_SEEK_END
#define MSEEK_SET     IO_SEEK_SET

#elif defined __AZURE_RTOS__

#define MSEEK_END    FX_SEEK_END
#define MSEEK_SET    FX_SEEK_BEGIN
#define MSEEK_CUR    FX_SEEK_FORWARD

#else

#define MSEEK_END    SEEK_END
#define MSEEK_SET    SEEK_SET
#define MSEEK_CUR    SEEK_CUR

#endif

/* thread types */
enum threadTypes
{
    ENTROPY_THREAD,
    DEBUG_CONSOLE,
    SSL_UPCALL_DAEMON,
    SSH_UPCALL_DAEMON,
    SSL_MAIN,
    SSL_SERVER_SESSION,
    DTLS_MAIN,
    SSH_MAIN,
    SSH_SESSION,
    HTTP_THREAD,
    IKE_MAIN,
    DEBUG_THREAD,
    EAP_MAIN,
    IPC_MAIN,
    RADIUS_MAIN,
    HARNESS_MAIN,
    HARNESS_MAIN1,
    HARNESS_TEST,
    CLI_THREAD,
    MOC_IPV4,
    FIREWALL_MAIN,
    FIREWALL_SERVER,
    NTP_MAIN,
    OCSP_MAIN,
    SCEP_MAIN,
    EST_MAIN,
    TP_THREAD,
    TP_TRANS_THREAD,
    TP_PROV_THREAD,
    MOCTPM_MAIN,
    CMP_MAIN,
    LDAP_MAIN,
    PKI_CLIENT_MAIN,
    PKI_IPC_MAIN,
    SRTP_MAIN,
    SYSLOG_MAIN,
    CRYPTO_MAIN,
    DEMO_COMM_MAIN,
    SSL_CLIENT_MAIN,
    UM_SCHED,
    TRUSTEDGE_MAIN,
    MQTT_SESSION
};

/* mutex types */
enum mutexTypes
{
    /* if updating this list, please be sure to make sure psos_rtos.c */
    /* and other oses are updated! ask James for details */
    SSL_CACHE_MUTEX,
    SYSLOG_CACHE_MUTEX,
    HW_ACCEL_CHANNEL_MUTEX,
    IPSEC_REASSEMBLY_MUTEX,
    IKE_MT_MUTEX,
    MCP_NW_MUTEX,
    SSH_SERVER_MUTEX,
    TACACS_CLIENT_MUTEX,
    HARNESS_DRV_MUTEX,
    GUARDIAN_MUTEX,
    MEM_PART_MUTEX,
    EAP_INSTANCE_MUTEX,
    EAP_SESSION_MUTEX,
    FIREWALL_MUTEX,
    SRTP_CACHE_MUTEX,
    PKI_CLIENT_CACHE_MUTEX,
    HSM_MUTEX,
    TP_SERVER_MUTEX,
    EC_COMB_MUTEX,
    OCSP_CACHE_MUTEX,
    FREERTOS_BINARY_MUTEX,
    MQTT_CACHE_MUTEX,
    MQTT_MUTEX,
    END_MUTEX
};

/* this structure is such that dates can be easily compared with memcmp */
typedef struct TimeDate
{
    ubyte2  m_year;     /* year 0 = 1970, 1 =1971 , etc...*/
    ubyte   m_month;    /* 1 = january, ... 12 = december */
    ubyte   m_day;      /* 1 - 31 */
    ubyte   m_hour;     /* 0 - 23 */
    ubyte   m_minute;   /* 0 - 59 */
    ubyte   m_second;   /* 0 - 59 */
} TimeDate;

/* Do not assume anything about the meaning of the fields of
  moctime_t: use the API functions only! */
typedef struct moctime_t
{
    union {
        ubyte4    time[2];
#if (defined(__KERNEL__) && (defined(__LINUX_RTOS__) || defined(__ANDROID_RTOS__)))
        long long jiffies;              /* Linux kernel mode */
#endif

    } u;
} moctime_t;

typedef void*                       RTOS_MUTEX;
typedef void*                       RTOS_COND;
#ifndef __RTOS_QNX_7__
typedef void*                       RTOS_THREAD;
#define RTOS_THREAD_INVALID         NULL
#endif
typedef void*                       RTOS_TIMEVAL;
typedef void*                       RTOS_RWLOCK;
#ifdef __ENABLE_DIGICERT_GLOBAL_MUTEX__
#define MAX_MUTEX_WAIT_RETRY_COUNT  3
typedef void*                       RTOS_GLOBAL_MUTEX;
#endif
typedef void*                       RTOS_SEM;
typedef void*                       RTOS_LOCK;

typedef struct RTOS_Notifier_s
{
    int pipe[2];
    void* value;
} RTOS_Notifier;

typedef RTOS_Notifier* RTOS_NOTIFIER_t;

#if !defined(__CUSTOM_RTOS__) /* If mrtos_custom.h has the mapping, skip this section */

#if defined (__SOLARIS_RTOS__)
#define RTOS_rtosInit               SOLARIS_rtosInit
#define RTOS_rtosShutdown           SOLARIS_rtosShutdown
#define RTOS_mutexCreate            SOLARIS_mutexCreate
#define RTOS_mutexWait              SOLARIS_mutexWait
#define RTOS_mutexRelease           SOLARIS_mutexRelease
#define RTOS_mutexFree              SOLARIS_mutexFree
#define RTOS_getUpTimeInMS          SOLARIS_getUpTimeInMS
#define RTOS_deltaMS                SOLARIS_deltaMS
#define RTOS_sleepMS                SOLARIS_sleepMS
#define RTOS_deltaConstMS           SOLARIS_deltaConstMS
#define RTOS_timerAddMS             SOLARIS_timerAddMS
#define RTOS_createThread           SOLARIS_createThread
#define RTOS_destroyThread          SOLARIS_destroyThread
#define RTOS_currentThreadId        SOLARIS_currentThreadId
#define RTOS_timeGMT                SOLARIS_timeGMT

#elif defined (__LINUX_RTOS__) || defined (__ANDROID_RTOS__)
#define RTOS_rtosInit               LINUX_rtosInit
#define RTOS_rtosShutdown           LINUX_rtosShutdown
#define RTOS_mutexCreate            LINUX_mutexCreate
#define RTOS_mutexWait              LINUX_mutexWait
#define RTOS_mutexWaitEx            LINUX_mutexWaitEx
#define RTOS_mutexRelease           LINUX_mutexRelease
#define RTOS_mutexFree              LINUX_mutexFree

#ifdef __ENABLE_DIGICERT_GLOBAL_MUTEX__
#define RTOS_globalMutexCreate      LINUX_globalMutexCreate
#define RTOS_globalMutexWait        LINUX_globalMutexWait
#define RTOS_globalMutexRelease     LINUX_globalMutexRelease
#define RTOS_globalMutexFree        LINUX_globalMutexFree
#endif

#define RTOS_lockFileCreate         LINUX_lockFileCreate
#if !defined(__RTOS_ZEPHYR__)
#define RTOS_lockFileAcquire        LINUX_lockFileAcquire
#define RTOS_lockFileRelease        LINUX_lockFileRelease
#endif
#define RTOS_lockFileFree           LINUX_lockFileFree

#define RTOS_condCreate             LINUX_condCreate
#define RTOS_condWait               LINUX_condWait
#define RTOS_condTimedWait          LINUX_condTimedWait
#define RTOS_condSignal             LINUX_condSignal
#define RTOS_condFree               LINUX_condFree
#define RTOS_getUpTimeInMS          LINUX_getUpTimeInMS

#if !defined(__RTOS_ZEPHYR__)
#define RTOS_processExecute         LINUX_processExecute
#define RTOS_processExecuteWithArg  LINUX_processExecuteWithArg
#endif
#if defined(__MOC_PLATFORM_MODULE__)
#define RTOS_deltaMS                DIGI_deltaMS
#else
#define RTOS_deltaMS                LINUX_deltaMS
#endif
#define RTOS_deltaConstMS           LINUX_deltaConstMS
#define RTOS_timerAddMS             LINUX_timerAddMS
#define RTOS_sleepMS                LINUX_sleepMS
#define RTOS_sleepCheckStatusMS     LINUX_sleepCheckStatusMS
#define RTOS_timeCompare            LINUX_timeCompare
#define RTOS_createThread           LINUX_createThread
#define RTOS_destroyThread          LINUX_destroyThread
#define RTOS_exitThread             LINUX_exitThread
#define RTOS_joinThread             LINUX_joinThread
#define RTOS_currentThreadId        LINUX_currentThreadId
#define RTOS_sameThreadId           LINUX_sameThreadId
#define RTOS_timeGMT                LINUX_timeGMT

#define RTOS_rwLockCreate           LINUX_rwLockCreate
#define RTOS_rwLockWaitR            LINUX_rwLockWaitR
#define RTOS_rwLockReleaseR         LINUX_rwLockReleaseR
#define RTOS_rwLockWaitW            LINUX_rwLockWaitW
#define RTOS_rwLockOwnerW           LINUX_rwLockOwnerW
#define RTOS_rwLockReleaseW         LINUX_rwLockReleaseW
#define RTOS_rwLockFree             LINUX_rwLockFree

#define RTOS_recursiveMutexCreate   LINUX_recursiveMutexCreate
#define RTOS_recursiveMutexWait     LINUX_recursiveMutexWait
#define RTOS_recursiveMutexRelease  LINUX_recursiveMutexRelease
#define RTOS_recursiveMutexFree     LINUX_recursiveMutexFree

#define RTOS_semCreate              LINUX_semCreate
#define RTOS_semWait                LINUX_semWait
#define RTOS_semTimedWait           LINUX_semTimedWait
#define RTOS_semTryWait             LINUX_semTryWait
#define RTOS_semSignal              LINUX_semSignal
#define RTOS_semFree                LINUX_semFree

#if defined(__LINUX_RTOS__) && !defined(__RTOS_ZEPHYR__)
#define RTOS_getHwAddr              LINUX_getHwAddr
#define RTOS_getHwAddrByIfname      LINUX_getHwAddrByIfname
#endif

#define RTOS_notifierCreate         UNIX_notifierCreate
#define RTOS_notifierWait           UNIX_notifierWait
#define RTOS_notifierTimedWait      UNIX_notifierTimedWait
#define RTOS_notifierNotify         UNIX_notifierNotify
#define RTOS_notifierFree           UNIX_notifierFree

#ifdef __KERNEL__
#if defined(__MOC_PLATFORM_MODULE__)
#define RTOS_malloc  				DIGI_malloc
#define RTOS_free    				DIGI_ffree
#else
#define RTOS_malloc                 LINUX_malloc
#define RTOS_free                   LINUX_free
#endif
#endif



#elif defined (__SYMBIAN32__)
#define RTOS_rtosInit               SYMBIAN_rtosInit
#define RTOS_rtosShutdown           SYMBIAN_rtosShutdown
#define RTOS_mutexCreate            SYMBIAN_mutexCreate
#define RTOS_mutexWait              SYMBIAN_mutexWait
#define RTOS_mutexRelease           SYMBIAN_mutexRelease
#define RTOS_mutexFree              SYMBIAN_mutexFree
#define RTOS_condCreate             SYMBIAN_condCreate
#define RTOS_condWait               SYMBIAN_condWait
#define RTOS_condSignal             SYMBIAN_condSignal
#define RTOS_condFree               SYMBIAN_condFree
#define RTOS_getUpTimeInMS          SYMBIAN_getUpTimeInMS
#define RTOS_deltaMS                SYMBIAN_deltaMS
#define RTOS_deltaConstMS           SYMBIAN_deltaConstMS
#define RTOS_timerAddMS             SYMBIAN_timerAddMS
#define RTOS_sleepMS                SYMBIAN_sleepMS
#define RTOS_createThread           SYMBIAN_createThread
#define RTOS_destroyThread          SYMBIAN_destroyThread
#define RTOS_currentThreadId        SYMBIAN_currentThreadId
#define RTOS_timeGMT                SYMBIAN_timeGMT

#elif defined __RTOS_WIN32__
#define RTOS_rtosInit               WIN32_rtosInit
#define RTOS_rtosShutdown           WIN32_rtosShutdown
#define RTOS_mutexCreate            WIN32_mutexCreate
#define RTOS_mutexWait              WIN32_mutexWait
#define RTOS_mutexRelease           WIN32_mutexRelease
#define RTOS_mutexFree              WIN32_mutexFree
#ifdef __ENABLE_DIGICERT_GLOBAL_MUTEX__
#define RTOS_globalMutexCreate      WIN32_globalMutexCreate
#define RTOS_globalMutexWait        WIN32_globalMutexWait
#define RTOS_globalMutexRelease     WIN32_globalMutexRelease
#define RTOS_globalMutexFree        WIN32_globalMutexFree
#endif

#define RTOS_lockFileCreate         WIN32_lockFileCreate
#define RTOS_lockFileAcquire        WIN32_lockFileAcquire
#define RTOS_lockFileRelease        WIN32_lockFileRelease
#define RTOS_lockFileFree           WIN32_lockFileFree

#define RTOS_recursiveMutexCreate   WIN32_mutexCreate
#define RTOS_recursiveMutexWait     WIN32_mutexWait
#define RTOS_recursiveMutexRelease  WIN32_mutexRelease
#define RTOS_recursiveMutexFree     WIN32_mutexFree

#define RTOS_getUpTimeInMS          WIN32_getUpTimeInMS
#define RTOS_deltaMS                WIN32_deltaMS
#define RTOS_deltaConstMS           WIN32_deltaConstMS
#define RTOS_timerAddMS             WIN32_timerAddMS
#define RTOS_sleepMS                WIN32_sleepMS
#define RTOS_createThread           WIN32_createThread
#define RTOS_destroyThread          WIN32_destroyThread
#define RTOS_currentThreadId        WIN32_currentThreadId
#define RTOS_timeGMT                WIN32_timeGMT
#define RTOS_getHwAddr              WIN32_getHwAddr
#define RTOS_getHwAddrByIfname      WIN32_getHwAddrByIfname


#elif defined __VXWORKS_RTOS__
#define RTOS_rtosInit               VXWORKS_rtosInit
#define RTOS_rtosShutdown           VXWORKS_rtosShutdown
#define RTOS_mutexCreate            VXWORKS_mutexCreate
#define RTOS_mutexWait              VXWORKS_mutexWait
#define RTOS_mutexWaitEx            VXWORKS_mutexWaitEx
#define RTOS_mutexRelease           VXWORKS_mutexRelease
#define RTOS_mutexFree              VXWORKS_mutexFree
#define RTOS_getUpTimeInMS          VXWORKS_getUpTimeInMS
#define RTOS_deltaMS                VXWORKS_deltaMS
#define RTOS_deltaConstMS           VXWORKS_deltaConstMS
#define RTOS_timerAddMS             VXWORKS_timerAddMS
#define RTOS_sleepMS                VXWORKS_sleepMS
#define RTOS_createThread           VXWORKS_createThread
#define RTOS_destroyThread          VXWORKS_destroyThread
#define RTOS_currentThreadId        VXWORKS_currentThreadId
#define RTOS_timeGMT                VXWORKS_timeGMT
#define RTOS_getHwAddrByIfname      VXWORKS_getHwAddrByIfname

#define RTOS_recursiveMutexCreate   VXWORKS_recursiveMutexCreate
#define RTOS_recursiveMutexWait     VXWORKS_recursiveMutexWait
#define RTOS_recursiveMutexRelease  VXWORKS_recursiveMutexRelease
#define RTOS_recursiveMutexFree     VXWORKS_recursiveMutexFree

#define RTOS_semCreate              VXWORKS_semCreate
#define RTOS_semWait                VXWORKS_mutexWait
#define RTOS_semTryWait             VXWORKS_semTryWait
#define RTOS_semSignal              VXWORKS_mutexRelease
#define RTOS_semFree                VXWORKS_mutexFree

#elif defined __NNOS_RTOS__
#define RTOS_rtosInit               NNOS_rtosInit
#define RTOS_rtosShutdown           NNOS_rtosShutdown
#define RTOS_mutexCreate            NNOS_mutexCreate
#define RTOS_mutexWait              NNOS_mutexWait
#define RTOS_mutexRelease           NNOS_mutexRelease
#define RTOS_mutexFree              NNOS_mutexFree
#define RTOS_getUpTimeInMS          NNOS_getUpTimeInMS
#define RTOS_deltaMS                NNOS_deltaMS
#define RTOS_sleepMS                NNOS_sleepMS
#define RTOS_createThread           NNOS_createThread
#define RTOS_destroyThread          NNOS_destroyThread
#define RTOS_currentThreadId        NNOS_currentThreadId
#define RTOS_timeGMT                NNOS_timeGMT

#elif defined __PSOS_RTOS__
#define RTOS_rtosInit               PSOS_rtosInit
#define RTOS_rtosShutdown           PSOS_rtosShutdown
#define RTOS_mutexCreate            PSOS_mutexCreate
#define RTOS_mutexWait              PSOS_mutexWait
#define RTOS_mutexRelease           PSOS_mutexRelease
#define RTOS_mutexFree              PSOS_mutexFree
#define RTOS_getUpTimeInMS          PSOS_getUpTimeInMS
#define RTOS_deltaMS                PSOS_deltaMS
#define RTOS_sleepMS                PSOS_sleepMS
#define RTOS_createThread           PSOS_createThread
#define RTOS_destroyThread          PSOS_destroyThread
#define RTOS_currentThreadId        PSOS_currentThreadId
#define RTOS_timeGMT                PSOS_timeGMT

#elif defined __NUCLEUS_RTOS__
#define RTOS_rtosInit               NUCLEUS_rtosInit
#define RTOS_rtosShutdown           NUCLEUS_rtosShutdown
#define RTOS_mutexCreate            NUCLEUS_mutexCreate
#define RTOS_mutexWait              NUCLEUS_mutexWait
#define RTOS_mutexRelease           NUCLEUS_mutexRelease
#define RTOS_mutexFree              NUCLEUS_mutexFree
#define RTOS_getUpTimeInMS          NUCLEUS_getUpTimeInMS
#define RTOS_deltaMS                NUCLEUS_deltaMS
#define RTOS_sleepMS                NUCLEUS_sleepMS
#define RTOS_createThread           NUCLEUS_createThread
#define RTOS_destroyThread          NUCLEUS_destroyThread
#define RTOS_currentThreadId        NUCLEUS_currentThreadId
#define RTOS_timeGMT                NUCLEUS_timeGMT

#elif defined __CYGWIN_RTOS__
#define RTOS_rtosInit               CYGWIN_rtosInit
#define RTOS_rtosShutdown           CYGWIN_rtosShutdown
#define RTOS_mutexCreate            CYGWIN_mutexCreate
#define RTOS_mutexWait              CYGWIN_mutexWait
#define RTOS_mutexRelease           CYGWIN_mutexRelease
#define RTOS_mutexFree              CYGWIN_mutexFree
#define RTOS_getUpTimeInMS          CYGWIN_getUpTimeInMS
#define RTOS_deltaMS                CYGWIN_deltaMS
#define RTOS_deltaConstMS           CYGWIN_deltaConstMS
#define RTOS_timerAddMS             CYGWIN_timerAddMS
#define RTOS_sleepMS                CYGWIN_sleepMS
#define RTOS_createThread           CYGWIN_createThread
#define RTOS_destroyThread          CYGWIN_destroyThread
#define RTOS_currentThreadId        CYGWIN_currentThreadId
#define RTOS_timeGMT                CYGWIN_timeGMT
#define RTOS_condCreate             CYGWIN_condCreate
#define RTOS_condWait               CYGWIN_condWait
#define RTOS_condSignal             CYGWIN_condSignal
#define RTOS_condFree               CYGWIN_condFree

#define RTOS_recursiveMutexCreate   CYGWIN_mutexCreate
#define RTOS_recursiveMutexWait     CYGWIN_mutexWait
#define RTOS_recursiveMutexRelease  CYGWIN_mutexRelease
#define RTOS_recursiveMutexFree     CYGWIN_mutexFree

#elif defined __OSX_RTOS__
#define RTOS_rtosInit               OSX_rtosInit
#define RTOS_rtosShutdown           OSX_rtosShutdown
#define RTOS_mutexCreate            OSX_mutexCreate
#define RTOS_mutexWait              OSX_mutexWait
#define RTOS_mutexRelease           OSX_mutexRelease
#define RTOS_mutexFree              OSX_mutexFree

#ifdef __ENABLE_DIGICERT_GLOBAL_MUTEX__
#define RTOS_globalMutexCreate      OSX_globalMutexCreate
#define RTOS_globalMutexWait        OSX_globalMutexWait
#define RTOS_globalMutexRelease     OSX_globalMutexRelease
#define RTOS_globalMutexFree        OSX_globalMutexFree
#endif

#define RTOS_getUpTimeInMS          OSX_getUpTimeInMS
#define RTOS_deltaMS                OSX_deltaMS
#define RTOS_sleepMS                OSX_sleepMS
#define RTOS_createThread           OSX_createThread
#define RTOS_destroyThread          OSX_destroyThread
#define RTOS_currentThreadId        OSX_currentThreadId
#define RTOS_timeGMT                OSX_timeGMT
#define RTOS_condCreate             OSX_condCreate
#define RTOS_condWait               OSX_condWait
#define RTOS_condSignal             OSX_condSignal
#define RTOS_condFree               OSX_condFree
#define RTOS_getHwAddr              OSX_getHwAddr

#define RTOS_notifierCreate         UNIX_notifierCreate
#define RTOS_notifierWait           UNIX_notifierWait
#define RTOS_notifierTimedWait      UNIX_notifierTimedWait
#define RTOS_notifierNotify         UNIX_notifierNotify
#define RTOS_notifierFree           UNIX_notifierFree

#elif defined __RTOS_THREADX__

/* The startup guard is disabled for two reasons:
 * There will only be a single main Mocana thread
 * The startup checks use memory allocation which is not initialized before RTOS_rtosInit is called
 */
#ifndef __RTOS_AZURE__
#define __DISABLE_DIGICERT_STARTUP_GUARD__
#endif

#define RTOS_rtosInit               THREADX_rtosInit
#define RTOS_rtosShutdown           THREADX_rtosShutdown
#define RTOS_mutexCreate            THREADX_mutexCreate
#define RTOS_mutexWait              THREADX_mutexWait
#define RTOS_mutexWaitEx            THREADX_mutexWaitEx
#define RTOS_mutexRelease           THREADX_mutexRelease
#define RTOS_mutexFree              THREADX_mutexFree
#define RTOS_getUpTimeInMS          THREADX_getUpTimeInMS
#define RTOS_deltaMS                THREADX_deltaMS
#define RTOS_sleepMS                THREADX_sleepMS
#define RTOS_createThread           THREADX_createThread
#define RTOS_destroyThread          THREADX_destroyThread
#define RTOS_currentThreadId        THREADX_currentThreadId
#define RTOS_timeGMT                THREADX_timeGMT
#define RTOS_malloc                 THREADX_malloc
#define RTOS_free                   THREADX_free
#define RTOS_mallocAlign16          THREADX_malloc_Align16
#define RTOS_freeAlign16            THREADX_freeAlign16

/* Underlying mutex implementation uses binary semaphores. Since the mutex and
 * semaphore abstraction uses the same underlying semaphore structure, some of
 * the RTOS_sem* APIs can also be mapped to the mutex APIs.
 */
#define RTOS_semCreate              THREADX_semCreate
#define RTOS_semWait                THREADX_mutexWait
#define RTOS_semTryWait             THREADX_semTryWait
#define RTOS_semSignal              THREADX_mutexRelease
#define RTOS_semFree                THREADX_mutexFree

#elif defined __POSNET_RTOS__
#define RTOS_rtosInit               POSNET_rtosInit
#define RTOS_rtosShutdown           POSNET_rtosShutdown
#define RTOS_mutexCreate            POSNET_mutexCreate
#define RTOS_mutexWait              POSNET_mutexWait
#define RTOS_mutexRelease           POSNET_mutexRelease
#define RTOS_mutexFree              POSNET_mutexFree
#define RTOS_getUpTimeInMS          POSNET_getUpTimeInMS
#define RTOS_deltaMS                POSNET_deltaMS
#define RTOS_sleepMS                POSNET_sleepMS
#define RTOS_createThread           POSNET_createThread
#define RTOS_destroyThread          POSNET_destroyThread
#define RTOS_currentThreadId        POSNET_currentThreadId
#define RTOS_timeGMT                POSNET_timeGMT

#elif defined __OSE_RTOS__
#define RTOS_rtosInit               OSE_rtosInit
#define RTOS_rtosShutdown           OSE_rtosShutdown
#define RTOS_mutexCreate            OSE_mutexCreate
#define RTOS_mutexWait              OSE_mutexWait
#define RTOS_mutexRelease           OSE_mutexRelease
#define RTOS_mutexFree              OSE_mutexFree
#define RTOS_getUpTimeInMS          OSE_getUpTimeInMS
#define RTOS_deltaMS                OSE_deltaMS
#define RTOS_sleepMS                OSE_sleepMS
#define RTOS_createThread           OSE_createThread
#define RTOS_destroyThread          OSE_destroyThread
#define RTOS_currentThreadId        OSE_currentThreadId
#define RTOS_timeGMT                OSE_timeGMT

#elif defined __MQX_RTOS__
#define RTOS_rtosInit               MQX_rtosInit
#define RTOS_rtosShutdown           MQX_rtosShutdown
#define RTOS_mutexCreate            MQX_mutexCreate
#define RTOS_mutexWait              MQX_mutexWait
#define RTOS_mutexRelease           MQX_mutexRelease
#define RTOS_mutexFree              MQX_mutexFree
#define RTOS_getUpTimeInMS          MQX_getUpTimeInMS
#define RTOS_deltaMS                MQX_deltaMS
#define RTOS_sleepMS                MQX_sleepMS
#define RTOS_createThread           MQX_createThread
#define RTOS_destroyThread          MQX_destroyThread
#define RTOS_currentThreadId        MQX_currentThreadId
#define RTOS_timeGMT                MQX_timeGMT
#define RTOS_malloc                 MQX_malloc
#define RTOS_free                   MQX_free

#elif defined __NETBURNER_RTOS__
#define RTOS_rtosInit               NETBURNER_rtosInit
#define RTOS_rtosShutdown           NETBURNER_rtosShutdown
#define RTOS_mutexCreate            NETBURNER_mutexCreate
#define RTOS_mutexWait              NETBURNER_mutexWait
#define RTOS_mutexRelease           NETBURNER_mutexRelease
#define RTOS_mutexFree              NETBURNER_mutexFree
#define RTOS_getUpTimeInMS          NETBURNER_getUpTimeInMS
#define RTOS_deltaMS                NETBURNER_deltaMS
#define RTOS_sleepMS                NETBURNER_sleepMS
#define RTOS_createThread           NETBURNER_createThread
#define RTOS_destroyThread          NETBURNER_destroyThread
#define RTOS_currentThreadId        NETBURNER_currentThreadId
#define RTOS_timeGMT                NETBURNER_timeGMT

#elif defined __OPENBSD_RTOS__
#define RTOS_rtosInit               OPENBSD_rtosInit
#define RTOS_rtosShutdown           OPENBSD_rtosShutdown
#define RTOS_mutexCreate            OPENBSD_mutexCreate
#define RTOS_mutexWait              OPENBSD_mutexWait
#define RTOS_mutexRelease           OPENBSD_mutexRelease
#define RTOS_mutexFree              OPENBSD_mutexFree
#define RTOS_getUpTimeInMS          OPENBSD_getUpTimeInMS
#define RTOS_deltaMS                OPENBSD_deltaMS
#define RTOS_deltaConstMS           OPENBSD_deltaConstMS
#define RTOS_timerAddMS             OPENBSD_timerAddMS
#define RTOS_sleepMS                OPENBSD_sleepMS
#define RTOS_createThread           OPENBSD_createThread
#define RTOS_destroyThread          OPENBSD_destroyThread
#define RTOS_currentThreadId        OPENBSD_currentThreadId
#define RTOS_timeGMT                OPENBSD_timeGMT

#elif defined __NUTOS_RTOS__
#define RTOS_rtosInit               NUTOS_rtosInit
#define RTOS_rtosShutdown           NUTOS_rtosShutdown
#define RTOS_mutexCreate            NUTOS_mutexCreate
#define RTOS_mutexWait              NUTOS_mutexWait
#define RTOS_mutexRelease           NUTOS_mutexRelease
#define RTOS_mutexFree              NUTOS_mutexFree
#define RTOS_getUpTimeInMS          NUTOS_getUpTimeInMS
#define RTOS_deltaMS                NUTOS_deltaMS
#define RTOS_sleepMS                NUTOS_sleepMS
#define RTOS_createThread           NUTOS_createThread
#define RTOS_destroyThread          NUTOS_destroyThread
#define RTOS_currentThreadId        NUTOS_currentThreadId
#define RTOS_timeGMT                NUTOS_timeGMT

#elif defined __INTEGRITY_RTOS__
#define RTOS_rtosInit               INTEGRITY_rtosInit
#define RTOS_rtosShutdown           INTEGRITY_rtosShutdown
#define RTOS_mutexCreate            INTEGRITY_mutexCreate
#define RTOS_mutexWait              INTEGRITY_mutexWait
#define RTOS_mutexRelease           INTEGRITY_mutexRelease
#define RTOS_mutexFree              INTEGRITY_mutexFree
#define RTOS_getUpTimeInMS          INTEGRITY_getUpTimeInMS
#define RTOS_deltaMS                INTEGRITY_deltaMS
#define RTOS_sleepMS                INTEGRITY_sleepMS
#define RTOS_createThread           INTEGRITY_createThread
#define RTOS_destroyThread          INTEGRITY_destroyThread
#define RTOS_currentThreadId        INTEGRITY_currentThreadId
#define RTOS_timeGMT                INTEGRITY_timeGMT

#elif defined __UITRON_RTOS__
#define RTOS_rtosInit               UITRON_rtosInit
#define RTOS_rtosShutdown           UITRON_rtosShutdown
#define RTOS_mutexCreate            UITRON_mutexCreate
#define RTOS_mutexWait              UITRON_mutexWait
#define RTOS_mutexRelease           UITRON_mutexRelease
#define RTOS_mutexFree              UITRON_mutexFree
#define RTOS_getUpTimeInMS          UITRON_getUpTimeInMS
#define RTOS_deltaMS                UITRON_deltaMS
#define RTOS_sleepMS                UITRON_sleepMS
#define RTOS_createThread           UITRON_createThread
#define RTOS_destroyThread          UITRON_destroyThread
#define RTOS_currentThreadId        UITRON_currentThreadId
#define RTOS_timeGMT                UITRON_timeGMT

#elif defined __FREEBSD_RTOS__
#define RTOS_rtosInit               FREEBSD_rtosInit
#define RTOS_rtosShutdown           FREEBSD_rtosShutdown
#define RTOS_mutexCreate            FREEBSD_mutexCreate
#define RTOS_mutexWait              FREEBSD_mutexWait
#define RTOS_mutexRelease           FREEBSD_mutexRelease
#define RTOS_mutexFree              FREEBSD_mutexFree
#define RTOS_getUpTimeInMS          FREEBSD_getUpTimeInMS
#define RTOS_deltaMS                FREEBSD_deltaMS
#define RTOS_deltaConstMS           FREEBSD_deltaConstMS
#define RTOS_timerAddMS             FREEBSD_timerAddMS
#define RTOS_sleepMS                FREEBSD_sleepMS
#define RTOS_createThread           FREEBSD_createThread
#define RTOS_destroyThread          FREEBSD_destroyThread
#define RTOS_currentThreadId        FREEBSD_currentThreadId
#define RTOS_timeGMT                FREEBSD_timeGMT

#elif defined __IRIX_RTOS__
#define RTOS_rtosInit               IRIX_rtosInit
#define RTOS_rtosShutdown           IRIX_rtosShutdown
#define RTOS_mutexCreate            IRIX_mutexCreate
#define RTOS_mutexWait              IRIX_mutexWait
#define RTOS_mutexRelease           IRIX_mutexRelease
#define RTOS_mutexFree              IRIX_mutexFree
#define RTOS_getUpTimeInMS          IRIX_getUpTimeInMS
#define RTOS_deltaMS                IRIX_deltaMS
#define RTOS_deltaConstMS           IRIX_deltaConstMS
#define RTOS_timerAddMS             IRIX_timerAddMS
#define RTOS_sleepMS                IRIX_sleepMS
#define RTOS_createThread           IRIX_createThread
#define RTOS_destroyThread          IRIX_destroyThread
#define RTOS_currentThreadId        IRIX_currentThreadId
#define RTOS_timeGMT                IRIX_timeGMT

#elif defined __QNX_RTOS__
/* Define RTOS_THREAD as a ubyte4 only for QNX 7 */
#ifdef __RTOS_QNX_7__
typedef ubyte4 RTOS_THREAD;
#define RTOS_THREAD_INVALID         0
#endif
#define RTOS_rtosInit               QNX_rtosInit
#define RTOS_rtosShutdown           QNX_rtosShutdown
#define RTOS_mutexCreate            QNX_mutexCreate
#define RTOS_mutexWait              QNX_mutexWait
#define RTOS_mutexWaitEx            QNX_mutexWaitEx
#define RTOS_mutexRelease           QNX_mutexRelease
#define RTOS_mutexFree              QNX_mutexFree
#define RTOS_getUpTimeInMS          QNX_getUpTimeInMS
#define RTOS_deltaMS                QNX_deltaMS
#define RTOS_deltaConstMS           QNX_deltaConstMS
#define RTOS_timerAddMS             QNX_timerAddMS
#define RTOS_sleepMS                QNX_sleepMS
#define RTOS_createThread           QNX_createThread
#define RTOS_destroyThread          QNX_destroyThread
#define RTOS_currentThreadId        QNX_currentThreadId
#define RTOS_timeGMT                QNX_timeGMT
#define RTOS_malloc                 QNX_malloc
#define RTOS_free                   QNX_free

#define RTOS_semCreate              QNX_semCreate
#define RTOS_semWait                QNX_mutexWait
#define RTOS_semTryWait             QNX_semTryWait
#define RTOS_semSignal              QNX_mutexRelease
#define RTOS_semFree                QNX_mutexFree

#elif defined __UITRON_RTOS__
#define RTOS_rtosInit               UITRON_rtosInit
#define RTOS_rtosShutdown           UITRON_rtosShutdown
#define RTOS_mutexCreate            UITRON_mutexCreate
#define RTOS_mutexWait              UITRON_mutexWait
#define RTOS_mutexRelease           UITRON_mutexRelease
#define RTOS_mutexFree              UITRON_mutexFree
#define RTOS_getUpTimeInMS          UITRON_getUpTimeInMS
#define RTOS_deltaMS                UITRON_deltaMS
#define RTOS_deltaConstMS           UITRON_deltaConstMS
#define RTOS_timerAddMS             UITRON_timerAddMS
#define RTOS_sleepMS                UITRON_sleepMS
#define RTOS_createThread           UITRON_createThread
#define RTOS_destroyThread          UITRON_destroyThread
#define RTOS_currentThreadId        UITRON_currentThreadId
#define RTOS_timeGMT                UITRON_timeGMT

#elif defined __WINCE_RTOS__
#define RTOS_rtosInit               WINCE_rtosInit
#define RTOS_rtosShutdown           WINCE_rtosShutdown
#define RTOS_mutexCreate            WINCE_mutexCreate
#define RTOS_mutexWait              WINCE_mutexWait
#define RTOS_mutexRelease           WINCE_mutexRelease
#define RTOS_mutexFree              WINCE_mutexFree
#define RTOS_getUpTimeInMS          WINCE_getUpTimeInMS
#define RTOS_deltaMS                WINCE_deltaMS
#define RTOS_deltaConstMS           WINCE_deltaConstMS
#define RTOS_timerAddMS             WINCE_timerAddMS
#define RTOS_sleepMS                WINCE_sleepMS
#define RTOS_createThread           WINCE_createThread
#define RTOS_destroyThread          WINCE_destroyThread
#define RTOS_currentThreadId        WINCE_currentThreadId
#define RTOS_timeGMT                WINCE_timeGMT

#elif defined __WTOS_RTOS__
#define RTOS_rtosInit               WTOS_rtosInit
#define RTOS_rtosShutdown           WTOS_rtosShutdown
#define RTOS_mutexCreate            WTOS_mutexCreate
#define RTOS_mutexWait              WTOS_mutexWait
#define RTOS_mutexRelease           WTOS_mutexRelease
#define RTOS_mutexFree              WTOS_mutexFree
#define RTOS_getUpTimeInMS          WTOS_getUpTimeInMS
#define RTOS_deltaMS                WTOS_deltaMS
#define RTOS_sleepMS                WTOS_sleepMS
#define RTOS_createThread           WTOS_createThread
#define RTOS_destroyThread          WTOS_destroyThread
#define RTOS_currentThreadId        WTOS_currentThreadId
#define RTOS_timeGMT

#elif defined __ECOS_RTOS__
#define RTOS_rtosInit               ECOS_rtosInit
#define RTOS_rtosShutdown           ECOS_rtosShutdown
#define RTOS_mutexCreate            ECOS_mutexCreate
#define RTOS_mutexWait              ECOS_mutexWait
#define RTOS_mutexRelease           ECOS_mutexRelease
#define RTOS_mutexFree              ECOS_mutexFree
#define RTOS_getUpTimeInMS          ECOS_getUpTimeInMS
#define RTOS_deltaMS                ECOS_deltaMS
#define RTOS_deltaConstMS           ECOS_deltaConstMS
#define RTOS_timerAddMS             ECOS_timerAddMS
#define RTOS_sleepMS                ECOS_sleepMS
#define RTOS_createThread           ECOS_createThread
#define RTOS_destroyThread          ECOS_destroyThread
#define RTOS_currentThreadId        ECOS_currentThreadId
#define RTOS_timeGMT                ECOS_timeGMT

#elif defined __FREERTOS_RTOS__
#define RTOS_rtosInit               FREERTOS_rtosInit
#define RTOS_rtosShutdown           FREERTOS_rtosShutdown
#define RTOS_mutexCreate            FREERTOS_mutexCreate
#define RTOS_mutexWait              FREERTOS_mutexWait
#define RTOS_mutexWaitEx            FREERTOS_mutexWaitEx
#define RTOS_mutexRelease           FREERTOS_mutexRelease
#define RTOS_mutexFree              FREERTOS_mutexFree
#define RTOS_getUpTimeInMS          FREERTOS_getUpTimeInMS
#define RTOS_deltaMS                FREERTOS_deltaMS
#define RTOS_deltaConstMS           FREERTOS_deltaConstMS
#define RTOS_timerAddMS             FREERTOS_timerAddMS
#define RTOS_sleepMS                FREERTOS_sleepMS
#define RTOS_createThread           FREERTOS_createThread
#define RTOS_destroyThread          FREERTOS_destroyThread
#define RTOS_currentThreadId        FREERTOS_currentThreadId
#define RTOS_timeGMT                FREERTOS_timeGMT
#define RTOS_recursiveMutexCreate   FREERTOS_recursiveMutexCreate
#define RTOS_recursiveMutexWait     FREERTOS_recursiveMutexWait
#define RTOS_recursiveMutexRelease  FREERTOS_recursiveMutexRelease
#define RTOS_recursiveMutexFree     FREERTOS_recursiveMutexFree
#define RTOS_startScheduler         FREERTOS_startScheduler
#define RTOS_stopScheduler          FREERTOS_stopScheduler
#define RTOS_taskSuspend            FREERTOS_taskSuspend
#define RTOS_taskResume             FREERTOS_taskResume
#define RTOS_malloc                 FREERTOS_malloc
#define RTOS_free                   FREERTOS_free
#define RTOS_setTimeGMT             FREERTOS_setTimeGMT
#define RTOS_semCreate              FREERTOS_semCreate
#define RTOS_semWait                FREERTOS_mutexWait
#define RTOS_semTryWait             FREERTOS_semTryWait
#define RTOS_semSignal              FREERTOS_mutexRelease
#define RTOS_semFree                FREERTOS_mutexFree

#elif defined (__AIX_RTOS__ )
#define RTOS_rtosInit               AIX_rtosInit
#define RTOS_rtosShutdown           AIX_rtosShutdown
#define RTOS_mutexCreate            AIX_mutexCreate
#define RTOS_mutexWait              AIX_mutexWait
#define RTOS_mutexRelease           AIX_mutexRelease
#define RTOS_mutexFree              AIX_mutexFree
#define RTOS_getUpTimeInMS          AIX_getUpTimeInMS
#define RTOS_deltaMS                AIX_deltaMS
#define RTOS_deltaConstMS           AIX_deltaConstMS
#define RTOS_timerAddMS             AIX_timerAddMS
#define RTOS_sleepMS                AIX_sleepMS
#define RTOS_createThread           AIX_createThread
#define RTOS_destroyThread          AIX_destroyThread
#define RTOS_currentThreadId        AIX_currentThreadId
#define RTOS_timeGMT                AIX_timeGMT

#elif defined (__HPUX_RTOS__ )
#define RTOS_rtosInit               HPUX_rtosInit
#define RTOS_rtosShutdown           HPUX_rtosShutdown
#define RTOS_mutexCreate            HPUX_mutexCreate
#define RTOS_mutexWait              HPUX_mutexWait
#define RTOS_mutexRelease           HPUX_mutexRelease
#define RTOS_mutexFree              HPUX_mutexFree
#define RTOS_getUpTimeInMS          HPUX_getUpTimeInMS
#define RTOS_deltaMS                HPUX_deltaMS
#define RTOS_deltaConstMS           HPUX_deltaConstMS
#define RTOS_timerAddMS             HPUX_timerAddMS
#define RTOS_sleepMS                HPUX_sleepMS
#define RTOS_createThread           HPUX_createThread
#define RTOS_destroyThread          HPUX_destroyThread
#define RTOS_currentThreadId        HPUX_currentThreadId
#define RTOS_timeGMT                HPUX_timeGMT

#elif defined (__QUADROS_RTOS__)
#define RTOS_rtosInit               QUADROS_rtosInit
#define RTOS_rtosShutdown           QUADROS_rtosShutdown
#define RTOS_mutexCreate            QUADROS_mutexCreate
#define RTOS_mutexWait              QUADROS_mutexWait
#define RTOS_mutexRelease           QUADROS_mutexRelease
#define RTOS_mutexFree              QUADROS_mutexFree
#define RTOS_getUpTimeInMS          QUADROS_getUpTimeInMS
#define RTOS_deltaMS                QUADROS_deltaMS
#define RTOS_deltaConstMS           QUADROS_deltaConstMS
#define RTOS_timerAddMS             QUADROS_timerAddMS
#define RTOS_sleepMS                QUADROS_sleepMS
#define RTOS_createThread           QUADROS_createThread
#define RTOS_destroyThread          QUADROS_destroyThread
#define RTOS_currentThreadId        QUADROS_currentThreadId
#define RTOS_timeGMT                QUADROS_timeGMT

#elif defined (__UCOS_RTOS__)
#define RTOS_rtosInit               UCOS_rtosInit
#define RTOS_rtosShutdown           UCOS_rtosShutdown
#define RTOS_mutexCreate            UCOS_mutexCreate
#define RTOS_mutexWait              UCOS_mutexWait
#define RTOS_mutexWaitEx            UCOS_mutexWaitEx
#define RTOS_mutexRelease           UCOS_mutexRelease
#define RTOS_mutexFree              UCOS_mutexFree
#define RTOS_getUpTimeInMS          UCOS_getUpTimeInMS
#define RTOS_deltaMS                UCOS_deltaMS
#define RTOS_deltaConstMS           UCOS_deltaConstMS
#define RTOS_timerAddMS             UCOS_timerAddMS
#define RTOS_sleepMS                UCOS_sleepMS
#define RTOS_createThread           UCOS_createThread
#define RTOS_destroyThread          UCOS_destroyThread
#define RTOS_currentThreadId        UCOS_currentThreadId
#define RTOS_timeGMT                UCOS_timeGMT
#define RTOS_semCreate              UCOS_semCreate
#define RTOS_semWait                UCOS_semWait
#define RTOS_semSignal              UCOS_semSignal
#define RTOS_semFree                UCOS_semFree

#elif defined (__UCOS_DIRECT_RTOS__)
#define RTOS_rtosInit               UCOS_rtosInit
#define RTOS_rtosShutdown           UCOS_rtosShutdown
#define RTOS_mutexCreate            UCOS_mutexCreate
#define RTOS_mutexWait              UCOS_mutexWait
#define RTOS_mutexRelease           UCOS_mutexRelease
#define RTOS_mutexFree              UCOS_mutexFree
#define RTOS_getUpTimeInMS          UCOS_getUpTimeInMS
#define RTOS_deltaMS                UCOS_deltaMS
#define RTOS_deltaConstMS           UCOS_deltaConstMS
#define RTOS_timerAddMS             UCOS_timerAddMS
#define RTOS_sleepMS                UCOS_sleepMS
#define RTOS_createThread           UCOS_createThread
#define RTOS_destroyThread          UCOS_destroyThread
#define RTOS_currentThreadId        UCOS_currentThreadId
#define RTOS_timeGMT                UCOS_timeGMT

#elif defined __DEOS_RTOS__
#define RTOS_rtosInit               DEOS_rtosInit
#define RTOS_rtosShutdown           DEOS_rtosShutdown
#define RTOS_mutexCreate            DEOS_mutexCreate
#define RTOS_mutexWait              DEOS_mutexWait
#define RTOS_mutexRelease           DEOS_mutexRelease
#define RTOS_mutexFree              DEOS_mutexFree
#define RTOS_getUpTimeInMS          DEOS_getUpTimeInMS
#define RTOS_deltaMS                DEOS_deltaMS
#define RTOS_deltaConstMS           DEOS_deltaConstMS
/* #define RTOS_timerAddMS             DEOS_timerAddMS */
#define RTOS_sleepMS                DEOS_sleepMS
#define RTOS_createThread           DEOS_createThread
#define RTOS_destroyThread          DEOS_destroyThread
#define RTOS_currentThreadId        DEOS_currentThreadId
#define RTOS_timeGMT                DEOS_timeGMT

#elif defined __DUMMY_RTOS__
#define RTOS_rtosInit               DUMMY_rtosInit
#define RTOS_rtosShutdown           DUMMY_rtosShutdown
#define RTOS_mutexCreate            DUMMY_mutexCreate
#define RTOS_mutexWait              DUMMY_mutexWait
#define RTOS_mutexRelease           DUMMY_mutexRelease
#define RTOS_mutexFree              DUMMY_mutexFree
#define RTOS_getUpTimeInMS          DUMMY_getUpTimeInMS
#define RTOS_deltaMS                DUMMY_deltaMS
#define RTOS_sleepMS                DUMMY_sleepMS
#define RTOS_createThread           DUMMY_createThread
#define RTOS_destroyThread          DUMMY_destroyThread
#define RTOS_currentThreadId        DUMMY_currentThreadId
#define RTOS_timeGMT                DUMMY_timeGMT
#define RTOS_deltaConstMS           DUMMY_deltaConstMS
#define RTOS_timerAddMS             DUMMY_timerAddMS

#elif defined (__ENABLE_DIGICERT_SEC_BOOT__)

/* Nanoboot does not require any OS */

#else

#error UNSUPPORTED PLATFORM

#endif
#endif /* !RTOS_CUSTOM */

#if defined (__MOC_PLATFORM_MODULE__)
MOC_EXTERN int      DIGI_rtosInit(void);
MOC_EXTERN int      DIGI_rtosShutdown(void);
MOC_EXTERN int      DIGI_mutexCreate2(RTOS_MUTEX* pMutex, int mutexCount);
MOC_EXTERN int      DIGI_mutexWait(RTOS_MUTEX mutex);
MOC_EXTERN int      DIGI_mutexRelease(RTOS_MUTEX mutex);
MOC_EXTERN int      DIGI_mutexFree(RTOS_MUTEX* pMutex);
MOC_EXTERN ubyte4   DIGI_getUpTimeInMS(void);
MOC_EXTERN ubyte4   DIGI_deltaMS(const moctime_t *pPrevTime, moctime_t *pRetCurrentTime);
MOC_EXTERN void     DIGI_sleepMS(ubyte4 sleepTimeInMS);
MOC_EXTERN int      DIGI_timeGMT(TimeDate* td);
MOC_EXTERN sbyte4   DIGI_readVFS(void *f, char *b, ubyte4 bLen, ubyte8 *off);
#endif

MOC_EXTERN MSTATUS      RTOS_rtosInit               (void);
MOC_EXTERN MSTATUS      RTOS_rtosShutdown           (void);
MOC_EXTERN MSTATUS      RTOS_mutexCreate            (RTOS_MUTEX* pMutex, enum mutexTypes mutexType, int mutexCount);
MOC_EXTERN MSTATUS      RTOS_mutexWait              (RTOS_MUTEX mutex);
MOC_EXTERN MSTATUS      RTOS_mutexRelease           (RTOS_MUTEX mutex);
MOC_EXTERN MSTATUS      RTOS_mutexFree              (RTOS_MUTEX* pMutex);
MOC_EXTERN MSTATUS      RTOS_mutexWaitEx            (RTOS_MUTEX mutex, ubyte4 timeoutMs);

MOC_EXTERN MSTATUS      RTOS_semCreate              (RTOS_SEM *sem, sbyte4 initialValue);
MOC_EXTERN MSTATUS      RTOS_semWait                (RTOS_SEM sem);
MOC_EXTERN MSTATUS      RTOS_semTimedWait           (RTOS_SEM sem, ubyte4 timeoutMS, byteBoolean *pTimeout);
MOC_EXTERN MSTATUS      RTOS_semTryWait             (RTOS_SEM sem);
MOC_EXTERN MSTATUS      RTOS_semSignal              (RTOS_SEM sem);
MOC_EXTERN MSTATUS      RTOS_semFree                (RTOS_SEM *pSem);

#ifdef __ENABLE_DIGICERT_GLOBAL_MUTEX__
MOC_EXTERN MSTATUS      RTOS_globalMutexCreate      (char *mutexName, RTOS_GLOBAL_MUTEX* pMutex);
MOC_EXTERN MSTATUS      RTOS_globalMutexWait        (RTOS_GLOBAL_MUTEX mutex, ubyte4 timeout);
MOC_EXTERN MSTATUS      RTOS_globalMutexRelease     (RTOS_GLOBAL_MUTEX mutex);
MOC_EXTERN MSTATUS      RTOS_globalMutexFree        (char *mutexName, RTOS_GLOBAL_MUTEX* pMutex);
#endif

MOC_EXTERN MSTATUS      RTOS_lockFileCreate         (char *pLockFile, RTOS_LOCK *ppLock);
MOC_EXTERN MSTATUS      RTOS_lockFileAcquire        (RTOS_LOCK pLock);
MOC_EXTERN MSTATUS      RTOS_lockFileRelease        (RTOS_LOCK pLock);
MOC_EXTERN MSTATUS      RTOS_lockFileFree           (RTOS_LOCK *ppLock);

MOC_EXTERN MSTATUS      RTOS_condCreate             (RTOS_COND* pcond, enum mutexTypes mutexType, int mutexCount);
MOC_EXTERN MSTATUS      RTOS_condWait               (RTOS_COND  cond,RTOS_MUTEX mutex);
MOC_EXTERN MSTATUS      RTOS_condTimedWait          (RTOS_COND  cond,RTOS_MUTEX mutex, ubyte4 timeoutMS, byteBoolean *pTimeout);
MOC_EXTERN MSTATUS      RTOS_condSignal             (RTOS_COND mutex);
MOC_EXTERN MSTATUS      RTOS_condFree               (RTOS_MUTEX* pCond);
MOC_EXTERN ubyte4       RTOS_getUpTimeInMS          (void);
MOC_EXTERN ubyte4       RTOS_deltaMS                (const moctime_t *pPrevTime, moctime_t *pRetCurrentTime);
MOC_EXTERN ubyte4       RTOS_deltaConstMS           (const moctime_t* origin, const moctime_t* cur);
MOC_EXTERN moctime_t*   RTOS_timerAddMS             (moctime_t* pTimer, ubyte4 addNumMS);
MOC_EXTERN void         RTOS_sleepMS                (ubyte4 sleepTimeInMS);
MOC_EXTERN intBoolean   RTOS_sleepCheckStatusMS     (ubyte4 sleepTimeInMS);
MOC_EXTERN sbyte4       RTOS_timeCompare            (const moctime_t *pTime1, const moctime_t *pTime2);
MOC_EXTERN MSTATUS      RTOS_createThread           (void(*threadEntry)(void*), void* context, ubyte4 threadType, RTOS_THREAD *pRetTid);
MOC_EXTERN void         RTOS_destroyThread          (RTOS_THREAD tid);
MOC_EXTERN void         RTOS_exitThread             (void *pRetVal);
MOC_EXTERN MSTATUS      RTOS_joinThread             (RTOS_THREAD tid, void **ppRetVal);
MOC_EXTERN MSTATUS      RTOS_timeGMT                (TimeDate* td);
MOC_EXTERN void         RTOS_setTimeGMT(TimeDate* td);

MOC_EXTERN MSTATUS      RTOS_processExecute         (sbyte *pCmd, sbyte **ppOutput);
MOC_EXTERN MSTATUS      RTOS_processExecuteWithArg  (sbyte *pCmd, sbyte *pArg, sbyte **ppOutput);

#if (defined(__LINUX_RTOS__) || defined(__ANDROID_RTOS__)) && !defined(__KERNEL__)
MOC_EXTERN RTOS_THREAD  RTOS_currentThreadId        (void);
MOC_EXTERN intBoolean   RTOS_sameThreadId           (RTOS_THREAD tid1, RTOS_THREAD tid2);
#endif
#if defined(__RTOS_WIN32__)
MOC_EXTERN sbyte4  RTOS_currentThreadId(void);
#endif
#if defined(__QNX_RTOS__)
MOC_EXTERN RTOS_THREAD  RTOS_currentThreadId(void);
#endif
MOC_EXTERN MSTATUS      RTOS_rwLockCreate           (RTOS_RWLOCK* pLock);
MOC_EXTERN MSTATUS      RTOS_rwLockWaitR            (RTOS_RWLOCK lock);
MOC_EXTERN MSTATUS      RTOS_rwLockReleaseR         (RTOS_RWLOCK lock);
MOC_EXTERN MSTATUS      RTOS_rwLockWaitW            (RTOS_RWLOCK lock);
MOC_EXTERN intBoolean   RTOS_rwLockOwnerW           (RTOS_RWLOCK lock);
MOC_EXTERN MSTATUS      RTOS_rwLockReleaseW         (RTOS_RWLOCK lock);
MOC_EXTERN MSTATUS      RTOS_rwLockFree             (RTOS_RWLOCK* pLock);

MOC_EXTERN MSTATUS      RTOS_recursiveMutexCreate   (RTOS_MUTEX* pMutex, enum mutexTypes mutexType, int mutexCount);
MOC_EXTERN MSTATUS      RTOS_recursiveMutexWait     (RTOS_MUTEX mutex);
MOC_EXTERN MSTATUS      RTOS_recursiveMutexRelease  (RTOS_MUTEX mutex);
MOC_EXTERN MSTATUS      RTOS_recursiveMutexFree     (RTOS_MUTEX* pMutex);
MOC_EXTERN MSTATUS      RTOS_getHwAddr              (ubyte *macAddr, ubyte4 len);

MOC_EXTERN MSTATUS      RTOS_getHwAddrByIfname(const sbyte *ifname, sbyte *adapter_name, ubyte *macAddr, ubyte4 len);


#if defined (RTOS_notifierCreate)
MOC_EXTERN RTOS_NOTIFIER_t RTOS_notifierCreate(void);
MOC_EXTERN MSTATUS        RTOS_notifierWait(RTOS_NOTIFIER_t notifier);
MOC_EXTERN MSTATUS        RTOS_notifierNotify(RTOS_NOTIFIER_t notifier, void* value);
MOC_EXTERN MSTATUS        RTOS_notifierTimedWait(RTOS_NOTIFIER_t notifier, RTOS_TIMEVAL timeout);
MOC_EXTERN MSTATUS        RTOS_notifierFree(RTOS_NOTIFIER_t notifier);
#endif

#ifdef __FREERTOS_RTOS__
/* For RTOS's that have scheduler and thread suspending functions */
MOC_EXTERN MSTATUS      RTOS_startScheduler         (void);
MOC_EXTERN MSTATUS      RTOS_stopScheduler          (void);
MOC_EXTERN MSTATUS      RTOS_taskSuspend            (RTOS_THREAD tid);
MOC_EXTERN MSTATUS      RTOS_taskResume             (RTOS_THREAD tid);
#endif

#ifdef RTOS_malloc
MOC_EXTERN void*        RTOS_malloc                 (ubyte4 bufsize);
#endif
#ifdef RTOS_free
MOC_EXTERN void         RTOS_free                   (void *p);
#endif

/* see mrtos.c: easy to use wrappers for RTOS_mutexWait() and RTOS_mutexRelease() */
MOC_EXTERN MSTATUS MRTOS_mutexWait(RTOS_MUTEX mutex, intBoolean *pIsMutexSet);
MOC_EXTERN MSTATUS MRTOS_mutexRelease(RTOS_MUTEX mutex, intBoolean *pIsMutexSet);

#ifdef __ENABLE_DIGICERT_GLOBAL_MUTEX__
MOC_EXTERN MSTATUS MRTOS_globalMutexWait(RTOS_GLOBAL_MUTEX mutex,
        intBoolean *pIsMutexSet, ubyte4 timeoutInSecs);
MOC_EXTERN MSTATUS MRTOS_globalMutexRelease(RTOS_GLOBAL_MUTEX mutex, intBoolean *pIsMutexSet);
#endif

#ifdef __ENABLE_DIGICERT_DEBUG_MEMORY__

#define MALLOC(X)       CONVERT_MALLOC((X))
#define FREE(X)         CONVERT_FREE((X))
#define MC_MALLOC(X)    dbg_malloc((X), (ubyte *)__FILE__, __LINE__)
#define MC_MALLOC_ALIGN(X, Y) dbg_malloc_align((X), (Y), (ubyte *)__FILE__, __LINE__)
#define MC_FREE(X)      dbg_free((void *)(X), (ubyte *)__FILE__, __LINE__)

/* dbg_dump_stat is just like dbg_dump, except it also prints out data on the
 * sizes of memory allocated. It will print out a list of sizes allocated and the
 * number of times that size was allocated.
 */
MOC_EXTERN void  dbg_dump_stat(void);
MOC_EXTERN void  dbg_dump(void);
MOC_EXTERN void* dbg_malloc(ubyte4 numBytes, ubyte *pFile, ubyte4 lineNum);
MOC_EXTERN void* dbg_malloc_align(ubyte4 numBytes, ubyte4 align, ubyte *pFile, ubyte4 lineNum);
MOC_EXTERN void  dbg_free(void *pBlockToFree, ubyte *pFile, ubyte4 lineNum);

#define DBG_DUMP dbg_dump ();

/* To prevent warnings with GNU or errors with MSVC++
   (with this compiler, we enforce that functions must be
   declared before being used), make sure we include
   stdlib.h */
#if (defined(__KERNEL__) && (defined(__LINUX_RTOS__) || defined(__ANDROID_RTOS__)))
    #include <linux/types.h>
    void *malloc(size_t size);
    void free(void *ptr);
#elif defined(__ENABLE_DIGICERT_IPSEC_SERVICE__) && defined(__WIN32_RTOS__) && (defined(_NTDDK_) || defined(_NTIFS_) || defined(_NDIS_))
    MOC_EXTERN void* malloc(unsigned int);
    MOC_EXTERN void free(void *);
#elif defined(__MOC_IPV4_STACK__) || defined(__QNX_RTOS__)
#elif defined(__ENABLE_DIGICERT_FREESTANDING__)
#elif defined(__GNUC__) || defined(_MSC_VER)
    #include <stdlib.h>
#endif

#else

#define DBG_DUMP

#ifndef MALLOC
#ifdef RTOS_malloc
#define MALLOC                      CONVERT_MALLOC
#define MC_MALLOC                   RTOS_malloc
#else
#define MALLOC                      CONVERT_MALLOC
#if defined(__ENABLE_DIGICERT_CUSTOM_MALLOC__) && defined(__RTOS_ZEPHYR__)
#define MC_MALLOC                   DIGICERT_customMalloc
#elif defined(__ENABLE_DIGICERT_K_MALLOC__) && defined(__RTOS_ZEPHYR__)
#define MC_MALLOC                   k_malloc
#else
#define MC_MALLOC                   malloc
#endif /* __ENABLE_DIGICERT_K_MALLOC__ */
#endif
#endif

#ifndef FREE
#ifdef RTOS_free
#define FREE                        CONVERT_FREE
#define MC_FREE                     RTOS_free
#else
#define FREE                        CONVERT_FREE
#if defined(__ENABLE_DIGICERT_CUSTOM_MALLOC__) && defined(__RTOS_ZEPHYR__)
#define MC_FREE                     DIGICERT_customFree
#elif defined(__ENABLE_DIGICERT_K_MALLOC__) && defined(__RTOS_ZEPHYR__)
#define MC_FREE                     k_free
#else
#define MC_FREE                     free
#endif /* __ENABLE_DIGICERT_K_MALLOC__ */
#endif
#endif

#if defined (__FREERTOS_RTOS__)
#define IS_FILE_DIRECTORY(x)       (((FILINFO *)x)->fattrib & AM_DIR)
#elif defined (__LINUX_RTOS__)
#define IS_FILE_DIRECTORY(x)       (((struct dirent *)x)->d_type == DT_DIR)
#endif

#if defined (__FREERTOS_RTOS__)
#define FILEINFO_FILE_NAME(x)       (((FILINFO *)x)->fname)
#elif defined (__LINUX_RTOS__)
#define FILEINFO_FILE_NAME(x)       (((struct dirent *)x)->d_name)
#endif

/* To prevent warnings with GNU or errors with MSVC++
   (with this compiler, we enforce that functions must be
   declared before being used), make sure we include
   stdlib.h */
#if (defined(__KERNEL__) && (defined(__LINUX_RTOS__) || defined(__ANDROID_RTOS__)))
    #include <linux/types.h>
    void *malloc(size_t size);
    void free(void *ptr);
#elif defined(__ENABLE_DIGICERT_IPSEC_SERVICE__) && defined(__WIN32_RTOS__) && (defined(_NTDDK_) || defined(_NTIFS_) || defined(_NDIS_))
    MOC_EXTERN void* malloc(unsigned int);
    MOC_EXTERN void free(void *);
#elif defined(__MOC_IPV4_STACK__) || defined(__QNX_RTOS__)
#elif defined(__ENABLE_DIGICERT_FREESTANDING__)
#elif defined(__GNUC__) || defined(_MSC_VER)
    #include <stdlib.h>
#endif

#endif /* __ENABLE_DIGICERT_DEBUG_MEMORY__ */

/*----------------------------------------------------------------------------*/

/* These macros expand to calls to rtosInit and rtosShutdown if needed, or to
 * nothing if not needed.
 */
#if !(defined(__KERNEL__) || defined(_KERNEL) || defined(IPCOM_KERNEL))

/**
 * @def      MOC_RTOS_INIT(_status)
 * @details  This macro will initialize platform specific functions.
 *
 * @param _status   The \ref MSTATUS value for return from the calling function.
 *
 * @par Flags
 * To enable this macro, \b one of the following conditions must be met:
 *   + \c \__KERNEL__   must \b not be defined
 *   + \c _KERNEL       \b must be defined
 *   + \c IPCOM_KERNEL  \b must be defined
 */
#define MOC_RTOS_INIT(_status)                                                 \
    _status = RTOS_rtosInit ();                                                \
    if (OK != status)                                                          \
      goto exit;

/**
 * @def      MOC_RTOS_SHUTDOWN(_status,_dStatus)
 * @details  This macro will uninitialize platform specific functions.
 *
 * @param _status   The \ref MSTATUS value for return from the calling function.
 * @param _dStatus  The temporary placeholder status used to check return values.
 *
 * @par Flags
 * To enable this macro, \b one of the following conditions must be met:
 *   + \c \__KERNEL__   must \b not be defined
 *   + \c _KERNEL       \b must be defined
 *   + \c IPCOM_KERNEL  \b must be defined
 */
#define MOC_RTOS_SHUTDOWN(_status,_dStatus)                                    \
    _dStatus = RTOS_rtosShutdown ();                                           \
    if (OK != _dStatus)                                                        \
      _status = _dStatus;

#else /* !(defined(__KERNEL__) etc. */

#define MOC_RTOS_INIT(_status)
#define MOC_RTOS_SHUTDOWN(_status,_dStatus)

#endif /* !(defined(__KERNEL__) etc. */

#ifdef __cplusplus
}
#endif

#endif /* __MRTOS_HEADER__ */

