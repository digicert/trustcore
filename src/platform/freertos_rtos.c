/*
 * freertos_rtos.c
 *
 * FreeRTOS.org RTOS Abstraction Layer
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

#include "../common/moptions.h"

#ifdef __FREERTOS_RTOS__

#include <FreeRTOS.h>
#include <task.h>
#include <semphr.h>
#include <queue.h>

#if defined(__FREERTOS_SIMULATOR__) || defined(__RTOS_FREERTOS_ESP32__)
#include <sys/time.h>
#include <sys/times.h>
#include <time.h>
#endif

#if !defined(__FREERTOS_SIMULATOR__) && !defined(__RTOS_FREERTOS_ESP32__)
#if !defined (__ENABLE_DIGICERT_NANOPNAC__) && !defined(__ENABLE_DIGICERT_RTOS_IGNORE_TIMEDATE__)
#include <ff_time.h>
#endif
#endif

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"

/*------------------------------------------------------------------*/
#ifndef MOCANA_DEFAULT_FREERTOS_MAX_SEM_COUNT
#define MOCANA_DEFAULT_FREERTOS_MAX_SEM_COUNT 20
#endif

#ifndef MOCANA_DEFAULT_FREERTOS_TASK_PRIORITY
#define MOCANA_DEFAULT_FREERTOS_TASK_PRIORITY   (5)
#endif

#ifdef __RTOS_FREERTOS_ESP32__
#ifndef MOCANA_DEFAULT_FREERTOS_STACK_SIZE
#define MOCANA_DEFAULT_FREERTOS_STACK_SIZE      (1500 * 4)
#endif
#define MOCANA_TPLOCAL_MAIN_FREERTOS_STACK_SIZE (3000 * 5)
#else
#ifndef MOCANA_DEFAULT_FREERTOS_STACK_SIZE
#define MOCANA_DEFAULT_FREERTOS_STACK_SIZE      (1500)
#endif

#define MOCANA_ENTROPY_FREERTOS_STACK_SIZE      (1500)

#define MOCANA_EST_MAIN_FREERTOS_STACK_SIZE 1500
#define MOCANA_TPLOCAL_MAIN_FREERTOS_STACK_SIZE 3000
#endif
/*
 * Thread configurations, default values and the values that user can set.
 * Any new thread "type" that is introduced in the product, this file also need to be updated for the
 * product to work on free rtos
 */
#ifdef MOCANA_ENTROPY_FREERTOS_TASK_NAME
#define DIGI_FREERTOS_ENTROPY_TASK_NAME                 MOCANA_ENTROPY_FREERTOS_TASK_NAME
#else
#define DIGI_FREERTOS_ENTROPY_TASK_NAME                 "mocEntropy"
#endif
#ifdef MOCANA_ENTROPY_FREERTOS_STACK_SIZE
#define DIGI_FREERTOS_ENTROPY_STACK_SIZE                MOCANA_ENTROPY_FREERTOS_STACK_SIZE
#else
#define DIGI_FREERTOS_ENTROPY_STACK_SIZE                MOCANA_DEFAULT_FREERTOS_STACK_SIZE
#endif
#ifdef MOCANA_ENTROPY_FREERTOS_TASK_PRIORITY
#define DIGI_FREERTOS_ENTROPY_TASK_PRIORITY             tskIDLE_PRIORITY + MOCANA_ENTROPY_FREERTOS_TASK_PRIORITY
#else
#define DIGI_FREERTOS_ENTROPY_TASK_PRIORITY             tskIDLE_PRIORITY + MOCANA_DEFAULT_FREERTOS_TASK_PRIORITY
#endif

#ifdef MOCANA_DEBUG_CONSOLE_FREERTOS_TASK_NAME
#define DIGI_FREERTOS_DEBUG_CONSOLE_TASK_NAME           MOCANA_DEBUG_CONSOLE_FREERTOS_TASK_NAME
#else
#define DIGI_FREERTOS_DEBUG_CONSOLE_TASK_NAME           "mocDebugConsole"
#endif
#ifdef MOCANA_DEBUG_CONSOLE_FREERTOS_STACK_SIZE
#define DIGI_FREERTOS_DEBUG_CONSOLE_STACK_SIZE          MOCANA_DEBUG_CONSOLE_FREERTOS_STACK_SIZE
#else
#define DIGI_FREERTOS_DEBUG_CONSOLE_STACK_SIZE          MOCANA_DEFAULT_FREERTOS_STACK_SIZE
#endif
#ifdef MOCANA_DEBUG_CONSOLE_FREERTOS_TASK_PRIORITY
#define DIGI_FREERTOS_DEBUG_CONSOLE_TASK_PRIORITY       tskIDLE_PRIORITY + MOCANA_DEBUG_CONSOLE_FREERTOS_TASK_PRIORITY
#else
#define DIGI_FREERTOS_DEBUG_CONSOLE_TASK_PRIORITY       tskIDLE_PRIORITY + MOCANA_DEFAULT_FREERTOS_TASK_PRIORITY
#endif

#ifdef MOCANA_SSL_UPCALL_DAEMON_FREERTOS_TASK_NAME
#define DIGI_FREERTOS_SSL_UPCALL_DAEMON_TASK_NAME        MOCANA_SSL_UPCALL_DAEMON_FREERTOS_TASK_NAME
#else
#define DIGI_FREERTOS_SSL_UPCALL_DAEMON_TASK_NAME        "mocSSLUpCallDaemon"
#endif
#ifdef MOCANA_SSL_UPCALL_DAEMON_FREERTOS_STACK_SIZE
#define DIGI_FREERTOS_SSL_UPCALL_DAEMON_STACK_SIZE       MOCANA_SSL_UPCALL_DAEMON_FREERTOS_STACK_SIZE
#else
#define DIGI_FREERTOS_SSL_UPCALL_DAEMON_STACK_SIZE       MOCANA_DEFAULT_FREERTOS_STACK_SIZE
#endif
#ifdef MOCANA_SSL_UPCALL_DAEMON_FREERTOS_TASK_PRIORITY
#define DIGI_FREERTOS_SSL_UPCALL_DAEMON_TASK_PRIORITY    tskIDLE_PRIORITY + MOCANA_SSL_UPCALL_DAEMON_FREERTOS_TASK_PRIORITY
#else
#define DIGI_FREERTOS_SSL_UPCALL_DAEMON_TASK_PRIORITY    tskIDLE_PRIORITY + MOCANA_DEFAULT_FREERTOS_TASK_PRIORITY
#endif

#ifdef MOCANA_SSH_UPCALL_DAEMON_FREERTOS_TASK_NAME
#define DIGI_FREERTOS_SSH_UPCALL_DAEMON_TASK_NAME        MOCANA_SSH_UPCALL_DAEMON_FREERTOS_TASK_NAME
#else
#define DIGI_FREERTOS_SSH_UPCALL_DAEMON_TASK_NAME        "mocSSHUpCallDaemon"
#endif
#ifdef MOCANA_SSH_UPCALL_DAEMON_FREERTOS_STACK_SIZE
#define DIGI_FREERTOS_SSH_UPCALL_DAEMON_STACK_SIZE       MOCANA_SSH_UPCALL_DAEMON_FREERTOS_STACK_SIZE
#else
#define DIGI_FREERTOS_SSH_UPCALL_DAEMON_STACK_SIZE       MOCANA_DEFAULT_FREERTOS_STACK_SIZE
#endif
#ifdef MOCANA_SSH_UPCALL_DAEMON_FREERTOS_TASK_PRIORITY
#define DIGI_FREERTOS_SSH_UPCALL_DAEMON_TASK_PRIORITY    tskIDLE_PRIORITY + MOCANA_SSH_UPCALL_DAEMON_FREERTOS_TASK_PRIORITY
#else
#define DIGI_FREERTOS_SSH_UPCALL_DAEMON_TASK_PRIORITY    tskIDLE_PRIORITY + MOCANA_DEFAULT_FREERTOS_TASK_PRIORITY
#endif

#ifdef MOCANA_SSL_MAIN_FREERTOS_TASK_NAME
#define DIGI_FREERTOS_SSL_MAIN_TASK_NAME                 MOCANA_SSL_MAIN_FREERTOS_TASK_NAME
#else
#define DIGI_FREERTOS_SSL_MAIN_TASK_NAME                 "mocSSLMain"
#endif
#ifdef MOCANA_SSL_MAIN_FREERTOS_STACK_SIZE
#define DIGI_FREERTOS_SSL_MAIN_STACK_SIZE                MOCANA_SSL_MAIN_FREERTOS_STACK_SIZE
#else
#define DIGI_FREERTOS_SSL_MAIN_STACK_SIZE                MOCANA_DEFAULT_FREERTOS_STACK_SIZE
#endif
#ifdef MOCANA_SSL_MAIN_FREERTOS_TASK_PRIORITY
#define DIGI_FREERTOS_SSL_MAIN_TASK_PRIORITY             tskIDLE_PRIORITY + MOCANA_SSL_MAIN_FREERTOS_TASK_PRIORITY
#else
#define DIGI_FREERTOS_SSL_MAIN_TASK_PRIORITY             tskIDLE_PRIORITY + MOCANA_DEFAULT_FREERTOS_TASK_PRIORITY
#endif

#ifdef MOCANA_SSL_SERVER_SESSION_FREERTOS_TASK_NAME
#define DIGI_FREERTOS_SSL_SERVER_SESSION_TASK_NAME       MOCANA_SSL_SERVER_SESSION_FREERTOS_TASK_NAME
#else
#define DIGI_FREERTOS_SSL_SERVER_SESSION_TASK_NAME       "mocSSLServerSession"
#endif
#ifdef MOCANA_SSL_SERVER_SESSION_FREERTOS_STACK_SIZE
#define DIGI_FREERTOS_SSL_SERVER_SESSION_STACK_SIZE      MOCANA_SSL_SERVER_SESSION_FREERTOS_STACK_SIZE
#else
#define DIGI_FREERTOS_SSL_SERVER_SESSION_STACK_SIZE      MOCANA_DEFAULT_FREERTOS_STACK_SIZE
#endif
#ifdef MOCANA_SSL_SERVER_SESSION_FREERTOS_TASK_PRIORITY
#define DIGI_FREERTOS_SSL_SERVER_SESSION_TASK_PRIORITIY  tskIDLE_PRIORITY + MOCANA_SSL_SERVER_SESSION_FREERTOS_TASK_PRIORITY
#else
#define DIGI_FREERTOS_SSL_SERVER_SESSION_TASK_PRIORITIY  tskIDLE_PRIORITY + MOCANA_DEFAULT_FREERTOS_TASK_PRIORITY
#endif

#ifdef MOCANA_DTLS_MAIN_FREERTOS_TASK_NAME
#define DIGI_FREERTOS_DTLS_MAIN_TASK_NAME                MOCANA_DTLS_MAIN_FREERTOS_TASK_NAME
#else
#define DIGI_FREERTOS_DTLS_MAIN_TASK_NAME                "mocDTLSMain"
#endif
#ifdef MOCANA_DTLS_MAIN_FREERTOS_STACK_SIZE
#define DIGI_FREERTOS_DTLS_MAIN_STACK_SIZE               MOCANA_DTLS_MAIN_FREERTOS_STACK_SIZE
#else
#define DIGI_FREERTOS_DTLS_MAIN_STACK_SIZE               MOCANA_DEFAULT_FREERTOS_STACK_SIZE
#endif
#ifdef MOCANA_DTLS_MAIN_FREERTOS_TASK_PRIORITY
#define DIGI_FREERTOS_DTLS_MAIN_TASK_PRIORITY            tskIDLE_PRIORITY + MOCANA_DTLS_MAIN_FREERTOS_TASK_PRIORITY
#else
#define DIGI_FREERTOS_DTLS_MAIN_TASK_PRIORITY            tskIDLE_PRIORITY + MOCANA_DEFAULT_FREERTOS_TASK_PRIORITY
#endif

#ifdef MOCANA_SSH_MAIN_FREERTOS_TASK_NAME
#define DIGI_FREERTOS_SSH_MAIN_TASK_NAME                 MOCANA_SSH_MAIN_FREERTOS_TASK_NAME
#else
#define DIGI_FREERTOS_SSH_MAIN_TASK_NAME                 "mocSSHMain"
#endif
#ifdef MOCANA_SSH_MAIN_FREERTOS_STACK_SIZE
#define DIGI_FREERTOS_SSH_MAIN_STACK_SIZE                MOCANA_SSH_MAIN_FREERTOS_STACK_SIZE
#else
#define DIGI_FREERTOS_SSH_MAIN_STACK_SIZE                MOCANA_DEFAULT_FREERTOS_STACK_SIZE
#endif
#ifdef MOCANA_SSH_MAIN_FREERTOS_TASK_PRIORITY
#define DIGI_FREERTOS_SSH_MAIN_TASK_PRIORITY             tskIDLE_PRIORITY + MOCANA_SSH_MAIN_FREERTOS_TASK_PRIORITY
#else
#define DIGI_FREERTOS_SSH_MAIN_TASK_PRIORITY             tskIDLE_PRIORITY + MOCANA_DEFAULT_FREERTOS_TASK_PRIORITY
#endif

#ifdef MOCANA_SSH_SESSION_FREERTOS_TASK_NAME
#define DIGI_FREERTOS_SSH_SESSION_TASK_NAME              MOCANA_SSH_SESSION_FREERTOS_TASK_NAME
#else
#define DIGI_FREERTOS_SSH_SESSION_TASK_NAME              "mocSSHSession"
#endif
#ifdef MOCANA_SSH_SESSION_FREERTOS_STACK_SIZE
#define DIGI_FREERTOS_SSH_SESSION_STACK_SIZE             MOCANA_SSH_SESSION_FREERTOS_STACK_SIZE
#else
#define DIGI_FREERTOS_SSH_SESSION_STACK_SIZE             MOCANA_DEFAULT_FREERTOS_STACK_SIZE
#endif
#ifdef MOCANA_SSH_SESSION_FREERTOS_TASK_PRIORITY
#define DIGI_FREERTOS_SSH_SESSION_TASK_PRIORITY          tskIDLE_PRIORITY + MOCANA_SSH_SESSION_FREERTOS_TASK_PRIORITY
#else
#define DIGI_FREERTOS_SSH_SESSION_TASK_PRIORITY          tskIDLE_PRIORITY + MOCANA_DEFAULT_FREERTOS_TASK_PRIORITY
#endif

#ifdef MOCANA_HTTP_FREERTOS_TASK_NAME
#define DIGI_FREERTOS_HTTP_TASK_NAME                     MOCANA_HTTP_FREERTOS_TASK_NAME
#else
#define DIGI_FREERTOS_HTTP_TASK_NAME                     "mocHTTP"
#endif
#ifdef MOCANA_HTTP_FREERTOS_STACK_SIZE
#define DIGI_FREERTOS_HTTP_STACK_SIZE                    MOCANA_HTTP_FREERTOS_STACK_SIZE
#else
#define DIGI_FREERTOS_HTTP_STACK_SIZE                    MOCANA_DEFAULT_FREERTOS_STACK_SIZE
#endif
#ifdef MOCANA_HTTP_FREERTOS_TASK_PRIORITY
#define DIGI_FREERTOS_HTTP_TASK_PRIORITY                 tskIDLE_PRIORITY + MOCANA_HTTP_FREERTOS_TASK_PRIORITY
#else
#define DIGI_FREERTOS_HTTP_TASK_PRIORITY                 tskIDLE_PRIORITY + MOCANA_DEFAULT_FREERTOS_TASK_PRIORITY
#endif

#ifdef MOCANA_IKE_MAIN_FREERTOS_TASK_NAME
#define DIGI_FREERTOS_IKE_MAIN_TASK_NAME                 MOCANA_IKE_MAIN_FREERTOS_TASK_NAME
#else
#define DIGI_FREERTOS_IKE_MAIN_TASK_NAME                 "mocIKEMain"
#endif
#ifdef MOCANA_IKE_MAIN_FREERTOS_STACK_SIZE
#define DIGI_FREERTOS_IKE_MAIN_STACK_SIZE                MOCANA_IKE_MAIN_FREERTOS_STACK_SIZE
#else
#define DIGI_FREERTOS_IKE_MAIN_STACK_SIZE                MOCANA_DEFAULT_FREERTOS_STACK_SIZE
#endif
#ifdef MOCANA_IKE_MAIN_FREERTOS_TASK_PRIORITY
#define DIGI_FREERTOS_IKE_MAIN_TASK_PRIORITY             tskIDLE_PRIORITY + MOCANA_IKE_MAIN_FREERTOS_TASK_PRIORITY
#else
#define DIGI_FREERTOS_IKE_MAIN_TASK_PRIORITY             tskIDLE_PRIORITY + MOCANA_DEFAULT_FREERTOS_TASK_PRIORITY
#endif

#ifdef MOCANA_DEBUGTHREAD_FREERTOS_TASK_NAME
#define DIGI_FREERTOS_DEBUGTHREAD_TASK_NAME              MOCANA_DEBUGTHREAD_FREERTOS_TASK_NAME
#else
#define DIGI_FREERTOS_DEBUGTHREAD_TASK_NAME              "mocDebugThread"
#endif
#ifdef MOCANA_DEBUGTHREAD_FREERTOS_STACK_SIZE
#define DIGI_FREERTOS_DEBUGTHREAD_STACK_SIZE             MOCANA_DEBUGTHREAD_FREERTOS_STACK_SIZE
#else
#define DIGI_FREERTOS_DEBUGTHREAD_STACK_SIZE             MOCANA_DEFAULT_FREERTOS_STACK_SIZE
#endif
#ifdef MOCANA_DEBUGTHREAD_FREERTOS_TASK_PRIORITY
#define DIGI_FREERTOS_DEBUGTHREAD_TASK_PRIORITY          tskIDLE_PRIORITY + MOCANA_DEBUGTHREAD_FREERTOS_TASK_PRIORITY
#else
#define DIGI_FREERTOS_DEBUGTHREAD_TASK_PRIORITY          tskIDLE_PRIORITY + MOCANA_DEFAULT_FREERTOS_TASK_PRIORITY
#endif

#ifdef MOCANA_EAP_MAIN_FREERTOS_TASK_NAME
#define DIGI_FREERTOS_EAP_MAIN_TASK_NAME                 MOCANA_EAP_MAIN_FREERTOS_TASK_NAME
#else
#define DIGI_FREERTOS_EAP_MAIN_TASK_NAME                 "mocEAPMain"
#endif
#ifdef MOCANA_EAP_MAIN_FREERTOS_STACK_SIZE
#define DIGI_FREERTOS_EAP_MAIN_STACK_SIZE                MOCANA_EAP_MAIN_FREERTOS_STACK_SIZE
#else
#define DIGI_FREERTOS_EAP_MAIN_STACK_SIZE                MOCANA_DEFAULT_FREERTOS_STACK_SIZE
#endif
#ifdef MOCANA_EAP_MAIN_FREERTOS_TASK_PRIORITY
#define DIGI_FREERTOS_EAP_MAIN_TASK_PRIORITY             tskIDLE_PRIORITY + MOCANA_EAP_MAIN_FREERTOS_TASK_PRIORITY
#else
#define DIGI_FREERTOS_EAP_MAIN_TASK_PRIORITY             tskIDLE_PRIORITY + MOCANA_DEFAULT_FREERTOS_TASK_PRIORITY
#endif

#ifdef MOCANA_IPC_MAIN_FREERTOS_TASK_NAME
#define DIGI_FREERTOS_IPC_MAIN_TASK_NAME                 MOCANA_IPC_MAIN_FREERTOS_TASK_NAME
#else
#define DIGI_FREERTOS_IPC_MAIN_TASK_NAME                 "mocIPCMain"
#endif
#ifdef MOCANA_IPC_MAIN_FREERTOS_STACK_SIZE
#define DIGI_FREERTOS_IPC_MAIN_STACK_SIZE                MOCANA_IPC_MAIN_FREERTOS_STACK_SIZE
#else
#define DIGI_FREERTOS_IPC_MAIN_STACK_SIZE                MOCANA_DEFAULT_FREERTOS_STACK_SIZE
#endif
#ifdef MOCANA_IPC_MAIN_FREERTOS_TASK_PRIORITY
#define DIGI_FREERTOS_IPC_MAIN_TASK_PRIORITY             tskIDLE_PRIORITY + MOCANA_IPC_MAIN_FREERTOS_TASK_PRIORITY
#else
#define DIGI_FREERTOS_IPC_MAIN_TASK_PRIORITY             tskIDLE_PRIORITY + MOCANA_DEFAULT_FREERTOS_TASK_PRIORITY
#endif

#ifdef MOCANA_RADIUS_MAIN_FREERTOS_TASK_NAME
#define DIGI_FREERTOS_RADIUS_MAIN_TASK_NAME              MOCANA_RADIUS_MAIN_FREERTOS_TASK_NAME
#else
#define DIGI_FREERTOS_RADIUS_MAIN_TASK_NAME              "mocRadiusMain"
#endif
#ifdef MOCANA_RADIUS_MAIN_FREERTOS_STACK_SIZE
#define DIGI_FREERTOS_RADIUS_MAIN_STACK_SIZE             MOCANA_RADIUS_MAIN_FREERTOS_STACK_SIZE
#else
#define DIGI_FREERTOS_RADIUS_MAIN_STACK_SIZE             MOCANA_DEFAULT_FREERTOS_STACK_SIZE
#endif
#ifdef MOCANA_RADIUS_MAIN_FREERTOS_TASK_PRIORITY
#define DIGI_FREERTOS_RADIUS_MAIN_TASK_PRIORITY          tskIDLE_PRIORITY + MOCANA_RADIUS_MAIN_FREERTOS_TASK_PRIORITY
#else
#define DIGI_FREERTOS_RADIUS_MAIN_TASK_PRIORITY          tskIDLE_PRIORITY + MOCANA_DEFAULT_FREERTOS_TASK_PRIORITY
#endif

#ifdef MOCANA_HARNESS_MAIN_FREERTOS_TASK_NAME
#define DIGI_FREERTOS_HARNESS_MAIN_TASK_NAME             MOCANA_HARNESS_MAIN_FREERTOS_TASK_NAME
#else
#define DIGI_FREERTOS_HARNESS_MAIN_TASK_NAME             "mocHarnessMain"
#endif
#ifdef MOCANA_HARNESS_MAIN_FREERTOS_STACK_SIZE
#define DIGI_FREERTOS_HARNESS_MAIN_STACK_SIZE            MOCANA_HARNESS_MAIN_FREERTOS_STACK_SIZE
#else
#define DIGI_FREERTOS_HARNESS_MAIN_STACK_SIZE            MOCANA_DEFAULT_FREERTOS_STACK_SIZE
#endif
#ifdef MOCANA_HARNESS_MAIN_FREERTOS_TASK_PRIORITY
#define DIGI_FREERTOS_HARNESS_MAIN_TASK_PRIORITY         tskIDLE_PRIORITY + MOCANA_HARNESS_MAIN_FREERTOS_TASK_PRIORITY
#else
#define DIGI_FREERTOS_HARNESS_MAIN_TASK_PRIORITY         tskIDLE_PRIORITY + 1
#endif

#ifdef MOCANA_HARNESS_MAIN1_FREERTOS_TASK_NAME
#define DIGI_FREERTOS_HARNESS_MAIN1_TASK_NAME            MOCANA_HARNESS_MAIN1_FREERTOS_TASK_NAME
#else
#define DIGI_FREERTOS_HARNESS_MAIN1_TASK_NAME            "mocIpsecHarness"
#endif
#ifdef MOCANA_HARNESS_MAIN1_FREERTOS_STACK_SIZE
#define DIGI_FREERTOS_HARNESS_MAIN1_STACK_SIZE           MOCANA_HARNESS_MAIN1_FREERTOS_STACK_SIZE
#else
#define DIGI_FREERTOS_HARNESS_MAIN1_STACK_SIZE           MOCANA_DEFAULT_FREERTOS_STACK_SIZE
#endif
#ifdef MOCANA_HARNESS_MAIN1_FREERTOS_TASK_PRIORITY
#define DIGI_FREERTOS_HARNESS_MAIN1_TASK_PRIORITY        tskIDLE_PRIORITY + MOCANA_HARNESS_MAIN1_FREERTOS_TASK_PRIORITY
#else
#define DIGI_FREERTOS_HARNESS_MAIN1_TASK_PRIORITY        tskIDLE_PRIORITY + MOCANA_DEFAULT_FREERTOS_TASK_PRIORITY
#endif

#ifdef MOCANA_HARNESS_TEST_FREERTOS_TASK_NAME
#define DIGI_FREERTOS_HARNESS_TEST_TASK_NAME             MOCANA_HARNESS_TEST_FREERTOS_TASK_NAME
#else
#define DIGI_FREERTOS_HARNESS_TEST_TASK_NAME            "mocHarnessTest"
#endif
#ifdef MOCANA_HARNESS_TEST_FREERTOS_STACK_SIZE
#define DIGI_FREERTOS_HARNESS_TEST_STACK_SIZE            MOCANA_HARNESS_TEST_FREERTOS_STACK_SIZE
#else
#define DIGI_FREERTOS_HARNESS_TEST_STACK_SIZE            MOCANA_DEFAULT_FREERTOS_STACK_SIZE
#endif
#ifdef MOCANA_HARNESS_TEST_FREERTOS_TASK_PRIORITY
#define DIGI_FREERTOS_HARNESS_TEST_TASK_PRIORITY         tskIDLE_PRIORITY + MOCANA_HARNESS_TEST_FREERTOS_TASK_PRIORITY
#else
#define DIGI_FREERTOS_HARNESS_TEST_TASK_PRIORITY         tskIDLE_PRIORITY + MOCANA_DEFAULT_FREERTOS_TASK_PRIORITY
#endif

#ifdef MOCANA_CLITHREAD_FREERTOS_TASK_NAME
#define DIGI_FREERTOS_CLITHREAD_TASK_NAME                MOCANA_CLITHREAD_FREERTOS_TASK_NAME
#else
#define DIGI_FREERTOS_CLITHREAD_TASK_NAME                "mocCLIThread"
#endif
#ifdef MOCANA_CLITHREAD_FREERTOS_STACK_SIZE
#define DIGI_FREERTOS_CLITHREAD_STACK_SIZE               MOCANA_CLITHREAD_FREERTOS_STACK_SIZE
#else
#define DIGI_FREERTOS_CLITHREAD_STACK_SIZE               MOCANA_DEFAULT_FREERTOS_STACK_SIZE
#endif
#ifdef MOCANA_CLITHREAD_FREERTOS_TASK_PRIORITY
#define DIGI_FREERTOS_CLITHREAD_TASK_PRIORITY            tskIDLE_PRIORITY + MOCANA_CLITHREAD_FREERTOS_TASK_PRIORITY
#else
#define DIGI_FREERTOS_CLITHREAD_TASK_PRIORITY            tskIDLE_PRIORITY + MOCANA_DEFAULT_FREERTOS_TASK_PRIORITY
#endif

#ifdef MOCANA_MOC_IPV4_FREERTOS_TASK_NAME
#define DIGI_FREERTOS_MOC_IPV4_TASK_NAME                 MOCANA_MOC_IPV4_FREERTOS_TASK_NAME
#else
#define DIGI_FREERTOS_MOC_IPV4_TASK_NAME                 "mocIPv4"
#endif
#ifdef MOCANA_MOC_IPV4_FREERTOS_STACK_SIZE
#define DIGI_FREERTOS_MOC_IPV4_STACK_SIZE                MOCANA_MOC_IPV4_FREERTOS_STACK_SIZE
#else
#define DIGI_FREERTOS_MOC_IPV4_STACK_SIZE                MOCANA_DEFAULT_FREERTOS_STACK_SIZE
#endif
#ifdef MOCANA_MOC_IPV4_FREERTOS_TASK_PRIORITY
#define DIGI_FREERTOS_MOC_IPV4_TASK_PRIORITY             tskIDLE_PRIORITY + MOCANA_MOC_IPV4_FREERTOS_TASK_PRIORITY
#else
#define DIGI_FREERTOS_MOC_IPV4_TASK_PRIORITY             tskIDLE_PRIORITY + MOCANA_DEFAULT_FREERTOS_TASK_PRIORITY
#endif

#ifdef MOCANA_FIREWALL_MAIN_FREERTOS_TASK_NAME
#define DIGI_FREERTOS_FIREWALL_MAIN_TASK_NAME            MOCANA_FIREWALL_MAIN_FREERTOS_TASK_NAME
#else
#define DIGI_FREERTOS_FIREWALL_MAIN_TASK_NAME            "mocFirewallMain"
#endif
#ifdef MOCANA_FIREWALL_MAIN_FREERTOS_STACK_SIZE
#define DIGI_FREERTOS_FIREWALL_MAIN_STACK_SIZE           MOCANA_FIREWALL_MAIN_FREERTOS_STACK_SIZE
#else
#define DIGI_FREERTOS_FIREWALL_MAIN_STACK_SIZE           MOCANA_DEFAULT_FREERTOS_STACK_SIZE
#endif
#ifdef MOCANA_FIREWALL_MAIN_FREERTOS_TASK_PRIORITY
#define DIGI_FREERTOS_FIREWALL_MAIN_TASK_PRIORITY        tskIDLE_PRIORITY + MOCANA_FIREWALL_MAIN_FREERTOS_TASK_PRIORITY
#else
#define DIGI_FREERTOS_FIREWALL_MAIN_TASK_PRIORITY        tskIDLE_PRIORITY + MOCANA_DEFAULT_FREERTOS_TASK_PRIORITY
#endif

#ifdef MOCANA_FIREWALL_SERVER_FREERTOS_TASK_NAME
#define DIGI_FREERTOS_FIREWALL_SERVER_TASK_NAME          MOCANA_FIREWALL_SERVER_FREERTOS_TASK_NAME
#else
#define DIGI_FREERTOS_FIREWALL_SERVER_TASK_NAME          "mocFirewallServer"
#endif
#ifdef MOCANA_FIREWALL_SERVER_FREERTOS_STACK_SIZE
#define DIGI_FREERTOS_FIREWALL_SERVER_STACK_SIZE         MOCANA_FIREWALL_SERVER_FREERTOS_STACK_SIZE
#else
#define DIGI_FREERTOS_FIREWALL_SERVER_STACK_SIZE         MOCANA_DEFAULT_FREERTOS_STACK_SIZE
#endif
#ifdef MOCANA_FIREWALL_SERVER_FREERTOS_TASK_PRIORITY
#define DIGI_FREERTOS_FIREWALL_SERVER_TASK_PRIORITY      tskIDLE_PRIORITY + MOCANA_FIREWALL_SERVER_FREERTOS_TASK_PRIORITY
#else
#define DIGI_FREERTOS_FIREWALL_SERVER_TASK_PRIORITY      tskIDLE_PRIORITY + MOCANA_DEFAULT_FREERTOS_TASK_PRIORITY
#endif

#ifdef MOCANA_NTP_MAIN_FREERTOS_TASK_NAME
#define DIGI_FREERTOS_NTP_MAIN_TASK_NAME                 MOCANA_NTP_MAIN_FREERTOS_TASK_NAME
#else
#define DIGI_FREERTOS_NTP_MAIN_TASK_NAME                 "mocNTPMain"
#endif
#ifdef MOCANA_NTP_MAIN_FREERTOS_STACK_SIZE
#define DIGI_FREERTOS_NTP_MAIN_STACK_SIZE                MOCANA_NTP_MAIN_FREERTOS_STACK_SIZE
#else
#define DIGI_FREERTOS_NTP_MAIN_STACK_SIZE                MOCANA_DEFAULT_FREERTOS_STACK_SIZE
#endif
#ifdef MOCANA_NTP_MAIN_FREERTOS_TASK_PRIORITY
#define DIGI_FREERTOS_NTP_MAIN_TASK_PRIORITY             tskIDLE_PRIORITY + MOCANA_NTP_MAIN_FREERTOS_TASK_PRIORITY
#else
#define DIGI_FREERTOS_NTP_MAIN_TASK_PRIORITY             tskIDLE_PRIORITY + MOCANA_DEFAULT_FREERTOS_TASK_PRIORITY
#endif

#ifdef MOCANA_OCSP_MAIN_FREERTOS_TASK_NAME
#define DIGI_FREERTOS_OCSP_MAIN_TASK_NAME                MOCANA_OCSP_MAIN_FREERTOS_TASK_NAME
#else
#define DIGI_FREERTOS_OCSP_MAIN_TASK_NAME                "mocOCSPMain"
#endif
#ifdef MOCANA_OCSP_MAIN_FREERTOS_STACK_SIZE
#define DIGI_FREERTOS_OCSP_MAIN_STACK_SIZE               MOCANA_OCSP_MAIN_FREERTOS_STACK_SIZE
#else
#define DIGI_FREERTOS_OCSP_MAIN_STACK_SIZE               MOCANA_DEFAULT_FREERTOS_STACK_SIZE
#endif
#ifdef MOCANA_OCSP_MAIN_FREERTOS_TASK_PRIORITY
#define DIGI_FREERTOS_OCSP_MAIN_TASK_PRIORITY            tskIDLE_PRIORITY + MOCANA_OCSP_MAIN_FREERTOS_TASK_PRIORITY
#else
#define DIGI_FREERTOS_OCSP_MAIN_TASK_PRIORITY            tskIDLE_PRIORITY + MOCANA_DEFAULT_FREERTOS_TASK_PRIORITY
#endif

#ifdef MOCANA_CMP_MAIN_FREERTOS_TASK_NAME
#define DIGI_FREERTOS_CMP_MAIN_TASK_NAME                 MOCANA_CMP_MAIN_FREERTOS_TASK_NAME
#else
#define DIGI_FREERTOS_CMP_MAIN_TASK_NAME                 "mocCMPMain"
#endif
#ifdef MOCANA_CMP_MAIN_FREERTOS_STACK_SIZE
#define DIGI_FREERTOS_CMP_MAIN_STACK_SIZE                MOCANA_CMP_MAIN_FREERTOS_STACK_SIZE
#else
#define DIGI_FREERTOS_CMP_MAIN_STACK_SIZE                MOCANA_DEFAULT_FREERTOS_STACK_SIZE
#endif
#ifdef MOCANA_CMP_MAIN_FREERTOS_TASK_PRIORITY
#define DIGI_FREERTOS_CMP_MAIN_TASK_PRIORITY             tskIDLE_PRIORITY + MOCANA_CMP_MAIN_FREERTOS_TASK_PRIORITY
#else
#define DIGI_FREERTOS_CMP_MAIN_TASK_PRIORITY             tskIDLE_PRIORITY + MOCANA_DEFAULT_FREERTOS_TASK_PRIORITY
#endif

#ifdef MOCANA_LDAP_MAIN_FREERTOS_TASK_NAME
#define DIGI_FREERTOS_LDAP_MAIN_TASK_NAME                MOCANA_LDAP_MAIN_FREERTOS_TASK_NAME
#else
#define DIGI_FREERTOS_LDAP_MAIN_TASK_NAME                "mocLDAPMain"
#endif
#ifdef MOCANA_LDAP_MAIN_FREERTOS_STACK_SIZE
#define DIGI_FREERTOS_LDAP_MAIN_STACK_SIZE               MOCANA_LDAP_MAIN_FREERTOS_STACK_SIZE
#else
#define DIGI_FREERTOS_LDAP_MAIN_STACK_SIZE               MOCANA_DEFAULT_FREERTOS_STACK_SIZE
#endif
#ifdef MOCANA_LDAP_MAIN_FREERTOS_TASK_PRIORITY
#define DIGI_FREERTOS_LDAP_MAIN_TASK_PRIORITY            tskIDLE_PRIORITY + MOCANA_LDAP_MAIN_FREERTOS_TASK_PRIORITY
#else
#define DIGI_FREERTOS_LDAP_MAIN_TASK_PRIORITY            tskIDLE_PRIORITY + MOCANA_DEFAULT_FREERTOS_TASK_PRIORITY
#endif

#ifdef MOCANA_PKI_CLIENT_MAIN_FREERTOS_TASK_NAME
#define DIGI_FREERTOS_PKI_CLIENT_MAIN_TASK_NAME          MOCANA_PKI_CLIENT_MAIN_FREERTOS_TASK_NAME
#else
#define DIGI_FREERTOS_PKI_CLIENT_MAIN_TASK_NAME          "mocPKIClientMain"
#endif
#ifdef MOCANA_PKI_CLIENT_MAIN_FREERTOS_STACK_SIZE
#define DIGI_FREERTOS_PKI_CLIENT_MAIN_STACK_SIZE         MOCANA_PKI_CLIENT_MAIN_FREERTOS_STACK_SIZE
#else
#define DIGI_FREERTOS_PKI_CLIENT_MAIN_STACK_SIZE         MOCANA_DEFAULT_FREERTOS_STACK_SIZE
#endif
#ifdef MOCANA_PKI_CLIENT_MAIN_FREERTOS_TASK_PRIORITY
#define DIGI_FREERTOS_PKI_CLIENT_MAIN_TASK_PRIORITY      tskIDLE_PRIORITY + MOCANA_PKI_CLIENT_MAIN_FREERTOS_TASK_PRIORITY
#else
#define DIGI_FREERTOS_PKI_CLIENT_MAIN_TASK_PRIORITY      tskIDLE_PRIORITY + MOCANA_DEFAULT_FREERTOS_TASK_PRIORITY
#endif

#ifdef MOCANA_PKI_IPC_MAIN_FREERTOS_TASK_NAME
#define DIGI_FREERTOS_PKI_IPC_MAIN_TASK_NAME             MOCANA_PKI_IPC_MAIN_FREERTOS_TASK_NAME
#else
#define DIGI_FREERTOS_PKI_IPC_MAIN_TASK_NAME             "mocPKIIpcMain"
#endif
#ifdef MOCANA_PKI_IPC_MAIN_FREERTOS_STACK_SIZE
#define DIGI_FREERTOS_PKI_IPC_MAIN_STACK_SIZE            MOCANA_PKI_IPC_MAIN_FREERTOS_STACK_SIZE
#else
#define DIGI_FREERTOS_PKI_IPC_MAIN_STACK_SIZE            MOCANA_DEFAULT_FREERTOS_STACK_SIZE
#endif
#ifdef MOCANA_PKI_IPC_MAIN_FREERTOS_TASK_PRIORITY
#define DIGI_FREERTOS_PKI_IPC_MAIN_TASK_PRIORITY         tskIDLE_PRIORITY + MOCANA_PKI_IPC_MAIN_FREERTOS_TASK_PRIORITY
#else
#define DIGI_FREERTOS_PKI_IPC_MAIN_TASK_PRIORITY         tskIDLE_PRIORITY + MOCANA_DEFAULT_FREERTOS_TASK_PRIORITY
#endif

#ifdef MOCANA_SRTP_MAIN_FREERTOS_TASK_NAME
#define DIGI_FREERTOS_SRTP_MAIN_TASK_NAME                MOCANA_SRTP_MAIN_FREERTOS_TASK_NAME
#else
#define DIGI_FREERTOS_SRTP_MAIN_TASK_NAME                "mocSRTPMain"
#endif
#ifdef MOCANA_SRTP_MAIN_FREERTOS_STACK_SIZE
#define DIGI_FREERTOS_SRTP_MAIN_STACK_SIZE               MOCANA_SRTP_MAIN_FREERTOS_STACK_SIZE
#else
#define DIGI_FREERTOS_SRTP_MAIN_STACK_SIZE               MOCANA_DEFAULT_FREERTOS_STACK_SIZE
#endif
#ifdef MOCANA_SRTP_MAIN_FREERTOS_TASK_PRIORITY
#define DIGI_FREERTOS_SRTP_MAIN_TASK_PRIORITY            tskIDLE_PRIORITY + MOCANA_SRTP_MAIN_FREERTOS_TASK_PRIORITY
#else
#define DIGI_FREERTOS_SRTP_MAIN_TASK_PRIORITY            tskIDLE_PRIORITY + MOCANA_DEFAULT_FREERTOS_TASK_PRIORITY
#endif

#ifdef MOCANA_DEMO_IP_MAIN_FREERTOS_TASK_NAME
#define DIGI_FREERTOS_DEMO_IP_MAIN_TASK_NAME             MOCANA_DEMO_IP_MAIN_FREERTOS_TASK_NAME
#else
#define DIGI_FREERTOS_DEMO_IP_MAIN_TASK_NAME             "mocDEMOIPMain"
#endif
#ifdef MOCANA_DEMO_IP_MAIN_FREERTOS_STACK_SIZE
#define DIGI_FREERTOS_DEMO_IP_MAIN_STACK_SIZE            MOCANA_DEMO_IP_MAIN_FREERTOS_STACK_SIZE
#else
#define DIGI_FREERTOS_DEMO_IP_MAIN_STACK_SIZE            MOCANA_DEFAULT_FREERTOS_STACK_SIZE
#endif
#ifdef MOCANA_DEMO_IP_MAIN_FREERTOS_TASK_PRIORITY
#define DIGI_FREERTOS_DEMO_IP_MAIN_TASK_PRIORITY         tskIDLE_PRIORITY + MOCANA_DEMO_IP_MAIN_FREERTOS_TASK_PRIORITY
#else
#define DIGI_FREERTOS_DEMO_IP_MAIN_TASK_PRIORITY         tskIDLE_PRIORITY + MOCANA_DEFAULT_FREERTOS_TASK_PRIORITY
#endif

#ifdef MOCANA_TPLOCAL_MAIN_FREERTOS_TASK_NAME
#define DIGI_FREERTOS_TPLOCAL_MAIN_TASK_NAME                MOCANA_TPLOCAL_MAIN_FREERTOS_TASK_NAME
#else
#define DIGI_FREERTOS_TPLOCAL_MAIN_TASK_NAME                "mocTPLocal"
#endif
#ifdef MOCANA_TPLOCAL_MAIN_FREERTOS_STACK_SIZE
#define DIGI_FREERTOS_TPLOCAL_MAIN_STACK_SIZE               MOCANA_TPLOCAL_MAIN_FREERTOS_STACK_SIZE
#else
#define DIGI_FREERTOS_TPLOCAL_MAIN_STACK_SIZE               MOCANA_DEFAULT_FREERTOS_STACK_SIZE
#endif
#ifdef MOCANA_TPLOCAL_MAIN_FREERTOS_TASK_PRIORITY
#define DIGI_FREERTOS_TPLOCAL_MAIN_TASK_PRIORITY            tskIDLE_PRIORITY + MOCANA_TPLOCAL_MAIN_FREERTOS_TASK_PRIORITY
#else
#define DIGI_FREERTOS_TPLOCAL_MAIN_TASK_PRIORITY            tskIDLE_PRIORITY + MOCANA_DEFAULT_FREERTOS_TASK_PRIORITY
#endif

#ifdef MOCANA_TPLOCAL_PROV_FREERTOS_TASK_NAME
#define DIGI_FREERTOS_TPLOCAL_PROV_TASK_NAME                MOCANA_TPLOCAL_PROV_FREERTOS_TASK_NAME
#else
#define DIGI_FREERTOS_TPLOCAL_PROV_TASK_NAME                "mocTPLocalProv"
#endif
#ifdef MOCANA_TPLOCAL_PROV_FREERTOS_STACK_SIZE
#define DIGI_FREERTOS_TPLOCAL_PROV_STACK_SIZE               MOCANA_TPLOCAL_PROV_FREERTOS_STACK_SIZE
#else
#define DIGI_FREERTOS_TPLOCAL_PROV_STACK_SIZE               MOCANA_DEFAULT_FREERTOS_STACK_SIZE + 3000
#endif
#ifdef MOCANA_TPLOCAL_PROV_FREERTOS_TASK_PRIORITY
#define DIGI_FREERTOS_TPLOCAL_PROV_TASK_PRIORITY            tskIDLE_PRIORITY + MOCANA_TPLOCAL_PROV_FREERTOS_TASK_PRIORITY
#else
#define DIGI_FREERTOS_TPLOCAL_PROV_TASK_PRIORITY            tskIDLE_PRIORITY + MOCANA_DEFAULT_FREERTOS_TASK_PRIORITY
#endif

#ifdef MOCANA_EST_MAIN_FREERTOS_TASK_NAME
#define DIGI_FREERTOS_EST_MAIN_TASK_NAME                 MOCANA_EST_MAIN_FREERTOS_TASK_NAME
#else
#define DIGI_FREERTOS_EST_MAIN_TASK_NAME                 "mocESTMain"
#endif
#ifdef MOCANA_EST_MAIN_FREERTOS_STACK_SIZE
#define DIGI_FREERTOS_EST_MAIN_STACK_SIZE                MOCANA_EST_MAIN_FREERTOS_STACK_SIZE
#else
#define DIGI_FREERTOS_EST_MAIN_STACK_SIZE                MOCANA_DEFAULT_FREERTOS_STACK_SIZE
#endif
#ifdef MOCANA_EST_MAIN_FREERTOS_TASK_PRIORITY
#define DIGI_FREERTOS_EST_MAIN_TASK_PRIORITY             tskIDLE_PRIORITY + MOCANA_EST_MAIN_FREERTOS_TASK_PRIORITY
#else
#define DIGI_FREERTOS_EST_MAIN_TASK_PRIORITY             tskIDLE_PRIORITY + MOCANA_DEFAULT_FREERTOS_TASK_PRIORITY
#endif

#ifdef MOCANA_UM_SCHED_FREERTOS_TASK_NAME
#define DIGI_FREERTOS_UM_SCHED_TASK_NAME                 MOCANA_UM_SCHED_FREERTOS_TASK_NAME
#else
#define DIGI_FREERTOS_UM_SCHED_TASK_NAME                 "mocUmSched"
#endif
#ifdef MOCANA_UM_SCHED_FREERTOS_STACK_SIZE
#define DIGI_FREERTOS_UM_SCHED_STACK_SIZE                MOCANA_UM_SCHED_FREERTOS_STACK_SIZE
#else
#define DIGI_FREERTOS_UM_SCHED_STACK_SIZE                MOCANA_DEFAULT_FREERTOS_STACK_SIZE
#endif
#ifdef MOCANA_UM_SCHED_FREERTOS_TASK_PRIORITY
#define DIGI_FREERTOS_UM_SCHED_TASK_PRIORITY             tskIDLE_PRIORITY + MOCANA_UM_SCHED_FREERTOS_TASK_PRIORITY
#else
#define DIGI_FREERTOS_UM_SCHED_TASK_PRIORITY             tskIDLE_PRIORITY + MOCANA_DEFAULT_FREERTOS_TASK_PRIORITY
#endif


/*------------------------------------------------------------------*/

extern MSTATUS
FREERTOS_rtosInit(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
FREERTOS_rtosShutdown(void)
{
    return OK;
}


/*------------------------------------------------------------------*/
/*
 * Since we are creating mutexes and not binary semaphores these cannot be called from ISR.
 * If we want to call mutexes from ISR, then we would have to create binary semaphores and that could be done either
 * by giving a specific type within "mutexType", this is however not supported as of now.
*/
extern MSTATUS
FREERTOS_mutexCreate(RTOS_MUTEX* pMutex, enum mutexTypes mutexType, int mutexCount)
{
    MSTATUS status = ERR_RTOS_MUTEX_CREATE;
    xSemaphoreHandle xMutex = NULL;

    MOC_UNUSED(mutexCount);

    if (FREERTOS_BINARY_MUTEX == mutexType)
    {
        xMutex = xSemaphoreCreateBinary();
    }
    else
    {
        xMutex = xSemaphoreCreateMutex();
    }

    if (xMutex != NULL)
    {
        *pMutex = xMutex;
        status = OK;
    }

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
FREERTOS_mutexWait(RTOS_MUTEX mutex)
{
    xSemaphoreHandle    xMutex = (xSemaphoreHandle)mutex;
    MSTATUS         status = ERR_RTOS_MUTEX_RELEASE;

    if ((xMutex) && (pdPASS == xSemaphoreTake(xMutex, portMAX_DELAY)))
        status = OK;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
FREERTOS_mutexWaitEx(RTOS_MUTEX mutex, ubyte4 timeoutMs)
{
    xSemaphoreHandle    xMutex = (xSemaphoreHandle)mutex;
    MSTATUS         status = ERR_NULL_POINTER;
    ubyte4 tickTime = pdMS_TO_TICKS(timeoutMs);
    BaseType_t ret;

    if (NULL == mutex)
        goto exit;

    ret = xSemaphoreTake(xMutex, tickTime);
    if (pdFALSE == ret)
    {
        status = ERR_RTOS_SEM_WAIT;
    }
    else
    {
        status = OK;
    }

exit:
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
FREERTOS_mutexRelease(RTOS_MUTEX mutex)
{
    xSemaphoreHandle    xMutex = (xSemaphoreHandle)mutex;
    MSTATUS         status = ERR_RTOS_MUTEX_RELEASE;

    if ((xMutex) && (pdPASS == xSemaphoreGive(xMutex)))
        status = OK;

    return status;
}


/*------------------------------------------------------------------*/
extern MSTATUS
FREERTOS_mutexFree(RTOS_MUTEX* pMutex)
{
    xSemaphoreHandle mutexHandle;
    MSTATUS status = ERR_RTOS_MUTEX_FREE;

    if ((NULL == pMutex) || (NULL == *pMutex))
        goto exit;

    mutexHandle = (xSemaphoreHandle)(*pMutex);
    vQueueDelete(mutexHandle);
    *pMutex = NULL;
    status = OK;

exit:
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
FREERTOS_semCreate(RTOS_SEM *pSem, sbyte4 initialValue)
{
    MSTATUS status = ERR_NULL_POINTER;
    xSemaphoreHandle xSem = NULL;

    if (NULL == pSem)
        goto exit;

    xSem = xSemaphoreCreateCounting(MOCANA_DEFAULT_FREERTOS_MAX_SEM_COUNT, initialValue);
    if (xSem != NULL)
    {
        *pSem = xSem;
        status = OK;
    }
    else
    {
        status = ERR_RTOS_SEM_INIT;
    }

exit:
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
FREERTOS_semTryWait(RTOS_SEM sem)
{
    MSTATUS status = OK;

    if (NULL == sem)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (pdTRUE != xSemaphoreTake((xSemaphoreHandle)sem, 0))
    {
        status = ERR_RTOS_SEM_WAIT;
        goto exit;
    }

    status = OK;

exit:
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
FREERTOS_recursiveMutexCreate(RTOS_MUTEX* pMutex, enum mutexTypes mutexType, int mutexCount)
{
    MSTATUS          status = ERR_RTOS_MUTEX_CREATE;
    xSemaphoreHandle xMutex;

    MOC_UNUSED(mutexType);
    MOC_UNUSED(mutexCount);

    xMutex = xSemaphoreCreateRecursiveMutex();

    if (xMutex != NULL)
    {
        *pMutex = xMutex;
        status = OK;
    }
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
FREERTOS_recursiveMutexWait(RTOS_MUTEX mutex)
{
    xSemaphoreHandle xMutex = (xSemaphoreHandle) mutex;
    MSTATUS          status = ERR_RTOS_MUTEX_WAIT;

    if((xMutex) && (xSemaphoreTakeRecursive(xMutex, (portTickType) portMAX_DELAY ) == pdPASS))
    {
        status = OK;
    }

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
FREERTOS_recursiveMutexRelease(RTOS_MUTEX mutex)
{
    xSemaphoreHandle xMutex = (xSemaphoreHandle) mutex;
    MSTATUS status = ERR_RTOS_MUTEX_RELEASE;

    if ((xMutex) && (pdPASS == xSemaphoreGiveRecursive(xMutex)))
        status = OK;

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
FREERTOS_recursiveMutexFree(RTOS_MUTEX *mutex)
{
    return FREERTOS_mutexFree(mutex);
}
/*------------------------------------------------------------------*/

extern ubyte4
FREERTOS_getUpTimeInMS(void)
{
    return (ubyte4)(xTaskGetTickCount() * portTICK_RATE_MS);
}


/*------------------------------------------------------------------*/

extern ubyte4
FREERTOS_deltaMS(const moctime_t* origin, moctime_t* current)
{
    ubyte4 tval;
    ubyte4 retVal = 0;

    tval = (ubyte4)(xTaskGetTickCount());

    /* origin and current can point to the same struct */
    if (origin)
    {
        ubyte4 diff = tval - origin->u.time[0];
        retVal = (ubyte4)(diff * portTICK_RATE_MS);
    }

    if (current)
    {
        current->u.time[0] = tval;
    }

    return retVal;

}


/*------------------------------------------------------------------*/

extern ubyte4
FREERTOS_deltaConstMS(const moctime_t* origin, const moctime_t* current)
{
/* #error Need to customize: This appears to be implementation specific --- FreeRTOS does not appear to have standard APIs for time related functions */
    sbyte4 diff_sec, diff_msec;

    diff_sec  = (sbyte4)(current->u.time[0] - origin->u.time[0]);
    diff_msec = (sbyte4)(current->u.time[1] - origin->u.time[1]);

    while ( diff_msec < 0 && diff_sec > 0)
    {
        diff_msec += 1000;
        diff_sec--;
    }

    /* belt ... */
    if ( diff_msec < 0) diff_msec = 0;

    /* ... and suspenders */
    if ( diff_sec < 0) diff_sec = 0;

    return diff_sec * 1000 + diff_msec;
}


/*------------------------------------------------------------------*/

extern moctime_t *
FREERTOS_timerAddMS(moctime_t* pTimer, ubyte4 addNumMS)
{
/* #error Need to customize: This appears to be implementation specific --- FreeRTOS does not appear to have standard APIs for time related functions */
    pTimer->u.time[0] += addNumMS / 1000;
    pTimer->u.time[1] += addNumMS % 1000;

    while (pTimer->u.time[1] > 1000)
    {
        pTimer->u.time[1] -= 1000;
        pTimer->u.time[0]++;
    }

    return pTimer;
}


/*------------------------------------------------------------------*/

extern void
FREERTOS_sleepMS(ubyte4 sleepTimeInMS)
{
    vTaskDelay((portTickType)(sleepTimeInMS / portTICK_RATE_MS));
}


/*------------------------------------------------------------------*/

extern MSTATUS
FREERTOS_createThread(void(*threadEntry)(void*), void* context, ubyte4 threadType, RTOS_THREAD *pRetTid)
{
    int     priority    = MOCANA_DEFAULT_FREERTOS_TASK_PRIORITY;
    int     stackSize   = MOCANA_DEFAULT_FREERTOS_STACK_SIZE;
    char    *threadName;
    MSTATUS status = OK;

    switch (threadType)
    {
        case ENTROPY_THREAD:
        {
            threadName = DIGI_FREERTOS_ENTROPY_TASK_NAME;
            stackSize  = DIGI_FREERTOS_ENTROPY_STACK_SIZE;
            priority   = DIGI_FREERTOS_ENTROPY_TASK_PRIORITY;
            break;
        }

        case SSL_UPCALL_DAEMON:
        {
            threadName = DIGI_FREERTOS_SSL_UPCALL_DAEMON_TASK_NAME;
            stackSize  = DIGI_FREERTOS_SSL_UPCALL_DAEMON_STACK_SIZE;
            priority   = DIGI_FREERTOS_SSL_UPCALL_DAEMON_TASK_PRIORITY;
            break;
        }

        case SSH_UPCALL_DAEMON:
        {
            threadName = DIGI_FREERTOS_SSH_UPCALL_DAEMON_TASK_NAME;
            stackSize  = DIGI_FREERTOS_SSH_UPCALL_DAEMON_STACK_SIZE;
            priority   = DIGI_FREERTOS_SSH_UPCALL_DAEMON_TASK_PRIORITY;
            break;
        }

        case SSL_MAIN:
        {
            threadName = DIGI_FREERTOS_SSL_MAIN_TASK_NAME;
            stackSize  = DIGI_FREERTOS_SSL_MAIN_STACK_SIZE;
            priority   = DIGI_FREERTOS_SSL_MAIN_TASK_PRIORITY;
            break;
        }

        case SSL_SERVER_SESSION:
        {
            threadName = DIGI_FREERTOS_SSL_SERVER_SESSION_TASK_NAME;
            stackSize  = DIGI_FREERTOS_SSL_SERVER_SESSION_STACK_SIZE;
            priority   = DIGI_FREERTOS_SSL_SERVER_SESSION_TASK_PRIORITIY;
            break;
        }

        case DTLS_MAIN:
        {
            threadName = DIGI_FREERTOS_DTLS_MAIN_TASK_NAME;
            stackSize  = DIGI_FREERTOS_DTLS_MAIN_STACK_SIZE;
            priority   = DIGI_FREERTOS_DTLS_MAIN_TASK_PRIORITY;
            break;
        }

        case SSH_MAIN:
        {
            threadName = DIGI_FREERTOS_SSH_MAIN_TASK_NAME;
            stackSize  = DIGI_FREERTOS_SSH_MAIN_STACK_SIZE;
            priority   = DIGI_FREERTOS_SSH_MAIN_TASK_PRIORITY;
            break;
        }

        case SSH_SESSION:
        {
            threadName = DIGI_FREERTOS_SSH_SESSION_TASK_NAME;
            stackSize  = DIGI_FREERTOS_SSH_SESSION_STACK_SIZE;
            priority   = DIGI_FREERTOS_SSH_SESSION_TASK_PRIORITY;
            break;
        }

        case HTTP_THREAD:
        {
            threadName = DIGI_FREERTOS_HTTP_TASK_NAME;
            stackSize  = DIGI_FREERTOS_HTTP_STACK_SIZE;
            priority   = DIGI_FREERTOS_HTTP_TASK_PRIORITY;
            break;
        }

        case EAP_MAIN:
        {
            threadName = DIGI_FREERTOS_EAP_MAIN_TASK_NAME;
            stackSize  = DIGI_FREERTOS_EAP_MAIN_STACK_SIZE;
            priority   = DIGI_FREERTOS_EAP_MAIN_TASK_PRIORITY;
            break;
        }

        case DEBUG_CONSOLE:
        {
            threadName = DIGI_FREERTOS_DEBUG_CONSOLE_TASK_NAME;
            stackSize  = DIGI_FREERTOS_DEBUG_CONSOLE_STACK_SIZE;
            priority   = DIGI_FREERTOS_DEBUG_CONSOLE_TASK_PRIORITY;
            break;
        }

        case MOC_IPV4:
        {
            threadName = DIGI_FREERTOS_MOC_IPV4_TASK_NAME;
            stackSize  = DIGI_FREERTOS_MOC_IPV4_STACK_SIZE;
            priority   = DIGI_FREERTOS_MOC_IPV4_TASK_PRIORITY;
            break;
        }

        case HARNESS_MAIN:
        {
            threadName = DIGI_FREERTOS_HARNESS_MAIN_TASK_NAME;
            stackSize  = DIGI_FREERTOS_HARNESS_MAIN_STACK_SIZE;
            priority   = DIGI_FREERTOS_HARNESS_MAIN_TASK_PRIORITY;
            break;
        }

        case HARNESS_MAIN1:
        {
            threadName = DIGI_FREERTOS_HARNESS_MAIN1_TASK_NAME;
            stackSize  = DIGI_FREERTOS_HARNESS_MAIN1_STACK_SIZE;
            priority   = DIGI_FREERTOS_HARNESS_MAIN1_TASK_PRIORITY;
            break;
        }

        case IKE_MAIN:
        {
            threadName = DIGI_FREERTOS_IKE_MAIN_TASK_NAME;
            stackSize  = DIGI_FREERTOS_IKE_MAIN_STACK_SIZE;
            priority   = DIGI_FREERTOS_IKE_MAIN_TASK_PRIORITY;
            break;
        }

        case DEBUG_THREAD:
        {
            threadName = DIGI_FREERTOS_DEBUGTHREAD_TASK_NAME;
            stackSize  = DIGI_FREERTOS_DEBUGTHREAD_STACK_SIZE;
            priority   = DIGI_FREERTOS_DEBUGTHREAD_TASK_PRIORITY;
            break;
        }

        case IPC_MAIN:
        {
            threadName = DIGI_FREERTOS_IPC_MAIN_TASK_NAME;
            stackSize  = DIGI_FREERTOS_IPC_MAIN_STACK_SIZE;
            priority   = DIGI_FREERTOS_IPC_MAIN_TASK_PRIORITY;
            break;
        }

        case RADIUS_MAIN:
        {
            threadName = DIGI_FREERTOS_RADIUS_MAIN_TASK_NAME;
            stackSize  = DIGI_FREERTOS_RADIUS_MAIN_STACK_SIZE;
            priority   = DIGI_FREERTOS_RADIUS_MAIN_TASK_PRIORITY;
            break;
        }

        case HARNESS_TEST:
        {
            threadName = DIGI_FREERTOS_HARNESS_TEST_TASK_NAME;
            stackSize  = DIGI_FREERTOS_HARNESS_TEST_STACK_SIZE;
            priority   = DIGI_FREERTOS_HARNESS_TEST_TASK_PRIORITY;
            break;
        }

        case CLI_THREAD:
        {
            threadName = DIGI_FREERTOS_CLITHREAD_TASK_NAME;
            stackSize  = DIGI_FREERTOS_CLITHREAD_STACK_SIZE;
            priority   = DIGI_FREERTOS_CLITHREAD_TASK_PRIORITY;
            break;
        }

        case FIREWALL_MAIN:
        {
            threadName = DIGI_FREERTOS_FIREWALL_MAIN_TASK_NAME;
            stackSize  = DIGI_FREERTOS_FIREWALL_MAIN_STACK_SIZE;
            priority   = DIGI_FREERTOS_FIREWALL_MAIN_TASK_PRIORITY;
            break;
        }

        case FIREWALL_SERVER:
        {
            threadName = DIGI_FREERTOS_FIREWALL_SERVER_TASK_NAME;
            stackSize  = DIGI_FREERTOS_FIREWALL_SERVER_STACK_SIZE;
            priority   = DIGI_FREERTOS_FIREWALL_SERVER_TASK_PRIORITY;
            break;
        }

        case NTP_MAIN:
        {
            threadName = DIGI_FREERTOS_NTP_MAIN_TASK_NAME;
            stackSize  = DIGI_FREERTOS_NTP_MAIN_STACK_SIZE;
            priority   = DIGI_FREERTOS_NTP_MAIN_TASK_PRIORITY;
            break;
        }

        case OCSP_MAIN:
        {
            threadName = DIGI_FREERTOS_OCSP_MAIN_TASK_NAME;
            stackSize  = DIGI_FREERTOS_OCSP_MAIN_STACK_SIZE;
            priority   = DIGI_FREERTOS_OCSP_MAIN_TASK_PRIORITY;
            break;
        }

        case CMP_MAIN:
        {
            threadName = DIGI_FREERTOS_CMP_MAIN_TASK_NAME;
            stackSize  = DIGI_FREERTOS_CMP_MAIN_STACK_SIZE;
            priority   = DIGI_FREERTOS_CMP_MAIN_TASK_PRIORITY;
            break;
        }

        case LDAP_MAIN:
        {
            threadName = DIGI_FREERTOS_LDAP_MAIN_TASK_NAME;
            stackSize  = DIGI_FREERTOS_LDAP_MAIN_STACK_SIZE;
            priority   = DIGI_FREERTOS_LDAP_MAIN_TASK_PRIORITY;
            break;
        }

        case PKI_CLIENT_MAIN:
        {
            threadName = DIGI_FREERTOS_PKI_CLIENT_MAIN_TASK_NAME;
            stackSize  = DIGI_FREERTOS_PKI_CLIENT_MAIN_STACK_SIZE;
            priority   = DIGI_FREERTOS_PKI_CLIENT_MAIN_TASK_PRIORITY;
            break;
        }

        case SRTP_MAIN:
        {
            threadName = DIGI_FREERTOS_SRTP_MAIN_TASK_NAME;
            stackSize  = DIGI_FREERTOS_SRTP_MAIN_STACK_SIZE;
            priority   = DIGI_FREERTOS_SRTP_MAIN_TASK_PRIORITY;
            break;
        }
        case DEMO_COMM_MAIN:
        {
            threadName = DIGI_FREERTOS_DEMO_IP_MAIN_TASK_NAME;
            stackSize  = DIGI_FREERTOS_DEMO_IP_MAIN_STACK_SIZE;
            priority   = DIGI_FREERTOS_DEMO_IP_MAIN_TASK_PRIORITY;
            break;
        }

        case TP_THREAD:
        {
            threadName = DIGI_FREERTOS_TPLOCAL_MAIN_TASK_NAME;
            stackSize  = DIGI_FREERTOS_TPLOCAL_MAIN_STACK_SIZE;
            priority   = DIGI_FREERTOS_TPLOCAL_MAIN_TASK_PRIORITY;
            break;
        }

        case TP_PROV_THREAD:
        {
            threadName = DIGI_FREERTOS_TPLOCAL_PROV_TASK_NAME;
            stackSize  = DIGI_FREERTOS_TPLOCAL_PROV_STACK_SIZE;
            priority   = DIGI_FREERTOS_TPLOCAL_PROV_TASK_PRIORITY;
            break;
        }

        case EST_MAIN:
        {
            threadName = DIGI_FREERTOS_EST_MAIN_TASK_NAME;
            stackSize  = DIGI_FREERTOS_EST_MAIN_STACK_SIZE;
            priority   = DIGI_FREERTOS_EST_MAIN_TASK_PRIORITY;
            break;
        }

        case UM_SCHED:
        {
            threadName = DIGI_FREERTOS_UM_SCHED_TASK_NAME;
            stackSize  = DIGI_FREERTOS_UM_SCHED_STACK_SIZE;
            priority   = DIGI_FREERTOS_UM_SCHED_TASK_PRIORITY;
            break;
        }

        default:
        {
            status = ERR_RTOS_THREAD_CREATE;
            DEBUG_PRINTNL(DEBUG_PLATFORM, "FREERTOS_createThread: unknown thread type.");
            DBUG_PRINT(DEBUG_PLATFORM, ("Unknown threadtype: %d", threadType));
            goto exit;
        }
    }

    /* threadType is ignored for this platform, use default values */
    if (pdPASS != xTaskCreate(threadEntry, (signed char *)threadName,
                              stackSize, context,
                              priority,
                              (TaskHandle_t *) pRetTid))
    {
        DEBUG_PRINTNL(DEBUG_PLATFORM, "FREERTOS_createThread: CreateThread() failed.");
        status = ERR_RTOS_THREAD_CREATE;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern void
FREERTOS_destroyThread(RTOS_THREAD handle)
{
    vTaskDelete((xTaskHandle)handle);
}


/*------------------------------------------------------------------*/

extern sbyte4
FREERTOS_currentThreadId()
{
    return (sbyte4)xTaskGetCurrentTaskHandle();
}


/*------------------------------------------------------------------*/
#if !defined(__FREERTOS_SIMULATOR__) && !defined(__RTOS_FREERTOS_ESP32__)
#if defined (__ENABLE_DIGICERT_NANOPNAC__) || defined(__ENABLE_DIGICERT_RTOS_IGNORE_TIMEDATE__)
TimeDate demo_time_date;
extern void
FREERTOS_setTimeGMT(TimeDate* td)
{
	DIGI_MEMCPY(&demo_time_date,td, sizeof(TimeDate));
}
#endif

extern MSTATUS
FREERTOS_timeGMT(TimeDate* td)
{
/* TODO: This function should get current time from a RTC chip*/
#if defined (__ENABLE_DIGICERT_NANOPNAC__) || defined(__ENABLE_DIGICERT_RTOS_IGNORE_TIMEDATE__)
	DIGI_MEMCPY(td,&demo_time_date, sizeof(TimeDate));
	return OK;
#else
    FF_SystemTime_t xTime = {0};
    FF_GetSystemTime(&xTime);
    DIGI_MEMSET(td,0,sizeof(TimeDate));
    td->m_year = xTime.Year - 1970;
    td->m_month  = (ubyte)xTime.Month;
    td->m_day    = (ubyte)xTime.Day;
    td->m_hour   = (ubyte)xTime.Hour;
    td->m_minute = (ubyte)xTime.Minute;
    td->m_second = (ubyte)xTime.Second;
    return OK;
#endif

}
#else

extern MSTATUS
FREERTOS_timeGMT(TimeDate* td)
{
    time_t      currentTime = time(NULL);
    struct tm*  pCurrentTime = gmtime(&currentTime);

    if (NULL == td)
        return ERR_NULL_POINTER;

    if (NULL == pCurrentTime)
        return ERR_RTOS_GMT_TIME_NOT_AVAILABLE;

    td->m_year   = (ubyte)(pCurrentTime->tm_year - 70);
    td->m_month  = (ubyte)pCurrentTime->tm_mon+ 1; /* 1..12 and gmtime returns 0.11 */
    td->m_day    = (ubyte)pCurrentTime->tm_mday;
    td->m_hour   = (ubyte)pCurrentTime->tm_hour;
    td->m_minute = (ubyte)pCurrentTime->tm_min;
    td->m_second = (ubyte)pCurrentTime->tm_sec;

    return OK;
}

#endif


extern MSTATUS
FREERTOS_startScheduler(void)
{
    vTaskStartScheduler();
    return OK;
}

extern MSTATUS
FREERTOS_taskResume(RTOS_THREAD tid)
{
    vTaskResume(tid);
    return OK;
}

extern MSTATUS
FREERTOS_taskSuspend(RTOS_THREAD tid)
{
    vTaskSuspend(tid);
    return OK;
}

extern MSTATUS
FREERTOS_stopScheduler(void)
{
    return OK;
}

extern void
FREERTOS_free(void *ppPtr)
{
	vPortFree(ppPtr);
}

extern void*
FREERTOS_malloc(ubyte4 bufSize)
{
	return pvPortMalloc(bufSize);
}

#endif /* __FREERTOS_RTOS__ */
