/*
 * THREADX_alt_rtos.c
 *
 * THREADX RTOS Abstraction Layer
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

#ifdef __THREADX_RTOS__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"
#include "../platform/threadx_rtos.h"

#include <tx_api.h>
#include <nx_api.h>
#include <nx_port.h>
#include <nx_user.h>

#include <time.h>


/*------------------------------------------------------------------*/
#ifndef MOCANA_DEFAULT_THREADX_TASK_PRIORITY
#define MOCANA_DEFAULT_THREADX_TASK_PRIORITY   (11)
#endif

#ifndef MOCANA_DEFAULT_THREADX_STACK_SIZE
#define MOCANA_DEFAULT_THREADX_STACK_SIZE      (5000)
#endif

/*
 * Thread configurations, default values and the values that user can set.
 * Any new thread "type" that is introduced in the product, this file also need to be updated for the
 * product to work on free rtos
 */
#ifdef MOCANA_ENTROPY_THREADX_TASK_NAME
#define MOC_THREADX_ENTROPY_TASK_NAME                 MOCANA_ENTROPY_THREADX_TASK_NAME
#else
#define MOC_THREADX_ENTROPY_TASK_NAME                 "mocEntropy"
#endif
#ifdef MOCANA_ENTROPY_THREADX_STACK_SIZE
#define MOC_THREADX_ENTROPY_STACK_SIZE                MOCANA_ENTROPY_THREADX_STACK_SIZE
#else
#define MOC_THREADX_ENTROPY_STACK_SIZE                MOCANA_DEFAULT_THREADX_STACK_SIZE
#endif
#ifdef MOCANA_ENTROPY_THREADX_TASK_PRIORITY
#define MOC_THREADX_ENTROPY_TASK_PRIORITY             MOCANA_ENTROPY_THREADX_TASK_PRIORITY
#else
#define MOC_THREADX_ENTROPY_TASK_PRIORITY             MOCANA_DEFAULT_THREADX_TASK_PRIORITY
#endif

#ifdef MOCANA_DEBUG_CONSOLE_THREADX_TASK_NAME
#define MOC_THREADX_DEBUG_CONSOLE_TASK_NAME           MOCANA_DEBUG_CONSOLE_THREADX_TASK_NAME
#else
#define MOC_THREADX_DEBUG_CONSOLE_TASK_NAME           "mocDebugConsole"
#endif
#ifdef MOCANA_DEBUG_CONSOLE_THREADX_STACK_SIZE
#define MOC_THREADX_DEBUG_CONSOLE_STACK_SIZE          MOCANA_DEBUG_CONSOLE_THREADX_STACK_SIZE
#else
#define MOC_THREADX_DEBUG_CONSOLE_STACK_SIZE          MOCANA_DEFAULT_THREADX_STACK_SIZE
#endif
#ifdef MOCANA_DEBUG_CONSOLE_THREADX_TASK_PRIORITY
#define MOC_THREADX_DEBUG_CONSOLE_TASK_PRIORITY       MOCANA_DEBUG_CONSOLE_THREADX_TASK_PRIORITY
#else
#define MOC_THREADX_DEBUG_CONSOLE_TASK_PRIORITY       MOCANA_DEFAULT_THREADX_TASK_PRIORITY
#endif

#ifdef MOCANA_SSL_UPCALL_DAEMON_THREADX_TASK_NAME
#define MOC_THREADX_SSL_UPCALL_DAEMON_TASK_NAME        MOCANA_SSL_UPCALL_DAEMON_THREADX_TASK_NAME
#else
#define MOC_THREADX_SSL_UPCALL_DAEMON_TASK_NAME        "mocSSLUpCallDaemon"
#endif
#ifdef MOCANA_SSL_UPCALL_DAEMON_THREADX_STACK_SIZE
#define MOC_THREADX_SSL_UPCALL_DAEMON_STACK_SIZE       MOCANA_SSL_UPCALL_DAEMON_THREADX_STACK_SIZE
#else
#define MOC_THREADX_SSL_UPCALL_DAEMON_STACK_SIZE       MOCANA_DEFAULT_THREADX_STACK_SIZE
#endif
#ifdef MOCANA_SSL_UPCALL_DAEMON_THREADX_TASK_PRIORITY
#define MOC_THREADX_SSL_UPCALL_DAEMON_TASK_PRIORITY    MOCANA_SSL_UPCALL_DAEMON_THREADX_TASK_PRIORITY
#else
#define MOC_THREADX_SSL_UPCALL_DAEMON_TASK_PRIORITY    MOCANA_DEFAULT_THREADX_TASK_PRIORITY
#endif

#ifdef MOCANA_SSH_UPCALL_DAEMON_THREADX_TASK_NAME
#define MOC_THREADX_SSH_UPCALL_DAEMON_TASK_NAME        MOCANA_SSH_UPCALL_DAEMON_THREADX_TASK_NAME
#else
#define MOC_THREADX_SSH_UPCALL_DAEMON_TASK_NAME        "mocSSHUpCallDaemon"
#endif
#ifdef MOCANA_SSH_UPCALL_DAEMON_THREADX_STACK_SIZE
#define MOC_THREADX_SSH_UPCALL_DAEMON_STACK_SIZE       MOCANA_SSH_UPCALL_DAEMON_THREADX_STACK_SIZE
#else
#define MOC_THREADX_SSH_UPCALL_DAEMON_STACK_SIZE       MOCANA_DEFAULT_THREADX_STACK_SIZE
#endif
#ifdef MOCANA_SSH_UPCALL_DAEMON_THREADX_TASK_PRIORITY
#define MOC_THREADX_SSH_UPCALL_DAEMON_TASK_PRIORITY    MOCANA_SSH_UPCALL_DAEMON_THREADX_TASK_PRIORITY
#else
#define MOC_THREADX_SSH_UPCALL_DAEMON_TASK_PRIORITY    MOCANA_DEFAULT_THREADX_TASK_PRIORITY
#endif

#ifdef MOCANA_SSL_MAIN_THREADX_TASK_NAME
#define MOC_THREADX_SSL_MAIN_TASK_NAME                 MOCANA_SSL_MAIN_THREADX_TASK_NAME
#else
#define MOC_THREADX_SSL_MAIN_TASK_NAME                 "mocSSLMain"
#endif
#ifdef MOCANA_SSL_MAIN_THREADX_STACK_SIZE
#define MOC_THREADX_SSL_MAIN_STACK_SIZE                MOCANA_SSL_MAIN_THREADX_STACK_SIZE
#else
#define MOC_THREADX_SSL_MAIN_STACK_SIZE                MOCANA_DEFAULT_THREADX_STACK_SIZE
#endif
#ifdef MOCANA_SSL_MAIN_THREADX_TASK_PRIORITY
#define MOC_THREADX_SSL_MAIN_TASK_PRIORITY             MOCANA_SSL_MAIN_THREADX_TASK_PRIORITY
#else
#define MOC_THREADX_SSL_MAIN_TASK_PRIORITY             MOCANA_DEFAULT_THREADX_TASK_PRIORITY
#endif

#ifdef MOCANA_SSL_SERVER_SESSION_THREADX_TASK_NAME
#define MOC_THREADX_SSL_SERVER_SESSION_TASK_NAME       MOCANA_SSL_SERVER_SESSION_THREADX_TASK_NAME
#else
#define MOC_THREADX_SSL_SERVER_SESSION_TASK_NAME       "mocSSLServerSession"
#endif
#ifdef MOCANA_SSL_SERVER_SESSION_THREADX_STACK_SIZE
#define MOC_THREADX_SSL_SERVER_SESSION_STACK_SIZE      MOCANA_SSL_SERVER_SESSION_THREADX_STACK_SIZE
#else
#define MOC_THREADX_SSL_SERVER_SESSION_STACK_SIZE      MOCANA_DEFAULT_THREADX_STACK_SIZE
#endif
#ifdef MOCANA_SSL_SERVER_SESSION_THREADX_TASK_PRIORITY
#define MOC_THREADX_SSL_SERVER_SESSION_TASK_PRIORITIY  MOCANA_SSL_SERVER_SESSION_THREADX_TASK_PRIORITY
#else
#define MOC_THREADX_SSL_SERVER_SESSION_TASK_PRIORITIY  MOCANA_DEFAULT_THREADX_TASK_PRIORITY
#endif

#ifdef MOCANA_DTLS_MAIN_THREADX_TASK_NAME
#define MOC_THREADX_DTLS_MAIN_TASK_NAME                MOCANA_DTLS_MAIN_THREADX_TASK_NAME
#else
#define MOC_THREADX_DTLS_MAIN_TASK_NAME                "mocDTLSMain"
#endif
#ifdef MOCANA_DTLS_MAIN_THREADX_STACK_SIZE
#define MOC_THREADX_DTLS_MAIN_STACK_SIZE               MOCANA_DTLS_MAIN_THREADX_STACK_SIZE
#else
#define MOC_THREADX_DTLS_MAIN_STACK_SIZE               MOCANA_DEFAULT_THREADX_STACK_SIZE
#endif
#ifdef MOCANA_DTLS_MAIN_THREADX_TASK_PRIORITY
#define MOC_THREADX_DTLS_MAIN_TASK_PRIORITY            MOCANA_DTLS_MAIN_THREADX_TASK_PRIORITY
#else
#define MOC_THREADX_DTLS_MAIN_TASK_PRIORITY            MOCANA_DEFAULT_THREADX_TASK_PRIORITY
#endif

#ifdef MOCANA_SSH_MAIN_THREADX_TASK_NAME
#define MOC_THREADX_SSH_MAIN_TASK_NAME                 MOCANA_SSH_MAIN_THREADX_TASK_NAME
#else
#define MOC_THREADX_SSH_MAIN_TASK_NAME                 "mocSSHMain"
#endif
#ifdef MOCANA_SSH_MAIN_THREADX_STACK_SIZE
#define MOC_THREADX_SSH_MAIN_STACK_SIZE                MOCANA_SSH_MAIN_THREADX_STACK_SIZE
#else
#define MOC_THREADX_SSH_MAIN_STACK_SIZE                MOCANA_DEFAULT_THREADX_STACK_SIZE
#endif
#ifdef MOCANA_SSH_MAIN_THREADX_TASK_PRIORITY
#define MOC_THREADX_SSH_MAIN_TASK_PRIORITY             MOCANA_SSH_MAIN_THREADX_TASK_PRIORITY
#else
#define MOC_THREADX_SSH_MAIN_TASK_PRIORITY             MOCANA_DEFAULT_THREADX_TASK_PRIORITY
#endif

#ifdef MOCANA_SSH_SESSION_THREADX_TASK_NAME
#define MOC_THREADX_SSH_SESSION_TASK_NAME              MOCANA_SSH_SESSION_THREADX_TASK_NAME
#else
#define MOC_THREADX_SSH_SESSION_TASK_NAME              "mocSSHSession"
#endif
#ifdef MOCANA_SSH_SESSION_THREADX_STACK_SIZE
#define MOC_THREADX_SSH_SESSION_STACK_SIZE             MOCANA_SSH_SESSION_THREADX_STACK_SIZE
#else
#define MOC_THREADX_SSH_SESSION_STACK_SIZE             MOCANA_DEFAULT_THREADX_STACK_SIZE
#endif
#ifdef MOCANA_SSH_SESSION_THREADX_TASK_PRIORITY
#define MOC_THREADX_SSH_SESSION_TASK_PRIORITY          MOCANA_SSH_SESSION_THREADX_TASK_PRIORITY
#else
#define MOC_THREADX_SSH_SESSION_TASK_PRIORITY          MOCANA_DEFAULT_THREADX_TASK_PRIORITY
#endif

#ifdef MOCANA_HTTP_THREADX_TASK_NAME
#define MOC_THREADX_HTTP_TASK_NAME                     MOCANA_HTTP_THREADX_TASK_NAME
#else
#define MOC_THREADX_HTTP_TASK_NAME                     "mocHTTP"
#endif
#ifdef MOCANA_HTTP_THREADX_STACK_SIZE
#define MOC_THREADX_HTTP_STACK_SIZE                    MOCANA_HTTP_THREADX_STACK_SIZE
#else
#define MOC_THREADX_HTTP_STACK_SIZE                    MOCANA_DEFAULT_THREADX_STACK_SIZE
#endif
#ifdef MOCANA_HTTP_THREADX_TASK_PRIORITY
#define MOC_THREADX_HTTP_TASK_PRIORITY                 MOCANA_HTTP_THREADX_TASK_PRIORITY
#else
#define MOC_THREADX_HTTP_TASK_PRIORITY                 MOCANA_DEFAULT_THREADX_TASK_PRIORITY
#endif

#ifdef MOCANA_IKE_MAIN_THREADX_TASK_NAME
#define MOC_THREADX_IKE_MAIN_TASK_NAME                 MOCANA_IKE_MAIN_THREADX_TASK_NAME
#else
#define MOC_THREADX_IKE_MAIN_TASK_NAME                 "mocIKEMain"
#endif
#ifdef MOCANA_IKE_MAIN_THREADX_STACK_SIZE
#define MOC_THREADX_IKE_MAIN_STACK_SIZE                MOCANA_IKE_MAIN_THREADX_STACK_SIZE
#else
#define MOC_THREADX_IKE_MAIN_STACK_SIZE                MOCANA_DEFAULT_THREADX_STACK_SIZE
#endif
#ifdef MOCANA_IKE_MAIN_THREADX_TASK_PRIORITY
#define MOC_THREADX_IKE_MAIN_TASK_PRIORITY             MOCANA_IKE_MAIN_THREADX_TASK_PRIORITY
#else
#define MOC_THREADX_IKE_MAIN_TASK_PRIORITY             MOCANA_DEFAULT_THREADX_TASK_PRIORITY
#endif

#ifdef MOCANA_DEBUGTHREAD_THREADX_TASK_NAME
#define MOC_THREADX_DEBUGTHREAD_TASK_NAME              MOCANA_DEBUGTHREAD_THREADX_TASK_NAME
#else
#define MOC_THREADX_DEBUGTHREAD_TASK_NAME              "mocDebugThread"
#endif
#ifdef MOCANA_DEBUGTHREAD_THREADX_STACK_SIZE
#define MOC_THREADX_DEBUGTHREAD_STACK_SIZE             MOCANA_DEBUGTHREAD_THREADX_STACK_SIZE
#else
#define MOC_THREADX_DEBUGTHREAD_STACK_SIZE             MOCANA_DEFAULT_THREADX_STACK_SIZE
#endif
#ifdef MOCANA_DEBUGTHREAD_THREADX_TASK_PRIORITY
#define MOC_THREADX_DEBUGTHREAD_TASK_PRIORITY          MOCANA_DEBUGTHREAD_THREADX_TASK_PRIORITY
#else
#define MOC_THREADX_DEBUGTHREAD_TASK_PRIORITY          MOCANA_DEFAULT_THREADX_TASK_PRIORITY
#endif

#ifdef MOCANA_EAP_MAIN_THREADX_TASK_NAME
#define MOC_THREADX_EAP_MAIN_TASK_NAME                 MOCANA_EAP_MAIN_THREADX_TASK_NAME
#else
#define MOC_THREADX_EAP_MAIN_TASK_NAME                 "mocEAPMain"
#endif
#ifdef MOCANA_EAP_MAIN_THREADX_STACK_SIZE
#define MOC_THREADX_EAP_MAIN_STACK_SIZE                MOCANA_EAP_MAIN_THREADX_STACK_SIZE
#else
#define MOC_THREADX_EAP_MAIN_STACK_SIZE                MOCANA_DEFAULT_THREADX_STACK_SIZE
#endif
#ifdef MOCANA_EAP_MAIN_THREADX_TASK_PRIORITY
#define MOC_THREADX_EAP_MAIN_TASK_PRIORITY             MOCANA_EAP_MAIN_THREADX_TASK_PRIORITY
#else
#define MOC_THREADX_EAP_MAIN_TASK_PRIORITY             + MOCANA_DEFAULT_THREADX_TASK_PRIORITY
#endif

#ifdef MOCANA_IPC_MAIN_THREADX_TASK_NAME
#define MOC_THREADX_IPC_MAIN_TASK_NAME                 MOCANA_IPC_MAIN_THREADX_TASK_NAME
#else
#define MOC_THREADX_IPC_MAIN_TASK_NAME                 "mocIPCMain"
#endif
#ifdef MOCANA_IPC_MAIN_THREADX_STACK_SIZE
#define MOC_THREADX_IPC_MAIN_STACK_SIZE                MOCANA_IPC_MAIN_THREADX_STACK_SIZE
#else
#define MOC_THREADX_IPC_MAIN_STACK_SIZE                MOCANA_DEFAULT_THREADX_STACK_SIZE
#endif
#ifdef MOCANA_IPC_MAIN_THREADX_TASK_PRIORITY
#define MOC_THREADX_IPC_MAIN_TASK_PRIORITY             MOCANA_IPC_MAIN_THREADX_TASK_PRIORITY
#else
#define MOC_THREADX_IPC_MAIN_TASK_PRIORITY             MOCANA_DEFAULT_THREADX_TASK_PRIORITY
#endif

#ifdef MOCANA_RADIUS_MAIN_THREADX_TASK_NAME
#define MOC_THREADX_RADIUS_MAIN_TASK_NAME              MOCANA_RADIUS_MAIN_THREADX_TASK_NAME
#else
#define MOC_THREADX_RADIUS_MAIN_TASK_NAME              "mocRadiusMain"
#endif
#ifdef MOCANA_RADIUS_MAIN_THREADX_STACK_SIZE
#define MOC_THREADX_RADIUS_MAIN_STACK_SIZE             MOCANA_RADIUS_MAIN_THREADX_STACK_SIZE
#else
#define MOC_THREADX_RADIUS_MAIN_STACK_SIZE             MOCANA_DEFAULT_THREADX_STACK_SIZE
#endif
#ifdef MOCANA_RADIUS_MAIN_THREADX_TASK_PRIORITY
#define MOC_THREADX_RADIUS_MAIN_TASK_PRIORITY          MOCANA_RADIUS_MAIN_THREADX_TASK_PRIORITY
#else
#define MOC_THREADX_RADIUS_MAIN_TASK_PRIORITY          MOCANA_DEFAULT_THREADX_TASK_PRIORITY
#endif

#ifdef MOCANA_HARNESS_MAIN_THREADX_TASK_NAME
#define MOC_THREADX_HARNESS_MAIN_TASK_NAME             MOCANA_HARNESS_MAIN_THREADX_TASK_NAME
#else
#define MOC_THREADX_HARNESS_MAIN_TASK_NAME             "mocHarnessMain"
#endif
#ifdef MOCANA_HARNESS_MAIN_THREADX_STACK_SIZE
#define MOC_THREADX_HARNESS_MAIN_STACK_SIZE            MOCANA_HARNESS_MAIN_THREADX_STACK_SIZE
#else
#define MOC_THREADX_HARNESS_MAIN_STACK_SIZE            MOCANA_DEFAULT_THREADX_STACK_SIZE
#endif
#ifdef MOCANA_HARNESS_MAIN_THREADX_TASK_PRIORITY
#define MOC_THREADX_HARNESS_MAIN_TASK_PRIORITY         MOCANA_HARNESS_MAIN_THREADX_TASK_PRIORITY
#else
#define MOC_THREADX_HARNESS_MAIN_TASK_PRIORITY         1
#endif

#ifdef MOCANA_HARNESS_MAIN1_THREADX_TASK_NAME
#define MOC_THREADX_HARNESS_MAIN1_TASK_NAME            MOCANA_HARNESS_MAIN1_THREADX_TASK_NAME
#else
#define MOC_THREADX_HARNESS_MAIN1_TASK_NAME            "mocIpsecHarness"
#endif
#ifdef MOCANA_HARNESS_MAIN1_THREADX_STACK_SIZE
#define MOC_THREADX_HARNESS_MAIN1_STACK_SIZE           MOCANA_HARNESS_MAIN1_THREADX_STACK_SIZE
#else
#define MOC_THREADX_HARNESS_MAIN1_STACK_SIZE           MOCANA_DEFAULT_THREADX_STACK_SIZE
#endif
#ifdef MOCANA_HARNESS_MAIN1_THREADX_TASK_PRIORITY
#define MOC_THREADX_HARNESS_MAIN1_TASK_PRIORITY        MOCANA_HARNESS_MAIN1_THREADX_TASK_PRIORITY
#else
#define MOC_THREADX_HARNESS_MAIN1_TASK_PRIORITY        MOCANA_DEFAULT_THREADX_TASK_PRIORITY
#endif

#ifdef MOCANA_HARNESS_TEST_THREADX_TASK_NAME
#define MOC_THREADX_HARNESS_TEST_TASK_NAME             MOCANA_HARNESS_TEST_THREADX_TASK_NAME
#else
#define MOC_THREADX_HARNESS_TEST_TASK_NAME            "mocHarnessTest"
#endif
#ifdef MOCANA_HARNESS_TEST_THREADX_STACK_SIZE
#define MOC_THREADX_HARNESS_TEST_STACK_SIZE            MOCANA_HARNESS_TEST_THREADX_STACK_SIZE
#else
#define MOC_THREADX_HARNESS_TEST_STACK_SIZE            MOCANA_DEFAULT_THREADX_STACK_SIZE
#endif
#ifdef MOCANA_HARNESS_TEST_THREADX_TASK_PRIORITY
#define MOC_THREADX_HARNESS_TEST_TASK_PRIORITY         MOCANA_HARNESS_TEST_THREADX_TASK_PRIORITY
#else
#define MOC_THREADX_HARNESS_TEST_TASK_PRIORITY         MOCANA_DEFAULT_THREADX_TASK_PRIORITY
#endif

#ifdef MOCANA_CLITHREAD_THREADX_TASK_NAME
#define MOC_THREADX_CLITHREAD_TASK_NAME                MOCANA_CLITHREAD_THREADX_TASK_NAME
#else
#define MOC_THREADX_CLITHREAD_TASK_NAME                "mocCLIThread"
#endif
#ifdef MOCANA_CLITHREAD_THREADX_STACK_SIZE
#define MOC_THREADX_CLITHREAD_STACK_SIZE               MOCANA_CLITHREAD_THREADX_STACK_SIZE
#else
#define MOC_THREADX_CLITHREAD_STACK_SIZE               MOCANA_DEFAULT_THREADX_STACK_SIZE
#endif
#ifdef MOCANA_CLITHREAD_THREADX_TASK_PRIORITY
#define MOC_THREADX_CLITHREAD_TASK_PRIORITY            MOCANA_CLITHREAD_THREADX_TASK_PRIORITY
#else
#define MOC_THREADX_CLITHREAD_TASK_PRIORITY            MOCANA_DEFAULT_THREADX_TASK_PRIORITY
#endif

#ifdef MOCANA_MOC_IPV4_THREADX_TASK_NAME
#define MOC_THREADX_MOC_IPV4_TASK_NAME                 MOCANA_MOC_IPV4_THREADX_TASK_NAME
#else
#define MOC_THREADX_MOC_IPV4_TASK_NAME                 "mocIPv4"
#endif
#ifdef MOCANA_MOC_IPV4_THREADX_STACK_SIZE
#define MOC_THREADX_MOC_IPV4_STACK_SIZE                MOCANA_MOC_IPV4_THREADX_STACK_SIZE
#else
#define MOC_THREADX_MOC_IPV4_STACK_SIZE                MOCANA_DEFAULT_THREADX_STACK_SIZE
#endif
#ifdef MOCANA_MOC_IPV4_THREADX_TASK_PRIORITY
#define MOC_THREADX_MOC_IPV4_TASK_PRIORITY             MOCANA_MOC_IPV4_THREADX_TASK_PRIORITY
#else
#define MOC_THREADX_MOC_IPV4_TASK_PRIORITY             MOCANA_DEFAULT_THREADX_TASK_PRIORITY
#endif

#ifdef MOCANA_FIREWALL_MAIN_THREADX_TASK_NAME
#define MOC_THREADX_FIREWALL_MAIN_TASK_NAME            MOCANA_FIREWALL_MAIN_THREADX_TASK_NAME
#else
#define MOC_THREADX_FIREWALL_MAIN_TASK_NAME            "mocFirewallMain"
#endif
#ifdef MOCANA_FIREWALL_MAIN_THREADX_STACK_SIZE
#define MOC_THREADX_FIREWALL_MAIN_STACK_SIZE           MOCANA_FIREWALL_MAIN_THREADX_STACK_SIZE
#else
#define MOC_THREADX_FIREWALL_MAIN_STACK_SIZE           MOCANA_DEFAULT_THREADX_STACK_SIZE
#endif
#ifdef MOCANA_FIREWALL_MAIN_THREADX_TASK_PRIORITY
#define MOC_THREADX_FIREWALL_MAIN_TASK_PRIORITY        MOCANA_FIREWALL_MAIN_THREADX_TASK_PRIORITY
#else
#define MOC_THREADX_FIREWALL_MAIN_TASK_PRIORITY        MOCANA_DEFAULT_THREADX_TASK_PRIORITY
#endif

#ifdef MOCANA_FIREWALL_SERVER_THREADX_TASK_NAME
#define MOC_THREADX_FIREWALL_SERVER_TASK_NAME          MOCANA_FIREWALL_SERVER_THREADX_TASK_NAME
#else
#define MOC_THREADX_FIREWALL_SERVER_TASK_NAME          "mocFirewallServer"
#endif
#ifdef MOCANA_FIREWALL_SERVER_THREADX_STACK_SIZE
#define MOC_THREADX_FIREWALL_SERVER_STACK_SIZE         MOCANA_FIREWALL_SERVER_THREADX_STACK_SIZE
#else
#define MOC_THREADX_FIREWALL_SERVER_STACK_SIZE         MOCANA_DEFAULT_THREADX_STACK_SIZE
#endif
#ifdef MOCANA_FIREWALL_SERVER_THREADX_TASK_PRIORITY
#define MOC_THREADX_FIREWALL_SERVER_TASK_PRIORITY      MOCANA_FIREWALL_SERVER_THREADX_TASK_PRIORITY
#else
#define MOC_THREADX_FIREWALL_SERVER_TASK_PRIORITY      MOCANA_DEFAULT_THREADX_TASK_PRIORITY
#endif

#ifdef MOCANA_NTP_MAIN_THREADX_TASK_NAME
#define MOC_THREADX_NTP_MAIN_TASK_NAME                 MOCANA_NTP_MAIN_THREADX_TASK_NAME
#else
#define MOC_THREADX_NTP_MAIN_TASK_NAME                 "mocNTPMain"
#endif
#ifdef MOCANA_NTP_MAIN_THREADX_STACK_SIZE
#define MOC_THREADX_NTP_MAIN_STACK_SIZE                MOCANA_NTP_MAIN_THREADX_STACK_SIZE
#else
#define MOC_THREADX_NTP_MAIN_STACK_SIZE                MOCANA_DEFAULT_THREADX_STACK_SIZE
#endif
#ifdef MOCANA_NTP_MAIN_THREADX_TASK_PRIORITY
#define MOC_THREADX_NTP_MAIN_TASK_PRIORITY             MOCANA_NTP_MAIN_THREADX_TASK_PRIORITY
#else
#define MOC_THREADX_NTP_MAIN_TASK_PRIORITY             MOCANA_DEFAULT_THREADX_TASK_PRIORITY
#endif

#ifdef MOCANA_OCSP_MAIN_THREADX_TASK_NAME
#define MOC_THREADX_OCSP_MAIN_TASK_NAME                MOCANA_OCSP_MAIN_THREADX_TASK_NAME
#else
#define MOC_THREADX_OCSP_MAIN_TASK_NAME                "mocOCSPMain"
#endif
#ifdef MOCANA_OCSP_MAIN_THREADX_STACK_SIZE
#define MOC_THREADX_OCSP_MAIN_STACK_SIZE               MOCANA_OCSP_MAIN_THREADX_STACK_SIZE
#else
#define MOC_THREADX_OCSP_MAIN_STACK_SIZE               MOCANA_DEFAULT_THREADX_STACK_SIZE
#endif
#ifdef MOCANA_OCSP_MAIN_THREADX_TASK_PRIORITY
#define MOC_THREADX_OCSP_MAIN_TASK_PRIORITY            MOCANA_OCSP_MAIN_THREADX_TASK_PRIORITY
#else
#define MOC_THREADX_OCSP_MAIN_TASK_PRIORITY            MOCANA_DEFAULT_THREADX_TASK_PRIORITY
#endif

#ifdef MOCANA_CMP_MAIN_THREADX_TASK_NAME
#define MOC_THREADX_CMP_MAIN_TASK_NAME                 MOCANA_CMP_MAIN_THREADX_TASK_NAME
#else
#define MOC_THREADX_CMP_MAIN_TASK_NAME                 "mocCMPMain"
#endif
#ifdef MOCANA_CMP_MAIN_THREADX_STACK_SIZE
#define MOC_THREADX_CMP_MAIN_STACK_SIZE                MOCANA_CMP_MAIN_THREADX_STACK_SIZE
#else
#define MOC_THREADX_CMP_MAIN_STACK_SIZE                MOCANA_DEFAULT_THREADX_STACK_SIZE
#endif
#ifdef MOCANA_CMP_MAIN_THREADX_TASK_PRIORITY
#define MOC_THREADX_CMP_MAIN_TASK_PRIORITY             MOCANA_CMP_MAIN_THREADX_TASK_PRIORITY
#else
#define MOC_THREADX_CMP_MAIN_TASK_PRIORITY             MOCANA_DEFAULT_THREADX_TASK_PRIORITY
#endif

#ifdef MOCANA_LDAP_MAIN_THREADX_TASK_NAME
#define MOC_THREADX_LDAP_MAIN_TASK_NAME                MOCANA_LDAP_MAIN_THREADX_TASK_NAME
#else
#define MOC_THREADX_LDAP_MAIN_TASK_NAME                "mocLDAPMain"
#endif
#ifdef MOCANA_LDAP_MAIN_THREADX_STACK_SIZE
#define MOC_THREADX_LDAP_MAIN_STACK_SIZE               MOCANA_LDAP_MAIN_THREADX_STACK_SIZE
#else
#define MOC_THREADX_LDAP_MAIN_STACK_SIZE               MOCANA_DEFAULT_THREADX_STACK_SIZE
#endif
#ifdef MOCANA_LDAP_MAIN_THREADX_TASK_PRIORITY
#define MOC_THREADX_LDAP_MAIN_TASK_PRIORITY            MOCANA_LDAP_MAIN_THREADX_TASK_PRIORITY
#else
#define MOC_THREADX_LDAP_MAIN_TASK_PRIORITY            MOCANA_DEFAULT_THREADX_TASK_PRIORITY
#endif

#ifdef MOCANA_PKI_CLIENT_MAIN_THREADX_TASK_NAME
#define MOC_THREADX_PKI_CLIENT_MAIN_TASK_NAME          MOCANA_PKI_CLIENT_MAIN_THREADX_TASK_NAME
#else
#define MOC_THREADX_PKI_CLIENT_MAIN_TASK_NAME          "mocPKIClientMain"
#endif
#ifdef MOCANA_PKI_CLIENT_MAIN_THREADX_STACK_SIZE
#define MOC_THREADX_PKI_CLIENT_MAIN_STACK_SIZE         MOCANA_PKI_CLIENT_MAIN_THREADX_STACK_SIZE
#else
#define MOC_THREADX_PKI_CLIENT_MAIN_STACK_SIZE         MOCANA_DEFAULT_THREADX_STACK_SIZE
#endif
#ifdef MOCANA_PKI_CLIENT_MAIN_THREADX_TASK_PRIORITY
#define MOC_THREADX_PKI_CLIENT_MAIN_TASK_PRIORITY      MOCANA_PKI_CLIENT_MAIN_THREADX_TASK_PRIORITY
#else
#define MOC_THREADX_PKI_CLIENT_MAIN_TASK_PRIORITY      MOCANA_DEFAULT_THREADX_TASK_PRIORITY
#endif

#ifdef MOCANA_PKI_IPC_MAIN_THREADX_TASK_NAME
#define MOC_THREADX_PKI_IPC_MAIN_TASK_NAME             MOCANA_PKI_IPC_MAIN_THREADX_TASK_NAME
#else
#define MOC_THREADX_PKI_IPC_MAIN_TASK_NAME             "mocPKIIpcMain"
#endif
#ifdef MOCANA_PKI_IPC_MAIN_THREADX_STACK_SIZE
#define MOC_THREADX_PKI_IPC_MAIN_STACK_SIZE            MOCANA_PKI_IPC_MAIN_THREADX_STACK_SIZE
#else
#define MOC_THREADX_PKI_IPC_MAIN_STACK_SIZE            MOCANA_DEFAULT_THREADX_STACK_SIZE
#endif
#ifdef MOCANA_PKI_IPC_MAIN_THREADX_TASK_PRIORITY
#define MOC_THREADX_PKI_IPC_MAIN_TASK_PRIORITY         MOCANA_PKI_IPC_MAIN_THREADX_TASK_PRIORITY
#else
#define MOC_THREADX_PKI_IPC_MAIN_TASK_PRIORITY         MOCANA_DEFAULT_THREADX_TASK_PRIORITY
#endif

#ifdef MOCANA_SRTP_MAIN_THREADX_TASK_NAME
#define MOC_THREADX_SRTP_MAIN_TASK_NAME                MOCANA_SRTP_MAIN_THREADX_TASK_NAME
#else
#define MOC_THREADX_SRTP_MAIN_TASK_NAME                "mocSRTPMain"
#endif
#ifdef MOCANA_SRTP_MAIN_THREADX_STACK_SIZE
#define MOC_THREADX_SRTP_MAIN_STACK_SIZE               MOCANA_SRTP_MAIN_THREADX_STACK_SIZE
#else
#define MOC_THREADX_SRTP_MAIN_STACK_SIZE               MOCANA_DEFAULT_THREADX_STACK_SIZE
#endif
#ifdef MOCANA_SRTP_MAIN_THREADX_TASK_PRIORITY
#define MOC_THREADX_SRTP_MAIN_TASK_PRIORITY            MOCANA_SRTP_MAIN_THREADX_TASK_PRIORITY
#else
#define MOC_THREADX_SRTP_MAIN_TASK_PRIORITY            MOCANA_DEFAULT_THREADX_TASK_PRIORITY
#endif

#ifdef MOCANA_DEMO_IP_MAIN_THREADX_TASK_NAME
#define MOC_THREADX_DEMO_IP_MAIN_TASK_NAME             MOCANA_DEMO_IP_MAIN_THREADX_TASK_NAME
#else
#define MOC_THREADX_DEMO_IP_MAIN_TASK_NAME             "mocDEMOIPMain"
#endif
#ifdef MOCANA_DEMO_IP_MAIN_THREADX_STACK_SIZE
#define MOC_THREADX_DEMO_IP_MAIN_STACK_SIZE            MOCANA_DEMO_IP_MAIN_THREADX_STACK_SIZE
#else
#define MOC_THREADX_DEMO_IP_MAIN_STACK_SIZE            MOCANA_DEFAULT_THREADX_STACK_SIZE
#endif
#ifdef MOCANA_DEMO_IP_MAIN_THREADX_TASK_PRIORITY
#define MOC_THREADX_DEMO_IP_MAIN_TASK_PRIORITY         MOCANA_DEMO_IP_MAIN_THREADX_TASK_PRIORITY
#else
#define MOC_THREADX_DEMO_IP_MAIN_TASK_PRIORITY         MOCANA_DEFAULT_THREADX_TASK_PRIORITY
#endif

#ifdef MOCANA_TPLOCAL_MAIN_THREADX_TASK_NAME
#define MOC_THREADX_TPLOCAL_MAIN_TASK_NAME                MOCANA_TPLOCAL_MAIN_THREADX_TASK_NAME
#else
#define MOC_THREADX_TPLOCAL_MAIN_TASK_NAME                "mocTPLocal"
#endif
#ifdef MOCANA_TPLOCAL_MAIN_THREADX_STACK_SIZE
#define MOC_THREADX_TPLOCAL_MAIN_STACK_SIZE               MOCANA_TPLOCAL_MAIN_THREADX_STACK_SIZE
#else
#define MOC_THREADX_TPLOCAL_MAIN_STACK_SIZE               (MOCANA_DEFAULT_THREADX_STACK_SIZE + 2000)
#endif
#ifdef MOCANA_TPLOCAL_MAIN_THREADX_TASK_PRIORITY
#define MOC_THREADX_TPLOCAL_MAIN_TASK_PRIORITY            MOCANA_TPLOCAL_MAIN_THREADX_TASK_PRIORITY
#else
#define MOC_THREADX_TPLOCAL_MAIN_TASK_PRIORITY            MOCANA_DEFAULT_THREADX_TASK_PRIORITY
#endif

#ifdef MOCANA_TPLOCAL_PROV_THREADX_TASK_NAME
#define MOC_THREADX_TPLOCAL_PROV_TASK_NAME                MOCANA_TPLOCAL_PROV_THREADX_TASK_NAME
#else
#define MOC_THREADX_TPLOCAL_PROV_TASK_NAME                "mocTPLocalProv"
#endif
#ifdef MOCANA_TPLOCAL_PROV_THREADX_STACK_SIZE
#define MOC_THREADX_TPLOCAL_PROV_STACK_SIZE               MOCANA_TPLOCAL_PROV_THREADX_STACK_SIZE
#else
#define MOC_THREADX_TPLOCAL_PROV_STACK_SIZE               MOCANA_DEFAULT_THREADX_STACK_SIZE + 2000
#endif
#ifdef MOCANA_TPLOCAL_PROV_THREADX_TASK_PRIORITY
#define MOC_THREADX_TPLOCAL_PROV_TASK_PRIORITY            MOCANA_TPLOCAL_PROV_THREADX_TASK_PRIORITY
#else
#define MOC_THREADX_TPLOCAL_PROV_TASK_PRIORITY            MOCANA_DEFAULT_THREADX_TASK_PRIORITY
#endif

#ifdef MOCANA_EST_MAIN_THREADX_TASK_NAME
#define MOC_THREADX_EST_MAIN_TASK_NAME                 MOCANA_EST_MAIN_THREADX_TASK_NAME
#else
#define MOC_THREADX_EST_MAIN_TASK_NAME                 "mocESTMain"
#endif
#ifdef MOCANA_EST_MAIN_THREADX_STACK_SIZE
#define MOC_THREADX_EST_MAIN_STACK_SIZE                MOCANA_EST_MAIN_THREADX_STACK_SIZE
#else
#define MOC_THREADX_EST_MAIN_STACK_SIZE                MOCANA_DEFAULT_THREADX_STACK_SIZE
#endif
#ifdef MOCANA_EST_MAIN_THREADX_TASK_PRIORITY
#define MOC_THREADX_EST_MAIN_TASK_PRIORITY             MOCANA_EST_MAIN_THREADX_TASK_PRIORITY
#else
#define MOC_THREADX_EST_MAIN_TASK_PRIORITY             MOCANA_DEFAULT_THREADX_TASK_PRIORITY
#endif

#ifdef MOCANA_UM_SCHED_THREADX_TASK_NAME
#define MOC_THREADX_UM_SCHED_TASK_NAME                 MOCANA_UM_SCHED_THREADX_TASK_NAME
#else
#define MOC_THREADX_UM_SCHED_TASK_NAME                 "mocUmSched"
#endif
#ifdef MOCANA_UM_SCHED_THREADX_STACK_SIZE
#define MOC_THREADX_UM_SCHED_STACK_SIZE                MOCANA_UM_SCHED_THREADX_STACK_SIZE
#else
#define MOC_THREADX_UM_SCHED_STACK_SIZE                MOCANA_DEFAULT_THREADX_STACK_SIZE
#endif
#ifdef MOCANA_UM_SCHED_THREADX_TASK_PRIORITY
#define MOC_THREADX_UM_SCHED_TASK_PRIORITY             MOCANA_UM_SCHED_THREADX_TASK_PRIORITY
#else
#define MOC_THREADX_UM_SCHED_TASK_PRIORITY             MOCANA_DEFAULT_THREADX_TASK_PRIORITY
#endif
/*------------------------------------------------------------------*/

#define MOCANA_THREAD_PRI           11
#define PT_SHARED_TCPIP_TLS_BYTE_POOL_SIZE (1024*64)

#define THREADX_UDP_QUEUE_MAX       8
#define THREADX_PACKET_POOL_SIZE    (16*1024)
#define THREADX_MAX_PACKET_SIZE     1456
#define THREADX_DRIVER_STACK_SIZE   4096
#define THREADX_IP_INSTANCE_PRIO    1

#define DEFAULT_IP_ADDRESS IP_ADDRESS(10, 8, 10, 19)
#define DEFAULT_IP_NETMASK 0xFFFFFF00UL

/* global declaration, needed by TCP and UDP */
NX_IP                mMocIpInstance;
NX_PACKET_POOL       mMocPacketPool;


static TX_BYTE_POOL  mocanaBytePool;

static char *mpMocPoolName = "Mocana Pool";
static void *mpMocMemBlock = NULL;
#if defined(__AZURE_RTOS__)
static ubyte4 mMocMemBlockSize = 0;

/* Memory block for Thread-Stacks */
static TX_BYTE_POOL  mocanaTSBytePool;
static char *mpMocTSPoolName = "Mocana Thread-Stack Pool";
static void *mpMocTSMemBlock = NULL;
static ubyte4 mMocTSMemBlockSize = 0;

static GetTimeInMSFunc fpGetEpochTime = NULL;
#endif

static char *mpMocPacketPoolBuffer = NULL;
static char *mpMocNetworkDriverStack = NULL;
static char *mpMocArpCache = NULL;

#ifndef __AZURE_RTOS__
/* at91sam9263 ethernet driver */
extern void sam9263_csp_init(void);
extern void nx_etherDriver_sam9263(struct NX_IP_DRIVER_STRUCT *driver_req);

/* mpc8360 ethernet driver */
/* extern void nx_etherDriver_mpc8360(struct NX_IP_DRIVER_STRUCT *driver_req); */

/* str912fa ethernet driver */
/* extern void nx_ether_driver(struct NX_IP_DRIVER_STRUCT *driver_req); */

#define ETHERNET_DRIVER_INIT    sam9263_csp_init
#define NX_ETHERNET_DRIVER      nx_etherDriver_sam9263

#endif /*!__AZURE_RTOS__*/

/*------------------------------------------------------------------*/

typedef VOID (*Thread_ENTRY_FUNC)(ULONG);

typedef struct _MTHREAD_CONTEXT
{
    TX_THREAD   ThreadControl;
    char        *pThreadStack;
    int         threadStackSize;
} MTHREAD_CONTEXT, *PMTHREAD_CONTEXT;


/*------------------------------------------------------------------*/

extern void
THREADX_dumpMemoryStats(ULONG *pMocMemAvail, ULONG *pMocMemFrags,
		ULONG *pMocThreadAvail, ULONG *pMocThreadFrags)
{
	ULONG available_bytes = 0;
	ULONG fragments = 0;

	if (mpMocMemBlock)
		tx_byte_pool_info_get(&mocanaBytePool,
		              NULL, &available_bytes,
		              &fragments, NULL,
		              NULL,
		              NULL);
	if (pMocMemAvail)
		*pMocMemAvail = available_bytes;

	if (pMocMemFrags)
		*pMocMemFrags = fragments;

	available_bytes = 0;
	fragments = 0;

	if (mpMocTSMemBlock)
		tx_byte_pool_info_get(&mocanaTSBytePool,
		              NULL, &available_bytes,
		              &fragments, NULL,
		              NULL,
		              NULL);
	if (pMocThreadAvail)
		*pMocThreadAvail = available_bytes;

	if (pMocThreadFrags)
		*pMocThreadFrags = fragments;


    return;
}

/*------------------------------------------------------------------*/
extern void
THREADX_setTimeMethod(GetTimeInMSFunc fpGetTimeFunc)
{
    if (NULL != fpGetTimeFunc)
        fpGetEpochTime = fpGetTimeFunc;
    return;
}


/*------------------------------------------------------------------*/

#ifdef __RTOS_AZURE__

extern MSTATUS
THREADX_setMemPoolBlock(void *pMemoryBlock, ubyte4 memoryBlockSize)
{
    if (NULL != pMemoryBlock && 0 < memoryBlockSize)
    {
      mpMocMemBlock = pMemoryBlock;
      mMocMemBlockSize = memoryBlockSize;

      return OK;
    }

    return ERR_MEM_;
}

extern MSTATUS
THREADX_setMemPoolBlockForThreadStack(void *pMemStack, ubyte4 totalThreadStackSize)
{
    if (NULL != pMemStack && 0 < totalThreadStackSize)
    {
      mpMocTSMemBlock = pMemStack;
      mMocTSMemBlockSize = totalThreadStackSize;

      return OK;
    }

    return ERR_MEM_;
}

extern void *
THREADX_getNetworkPacketPool()
{
    return (void *)&mMocPacketPool;
}

extern void *
THREADX_getNetworkIpInstance()
{
    return (void *)&mMocIpInstance;
}

#endif  /* __RTOS_AZURE__ */

/*------------------------------------------------------------------*/
void *THREADX_getMallocBytePoolPtr()
{
	return &mocanaBytePool;
}

/* Allocate a memory block of size from the kernel */
extern void*
THREADX_malloc(ubyte4 size)
{
    void *memoryBlockPtr;
    int errorCode;

    /* ThreadX does the long word alignment so we don't have to */
    errorCode=tx_byte_allocate(&mocanaBytePool,
                               (VOID **)&memoryBlockPtr,
                               (ULONG)size,
                                TX_NO_WAIT);

    if (errorCode!=TX_SUCCESS)
    {
        memoryBlockPtr=(void *)0;
    }

    return (memoryBlockPtr);
}


/*------------------------------------------------------------------*/

/* Free the memory back to the kernel */
extern void
THREADX_free(void *memoryBlockPtr)
{
    (void)tx_byte_release(memoryBlockPtr);
}


/*------------------------------------------------------------------*/
/* Allocate a memory block of size from the kernel */
static void*
THREADX_malloc_forTS(ubyte4 size)
{
    void *memoryBlockPtr;
    int errorCode;

    /* ThreadX does the long word alignment so we don't have to */
    errorCode=tx_byte_allocate(&mocanaTSBytePool,
                               (VOID **)&memoryBlockPtr,
                               (ULONG)size,
                                TX_NO_WAIT);

    if (errorCode!=TX_SUCCESS)
    {
        memoryBlockPtr=(void *)0;
    }

    return (memoryBlockPtr);
}

/*------------------------------------------------------------------*/

#ifndef __AZURE_RTOS__
extern MSTATUS
THREADX_rtosInit(void)
{
    MSTATUS status = ERR_RTOS;

    /* Note: generally threadX expects applications to manually obtain whatever memory they need
       (see demo_netx_mpc8360) - the initialization fn is manually allocating stack/heap space to
       various applications/threads as they are created.  We need to figure out a good way to do
       this... */

    DIGI_MEMSET((ubyte *)&mocanaBytePool, 0x00, sizeof(TX_BYTE_POOL));
    DIGI_MEMSET((ubyte *)&mMocPacketPool, 0x00, sizeof(NX_PACKET_POOL));
    DIGI_MEMSET((ubyte *)&mMocIpInstance, 0x00, sizeof(NX_IP));

    status = tx_byte_pool_create(&mocanaBytePool,
                                  mpMocPoolName,
                                  mpMocMemBlock,
                                 (ULONG)PT_SHARED_TCPIP_TLS_BYTE_POOL_SIZE);

    if (TX_SUCCESS != status)
    {
        goto exit;
    }

    /* initialize ethernet driver */
    ETHERNET_DRIVER_INIT();

    nx_system_initialize();

    if (NULL == (mpMocPacketPoolBuffer = MALLOC(THREADX_PACKET_POOL_SIZE)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    status = nx_packet_pool_create(&mMocPacketPool, "mocPacketPool",
                                    THREADX_MAX_PACKET_SIZE, mpMocPacketPoolBuffer,
                                    THREADX_PACKET_POOL_SIZE);

    if (NX_SUCCESS != status)
    {
        goto exit;
    }

    if (NULL == (mpMocNetworkDriverStack = MALLOC(THREADX_DRIVER_STACK_SIZE)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    status = nx_ip_create(&mMocIpInstance, "mocUdpIpInstance",
                           DEFAULT_IP_ADDRESS, DEFAULT_IP_NETMASK,
                           &mMocPacketPool, NX_ETHERNET_DRIVER,
                           mpMocNetworkDriverStack, THREADX_DRIVER_STACK_SIZE,
                           THREADX_IP_INSTANCE_PRIO);

    if (NX_SUCCESS != status)
    {
        goto exit;
    }

    if (NULL == (mpMocArpCache = MALLOC(1024)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (NX_SUCCESS != nx_arp_enable(&mMocIpInstance, (void *) mpMocArpCache, 1024))
    {
        goto exit;
    }

    /* enable UDP on the IP instance */
    if (NX_SUCCESS != nx_udp_enable(&mMocIpInstance))
    {
        goto exit;
    }

    /* enable TCP on the IP instance */
    if (NX_SUCCESS != nx_tcp_enable(&mMocIpInstance))
    {
        goto exit;
    }

    /* enable ICMP on the IP instance */
    if (NX_SUCCESS != nx_icmp_enable(&mMocIpInstance))
    {
        goto exit;
    }

    status = OK;

exit:
    return status;
}
#else
/**
 * Sets up byte pool for memory allocation
 *
 */
extern MSTATUS THREADX_rtosInit(void)
{
    MSTATUS status = ERR_RTOS;


    DIGI_MEMSET((ubyte *)&mocanaBytePool, 0x00, sizeof(TX_BYTE_POOL));

    if (NULL == mpMocMemBlock)
    {
    	status = ERR_MEM_;
    	goto exit;
    }

    status = tx_byte_pool_create(&mocanaBytePool,
                                  mpMocPoolName,
                                  mpMocMemBlock,
                                 (ULONG)mMocMemBlockSize);

    if (TX_SUCCESS != status)
    {
        goto exit;
    }

    if (NULL == mpMocTSMemBlock)
    {
    	status = ERR_MEM_;
    	goto exit;
    }

    status = tx_byte_pool_create(&mocanaTSBytePool,
                                  mpMocTSPoolName,
                                  mpMocTSMemBlock,
                                 (ULONG)mMocTSMemBlockSize);

    if (TX_SUCCESS != status)
    {
        goto exit;
    }

exit:
    return status;
} /* THREADX_rtosInit */


#endif /*!__AZURE_RTOS__*/


/*------------------------------------------------------------------*/

#ifndef __AZURE_RTOS__

extern MSTATUS
THREADX_rtosShutdown(void)
{
    MSTATUS status = OK;

    if (NULL != mpMocPacketPoolBuffer)
        FREE(mpMocPacketPoolBuffer);
    if (NULL != mpMocNetworkDriverStack)
        FREE(mpMocNetworkDriverStack);
    if (NULL != mpMocArpCache)
        FREE(mpMocArpCache);

    return status;
}

#else

extern MSTATUS
THREADX_rtosShutdown(void)
{
    MSTATUS status = OK;

    tx_byte_pool_delete(&mocanaBytePool);
    tx_byte_pool_delete(&mocanaTSBytePool);

    return status;
}

#endif

/*------------------------------------------------------------------*/

extern MSTATUS
THREADX_mutexCreate(RTOS_MUTEX* pMutex, enum mutexTypes mutexType, int mutexCount)
{
    TX_SEMAPHORE*    pTxMutex;
    MSTATUS      status = ERR_RTOS_MUTEX_CREATE;

    MOC_UNUSED(mutexType);
    MOC_UNUSED(mutexCount);

    if (NULL == (pTxMutex = MALLOC(sizeof(TX_SEMAPHORE))))
        goto exit;

    DIGI_MEMSET((ubyte *)pTxMutex, 0x00, sizeof(TX_SEMAPHORE));

    /* Creating binary semaphore */
    if (TX_SUCCESS == tx_semaphore_create(pTxMutex, "Mocana Mtx", 1))
    {
        *pMutex = (RTOS_MUTEX)pTxMutex;
        status = OK;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
THREADX_mutexWait(RTOS_MUTEX mutex)
{
    TX_SEMAPHORE*    pTxMutex = (TX_SEMAPHORE *)mutex;
    MSTATUS      status = ERR_RTOS_MUTEX_WAIT;

    if ((NULL != pTxMutex) &&
        (TX_SUCCESS == tx_semaphore_get(pTxMutex, TX_WAIT_FOREVER)))
    {
        status = OK;
    }

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
THREADX_mutexWaitEx(RTOS_MUTEX mutex, ubyte4 timeoutMs)
{
    TX_SEMAPHORE*    pTxMutex = (TX_SEMAPHORE *)mutex;
    MSTATUS      status = ERR_RTOS_SEM_WAIT;

    if ((NULL != pTxMutex) &&
        (TX_SUCCESS == tx_semaphore_get(pTxMutex, TX_TIMER_TICKS_PER_SECOND * (timeoutMs/1000))))
    {
        status = OK;
    }

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
THREADX_mutexRelease(RTOS_MUTEX mutex)
{
    TX_SEMAPHORE*    pTxMutex = (TX_SEMAPHORE *)mutex;
    MSTATUS      status  = ERR_RTOS_MUTEX_RELEASE;

    if ((NULL != pTxMutex) &&
        (TX_SUCCESS == tx_semaphore_put(pTxMutex)))
    {
         status = OK;
    }

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
THREADX_mutexFree(RTOS_MUTEX* pMutex)
{
    TX_SEMAPHORE*    pTxMutex;
    MSTATUS      status = ERR_RTOS_MUTEX_FREE;

    if ((NULL == pMutex) || (NULL == *pMutex))
        goto exit;

    pTxMutex = (TX_SEMAPHORE *)(*pMutex);

    if (TX_SUCCESS == tx_semaphore_delete(pTxMutex))
    {
        FREE(*pMutex);
        *pMutex = NULL;
        status = OK;
    }

exit:
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
THREADX_semCreate(RTOS_SEM *pSem, sbyte4 initialValue)
{
    TX_SEMAPHORE *pTxSem;
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pSem)
    	goto exit;

    if (NULL == (pTxSem = MALLOC(sizeof(TX_SEMAPHORE))))
    {
    	status = ERR_RTOS_SEM_ALLOC;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)pTxSem, 0x00, sizeof(TX_SEMAPHORE));

    /* Creating binary semaphore */
    if (TX_SUCCESS != tx_semaphore_create(pTxSem, "Mocana Sem", initialValue))
    {
    	status = ERR_RTOS_SEM_INIT;
    	goto exit;
    }

    *pSem = (RTOS_SEM)pTxSem;
    status = OK;

exit:
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
THREADX_semTryWait(RTOS_SEM sem)
{
	MSTATUS status;

	if (NULL == sem)
	{
		status = ERR_NULL_POINTER;
		goto exit;
	}

    if (TX_SUCCESS != tx_semaphore_get(sem, TX_NO_WAIT))
    {
        status = ERR_RTOS_SEM_WAIT;
        goto exit;
    }

	status = OK;

exit:
	return status;
}

/*------------------------------------------------------------------*/

extern ubyte4
THREADX_getUpTimeInMS(void)
{
    return tx_time_get();
}


/*------------------------------------------------------------------*/

extern ubyte4
THREADX_deltaMS(const moctime_t* origin, moctime_t* current)
{
    ubyte4  retVal = 0;
    ubyte4  tickCount;

    tickCount = tx_time_get();

    if (origin)
    {
        retVal = (tickCount - origin->u.time[0]);
    }

    if (current)
    {
        current->u.time[0] = tickCount;
    }

    return retVal;
}


/*------------------------------------------------------------------*/

extern void
THREADX_sleepMS(ubyte4 sleepTimeInMS)
{
    tx_thread_sleep(sleepTimeInMS);
}

/*------------------------------------------------------------------*/

extern MSTATUS
THREADX_createThread(void(*threadEntry)(void*), void* context, ubyte4 threadType, RTOS_THREAD *pRetTid)
{
    MSTATUS status = OK;
    PMTHREAD_CONTEXT    pThreadContext = NULL;
    char    *threadName = NULL;
    int     priority    = MOCANA_DEFAULT_THREADX_TASK_PRIORITY;
    int stackSize = MOCANA_DEFAULT_THREADX_STACK_SIZE;

    switch (threadType)
    {
        case ENTROPY_THREAD:
        {
            threadName = MOC_THREADX_ENTROPY_TASK_NAME;
            stackSize  = MOC_THREADX_ENTROPY_STACK_SIZE;
            priority   = MOC_THREADX_ENTROPY_TASK_PRIORITY;
            break;
        }
        case SSL_UPCALL_DAEMON:
        {
            threadName = MOC_THREADX_SSL_UPCALL_DAEMON_TASK_NAME;
            stackSize  = MOC_THREADX_SSL_UPCALL_DAEMON_STACK_SIZE;
            priority   = MOC_THREADX_SSL_UPCALL_DAEMON_TASK_PRIORITY;
            break;
        }
        case SSH_UPCALL_DAEMON:
        {
            threadName = MOC_THREADX_SSH_UPCALL_DAEMON_TASK_NAME;
            stackSize  = MOC_THREADX_SSH_UPCALL_DAEMON_STACK_SIZE;
            priority   = MOC_THREADX_SSH_UPCALL_DAEMON_TASK_PRIORITY;
            break;
        }
        case SSL_MAIN:
        {
            threadName = MOC_THREADX_SSL_MAIN_TASK_NAME;
            stackSize  = MOC_THREADX_SSL_MAIN_STACK_SIZE;
            priority   = MOC_THREADX_SSL_MAIN_TASK_PRIORITY;
            break;
        }
        case SSL_SERVER_SESSION:
        {
            threadName = MOC_THREADX_SSL_SERVER_SESSION_TASK_NAME;
            stackSize  = MOC_THREADX_SSL_SERVER_SESSION_STACK_SIZE;
            priority   = MOC_THREADX_SSL_SERVER_SESSION_TASK_PRIORITIY;
            break;
        }
        case DTLS_MAIN:
        {
            threadName = MOC_THREADX_DTLS_MAIN_TASK_NAME;
            stackSize  = MOC_THREADX_DTLS_MAIN_STACK_SIZE;
            priority   = MOC_THREADX_DTLS_MAIN_TASK_PRIORITY;
            break;
        }
        case SSH_MAIN:
        {
            threadName = MOC_THREADX_SSH_MAIN_TASK_NAME;
            stackSize  = MOC_THREADX_SSH_MAIN_STACK_SIZE;
            priority   = MOC_THREADX_SSH_MAIN_TASK_PRIORITY;
            break;
        }
        case SSH_SESSION:
        {
            threadName = MOC_THREADX_SSH_SESSION_TASK_NAME;
            stackSize  = MOC_THREADX_SSH_SESSION_STACK_SIZE;
            priority   = MOC_THREADX_SSH_SESSION_TASK_PRIORITY;
            break;
        }
        case HTTP_THREAD:
        {
            threadName = MOC_THREADX_HTTP_TASK_NAME;
            stackSize  = MOC_THREADX_HTTP_STACK_SIZE;
            priority   = MOC_THREADX_HTTP_TASK_PRIORITY;
            break;
        }
        case EAP_MAIN:
        {
            threadName = MOC_THREADX_EAP_MAIN_TASK_NAME;
            stackSize  = MOC_THREADX_EAP_MAIN_STACK_SIZE;
            priority   = MOC_THREADX_EAP_MAIN_TASK_PRIORITY;
            break;
        }
        case DEBUG_CONSOLE:
        {
            threadName = MOC_THREADX_DEBUG_CONSOLE_TASK_NAME;
            stackSize  = MOC_THREADX_DEBUG_CONSOLE_STACK_SIZE;
            priority   = MOC_THREADX_DEBUG_CONSOLE_TASK_PRIORITY;
            break;
        }
        case MOC_IPV4:
        {
            threadName = MOC_THREADX_MOC_IPV4_TASK_NAME;
            stackSize  = MOC_THREADX_MOC_IPV4_STACK_SIZE;
            priority   = MOC_THREADX_MOC_IPV4_TASK_PRIORITY;
            break;
        }
        case HARNESS_MAIN:
        {
            threadName = MOC_THREADX_HARNESS_MAIN_TASK_NAME;
            stackSize  = MOC_THREADX_HARNESS_MAIN_STACK_SIZE;
            priority   = MOC_THREADX_HARNESS_MAIN_TASK_PRIORITY;
            break;
        }
        case HARNESS_MAIN1:
        {
            threadName = MOC_THREADX_HARNESS_MAIN1_TASK_NAME;
            stackSize  = MOC_THREADX_HARNESS_MAIN1_STACK_SIZE;
            priority   = MOC_THREADX_HARNESS_MAIN1_TASK_PRIORITY;
            break;
        }
        case IKE_MAIN:
        {
            threadName = MOC_THREADX_IKE_MAIN_TASK_NAME;
            stackSize  = MOC_THREADX_IKE_MAIN_STACK_SIZE;
            priority   = MOC_THREADX_IKE_MAIN_TASK_PRIORITY;
            break;
        }
        case DEBUG_THREAD:
        {
            threadName = MOC_THREADX_DEBUGTHREAD_TASK_NAME;
            stackSize  = MOC_THREADX_DEBUGTHREAD_STACK_SIZE;
            priority   = MOC_THREADX_DEBUGTHREAD_TASK_PRIORITY;
            break;
        }
        case IPC_MAIN:
        {
            threadName = MOC_THREADX_IPC_MAIN_TASK_NAME;
            stackSize  = MOC_THREADX_IPC_MAIN_STACK_SIZE;
            priority   = MOC_THREADX_IPC_MAIN_TASK_PRIORITY;
            break;
        }
        case RADIUS_MAIN:
        {
            threadName = MOC_THREADX_RADIUS_MAIN_TASK_NAME;
            stackSize  = MOC_THREADX_RADIUS_MAIN_STACK_SIZE;
            priority   = MOC_THREADX_RADIUS_MAIN_TASK_PRIORITY;
            break;
        }
        case HARNESS_TEST:
        {
            threadName = MOC_THREADX_HARNESS_TEST_TASK_NAME;
            stackSize  = MOC_THREADX_HARNESS_TEST_STACK_SIZE;
            priority   = MOC_THREADX_HARNESS_TEST_TASK_PRIORITY;
            break;
        }
        case CLI_THREAD:
        {
            threadName = MOC_THREADX_CLITHREAD_TASK_NAME;
            stackSize  = MOC_THREADX_CLITHREAD_STACK_SIZE;
            priority   = MOC_THREADX_CLITHREAD_TASK_PRIORITY;
            break;
        }
        case FIREWALL_MAIN:
        {
            threadName = MOC_THREADX_FIREWALL_MAIN_TASK_NAME;
            stackSize  = MOC_THREADX_FIREWALL_MAIN_STACK_SIZE;
            priority   = MOC_THREADX_FIREWALL_MAIN_TASK_PRIORITY;
            break;
        }
        case FIREWALL_SERVER:
        {
            threadName = MOC_THREADX_FIREWALL_SERVER_TASK_NAME;
            stackSize  = MOC_THREADX_FIREWALL_SERVER_STACK_SIZE;
            priority   = MOC_THREADX_FIREWALL_SERVER_TASK_PRIORITY;
            break;
        }
        case NTP_MAIN:
        {
            threadName = MOC_THREADX_NTP_MAIN_TASK_NAME;
            stackSize  = MOC_THREADX_NTP_MAIN_STACK_SIZE;
            priority   = MOC_THREADX_NTP_MAIN_TASK_PRIORITY;
            break;
        }
        case OCSP_MAIN:
        {
            threadName = MOC_THREADX_OCSP_MAIN_TASK_NAME;
            stackSize  = MOC_THREADX_OCSP_MAIN_STACK_SIZE;
            priority   = MOC_THREADX_OCSP_MAIN_TASK_PRIORITY;
            break;
        }
        case CMP_MAIN:
        {
            threadName = MOC_THREADX_CMP_MAIN_TASK_NAME;
            stackSize  = MOC_THREADX_CMP_MAIN_STACK_SIZE;
            priority   = MOC_THREADX_CMP_MAIN_TASK_PRIORITY;
            break;
        }
        case LDAP_MAIN:
        {
            threadName = MOC_THREADX_LDAP_MAIN_TASK_NAME;
            stackSize  = MOC_THREADX_LDAP_MAIN_STACK_SIZE;
            priority   = MOC_THREADX_LDAP_MAIN_TASK_PRIORITY;
            break;
        }
        case PKI_CLIENT_MAIN:
        {
            threadName = MOC_THREADX_PKI_CLIENT_MAIN_TASK_NAME;
            stackSize  = MOC_THREADX_PKI_CLIENT_MAIN_STACK_SIZE;
            priority   = MOC_THREADX_PKI_CLIENT_MAIN_TASK_PRIORITY;
            break;
        }
        case SRTP_MAIN:
        {
            threadName = MOC_THREADX_SRTP_MAIN_TASK_NAME;
            stackSize  = MOC_THREADX_SRTP_MAIN_STACK_SIZE;
            priority   = MOC_THREADX_SRTP_MAIN_TASK_PRIORITY;
            break;
        }
        case DEMO_COMM_MAIN:
        {
            threadName = MOC_THREADX_DEMO_IP_MAIN_TASK_NAME;
            stackSize  = MOC_THREADX_DEMO_IP_MAIN_STACK_SIZE;
            priority   = MOC_THREADX_DEMO_IP_MAIN_TASK_PRIORITY;
            break;
        }
        case TP_THREAD:
        {
            threadName = MOC_THREADX_TPLOCAL_MAIN_TASK_NAME;
            stackSize  = MOC_THREADX_TPLOCAL_MAIN_STACK_SIZE;
            priority   = MOC_THREADX_TPLOCAL_MAIN_TASK_PRIORITY;
            break;
        }
        case TP_PROV_THREAD:
        {
            threadName = MOC_THREADX_TPLOCAL_PROV_TASK_NAME;
            stackSize  = MOC_THREADX_TPLOCAL_PROV_STACK_SIZE;
            priority   = MOC_THREADX_TPLOCAL_PROV_TASK_PRIORITY;
            break;
        }
        case EST_MAIN:
        {
            threadName = MOC_THREADX_EST_MAIN_TASK_NAME;
            stackSize  = MOC_THREADX_EST_MAIN_STACK_SIZE;
            priority   = MOC_THREADX_EST_MAIN_TASK_PRIORITY;
            break;
        }
        case UM_SCHED:
        {
            threadName = MOC_THREADX_UM_SCHED_TASK_NAME;
            stackSize  = MOC_THREADX_UM_SCHED_STACK_SIZE;
            priority   = MOC_THREADX_UM_SCHED_TASK_PRIORITY;
            break;
        }
        default:
        {
            status = ERR_RTOS_THREAD_CREATE;
            DEBUG_PRINTNL(DEBUG_PLATFORM, "THREADX_createThread: unknown thread type.");
            DBUG_PRINT(DEBUG_PLATFORM, ("Unknown threadtype: %d", threadType));
            goto exit;
        }
    }

    stackSize = stackSize * 4;

    pThreadContext = THREADX_malloc(sizeof(MTHREAD_CONTEXT));
    if (pThreadContext)
    {
        DIGI_MEMSET((ubyte *)pThreadContext, 0x00, sizeof(MTHREAD_CONTEXT));

        pThreadContext->threadStackSize = stackSize;
        pThreadContext->pThreadStack = THREADX_malloc_forTS(pThreadContext->threadStackSize);
        DIGI_MEMSET((ubyte *)pThreadContext->pThreadStack, 0x00, pThreadContext->threadStackSize);
    }

    if (NULL != pThreadContext &&
        NULL != pThreadContext->pThreadStack)
    {

        status = tx_thread_create(&(pThreadContext->ThreadControl),
                                threadName,
                                (Thread_ENTRY_FUNC)threadEntry,
                                (ULONG ) context,
                                (VOID *) pThreadContext->pThreadStack,
                                pThreadContext->threadStackSize,
                                priority,
                                priority,
                                TX_NO_TIME_SLICE,
                                TX_AUTO_START
                                );

        if (status == TX_SUCCESS)
        {
            *pRetTid = pThreadContext;
        }
        else
        {
            DEBUG_ERROR(DEBUG_PLATFORM, "THREADX_createThread: Error tx_thread_create. Return-Code = ", status);
            THREADX_free(pThreadContext->pThreadStack);
            THREADX_free(pThreadContext);
            status = ERR_RTOS_THREAD_CREATE;
        }
    }
    else
    {
        if (pThreadContext->pThreadStack)
            THREADX_free(pThreadContext->pThreadStack);

        if(pThreadContext)
            THREADX_free(pThreadContext);

        status = ERR_MEM_ALLOC_FAIL;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
THREADX_timeGMT(TimeDate *td)
{
    ubyte4 epochTime = 0;
    MSTATUS status = OK;
    struct tm* pTime = NULL;

    if (NULL == td)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL != fpGetEpochTime)
        epochTime = fpGetEpochTime();
    else
        epochTime = tx_time_get();

    /*
    if (0 == epochTime)
    {
        status = ERR_RTOS_GMT_TIME_NOT_AVAILABLE;
        goto exit;
    }
    */

    pTime = gmtime((const time_t *)&epochTime);
    if (NULL == pTime)
    {
        status = ERR_RTOS_GMT_TIME_NOT_AVAILABLE;
        goto exit;
    }

    td->m_year   = (ubyte)(pTime->tm_year - 70); /* 0,1... since 1970 and gmtime returns since 1970 */
    td->m_month  = (ubyte)pTime->tm_mon+ 1; /* 1..12 and gmtime returns 0.11 */
    td->m_day    = (ubyte)pTime->tm_mday;
    td->m_hour   = (ubyte)pTime->tm_hour;
    td->m_minute = (ubyte)pTime->tm_min;
    td->m_second = (ubyte)pTime->tm_sec;

    status = OK;

exit:
    return status;
}

/*------------------------------------------------------------------*/

static void
THREADX_terminateAndDestroy(PMTHREAD_CONTEXT pThreadContext)
{
    if (pThreadContext!= NULL)
    {
        /* Terminate handles threads at both TX_TERMINATED and
         * TX_COMPLETED state.
         */
        tx_thread_terminate(&(pThreadContext->ThreadControl));
        tx_thread_delete(&(pThreadContext->ThreadControl));
        THREADX_free(pThreadContext->pThreadStack);
        THREADX_free(pThreadContext);
    }
}

/*------------------------------------------------------------------*/

/* Method registered when the thread is destroyed. Will handle
 * cleaning up the thread when it completes.
 */
static void my_entry_exit_notify(TX_THREAD *thread_ptr, UINT condition)
{
    /* Determine if the thread has exited. */
    if (condition == TX_THREAD_EXIT)
    {
        THREADX_terminateAndDestroy((PMTHREAD_CONTEXT) thread_ptr);
    }
}

/*------------------------------------------------------------------*/

extern void
THREADX_destroyThread(RTOS_THREAD tid)
{
    UINT ret;
    UINT state = 0;
    PMTHREAD_CONTEXT  pThreadContext = (PMTHREAD_CONTEXT)tid;

    if (pThreadContext!= NULL)
    {
        ret = tx_thread_info_get(
                &(pThreadContext->ThreadControl), NULL, &state,
                NULL, NULL, NULL, NULL, NULL, NULL);
        if (TX_SUCCESS != ret)
        {
            return;
        }

        /* If the thread is completed or terminated then
         * free it immediately, otherwise register a exit notify
         * method that will perform the thread cleanup once the
         * thread has finished.
         */
        if (TX_COMPLETED == state || TX_TERMINATED == state)
        {
            THREADX_terminateAndDestroy(pThreadContext);
        }
        else
        {
            tx_thread_entry_exit_notify(
                    pThreadContext, my_entry_exit_notify);
        }
    }
}

#endif /* __THREADX_RTOS__ */

