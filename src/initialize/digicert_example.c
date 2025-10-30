/*
 * digicert_example.c
 *
 * DigiCert Example Initialization
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

#if defined(__ENABLE_MOCANA_EXAMPLES__) || defined(__ENABLE_MOCANA_BIN_EXAMPLES__)

#include "../common/mtypes.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mocana.h"
#include "../common/random.h"
#include "../common/debug_console.h"

#include <stdio.h>
/* This is a GCCE toolchain workaround
   and using main() entry point */
#ifdef __GCCE__
#include <staticlibinit_gcce.h>
#endif

/*** Only enable this, if you fully understand the implications ***/
/*** #define USE_ONLY_EXTERNAL_ENTROPY ***/

typedef void (*VOID_FUNC_PTR)(void *);

#if defined(__ENABLE_MOCANA_RADIUS_CLIENT_EXAMPLE__) && !defined(__ENABLE_MOCANA_EXAMPLE_SSH_RADIUS_PASSWORD_AUTH__)
#if defined(__ENABLE_RADIUS_SERVER__)
extern void RADIUS_EXAMPLE_SERVER_main(void*);
#elif (!defined(__ENABLE_MOCANA_EAP_RADIUS__))
extern sbyte4 RADIUS_EXAMPLE_getArgs(int argc, char *argv[]);
extern void RADIUS_EXAMPLE_main(void*);
#endif
#endif

#ifdef __ENABLE_MOCANA_DOT11_SME_EXAMPLE__
#if defined (__ENABLE_MOCANA_WPA2_WEXT__) || defined(__ENABLE_MOCANA_WPA2_WIRED__)
extern sbyte4
DOT11_SME_EXAMPLE_getArgs(int argc, char *argv[]);
#endif
#endif

#ifdef __ENABLE_MOCANA_SSH_CLIENT_EXAMPLE__
extern sbyte4 SSHC_EXAMPLE_getArgs(int argc, char *argv[]);
extern void SSH_CLIENTEXAMPLE_main(void*);
#endif

#ifdef __ENABLE_MOCANA_SSH_SERVER_EXAMPLE__
extern sbyte4 SSH_EXAMPLE_getArgs(int argc, char *argv[]);
extern void SSH_EXAMPLE_main(void*);
#endif

#ifdef __ENABLE_MOCANA_LDAP_CLIENT_EXAMPLE__
extern sbyte4 LDAP_CLIENT_EXAMPLE_getArgs(int argc, char *argv[]);
extern sbyte4 LDAP_CLIENT_EXAMPLE_main(void*);
#endif

#ifdef __ENABLE_MOCANA_UMP_CLIENT_EXAMPLE__
extern sbyte4 UMP_HTTP_EXAMPLE_getArgs(int argc, char *argv[]);
extern sbyte4 UMP_HTTP_EXAMPLE_main(void*);
#endif

#ifdef __ENABLE_MOCANA_UMPC__
extern sbyte4 UMPC_PRODUCT_getArgs(int argc, char *argv[]);
extern sbyte4 UMPC_PRODUCT_main(void*);
#endif

#ifdef __ENABLE_MOCANA_MSVB_BOOT_EXAMPLE__
extern sbyte4 MSVB_EXAMPLE_getArgs(int argc, char *argv[]);
extern sbyte4 MSVB_EXAMPLE_main(void*);
#endif

#ifdef __ENABLE_MOCANA_TPUC_SVC__
extern sbyte4 TPUC_SVC_getArgs(int argc, char *argv[]);
extern sbyte4 TPUC_SVC_main(void*);
#endif

#if ((defined (__ENABLE_MOCANA_SCEP_CLIENT_EXAMPLE__) || defined (__ENABLE_MOCANA_SCEP_CLIENT_ECDSA_EXAMPLE__)) && (!defined(__ENABLE_MOCANA_SCEPC__)))
#if defined (__ENABLE_MOCANA_SCEP_CLIENT_OPT__)
extern sbyte4 SCEP_CLIENT_EXAMPLE_getArgs(int argc, char *argv[]);
#endif
extern void SCEP_CLIENT_EXAMPLE_main(void*);
#endif

#if ((defined (__ENABLE_MOCANA_SCEPC__) || defined (__ENABLE_MOCANA_SCEP_CLIENT_ECDSA_EXAMPLE__)) && (!defined (__ENABLE_MOCANA_SCEP_CLIENT_EXAMPLE__)))
#if defined (__ENABLE_MOCANA_SCEP_CLIENT_OPT__)
extern sbyte4 SCEP_CLIENT_getArgs(int argc, char *argv[]);
#endif
extern void SCEP_CLIENT_main(void*);
#endif

#if defined (__ENABLE_MOCANA_EST_CLIENT_EXAMPLE__)
extern sbyte4 EST_CLIENT_EXAMPLE_getArgs(int argc, char *argv[]);
extern void EST_CLIENT_EXAMPLE_main(void*);
#endif

#if defined (__ENABLE_MOCANA_ESTC__)
extern sbyte4 EST_CLIENT_getArgs(int argc, char *argv[]);
extern void EST_CLIENT_main(void*);
#endif


#ifdef __ENABLE_MOCANA_TRUSTPOINT_LOCAL__
extern sbyte4 TPLA_getArgs(int argc, char *argv[]);
extern int TPLA_main(void* dummy);
#endif


#if defined (__ENABLE_MOCTPM_ESTC__)
extern sbyte4 MOCTPM_ESTC_getArgs(int argc, char *argv[]);
extern void MOCTPM_ESTC_main(void*);
#endif

#ifdef __ENABLE_MOCANA_SYSLOG_CLIENT_EXAMPLE__
extern void SYSLOG_EXAMPLE_main(void*);
#endif

#ifdef __ENABLE_MOCANA_SCEPCC_SERVER_EXAMPLE__
extern sbyte4 SCEP_SERVER_EXAMPLE_getArgs(int argc, char *argv[]);
extern void SCEP_SERVER_EXAMPLE_main(void*);
#endif

#if (defined(__ENABLE_MOCANA_SSL_SERIALIZE_PSK_EXAMPLE__))
extern sbyte4 SSL_SERIALIZE_PSK_getArgs(int argc, char *argv[]);
extern void SSL_SERIALIZE_PSK_main(void*);
#elif (defined(__ENABLE_MOCANA_DTLS_CLIENT_EXAMPLE__))
extern sbyte4 SSL_DTLS_CLIENTEXAMPLE_getArgs(int argc, char *argv[]);
extern void SSL_DTLS_CLIENTEXAMPLE_main(void*);
#elif (defined(__ENABLE_MOCANA_DTLS_SERVER_EXAMPLE__))
extern sbyte4 SSL_DTLS_WRAPPER_EXAMPLE_getArgs(int argc, char *argv[]);
extern void SSL_DTLS_EXAMPLE_main(void*);
#elif (defined(__ENABLE_MOCANA_SSL_CLIENT_EXAMPLE__))
extern sbyte4 SSL_CLIENTEXAMPLE_getArgs(int argc, char *argv[]);
extern void SSL_CLIENTEXAMPLE_main(void*);
#elif (defined(__ENABLE_MOCANA_SSL_SERVER_EXAMPLE__))
extern sbyte4 SSL_EXAMPLE_getArgs(int argc, char *argv[]);
extern void SSL_EXAMPLE_main(void*);
#endif

#if (defined(__ENABLE_MOCANA_SRTP_EXAMPLE__))
extern void
SRTP_EXAMPLE_MAIN(void *dummy);
#endif

#if (defined(__ENABLE_MOCANA_SRTP_DTLS_EXAMPLE__))
extern void
SRTP_DTLS_EXAMPLE_main(void *dummy);
#endif

#ifdef __PARAGON__
#undef __PARAGON__
#endif

#ifdef __ENABLE_MOCANA_IKE_SERVER_EXAMPLE__
#ifdef __ENABLE_MOCANA_MCP_EXAMPLE__
extern void MCP_EXAMPLE_main(void*);
extern sbyte4 MCP_EXAMPLE_getArgs(int argc, char *argv[]);
#define IKE_MAIN_ENTRY  MCP_EXAMPLE_main
#define IKE_GET_ARGS    MCP_EXAMPLE_getArgs
#else
extern void IKE_EXAMPLE_main(void*);
extern sbyte4 IKE_EXAMPLE_getArgs(int argc, char *argv[]);
#define IKE_MAIN_ENTRY  IKE_EXAMPLE_main
#define IKE_GET_ARGS    IKE_EXAMPLE_getArgs
#if ((defined(__RTOS_WINCE__) || defined(__RTOS_WIN32__) || defined(__RTOS_LINUX__)) && defined(__ENABLE_MOCANA_VPN_EXAMPLE__))
extern MSTATUS MVC_DIALOG_init(void);
extern MSTATUS MVC_DIALOG_deinit(void);
extern MSTATUS MVC_DIALOG_initdone(MSTATUS err);
#define __PARAGON__
#endif
#endif
#else

#if (defined(__ENABLE_MOCANA_EAP_AUTH__))
#if (defined(__ENABLE_MOCANA_EAP_FAST__) && defined (__ENABLE_MOCANA_SSL_ASYNC_SERVER_API__) )
extern sbyte4 EAP_FAST_AUTH_EXAMPLE_getArgs(int argc, char *argv[]);
extern void EAP_FAST_AUTH_EXAMPLE_main(void*);

#elif (defined(__ENABLE_MOCANA_EAP_PEAP__))
extern sbyte4 EAP_PEAP_AUTH_EXAMPLE_getArgs(int argc, char *argv[]);
extern sbyte4 EAP_PEAP_AUTH_EXAMPLE_main(void*);

#elif (defined(__ENABLE_MOCANA_EAP_TTLS__))
extern sbyte4 EAP_TTLS_AUTH_EXAMPLE_getArgs(int argc, char *argv[]);
extern sbyte4 EAP_TTLS_AUTH_EXAMPLE_main(void*);

#elif (defined(__ENABLE_MOCANA_EAP_TLS__))
extern sbyte4 EAP_TLS_AUTH_EXAMPLE_getArgs(int argc, char *argv[]);
extern sbyte4 EAP_TLS_AUTH_EXAMPLE_main(void*);

#elif (defined(__ENABLE_MOCANA_EAP_MD5__))
extern sbyte4 EAP_MD5_AUTH_EXAMPLE_getArgs(int argc, char *argv[]);
extern sbyte4 EAP_MD5_AUTH_EXAMPLE_main(void*);

#elif (defined(__ENABLE_MOCANA_EAP_LEAP__))
extern sbyte4 EAP_LEAP_AUTH_EXAMPLE_getArgs(int argc, char *argv[]);
extern sbyte4 EAP_LEAP_AUTH_EXAMPLE_main(void*);

#elif (defined(__ENABLE_MOCANA_EAP_MSCHAPv2__))
extern sbyte4 EAP_MSCHAPv2_AUTH_EXAMPLE_getArgs(int argc, char *argv[]);
extern sbyte4 EAP_MSCHAPv2_AUTH_EXAMPLE_main(void*);

#elif (defined(__ENABLE_MOCANA_EAP_SIM__))
extern sbyte4 EAP_SIM_AUTH_EXAMPLE_getArgs(int argc, char *argv[]);
extern sbyte4 EAP_SIM_AUTH_EXAMPLE_main(void*);

#elif (defined(__ENABLE_MOCANA_EAP_SRP__))
extern sbyte4 EAP_SRP_AUTH_EXAMPLE_getArgs(int argc, char *argv[]);
extern sbyte4 EAP_SRP_AUTH_EXAMPLE_main(void*);

#elif (defined(__ENABLE_MOCANA_EAP_PSK__))
extern sbyte4 EAP_PSK_AUTH_EXAMPLE_getArgs(int argc, char *argv[]);
extern sbyte4 EAP_PSK_AUTH_EXAMPLE_main(void*);

#elif (defined(__ENABLE_MOCANA_EAP_RADIUS__))
extern sbyte4 EAP_RADIUS_PASSTHRU_EXAMPLE_getArgs(int argc, char *argv[]);
extern void EAP_RADIUS_PASSTHRU_EXAMPLE_main(void*);
#endif

#elif (defined(__ENABLE_MOCANA_EAP_PEER__))     /* not authenticator but a peer/supplicant */

#if (defined(__ENABLE_MOCANA_EAP_FAST__) && defined (__ENABLE_MOCANA_SSL_ASYNC_CLIENT_API__) \
     && !defined(__ENABLE_MOCANA_DOT11_SME_EXAMPLE__) )
extern sbyte4 EAP_FAST_PEER_EXAMPLE_getArgs(int argc, char *argv[]);
extern void EAP_FAST_PEER_EXAMPLE_main(void*);

#elif (defined(__ENABLE_MOCANA_EAP_PEAP__) && !defined(__ENABLE_MOCANA_DOT11_SME_EXAMPLE__) && !defined(__ENABLE_MOCANA_EAP_CLI_EXAMPLES__) )
extern sbyte4 EAP_PEAP_PEER_EXAMPLE_getArgs(int argc, char *argv[]);
extern sbyte4 EAP_PEAP_PEER_EXAMPLE_main(void*);

#elif (defined(__ENABLE_MOCANA_EAP_TTLS__) && !defined(__ENABLE_MOCANA_DOT11_SME_EXAMPLE__) && !defined(__ENABLE_MOCANA_EAP_CLI_EXAMPLES__) )
extern sbyte4 EAP_TTLS_PEER_EXAMPLE_getArgs(int argc, char *argv[]);
extern sbyte4 EAP_TTLS_PEER_EXAMPLE_main(void*);

#elif (defined(__ENABLE_MOCANA_EAP_TLS__) && !defined(__ENABLE_MOCANA_DOT11_SME_EXAMPLE__) && !defined(__ENABLE_MOCANA_EAP_CLI_EXAMPLES__) )
extern sbyte4 EAP_TLS_PEER_EXAMPLE_getArgs(int argc, char *argv[]);
extern sbyte4 EAP_TLS_PEER_EXAMPLE_main(void*);

#elif (defined(__ENABLE_MOCANA_EAP_MD5__) && !defined(__ENABLE_MOCANA_DOT11_SME_EXAMPLE__)&& !defined(__ENABLE_MOCANA_EAP_CLI_EXAMPLES__) )
extern sbyte4 EAP_MD5_PEER_EXAMPLE_getArgs(int argc, char *argv[]);
extern sbyte4 EAP_MD5_PEER_EXAMPLE_main(void*);

#elif (defined(__ENABLE_MOCANA_EAP_SIM__))
extern sbyte4 EAP_SIM_PEER_EXAMPLE_getArgs(int argc, char *argv[]);
extern sbyte4 EAP_SIM_PEER_EXAMPLE_main(void*);

#elif (defined(__ENABLE_MOCANA_EAP_SRP__))
extern sbyte4 EAP_SRP_PEER_EXAMPLE_getArgs(int argc, char *argv[]);
extern sbyte4 EAP_SRP_PEER_EXAMPLE_main(void*);

#elif (defined(__ENABLE_MOCANA_EAP_LEAP__) && !defined(__ENABLE_MOCANA_DOT11_SME_EXAMPLE__) )
extern sbyte4 EAP_LEAP_PEER_EXAMPLE_getArgs(int argc, char *argv[]);
extern sbyte4 EAP_LEAP_PEER_EXAMPLE_main(void*);

#elif (defined(__ENABLE_MOCANA_EAP_MSCHAPv2__) && !defined(__ENABLE_MOCANA_DOT11_SME_EXAMPLE__) && !defined(__ENABLE_MOCANA_EAP_CLI_EXAMPLES__) )
extern sbyte4 EAP_MSCHAPv2_PEER_EXAMPLE_getArgs(int argc, char *argv[]);
extern sbyte4 EAP_MSCHAPv2_PEER_EXAMPLE_main(void*);

#elif (defined(__ENABLE_MOCANA_EAP_PSK__) && !defined(__ENABLE_MOCANA_DOT11_SME_EXAMPLE__)&& !defined(__ENABLE_MOCANA_EAP_CLI_EXAMPLES__) )
extern sbyte4 EAP_PSK_PEER_EXAMPLE_getArgs(int argc, char *argv[]);
extern sbyte4 EAP_PSK_PEER_EXAMPLE_main(void*);

#elif (defined(__ENABLE_MOCANA_EAP_CLI_EXAMPLES__) && !defined(__ENABLE_MOCANA_DOT11_SME_EXAMPLE__) )
extern void EAP_PEER_EXAMPLE_main(void*);
#endif

#endif /* defined(__ENABLE_MOCANA_EAP_AUTH__) */

#endif /* __ENABLE_MOCANA_IKE_SERVER_EXAMPLE__ */

#ifdef __ENABLE_MOCANA_DOT11_SME_EXAMPLE__
extern void DOT11_SME_EXAMPLE_main(void*);
#endif

#ifdef __ENABLE_MOCANA_HTTPCC_SERVER_EXAMPLE__
extern sbyte4 HTTP_SERVER_EXAMPLE_getArgs(int argc, char *argv[]);
extern void HTTP_SERVER_EXAMPLE_main(void*);
#endif

#ifdef __ENABLE_MOCANA_HTTP_CLIENT_EXAMPLE__
extern sbyte4 HTTP_CLIENT_EXAMPLE_getArgs(int argc, char *argv[]);
extern void HTTP_CLIENT_EXAMPLE_main(void*);
#endif

#ifdef __ENABLE_MOCANA_IPC_EXAMPLE__
extern void IPC_EXAMPLE_main(void*);
extern void IPC_EXAMPLE_startModClient(sbyte4);
extern void IPC_EXAMPLE_MSGQ_main(void*);
extern void IPC_EXAMPLE_MSGQ_startModClient(sbyte4);
#endif

#ifdef __ENABLE_MOCANA_SYSLOG_CLIENT_EXAMPLE__
extern  void SYSLOG_CLIENT_EXAMPLE_main(void *);
#endif
#ifdef __ENABLE_MOCANA_OCSP_CLIENT_EXAMPLE__
extern sbyte4 OCSP_CLIENT_EXAMPLE_getArgs(int argc, char *argv[]);
extern  void OCSP_CLIENT_EXAMPLE_main(void *);
#endif

#ifdef __ENABLE_MOCANA_CMP_CLIENT_EXAMPLE__
extern void CMP_CLIENT_EXAMPLE_ASYNC_main(void *);
#endif

#ifdef __ENABLE_MOCANA_PKI_CLIENT_EXAMPLE__
extern void PKI_CLIENT_EXAMPLE_main(void *);
#endif

#ifdef __ENABLE_MOCANA_PKI_IPC_EXAMPLE__
extern void PKI_IPC_EXAMPLE_main(void *);
#endif

#ifdef __ENABLE_MOCANA_PKI_IPC_CHILD_EXAMPLE__
extern void PKI_IPC_EXAMPLE_CHILD_main(void *dummy);
#endif

#ifdef __ENABLE_MOCANA_CRYPTO_EXAMPLE__
extern void CRYPTO_EXAMPLE_main(void *dummy);
#endif

#ifdef __FREERTOS_RTOS__
extern void FREERTOS_initMocana_main(void *dummy);
#endif


#ifdef __ENABLE_MOCANA_WPA2__
static ubyte4 s_waitTime = 60000;       /* Startup wait time */
#else
static ubyte4 s_waitTime = 5000;       /* Startup wait time */
#endif



#if (defined (__ENABLE_MOCANA_DTLS_CLIENT_EXAMPLE__) || \
     defined (__ENABLE_MOCANA_DTLS_SERVER_EXAMPLE__))
static intBoolean s_runSSL = FALSE;     /* default will run DTLS */
#endif

#ifdef __PLATFORM_HAS_GETOPT__

#if ((defined(__ENABLE_MOCANA_EAP_RADIUS__) && !defined(__ENABLE_MOCANA_DOT11_SME_EXAMPLE__) && !defined(__ENABLE_RADIUS_SERVER__)) || \
     (defined(__ENABLE_MOCANA_EAP_PEAP__) && !defined(__ENABLE_MOCANA_DOT11_SME_EXAMPLE__) && !defined(__ENABLE_MOCANA_EAP_CLI_EXAMPLES__)))
static ubyte* s_ipAddr = NULL ;     /* For Use with EAP */
#endif

#endif /* __PLATFORM_HAS_GETOPT__ */

#define MAX_APP_THREAD_ID        10
RTOS_THREAD    threadIds[MAX_APP_THREAD_ID] = {NULL};

/*------------------------------------------------------------------*/

void exampleLogFn(sbyte4 module, sbyte4 severity, sbyte *msg)
{
    sbyte *moduleStr;
    sbyte *severityStr;

    switch (module)
    {
    case MOCANA_MSS:    moduleStr = (sbyte *)"MSS"; break;
    case MOCANA_SSH:    moduleStr = (sbyte *)"SSH"; break;
    case MOCANA_SSL:    moduleStr = (sbyte *)"SSL"; break;
    case MOCANA_IKE:    moduleStr = (sbyte *)"IKE"; break;
    case MOCANA_EAP:    moduleStr = (sbyte *)"EAP"; break;
    case MOCANA_RADIUS: moduleStr = (sbyte *)"RADIUS"; break;
    case MOCANA_SRTP:   moduleStr = (sbyte *)"SRTP"; break;
    case MOCANA_HTTP:   moduleStr = (sbyte *)"HTTP"; break;
    default:            moduleStr = (sbyte *)"UNKNOWN MODULE"; break;
    }

    switch (severity)
    {
    case LS_CRITICAL:   severityStr = (sbyte *)"CRITICAL";    break;
    case LS_MAJOR:      severityStr = (sbyte *)"MAJOR";       break;
    case LS_MINOR:      severityStr = (sbyte *)"MINOR";       break;
    case LS_WARNING:    severityStr = (sbyte *)"WARNING";     break;
    case LS_INFO:       severityStr = (sbyte *)"INFO";        break;
    default:            severityStr = (sbyte *)"UNKNOWN SEVERITY"; break;
    }

#ifdef __ENABLE_MOCANA_EXAMPLE_DEBUG_CONSOLE__
    DB_PRINT ("LOG_OUTPUT: %s %s %s\n", moduleStr, severityStr, msg);
#else
    printf("LOG_OUTPUT: %s %s %s\n", moduleStr, severityStr, msg);
#endif
}

#ifdef __ENABLE_MOCANA_NANOPNAC__
extern void FREERTOS_init_for_STNucleo();
#endif
/*------------------------------------------------------------------*/

#if defined(__DISABLE_MOCANA_MAIN_FUNC_ENTRY__) && defined(__PLATFORM_HAS_GETOPT__)
#undef __PLATFORM_HAS_GETOPT__
#endif

#ifdef __PLATFORM_HAS_GETOPT__

#ifdef __OSE_RTOS__
#include <getopt.h>
#include <string.h>
#endif
#include <unistd.h>
#include <stdlib.h>

#ifndef __ENABLE_MOCANA_IKE_SERVER_EXAMPLE__
static MSTATUS
processOptions(int argc, char *argv[])
{
    MSTATUS status = OK;
    int    c;

    extern char *optarg;
    /*extern int optopt;*/

    while ((c = getopt(argc, argv, "w:o:t:a:")) != EOF) {
        switch (c) {

#ifdef __ENABLE_MOCANA_DEBUG_CONSOLE__
        case 'o':
            DEBUG_CONSOLE_setOutput(optarg);
            break;
#endif

        case 'w':
            s_waitTime = strtol(optarg, NULL, 0) * 1000;
            break;

#if (defined (__ENABLE_MOCANA_DTLS_CLIENT_EXAMPLE__) || \
     defined (__ENABLE_MOCANA_DTLS_SERVER_EXAMPLE__))
        case 't':
            s_runSSL = (strcmp(optarg, "ssl") == 0);
            break;
#endif /* DTLS client or server */

#if ((defined(__ENABLE_MOCANA_EAP_RADIUS__) && !defined(__ENABLE_MOCANA_DOT11_SME_EXAMPLE__) && !defined(__ENABLE_RADIUS_SERVER__)) || \
     (defined(__ENABLE_MOCANA_EAP_PEAP__) && !defined(__ENABLE_MOCANA_DOT11_SME_EXAMPLE__) && !defined(__ENABLE_MOCANA_EAP_CLI_EXAMPLES__)))
        case 'a':
            s_ipAddr = optarg;
            break;
#endif

        default:
            /*fprintf(stderr, "Invalid option -%c\n", optopt);*/
            status = -1;
            break;
        }
    }
    return status;
}
#endif /* __ENABLE_MOCANA_IKE_SERVER_EXAMPLE__ */
#endif /* __PLATFORM_HAS_GETOPT__ */

/*------------------------------------------------------------------*/

#if defined(__ENABLE_MOCANA_MEM_PART__) && !defined(__ENABLE_MOCANA_IKE_SERVER__)

#ifdef __ENABLE_MOCANA_EXTERNAL_STATIC_MEM__
extern char *pTpStaticMem;
extern int tpStaticMemSize;
ubyte *memData = NULL;
ubyte4 memDataSize = 0;
#else
#ifndef MOC_PARTITION_SIZE
#define MOC_PARTITION_SIZE (1024*1024)
#endif

ubyte memData[MOC_PARTITION_SIZE]; /* Update based on Application Memory Requirement */
ubyte4 memDataSize = MOC_PARTITION_SIZE;
#endif
#endif

#ifndef __ENABLE_MOCANA_TEST_MAIN__
#if !defined(__DISABLE_MOCANA_MAIN_FUNC_ENTRY__)
#if defined(__RTOS_VXWORKS__)
sbyte4 VxWmain(sbyte4 argc, char *argv[])
#else
sbyte4 main(sbyte4 argc, char *argv[])
#endif
#elif defined(__OSE_RTOS__) || defined(__INTEGRITY_RTOS__) || defined(__FREERTOS_RTOS__) || defined(__AZURE_RTOS__) || defined(__QNX_RTOS__) || defined(__RTOS_VXWORKS__)
#if defined(__ENABLE_MOCANA_TRUSTPOINT_LOCAL__)
extern sbyte4 launchTaskTPLA(sbyte4 argc, char *argv[])
#else
extern sbyte4 startMocanaExample(sbyte4 argc, char *argv[])
#endif
#else
#if defined(__ENABLE_MOCANA_TRUSTPOINT_LOCAL__)
extern sbyte4 launchTaskTPLA(void)
#else
extern sbyte4 startMocanaExample(void)
#endif
#endif
{
    RTOS_THREAD tid = RTOS_THREAD_INVALID;
#if !defined(__DISABLE_MOCANA_INIT__) || defined(__ENABLE_MOCANA_SERVICE_MAIN__)
    MSTATUS status;
#endif
#if defined(__ENABLE_MOCANA_SERVICE_MAIN__)
    MSTATUS threadStatus = ERR_RTOS_THREAD_CREATE;
#endif
#ifdef __ENABLE_MOCANA_SSH_CLIENT_EXAMPLE__
    ubyte4      tidCount = 0;
#endif
#if !defined(__DISABLE_MOCANA_MAIN_FUNC_ENTRY__) || \
    defined(__OSE_RTOS__) || defined(__INTEGRITY_RTOS__)
#if !defined(__ENABLE_MOCANA_IKE_SERVER_EXAMPLE__)
#if defined(__PLATFORM_HAS_GETOPT__)
    if (0 > processOptions(argc, argv))
        goto exit;
#else
    MOC_UNUSED(argc);
    MOC_UNUSED(argv);
#endif
#endif
#endif

#ifdef __PARAGON__
    /* Start the MVC GUI Thread here*/
    if (OK > MVC_DIALOG_init())
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: Mocana VPN Client GUI Thread failed.");
        return MVC_DIALOG_initdone((MSTATUS)-1);
    }
#endif

#ifdef __ENABLE_FIPS_POWERUP_TEST__
    if (OK > FIPS_powerupSelfTest())
    {
    	DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"powerup test failed!\n");
        goto exit;
    }
    else
    {
    	DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"powerup test passed!\n");
    }
#endif

#ifdef USE_ONLY_EXTERNAL_ENTROPY
    if (OK > RANDOM_setEntropySource(ENTROPY_SRC_EXTERNAL))
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RANDOM_setEntropySource failed ");
    }
#endif

#ifndef __DISABLE_MOCANA_INIT__

#ifdef __FREERTOS_RTOS__
#if defined(__ENABLE_MOCANA_RTOS_IGNORE_TIMEDATE__)
    TimeDate td;
    td.m_year = 51; /*2021*/
    td.m_month = 01; /*February*/
    td.m_day = 27;
    td.m_hour = 19;
    td.m_minute = 12;
    td.m_second = 50;

    RTOS_setTimeGMT(&td);
#endif

#ifdef __ENABLE_MOCANA_NANOPNAC__
    FREERTOS_init_for_STNucleo();
#endif
#endif

#if  0 /*__FREERTOS_RTOS__ */
/* TODO */
    /* Since MOCANA_initMocana() creates off threads and waits till its conditions are met, this would not work fine
       for free rtos as the scheduler has still not started. Create a thread and perform this operation in that thread */
    if (OK > RTOS_createThread(FREERTOS_initMocana_main, 0, ENTROPY_THREAD, &tid))
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread FREERTOS_initMocana_main failed ");
        gMocanaAppsRunning-- ;
    }
#else

#if defined(__ENABLE_MOCANA_MEM_PART__) && !defined(__ENABLE_MOCANA_IKE_SERVER__)
#ifdef __ENABLE_MOCANA_EXTERNAL_STATIC_MEM__
    memData = pTpStaticMem;
    memDataSize = tpStaticMemSize;
#endif
    /* Handling for Static Memory Allocation
     */
    status = (MSTATUS)MOCANA_initMocanaStaticMemory (
    (ubyte *)memData, memDataSize);
#else
     status = (MSTATUS)MOCANA_initMocana();
#endif
     if (OK != status) /* Initialization Status */
     {
         DEBUG_ERROR(DEBUG_COMMON, (sbyte*)"Init status = ", status);
         goto exit;
     }

#if 0
    /* sample code for RANDOM apis */
    {
        randomContext* pRandomContext = NULL;
        MSTATUS status = OK;
        TimeDate timeSeed;
        ubyte key[64];

        RTOS_timeGMT(&timeSeed);
        MOC_MEMCPY(key, &timeSeed, sizeof(timeSeed));
        if (OK > (status = RANDOM_newFIPS186Context((randomContext **) &pRandomContext,
                                                        64, key, 0, NULL)))
        {
            goto exit;
        }
        RANDOM_releaseContext(&pRandomContext);

        if (OK > (status = RANDOM_acquireContext(&pRandomContext)))
            goto exit;

        RANDOM_releaseContext(&pRandomContext);

        if (OK > (status = RANDOM_acquireContextEx(&pRandomContext, RANDOM_DEFAULT_ALGO)))
            goto exit;

        RANDOM_releaseContext(&pRandomContext);
    }
#endif /* #if 0 */
#endif /* else of other #if 0*/
#endif /* __DISABLE_MOCANA_INIT__ */

    if (0 > MOCANA_initLog(exampleLogFn))
        goto exit;

#if defined(__ENABLE_MOCANA_RADIUS_CLIENT_EXAMPLE__) && !defined(__ENABLE_MOCANA_EXAMPLE_SSH_RADIUS_PASSWORD_AUTH__)
#if defined(__ENABLE_RADIUS_SERVER__)
    if (OK > RTOS_createThread(RADIUS_EXAMPLE_SERVER_main, 0, RADIUS_MAIN, &tid))
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread RADIUS_EXAMPLE_SERVER_main failed.");
    }
#elif (!defined(__ENABLE_MOCANA_EAP_RADIUS__))
    if (OK > RADIUS_EXAMPLE_getArgs(argc, argv))
        goto exit;
    if (OK > RTOS_createThread(RADIUS_EXAMPLE_main, 0, RADIUS_MAIN, &tid))
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread RADIUS_EXAMPLE_main failed.");
    }
#endif
#endif

#ifdef __ENABLE_MOCANA_SSH_SERVER_EXAMPLE__
    if (OK > SSH_EXAMPLE_getArgs(argc, argv))
        goto exit;

    if (OK > RTOS_createThread(SSH_EXAMPLE_main, 0, SSH_MAIN, &tid))
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread SSH_EXAMPLE_main failed.");
    }
#endif

#ifdef __ENABLE_MOCANA_SSH_CLIENT_EXAMPLE__
    if (OK > SSHC_EXAMPLE_getArgs(argc, argv))
        goto exit;

    if (OK > RTOS_createThread(SSH_CLIENTEXAMPLE_main, 0, SSH_MAIN, &tid))
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread SSH_EXAMPLE_main failed.");
    }
    threadIds[tidCount] = tid;
    tidCount++;
#endif

#ifdef __ENABLE_MOCANA_LDAP_CLIENT_EXAMPLE__
    if (OK > LDAP_CLIENT_EXAMPLE_getArgs(argc, argv))
        goto exit;

    if (OK > RTOS_createThread(LDAP_CLIENT_EXAMPLE_main, 0, LDAP_MAIN, &tid))
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread LDAP_CLIENT_EXAMPLE_main failed.");
    }
#endif

#ifdef __ENABLE_MOCANA_UMP_CLIENT_EXAMPLE__
    if (OK > UMP_HTTP_EXAMPLE_getArgs(argc, argv))
        goto exit;

    if (OK > RTOS_createThread(UMP_HTTP_EXAMPLE_main, 0, HTTP_THREAD, &tid))
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread UMP_HTTP_EXAMPLE_main failed.");
    }
#endif

#ifdef __ENABLE_MOCANA_UMPC__
    if (OK > UMPC_PRODUCT_getArgs(argc, argv))
        goto exit;

    if (OK > RTOS_createThread(UMPC_PRODUCT_main, 0, HTTP_THREAD, &tid))
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread UMPC_PRODUCT_main failed.");
    }
#endif

#ifdef __ENABLE_MOCANA_MSVB_BOOT_EXAMPLE__
    if (OK > MSVB_EXAMPLE_getArgs(argc, argv))
        goto exit;

    if (OK > RTOS_createThread(MSVB_EXAMPLE_main, 0, HTTP_THREAD, &tid))
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread MSVB_EXAMPLE_main failed.");
    }
#endif

#ifdef __ENABLE_MOCANA_TPUC_SVC__
#if defined(__ENABLE_MOCANA_SERVICE_MAIN__)
    if (OK > (status = TPUC_SVC_getArgs(argc, argv)))
#else
    if (OK > TPUC_SVC_getArgs(argc, argv))
#endif
        goto exit;

#if defined(__ENABLE_MOCANA_SERVICE_MAIN__)
    if (OK > (status = RTOS_createThread((void (*)(void *)) TPUC_SVC_main, &threadStatus, HTTP_THREAD, &tid)))
#else
    if (OK > RTOS_createThread((void (*)(void *)) TPUC_SVC_main, 0, HTTP_THREAD, &tid))
#endif
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread UMCD_EXAMPLE_main failed.");
    }
#endif

#if ((defined (__ENABLE_MOCANA_SCEP_CLIENT_EXAMPLE__) || defined (__ENABLE_MOCANA_SCEP_CLIENT_ECDSA_EXAMPLE__)) && (!defined(__ENABLE_MOCANA_SCEPC__)))

#if defined (__ENABLE_MOCANA_SCEP_CLIENT_OPT__)
    if (OK > SCEP_CLIENT_EXAMPLE_getArgs(argc, argv))
        goto exit;
#endif

    if (OK > RTOS_createThread(SCEP_CLIENT_EXAMPLE_main, 0, SCEP_MAIN, &tid))
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread SCEP_CLIENT_EXAMPLE_main failed.");
    }
#endif

#if ((defined (__ENABLE_MOCANA_SCEPC__) || defined (__ENABLE_MOCANA_SCEP_CLIENT_ECDSA_EXAMPLE__)) && (!defined (__ENABLE_MOCANA_SCEP_CLIENT_EXAMPLE__)))

#if defined (__ENABLE_MOCANA_SCEP_CLIENT_OPT__)
    if (OK > SCEP_CLIENT_getArgs(argc, argv))
        goto exit;
#endif

    if (OK > RTOS_createThread(SCEP_CLIENT_main, 0, SCEP_MAIN, &tid))
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread SCEP_CLIENT_main failed.");
    }
#endif

#ifdef __ENABLE_MOCANA_SCEPCC_SERVER_EXAMPLE__
    if (OK > SCEP_SERVER_EXAMPLE_getArgs(argc, argv)) {
        goto exit;
    }
    if (OK > RTOS_createThread(SCEP_SERVER_EXAMPLE_main, 0, SCEP_MAIN, &tid))
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread SCEP_SERVER_EXAMPLE_main failed.");
    }
#endif


#if defined (__ENABLE_MOCANA_EST_CLIENT_EXAMPLE__)
    if (OK > EST_CLIENT_EXAMPLE_getArgs(argc, argv))
        goto exit;
    if (OK > RTOS_createThread(EST_CLIENT_EXAMPLE_main, 0, EST_MAIN, &tid))
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread EST_CLIENT_EXAMPLE_main failed.");
    }
#endif

#if (defined (__ENABLE_MOCANA_ESTC__) && !(defined(__ENABLE_MOCANA_TRUSTPOINT_LOCAL__)))
    if (OK > EST_CLIENT_getArgs(argc, argv))
    {
#ifndef __DISABLE_MOCANA_INIT__
        MOCANA_freeMocana();
#endif
        goto exit;
    }
    if (OK > RTOS_createThread(EST_CLIENT_main, 0, EST_MAIN, &tid))
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread EST_CLIENT_main failed.");
    }
#endif

#if defined (__ENABLE_MOCANA_TRUSTPOINT_LOCAL__)
    if (OK > TPLA_getArgs(argc, argv))
        goto exit;

    if (OK > RTOS_createThread((void (*)(void *))TPLA_main, 0, TP_THREAD, &tid))
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread TPLA_main failed.");
    }
#endif

#if defined (__ENABLE_MOCTPM_ESTC__)
    if (OK > MOCTPM_ESTC_getArgs(argc, argv))
        goto exit;
    if (OK > RTOS_createThread(MOCTPM_ESTC_main, 0, EST_MAIN, &tid))
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread EST_CLIENT_EXAMPLE_main failed.");
    }
#endif

#if (defined(__ENABLE_MOCANA_SSL_SERIALIZE_PSK_EXAMPLE__))
    if (OK > SSL_SERIALIZE_PSK_getArgs(argc, argv))
        goto exit;
    if (OK > RTOS_createThread(SSL_SERIALIZE_PSK_main, 0, SSL_MAIN, &tid))
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread SSL_SERIALIZE_PSK_main failed.");
    }
#elif (defined(__ENABLE_MOCANA_DTLS_CLIENT_EXAMPLE__))
    if (OK > SSL_DTLS_CLIENTEXAMPLE_getArgs(argc, argv))
        goto exit;
    if (OK > RTOS_createThread(SSL_DTLS_CLIENTEXAMPLE_main, &s_runSSL, DTLS_MAIN, &tid))
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread DTLS_CLIENTEXAMPLE_main failed.");
    }
#elif (defined(__ENABLE_MOCANA_SYSLOG_CLIENT_EXAMPLE__))
    if (OK > RTOS_createThread(SYSLOG_EXAMPLE_main, 0, SYSLOG_MAIN, &tid))
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread SYSLOG_EXAMPLE_main failed.");
    }
#elif (defined(__ENABLE_MOCANA_SRTP_DTLS_EXAMPLE__))
    if (OK > RTOS_createThread(SRTP_DTLS_EXAMPLE_main, 0, SRTP_MAIN, &tid))
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread SRTP_DTLS_EXAMPLE_main failed.");
    }
#elif (defined(__ENABLE_MOCANA_DTLS_SERVER_EXAMPLE__))
    if (OK > SSL_DTLS_WRAPPER_EXAMPLE_getArgs(argc, argv))
        goto exit;
    if (OK > RTOS_createThread(SSL_DTLS_EXAMPLE_main, &s_runSSL, DTLS_MAIN, &tid))
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread DTLS_EXAMPLE_main failed.");
    }
#elif (defined(__ENABLE_MOCANA_HTTP_CLIENT_EXAMPLE__))
    if (OK > HTTP_CLIENT_EXAMPLE_getArgs(argc, argv))
        goto exit;

    if (OK > RTOS_createThread(HTTP_CLIENT_EXAMPLE_main, 0, HTTP_THREAD, &tid))
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread HTTP_CLIENT_EXAMPLE_main failed.");
    }
#elif ((defined(__ENABLE_MOCANA_SSL_CLIENT_EXAMPLE__)) && (!(defined(__ENABLE_MOCANA_LDAP_CLIENT_EXAMPLE__) || defined(__ENABLE_MOCANA_EAP_AUTH__) || defined(__ENABLE_MOCANA_EAP_PEER__) || defined(__ENABLE_MOCANA_CFGMON__) || defined(__ENABLE_MOCANA_EST_CLIENT_EXAMPLE__) || defined(__ENABLE_MOCANA_ESTC__) || defined(__ENABLE_UMP_CLIENT_CMS_EXAMPLE__) || defined(__ENABLE_MOCANA_TPUC_SVC__) || defined(__ENABLE_MOCANA_CLI__))))
    if (OK > SSL_CLIENTEXAMPLE_getArgs(argc, argv))
        goto exit;

    if (OK > RTOS_createThread(SSL_CLIENTEXAMPLE_main, 0, SSL_MAIN, &tid))
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread SSL_CLIENTEXAMPLE_main failed.");
    }
#elif ((defined(__ENABLE_MOCANA_SSL_SERVER_EXAMPLE__)) && (!(defined(__ENABLE_MOCANA_EAP_AUTH__) || defined(__ENABLE_MOCANA_EAP_PEER__) || defined(__ENABLE_MOCANA_TRUSTPOINT_LOCAL__) )))

#ifndef __ENABLE_MOCANA_TPM_SSL_SERVER__
    if (OK > SSL_EXAMPLE_getArgs(argc, argv))
        goto exit;
#endif

    if (OK > RTOS_createThread(SSL_EXAMPLE_main, 0, SSL_MAIN, &tid))
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread SSL_EXAMPLE_main failed.");
    }
#elif (defined(__ENABLE_MOCANA_SRTP_EXAMPLE__))
    if (OK > RTOS_createThread(SRTP_EXAMPLE_MAIN, 0, SRTP_MAIN, &tid))
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread SRTP_EXAMPLE_main failed.");
    }
#endif

#ifdef __ENABLE_MOCANA_IKE_SERVER_EXAMPLE__

#if !defined(__DISABLE_MOCANA_MAIN_FUNC_ENTRY__) || \
    defined(__OSE_RTOS__) || defined(__INTEGRITY_RTOS__)
#ifndef __PARAGON__
    if (OK > IKE_GET_ARGS(argc, argv))
        goto exit;
#endif
#endif
    if (OK > RTOS_createThread(IKE_MAIN_ENTRY, 0, IKE_MAIN, &tid))
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread IKE_EXAMPLE_main failed.");
#ifdef __PARAGON__
        return MVC_DIALOG_initdone((MSTATUS)-1);
#endif
    }

#ifdef __PARAGON__
    MVC_DIALOG_initdone(OK);
#endif

#else

#if (defined(__ENABLE_MOCANA_EAP_AUTH__))
#if (defined(__ENABLE_MOCANA_EAP_FAST__) && defined (__ENABLE_MOCANA_SSL_ASYNC_SERVER_API__)) && !(defined(__ENABLE_RADIUS_SERVER__))
    if (OK > EAP_FAST_AUTH_EXAMPLE_getArgs(argc, argv))
        goto exit;
    if (OK > RTOS_createThread((VOID_FUNC_PTR)EAP_FAST_AUTH_EXAMPLE_main, 0, EAP_MAIN, &tid))
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread EAP_FAST_AUTH_EXAMPLE_main failed.");
    }
    DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"EAP_FAST_AUTH_EXAMPLE_main Called");

#elif (defined(__ENABLE_MOCANA_EAP_PEAP__))
    if (OK > EAP_PEAP_AUTH_EXAMPLE_getArgs(argc, argv))
        goto exit;
    if (OK > RTOS_createThread((VOID_FUNC_PTR)EAP_PEAP_AUTH_EXAMPLE_main, 0, EAP_MAIN, &tid))
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread EAP_PEAP_AUTH_EXAMPLE_main failed.");
    }
    DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"EAP_PEAP_AUTH_EXAMPLE_main Called");

#elif (defined(__ENABLE_MOCANA_EAP_TTLS__)  )
    if (OK > EAP_TTLS_AUTH_EXAMPLE_getArgs(argc, argv))
        goto exit;
    if (OK > RTOS_createThread((VOID_FUNC_PTR)EAP_TTLS_AUTH_EXAMPLE_main, 0, EAP_MAIN, &tid))
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread EAP_TTLS_AUTH_EXAMPLE_main failed.");
    }
    DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"EAP_TTLS_AUTH_EXAMPLE_main Called");

#elif (defined(__ENABLE_MOCANA_EAP_TLS__) && !defined(__ENABLE_MOCANA_EAP_PEAP__) && !defined(__ENABLE_MOCANA_DOT11_SME_EXAMPLE__)) && !(defined(__ENABLE_RADIUS_SERVER__))
    if (OK > EAP_TLS_AUTH_EXAMPLE_getArgs(argc, argv))
        goto exit;
    if (OK > RTOS_createThread((VOID_FUNC_PTR)EAP_TLS_AUTH_EXAMPLE_main, 0, EAP_MAIN, &tid))
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread EAP_TLS_AUTH_EXAMPLE_main failed.");
    }
    DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"EAP_TLS_AUTH_EXAMPLE_main Called");

#elif (defined(__ENABLE_MOCANA_EAP_MD5__) && !(defined(__ENABLE_RADIUS_SERVER__)))
    if (OK > EAP_MD5_AUTH_EXAMPLE_getArgs(argc, argv))
        goto exit;
    if (OK > RTOS_createThread((VOID_FUNC_PTR)EAP_MD5_AUTH_EXAMPLE_main, 0, EAP_MAIN, &tid))
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread EAP_MD5_AUTH_EXAMPLE_main failed.");
    }
    DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"EAP_MD5_AUTH_EXAMPLE_main Called");

#elif (defined(__ENABLE_MOCANA_EAP_LEAP__))
    if (OK > EAP_LEAP_AUTH_EXAMPLE_getArgs(argc, argv))
        goto exit;
    if (OK > RTOS_createThread((VOID_FUNC_PTR)EAP_LEAP_AUTH_EXAMPLE_main, 0, EAP_MAIN, &tid))
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread EAP_LEAP_AUTH_EXAMPLE_main failed.");
    }
    DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"EAP_LEAP_AUTH_EXAMPLE_main Called");

#elif (defined(__ENABLE_MOCANA_EAP_MSCHAPv2__)) && !(defined(__ENABLE_RADIUS_SERVER__))
    if (OK > EAP_MSCHAPv2_AUTH_EXAMPLE_getArgs(argc, argv))
        goto exit;
    if (OK > RTOS_createThread((VOID_FUNC_PTR)EAP_MSCHAPv2_AUTH_EXAMPLE_main, 0, EAP_MAIN, &tid))
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread EAP_MSCHAPv2_AUTH_EXAMPLE_main failed.");
    }
    DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"EAP_MSCHAPv2_AUTH_EXAMPLE_main Called");

#elif (defined(__ENABLE_MOCANA_EAP_SIM__))
    if (OK > EAP_SIM_AUTH_EXAMPLE_getArgs(argc, argv))
        goto exit;
    if (OK > RTOS_createThread((VOID_FUNC_PTR)EAP_SIM_AUTH_EXAMPLE_main, 0, EAP_MAIN, &tid))
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread EAP_SIM_AUTH_EXAMPLE_main failed.");
    }
    DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"EAP_SIM_AUTH_EXAMPLE_main Called");

#elif (defined(__ENABLE_MOCANA_EAP_PSK__))
    if (OK > EAP_PSK_AUTH_EXAMPLE_getArgs(argc, argv))
        goto exit;
    if (OK > RTOS_createThread((VOID_FUNC_PTR)EAP_PSK_AUTH_EXAMPLE_main, 0, EAP_MAIN, &tid))
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread EAP_PSK_AUTH_EXAMPLE_main failed.");
    }
    DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"EAP_PSK_AUTH_EXAMPLE_main Called");

#elif (defined(__ENABLE_MOCANA_EAP_SRP__))
    if (OK > EAP_SRP_AUTH_EXAMPLE_getArgs(argc, argv))
        goto exit;
    if (OK > RTOS_createThread((VOID_FUNC_PTR)EAP_SRP_AUTH_EXAMPLE_main, 0, EAP_MAIN, &tid))
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread EAP_SRP_AUTH_EXAMPLE_main failed.");
    }
    DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"EAP_SRP_AUTH_EXAMPLE_main Called");

#elif (defined(__ENABLE_MOCANA_EAP_RADIUS__) && !defined(__ENABLE_MOCANA_DOT11_SME_EXAMPLE__) && !defined(__ENABLE_RADIUS_SERVER__) )
    if (OK > EAP_RADIUS_PASSTHRU_EXAMPLE_getArgs(argc, argv))
        goto exit;
    if (OK > RTOS_createThread(EAP_RADIUS_PASSTHRU_EXAMPLE_main, 0, EAP_MAIN, &tid))
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread EAP_RADIUS_PASSTHRU_EXAMPLE_main failed.");
    }
    DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"EAP_RADIUS_PASSTHRU_EXAMPLE_main Called");
#endif

#elif (defined(__ENABLE_MOCANA_EAP_PEER__))

#if ( defined(__ENABLE_MOCANA_EAP_FAST__) && !defined(__ENABLE_MOCANA_DOT11_SME_EXAMPLE__))
    if (OK > EAP_FAST_PEER_EXAMPLE_getArgs(argc, argv))
        goto exit;
    if (OK > RTOS_createThread((VOID_FUNC_PTR)EAP_FAST_PEER_EXAMPLE_main, 0, EAP_MAIN, &tid))
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread EAP_FAST_PEER_EXAMPLE_main failed.");
    }
    DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"EAP_FAST_PEER_EXAMPLE_main Called");

#elif (defined(__ENABLE_MOCANA_EAP_PEAP__) && !defined(__ENABLE_MOCANA_DOT11_SME_EXAMPLE__) && !defined(__ENABLE_MOCANA_EAP_CLI_EXAMPLES__) )
    if (OK > EAP_PEAP_PEER_EXAMPLE_getArgs(argc, argv))
        goto exit;
    if (OK > RTOS_createThread((VOID_FUNC_PTR)EAP_PEAP_PEER_EXAMPLE_main, 0, EAP_MAIN, &tid))
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread EAP_PEAP_PEER_EXAMPLE_main failed.");
    }
    DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"EAP_PEAP_PEER_EXAMPLE_main Called");

#elif (defined(__ENABLE_MOCANA_EAP_TTLS__) && !defined(__ENABLE_MOCANA_DOT11_SME_EXAMPLE__) && !defined(__ENABLE_MOCANA_EAP_CLI_EXAMPLES__) )
    if (OK > EAP_TTLS_PEER_EXAMPLE_getArgs(argc, argv))
        goto exit;
    if (OK > RTOS_createThread((VOID_FUNC_PTR)EAP_TTLS_PEER_EXAMPLE_main, 0, EAP_MAIN, &tid))
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread EAP_TTLS_PEER_EXAMPLE_main failed.");
    }
    DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"EAP_TTLS_PEER_EXAMPLE_main Called");

#elif (defined(__ENABLE_MOCANA_EAP_TLS__) && !defined(__ENABLE_MOCANA_EAP_PEAP__) && !defined(__ENABLE_MOCANA_DOT11_SME_EXAMPLE__) && !defined(__ENABLE_MOCANA_EAP_CLI_EXAMPLES__))
    if (OK > EAP_TLS_PEER_EXAMPLE_getArgs(argc, argv))
        goto exit;
    if (OK > RTOS_createThread((VOID_FUNC_PTR)EAP_TLS_PEER_EXAMPLE_main, 0, EAP_MAIN, &tid))
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread EAP_TLS_PEER_EXAMPLE_main failed.");
    }
    DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"EAP_TLS_PEER_EXAMPLE_main Called");

#elif (defined(__ENABLE_MOCANA_EAP_MD5__) && !defined(__ENABLE_MOCANA_DOT11_SME_EXAMPLE__) && !defined(__ENABLE_MOCANA_EAP_CLI_EXAMPLES__) )
    if (OK > EAP_MD5_PEER_EXAMPLE_getArgs(argc, argv))
        goto exit;
    if (OK > RTOS_createThread((VOID_FUNC_PTR)EAP_MD5_PEER_EXAMPLE_main, 0, EAP_MAIN, &tid))
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread EAP_MD5_PEER_EXAMPLE_main failed.");
    }
    DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"EAP_MD5_PEER_EXAMPLE_main Called");

#elif (defined(__ENABLE_MOCANA_EAP_SIM__))
    if (OK > EAP_SIM_PEER_EXAMPLE_getArgs(argc, argv))
        goto exit;
    if (OK > RTOS_createThread((VOID_FUNC_PTR)EAP_SIM_PEER_EXAMPLE_main, 0, EAP_MAIN, &tid))
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread EAP_SIM_PEER_EXAMPLE_main failed.");
    }
    DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"EAP_SIM_PEER_EXAMPLE_main Called");

#elif ( defined(__ENABLE_MOCANA_EAP_PSK__) && !defined(__ENABLE_MOCANA_DOT11_SME_EXAMPLE__)&& !defined(__ENABLE_MOCANA_EAP_CLI_EXAMPLES__) )
    if (OK > EAP_PSK_PEER_EXAMPLE_getArgs(argc, argv))
        goto exit;
    if (OK > RTOS_createThread((VOID_FUNC_PTR)EAP_PSK_PEER_EXAMPLE_main, 0, EAP_MAIN, &tid))
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread EAP_PSK_PEER_EXAMPLE_main failed.");
    }
    DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"EAP_PSK_PEER_EXAMPLE_main Called");

#elif (defined(__ENABLE_MOCANA_EAP_SRP__))
    if (OK > EAP_SRP_PEER_EXAMPLE_getArgs(argc, argv))
        goto exit;
    if (OK > RTOS_createThread((VOID_FUNC_PTR)EAP_SRP_PEER_EXAMPLE_main, 0, EAP_MAIN, &tid))
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread EAP_SRP_PEER_EXAMPLE_main failed.");
    }
    DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"EAP_SRP_PEER_EXAMPLE_main Called");

#elif (defined(__ENABLE_MOCANA_EAP_LEAP__) && !defined(__ENABLE_MOCANA_DOT11_SME_EXAMPLE__) )
    if (OK > EAP_LEAP_PEER_EXAMPLE_getArgs(argc, argv))
        goto exit;
    if (OK > RTOS_createThread((VOID_FUNC_PTR)EAP_LEAP_PEER_EXAMPLE_main, 0, EAP_MAIN, &tid))
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread EAP_LEAP_PEER_EXAMPLE_main, failed.");
    }
    DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"EAP_LEAP_PEER_EXAMPLE_main, Called");

#elif (defined(__ENABLE_MOCANA_EAP_MSCHAPv2__) && !defined(__ENABLE_MOCANA_DOT11_SME_EXAMPLE__) && !defined(__ENABLE_MOCANA_EAP_CLI_EXAMPLES__) )
    if (OK > EAP_MSCHAPv2_PEER_EXAMPLE_getArgs(argc, argv))
        goto exit;
    if (OK > RTOS_createThread((VOID_FUNC_PTR)EAP_MSCHAPv2_PEER_EXAMPLE_main, 0, EAP_MAIN, &tid))
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread EAP_MSCHAPv2_PEER_EXAMPLE_main, failed.");
    }
    DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"EAP_MSCHAPv2_PEER_EXAMPLE_main, Called");
#elif (defined(__ENABLE_MOCANA_EAP_CLI_EXAMPLES__) && !defined(__ENABLE_MOCANA_DOT11_SME_EXAMPLE__))
    if (OK > EAP_PEER_EXAMPLE_getArgs(argc, argv))
        goto exit;

    if (OK > RTOS_createThread(EAP_PEER_EXAMPLE_main, 0, EAP_MAIN, &tid))
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread EAP_PEER_EXAMPLE_main, failed.");
    }
    DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"EAP_PEER_EXAMPLE_main, Called");
#endif

#endif  /* __ENABLE_MOCANA_EAP_AUTH__ */

#endif /* __ENABLE_MOCANA_IKE_SERVER_EXAMPLE__ */

#ifdef __ENABLE_MOCANA_DOT11_SME_EXAMPLE__
#if defined (__ENABLE_MOCANA_WPA2_WEXT__) || defined(__ENABLE_MOCANA_WPA2_WIRED__)  /* Add all compilation modes where command line arguments need to be processed*/
    if (OK > DOT11_SME_EXAMPLE_getArgs(argc, argv))
        goto exit;
#endif
    if (OK > RTOS_createThread(DOT11_SME_EXAMPLE_main, (void*) argv, EAP_MAIN, &tid))
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread DOT11_SME_EXAMPLE_main failed.");
    }
#endif


#ifdef __ENABLE_MOCANA_HTTPCC_SERVER_EXAMPLE__
    if (OK > HTTP_SERVER_EXAMPLE_getArgs(argc, argv))
        goto exit;

    if (OK > RTOS_createThread(HTTP_SERVER_EXAMPLE_main, 0, HTTP_THREAD, &tid))
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread HTTP_SERVER_EXAMPLE_main failed.");
    }
#endif

#ifdef __ENABLE_MOCANA_IPC_EXAMPLE__
    if (OK > RTOS_createThread(IPC_EXAMPLE_main, 0, HTTP_THREAD, &tid))
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread IPC_EXAMPLE_main failed.");
    }

    RTOS_sleepMS(3000);

    if (OK > RTOS_createThread(IPC_EXAMPLE_startModClient, 0, IPC_MAIN, &tid))
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread IPC_EXAMPLE_startmodClient failed.");
    }

    if (OK > RTOS_createThread(IPC_EXAMPLE_MSGQ_main, 0, HTTP_THREAD, &tid))
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread IPC_EXAMPLE_main failed.");
    }

    RTOS_sleepMS(3000);

    if (OK > RTOS_createThread(IPC_EXAMPLE_MSGQ_startModClient, 0, IPC_MAIN, &tid))
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread IPC_EXAMPLE_startmodClient failed.");
    }
#endif

#ifdef __ENABLE_MOCANA_OCSP_CLIENT_EXAMPLE__

    if (OK > OCSP_CLIENT_EXAMPLE_getArgs(argc, argv))
        goto exit;

    if (OK > RTOS_createThread(OCSP_CLIENT_EXAMPLE_main, (void*) argv, OCSP_MAIN, &tid))
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread OCSP_CLIENT_EXAMPLE_main failed.");
    }
#endif

#ifdef __ENABLE_MOCANA_CMP_CLIENT_EXAMPLE__
    if (OK > RTOS_createThread(CMP_CLIENT_EXAMPLE_ASYNC_main, (void*) argv, CMP_MAIN, &tid))
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread CMP_CLIENT_EXAMPLE_ASYNC_main, failed.");
    }
#endif


#ifdef __ENABLE_MOCANA_PKI_CLIENT_EXAMPLE__
    if (OK > RTOS_createThread(PKI_CLIENT_EXAMPLE_main, (void*) argv, PKI_CLIENT_MAIN, &tid))
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread CMP_CLIENT_EXAMPLE_main failed.");
    }
#endif

#ifdef __ENABLE_MOCANA_PKI_IPC_EXAMPLE__
    if (OK > RTOS_createThread(PKI_IPC_EXAMPLE_main, 0, PKI_IPC_MAIN, &tid))
    {
       DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread PKI_IPC_EXAMPLE_main failed.");
    }
#endif

#ifdef __ENABLE_MOCANA_PKI_IPC_CHILD_EXAMPLE__
    if (OK > RTOS_createThread(PKI_IPC_EXAMPLE_CHILD_main, 0, PKI_IPC_MAIN, &tid))
    {
       DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread PKI_IPC_EXAMPLE_CHILD_main failed.");
    }
#endif

#ifdef __ENABLE_MOCANA_CRYPTO_EXAMPLE__
    if (OK > RTOS_createThread(CRYPTO_EXAMPLE_main, 0, CRYPTO_MAIN, &tid))
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread CRYPTO_EXAMPLE_main failed.");
    }
#endif

#if defined (__FREERTOS_RTOS__)  && defined (__ENABLE_MOCANA_NANOPNAC__)
    if (0 <= gMocanaAppsRunning)
        RTOS_startScheduler();
#else

#ifndef __PARAGON__
    RTOS_sleepMS(s_waitTime);
#endif

    do
    {
        RTOS_sleepMS(50);
    }
    while (0 < gMocanaAppsRunning);

    RTOS_sleepMS(50);     /* we need this extra wait, otherwise we have a race condition that leads to a bogus memory leak report */
#endif

#if defined(__ENABLE_MOCANA_SERVICE_MAIN__)
    /* Update status value to the one set by the thread */
    if (OK <= status)
        status = threadStatus;
#endif

#ifdef __PARAGON__
    MVC_DIALOG_deinit();
#endif
#ifndef __DISABLE_MOCANA_INIT__
    MOCANA_freeMocana();
    RTOS_sleepMS(2000);     /* we need this extra wait, otherwise we have a race condition that leads to a bogus memory leak report */
#endif

#ifdef __ENABLE_MOCANA_DEBUG_MEMORY__
    dbg_dump();

#ifndef __FREERTOS_RTOS__
    /* give debug a chance to dump */
    RTOS_sleepMS(35000);
#endif

#endif

exit:
#ifndef __FREERTOS_RTOS__
    if (tid != NULL)
        RTOS_destroyThread(tid);
#endif
#ifdef __ENABLE_MOCANA_SERVICE_MAIN__
    if (OK > status)
        return -1;
    else
        return 0;
#else
    return 0;
#endif
}

/*------------------------------------------------------------------*/

#if defined(__RTOS_VXWORKS__)

/* The vxworks build supports both ssl client and server in the same build,
 * so we need these prototypes even though we already got the client ones. */
#if defined(__ENABLE_MOCANA_SSL_SERVER_EXAMPLE__)
extern sbyte4 SSL_EXAMPLE_getArgs(int argc, char *argv[]);
extern void SSL_EXAMPLE_main(void*);
#endif

sbyte4 VxWmainExt(sbyte4 argc, char *argv[], ubyte mainType)
{
    MSTATUS status;
    RTOS_THREAD tid = RTOS_THREAD_INVALID;

#ifdef USE_ONLY_EXTERNAL_ENTROPY
    if (OK > RANDOM_setEntropySource(ENTROPY_SRC_EXTERNAL))
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RANDOM_setEntropySource failed ");
    }
#endif

#if defined(__ENABLE_MOCANA_MEM_PART__) && !defined(__ENABLE_MOCANA_IKE_SERVER__)
    /* Handling for Static Memory Allocation
    */
    status = (MSTATUS)MOCANA_initMocanaStaticMemory (
    (ubyte *)memData, sizeof (memData));
#else
    status = (MSTATUS)MOCANA_initMocana();
#endif
    if (OK != status) /* Initialization Status */
    {
        DEBUG_ERROR(DEBUG_COMMON, (sbyte*)"Init status = ", status);
        goto exit;
    }

    if (0 > MOCANA_initLog(exampleLogFn))
        goto exit;

    switch(mainType)
    {
#if defined (__ENABLE_MOCANA_TRUSTPOINT_LOCAL__)
        case TP_THREAD:
        {
            status = TPLA_getArgs(argc, argv);
            if (OK != status)
                goto exit;

            status = RTOS_createThread((void (*)(void *))TPLA_main, 0, TP_THREAD, &tid);
            if (OK != status)
            {
                DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread TPLA_main failed.");
            }
        }
        break;
#endif
#if defined(__ENABLE_MOCANA_SSL_CLIENT_EXAMPLE_VXWORKS__)
        case SSL_CLIENT_MAIN:
        {
            status = SSL_CLIENTEXAMPLE_getArgs(argc, argv);
            if (OK != status)
                goto exit;

            status = RTOS_createThread(SSL_CLIENTEXAMPLE_main, 0, SSL_MAIN, &tid);
            if (OK != status)
            {
                DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread SSL_CLIENTEXAMPLE_main failed.");
            }
        }
        break;
#endif
#if defined(__ENABLE_MOCANA_SSL_SERVER_EXAMPLE_VXWORKS__)
        case SSL_MAIN:
        {
            status = SSL_EXAMPLE_getArgs(argc, argv);
            if (OK != status)
                goto exit;

            status = RTOS_createThread(SSL_EXAMPLE_main, 0, SSL_MAIN, &tid);
            if (OK != status)
            {
                DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread SSL_EXAMPLE_main failed.");
            }
        }
        break;
#endif
        default:
            DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: Unknown thread type.");
            goto exit;
    }

    do
    {
        RTOS_sleepMS(50);
    }
    while (0 < gMocanaAppsRunning);

    RTOS_sleepMS(50);


exit:

#ifndef __DISABLE_MOCANA_INIT__
    MOCANA_freeMocana();
    RTOS_sleepMS(2000);     /* we need this extra wait, otherwise we have a race condition that leads to a bogus memory leak report */
#endif

    return status;
}
#endif

#ifdef __FREERTOS_RTOS__
/* Making initMocana run in a different task. Only valid for FREERTOS */
void
FREERTOS_initMocana_main(void *dummy)
{
    ubyte4 tidCount = 0;

    if (OK > MOCANA_initMocana())
        gMocanaAppsRunning = -1;

    for (; threadIds[tidCount] != NULL; tidCount++)
    {
        RTOS_taskResume(threadIds[tidCount]);
    }
#ifdef __ENABLE_MOCANA_NANOPNAC__ /* This should be added for entire FreeRTOS range*/
/* Make thread self destroying*/
    RTOS_destroyThread( NULL );     /* Delete the task thread as processing has been completed.*/
#else
    return;
#endif
}

#endif

#endif /* __ENABLE_MOCANA_TEST_MAIN__ */

#endif /* defined(__ENABLE_MOCANA_EXAMPLES__) */

