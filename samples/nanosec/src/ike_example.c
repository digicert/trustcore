/*
 * ike_example.c
 *
 * Sample implementation of an IKE server
 *
 * Copyright 2026 DigiCert, Inc. All Rights Reserved.
 *
 * DigiCert® TrustCore SDK and TrustEdge are licensed under a dual-license model:
 *
 * 1. **Open Source License**: GNU Affero General Public License v3.0 (AGPL v3).
 * See: https://github.com/digicert/trustcore/blob/main/LICENSE.md
 * 2. **Commercial License**: Available under DigiCert's Master Services Agreement.
 * See: https://www.digicert.com/master-services-agreement/
 *
 * *Use of TrustCore SDK or TrustEdge outside the scope of AGPL v3 requires a commercial license.*
 * *Contact DigiCert at sales@digicert.com for more details.*
 */

#include "../common/moptions.h"

#if defined(__ENABLE_DIGICERT_EXAMPLES__) || defined(__ENABLE_DIGICERT_BIN_EXAMPLES__)
#ifdef __ENABLE_DIGICERT_IKE_SERVER_EXAMPLE__

#include <string.h>
#include <stdio.h>
#include <ctype.h>
#ifndef __RTOS_WINCE__
#include <errno.h>
#endif

#ifdef __PLATFORM_HAS_GETOPT__
#ifdef __OSE_RTOS__
#include <getopt.h>
#include <string.h>
#endif
#include <unistd.h>
#include <stdlib.h>
#endif

#if defined(__WIN32_RTOS__) || defined(__RTOS_WINCE__)
  #define WIN32_LEAN_AND_MEAN
  #ifndef _WIN32_WINNT
  #define _WIN32_WINNT 0x0400
  #endif

  #include <windows.h>
  #include <winbase.h>
  #include <winsock2.h>
  #include <Ws2tcpip.h>
  #include <iphlpapi.h>
  #if defined(_DEBUG) && !defined(__RTOS_WINCE__)
  #include <crtdbg.h>
  #endif
#elif defined(__LINUX_RTOS__) || defined(__OPENBSD_RTOS__) || defined(__QNX_RTOS__) || defined(__CYGWIN_RTOS__) || defined(__ANDROID_RTOS__) || defined(__OSX_RTOS__)
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <netdb.h>
  #include <arpa/inet.h>
  #include <signal.h>
  #include <pthread.h>
#elif defined(__VXWORKS_RTOS__)
  #include <vxWorks.h>
  #include <sockLib.h>
  #include <inetLib.h>
#elif defined(__OSE_RTOS__)
  #include <inet.h>
#elif defined(__INTEGRITY_RTOS__)
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <netdb.h>
  #include <arpa/inet.h>
#endif

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mocana.h"
#include "../common/debug_console.h"
#include "../common/mstdlib.h"
#include "../common/mudp.h"
#include "../common/vlong.h"
#include "../common/random.h"
#include "../common/mfmgmt.h"
#include "../crypto/crypto.h"
#include "../crypto/pubcrypto.h"
#include "../crypto/ca_mgmt.h"
#include "../asn1/oiddefs.h"
#include "../common/sizedbuffer.h"
#include "../crypto/cert_store.h"
#include "../crypto/hw_accel.h"
#ifdef __ENABLE_DIGICERT_MEM_PART__
#include "../common/mem_part.h"
#endif
#ifdef __ENABLE_DIGICERT_PFKEY__
#include "../pfkey/pfkey.h"
#endif
#if (defined(__ENABLE_DIGICERT_EAP_AUTH__) || defined(__ENABLE_DIGICERT_EAP_PEER__)) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
#include "../eap/eap.h"
#ifdef __ENABLE_DIGICERT_EAP_SIM__
#include "../eap/eap_sim.h"
#endif
#if defined(__ENABLE_DIGICERT_EAP_PEER__) && defined(__ENABLE_DIGICERT_EAP_TTLS__)
#include "../eap/eap_ttls.h"
#endif
#endif
#if defined(__ENABLE_DIGICERT_EAP_AUTH__) && defined(__ENABLE_DIGICERT_EAP_RADIUS__) && defined(__ENABLE_DIGICERT_RADIUS_CLIENT__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
#include "../radius/radius.h"
#endif
#if (defined(__ENABLE_DIGICERT_EAP_AUTH__) || defined(__ENABLE_DIGICERT_EAP_PEER__)) && !defined(__DISABLE_DIGICERT_IKE_EAP__) && \
    defined(__ENABLE_DIGICERT_EAP_TLS__)
#include "../ssl/ssl.h"
#endif
#if defined(__ENABLE_DIGICERT_EAP_AUTH__) && defined(__ENABLE_DIGICERT_EAP_GTC__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
#include "../crypto/sha1.h"
#endif
#ifdef __ENABLE_DIGICERT_TAP__
#include "../smp/smp_cc.h"
#include "../tap/tap_api.h"
#include "../tap/tap_utils.h"
#include "../tap/tap_smp.h"
#include "../crypto/mocasym.h"
#include "../crypto/mocasymkeys/tap/rsatap.h"
#include "../crypto/mocasymkeys/tap/ecctap.h"
#include "../crypto_interface/cryptointerface.h"
#endif
#include "../ipsec/ipsec.h"
#include "../ipsec/ipsec_defs.h"
#include "../ipsec/ipsecconf.h"
#include "../ipsec/ipseckey.h"
#include "../ike/ike.h"
#include "../ike/ike_defs.h"
#include "../ike/ike_event.h"
#include "../ike/ike_utils.h"
#include "../ike/ike_status.h"
#include "../ike/ike_state.h"
#include "../ike/ikesa.h"
#include "../ike/ikekey.h"

#if ((defined(__RTOS_WINCE__) || defined(__RTOS_WIN32__) || defined(__RTOS_LINUX__)) && defined(__ENABLE_DIGICERT_VPN_EXAMPLE__))
#include "ikeConfig.h"
#include "paragon/ui/dialog_interface.h"

#ifdef __RTOS_WIN32__
extern int gInterfaceChange;
extern void MonitorIPAddressChange(void *dummy);
#else
int gInterfaceChange;
extern void MonitorIPAddressChange(void *dummy);
#endif

static sbyte4
IKE_EXAMPLE_readdServer(MOC_IP_ADDRESS saddr, ubyte2 port,
                      ubyte2 natt_port,
                      ubyte4 cookie);
static sbyte4
IKE_EXAMPLE_addServer(MOC_IP_ADDRESS saddr, ubyte2 port,
                      ubyte2 natt_port,
                      ubyte4 cookie);
extern sbyte4   parser_main(void);
#ifdef __RTOS_LINUX__
extern sbyte4   Add_Route( sbyte4 destination, sbyte4 gateway, MOC_IP_ADDRESS mask, sbyte4 direct );
extern sbyte4   OnIp2Intf(MOC_IP_ADDRESS * ipAddr,sbyte4 *rIfIndex);
extern sbyte4   OnIp2MultiIntf(MOC_IP_ADDRESS * ipAddr, sbyte4 maxInst,sbyte4 *rIfIndex);
extern void     GetAllIntf(MOC_IP_ADDRESS * ipAddr, sbyte4  maxInst);
extern sbyte4   OnAddIP(sbyte4 IfIndex, MOC_IP_ADDRESS Address, MOC_IP_ADDRESS IpMask, sbyte4* m_NTEContext,  MOC_IP_ADDRESS DNSAddr );
extern void     OnDelIP(ubyte4 m_NTEContext);
#else
extern sbyte4   IKE_setMocanaAdapter(LPWSTR mocAdapterName);
extern DWORD    OnIp2Intf(PULONG ipAddr,DWORD *rIfIndex);
extern DWORD    OnIp2MultiIntf(PULONG ipAddr, DWORD maxInst,DWORD *rIfIndex);
extern void     GetAllIntf(PULONG ipAddr, DWORD  maxInst);
extern DWORD    OnAddIP(DWORD IfIndex, IPAddr Address, IPMask IpMask, PULONG m_NTEContext, IPAddr DNSAddr );
extern void     OnDelIP(ULONG m_NTEContext);
extern DWORD    Add_Route( DWORD destination, DWORD gateway, DWORD mask, DWORD direct ) ;
#endif
extern sbyte4   computeHostKeysFromGivenFiles(certDescriptor *pRetCertificateDescr, sbyte *CACertPath, sbyte *ClientCertPath, sbyte *ClientKey);

sbyte4 m_IfIndex = 1;
#ifdef __RTOS_LINUX__
void *g_hIKEShutdown = NULL;
void *g_hIKEConnect = NULL;
void *g_hIKEConnectAck = NULL;
RTOS_COND g_hIKEDisconnect = NULL;
RTOS_MUTEX g_mIKEDisconnect = NULL;
#else
HANDLE g_hIKEShutdown = NULL;
HANDLE g_hIKEConnect = NULL;
HANDLE g_hIKEConnectAck = NULL;
HANDLE g_hIKEDisconnect = NULL;
#endif
certDescriptor mvcIKECertDesc = { NULL };

static ubyte4 gdwPeerAddr = 0; /* IP Address of the current Connected GW */

#ifndef __PARAGON__
#define __PARAGON__
#endif
#else
#ifdef __PARAGON__
#undef __PARAGON__
#endif
#endif


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_EAP_AUTH__) || defined(__ENABLE_DIGICERT_EAP_PEER__)) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
extern void IKE_CERT_UTILS_getArgs(int argc, char *argv[]);
extern void IKE_CERT_UTILS_initStore();
extern void IKE_CERT_UTILS_freeStore();
extern certDescriptor g_IKECert;
extern certStorePtr g_pIKECertStore;
#ifdef __ENABLE_DIGICERT_EAP_TLS__
extern sbyte g_IKECertCommonName[]; /* sbyte *g_IKECertCommonName; will crash! */
extern void setCertCommonName (ubyte *pName, ubyte4 nameLength);
#endif

#else
extern sbyte4   CA_MGMT_EXAMPLE_computeHostKeys(certDescriptor *pCert);
extern sbyte4   CA_MGMT_EXAMPLE_releaseHostKeys(certDescriptor *pCert);
#endif
extern void     CA_MGMT_EXAMPLE_initUpcalls(void);
extern void     CA_MGMT_EXAMPLE_uninitUpcalls(void);

#ifdef __ENABLE_DIGICERT_IKE_REF_IDENTIFIER_MATCH__
sbyte *m_peerHost = NULL;
#endif

#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
#define IKE_OUTPUT_FILE      "ike-output.txt"
#endif
/*------------------------------------------------------------------*/


#ifdef __ENABLE_DIGICERT_TAP__

static TAP_Context              *g_pTapContext;
static TAP_EntityCredentialList *g_pTapEntityCred = NULL;
static TAP_CredentialList       *g_pTapKeyCred    = NULL;
static TAP_ModuleList g_moduleList                = { 0 };

#include "../common/tpm2_path.h"

#if (defined(__ENABLE_DIGICERT_TAP_REMOTE__))
static unsigned short  taps_ServerPort     = 8277;
static char *          taps_ServerName     = NULL;
#endif
static char *          tap_ConfigFile      = (char *)TPM2_CONFIGURATION_FILE;

extern void
setIKETapConfig(char *pConfig)
{
    if (NULL != pConfig)
        tap_ConfigFile = pConfig;
}
#endif /* __ENABLE_DIGICERT_TAP__ */


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_EAP_AUTH__) || defined(__ENABLE_DIGICERT_EAP_PEER__)) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
static void
setParameter(sbyte ** param, char *value)
{
    int l = DIGI_STRLEN((const sbyte*)value);
    *param = (sbyte*)MALLOC(l+1);
    if (NULL != *param)
    {
        DIGI_MEMCPY(*param, value, l);
        (*param)[l] = '\0';
    }
}
#endif

/*------------------------------------------------------------------*/

#if defined(__ENABLE_IKE_XAUTH__) || defined(__ENABLE_IKE_MODE_CFG__) || defined(__ENABLE_IKE_CP__)

extern sbyte4   IKECFG_EXAMPLE_initUpcalls(void);

/* XAUTH Client [v1] */
#ifdef __ENABLE_IKE_XAUTH__
extern sbyte       *m_XuserName;
extern sbyte       *m_Xpassword;
#endif

extern sbyte4       m_vpnAgent; /* 1=client, 2=server, o/w none */

/* MODE-CFG [v1] */
#ifdef __ENABLE_IKE_MODE_CFG__
/*
    PULL: Client initiates "Request/Response" transaction
    PUSH: Server initiates "Set/Ack" transaction
 */
extern intBoolean   m_bPullCfg; /* TRUE (PULL) or FALSE (PUSH) */
extern intBoolean   m_bInitQM;
#endif

#endif


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_PFKEY__
extern sbyte4   PFKEY_EXAMPLE_main(void);
#else
extern sbyte4   IPSECKEY_EXAMPLE_main(void);
#endif
#ifdef MOCANA_IKEADM_PORT
extern sbyte4   IKEADM_EXAMPLE_main(void);
#endif


/*------------------------------------------------------------------*/

intBoolean g_ikeBreakSignalRequest = FALSE;
#ifdef __ENABLE_IPSEC_MARGIN_LIFETIME__
ubyte4 g_IkeP2MarginLifeSecs = 0;
#endif

/*------------------------------------------------------------------*/

static ubyte4 msTimeout = 4000; /* 4 secs */

static intBoolean mIsHexPSK = TRUE;     /* hexadecimal */
static sbyte *mPSK  = (sbyte *)"6578616d706c6520707265736861726564206b6579"; /* pragma: allowlist secret */
static sbyte4 mPSKlen = 42;

#if !defined(__PARAGON__)
static intBoolean mComputeHostKeys = TRUE;
#endif

static MOC_IP_ADDRESS_S mPeerAddr = MOC_IPADDR_NONE;

static void     IKE_SAMPLE_ikeStatHdlr(sbyte4 cat, sbyte4 type, ubyte4 id,
                                       void *data1, void *data2);

extern sbyte4   IKE_SAMPLE_ikeGetHostAddr(MOC_IP_ADDRESS_S *pHostAddr,
                                          sbyte4 serverInstance);

/*------------------------------------------------------------------*/

#ifndef IKE_EVENT_PORT
#define IKE_EVENT_PORT 13579
#endif

/* Runtime-configurable event port; overridden by -E <port> so two IKE
   instances on the same machine can each use a distinct loopback port. */
static ubyte2 g_ikeEventPort = IKE_EVENT_PORT;

#define ipv4_addr(a,b,c,d) ((a<<24)+(b<<16)+(c<<8)+d)

#ifndef __ENABLE_DIGICERT_IPV6__

#define MOC_UDP_LOOPBACK_ADDR ipv4_addr(127,0,0,1)
#define MOC_UDP_LOOPBACK_ADDR_S MOC_UDP_LOOPBACK_ADDR

#else

static MOC_IP_ADDRESS_S m_addrLoopback =
{
    AF_INET,
    { { ipv4_addr(127,0,0,1) } },
};
#define MOC_UDP_LOOPBACK_ADDR &m_addrLoopback
#define MOC_UDP_LOOPBACK_ADDR_S m_addrLoopback

#endif /* __ENABLE_DIGICERT_IPV6__ */

static ubyte m_useMsgRecv = 1;

/*------------------------------------------------------------------*/

#if (defined(__WIN32_RTOS__) || defined (__RTOS_WINCE__))
static BOOL
WINAPI HandlerRoutine(DWORD dw)
{
    MOC_UNUSED(dw);
    g_ikeBreakSignalRequest = TRUE;

    return TRUE;
}
#elif defined(__LINUX_RTOS__)
static pthread_t g_ikeListenThreadId = 0;
static void
IKE_EXAMPLE_sigHandler(int sig)
{
    g_ikeBreakSignalRequest = TRUE;
    /* If the signal was delivered to the main thread (or any other thread),
     * forward it to the IKE listen thread so its select() returns EINTR
     * and the loop checks g_ikeBreakSignalRequest immediately. */
    if (g_ikeListenThreadId && !pthread_equal(pthread_self(), g_ikeListenThreadId))
        pthread_kill(g_ikeListenThreadId, sig);
}
#endif


/*------------------------------------------------------------------*/

extern int
IKE_EXAMPLE_getLastError(void)
{
#if defined(__WIN32_RTOS__) || defined(__RTOS_WINCE__)
    return WSAGetLastError();
#else
    return errno;
#endif
}


/*------------------------------------------------------------------*/

extern void
IKE_EXAMPLE_sprintIpAddr(char *addr, int len, MOC_IP_ADDRESS ipAddr)
{
#ifdef __ENABLE_DIGICERT_IPV6__
    if (AF_INET6 == ipAddr->family)
    {
        const ubyte *in_addr6 = GET_MOC_IPADDR6(ipAddr);
#if defined(__LINUX_RTOS__)
        if (NULL == inet_ntop(AF_INET6, in_addr6, addr, len))
#else
        MOC_UNUSED(len);
#endif
        {
            char *ptr = addr;
            sbyte4 i, zeros=0;
            for (i=0; i < 16; i += 2)
            {
                if (i && (0 >= zeros)) *ptr++ = ':';

                if (in_addr6[i])
                {
                    if (0 < zeros) zeros = -1;
                    sprintf(ptr, "%x%02x", (int) in_addr6[i], (int) in_addr6[i+1]);
                    ptr = addr + strlen(addr);
                }
                else if (in_addr6[i+1])
                {
                    if (0 < zeros) zeros = -1;
                    sprintf(ptr, "%x", (int) in_addr6[i+1]);
                    ptr = addr + strlen(addr);
                }
                else if (i && (0 > zeros) && (14 > i))
                {
                    *ptr++ = '0';
                }
                else if (i && (0 <= zeros))
                {
                    if ((0 == zeros++) && (14 > i))
                        *ptr++ = ':';
                }
            }
            *ptr = '\0';
        }
    }
    else
#endif
    {
        ubyte4 dwIpAddr = GET_MOC_IPADDR4(ipAddr);
        sprintf(addr, "%d.%d.%d.%d",
                (dwIpAddr >> 24),
                ((dwIpAddr & 0x00ff0000) >> 16),
                ((dwIpAddr & 0x0000ff00) >> 8),
                (dwIpAddr & 0x000000ff));
    }

    return;
} /* IKE_EXAMPLE_sprintIpAddr */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__

static void
IKE_EXAMPLE_printIpAddr(MOC_IP_ADDRESS ipAddr)
{
#ifdef __ENABLE_DIGICERT_IPV6__
    if (AF_INET6 == ipAddr->family)
    {
        char addr6[48] = "";
        IKE_EXAMPLE_sprintIpAddr(addr6, 47, ipAddr);
        DEBUG_PRINT(DEBUG_IKE_EXAMPLE, (sbyte *)addr6);
    }
    else
#endif
    {
        char *tmp;
        struct in_addr iaddr;
        SET_HTONL(iaddr.s_addr, GET_MOC_IPADDR4(ipAddr));

        if (NULL != (tmp = inet_ntoa(iaddr)))
        {
            DEBUG_PRINT(DEBUG_IKE_EXAMPLE, (sbyte *)tmp);

            /* Note: Some systems (e.g. VxWorks bsd) may allocate from
               memory for inet_ntoa(). */
#if defined(__VXWORKS_RTOS__) && !defined(INCLUDE_IPNET_STACK)
            free(tmp);
#endif
        }
    }

    return;
}


/*------------------------------------------------------------------*/

static void
IKE_EXAMPLE_printLastError(sbyte *msg)
{
    int errNo = IKE_EXAMPLE_getLastError();

    if (errNo)
    {
        DEBUG_ERROR(DEBUG_PLATFORM, msg, errNo);
#ifndef __RTOS_WINCE__
        perror("           ");
#endif
    }
    return;
}

#else
#define IKE_EXAMPLE_printIpAddr(_ip)
#define IKE_EXAMPLE_printLastError(_msg)
#endif


/*------------------------------------------------------------------*/
/* IKE Server Instance(s)                                           */
/*------------------------------------------------------------------*/

#if defined(__ENABLE_MOBIKE__) && defined(__IKE_MULTI_HOMING__)

#define SVR_INST_MAX 32

static struct svrInst
{
    MOC_IP_ADDRESS_S    saddr;
    ubyte2              port[2];
    sbyte4              sktDescr[2]; /* e.g. 500, 4500 */

#if defined(__ENABLE_IPSEC_COOKIE__) && !defined(__ENABLE_DIGICERT_PFKEY__)
    ubyte4              cookie;
#endif
    sbyte4              errNo;
    sbyte4              serverInstanceNew;
}
m_svrInst[SVR_INST_MAX];

static sbyte4 m_numSvrInst = 0;

#endif


/*------------------------------------------------------------------*/
/* Socket Helpers                                                   */
/*------------------------------------------------------------------*/

typedef sbyte4 (*SktReadFunc)(ubyte4 *ret, void *pSktDescr,
                              ubyte *poBuffer, ubyte4 dwBufferSize,
                              MOC_IP_ADDRESS_S *peer, ubyte2 *port);

typedef sbyte4 (*SktProcFunc)(void *pSktDescr, void *cb,
                              ubyte *poBuffer, ubyte4 dwBufferSize,
                              MOC_IP_ADDRESS peerAddr, ubyte2 wPeerPort);

typedef sbyte4 (*SktCloseFunc)(void **ppSktDescr, void *cb);


/*------------------------------------------------------------------*/

#define SKT_DESCR_MAX 64

static struct sktDescr
{
    void *              pSktDescr;
    void *              cb;
    SktReadFunc         readfn;
    SktProcFunc         procfn;
    SktCloseFunc        closefn;
}
m_sktDescr[SKT_DESCR_MAX] = { { 0 } };

static sbyte4 m_numSktDescr = 0;


/*------------------------------------------------------------------*/

static sbyte4
IKE_EXAMPLE_addSktDescr(void *pSktDescr, void *cb,
                        SktReadFunc funcPtrRead,
                        SktProcFunc funcPtrProc,
                        SktCloseFunc funcPtrClose)
{
    sbyte4 status = ERR_IKE;

    sbyte4 i = m_numSktDescr;

    for (i = 0; i < m_numSktDescr; i++)
    {
        if (!m_sktDescr[i].pSktDescr)
            break;
    }

    if (SKT_DESCR_MAX <= i)
    {
        DEBUG_PRINTNL(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_EXAMPLE: Too many sockets!");
        goto exit;
    }

    m_sktDescr[i].pSktDescr = pSktDescr;
    m_sktDescr[i].cb        = cb;

    m_sktDescr[i].readfn    = funcPtrRead;
    m_sktDescr[i].procfn    = funcPtrProc;
    m_sktDescr[i].closefn   = funcPtrClose;

    if (i >= m_numSktDescr)
        m_numSktDescr++;

    status = i;

exit:
    return status;
} /* IKE_EXAMPLE_addSktDescr */


/*------------------------------------------------------------------*/

static sbyte4
IKE_EXAMPLE_udpRead(ubyte4 *ret, void *pUdpDescr,
                    ubyte *poBuffer, ubyte4 dwBufferSize,
                    MOC_IP_ADDRESS_S *peer, ubyte2 *port)
{
    sbyte4 status;

    if (OK > (status = UDP_recvFrom(pUdpDescr, peer, port,
                                    poBuffer, dwBufferSize, ret)))
    {
        DEBUG_ERROR(DEBUG_PLATFORM, (sbyte *)"IKE_EXAMPLE: UDP_recvFrom() failed, status = ", status);
        IKE_EXAMPLE_printLastError( (sbyte *)"             recvfrom() returns error ");
        goto exit;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

static sbyte4
IKE_EXAMPLE_udpClose(void **ppUdpDescr, void *cb)
{
    MOC_UNUSED(cb);
    return UDP_unbind(ppUdpDescr);
}


/*------------------------------------------------------------------*/

extern sbyte4
IKE_EXAMPLE_addUdpSkt(void **ppUdpDescr,
                      void *cb, SktProcFunc funcPtrProc,
                      MOC_IP_ADDRESS hostAddr, ubyte2 wHostPort)
{
    sbyte4 status;
    char tmp[64] = "";

    void *pUdpDescr = NULL;

    IKE_EXAMPLE_sprintIpAddr(tmp, sizeof(tmp), hostAddr);
#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
    DEBUG_CONSOLE_printf("IKE_EXAMPLE: Creating socket on [%s]:%u", tmp, (ubyte4) wHostPort);
#endif

    /* create socket */
    if (OK > (status = UDP_simpleBind(&pUdpDescr, hostAddr, wHostPort, TRUE)))
    {
        DEBUG_PRINTNL(DEBUG_PLATFORM, (sbyte *)NULL);
        DEBUG_ERROR(DEBUG_PLATFORM, (sbyte *)"IKE_EXAMPLE: UDP_simpleBind() failed, status = ", status);
        IKE_EXAMPLE_printLastError( (sbyte *)"             returns error ");
        goto exit;
    }

    if (0 > (status = IKE_EXAMPLE_addSktDescr(pUdpDescr, cb,
                                              IKE_EXAMPLE_udpRead,
                                              funcPtrProc,
                                              IKE_EXAMPLE_udpClose)))
    {
        UDP_unbind(&pUdpDescr);
        goto exit;
    }

    if (NULL != ppUdpDescr)
        *ppUdpDescr = pUdpDescr;

    DEBUG_PRINTNL(DEBUG_IKE_EXAMPLE, (sbyte *)" completed.");

exit:
    return status;
} /* IKE_EXAMPLE_addUdpSkt */


/*------------------------------------------------------------------*/

#define mBufSize 65535


#ifdef __IKE_MULTI_THREADED__

/*------------------------------------------------------------------*/

#define IKE_THREAD_MAX 256
static sbyte4 m_threadNum = 10;
static RTOS_THREAD m_ikeThread[IKE_THREAD_MAX];
static ubyte m_threadBuf[IKE_THREAD_MAX][mBufSize];

#define IKE_THREAD_PORT 21365

static void
IKE_EXAMPLE_workerMain(void *data)
{
    sbyte4 i = (sbyte4)data;

    ubyte *poBuffer = &(m_threadBuf[i][0]);
    ubyte4 dwBufferSize;

    MOC_IP_ADDRESS_S peerAddr;
    ubyte2 wPeerPort;

    MSTATUS status;

    void *pUdpDescr = NULL;
    if (OK > (status = UDP_simpleBind(&pUdpDescr,
                                      MOC_UDP_LOOPBACK_ADDR, IKE_THREAD_PORT+i,
                                      TRUE)))
    {
        DEBUG_ERROR(DEBUG_PLATFORM, (sbyte *)"IKE_EXAMPLE: UDP_simpleBind() failed, status = ", status);
        IKE_EXAMPLE_printLastError( (sbyte *)"             returns error ");
        goto exit;
    }

    /* Loop forever accepting connections */
    while (FALSE == g_ikeBreakSignalRequest)
    {
        if (OK > (status = UDP_selReadAvl(&pUdpDescr, 1, msTimeout)))
        {
            if (ERR_UDP_READ_TIMEOUT == status) continue;
#ifdef __LINUX_RTOS__
            if (EINTR == errno) continue;
#endif
            DEBUG_ERROR(DEBUG_PLATFORM, (sbyte *)"IKE_EXAMPLE: UDP_selectAvl() failed, status = ", status);
            IKE_EXAMPLE_printLastError( (sbyte *)"             select() returns error ");
            goto exit;
        }

        /* receive */
        for (;;)
        {
            if (OK > (status = UDP_recvFrom(pUdpDescr, &peerAddr, &wPeerPort,
                                            poBuffer, mBufSize, &dwBufferSize)))
            {
                DEBUG_ERROR(DEBUG_PLATFORM, (sbyte *)"IKE_EXAMPLE: UDP_recvFrom() failed, status = ", status);
                IKE_EXAMPLE_printLastError( (sbyte *)"             recvfrom() returns error ");
                goto exit;
            }

            if (0 == dwBufferSize) break;

            /* process */
            if (SAME_MOC_IPADDR(MOC_UDP_LOOPBACK_ADDR, peerAddr) &&
                (sizeof(struct dpcHdr) <= dwBufferSize))
            {
                ((DPC_HDR)poBuffer)->dpc_len = (ubyte2)dwBufferSize;
                IKE_dpcRecv(poBuffer, mBufSize);
            }
        }
    } /* while */

exit:
    if (NULL != pUdpDescr)
        UDP_unbind(&pUdpDescr);
    return;
} /* IKE_EXAMPLE_workerMain */


/*------------------------------------------------------------------*/

static sbyte4
IKE_SAMPLE_ikeGetThreadId(RTOS_THREAD *pTid,
                          const ubyte *poCkyI,/* IKE_COOKIE_SIZE(8) */
                          sbyte4 version,      /* 1 or 2 */
                          intBoolean bInitiator,/* Am I initiator? */
                          /* Note: IKEv1 message does not use
                           IKE_FLAG_INITIATOR bit in its flags! */
                          sbyte4 serverInstance)
{
    *pTid = m_ikeThread[poCkyI[0] % m_threadNum];
    return (sbyte4)OK;
} /* IKE_SAMPLE_ikeGetThreadId */


/*------------------------------------------------------------------*/

static sbyte4
IKE_SAMPLE_ikeThreadSend(RTOS_THREAD tid, ubyte *args, ubyte4 size)
{
    MSTATUS status = OK;

    void *pUdpDescr = NULL;

    sbyte4 i;
    for (i=0; i < m_threadNum; i++)
    {
        if (TRUE == RTOS_sameThreadId(tid, m_ikeThread[i])) /* found */
        {
            /* create socket */
            if (OK > (status = UDP_connect(&pUdpDescr,
                                        MOC_UDP_LOOPBACK_ADDR, MOC_UDP_ANY_PORT,
                                        MOC_UDP_LOOPBACK_ADDR, IKE_THREAD_PORT+i,
                                        TRUE)))
            {
                DEBUG_ERROR(DEBUG_PLATFORM, (sbyte *)"IKE_SAMPLE_ikeThreadSend: UDP_connect() failed, status = ", status);
                IKE_EXAMPLE_printLastError( (sbyte *)"             connect() returns error ");
                DEBUG_PRINTNL(DEBUG_PLATFORM, (sbyte *)NULL);
                goto exit;
            }

            /* relay the call to the proper thread */
            if (OK > (status = UDP_send(pUdpDescr, args, size)))
            {
                DEBUG_ERROR(DEBUG_PLATFORM, (sbyte *)"IKE_SAMPLE_ikeThreadSend: UDP_send() failed, status = ", status);
                IKE_EXAMPLE_printLastError( (sbyte *)"             send() returns error ");
                goto exit;
            }

            goto exit; /* !!! */
        }
    }

    DB_PRINT("%s: Thread %p not found!\n", __FUNCTION__, (void *)tid);
    status = ERR_IKE; /* ERR_IKE_THREAD */

exit:
    if (NULL != pUdpDescr)
        UDP_unbind(&pUdpDescr);
    return (sbyte4)status;
} /* IKE_SAMPLE_ikeThreadSend */


/*------------------------------------------------------------------*/

typedef struct dpcMsgRecv
{
    struct dpcHdr hdr;
    sbyte4 version;
    MOC_IP_ADDRESS_S peerAddr;
    ubyte2 wPeerPort;
    sbyte4 serverInstance;
    intBoolean bUseNattPort;

} *IKE_DPC_MSG_RECV;


static sbyte4
IKE_dpcMsgRecv(IKE_DPC_MSG_RECV rcv, ubyte4 rcvSize)
{
    sbyte4 status = 0;

    if ((sizeof(struct dpcMsgRecv) < rcvSize) &&
        (rcvSize >= rcv->hdr.dpc_len) &&
        ((IKE_dpcFunc)IKE_dpcMsgRecv == rcv->hdr.dpc_func))
    {
        ubyte *poBuffer = ((ubyte *)rcv) + sizeof(struct dpcMsgRecv);
        ubyte4 dwBufferSize = rcvSize - sizeof(struct dpcMsgRecv);

        if (2 == rcv->version)
        {
            status = IKE2_msgRecv(REF_MOC_IPADDR(rcv->peerAddr), rcv->wPeerPort,
                                  poBuffer, dwBufferSize,
                                  rcv->serverInstance, rcv->bUseNattPort
#ifdef __IKE_TRACK__
                                , NULL
#endif
                                  );
        }
        else
        {
            status = IKE_msgRecv(REF_MOC_IPADDR(rcv->peerAddr), rcv->wPeerPort,
                                 poBuffer, dwBufferSize,
                                 rcv->serverInstance, rcv->bUseNattPort
#ifdef __IKE_TRACK__
                               , NULL
#endif
                                 );
        }
    }

    return status;
}

static sbyte4
DPC_IKE_msgRecv(sbyte4 version,
                MOC_IP_ADDRESS peerAddr, ubyte2 wPeerPort,
                ubyte *poBuffer, ubyte4 dwBufferSize,
                sbyte4 serverInstance, intBoolean bUseNattPort)
{
    RTOS_THREAD tid;

    IKE_DPC_MSG_RECV rcv = (IKE_DPC_MSG_RECV)(poBuffer - sizeof(struct dpcMsgRecv));
    rcv->hdr.dpc_func = (IKE_dpcFunc)IKE_dpcMsgRecv;
    rcv->hdr.dpc_len = (ubyte2)(dwBufferSize + sizeof(struct dpcMsgRecv));
    rcv->version = version;
    rcv->peerAddr = DEREF_MOC_IPADDR(peerAddr);
    rcv->wPeerPort = wPeerPort;
    rcv->serverInstance = serverInstance;
    rcv->bUseNattPort = bUseNattPort;

#ifdef __ENABLE_IPSEC_NAT_T__
    if (bUseNattPort)
        IKE_SAMPLE_ikeGetThreadId(&tid, poBuffer+4, version, FALSE, serverInstance);
    else
#endif
    IKE_SAMPLE_ikeGetThreadId(&tid, poBuffer, version, FALSE, serverInstance);

    return IKE_SAMPLE_ikeThreadSend(tid, (ubyte *)rcv,
                            (ubyte4)sizeof(struct dpcMsgRecv) + dwBufferSize);
}


/*------------------------------------------------------------------*/

static void
IKE_EXAMPLE_idle(void *dummy)
{
    /* Loop forever */
    while (FALSE == g_ikeBreakSignalRequest)
    {
#ifdef __IKE_UPDATE_TIMER__
        RTOS_sleepMS(1000);
#else
        RTOS_sleepMS(msTimeout);
#endif
        /*status = */IKE_msgIdle();
    }
    return;
}
#else

/*------------------------------------------------------------------*/

#ifdef __ENABLE_MSGIDLE_THREAD__
static void
IKE_EXAMPLE_att_idle(void *dummy)
{
    /* Loop forever */
    while (FALSE == g_ikeBreakSignalRequest)
    {
#ifdef __IKE_UPDATE_TIMER__
        RTOS_sleepMS(1000);
#else
        RTOS_sleepMS(msTimeout);
#endif
        /*status = */IKE_msgIdle();
    }
    return;
}
#endif /* __ENABLE_MSGIDLE_THREAD__ */
#endif /* __IKE_MULTI_THREADED__ */


/*------------------------------------------------------------------*/

static ubyte mBuffer[mBufSize];

static sbyte4
IKE_EXAMPLE_listen(void)
{
    sbyte4 status = 0;
#ifndef __IKE_MULTI_THREADED__
    moctime_t timeidle = { { {0} } };
#endif
#ifdef __PARAGON__
    intBoolean bActive = FALSE;
    ubyte4 idleTimes  = 0;
    MOC_IP_ADDRESS_S hostAddrNew;
#endif

#if defined(__WIN32_RTOS__) && !defined(__RTOS_WINCE__)
    SetConsoleCtrlHandler(HandlerRoutine, TRUE);
#elif defined(__LINUX_RTOS__)
    g_ikeListenThreadId = pthread_self();
    {
        struct sigaction sa;
        sa.sa_handler = IKE_EXAMPLE_sigHandler;
        sa.sa_flags = 0;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGTERM, &sa, NULL);
        sigaction(SIGINT, &sa, NULL);
    }
#endif

    DIGICERT_log(MOCANA_IKE, LS_INFO, (sbyte *)"IKE server listening for data");

    /* Loop forever accepting connections */
    while (FALSE == g_ikeBreakSignalRequest)
    {
        sbyte4 i;
        void* sktDescr[SKT_DESCR_MAX] = { NULL };

        if (0 >= m_numSktDescr) /* jic */
        {
            RTOS_sleepMS(msTimeout * 2);
#ifndef __IKE_MULTI_THREADED__
            goto idle;
#else
            continue;
#endif
        }

        for (i=0; i < m_numSktDescr; i++)
            sktDescr[i] = m_sktDescr[i].pSktDescr;

        if (OK > (status = UDP_selReadAvl(sktDescr, m_numSktDescr, msTimeout)))
        {
            if (ERR_UDP_READ_TIMEOUT == status)
            {
#if defined(__ENABLE_MOBIKE__) && defined(__IKE_MULTI_HOMING__)
#ifdef __PARAGON__
                if (gInterfaceChange)
                {
                    sbyte4 j=0;
                    MOC_IP_ADDRESS ipAddr[SVR_INST_MAX];

                    memset(ipAddr, 0, sizeof(ipAddr));
                    GetAllIntf(ipAddr, SVR_INST_MAX);

                    while (j < SVR_INST_MAX)
                    {
                        if (!ipAddr[j])
                            break;

                        IKE_EXAMPLE_readdServer(htonl(ipAddr[j++]),
                            IKE_DEFAULT_UDP_PORT,
                            IKE_NAT_UDP_PORT,
                            0);
                    }
                    gInterfaceChange = 0;
                }
#endif
                for (i=0; i < m_numSvrInst; i++)
                {
                    struct svrInst *pSvrInst = &m_svrInst[i];
                    if (!pSvrInst->errNo)
                    {
                        ubyte c = 0;
                        sbyte4 sktIndex = pSvrInst->sktDescr[0];
                        void *pUdpDescr = m_sktDescr[sktIndex].pSktDescr;
                        MOC_IP_ADDRESS myAddress = MOC_UDP_LOOPBACK_ADDR;

                        if (OK > UDP_sendTo(pUdpDescr, myAddress, 500, &c, 1))
                        {
                            int errNo = IKE_EXAMPLE_getLastError();
                            if (10049 == errNo)
                                pSvrInst->errNo = errNo;
                        }
                    }
                }
#endif
#ifndef __IKE_MULTI_THREADED__
                goto idle;
#else
                continue;
#endif
            }
#ifdef __LINUX_RTOS__
#ifndef __IKE_MULTI_THREADED__
            if (EINTR == errno) goto retry;
#else
            if (EINTR == errno) continue;
#endif
#endif
            DEBUG_ERROR(DEBUG_PLATFORM, (sbyte *)"IKE_EXAMPLE: UDP_selectAvl() failed, status = ", status);
            IKE_EXAMPLE_printLastError( (sbyte *)"             select() returns error ");
            goto exit;
        }

        /* receive */
        for (i=0; i < m_numSktDescr; i++)
        {
            MOC_IP_ADDRESS_S dwPeerAddr;
            ubyte2 wPeerPort;
            ubyte4 ret;

            void *pSktDescr = sktDescr[i];
            if (NULL == pSktDescr) continue;

            if (OK > (status = m_sktDescr[i].readfn(&ret, pSktDescr,
#ifdef __IKE_MULTI_THREADED__
                                                    mBuffer + sizeof(struct dpcMsgRecv),
                                                    mBufSize - sizeof(struct dpcMsgRecv),
#else
                                                    mBuffer, mBufSize,
#endif
                                                    &dwPeerAddr, &wPeerPort)))
            {
                DEBUG_ERROR(DEBUG_PLATFORM, (sbyte *)"IKE_EXAMPLE: UDP_readFn failed, status = ", status);
                IKE_EXAMPLE_printLastError( (sbyte *)"             select() returns error ");
                continue;
            }

            if (0 == ret) continue;

            /* process */
            status = m_sktDescr[i].procfn(pSktDescr, m_sktDescr[i].cb,
#ifdef __IKE_MULTI_THREADED__
                                          mBuffer + sizeof(struct dpcMsgRecv),
#else
                                          mBuffer,
#endif
                                          ret,
                                          REF_MOC_IPADDR(dwPeerAddr),
                                          wPeerPort);

        } /* for */

#ifndef __IKE_MULTI_THREADED__
#ifdef __LINUX_RTOS__
retry:
#endif

        /* process idle-time tasks */
        if (msTimeout >= RTOS_deltaMS(&timeidle, NULL))
            continue;
idle:
#if defined(__ENABLE_MOBIKE__) && defined(__IKE_MULTI_HOMING__)
        for (i = 0; i < m_numSvrInst; i++)
        {
            struct svrInst *pSvrInst = &m_svrInst[i];
            if (pSvrInst->errNo)
            {
                sbyte4 j = pSvrInst->serverInstanceNew - 1;
                if ((0 <= j) && (j < m_numSvrInst) && !m_svrInst[j].errNo)
                    continue;

                for (j = 0; j < m_numSvrInst; j++)
                {
                    if ((j != i) && !m_svrInst[j].errNo)
                    {
#ifdef __PARAGON__
#ifdef __VPN_ADD_DEFAULT_ROUTE__
                        /* Change the GW Route to the new interface only if the Server sends default route over
                           the tunnel*/
                        status = IKE_SAMPLE_ikeGetHostAddr(&hostAddrNew
                                    MOC_MTHM_REQ_VALUE(j + 1));
                        if ((OK == status) && (gdwPeerAddr))
                            Add_Route(gdwPeerAddr, htonl(hostAddrNew), inet_addr("255.255.255.255"), 0);
#endif
#endif
                        if (OK > IKE2_keyUpdate(i+1, j+1))
                            continue;

                        pSvrInst->serverInstanceNew = j+1;
                        break;
                    }
                }
            }
        }
#endif
#ifdef __ENABLE_MSGIDLE_THREAD__
        RTOS_deltaMS(NULL, &timeidle);
#else
        status = IKE_msgIdle();

        RTOS_deltaMS(NULL, &timeidle);
#endif
#endif /* !__IKE_MULTI_THREADED__ */

    } /* while */

exit:
    return status;
} /* IKE_EXAMPLE_listen */


/*------------------------------------------------------------------*/
/* RADIUS Passthru [v2]                                             */
/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_EAP_AUTH__) && defined(__ENABLE_DIGICERT_EAP_RADIUS__) && defined(__ENABLE_DIGICERT_RADIUS_CLIENT__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)

static sbyte   *mRSS    = NULL;
static ubyte4   mRSSlen = 0;

static sbyte   *mRadSvrAddr     = NULL;
static sbyte4   mRadSvrPort     = RADIUS_STANDARD_PORT;

static sbyte4   mRadSvrId       = 0;
static ubyte2   mRadPortNo      = 0;

#ifdef __ENABLE_DIGICERT_IPV6__
#undef MOC_UDP_ANY_ADDR
static MOC_IP_ADDRESS_S m_addrAny =
{
    AF_INET, { { 0 } },
};
#define MOC_UDP_ANY_ADDR &m_addrAny
#endif


/*------------------------------------------------------------------*/

static int
IKE_EXAMPLE_EAP_RADIUS_getArgs(int argc, char *argv[])
{
    int status = argc;
    int i, j;
    int rsrvSet, ridSet, rportSet;

    rsrvSet = ridSet = rportSet = 0;

    for (i = 1; i < argc; ) /*Skiping argv[0] which is example progam name*/
    {
        if (DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--rad_server") == 0)
        {
            rsrvSet = 1; /* Radius server should not be set to default*/
            i++;
            setParameter(&mRadSvrAddr, argv[i]);
            for (j=i-1; j<(argc-2); ++j)
                argv[j] = argv[j+2];
            argc -= 2;
            i--;
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--rad_secret") == 0)
        {
            ridSet = 1; /* Radius secret should not be set to default*/
            i++;
            setParameter(&mRSS, argv[i]);
            mRSSlen = DIGI_STRLEN(mRSS);
            for (j=i-1; j<(argc-2); ++j)
                argv[j] = argv[j+2];
            argc -= 2;
            i--;
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--rad_authPort") == 0)
        {
            rportSet = 1; /* Radius Port should not be set to default*/
            i++;
            mRadSvrPort = atoi(argv[i]);
            for (j=i-1; j<(argc-2); ++j)
                argv[j] = argv[j+2];
            argc -= 2;
            i--;
            continue;
        }
        /* Nothing found */
        i++;
    }

    if (!rsrvSet)
    {
        setParameter(&mRadSvrAddr, "127.0.0.1");
    }
    if (!ridSet)
    {
        setParameter(&mRSS, "secret");
        mRSSlen = DIGI_STRLEN(mRSS);
    }

    /*End of defaults*/
    return argc;
}


/*------------------------------------------------------------------*/

static sbyte4
IKE_EXAMPLE_radRecv(void *pUdpDescr, void *cb,
                    ubyte *poBuffer, ubyte4 dwBufferSize,
                    MOC_IP_ADDRESS peerAddr, ubyte2 wPeerPort)
{
    MOC_UNUSED(pUdpDescr);
    MOC_UNUSED(cb);
    MOC_UNUSED(peerAddr);
    MOC_UNUSED(wPeerPort);

    return IKE_radRecv(MOC_UDP_ANY_ADDR, mRadPortNo,
                       poBuffer, dwBufferSize,
                       mRadSvrId);
}


/*------------------------------------------------------------------*/

static sbyte4
IKE_SAMPLE_getRadSvrId(sbyte4 *pRadSvrId, sbyte4 radInstId,
                       const ubyte *poUser, ubyte4 dwUserLen,
                       MOC_IP_ADDRESS peerAddr,
                       sbyte4 serverInstance)
{
    sbyte4 status = OK;

    MOC_UNUSED(poUser);
    MOC_UNUSED(dwUserLen);
    MOC_UNUSED(peerAddr);
    MOC_UNUSED(serverInstance);

    if (0 == mRadSvrId)
    {
        void *pUdpDescr = NULL;

        if (0 > (status = RADIUS_addServer(radInstId, MOC_UDP_ANY_ADDR,
                                           mRadSvrAddr, mRadSvrPort,
                                           (ubyte *)mRSS, mRSSlen,
                                           &mRadSvrId)))
        {
            DEBUG_ERROR(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_EXAMPLE: RADIUS_addServer() failed, status = ", status);
            goto exit;
        }

        if (0 > (status = RADIUS_getUDPCookieFromServerID(mRadSvrId, &pUdpDescr)))
        {
            DEBUG_ERROR(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_EXAMPLE: RADIUS_getUDPCookieFromServerID() failed, status = ", status);
            goto exit;
        }
        else
        {
            MOC_IP_ADDRESS_S srcAddr;

            if (OK > (status = UDP_getSrcPortAddr(pUdpDescr, &mRadPortNo, &srcAddr)))
            {
                DEBUG_ERROR(DEBUG_PLATFORM, (sbyte *)"IKE_EXAMPLE: UDP_getSrcPortAddr() failed, status = ", status);
                goto exit;
            }
        }

        if (0 > (status = IKE_EXAMPLE_addSktDescr(pUdpDescr, NULL,
                                                  IKE_EXAMPLE_udpRead,
                                                  IKE_EXAMPLE_radRecv,
                                                  NULL))) /* !!! */
        {
            goto exit;
        }

        DEBUG_PRINT(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_EXAMPLE: Socket created on [");
        DEBUG_INT(DEBUG_IKE_EXAMPLE, (sbyte4)mRadPortNo);
        DEBUG_PRINTNL(DEBUG_IKE_EXAMPLE, (sbyte *)"]");
    }

    *pRadSvrId = mRadSvrId;

exit:
    return status;
} /* IKE_SAMPLE_getRadSvrId */

#endif /* RADIUS passthru */


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_EAP_AUTH__) || defined(__ENABLE_DIGICERT_EAP_PEER__)) && !defined(__DISABLE_DIGICERT_IKE_EAP__) && \
    defined(__ENABLE_DIGICERT_EAP_TLS__)
static sbyte4
IKE_SAMPLE_getTlsCertStore(certStorePtr *ppCertStore, sbyte **ppCommonName,
                           const ubyte *poUser, ubyte4 dwUserLen,
                           MOC_IP_ADDRESS peerAddr,
                           sbyte4 serverInstance)
{
    if (ppCertStore)
        *ppCertStore = g_pIKECertStore;

    if (ppCommonName)
        *ppCommonName = g_IKECertCommonName;

    return OK;
}
#endif


/*------------------------------------------------------------------*/
/* IKE Server Instance(s)                                           */
/*------------------------------------------------------------------*/

#if !(defined(__ENABLE_MOBIKE__) && defined(__IKE_MULTI_HOMING__))

#ifndef __IKE_MULTI_HOMING__
#define SVR_INST_MAX 1
#else
#define SVR_INST_MAX 32
#endif

static struct svrInst
{
    MOC_IP_ADDRESS_S    saddr;
    ubyte2              port[2];
    sbyte4              sktDescr[2]; /* e.g. 500, 4500 */

#if defined(__ENABLE_IPSEC_COOKIE__) && !defined(__ENABLE_DIGICERT_PFKEY__)
    ubyte4              cookie;
#endif
}
m_svrInst[SVR_INST_MAX];

static sbyte4 m_numSvrInst = 0;

#endif


/*------------------------------------------------------------------*/

static sbyte4
IKE_EXAMPLE_msgRecv(void *pUdpDescr, void *cb,
                    ubyte *poBuffer, ubyte4 dwBufferSize,
                    MOC_IP_ADDRESS peerAddr, ubyte2 wPeerPort)
{
    sbyte4 status = OK;

    sbyte4 i = (sbyte4)((uintptr)cb);
    sbyte4 serverInstance = 0;
    intBoolean bUseNattPort = FALSE;
#ifdef __IKE_TRACK__
    enum ike_status_ex1 ikeStatus = UNSPECIFIED_STATUS;
#endif
    /* check server instance */
    if ((0 > i) || (i >= m_numSvrInst))
    {
        DEBUG_ERROR(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_EXAMPLE: Socket not found, index = ", i);
        status = ERR_IKE;
        goto exit;
    }
    else
    {
        struct svrInst *pSvrInst = &m_svrInst[i];
        sbyte4 j = 0;
#ifdef __ENABLE_IPSEC_NAT_T__
        for (; j < 2; j++)
#endif
        {
            sbyte4 sktDescr = pSvrInst->sktDescr[j];
            if ((0 <= sktDescr) && (sktDescr < m_numSktDescr))
            {
                if (pUdpDescr == m_sktDescr[sktDescr].pSktDescr)
                {
                    serverInstance = i + 1;
#ifdef __ENABLE_IPSEC_NAT_T__
                    if (j) bUseNattPort = TRUE;
#endif
                }
            }
        }
    }

    if (0 >= serverInstance)
    {
        DEBUG_ERROR(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_EXAMPLE: Socket not found, index = ", i);
        status = ERR_IKE;
        goto exit;
    }
    else
    {
        /* get IKE version */
        sbyte4 ver_pos = 17;
#ifdef __ENABLE_IPSEC_NAT_T__
        if (bUseNattPort) ver_pos += 4;
#endif
        /* process message */
        if (((ubyte4)ver_pos < dwBufferSize) && ((2<<4) == poBuffer[ver_pos]))
        {
#ifdef __IKE_MULTI_THREADED__
            status = DPC_IKE_msgRecv(2,
                    peerAddr, wPeerPort,
                    poBuffer, dwBufferSize,
                    serverInstance, bUseNattPort);
#else

            if (m_useMsgRecv)
            {
                status = IKE2_msgRecv(peerAddr, wPeerPort,
                        poBuffer, dwBufferSize,
                        serverInstance, bUseNattPort
#ifdef __IKE_TRACK__
                        , NULL
#endif
                        );
            }
            else
            {
#ifdef __IKE_TRACK__
                status = IKE2_msgRecvEx1(peerAddr, wPeerPort,
                        poBuffer, dwBufferSize,
                        serverInstance, bUseNattPort,
                        &ikeStatus);
#endif
            }
#endif
        }
        else
        {
#ifdef __IKE_MULTI_THREADED__
            status = DPC_IKE_msgRecv(1,
                    peerAddr, wPeerPort,
                    poBuffer, dwBufferSize,
                    serverInstance, bUseNattPort);
#else
            if (m_useMsgRecv)
            {
                status = IKE_msgRecv(peerAddr, wPeerPort,
                        poBuffer, dwBufferSize,
                        serverInstance, bUseNattPort
#ifdef __IKE_TRACK__
                        , NULL
#endif
                        );
            }
            else
            {
#ifdef __IKE_TRACK__
                status = IKE_msgRecvEx1(peerAddr, wPeerPort,
                        poBuffer, dwBufferSize,
                        serverInstance, bUseNattPort, &ikeStatus);
#endif
            }
#endif
        }
    }

exit:
    return status;
} /* IKE_EXAMPLE_msgRecv */


/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_EAP_AUTH__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
static intBoolean m_bEapProtoAuth       = FALSE;
#endif

static sbyte4
IKE_EXAMPLE_evtRecv(void *pUdpDescr, void *cb,
                    ubyte *poBuffer, ubyte4 dwBufferSize,
                    MOC_IP_ADDRESS peerAddr, ubyte2 wPeerPort)
{
    sbyte4 status;

    MOC_UNUSED(pUdpDescr);
    MOC_UNUSED(cb);
    MOC_UNUSED(wPeerPort);

    if (SAME_MOC_IPADDR(peerAddr, MOC_UDP_LOOPBACK_ADDR_S) &&
        (sizeof(struct ike_event) == dwBufferSize))
    {
        IKEEVT pxEvt = (IKEEVT)poBuffer;

        MOC_IP_ADDRESS hostAddr;
        if (OK > (status = IKE_evtGetAddr(pxEvt, &hostAddr, NULL)))
        {
            DEBUG_ERROR(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_EXAMPLE: Bad event type = ", (sbyte4) pxEvt->type);
            goto exit;
        }
        else
        {
            sbyte4 i;
            for (i = 0; i < m_numSvrInst; i++)
            {
                struct svrInst *pSvrInst = &m_svrInst[i];
                if (SAME_MOC_IPADDR(hostAddr, pSvrInst->saddr))
                {
                    /* found */
                    if (
#if defined(__ENABLE_IKE_MODE_CFG__) || defined(__ENABLE_IKE_CP__)
                        (2 == m_vpnAgent) ||
#endif
#if defined(__ENABLE_DIGICERT_EAP_AUTH__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
                        (m_bEapProtoAuth) ||
#endif
                        FALSE)
                    switch (IKE_KEY_TYPE_MASK & pxEvt->type)
                    {
                    case IKE_KEY_TYPE_ACQUIRE :
                    case IKE_KEY_TYPE_SAINIT :
                        goto exit; /* do not initiate exchange */
                    }
                    status = IKE_evtRecv(pxEvt, i+1, FALSE);
                    goto exit;
                }
            }

            DEBUG_PRINT(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_EXAMPLE: Bad event host = ");
            IKE_EXAMPLE_printIpAddr(hostAddr);
            DEBUG_PRINTNL(DEBUG_IKE_EXAMPLE, (sbyte *)NULL);
            status = ERR_IKE;
        }
    }
    else
    {
        DEBUG_PRINT(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_EXAMPLE: Bad event peer = ");
        IKE_EXAMPLE_printIpAddr(peerAddr);
        DEBUG_PRINTNL(DEBUG_IKE_EXAMPLE, (sbyte *)NULL);
        status = ERR_IKE;
    }

exit:
    return status;
} /* IKE_EXAMPLE_evtRecv */


/*------------------------------------------------------------------*/

#ifdef __PARAGON__
#if defined(__ENABLE_MOBIKE__) && defined(__IKE_MULTI_HOMING__)

static sbyte4
IKE_EXAMPLE_readdServer(MOC_IP_ADDRESS saddr, ubyte2 port,
                        ubyte2 natt_port,
                        ubyte4 cookie)
{
    sbyte4 status = -1;
    void *pUdpDescr = NULL;

    sbyte4 i = 0;

    while (i < m_numSvrInst)
    {
        if (SAME_MOC_IPADDR(saddr, m_svrInst[i].saddr))
            break;
        i++;
    }

    /* New Host Addr Added to the Machine */
    if (m_numSvrInst <= i)
    {
         return IKE_EXAMPLE_addServer(saddr, port,
                                      natt_port,
                                      cookie);
    }

    if (!m_svrInst[i].errNo)
    {
        status = OK;
        goto exit;
    }

    if (m_sktDescr[m_svrInst[i].sktDescr[0]].pSktDescr)
        m_sktDescr[m_svrInst[i].sktDescr[0]].closefn(&(m_sktDescr[m_svrInst[i].sktDescr[0]].pSktDescr),
                                                     m_sktDescr[m_svrInst[i].sktDescr[0]].cb);
    if (m_sktDescr[m_svrInst[i].sktDescr[1]].pSktDescr)
        m_sktDescr[m_svrInst[i].sktDescr[1]].closefn(&(m_sktDescr[m_svrInst[i].sktDescr[1]].pSktDescr),
                                                    m_sktDescr[m_svrInst[i].sktDescr[1]].cb);
    m_sktDescr[m_svrInst[i].sktDescr[0]].pSktDescr = NULL;
    m_sktDescr[m_svrInst[i].sktDescr[1]].pSktDescr = NULL;
    m_svrInst[i].sktDescr[1] = -1;
    m_svrInst[i].sktDescr[0] = -1;
    m_svrInst[i].errNo = 0;
    m_svrInst[i].serverInstanceNew =0;

    /* 500 */
    if (port)
    {
        if (0 > (status = IKE_EXAMPLE_addUdpSkt(&pUdpDescr, (void *)i,
                                                IKE_EXAMPLE_msgRecv,
                                                saddr, port)))
        {
            goto exit;
        }
        m_svrInst[i].sktDescr[0] = status;
        m_svrInst[i].port[0] = port;
    }
    else m_svrInst[i].sktDescr[0] = -1;

    /* 4500 */
#ifdef __ENABLE_IPSEC_NAT_T__
    if (natt_port)
    {
        if (0 > (status = IKE_EXAMPLE_addUdpSkt(NULL, (void *)i,
                                                IKE_EXAMPLE_msgRecv,
                                                saddr, natt_port)))
        {
            if (port && (NULL != pUdpDescr)) /* jic */
            {
                UDP_unbind(&pUdpDescr);

            }
            goto exit;
        }
        m_svrInst[i].sktDescr[1] = status;
        m_svrInst[i].port[1] = natt_port;
    }
    else
#else
    MOC_UNUSED(natt_port);
    DEBUG_ERROR(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_EXAMPLE: NAT-T is not enabled, port = ", (sbyte4)natt_port);
#endif
    m_svrInst[i].sktDescr[1] = -1;

    if (0 > status) goto exit; /* jic */

    COPY_MOC_IPADDR(m_svrInst[i].saddr, saddr);

#if defined(__ENABLE_IPSEC_COOKIE__) && !defined(__ENABLE_DIGICERT_PFKEY__)
    m_svrInst[i].cookie = cookie;
#else
    MOC_UNUSED(cookie);
#endif

    status = i;

exit:
    return status;
} /* IKE_EXAMPLE_readdServer */

#endif /* defined(__ENABLE_MOBIKE__) && defined(__IKE_MULTI_HOMING__) */
#endif /* __PARAGON__ */


/*------------------------------------------------------------------*/

static sbyte4
IKE_EXAMPLE_addServer(MOC_IP_ADDRESS saddr, ubyte2 port,
                      ubyte2 natt_port,
                      ubyte4 cookie)
{
    sbyte4 status = -1;
    void *pUdpDescr = NULL;

    sbyte4 i = m_numSvrInst;
    if (SVR_INST_MAX <= i)
    {
        DEBUG_PRINTNL(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_EXAMPLE: Too many server instances!");
        status = ERR_IKE;
        goto exit;
    }

    /* 500 */
    if (port)
    {
        if (0 > (status = IKE_EXAMPLE_addUdpSkt(&pUdpDescr, (void *)((uintptr)i),
                                                IKE_EXAMPLE_msgRecv,
                                                saddr, port)))
        {
            goto exit;
        }
        m_svrInst[i].sktDescr[0] = status;
        m_svrInst[i].port[0] = port;
    }
    else m_svrInst[i].sktDescr[0] = -1;

    /* 4500 */
#ifdef __ENABLE_IPSEC_NAT_T__
    if (natt_port)
    {
        if (0 > (status = IKE_EXAMPLE_addUdpSkt(NULL, (void *)((uintptr)i),
                                                IKE_EXAMPLE_msgRecv,
                                                saddr, natt_port)))
        {
            if (port && (NULL != pUdpDescr)) /* jic */
            {
                UDP_unbind(&pUdpDescr);
                m_numSktDescr--;
            }
            goto exit;
        }
        m_svrInst[i].sktDescr[1] = status;
        m_svrInst[i].port[1] = natt_port;
    }
    else
#else
    MOC_UNUSED(natt_port);
    DEBUG_ERROR(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_EXAMPLE: NAT-T is not enabled, port = ", (sbyte4)natt_port);
#endif
    m_svrInst[i].sktDescr[1] = -1;

    if (0 > status) goto exit; /* jic */

    COPY_MOC_IPADDR(m_svrInst[i].saddr, saddr);

#if defined(__ENABLE_IPSEC_COOKIE__) && !defined(__ENABLE_DIGICERT_PFKEY__)
    m_svrInst[i].cookie = cookie;
#else
    MOC_UNUSED(cookie);
#endif

    m_numSvrInst++;
    status = i;

exit:
    return status;
} /* IKE_EXAMPLE_addServer */


/*------------------------------------------------------------------*/

static void
IKE_EXAMPLE_addDefaultServers(void)
{
#if 1
    sbyte4 status;
    MOC_IP_ADDRESS_S hostAddr;

#ifdef __PARAGON__
#ifdef __IKE_MULTI_HOMING__
    MOC_IP_ADDRESS ipAddr[SVR_INST_MAX];
    ubyte2 i = 0;

    DIGI_MEMSET((ubyte *)ipAddr, 0, sizeof(ipAddr));
    getLocalBindIPAddr(&hostAddr);
    hostAddr = htonl(hostAddr);

    /* Add the Preferred address as the first address */
    IKE_EXAMPLE_addServer(REF_MOC_IPADDR(hostAddr),
                          IKE_DEFAULT_UDP_PORT,
                          IKE_NAT_UDP_PORT,
                          0);
#ifdef __RTOS_LINUX__
    status = OnIp2MultiIntf((MOC_IP_ADDRESS *)ipAddr, SVR_INST_MAX,(sbyte4 *)&m_IfIndex);
#else
    status = OnIp2MultiIntf((PULONG)ipAddr, SVR_INST_MAX,(DWORD *)&m_IfIndex);
#endif

    DEBUG_ERROR(DEBUG_PLATFORM, (sbyte *)"IKE_EXAMPLE: OnIp2MultiIntf() returned status = ", status);
    if (status == 0)
    {
        while (ipAddr[i])
        {
            DEBUG_ERROR(DEBUG_PLATFORM, (sbyte *)"IKE_EXAMPLE: OnIp2Intf() returned Address ", ipAddr[i]);
            if (REF_MOC_IPADDR(hostAddr) != htonl(ipAddr[i]))
                IKE_EXAMPLE_addServer(htonl(ipAddr[i]),
                                  IKE_DEFAULT_UDP_PORT,
                                  IKE_NAT_UDP_PORT,
                                  0);
            i++;
        }
        return;
    }

#else

    getLocalBindIPAddr(&hostAddr);
    hostAddr = htonl(hostAddr);
#endif /* MULTIHOMING */

#else /* Not RTOS_WINCE */

    /* get IP address */
    if (OK > (status = UDP_getIfAddr(NULL, &hostAddr)))
    {
        DEBUG_ERROR(DEBUG_PLATFORM, (sbyte *)"IKE_EXAMPLE: UDP_getIfAddr() failed, status = ", status);
        IKE_EXAMPLE_printLastError( (sbyte *)"             gethost[by]name() returns error ");
        return;
    }
#endif

    IKE_EXAMPLE_addServer(REF_MOC_IPADDR(hostAddr),
#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) || defined(__ENABLE_DIGICERT_GDOI_SERVER__)
                          IKE_GDOI_UDP_PORT,
#else
                          IKE_DEFAULT_UDP_PORT,
#endif
                          IKE_NAT_UDP_PORT,
                          0);

#elif defined(__WIN32_RTOS__) || defined(__LINUX_RTOS__) || defined(__RTOS_WINCE__)
    char nodename[256];
    struct addrinfo* res;
    struct addrinfo hints = { AI_PASSIVE | AI_CANONNAME };

    if ((0 == gethostname(nodename, sizeof(nodename))) &&
        (0 == getaddrinfo(nodename, NULL, &hints, &res)))
    {
        struct addrinfo* r = res;

        for (; r; r = r->ai_next)
        {
            MOC_IP_ADDRESS_S hostAddr;

            if (AF_INET == r->ai_family)
            {
                struct sockaddr_in *a = (struct sockaddr_in *) r->ai_addr;
                SET_MOC_IPADDR4(hostAddr, GET_NTOHL(a->sin_addr.s_addr));
                if (SAME_MOC_IPADDR(MOC_UDP_LOOPBACK_ADDR, hostAddr))
                    continue;
            }
#ifdef __ENABLE_DIGICERT_IPV6__
            else if (AF_INET6 == r->ai_family)
            {
                struct sockaddr_in6 *a = (struct sockaddr_in6 *) r->ai_addr;
                ubyte *addr6 = (ubyte *) a->sin6_addr.s6_addr;
                SET_MOC_IPADDR6(hostAddr, addr6);
                if (SAME_MOC_IPADDR(MOC_UDP_LOOPBACK_ADDR6, hostAddr))
                    continue;
            }
#endif
            else continue;

            IKE_EXAMPLE_addServer(REF_MOC_IPADDR(hostAddr),
#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) || defined(__ENABLE_DIGICERT_GDOI_SERVER__)
                                  IKE_GDOI_UDP_PORT,
#else
                                  IKE_DEFAULT_UDP_PORT,
#endif
                                  IKE_NAT_UDP_PORT,
                                  0);
        }

        freeaddrinfo(res);
    }
#endif /* defined(__WIN32_RTOS__) */

    return;
} /*  IKE_EXAMPLE_addDefaultServers */


/*------------------------------------------------------------------*/

extern sbyte4
IKE_SAMPLE_ikeGetHostAddr(MOC_IP_ADDRESS_S *pHostAddr, sbyte4 serverInstance)
{
    sbyte4 status = OK;
    sbyte4 i;

#ifndef __IKE_MULTI_HOMING__
    MOC_UNUSED(serverInstance);
    i = 0;
#else
    i = serverInstance - 1;
#endif
    if ((0 > i) || (i >= m_numSvrInst))
    {
        status = ERR_IKE;
        goto exit;
    }

    *pHostAddr = m_svrInst[i].saddr;

exit:
    return status;
} /* IKE_SAMPLE_ikeGetHostAddr */


/*------------------------------------------------------------------*/

#if defined(__ENABLE_IPSEC_COOKIE__) && !defined(__ENABLE_DIGICERT_PFKEY__)

extern sbyte4
IKE_SAMPLE_ikeGetCookie(ubyte4 *cookie, sbyte4 serverInstance)
{
    sbyte4 status = OK;
    sbyte4 i;

#ifndef __IKE_MULTI_HOMING__
    MOC_UNUSED(serverInstance);
    i = 0;
#else
    i = serverInstance - 1;
#endif
    if ((0 > i) || (i >= m_numSvrInst))
    {
        status = ERR_IKE;
        goto exit;
    }

    *cookie = m_svrInst[i].cookie;

exit:
    return status;
} /* IKE_SAMPLE_ikeGetCookie */

#endif


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_GDOI_SERVER__

extern sbyte4
IKE_SAMPLE_isKeyServer(intBoolean *result, sbyte4 serverInstance)
{
    sbyte4 status = 0;
    sbyte4 i;

#ifndef __IKE_MULTI_HOMING__
    MOC_UNUSED(serverInstance);
    i = 0;
#else
    i = serverInstance - 1;
#endif
    if ((0 > i) || (i >= m_numSvrInst))
    {
        status = (sbyte4)ERR_IKE;
        goto exit;
    }

    *result = TRUE;

exit:
    return status;
} /* IKE_SAMPLE_isKeyServer */

#endif


/*------------------------------------------------------------------*/

static sbyte4
IKE_SAMPLE_ikeXchgSend(MOC_IP_ADDRESS dwPeerAddr, ubyte2 wPeerPort,
                       ubyte *pBuffer, ubyte4 dwBufferSize,
                       sbyte4 serverInstance,
                       intBoolean bUseNattPort)
{
    /* Send an ISAKMP exchange message to a peer IKE server. */
    sbyte4 status = ERR_IKE;

    sbyte4 i, j;
    void *pUdpDescr;
    sbyte4 sktDescr;

#ifndef __IKE_MULTI_HOMING__
    MOC_UNUSED(serverInstance);
    i = 0;
#else
    i = serverInstance - 1;
#endif
    /* locate local IKE socket */
    if ((0 > i) || (i >= m_numSvrInst))
    {
        DEBUG_ERROR(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_SAMPLE_ikeXchgSend: Socket not found, index = ", i);
        goto exit;
    }

#ifdef __ENABLE_IPSEC_NAT_T__
    j = bUseNattPort ? 1 : 0;
#else
    j = 0;
    MOC_UNUSED(bUseNattPort);
#endif
    sktDescr = m_svrInst[i].sktDescr[j];

    if ((0 > sktDescr) || (sktDescr >= m_numSktDescr) ||
        (NULL == (pUdpDescr = m_sktDescr[sktDescr].pSktDescr)))
    {
        DEBUG_ERROR(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_SAMPLE_ikeXchgSend: Invalid socket descriptor = ", sktDescr);
        goto exit;
    }

    /* send message */
    if (OK > (status = UDP_sendTo(pUdpDescr, dwPeerAddr, wPeerPort, pBuffer, dwBufferSize)))
    {
#if defined(__ENABLE_MOBIKE__) && defined(__IKE_MULTI_HOMING__)
        int errNo = IKE_EXAMPLE_getLastError();
        if (10049 == errNo) /* Cannot assign requested address */
            m_svrInst[i].errNo = errNo;
#endif
        DEBUG_ERROR(DEBUG_PLATFORM, (sbyte *)"IKE_EXAMPLE: UDP_sendTo() failed, status = ", status);
        IKE_EXAMPLE_printLastError( (sbyte *)"             sendto() returns error ");
        DEBUG_PRINT(DEBUG_PLATFORM, (sbyte *)"             Remote IP address = ");
        IKE_EXAMPLE_printIpAddr(dwPeerAddr);
        DEBUG_PRINTNL(DEBUG_PLATFORM, (sbyte *)NULL);
        goto exit;
    }

#if defined(__ENABLE_MOBIKE__) && defined(__IKE_MULTI_HOMING__)
    m_svrInst[i].errNo = 0;
    m_svrInst[i].serverInstanceNew = 0;
#endif

exit:
    return status;
} /* IKE_SAMPLE_ikeXchgSend */


/*------------------------------------------------------------------*/

static sbyte4
IKE_SAMPLE_ikeEvtSend(ubyte *pBuffer, ubyte4 dwBufferSize,
                      MOC_IP_ADDRESS hostAddr,
                      ubyte4 cookie)
{
    /* Send an IPsec event to the host IKE server (called from IPsec) */
    sbyte4 status = ERR_IKE;

    void *pUdpDescr = NULL;
    MOC_IP_ADDRESS myAddress = MOC_UDP_LOOPBACK_ADDR;/*MOC_UDP_ANY_ADDR;*/

    MOC_UNUSED(hostAddr);
    MOC_UNUSED(cookie);

    /* create socket and contact local IKE server */
    if (OK > (status = UDP_connect(&pUdpDescr, myAddress, MOC_UDP_ANY_PORT,
                                   MOC_UDP_LOOPBACK_ADDR, g_ikeEventPort, TRUE)))
    {
        DEBUG_ERROR(DEBUG_PLATFORM, (sbyte *)"IKE_EXAMPLE: UDP_connect() failed, status = ", status);
        IKE_EXAMPLE_printLastError( (sbyte *)"             connect() returns error ");
        DEBUG_PRINTNL(DEBUG_PLATFORM, (sbyte *)NULL);
        goto exit;
    }

    /* send event */
    if (OK > (status = UDP_send(pUdpDescr, pBuffer, dwBufferSize)))
    {
        DEBUG_ERROR(DEBUG_PLATFORM, (sbyte *)"IKE_EXAMPLE: UDP_send() failed, status = ", status);
        IKE_EXAMPLE_printLastError( (sbyte *)"             send() returns error ");
        goto exit;
    }

exit:
    if (NULL != pUdpDescr)
        UDP_unbind(&pUdpDescr);

    return status;
} /* IKE_SAMPLE_ikeEvtSend */


/*------------------------------------------------------------------*/
/* Command Line Options                                             */
/*------------------------------------------------------------------*/

/* used in ike_cert_utils.c */
ikeSettings m_ikeOptSettings = { 0 };

static intBoolean m_bIkeTimeoutNegotiation = FALSE;
static intBoolean m_bIkeTimeoutDpd      = FALSE;

static intBoolean m_bIkeVersion         = FALSE;

#ifdef __ENABLE_IKE_AGGRESSIVE_MODE__
static intBoolean m_bIkeP1Mode          = FALSE;
#endif

static intBoolean m_bIkeP1LifeSecs      = FALSE;
static intBoolean m_bIkeP1LifeSecsMax   = FALSE;

static intBoolean m_bIkeP2LifeSecs      = FALSE;
static intBoolean m_bIkeP2LifeSecsMax   = FALSE;

static intBoolean m_bIkeP1DHgroup       = FALSE;
static intBoolean m_bIkeP2PFS           = FALSE;

#ifdef __ENABLE_IKE_XAUTH__
static intBoolean m_bXauthType          = FALSE;
#ifdef __ENABLE_IKE_HYBRID_RSA__
static intBoolean m_bHybrid             = FALSE;
#endif
#endif

#ifdef __ENABLE_IKE_REDIRECT__
static intBoolean m_redirectGwAddr      = FALSE;
#endif

#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
static intBoolean m_bKeyServerAddr      = FALSE;
#endif


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_EAP_AUTH__) || defined(__ENABLE_DIGICERT_EAP_PEER__)) && !defined(__DISABLE_DIGICERT_IKE_EAP__)

#ifdef __ENABLE_DIGICERT_EAP_SIM__
static ubyte eapSimTriplets[] = /* must be specified in the following order! */
{/*
    (RAND1,SRES1,Kc1) = (10111213 14151617 18191a1b 1c1d1e1f,
                         d1d2d3d4,
                         a0a1a2a3 a4a5a6a7)
    (RAND2,SRES2,Kc2) = (20212223 24252627 28292a2b 2c2d2e2f,
                         e1e2e3e4,
                         b0b1b2b3 b4b5b6b7)
    (RAND3,SRES3,Kc3) = (30313233 34353637 38393a3b 3c3d3e3f,
                         f1f2f3f4,
                         c0c1c2c3 c4c5c6c7)
  */
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0xd1, 0xd2, 0xd3, 0xd4,
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,

    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0xe1, 0xe2, 0xe3, 0xe4,
    0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,

    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    0xf1, 0xf2, 0xf3, 0xf4,
    0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
};

static ubyte eapAkaVector[] = /* must be specified in the following order! */
{/*
    (RAND, AUTN, CK, IK, RES) = (00112233445566778899AABBCCDDEEFF,
                                 112233445566778899AABBCCDDEEFF00,
                                 2233445566778899AABBCCDDEEFF0011,
                                 33445566778899AABBCCDDEEFF001122,
                                 00112233445566778899) <= variable 4-16 bytes
  */
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
    0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
    0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99
};
#endif /* __ENABLE_DIGICERT_EAP_SIM__ */

#ifdef __ENABLE_IKE_EAP_ONLY__
static intBoolean m_bDoEapOnly          = FALSE;
#endif


#ifdef __ENABLE_DIGICERT_EAP_PEER__

intBoolean m_bEapProtoPeer       = FALSE;

#ifdef __ENABLE_DIGICERT_EAP_TTLS__
static intBoolean m_bEapTtlsType        = FALSE;
#endif


/*------------------------------------------------------------------*/

static sbyte *passwordString = NULL;

static sbyte4
IKE_SAMPLE_getToken(ubyte *pData, ubyte4 dataLen,
                    ubyte **ppSecret, ubyte4 *pSecretLen, sbyte4 serverInstance)
{
    MSTATUS status = OK;

    ubyte4 secretLen;
    ubyte *secret;
    char ptr[40];


    if (!ppSecret || !pSecretLen)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (pData && dataLen)
    {
        ubyte4 i;

#ifdef __ENABLE_DIGICERT_EAP_SIM__
        sbyte4 cmp;

        /* check EAP-SIM triplets */
        ubyte numRand = (ubyte)(dataLen / EAP_SIM_RAND_LEN);
        if ((0 == (dataLen % EAP_SIM_RAND_LEN)) &&
            ((2 == numRand) || (3 == numRand)))
        {
            #define SRES_KC_LEN (EAP_SIM_SRES_LEN + EAP_SIM_KC_LEN)
            #define TRIPLET_LEN (EAP_SIM_RAND_LEN + SRES_KC_LEN)
            ubyte numTriplets = (ubyte)(sizeof(eapSimTriplets) / TRIPLET_LEN);
            if (numTriplets >= numRand)
            {
                ubyte *pSecret;
                secretLen = numRand * SRES_KC_LEN;
                if (NULL == (pSecret = (ubyte *) MALLOC(secretLen)))
                {
                    status = ERR_MEM_ALLOC_FAIL;
                    goto exit;
                }

                for (i=0; i < numRand; i++)
                {
                    /* traverse all [RAND, SRES, KC] triplets */
                    ubyte *rand = pData + (i * EAP_SIM_RAND_LEN);
                    ubyte j;
                    for (j=0; j < numTriplets; j++)
                    {
                        /* match RAND value in each triplet */
                        ubyte *triplet = &eapSimTriplets[j * TRIPLET_LEN];
                        if (OK > (status = DIGI_MEMCMP(rand, triplet,
                                                      EAP_SIM_RAND_LEN, &cmp)))
                            goto exit;

                        if (!cmp)
                        {
                            /* return concatenation of [SRES, kC]'s */
                            DIGI_MEMCPY(pSecret + (i * SRES_KC_LEN),
                                       triplet + EAP_SIM_RAND_LEN, SRES_KC_LEN);
                            break;
                        }
                    } /* for (... numTriplets */

                    if (j >= numTriplets)
                    {
                        FREE(pSecret);
                        goto next;
                    }
                } /* for (... numRand */

                *ppSecret = pSecret;
                *pSecretLen = secretLen;
                goto exit;
            }
        }

next:
        /* check EAP-AKA quintuplet */
        if ((EAP_SIM_RAND_LEN + EAP_AKA_AUTN_LEN) == dataLen)
        {
            /* match [RAND, AUTN] */
            if (OK > (status = DIGI_MEMCMP(pData, eapAkaVector, dataLen, &cmp)))
                goto exit;

            if (!cmp)
            {
                /* return [CK, IK, RES] */
                secret = &eapAkaVector[dataLen];
                secretLen = sizeof(eapAkaVector) - dataLen;
                goto done;
            }
        }
#endif
        /* display EAP-GTC message */
        for (i=0; i < dataLen; i++)
        {
            ubyte c = pData[i];
            fprintf(stderr, "%c", isprint((int)c) ? c : '.');
        }
        if ((2 > dataLen) || memcmp(": ", pData+(dataLen-2), 2))
            fprintf(stderr, ": ");

        /* enter EAP-GTC token interactively. */
        if(1 != scanf("%39s", ptr))
        {
            status = ERR_EAP;
            goto exit;
        }
        secret = (ubyte *)ptr;
        secretLen = (ubyte4) strlen(ptr);
    }
    else
    {
        secret = (ubyte *)passwordString;
        secretLen = DIGI_STRLEN(passwordString);
    }

#ifdef __ENABLE_DIGICERT_EAP_SIM__
done:
#endif
    if (NULL == (*ppSecret = (ubyte *) MALLOC(secretLen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    DIGI_MEMCPY(*ppSecret, secret, (sbyte4)secretLen);
    *pSecretLen = secretLen;

exit:
    return (sbyte4)status;
} /* IKE_SAMPLE_getToken */

#endif /* __ENABLE_DIGICERT_EAP_PEER__ */


/*------------------------------------------------------------------*/

static sbyte *identityString = NULL;

static int
IKE_EXAMPLE_EAP_PEER_getArgs(int argc, char *argv[])
{
    int i, j;
    int idSet = 0;
#ifdef __ENABLE_DIGICERT_EAP_PEER__
    int pwdSet = 0;
#endif

    for (i = 1; i < argc; ) /*Skiping argv[0] which is example progam name*/
    {
        if (DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--eap_identity") == 0)
        {
            idSet = 1; /*Identity should not be set to default*/
            i++;
            setParameter(&identityString, argv[i]);
            for (j=i-1; j<(argc-2); ++j)
                argv[j] = argv[j+2];
            argc -= 2;
            i--;
            continue;
        }
#ifdef __ENABLE_DIGICERT_EAP_PEER__
        else if (DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--eap_password") == 0)
        {
            pwdSet = 1; /*password should not be set to default*/
            i++;
            setParameter(&passwordString, argv[i]);
            for (j=i-1; j<(argc-2); ++j)
                argv[j] = argv[j+2];
            argc -= 2;
            i--;
            continue;
        }
#if (defined(__ENABLE_DIGICERT_EAP_TTLS__) || defined(__ENABLE_DIGICERT_EAP_TLS__))
        else if (DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--eap_server_commonname") == 0)
        {
            i++;
            setCertCommonName ((ubyte *) argv[i], DIGI_STRLEN ((sbyte *) argv[i]));
            for (j=i-1; j<(argc-2); ++j)
                argv[j] = argv[j+2];
            argc -= 2;
            i--;
            continue;
        }
#endif
#ifdef __ENABLE_DIGICERT_EAP_TTLS__
        else if (DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--eap_ttls_type") == 0)
        {
            i++;
            if (DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"pap") == 0)
            {
                m_ikeOptSettings.eapTtlsType = (sbyte4)EAP_METHOD_TYPE_PAP;
                m_bEapTtlsType = TRUE;
            }
            else if (DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"chap") == 0)
            {
                m_ikeOptSettings.eapTtlsType = (sbyte4)EAP_METHOD_TYPE_CHAP;
                m_bEapTtlsType = TRUE;
            }
            else if (DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"mschap") == 0)
            {
                m_ikeOptSettings.eapTtlsType = (sbyte4)EAP_METHOD_TYPE_MSCHAP;
                m_bEapTtlsType = TRUE;
            }
            else if (DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"mschapv2") == 0)
            {
                m_ikeOptSettings.eapTtlsType = (sbyte4)EAP_METHOD_TYPE_MSCHAPV2;
                m_bEapTtlsType = TRUE;
            }
            else if (DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"eap") == 0)
            {
                m_ikeOptSettings.eapTtlsType = (sbyte4)EAP_METHOD_TYPE_EAP;
                m_bEapTtlsType = TRUE;
            }
            else
            {
                fprintf(stderr, "IKE: Bad option value --eap_ttls_type %s\n", argv[i]);
            }
            for (j=i-1; j<(argc-2); ++j)
                argv[j] = argv[j+2];
            argc -= 2;
            i--;
            continue;
        }
#endif
#endif
        /* Nothing found */
        i++;
    }

    if (!idSet)
    {
        setParameter(&identityString, "user");
    }
#ifdef __ENABLE_DIGICERT_EAP_PEER__
    if (!pwdSet)
    {
        setParameter(&passwordString, "testing");
    }
#endif
    /*End of defaults*/
    return argc;
}


/*------------------------------------------------------------------*/

static sbyte4
IKE_EXAMPLE_getOptEapType(char *arg, sbyte4 auth)
{
    sbyte4 eap_t;

#ifdef __ENABLE_DIGICERT_EAP_LEAP__
    if (!strcmp(arg, "leap"))          eap_t = EAP_PROTO_LEAP;
    else
#endif
#ifdef __ENABLE_DIGICERT_EAP_MD5__
    if (!strcmp(arg, "md5"))           eap_t = EAP_PROTO_MD5;
    else
#endif
#ifdef __ENABLE_DIGICERT_EAP_MSCHAPv2__
    if (!strcmp(arg, "mschapv2"))      eap_t = EAP_PROTO_MSCHAPv2;
    else
#endif
#ifdef __ENABLE_DIGICERT_EAP_PSK__
    if (!strcmp(arg, "psk"))           eap_t = EAP_PROTO_PSK;
    else
#endif
#if defined(__ENABLE_DIGICERT_EAP_AUTH__) && defined(__ENABLE_DIGICERT_EAP_RADIUS__) && defined(__ENABLE_DIGICERT_RADIUS_CLIENT__)
    if (auth && !strcmp(arg, "radius"))eap_t = EAP_PROTO_RADIUS;
    else
#endif
#ifdef __ENABLE_DIGICERT_EAP_SIM__
    if (!strcmp(arg, "sim"))           eap_t = EAP_PROTO_SIM;
    else
    if (!strcmp(arg, "aka"))           eap_t = EAP_PROTO_AKA;
    else
#endif
#ifdef __ENABLE_DIGICERT_EAP_SRP__
    if (!strcmp(arg, "srp"))           eap_t = EAP_PROTO_SRP;
    else
#endif
#ifdef __ENABLE_DIGICERT_EAP_TLS__
    if (!strcmp(arg, "tls"))           eap_t = EAP_PROTO_TLS;
    else
#endif
#ifdef __ENABLE_DIGICERT_EAP_TTLS__
    if (!strcmp(arg, "ttls"))          eap_t = EAP_PROTO_TTLS;
    else
#endif
#ifdef __ENABLE_DIGICERT_EAP_GTC__
    if (!strcmp(arg, "gtc"))           eap_t = EAP_PROTO_GTC;
    else
#endif
#ifdef __ENABLE_DIGICERT_EAP_PEER__
    if (!auth && !strcmp(arg, "any"))  eap_t = EAP_PROTO_ANY;
    else
#endif
    eap_t = -1;

    return eap_t;
} /* IKE_EXAMPLE_getOptEapType */

#else

/*------------------------------------------------------------------*/

extern char *g_pIKECertFile;
extern char *g_pIKEHostKeyFile;
extern char *g_pIKERootFile;

static int
CA_MGMT_EXAMPLE_getArgs(int argc, char *argv[])
{
    int i, j;
    for (i = 1; i < argc; i++) /* Skiping argv[0] which is example progam name */
    {
        const sbyte *arg = (const sbyte *)argv[i];

        if (DIGI_STRCMP(arg, (const sbyte *)"--ike_cert") == 0)
        {
            for (j=i; j<(argc-1); ++j)
                argv[j] = argv[j+1];
            if (--argc == i) break;
            if ('-' == argv[i][0])
            {
                i--; continue;
            }
            g_pIKECertFile = argv[i];
            for (j=i; j<(argc-1); ++j)
                argv[j] = argv[j+1];
            argc--; i--;
        }
        else if (DIGI_STRCMP(arg, (const sbyte *)"--ike_keyblob") == 0)
        {
            for (j=i; j<(argc-1); ++j)
                argv[j] = argv[j+1];
            if (--argc == i) break;
            if ('-' == argv[i][0])
            {
                i--; continue;
            }
            g_pIKEHostKeyFile = argv[i];
            for (j=i; j<(argc-1); ++j)
                argv[j] = argv[j+1];
            argc--; i--;
        }
        else if (DIGI_STRCMP(arg, (const sbyte *)"--ike_ca_cert") == 0)
        {
            for (j=i; j<(argc-1); ++j)
                argv[j] = argv[j+1];
            if (--argc == i) break;
            if ('-' == argv[i][0])
            {
                i--; continue;
            }
            g_pIKERootFile = argv[i];
            for (j=i; j<(argc-1); ++j)
                argv[j] = argv[j+1];
            argc--; i--;
        }
#ifdef __ENABLE_DIGICERT_IKE_REF_IDENTIFIER_MATCH__
        else if (DIGI_STRCMP(arg, (const sbyte *)"--ike_peer_host") == 0)
        {
            for (j=i; j<(argc-1); ++j)
                argv[j] = argv[j+1];
            if (--argc == i) break;
            if ('-' == argv[i][0])
            {
                i--; continue;
            }
            m_peerHost= argv[i];
            for (j=i; j<(argc-1); ++j)
                argv[j] = argv[j+1];
            argc--; i--;
        }
#endif
#ifdef __ENABLE_DIGICERT_TAP__
#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
        else if (DIGI_STRCMP(arg, (const sbyte *)"--tap_server_name") == 0)
        {
            for (j=i; j<(argc-1); ++j)
                argv[j] = argv[j+1];
            if (--argc == i) break;
            if ('-' == argv[i][0])
            {
                i--; continue;
            }
            taps_ServerName = argv[i];
            for (j=i; j<(argc-1); ++j)
                argv[j] = argv[j+1];
            argc--; i--;
        }
        else if (DIGI_STRCMP(arg, (const sbyte *)"--tap_server_port") == 0)
        {
            for (j=i; j<(argc-1); ++j)
                argv[j] = argv[j+1];
            if (--argc == i) break;
            if ('-' == argv[i][0])
            {
                i--; continue;
            }
            taps_ServerPort = DIGI_ATOL((sbyte *)argv[i], NULL);
            for (j=i; j<(argc-1); ++j)
                argv[j] = argv[j+1];
            argc--; i--;
        }
#else
        else if (DIGI_STRCMP(arg, (const sbyte *)"--tap_config_file") == 0)
        {
            for (j=i; j<(argc-1); ++j)
                argv[j] = argv[j+1];
            if (--argc == i) break;
            if ('-' == argv[i][0])
            {
                i--; continue;
            }
            tap_ConfigFile = argv[i];
            for (j=i; j<(argc-1); ++j)
                argv[j] = argv[j+1];
            argc--; i--;
        }
#endif
#endif
    }

    return argc;
} /* CA_MGMT_EXAMPLE_getArgs */

#endif

#ifdef __ENABLE_IKE_PPK_RFC8784__

static char *iked_ppk_id = NULL;
static char *iked_ppk = NULL;
static intBoolean isHexPpk = FALSE;
static int
IKE_EXAMPLE_PPK_getArgs(int argc, char *argv[], int *pRetVal)
{
    int i, j;
    iked_ppk_id = iked_ppk = NULL;
    *pRetVal = 0;

    for (i = 1; i < argc; i++) /* Skiping argv[0] which is example progam name */
    {

        if (DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--ppk_id") == 0)
        {
            for (j=i; j<(argc-1); ++j)
                argv[j] = argv[j+1];
            if (--argc == i) break;
            if ('-' == argv[i][0])
            {
                i--; continue;
            }
            iked_ppk_id = argv[i];
            for (j=i; j<(argc-1); ++j)
                argv[j] = argv[j+1];
            argc--; i--;
        }
        else if (DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--ppk") == 0)
        {
            for (j=i; j<(argc-1); ++j)
                argv[j] = argv[j+1];
            if (--argc == i) break;
            if ('-' == argv[i][0])
            {
                i--; continue;
            }
            iked_ppk = argv[i];
            for (j=i; j<(argc-1); ++j)
                argv[j] = argv[j+1];
            argc--; i--;
        }
    }
    if(iked_ppk)
    {
        ubyte4 secretLen = DIGI_STRLEN((sbyte *) iked_ppk);

        /* handle hexadecimal string */
        if ((2 < secretLen) && ('0' == iked_ppk[0]) &&
                    (('x' == iked_ppk[1]) || ('X' == iked_ppk[1])))
        {
            isHexPpk = TRUE;
            for (i=2; i < (int) secretLen; i++) /* check valid hex-string */
            {
                sbyte s = iked_ppk[i];
                if (('0' <= s) && ('9' >= s)) continue;
                if (('A' <= s) && ('F' >= s)) continue;
                if (('a' <= s) && ('f' >= s)) continue;

                fprintf(stderr, "IKE: Bad option value --ppk %s\n", iked_ppk);
                isHexPpk = FALSE;
                *pRetVal = 1;
                break;
            }
            if (isHexPpk)
            {
                if (secretLen % 2) /* make it even length! */
                {
                    iked_ppk[1] = '0';
                    secretLen--;
                    iked_ppk++;
                }
                else
                {
                    secretLen -= 2;
                    iked_ppk += 2;
                }
            }
        }
    }
    return argc;
}

#endif


/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_EAP_AUTH__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)

static sbyte mEapIdentity[] = "user";
static sbyte mEapSecret[]   = "testing"; /* pragma: allowlist secret */
static ubyte4 mEapSecretLen = sizeof(mEapSecret) - 1;

#define EAP_SECRET_MAX 8

static struct eapSecret
{
    const ubyte *identity;
    ubyte4 identityLen;

    const ubyte *secret;
    ubyte4 secretLen;
    ubyte secretEx[256];

#ifdef __ENABLE_DIGICERT_EAP_GTC__
    ubyte shaHash[SHA1_RESULT_SIZE];
#endif
}
m_eapSecret[EAP_SECRET_MAX] = {{ NULL }};

static sbyte4 m_numEapSecret = 0;


/*------------------------------------------------------------------*/

static sbyte4
IKE_EXAMPLE_addEapSecret(sbyte *identity, intBoolean isHexSecret,
                         sbyte *secret, ubyte4 secretLen)
{
    MSTATUS status = OK;

    sbyte4 i, cmp;
    ubyte4 identityLen;
    struct eapSecret *es;

#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__) && \
    defined(__ENABLE_DIGICERT_EAP_GTC__)
    hwAccelDescr hwAccelCtx;
    if (OK > (status = (MSTATUS) HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_IKE, &hwAccelCtx)))
        goto abort;
#endif
    if (EAP_SECRET_MAX <= m_numEapSecret)
    {
        fprintf(stderr, "IKE: Ignore option value -A %s\n", identity);
        status = ERR_IKE;
        goto exit;
    }

    identityLen = DIGI_STRLEN(identity);

    for (i=0; i < m_numEapSecret; i++)
    {
        es = &m_eapSecret[i];
        if (identityLen != es->identityLen)
            continue;

        if (OK > (status = DIGI_MEMCMP(es->identity, (ubyte *) identity, identityLen, &cmp)))
            goto exit;

        if (cmp) continue;

        fprintf(stderr, "IKE: Ignore option value -A %s\n", identity);
        status = ERR_IKE;
        goto exit;
    }

    es = &m_eapSecret[m_numEapSecret];
    es->identity = (const ubyte *)identity;
    es->identityLen = identityLen;

    if (isHexSecret)
    {
        IKE_scanHexKey((sbyte4)secretLen, secret, sizeof(es->secretEx), es->secretEx);
        es->secret = es->secretEx;
        es->secretLen = secretLen / 2;
    }
    else
    {
        es->secret = (const ubyte *)secret;
        es->secretLen = secretLen;
    }

#ifdef __ENABLE_DIGICERT_EAP_GTC__
    if (OK > (status = SHA1_completeDigest(MOC_HASH(hwAccelCtx)
                                           es->secret, es->secretLen,
                                           es->shaHash)))
        goto exit;
#endif
    m_numEapSecret++;

exit:
#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__) && \
    defined(__ENABLE_DIGICERT_EAP_GTC__)
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_IKE, &hwAccelCtx);
abort:
#endif
    return (sbyte4)status;
} /* IKE_EXAMPLE_addEapSecrett */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_EAP_GTC__
static sbyte4
IKE_SAMPLE_verifyPassword(const ubyte *user, ubyte4 userLen,
                          const ubyte *password, ubyte4 passwordLen,
                          sbyte4 serverInstance)
{
    MSTATUS status = OK;

    sbyte4 i, cmp;
    ubyte hash[SHA1_RESULT_SIZE];

#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    hwAccelDescr hwAccelCtx;
    if (OK > (status = (MSTATUS) HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_IKE, &hwAccelCtx)))
        goto abort;
#endif
    MOC_UNUSED(serverInstance);

    for (i=0; i < m_numEapSecret; i++)
    {
        if (userLen != m_eapSecret[i].identityLen)
            continue;

        if (OK > (status = DIGI_MEMCMP(m_eapSecret[i].identity, user, userLen, &cmp)))
            goto exit;

        if (cmp) continue;

        if (OK > (status = SHA1_completeDigest(MOC_HASH(hwAccelCtx)
                                               password, passwordLen,
                                               hash)))
            goto exit;

        if (OK > (status = DIGI_MEMCMP(m_eapSecret[i].shaHash, hash,
                                      SHA1_RESULT_SIZE, &cmp)))
            goto exit;

        if (!cmp) goto exit; /* match */
        break;
    }

    status = ERR_IKE; /* no match!!! */

exit:
#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_IKE, &hwAccelCtx);
abort:
#endif
    return (sbyte4)status;
} /* IKE_SAMPLE_verifyPassword */
#endif


/*------------------------------------------------------------------*/

static sbyte4
IKE_SAMPLE_findSecret(const ubyte *identity, ubyte4 identityLen,
                      ubyte **secret, ubyte4 *secretLen,
                      sbyte4 serverInstance)
{
    MSTATUS status = OK;

    sbyte4 i, cmp;
    MOC_UNUSED(serverInstance);

    if (NULL == secret || NULL == secretLen)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    for (i=0; i < m_numEapSecret; i++)
    {
        if (identityLen != m_eapSecret[i].identityLen)
            continue;

        if (OK > (status = DIGI_MEMCMP(m_eapSecret[i].identity,
                                      identity, identityLen, &cmp)))
            goto exit;

        if (cmp) continue;

        *secret = (ubyte*)m_eapSecret[i].secret;
        *secretLen = m_eapSecret[i].secretLen;
        goto exit; /* found */
    }

    status = ERR_IKE; /* not found!!! */

exit:
    return (sbyte4)status;
} /* IKE_SAMPLE_findSecret */


/*------------------------------------------------------------------*/

#endif /* defined(__ENABLE_DIGICERT_EAP_AUTH__) && !defined(__DISABLE_DIGICERT_IKE_EAP__) */


/*------------------------------------------------------------------*/

static void
IKE_EXAMPLE_displayHelp(char *prog)
{
    printf("Usage: %s <option>* <ipaddr>*\n\n", prog);

    printf("  option:\n");
    printf("    -c <ipaddr>     initiates connection\n");
    printf("    -d [mins]       sets or shows DPD interval (in minutes)\n");
#ifdef __ENABLE_IKE_AGGRESSIVE_MODE__
    printf("    -m [mode]       sets or shows phase 1 exchange mode (v1)\n");
#endif
    printf("    -n [secs]       sets or shows negotiation timeout (in seconds)\n");
    printf("    -p <key>        sets pre-shared key\n");
    printf("    -v [num]        sets or shows IKE version\n");
    printf("\n");

    printf("    -g {dh|0}       sets DH group; 0=default\n");
    printf("    -G {dh|0|-1}    sets PFS; 0=no PFS, -1=parent DH group\n");
    printf("    -l [secs]       sets or shows IKE_SA lifetime seconds\n");
    printf("    -L [secs]       sets or shows IPsec SA lifetime seconds\n");
#ifdef __ENABLE_IPSEC_MARGIN_LIFETIME__
    printf("    -M [secs]       sets IPsec SA margin lifetime seconds\n");
#endif
    printf("\n");

#if (defined(__ENABLE_DIGICERT_EAP_AUTH__) || defined(__ENABLE_DIGICERT_EAP_PEER__)) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
#ifdef __ENABLE_DIGICERT_EAP_AUTH__
    printf("    -a <eap>        sets EAP Authenticator protocol (v2)\n"
           "    -A <id>:<key> + sets EAP Authenticator user credentials (v2)\n"
           "                    (either <id> or <key> may be omitted)\n");
#endif
#ifdef __ENABLE_IKE_EAP_ONLY__
    printf("    -e              enables EAP-Only authentication (v2)\n");
#endif
    printf("    --eap_identity  sets EAP identity (v2)\n");
#ifdef __ENABLE_DIGICERT_EAP_PEER__
    printf("    --eap_password  sets EAP Supplicant secret (v2)\n"
           "    -s <eap>        sets EAP Supplicant protocol (v2)\n");
#endif
#else
    printf("    --ike_cert <file>        sets the host certificate (default: %s.der)\n",
#ifdef __ENABLE_DIGICERT_ECC__
           "ecdsa"
#else
           "rsa"
#endif
           );
    printf("    --ike_keyblob <file>     sets its private keyblob  (defulat: %s.dat)\n",
#ifdef __ENABLE_DIGICERT_ECC__
           "ecdsakey"
#else
           "rsakey"
#endif
           );
    printf("    --ike_ca_cert <file>     sets the CA certificate   (default: ca.der)\n");
#ifdef __ENABLE_DIGICERT_TAP__
#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
    printf("    --tap_server_name <TAP Server Name> sets the address of the TAP Server service\n");
    printf("    --tap_server_port <Port number> sets the port number on which TAP Server is listening (default: 8277)\n");
#else
    printf("    --tap_config_file <file> sets the TAP config file  (default: "
           TPM2_CONFIGURATION_FILE ")\n");
#endif
#endif
#endif
    printf("\n");

#ifdef __ENABLE_IKE_PPK_RFC8784__
    printf("    --ppk <ppk preshared key>  sets the Post Quantum Preshared key \n");
    printf("    --ppk_id <ppk id>  sets the Post Quantum Preshared key identifier \n");
#endif

#if defined(__ENABLE_IKE_MODE_CFG__) || defined(__ENABLE_IKE_CP__)
    printf("    -k <agent>      enables configuration (v1 MODE-CFG or v2 CP)\n");
#endif
#ifdef __ENABLE_IKE_MODE_CFG__
    printf("    -K {1...4}      sets MODE-CFG mode (v1); 1=PULL (default), 2=PUSH,\n"
           "                                             3=PULL* (server initiates QM)\n"
           "                                             4=PUSH* (client initiates QM)\n");
#endif
#ifdef __ENABLE_IKE_REDIRECT__
    printf("    -r <ipaddr>     sets redirect gateway address.\n");
#endif
#ifdef __IKE_MULTI_THREADED__
    printf("    -t <num>        sets # of threads.\n");
#endif
#ifdef __ENABLE_IKE_XAUTH__
    printf("    -x <usr>:<pwd>  acts as XAUTH client (v1)\n");
#ifdef __ENABLE_IKE_MODE_CFG__
    printf("                         or XAUTH server if -k Server is specified.\n");
#endif
#ifdef __ENABLE_IKE_HYBRID_RSA__
    printf("    -y              enables Hybrid-RSA (v1) if -x is specified.\n");
#endif
#endif
#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
    printf("    -z <ipaddr>     sets GDOI (v1) key server address.\n");
#endif

#if defined(__ENABLE_IKE_MODE_CFG__) || defined(__ENABLE_IKE_CP__) || \
    defined(__ENABLE_IKE_REDIRECT__) || \
    defined(__IKE_MULTI_THREADED__) || \
    defined(__ENABLE_IKE_XAUTH__) || \
    defined(__ENABLE_DIGICERT_GDOI_CLIENT__)
    printf("\n");
#endif

    printf("    -E <port>       overrides event port (default: %d); use different\n"
           "                    ports when running two instances on the same host\n",
           IKE_EVENT_PORT);
    printf("    -h              displays this help\n");
#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
    printf("    -o              sets debug console output\n");
#endif
    printf("    -w <secs>       sets socket wait time (in seconds)\n");
#ifdef __IKE_TRACK__
    printf("    -u              enables use of IKE_msgRecvEx1/IKE2_msgRecvEx1 instead of IKE_msgRecv/IKE2_msgRecv function\n");
#endif
    printf("\n");

#if defined(__ENABLE_IKE_MODE_CFG__) || defined(__ENABLE_IKE_CP__)
    printf("  agent: { client | server | c | s | C | S }\n");
#endif
    printf("  dh:   { 1 | 2 | 5 | 14 | 15 | 16 | 17 | 18%s%s%s | 24%s%s%s%s }\n",
#if defined(__ENABLE_DIGICERT_ECC__) && !defined(__DISABLE_DIGICERT_ECC_P256__)
           " | 19",
#else
           "",
#endif
#if defined(__ENABLE_DIGICERT_ECC__) && !defined(__DISABLE_DIGICERT_ECC_P384__)
           " | 20",
#else
           "",
#endif
#if defined(__ENABLE_DIGICERT_ECC__) && !defined(__DISABLE_DIGICERT_ECC_P521__)
           " | 21",
#else
           "",
#endif
#if defined(__ENABLE_DIGICERT_ECC__) && defined(__ENABLE_DIGICERT_ECC_P192__)
           " | 25",
#else
           "",
#endif
#if defined(__ENABLE_DIGICERT_ECC__) && !defined(__DISABLE_DIGICERT_ECC_P224__)
           " | 26",
#else
           "",
#endif
#if defined(__ENABLE_DIGICERT_ECC__) && defined(__ENABLE_DIGICERT_ECC_EDDH_25519__)
           " | 31",
#else
           "",
#endif
#if defined(__ENABLE_DIGICERT_ECC__) && defined(__ENABLE_DIGICERT_ECC_EDDH_448__)
           " | 32"
#else
           ""
#endif
           );
#if (defined(__ENABLE_DIGICERT_EAP_AUTH__) || defined(__ENABLE_DIGICERT_EAP_PEER__)) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
    printf("  eap:  { aka | gtc | leap | md5 | mschapv2 | psk | radius | sim | srp | tls | ttls }\n");
#endif
    printf("  key:  { <ascii string> | 0x<hexadecimal digits> }\n");
#ifdef __ENABLE_IKE_AGGRESSIVE_MODE__
    printf("  mode: { main | aggressive | m | a | M | A }\n");
#endif

#ifdef __ENABLE_DIGICERT_MISSIU__
    printf("    -i <iface>\n"
           "       network interface on which missiu is running.\n"
           "       if only one instance is running, this option\n"
           "       may be omitted.\n");
#endif

    printf("\n");
    return;
} /* IKE_EXAMPLE_displayHelp */


/*------------------------------------------------------------------*/

#if defined(__DISABLE_DIGICERT_MAIN_FUNC_ENTRY__) && defined(__PLATFORM_HAS_GETOPT__)
#undef __PLATFORM_HAS_GETOPT__
#endif

extern sbyte4
IKE_EXAMPLE_getArgs(int argc, char *argv[])
{
    sbyte4 status = 0;

    int i;

#ifndef __PLATFORM_HAS_GETOPT__
    int optind = 1;
    int optopt;
    char *optarg;
#else
    extern int optind;
    extern int optopt;
    extern char *optarg;
#endif

    int c;

#if (defined(__ENABLE_DIGICERT_EAP_AUTH__) || defined(__ENABLE_DIGICERT_EAP_PEER__)) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
    IKE_CERT_UTILS_getArgs(argc,argv);
#else
    argc = CA_MGMT_EXAMPLE_getArgs(argc,argv);
#endif
#if defined(__ENABLE_DIGICERT_EAP_PEER__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
    argc = IKE_EXAMPLE_EAP_PEER_getArgs(argc,argv);
#endif
#if defined(__ENABLE_DIGICERT_EAP_AUTH__) && defined(__ENABLE_DIGICERT_EAP_RADIUS__) && defined(__ENABLE_DIGICERT_RADIUS_CLIENT__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
    argc = IKE_EXAMPLE_EAP_RADIUS_getArgs(argc,argv);
#endif
#ifdef __ENABLE_IKE_PPK_RFC8784__
    int retVal = 0;
    argc = IKE_EXAMPLE_PPK_getArgs(argc, argv, &retVal);
    if(retVal)
    {
        IKE_EXAMPLE_displayHelp(argv[0]);
        return -1;
    }
#endif
    if ((2 <= argc) && ('?' == argv[1][0]))
    {
        IKE_EXAMPLE_displayHelp(argv[0]);
        return -1;
    }

#if (defined __ENABLE_DIGICERT_TAP__) && (defined __ENABLE_DIGICERT_TAP_REMOTE__)
    if (NULL == taps_ServerName)
    {
        printf("Error: TAP server name must be specified in Remote mode. Use --tap_server_name option\n");
        IKE_EXAMPLE_displayHelp(argv[0]);
        return -1;
    }
#endif
    ZERO_MOC_IPADDR(mPeerAddr);

#ifndef __PLATFORM_HAS_GETOPT__
    for (; optind < argc; optind++)
    {
        int optarg_len;

        optarg = argv[optind];
        optarg_len = strlen(optarg);

        if ((0 >= optarg_len) || ('-' != optarg[0]))
            break;

        if ((1 >= optarg_len) || ('-' == (c = optarg[1])))
        {
            optind++;
            break;
        }

        optopt = c;
        optarg += 2;
        optarg_len -= 2;

        switch (c)
        {
        case 'h':
            if (0 < optarg_len)
            {
                fprintf(stderr, "IKE: Option -%c operand is ignored.\n", optopt);
            }
            break;

        case 'a':
        case 'A':
        case 'c':
        case 'd':
        case 'E':
        case 'g':
        case 'G':
        case 'i':
        case 'k':
        case 'K':
        case 'l':
        case 'L':
        case 'm':
        case 'M':
        case 'n':
        case 'p':
        case 'P':
        case 'r':
        case 's':
        case 't':
        case 'v':
        case 'w':
        case 'x':
        case 'z':
            if (0 >= optarg_len)
            {
                if (((1 + optind) >= argc) ||
                    (('-' == argv[optind + 1][0]) &&
                     isalpha(argv[optind + 1][1])))
                {
                    c = ':';
                }
                else
                {
                    optind++;
                    optarg = argv[optind];
                }
            }
            break;
/*
        case 'e':
        case 'h':
        case 'y':
*/

#ifdef __IKE_TRACK__
        case 'u':
            m_useMsgRecv = 0;
            printf("Using IKE_msgRecvEx1/IKE2_msgRecvEx1 in place of IKE_msgRecv/IKE2_msgRecv\n");
            break;
#endif
        default :
            break;
        }
#else
#ifdef __IKE_TRACK__
    while ((c = getopt(argc, argv, "a:A:c:d:eE:g:G:hi:k:K:l:L:m:M:n:op:P:r:s:t:v:w:u:x:yz:")) != -1)
#else
    while ((c = getopt(argc, argv, "a:A:c:d:eE:g:G:hi:k:K:l:L:m:M:n:op:P:r:s:t:v:w:x:yz:")) != -1)
#endif
    {
#endif
        switch (c)
        {
        case 'a': /* set EAP authenticator protocol */
        {
#if defined(__ENABLE_DIGICERT_EAP_AUTH__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
            sbyte4 eap_auth_t = IKE_EXAMPLE_getOptEapType(optarg, TRUE);
            if ((0 >= eap_auth_t) || ((sbyte4)EAP_PROTO_ANY == eap_auth_t))
                fprintf(stderr, "IKE: Bad option value -a %s (unsupported)\n", optarg);
            else if (TRUE == m_bEapProtoAuth)
                fprintf(stderr, "IKE: Ignore option value -a %s\n", optarg);
            else
            {
                m_ikeOptSettings.eapProtoAuth = eap_auth_t;
                m_bEapProtoAuth = TRUE;
            }
#else
            fprintf(stderr, "IKE: Bad option -a (disabled)\n");
#endif
            break;
        }

        case 'A':
        {
#if defined(__ENABLE_DIGICERT_EAP_AUTH__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
            sbyte *secret = (sbyte *) strchr(optarg, ':');
            if (secret)
            {
                ubyte4 secretLen = DIGI_STRLEN(secret) - 1;
                intBoolean isHexSecret = FALSE;
                *secret++ = 0;

                if (!optarg[0] && !secret[0]) /* sanity-check */
                {
                    fprintf(stderr, "IKE: Bad option value -A :\n");
                    break;
                }

                /* handle hexadecimal string */
                if ((2 < secretLen) && ('0' == secret[0]) &&
                    (('x' == secret[1]) || ('X' == secret[1])))
                {
                    isHexSecret = TRUE;
                    for (i=2; i < (int) secretLen; i++) /* check valid hex-string */
                    {
                        sbyte s = secret[i];
                        if (('0' <= s) && ('9' >= s)) continue;
                        if (('A' <= s) && ('F' >= s)) continue;
                        if (('a' <= s) && ('f' >= s)) continue;

                        fprintf(stderr, "IKE: Bad option value -A %s:%s\n", optarg, secret);
                        isHexSecret = FALSE;
                        break;
                    }
                    if (isHexSecret)
                    {
                        if (secretLen % 2) /* make it even length! */
                        {
                            secret[1] = '0';
                            secretLen--;
                            secret++;
                        }
                        else
                        {
                            secretLen -= 2;
                            secret += 2;
                        }
                    }
                }

                if (secretLen)
                {
                    IKE_EXAMPLE_addEapSecret(*optarg ? (sbyte *)optarg : mEapIdentity,
                                             isHexSecret, secret, secretLen);
                    break;
                }
            }

#ifdef __ENABLE_DIGICERT_EAP_SIM__
            if (EAP_PROTO_SIM == m_ikeOptSettings.eapProtoAuth)
            {
                IKE_EXAMPLE_addEapSecret((sbyte *)optarg, FALSE,
                             (sbyte *)eapSimTriplets, sizeof(eapSimTriplets));
            }
            else if (EAP_PROTO_AKA == m_ikeOptSettings.eapProtoAuth)
            {
                IKE_EXAMPLE_addEapSecret((sbyte *)optarg, FALSE,
                                 (sbyte *)eapAkaVector, sizeof(eapAkaVector));
            }
            else
#endif
            IKE_EXAMPLE_addEapSecret((sbyte *)optarg, FALSE, mEapSecret, mEapSecretLen);
#else
            fprintf(stderr, "IKE: Bad option -A (disabled)\n");
#endif
            break;
        }

        case 's': /* set EAP supplicant protocol */
        {
#if defined(__ENABLE_DIGICERT_EAP_PEER__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
            sbyte4 eap_peer_t = IKE_EXAMPLE_getOptEapType(optarg, FALSE);
            if ((0 >= eap_peer_t) || ((sbyte4)EAP_PROTO_RADIUS == eap_peer_t))
                fprintf(stderr, "IKE: Bad option value -s %s (unsupported)\n", optarg);
            else if (TRUE == m_bEapProtoPeer)
                fprintf(stderr, "IKE: Ignore option value -s %s\n", optarg);
            else
            {
                m_ikeOptSettings.eapProtoPeer = eap_peer_t;
                m_bEapProtoPeer = TRUE;

                if (2 != m_ikeOptSettings.ikeVersion)
                {
                    fprintf(stderr, "IKE: Set option value -v 2 (required by -s)\n");
                    m_ikeOptSettings.ikeVersion = 2;
                    m_bIkeVersion = TRUE;
                }
            }
#else
            fprintf(stderr, "IKE: Bad option -s (disabled)\n");
#endif
            break;
        }

        case 'E': /* override IKE event port (loopback UDP, default 13579) */
        {
            int port = atoi(optarg);
            if (port <= 0 || port > 65535)
            {
                fprintf(stderr, "IKE: Bad option value -E %s (must be 1-65535)\n", optarg);
                break;
            }
            g_ikeEventPort = (ubyte2)port;
            break;
        }

        case 'e': /* enables EAP-Only authentication */
#if (defined(__ENABLE_DIGICERT_EAP_AUTH__) || defined(__ENABLE_DIGICERT_EAP_PEER__)) && !defined(__DISABLE_DIGICERT_IKE_EAP__) && \
    defined(__ENABLE_IKE_EAP_ONLY__)
            m_bDoEapOnly = TRUE;
#else
            fprintf(stderr, "IKE: Bad option -e (disabled)\n");
#endif
            break;

        case 'c': /* initiates connection */
        {
            /* get peer IP address */
            ubyte4 dwPeerAddr = (ubyte4) inet_addr(optarg);
            if (((ubyte4)-1) != dwPeerAddr)
            {
                /* IPv4 address */
                if (dwPeerAddr)
                {
                    SET_MOC_IPADDR4(mPeerAddr, GET_NTOHL(dwPeerAddr));
                }
            }
            else
            {
#ifdef __ENABLE_DIGICERT_IPV6__
                /* IPv6 address */
#if defined(__LINUX_RTOS__)
                ubyte addr6[16];
                if (0 < inet_pton(AF_INET6, optarg, addr6))
                {
                    SET_MOC_IPADDR6(mPeerAddr, addr6);
                }
                else
#endif
#endif
                /* symbolic name (e.g. DNS) */
                UDP_getAddrOfHost((sbyte *)optarg, &mPeerAddr);
            }
            break;
        }

        case 'd': /* set DPD interval (in mins) */
        {
            sbyte4 ikeTimeoutDpd = strtol(optarg, NULL, 0);
            if (0 > ikeTimeoutDpd)
            {
                fprintf(stderr, "IKE: Bad option value -d %s (invalid)\n", optarg);
                break;
            }
            m_ikeOptSettings.ikeTimeoutDpd = (ubyte4)(ikeTimeoutDpd * 60); /* secs */
            m_bIkeTimeoutDpd = TRUE;
            break;
        }
        case 'g': /* set default DH group for [v1] phase 1 or [v2] IKE_SA_INIT */
            m_ikeOptSettings.ikeP1DHgroup = (ubyte2) strtol(optarg, NULL, 0);
            m_bIkeP1DHgroup = TRUE;
            if((OAKLEY_GROUP_ED25519 == m_ikeOptSettings.ikeP1DHgroup) ||
                    (OAKLEY_GROUP_ED448 == m_ikeOptSettings.ikeP1DHgroup))
            {
                if (2 != m_ikeOptSettings.ikeVersion)
                {
                    fprintf(stderr, "IKE: Set option value -v 2 (required by -g)\n");
                    m_ikeOptSettings.ikeVersion = 2;
                    m_bIkeVersion = TRUE;
                }
            }
            break;

        case 'G': /* set PFS; 0=no PFS */
        {
            int grp = strtol(optarg, NULL, 0);
            m_ikeOptSettings.ikeP2PFS = (grp != -1) ? (ubyte2)grp : OAKLEY_GROUP_DEFAULT;
            m_bIkeP2PFS = TRUE;
            break;
        }

        case 'h':
            IKE_EXAMPLE_displayHelp(argv[0]);
            break;

        case 'i':
        {
#if defined(__ENABLE_DIGICERT_MISSIU__)
            IPSEC_setInterface(optarg);
#else
            fprintf(stderr, "IKE: Bad option -i (disabled)\n");
#endif
            break;
        }
        case 'k': /* enables configuration (v1 MODE-CFG or v2 CP); 1=client, 2=server */
        {
#if defined(__ENABLE_IKE_MODE_CFG__) || defined(__ENABLE_IKE_CP__)
            int a = optarg[0];
            if (('c' == a) || ('C' == a))
            {
                m_vpnAgent = 1;
            }
            else if (('s' == a) || ('S' == a))
            {
                m_vpnAgent = 2;
#ifdef __ENABLE_IKE_MODE_CFG__
                m_bInitQM = FALSE; /* !!! */
#ifdef __ENABLE_IKE_XAUTH__
                if (m_bXauthType) m_ikeOptSettings.xauthType = (ubyte)2;
#endif
#endif
            }
            else
            {
                fprintf(stderr, "IKE: Bad option value -k %s \n", optarg);
            }
#else
            fprintf(stderr, "IKE: Bad option -k (disabled)\n");
#endif
            break;
        }
        case 'K': /* sets MODE-CFG mode; 1=PULL, 2=PUSH */
#ifdef __ENABLE_IKE_MODE_CFG__
            if ((1 != m_vpnAgent) && (2 != m_vpnAgent))
            {
                fprintf(stderr, "IKE: Must specify -k option before -K\n");
                break;
            }
            switch (strtol(optarg, NULL, 0))
            {
            case 1 : m_bPullCfg = TRUE;  m_bInitQM = ((1==m_vpnAgent)?TRUE:FALSE); break;
            case 2 : m_bPullCfg = FALSE; m_bInitQM = ((1==m_vpnAgent)?FALSE:TRUE); break;
            case 3 : m_bPullCfg = TRUE;  m_bInitQM = ((1==m_vpnAgent)?FALSE:TRUE); break;
            case 4 : m_bPullCfg = FALSE; m_bInitQM = ((1==m_vpnAgent)?TRUE:FALSE); break;
            default :
                fprintf(stderr, "IKE: Bad option value -K %s\n", optarg);
                break;
            }
#else
            fprintf(stderr, "IKE: Bad option -K (disabled)\n");
#endif
            break;
        case 'l': /* set IKE_SA lifetime seconds */
            m_ikeOptSettings.ikeP1LifeSecs = strtol(optarg, NULL, 0);
            m_bIkeP1LifeSecs = TRUE;

            m_ikeOptSettings.ikeP1LifeSecsMax = m_ikeOptSettings.ikeP1LifeSecs;
            m_bIkeP1LifeSecsMax = TRUE; /* FOR NOW */
            break;

        case 'L': /* set IPsec SA lifetime seconds */
            m_ikeOptSettings.ikeP2LifeSecs = strtol(optarg, NULL, 0);
            m_bIkeP2LifeSecs = TRUE;

            m_ikeOptSettings.ikeP2LifeSecsMax = m_ikeOptSettings.ikeP2LifeSecs;
            m_bIkeP2LifeSecsMax = TRUE; /* FOR NOW */
            break;

        case 'm': /* set phase 1 mode (IKEv1) */
        {
#ifdef __ENABLE_IKE_AGGRESSIVE_MODE__
            int m = optarg[0];
            if (('M' == m) || ('m' == m))
            {
                m_ikeOptSettings.ikeP1Mode = 2; /* 2=main */;
                m_bIkeP1Mode = TRUE;
            }
            else if (('A' == m) || ('a' == m))
            {
                m_ikeOptSettings.ikeP1Mode = 4; /* 4=aggressive */;
                m_bIkeP1Mode = TRUE;
            }
            else fprintf(stderr, "IKE: Bad option value -m %s\n", optarg);
#else
            fprintf(stderr, "IKE: Bad option -m (disabled)\n");
#endif
            break;
        }
#ifdef __ENABLE_IPSEC_MARGIN_LIFETIME__
        /*  This fixes the issue where quick mode RESPONDER-LIFETIME notification is not
            accepted by MS Windows 10. We add a margin lifetime to the already configured
            IPsec SA lifetime if the initiator's proposed lifetime is > responder's configured
            lifetime. How much this margin lifetime should be is at the user's discretion.
        */
        case 'M': /* set Phase 2 margin lifetime seconds */
            g_IkeP2MarginLifeSecs = strtol(optarg, NULL, 0);
            break;
#else
        fprintf(stderr, "IKE: Bad option -M (disabled)\n");
#endif

        case 'n': /* set negotiation timeout (in secs) */
        {
            sbyte4 ikeTimeoutNegotiation = strtol(optarg, NULL, 0);
            if ((5 > ikeTimeoutNegotiation) || (300 < ikeTimeoutNegotiation)) /* FOR NOW */
            {
                fprintf(stderr, "IKE: Bad option value -n %s\n", optarg);
                break;
            }
            m_ikeOptSettings.ikeTimeoutNegotiation = (ubyte4)ikeTimeoutNegotiation;
            m_bIkeTimeoutNegotiation = TRUE;
            break;
        }
        case 'o':
#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
            DEBUG_CONSOLE_setOutput(IKE_OUTPUT_FILE);
#else
            fprintf(stderr, "IKE: Bad option -o (disabled)\n");
#endif
            break;

#if !defined(__PARAGON__)
        case 'P':
#endif
        case 'p': /* set pre-shared key */
        {
            int psklen = strlen((char *)optarg);

            if ((2 < psklen) && ('0' == optarg[0]) &&
                (('x' == optarg[1]) || ('X' == optarg[1])))
            {
                mIsHexPSK = TRUE;
                mPSK = (sbyte *)(optarg + 2);
                mPSKlen = psklen - 2;
                psklen = (psklen - 1) / 2;
            }
            else
            {
                mIsHexPSK = FALSE;
                mPSK = (sbyte *)optarg;
                mPSKlen = psklen;
            }

#if !defined(__PARAGON__)
            if ((0 < psklen) && ('p' == c))
            {
                mComputeHostKeys = FALSE; /* no host certificate */
            }
#endif

            DEBUG_PRINT(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_EXAMPLE: Preshared key is set (");
            if (IKE_PSK_MAX < psklen)
            {
                psklen = IKE_PSK_MAX;
                mPSKlen = mIsHexPSK ? (2 * IKE_PSK_MAX) : IKE_PSK_MAX;
                DEBUG_PRINTNL(DEBUG_IKE_EXAMPLE, (sbyte *)"truncated ");
            }
            DEBUG_INT(DEBUG_IKE_EXAMPLE, psklen);
            DEBUG_PRINTNL(DEBUG_IKE_EXAMPLE, (sbyte *)" bytes)");
            break;
        }
        case 'r': /* set redirect gateway */
        {
#ifdef __ENABLE_IKE_REDIRECT__
            /* get peer IP address */
            ubyte4 dwRedirectAddr = (ubyte4) inet_addr(optarg);
            if (((ubyte4)-1) != dwRedirectAddr)
            {
                /* IPv4 address */
                if (dwRedirectAddr)
                {
                    SET_MOC_IPADDR4(m_ikeOptSettings.redirectGwAddr, GET_NTOHL(dwRedirectAddr));
                }
            }
            else
            {
#ifdef __ENABLE_DIGICERT_IPV6__
                /* IPv6 address */
#if defined(__LINUX_RTOS__)
                ubyte addr6[16];
                if (0 < inet_pton(AF_INET6, optarg, addr6))
                {
                    SET_MOC_IPADDR6(m_ikeOptSettings.redirectGwAddr, addr6);
                }
                else
#endif
#endif
                /* symbolic name (e.g. DNS) */
                UDP_getAddrOfHost((sbyte *)optarg, &m_ikeOptSettings.redirectGwAddr);
            }
            m_redirectGwAddr = TRUE;
#else
            fprintf(stderr, "IKE: Bad option -r (disabled)\n");
#endif
            break;
        }
        case 't':
        {
#ifdef __IKE_MULTI_THREADED__
            m_threadNum = strtol(optarg, NULL, 0);
            if ((2 > m_threadNum) || (IKE_THREAD_MAX < m_threadNum))
            {
                fprintf(stderr, "IKE: Bad option value -t %s (invalid or too large)\n", optarg);
                m_threadNum = 10;
            }
#else
            fprintf(stderr, "IKE: Bad option -t (disabled)\n");
#endif
            break;
        }
        case 'v': /* set version (1 or 2) */
        {
            int version = strtol(optarg, NULL, 0);
            if (m_bIkeVersion) /* already set */
            {
                if (version != m_ikeOptSettings.ikeVersion)
                    fprintf(stderr, "IKE: Ignore option value -v %s\n", optarg);
            }
            else if ((2 == version) || (1 == version))
            {
                m_ikeOptSettings.ikeVersion = (ubyte)version;
                m_bIkeVersion = TRUE;
            }
            else fprintf(stderr, "IKE: Bad option value -v %s\n", optarg);
            break;
        }

        case 'w': /* set socket listen timeout (in secs) */
            msTimeout = strtol(optarg, NULL, 0);
            if ((0==msTimeout) || (60<(ubyte4)msTimeout))
            {
                fprintf(stderr, "IKE: Bad option value -w %s (invalid or too large)\n", optarg);
                msTimeout = 4;
            }
            msTimeout *= 1000; /* ms */
            break;

        case 'x':
#ifdef __ENABLE_IKE_XAUTH__
            if (NULL != (m_Xpassword = (sbyte *)strchr(optarg, ':')))
            {
                m_XuserName = (sbyte *)optarg;
                *m_Xpassword = 0;
                m_Xpassword++;

                m_bXauthType = TRUE;
#if defined(__ENABLE_IKE_MODE_CFG__) || defined(__ENABLE_IKE_CP__)
                if (2 == m_vpnAgent) /* server */
                    m_ikeOptSettings.xauthType = (ubyte)2;
                else
#endif
                    m_ikeOptSettings.xauthType = (ubyte)1;
            }
            else
            {
                fprintf(stderr, "IKE: Bad option value -x %s\n", optarg);
            }
#else
            fprintf(stderr, "IKE: Bad option -x (disabled)\n");
#endif
            break;

        case 'y':
#if defined(__ENABLE_IKE_XAUTH__) && defined(__ENABLE_IKE_HYBRID_RSA__)
            m_bHybrid = TRUE;
            m_ikeOptSettings.bDoHybrid = TRUE;
#else
            fprintf(stderr, "IKE: Bad option -y (disabled)\n");
#endif
            break;

        case 'z': /* set GDOI (v1) key server address */
        {
#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
            /* get peer IP address */
            ubyte4 dwKsAddr = (ubyte4) inet_addr(optarg);
            if (((ubyte4)-1) != dwKsAddr)
            {
                /* IPv4 address */
                if (dwKsAddr)
                {
                    SET_MOC_IPADDR4(m_ikeOptSettings.keyServerAddr, GET_NTOHL(dwKsAddr));
                }
            }
            else
            {
#ifdef __ENABLE_DIGICERT_IPV6__
                /* IPv6 address */
#if defined(__LINUX_RTOS__)
                ubyte addr6[16];
                if (0 < inet_pton(AF_INET6, optarg, addr6))
                {
                    SET_MOC_IPADDR6(m_ikeOptSettings.keyServerAddr, addr6);
                }
                else
#endif
#endif
                /* symbolic name (e.g. DNS) */
                UDP_getAddrOfHost((sbyte *)optarg, &m_ikeOptSettings.keyServerAddr);
            }
            m_bKeyServerAddr = TRUE;
#else
            fprintf(stderr, "IKE: Bad option -z (disabled)\n");
#endif
            break;
        }
        case ':': /* without operand */
            switch (optopt)
            {
            case 'd' :
                printf("DPD interval: %d minutes\n", TIMEOUT_IKE_DPD / 60);
                break;
            case 'l' :
                printf("IKE_SA lifetime: %d~%d seconds\n",
                       ISAKMP_SA_LIFE_SECS, ISAKMP_SA_LIFE_SECS_MAX);
                break;
            case 'L' :
                printf("IPsec SA lifetime: %d~%d seconds\n",
                       IPSEC_SA_LIFE_SECS, IPSEC_SA_LIFE_SECS_MAX);
                break;
            case 'm' :
                printf("Phase 1 exchange mode: %s\n",
#ifdef __ENABLE_IKE_AGGRESSIVE_MODE__
                       (IKE_P1_MODE==4) ? "Aggressive" :
#endif
                                          "Main");
                break;
            case 'n' :
                printf("Negotiation timeout: %d seconds\n", TIMEOUT_IKE_NEGOTIATION);
                break;
            case 'v' :
                printf("Verion: %d\n", MOC_IKE_VERSION);
                break;
#ifdef __ENABLE_IKE_XAUTH__
            case 'x':
                printf("XAUTH: defaut user=\"%s\" pwd=\"%s\"\n",
                       m_XuserName, m_Xpassword);
#if defined(__ENABLE_IKE_MODE_CFG__) || defined(__ENABLE_IKE_CP__)
                if (2 == m_vpnAgent) /* server */
                    m_ikeOptSettings.xauthType = (ubyte)2;
                else
#endif
                    m_ikeOptSettings.xauthType = (ubyte)1;
                m_bXauthType = TRUE;
                break;
#endif
            default :
                fprintf(stderr, "IKE: Option -%c requires an operand.\n", optopt);
                break;
            }
            break;

#ifdef __IKE_TRACK__
        case 'u':
            m_useMsgRecv = 0;
            printf("Using IKE_msgRecvEx1/IKE2_msgRecvEx1 in place of IKE_msgRecv/IKE2_msgRecv\n");
            break;
#endif
        default:
            fprintf(stderr, "IKE: Invalid option -%c\n", optopt);
            break;
        }
    }
    for (i=0 ; optind < argc; optind++, i++)
    {
#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) || defined(__ENABLE_DIGICERT_GDOI_SERVER__)
        ubyte2 port = IKE_GDOI_UDP_PORT;
#else
        ubyte2 port = IKE_DEFAULT_UDP_PORT;
#endif
        ubyte2 natt_port = IKE_NAT_UDP_PORT;
        ubyte4 cookie = 0;

        MOC_IP_ADDRESS_S hostAddr = MOC_IPADDR_NONE;
        ubyte4 dwNetAddr;

        optarg = argv[optind];

        /* get host IP address */
        dwNetAddr = (ubyte4) inet_addr(optarg);
        if (((ubyte4)-1) != dwNetAddr)
        {
            /* IPv4 dotted address */
            if (!dwNetAddr) continue;
            SET_MOC_IPADDR4(hostAddr, GET_NTOHL(dwNetAddr));
        }
        else
        {
#ifdef __ENABLE_DIGICERT_IPV6__
            /* IPv6 address (colon notation) */
#if defined(__LINUX_RTOS__) || defined(__WIN32_RTOS__) || defined(__RTOS_WINCE__)
            struct addrinfo hints = { 0 }, *res;

            hints.ai_family = AF_INET6;
            hints.ai_socktype = SOCK_DGRAM;
            hints.ai_flags = AI_NUMERICHOST | AI_PASSIVE;

            if (0 == getaddrinfo(optarg, NULL, &hints, &res))
            {
                struct sockaddr_in6 *pAddr = (struct sockaddr_in6 *) res->ai_addr;
                ubyte *addr6 = (ubyte *) &(pAddr->sin6_addr);
                SET_MOC_IPADDR6(hostAddr, addr6);

                if (pAddr->sin6_scope_id)
                    hostAddr.uin.addr6[4] = pAddr->sin6_scope_id; /* !!! */

                freeaddrinfo(res);
            }
            else
#endif
#endif
            /* symbolic (e.g. DNS) name lookup */
            if (OK > UDP_getAddrOfHost((sbyte *)optarg, &hostAddr))
                continue;
        }

        DEBUG_PRINT(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_EXAMPLE: Host IP address is ");
        DEBUG_PRINTNL(DEBUG_IKE_EXAMPLE, (sbyte *)optarg);

        IKE_EXAMPLE_addServer(REF_MOC_IPADDR(hostAddr), port,
                              natt_port, cookie);
    } /* for */

#ifdef __ENABLE_DIGICERT_IKE_REF_IDENTIFIER_MATCH__
    DEBUG_PRINT(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_EXAMPLE: Expected Peer Host is ");
    DEBUG_PRINTNL(DEBUG_IKE_EXAMPLE, (sbyte *)m_peerHost);
#endif

    if ((0 < i) && (0 >= m_numSvrInst))
        status = -1;

    return status;
} /* IKE_EXAMPLE_getArgs */


/*------------------------------------------------------------------*/

#ifdef __PARAGON__

extern sbyte4
IKE_EXAMPLE_getArgsFromFile(char * confFileName)
{
    sbyte4 status = 0;
    int i = 0;
    int c;
    ikeConfig_t  ikeConfig;
    ikeSettings  mIkeSetting;

    ZERO_MOC_IPADDR(mPeerAddr);

    DIGI_MEMSET((ubyte *)&ikeConfig, 0, sizeof(ikeConfig_t));
    DIGI_MEMSET((ubyte *)&mIkeSetting, 0, sizeof(ikeSettings));
    status = parse_ike_config_file(&ikeConfig,&mIkeSetting);
    if (OK != status)
        goto exit;

    if (ikeConfig.m_bEapProtoAuth) /* set EAP authenticator protocol */
    {
#if defined(__ENABLE_DIGICERT_EAP_AUTH__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
        sbyte4 eap_auth_t = IKE_EXAMPLE_getOptEapType(optarg, TRUE);
        if (0 >= eap_auth_t)
            fprintf(stderr, "IKE: Bad option value -a %s (unsupported)\n", optarg);
        else
        {
            m_ikeOptSettings.eapProtoAuth = eap_auth_t;
            m_bEapProtoAuth = TRUE;
        }
#else
        fprintf(stderr, "IKE: Bad option -a (disabled)\n");
#endif
    }

    if (ikeConfig.m_bEapProtoPeer) /* set EAP supplicant protocol */
    {
#if defined(__ENABLE_DIGICERT_EAP_PEER__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
        sbyte4 eap_peer_t = IKE_EXAMPLE_getOptEapType(optarg, FALSE);
        if (0 >= eap_peer_t)
            fprintf(stderr, "IKE: Bad option value -s %s (unsupported)\n", optarg);
        else
        {
            m_ikeOptSettings.eapProtoPeer = eap_peer_t;
            m_bEapProtoPeer = TRUE;
        }
#else
        fprintf(stderr, "IKE: Bad option -s (disabled)\n");
#endif
    }

    if (ikeConfig.mPeerAddr) /* initiates connection */
    {
        /* get peer IP address */
        ubyte4 dwPeerAddr = (ubyte4) inet_addr(ikeConfig.mPeerAddr);
        if (-1 != dwPeerAddr)
        {
            if (dwPeerAddr)
            {
                SET_MOC_IPADDR4(mPeerAddr, GET_NTOHL(dwPeerAddr));
            }
        }

#ifdef __ENABLE_DIGICERT_IPV6__
        else
        {
#if defined(__LINUX_RTOS__)
            ubyte addr6[16];
            if (0 < inet_pton(AF_INET6, ikeConfig.mPeerAddr, addr6))
            {
                SET_MOC_IPADDR6(mPeerAddr, addr6);
            }
#else
            UDP_getAddrOfHost((sbyte *)ikeConfig.mPeerAddr, &mPeerAddr);
#endif
        }
#endif
        FREE(ikeConfig.mPeerAddr);
    }

    if (ikeConfig.m_bIkeTimeoutDpd) /* set DPD interval (in mins) */
    {
        m_ikeOptSettings.ikeTimeoutDpd = (ubyte4)(mIkeSetting.ikeTimeoutDpd * 60); /* secs */
        m_bIkeTimeoutDpd = TRUE;
    }

    if (ikeConfig.m_bIkeP1DHgroup) /* set default DH group for [v1] aggressive mode or [v2] IKE_SA_INIT */
    {
        m_ikeOptSettings.ikeP1DHgroup = (ubyte2) mIkeSetting.ikeP1DHgroup;
        m_bIkeP1DHgroup = TRUE;
    }

    if (ikeConfig.m_bIkeP2PFS) /* set PFS; 0=no PFS */
    {
        m_ikeOptSettings.ikeP2PFS = (ubyte2) mIkeSetting.ikeP2PFS;
        m_bIkeP2PFS = TRUE;
    }

    if (ikeConfig.m_ModeCfgAgent) /* enables configuration (v1 MODE-CFG or v2 CP); 1=client, 2=server */
    {
#if defined(__ENABLE_IKE_MODE_CFG__) || defined(__ENABLE_IKE_CP__)
        m_vpnAgent = ikeConfig.m_ModeCfgAgent;
        if ((1 != m_vpnAgent) && (2 != m_vpnAgent))
            fprintf(stderr, "IKE: Bad option value -k %d \n", m_vpnAgent);
#else
        fprintf(stderr, "IKE: Bad option -k (disabled)\n");
#endif
    }

    if (ikeConfig.m_ModeCfgMode) /* sets MODE-CFG mode; 1=PULL, 2=PUSH */
    {
#ifdef __ENABLE_IKE_MODE_CFG__
        if ((1 != m_vpnAgent) && (2 != m_vpnAgent))
        {
            fprintf(stderr, "IKE: Must pair -K option with -k\n");
        }
        else
        switch (ikeConfig.m_ModeCfgMode)
        {
        case 1 : m_bPullCfg = TRUE;  m_bInitQM = ((1==m_vpnAgent)?TRUE:FALSE); break;
        case 2 : m_bPullCfg = FALSE; m_bInitQM = ((1==m_vpnAgent)?FALSE:TRUE); break;
        case 3 : m_bPullCfg = TRUE;  m_bInitQM = ((1==m_vpnAgent)?FALSE:TRUE); break;
        case 4 : m_bPullCfg = FALSE; m_bInitQM = ((1==m_vpnAgent)?TRUE:FALSE); break;
        default : fprintf(stderr, "IKE: Bad option value -K %d \n",ikeConfig.m_ModeCfgMode ); break;
        }
#else
        fprintf(stderr, "IKE: Bad option -K (disabled)\n");
#endif
    }

    if (ikeConfig.m_bIkeP1LifeSecs) /* set IKE_SA lifetime seconds */
    {
        m_ikeOptSettings.ikeP1LifeSecs = mIkeSetting.ikeP1LifeSecs ;
        m_bIkeP1LifeSecs = TRUE;

        m_ikeOptSettings.ikeP1LifeSecsMax = m_ikeOptSettings.ikeP1LifeSecs;
        m_bIkeP1LifeSecsMax = TRUE; /* FOR NOW */
    }

    if(ikeConfig.m_bIkeP2LifeSecs) /* set IPsec SA lifetime seconds */
    {
        m_ikeOptSettings.ikeP2LifeSecs = mIkeSetting.ikeP2LifeSecs;
        m_bIkeP2LifeSecs = TRUE;

        m_ikeOptSettings.ikeP2LifeSecsMax = m_ikeOptSettings.ikeP2LifeSecs;
        m_bIkeP2LifeSecsMax = TRUE; /* FOR NOW */
    }

    if(ikeConfig.m_bIkeP1Mode) /* set phase 1 mode (IKEv1) */
    {
#ifdef __ENABLE_IKE_AGGRESSIVE_MODE__
        if (mIkeSetting.ikeP1Mode == 2)
        {
            m_ikeOptSettings.ikeP1Mode = 2; /* 2=main */;
            m_bIkeP1Mode = TRUE;
        }
        else if (mIkeSetting.ikeP1Mode == 4)
        {
            m_ikeOptSettings.ikeP1Mode = 4; /* 4=aggressive */;
            m_bIkeP1Mode = TRUE;
        }
        else
            fprintf(stderr, "IKE: Bad option value -m (2 for Main, 4 for Aggresive) %d\n", mIkeSetting.ikeP1Mode );
#else
        fprintf(stderr, "IKE: Bad option -m (disabled)\n");
#endif
    }

    if (ikeConfig.m_bOutput)
    {
#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
        DEBUG_CONSOLE_setOutput(ikeConfig.m_Output);
#else
        fprintf(stderr, "IKE: Bad option -o (disabled)\n");
#endif
        FREE(ikeConfig.m_Output);
    }
    CA_MGMT_freeCertificate(&mvcIKECertDesc);
    mPSK = NULL;
    mPSKlen = 0;
    if ((ikeConfig.m_authMethod == 1) && (ikeConfig.m_bCertsSet))
    {
        status = computeHostKeysFromGivenFiles(&mvcIKECertDesc, ikeConfig.m_CACert,ikeConfig.m_cliCert,ikeConfig.m_cliKey );
        if (OK > status)
            goto exit;
    }
    else
    {
        if (ikeConfig.m_bPresharedKey) /* set pre-shared key */
        {
          mIsHexPSK = FALSE;
          mPSK = (sbyte *)ikeConfig.mPSK;
          mPSKlen = strlen((char *)mPSK);
          DEBUG_PRINT(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_EXAMPLE: Preshared key is set (");
          if (IKE_PSK_MAX < mPSKlen)
          {
              mPSKlen = IKE_PSK_MAX;
              DEBUG_PRINTNL(DEBUG_IKE_EXAMPLE, (sbyte *)"truncated ");
          }
          DEBUG_INT(DEBUG_IKE_EXAMPLE, mPSKlen);
          DEBUG_PRINTNL(DEBUG_IKE_EXAMPLE, (sbyte *)" bytes)");
        }
        else
        {  /* No PSK or Cert */
            DEBUG_PRINT(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_EXAMPLE: No Cert or Preshared key is set (");
            status = -1;
            goto exit;
        }
    }

    if (ikeConfig.m_bIkeVersion) /* set version (1 or 2) */
    {
        int version = mIkeSetting.ikeVersion;
        if ((2 == version) || (1 == version))
        {
            m_ikeOptSettings.ikeVersion = (ubyte)version;
            m_bIkeVersion = TRUE;
        }
        else
            fprintf(stderr, "IKE: Bad option value -v %d\n", version);

    }

    if (ikeConfig.m_bSocketTimeout) /* set socket listen timeout (in secs) */
    {
        msTimeout = ikeConfig.msTimeout;
        if ((0==msTimeout) || (60<(ubyte4)msTimeout))
        {
            fprintf(stderr, "IKE: Bad option value -w %s (invalid or too large)\n",msTimeout );
            msTimeout = 4;
        }
        msTimeout *= 1000;
    }

    if (ikeConfig.m_bXauthType)
    {
#ifdef __ENABLE_IKE_XAUTH__
        m_ikeOptSettings.xauthType = mIkeSetting.xauthType;
        m_bXauthType = TRUE;
#else
        fprintf(stderr, "IKE: Bad option -x (disabled)\n");
#endif
    }

exit:
    return status;
} /* IKE_EXAMPLE_getArgsFromFile */

#endif /* __PARAGON__ */


/*------------------------------------------------------------------*/

static void
IKE_EXAMPLE_processOpts(void)
{
    ikeSettings *pxIkeSettings = IKE_ikeSettings();

    if (m_bIkeTimeoutNegotiation)
        pxIkeSettings->ikeTimeoutNegotiation = m_ikeOptSettings.ikeTimeoutNegotiation;

    if (m_bIkeTimeoutDpd)
        pxIkeSettings->ikeTimeoutDpd    = m_ikeOptSettings.ikeTimeoutDpd;

    if (m_bIkeVersion)
        pxIkeSettings->ikeVersion       = m_ikeOptSettings.ikeVersion;

#ifdef __ENABLE_IKE_AGGRESSIVE_MODE__
    if (m_bIkeP1Mode)
        pxIkeSettings->ikeP1Mode        = m_ikeOptSettings.ikeP1Mode;
#endif
    if (m_bIkeP1LifeSecs)
        pxIkeSettings->ikeP1LifeSecs    = m_ikeOptSettings.ikeP1LifeSecs;

    if (m_bIkeP1LifeSecsMax)
        pxIkeSettings->ikeP1LifeSecsMax = m_ikeOptSettings.ikeP1LifeSecsMax;

    if (m_bIkeP2LifeSecs)
        pxIkeSettings->ikeP2LifeSecs    = m_ikeOptSettings.ikeP2LifeSecs;

    if (m_bIkeP2LifeSecsMax)
        pxIkeSettings->ikeP2LifeSecsMax = m_ikeOptSettings.ikeP2LifeSecsMax;

    if (m_bIkeP1DHgroup)
        pxIkeSettings->ikeP1DHgroup     = m_ikeOptSettings.ikeP1DHgroup;    /* P1 DH group, 0=default */

    if (m_bIkeP2PFS)
        pxIkeSettings->ikeP2PFS         = m_ikeOptSettings.ikeP2PFS;        /* P2 DH group, 0=no PFS */

#ifdef __ENABLE_IKE_XAUTH__
    if (m_bXauthType)
    {
        pxIkeSettings->xauthType        = m_ikeOptSettings.xauthType;
#ifdef __ENABLE_IKE_HYBRID_RSA__
        if (m_bHybrid)
            pxIkeSettings->bDoHybrid    = m_ikeOptSettings.bDoHybrid;
#endif
    }
#endif

#if defined(__ENABLE_DIGICERT_EAP_AUTH__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
    if (m_bEapProtoAuth)
    {
        pxIkeSettings->eapProtoAuth     = m_ikeOptSettings.eapProtoAuth;
        if (0 == m_numEapSecret)
        {
#ifdef __ENABLE_DIGICERT_EAP_SIM__
            if (EAP_PROTO_SIM == pxIkeSettings->eapProtoAuth)
            {
                IKE_EXAMPLE_addEapSecret(mEapIdentity, FALSE,
                             (sbyte *)eapSimTriplets, sizeof(eapSimTriplets));
            }
            else if (EAP_PROTO_AKA == pxIkeSettings->eapProtoAuth)
            {
                IKE_EXAMPLE_addEapSecret(mEapIdentity, FALSE,
                                 (sbyte *)eapAkaVector, sizeof(eapAkaVector));
            }
            else
#endif
            IKE_EXAMPLE_addEapSecret(mEapIdentity, FALSE, mEapSecret, mEapSecretLen);
        }
    }
#endif
#if defined(__ENABLE_DIGICERT_EAP_PEER__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
    if (m_bEapProtoPeer)
        pxIkeSettings->eapProtoPeer     = m_ikeOptSettings.eapProtoPeer;
#ifdef __ENABLE_DIGICERT_EAP_TTLS__
    if (m_bEapTtlsType)
        pxIkeSettings->eapTtlsType      = m_ikeOptSettings.eapTtlsType;
#endif
#endif

#if (defined(__ENABLE_DIGICERT_EAP_AUTH__) || defined(__ENABLE_DIGICERT_EAP_PEER__)) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
    pxIkeSettings->eapIdentity          = identityString;
#ifdef __ENABLE_IKE_EAP_ONLY__
    if (m_bDoEapOnly)
        pxIkeSettings->bDoEapOnly       = TRUE;
#endif
#endif

#ifdef __ENABLE_IKE_REDIRECT__
    if (m_redirectGwAddr)
        pxIkeSettings->redirectGwAddr   = m_ikeOptSettings.redirectGwAddr;
#endif
#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
    if (m_bKeyServerAddr)
        pxIkeSettings->keyServerAddr    = m_ikeOptSettings.keyServerAddr;
#endif

    pxIkeSettings->ikeBufferSize = 65535;

    return;
} /* IKE_EXAMPLE_processOpts */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_TAP__

/*------------------------------------------------------------------*/

static sbyte4
IKE_EXAMPLE_getTapContext(TAP_Context **ppTapContext,
                          TAP_EntityCredentialList **ppTapEntityCred,
                          TAP_CredentialList **ppTapKeyCred,
                          void *pKey, TapOperation op, ubyte getContext)
{
    MSTATUS status = OK;
    TAP_ErrorContext *pErrContext = NULL;

    if (pKey == NULL)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    if (getContext)
    {
        /* Initialize context on first module */
        status = TAP_initContext(&(g_moduleList.pModuleList[0]), g_pTapEntityCred,
                                 NULL, ppTapContext, pErrContext);
        if (OK != status)
        {
            DEBUG_ERROR(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_EXAMPLE: TAP_initContext failed, status = ", status);
            goto exit;
        }

        *ppTapEntityCred = g_pTapEntityCred;
        *ppTapKeyCred    = g_pTapKeyCred;
    }
    else
    {
        /* Destroy the TAP context */
        if (OK > (status = TAP_uninitContext(ppTapContext, pErrContext)))
        {
            DEBUG_ERROR(DEBUG_IKE_EXAMPLE, (sbyte*)"IKE_EXAMPLE: TAP_uninitContext failed, status = ", status);
        }
    }

exit:
    return status;
} /* IKE_EXAMPLE_getTapContext */


/*------------------------------------------------------------------*/

static MSTATUS
IKE_EXAMPLE_InitializeTapContext(ubyte *pTpm2ConfigFile, TAP_Context **ppTapCtx,
                                 TAP_EntityCredentialList **ppTapEntityCred,
                                 TAP_CredentialList **ppTapKeyCred)
{
    MSTATUS status = OK;
    TAP_ConfigInfoList configInfoList = { 0, };
    TAP_Context *pTapContext = NULL;
    TAP_ErrorContext *pErrContext = NULL;
    ubyte gotModuleList = FALSE;
    TAP_EntityCredentialList *pEntityCredentials = { 0 };
    TAP_CredentialList *pKeyCredentials = { 0 };
#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
    TAP_ConnectionInfo connInfo = { 0 };
#endif

    if (ppTapCtx == NULL)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

#if (!defined(__ENABLE_DIGICERT_TAP_REMOTE__))
    status = DIGI_CALLOC((void **)&(configInfoList.pConfig), 1, sizeof(TAP_ConfigInfo));
    if (OK != status)
    {
        DEBUG_ERROR(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_EXAMPLE: Failed to allocate memory, status = ", status);
        goto exit;
    }

    status = TAP_readConfigFile((char *) pTpm2ConfigFile, &configInfoList.pConfig[0].configInfo, 0);
    if (OK != status)
    {
        DEBUG_ERROR(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_EXAMPLE: Failed to read config file, status = ", status);
        goto exit;
    }

    configInfoList.count = 1;
    configInfoList.pConfig[0].provider = TAP_PROVIDER_TPM2;
#endif

    status = TAP_init(&configInfoList, pErrContext);
    if (OK != status)
    {
        DEBUG_ERROR(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_EXAMPLE: TAP_init failed, status = ", status);
        goto exit;
    }

#if (defined(__ENABLE_DIGICERT_TAP_REMOTE__))
    connInfo.serverName.bufferLen = DIGI_STRLEN((sbyte *)taps_ServerName)+1;
    status = DIGI_CALLOC ((void **)&(connInfo.serverName.pBuffer), 1, connInfo.serverName.bufferLen);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY ((void *)(connInfo.serverName.pBuffer), (void *)taps_ServerName, DIGI_STRLEN((sbyte *)taps_ServerName));
    if (OK != status)
        goto exit;

    connInfo.serverPort = taps_ServerPort;

    status = TAP_getModuleList(&connInfo, TAP_PROVIDER_TPM2, NULL,
                               &g_moduleList, pErrContext);
#else
    status = TAP_getModuleList(NULL, TAP_PROVIDER_TPM2, NULL,
                               &g_moduleList, pErrContext);
#endif
    if (OK != status)
    {
        DEBUG_ERROR(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_EXAMPLE: TAP_getModuleList failed, status = ", status);
        goto exit;
    }
    gotModuleList = TRUE;
    if (0 == g_moduleList.numModules)
    {
        DEBUG_PRINTNL(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_EXAMPLE: No TPM2 modules found");
        goto exit;
    }

    /* For local TAP, parse the config file and get the Entity Credentials */
#if (!defined(__ENABLE_DIGICERT_TAP_REMOTE__))
    status = TAP_getModuleCredentials(&(g_moduleList.pModuleList[0]),
                                      (char *) pTpm2ConfigFile, 0,
                                      &pEntityCredentials,
                                      pErrContext);
    if (OK != status)
    {
        DEBUG_ERROR(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_EXAMPLE: Failed to get credentials from Credential configuration file, status = ", status);
        goto exit;
    }
#endif

    *ppTapEntityCred = pEntityCredentials;
    *ppTapKeyCred    = pKeyCredentials;

    /* Free module list */
    /*if ((TRUE == gotModuleList) && (g_moduleList.pModuleList))
     {
     status = TAP_freeModuleList(&g_moduleList);
     if (OK != status)
     printf("TAP_freeModuleList : %d\n", status);
     }*/

    /* Free config info */
    if (NULL != configInfoList.pConfig)
    {
        status = TAP_UTILS_freeConfigInfoList(&configInfoList);
        if (OK != status)
        {
            DEBUG_ERROR(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_EXAMPLE: TAP_UTILS_freeConfigInfoList failed, statud = ", status);
        }
    }

exit:
#if (defined(__ENABLE_DIGICERT_TAP_REMOTE__))
    if (connInfo.serverName.pBuffer != NULL)
    {
        DIGI_FREE((void **)&connInfo.serverName.pBuffer);
    }
#endif
    return status;
} /* IKE_EXAMPLE_InitializeTapContext */


#endif /* __ENABLE_DIGICERT_TAP__ */


/*------------------------------------------------------------------*/
/* IKE Server Main Entry                                            */
/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_IKE_EXAMPLE_INIT_CERT_CHAIN__
/* XAUTH with certificate based check enable the flag in the above line */
extern sbyte4 computeHostKeysFromGivenFiles(certDescriptor *pRetCertificateDescr, sbyte *CACertPath, sbyte *ClientCertPath, sbyte *ClientKey);
/*setting certificates */
#define USER_CA_FILE_PATH                 (sbyte*) "./SigningCert.pem"
#define USER_CLIENT_FILE_CERT_PATH        (sbyte*) "./keyUsage.pem"
#define USER_CLIENT_KEY_PATH              (sbyte*) "./keyUsage_key.pem"
#endif

#ifdef __ENABLE_DIGICERT_MEM_PART__
extern memPartDescr *gMemPartDescr;
#endif

extern void
IKE_EXAMPLE_main(void* dummy)
{
    sbyte4 ret, i;

#ifdef __ENABLE_DIGICERT_TAP__
    TAP_ErrorContext *pErrContext = NULL;
#endif
#if !defined(__PARAGON__)
#if !(defined(__ENABLE_DIGICERT_EAP_AUTH__) && !defined(__DISABLE_DIGICERT_IKE_EAP__))
    certDescriptor ikeCert = { NULL };
#endif
#ifdef __ENABLE_DIGICERT_IKE_EXAMPLE_INIT_CERT_CHAIN__
    certDescriptor serverCert[2] = {{ NULL }};

    mComputeHostKeys = FALSE;
#endif
#endif /* !__PARAGON__ */

    MOC_UNUSED(dummy);

    g_ikeBreakSignalRequest = FALSE;

#ifndef __DISABLE_DIGICERT_INIT__
    gMocanaAppsRunning++;
#endif

#ifdef __ENABLE_DIGICERT_SECURE_PATH__
    if (0 > (ret = FMGMT_changeCWD(MANDATORY_BASE_PATH)))
        goto exit_server;
#endif

#ifdef __ENABLE_DIGICERT_TAP__
    if (0 > (ret = DIGICERT_initDigicert()))
    {
        goto exit_tap;
    }

#if !defined(__ENABLE_DIGICERT_TAP_EXTERN__)
    if (0 > (ret = IKE_EXAMPLE_InitializeTapContext((ubyte *) tap_ConfigFile,
                                                    &g_pTapContext,
                                                    &g_pTapEntityCred,
                                                    &g_pTapKeyCred)))
    {
        DEBUG_ERROR(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_EXAMPLE_InitializeTapContext failed, status = ", ret);
        goto exit_tap;
    }

    if (0 > (ret = CRYPTO_INTERFACE_registerTapCtxCallback((void *)&IKE_EXAMPLE_getTapContext)))
    {
        DEBUG_ERROR(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_EXAMPLE: CRYPTO_INTERFACE_registerTapCtxCallback failed, status = ", ret);
        goto exit_tap;
    }
#endif

#endif /* __ENABLE_DIGICERT_TAP__ */

#ifdef __ENABLE_DIGICERT_MEM_PART__
    if (NULL != gMemPartDescr)
    {
        /* make sure it's thread-safe! */
        MEM_PART_enableMutexGuard(gMemPartDescr);
    }
#endif

#define EXIT_IKE goto exit_server;

    /* [v2] initialize EAP */
#if (defined(__ENABLE_DIGICERT_EAP_AUTH__) || defined(__ENABLE_DIGICERT_EAP_PEER__)) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
    if (0 > (ret = EAP_init())) /* Note: should only be called once in the main thread */
    {
        DEBUG_ERROR(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_EXAMPLE: EAP_init() failed, status = ", ret);
        EXIT_IKE
    }
#undef EXIT_IKE
#define EXIT_IKE goto exit_eap;
#endif

    /* [v2] initialize RADIUS passthru authenticator */
#if defined(__ENABLE_DIGICERT_EAP_AUTH__) && defined(__ENABLE_DIGICERT_EAP_RADIUS__) && defined(__ENABLE_DIGICERT_RADIUS_CLIENT__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
    if (0 > (ret = RADIUS_init())) /* Note: should only be called once in the main thread */
    {
        DEBUG_ERROR(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_EXAMPLE: RADIUS_init() failed, status = ", ret);
        EXIT_IKE
    }
    DIGICERT_log(MOCANA_RADIUS, LS_INFO, (sbyte *)"Initialized RADIUS");
#undef EXIT_IKE
#define EXIT_IKE goto exit_radius;
#endif

    /* [v2] initialize SSL for EAP-[T]TLS */
#if (defined(__ENABLE_DIGICERT_EAP_AUTH__) || defined(__ENABLE_DIGICERT_EAP_PEER__)) && !defined(__DISABLE_DIGICERT_IKE_EAP__) && \
    defined(__ENABLE_DIGICERT_EAP_TLS__)
    /* Note: should only be called once in the main thread */
    if (0 > (ret = SSL_ASYNC_init(
#ifdef __ENABLE_DIGICERT_EAP_AUTH__
                                  IKE_SA_MAX*2,
#else
                                  0,
#endif
#ifdef __ENABLE_DIGICERT_EAP_PEER__
                                  IKE_SA_MAX*2)
#else
                                  0)
#endif
        ))
    {
        DEBUG_ERROR(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_EXAMPLE: SSL_ASYNC_init() failed, status = ", ret);
        EXIT_IKE
    }
    DIGICERT_log(MOCANA_SSL, LS_INFO, (sbyte *)"Initialized SSL");
#undef EXIT_IKE
#define EXIT_IKE goto exit_ssl;
#endif

    DEBUG_PRINTNL(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_EXAMPLE: Starting up IKE server");

#ifdef __PARAGON__
#ifdef __RTOS_LINUX__
    CreateConditionVar(&g_hIKEShutdown);
    CreateConditionVar(&g_hIKEConnect);
    CreateConditionVar(&g_hIKEConnectAck);
#else
    if (NULL == (g_hIKEShutdown = CreateEvent(NULL, TRUE, FALSE, NULL)))
    {
        DEBUG_ERROR(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_EXAMPLE: IKE_init() failed, status = ", -1);
        EXIT_IKE
    }
    if (NULL == (g_hIKEConnect = CreateEvent(NULL, TRUE, FALSE, NULL)))
    {
        DEBUG_ERROR(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_EXAMPLE: IKE_init() failed, status = ", -1);
        EXIT_IKE
    }
    if (NULL == (g_hIKEConnectAck = CreateEvent(NULL, TRUE, FALSE, NULL)))
    {
        DEBUG_ERROR(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_EXAMPLE: IKE_init() failed, status = ", -1);
        EXIT_IKE
    }
#endif
#endif

    /* initialize the IKE tables and structures */
    if (0 > (ret = IKE_init()))
    {
        DEBUG_ERROR(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_EXAMPLE: IKE_init() failed, status = ", ret);
        EXIT_IKE
    }

    /* customize and change default settings here */
    IKE_ikeSettings()->funcPtrIkeEvtSend        = IKE_SAMPLE_ikeEvtSend;
    IKE_ikeSettings()->funcPtrIkeXchgSend       = IKE_SAMPLE_ikeXchgSend;
#ifdef __IKE_MULTI_THREADED__
    IKE_ikeSettings()->funcPtrIkeThreadSend     = IKE_SAMPLE_ikeThreadSend;
    IKE_ikeSettings()->funcPtrIkeGetThreadId    = IKE_SAMPLE_ikeGetThreadId;
#endif
    IKE_ikeSettings()->funcPtrIkeGetHostAddr    = IKE_SAMPLE_ikeGetHostAddr;
#if defined(__ENABLE_IPSEC_COOKIE__) && !defined(__ENABLE_DIGICERT_PFKEY__)
    IKE_ikeSettings()->funcPtrIkeGetCookie      = IKE_SAMPLE_ikeGetCookie;
#endif
#ifdef __ENABLE_DIGICERT_GDOI_SERVER__
    IKE_ikeSettings()->funcPtrIsKeyServer       = IKE_SAMPLE_isKeyServer;
#endif
    IKE_ikeSettings()->funcPtrIkeStatHdlr       = IKE_SAMPLE_ikeStatHdlr;

#if defined(__ENABLE_IKE_XAUTH__) || defined(__ENABLE_IKE_MODE_CFG__) || defined(__ENABLE_IKE_CP__)
    IKECFG_EXAMPLE_initUpcalls();
#endif
#if defined(__ENABLE_DIGICERT_EAP_AUTH__) && defined(__ENABLE_DIGICERT_EAP_RADIUS__) && defined(__ENABLE_DIGICERT_RADIUS_CLIENT__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
    IKE_ikeSettings()->funcPtrIkeGetRadSvrId    = IKE_SAMPLE_getRadSvrId; /* RADIUS */
#endif
#if (defined(__ENABLE_DIGICERT_EAP_AUTH__) || defined(__ENABLE_DIGICERT_EAP_PEER__)) && !defined(__DISABLE_DIGICERT_IKE_EAP__) && \
    defined(__ENABLE_DIGICERT_EAP_TLS__)
    IKE_ikeSettings()->funcPtrIkeGetTlsCertStore= IKE_SAMPLE_getTlsCertStore;
#endif
#if defined(__ENABLE_DIGICERT_EAP_AUTH__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
#ifdef __ENABLE_DIGICERT_EAP_GTC__
    IKE_ikeSettings()->funcPtrVerifyPassword    = IKE_SAMPLE_verifyPassword;
#endif
    IKE_ikeSettings()->funcPtrLookupSecret      = IKE_SAMPLE_findSecret;
    /*IKE_ikeSettings()->funcPtrReleaseSecret   = IKE_SAMPLE_freeSecret;*/
#endif
#if defined(__ENABLE_DIGICERT_EAP_PEER__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
    IKE_ikeSettings()->funcPtrGetToken          = IKE_SAMPLE_getToken;
#endif
    IKE_ikeSettings()->ikeBufferSize            = 65535;
    IKE_ikeSettings()->bNotifyCookie            = TRUE; /* [v2] */

#if !defined(__PARAGON__)
    IKE_EXAMPLE_processOpts();

    CA_MGMT_EXAMPLE_initUpcalls();

#if (defined(__ENABLE_DIGICERT_EAP_AUTH__) || defined(__ENABLE_DIGICERT_EAP_PEER__)) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
    IKE_CERT_UTILS_initStore(); /* call *after* IKE_EXAMPLE_processOpts() !!! */
#endif

#ifdef __ENABLE_IKE_PPK_RFC8784__
    if(iked_ppk && iked_ppk_id)
    {
        ret = IKE_setPpkPeerConfig(IKE_globalPeerConfig(), (sbyte *) iked_ppk, strlen(iked_ppk), (sbyte *) iked_ppk_id, strlen(iked_ppk_id), isHexPpk);
        if(0 > ret)
        {
            DEBUG_ERROR(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_EXAMPLE: IKE_setPpkPeerConfig() failed, status = ", ret);
            goto exit;
        }
    }
#endif

#ifdef __ENABLE_DIGICERT_IKE_REF_IDENTIFIER_MATCH__
    IKE_ikeSettings()->ikePeerHost = m_peerHost;
#endif

    /* configure authentication method(s) */
    if (mComputeHostKeys)
    {
#if ((!defined(__DISABLE_DIGICERT_IKE_EAP__)) && defined(__ENABLE_DIGICERT_EAP_PEER__))
        if (TRUE == m_bEapProtoPeer)
        {
            ret = IKE_initServer(NULL, mPSK, mPSKlen, mIsHexPSK);
        }
        else
        {
            ret = IKE_initServer(&g_IKECert, mPSK, mPSKlen, mIsHexPSK);
        }
#elif ((!defined(__DISABLE_DIGICERT_IKE_EAP__)) && defined(__ENABLE_DIGICERT_EAP_AUTH__))
        ret = IKE_initServer(&g_IKECert, mPSK, mPSKlen, mIsHexPSK);
#else
        if (0 > (ret = CA_MGMT_EXAMPLE_computeHostKeys(&ikeCert)))
        {
            DBUG_PRINT(DEBUG_IKE_EXAMPLE,("Failed here.  Status = %d", ret));
            goto exit;
        }

        ret = IKE_initServer(&ikeCert, mPSK, mPSKlen, mIsHexPSK);

        if (0 > CA_MGMT_EXAMPLE_releaseHostKeys(&ikeCert))
        {
            DEBUG_PRINTNL(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_EXAMPLE: CA_MGMT_EXAMPLE_releaseHostKeys() failed");
        }
#endif
    }
    else
    ret = IKE_initServer(NULL, mPSK, mPSKlen, mIsHexPSK);

    if (0 > ret)
    {
        DEBUG_ERROR(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_EXAMPLE: IKE_initServer() failed, status = ", ret);
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_IKE_EXAMPLE_INIT_CERT_CHAIN__
    /*Creating the chain and setting the same within IKE server */
    if (0 > (ret = computeHostKeysFromGivenFiles((certDescriptor *)&serverCert, USER_CA_FILE_PATH, USER_CLIENT_FILE_CERT_PATH, USER_CLIENT_KEY_PATH)))
    {
        DEBUG_ERROR(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_EXAMPLE: computeHostKeysFromGivenFiles() failed = ", ret);
        goto exit;
    }

    if (0 > (ret = IKE_initCertChain((certDescriptor *)&serverCert, 2)))
    {
        DEBUG_ERROR(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_EXAMPLE: IKE_initCertChain() failed, status = ", ret);
        goto exit;
    }
#endif

    /* add default IKE server */
    if (0 >= m_numSvrInst) IKE_EXAMPLE_addDefaultServers();
    if (0 >= m_numSvrInst) goto exit;

    /* add internal (IPsec) event handler socket */
    if (0 > (ret = IKE_EXAMPLE_addUdpSkt(NULL, NULL,
                                         IKE_EXAMPLE_evtRecv,
                                         MOC_UDP_LOOPBACK_ADDR, g_ikeEventPort)))
    {
        DEBUG_ERROR(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_EXAMPLE: IKE_EXAMPLE_addUdpSkt() failed, status = ", ret);
        goto exit;
    }

#ifdef __IKE_MULTI_THREADED__
    if (0 > (ret = IKE_dpcRegister((IKE_dpcFunc)IKE_dpcMsgRecv)))
    {
        DEBUG_ERROR(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_EXAMPLE: IKE_dpcRegister() failed, status = ", ret);
        goto exit;
    }

    for (i=0; i < m_threadNum; i++)
    {
        if (OK > (ret = RTOS_createThread(IKE_EXAMPLE_workerMain, (void *)i,
                                          IKE_MAIN, &m_ikeThread[i])))
        {
            DEBUG_ERROR(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_EXAMPLE: RTOS_createThread(\"worker\") failed, status = ", ret);
            goto exit;
        }
        DEBUG_PRINTNL(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_EXAMPLE: RTOS_createThread(\"worker\") done.");
    }
#endif

#endif /* !__PARAGON__ */

#ifdef __ENABLE_DIGICERT_PFKEY__
    if (0 > PFKEY_EXAMPLE_main())
        goto exit;

    /* - Implement RPC's from IKE (user) to IPsec (kernel).
       - Create a uni-directional channel from IPsec (kernel) to IKE (user).
     */
#else
    if (0 > IPSECKEY_EXAMPLE_main())
    {
        ERROR_PRINT(("Failed to connect to Mocana IPsec"));
        goto exit;
    }
#endif

#ifdef MOCANA_IKEADM_PORT
    IKEADM_EXAMPLE_main();
#endif

#ifdef __PARAGON__
    g_ikeBreakSignalRequest = TRUE; /* this means in "disconnected" state */
    OnDelIP(0);

#ifdef __RTOS_WIN32__
    {
        RTOS_THREAD tid;
        if (OK > (ret = RTOS_createThread(MonitorIPAddressChange, 0, IKE_MAIN, &tid)))
        {
            printf("IKE_EXAMPLE: RTOS_createThread() error: %d\n", ret);
        }
    }
#endif
#ifdef __RTOS_LINUX__
    while(OK != WaitOnConditionVar(g_hIKEShutdown, 100))
#else
    while(WAIT_OBJECT_0 != WaitForSingleObject(g_hIKEShutdown, 100))
#endif
    {
#ifdef __RTOS_LINUX__
        if (OK != WaitOnConditionVar(g_hIKEConnect, 1000))/*This would return only when user enters connect*/
        {
            continue;
        }
#else
        if (WAIT_OBJECT_0 != WaitForSingleObject(g_hIKEConnect, 1000))/*This would return only when user enters connect*/
        {
            continue;
        }
        ResetEvent(g_hIKEConnect);
#endif
        g_ikeBreakSignalRequest = FALSE;

        if (OK > (IKE_EXAMPLE_getArgsFromFile(MOCANA_VPN_INI_CONFIG_PATH)))
        {
            continue;
        }

        ret = IKE_initServer(&mvcIKECertDesc, mPSK, mPSKlen, mIsHexPSK);

        if (0 > CA_MGMT_EXAMPLE_releaseHostKeys(&mvcIKECertDesc))
        {
            DEBUG_PRINTNL(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_EXAMPLE: CA_MGMT_EXAMPLE_releaseHostKeys() failed");
        }
        IKE_EXAMPLE_processOpts();

        CA_MGMT_EXAMPLE_initUpcalls();

#ifndef __RTOS_LINUX__
        IKE_setMocanaAdapter(NULL);
#endif

        /* add default IKE server */
        if (0 >= m_numSvrInst) IKE_EXAMPLE_addDefaultServers();
        if (0 >= m_numSvrInst) continue;

#ifndef __RTOS_LINUX__
        IPSECKEY_EXAMPLE_main();
#endif
#endif /* __PARAGON__ */

    /* connecting to peer, if applicable */
    if (!ISZERO_MOC_IPADDR(mPeerAddr))
    {
        for (i = 0; i < m_numSvrInst; i++)
        {
            ubyte4 dwIkeId = 0;
            MOC_IP_ADDRESS hostAddr = REF_MOC_IPADDR(m_svrInst[i].saddr);

#ifndef __ENABLE_DIGICERT_IPV6__
            MOC_UNUSED(hostAddr);
#else
            if (mPeerAddr.family != hostAddr->family)
               continue;
#endif
            if (0 > (ret = IKE_keyConnect(REF_MOC_IPADDR(mPeerAddr),
                                          i+1, 0, FALSE, &dwIkeId,
                                          TRUE, FALSE, TRUE, NULL)))
            {
                DEBUG_ERROR(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_EXAMPLE: IKE_keyConnect() failed, status = ", ret);
            }
            else
            {
                DEBUG_PRINT(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_EXAMPLE: IKE_keyConnect() started, id = 0x");
                DEBUG_HEXINT(DEBUG_IKE_EXAMPLE, (sbyte4)dwIkeId);
                DEBUG_PRINTNL(DEBUG_IKE_EXAMPLE, (sbyte *)"...");
            }

            if ( 0  < IKE_ikeSettings()->ikeVersion) break;
        }
    }

#ifdef __IKE_MULTI_THREADED__
    {
        RTOS_THREAD tid;
        if (OK > (ret = RTOS_createThread(IKE_EXAMPLE_idle, 0, IKE_MAIN, &tid)))
        {
            DEBUG_ERROR(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_EXAMPLE: RTOS_createThread(\"idle\") failed, status = ", ret);
            goto exit;
        }
        DEBUG_PRINTNL(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_EXAMPLE: RTOS_createThread(\"idle\") done.");
    }
#else
#ifdef __ENABLE_MSGIDLE_THREAD__
    {
        RTOS_THREAD tid;
        DEBUG_PRINTNL(DEBUG_IKE_EXAMPLE, (sbyte *)"==== IKE_EXAMPLE: Testing with Idle message poll in separate thread =====\n");
        if (OK > (ret = RTOS_createThread(IKE_EXAMPLE_att_idle, 0, IKE_MAIN, &tid)))
        {
            DEBUG_ERROR(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_EXAMPLE: RTOS_createThread(\"att_idle\") failed, status = ", ret);
            goto exit;
        }
        DEBUG_PRINTNL(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_EXAMPLE: RTOS_createThread(\"att_idle\") done.");
    }
#endif
#endif

    /* start up the IKE server */
    IKE_EXAMPLE_listen();

#ifdef __PARAGON__
        if (TRUE == g_ikeBreakSignalRequest)
        {
            for (i=0; i < m_numSktDescr; i++)
            {
                void **ppSktDescr = &(m_sktDescr[i].pSktDescr);
                if (NULL != *ppSktDescr)
                {
                    if (NULL != m_sktDescr[i].closefn)
                        m_sktDescr[i].closefn(ppSktDescr, m_sktDescr[i].cb);

                    *ppSktDescr = NULL;
                }
            }
            m_numSktDescr = 0;
            m_numSvrInst = 0;

            OnDelIP(0);
        }

    } /*(WAIT_OBJECT_0 != WaitForSingleObject(g_hIKEShutdown, 10))*/

    MVC_DIALOG_sendEvent(MVC_SA_SHUTDOWN, NULL);

    RTOS_sleepMS(2000);
#endif /* __PARAGON__ */

exit:
    g_ikeBreakSignalRequest = TRUE; /* jic */

    /* shut down the IKE server */
    if (0 > (ret = IKE_shutdown()))
    {
        DEBUG_ERROR(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_EXAMPLE: IKE_shutdown() failed, status = ", ret);
    }

#if (defined(__ENABLE_DIGICERT_EAP_AUTH__) || defined(__ENABLE_DIGICERT_EAP_PEER__)) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
    IKE_CERT_UTILS_freeStore();
#endif
    CA_MGMT_EXAMPLE_uninitUpcalls();

    /* close socket(s) */
    for (i=0; i < m_numSktDescr; i++)
    {
        void **ppSktDescr = &(m_sktDescr[i].pSktDescr);
        if (NULL != *ppSktDescr)
        {
            if (NULL != m_sktDescr[i].closefn)
                m_sktDescr[i].closefn(ppSktDescr, m_sktDescr[i].cb);

            *ppSktDescr = NULL;
        }
    }
    m_numSktDescr = 0;
    m_numSvrInst = 0;

    /* [v2] shut down SSL for EAP-[T]TLS */
#if (defined(__ENABLE_DIGICERT_EAP_AUTH__) || defined(__ENABLE_DIGICERT_EAP_PEER__)) && !defined(__DISABLE_DIGICERT_IKE_EAP__) && \
    defined(__ENABLE_DIGICERT_EAP_TLS__)
exit_ssl:
    /* Note: NOT thread-safe; the following should be called by one thread only */
    SSL_releaseTables();
    SSL_shutdownStack();
#endif

    /* [v2] shut down RADIUS passthru authenticator */
#if defined(__ENABLE_DIGICERT_EAP_AUTH__) && defined(__ENABLE_DIGICERT_EAP_RADIUS__) && defined(__ENABLE_DIGICERT_RADIUS_CLIENT__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
exit_radius:
    RADIUS_shutdown(); /* Note: NOT thread-safe; should be called by one thread only */
#endif

    /* [v2] shut down EAP */
#if (defined(__ENABLE_DIGICERT_EAP_AUTH__) || defined(__ENABLE_DIGICERT_EAP_PEER__)) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
exit_eap:
    if (0 > (ret = EAP_shutdown())) /* Note: NOT thread-safe; should be called by one thread only */
    {
        DEBUG_ERROR(DEBUG_IKE_EXAMPLE, (sbyte *)"IKE_EXAMPLE: EAP_shutdown() failed, status = ", ret);
    }
#endif

exit_tap:
#ifdef __ENABLE_DIGICERT_TAP__
    TAP_uninit(pErrContext);
#ifdef __DISABLE_DIGICERT_INIT__
    MOC_MEM_PART_UNINIT(ret, ret)
#endif
#endif

    /* in your design, you will want to wait for upper layer to signal it's dead */
    RTOS_sleepMS(2000);

exit_server:
#ifndef __DISABLE_DIGICERT_INIT__
    gMocanaAppsRunning--;
#endif
    return;
} /* IKE_EXAMPLE_main */


static void IKE_SAMPLE_DelIkeAndIpsecSA(IKESA pxSa, MSTATUS mError)
{

    MSTATUS status = OK;
    struct ipsecKey key = { 0 };

    if (!pxSa || !IS_VALID(pxSa)) goto exit;

    INIT_MOC_IPADDR(peerAddr, pxSa->dwPeerAddr)
#ifdef __ENABLE_DIGICERT_PFKEY__
    INIT_MOC_IPADDR(hostAddr, pxSa->dwHostAddr)
#endif
    TEST_MOC_IPADDR6(peerAddr,
    {
        key.flags |= IPSEC_SA_FLAG_IP6;
        key.dwDestAddr = (CAST_MOC_IPADDR) GET_MOC_IPADDR6(peerAddr);
    })
    key.dwDestAddr = GET_MOC_IPADDR4(peerAddr);
#ifdef __ENABLE_DIGICERT_PFKEY__
    TEST_MOC_IPADDR6(hostAddr, {
            key.dwSrcAddr = (CAST_MOC_IPADDR) GET_MOC_IPADDR6(hostAddr);
    })
    key.dwSrcAddr = GET_MOC_IPADDR4(hostAddr);
#endif
#ifdef __ENABLE_IPSEC_NAT_T__
    if (IS_PEER_BEHIND_NAT(pxSa))
        key.wUdpEncPort = pxSa->wPeerPort;
#endif
    key.dwIkeSaId = pxSa->dwId0; /* see RFC4306 1.4. 2nd paragraph */

    IPSEC_keyDelete(&key);

    if (!(IKE_SA_FLAG_DELETED & pxSa->flags))
    {
        if (IS_IKE2_SA(pxSa))
        {
            IKE2_delSa(pxSa, TRUE, mError);

        }
        else
        {
            IKE_delSa(pxSa, TRUE, mError);
        }
    }
exit:
    return ;
}


/*------------------------------------------------------------------*/
/* IKE Status Handler (alarms, loggings, counters, etc.)           */
/*------------------------------------------------------------------*/

static void
IKE_SAMPLE_ikeStatHdlr(sbyte4 cat, sbyte4 type, ubyte4 id,
                       void *data1, void *data2)
{
    /* See "ike_status.h" and "ikesa.h" for parameter values. */
    IKESA pxSa = NULL;
    IPSECSA pxIPsecSa = NULL;

    sbyte4 ikeVer = 0;
    ubyte4 ikeId = 0;
    sbyte *initiator = (sbyte *)"";

    if (ISC_SA == cat) goto handle_sa;
    if (ISC_CHILDSA == cat) goto handle_childsa;
    goto exit;

/* IKE_SA */
handle_sa:
    pxSa = (IKESA)data1;
    ikeId = id;

    ikeVer = IS_IKE2_SA(pxSa) ? 2 : 1;
    initiator = IS_INITIATOR(pxSa) ? (sbyte *)" I" : (sbyte *)" R";

    /* check status */
    switch (type)
    {
    case IST_FAIL :
    {
#if defined(__ENABLE_ALL_DEBUGGING__)
/*      printf("  IKE_SA [v%d%s] (id=0x%x) failed", ikeVer, initiator, ikeId);
        if (pxSa->merror) printf(", status = %d", (int) pxSa->merror);
        printf(".\n");*/
        DEBUG_PRINT(DEBUG_PLATFORM,(sbyte*) " IKE_SA Failed [v");
        DEBUG_INT(DEBUG_PLATFORM, ikeVer);
        DEBUG_PRINT(DEBUG_PLATFORM, initiator);
        DEBUG_PRINT(DEBUG_PLATFORM,(sbyte*) "](id=0x");
        DEBUG_HEXINT(DEBUG_PLATFORM, ikeId);
        DEBUG_PRINT(DEBUG_PLATFORM,(sbyte*) ")");
        if (pxSa->merror) DEBUG_ERROR(DEBUG_PLATFORM,(sbyte*) ", status = ", (int) pxSa->merror);
        debug_uptime();
        DEBUG_PRINTNL(DEBUG_PLATFORM,(sbyte*) " ");
#endif
#ifdef __PARAGON__
        MVC_DIALOG_sendEvent(MVC_SA_FAILED, NULL);
#endif
        break;
    }
    case IST_SUCCESS :
    {
#if defined(__ENABLE_ALL_DEBUGGING__)
/*      printf("  IKE_SA [v%d%s] (id=0x%x) created.\n", ikeVer, initiator, ikeId);*/
        DEBUG_PRINT(DEBUG_PLATFORM,(sbyte*) " IKE_SA Created [v");
        DEBUG_INT(DEBUG_PLATFORM, ikeVer);
        DEBUG_PRINT(DEBUG_PLATFORM, initiator);
        DEBUG_PRINT(DEBUG_PLATFORM,(sbyte*) "](id=0x");
        DEBUG_HEXINT(DEBUG_PLATFORM, ikeId);
        DEBUG_PRINTNL(DEBUG_PLATFORM,(sbyte*) ")");
#endif
#ifdef __PARAGON__
        MVC_DIALOG_sendEvent(MVC_IKE_SA_DONE, NULL);
#endif
        break;
    }
    case IST_DELETED :
    {
#if defined(__ENABLE_ALL_DEBUGGING__)
/*      printf("  IKE_SA        (id=0x%x) deleted", ikeId);
        if (pxSa->merror) printf(", status = %d", (int) pxSa->merror);
        printf(".\n");*/
        DEBUG_PRINT(DEBUG_PLATFORM, (sbyte *)" IKE_SA Deleted [v");
        DEBUG_INT(DEBUG_PLATFORM, ikeVer);
        DEBUG_PRINT(DEBUG_PLATFORM, initiator);
        DEBUG_PRINT(DEBUG_PLATFORM, (sbyte *)"](id=0x");
        DEBUG_HEXINT(DEBUG_PLATFORM, ikeId);
        DEBUG_PRINT(DEBUG_PLATFORM, (sbyte *)")");
        if (pxSa->merror) DEBUG_ERROR(DEBUG_PLATFORM, (sbyte *)", status = ", (int) pxSa->merror);
        else DEBUG_PRINTNL(DEBUG_PLATFORM, (sbyte *)" ");
#endif
#ifdef __PARAGON__
        MVC_DIALOG_sendEvent(MVC_SA_DELETED, NULL);
#endif
        break;
    }
    case IST_DPD :
    {
#if defined(__ENABLE_ALL_DEBUGGING__)
        printf("  IKE_SA        (id=0x%x) dead peer detected.\n", ikeId);
#endif
        IKE_SAMPLE_DelIkeAndIpsecSA(pxSa, ERR_IKE_TIMEOUT);
        break;
    }
    case IST_INITIAL_CONTACT :
    {
#ifdef __ENABLE_DIGICERT_PFKEY__
        /* TODO: delete old CHILD_SA's (IPsec) */
#endif
        break;
    }
   default :
        break;
    }

    goto exit;

/* CHILD_SA (i.e. IPsec SA) */
handle_childsa:
    pxIPsecSa = (IPSECSA)data1;
    pxSa = (IKESA)data2;

    if (!pxSa) ikeVer = 1; /* !!! */
    else
    ikeVer = IS_IKE2_SA(pxSa) ? 2 : 1;
    initiator = IS_CHILD_INITIATOR(pxIPsecSa) ? (sbyte *)" I" : (sbyte *)" R";

    switch (type)
    {
    case IST_FAIL :
    {
#if defined(__ENABLE_ALL_DEBUGGING__)
/*      printf("  CHILD_SA [v%d%s] failed", ikeVer, initiator);
        if (pxIPsecSa->merror) printf(", status = %d", (int) pxIPsecSa->merror);
        printf(".\n");*/
        DEBUG_PRINT(DEBUG_PLATFORM,(sbyte*) "  CHILD_SA failed [v");
        DEBUG_INT(DEBUG_PLATFORM, ikeVer);
        DEBUG_PRINT(DEBUG_PLATFORM, initiator);
        DEBUG_PRINT(DEBUG_PLATFORM,(sbyte*) "]");
        if (pxIPsecSa->merror) DEBUG_ERROR(DEBUG_PLATFORM,(sbyte*) ", status = ", (int) pxIPsecSa->merror);
        else DEBUG_PRINTNL(DEBUG_PLATFORM,(sbyte*) ".");
#endif
#ifdef __PARAGON__
        MVC_DIALOG_sendEvent(MVC_SA_FAILED, NULL);
        OnDelIP(0);
#endif
        break;
    }
    case IST_SUCCESS :
    {
#if defined(__ENABLE_ALL_DEBUGGING__)
/*      printf("  CHILD_SA [v%d%s] created.\n", ikeVer, initiator);*/
        DEBUG_PRINT(DEBUG_PLATFORM,(sbyte*)"  CHILD_SA created [v");
        DEBUG_INT(DEBUG_PLATFORM, ikeVer);
        DEBUG_PRINT(DEBUG_PLATFORM, initiator);
        DEBUG_PRINTNL(DEBUG_PLATFORM,(sbyte*) "].");
#endif
#ifdef __PARAGON__
        MVC_DIALOG_sendEvent(MVC_IPSEC_SA_DONE, NULL);
#endif
        break;
    }
    default :
        break;
    }

exit:
    return;
} /* IKE_SAMPLE_ikeStatHdlr */


/*------------------------------------------------------------------*/
/* Advanced Customization                                           */
/*------------------------------------------------------------------*/

/* Set the following flags in "moptions.h" as needed (matching their
   corresponding custom functions):

    #define CUSTOM_IKE_GET_PSK          IKE_CUSTOM_getPsk
    #define CUSTOM_IKE_USE_CERT         IKE_CUSTOM_useCert
    #define CUSTOM_IKE_GET_P1_DHGRP     IKE_CUSTOM_getP1DhGrp
    #define CUSTOM_IKE_GET_P2_PFS       IKE_CUSTOM_getP2Pfs
    #define CUSTOM_IKE_GET_ID           IKE_CUSTOM_getId
    #define CUSTOM_IKE_GET_EAP_PROTO    IKE_CUSTOM_getEapProto
 */


/*------------------------------------------------------------------*/

#ifdef CUSTOM_IKE_GET_PSK
extern sbyte4
IKE_CUSTOM_getPsk(/* [output] */
                  ubyte *poPsk,         /* may be NULL */
                  ubyte4 *pdwPskLen,    /* +[input] */

                  /* [input] */
                  const ubyte *poId,        /* peer ID; may be NULL */
                  ubyte2 wIdLen,            /* [v1] aggresive mode or [v2] responder or inbound */
                  sbyte4 idType,            /* see IKE_ID_T in "ike/ike_defs.h" */

                  MOC_IP_ADDRESS peerAddr,
                  sbyte4 dir,               /* [v1] 0=both or [v2] 1=in/peer, 2=out/host */
                  intBoolean bInitiator,    /* Am I the initiator? */
                  sbyte4 serverInstance)
{
    MSTATUS status = STATUS_IKE_CUSTOM_CONTINUE;

    MOC_UNUSED(poId);
    MOC_UNUSED(wIdLen);
    MOC_UNUSED(idType);

    MOC_UNUSED(dir);
    MOC_UNUSED(bInitiator);
    MOC_UNUSED(serverInstance);

    TEST_MOC_IPADDR6(peerAddr,
    {
        /* use default setting */
    })
    {
        ubyte4 dwPeerAddr = GET_MOC_IPADDR4(peerAddr);

        if (ipv4_addr(10,6,21,251) == dwPeerAddr)
        {
            /* use a specific PSK */
            if (poPsk) DIGI_MEMCPY(poPsk, "testing", 7);
            *pdwPskLen = 7;
            status = OK;
        }
        else if (ipv4_addr(10,9,17,255) == dwPeerAddr)
        {
            /* do not use PSK auth. */
            *pdwPskLen = 0;
            status = STATUS_IKE_CUSTOM_NONE;
        }
        else
        {
            /* use default setting */
        }
    }

    return (sbyte4)status;
} /* IKE_CUSTOM_getPsk */
#endif


/*------------------------------------------------------------------*/

#ifdef CUSTOM_IKE_USE_CERT
extern sbyte4
IKE_CUSTOM_useCert(/* [output] */
                   struct certDescriptor axCert[], /* host certificate(s), leaf first; may be NULL */
                   sbyte4 *certNum, /* +[input] */

                   /* [input] */
                   const ubyte *poId,       /* host ID; may be NULL */
                   ubyte2 wIdLen,           /* responder or [v1] aggresive mode or [v2] inbound */
                   sbyte4 idType,           /* see IKE_ID_T in "ike/ike_defs.h" */

                   MOC_IP_ADDRESS peerAddr,
                   sbyte4 dir,              /* [v1] 0=both or [v2] 1=in/peer, 2=out/host */
                   intBoolean bInitiator,
                   sbyte4 serverInstance)
{
    MSTATUS status = STATUS_IKE_CUSTOM_CONTINUE;

    MOC_UNUSED(axCert);
    MOC_UNUSED(certNum);

    MOC_UNUSED(poId);
    MOC_UNUSED(wIdLen);
    MOC_UNUSED(idType);

    MOC_UNUSED(dir);
    MOC_UNUSED(bInitiator);
    MOC_UNUSED(serverInstance);

    TEST_MOC_IPADDR6(peerAddr,
    {
        /* use default setting */
    })
    {
        ubyte4 dwPeerAddr = GET_MOC_IPADDR4(peerAddr);

        if (ipv4_addr(192,168,3,245) == dwPeerAddr)
        {
            /* do not use "RSA Sigature" auth mtd */
            status = STATUS_IKE_CUSTOM_NONE;
        }
    }

    return (sbyte4)status;
} /* IKE_CUSTOM_useCert */
#endif


/*------------------------------------------------------------------*/

#ifdef CUSTOM_IKE_GET_P1_DHGRP
extern sbyte4
IKE_CUSTOM_getP1DhGrp(/* [output] */
                      ubyte2 awDhGrp[],
                      sbyte4 *num, /* +[input] */

                      /* [input] */
                      MOC_IP_ADDRESS peerAddr,
                      sbyte4 dir,             /* n/a */
                      intBoolean bInitiator,
                      sbyte4 serverInstance)
{
    MSTATUS status = STATUS_IKE_CUSTOM_CONTINUE;

    static ubyte2 m_pfs[6] = { 2, 1, 5, 14 };
    const sbyte4 m_pfsNum = 4;

    sbyte4 i=0, j=0;

    sbyte4 num_out = (bInitiator ? 2 : m_pfsNum);
    sbyte4 num_in = *num;
    *num = 0;

    MOC_UNUSED(peerAddr);
    MOC_UNUSED(dir);
    MOC_UNUSED(serverInstance);

    for (; (i < num_in) && (j < num_out); i++, j++)
    {
        awDhGrp[i] = m_pfs[j];
        (*num)++;
    }
    status = OK;

    return (sbyte4)status;
} /* IKE_CUSTOM_getP1DhGrp*/
#endif


/*------------------------------------------------------------------*/

#ifdef CUSTOM_IKE_GET_P2_PFS
extern sbyte4
IKE_CUSTOM_getP2Pfs(/* [output] */
                    ubyte2 awDhGrp[],
                    sbyte4 *num, /* +[input] */

                    /* [input] */
                    MOC_IP_ADDRESS peerAddr,
                    sbyte4 dir,             /* n/a */
                    intBoolean bInitiator,
                    sbyte4 serverInstance)
{
    MSTATUS status = STATUS_IKE_CUSTOM_CONTINUE;

    static ubyte2 m_pfs[6] = { OAKLEY_GROUP_DEFAULT, 0, 2, 1, 5, 14 };
    const sbyte4 m_pfsNum = 6;

    sbyte4 num_in = *num;
    *num = 0;

    MOC_UNUSED(dir);
    MOC_UNUSED(serverInstance);

    TEST_MOC_IPADDR6(peerAddr,
    {
        /* use default setting */
    })
    {
        ubyte4 dwPeerAddr = GET_MOC_IPADDR4(peerAddr);

        if (ipv4_addr(10,6,21,251) == dwPeerAddr)
        {
            /* specify PFS */
            sbyte4 i=0, j =(bInitiator ? 0 : 1);
            for (; (i < num_in) && (j < m_pfsNum); i++, j++)
            {
                awDhGrp[i] = m_pfs[j];
                (*num)++;
            }
            status = OK;
        }
        else if (ipv4_addr(10,9,17,255) == dwPeerAddr)
        {
            /* no PFS */
            if (bInitiator)
            {
                awDhGrp[0] = 0;
                *num = 1;
                status = OK;
            }
        }
        else
        {
            /* use default setting */
        }
    }

    return (sbyte4)status;
} /* IKE_CUSTOM_getP2Pfs */
#endif


/*------------------------------------------------------------------*/

#ifdef CUSTOM_IKE_GET_ID
extern sbyte4
IKE_CUSTOM_getId(/* [output] */
                 const ubyte **ppoId,   /* ID payload data; allocated by callee (static) */
                 ubyte2 *pwIdLen,
                 sbyte4 *pIdType,       /* see IKE_ID_T in "ike/ike_defs.h" */

                 /* [input] */
                 MOC_IP_ADDRESS peerAddr,
                 sbyte4 dir,            /* 1=in/remote [v2], 2=out/local */
                 intBoolean bInitiator, /* Am I the initiator (e.g. [v2] EAP supplicant)? */
                 sbyte4 serverInstance)
{
    static ubyte *myEmailAddr = (ubyte *)"info@test.com";

    MSTATUS status = STATUS_IKE_CUSTOM_CONTINUE;

    MOC_UNUSED(bInitiator);
    MOC_UNUSED(serverInstance);

    TEST_MOC_IPADDR6(peerAddr,
    {
        /* use default ID; i.e. IP address */
    })
    {
        ubyte4 dwPeerAddr = GET_MOC_IPADDR4(peerAddr);

        if ((2 == dir) && /* get our ID */
            (ipv4_addr(192,168,3,248) == dwPeerAddr))
        {
            *pwIdLen = 13;
            *pIdType = 3/* ID_RFC822_ADDR */;
            *ppoId = myEmailAddr; /* use Email address in ID Payload */

            status = OK;
        }
    }

    return (sbyte4)status;
} /* IKE_CUSTOM_getId */
#endif


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_EAP_AUTH__) || defined(__ENABLE_DIGICERT_EAP_PEER__)) && !defined(__DISABLE_DIGICERT_IKE_EAP__)

/* [v2] see IKE_EAP_PROTO_T in "ike/ike_defs.h" */
#ifdef CUSTOM_IKE_GET_EAP_PROTO
extern sbyte4
IKE_CUSTOM_getEapProto(/* [output] */
                       sbyte4 *eapProto,        /* see IKE_EAP_PROTO_T in "ike/ike_defs.h" */

                       /* [input] */
                       const ubyte *poId,       /* peer ID */
                       ubyte2 wIdLen,
                       sbyte4 idType,           /* see IKE_ID_T in "ike/ike_defs.h" */

                       MOC_IP_ADDRESS peerAddr,
                       sbyte4 dir,              /* n/a */
                       intBoolean bInitiator,   /* Am I the supplicant (i.e. initiator)? */
                       sbyte4 serverInstance)
{
    MSTATUS status = STATUS_IKE_CUSTOM_CONTINUE;

    MOC_UNUSED(poId);
    MOC_UNUSED(wIdLen);
    MOC_UNUSED(idType);
    MOC_UNUSED(dir);
    MOC_UNUSED(bInitiator);
    MOC_UNUSED(serverInstance);

    TEST_MOC_IPADDR6(peerAddr,
    {
        /* use default setting */
    })
    {
        ubyte4 dwPeerAddr = GET_MOC_IPADDR4(peerAddr);

        if ((ipv4_addr(192,168,3,131) == dwPeerAddr) ||
            (ipv4_addr(192,168,3,101) == dwPeerAddr))
        {
            /* use a specific EAP auth. protocol */
            *eapProto = (sbyte4)
/*              EAP_PROTO_LEAP; */
                EAP_PROTO_MSCHAPv2;
/*              EAP_PROTO_MD5; */
/*              EAP_PROTO_PSK; */
/*              EAP_PROTO_SRP; */
/*              EAP_PROTO_SIM; */
/*              EAP_PROTO_AKA; */

            status = OK;
        }
        else if (ipv4_addr(10,8,10,255) == dwPeerAddr)
        {
            /* do not use EAP auth. */
            *eapProto = 0; /* jic */
            status = STATUS_IKE_CUSTOM_NONE;
        }
        else
        {
            /* use default setting */
        }
    }

    return (sbyte4)status;
} /* IKE_CUSTOM_getEapProto */
#endif

#endif /* (defined(__ENABLE_DIGICERT_EAP_AUTH__) || defined(__ENABLE_DIGICERT_EAP_PEER__)) && !defined(__DISABLE_DIGICERT_IKE_EAP__) */


/*------------------------------------------------------------------*/

#ifdef __PARAGON__

extern void
IKE_EXAMPLE_close(void)
{
    g_ikeBreakSignalRequest = TRUE; /* jic */
    RTOS_sleepMS(3000);
}


/*------------------------------------------------------------------*/

extern MSTATUS
startIkeThread(void)
{
    MSTATUS status = OK;
    RTOS_THREAD tid;

    if (OK > RTOS_createThread(IKE_EXAMPLE_main, 0, IKE_MAIN, &tid))
    {
        DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: RTOS_createThread IKE_EXAMPLE_main failed.");
    }

    return status;
}

#endif /* __PARAGON__*/


#endif /* __ENABLE_DIGICERT_IKE_SERVER_EXAMPLE__ */
#endif /* __ENABLE_DIGICERT_EXAMPLES__ */
