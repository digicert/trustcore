/**
 * @file   mtcp.h
 * @brief  Mocana TCP Abstraction Layer
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

#ifndef __MTCP_HEADER__
#define __MTCP_HEADER__

#include "mtypes.h"
#include "../common/mtcp_custom.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TCP_NO_TIMEOUT      (0)

#if !defined(__CUSTOM_TCP__)

#if defined __SOLARIS_TCP__

#define TCP_SOCKET          int
#define TCP_INIT            SOLARIS_TCP_init
#define TCP_SHUTDOWN        SOLARIS_TCP_shutdown
#define TCP_LISTEN_SOCKET   SOLARIS_TCP_listenSocket
#define TCP_ACCEPT_SOCKET   SOLARIS_TCP_acceptSocket
#define TCP_CLOSE_SOCKET    SOLARIS_TCP_closeSocket
#define TCP_READ_AVL        SOLARIS_TCP_readSocketAvailable
#define TCP_WRITE           SOLARIS_TCP_writeSocket
#define TCP_CONNECT         SOLARIS_TCP_connectSocket
#define TCP_IS_SOCKET_VALID(s) (s >= 0)

#elif defined __LINUX_TCP__

#define TCP_SOCKET                  int
#define TCP_INIT                    LINUX_TCP_init
#define TCP_SHUTDOWN                LINUX_TCP_shutdown
#define TCP_LISTEN_SOCKET           LINUX_TCP_listenSocket
#define TCP_LISTEN_SOCKET_LOCAL     LINUX_TCP_listenSocketLocal
#define TCP_LISTEN_SOCKET_ADDR      LINUX_TCP_listenSocketAddr
#define TCP_ACCEPT_SOCKET           LINUX_TCP_acceptSocket
#define TCP_ACCEPT_SOCKET_TIMEOUT   LINUX_TCP_acceptSocketTimeout
#define TCP_CLOSE_SOCKET            LINUX_TCP_closeSocket
#define TCP_READ_AVL                LINUX_TCP_readSocketAvailable
#define TCP_READ_AVL_EX             LINUX_TCP_readSocketAvailableEx
#define TCP_WRITE                   LINUX_TCP_writeSocket
#define TCP_CONNECT                 LINUX_TCP_connectSocket
#define TCP_CONNECT_TIMEOUT         LINUX_TCP_connectSocketTimeout
#define TCP_CONNECT_NONBLOCK        LINUX_TCP_connectSocketNonBlocking
#define TCP_getPeerName             LINUX_TCP_getPeerName
#define UNIXDOMAIN_CONNECT          LINUX_unixDomain_connectSocket
#define UNIXDOMAIN_ACCEPT           LINUX_unixDomain_acceptSocket
#define UNIXDOMAIN_LISTEN           LINUX_unixDomain_listenSocket
#define UNIXDOMAIN_CLOSE            LINUX_unixDomain_closeSocket
#define TCP_IS_SOCKET_VALID(s)      (s >= 0)


#elif defined __SYMBIAN_TCP__

#define TCP_SOCKET          int
#define TCP_INIT            SYMBIAN_TCP_init
#define TCP_SHUTDOWN        SYMBIAN_TCP_shutdown
#define TCP_LISTEN_SOCKET   SYMBIAN_TCP_listenSocket
#define TCP_ACCEPT_SOCKET   SYMBIAN_TCP_acceptSocket
#define TCP_CLOSE_SOCKET    SYMBIAN_TCP_closeSocket
#define TCP_READ_AVL        SYMBIAN_TCP_readSocketAvailable
#define TCP_WRITE           SYMBIAN_TCP_writeSocket
#define TCP_CONNECT         SYMBIAN_TCP_connectSocket
#define TCP_getPeerName     SYMBIAN_TCP_getPeerName
#define TCP_IS_SOCKET_VALID(s) (s >= 0)


#elif defined __WIN32_TCP__

#ifndef INVALID_SOCKET
#define INVALID_SOCKET  (~0)
#endif

#define TCP_SOCKET               unsigned int
#define TCP_INIT                 WIN32_TCP_init
#define TCP_SHUTDOWN             WIN32_TCP_shutdown
#define TCP_LISTEN_SOCKET        WIN32_TCP_listenSocket
#define TCP_LISTEN_SOCKET_LOCAL  WIN32_TCP_listenSocketLocal
#define TCP_ACCEPT_SOCKET        WIN32_TCP_acceptSocket
#define TCP_CLOSE_SOCKET         WIN32_TCP_closeSocket
#define TCP_READ_AVL             WIN32_TCP_readSocketAvailable
#define TCP_WRITE                WIN32_TCP_writeSocket
#define TCP_CONNECT              WIN32_TCP_connectSocket
#define TCP_getPeerName          WIN32_TCP_getPeerName
#define TCP_IS_SOCKET_VALID(s) (s != INVALID_SOCKET)

#elif defined __VXWORKS_TCP__

#define TCP_SOCKET               int
#define TCP_INIT                 VXWORKS_TCP_init
#define TCP_SHUTDOWN             VXWORKS_TCP_shutdown
#define TCP_LISTEN_SOCKET        VXWORKS_TCP_listenSocket
#define TCP_LISTEN_SOCKET_LOCAL  VXWORKS_TCP_listenSocketLocal
#define TCP_ACCEPT_SOCKET        VXWORKS_TCP_acceptSocket
#define TCP_CLOSE_SOCKET         VXWORKS_TCP_closeSocket
#define TCP_READ_AVL             VXWORKS_TCP_readSocketAvailable
#define TCP_WRITE                VXWORKS_TCP_writeSocket
#define TCP_CONNECT              VXWORKS_TCP_connectSocket
#define TCP_getPeerName          VXWORKS_TCP_getPeerName
#define TCP_IS_SOCKET_VALID(s) (s >= 0)

#elif defined __NNOS_TCP__

#define TCP_SOCKET          int
#define TCP_INIT            NNOS_TCP_init
#define TCP_SHUTDOWN        NNOS_TCP_shutdown
#define TCP_LISTEN_SOCKET   NNOS_TCP_listenSocket
#define TCP_ACCEPT_SOCKET   NNOS_TCP_acceptSocket
#define TCP_CLOSE_SOCKET    NNOS_TCP_closeSocket
#define TCP_READ_AVL        NNOS_TCP_readSocketAvailable
#define TCP_WRITE           NNOS_TCP_writeSocket
#define TCP_CONNECT         NNOS_TCP_connectSocket
#define TCP_IS_SOCKET_VALID(s) (s >= 0)

#elif defined __PSOS_TCP__

#define TCP_SOCKET          int
#define TCP_INIT            PSOS_TCP_init
#define TCP_SHUTDOWN        PSOS_TCP_shutdown
#define TCP_LISTEN_SOCKET   PSOS_TCP_listenSocket
#define TCP_ACCEPT_SOCKET   PSOS_TCP_acceptSocket
#define TCP_CLOSE_SOCKET    PSOS_TCP_closeSocket
#define TCP_READ_AVL        PSOS_TCP_readSocketAvailable
#define TCP_WRITE           PSOS_TCP_writeSocket
#define TCP_CONNECT         PSOS_TCP_connectSocket
#define TCP_SHARE_SOCKET    PSOS_TCP_shareSocket
#define TCP_IS_SOCKET_VALID(s) (s >= 0)

#elif defined __NUCLEUS_TCP__

#define TCP_SOCKET          int
#define TCP_INIT            NUCLEUS_TCP_init
#define TCP_SHUTDOWN        NUCLEUS_TCP_shutdown
#define TCP_LISTEN_SOCKET   NUCLEUS_TCP_listenSocket
#define TCP_ACCEPT_SOCKET   NUCLEUS_TCP_acceptSocket
#define TCP_CLOSE_SOCKET    NUCLEUS_TCP_closeSocket
#define TCP_READ_AVL        NUCLEUS_TCP_readSocketAvailable
#define TCP_WRITE           NUCLEUS_TCP_writeSocket
#define TCP_CONNECT         NUCLEUS_TCP_connectSocket
#define TCP_IS_SOCKET_VALID(s) (s >= 0)

#elif defined __CYGWIN_TCP__

#define TCP_SOCKET          int
#define TCP_INIT            CYGWIN_TCP_init
#define TCP_SHUTDOWN        CYGWIN_TCP_shutdown
#define TCP_LISTEN_SOCKET   CYGWIN_TCP_listenSocket
#define TCP_ACCEPT_SOCKET   CYGWIN_TCP_acceptSocket
#define TCP_CLOSE_SOCKET    CYGWIN_TCP_closeSocket
#define TCP_READ_AVL        CYGWIN_TCP_readSocketAvailable
#define TCP_WRITE           CYGWIN_TCP_writeSocket
#define TCP_CONNECT         CYGWIN_TCP_connectSocket
#define TCP_getPeerName     CYGWIN_TCP_getPeerName
#define TCP_IS_SOCKET_VALID(s) (s >= 0)

#elif defined __OSX_TCP__

#define TCP_SOCKET          int
#define TCP_INIT            OSX_TCP_init
#define TCP_SHUTDOWN        OSX_TCP_shutdown
#define TCP_LISTEN_SOCKET   OSX_TCP_listenSocket
#define TCP_ACCEPT_SOCKET   OSX_TCP_acceptSocket
#define TCP_CLOSE_SOCKET    OSX_TCP_closeSocket
#define TCP_READ_AVL        OSX_TCP_readSocketAvailable
#define TCP_WRITE           OSX_TCP_writeSocket
#define TCP_CONNECT         OSX_TCP_connectSocket
#define TCP_getPeerName     OSX_TCP_getPeerName
#define TCP_IS_SOCKET_VALID(s) (s >= 0)

#elif defined __AZURE_TCP__

#define TCP_SOCKET                int
#define TCP_INIT                  THREADX_TCP_init
#define TCP_SHUTDOWN              THREADX_TCP_shutdown
#define TCP_LISTEN_SOCKET         THREADX_TCP_listenSocket
#define TCP_ACCEPT_SOCKET         THREADX_TCP_acceptSocket
#define TCP_CLOSE_SOCKET          THREADX_TCP_closeSocket
#define TCP_READ_AVL              THREADX_TCP_readSocketAvailable
#define TCP_WRITE                 THREADX_TCP_writeSocket
#define TCP_CONNECT               THREADX_TCP_connectSocket
#define TCP_LISTEN_SOCKET_LOCAL   THREADX_TCP_listenSocketLocal
#define TCP_IS_SOCKET_VALID(s)    (s >= 0)

#elif defined __THREADX_TCP__

#include "nx_bsd.h"
#define TCP_SOCKET          int
#define TCP_LISTEN_SOCKET   THREAD_TCP_LISTEN_BSD
#define TCP_INIT            THREADX_TCP_init
#define TCP_SHUTDOWN        THREADX_TCP_shutdown
#define TCP_ACCEPT_SOCKET   THREADX_TCP_BSD_acceptSocket
#define TCP_CLOSE_SOCKET    THREADX_TCP_BSD_closeSocket
#define TCP_READ_AVL        THREADX_TCP_BSD_readSocketAvailable
#define TCP_WRITE           THREADX_TCP_BSD_writeSocket
#define TCP_CONNECT         THREADX_TCP_BSD_connectSocket
#define TCP_IS_SOCKET_VALID(s) (s >= 0)


#elif defined __POSNET_TCP__

#define TCP_SOCKET          int
#define TCP_INIT            POSNET_TCP_init
#define TCP_SHUTDOWN        POSNET_TCP_shutdown
#define TCP_CLOSE_SOCKET    POSNET_TCP_closeSocket
#define TCP_READ_AVL        POSNET_TCP_readSocketAvailable
#define TCP_WRITE           POSNET_TCP_writeSocket
#define TCP_CONNECT         POSNET_TCP_connectSocket
#define TCP_IS_SOCKET_VALID(s) (s >= 0)

#elif defined __OSE_TCP__

#define TCP_SOCKET          int
#define TCP_INIT            OSE_TCP_init
#define TCP_SHUTDOWN        OSE_TCP_shutdown
#define TCP_LISTEN_SOCKET   OSE_TCP_listenSocket
#define TCP_ACCEPT_SOCKET   OSE_TCP_acceptSocket
#define TCP_CLOSE_SOCKET    OSE_TCP_closeSocket
#define TCP_READ_AVL        OSE_TCP_readSocketAvailable
#define TCP_WRITE           OSE_TCP_writeSocket
#define TCP_CONNECT         OSE_TCP_connectSocket
#define TCP_IS_SOCKET_VALID(s) (s >= 0)

#elif defined __RTCS_TCP__

#define TCP_SOCKET          int
#define TCP_INIT            RTCS_TCP_init
#define TCP_SHUTDOWN        RTCS_TCP_shutdown
#define TCP_LISTEN_SOCKET   RTCS_TCP_listenSocket
#define TCP_ACCEPT_SOCKET   RTCS_TCP_acceptSocket
#define TCP_CLOSE_SOCKET    RTCS_TCP_closeSocket
#define TCP_READ_AVL        RTCS_TCP_readSocketAvailable
#define TCP_WRITE           RTCS_TCP_writeSocket
#define TCP_CONNECT         RTCS_TCP_connectSocket
#define TCP_SHARE_SOCKET    RTCS_TCP_shareSocket
#define TCP_IS_SOCKET_VALID(s) (s >= 0)

#elif defined __TRECK_TCP__

#define TCP_SOCKET          int
#define TCP_INIT            TRECK_TCP_init
#define TCP_SHUTDOWN        TRECK_TCP_shutdown
#define TCP_LISTEN_SOCKET   TRECK_TCP_listenSocket
#define TCP_ACCEPT_SOCKET   TRECK_TCP_acceptSocket
#define TCP_CLOSE_SOCKET    TRECK_TCP_closeSocket
#define TCP_READ_AVL        TRECK_TCP_readSocketAvailable
#define TCP_WRITE           TRECK_TCP_writeSocket
#define TCP_CONNECT         TRECK_TCP_connectSocket
#define TCP_IS_SOCKET_VALID(s) (s >= 0)

#elif defined __NETBURNER_TCP__

#define TCP_SOCKET          int
#define TCP_INIT            NETBURNER_TCP_init
#define TCP_SHUTDOWN        NETBURNER_TCP_shutdown
#define TCP_LISTEN_SOCKET   NETBURNER_TCP_listenSocket
#define TCP_ACCEPT_SOCKET   NETBURNER_TCP_acceptSocket
#define TCP_CLOSE_SOCKET    NETBURNER_TCP_closeSocket
#define TCP_READ_AVL        NETBURNER_TCP_readSocketAvailable
#define TCP_WRITE           NETBURNER_TCP_writeSocket
#define TCP_CONNECT         NETBURNER_TCP_connectSocket
#define TCP_IS_SOCKET_VALID(s) (s >= 0)

#elif defined __OPENBSD_TCP__

#define TCP_SOCKET          int
#define TCP_INIT            OPENBSD_TCP_init
#define TCP_SHUTDOWN        OPENBSD_TCP_shutdown
#define TCP_LISTEN_SOCKET   OPENBSD_TCP_listenSocket
#define TCP_ACCEPT_SOCKET   OPENBSD_TCP_acceptSocket
#define TCP_CLOSE_SOCKET    OPENBSD_TCP_closeSocket
#define TCP_READ_AVL        OPENBSD_TCP_readSocketAvailable
#define TCP_WRITE           OPENBSD_TCP_writeSocket
#define TCP_CONNECT         OPENBSD_TCP_connectSocket
#define TCP_getPeerName     OPENBSD_TCP_getPeerName
#define TCP_IS_SOCKET_VALID(s) (s >= 0)

#elif defined __NUTOS_TCP__

#define TCP_SOCKET          void*
#define TCP_INIT            NUTOS_TCP_init
#define TCP_SHUTDOWN        NUTOS_TCP_shutdown
#define TCP_LISTEN_SOCKET   NUTOS_TCP_listenSocket
#define TCP_ACCEPT_SOCKET   NUTOS_TCP_acceptSocket
#define TCP_CLOSE_SOCKET    NUTOS_TCP_closeSocket
#define TCP_READ_AVL        NUTOS_TCP_readSocketAvailable
#define TCP_WRITE           NUTOS_TCP_writeSocket
#define TCP_CONNECT         NUTOS_TCP_connectSocket
#define TCP_IS_SOCKET_VALID(s) (s != NULL)

#elif defined __INTEGRITY_TCP__

#define TCP_SOCKET          int
#define TCP_INIT            INTEGRITY_TCP_init
#define TCP_SHUTDOWN        INTEGRITY_TCP_shutdown
#define TCP_LISTEN_SOCKET   INTEGRITY_TCP_listenSocket
#define TCP_ACCEPT_SOCKET   INTEGRITY_TCP_acceptSocket
#define TCP_CLOSE_SOCKET    INTEGRITY_TCP_closeSocket
#define TCP_READ_AVL        INTEGRITY_TCP_readSocketAvailable
#define TCP_WRITE           INTEGRITY_TCP_writeSocket
#define TCP_CONNECT         INTEGRITY_TCP_connectSocket
#define TCP_getPeerName     INTEGRITY_TCP_getPeerName
#define TCP_IS_SOCKET_VALID(s) (s >= 0)

#elif defined __ANDROID_TCP__

#define TCP_SOCKET          int
#define TCP_INIT            ANDROID_TCP_init
#define TCP_SHUTDOWN        ANDROID_TCP_shutdown
#define TCP_LISTEN_SOCKET   ANDROID_TCP_listenSocket
#define TCP_ACCEPT_SOCKET   ANDROID_TCP_acceptSocket
#define TCP_CLOSE_SOCKET    ANDROID_TCP_closeSocket
#define TCP_READ_AVL        ANDROID_TCP_readSocketAvailable
#define TCP_WRITE           ANDROID_TCP_writeSocket
#define TCP_CONNECT         ANDROID_TCP_connectSocket
#define TCP_getPeerName     ANDROID_TCP_getPeerName
#define TCP_IS_SOCKET_VALID(s) (s >= 0)

#elif defined __FREEBSD_TCP__

#define TCP_SOCKET          int
#define TCP_INIT            FREEBSD_TCP_init
#define TCP_SHUTDOWN        FREEBSD_TCP_shutdown
#define TCP_LISTEN_SOCKET   FREEBSD_TCP_listenSocket
#define TCP_ACCEPT_SOCKET   FREEBSD_TCP_acceptSocket
#define TCP_CLOSE_SOCKET    FREEBSD_TCP_closeSocket
#define TCP_READ_AVL        FREEBSD_TCP_readSocketAvailable
#define TCP_WRITE           FREEBSD_TCP_writeSocket
#define TCP_CONNECT         FREEBSD_TCP_connectSocket
#define TCP_IS_SOCKET_VALID(s) (s >= 0)

#elif defined __IRIX_TCP__

#define TCP_SOCKET          int
#define TCP_INIT            IRIX_TCP_init
#define TCP_SHUTDOWN        IRIX_TCP_shutdown
#define TCP_LISTEN_SOCKET   IRIX_TCP_listenSocket
#define TCP_ACCEPT_SOCKET   IRIX_TCP_acceptSocket
#define TCP_CLOSE_SOCKET    IRIX_TCP_closeSocket
#define TCP_READ_AVL        IRIX_TCP_readSocketAvailable
#define TCP_WRITE           IRIX_TCP_writeSocket
#define TCP_CONNECT         IRIX_TCP_connectSocket
#define TCP_IS_SOCKET_VALID(s) (s >= 0)

#elif defined __QNX_TCP__

#define TCP_SOCKET          int
#define TCP_INIT            QNX_TCP_init
#define TCP_SHUTDOWN        QNX_TCP_shutdown
#define TCP_LISTEN_SOCKET   QNX_TCP_listenSocket
#define TCP_ACCEPT_SOCKET   QNX_TCP_acceptSocket
#define TCP_CLOSE_SOCKET    QNX_TCP_closeSocket
#define TCP_READ_AVL        QNX_TCP_readSocketAvailable
#define TCP_WRITE           QNX_TCP_writeSocket
#define TCP_CONNECT         QNX_TCP_connectSocket
#define TCP_getPeerName     QNX_TCP_getPeerName
#define TCP_IS_SOCKET_VALID(s) (s >= 0)

#elif defined __UITRON_TCP__

typedef struct
{
    intBoolean      isListenSocket;
    ubyte2          srcPortNumber;

    intBoolean      isConnected;
    MOC_IP_ADDRESS_S dstAddress;
    ubyte2          dstPortNumber;

    signed int      repId;
    signed int      cepId;

} uitronSocketDescr;

typedef uitronSocketDescr*  uitronSocketDescrPtr;

#define TCP_SOCKET          uitronSocketDescrPtr
#define TCP_INIT            UITRON_TCP_init
#define TCP_SHUTDOWN        UITRON_TCP_shutdown
#define TCP_LISTEN_SOCKET   UITRON_TCP_listenSocket
#define TCP_ACCEPT_SOCKET   UITRON_TCP_acceptSocket
#define TCP_CLOSE_SOCKET    UITRON_TCP_closeSocket
#define TCP_READ_AVL        UITRON_TCP_readSocketAvailable
#define TCP_WRITE           UITRON_TCP_writeSocket
#define TCP_CONNECT         UITRON_TCP_connectSocket
#define TCP_getPeerName     UITRON_TCP_getPeerName
#define TCP_IS_SOCKET_VALID(s) (s != NULL)

#elif defined __WINCE_TCP__

#ifndef INVALID_SOCKET
#define INVALID_SOCKET  (~0)
#endif

#define TCP_SOCKET          unsigned int
#define TCP_INIT            WINCE_TCP_init
#define TCP_SHUTDOWN        WINCE_TCP_shutdown
#define TCP_LISTEN_SOCKET   WINCE_TCP_listenSocket
#define TCP_ACCEPT_SOCKET   WINCE_TCP_acceptSocket
#define TCP_CLOSE_SOCKET    WINCE_TCP_closeSocket
#define TCP_READ_AVL        WINCE_TCP_readSocketAvailable
#define TCP_WRITE           WINCE_TCP_writeSocket
#define TCP_CONNECT         WINCE_TCP_connectSocket
#define TCP_getPeerName     WINCE_TCP_getPeerName
#define TCP_IS_SOCKET_VALID(s) (s != INVALID_SOCKET)

#elif defined __WTOS_TCP__

#define TCP_SOCKET          int
#define TCP_INIT            WTOS_TCP_init
#define TCP_SHUTDOWN        WTOS_TCP_shutdown
#define TCP_LISTEN_SOCKET   WTOS_TCP_listenSocket
#define TCP_ACCEPT_SOCKET   WTOS_TCP_acceptSocket
#define TCP_CLOSE_SOCKET    WTOS_TCP_closeSocket
#define TCP_READ_AVL        WTOS_TCP_readSocketAvailable
#define TCP_WRITE           WTOS_TCP_writeSocket
#define TCP_CONNECT         WTOS_TCP_connectSocket
#define TCP_IS_SOCKET_VALID(s) (s >= 0)

#elif defined __ECOS_TCP__

#define TCP_SOCKET          int
#define TCP_INIT            ECOS_TCP_init
#define TCP_SHUTDOWN        ECOS_TCP_shutdown
#define TCP_LISTEN_SOCKET   ECOS_TCP_listenSocket
#define TCP_ACCEPT_SOCKET   ECOS_TCP_acceptSocket
#define TCP_CLOSE_SOCKET    ECOS_TCP_closeSocket
#define TCP_READ_AVL        ECOS_TCP_readSocketAvailable
#define TCP_WRITE           ECOS_TCP_writeSocket
#define TCP_CONNECT         ECOS_TCP_connectSocket
#define TCP_IS_SOCKET_VALID(s) (s >= 0)

#elif defined __AIX_TCP__

#define TCP_SOCKET          int
#define TCP_INIT            AIX_TCP_init
#define TCP_SHUTDOWN        AIX_TCP_shutdown
#define TCP_LISTEN_SOCKET   AIX_TCP_listenSocket
#define TCP_ACCEPT_SOCKET   AIX_TCP_acceptSocket
#define TCP_CLOSE_SOCKET    AIX_TCP_closeSocket
#define TCP_READ_AVL        AIX_TCP_readSocketAvailable
#define TCP_WRITE           AIX_TCP_writeSocket
#define TCP_CONNECT         AIX_TCP_connectSocket
#define TCP_getPeerName     AIX_TCP_getPeerName
#define TCP_IS_SOCKET_VALID(s) (s >= 0)

#elif defined __HPUX_TCP__

#define TCP_SOCKET          int
#define TCP_INIT            HPUX_TCP_init
#define TCP_SHUTDOWN        HPUX_TCP_shutdown
#define TCP_LISTEN_SOCKET   HPUX_TCP_listenSocket
#define TCP_ACCEPT_SOCKET   HPUX_TCP_acceptSocket
#define TCP_CLOSE_SOCKET    HPUX_TCP_closeSocket
#define TCP_READ_AVL        HPUX_TCP_readSocketAvailable
#define TCP_WRITE           HPUX_TCP_writeSocket
#define TCP_CONNECT         HPUX_TCP_connectSocket
#define TCP_getPeerName     HPUX_TCP_getPeerName
#define TCP_IS_SOCKET_VALID(s) (s >= 0)

#elif defined __MICROCHIP_BSD_TCP__

#define TCP_SOCKET          char
#define TCP_INIT            MICROCHIP_TCP_init
#define TCP_SHUTDOWN        MICROCHIP_TCP_shutdown
#define TCP_LISTEN_SOCKET   MICROCHIP_TCP_listenSocket
#define TCP_ACCEPT_SOCKET   MICROCHIP_TCP_acceptSocket
#define TCP_CLOSE_SOCKET    MICROCHIP_TCP_closeSocket
#define TCP_READ_AVL        MICROCHIP_TCP_readSocketAvailable
#define TCP_WRITE           MICROCHIP_TCP_writeSocket
#define TCP_CONNECT         MICROCHIP_TCP_connectSocket
#define TCP_IS_SOCKET_VALID(s) (s >= 0)

#elif defined __UCOS_TCP__

#define TCP_SOCKET          char
#define TCP_INIT            UCOS_TCP_init
#define TCP_SHUTDOWN        UCOS_TCP_shutdown
#define TCP_LISTEN_SOCKET   UCOS_TCP_listenSocket
#define TCP_ACCEPT_SOCKET   UCOS_TCP_acceptSocket
#define TCP_CLOSE_SOCKET    UCOS_TCP_closeSocket
#define TCP_READ_AVL        UCOS_TCP_readSocketAvailable
#define TCP_WRITE           UCOS_TCP_writeSocket
#define TCP_CONNECT         UCOS_TCP_connectSocket
#define TCP_IS_SOCKET_VALID(s) (s >= 0)

#elif defined __UCOS_DIRECT_TCP__

#define TCP_SOCKET          int
#define TCP_INIT            UCOS_TCP_init
#define TCP_SHUTDOWN        UCOS_TCP_shutdown
#define TCP_LISTEN_SOCKET   UCOS_TCP_listenSocket
#define TCP_ACCEPT_SOCKET   UCOS_TCP_acceptSocket
#define TCP_CLOSE_SOCKET    UCOS_TCP_closeSocket
#define TCP_READ_AVL        UCOS_TCP_readSocketAvailable
#define TCP_WRITE           UCOS_TCP_writeSocket
#define TCP_CONNECT         UCOS_TCP_connectSocket
#define TCP_IS_SOCKET_VALID(s) (s >= 0)

#elif defined __LWIP_TCP__

#define TCP_SOCKET          int
#define TCP_INIT            LWIP_TCP_init
#define TCP_SHUTDOWN        LWIP_TCP_shutdown
#define TCP_LISTEN_SOCKET   LWIP_TCP_listenSocket
#define TCP_LISTEN_SOCKET_LOCAL   LWIP_TCP_listenSocketLocal
#define TCP_ACCEPT_SOCKET   LWIP_TCP_acceptSocket
#define TCP_CLOSE_SOCKET    LWIP_TCP_closeSocket
#define TCP_READ_AVL        LWIP_TCP_readSocketAvailable
#define TCP_WRITE           LWIP_TCP_writeSocket
#define TCP_CONNECT         LWIP_TCP_connectSocket
#define TCP_IS_SOCKET_VALID(s) (s >= 0)

#elif defined __FREERTOS_TCP__

#ifdef __FREERTOS_SIMULATOR__
#define TCP_SOCKET          void *
#else
typedef void *Socket_t;
#define TCP_SOCKET          Socket_t
#endif

#define TCP_INIT            FREERTOS_TCP_init
#define TCP_SHUTDOWN        FREERTOS_TCP_shutdown
#define TCP_LISTEN_SOCKET   FREERTOS_TCP_listenSocket
#define TCP_LISTEN_SOCKET_LOCAL   FREERTOS_TCP_listenSocketLocal
#define TCP_ACCEPT_SOCKET   FREERTOS_TCP_acceptSocket
#define TCP_CLOSE_SOCKET    FREERTOS_TCP_closeSocket
#define TCP_READ_AVL        FREERTOS_TCP_readSocketAvailable
#define TCP_WRITE           FREERTOS_TCP_writeSocket
#define TCP_CONNECT         FREERTOS_TCP_connectSocket
#define TCP_IS_SOCKET_VALID(s) (s != 0)

#elif defined __DEOS_TCP__

#define TCP_SOCKET          int
#define TCP_INIT            DEOS_TCP_init
#define TCP_SHUTDOWN        DEOS_TCP_shutdown
#define TCP_LISTEN_SOCKET   DEOS_TCP_listenSocket
#define TCP_ACCEPT_SOCKET   DEOS_TCP_acceptSocket
#define TCP_CLOSE_SOCKET    DEOS_TCP_closeSocket
#define TCP_READ_AVL        DEOS_TCP_readSocketAvailable
#define TCP_WRITE           DEOS_TCP_writeSocket
#define TCP_CONNECT         DEOS_TCP_connectSocket
#define TCP_getPeerName     DEOS_TCP_getPeerName
#define TCP_IS_SOCKET_VALID(s) (s >= 0)

#elif defined __DUMMY_TCP__

#define TCP_SOCKET          int
#define TCP_INIT            DUMMY_TCP_init
#define TCP_SHUTDOWN        DUMMY_TCP_shutdown
#define TCP_LISTEN_SOCKET   DUMMY_TCP_listenSocket
#define TCP_ACCEPT_SOCKET   DUMMY_TCP_acceptSocket
#define TCP_CLOSE_SOCKET    DUMMY_TCP_closeSocket
#define TCP_READ_AVL        DUMMY_TCP_readSocketAvailable
#define TCP_WRITE           DUMMY_TCP_writeSocket
#define TCP_CONNECT         DUMMY_TCP_connectSocket
#define TCP_IS_SOCKET_VALID(s) (s >= 0)

#elif defined __WIZNET_TCP__

#define TCP_SOCKET          char
#define TCP_INIT            FREERTOS_TCP_init
#define TCP_SHUTDOWN        FREERTOS_TCP_shutdown
#define TCP_LISTEN_SOCKET   FREERTOS_TCP_listenSocket
#define TCP_ACCEPT_SOCKET   FREERTOS_TCP_acceptSocket
#define TCP_CLOSE_SOCKET    FREERTOS_TCP_closeSocket
#define TCP_READ_AVL        FREERTOS_TCP_readSocketAvailable
#define TCP_WRITE           FREERTOS_TCP_writeSocket
#define TCP_CONNECT         FREERTOS_TCP_connectSocket
#define TCP_IS_SOCKET_VALID(s) (s > 0)

#else

#error UNSUPPORTED PLATFORM

#endif
#endif

#if defined __DIGICERT_TCP__

#define MOC_TCP_SOCKET          int
#define DIGI_TCP_INIT            MO_TCP_init
#define DIGI_TCP_SHUTDOWN        MO_TCP_shutdown
#define DIGI_TCP_LISTEN_SOCKET   MO_TCP_listenSocket
#define DIGI_TCP_ACCEPT_SOCKET   MO_TCP_acceptSocket
#define DIGI_TCP_CLOSE_SOCKET    MO_TCP_closeSocket
#define DIGI_TCP_READ_AVL        MO_TCP_readSocketAvailable
#define DIGI_TCP_WRITE           MO_TCP_writeSocket
#define DIGI_TCP_CONNECT         MO_TCP_connectSocket

#endif


MOC_EXTERN MSTATUS TCP_INIT         (void);
MOC_EXTERN MSTATUS TCP_SHUTDOWN     (void);
MOC_EXTERN MSTATUS TCP_LISTEN_SOCKET(TCP_SOCKET *socket, ubyte2 portNumber);
MOC_EXTERN MSTATUS TCP_LISTEN_SOCKET_LOCAL(TCP_SOCKET *socket, ubyte2 portNumber);
MOC_EXTERN MSTATUS TCP_LISTEN_SOCKET_ADDR(TCP_SOCKET *pSocket, sbyte *pIpAddress, ubyte2 portNumber);
MOC_EXTERN MSTATUS TCP_ACCEPT_SOCKET(TCP_SOCKET *clientSocket, TCP_SOCKET listenSocket, intBoolean *isBreakSignalRequest);
MOC_EXTERN MSTATUS TCP_ACCEPT_SOCKET_TIMEOUT(TCP_SOCKET *clientSocket, TCP_SOCKET listenSocket, ubyte4 timeoutSeconds);
#ifndef __THREADX_TCP__
MOC_EXTERN MSTATUS TCP_CONNECT      (TCP_SOCKET *pConnectSocket, sbyte *pIpAddress, ubyte2 portNo);
#else
MOC_EXTERN MSTATUS TCP_CONNECT      (TCP_SOCKET *pConnectSocket, sbyte *ipAddress, ubyte2 portNo);
#endif
MOC_EXTERN MSTATUS TCP_CONNECT_TIMEOUT (TCP_SOCKET *pConnectSocket, sbyte *ipAddress, ubyte2 portNo, ubyte4 msTimeout);
MOC_EXTERN MSTATUS TCP_CLOSE_SOCKET (TCP_SOCKET socket);

MOC_EXTERN MSTATUS TCP_READ_AVL     (TCP_SOCKET socket, sbyte *pBuffer, ubyte4 maxBytesToRead,  ubyte4 *pNumBytesRead, ubyte4 msTimeout);
MOC_EXTERN MSTATUS TCP_READ_AVL_EX  (TCP_SOCKET socket, sbyte *pBuffer, ubyte4 maxBytesToRead,  ubyte4 *pNumBytesRead, ubyte4 msTimeout);
MOC_EXTERN MSTATUS TCP_WRITE        (TCP_SOCKET socket, sbyte *pBuffer, ubyte4 numBytesToWrite, ubyte4 *pNumBytesWritten);

MOC_EXTERN MSTATUS TCP_READ_ALL     (TCP_SOCKET socket, sbyte *pBuffer, ubyte4 maxBytesToRead,  ubyte4 *pNumBytesRead, ubyte4 msTimeout);
MOC_EXTERN MSTATUS TCP_WRITE_ALL    (TCP_SOCKET socket, sbyte *pBuffer, ubyte4 numBytesToWrite, ubyte4 *pNumBytesWritten);
MOC_EXTERN MSTATUS TCP_getPeerName  (TCP_SOCKET socket, ubyte2 *portNo, MOC_IP_ADDRESS_S *addr);


MOC_EXTERN MSTATUS DIGI_TCP_INIT         (void);
MOC_EXTERN MSTATUS DIGI_TCP_SHUTDOWN     (void);
MOC_EXTERN MSTATUS DIGI_TCP_LISTEN_SOCKET(TCP_SOCKET *socket, ubyte2 portNumber);
MOC_EXTERN MSTATUS DIGI_TCP_ACCEPT_SOCKET(TCP_SOCKET *clientSocket, TCP_SOCKET listenSocket, intBoolean *isBreakSignalRequest);
MOC_EXTERN MSTATUS DIGI_TCP_CLOSE_SOCKET (TCP_SOCKET socket);
MOC_EXTERN MSTATUS DIGI_TCP_READ_AVL     (TCP_SOCKET socket, sbyte *pBuffer, ubyte4 maxBytesToRead,  ubyte4 *pNumBytesRead, ubyte4 msTimeout);
MOC_EXTERN MSTATUS DIGI_TCP_WRITE        (TCP_SOCKET socket, sbyte *pBuffer, ubyte4 numBytesToWrite, ubyte4 *pNumBytesWritten);
MOC_EXTERN MSTATUS DIGI_TCP_CONNECT      (TCP_SOCKET *pConnectSocket, sbyte *pIpAddress, ubyte2 portNo);

MOC_EXTERN MSTATUS UNIXDOMAIN_CONNECT   (TCP_SOCKET *socket, sbyte *soc_path);
MOC_EXTERN MSTATUS UNIXDOMAIN_ACCEPT    (TCP_SOCKET *clientSocket, TCP_SOCKET listenSocket, intBoolean *isBreakSignalRequest);
MOC_EXTERN MSTATUS UNIXDOMAIN_LISTEN    (TCP_SOCKET *listenSocket, sbyte *soc_path);
MOC_EXTERN MSTATUS UNIXDOMAIN_CLOSE     (TCP_SOCKET socket);

#ifdef TCP_SHARE_SOCKET
MOC_EXTERN MSTATUS TCP_SHARE_SOCKET (TCP_SOCKET socket);
#endif

/*----------------------------------------------------------------------------*/

/* These macros expand to call init and uninit if enabled, otherwise they expand
 * to do nothing.
 */
#if !(defined(__KERNEL__) || defined(_KERNEL) || defined(IPCOM_KERNEL))
#if !defined(__DISABLE_DIGICERT_TCP_INTERFACE__)

/**
 * @def      MOC_CHECK_TCP_INIT(_status)
 * @details  This macro will initialize the TCP interface.
 *
 * @param _status   The \ref MSTATUS value for return from the calling function.
 *
 * @par Flags
 * To enable this macro, \b both conditions 1 and 2 must be met:
 *   1. The following flags must \b not be defined:
 *     + \c \__DISABLE_DIGICERT_TCP_INTERFACE__
 *     .
 *   2. At least \b one of the following conditions must be met:
 *     + \c \__KERNEL__   must \b not be defined
 *     + \c _KERNEL       \b must be defined
 *     + \c IPCOM_KERNEL  \b must be defined
 */
#define MOC_CHECK_TCP_INIT(_status)                                            \
    _status = TCP_INIT ();                                                     \
    if (OK != _status)                                                         \
      goto exit;

/**
 * @def      MOC_CHECK_TCP_SHUTDOWN(_status,_dStatus)
 * @details  This macro will shutdown the TCP interface.
 *
 * @param _status   The \ref MSTATUS value for return from the calling function.
 * @param _dStatus  The temporary placeholder status used to check return values.
 *
 * @par Flags
 * To enable this macro, \b both conditions 1 and 2 must be met:
 *   1. The following flags must \b not be defined:
 *     + \c \__DISABLE_DIGICERT_TCP_INTERFACE__
 *     .
 *   2. At least \b one of the following conditions must be met:
 *     + \c \__KERNEL__   must \b not be defined
 *     + \c _KERNEL       \b must be defined
 *     + \c IPCOM_KERNEL  \b must be defined
 */
#define MOC_CHECK_TCP_SHUTDOWN(_status,_dStatus)                               \
    _dStatus = TCP_SHUTDOWN ();                                                \
    if (OK != _dStatus)                                                        \
      _status = _dStatus;

#endif /* !defined(__DISABLE_DIGICERT_TCP_INTERFACE__) */
#endif /* !defined(__KERNEL__) etc */

#ifndef MOC_CHECK_TCP_INIT
#define MOC_CHECK_TCP_INIT(_status)
#endif
#ifndef MOC_CHECK_TCP_SHUTDOWN
#define MOC_CHECK_TCP_SHUTDOWN(_status,_dStatus)
#endif

#ifdef __cplusplus
}
#endif

#endif /* __MTCP_HEADER__ */
