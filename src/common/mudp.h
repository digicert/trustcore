/**
 * @file   mudp.h
 * @brief  Mocana UDP Abstraction Layer
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

#ifndef __MUDP_HEADER__
#define __MUDP_HEADER__

#include "../common/mudp_custom.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MOC_UDP_ANY_PORT    (0)
#define MOC_UDP_ANY_ADDR    (0)

#if !defined(__CUSTOM_UDP__)

#if defined __SOLARIS_UDP__

#define UDP_SOCKET          int
#define UDP_init            SOLARIS_UDP_init
#define UDP_shutdown        SOLARIS_UDP_shutdown
#define UDP_getIfAddr       SOLARIS_UDP_getInterfaceAddress
#define UDP_getAddrOfHost   SOLARIS_UDP_getAddressOfHost
#define UDP_simpleBind      SOLARIS_UDP_simpleBind
#define UDP_connect         SOLARIS_UDP_connect
#define UDP_unbind          SOLARIS_UDP_unbind
#define UDP_send            SOLARIS_UDP_send
#define UDP_recv            SOLARIS_UDP_recv
#define UDP_sendTo          SOLARIS_UDP_sendTo
#define UDP_recvFrom        SOLARIS_UDP_recvFrom
#define UDP_getSrcPortAddr  SOLARIS_UDP_getSrcPortAddr
#define UDP_getFd           SOLARIS_UDP_getFd

#elif defined __LINUX_UDP__

#define UDP_SOCKET          int
#define UDP_init            LINUX_UDP_init
#define UDP_shutdown        LINUX_UDP_shutdown
#define UDP_getIfAddr       LINUX_UDP_getInterfaceAddress
#define UDP_getAddrOfHost   LINUX_UDP_getAddressOfHost
#define UDP_simpleBind      LINUX_UDP_simpleBind
#define UDP_connect         LINUX_UDP_connect
#define UDP_unbind          LINUX_UDP_unbind
#define UDP_send            LINUX_UDP_send
#define UDP_recv            LINUX_UDP_recv
#define UDP_sendTo          LINUX_UDP_sendTo
#define UDP_recvFrom        LINUX_UDP_recvFrom
#define UDP_getSrcPortAddr  LINUX_UDP_getSrcPortAddr
#define UDP_getFd           LINUX_UDP_getFd
#define UDP_selReadAvl      LINUX_UDP_selReadAvl


#elif defined __SYMBIAN_UDP__

#define UDP_SOCKET          int
#define UDP_init            SYMBIAN_UDP_init
#define UDP_shutdown        SYMBIAN_UDP_shutdown
#define UDP_getIfAddr       SYMBIAN_UDP_getInterfaceAddress
#define UDP_getAddrOfHost   SYMBIAN_UDP_getAddressOfHost
#define UDP_simpleBind      SYMBIAN_UDP_simpleBind
#define UDP_connect         SYMBIAN_UDP_connect
#define UDP_unbind          SYMBIAN_UDP_unbind
#define UDP_send            SYMBIAN_UDP_send
#define UDP_recv            SYMBIAN_UDP_recv
#define UDP_sendTo          SYMBIAN_UDP_sendTo
#define UDP_recvFrom        SYMBIAN_UDP_recvFrom
#define UDP_getSrcPortAddr  SYMBIAN_UDP_getSrcPortAddr
#define UDP_getFd           SYMBIAN_UDP_getFd
#define UDP_selReadAvl      SYMBIAN_UDP_selReadAvl

#elif defined __WIN32_UDP__

#define UDP_SOCKET          unsigned int
#define UDP_init            WIN32_UDP_init
#define UDP_shutdown        WIN32_UDP_shutdown
#define UDP_getIfAddr       WIN32_UDP_getInterfaceAddress
#define UDP_getAddrOfHost   WIN32_UDP_getAddressOfHost
#define UDP_simpleBind      WIN32_UDP_simpleBind
#define UDP_connect         WIN32_UDP_connect
#define UDP_unbind          WIN32_UDP_unbind
#define UDP_send            WIN32_UDP_send
#define UDP_recv            WIN32_UDP_recv
#define UDP_sendTo          WIN32_UDP_sendTo
#define UDP_recvFrom        WIN32_UDP_recvFrom
#define UDP_getSrcPortAddr  WIN32_UDP_getSrcPortAddr
#define UDP_getFd           WIN32_UDP_getFd
#define UDP_selReadAvl      WIN32_UDP_selReadAvl

#elif defined __VXWORKS_UDP__

#define UDP_SOCKET          int
#define UDP_init            VXWORKS_UDP_init
#define UDP_shutdown        VXWORKS_UDP_shutdown
#define UDP_getIfAddr       VXWORKS_UDP_getInterfaceAddress
#define UDP_getAddrOfHost   VXWORKS_UDP_getAddressOfHost
#define UDP_simpleBind      VXWORKS_UDP_simpleBind
#define UDP_connect         VXWORKS_UDP_connect
#define UDP_unbind          VXWORKS_UDP_unbind
#define UDP_send            VXWORKS_UDP_send
#define UDP_recv            VXWORKS_UDP_recv
#define UDP_sendTo          VXWORKS_UDP_sendTo
#define UDP_recvFrom        VXWORKS_UDP_recvFrom
#define UDP_getFd           VXWORKS_UDP_getFd
#define UDP_selReadAvl      VXWORKS_UDP_selReadAvl
#define UDP_getSrcPortAddr  VXWORKS_UDP_getSrcPortAddr

#elif defined __PSOS_UDP__

#define UDP_SOCKET          int
#define UDP_init            PSOS_UDP_init
#define UDP_shutdown        PSOS_UDP_shutdown
#define UDP_getIfAddr       PSOS_UDP_getInterfaceAddress
#define UDP_getAddrOfHost   PSOS_UDP_getAddressOfHost
#define UDP_simpleBind      PSOS_UDP_simpleBind
#define UDP_connect         PSOS_UDP_connect
#define UDP_unbind          PSOS_UDP_unbind
#define UDP_send            PSOS_UDP_send
#define UDP_recv            PSOS_UDP_recv
#define UDP_sendTo          PSOS_UDP_sendTo
#define UDP_recvFrom        PSOS_UDP_recvFrom
#define UDP_getSrcPortAddr  PSOS_UDP_getSrcPortAddr

#elif defined __TRECK_UDP__

#define UDP_SOCKET          int
#define UDP_init            TRECK_UDP_init
#define UDP_shutdown        TRECK_UDP_shutdown
#define UDP_getIfAddr       TRECK_UDP_getInterfaceAddress
#define UDP_getAddrOfHost   TRECK_UDP_getAddressOfHost
#define UDP_simpleBind      TRECK_UDP_simpleBind
#define UDP_connect         TRECK_UDP_connect
#define UDP_unbind          TRECK_UDP_unbind
#define UDP_send            TRECK_UDP_send
#define UDP_recv            TRECK_UDP_recv
#define UDP_sendTo          TRECK_UDP_sendTo
#define UDP_recvFrom        TRECK_UDP_recvFrom
#define UDP_getSrcPortAddr  TRECK_UDP_getSrcPortAddr
#define UDP_getFd           TRECK_UDP_getFd
#define UDP_selReadAvl      TRECK_UDP_selReadAvl

#elif defined __NETBURNER_UDP__

#define UDP_SOCKET          int
#define UDP_init            NETBURNER_UDP_init
#define UDP_shutdown        NETBURNER_UDP_shutdown
#define UDP_getIfAddr       NETBURNER_UDP_getInterfaceAddress
#define UDP_getAddrOfHost   NETBURNER_UDP_getAddressOfHost
#define UDP_simpleBind      NETBURNER_UDP_simpleBind
#define UDP_connect         NETBURNER_UDP_connect
#define UDP_unbind          NETBURNER_UDP_unbind
#define UDP_send            NETBURNER_UDP_send
#define UDP_recv            NETBURNER_UDP_recv
#define UDP_sendTo          NETBURNER_UDP_sendTo
#define UDP_recvFrom        NETBURNER_UDP_recvFrom

#elif defined __CYGWIN_UDP__

#define UDP_SOCKET          int
#define UDP_init            CYGWIN_UDP_init
#define UDP_shutdown        CYGWIN_UDP_shutdown
#define UDP_getIfAddr       CYGWIN_UDP_getInterfaceAddress
#define UDP_getAddrOfHost   CYGWIN_UDP_getAddressOfHost
#define UDP_simpleBind      CYGWIN_UDP_simpleBind
#define UDP_connect         CYGWIN_UDP_connect
#define UDP_unbind          CYGWIN_UDP_unbind
#define UDP_send            CYGWIN_UDP_send
#define UDP_recv            CYGWIN_UDP_recv
#define UDP_sendTo          CYGWIN_UDP_sendTo
#define UDP_recvFrom        CYGWIN_UDP_recvFrom
#define UDP_getSrcPortAddr  CYGWIN_UDP_getSrcPortAddr
#define UDP_getFd           CYGWIN_UDP_getFd
#define UDP_selReadAvl      CYGWIN_UDP_selReadAvl

#elif defined __OSX_UDP__

#define UDP_SOCKET          int
#define UDP_init            OSX_UDP_init
#define UDP_shutdown        OSX_UDP_shutdown
#define UDP_getIfAddr       OSX_UDP_getInterfaceAddress
#define UDP_getAddrOfHost   OSX_UDP_getAddressOfHost
#define UDP_simpleBind      OSX_UDP_simpleBind
#define UDP_connect         OSX_UDP_connect
#define UDP_unbind          OSX_UDP_unbind
#define UDP_send            OSX_UDP_send
#define UDP_recv            OSX_UDP_recv
#define UDP_sendTo          OSX_UDP_sendTo
#define UDP_recvFrom        OSX_UDP_recvFrom
#define UDP_getFd           OSX_UDP_getFd
#define UDP_getSrcPortAddr  OSX_UDP_getSrcPortAddr
#define UDP_selReadAvl      OSX_UDP_selReadAvl

#elif defined __OSE_UDP__

#define UDP_SOCKET          int
#define UDP_init            OSE_UDP_init
#define UDP_shutdown        OSE_UDP_shutdown
#define UDP_getIfAddr       OSE_UDP_getInterfaceAddress
#define UDP_getAddrOfHost   OSE_UDP_getAddressOfHost
#define UDP_simpleBind      OSE_UDP_simpleBind
#define UDP_connect         OSE_UDP_connect
#define UDP_unbind          OSE_UDP_unbind
#define UDP_send            OSE_UDP_send
#define UDP_recv            OSE_UDP_recv
#define UDP_sendTo          OSE_UDP_sendTo
#define UDP_recvFrom        OSE_UDP_recvFrom
#define UDP_getSrcPortAddr  OSE_UDP_getSrcPortAddr
#define UDP_getFd           OSE_UDP_getFd
#define UDP_selReadAvl      OSE_UDP_selReadAvl

#elif defined __OPENBSD_UDP__

#define UDP_SOCKET          int
#define UDP_init            OPENBSD_UDP_init
#define UDP_shutdown        OPENBSD_UDP_shutdown
#define UDP_getIfAddr       OPENBSD_UDP_getInterfaceAddress
#define UDP_getAddrOfHost   OPENBSD_UDP_getAddressOfHost
#define UDP_simpleBind      OPENBSD_UDP_simpleBind
#define UDP_connect         OPENBSD_UDP_connect
#define UDP_unbind          OPENBSD_UDP_unbind
#define UDP_send            OPENBSD_UDP_send
#define UDP_recv            OPENBSD_UDP_recv
#define UDP_sendTo          OPENBSD_UDP_sendTo
#define UDP_recvFrom        OPENBSD_UDP_recvFrom
#define UDP_getSrcPortAddr  OPENBSD_UDP_getSrcPortAddr
#define UDP_selReadAvl      OPENBSD_UDP_selReadAvl

#elif defined __LWIP_UDP__

#define UDP_SOCKET          int
#define UDP_init            LWIP_UDP_init
#define UDP_shutdown        LWIP_UDP_shutdown
#define UDP_getIfAddr       LWIP_UDP_getInterfaceAddress
#define UDP_getAddrOfHost   LWIP_UDP_getAddressOfHost
#define UDP_simpleBind      LWIP_UDP_simpleBind
#define UDP_connect         LWIP_UDP_connect
#define UDP_unbind          LWIP_UDP_unbind
#define UDP_send            LWIP_UDP_send
#define UDP_recv            LWIP_UDP_recv
#define UDP_sendTo          LWIP_UDP_sendTo
#define UDP_recvFrom        LWIP_UDP_recvFrom
#define UDP_getSrcPortAddr  LWIP_UDP_getSrcPortAddr
#define UDP_selReadAvl      LWIP_UDP_selReadAvl
#define UDP_getFd           LWIP_UDP_getFd

#elif defined __FREERTOS_UDP__

typedef void *Socket_t;

#define UDP_SOCKET          Socket_t
#define UDP_init            FREERTOS_UDP_init
#define UDP_shutdown        FREERTOS_UDP_shutdown
#define UDP_getIfAddr       FREERTOS_UDP_getInterfaceAddress
#define UDP_getAddrOfHost   FREERTOS_UDP_getAddressOfHost
#define UDP_simpleBind      FREERTOS_UDP_simpleBind
#define UDP_connect         FREERTOS_UDP_connect
#define UDP_unbind          FREERTOS_UDP_unbind
#define UDP_send            FREERTOS_UDP_send
#define UDP_recv            FREERTOS_UDP_recv
#define UDP_sendTo          FREERTOS_UDP_sendTo
#define UDP_recvFrom        FREERTOS_UDP_recvFrom
#define UDP_getSrcPortAddr  FREERTOS_UDP_getSrcPortAddr
#define UDP_selReadAvl      FREERTOS_UDP_selReadAvl
#define UDP_getFd           FREERTOS_UDP_getFd


#elif defined __INTEGRITY_UDP__

#define UDP_SOCKET          int
#define UDP_init            INTEGRITY_UDP_init
#define UDP_shutdown        INTEGRITY_UDP_shutdown
#define UDP_getIfAddr       INTEGRITY_UDP_getInterfaceAddress
#define UDP_getAddrOfHost   INTEGRITY_UDP_getAddressOfHost
#define UDP_simpleBind      INTEGRITY_UDP_simpleBind
#define UDP_connect         INTEGRITY_UDP_connect
#define UDP_unbind          INTEGRITY_UDP_unbind
#define UDP_send            INTEGRITY_UDP_send
#define UDP_recv            INTEGRITY_UDP_recv
#define UDP_sendTo          INTEGRITY_UDP_sendTo
#define UDP_recvFrom        INTEGRITY_UDP_recvFrom
#define UDP_getSrcPortAddr  INTEGRITY_UDP_getSrcPortAddr
#define UDP_getFd           INTEGRITY_UDP_getFd
#define UDP_selReadAvl      INTEGRITY_UDP_selReadAvl

#elif defined __ANDROID_UDP__

#define UDP_SOCKET          int
#define UDP_init            ANDROID_UDP_init
#define UDP_shutdown        ANDROID_UDP_shutdown
#define UDP_getIfAddr       ANDROID_UDP_getInterfaceAddress
#define UDP_getAddrOfHost   ANDROID_UDP_getAddressOfHost
#define UDP_simpleBind      ANDROID_UDP_simpleBind
#define UDP_connect         ANDROID_UDP_connect
#define UDP_unbind          ANDROID_UDP_unbind
#define UDP_send            ANDROID_UDP_send
#define UDP_recv            ANDROID_UDP_recv
#define UDP_sendTo          ANDROID_UDP_sendTo
#define UDP_recvFrom        ANDROID_UDP_recvFrom
#define UDP_getSrcPortAddr  ANDROID_UDP_getSrcPortAddr
#define UDP_getFd           ANDROID_UDP_getFd
#define UDP_selReadAvl      ANDROID_UDP_selReadAvl

#elif defined __FREEBSD_UDP__

#define UDP_SOCKET          int
#define UDP_init            FREEBSD_UDP_init
#define UDP_shutdown        FREEBSD_UDP_shutdown
#define UDP_getIfAddr       FREEBSD_UDP_getInterfaceAddress
#define UDP_getAddrOfHost   FREEBSD_UDP_getAddressOfHost
#define UDP_simpleBind      FREEBSD_UDP_simpleBind
#define UDP_connect         FREEBSD_UDP_connect
#define UDP_unbind          FREEBSD_UDP_unbind
#define UDP_send            FREEBSD_UDP_send
#define UDP_recv            FREEBSD_UDP_recv
#define UDP_sendTo          FREEBSD_UDP_sendTo
#define UDP_recvFrom        FREEBSD_UDP_recvFrom
#define UDP_getFd           FREEBSD_UDP_getFd
#define UDP_getSrcPortAddr  FREEBSD_UDP_getSrcPortAddr

#elif defined __IRIX_UDP__

#define UDP_SOCKET          int
#define UDP_init            IRIX_UDP_init
#define UDP_shutdown        IRIX_UDP_shutdown
#define UDP_getIfAddr       IRIX_UDP_getInterfaceAddress
#define UDP_getAddrOfHost   IRIX_UDP_getAddressOfHost
#define UDP_simpleBind      IRIX_UDP_simpleBind
#define UDP_connect         IRIX_UDP_connect
#define UDP_unbind          IRIX_UDP_unbind
#define UDP_send            IRIX_UDP_send
#define UDP_recv            IRIX_UDP_recv
#define UDP_sendTo          IRIX_UDP_sendTo
#define UDP_recvFrom        IRIX_UDP_recvFrom
#define UDP_getFd           IRIX_UDP_getFd
#define UDP_getSrcPortAddr  IRIX_UDP_getSrcPortAddr

#elif defined __QNX_UDP__

#define UDP_SOCKET          int
#define UDP_init            QNX_UDP_init
#define UDP_shutdown        QNX_UDP_shutdown
#define UDP_getIfAddr       QNX_UDP_getInterfaceAddress
#define UDP_getAddrOfHost   QNX_UDP_getAddressOfHost
#define UDP_simpleBind      QNX_UDP_simpleBind
#define UDP_connect         QNX_UDP_connect
#define UDP_unbind          QNX_UDP_unbind
#define UDP_send            QNX_UDP_send
#define UDP_recv            QNX_UDP_recv
#define UDP_sendTo          QNX_UDP_sendTo
#define UDP_recvFrom        QNX_UDP_recvFrom
#define UDP_getSrcPortAddr  QNX_UDP_getSrcPortAddr
#define UDP_getFd           QNX_UDP_getFd
#define UDP_selReadAvl      QNX_UDP_selReadAvl

#elif defined __UITRON_UDP__

#define UDP_SOCKET          int
#define UDP_init            UITRON_UDP_init
#define UDP_shutdown        UITRON_UDP_shutdown
#define UDP_getIfAddr       UITRON_UDP_getInterfaceAddress
#define UDP_getAddrOfHost   UITRON_UDP_getAddressOfHost
#define UDP_simpleBind      UITRON_UDP_simpleBind
#define UDP_connect         UITRON_UDP_connect
#define UDP_unbind          UITRON_UDP_unbind
#define UDP_send            UITRON_UDP_send
#define UDP_recv            UITRON_UDP_recv
#define UDP_sendTo          UITRON_UDP_sendTo
#define UDP_recvFrom        UITRON_UDP_recvFrom
#define UDP_getFd           UITRON_UDP_getFd
#define UDP_getSrcPortAddr  UITRON_UDP_getSrcPortAddr

#elif defined __WINCE_UDP__

#define UDP_SOCKET          unsigned int
#define UDP_init            WINCE_UDP_init
#define UDP_shutdown        WINCE_UDP_shutdown
#define UDP_getIfAddr       WINCE_UDP_getInterfaceAddress
#define UDP_getAddrOfHost   WINCE_UDP_getAddressOfHost
#define UDP_simpleBind      WINCE_UDP_simpleBind
#define UDP_connect         WINCE_UDP_connect
#define UDP_unbind          WINCE_UDP_unbind
#define UDP_send            WINCE_UDP_send
#define UDP_recv            WINCE_UDP_recv
#define UDP_sendTo          WINCE_UDP_sendTo
#define UDP_recvFrom        WINCE_UDP_recvFrom
#define UDP_getSrcPortAddr  WINCE_UDP_getSrcPortAddr
#define UDP_getFd           WINCE_UDP_getFd
#define UDP_selReadAvl      WINCE_UDP_selReadAvl

#elif defined __THREADX_UDP__

#define UDP_SOCKET          int
#define UDP_init            THREADX_UDP_init
#define UDP_shutdown        THREADX_UDP_shutdown
#define UDP_getIfAddr       THREADX_UDP_getInterfaceAddress
#define UDP_getAddrOfHost   THREADX_UDP_getAddressOfHost
#define UDP_simpleBind      THREADX_UDP_simpleBind
#define UDP_connect         THREADX_UDP_connect
#define UDP_unbind          THREADX_UDP_unbind
#define UDP_send            THREADX_UDP_send
#define UDP_recv            THREADX_UDP_recv
#define UDP_sendTo          THREADX_UDP_sendTo
#define UDP_recvFrom        THREADX_UDP_recvFrom
#define UDP_getSrcPortAddr  THREADX_UDP_getSrcPortAddr
#define UDP_getFd           THREADX_UDP_getFd
#define UDP_selReadAvl      THREADX_UDP_selReadAvl

#elif defined __WTOS_UDP__

#define UDP_SOCKET          int
#define UDP_init            WTOS_UDP_init
#define UDP_shutdown        WTOS_UDP_shutdown
#define UDP_getIfAddr       WTOS_UDP_getInterfaceAddress
#define UDP_getAddrOfHost   WTOS_UDP_getAddressOfHost
#define UDP_simpleBind      WTOS_UDP_simpleBind
#define UDP_connect         WTOS_UDP_connect
#define UDP_unbind          WTOS_UDP_unbind
#define UDP_send            WTOS_UDP_send
#define UDP_recv            WTOS_UDP_recv
#define UDP_sendTo          WTOS_UDP_sendTo
#define UDP_recvFrom        WTOS_UDP_recvFrom
#define UDP_getSrcPortAddr  WTOS_UDP_getSrcPortAddr
#define UDP_getFd           WTOS_UDP_getFd
#define UDP_selReadAvl      WTOS_UDP_selReadAvl

#elif defined __AIX_UDP__

#define UDP_SOCKET          int
#define UDP_init            AIX_UDP_init
#define UDP_shutdown        AIX_UDP_shutdown
#define UDP_getIfAddr       AIX_UDP_getInterfaceAddress
#define UDP_getAddrOfHost   AIX_UDP_getAddressOfHost
#define UDP_simpleBind      AIX_UDP_simpleBind
#define UDP_connect         AIX_UDP_connect
#define UDP_unbind          AIX_UDP_unbind
#define UDP_send            AIX_UDP_send
#define UDP_recv            AIX_UDP_recv
#define UDP_sendTo          AIX_UDP_sendTo
#define UDP_recvFrom        AIX_UDP_recvFrom
#define UDP_getSrcPortAddr  AIX_UDP_getSrcPortAddr
#define UDP_getFd           AIX_UDP_getFd
#define UDP_selReadAvl      AIX_UDP_selReadAvl

#elif defined __HPUX_UDP__

#define UDP_SOCKET          int
#define UDP_init            HPUX_UDP_init
#define UDP_shutdown        HPUX_UDP_shutdown
#define UDP_getIfAddr       HPUX_UDP_getInterfaceAddress
#define UDP_getAddrOfHost   HPUX_UDP_getAddressOfHost
#define UDP_simpleBind      HPUX_UDP_simpleBind
#define UDP_connect         HPUX_UDP_connect
#define UDP_unbind          HPUX_UDP_unbind
#define UDP_send            HPUX_UDP_send
#define UDP_recv            HPUX_UDP_recv
#define UDP_sendTo          HPUX_UDP_sendTo
#define UDP_recvFrom        HPUX_UDP_recvFrom
#define UDP_getSrcPortAddr  HPUX_UDP_getSrcPortAddr
#define UDP_getFd           HPUX_UDP_getFd
#define UDP_selReadAvl      HPUX_UDP_selReadAvl

#elif defined __DEOS_UDP__

#define UDP_SOCKET          int
#define UDP_init            DEOS_UDP_init
#define UDP_shutdown        DEOS_UDP_shutdown
#define UDP_getIfAddr       DEOS_UDP_getInterfaceAddress
#define UDP_getAddrOfHost   DEOS_UDP_getAddressOfHost
#define UDP_simpleBind      DEOS_UDP_simpleBind
#define UDP_connect         DEOS_UDP_connect
#define UDP_unbind          DEOS_UDP_unbind
#define UDP_send            DEOS_UDP_send
#define UDP_recv            DEOS_UDP_recv
#define UDP_sendTo          DEOS_UDP_sendTo
#define UDP_recvFrom        DEOS_UDP_recvFrom
#define UDP_getSrcPortAddr  DEOS_UDP_getSrcPortAddr
#define UDP_selReadAvl      DEOS_UDP_selReadAvl

#elif defined __WIZNET_UDP__

#define UDP_SOCKET          int
#define UDP_init            FREERTOS_UDP_init
#define UDP_shutdown        FREERTOS_UDP_shutdown
#define UDP_getIfAddr       FREERTOS_UDP_getInterfaceAddress
#define UDP_getAddrOfHost   FREERTOS_UDP_getAddressOfHost
#define UDP_simpleBind      FREERTOS_UDP_simpleBind
#define UDP_connect         FREERTOS_UDP_connect
#define UDP_unbind          FREERTOS_UDP_unbind
#define UDP_send            FREERTOS_UDP_send
#define UDP_recv            FREERTOS_UDP_recv
#define UDP_sendTo          FREERTOS_UDP_sendTo
#define UDP_recvFrom        FREERTOS_UDP_recvFrom
#define UDP_getFd           FREERTOS_UDP_getFd
#define UDP_getSrcPortAddr  FREERTOS_UDP_getSrcPortAddr
#define UDP_selReadAvl      FREERTOS_UDP_selReadAvl

#elif defined __UCOS_UDP__

#define UDP_SOCKET          int
#define UDP_init            UCOS_UDP_init
#define UDP_shutdown        UCOS_UDP_shutdown
#define UDP_getIfAddr       UCOS_UDP_getInterfaceAddress
#define UDP_getAddrOfHost   UCOS_UDP_getAddressOfHost
#define UDP_simpleBind      UCOS_UDP_simpleBind
#define UDP_connect         UCOS_UDP_connect
#define UDP_unbind          UCOS_UDP_unbind
#define UDP_send            UCOS_UDP_send
#define UDP_recv            UCOS_UDP_recv
#define UDP_sendTo          UCOS_UDP_sendTo
#define UDP_recvFrom        UCOS_UDP_recvFrom
#define UDP_getFd           UCOS_UDP_getFd
#define UDP_getSrcPortAddr  UCOS_UDP_getSrcPortAddr
#define UDP_selReadAvl      UCOS_UDP_selReadAvl

#elif defined(__DUMMY_UDP__) || defined(__FREERTOS_SIMULATOR__)

#define UDP_SOCKET          int
#define UDP_init            DUMMY_UDP_init
#define UDP_shutdown        DUMMY_UDP_shutdown
#define UDP_getIfAddr       DUMMY_UDP_getInterfaceAddress
#define UDP_getAddrOfHost   DUMMY_UDP_getAddressOfHost
#define UDP_simpleBind      DUMMY_UDP_simpleBind
#define UDP_connect         DUMMY_UDP_connect
#define UDP_unbind          DUMMY_UDP_unbind
#define UDP_send            DUMMY_UDP_send
#define UDP_recv            DUMMY_UDP_recv
#define UDP_sendTo          DUMMY_UDP_sendTo
#define UDP_recvFrom        DUMMY_UDP_recvFrom
#define UDP_getFd           DUMMY_UDP_getFd
#define UDP_getSrcPortAddr  DUMMY_UDP_getSrcPortAddr
#define UDP_selReadAvl      DUMMY_UDP_selReadAvl

#else

#error UNSUPPORTED PLATFORM

#endif
#endif
#if defined __DIGICERT_UDP__

#define MOC_UDP_SOCKET          int
#define MOC_UDP_init            MO_UDP_init
#define MOC_UDP_shutdown        MO_UDP_shutdown
#define MOC_UDP_getIfAddr       MO_UDP_getInterfaceAddress
#define MOC_UDP_getAddrOfHost   MO_UDP_getAddressOfHost
#define MOC_UDP_simpleBind      MO_UDP_simpleBind
#define MOC_UDP_connect         MO_UDP_connect
#define MOC_UDP_unbind          MO_UDP_unbind
#define MOC_UDP_send            MO_UDP_send
#define MOC_UDP_recv            MO_UDP_recv
#define MOC_UDP_sendTo          MO_UDP_sendTo
#define MOC_UDP_recvFrom        MO_UDP_recvFrom

#endif


MOC_EXTERN MSTATUS UDP_init             (void);
MOC_EXTERN MSTATUS UDP_shutdown         (void);
MOC_EXTERN MSTATUS UDP_getIfAddr        (sbyte *pHostName, MOC_IP_ADDRESS_S *pRetIpAddress);
MOC_EXTERN MSTATUS UDP_getAddrOfHost    (sbyte *pHostName, MOC_IP_ADDRESS_S *pRetIpAddress);

MOC_EXTERN MSTATUS UDP_simpleBind       (void **ppRetUdpDescr, MOC_IP_ADDRESS srcAddress, ubyte2 srcPortNo, intBoolean isNonBlocking); /* server */
MOC_EXTERN MSTATUS UDP_connect          (void **ppRetUdpDescr, MOC_IP_ADDRESS srcAddress, ubyte2 srcPortNo, MOC_IP_ADDRESS dstAddress, ubyte2 dstPortNo, intBoolean isNonBlocking); /* client */
MOC_EXTERN MSTATUS UDP_unbind           (void **ppReleaseUdpDescr);

MOC_EXTERN MSTATUS UDP_send             (void *pUdpDescr, ubyte *pData, ubyte4 dataLength); /* client */
MOC_EXTERN MSTATUS UDP_recv             (void *pUdpDescr, ubyte *pBuf, ubyte4 bufSize, ubyte4 *pRetDataLength); /* client */

MOC_EXTERN MSTATUS UDP_sendTo           (void *pUdpDescr, MOC_IP_ADDRESS peerAddress, ubyte2 peerPortNo, ubyte *pData, ubyte4 dataLength);  /* server */
MOC_EXTERN MSTATUS UDP_recvFrom         (void *pUdpDescr, MOC_IP_ADDRESS_S *pPeerAddress, ubyte2* pPeerPortNo, ubyte *pBuf, ubyte4 bufSize, ubyte4 *pRetDataLength);  /* server */
MOC_EXTERN MSTATUS UDP_getSrcPortAddr   (void *pUdpDescr, ubyte2 *pRetPortNo, MOC_IP_ADDRESS_S *pRetAddr); /* server */

MOC_EXTERN MSTATUS UDP_getFd            (void *pUdpDescr, UDP_SOCKET *fd);

MOC_EXTERN MSTATUS UDP_selReadAvl       (void *ppUdpDescr[], sbyte4 numUdpDescr, ubyte4 msTimeout);


MOC_EXTERN MSTATUS MOC_UDP_init             (void);
MOC_EXTERN MSTATUS MOC_UDP_shutdown         (void);
MOC_EXTERN MSTATUS MOC_UDP_getIfAddr        (sbyte *pInterfaceName, MOC_IP_ADDRESS *pRetIpAddress);
MOC_EXTERN MSTATUS MOC_UDP_getAddrOfHost    (sbyte *pHostName, MOC_IP_ADDRESS *pRetIpAddress);

MOC_EXTERN MSTATUS MOC_UDP_simpleBind       (void **ppRetUdpDescr, MOC_IP_ADDRESS srcAddress, ubyte2 srcPortNo, intBoolean isNonBlocking); /* server */
MOC_EXTERN MSTATUS MOC_UDP_connect          (void **ppRetUdpDescr, MOC_IP_ADDRESS srcAddress, ubyte2 srcPortNo, MOC_IP_ADDRESS dstAddress, ubyte2 dstPortNo, intBoolean isNonBlocking); /* client */
MOC_EXTERN MSTATUS MOC_UDP_unbind           (void **ppReleaseUdpDescr);

MOC_EXTERN MSTATUS MOC_UDP_send             (void *pUdpDescr, ubyte *pData, ubyte4 dataLength); /* client */
MOC_EXTERN MSTATUS MOC_UDP_recv             (void *pUdpDescr, ubyte *pBuf, ubyte4 bufSize, ubyte4 *pRetDataLength); /* client */

MOC_EXTERN MSTATUS MOC_UDP_sendTo           (void *pUdpDescr, MOC_IP_ADDRESS peerAddress, ubyte2 peerPortNo, ubyte *pData, ubyte4 dataLength);  /* server */
MOC_EXTERN MSTATUS MOC_UDP_recvFrom         (void *pUdpDescr, MOC_IP_ADDRESS* pPeerAddress, ubyte2* pPeerPortNo, ubyte *pBuf, ubyte4 bufSize, ubyte4 *pRetDataLength);  /* server */

/*----------------------------------------------------------------------------*/

/* These macros expand to call init and uninit if enabled, otherwise they expand
 * to do nothing.
 */
#if (defined(UDP_init) && \
    (defined(__ENABLE_DIGICERT_RADIUS_CLIENT__) || \
    defined(__ENABLE_DIGICERT_IKE_SERVER__) || \
    defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || \
    defined(__ENABLE_DIGICERT_DTLS_SERVER__) ))
#if !(defined(__KERNEL__) || defined(_KERNEL) || defined(IPCOM_KERNEL))

/**
 * @def      MOC_UDP_INIT(_status)
 * @details  This macro will initialize the UDP interface.
 *
 * @param _status   The \ref MSTATUS value for return from the calling function.
 *
 * @par Flags
 * To enable this macro, \b all conditions must be met:
 *   1. The following flags \b must be defined:
 *     + \c UDP_init
 *     .
 *   2. At least \b one of the following flags \b must be defined:
 *     + \c \__ENABLE_DIGICERT_RADIUS_CLIENT__
 *     + \c \__ENABLE_DIGICERT_IKE_SERVER__
 *     + \c \__ENABLE_DIGICERT_DTLS_CLIENT__
 *     + \c \__ENABLE_DIGICERT_DTLS_SERVER__
 *     .
 *   3. At least \b one of the following conditions must be met:
 *     + \c \__KERNEL__   must \b not be defined
 *     + \c _KERNEL       \b must be defined
 *     + \c IPCOM_KERNEL  \b must be defined
 *     .
 */
#define MOC_UDP_INIT(_status)                                                  \
    _status = UDP_init ();                                                     \
    if (OK != _status)                                                         \
      goto exit;

/**
 * @def      MOC_UDP_SHUTDOWN(_status,_dStatus)
 * @details  This macro will shutdown the UDP interface.
 *
 * @param _status   The \ref MSTATUS value for return from the calling function.
 * @param _dStatus  The temporary placeholder status used to check return values.
 *
 * @par Flags
 * To enable this macro, \b all conditions must be met:
 *   1. The following flags \b must be defined:
 *     + \c UDP_init
 *     .
 *   2. At least \b one of the following flags \b must be defined:
 *     + \c \__ENABLE_DIGICERT_RADIUS_CLIENT__
 *     + \c \__ENABLE_DIGICERT_IKE_SERVER__
 *     + \c \__ENABLE_DIGICERT_DTLS_CLIENT__
 *     + \c \__ENABLE_DIGICERT_DTLS_SERVER__
 *     .
 *   3. At least \b one of the following conditions must be met:
 *     + \c \__KERNEL__   must \b not be defined
 *     + \c _KERNEL       \b must be defined
 *     + \c IPCOM_KERNEL  \b must be defined
 *     .
 */
#define MOC_UDP_SHUTDOWN(_status,_dStatus)                                     \
    _dStatus = UDP_shutdown ();                                                \
    if (OK != _dStatus)                                                        \
      _status = _dStatus;

#endif /* defined (UDP_init) etc */
#endif /* !defined (__KERNEL__) etc */

#ifndef MOC_UDP_INIT
#define MOC_UDP_INIT(_status)
#endif
#ifndef MOC_UDP_SHUTDOWN
#define MOC_UDP_SHUTDOWN(_status,_dStatus)
#endif

#ifdef __cplusplus
}
#endif

#endif /* __MUDP_HEADER__ */
