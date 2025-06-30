/*
 * mtcp_async.h
 *
 * Mocana Async TCP Abstraction Layer
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

#ifndef __MTCP_ASYNC_HEADER__
#define __MTCP_ASYNC_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__LINUX_TCP__)

#define TCP_INIT_ASYNC                LINUX_TCP_initAsync
#define TCP_DEINIT_ASYNC              LINUX_TCP_deinitAsync
#define TCP_ADDTO_READ_LIST           LINUX_TCP_addToReadList
#define TCP_REMOVEFROM_READ_LIST      LINUX_TCP_removeFromReadList
#define TCP_SELECT_ALL                LINUX_TCP_selectAll
#define TCP_GETHOSTBYNAME             LINUX_TCP_getHostByName

typedef void* TCP_SOCKET_LIST;

#define TCP_ASYNC_CREATE_LIST         LINUX_TCP_ASYNC_createSelectConnectionList
#define TCP_ASYNC_ADD_TO_LIST         LINUX_TCP_ASYNC_addSocketToConnectionList
#define TCP_ASYNC_REM_FR_LIST         LINUX_TCP_ASYNC_removeSocketFromConnectionList
#define TCP_ASYNC_SELECT              LINUX_TCP_ASYNC_select
#define TCP_ASYNC_FIRST_RD            LINUX_TCP_ASYNC_getFirstReadConnection
#define TCP_ASYNC_NEXT_RD             LINUX_TCP_ASYNC_getNextReadConnection
#define TCP_ASYNC_FIRST_WR            LINUX_TCP_ASYNC_getFirstWriteConnection
#define TCP_ASYNC_NEXT_WR             LINUX_TCP_ASYNC_getNextWriteConnection
#define TCP_ASYNC_FIRST_ERR           LINUX_TCP_ASYNC_getFirstErrorConnection
#define TCP_ASYNC_NEXT_ERR            LINUX_TCP_ASYNC_getNextErrorConnection
#elif defined __SYMBIAN_TCP__

#define TCP_INIT_ASYNC                SYMBIAN_TCP_initAsync
#define TCP_DEINIT_ASYNC              SYMBIAN_TCP_deinitAsync
#define TCP_ADDTO_READ_LIST           SYMBIAN_TCP_addToReadList
#define TCP_REMOVEFROM_READ_LIST      SYMBIAN_TCP_removeFromReadList
#define TCP_SELECT_ALL                SYMBIAN_TCP_selectAll
#define TCP_GETHOSTBYNAME             SYMBIAN_TCP_getHostByName

#elif defined __WIN32_TCP__

#define TCP_INIT_ASYNC                WIN32_TCP_initAsync
#define TCP_DEINIT_ASYNC              WIN32_TCP_deinitAsync
#define TCP_ADDTO_READ_LIST           WIN32_TCP_addToReadList
#define TCP_REMOVEFROM_READ_LIST      WIN32_TCP_removeFromReadList
#define TCP_SELECT_ALL                WIN32_TCP_selectAll
#define TCP_GETHOSTBYNAME             WIN32_TCP_getHostByName

typedef void* TCP_SOCKET_LIST;

#define TCP_ASYNC_CREATE_LIST           WIN32_TCP_ASYNC_createSelectConnectionList
#define TCP_ASYNC_ADD_TO_LIST           WIN32_TCP_ASYNC_addSocketToConnectionList
#define TCP_ASYNC_REM_FR_LIST           WIN32_TCP_ASYNC_removeSocketFromConnectionList
#define TCP_ASYNC_SELECT                WIN32_TCP_ASYNC_select
#define TCP_ASYNC_FIRST_RD              WIN32_TCP_ASYNC_getFirstReadConnection
#define TCP_ASYNC_NEXT_RD               WIN32_TCP_ASYNC_getNextReadConnection
#define TCP_ASYNC_FIRST_WR              WIN32_TCP_ASYNC_getFirstWriteConnection
#define TCP_ASYNC_NEXT_WR               WIN32_TCP_ASYNC_getNextWriteConnection
#define TCP_ASYNC_FIRST_ERR             WIN32_TCP_ASYNC_getFirstErrorConnection
#define TCP_ASYNC_NEXT_ERR              WIN32_TCP_ASYNC_getNextErrorConnection

#elif defined __ANDROID_TCP__

#define TCP_INIT_ASYNC                ANDROID_TCP_initAsync
#define TCP_DEINIT_ASYNC              ANDROID_TCP_deinitAsync
#define TCP_ADDTO_READ_LIST           ANDROID_TCP_addToReadList
#define TCP_REMOVEFROM_READ_LIST      ANDROID_TCP_removeFromReadList
#define TCP_SELECT_ALL                ANDROID_TCP_selectAll
#define TCP_GETHOSTBYNAME             ANDROID_TCP_getHostByName

#elif defined __CYGWIN_TCP__

#define TCP_INIT_ASYNC                CYGWIN_TCP_initAsync
#define TCP_DEINIT_ASYNC              CYGWIN_TCP_deinitAsync
#define TCP_ADDTO_READ_LIST           CYGWIN_TCP_addToReadList
#define TCP_REMOVEFROM_READ_LIST      CYGWIN_TCP_removeFromReadList
#define TCP_SELECT_ALL                CYGWIN_TCP_selectAll
#define TCP_GETHOSTBYNAME             CYGWIN_TCP_getHostByName

#elif defined __OPENBSD_TCP__

typedef void* TCP_SOCKET_LIST;

#define TCP_INIT_ASYNC                OPENBSD_TCP_initAsync
#define TCP_DEINIT_ASYNC              OPENBSD_TCP_deinitAsync
#define TCP_ADDTO_READ_LIST           OPENBSD_TCP_addToReadList
#define TCP_REMOVEFROM_READ_LIST      OPENBSD_TCP_removeFromReadList
#define TCP_SELECT_ALL                OPENBSD_TCP_selectAll
#define TCP_GETHOSTBYNAME             OPENBSD_TCP_getHostByName

#elif defined __SOLARIS_TCP__

#define TCP_INIT_ASYNC                SOLARIS_TCP_initAsync
#define TCP_DEINIT_ASYNC              SOLARIS_TCP_deinitAsync
#define TCP_ADDTO_READ_LIST           SOLARIS_TCP_addToReadList
#define TCP_REMOVEFROM_READ_LIST      SOLARIS_TCP_removeFromReadList
#define TCP_SELECT_ALL                SOLARIS_TCP_selectAll
#define TCP_GETHOSTBYNAME             SOLARIS_TCP_getHostByName

#elif defined __VXWORKS_TCP__

#define TCP_INIT_ASYNC                VXWORKS_TCP_initAsync
#define TCP_DEINIT_ASYNC              VXWORKS_TCP_deinitAsync
#define TCP_ADDTO_READ_LIST           VXWORKS_TCP_addToReadList
#define TCP_REMOVEFROM_READ_LIST      VXWORKS_TCP_removeFromReadList
#define TCP_SELECT_ALL                VXWORKS_TCP_selectAll
#define TCP_GETHOSTBYNAME             VXWORKS_TCP_getHostByName

#elif defined __OSX_TCP__

typedef void* TCP_SOCKET_LIST;

#define TCP_INIT_ASYNC                OSX_TCP_initAsync
#define TCP_DEINIT_ASYNC              OSX_TCP_deinitAsync
#define TCP_ADDTO_READ_LIST           OSX_TCP_addToReadList
#define TCP_REMOVEFROM_READ_LIST      OSX_TCP_removeFromReadList
#define TCP_SELECT_ALL                OSX_TCP_selectAll
#define TCP_GETHOSTBYNAME             OSX_TCP_getHostByName
#define TCP_ASYNC_CREATE_LIST         OSX_TCP_ASYNC_createSelectConnectionList
#define TCP_ASYNC_ADD_TO_LIST         OSX_TCP_ASYNC_addSocketToConnectionList
#define TCP_ASYNC_REM_FR_LIST         OSX_TCP_ASYNC_removeSocketFromConnectionList
#define TCP_ASYNC_SELECT              OSX_TCP_ASYNC_select
#define TCP_ASYNC_FIRST_RD            OSX_TCP_ASYNC_getFirstReadConnection
#define TCP_ASYNC_NEXT_RD             OSX_TCP_ASYNC_getNextReadConnection
#define TCP_ASYNC_FIRST_WR            OSX_TCP_ASYNC_getFirstWriteConnection
#define TCP_ASYNC_NEXT_WR             OSX_TCP_ASYNC_getNextWriteConnection
#define TCP_ASYNC_FIRST_ERR           OSX_TCP_ASYNC_getFirstErrorConnection
#define TCP_ASYNC_NEXT_ERR            OSX_TCP_ASYNC_getNextErrorConnection

#elif defined __FREETOS_SIMULATOR_TCP__

#define TCP_GETHOSTBYNAME             FREERTOS_TCP_getHostByName

#elif defined __QNX_TCP__

#define TCP_GETHOSTBYNAME             QNX_TCP_getHostByName

#elif defined __LWIP_TCP__

#define TCP_GETHOSTBYNAME             LWIP_TCP_getHostByName

#elif defined __AZURE_TCP__

#else

#error UNSUPPORTED PLATFORM

#endif



MOC_EXTERN MSTATUS TCP_INIT_ASYNC(void);
MOC_EXTERN MSTATUS TCP_DEINIT_ASYNC(void);
MOC_EXTERN MSTATUS TCP_ADDTO_READ_LIST         (TCP_SOCKET  socket);
MOC_EXTERN MSTATUS TCP_REMOVEFROM_READ_LIST    (TCP_SOCKET  socket);
MOC_EXTERN MSTATUS TCP_SELECT_ALL              (TCP_SOCKET* pSocket);
MOC_EXTERN MSTATUS TCP_GETHOSTBYNAME           (char* pDomainName, char* pIpAddress);

typedef struct tcpAsyncConnection
{
    TCP_SOCKET          socket;
    ubyte4              state;              /* could be used to look up into vector table for callback handler, or for switch statement */
    void*               pCookie;

} tcpAsyncConnection;

#ifdef __WIN32_TCP__
MOC_EXTERN MSTATUS TCP_ASYNC_CREATE_LIST(ubyte4 listMaxSize, TCP_SOCKET_LIST **ppRetSocketList);
MOC_EXTERN MSTATUS TCP_ASYNC_ADD_TO_LIST(TCP_SOCKET_LIST *pSocketList, TCP_SOCKET socket, ubyte4 state, void *pCookie);
MOC_EXTERN MSTATUS TCP_ASYNC_REM_FR_LIST(TCP_SOCKET_LIST *pSocketList, TCP_SOCKET socket, ubyte4 *pRetState, void **ppRetCookie);
MOC_EXTERN MSTATUS TCP_ASYNC_SELECT(TCP_SOCKET_LIST *pSocketList, ubyte4 msTimeout);
MOC_EXTERN MSTATUS TCP_ASYNC_FIRST_RD(TCP_SOCKET_LIST *pSocketList, ubyte4 *pRetTraverseCookie, tcpAsyncConnection **ppRetConnection);
MOC_EXTERN MSTATUS TCP_ASYNC_NEXT_RD(TCP_SOCKET_LIST *pSocketList, ubyte4 *pRetTraverseCookie, tcpAsyncConnection **ppRetConnection);
MOC_EXTERN MSTATUS TCP_ASYNC_FIRST_WR(TCP_SOCKET_LIST *pSocketList, ubyte4 *pRetTraverseCookie, tcpAsyncConnection **ppRetConnection);
MOC_EXTERN MSTATUS TCP_ASYNC_NEXT_WR(TCP_SOCKET_LIST *pSocketList, ubyte4 *pRetTraverseCookie, tcpAsyncConnection **ppRetConnection);
MOC_EXTERN MSTATUS TCP_ASYNC_FIRST_ERR(TCP_SOCKET_LIST *pSocketList, ubyte4 *pRetTraverseCookie, tcpAsyncConnection **ppRetConnection);
MOC_EXTERN MSTATUS TCP_ASYNC_NEXT_ERR(TCP_SOCKET_LIST *pSocketList, ubyte4 *pRetTraverseCookie, tcpAsyncConnection **ppRetConnection);
#endif

#ifdef __cplusplus
}
#endif

#endif
