/*
 * win32_tcp.c
 *
 * Win32 TCP Abstraction Layer
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

#if defined(__ENABLE_DIGICERT_WIN_STUDIO_BUILD__)
#include <winsock2.h>
#include <Ws2tcpip.h>
#endif

#include "../common/moptions.h"

#ifdef __WIN32_TCP__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/mstdlib.h"
#include "../common/redblack.h"
#include "../common/mem_pool.h"
#include "../common/debug_console.h"
#include "../common/mtcp_async.h"

#include <stdio.h>
#include <winsock2.h>
#include <Ws2tcpip.h>


/*------------------------------------------------------------------*/

#define TCP_ASYNC_PRIVATE_SELECT        WIN32_TCP_ASYNC_selectInternal


/*------------------------------------------------------------------*/

static fd_set read_fd;
static fd_set master;
static unsigned int fd_max = 0;


/*------------------------------------------------------------------*/

extern MSTATUS
WIN32_TCP_initAsync(void)
{
    FD_ZERO(&master);
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
WIN32_TCP_deinitAsync(void)
{
    FD_ZERO(&master);
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
WIN32_TCP_addToReadList(TCP_SOCKET socket)
{
    FD_SET(socket,&master);

    if ( socket > fd_max )
    {
        fd_max = socket;
    }
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
WIN32_TCP_removeFromReadList(TCP_SOCKET socket)
{
    FD_CLR(socket,&master);
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
WIN32_TCP_selectAll(TCP_SOCKET* pSocket)
{
    MSTATUS status = ERR_TCP_READ_ERROR;
    unsigned int count = 0;
    struct timeval timeout;

    timeout.tv_sec = 0;
    timeout.tv_usec = 0;

    read_fd = master;
    if ( SOCKET_ERROR == select(FD_SETSIZE, &read_fd, NULL, NULL, &timeout ))
    {
        goto exit;
    }

    for ( count = 0; count <= fd_max; count++ )
    {
        if ( FD_ISSET( count, &read_fd ) )
        {
            (*pSocket) = count;
            status = OK;
            goto exit;
        }
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
WIN32_TCP_getHostByName(char* pDomainName, char* pIpAddress)
{
    struct hostent* h = NULL;
    MSTATUS         status = OK;

    if (NULL == (h = gethostbyname(pDomainName)))
    {
        status = ERR_TCP;
        goto exit;
    }

    strcpy( pIpAddress, inet_ntoa(*((struct in_addr *)h->h_addr)));

exit:
    return status;
}


/*------------------------------------------------------------------*/

#if (!defined(MAX_TCP_ASYNC_SERVER_SOCKETS))
#define MAX_TCP_ASYNC_SERVER_SOCKETS                (16)
#endif


/*------------------------------------------------------------------*/

typedef struct connectionList
{
    fd_set              readList;
    fd_set              writeList;
    fd_set              errorList;
    fd_set              masterList;
    unsigned int        fd_max;
    intBoolean          searchForNewMax;

    redBlackTreeDescr*  pRbTree;

    poolHeaderDescr*    pListMemberPool;
    void*               pListMemberPoolBase;

    poolHeaderDescr*    pRedBlackPool;
    void*               pRedBlackPoolBase;

} connectionList;


/*------------------------------------------------------------------*/

static MSTATUS
compareSockets(const void *pRedBlackCookie,
               const void *pSearchKey, const void *pNodeKey,
               sbyte4 *pRetResult)
{
    tcpAsyncConnection* a = (tcpAsyncConnection *)pSearchKey;
    tcpAsyncConnection* b = (tcpAsyncConnection *)pNodeKey;

    if (a->socket < b->socket)
        *pRetResult = -1;
    else if (a->socket > b->socket)
        *pRetResult = 1;
    else
        *pRetResult = 0;

    return OK;
}


/*--------------------------------------------------------------------------*/

static MSTATUS
WIN32_TCP_ASYNC_getNode(void *pAllocCookie, void **ppNewNode)
{
    return MEM_POOL_getPoolObject((poolHeaderDescr *)pAllocCookie, ppNewNode);
}


/*--------------------------------------------------------------------------*/

static MSTATUS
WIN32_TCP_ASYNC_putNode(void *pAllocCookie, void **ppFreeNode)
{
    return MEM_POOL_putPoolObject((poolHeaderDescr *)pAllocCookie, ppFreeNode);
}


/*------------------------------------------------------------------*/

extern MSTATUS
WIN32_TCP_ASYNC_createSelectConnectionList(ubyte4 listMaxSize, TCP_SOCKET_LIST **ppRetSocketList)
{
    connectionList*     pConnectionList   = NULL;
    void*               pRedBlackPoolBase = NULL;
    void*               pMemPoolBase      = NULL;
    redBlackTreeDescr*  pRbTree           = NULL;
    MSTATUS             status;

    /* add one extra node for searches */
    listMaxSize++;

    /* allocate a zeroize buffer for connection list head */
    if (OK > (status = DIGI_MALLOC(&pConnectionList, sizeof(connectionList))))
        goto exit;

    DIGI_MEMSET((ubyte *)pConnectionList, 0x00, sizeof(connectionList));

    /* allocate a zeroize buffer for pool of connections */
    if (OK > (status = DIGI_MALLOC(&pMemPoolBase, sizeof(tcpAsyncConnection) * listMaxSize)))
        goto exit;

    DIGI_MEMSET((ubyte *)pMemPoolBase, 0x00, sizeof(tcpAsyncConnection) * listMaxSize);

    /* create a pool --- pools are not reentrant */
    if (OK > (status = MEM_POOL_createPool(&pConnectionList->pListMemberPool, pMemPoolBase,
                                           sizeof(tcpAsyncConnection) * listMaxSize, sizeof(tcpAsyncConnection))))
    {
        goto exit;
    }

    /* allocate a zeroize buffer for pool red-black nodes */
    /* !!!!! how many should we buffer more for???  log(n)?  */
    if (OK > (status = DIGI_MALLOC(&pRedBlackPoolBase, sizeof(redBlackNodeDescr) * listMaxSize)))
        goto exit;

    DIGI_MEMSET((ubyte *)pRedBlackPoolBase, 0x00, sizeof(redBlackNodeDescr) * listMaxSize);

    /* create a pool --- pools are not reentrant */
    if (OK > (status = MEM_POOL_createPool(&pConnectionList->pRedBlackPool, pRedBlackPoolBase,
                                           sizeof(redBlackNodeDescr) * listMaxSize, sizeof(redBlackNodeDescr))))
    {
        goto exit;
    }

    /* allocate red-black tree */
    if (OK > (status = REDBLACK_allocTree(&pRbTree,
                                          WIN32_TCP_ASYNC_getNode, WIN32_TCP_ASYNC_putNode,
                                          compareSockets, pConnectionList,
                                          pConnectionList->pRedBlackPool)))
    {
        goto exit;
    }

    /* initialize */
    FD_ZERO(&pConnectionList->masterList);
    FD_ZERO(&pConnectionList->readList);
    pConnectionList->fd_max = 0;
    pConnectionList->searchForNewMax = FALSE;

    /* set and clear for clean return */
    pConnectionList->pRedBlackPoolBase = pRedBlackPoolBase;
    pRedBlackPoolBase = NULL;

    pConnectionList->pListMemberPoolBase = pMemPoolBase;
    pMemPoolBase = NULL;

    pConnectionList->pRbTree = pRbTree;
    pRbTree = NULL;

    *ppRetSocketList = (TCP_SOCKET_LIST)pConnectionList;
    pConnectionList = NULL;

exit:
    REDBLACK_freeTree(&pRbTree, NULL, NULL, NULL);
    DIGI_FREE(&pRedBlackPoolBase);
    DIGI_FREE(&pMemPoolBase);
    DIGI_FREE(&pConnectionList);

    return status;

} /* WIN32_TCP_ASYNC_createSelectConnectionList */


/*------------------------------------------------------------------*/

extern MSTATUS
WIN32_TCP_ASYNC_addSocketToConnectionList(TCP_SOCKET_LIST *pSocketList, TCP_SOCKET socket, ubyte4 state, void *pCookie)
{
    connectionList*     pConnectionList = (connectionList *)pSocketList;
    tcpAsyncConnection* pConnection = NULL;
    tcpAsyncConnection* pFoundConnection = NULL;
    MSTATUS             status;

    if (NULL == pConnectionList)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (status = MEM_POOL_getPoolObject(pConnectionList->pListMemberPool, &pConnection)))
        goto exit;

    /* make sure we haven't exhausted the pool, otherwise we end up stuck */
    if (NULL == pConnectionList->pListMemberPool->pHeadOfPool)
    {
        status = ERR_TCP_TOO_MANY_SOCKETS;
        goto exit;
    }

    /* populate new connection */
    pConnection->state = state;
    pConnection->socket = socket;
    pConnection->pCookie = pCookie;

    /* add to redblack tree */
    if (OK > (status = REDBLACK_findOrInsert(pConnectionList->pRbTree, pConnection, &pFoundConnection)))
        goto exit;

    /* update master list */
    FD_SET(socket, &pConnectionList->masterList);

    /* check if we have a new max */
    if (socket > pConnectionList->fd_max)
    {
        pConnectionList->fd_max = socket;
        pConnectionList->searchForNewMax = FALSE;
    }

    pConnection = NULL;

exit:
    MEM_POOL_putPoolObject(pConnectionList->pListMemberPool, &pConnection);

    return status;

} /* WIN32_TCP_ASYNC_addSocketToConnectionList */


/*------------------------------------------------------------------*/

extern MSTATUS
WIN32_TCP_ASYNC_removeSocketFromConnectionList(TCP_SOCKET_LIST *pSocketList, TCP_SOCKET socket, ubyte4 *pRetState, void **ppRetCookie)
{
    connectionList*     pConnectionList = (connectionList *)pSocketList;
    tcpAsyncConnection* pConnection = NULL;
    tcpAsyncConnection* pFoundConnection = NULL;
    MSTATUS             status;

    if ((NULL == pConnectionList) || (NULL == pRetState) || (NULL == ppRetCookie))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (status = MEM_POOL_getPoolObject(pConnectionList->pListMemberPool, &pConnection)))
        goto exit;

    /* populate search connection */
    pConnection->socket = socket;

    if (OK > (status = REDBLACK_delete(pConnectionList->pRbTree, pConnection, &pFoundConnection)))
        goto exit;

    if (NULL == pFoundConnection)
    {
        status = ERR_TCP_NO_SUCH_SOCKET;
        goto exit;
    }

    *ppRetCookie = pFoundConnection->pCookie;
    *pRetState = pFoundConnection->state;

    FD_CLR(socket,&pConnectionList->masterList);

exit:
    MEM_POOL_putPoolObject(pConnectionList->pListMemberPool, &pConnection);
    MEM_POOL_putPoolObject(pConnectionList->pListMemberPool, &pFoundConnection);

    return status;

} /* WIN32_TCP_ASYNC_removeSocketFromConnectionList */


/*------------------------------------------------------------------*/

static MSTATUS
WIN32_TCP_ASYNC_selectInternal(TCP_SOCKET_LIST *pSocketList, ubyte4 msTimeout,
                               int (__stdcall *SELECT)(int, fd_set *, fd_set *, fd_set *, const struct timeval *))
{
    /* allows us to plug different select() function for test automation */
    connectionList*     pConnectionList = (connectionList *)pSocketList;
    tcpAsyncConnection* pConnection = NULL;
    tcpAsyncConnection* pFoundConnection = NULL;
    struct              timeval timeout;
    int                 result;
    MSTATUS             status = ERR_TCP_SELECT_ERROR;

    if (0 == msTimeout)
    {
        /* quick poll */
        timeout.tv_sec = 0;
        timeout.tv_usec = 0;
    }
    else
    {
        /* compute timeout (milliseconds) */
        timeout.tv_sec  = msTimeout / 1000;
        timeout.tv_usec = (msTimeout % 1000) * 1000;    /* convert ms to us */
    }

    /* clone master list to read and error list */
    pConnectionList->readList.fd_count = pConnectionList->masterList.fd_count;
    DIGI_MEMCPY(&(pConnectionList->readList.fd_array[0]),
               &(pConnectionList->masterList.fd_array[0]),
               pConnectionList->masterList.fd_count * sizeof(SOCKET));

    pConnectionList->writeList.fd_count = pConnectionList->masterList.fd_count;
    DIGI_MEMCPY(&(pConnectionList->writeList.fd_array[0]),
               &(pConnectionList->masterList.fd_array[0]),
               pConnectionList->masterList.fd_count * sizeof(SOCKET));

    pConnectionList->errorList.fd_count = pConnectionList->masterList.fd_count;
    DIGI_MEMCPY(&(pConnectionList->errorList.fd_array[0]),
               &(pConnectionList->masterList.fd_array[0]),
               pConnectionList->masterList.fd_count * sizeof(SOCKET));

    /* select */
    if (SOCKET_ERROR == (result = SELECT(FD_SETSIZE /* windows ignores this parameter */,
                                         &pConnectionList->readList,
                                         &pConnectionList->writeList,
                                         &pConnectionList->errorList,
                                         &timeout)))
    {
        /*!!!! WSAGetLastError */
        goto exit;
    }

    status = OK;

exit:
    return status;

} /* WIN32_TCP_ASYNC_selectInternal */


/*------------------------------------------------------------------*/

extern MSTATUS
WIN32_TCP_ASYNC_select(TCP_SOCKET_LIST *pSocketList, ubyte4 msTimeout)
{
    return WIN32_TCP_ASYNC_selectInternal(pSocketList, msTimeout, select);
}


/*------------------------------------------------------------------*/

static MSTATUS
WIN32_TCP_ASYNC_getNextConnection(connectionList* pConnectionList, fd_set *pSet,
                                  ubyte4 *pRetTraverseCookie, tcpAsyncConnection **ppRetConnection)
{
    tcpAsyncConnection* pConnection = NULL;
    MSTATUS             status;

    if (OK > (status = MEM_POOL_getPoolObject(pConnectionList->pListMemberPool, &pConnection)))
        goto exit;

    do
    {
        if (*pRetTraverseCookie >= pSet->fd_count)
        {
            status = ERR_TCP_END_OF_SOCKET_LIST;
            goto exit;
        }

        /* we're peering inside of Window internal structure */
        /* populate search connection */
        pConnection->socket = (TCP_SOCKET)(pSet->fd_array[(*pRetTraverseCookie)]);

        if (OK > (status = REDBLACK_find(pConnectionList->pRbTree, pConnection, ppRetConnection)))
            goto exit;

        (*pRetTraverseCookie)++;
    }
    while (NULL == *ppRetConnection);

exit:
    MEM_POOL_putPoolObject(pConnectionList->pListMemberPool, &pConnection);

    return status;

} /* WIN32_TCP_ASYNC_getNextConnection */


/*------------------------------------------------------------------*/

static MSTATUS
WIN32_TCP_ASYNC_getFirstConnection(connectionList* pConnectionList, fd_set *pSet,
                                   ubyte4 *pRetTraverseCookie, tcpAsyncConnection **ppRetConnection)
{
    tcpAsyncConnection* pConnection = NULL;
    MSTATUS             status;

    if (0 == pSet->fd_count)
    {
        status = ERR_TCP_END_OF_SOCKET_LIST;
        goto exit;
    }

    *pRetTraverseCookie = 1;

    if (OK > (status = MEM_POOL_getPoolObject(pConnectionList->pListMemberPool, &pConnection)))
        goto exit;

    /* we're peering inside of Window internal structure */
    /* populate search connection */
    pConnection->socket = (TCP_SOCKET)(pSet->fd_array[0]);

    if (OK > (status = REDBLACK_find(pConnectionList->pRbTree, pConnection, ppRetConnection)))
        goto exit;

    if (NULL == *ppRetConnection)
    {
        /* need to put before doing another get, or we may run out of connections */
        MEM_POOL_putPoolObject(pConnectionList->pListMemberPool, &pConnection);

        /* the head was empty let's search the tail! */
        status = WIN32_TCP_ASYNC_getNextConnection(pConnectionList, pSet, pRetTraverseCookie, ppRetConnection);
    }

exit:
    MEM_POOL_putPoolObject(pConnectionList->pListMemberPool, &pConnection);

    return status;

} /* WIN32_TCP_ASYNC_getFirstConnection */


/*------------------------------------------------------------------*/

extern MSTATUS
WIN32_TCP_ASYNC_getFirstReadConnection(TCP_SOCKET_LIST *pSocketList,
                                       ubyte4 *pRetTraverseCookie, tcpAsyncConnection **ppRetConnection)
{
    connectionList* pConnectionList = (connectionList *)pSocketList;

    return WIN32_TCP_ASYNC_getFirstConnection(pConnectionList, &pConnectionList->readList, pRetTraverseCookie, ppRetConnection);
}


/*------------------------------------------------------------------*/

extern MSTATUS
WIN32_TCP_ASYNC_getNextReadConnection(TCP_SOCKET_LIST *pSocketList,
                                      ubyte4 *pRetTraverseCookie, tcpAsyncConnection **ppRetConnection)
{
    connectionList* pConnectionList = (connectionList *)pSocketList;

    return WIN32_TCP_ASYNC_getNextConnection(pConnectionList, &pConnectionList->readList, pRetTraverseCookie, ppRetConnection);
}


/*------------------------------------------------------------------*/

extern MSTATUS
WIN32_TCP_ASYNC_getFirstWriteConnection(TCP_SOCKET_LIST *pSocketList,
                                        ubyte4 *pRetTraverseCookie, tcpAsyncConnection **ppRetConnection)
{
    connectionList* pConnectionList = (connectionList *)pSocketList;

    return WIN32_TCP_ASYNC_getFirstConnection(pConnectionList, &pConnectionList->writeList, pRetTraverseCookie, ppRetConnection);
}


/*------------------------------------------------------------------*/

extern MSTATUS
WIN32_TCP_ASYNC_getNextWriteConnection(TCP_SOCKET_LIST *pSocketList,
                                       ubyte4 *pRetTraverseCookie, tcpAsyncConnection **ppRetConnection)
{
    connectionList* pConnectionList = (connectionList *)pSocketList;

    return WIN32_TCP_ASYNC_getNextConnection(pConnectionList, &pConnectionList->writeList, pRetTraverseCookie, ppRetConnection);
}


/*------------------------------------------------------------------*/

extern MSTATUS
WIN32_TCP_ASYNC_getFirstErrorConnection(TCP_SOCKET_LIST *pSocketList,
                                        ubyte4 *pRetTraverseCookie, tcpAsyncConnection **ppRetConnection)
{
    connectionList* pConnectionList = (connectionList *)pSocketList;

    return WIN32_TCP_ASYNC_getFirstConnection(pConnectionList, &pConnectionList->errorList, pRetTraverseCookie, ppRetConnection);
}


/*------------------------------------------------------------------*/

extern MSTATUS
WIN32_TCP_ASYNC_getNextErrorConnection(TCP_SOCKET_LIST *pSocketList,
                                       ubyte4 *pRetTraverseCookie, tcpAsyncConnection **ppRetConnection)
{
    connectionList* pConnectionList = (connectionList *)pSocketList;

    return WIN32_TCP_ASYNC_getNextConnection(pConnectionList, &pConnectionList->errorList, pRetTraverseCookie, ppRetConnection);
}


/*------------------------------------------------------------------*/

#if 0
static int __stdcall
TEST_SELECT(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const struct timeval *timeout)
{
    /* simulate all connections being active */
    return readfds->fd_count + writefds->fd_count + exceptfds->fd_count;
}


/*------------------------------------------------------------------*/

/*!!!! should be generalized and added to test monkeys */
main1()
{
    sbyte*              names[] = { "00", "01", "02", "03", "04", "05", "06", "07", "08", "09",
                                    "10", "11", "12", "13", "14", "15", "16", "17", "18", "19",
                                    "20", "21", "22", "23", "24", "25", "26", "27", "28", "29",
                                    "30", "31" };
    TCP_SOCKET_LIST*    pSocketList = NULL;
    int                 count;
    sbyte*              pCookie;
    ubyte4              traverseCookie;
    ubyte4              fakeState = 0;
    tcpAsyncConnection* pConnection;
    MSTATUS             status;

    status = WIN32_TCP_ASYNC_createSelectConnectionList(30, &pSocketList);

    if (OK > status)
    {
        printf("line = %d, status = %d\n", __LINE__, status);
        goto exit;
    }

    for (count = 0; count < 30; count++)
    {
        status = WIN32_TCP_ASYNC_addSocketToConnectionList(pSocketList, count, fakeState, names[count]);

        if (OK > status)
        {
            printf("count = %d, line = %d, status = %d\n", count, __LINE__, status);
            goto exit;
        }
    }

    /* negative test */
    status = WIN32_TCP_ASYNC_addSocketToConnectionList(pSocketList, count, fakeState, &names[count]);

    if (OK <= status)
    {
        printf("line = %d, status = %d\n", __LINE__, status);
        goto exit;
    }


    for (count = 0; count < 30; count++)
    {
        status = WIN32_TCP_ASYNC_removeSocketFromConnectionList(pSocketList, count, &fakeState, &pCookie);

        if (OK > status)
        {
            printf("count = %d, line = %d, status = %d\n", count, __LINE__, status);
            goto exit;
        }

        if (pCookie != names[count])
        {
            printf("count = %d, line = %d\n", count, __LINE__);
            goto exit;
        }

        /* try to do a double remove */
        status = WIN32_TCP_ASYNC_removeSocketFromConnectionList(pSocketList, count, &fakeState, &pCookie);

        if (OK <= status)
        {
            printf("count = %d, line = %d, status = %d\n", count, __LINE__, status);
            goto exit;
        }
    }

    /* negative test */
    status = WIN32_TCP_ASYNC_removeSocketFromConnectionList(pSocketList, count, &fakeState, &pCookie);

    if (OK <= status)
    {
        printf("line = %d, status = %d\n", __LINE__, status);
        goto exit;
    }

    for (count = 0; count < 30; count++)
    {
        status = WIN32_TCP_ASYNC_addSocketToConnectionList(pSocketList, count, fakeState, names[count]);

        if (OK > status)
        {
            printf("count = %d, line = %d, status = %d\n", count, __LINE__, status);
            goto exit;
        }
    }

    status = WIN32_TCP_ASYNC_selectInternal(pSocketList, 100, TEST_SELECT);

    if (OK > status)
    {
        printf("line = %d, status = %d\n", __LINE__, status);
        goto exit;
    }

    /* walk the read list */
    status = WIN32_TCP_ASYNC_getFirstReadConnection(pSocketList, &traverseCookie, &pConnection);

    if (OK > status)
    {
        printf("line = %d, status = %d\n", __LINE__, status);
        goto exit;
    }

    status = WIN32_TCP_ASYNC_getFirstReadConnection(pSocketList, &traverseCookie, &pConnection);

    if (OK > status)
    {
        printf("line = %d, status = %d\n", __LINE__, status);
        goto exit;
    }

    printf("READ ===> cookie = %s\n", (char *)pConnection->pCookie);

    /* walk the list simulating deletion */
    for (count = 1; count < 30; count++)
    {
        status = WIN32_TCP_ASYNC_getNextReadConnection(pSocketList, &traverseCookie, &pConnection);

        if (OK > status)
        {
            printf("line = %d, status = %d\n", __LINE__, status);
            goto exit;
        }

        printf("READ ===> cookie = %s\n", (char *)pConnection->pCookie);
    }

    /* try to move off end of list */
    status = WIN32_TCP_ASYNC_getNextReadConnection(pSocketList, &traverseCookie, &pConnection);

    if (OK <= status)
    {
        printf("line = %d, status = %d\n", __LINE__, status);
        printf("READ ===> cookie = %s\n", (char *)pConnection->pCookie);
        goto exit;
    }

    /* walk the error list; simulate a close for dead sockets */
    status = WIN32_TCP_ASYNC_getFirstErrorConnection(pSocketList, &traverseCookie, &pConnection);

    if (OK > status)
    {
        printf("line = %d, status = %d\n", __LINE__, status);
        goto exit;
    }

    /* remove head of list */
    status = WIN32_TCP_ASYNC_removeSocketFromConnectionList(pSocketList, pConnection->socket, &fakeState, &pCookie);

    printf("ERROR ===> cookie = %s\n", (char *)pConnection->pCookie);

    /* walk the list simulating deletion */
    for (count = 1; count < 30; count++)
    {
        status = WIN32_TCP_ASYNC_getNextErrorConnection(pSocketList, &traverseCookie, &pConnection);

        if (OK > status)
        {
            printf("line = %d, status = %d\n", __LINE__, status);
            goto exit;
        }

        printf("ERROR ===> cookie = %s\n", (char *)pConnection->pCookie);
    }

    /* simualte write handling after all sockets have been closed by simulated errors */
    status = WIN32_TCP_ASYNC_getFirstWriteConnection(pSocketList, &traverseCookie, &pConnection);

    if (OK > status)
    {
        printf("line = %d, status = %d\n", __LINE__, status);
        goto exit;
    }

    status = WIN32_TCP_ASYNC_removeSocketFromConnectionList(pSocketList, pConnection->socket, &fakeState, &pCookie);

    /* walk the list */
    for (count = 1; count < 29; count++)
    {
        status = WIN32_TCP_ASYNC_getNextWriteConnection(pSocketList, &traverseCookie, &pConnection);

        if (OK > status)
        {
            printf("line = %d, status = %d\n", __LINE__, status);
            goto exit;
        }

        printf("WRITE ===> cookie = %s\n", (char *)pConnection->pCookie);

        status = WIN32_TCP_ASYNC_removeSocketFromConnectionList(pSocketList, pConnection->socket, &fakeState, &pCookie);
    }

    /* go back and make sure read head fails, now that all connections have been closed */
    status = WIN32_TCP_ASYNC_getFirstReadConnection(pSocketList, &traverseCookie, &pConnection);

    if (OK <= status)
    {
        printf("line = %d, status = %d\n", __LINE__, status);
        goto exit;
    }

    /* negative test: all connections have been closed, the select should find no connections! */
    /* we want to verify the master socket list was cleared */
    status = WIN32_TCP_ASYNC_selectInternal(pSocketList, 100, TEST_SELECT);

    if (OK > status)
    {
        printf("line = %d, status = %d\n", __LINE__, status);
        goto exit;
    }

    /* negative test */
    status = WIN32_TCP_ASYNC_getFirstReadConnection(pSocketList, &traverseCookie, &pConnection);

    if (OK <= status)
    {
        printf("line = %d, status = %d\n", __LINE__, status);
        goto exit;
    }

    /* negative test */
    status = WIN32_TCP_ASYNC_getFirstWriteConnection(pSocketList, &traverseCookie, &pConnection);

    if (OK <= status)
    {
        printf("line = %d, status = %d\n", __LINE__, status);
        goto exit;
    }

    /* negative test */
    status = WIN32_TCP_ASYNC_getFirstErrorConnection(pSocketList, &traverseCookie, &pConnection);

    if (OK <= status)
    {
        printf("line = %d, status = %d\n", __LINE__, status);
        goto exit;
    }

exit:
    return 0;
}
#endif

#endif /* __WIN32_TCP__ */

