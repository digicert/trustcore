/*
 * vxworks_tcp_async.c
 *
 * vxWorks TCP Async Abstraction Layer
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

#ifdef __VXWORKS_TCP__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"
#include "../common/mtcp_async.h"


#include <vxWorks.h>
#include <stdio.h>
#include <sockLib.h>
#include <time.h>
#include <selectLib.h>
#include <inetLib.h>
#include <stdlib.h>
#include <errnoLib.h>
#include <hostLib.h>

#ifndef PRINTF
#define PRINTF      printf
#endif

#ifdef VXWORKS_ASYNC_ENABLE
static fd_set read_fd;
static fd_set master;
static unsigned int fd_max = 0;
#endif
/*------------------------------------------------------------------*/
extern MSTATUS VXWORKS_TCP_initAsync(void)
{
#ifdef VXWORKS_ASYNC_ENABLE
    FD_ZERO(&master);
#endif

    PRINTF(  "\nVXWORKS_TCP_initAsync...BAD!\n");

    return OK;
}

/*------------------------------------------------------------------*/
extern MSTATUS VXWORKS_TCP_deinitAsync(void)
{
#ifdef VXWORKS_ASYNC_ENABLE
    FD_ZERO(&master);
#endif
    PRINTF(  "\nVXWORKS_TCP_deinitAsync...BAD!\n");

    return OK;
}

/*------------------------------------------------------------------*/
extern MSTATUS VXWORKS_TCP_addToReadList(TCP_SOCKET  socket)
{
#ifdef VXWORKS_ASYNC_ENABLE
    FD_SET(socket,&master);

    if ( socket > fd_max )
    {
        fd_max = socket;
    }
#endif
    PRINTF(  "\nVXWORKS_TCP_addToReadList...BAD!\n");

    return OK;
}

/*------------------------------------------------------------------*/
extern MSTATUS VXWORKS_TCP_removeFromReadList(TCP_SOCKET  socket)
{
#ifdef VXWORKS_ASYNC_ENABLE
    FD_CLR(socket,&master);
#endif
    PRINTF(  "\nVXWORKS_TCP_removeFromReadList...BAD!\n");

    return OK;
}

/*------------------------------------------------------------------*/
extern MSTATUS VXWORKS_TCP_selectAll(TCP_SOCKET* pSocket)
{
    MSTATUS status = ERR_TCP_READ_ERROR;
#ifdef VXWORKS_ASYNC_ENABLE
    unsigned int count = 0;
    struct timeval timeout;

    timeout.tv_sec = 0;
    timeout.tv_usec = 0;

    read_fd = master;
    if ( 0 > select(FD_SETSIZE, &read_fd, NULL, NULL, &timeout ))
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
#endif
    PRINTF(  "\nVXWORKS_TCP_selectAll...BAD!\n");

    return status;
}
/*------------------------------------------------------------------*/
extern MSTATUS VXWORKS_TCP_getHostByName(char* pDomainName, char* pIpAddress)
{
    MSTATUS    status = OK;
#ifdef VXWORKS_ASYNC_ENABLE
    struct hostent *h = NULL;

    if ( NULL == ( h = gethostbyname(pDomainName)))
    {
        status = ERR_TCP;
        goto exit;
    }

    strcpy( pIpAddress, inet_ntoa(*((struct in_addr *)h->h_addr)) );

exit:
#endif
    PRINTF(  "\nVXWORKS_TCP_getHostByName...BAD!\n");

    return status;
}
/*------------------------------------------------------------------*/
#endif /* __VXWORKS_TCP__ */
