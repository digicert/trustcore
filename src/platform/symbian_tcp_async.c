/*
 * symbian_tcp_async.c
 *
 * Symbian TCP Abstraction Layer
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

#ifdef __SYMBIAN_TCP__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"
#include "../common/mtcp_async.h"

#define _REENTRANT

#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/select.h>

static fd_set read_fd;
static fd_set master;
static unsigned int fd_max = 0;
/*------------------------------------------------------------------*/
extern MSTATUS SYMBIAN_TCP_initAsync(void)
{
    FD_ZERO(&master);
    return OK;
}

/*------------------------------------------------------------------*/
extern MSTATUS SYMBIAN_TCP_deinitAsync(void)
{
    FD_ZERO(&master);
    return OK;
}

/*------------------------------------------------------------------*/
extern MSTATUS SYMBIAN_TCP_addToReadList(TCP_SOCKET  socket)
{
    FD_SET(socket,&master);

    if ( socket > fd_max )
    {
        fd_max = socket;
    }
    return OK;
}

/*------------------------------------------------------------------*/
extern MSTATUS SYMBIAN_TCP_removeFromReadList(TCP_SOCKET  socket)
{
    FD_CLR(socket,&master);
    return OK;
}

/*------------------------------------------------------------------*/
extern MSTATUS SYMBIAN_TCP_selectAll(TCP_SOCKET* pSocket)
{
    MSTATUS status = ERR_TCP_READ_ERROR;
    unsigned int count = 0;

    read_fd = master;
    if ( 0 > select(FD_SETSIZE, &read_fd, NULL, NULL, NULL ))
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
extern MSTATUS SYMBIAN_TCP_getHostByName(char* pDomainName, char* pIpAddress)
{
    MSTATUS    status = OK;
    struct hostent *h = NULL;

    if ( NULL == ( h = gethostbyname(pDomainName)))
    {
        status = ERR_TCP;
        goto exit;
    }

    strcpy( pIpAddress, inet_ntoa(*((struct in_addr *)h->h_addr)) );

exit:
    return status;
}
/*------------------------------------------------------------------*/
#endif /* __SYMBIAN_TCP__ */
