/*
 * android_tcp_async.c
 *
 * Android/Linux TCP Abstraction Layer
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
 *
 */

#include "../common/moptions.h"

#ifdef __ANDROID_TCP__

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
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <netdb.h>

static fd_set read_fd;
static fd_set master;
static unsigned int fd_max = 0;


/*------------------------------------------------------------------*/

extern MSTATUS
ANDROID_TCP_initAsync(void)
{
    FD_ZERO(&master);
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
ANDROID_TCP_deinitAsync(void)
{
    FD_ZERO(&master);
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
ANDROID_TCP_addToReadList(TCP_SOCKET  socket)
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
ANDROID_TCP_removeFromReadList(TCP_SOCKET  socket)
{
    FD_CLR(socket,&master);
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
ANDROID_TCP_selectAll(TCP_SOCKET* pSocket)
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

extern MSTATUS
ANDROID_TCP_getHostByName(char* pDomainName, char* pIpAddress)
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

#endif /* __ANDROID_TCP__ */
