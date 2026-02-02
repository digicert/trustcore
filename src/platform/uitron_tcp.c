/*
 * uitron_tcp.c
 *
 * uITRON TCP Abstraction Layer
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

#ifdef __UITRON_TCP__

/* uITRON is a very different RTOS! This is a good example for dealing with a nasty socket interface. */

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"

#include <s_services.h>
#include <t_services.h>
#include "kernel_id.h"
#include "tinet_id.h"

#include <stdlib.h>
#include <string.h>

#include <tinet_defs.h>
#include <tinet_config.h>

#include <net/if.h>
#include <net/if_ppp.h>
#include <net/if_loop.h>
#include <net/ethernet.h>
#include <net/net.h>
#include <net/net_buf.h>
#include <net/net_timer.h>
#include <net/net_count.h>

#include <netinet/in.h>
#include <netinet/in_itron.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>

#if (defined(SUPPORT_INET4))

#define BUF_SIZE                (TCP_MSS)
typedef T_IPV4EP                uitronIpAddrPort;

#if (defined(__ENABLE_DIGICERT_IPV6__))
#error Need to undefine __ENABLE_DIGICERT_IPV6__, UITRON does not support mixed mode IPv4 & IPv6
#endif

#elif (defined(SUPPORT_INET6))

#define BUF_SIZE                (TCP6_MSS)
typedef T_IPV6EP                uitronIpAddrPort;

#if (!defined(__ENABLE_DIGICERT_IPV6__))
#error Need to define __ENABLE_DIGICERT_IPV6__
#endif

#else
#error Need to define either SUPPORT_INET4 or SUPPORT_INET6
#endif


/*------------------------------------------------------------------*/

extern MSTATUS
UITRON_TCP_init()
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
UITRON_TCP_shutdown()
{
    return OK;
}


/*------------------------------------------------------------------*/

static TCP_SOCKET
UITRON_allocSocketDescr(intBoolean isListenSocket)
{
    TCP_SOCKET  pSocketDescr;

    if (NULL != (pSocketDescr = MALLOC(sizeof(uitronSocketDescr))))
    {
        DIGI_MEMSET((ubyte *)pSocketDescr, 0x00, sizeof(uitronSocketDescr));

        pSocketDescr->isListenSocket = isListenSocket;
        pSocketDescr->srcPortNumber = 0;

        pSocketDescr->isConnected = FALSE;

#if 0
        /* uITRON's TPC/IP stack (TINET) does not appear to allow mixing IPv4 and IPv6 */
#ifdef __ENABLE_DIGICERT_IPV6__
        pSocketDescr->dstAddress.family = UITRON_AF_INET6;
#endif
#endif

        pSocketDescr->dstPortNumber = 0;

        pSocketDescr->repId = INT_ID_NONE;
        pSocketDescr->cepId = INT_ID_NONE;
    }

    return pSocketDescr;
}


/*------------------------------------------------------------------*/

static void
UITRON_deallocSocketDescr(TCP_SOCKET *pFreeSocketDescr)
{
    if (((NULL != pFreeSocketDescr) && (NULL != *pFreeSocketDescr))
    {
        if (INT_ID_NONE != *pFreeSocketDescr->repId)
            free_tcp_rep(*pFreeSocketDescr->repId);

        if (INT_ID_NONE != *pFreeSocketDescr->cepId)
            free_tcp_cep(*pFreeSocketDescr->cepId);

        FREE(*pFreeSocketDescr);
        *pFreeSocketDescr = NULL;
    }
}


/*------------------------------------------------------------------*/

extern MSTATUS
UITRON_TCP_listenSocket(TCP_SOCKET *listenSocket, ubyte2 portNumber)
{
    MSTATUS status = OK;

    if (NULL == (*listenSocket = UITRON_allocSocketDescr(TRUE)))
    {
        status = ERR_TCP_LISTEN_SOCKET_ERROR;
        goto exit;
    }

    (*listenSocket)->srcPortNumber = portNumber;

exit:
    return status;
}


/*------------------------------------------------------------------*/

static TCP_SOCKET *
UITRON_allocTcpSocket(intBoolean isListenSocket, ubyte2 portNumber, ID cepId)
{
    T_TCP_CREP  crep;

    crep.repatr = 0;
    crep.myaddr.portno = portNumber;

#if (defined(SUPPORT_INET4))
    crep.myaddr.ipaddr = IPV4_ADDRANY;
#elif (defined(SUPPORT_INET6))
    memcpy(&crep.myaddr.ipaddr, &ipv6_addrany, sizeof(T_IN6_ADDR));
#endif

    return alloc_tcp_rep(pRepid, tskid, &crep);
}


/*------------------------------------------------------------------*/

static ER
UITRON_allocTcpRep(ID *pRepid, ID tskid, ubyte2 portNumber)
{
    T_TCP_CREP  crep;

    crep.repatr = 0;
    crep.myaddr.portno = portNumber;

#if (defined(SUPPORT_INET4))
    crep.myaddr.ipaddr = IPV4_ADDRANY;
#elif (defined(SUPPORT_INET6))
    memcpy(&crep.myaddr.ipaddr, &ipv6_addrany, sizeof(T_IN6_ADDR));
#endif

    return alloc_tcp_rep(pRepid, tskid, &crep);
}


/*------------------------------------------------------------------*/

static ER
UITRON_allocTcpCep(ID *pCepid, ID tskid)
{
    T_TCP_CCEP  ccep;

    ccep.cepatr   = 0;
    ccep.sbufsz   = BUF_SIZE;
    ccep.rbufsz   = BUF_SIZE;
    ccep.callback = NULL;
    ccep.sbuf     = NADR;
    ccep.rbuf     = NADR;

    return alloc_tcp_cep(pCepid, tskid, &ccep);
}


/*------------------------------------------------------------------*/

extern MSTATUS
UITRON_TCP_acceptSocket(TCP_SOCKET *pClientSocket, TCP_SOCKET listenSocket, intBoolean *isBreakSignalRequest)
{
    TCP_SOCKET          newSocket = NULL;
    ID                    tskid;
    ER                  error;
    uitronIpAddrPort    dstAddrPort;
    MSTATUS             status  = OK;

    if (NULL == listenSocket)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    syscall(slp_tsk());

    get_tid(&tskid);

    if (NULL == (newSocket = UITRON_allocSocketDescr(FALSE)))
    {
        status = ERR_TCP_ACCEPT_CREATE;
        goto exit;
    }

    newSocket->srcPortNumber = listenSocket->srcPortNumber;

    if (E_OK != (error = UITRON_allocTcpCep(&(listenSocket->cepId), tskid)))
    {
        DEBUG_PRINT(DEBUG_PLATFORM, "UITRON_TCP_acceptSocket: UITRON_allocTcpCep() failed: ");
        DEBUG_PRINTNL(DEBUG_PLATFORM, itron_strerror(error));

        status = ERR_TCP_LISTEN_SOCKET_ERROR;
        goto exit;
    }

    if (E_OK != (error = UITRON_allocTcpRep(&(listenSocket->repId), tskid, listenSocket->portNumber)))
    {
        DEBUG_PRINT(DEBUG_PLATFORM, "UITRON_TCP_acceptSocket: UITRON_allocTcpRep() failed: ");
        DEBUG_PRINTNL(DEBUG_PLATFORM, itron_strerror(error));

        status = ERR_TCP_LISTEN_BIND_ERROR;
        goto error_cleanup;
    }

    /* need to do the accept here */
    if (E_OK != (error = TCP_ACP_CEP(listenSocket->cepId, listenSocket->repId, &dstAddrPort, TMO_FEVR)))
    {
        DEBUG_PRINT(DEBUG_PLATFORM, "UITRON_TCP_acceptSocket: TCP_ACP_CEP() failed: ");
        DEBUG_PRINTNL(DEBUG_PLATFORM, itron_strerror(error));

        status = ERR_TCP_ACCEPT_ERROR;
        goto error_cleanup;
    }

    /* copy out dstAddrPort, for future use by getpeername() */
#if (defined(SUPPORT_INET4))
    newSocket->dstAddress = dstAddrPort->ipaddr;
#elif (defined(SUPPORT_INET6))
    newSocket->dstAddress.family = UITRON_AF_INET6;
    DIGI_MEMCPY((ubyte *) newSocket->dstAddress.uin.addr6, dstAddrPort->__u6_addr.__u6_addr8, 16);
#endif

    newSocket->dstPortNumber = dstAddrPort->portNo;
    *listenSocket = newSocket;
    newSocket = NULL;

exit:
    if (NULL != newSocket);
        UITRON_deallocSocketDescr(&newSocket);

    return status;

} /* UITRON_TCP_acceptSocket */


/*------------------------------------------------------------------*/

extern MSTATUS
UITRON_TCP_connectSocket(TCP_SOCKET *pConnectSocket, sbyte *pIpAddress, ubyte2 portNo)
{
    static uitronIpAddrPort srcAddrPort = { IP_ADDRANY, TCP_PORTANY };
    uitronIpAddrPort        dstAddrPort;
    TCP_SOCKET              newSocket = NULL;
    ER                      error;
    MSTATUS                 status = OK;

    syscall(slp_tsk());

    get_tid(&tskid);

    if (NULL == (newSocket = UITRON_allocSocketDescr(FALSE)))
    {
        status = ERR_TCP_CONNECT_CREATE;
        goto exit;
    }

    server.sin_family = AF_INET;
    server.sin_port = htons(portNo);

    inet_pton(AF_INET, (char *)pIpAddress, &server.sin_addr);

    if (E_OK != (error = TCP_CON_CEP(cepid, &srcAddrPort, &dstAddrPort, 10 * SYSTIM_HZ)))    /* give 10 seconds to connect */
    {
        DEBUG_PRINT(DEBUG_PLATFORM, "UITRON_TCP_connectSocket: TCP_CON_CEP() failed: ");
        DEBUG_PRINTNL(DEBUG_PLATFORM, itron_strerror(error));

        goto exit;
    }

    *pConnectSocket = newSocket;
    newSocket = NULL;

exit:
    if (NULL != newSocket)
        UITRON_deallocSocketDescr(&newSocket);

    return status;
}

static void
send_tcp_echo (ID cepid, T_IN_ADDR *ipaddr, UH portno)
{
    static UB smsg[SND_BUF_SIZE];
    static T_IPEP src = {
        IP_ADDRANY,
        TCP_PORTANY,
        };

    T_IPEP    dst;
    UW    total;
    UH    soff, echo, rep;
    UB    pat, *p;
    ER_UINT    slen;
    ER    error;
    SYSTIM    time;

    dst.ipaddr = *ipaddr;
    dst.portno = portno;

    p = smsg;
    for (rep = NUM_REP_PAT; rep -- > 0; )
        for (pat = PAT_BEGIN; pat <= PAT_END; pat ++)
            *p ++ = pat;

}


/*------------------------------------------------------------------*/

extern MSTATUS
UITRON_TCP_closeSocket(TCP_SOCKET socket)
{
    tcp_cls_cep(socket->cepId, TMO_FEVR);
    UITRON_deallocSocketDescr(&socket);

    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
UITRON_TCP_readSocketAvailable(TCP_SOCKET socket, sbyte *pBuffer,
                               ubyte4 maxBytesToRead, ubyte4 *pNumBytesRead, ubyte4 msTimeout)
{
    TMO     timeout;
    VP      pRecvSegment;
    int     recvSegmentLen;
    int     totalBytesRead;
    MSTATUS status = OK;

    if ((NULL == pBuffer) || (NULL == pNumBytesRead))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* initialize counters */
    totalBytesRead = *pNumBytesRead = 0;

    /* make sure we have something to do... */
    if (0 == maxBytesToRead)
        goto exit;

    /* handle timeout conversion */
    if (TCP_NO_TIMEOUT == msTimeout)
        timeout = TMO_FEVR;
    else
        timeout = msTimeout;    /* easiest part of the port TMO is in milliseconds! */

    /* fetch pointer to the first segment */
    recvSegmentLen = tcp_rcv_buf(socket, &pRecvSegment, timeout);

    do
    {
        if (0 > recvSegmentLen)
        {
            if (E_TMOUT == recvSegmentLen)
                break;

            status = ERR_TCP_READ_ERROR;
            goto exit;
        }

        if (0 == recvSegmentLen)
        {
            status = ERR_TCP_SOCKET_CLOSED;
            goto exit;
        }

        if (recvSegmentLen > (int)maxBytesToRead)
            recvSegmentLen = (int)maxBytesToRead;

        /* transfer date from segment to buffer */
        bcopy(pRecvSegment, (VP)pBuffer, recvSegmentLen);

        /* update pointers and counters */
        pBuffer += recvSegmentLen;
        maxBytesToRead -= recvSegmentLen;
        totalBytesRead += recvSegmentLen;

        /* acknowledge the bytes copied */
        if (0 > tcp_rel_buf(socket, recvSegmentLen))
            break;

        /* get pointer to next segment */
        recvSegmentLen = tcp_rcv_buf(socket, &pRecvSegment, TMO_POL);
    }
    while (maxBytesToRead > 0);

    *pNumBytesRead = totalBytesRead;

    status = OK;

exit:
    return status;

} /* UITRON_TCP_readSocketAvailable */


/*------------------------------------------------------------------*/

extern MSTATUS
UITRON_TCP_writeSocket(TCP_SOCKET socket, sbyte *pBuffer, ubyte4 numBytesToWrite,
                      ubyte4 *pNumBytesWritten)
{
    VP      pSendSegment;
    int     sendSegmentLen;
    ubyte4  numBytesWritten = 0;
    MSTATUS status;

    if ((NULL == pBuffer) || (NULL == pNumBytesWritten))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /*!!!! we might need a mutex here to prevent to threads from accessing the same segment */

    /* get the first segment */
    if (0 >= (sendSegmentLen = tcp_get_buf(socket, &pSendSegment, TMO_POL)))
        goto exit;

    while ((0 < numBytesToWrite) && (0 < sendSegmentLen))
    {
        if (sendSegmentLen > (int)numBytesToWrite)
            sendSegmentLen = (int)numBytesToWrite;

        /* copy buffer to segment */
        bcopy((VP)pBuffer, pSendSegment, sendSegmentLen);

        /* adjust pointers and counters */
        pBuffer += sendSegmentLen;
        numBytesToWrite -= (ubyte4)sendSegmentLen;
        numBytesWritten += (ubyte4)sendSegmentLen;

        /* send the segment on deck out */
        if (0 > tcp_snd_buf(socket, sendSegmentLen))
            break;

        /* get the next segment */
        if (0 >= (sendSegmentLen = tcp_get_buf(socket, &pSendSegment, TMO_POL)))
            break;
    }

    status = OK;

exit:
    *pNumBytesWritten = numBytesWritten;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
UITRON_TCP_getPeerName(TCP_SOCKET socket, ubyte2 *pRetPortNo, MOC_IP_ADDRESS_S *pRetAddr)
{
    MSTATUS                 status = OK;

    if (TRUE == socket->isListenSocket)
    {
        status = ERR_TCP_GETSOCKNAME;
        goto exit;
    }

    *pRetPortNo = socket->portNumber;
    *pRetAddr = socket->dstAddress;

exit:
    return status;
}


#endif /* __UITRON_TCP__ */
