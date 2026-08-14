/*
 * tcp_netxduo.c
 *
 * TrustCore NanoSSL socket adapter for NetX Duo on ThreadX.
 *
 * This file bridges the small TCP abstraction used by the TrustCore transport
 * layer to the NetX Duo socket API via nx_tcp_* calls.
 */

#include "platform/threadx/tcp_netxduo.h"

#include <string.h>
#include <stdint.h>
#include <limits.h>

#include "tx_api.h"
#include "nx_api.h"
#include "nx_tcp.h"

#define NETXDUO_MAX_SOCKETS 16U
#define NETXDUO_TCP_WINDOW 4096U
#define NETXDUO_LISTEN_BACKLOG 4U

typedef struct
{
    UINT in_use;
    UINT is_server;
    UINT server_port;
    NX_TCP_SOCKET nx_socket;
    NX_IP *ip;
    NX_PACKET_POOL *pool;
} NETXDUO_SOCKET_SLOT;

static NETXDUO_SOCKET_SLOT g_socket_slots[NETXDUO_MAX_SOCKETS];
static NX_IP *g_netx_ip = NX_NULL;
static NX_PACKET_POOL *g_netx_pool = NX_NULL;

static NETXDUO_SOCKET_SLOT *slot_from_socket(TCP_SOCKET socket)
{
    int slot_index;

    if (socket <= 0) {
        return NX_NULL;
    }

    slot_index = (int)socket - 1;
    if (slot_index < 0 || (UINT)slot_index >= NETXDUO_MAX_SOCKETS) {
        return NX_NULL;
    }

    if (!g_socket_slots[slot_index].in_use) {
        return NX_NULL;
    }

    return &g_socket_slots[slot_index];
}

static TCP_SOCKET slot_allocate(NETXDUO_SOCKET_SLOT **slot_out)
{
    UINT i;

    for (i = 0; i < NETXDUO_MAX_SOCKETS; ++i) {
        if (!g_socket_slots[i].in_use) {
            memset(&g_socket_slots[i], 0, sizeof(g_socket_slots[i]));
            g_socket_slots[i].in_use = 1U;
            g_socket_slots[i].ip = g_netx_ip;
            g_socket_slots[i].pool = g_netx_pool;
            if (slot_out != NX_NULL) {
                *slot_out = &g_socket_slots[i];
            }
            return (TCP_SOCKET)(i + 1);
        }
    }

    if (slot_out != NX_NULL) {
        *slot_out = NX_NULL;
    }
    return 0;
}

static ULONG netxduo_wait_ticks(ubyte4 ms_timeout)
{
    if (ms_timeout == 0U) {
        return NX_NO_WAIT;
    }

    if (ms_timeout >= 0xFFFFFFFEUL) {
        return NX_WAIT_FOREVER;
    }

    return (ULONG)((ms_timeout * TX_TIMER_TICKS_PER_SECOND + 999U) / 1000U);
}

void TRUSTCORE_NETXDUO_SetContext(NX_IP *ip_ptr, NX_PACKET_POOL *pool_ptr)
{
    g_netx_ip = ip_ptr;
    g_netx_pool = pool_ptr;
}

MSTATUS THREADX_TCP_BSD_closeSocket(TCP_SOCKET socket)
{
    NETXDUO_SOCKET_SLOT *slot;

    slot = slot_from_socket(socket);
    if (slot == NX_NULL) {
        return ERR_NULL_POINTER;
    }

    if (slot->is_server) {
        (void)nx_tcp_server_socket_unlisten(slot->ip, slot->server_port);
    } else {
        (void)nx_tcp_client_socket_unbind(&slot->nx_socket);
    }

    (void)nx_tcp_socket_disconnect(&slot->nx_socket, NX_NO_WAIT);
    (void)nx_tcp_socket_delete(&slot->nx_socket);

    memset(slot, 0, sizeof(*slot));
    return OK;
}

/* Forward declarations from threadx_alt_udp.c — no dedicated header */
extern MOC_IP_ADDRESS THREADX_inet_addr(char *addrstr);
extern MSTATUS THREADX_UDP_getAddressOfHost(sbyte *pHostName, MOC_IP_ADDRESS *pRetIpAddress);

MSTATUS THREADX_TCP_BSD_connectSocket(TCP_SOCKET *pConnectSocket,
                                      sbyte *pIpAddress,
                                      ubyte2 portNo)
{
    NETXDUO_SOCKET_SLOT *slot;
    ULONG server_ip;
    UINT status;
    MOC_IP_ADDRESS resolved = 0;

    if (pConnectSocket == NX_NULL || pIpAddress == NX_NULL) {
        return ERR_NULL_POINTER;
    }

    /* Resolve hostname or dotted-decimal string to numeric IP */
    if ((*pIpAddress >= '0') && (*pIpAddress <= '9')) {
        resolved = THREADX_inet_addr((char *)pIpAddress);
    }
    if (resolved == 0) {
        THREADX_UDP_getAddressOfHost(pIpAddress, &resolved);
    }
    if (resolved == 0) {
        return ERR_TCP_CONNECT_ERROR;
    }

    *pConnectSocket = 0;
    if (g_netx_ip == NX_NULL || g_netx_pool == NX_NULL) {
        return ERR_TCP_CONNECT_CREATE;
    }

    *pConnectSocket = slot_allocate(&slot);
    if (*pConnectSocket == 0 || slot == NX_NULL) {
        return ERR_TCP_CONNECT_CREATE;
    }

    status = nx_tcp_socket_create(g_netx_ip, &slot->nx_socket,
                                  "trustcore-client", NX_IP_NORMAL,
                                  NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE,
                                  NETXDUO_TCP_WINDOW, NX_NULL, NX_NULL);
    if (status != NX_SUCCESS) {
        memset(slot, 0, sizeof(*slot));
        return ERR_TCP_CONNECT_CREATE;
    }

    status = nx_tcp_client_socket_bind(&slot->nx_socket, NX_ANY_PORT, NX_NO_WAIT);
    if (status != NX_SUCCESS) {
        (void)nx_tcp_socket_delete(&slot->nx_socket);
        memset(slot, 0, sizeof(*slot));
        return ERR_TCP_CONNECT_CREATE;
    }

    server_ip = (ULONG)resolved;
    status = nx_tcp_client_socket_connect(&slot->nx_socket, server_ip, portNo,
                                          NX_WAIT_FOREVER);
    if (status != NX_SUCCESS) {
        (void)nx_tcp_client_socket_unbind(&slot->nx_socket);
        (void)nx_tcp_socket_delete(&slot->nx_socket);
        memset(slot, 0, sizeof(*slot));
        return ERR_TCP_CONNECT_ERROR;
    }

    return OK;
}

MSTATUS THREADX_TCP_BSD_readSocketAvailable(TCP_SOCKET socket,
                                             sbyte *pBuffer,
                                             ubyte4 maxBytesToRead,
                                             ubyte4 *pNumBytesRead,
                                             ubyte4 msTimeout)
{
    NETXDUO_SOCKET_SLOT *slot;
    NX_PACKET *packet = NX_NULL;
    ULONG packet_length = 0;
    ULONG bytes_copied = 0;
    UINT status;
    ULONG wait_ticks;

    if (pBuffer == NX_NULL || pNumBytesRead == NX_NULL) {
        return ERR_NULL_POINTER;
    }

    *pNumBytesRead = 0;
    slot = slot_from_socket(socket);
    if (slot == NX_NULL) {
        return ERR_NULL_POINTER;
    }

    wait_ticks = netxduo_wait_ticks(msTimeout);
    status = nx_tcp_socket_receive(&slot->nx_socket, &packet, wait_ticks);
    if (status != NX_SUCCESS) {
        if (status == NX_NO_PACKET) {
            return ERR_TCP_READ_TIMEOUT;
        }
        if (status == NX_NOT_CONNECTED) {
            return ERR_TCP_SOCKET_CLOSED;
        }
        return ERR_TCP_READ_ERROR;
    }

    (void)nx_packet_length_get(packet, &packet_length);
    if (packet_length > maxBytesToRead) {
        packet_length = maxBytesToRead;
    }

    status = nx_packet_data_retrieve(packet, pBuffer, &bytes_copied);
    if (status != NX_SUCCESS) {
        (void)nx_packet_release(packet);
        return ERR_TCP_READ_ERROR;
    }

    *pNumBytesRead = (ubyte4)bytes_copied;
    (void)nx_packet_release(packet);
    return OK;
}

MSTATUS THREADX_TCP_BSD_writeSocket(TCP_SOCKET socket,
                                     sbyte *pBuffer,
                                     ubyte4 numBytesToWrite,
                                     ubyte4 *pNumBytesWritten)
{
    NETXDUO_SOCKET_SLOT *slot;
    NX_PACKET *packet = NX_NULL;
    UINT status;

    if (pBuffer == NX_NULL || pNumBytesWritten == NX_NULL) {
        return ERR_NULL_POINTER;
    }

    *pNumBytesWritten = 0;
    slot = slot_from_socket(socket);
    if (slot == NX_NULL) {
        return ERR_NULL_POINTER;
    }

    status = nx_packet_allocate(slot->pool, &packet, NX_TCP_PACKET, NX_NO_WAIT);
    if (status != NX_SUCCESS) {
        return ERR_MEM_ALLOC_FAIL;
    }

    status = nx_packet_data_append(packet, pBuffer, numBytesToWrite,
                                   slot->pool, NX_NO_WAIT);
    if (status != NX_SUCCESS) {
        (void)nx_packet_release(packet);
        return ERR_TCP_WRITE_ERROR;
    }

    status = nx_tcp_socket_send(&slot->nx_socket, packet, NX_WAIT_FOREVER);
    if (status != NX_SUCCESS) {
        (void)nx_packet_release(packet);
        return ERR_TCP_WRITE_ERROR;
    }

    *pNumBytesWritten = numBytesToWrite;
    return OK;
}

MSTATUS THREADX_TCP_BSD_listenSocket(TCP_SOCKET *listenSocket, ubyte2 portNumber)
{
    NETXDUO_SOCKET_SLOT *slot;
    UINT status;

    if (listenSocket == NX_NULL) {
        return ERR_NULL_POINTER;
    }

    *listenSocket = 0;
    if (g_netx_ip == NX_NULL || g_netx_pool == NX_NULL) {
        return ERR_TCP_LISTEN_SOCKET_ERROR;
    }

    *listenSocket = slot_allocate(&slot);
    if (*listenSocket == 0 || slot == NX_NULL) {
        return ERR_TCP_LISTEN_SOCKET_ERROR;
    }

    status = nx_tcp_socket_create(g_netx_ip, &slot->nx_socket,
                                  "trustcore-listen", NX_IP_NORMAL,
                                  NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE,
                                  NETXDUO_TCP_WINDOW, NX_NULL, NX_NULL);
    if (status != NX_SUCCESS) {
        memset(slot, 0, sizeof(*slot));
        return ERR_TCP_LISTEN_SOCKET_ERROR;
    }

    status = nx_tcp_server_socket_listen(g_netx_ip, portNumber,
                                         &slot->nx_socket, NETXDUO_LISTEN_BACKLOG,
                                         NX_NULL);
    if (status != NX_SUCCESS) {
        (void)nx_tcp_socket_delete(&slot->nx_socket);
        memset(slot, 0, sizeof(*slot));
        return ERR_TCP_LISTEN_ERROR;
    }

    slot->is_server = 1U;
    slot->server_port = portNumber;
    return OK;
}

MSTATUS THREADX_TCP_BSD_acceptSocket(TCP_SOCKET *clientSocket,
                                     TCP_SOCKET listenSocket,
                                     intBoolean *isBreakSignalRequest)
{
    NETXDUO_SOCKET_SLOT *slot;
    UINT status;

    (void)isBreakSignalRequest;
    if (clientSocket == NX_NULL) {
        return ERR_NULL_POINTER;
    }

    *clientSocket = 0;
    slot = slot_from_socket(listenSocket);
    if (slot == NX_NULL || !slot->is_server) {
        return ERR_TCP_ACCEPT_ERROR;
    }

    status = nx_tcp_server_socket_accept(&slot->nx_socket, NX_WAIT_FOREVER);
    if (status != NX_SUCCESS) {
        return ERR_TCP_ACCEPT_ERROR;
    }

    slot->is_server = 0U;
    *clientSocket = listenSocket;
    return OK;
}
