/*
 * tcp_netxduo.h
 *
 * Minimal TrustCore socket adapter for NetX Duo / ThreadX.
 *
 * This header exposes the small set of TCP entry points needed by the
 * TrustCore NanoSSL transport shim. The implementation bridges those calls to
 * the project’s NetX Duo socket API.
 */

#ifndef TRUSTCORE_PLATFORM_THREADX_TCP_NETXDUO_H_
#define TRUSTCORE_PLATFORM_THREADX_TCP_NETXDUO_H_

#include "nx_api.h"
#include "common/moptions.h" /* MOC_EXTERN and TrustCore build config */
#include "common/mtypes.h"   /* sbyte4, ubyte, bool-like types */
#include "common/merrors.h"  /* MSTATUS, error codes */
#include "common/mtcp.h"     /* TCP_SOCKET = int via mtcp_custom.h */

#ifdef __cplusplus
extern "C" {
#endif

void TRUSTCORE_NETXDUO_SetContext(NX_IP *ip_ptr, NX_PACKET_POOL *pool_ptr);

MSTATUS THREADX_TCP_BSD_closeSocket(TCP_SOCKET socket);
MSTATUS THREADX_TCP_BSD_connectSocket(TCP_SOCKET *pConnectSocket,
                                      sbyte *pIpAddress,
                                      ubyte2 portNo);
MSTATUS THREADX_TCP_BSD_readSocketAvailable(TCP_SOCKET socket,
                                             sbyte *pBuffer,
                                             ubyte4 maxBytesToRead,
                                             ubyte4 *pNumBytesRead,
                                             ubyte4 msTimeout);
MSTATUS THREADX_TCP_BSD_writeSocket(TCP_SOCKET socket,
                                     sbyte *pBuffer,
                                     ubyte4 numBytesToWrite,
                                     ubyte4 *pNumBytesWritten);
MSTATUS THREADX_TCP_BSD_listenSocket(TCP_SOCKET *listenSocket, ubyte2 portNumber);
MSTATUS THREADX_TCP_BSD_acceptSocket(TCP_SOCKET *clientSocket,
                                     TCP_SOCKET listenSocket,
                                     intBoolean *isBreakSignalRequest);

#ifdef __cplusplus
}
#endif

#endif /* TRUSTCORE_PLATFORM_THREADX_TCP_NETXDUO_H_ */
