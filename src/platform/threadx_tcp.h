/*
 * THREADX_tcp.h
 *
 * THREADX TCP Abstraction Layer
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

#ifndef PLATFORM_THREADX_TCP_H_
#define PLATFORM_THREADX_TCP_H_

#include "common/merrors.h"
#include "common/mtypes.h"

extern MSTATUS THREADX_TCP_BSD_closeSocket(TCP_SOCKET socket);
extern MSTATUS THREADX_TCP_BSD_connectSocket(TCP_SOCKET *pConnectSocket, MOC_IP_ADDRESS pIpAddress, ubyte2 portNo);
extern MSTATUS THREADX_TCP_BSD_readSocketAvailable(TCP_SOCKET socket, sbyte *pBuffer, ubyte4 maxBytesToRead, ubyte4 *pNumBytesRead, ubyte4 msTimeout);
extern MSTATUS THREADX_TCP_BSD_writeSocket(TCP_SOCKET socket, sbyte *pBuffer, ubyte4 numBytesToWrite, ubyte4 *pNumBytesWritten);
extern MSTATUS THREADX_TCP_init();
extern MSTATUS THREADX_TCP_BSD_listenSocket(TCP_SOCKET *listenSocket, ubyte2 portNumber);
#endif /* PLATFORM_THREADX_TCP_H_ */
