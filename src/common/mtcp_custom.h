/*
 * mtcp_custom.h
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
 */
#ifndef __MTCP_CUSTOM_HEADER__
#define __MTCP_CUSTOM_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

/*------------------------------------------------------------------*/
/*                Add your own custom #defines here                 */
/*------------------------------------------------------------------*/

#if defined(__MYOS_TCP__)
#define __CUSTOM_TCP__

/* Map TCP_ macros from mtcp.h for the appropriate methods/structures.
 * For example:
 *   #define TCP_INIT       MYOS_TCP_init
 *
 * where MYOS_TCP_init is an user defined method.
 */


#endif

#if defined(__RTOS_THREADX__)
/* ── ThreadX + NetX Duo custom TCP platform ──────────────────────────────────
 *
 * The tcp_netxduo.c adapter provides its own THREADX_TCP_BSD_* functions that
 * bridge NanoSSL TCP calls to NetX Duo sockets.  We declare __CUSTOM_TCP__ so
 * mtcp.h does NOT try to use any POSIX/RTOS BSD-socket platform, and we define
 * TCP_SOCKET as a plain int (used as a 1-based slot index in tcp_netxduo.c).
 */
#if !defined(__CUSTOM_TCP__)
#define __CUSTOM_TCP__
#define CUSTOM_TCP
#define TCP_SOCKET int
#define TCP_LISTEN_SOCKET THREADX_TCP_BSD_listenSocket
#define TCP_ACCEPT_SOCKET THREADX_TCP_BSD_acceptSocket
#define TCP_CLOSE_SOCKET THREADX_TCP_BSD_closeSocket
#define TCP_READ_AVL    THREADX_TCP_BSD_readSocketAvailable
#define TCP_READ_AVL_EX THREADX_TCP_BSD_readSocketAvailable
#define TCP_WRITE THREADX_TCP_BSD_writeSocket
#define TCP_CONNECT THREADX_TCP_BSD_connectSocket
#define TCP_IS_SOCKET_VALID(s) ((s) > 0)
/* Pull in the function declarations for all THREADX_TCP_BSD_* symbols above */
#include "../platform/threadx/tcp_netxduo.h"
#endif
#endif

/*------------------------------------------------------------------*/
#ifdef __cplusplus
}
#endif
#endif
