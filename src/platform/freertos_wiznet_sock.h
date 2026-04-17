/*
 * FREERTOS_Wiznet_sock.h
 *
 * FREERTOS TCP Abstraction Layer
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

#if defined(__FREERTOS_RTOS__) && defined(__ENABLE_WIZNET_WIRED__)

#define _REENTRANT


#include <FreeRTOS.h>

#include <wizchip_conf.h>
#include <socket.h>
#include "../common/mtypes.h"


#define FAIL -1
extern ubyte m_socketNumber[_WIZCHIP_SOCK_NUM_];
sbyte get_socket_number();
sbyte clear_socket_number(ubyte socketNumber);
extern int LoggingPrintf(const char *apFmt, ...);


#endif /* __FREERTOS_TCP__ */
