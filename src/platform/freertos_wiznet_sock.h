/*
 * FREERTOS_Wiznet_sock.h
 *
 * FREERTOS TCP Abstraction Layer
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
