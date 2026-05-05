/*
 * win32_signal.c
 *
 * Win32 Signal Handling Abstraction Layer
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

#if defined(__ENABLE_DIGICERT_WIN_STUDIO_BUILD__)
#include <winsock2.h>
#include <Ws2tcpip.h>
#endif
#include "../common/moptions.h"

#if defined(__ENABLE_DIGICERT_RTOS_SIGNAL__) && defined(__RTOS_WIN32__)

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/msignal.h"

#include <windows.h>
#include <signal.h>

/*------------------------------------------------------------------*/

extern MSTATUS
WIN32_registerHandler(int sig, funcPtrSignalHandlerCallback handler)
{
  MSTATUS status = OK;

  if (NULL == handler)
  {
    status = ERR_NULL_POINTER;
    goto exit;
  }

  if (signal(sig, handler) == SIG_ERR)
  {
    status = ERR_RTOS;
  }

exit:
  return status;
}

#endif /* __WIN32_SIGNAL__ */
